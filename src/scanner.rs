use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use anyhow::{Context, Result, bail};

use crate::{
    db::Database,
    detection::CandidateValidator,
    progress::{ProgressMode, ProgressReporter},
    rpc::RpcClient,
};

#[derive(Clone, Debug)]
pub struct ScanConfig {
    pub requested_start_height: u64,
    pub requested_end_height: Option<u64>,
    pub taproot_activation_height: Option<u64>,
    pub progress_mode: ProgressMode,
    pub max_witness_items: usize,
    pub reorg_retention_blocks: u64,
    pub min_free_disk_bytes: u64,
    pub max_in_memory_p2tr_utxos: usize,
}

pub struct Scanner<'a> {
    rpc: RpcClient,
    db: &'a mut Database,
    config: ScanConfig,
    validator: Option<Box<dyn CandidateValidator>>,
}

impl<'a> Scanner<'a> {
    pub fn new(rpc: RpcClient, db: &'a mut Database, config: ScanConfig) -> Self {
        Self {
            rpc,
            db,
            config,
            validator: None,
        }
    }

    pub fn with_validator(mut self, validator: Box<dyn CandidateValidator>) -> Self {
        self.validator = Some(validator);
        self
    }

    pub fn run(mut self) -> Result<()> {
        let info = self.rpc.blockchain_info()?;
        if info.pruned {
            bail!("a non-pruned Bitcoin Core node is required for a complete historical scan");
        }
        let target = self.config.requested_end_height.unwrap_or(info.blocks);
        if target > info.blocks {
            bail!(
                "requested end height {target} is above node tip {}",
                info.blocks
            );
        }
        let activation_height = self
            .config
            .taproot_activation_height
            .unwrap_or_else(|| default_activation_height(&info.chain));
        let mut state = self.db.prepare_scan(
            &info.chain,
            self.config.requested_start_height,
            target,
            activation_height,
            self.config.reorg_retention_blocks,
        )?;

        self.reconcile_reorg(&mut state)?;
        state = self.db.scan_state()?.context("scan state disappeared")?;
        let mut unspent_index = self
            .db
            .load_unspent_index(self.config.max_in_memory_p2tr_utxos)?;
        let status = self.db.status()?;
        let mut progress = ProgressReporter::new(
            self.config.progress_mode,
            state.start_height,
            state.next_height,
            target,
            &status,
        );
        let interrupted = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&interrupted);
        ctrlc::set_handler(move || {
            signal.store(true, Ordering::SeqCst);
        })
        .context("install interrupt handler")?;

        let mut height = state.next_height;
        while height <= target {
            let block_started = Instant::now();
            if interrupted.load(Ordering::SeqCst) {
                progress.finish(true);
                return Ok(());
            }
            self.db
                .ensure_min_free_space(self.config.min_free_disk_bytes)?;
            let hash = self
                .rpc
                .block_hash(height)
                .with_context(|| format!("fetch block hash at height {height}"))?;
            let block = self
                .rpc
                .block(&hash)
                .with_context(|| format!("fetch block {hash} at height {height}"))?;
            if block.height != height || block.hash != hash {
                bail!("node returned inconsistent block identity at height {height}");
            }
            if let Some(expected_previous) = &state.last_block_hash {
                if block.previousblockhash.as_ref() != Some(expected_previous) {
                    bail!("chain changed while scanning at height {height}; restart to reconcile");
                }
            }
            self.db
                .ensure_min_free_space(self.config.min_free_disk_bytes)?;
            let counts = self.db.commit_block(
                &block,
                activation_height,
                self.config.max_witness_items,
                self.config.reorg_retention_blocks,
                &mut unspent_index,
                self.validator.as_deref_mut(),
            )?;
            progress.block_committed(height, &hash, counts, block_started.elapsed().as_millis());
            if self.config.max_in_memory_p2tr_utxos > 0
                && unspent_index.len() > self.config.max_in_memory_p2tr_utxos
            {
                bail!(
                    "P2TR memory guard stopped the scan after committing height {height}: \
                     {} unspent entries, configured limit {}",
                    unspent_index.len(),
                    self.config.max_in_memory_p2tr_utxos
                );
            }
            state.last_block_hash = Some(hash);
            state.next_height = height + 1;
            height += 1;
        }
        progress.finish(false);
        Ok(())
    }

    fn reconcile_reorg(&mut self, state: &mut crate::db::ScanState) -> Result<()> {
        if state.next_height == state.start_height {
            return Ok(());
        }

        let mut cursor = state.next_height - 1;
        let common_ancestor = loop {
            let canonical = self.rpc.block_hash(cursor).with_context(|| {
                format!("fetch canonical block hash at height {cursor} during reorg reconciliation")
            })?;
            let local = self
                .db
                .scanned_block_hash(cursor)?
                .with_context(|| format!("missing local block checkpoint at height {cursor}"))?;
            if local == canonical {
                break Some(cursor);
            }
            if cursor == state.start_height {
                break None;
            }
            cursor -= 1;
        };

        let first_rollback_height = common_ancestor
            .map(|height| height + 1)
            .unwrap_or(state.start_height);
        if first_rollback_height == state.next_height {
            return Ok(());
        }
        self.db
            .ensure_reorg_can_rollback_from(first_rollback_height)?;

        while state.next_height > first_rollback_height {
            self.db
                .rollback_tip()?
                .context("checkpoint references a block missing from scanned_blocks")?;
            *state = self.db.scan_state()?.context("scan state disappeared")?;
        }
        Ok(())
    }
}

fn default_activation_height(chain: &str) -> u64 {
    match chain {
        "main" => 709_632,
        "test" => 2_011_968,
        "signet" | "regtest" | "testnet4" => 0,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use tempfile::NamedTempFile;

    use super::*;
    use crate::rpc::{Auth, RpcOptions};

    const FORUM_FUNDING_HEIGHT: u64 = 959_019;
    const FORUM_REVEAL_HEIGHT: u64 = 959_020;
    const FORUM_REVEAL_TXID: &str =
        "56f4c8b2c11ce6010637f8f831ad03430bc1686fc39d4833ec0281ddbef01a22";
    const FORUM_SCRIPT_HEX: &str = concat!(
        "20",
        "fa9b5ec193f735c41b804fc6ace1d28e81a299fc815c0f5009dd2dd7d0293c3b",
        "ac63",
        "20",
        "51bb73b4a36470cca81fba01fb52a5706052e7240c8d51f4d8085feaa4230839",
        "68"
    );

    #[test]
    #[ignore = "requires BITCOIN_RPC_URL with read access to fixed mainnet blocks"]
    fn mainnet_forum_incident_is_detected_via_read_only_rpc() {
        let _ = dotenvy::dotenv();
        let rpc_url =
            env::var("BITCOIN_RPC_URL").expect("BITCOIN_RPC_URL must be set for this E2E test");
        let rpc = RpcClient::with_options(rpc_url, Auth::None, RpcOptions::default()).unwrap();
        let file = NamedTempFile::new().unwrap();
        let mut db = Database::open(file.path()).unwrap();
        let config = ScanConfig {
            requested_start_height: FORUM_FUNDING_HEIGHT,
            requested_end_height: Some(FORUM_REVEAL_HEIGHT),
            taproot_activation_height: None,
            progress_mode: ProgressMode::None,
            max_witness_items: 4,
            reorg_retention_blocks: 144,
            min_free_disk_bytes: 0,
            max_in_memory_p2tr_utxos: 100_000,
        };

        Scanner::new(rpc, &mut db, config).run().unwrap();

        let status = db.status().unwrap();
        assert_eq!(status.scanned_blocks, 2);
        let detection = db
            .detection_for_revelation(FORUM_REVEAL_TXID)
            .unwrap()
            .expect("known reveal transaction must have persisted analysis");
        assert_eq!(detection.0, "candidate_weak");
        assert_eq!(detection.1, FORUM_SCRIPT_HEX);
    }
}
