use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
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
    pub progress_interval_secs: u64,
    pub max_witness_items: usize,
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
        )?;

        self.reconcile_reorg(&mut state)?;
        state = self.db.scan_state()?.context("scan state disappeared")?;
        let mut unspent_index = self.db.load_unspent_index()?;
        let status = self.db.status()?;
        let mut progress = ProgressReporter::new(
            self.config.progress_mode,
            self.config.progress_interval_secs,
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
            if interrupted.load(Ordering::SeqCst) {
                progress.finish(true);
                return Ok(());
            }
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
            let counts = self.db.commit_block(
                &block,
                activation_height,
                self.config.max_witness_items,
                &mut unspent_index,
                self.validator.as_deref_mut(),
            )?;
            state.last_block_hash = Some(hash);
            state.next_height = height + 1;
            progress.block_committed(height, counts);
            height += 1;
        }
        progress.finish(false);
        Ok(())
    }

    fn reconcile_reorg(&mut self, state: &mut crate::db::ScanState) -> Result<()> {
        while state.next_height > state.start_height {
            let last_height = state.next_height - 1;
            let canonical = self.rpc.block_hash(last_height).with_context(|| {
                format!(
                    "fetch canonical block hash at height {last_height} during reorg reconciliation"
                )
            })?;
            if state.last_block_hash.as_deref() == Some(canonical.as_str()) {
                break;
            }
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
