use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::Serialize;

use crate::{
    analyzer::{ANALYZER_VERSION, AnalysisStatus, SEARCH_WITNESS_ATOMS, analyze_script},
    detection::{
        CandidateValidator, ConsensusStatus, DetectionStatus, PolicyStatus, ValidationEvidence,
    },
    rpc::Block,
    taproot::{p2tr_output_key, parse_and_verify_script_path},
};

pub struct Database {
    conn: Connection,
    path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OutPoint {
    txid: [u8; 32],
    vout: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct P2trPrevout {
    output_key: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct ScanState {
    pub chain: String,
    pub start_height: u64,
    pub next_height: u64,
    pub target_height: u64,
    pub last_block_hash: Option<String>,
    pub taproot_activation_height: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct BlockCounts {
    pub transactions: u64,
    pub inputs: u64,
    pub outputs: u64,
    pub p2tr_created: u64,
    pub p2tr_spent: u64,
    pub script_paths: u64,
    pub analyzed_scripts: u64,
    pub weak_scripts: u64,
    pub confirmed_weak_scripts: u64,
    pub candidate_weak_scripts: u64,
    pub no_proof_found_scripts: u64,
    pub inconclusive_scripts: u64,
    pub invalid_script_scripts: u64,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub chain: Option<String>,
    pub start_height: Option<u64>,
    pub next_height: Option<u64>,
    pub target_height: Option<u64>,
    pub last_block_hash: Option<String>,
    pub taproot_activation_height: Option<u64>,
    pub reorg_retention_blocks: Option<u64>,
    pub oldest_reorg_safe_height: Option<u64>,
    pub coverage_complete_from_genesis: bool,
    pub scanned_blocks: u64,
    pub scanned_transactions: u64,
    pub scanned_inputs: u64,
    pub scanned_outputs: u64,
    pub revealed_script_paths: u64,
    pub weak_scripts: u64,
    pub analyzed_scripts: u64,
    pub confirmed_weak_scripts: u64,
    pub candidate_weak_scripts: u64,
    pub no_proof_found_scripts: u64,
    pub inconclusive_scripts: u64,
    pub invalid_script_scripts: u64,
    pub retained_evidence_scripts: u64,
    pub compacted_no_proof_scripts: u64,
    pub current_p2tr_utxos: u64,
    pub current_p2tr_balance_sats: u64,
}

#[derive(Debug, Serialize)]
pub struct RiskReport {
    pub generated_at_unix: u64,
    pub scanner_status: Status,
    pub risks: Vec<RiskItem>,
}

#[derive(Debug, Serialize)]
pub struct RiskItem {
    pub severity: String,
    pub output_key: String,
    pub current_balance_sats: u64,
    pub utxo_count: usize,
    pub unspent_outpoints: Vec<String>,
    pub vulnerable_script: String,
    pub vulnerability_class: String,
    pub proof_witness: Vec<String>,
    pub execution_trace: serde_json::Value,
    pub first_revealed_txid: String,
    pub detection_status: String,
    pub consensus_status: String,
    pub policy_status: String,
    pub validator: String,
    pub validation_details: Option<String>,
    pub confidence: String,
    pub limitations: Vec<String>,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("open SQLite database {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(30))?;
        let db = Self {
            conn,
            path: path.to_owned(),
        };
        db.migrate()?;
        Ok(db)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scanned_blocks (
                height INTEGER PRIMARY KEY,
                block_hash TEXT NOT NULL UNIQUE,
                previous_block_hash TEXT,
                transactions INTEGER NOT NULL,
                inputs INTEGER NOT NULL,
                outputs INTEGER NOT NULL,
                p2tr_created INTEGER NOT NULL,
                p2tr_spent INTEGER NOT NULL,
                script_paths INTEGER NOT NULL,
                weak_scripts INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS p2tr_outputs (
                txid TEXT NOT NULL,
                vout INTEGER NOT NULL,
                output_key BLOB NOT NULL,
                value_sats INTEGER NOT NULL,
                created_height INTEGER NOT NULL,
                created_block_hash TEXT NOT NULL,
                spent_height INTEGER,
                spent_block_hash TEXT,
                spending_txid TEXT,
                spending_input_index INTEGER,
                PRIMARY KEY (txid, vout)
            );
            CREATE INDEX IF NOT EXISTS p2tr_outputs_unspent_key
                ON p2tr_outputs(output_key) WHERE spent_height IS NULL;
            CREATE INDEX IF NOT EXISTS p2tr_outputs_spent_block
                ON p2tr_outputs(spent_block_hash);
            CREATE INDEX IF NOT EXISTS p2tr_outputs_spent_height
                ON p2tr_outputs(spent_height) WHERE spent_height IS NOT NULL;
            CREATE INDEX IF NOT EXISTS p2tr_outputs_created_block
                ON p2tr_outputs(created_block_hash);

            CREATE TABLE IF NOT EXISTS tapleaves (
                id INTEGER PRIMARY KEY,
                output_key BLOB NOT NULL,
                internal_key BLOB NOT NULL,
                tapleaf_hash BLOB NOT NULL,
                leaf_version INTEGER NOT NULL,
                script BLOB NOT NULL,
                script_size INTEGER NOT NULL DEFAULT 0,
                evidence_retained INTEGER NOT NULL DEFAULT 1,
                control_block BLOB NOT NULL,
                merkle_path_json TEXT NOT NULL,
                UNIQUE(output_key, tapleaf_hash, control_block)
            );

            CREATE TABLE IF NOT EXISTS revelation_events (
                id INTEGER PRIMARY KEY,
                tapleaf_id INTEGER NOT NULL REFERENCES tapleaves(id) ON DELETE CASCADE,
                prev_txid TEXT NOT NULL,
                prev_vout INTEGER NOT NULL,
                spending_txid TEXT NOT NULL,
                spending_input_index INTEGER NOT NULL,
                block_height INTEGER NOT NULL,
                block_hash TEXT NOT NULL,
                observed_witness_json TEXT NOT NULL,
                annex_hex TEXT,
                UNIQUE(spending_txid, spending_input_index)
            );
            CREATE INDEX IF NOT EXISTS revelation_events_block
                ON revelation_events(block_hash);

            CREATE TABLE IF NOT EXISTS weaknesses (
                tapleaf_id INTEGER PRIMARY KEY REFERENCES tapleaves(id) ON DELETE CASCADE,
                vulnerability_class TEXT NOT NULL,
                proof_witness_json TEXT NOT NULL,
                execution_trace_json TEXT NOT NULL,
                limitations_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS analysis_runs (
                tapleaf_id INTEGER PRIMARY KEY REFERENCES tapleaves(id) ON DELETE CASCADE,
                analysis_status TEXT NOT NULL,
                detection_status TEXT NOT NULL,
                analyzer_version TEXT NOT NULL,
                search_config_json TEXT NOT NULL,
                consensus_status TEXT NOT NULL,
                policy_status TEXT NOT NULL,
                validator TEXT NOT NULL,
                validation_details TEXT,
                analyzed_at_unix INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS analysis_runs_detection_status
                ON analysis_runs(detection_status);
            "#,
        )?;
        ensure_column(
            &self.conn,
            "tapleaves",
            "script_size",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(
            &self.conn,
            "tapleaves",
            "evidence_retained",
            "INTEGER NOT NULL DEFAULT 1",
        )?;
        self.conn.execute(
            "UPDATE tapleaves
             SET script_size=LENGTH(script)
             WHERE script_size=0 AND LENGTH(script)>0",
            [],
        )?;
        self.conn.execute_batch(
            r#"
            UPDATE revelation_events
            SET observed_witness_json='[]', annex_hex=NULL
            WHERE tapleaf_id IN (
                SELECT a.tapleaf_id
                FROM analysis_runs a
                LEFT JOIN weaknesses w ON w.tapleaf_id=a.tapleaf_id
                WHERE a.detection_status='no_proof_found'
                  AND w.tapleaf_id IS NULL
            )
              AND (observed_witness_json<>'[]' OR annex_hex IS NOT NULL);
            UPDATE tapleaves
            SET script=X'', merkle_path_json='[]', evidence_retained=0
            WHERE id IN (
                SELECT a.tapleaf_id
                FROM analysis_runs a
                LEFT JOIN weaknesses w ON w.tapleaf_id=a.tapleaf_id
                WHERE a.detection_status='no_proof_found'
                  AND w.tapleaf_id IS NULL
            )
              AND evidence_retained<>0;
            "#,
        )?;
        Ok(())
    }

    pub fn prepare_scan(
        &mut self,
        chain: &str,
        start_height: u64,
        target_height: u64,
        activation_height: u64,
        reorg_retention_blocks: u64,
    ) -> Result<ScanState> {
        if reorg_retention_blocks == 0 {
            bail!("reorg retention must be at least one block");
        }
        let existing = self.scan_state()?;
        if let Some(mut state) = existing {
            if state.chain != chain {
                bail!(
                    "database belongs to chain {}, node reports {}",
                    state.chain,
                    chain
                );
            }
            if state.start_height != start_height {
                bail!(
                    "database start height is {}, requested {}",
                    state.start_height,
                    start_height
                );
            }
            if state.taproot_activation_height != activation_height {
                bail!(
                    "database activation height is {}, requested {}",
                    state.taproot_activation_height,
                    activation_height
                );
            }
            state.target_height = target_height;
            set_meta(&self.conn, "target_height", &target_height.to_string())?;
            set_meta(
                &self.conn,
                "reorg_retention_blocks",
                &reorg_retention_blocks.to_string(),
            )?;
            if get_meta(&self.conn, "oldest_reorg_safe_height")?.is_none() {
                set_meta(
                    &self.conn,
                    "oldest_reorg_safe_height",
                    &state.start_height.to_string(),
                )?;
            }
            return Ok(state);
        }

        let tx = self.conn.transaction()?;
        set_meta_tx(&tx, "chain", chain)?;
        set_meta_tx(&tx, "start_height", &start_height.to_string())?;
        set_meta_tx(&tx, "next_height", &start_height.to_string())?;
        set_meta_tx(&tx, "target_height", &target_height.to_string())?;
        set_meta_tx(
            &tx,
            "taproot_activation_height",
            &activation_height.to_string(),
        )?;
        set_meta_tx(
            &tx,
            "reorg_retention_blocks",
            &reorg_retention_blocks.to_string(),
        )?;
        set_meta_tx(&tx, "oldest_reorg_safe_height", &start_height.to_string())?;
        tx.commit()?;
        Ok(ScanState {
            chain: chain.to_owned(),
            start_height,
            next_height: start_height,
            target_height,
            last_block_hash: None,
            taproot_activation_height: activation_height,
        })
    }

    pub fn scan_state(&self) -> Result<Option<ScanState>> {
        let Some(chain) = get_meta(&self.conn, "chain")? else {
            return Ok(None);
        };
        Ok(Some(ScanState {
            chain,
            start_height: parse_meta(&self.conn, "start_height")?,
            next_height: parse_meta(&self.conn, "next_height")?,
            target_height: parse_meta(&self.conn, "target_height")?,
            last_block_hash: get_meta(&self.conn, "last_block_hash")?,
            taproot_activation_height: parse_meta(&self.conn, "taproot_activation_height")?,
        }))
    }

    pub fn commit_block(
        &mut self,
        block: &Block,
        activation_height: u64,
        max_witness_items: usize,
        reorg_retention_blocks: u64,
        unspent_index: &mut HashMap<OutPoint, P2trPrevout>,
        mut validator: Option<&mut (dyn CandidateValidator + 'static)>,
    ) -> Result<BlockCounts> {
        if reorg_retention_blocks == 0 {
            bail!("reorg retention must be at least one block");
        }
        let tx = self.conn.transaction()?;
        let mut counts = BlockCounts {
            transactions: block.tx.len() as u64,
            ..Default::default()
        };

        for transaction in &block.tx {
            counts.inputs += transaction.vin.len() as u64;
            counts.outputs += transaction.vout.len() as u64;

            for (input_index, input) in transaction.vin.iter().enumerate() {
                if input.coinbase.is_some() {
                    continue;
                }
                let (Some(prev_txid), Some(prev_vout)) = (&input.txid, input.vout) else {
                    continue;
                };
                let outpoint = OutPoint::parse(prev_txid, prev_vout)?;
                let Some(prevout) = unspent_index.remove(&outpoint) else {
                    continue;
                };
                counts.p2tr_spent += 1;

                if block.height >= activation_height {
                    if let Some(reveal) =
                        parse_and_verify_script_path(&input.txinwitness, &prevout.output_key)?
                    {
                        counts.script_paths += 1;
                        let merkle_path = reveal
                            .merkle_path
                            .iter()
                            .map(hex::encode)
                            .collect::<Vec<_>>();
                        tx.execute(
                            r#"
                            INSERT INTO tapleaves(
                                output_key, internal_key, tapleaf_hash, leaf_version,
                                script, script_size, evidence_retained,
                                control_block, merkle_path_json
                            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8)
                            ON CONFLICT(output_key, tapleaf_hash, control_block) DO UPDATE SET
                                internal_key=excluded.internal_key,
                                leaf_version=excluded.leaf_version,
                                script=excluded.script,
                                script_size=excluded.script_size,
                                evidence_retained=1,
                                merkle_path_json=excluded.merkle_path_json
                            "#,
                            params![
                                prevout.output_key.as_slice(),
                                reveal.internal_key.as_slice(),
                                reveal.tapleaf_hash.as_slice(),
                                reveal.leaf_version,
                                reveal.script,
                                reveal.script.len(),
                                reveal.control_block,
                                serde_json::to_string(&merkle_path)?,
                            ],
                        )?;
                        let tapleaf_id: i64 = tx.query_row(
                            "SELECT id FROM tapleaves WHERE output_key=?1 AND tapleaf_hash=?2 AND control_block=?3",
                            params![
                                prevout.output_key.as_slice(),
                                reveal.tapleaf_hash.as_slice(),
                                reveal.control_block,
                            ],
                            |row| row.get(0),
                        )?;
                        tx.execute(
                            r#"
                            INSERT INTO revelation_events(
                                tapleaf_id, prev_txid, prev_vout, spending_txid,
                                spending_input_index, block_height, block_hash,
                                observed_witness_json, annex_hex
                            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                            ON CONFLICT(spending_txid, spending_input_index) DO NOTHING
                            "#,
                            params![
                                tapleaf_id,
                                prev_txid,
                                prev_vout,
                                transaction.txid,
                                input_index as u32,
                                block.height,
                                block.hash,
                                serde_json::to_string(&input.txinwitness)?,
                                reveal.annex.as_ref().map(hex::encode),
                            ],
                        )?;

                        if reveal.leaf_version == 0xc0 {
                            let analysis = analyze_script(&reveal.script, max_witness_items);
                            let evidence = if matches!(analysis.status, AnalysisStatus::Weak) {
                                if let Some(candidate_validator) = validator.as_deref_mut() {
                                    let proof = analysis
                                        .proof_witness
                                        .as_deref()
                                        .unwrap_or_default()
                                        .iter()
                                        .map(hex::decode)
                                        .collect::<Result<Vec<_>, _>>()?;
                                    let validator_name = candidate_validator.name().to_owned();
                                    match candidate_validator.validate(&reveal.script, &proof) {
                                        Ok(evidence) => evidence,
                                        Err(error) => ValidationEvidence::validation_failed(
                                            &validator_name,
                                            &error,
                                        ),
                                    }
                                } else {
                                    ValidationEvidence::candidate_without_authoritative_validation()
                                }
                            } else {
                                ValidationEvidence {
                                    detection_status: detection_status_for_analysis(
                                        analysis.status,
                                    ),
                                    consensus_status: ConsensusStatus::NotChecked,
                                    policy_status: PolicyStatus::NotChecked,
                                    validator: "none".to_owned(),
                                    details: None,
                                }
                            };
                            counts.analyzed_scripts += 1;
                            let search_config = serde_json::json!({
                                "requested_max_witness_items": max_witness_items,
                                "effective_max_witness_items": max_witness_items.min(12),
                                "witness_atoms": SEARCH_WITNESS_ATOMS,
                            });
                            tx.execute(
                                r#"
                                INSERT INTO analysis_runs(
                                    tapleaf_id, analysis_status, detection_status,
                                    analyzer_version, search_config_json, consensus_status,
                                    policy_status, validator, validation_details, analyzed_at_unix
                                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                                ON CONFLICT(tapleaf_id) DO UPDATE SET
                                    analysis_status=CASE
                                        WHEN analysis_runs.detection_status='confirmed_weak'
                                          OR (
                                            analysis_runs.detection_status='candidate_weak'
                                            AND excluded.detection_status<>'confirmed_weak'
                                          )
                                        THEN analysis_runs.analysis_status
                                        ELSE excluded.analysis_status
                                    END,
                                    detection_status=CASE
                                        WHEN analysis_runs.detection_status='confirmed_weak'
                                        THEN analysis_runs.detection_status
                                        WHEN analysis_runs.detection_status='candidate_weak'
                                          AND excluded.detection_status<>'confirmed_weak'
                                        THEN analysis_runs.detection_status
                                        ELSE excluded.detection_status
                                    END,
                                    analyzer_version=CASE
                                        WHEN analysis_runs.detection_status='confirmed_weak'
                                          OR (
                                            analysis_runs.detection_status='candidate_weak'
                                            AND excluded.detection_status<>'confirmed_weak'
                                          )
                                        THEN analysis_runs.analyzer_version
                                        ELSE excluded.analyzer_version
                                    END,
                                    search_config_json=CASE
                                        WHEN analysis_runs.detection_status='confirmed_weak'
                                          OR (
                                            analysis_runs.detection_status='candidate_weak'
                                            AND excluded.detection_status<>'confirmed_weak'
                                          )
                                        THEN analysis_runs.search_config_json
                                        ELSE excluded.search_config_json
                                    END,
                                    consensus_status=CASE
                                        WHEN analysis_runs.detection_status='confirmed_weak'
                                        THEN analysis_runs.consensus_status
                                        WHEN analysis_runs.detection_status='candidate_weak'
                                          AND excluded.detection_status<>'confirmed_weak'
                                        THEN analysis_runs.consensus_status
                                        ELSE excluded.consensus_status
                                    END,
                                    policy_status=CASE
                                        WHEN analysis_runs.detection_status='confirmed_weak'
                                        THEN analysis_runs.policy_status
                                        WHEN analysis_runs.detection_status='candidate_weak'
                                          AND excluded.detection_status<>'confirmed_weak'
                                        THEN analysis_runs.policy_status
                                        ELSE excluded.policy_status
                                    END,
                                    validator=CASE
                                        WHEN analysis_runs.detection_status='confirmed_weak'
                                        THEN analysis_runs.validator
                                        WHEN analysis_runs.detection_status='candidate_weak'
                                          AND excluded.detection_status<>'confirmed_weak'
                                        THEN analysis_runs.validator
                                        ELSE excluded.validator
                                    END,
                                    validation_details=CASE
                                        WHEN analysis_runs.detection_status='confirmed_weak'
                                        THEN analysis_runs.validation_details
                                        WHEN analysis_runs.detection_status='candidate_weak'
                                          AND excluded.detection_status<>'confirmed_weak'
                                        THEN analysis_runs.validation_details
                                        ELSE excluded.validation_details
                                    END,
                                    analyzed_at_unix=CASE
                                        WHEN analysis_runs.detection_status='confirmed_weak'
                                          OR (
                                            analysis_runs.detection_status='candidate_weak'
                                            AND excluded.detection_status<>'confirmed_weak'
                                          )
                                        THEN analysis_runs.analyzed_at_unix
                                        ELSE excluded.analyzed_at_unix
                                    END
                                "#,
                                params![
                                    tapleaf_id,
                                    analysis.status.as_str(),
                                    evidence.detection_status.as_str(),
                                    ANALYZER_VERSION,
                                    serde_json::to_string(&search_config)?,
                                    evidence.consensus_status.as_str(),
                                    evidence.policy_status.as_str(),
                                    evidence.validator,
                                    evidence.details,
                                    unix_timestamp(),
                                ],
                            )?;
                            let effective_detection_status: String = tx.query_row(
                                "SELECT detection_status FROM analysis_runs WHERE tapleaf_id=?1",
                                [tapleaf_id],
                                |row| row.get(0),
                            )?;
                            match effective_detection_status.as_str() {
                                "confirmed_weak" => counts.confirmed_weak_scripts += 1,
                                "candidate_weak" => counts.candidate_weak_scripts += 1,
                                "no_proof_found" => counts.no_proof_found_scripts += 1,
                                "inconclusive" => counts.inconclusive_scripts += 1,
                                "invalid_script" => counts.invalid_script_scripts += 1,
                                value => bail!("stored unknown detection status {value}"),
                            }
                            if matches!(analysis.status, AnalysisStatus::Weak) {
                                counts.weak_scripts += 1;
                                tx.execute(
                                    r#"
                                    INSERT INTO weaknesses(
                                        tapleaf_id, vulnerability_class, proof_witness_json,
                                        execution_trace_json, limitations_json
                                    ) VALUES (?1, ?2, ?3, ?4, ?5)
                                    ON CONFLICT(tapleaf_id) DO UPDATE SET
                                        vulnerability_class=excluded.vulnerability_class,
                                        proof_witness_json=excluded.proof_witness_json,
                                        execution_trace_json=excluded.execution_trace_json,
                                        limitations_json=excluded.limitations_json
                                    "#,
                                    params![
                                        tapleaf_id,
                                        analysis.vulnerability_class.unwrap_or_default(),
                                        serde_json::to_string(
                                            &analysis.proof_witness.unwrap_or_default()
                                        )?,
                                        serde_json::to_string(&analysis.execution_trace)?,
                                        serde_json::to_string(&analysis.limitations)?,
                                    ],
                                )?;
                            }
                            if effective_detection_status == "no_proof_found" {
                                let has_prior_weakness: bool = tx.query_row(
                                    "SELECT EXISTS(
                                        SELECT 1 FROM weaknesses WHERE tapleaf_id=?1
                                    )",
                                    [tapleaf_id],
                                    |row| row.get(0),
                                )?;
                                if !has_prior_weakness {
                                    compact_no_proof_evidence(&tx, tapleaf_id)?;
                                }
                            }
                        }
                    }
                }

                tx.execute(
                    r#"
                    UPDATE p2tr_outputs
                    SET spent_height=?1, spent_block_hash=?2, spending_txid=?3,
                        spending_input_index=?4
                    WHERE txid=?5 AND vout=?6 AND spent_height IS NULL
                    "#,
                    params![
                        block.height,
                        block.hash,
                        transaction.txid,
                        input_index as u32,
                        prev_txid,
                        prev_vout,
                    ],
                )?;
            }

            for output in &transaction.vout {
                let Some(output_key) = p2tr_output_key(&output.script_pub_key.hex)? else {
                    continue;
                };
                counts.p2tr_created += 1;
                tx.execute(
                    r#"
                    INSERT INTO p2tr_outputs(
                        txid, vout, output_key, value_sats,
                        created_height, created_block_hash
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                    "#,
                    params![
                        transaction.txid,
                        output.n,
                        output_key.as_slice(),
                        output.value.0,
                        block.height,
                        block.hash,
                    ],
                )?;
                unspent_index.insert(OutPoint::parse(&transaction.txid, output.n)?, P2trPrevout {
                    output_key,
                });
            }
        }

        tx.execute(
            r#"
            INSERT INTO scanned_blocks(
                height, block_hash, previous_block_hash, transactions, inputs,
                outputs, p2tr_created, p2tr_spent, script_paths, weak_scripts
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
            "#,
            params![
                block.height,
                block.hash,
                block.previousblockhash,
                counts.transactions,
                counts.inputs,
                counts.outputs,
                counts.p2tr_created,
                counts.p2tr_spent,
                counts.script_paths,
                counts.weak_scripts,
            ],
        )?;
        set_meta_tx(&tx, "next_height", &(block.height + 1).to_string())?;
        set_meta_tx(&tx, "last_block_hash", &block.hash)?;
        prune_spent_reorg_state(
            &tx,
            block.height,
            reorg_retention_blocks,
            parse_meta_tx(&tx, "start_height")?,
        )?;
        tx.commit()?;
        Ok(counts)
    }

    pub fn load_unspent_index(&self, max_entries: usize) -> Result<HashMap<OutPoint, P2trPrevout>> {
        let stored_entries: u64 = self.conn.query_row(
            "SELECT COUNT(*) FROM p2tr_outputs WHERE spent_height IS NULL",
            [],
            |row| row.get(0),
        )?;
        if max_entries > 0 && stored_entries > max_entries as u64 {
            bail!(
                "P2TR memory guard stopped the scan: {stored_entries} unspent entries, \
                 configured limit {max_entries}"
            );
        }
        let mut statement = self.conn.prepare(
            "SELECT txid, vout, output_key FROM p2tr_outputs WHERE spent_height IS NULL",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, u32>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut index = HashMap::new();
        for row in rows {
            let (txid, vout, key) = row?;
            let output_key = key
                .try_into()
                .map_err(|_| anyhow::anyhow!("stored output key is not 32 bytes"))?;
            index.insert(OutPoint::parse(&txid, vout)?, P2trPrevout { output_key });
        }
        Ok(index)
    }

    pub fn ensure_min_free_space(&self, required_bytes: u64) -> Result<()> {
        if required_bytes == 0 || self.path == Path::new(":memory:") {
            return Ok(());
        }
        let directory = self
            .path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let available = fs2::available_space(directory)
            .with_context(|| format!("check free space for {}", directory.display()))?;
        if available < required_bytes {
            bail!(
                "disk guard stopped the scan: {} MiB free at {}, {} MiB required",
                available / 1024 / 1024,
                directory.display(),
                required_bytes / 1024 / 1024
            );
        }
        Ok(())
    }

    pub fn rollback_tip(&mut self) -> Result<Option<u64>> {
        let Some((height, block_hash)): Option<(u64, String)> = self
            .conn
            .query_row(
                "SELECT height, block_hash FROM scanned_blocks ORDER BY height DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
        else {
            return Ok(None);
        };
        self.ensure_reorg_can_rollback_from(height)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            r#"
            UPDATE p2tr_outputs
            SET spent_height=NULL, spent_block_hash=NULL,
                spending_txid=NULL, spending_input_index=NULL
            WHERE spent_block_hash=?1
            "#,
            [&block_hash],
        )?;
        tx.execute("DELETE FROM p2tr_outputs WHERE created_block_hash=?1", [
            &block_hash,
        ])?;
        tx.execute("DELETE FROM revelation_events WHERE block_hash=?1", [
            &block_hash,
        ])?;
        tx.execute("DELETE FROM scanned_blocks WHERE height=?1", [height])?;
        tx.execute(
            "DELETE FROM tapleaves WHERE NOT EXISTS (
                SELECT 1 FROM revelation_events WHERE tapleaf_id=tapleaves.id
            )",
            [],
        )?;
        let prior_hash: Option<String> = tx
            .query_row(
                "SELECT block_hash FROM scanned_blocks ORDER BY height DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        set_meta_tx(&tx, "next_height", &height.to_string())?;
        match prior_hash {
            Some(hash) => set_meta_tx(&tx, "last_block_hash", &hash)?,
            None => {
                tx.execute("DELETE FROM metadata WHERE key='last_block_hash'", [])?;
            }
        }
        tx.commit()?;
        Ok(Some(height))
    }

    pub fn scanned_block_hash(&self, height: u64) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row(
                "SELECT block_hash FROM scanned_blocks WHERE height=?1",
                [height],
                |row| row.get(0),
            )
            .optional()?)
    }

    #[cfg(test)]
    pub fn detection_for_revelation(
        &self,
        spending_txid: &str,
    ) -> Result<Option<(String, String)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT a.detection_status, lower(hex(l.script))
                 FROM revelation_events e
                 JOIN analysis_runs a ON a.tapleaf_id=e.tapleaf_id
                 JOIN tapleaves l ON l.id=e.tapleaf_id
                 WHERE e.spending_txid=?1
                 ORDER BY e.spending_input_index
                 LIMIT 1",
                [spending_txid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?)
    }

    pub fn ensure_reorg_can_rollback_from(&self, first_height: u64) -> Result<()> {
        let oldest = get_meta(&self.conn, "oldest_reorg_safe_height")?
            .map(|value| {
                value
                    .parse::<u64>()
                    .context("metadata key oldest_reorg_safe_height is invalid")
            })
            .transpose()?
            .unwrap_or(first_height);
        if first_height < oldest {
            bail!(
                "reorganization requires rolling back from height {first_height}, \
                 but compact storage only retains rollback state from height {oldest}; \
                 rebuild the database from a trusted checkpoint"
            );
        }
        Ok(())
    }

    pub fn status(&self) -> Result<Status> {
        let state = self.scan_state()?;
        let aggregate = self.conn.query_row(
            r#"
            SELECT
                COUNT(*),
                COALESCE(SUM(transactions), 0),
                COALESCE(SUM(inputs), 0),
                COALESCE(SUM(outputs), 0),
                COALESCE(SUM(script_paths), 0)
            FROM scanned_blocks
            "#,
            [],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                ))
            },
        )?;
        let weak_scripts = self
            .conn
            .query_row("SELECT COUNT(*) FROM weaknesses", [], |row| row.get(0))?;
        let analysis_counts = self.conn.query_row(
            r#"
            SELECT
                COUNT(*),
                COALESCE(SUM(detection_status='confirmed_weak'), 0),
                COALESCE(SUM(detection_status='candidate_weak'), 0),
                COALESCE(SUM(detection_status='no_proof_found'), 0),
                COALESCE(SUM(detection_status='inconclusive'), 0),
                COALESCE(SUM(detection_status='invalid_script'), 0)
            FROM analysis_runs
            "#,
            [],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u64>(4)?,
                    row.get::<_, u64>(5)?,
                ))
            },
        )?;
        let (utxos, balance) = self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(value_sats), 0)
             FROM p2tr_outputs WHERE spent_height IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let evidence_counts = self.conn.query_row(
            "SELECT
                COALESCE(SUM(evidence_retained<>0), 0),
                COALESCE(SUM(evidence_retained=0), 0)
             FROM tapleaves",
            [],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, u64>(1)?)),
        )?;

        Ok(Status {
            chain: state.as_ref().map(|value| value.chain.clone()),
            start_height: state.as_ref().map(|value| value.start_height),
            next_height: state.as_ref().map(|value| value.next_height),
            target_height: state.as_ref().map(|value| value.target_height),
            last_block_hash: state.and_then(|value| value.last_block_hash),
            taproot_activation_height: self
                .scan_state()?
                .map(|value| value.taproot_activation_height),
            reorg_retention_blocks: optional_meta_u64(&self.conn, "reorg_retention_blocks")?,
            oldest_reorg_safe_height: optional_meta_u64(&self.conn, "oldest_reorg_safe_height")?,
            coverage_complete_from_genesis: self
                .scan_state()?
                .is_some_and(|value| value.start_height == 0),
            scanned_blocks: aggregate.0,
            scanned_transactions: aggregate.1,
            scanned_inputs: aggregate.2,
            scanned_outputs: aggregate.3,
            revealed_script_paths: aggregate.4,
            weak_scripts,
            analyzed_scripts: analysis_counts.0,
            confirmed_weak_scripts: analysis_counts.1,
            candidate_weak_scripts: analysis_counts.2,
            no_proof_found_scripts: analysis_counts.3,
            inconclusive_scripts: analysis_counts.4,
            invalid_script_scripts: analysis_counts.5,
            retained_evidence_scripts: evidence_counts.0,
            compacted_no_proof_scripts: evidence_counts.1,
            current_p2tr_utxos: utxos,
            current_p2tr_balance_sats: balance,
        })
    }

    pub fn report(&self) -> Result<RiskReport> {
        let mut statement = self.conn.prepare(
            r#"
            SELECT
                l.id, hex(l.output_key), hex(l.script),
                w.vulnerability_class, w.proof_witness_json,
                w.execution_trace_json, w.limitations_json,
                a.detection_status, a.consensus_status, a.policy_status,
                a.validator, a.validation_details,
                (
                    SELECT spending_txid FROM revelation_events e
                    WHERE e.tapleaf_id=l.id
                    ORDER BY block_height, id LIMIT 1
                )
            FROM tapleaves l
            JOIN weaknesses w ON w.tapleaf_id=l.id
            JOIN analysis_runs a ON a.tapleaf_id=l.id
            ORDER BY l.id
            "#,
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
                row.get::<_, String>(9)?,
                row.get::<_, String>(10)?,
                row.get::<_, Option<String>>(11)?,
                row.get::<_, String>(12)?,
            ))
        })?;
        let mut risks = Vec::new();
        for row in rows {
            let (
                _leaf_id,
                output_key,
                script,
                class,
                proof_json,
                trace_json,
                limitations_json,
                detection_status,
                consensus_status,
                policy_status,
                validator,
                validation_details,
                first_txid,
            ) = row?;
            let output_key_bytes = hex::decode(&output_key)?;
            let mut utxo_statement = self.conn.prepare(
                "SELECT txid, vout, value_sats FROM p2tr_outputs
                 WHERE output_key=?1 AND spent_height IS NULL
                 ORDER BY created_height, txid, vout",
            )?;
            let utxo_rows = utxo_statement.query_map([output_key_bytes], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, u64>(2)?,
                ))
            })?;
            let mut outpoints = Vec::new();
            let mut balance = 0u64;
            for utxo in utxo_rows {
                let (txid, vout, value) = utxo?;
                outpoints.push(format!("{txid}:{vout}"));
                balance = balance
                    .checked_add(value)
                    .context("risk balance overflow")?;
            }
            if outpoints.is_empty() {
                continue;
            }
            risks.push(RiskItem {
                severity: if detection_status == "confirmed_weak" {
                    "critical"
                } else {
                    "candidate"
                }
                .to_owned(),
                output_key: output_key.to_lowercase(),
                current_balance_sats: balance,
                utxo_count: outpoints.len(),
                unspent_outpoints: outpoints,
                vulnerable_script: script.to_lowercase(),
                vulnerability_class: class,
                proof_witness: serde_json::from_str(&proof_json)?,
                execution_trace: serde_json::from_str(&trace_json)?,
                first_revealed_txid: first_txid,
                detection_status: detection_status.clone(),
                consensus_status,
                policy_status,
                validator,
                validation_details,
                confidence: if detection_status == "confirmed_weak" {
                    "bitcoin_core_validated"
                } else {
                    "consensus_commitment_verified_candidate"
                }
                .to_owned(),
                limitations: serde_json::from_str(&limitations_json)?,
            });
        }

        Ok(RiskReport {
            generated_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            scanner_status: self.status()?,
            risks,
        })
    }
}

impl OutPoint {
    fn parse(txid: &str, vout: u32) -> Result<Self> {
        let bytes = hex::decode(txid).context("decode txid")?;
        let txid = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("txid is not 32 bytes"))?;
        Ok(Self { txid, vout })
    }
}

fn prune_spent_reorg_state(
    tx: &Transaction<'_>,
    height: u64,
    retention_blocks: u64,
    start_height: u64,
) -> Result<()> {
    let Some(cutoff) = height.checked_sub(retention_blocks) else {
        return Ok(());
    };
    tx.execute(
        "DELETE FROM p2tr_outputs
         WHERE spent_height IS NOT NULL AND spent_height <= ?1",
        [cutoff],
    )?;
    let proposed_oldest = cutoff.saturating_add(1).max(start_height);
    let current_oldest = get_meta_tx(tx, "oldest_reorg_safe_height")?
        .map(|value| {
            value
                .parse::<u64>()
                .context("metadata key oldest_reorg_safe_height is invalid")
        })
        .transpose()?
        .unwrap_or(start_height);
    if proposed_oldest > current_oldest {
        set_meta_tx(tx, "oldest_reorg_safe_height", &proposed_oldest.to_string())?;
    }
    Ok(())
}

fn compact_no_proof_evidence(tx: &Transaction<'_>, tapleaf_id: i64) -> Result<()> {
    tx.execute(
        "UPDATE tapleaves
         SET script=X'', merkle_path_json='[]', evidence_retained=0
         WHERE id=?1",
        [tapleaf_id],
    )?;
    tx.execute(
        "UPDATE revelation_events
         SET observed_witness_json='[]', annex_hex=NULL
         WHERE tapleaf_id=?1",
        [tapleaf_id],
    )?;
    Ok(())
}

fn ensure_column(conn: &Connection, table: &str, column: &str, definition: &str) -> Result<()> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    for existing in columns {
        if existing? == column {
            return Ok(());
        }
    }
    conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    )?;
    Ok(())
}

fn set_meta(conn: &Connection, key: &str, value: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO metadata(key,value) VALUES (?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn detection_status_for_analysis(status: AnalysisStatus) -> DetectionStatus {
    match status {
        AnalysisStatus::Weak => DetectionStatus::CandidateWeak,
        AnalysisStatus::NoProofFound => DetectionStatus::NoProofFound,
        AnalysisStatus::Inconclusive => DetectionStatus::Inconclusive,
        AnalysisStatus::InvalidScript => DetectionStatus::InvalidScript,
    }
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn set_meta_tx(tx: &Transaction<'_>, key: &str, value: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES (?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn get_meta(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM metadata WHERE key=?1", [key], |row| {
            row.get(0)
        })
        .optional()?)
}

fn get_meta_tx(tx: &Transaction<'_>, key: &str) -> Result<Option<String>> {
    Ok(tx
        .query_row("SELECT value FROM metadata WHERE key=?1", [key], |row| {
            row.get(0)
        })
        .optional()?)
}

fn parse_meta<T>(conn: &Connection, key: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    get_meta(conn, key)?
        .with_context(|| format!("metadata key {key} is missing"))?
        .parse()
        .with_context(|| format!("metadata key {key} is invalid"))
}

fn parse_meta_tx<T>(tx: &Transaction<'_>, key: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::error::Error + Send + Sync + 'static,
{
    get_meta_tx(tx, key)?
        .with_context(|| format!("metadata key {key} is missing"))?
        .parse()
        .with_context(|| format!("metadata key {key} is invalid"))
}

fn optional_meta_u64(conn: &Connection, key: &str) -> Result<Option<u64>> {
    get_meta(conn, key)?
        .map(|value| {
            value
                .parse::<u64>()
                .with_context(|| format!("metadata key {key} is invalid"))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use tempfile::NamedTempFile;

    use crate::{
        rpc::{BtcAmount, ScriptPubKey, Transaction as RpcTransaction, TxIn, TxOut},
        taproot::single_leaf_commitment,
    };

    use super::*;

    #[test]
    fn initializes_and_reopens_scan_state() {
        let file = NamedTempFile::new().unwrap();
        let mut db = Database::open(file.path()).unwrap();
        let state = db.prepare_scan("regtest", 0, 100, 0, 144).unwrap();
        assert_eq!(state.next_height, 0);
        drop(db);

        let db = Database::open(file.path()).unwrap();
        let state = db.scan_state().unwrap().unwrap();
        assert_eq!(state.chain, "regtest");
        assert_eq!(state.target_height, 100);
    }

    #[test]
    fn disk_guard_can_stop_before_database_writes() {
        let file = NamedTempFile::new().unwrap();
        let db = Database::open(file.path()).unwrap();

        db.ensure_min_free_space(0).unwrap();
        let error = db.ensure_min_free_space(u64::MAX).unwrap_err().to_string();

        assert!(error.contains("disk guard stopped the scan"));
    }

    #[test]
    fn p2tr_index_guard_checks_count_before_allocating_the_index() {
        let file = NamedTempFile::new().unwrap();
        let db = Database::open(file.path()).unwrap();
        for vout in 0..2 {
            db.conn
                .execute(
                    "INSERT INTO p2tr_outputs(
                        txid, vout, output_key, value_sats,
                        created_height, created_block_hash
                     ) VALUES (?1, ?2, ?3, 1, 0, ?4)",
                    params!["70".repeat(32), vout, [1u8; 32].as_slice(), "71".repeat(32)],
                )
                .unwrap();
        }

        let error = db.load_unspent_index(1).unwrap_err().to_string();

        assert!(error.contains("P2TR memory guard stopped the scan"));
        assert_eq!(db.load_unspent_index(0).unwrap().len(), 2);
    }

    #[test]
    fn prunes_old_spent_outputs_and_refuses_an_unsafe_deep_rollback() {
        let file = NamedTempFile::new().unwrap();
        let mut db = Database::open(file.path()).unwrap();
        db.prepare_scan("regtest", 0, 2, 0, 1).unwrap();
        let mut index = HashMap::new();
        let funding_txid = "10".repeat(32);
        let output_key = "11".repeat(32);
        let block0 = Block {
            hash: "20".repeat(32),
            height: 0,
            previousblockhash: None,
            tx: vec![RpcTransaction {
                txid: funding_txid.clone(),
                vin: vec![TxIn {
                    txid: None,
                    vout: None,
                    coinbase: Some("00".to_owned()),
                    txinwitness: vec![],
                }],
                vout: vec![TxOut {
                    value: BtcAmount(1_000),
                    n: 0,
                    script_pub_key: ScriptPubKey {
                        hex: format!("5120{output_key}"),
                    },
                }],
            }],
        };
        db.commit_block(&block0, 0, 4, 1, &mut index, None).unwrap();
        let block1 = Block {
            hash: "21".repeat(32),
            height: 1,
            previousblockhash: Some(block0.hash.clone()),
            tx: vec![RpcTransaction {
                txid: "12".repeat(32),
                vin: vec![TxIn {
                    txid: Some(funding_txid),
                    vout: Some(0),
                    coinbase: None,
                    txinwitness: vec![],
                }],
                vout: vec![],
            }],
        };
        db.commit_block(&block1, 0, 4, 1, &mut index, None).unwrap();
        let block2 = Block {
            hash: "22".repeat(32),
            height: 2,
            previousblockhash: Some(block1.hash.clone()),
            tx: vec![],
        };
        db.commit_block(&block2, 0, 4, 1, &mut index, None).unwrap();

        let stored_outputs: u64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM p2tr_outputs", [], |row| row.get(0))
            .unwrap();
        assert_eq!(stored_outputs, 0);
        assert_eq!(db.status().unwrap().oldest_reorg_safe_height, Some(2));

        assert_eq!(db.rollback_tip().unwrap(), Some(2));
        let error = db.rollback_tip().unwrap_err().to_string();
        assert!(error.contains("compact storage only retains rollback state"));
        assert_eq!(db.status().unwrap().scanned_blocks, 2);
    }

    #[test]
    fn no_proof_found_keeps_summary_but_compacts_large_evidence() {
        let file = NamedTempFile::new().unwrap();
        let mut db = Database::open(file.path()).unwrap();
        db.prepare_scan("regtest", 0, 1, 0, 144).unwrap();
        let mut index = HashMap::new();
        let script = [vec![0x20], vec![0x02; 32], vec![0xac], vec![0x61; 8_000]].concat();
        let commitment = single_leaf_commitment(&script).unwrap();
        let funding_txid = "31".repeat(32);
        let block0 = Block {
            hash: "40".repeat(32),
            height: 0,
            previousblockhash: None,
            tx: vec![RpcTransaction {
                txid: funding_txid.clone(),
                vin: vec![],
                vout: vec![TxOut {
                    value: BtcAmount(1_000),
                    n: 0,
                    script_pub_key: ScriptPubKey {
                        hex: format!("5120{}", hex::encode(commitment.output_key)),
                    },
                }],
            }],
        };
        db.commit_block(&block0, 0, 4, 144, &mut index, None)
            .unwrap();
        let block1 = Block {
            hash: "41".repeat(32),
            height: 1,
            previousblockhash: Some(block0.hash.clone()),
            tx: vec![RpcTransaction {
                txid: "32".repeat(32),
                vin: vec![TxIn {
                    txid: Some(funding_txid),
                    vout: Some(0),
                    coinbase: None,
                    txinwitness: vec![
                        "00".repeat(8_000),
                        hex::encode(&script),
                        hex::encode(commitment.control_block),
                    ],
                }],
                vout: vec![],
            }],
        };

        let counts = db
            .commit_block(&block1, 0, 4, 144, &mut index, None)
            .unwrap();

        assert_eq!(counts.no_proof_found_scripts, 1);
        let stored: (u64, u64, bool, String, String) = db
            .conn
            .query_row(
                "SELECT
                    LENGTH(l.script), l.script_size, l.evidence_retained,
                    l.merkle_path_json, e.observed_witness_json
                 FROM tapleaves l
                 JOIN revelation_events e ON e.tapleaf_id=l.id",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(stored.0, 0);
        assert_eq!(stored.1, script.len() as u64);
        assert!(!stored.2);
        assert_eq!(stored.3, "[]");
        assert_eq!(stored.4, "[]");
    }

    #[test]
    fn candidate_weak_leaf_matches_later_unspent_output_key() {
        let file = NamedTempFile::new().unwrap();
        let mut db = Database::open(file.path()).unwrap();
        db.prepare_scan("main", 709_632, 709_634, 709_632, 144)
            .unwrap();
        let mut index = HashMap::new();
        let funding_txid = "11".repeat(32);
        let output_key = "f1f9462868873c84f8a475307a26116f5f74c1caa5d7458f418ed97a399bc5b4";
        let block1 = Block {
            hash: "a1".repeat(32),
            height: 709_632,
            previousblockhash: Some("00".repeat(32)),
            tx: vec![RpcTransaction {
                txid: funding_txid.clone(),
                vin: vec![TxIn {
                    txid: None,
                    vout: None,
                    coinbase: Some("00".to_owned()),
                    txinwitness: vec![],
                }],
                vout: vec![TxOut {
                    value: BtcAmount(10_000),
                    n: 0,
                    script_pub_key: ScriptPubKey {
                        hex: format!("5120{output_key}"),
                    },
                }],
            }],
        };
        db.commit_block(&block1, 709_632, 4, 144, &mut index, None)
            .unwrap();

        let script = concat!(
            "20",
            "fa9b5ec193f735c41b804fc6ace1d28e81a299fc815c0f5009dd2dd7d0293c3b",
            "ac63",
            "20",
            "ff1275b635cd160914cfe1bc516f521abde0fc8ae3fd92ae01ca16449e4758e9",
            "68"
        );
        let block2 = Block {
            hash: "a2".repeat(32),
            height: 709_633,
            previousblockhash: Some(block1.hash.clone()),
            tx: vec![RpcTransaction {
                txid: "22".repeat(32),
                vin: vec![TxIn {
                    txid: Some(funding_txid),
                    vout: Some(0),
                    coinbase: None,
                    txinwitness: vec![
                        "51".to_owned(),
                        String::new(),
                        script.to_owned(),
                        "c0fa9b5ec193f735c41b804fc6ace1d28e81a299fc815c0f5009dd2dd7d0293c3b"
                            .to_owned(),
                    ],
                }],
                vout: vec![],
            }],
        };
        let block2_counts = db
            .commit_block(&block2, 709_632, 4, 144, &mut index, None)
            .unwrap();
        assert_eq!(block2_counts.analyzed_scripts, 1);
        assert_eq!(block2_counts.candidate_weak_scripts, 1);
        assert_eq!(block2_counts.confirmed_weak_scripts, 0);
        let retained: (u64, bool, String) = db
            .conn
            .query_row(
                "SELECT
                    LENGTH(l.script), l.evidence_retained, e.observed_witness_json
                 FROM tapleaves l
                 JOIN revelation_events e ON e.tapleaf_id=l.id",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert!(retained.0 > 0);
        assert!(retained.1);
        assert_ne!(retained.2, "[]");
        assert!(db.report().unwrap().risks.is_empty());

        let sticky_prev_txid = "55".repeat(32);
        assert!(matches!(
            analyze_script(&hex::decode(script).unwrap(), 1).status,
            AnalysisStatus::NoProofFound
        ));
        index.insert(
            OutPoint::parse(&sticky_prev_txid, 0).unwrap(),
            P2trPrevout {
                output_key: hex::decode(output_key).unwrap().try_into().unwrap(),
            },
        );
        let block3 = Block {
            hash: "a3".repeat(32),
            height: 709_634,
            previousblockhash: Some(block2.hash.clone()),
            tx: vec![
                RpcTransaction {
                    txid: "66".repeat(32),
                    vin: vec![TxIn {
                        txid: Some(sticky_prev_txid),
                        vout: Some(0),
                        coinbase: None,
                        txinwitness: vec![
                            "51".to_owned(),
                            String::new(),
                            script.to_owned(),
                            "c0fa9b5ec193f735c41b804fc6ace1d28e81a299fc815c0f5009dd2dd7d0293c3b"
                                .to_owned(),
                        ],
                    }],
                    vout: vec![],
                },
                RpcTransaction {
                    txid: "33".repeat(32),
                    vin: vec![TxIn {
                        txid: None,
                        vout: None,
                        coinbase: Some("00".to_owned()),
                        txinwitness: vec![],
                    }],
                    vout: vec![TxOut {
                        value: BtcAmount(25_000),
                        n: 1,
                        script_pub_key: ScriptPubKey {
                            hex: format!("5120{output_key}"),
                        },
                    }],
                },
            ],
        };
        let sticky_counts = db
            .commit_block(&block3, 709_632, 1, 144, &mut index, None)
            .unwrap();
        assert_eq!(sticky_counts.candidate_weak_scripts, 1);
        assert_eq!(sticky_counts.no_proof_found_scripts, 0);
        let sticky_config: String = db
            .conn
            .query_row("SELECT search_config_json FROM analysis_runs", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert!(sticky_config.contains("\"requested_max_witness_items\":4"));
        let report = db.report().unwrap();
        assert_eq!(report.risks.len(), 1);
        assert_eq!(report.risks[0].current_balance_sats, 25_000);
        assert_eq!(report.risks[0].proof_witness, vec!["01", ""]);
        assert_eq!(report.risks[0].detection_status, "candidate_weak");
        assert_eq!(report.risks[0].consensus_status, "not_checked");

        db.conn
            .execute(
                "UPDATE analysis_runs SET
                    detection_status='confirmed_weak',
                    consensus_status='confirmed_valid',
                    policy_status='accepted',
                    validator='test-validator'
                 WHERE tapleaf_id=(SELECT id FROM tapleaves LIMIT 1)",
                [],
            )
            .unwrap();
        let block4 = Block {
            hash: "a4".repeat(32),
            height: 709_635,
            previousblockhash: Some(block3.hash),
            tx: vec![RpcTransaction {
                txid: "44".repeat(32),
                vin: vec![TxIn {
                    txid: Some("33".repeat(32)),
                    vout: Some(1),
                    coinbase: None,
                    txinwitness: vec![
                        "51".to_owned(),
                        String::new(),
                        script.to_owned(),
                        "c0fa9b5ec193f735c41b804fc6ace1d28e81a299fc815c0f5009dd2dd7d0293c3b"
                            .to_owned(),
                    ],
                }],
                vout: vec![TxOut {
                    value: BtcAmount(20_000),
                    n: 0,
                    script_pub_key: ScriptPubKey {
                        hex: format!("5120{output_key}"),
                    },
                }],
            }],
        };
        let block4_counts = db
            .commit_block(&block4, 709_632, 4, 144, &mut index, None)
            .unwrap();
        assert_eq!(block4_counts.candidate_weak_scripts, 0);
        assert_eq!(block4_counts.confirmed_weak_scripts, 1);
        let report = db.report().unwrap();
        assert_eq!(report.risks[0].detection_status, "confirmed_weak");
        assert_eq!(report.risks[0].validator, "test-validator");
    }
}
