use std::time::Instant;

use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;

use crate::db::{BlockCounts, Status};

#[derive(Clone, Copy, Debug)]
pub enum ProgressMode {
    Text,
    Json,
    None,
}

pub struct ProgressReporter {
    mode: ProgressMode,
    bar: Option<ProgressBar>,
    started: Instant,
    start_height: u64,
    target_height: u64,
    current_height: Option<u64>,
    totals: BlockCounts,
}

#[derive(Debug, Serialize)]
struct ScanStarted<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    chain: Option<&'a str>,
    start_height: u64,
    target_height: u64,
    resumed: bool,
}

#[derive(Debug, Serialize)]
struct BlockResult<'a> {
    #[serde(rename = "type")]
    event_type: &'static str,
    height: u64,
    block_hash: &'a str,
    transactions: u64,
    inputs: u64,
    outputs: u64,
    p2tr_created: u64,
    p2tr_spent: u64,
    revealed_script_paths: u64,
    analyzed_scripts: u64,
    analyzer_weak_scripts: u64,
    confirmed_weak_scripts: u64,
    candidate_weak_scripts: u64,
    no_proof_found_scripts: u64,
    inconclusive_scripts: u64,
    invalid_script_scripts: u64,
    block_elapsed_ms: u128,
    scan_elapsed_ms: u128,
}

#[derive(Debug, Serialize)]
struct ScanSummary {
    #[serde(rename = "type")]
    event_type: &'static str,
    interrupted: bool,
    start_height: u64,
    last_committed_height: Option<u64>,
    target_height: u64,
    completed_blocks: u64,
    transactions: u64,
    inputs: u64,
    outputs: u64,
    p2tr_created: u64,
    p2tr_spent: u64,
    revealed_script_paths: u64,
    analyzed_scripts: u64,
    analyzer_weak_scripts: u64,
    confirmed_weak_scripts: u64,
    candidate_weak_scripts: u64,
    no_proof_found_scripts: u64,
    inconclusive_scripts: u64,
    invalid_script_scripts: u64,
    elapsed_ms: u128,
}

impl ProgressReporter {
    pub fn new(
        mode: ProgressMode,
        state_start_height: u64,
        next_height: u64,
        target_height: u64,
        status: &Status,
    ) -> Self {
        let total = target_height.saturating_sub(state_start_height) + 1;
        let completed = next_height.saturating_sub(state_start_height);
        let bar = match mode {
            ProgressMode::Text => {
                let bar = ProgressBar::new(total);
                bar.set_position(completed.min(total));
                bar.set_style(
                    ProgressStyle::with_template(
                        "{spinner:.cyan} [{elapsed_precise}] [{bar:36.cyan/blue}] \
                         {pos}/{len} {percent}% {msg}",
                    )
                    .expect("static progress template")
                    .progress_chars("=>-"),
                );
                Some(bar)
            }
            _ => None,
        };
        let reporter = Self {
            mode,
            bar,
            started: Instant::now(),
            start_height: next_height,
            target_height,
            current_height: None,
            totals: BlockCounts::default(),
        };
        reporter.emit_started(status.chain.as_deref(), next_height > state_start_height);
        reporter
    }

    pub fn block_committed(
        &mut self,
        height: u64,
        block_hash: &str,
        counts: BlockCounts,
        block_elapsed_ms: u128,
    ) {
        self.current_height = Some(height);
        add_counts(&mut self.totals, counts);
        if let Some(bar) = &self.bar {
            bar.inc(1);
        }
        let event = BlockResult {
            event_type: "block_result",
            height,
            block_hash,
            transactions: counts.transactions,
            inputs: counts.inputs,
            outputs: counts.outputs,
            p2tr_created: counts.p2tr_created,
            p2tr_spent: counts.p2tr_spent,
            revealed_script_paths: counts.script_paths,
            analyzed_scripts: counts.analyzed_scripts,
            analyzer_weak_scripts: counts.weak_scripts,
            confirmed_weak_scripts: counts.confirmed_weak_scripts,
            candidate_weak_scripts: counts.candidate_weak_scripts,
            no_proof_found_scripts: counts.no_proof_found_scripts,
            inconclusive_scripts: counts.inconclusive_scripts,
            invalid_script_scripts: counts.invalid_script_scripts,
            block_elapsed_ms,
            scan_elapsed_ms: self.started.elapsed().as_millis(),
        };
        self.emit_block(&event);
    }

    pub fn finish(&self, interrupted: bool) {
        let summary = self.summary(interrupted);
        match self.mode {
            ProgressMode::Text => {
                if let Some(bar) = &self.bar {
                    if interrupted {
                        bar.abandon_with_message(
                            "interrupted after last committed block; safe to resume",
                        );
                    } else {
                        bar.finish_with_message("scan complete");
                    }
                }
                println!(
                    "summary blocks={} tx={} leaves={} analyzed={} candidate={} confirmed={} \
                     inconclusive={} interrupted={}",
                    summary.completed_blocks,
                    summary.transactions,
                    summary.revealed_script_paths,
                    summary.analyzed_scripts,
                    summary.candidate_weak_scripts,
                    summary.confirmed_weak_scripts,
                    summary.inconclusive_scripts,
                    summary.interrupted,
                );
            }
            ProgressMode::Json => print_json(&summary),
            ProgressMode::None => {}
        }
    }

    fn emit_started(&self, chain: Option<&str>, resumed: bool) {
        let event = ScanStarted {
            event_type: "scan_started",
            chain,
            start_height: self.start_height,
            target_height: self.target_height,
            resumed,
        };
        match self.mode {
            ProgressMode::Text => {
                println!(
                    "scan_started chain={} start={} target={} resumed={resumed}",
                    chain.unwrap_or("unknown"),
                    self.start_height,
                    self.target_height,
                );
            }
            ProgressMode::Json => print_json(&event),
            ProgressMode::None => {}
        }
    }

    fn emit_block(&self, event: &BlockResult<'_>) {
        match self.mode {
            ProgressMode::Text => {
                println!(
                    "block={} hash={} tx={} in={} out={} p2tr_created={} p2tr_spent={} \
                     script_paths={} analyzed={} candidate={} confirmed={} no_proof={} \
                     inconclusive={} invalid={}",
                    event.height,
                    event.block_hash,
                    event.transactions,
                    event.inputs,
                    event.outputs,
                    event.p2tr_created,
                    event.p2tr_spent,
                    event.revealed_script_paths,
                    event.analyzed_scripts,
                    event.candidate_weak_scripts,
                    event.confirmed_weak_scripts,
                    event.no_proof_found_scripts,
                    event.inconclusive_scripts,
                    event.invalid_script_scripts,
                );
                if let Some(bar) = &self.bar {
                    bar.set_message(format!(
                        "h={} analyzed={} candidate={} confirmed={}",
                        event.height,
                        self.totals.analyzed_scripts,
                        self.totals.candidate_weak_scripts,
                        self.totals.confirmed_weak_scripts,
                    ));
                }
            }
            ProgressMode::Json => print_json(event),
            ProgressMode::None => {}
        }
    }

    fn summary(&self, interrupted: bool) -> ScanSummary {
        ScanSummary {
            event_type: "scan_summary",
            interrupted,
            start_height: self.start_height,
            last_committed_height: self.current_height,
            target_height: self.target_height,
            completed_blocks: self
                .current_height
                .map_or(0, |height| height.saturating_sub(self.start_height) + 1),
            transactions: self.totals.transactions,
            inputs: self.totals.inputs,
            outputs: self.totals.outputs,
            p2tr_created: self.totals.p2tr_created,
            p2tr_spent: self.totals.p2tr_spent,
            revealed_script_paths: self.totals.script_paths,
            analyzed_scripts: self.totals.analyzed_scripts,
            analyzer_weak_scripts: self.totals.weak_scripts,
            confirmed_weak_scripts: self.totals.confirmed_weak_scripts,
            candidate_weak_scripts: self.totals.candidate_weak_scripts,
            no_proof_found_scripts: self.totals.no_proof_found_scripts,
            inconclusive_scripts: self.totals.inconclusive_scripts,
            invalid_script_scripts: self.totals.invalid_script_scripts,
            elapsed_ms: self.started.elapsed().as_millis(),
        }
    }
}

fn add_counts(total: &mut BlockCounts, value: BlockCounts) {
    total.transactions += value.transactions;
    total.inputs += value.inputs;
    total.outputs += value.outputs;
    total.p2tr_created += value.p2tr_created;
    total.p2tr_spent += value.p2tr_spent;
    total.script_paths += value.script_paths;
    total.analyzed_scripts += value.analyzed_scripts;
    total.weak_scripts += value.weak_scripts;
    total.confirmed_weak_scripts += value.confirmed_weak_scripts;
    total.candidate_weak_scripts += value.candidate_weak_scripts;
    total.no_proof_found_scripts += value.no_proof_found_scripts;
    total.inconclusive_scripts += value.inconclusive_scripts;
    total.invalid_script_scripts += value.invalid_script_scripts;
}

fn print_json<T: Serialize>(value: &T) {
    if let Ok(line) = serde_json::to_string(value) {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_result_contains_only_that_blocks_counts() {
        let counts = BlockCounts {
            transactions: 12,
            script_paths: 2,
            analyzed_scripts: 2,
            candidate_weak_scripts: 1,
            confirmed_weak_scripts: 1,
            ..Default::default()
        };
        let event = BlockResult {
            event_type: "block_result",
            height: 42,
            block_hash: "abcd",
            transactions: counts.transactions,
            inputs: counts.inputs,
            outputs: counts.outputs,
            p2tr_created: counts.p2tr_created,
            p2tr_spent: counts.p2tr_spent,
            revealed_script_paths: counts.script_paths,
            analyzed_scripts: counts.analyzed_scripts,
            analyzer_weak_scripts: counts.weak_scripts,
            confirmed_weak_scripts: counts.confirmed_weak_scripts,
            candidate_weak_scripts: counts.candidate_weak_scripts,
            no_proof_found_scripts: counts.no_proof_found_scripts,
            inconclusive_scripts: counts.inconclusive_scripts,
            invalid_script_scripts: counts.invalid_script_scripts,
            block_elapsed_ms: 3,
            scan_elapsed_ms: 7,
        };
        let value = serde_json::to_value(event).unwrap();
        assert_eq!(value["type"], "block_result");
        assert_eq!(value["height"], 42);
        assert_eq!(value["candidate_weak_scripts"], 1);
        assert_eq!(value["confirmed_weak_scripts"], 1);
    }

    #[test]
    fn count_accumulation_keeps_detection_states_separate() {
        let mut total = BlockCounts::default();
        add_counts(&mut total, BlockCounts {
            analyzed_scripts: 3,
            candidate_weak_scripts: 1,
            no_proof_found_scripts: 2,
            ..Default::default()
        });
        add_counts(&mut total, BlockCounts {
            analyzed_scripts: 2,
            confirmed_weak_scripts: 1,
            inconclusive_scripts: 1,
            ..Default::default()
        });
        assert_eq!(total.analyzed_scripts, 5);
        assert_eq!(total.candidate_weak_scripts, 1);
        assert_eq!(total.confirmed_weak_scripts, 1);
        assert_eq!(total.no_proof_found_scripts, 2);
        assert_eq!(total.inconclusive_scripts, 1);
    }
}
