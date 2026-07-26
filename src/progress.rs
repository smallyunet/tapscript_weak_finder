use std::time::{Duration, Instant};

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
    interval: Duration,
    last_emit: Instant,
    started: Instant,
    start_height: u64,
    target_height: u64,
    current_height: u64,
    transactions: u64,
    inputs: u64,
    outputs: u64,
    script_paths: u64,
    weak_scripts: u64,
}

#[derive(Serialize)]
struct JsonProgress {
    stage: &'static str,
    current_height: u64,
    target_height: u64,
    completed_blocks_this_run: u64,
    percent: f64,
    blocks_per_second: f64,
    eta_seconds: Option<u64>,
    transactions: u64,
    inputs: u64,
    outputs: u64,
    revealed_script_paths: u64,
    weak_scripts: u64,
}

impl ProgressReporter {
    pub fn new(
        mode: ProgressMode,
        interval_secs: u64,
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
        Self {
            mode,
            bar,
            interval: Duration::from_secs(interval_secs.max(1)),
            last_emit: Instant::now()
                .checked_sub(Duration::from_secs(interval_secs.max(1)))
                .unwrap_or_else(Instant::now),
            started: Instant::now(),
            start_height: next_height,
            target_height,
            current_height: next_height.saturating_sub(1),
            transactions: status.scanned_transactions,
            inputs: status.scanned_inputs,
            outputs: status.scanned_outputs,
            script_paths: status.revealed_script_paths,
            weak_scripts: status.weak_scripts,
        }
    }

    pub fn block_committed(&mut self, height: u64, counts: BlockCounts) {
        self.current_height = height;
        self.transactions += counts.transactions;
        self.inputs += counts.inputs;
        self.outputs += counts.outputs;
        self.script_paths += counts.script_paths;
        self.weak_scripts += counts.weak_scripts;
        if let Some(bar) = &self.bar {
            bar.inc(1);
        }
        if self.last_emit.elapsed() >= self.interval || height == self.target_height {
            self.emit();
            self.last_emit = Instant::now();
        }
    }

    fn snapshot(&self) -> JsonProgress {
        let completed = self
            .current_height
            .saturating_add(1)
            .saturating_sub(self.start_height);
        let run_total = self
            .target_height
            .saturating_add(1)
            .saturating_sub(self.start_height);
        let elapsed = self.started.elapsed().as_secs_f64();
        let rate = if elapsed > 0.0 {
            completed as f64 / elapsed
        } else {
            0.0
        };
        let remaining = self.target_height.saturating_sub(self.current_height);
        JsonProgress {
            stage: "block_scan",
            current_height: self.current_height,
            target_height: self.target_height,
            completed_blocks_this_run: completed,
            percent: if run_total == 0 {
                100.0
            } else {
                completed as f64 * 100.0 / run_total as f64
            },
            blocks_per_second: rate,
            eta_seconds: (rate > 0.0).then(|| (remaining as f64 / rate) as u64),
            transactions: self.transactions,
            inputs: self.inputs,
            outputs: self.outputs,
            revealed_script_paths: self.script_paths,
            weak_scripts: self.weak_scripts,
        }
    }

    fn emit(&self) {
        let snapshot = self.snapshot();
        match self.mode {
            ProgressMode::Text => {
                if let Some(bar) = &self.bar {
                    let eta = snapshot
                        .eta_seconds
                        .map(format_duration)
                        .unwrap_or_else(|| "--".to_owned());
                    bar.set_message(format!(
                        "h={} tx={} in={} out={} leaves={} weak={} {:.2} blk/s ETA {}",
                        snapshot.current_height,
                        snapshot.transactions,
                        snapshot.inputs,
                        snapshot.outputs,
                        snapshot.revealed_script_paths,
                        snapshot.weak_scripts,
                        snapshot.blocks_per_second,
                        eta,
                    ));
                }
            }
            ProgressMode::Json => {
                if let Ok(line) = serde_json::to_string(&snapshot) {
                    println!("{line}");
                }
            }
            ProgressMode::None => {}
        }
    }

    pub fn finish(&self, interrupted: bool) {
        if let Some(bar) = &self.bar {
            if interrupted {
                bar.abandon_with_message("interrupted after last committed block; safe to resume");
            } else {
                bar.finish_with_message("scan complete");
            }
        }
    }
}

fn format_duration(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}
