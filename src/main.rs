// Clippy 1.88 reports a false-positive formatting-literal warning at the
// `detection` module declaration while checking the serde-derived test target.
#![allow(clippy::literal_string_with_formatting_args)]

mod analyzer;
mod core_validator;
mod db;
mod detection;
mod progress;
mod rpc;
mod scanner;
mod taproot;

use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::{
    analyzer::{AnalysisStatus, analyze_script},
    core_validator::CoreRegtestValidator,
    db::Database,
    detection::{CandidateValidator, ValidationEvidence},
    progress::ProgressMode,
    rpc::{Auth, RpcClient, RpcOptions},
    scanner::{ScanConfig, Scanner},
};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[arg(long, default_value = "tapscript-audit.sqlite", global = true)]
    db: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan blocks in canonical order. Existing progress is resumed automatically.
    Scan(ScanArgs),
    /// Show the durable scanner checkpoint and accumulated counts.
    Status,
    /// Export current confirmed matches as JSON.
    Report(ReportArgs),
    /// Analyze one raw TapScript locally, with optional isolated Core validation.
    AnalyzeScript(AnalyzeScriptArgs),
}

#[derive(Args, Debug)]
struct ScanArgs {
    #[arg(long, env = "BITCOIN_RPC_URL", default_value = "http://127.0.0.1:8332")]
    rpc_url: String,

    #[arg(long, env = "BITCOIN_RPC_COOKIE")]
    rpc_cookie: Option<PathBuf>,

    #[arg(long, env = "BITCOIN_RPC_USER", requires = "rpc_password")]
    rpc_user: Option<String>,

    #[arg(long, env = "BITCOIN_RPC_PASSWORD", requires = "rpc_user")]
    rpc_password: Option<String>,

    /// Per-request HTTP timeout.
    #[arg(long, env = "BITCOIN_RPC_TIMEOUT_SECS", default_value_t = 180)]
    rpc_timeout_secs: u64,

    /// Retries after transient transport, 408/429/5xx, warmup, or decode failures.
    #[arg(long, env = "BITCOIN_RPC_MAX_RETRIES", default_value_t = 5)]
    rpc_max_retries: u32,

    /// Initial exponential retry delay.
    #[arg(long, env = "BITCOIN_RPC_RETRY_INITIAL_MS", default_value_t = 1_000)]
    rpc_retry_initial_ms: u64,

    /// Maximum retry delay, including a server Retry-After value.
    #[arg(long, env = "BITCOIN_RPC_RETRY_MAX_MS", default_value_t = 30_000)]
    rpc_retry_max_ms: u64,

    /// Maximum RPC response-body size used as an input-memory guard.
    #[arg(long, env = "BITCOIN_RPC_MAX_RESPONSE_MIB", default_value_t = 64)]
    rpc_max_response_mib: u64,

    /// Defaults to zero so the local P2TR UTXO view is complete.
    #[arg(long, default_value_t = 0)]
    start_height: u64,

    /// Pin the initial run to a height. By default the current node tip is used.
    #[arg(long)]
    end_height: Option<u64>,

    /// Override the network's known Taproot activation height.
    #[arg(long)]
    taproot_activation_height: Option<u64>,

    /// Print one result for every committed block. `--progress` is retained as an alias.
    #[arg(long, visible_alias = "progress", value_enum, default_value_t = OutputArg::Text)]
    output: OutputArg,

    #[arg(long, default_value_t = 4)]
    max_witness_items: usize,

    /// Keep spent P2TR rows only for this many recent blocks of reorg rollback.
    #[arg(long, default_value_t = 144)]
    reorg_retention_blocks: u64,

    /// Stop before fetching or committing a block when less disk is available.
    #[arg(long, env = "TAPSCRIPT_MIN_FREE_DISK_MIB", default_value_t = 1_024)]
    min_free_disk_mib: u64,

    /// Stop when the in-memory unspent P2TR index exceeds this entry count.
    #[arg(
        long,
        env = "TAPSCRIPT_MAX_IN_MEMORY_P2TR_UTXOS",
        default_value_t = 1_000_000
    )]
    max_in_memory_p2tr_utxos: usize,

    /// Validate candidates using a fresh, isolated Bitcoin Core regtest node.
    #[arg(long, default_value_t = false)]
    verify_with_bitcoin_core: bool,

    /// Bitcoin Core executable used only for isolated regtest validation.
    #[arg(long, default_value = "bitcoind")]
    bitcoind: PathBuf,
}

#[derive(Args, Debug)]
struct AnalyzeScriptArgs {
    #[arg(long)]
    script_hex: String,

    #[arg(long, default_value_t = 4)]
    max_witness_items: usize,

    /// Validate a candidate using a fresh, isolated Bitcoin Core regtest node.
    #[arg(long, default_value_t = false)]
    verify_with_bitcoin_core: bool,

    /// Bitcoin Core executable used only for isolated regtest validation.
    #[arg(long, default_value = "bitcoind")]
    bitcoind: PathBuf,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputArg {
    Text,
    Json,
    None,
}

impl From<OutputArg> for ProgressMode {
    fn from(value: OutputArg) -> Self {
        match value {
            OutputArg::Text => Self::Text,
            OutputArg::Json => Self::Json,
            OutputArg::None => Self::None,
        }
    }
}

#[derive(Args, Debug)]
struct ReportArgs {
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    pretty: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut db = Database::open(&cli.db)?;

    match cli.command {
        Command::Scan(args) => {
            let auth = match (args.rpc_cookie, args.rpc_user, args.rpc_password) {
                (Some(path), None, None) => Auth::CookieFile(path),
                (None, Some(user), Some(password)) => Auth::UserPassword { user, password },
                (None, None, None) => Auth::None,
                _ => anyhow::bail!("use either --rpc-cookie or --rpc-user/--rpc-password"),
            };
            let rpc = RpcClient::with_options(args.rpc_url, auth, RpcOptions {
                timeout: Duration::from_secs(args.rpc_timeout_secs),
                max_retries: args.rpc_max_retries,
                retry_initial_delay: Duration::from_millis(args.rpc_retry_initial_ms),
                retry_max_delay: Duration::from_millis(args.rpc_retry_max_ms),
                max_response_bytes: mib_to_bytes(
                    args.rpc_max_response_mib,
                    "RPC maximum response",
                )?,
            })?;
            let config = ScanConfig {
                requested_start_height: args.start_height,
                requested_end_height: args.end_height,
                taproot_activation_height: args.taproot_activation_height,
                progress_mode: args.output.into(),
                max_witness_items: args.max_witness_items,
                reorg_retention_blocks: args.reorg_retention_blocks,
                min_free_disk_bytes: mib_to_bytes(args.min_free_disk_mib, "minimum free disk")?,
                max_in_memory_p2tr_utxos: args.max_in_memory_p2tr_utxos,
            };
            let scanner = Scanner::new(rpc, &mut db, config);
            if args.verify_with_bitcoin_core {
                scanner
                    .with_validator(Box::new(CoreRegtestValidator::start(&args.bitcoind)?))
                    .run()
            } else {
                scanner.run()
            }
        }
        Command::Status => {
            println!("{}", serde_json::to_string_pretty(&db.status()?)?);
            Ok(())
        }
        Command::Report(args) => {
            let report = db.report()?;
            let bytes = if args.pretty {
                serde_json::to_vec_pretty(&report)?
            } else {
                serde_json::to_vec(&report)?
            };
            if let Some(path) = args.output {
                std::fs::write(path, bytes)?;
            } else {
                println!("{}", String::from_utf8(bytes)?);
            }
            Ok(())
        }
        Command::AnalyzeScript(args) => {
            let script = hex::decode(args.script_hex)?;
            let analysis = analyze_script(&script, args.max_witness_items);
            let validation = if args.verify_with_bitcoin_core
                && matches!(analysis.status, AnalysisStatus::Weak)
            {
                let proof = analysis
                    .proof_witness
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .map(hex::decode)
                    .collect::<Result<Vec<_>, _>>()?;
                let mut validator = CoreRegtestValidator::start(&args.bitcoind)?;
                Some(validator.validate(&script, &proof).unwrap_or_else(|error| {
                    ValidationEvidence::validation_failed(validator.name(), &error)
                }))
            } else if matches!(analysis.status, AnalysisStatus::Weak) {
                Some(ValidationEvidence::candidate_without_authoritative_validation())
            } else {
                None
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "analysis": analysis,
                    "validation": validation,
                }))?
            );
            Ok(())
        }
    }
}

fn mib_to_bytes(value: u64, name: &str) -> Result<u64> {
    value
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("{name} value is too large"))
}
