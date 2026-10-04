# tapscript-weak-finder

`tapscript-weak-finder` is an experimental, read-only Bitcoin Taproot audit
scanner. It looks for revealed TapScript leaves that can be satisfied without a
valid signature, records a reproducible witness and execution trace, and reports
currently unspent P2TR outputs that reuse the same Taproot output key.

> [!WARNING]
> This project is research software, not a production security oracle. A
> local `weak` result is only a candidate produced by the bounded analyzer.
> Only a synthetic equivalent accepted by Bitcoin Core on isolated regtest is
> promoted to `confirmed_weak`. A result other than `weak` does not prove that a
> script is safe.

The chain scanner never creates, signs, or broadcasts transactions on the
configured network. Optional validation creates and confirms only synthetic
fixtures in a fresh temporary regtest. Candidate spends are checked with
`testmempoolaccept` and are never broadcast. Finding a spendable output does not
establish ownership or authorize moving funds.

## Why this project exists

The project was motivated by the BitcoinTalk discussion
[“How to handle weak scripts?”](https://bitcointalk.org/index.php?topic=5588964.0).
The thread describes a revealed TapScript with this structure:

```text
<pubkey A> OP_CHECKSIG OP_IF <pubkey B> OP_ENDIF
```

The intended path appears to require a signature for `pubkey A`. However, an
empty signature makes `OP_CHECKSIG` push false, which causes `OP_IF` to skip its
body. A separate true item remains on the stack, so the script still finishes
successfully without any valid signature.

This incident raises two separate technical questions:

1. Can we mechanically prove that a revealed TapScript has a signatureless
   satisfaction path?
2. After one weak leaf is revealed, are there still-unspent outputs committing
   to the same Taproot tree?

This project is designed to investigate those questions without taking custody
of anyone's funds. See [Project background](docs/background.md) for the full
motivation and the limits imposed by Taproot privacy.

## What it does

- Connects to a non-pruned Bitcoin Core node over JSON-RPC.
- Scans canonical blocks in height order.
- Maintains a local P2TR UTXO index in SQLite.
- Detects Taproot script-path spends and verifies their control-block
  commitment against the spent output key.
- Analyzes revealed leaf-version `0xc0` TapScripts with bounded boolean,
  small-number/script-constant, and observed-signature-removal searches.
- Optionally validates candidate witnesses with Bitcoin Core in an isolated
  synthetic regtest.
- Stores full evidence for weak and abnormal results, compact summaries for
  `no_proof_found`, validation evidence, compact per-block checkpoints,
  currently unspent P2TR outputs, and only a bounded recent window of spent
  P2TR rollback state.
- Resumes after interruption and attempts to reconcile chain reorganizations.
- Exports current risks as JSON, limited to unspent outputs sharing an output
  key with a revealed candidate weak leaf.

## What it cannot do

- It cannot recover an unrevealed TapScript tree from a Taproot output key.
- It cannot find every victim whose weak leaf has never appeared on chain.
- It does not prove that `no_proof_found` means safe.
- When `testmempoolaccept` rejects a candidate, a
  `non-mandatory-script-verify-flag` reason is recorded as consensus-valid and
  `policy_rejected`. A `mandatory-script-verify-flag` reason is recorded as
  `consensus_invalid`. Any other reason leaves both consensus and policy
  inconclusive.
- It does not identify the wallet or tool that created a weak script.
- It does not determine the legal or moral owner of a spendable output.
- It does not sweep, rescue, sign, or broadcast transactions.

Taproot intentionally hides unused script paths. An unseen weak leaf becomes
discoverable only when it is revealed, when the tree construction is known from
some off-chain source, or when an already-revealed commitment is reused.

## How the design fits the problem

An exact byte-pattern matcher would reproduce the motivating incident but miss
structurally different scripts with the same property. The project therefore
separates the problem into three layers:

1. **Chain evidence** — track P2TR outputs and observe script-path revelations.
2. **Commitment verification** — prove that the revealed leaf belongs to the
   output being spent, following BIP 341.
3. **Candidate witness search** — look for a small witness that makes the
   TapScript succeed without a valid signature.

The custom analyzer exists for layer 3: ordinary script validation answers
whether one supplied witness is valid, while this project needs to generate
candidate witnesses. The analyzer is intentionally bounded and should be
treated as a search and tracing engine. Bitcoin Core is the validation authority
before a candidate is promoted.

See:

- [Architecture](docs/architecture.md)
- [Detection model and limitations](docs/detection-model.md)
- [Operations](docs/operations.md)
- [Responsible handling](docs/responsible-handling.md)

## Requirements

- Rust with Edition 2024 support
- A non-pruned Bitcoin Core node
- RPC access through a cookie file or username/password
- Enough disk, memory, and time for the requested scan range

The default scan starts at genesis so the local P2TR UTXO view is complete.
Scanning from a later height is supported, but the resulting UTXO coverage is
partial and is reported as such.

## Build

```bash
cargo build --release
```

The resulting binary is:

```text
target/release/tapscript-weak-finder
```

## Quick start

### Analyze one raw TapScript

```bash
cargo run --release -- analyze-script \
  --script-hex 51 \
  --max-witness-items 4
```

The command prints `analysis` and optional `validation` JSON. To validate a
candidate with a fresh temporary regtest:

```bash
cargo run --release -- analyze-script \
  --script-hex <hex> \
  --verify-with-bitcoin-core \
  --bitcoind /path/to/bitcoind
```

The analysis contains:

- `status`
- `vulnerability_class`
- `proof_witness`
- `proof_strategy`
- `execution_trace`
- `valid_signatures_required`
- `limitations`

The analyzer searches in this order:

1. Every combination of empty and minimally true items through the configured
   depth, capped at 12 witness items.
2. Small script numbers plus up to eight unique constants pushed by the script,
   capped at three witness items.
3. During chain scanning only, variants of the verified TapScript initial stack
   with each observed 64/65-byte signature-shaped item emptied or removed, plus
   variants that empty or remove all such items together.

The standalone `analyze-script` command has no observed transaction witness, so
its third strategy has no candidates. Each successful result names the strategy
that produced its proof. These strategies are bounded candidate generators;
Bitcoin Core validation is still required for `confirmed_weak`.

### Scan with Bitcoin Core cookie authentication

For an RPC endpoint that does not require client-side authentication:

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  scan \
  --rpc-url https://node.example.com \
  --output json
```

Most private nodes also require `--rpc-cookie` or
`--rpc-user`/`--rpc-password`:

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  scan \
  --rpc-cookie /path/to/bitcoin/.cookie \
  --verify-with-bitcoin-core \
  --bitcoind /path/to/bitcoind \
  --output text
```

For an initial bounded run:

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  scan \
  --rpc-cookie /path/to/bitcoin/.cookie \
  --end-height 710000 \
  --output json
```

`--output text` prints one human-readable line after every block is durably
committed. `--output json` emits newline-delimited events suitable for piping
to a file or log collector:

```json
{"type":"scan_started","chain":"main","start_height":709632,"target_height":710000,"resumed":false}
{"type":"block_result","height":709632,"block_hash":"...","transactions":2341,"p2tr_created":12,"revealed_script_paths":0,"analyzed_scripts":0,"candidate_weak_scripts":0,"confirmed_weak_scripts":0}
{"type":"scan_summary","interrupted":false,"start_height":709632,"last_committed_height":710000,"target_height":710000,"completed_blocks":369}
```

Every `block_result` contains counts for that block only. `scan_summary`
contains totals for the current invocation. The legacy `--progress` spelling is
retained as an alias for `--output`.

The same command can be run again to resume. The database is tied to the
original chain, start height, and Taproot activation height.

Without `--end-height`, the scanner captures the node tip once at startup,
scans through that fixed target, and exits. Blocks mined after startup are not
added to the current run.

RPC credentials can also be supplied through:

```text
BITCOIN_RPC_URL
BITCOIN_RPC_COOKIE
BITCOIN_RPC_USER
BITCOIN_RPC_PASSWORD
BITCOIN_RPC_TIMEOUT_SECS
BITCOIN_RPC_MAX_RETRIES
BITCOIN_RPC_RETRY_INITIAL_MS
BITCOIN_RPC_RETRY_MAX_MS
BITCOIN_RPC_MAX_RESPONSE_MIB
TAPSCRIPT_MIN_FREE_DISK_MIB
TAPSCRIPT_MAX_IN_MEMORY_P2TR_UTXOS
```

The binary loads a local `.env` automatically, without overriding variables
already present in the process environment. Copy `.env.example` and keep the
real RPC endpoint only in `.env`; the repository ignores `.env` files.

Read RPCs retry transient transport failures, HTTP 408/425/429/5xx responses,
Bitcoin Core warmup errors, and malformed success responses. Defaults are five
retries with exponential delays from one to thirty seconds. Authentication and
other permanent HTTP/RPC failures are not retried.

RPC JSON is deserialized directly from a size-limited response stream. The
default `--rpc-max-response-mib 64` stops on a larger response instead of
buffering an unbounded block body. The default
`--min-free-disk-mib 1024` checks the database filesystem before fetching and
again before committing each block.

The unspent P2TR HashMap is separately guarded by
`--max-in-memory-p2tr-utxos`, defaulting to 1,000,000 entries. Zero disables
this entry-count guard.

The database never stores complete block or transaction responses. By default,
`--reorg-retention-blocks 144` keeps spent P2TR rows only while they are needed
to reverse the most recent 144 blocks. Older spent rows are deleted, while
unspent P2TR state, compact block counts, checkpoints, and detection evidence
remain. A deeper reorganization stops before changing local state and requires
a database rebuild from a trusted checkpoint.

For `no_proof_found`, the database keeps the TapLeaf hash, output key, original
script size, revelation location, analyzer version, search configuration, and
status, but clears the full script, Merkle-path JSON, annex, and observed
witness. Candidate/confirmed weaknesses plus `inconclusive` and
`invalid_script` outcomes retain complete evidence. Weakness evidence also
records the proof strategy; older databases are migrated with
`legacy_unspecified` for proofs created before that field existed.

### Show scan progress in a browser

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  serve \
  --bind 0.0.0.0:8787
```

The page and `/api/status` show checkpoint heights, per-block counts, and
detection totals. They do not list outpoints, scripts, or witnesses. The
default listen address is `0.0.0.0:8787`. `docker-compose.yml` builds that
binary on the server, scans a bounded height range, and publishes the panel.

### Inspect scan status

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  status
```

### Export current findings

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  report \
  --pretty \
  --output report.json
```

A report contains only candidate weak leaves whose Taproot output key currently
has at least one unspent output in the scanner's local view. Each item includes
the concrete proof witness and `proof_strategy` alongside consensus, policy,
validator, and limitation evidence.

## Detection statuses

| Status | Meaning |
| --- | --- |
| `confirmed_weak` | A synthetic equivalent was accepted by Bitcoin Core `testmempoolaccept` on isolated regtest. |
| `policy_rejected` | Mandatory script checks passed, but current standard mempool policy rejected the synthetic spend. |
| `candidate_weak` | The bounded analyzer found a witness, but Core validation was absent, failed, or rejected without separable consensus/policy evidence. |
| `consensus_invalid` | Bitcoin Core rejected the witness under consensus script rules. It is not reported as a spendable risk. |
| `no_proof_found` | No candidate was found inside the configured search space. This is not a safety proof. |
| `inconclusive` | Execution reached semantics the analyzer does not support. |
| `invalid_script` | The script could not be parsed by the analyzer. |

The database persists every analyzed `0xc0` leaf, including analyzer version,
the configured bounded search strategies and limits, consensus status, policy
status, validator, and details. Candidate and confirmed results additionally
retain their proof strategy. Reports include candidate and confirmed weak
leaves only.

## Current project status

The repository is a functional research prototype:

- The motivating incident is represented in analyzer, Taproot commitment, and
  database-flow tests, plus an opt-in Bitcoin Core regtest integration test.
- Core scanning, evidence persistence, reporting, and reorganization structures
  exist.
- Reorganization reconciliation propagates RPC failures instead of treating
  them as canonical-hash mismatches.
- Transient HTTP and malformed-response retry paths have fault-injection tests.
- An opt-in read-only mainnet E2E test scans fixed heights `959019..=959020`
  and asserts that revealing transaction
  `56f4c8b2c11ce6010637f8f831ad03430bc1686fc39d4833ec0281ddbef01a22`
  is persisted as `candidate_weak`.
- Initial bounded search-space expansion covers small numbers, script constants,
  and observed signature-shaped witness items.
- Broader differential and reorganization tests, transaction-context semantics,
  preimage/structured-witness search, and mainnet-scale benchmarks are still
  needed.

Do not use the current scanner unattended against an irreplaceable database.
Keep backups and validate findings independently.

Run the fixed-chain E2E test with a read-only RPC configured in `.env`:

```bash
cargo test \
  scanner::tests::mainnet_forum_incident_is_detected_via_read_only_rpc \
  -- --ignored
```

## Protocol references

- [BIP 341 — Taproot spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP 342 — Validation of Taproot scripts](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
- [Bitcoin Core `getblockchaininfo`](https://bitcoincore.org/en/doc/31.0.0/rpc/blockchain/getblockchaininfo/)
- [Bitcoin Core `getblock`](https://bitcoincore.org/en/doc/31.0.0/rpc/blockchain/getblock/)
- [Original BitcoinTalk discussion](https://bitcointalk.org/index.php?topic=5588964.0)

## License

The crate declares the MIT license in `Cargo.toml`.
