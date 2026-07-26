# Operations

The concrete deployment record and runbook for SSH host `a` is maintained in
[`deployment-host-a.md`](deployment-host-a.md).

## Safety model

The configured chain node is always read-only:

- it calls blockchain-information and block-reading RPC methods;
- it does not use wallet, mining, signing, or transaction-submission RPCs.

With `--verify-with-bitcoin-core`, the process starts a second Bitcoin Core
instance using a uniquely named temporary datadir, regtest, localhost-only RPC,
and a synthetic wallet. It mines synthetic funds, confirms a synthetic fixture,
and calls `testmempoolaccept` for the candidate. It does not broadcast the
candidate spend. The temporary node is stopped and its exact temporary datadir
is removed on exit.

It does write to a local SQLite database and may roll back local rows while
reconciling a chain reorganization.

## Node preparation

Use a fully synchronized, non-pruned Bitcoin Core node. The scanner requests
complete decoded blocks using `getblock` with verbosity 2.

The RPC client retries transient transport errors, HTTP 408/425/429/5xx
responses, Bitcoin Core warmup (`-28`), and malformed HTTP 200 response bodies.
It does not retry authentication failures or ordinary JSON-RPC method errors.
RPC diagnostics go to stderr and do not include the configured URL, so an API
key embedded in that URL is not copied into scanner logs.

Authentication options:

1. RPC cookie file, recommended for a local node.
2. RPC username and password.
3. No authentication, only when the endpoint is already safely isolated.

Never expose an unauthenticated Bitcoin Core RPC endpoint to an untrusted
network.

Example:

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  scan \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-cookie /path/to/bitcoin/.cookie
```

For a hosted provider, the defaults can be adjusted through CLI options or
environment variables:

```text
--rpc-timeout-secs / BITCOIN_RPC_TIMEOUT_SECS
--rpc-max-retries / BITCOIN_RPC_MAX_RETRIES
--rpc-retry-initial-ms / BITCOIN_RPC_RETRY_INITIAL_MS
--rpc-retry-max-ms / BITCOIN_RPC_RETRY_MAX_MS
--rpc-max-response-mib / BITCOIN_RPC_MAX_RESPONSE_MIB
--min-free-disk-mib / TAPSCRIPT_MIN_FREE_DISK_MIB
--max-in-memory-p2tr-utxos / TAPSCRIPT_MAX_IN_MEMORY_P2TR_UTXOS
```

The process loads `.env` from the working directory when present. Existing
process environment variables take precedence. `.env` is ignored by Git and
should be mode `0600` on a multi-user host; `.env.example` contains only safe
placeholders.

`--rpc-max-response-mib` defaults to 64 MiB. Responses above the limit are not
retried because raising the limit is an operator decision. JSON is parsed from
the limited stream without first copying the complete response into a second
buffer.

`--min-free-disk-mib` defaults to 1024 MiB. The scanner checks the filesystem
containing the SQLite database before fetching and before committing every
block. Falling below the threshold stops the run at the last durable
checkpoint. Setting the disk threshold to zero disables only this guard.

`--max-in-memory-p2tr-utxos` defaults to 1,000,000 entries. The scanner checks
the persisted count before allocating the startup HashMap and checks the live
count after each committed block. Crossing the limit stops at that durable
height; increase the limit only after confirming the host has enough memory.
Zero disables this entry-count guard.

## Scan ranges and coverage

### Complete local UTXO coverage

The default start height is zero. This lets the scanner build its own complete
P2TR output lifecycle from the chain history.

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  scan \
  --rpc-cookie /path/to/bitcoin/.cookie
```

### Partial research scan

For experiments, a later start height and fixed end height can be used:

```bash
cargo run --release -- \
  --db experiment.sqlite \
  scan \
  --rpc-cookie /path/to/bitcoin/.cookie \
  --start-height 709632 \
  --end-height 710000 \
  --output json
```

This database cannot recognize spends of P2TR outputs created before its start
height. Its status reports `coverage_complete_from_genesis: false`.

Use a separate database for a different start height or activation-height
configuration.

When `--end-height` is omitted, the target is the node tip observed by the
initial `getblockchaininfo` call. The process scans to that fixed height and
exits; it does not follow blocks mined later.

## Resuming

The scanner commits after every block. Re-run the same command to continue from
`next_height`.

Use:

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  status
```

Important status fields:

| Field | Meaning |
| --- | --- |
| `next_height` | First height not yet committed. |
| `target_height` | Current requested scan target. |
| `last_block_hash` | Hash anchoring the checkpoint. |
| `coverage_complete_from_genesis` | Whether the database started at height zero. |
| `revealed_script_paths` | Verified script-path revelations observed. |
| `weak_scripts` | Leaves for which the bounded analyzer produced a weak witness, including candidate and Core-confirmed results. |
| `analyzed_scripts` | Revealed `0xc0` leaves with persisted analysis coverage. |
| `confirmed_weak_scripts` | Candidates accepted by the isolated Core validator. |
| `candidate_weak_scripts` | Candidates without conclusive Core acceptance. |
| `retained_evidence_scripts` | TapLeaves whose complete script evidence remains stored. |
| `compacted_no_proof_scripts` | `no_proof_found` TapLeaves retained as summaries. |
| `current_p2tr_utxos` | Unspent P2TR outputs known to this database. |
| `reorg_retention_blocks` | Configured number of recent blocks whose spent P2TR state is retained. |
| `oldest_reorg_safe_height` | Oldest block that can currently be rolled back without rebuilding. |

Ctrl-C is handled between blocks. The current block completes before its
transaction is committed or discarded.

## Per-block output

### Text

```bash
--output text
```

Prints one line after every block transaction is committed to SQLite. Counts on
that line belong only to that block. A progress bar remains visible on an
interactive terminal.

### JSON

```bash
--output json
```

Emits newline-delimited JSON suitable for log collection. Event types are:

| Type | Meaning |
| --- | --- |
| `scan_started` | Chain, invocation start height, target height, and resume flag. |
| `block_result` | The just-committed block hash, per-block chain counts, analysis outcomes, and timing. |
| `scan_summary` | Current-invocation totals and whether scanning was interrupted. |

Important `block_result` fields include:

- `transactions`, `inputs`, and `outputs`;
- `p2tr_created` and `p2tr_spent`;
- `revealed_script_paths` and `analyzed_scripts`;
- `candidate_weak_scripts` and `confirmed_weak_scripts`;
- `no_proof_found_scripts`, `inconclusive_scripts`, and
  `invalid_script_scripts`;
- `block_elapsed_ms` and `scan_elapsed_ms`.

One JSON object is printed per line. Redirect stdout to retain the stream:

```bash
cargo run --release -- \
  --db audit.sqlite \
  scan \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-cookie /path/to/bitcoin/.cookie \
  --output json > block-results.ndjson
```

Cargo build messages and fatal errors use stderr, so the redirected file
contains only scanner JSON after the process starts.

### None

```bash
--output none
```

Suppresses progress reporting.

The former `--progress text|json|none` option remains an alias.

## Reports

Generate a human-readable JSON file:

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  report \
  --pretty \
  --output report.json
```

Treat the output as sensitive security research. Even though all underlying
chain data is public, the report aggregates potentially exploitable conditions
and current unspent outpoints.

Before sharing a report:

1. validate the candidate witness independently;
2. confirm the local chain is current and canonical;
3. confirm the outputs are still unspent;
4. remove unnecessary operational details;
5. follow a responsible disclosure process.

## Database handling

SQLite uses WAL mode. While the scanner is running, the database may have:

```text
tapscript-audit.sqlite
tapscript-audit.sqlite-wal
tapscript-audit.sqlite-shm
```

Do not copy only the main database file during an active scan. Stop the scanner
cleanly or use a SQLite-aware backup procedure.

The database does not retain complete block or transaction JSON. It stores:

- the current unspent P2TR index required to match later spends;
- spent P2TR rows inside the recent reorganization window;
- block hashes and aggregate counts;
- verified revelation and analysis evidence;
- the durable resume checkpoint.

Full scripts and witnesses are retained for candidate/confirmed weaknesses,
`inconclusive`, and `invalid_script`. A `no_proof_found` row keeps coverage and
provenance summaries—including TapLeaf hash, original script size, revelation
transaction/block, analyzer version, and search configuration—but clears its
large script/witness evidence. Existing databases are compacted on their next
open. SQLite reuses freed pages, but run `VACUUM` only during planned downtime
if physically shrinking an existing file is necessary.

The default `--reorg-retention-blocks 144` deletes spent P2TR rows once they
fall outside the rollback window. SQLite reuses those pages for later writes;
deleting rows does not necessarily shrink the existing file immediately. A
reorganization deeper than the retained window is rejected before any rollback
and requires rebuilding the database from a trusted checkpoint.

Keep periodic recoverable backups. Reconciliation aborts on RPC errors and
plans the complete rollback before modifying local rows. Rollback activity
still should not be treated as independent proof of a real chain
reorganization.

## Performance expectations

The current scanner is deliberately simple:

- one height at a time;
- one `getblockhash` request per height;
- one decoded `getblock` request per block;
- one configured response-size guard per RPC body;
- one in-memory entry per currently unspent tracked P2TR output;
- one SQLite transaction per block.

No mainnet-scale throughput guarantee has been established. Before relying on a
full-history run, benchmark a bounded range using the same node, disk, and
machine.

Potential future improvements include:

- JSON-RPC batching or pipelining;
- a UTXO snapshot/bootstrap mode with explicit provenance;
- reduced-memory indexing;
- periodic database checkpoints and verified backups;
- metrics for analyzer coverage and inconclusive leaves.

## Validation checklist

Before treating a build as usable:

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

For security-relevant releases, also require:

- Bitcoin Core regtest integration tests;
- transient RPC failure tests;
- shallow and deep reorganization tests;
- differential analyzer tests;
- fixture replay of the motivating incident;
- a bounded performance benchmark.

Run the opt-in local Core integration test with:

```bash
BITCOIND_PATH=/path/to/bitcoind \
  cargo test bitcoin_core_confirms_the_motivating_signatureless_path -- --ignored
```

Run the fixed historical mainnet E2E test with `BITCOIN_RPC_URL` configured in
the environment or local `.env`:

```bash
cargo test \
  scanner::tests::mainnet_forum_incident_is_detected_via_read_only_rpc \
  -- --ignored
```

This test performs only `getblockchaininfo`, `getblockhash`, and decoded
`getblock` reads. It scans funding height `959019` and reveal height `959020`,
then requires the known revealing transaction to have persisted
`candidate_weak` evidence. It is ignored during ordinary test runs so CI does
not depend on a provider credential or external chain availability.

## Troubleshooting

### Node is pruned

The scanner currently stops because it cannot guarantee access to the requested
historical blocks. Use a non-pruned node or implement a separately documented
partial-coverage mode.

### Database chain or start-height mismatch

The database records its initial scan identity. Use the original parameters or
create a new database.

### Requested end height is above the tip

Lower `--end-height` or wait for the node to synchronize.

### RPC request fails

Check:

- node synchronization and availability;
- RPC URL;
- cookie path and permissions;
- username/password pairing;
- local firewall;
- whether the HTTP request exceeded the current timeout.

Do not delete the database as the first recovery step. The last committed block
is intended to be resumable.
