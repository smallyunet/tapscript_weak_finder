# Operations

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
  --progress json
```

This database cannot recognize spends of P2TR outputs created before its start
height. Its status reports `coverage_complete_from_genesis: false`.

Use a separate database for a different start height or activation-height
configuration.

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
| `weak_scripts` | Candidate weak leaves currently stored. |
| `analyzed_scripts` | Revealed `0xc0` leaves with persisted analysis coverage. |
| `confirmed_weak_scripts` | Candidates accepted by the isolated Core validator. |
| `candidate_weak_scripts` | Candidates without conclusive Core acceptance. |
| `current_p2tr_utxos` | Unspent P2TR outputs known to this database. |

Ctrl-C is handled between blocks. The current block completes before its
transaction is committed or discarded.

## Progress output

### Text

```bash
--progress text
```

Displays a progress bar, current height, aggregate transaction/input/output
counts, revealed leaves, candidate weaknesses, scan rate, and ETA.

### JSON

```bash
--progress json --progress-interval-secs 10
```

Emits newline-delimited JSON suitable for log collection.

### None

```bash
--progress none
```

Suppresses progress reporting.

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

Keep periodic recoverable backups. Reconciliation now aborts on RPC errors and
rolls back only after a successfully retrieved canonical hash differs from the
checkpoint. Rollback activity still should not be treated as independent proof
of a real chain reorganization.

## Performance expectations

The current scanner is deliberately simple:

- one height at a time;
- one `getblockhash` request per height;
- one decoded `getblock` request per block;
- one in-memory entry per currently unspent tracked P2TR output;
- one SQLite transaction per block.

No mainnet-scale throughput guarantee has been established. Before relying on a
full-history run, benchmark a bounded range using the same node, disk, and
machine.

Potential future improvements include:

- JSON-RPC batching or pipelining;
- retry and exponential backoff for read RPCs;
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
