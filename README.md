# tapscript-weak-finder

`tapscript-weak-finder` is an experimental, read-only Bitcoin Taproot audit
scanner. It looks for revealed TapScript leaves that can be satisfied without a
valid signature, records a reproducible witness and execution trace, and reports
currently unspent P2TR outputs that reuse the same Taproot output key.

> [!WARNING]
> This project is research software, not a production security oracle. A
> A local `weak` result is only a candidate produced by the bounded analyzer.
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
- Analyzes revealed leaf-version `0xc0` TapScripts with a bounded witness search.
- Optionally validates candidate witnesses with Bitcoin Core in an isolated
  synthetic regtest.
- Stores confirmed commitments, observed revelations, all analysis outcomes,
  validation evidence, and per-block checkpoints.
- Resumes after interruption and attempts to reconcile chain reorganizations.
- Exports current risks as JSON, limited to unspent outputs sharing an output
  key with a revealed candidate weak leaf.

## What it cannot do

- It cannot recover an unrevealed TapScript tree from a Taproot output key.
- It cannot find every victim whose weak leaf has never appeared on chain.
- It does not prove that `no_proof_found` means safe.
- Its Core validator cannot always separate consensus validity from policy when
  `testmempoolaccept` rejects a candidate; both evidence fields remain
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
- `execution_trace`
- `valid_signatures_required`
- `limitations`

### Scan with Bitcoin Core cookie authentication

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  scan \
  --rpc-cookie /path/to/bitcoin/.cookie \
  --verify-with-bitcoin-core \
  --bitcoind /path/to/bitcoind \
  --progress text
```

For an initial bounded run:

```bash
cargo run --release -- \
  --db tapscript-audit.sqlite \
  scan \
  --rpc-cookie /path/to/bitcoin/.cookie \
  --end-height 710000 \
  --progress json
```

The same command can be run again to resume. The database is tied to the
original chain, start height, and Taproot activation height.

RPC credentials can also be supplied through:

```text
BITCOIN_RPC_URL
BITCOIN_RPC_COOKIE
BITCOIN_RPC_USER
BITCOIN_RPC_PASSWORD
```

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
has at least one unspent output in the scanner's local view.

## Detection statuses

| Status | Meaning |
| --- | --- |
| `confirmed_weak` | A synthetic equivalent was accepted by Bitcoin Core `testmempoolaccept` on isolated regtest. |
| `candidate_weak` | The bounded analyzer found a witness, but Core validation was absent, failed, or rejected without separable consensus/policy evidence. |
| `no_proof_found` | No candidate was found inside the configured search space. This is not a safety proof. |
| `inconclusive` | Execution reached semantics the analyzer does not support. |
| `invalid_script` | The script could not be parsed by the analyzer. |

The database persists every analyzed `0xc0` leaf, including analyzer version,
search configuration, consensus status, policy status, validator, and details.
Reports include candidate and confirmed weak leaves only.

## Current project status

The repository is a functional research prototype:

- The motivating incident is represented in analyzer, Taproot commitment, and
  database-flow tests, plus an opt-in Bitcoin Core regtest integration test.
- Core scanning, evidence persistence, reporting, and reorganization structures
  exist.
- Reorganization reconciliation propagates RPC failures instead of treating
  them as canonical-hash mismatches.
- Broader differential tests, RPC fault injection, transaction-context
  semantics, search-space expansion, and mainnet-scale benchmarks are still
  needed.

Do not use the current scanner unattended against an irreplaceable database.
Keep backups and validate findings independently.

## Protocol references

- [BIP 341 — Taproot spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP 342 — Validation of Taproot scripts](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
- [Bitcoin Core `getblockchaininfo`](https://bitcoincore.org/en/doc/31.0.0/rpc/blockchain/getblockchaininfo/)
- [Bitcoin Core `getblock`](https://bitcoincore.org/en/doc/31.0.0/rpc/blockchain/getblock/)
- [Original BitcoinTalk discussion](https://bitcointalk.org/index.php?topic=5588964.0)

## License

The crate declares the MIT license in `Cargo.toml`.
