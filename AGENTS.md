# Repository instructions

## Project mission

`tapscript-weak-finder` is an authorized, defensive Bitcoin security research
project. Its purpose is to:

- inspect public Bitcoin chain data through read-only RPC methods;
- verify that revealed TapScript leaves are committed to the spent Taproot
  output;
- generate candidate witnesses for scripts that may succeed without a valid
  cryptographic signature;
- reduce false positives by validating synthetic reproductions against an
  isolated Bitcoin Core regtest node;
- report evidence and uncertainty without taking custody of funds.

The project is a detector and research tool. It is not a wallet, exploit tool,
transaction broadcaster, mempool bot, or automated fund-rescue system.

## Authorized environment

Work in this repository is authorized only within these boundaries:

- Local source code and tests under this repository.
- A locally installed Bitcoin Core node.
- Temporary, isolated `regtest` datadirs.
- Synthetic regtest blocks, transactions, outputs, scripts, and test funds.
- Public blockchain data accessed through read-only RPC calls.
- Local SQLite databases created by the scanner or its tests.

All Bitcoin Core validation fixtures must use synthetic regtest assets. A test
must never depend on a live mainnet UTXO remaining unspent.

## Prohibited behavior

Do not add, run, or recommend code that:

- constructs a spending transaction for a real mainnet, testnet, signet, or
  third-party UTXO;
- signs or broadcasts a transaction outside an isolated regtest;
- automatically sweeps, rescues, redirects, fee-bumps, or monitors funds for
  capture;
- obtains or uses private keys, seed phrases, wallet credentials, RPC
  credentials, or other secrets beyond the temporary regtest fixture;
- probes wallets, nodes, services, or hosts that the user has not explicitly
  placed in scope;
- publishes or transmits a current list of potentially vulnerable unspent
  outpoints;
- treats consensus spendability as proof of social, legal, or intended
  ownership;
- weakens validation, removes uncertainty labels, or fabricates a successful
  validator merely to make a test pass.

The production scanner must remain read-only with respect to Bitcoin Core.
Wallet, signing, raw-transaction submission, block-submission, and mining RPCs
are permitted only inside an explicitly isolated regtest test harness.

## Detection terminology

Use evidence-based states consistently:

- `confirmed_weak`: a synthetic equivalent has passed an authoritative Bitcoin
  Core consensus-validation path without requiring a valid signature.
- `candidate_weak`: the local analyzer found a candidate witness, but
  authoritative validation is incomplete.
- `policy_rejected`: mandatory script checks passed, but current standard
  mempool policy rejected the synthetic spend. Do not describe this as a
  consensus failure.
- `consensus_invalid`: Bitcoin Core rejected the candidate under consensus
  script rules. Do not report it as a spendable risk.
- `no_proof_found`: no witness was found inside the configured search space; it
  is not a safety proof.
- `inconclusive`: required semantics, transaction context, or validation
  evidence are unavailable.
- `invalid_commitment`: the revealed leaf/control block does not commit to the
  expected Taproot output key.

Never promote `candidate_weak` to `confirmed_weak` based only on the custom
interpreter.

## Analyzer and validator boundary

Treat `src/analyzer.rs` as a candidate generator, bounded executor, and trace
producer. It is not an authoritative replacement for Bitcoin Core.

The preferred validation flow is:

1. Generate a candidate witness locally.
2. Record the analyzer version, search configuration, and execution trace.
3. Recreate an equivalent Taproot output using only synthetic regtest funds.
4. Validate the candidate through Bitcoin Core.
5. Record consensus and standard-policy outcomes separately.
6. Promote the finding only when the required evidence is present.

If Bitcoin Core validation cannot be completed, return or persist
`candidate_weak` or `inconclusive`; do not assume success.

`testmempoolaccept` evaluates both consensus and policy. It is useful for
standardness evidence but cannot by itself prove that a policy-rejected
transaction is consensus-invalid. Tests for `OP_SUCCESSx`, upgradeable public-key
types, or other non-standard behavior must preserve that distinction.

## Chain scanner rules

- Mainnet, testnet, signet, and public-node access must use read-only RPCs.
- Keep the scanner resumable and block-atomic.
- Distinguish RPC transport/server errors from actual canonical-hash
  mismatches.
- Never authorize a rollback solely because an RPC call failed.
- Preserve explicit coverage metadata when a scan begins after genesis.
- Do not claim that unrevealed TapScript leaves can be recovered from an output
  key using chain data alone.
- Reports must state analyzer limitations and whether Bitcoin Core validation
  was performed.

## Responsible handling

Potential findings aggregate public information into security-sensitive
evidence. Handle them as follows:

- validate privately before publication;
- use synthetic or redacted examples in tests and documentation;
- avoid exposing live unspent outpoints unnecessarily;
- require independent reproduction for security-relevant claims;
- distinguish confirmed chain evidence from attribution or ownership
  inference;
- follow `docs/responsible-handling.md`.

## Implementation priorities

Unless the user specifies a different priority, work in this order:

1. Candidate-generation to Bitcoin Core validation closure.
2. Explicit detection states and persisted analysis coverage.
3. Regression and differential tests for BIP 341/342 behavior.
4. RPC failure and reorganization safety.
5. Search-space expansion and transaction-context modeling.
6. Full-chain performance and operational optimization.

Scanning faster is lower priority than producing trustworthy classifications.

## Required tests

The security-relevant test matrix should include:

- the motivating BitcoinTalk construction as a synthetic regtest fixture;
- a normal single-key `OP_CHECKSIG` negative case;
- conditional and stack-manipulation variants;
- invalid control blocks and output-key mismatches;
- minimal-number-encoding boundaries;
- stack and witness resource limits;
- `OP_SUCCESSx`;
- upgradeable public-key types;
- `OP_CHECKSIGADD`;
- locktime and sequence-dependent scripts;
- analyzer/Bitcoin Core differential cases;
- transient RPC failures;
- shallow and deep reorganizations;
- resume after interruption.

Tests that need Bitcoin Core must:

- create a uniquely named temporary regtest datadir;
- bind only to localhost;
- use synthetic funds generated inside that regtest;
- stop the child node cleanly;
- remove only the exact temporary directory created by the test;
- never reuse the user's normal Bitcoin datadir or wallet.

## Verification

After implementation changes, run when dependencies are available:

```bash
cargo fmt --all -- --check
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo build --release
```

Also run the isolated Bitcoin Core regtest integration tests for changes to:

- Taproot commitment construction or verification;
- candidate witness generation;
- consensus or policy classification;
- transaction-context modeling.

If dependency download, Bitcoin Core availability, or sandbox restrictions
block a check, report the exact unrun verification. Do not describe the
worktree as green based on an older binary.

## Review expectations

After every code change:

1. perform an independent reviewer-style second pass;
2. check consensus-versus-policy wording;
3. look for false-positive and false-negative paths;
4. verify that no real-asset transaction capability was introduced;
5. directly fix confirmed defects;
6. keep documentation synchronized with implemented behavior.

Rerunning the original tests alone does not count as the independent review.

## Git and release behavior

- Preserve unrelated user changes.
- Leave changes uncommitted unless the user explicitly asks for a commit.
- Do not push, tag, publish, or open a pull request unless explicitly
  authorized.
- Do not include sensitive finding data in commits, issues, pull requests, or
  release artifacts.

## Project references

Read these before changing detection semantics or operating behavior:

- `README.md`
- `docs/background.md`
- `docs/architecture.md`
- `docs/detection-model.md`
- `docs/operations.md`
- `docs/responsible-handling.md`
- BIP 341
- BIP 342
