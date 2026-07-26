# Responsible handling

## Scope

This project may identify public Bitcoin outputs that appear spendable without
the signature their creator likely intended to require. That information can
help defenders, but it can also lower the effort required for theft.

Technical spendability is not ownership. A transaction accepted by consensus
may still be unauthorized, unlawful, or harmful.

## Project policy

The repository should remain:

- read-only;
- non-custodial;
- non-broadcasting;
- evidence-oriented;
- explicit about uncertainty;
- separated from private-key and wallet operations.

Features that automatically construct, sign, fee-bump, submit, or monitor a
sweep transaction are out of scope.

## Handling a candidate finding

### 1. Preserve evidence privately

Record:

- chain and block height;
- revealing transaction and input;
- spent output;
- output key;
- script and control block;
- candidate witness;
- execution trace;
- analyzer version and limitations;
- current unspent outpoints observed.

Do not publish a live target list merely to demonstrate that the scanner works.

### 2. Reproduce independently

Before contacting anyone or describing the result as a vulnerability:

- verify the BIP 341 commitment independently;
- validate the candidate satisfaction through Bitcoin Core in an isolated
  environment;
- confirm the result does not depend on a custom-interpreter bug;
- verify the output remains unspent;
- have a second reviewer reproduce the result.

### 3. Minimize disclosure

Prefer sharing:

- the vulnerable construction;
- a redacted proof;
- the affected wallet or tool version, when attributable;
- remediation guidance.

Avoid sharing current unspent outpoints or a ready-to-broadcast transaction
before remediation, unless coordinated disclosure clearly requires it.

### 4. Contact maintainers or operators

If a wallet, library, descriptor generator, or service can be attributed:

- use its published security contact;
- provide reproducible technical evidence;
- state what is confirmed and what remains inferred;
- agree on a disclosure timeline when possible.

Do not infer attribution solely because two outputs reuse a key or commitment.

### 5. Do not move funds

The scanner finding a valid spending path does not authorize the project or its
operators to use it. Any proposed fund-rescue action requires independent legal,
ethical, operational, and ownership review outside this repository.

## Reporting language

Use precise labels:

| Avoid | Prefer |
| --- | --- |
| “The coins have no owner.” | “The observed script appears satisfiable without a valid signature.” |
| “Bitcoin confirms this is theft.” | “Bitcoin consensus validates spending conditions, not social authorization.” |
| “All affected wallets were found.” | “These outputs reuse a commitment learned from a revealed leaf.” |
| “No vulnerability exists.” | “No proof was found within the analyzer's bounded search.” |
| “Consensus-verified exploit.” | “Synthetic equivalent accepted by Bitcoin Core on isolated regtest; ownership and operational implications are not established.” |

## Publication checklist

- [ ] Candidate reproduced outside the custom analyzer.
- [ ] Chain state and unspent status refreshed.
- [ ] At least one independent reviewer confirmed the result.
- [ ] Affected software attribution is evidence-backed.
- [ ] Maintainer/security contact attempted when applicable.
- [ ] Live outpoints and operational exploit details minimized.
- [ ] Analyzer limitations included.
- [ ] No transaction was created or broadcast by the scanner.

## Original discussion

The ethical question that motivated this policy appears in the BitcoinTalk
thread [“How to handle weak scripts?”](https://bitcointalk.org/index.php?topic=5588964.0).
The discussion includes suggestions for moving exposed funds and returning them
after proof of ownership. This repository documents that context but does not
implement those suggestions.
