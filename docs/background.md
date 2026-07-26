# Project background

## The motivating incident

This project began with the BitcoinTalk thread
[“How to handle weak scripts?”](https://bitcointalk.org/index.php?topic=5588964.0).
The thread documented a Taproot script-path spend whose revealed leaf was:

```text
OP_PUSHBYTES_32 <pubkey A>
OP_CHECKSIG
OP_IF
OP_PUSHBYTES_32 <pubkey B>
OP_ENDIF
```

At first glance, the script appears to gate spending on a valid signature for
`pubkey A`. Its actual stack behavior allows a signatureless path.

Given the candidate witness stack:

```text
[01, <empty>]
```

the script evolves conceptually as follows:

| Step | Effect |
| --- | --- |
| Push `pubkey A` | The public key is placed on top of the initial witness stack. |
| `OP_CHECKSIG` | It consumes `pubkey A` and the empty signature, then pushes false. |
| `OP_IF` | It consumes that false value, but the separate `01` remains on the stack. |
| Conditional body | The body is skipped because the condition is false. |
| End of script | The remaining `01` is truthy, so the script succeeds. |

The exact order is easy to misunderstand when reading the script as source
code rather than simulating the stack. This is precisely the kind of
construction error that motivates mechanical analysis.

The forum discussion then moved beyond the single output:

- Other outputs appeared to reuse related keys or constructions.
- Participants asked whether a buggy wallet or script-building tool generated
  the pattern.
- Participants debated what responsible handling should look like if funds are
  spendable by anyone.
- The original post noted the central discovery problem: TapScripts remain
  hidden until their script path is revealed.

This repository addresses discovery and evidence collection. It deliberately
does not implement the proposed fund-moving or “rescue” workflows.

## Why Taproot makes discovery difficult

BIP 341 represents a Taproot output with a 32-byte output key. That output can
be spent through:

- a key path, which reveals no script tree; or
- a script path, which reveals one script leaf, its control block, and the
  Merkle path needed to prove that the output key committed to the leaf.

Unused leaves stay hidden. Even after a script-path spend, only the executed
leaf and its commitment path are revealed—not every sibling script.

This creates a hard information boundary:

> A chain-only scanner cannot inspect a TapScript leaf that has never been
> revealed.

The scanner can nevertheless produce useful evidence in several cases:

1. A weak leaf is revealed in a confirmed transaction.
2. Another unspent output uses the exact same Taproot output key.
3. The same leaf or tree can be reconstructed from a known wallet template,
   descriptor, source code, or other off-chain evidence.

The current implementation covers the first two cases. It does not ingest
wallet templates or descriptors.

## The actual research question

The narrow research question is not:

> Can every hidden weak TapScript be discovered from the blockchain?

That is generally impossible because hiding unused scripts is a Taproot privacy
feature.

The tractable question is:

> When the chain reveals a TapScript, can we verify its commitment, find a
> signatureless satisfaction proof, and determine whether the same commitment
> still protects unspent funds?

This question leads directly to the project's three-part architecture:

1. canonical-chain and UTXO tracking;
2. BIP 341 commitment verification;
3. bounded signatureless witness search.

## Why not match only the known script

An exact signature or byte-pattern rule would find only copies of the original
leaf. Similar failures can be expressed through:

- different conditional layouts;
- stack manipulation before or after a signature check;
- equality, arithmetic, or hashing operations;
- `OP_SUCCESSx` behavior;
- upgradeable public-key types;
- combinations of supported operations.

The project therefore executes scripts against generated candidate witness
stacks. This expands coverage beyond one incident while retaining a concrete,
replayable proof witness for every reported candidate.

The cost of this approach is semantic risk: a custom interpreter can diverge
from Bitcoin consensus. The custom analyzer therefore remains a candidate
generator and trace producer. When requested, the implemented validator
recreates the script with synthetic regtest funds and asks Bitcoin Core
`testmempoolaccept` to evaluate the candidate. Only an accepted result is
promoted to `confirmed_weak`.

## Ownership and responsible handling

Bitcoin consensus validates spending conditions; it does not identify a
social, legal, or intended “true owner.” A signatureless satisfaction path may
make a transaction valid without making it authorized.

This project therefore follows these boundaries:

- read chain data;
- verify commitments;
- generate local proofs;
- report evidence;
- never automatically construct or broadcast a spend;
- never treat technical spendability as ownership.

See [Responsible handling](responsible-handling.md) for the reporting model.

## Related specifications

- [BIP 341 — Taproot spending rules](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)
- [BIP 342 — Validation of Taproot scripts](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki)
