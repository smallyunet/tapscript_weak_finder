use anyhow::{Context, Result, bail};
use secp256k1::{Parity, Scalar, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct RevealedScriptPath {
    /// Witness elements supplied as the TapScript initial stack, after
    /// removing the optional annex, script, and control block.
    pub initial_stack: Vec<Vec<u8>>,
    pub script: Vec<u8>,
    pub control_block: Vec<u8>,
    pub annex: Option<Vec<u8>>,
    pub internal_key: [u8; 32],
    pub leaf_version: u8,
    pub tapleaf_hash: [u8; 32],
    pub merkle_path: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub struct SingleLeafCommitment {
    pub output_key: [u8; 32],
    pub control_block: Vec<u8>,
}

pub fn single_leaf_commitment(script: &[u8]) -> Result<SingleLeafCommitment> {
    // The generator x-coordinate is a valid, fixed internal key for isolated
    // regtest fixtures. The key-path secret is never used by this validator.
    let internal_key: [u8; 32] =
        hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("fixed internal key hex")
            .try_into()
            .expect("fixed internal key length");
    let internal = XOnlyPublicKey::from_byte_array(internal_key)
        .context("fixed internal key is not a curve point")?;
    let leaf_version = 0xc0;
    let tapleaf_hash = tagged_hash(b"TapLeaf", &[
        &[leaf_version],
        &compact_size(script.len() as u64),
        script,
    ]);
    let tweak = tagged_hash(b"TapTweak", &[&internal_key, &tapleaf_hash]);
    let scalar =
        Scalar::from_be_bytes(tweak).map_err(|_| anyhow::anyhow!("TapTweak >= curve order"))?;
    let secp = Secp256k1::verification_only();
    let (output_key, parity) = internal
        .add_tweak(&secp, &scalar)
        .context("Taproot tweak produced an invalid output key")?;
    let parity_bit = if parity == Parity::Odd { 1 } else { 0 };
    let mut control_block = Vec::with_capacity(33);
    control_block.push(leaf_version | parity_bit);
    control_block.extend_from_slice(&internal_key);
    Ok(SingleLeafCommitment {
        output_key: output_key.serialize(),
        control_block,
    })
}

/// Returns a verified script-path revelation, or `None` when the witness has
/// key-path shape. This function verifies only script-path commitments; it
/// does not validate key-path signatures.
pub fn parse_and_verify_script_path(
    witness_hex: &[String],
    expected_output_key: &[u8; 32],
) -> Result<Option<RevealedScriptPath>> {
    if witness_hex.is_empty() {
        return Ok(None);
    }
    let mut witness = witness_hex
        .iter()
        .map(|item| hex::decode(item).context("decode witness item"))
        .collect::<Result<Vec<_>>>()?;

    let annex = if witness.len() >= 2
        && witness
            .last()
            .and_then(|item| item.first())
            .is_some_and(|byte| *byte == 0x50)
    {
        witness.pop()
    } else {
        None
    };

    if witness.len() <= 1 {
        return Ok(None);
    }

    let control_block = witness.pop().expect("length checked");
    let script = witness.pop().expect("length checked");
    let proof = verify_control_block(&script, &control_block, expected_output_key)?;

    Ok(Some(RevealedScriptPath {
        initial_stack: witness,
        script,
        control_block,
        annex,
        internal_key: proof.internal_key,
        leaf_version: proof.leaf_version,
        tapleaf_hash: proof.tapleaf_hash,
        merkle_path: proof.merkle_path,
    }))
}

struct CommitmentProof {
    internal_key: [u8; 32],
    leaf_version: u8,
    tapleaf_hash: [u8; 32],
    merkle_path: Vec<[u8; 32]>,
}

fn verify_control_block(
    script: &[u8],
    control: &[u8],
    expected_output_key: &[u8; 32],
) -> Result<CommitmentProof> {
    if control.len() < 33 || (control.len() - 33) % 32 != 0 {
        bail!("invalid control block length {}", control.len());
    }
    let depth = (control.len() - 33) / 32;
    if depth > 128 {
        bail!("control block Merkle path exceeds 128 nodes");
    }

    let leaf_version = control[0] & 0xfe;
    let expected_parity = control[0] & 1;
    let internal_key: [u8; 32] = control[1..33].try_into().expect("fixed slice");
    let internal = XOnlyPublicKey::from_byte_array(internal_key)
        .context("control block internal key is not a curve point")?;

    let tapleaf_hash = tagged_hash(b"TapLeaf", &[
        &[leaf_version],
        &compact_size(script.len() as u64),
        script,
    ]);
    let mut root = tapleaf_hash;
    let mut merkle_path = Vec::with_capacity(depth);
    for node in control[33..].chunks_exact(32) {
        let sibling: [u8; 32] = node.try_into().expect("exact chunk");
        merkle_path.push(sibling);
        root = if root < sibling {
            tagged_hash(b"TapBranch", &[&root, &sibling])
        } else {
            tagged_hash(b"TapBranch", &[&sibling, &root])
        };
    }

    let tweak = tagged_hash(b"TapTweak", &[&internal_key, &root]);
    let scalar =
        Scalar::from_be_bytes(tweak).map_err(|_| anyhow::anyhow!("TapTweak >= curve order"))?;
    let secp = Secp256k1::verification_only();
    let (computed_key, parity) = internal
        .add_tweak(&secp, &scalar)
        .context("Taproot tweak produced an invalid output key")?;
    if computed_key.serialize() != *expected_output_key {
        bail!("control block does not commit to prevout output key");
    }
    let parity_bit = if parity == Parity::Odd { 1 } else { 0 };
    if parity_bit != expected_parity {
        bail!("control block output-key parity mismatch");
    }

    Ok(CommitmentProof {
        internal_key,
        leaf_version,
        tapleaf_hash,
        merkle_path,
    })
}

fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn compact_size(value: u64) -> Vec<u8> {
    match value {
        0..=0xfc => vec![value as u8],
        0xfd..=0xffff => {
            let mut out = vec![0xfd];
            out.extend_from_slice(&(value as u16).to_le_bytes());
            out
        }
        0x1_0000..=0xffff_ffff => {
            let mut out = vec![0xfe];
            out.extend_from_slice(&(value as u32).to_le_bytes());
            out
        }
        _ => {
            let mut out = vec![0xff];
            out.extend_from_slice(&value.to_le_bytes());
            out
        }
    }
}

pub fn p2tr_output_key(script_pubkey_hex: &str) -> Result<Option<[u8; 32]>> {
    let bytes = hex::decode(script_pubkey_hex).context("decode scriptPubKey")?;
    if bytes.len() != 34 || bytes[0] != 0x51 || bytes[1] != 0x20 {
        return Ok(None);
    }
    Ok(Some(bytes[2..34].try_into().expect("fixed length")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_native_v1_32_byte_programs() {
        let key = "11".repeat(32);
        assert!(p2tr_output_key(&format!("5120{key}")).unwrap().is_some());
        assert!(p2tr_output_key(&format!("0020{key}")).unwrap().is_none());
        assert!(p2tr_output_key("51").unwrap().is_none());
    }

    #[test]
    fn compact_size_boundaries() {
        assert_eq!(compact_size(252), vec![252]);
        assert_eq!(compact_size(253), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(compact_size(65_536), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn builds_a_verifiable_single_leaf_commitment() {
        let script = [0x51];
        let commitment = single_leaf_commitment(&script).unwrap();
        let proof =
            verify_control_block(&script, &commitment.control_block, &commitment.output_key)
                .unwrap();
        assert_eq!(proof.leaf_version, 0xc0);
        assert!(proof.merkle_path.is_empty());
    }

    #[test]
    fn verifies_forum_incident_commitment_and_extracts_script_path() {
        let output_key: [u8; 32] =
            hex::decode("f1f9462868873c84f8a475307a26116f5f74c1caa5d7458f418ed97a399bc5b4")
                .unwrap()
                .try_into()
                .unwrap();
        let script = concat!(
            "20",
            "fa9b5ec193f735c41b804fc6ace1d28e81a299fc815c0f5009dd2dd7d0293c3b",
            "ac63",
            "20",
            "ff1275b635cd160914cfe1bc516f521abde0fc8ae3fd92ae01ca16449e4758e9",
            "68"
        );
        let witness = vec![
            "51".to_owned(),
            String::new(),
            script.to_owned(),
            "c0fa9b5ec193f735c41b804fc6ace1d28e81a299fc815c0f5009dd2dd7d0293c3b".to_owned(),
        ];
        let reveal = parse_and_verify_script_path(&witness, &output_key)
            .unwrap()
            .unwrap();
        assert_eq!(reveal.initial_stack, vec![vec![0x51], Vec::new()]);
        assert_eq!(hex::encode(reveal.script), script);
        assert_eq!(reveal.leaf_version, 0xc0);
        assert!(reveal.merkle_path.is_empty());
    }

    #[test]
    fn extracts_annex_and_an_empty_tapscript_initial_stack() {
        let script = [0x51];
        let commitment = single_leaf_commitment(&script).unwrap();
        let witness = vec![
            hex::encode(script),
            hex::encode(&commitment.control_block),
            "50aabb".to_owned(),
        ];

        let reveal = parse_and_verify_script_path(&witness, &commitment.output_key)
            .unwrap()
            .unwrap();

        assert!(reveal.initial_stack.is_empty());
        assert_eq!(reveal.annex, Some(vec![0x50, 0xaa, 0xbb]));
        assert_eq!(reveal.script, script);
        assert_eq!(reveal.control_block, commitment.control_block);
    }

    #[test]
    fn preserves_a_stack_item_starting_with_annex_tag() {
        let script = [0x51];
        let commitment = single_leaf_commitment(&script).unwrap();
        let witness = vec![
            "50aabb".to_owned(),
            hex::encode(script),
            hex::encode(&commitment.control_block),
        ];

        let reveal = parse_and_verify_script_path(&witness, &commitment.output_key)
            .unwrap()
            .unwrap();

        assert_eq!(reveal.initial_stack, vec![vec![0x50, 0xaa, 0xbb]]);
        assert!(reveal.annex.is_none());
    }

    #[test]
    fn recognizes_key_path_spends_with_or_without_an_annex() {
        let output_key = [0x11; 32];
        let key_path = vec!["22".repeat(64)];
        let key_path_with_annex = vec!["22".repeat(64), "50aabb".to_owned()];

        assert!(
            parse_and_verify_script_path(&key_path, &output_key)
                .unwrap()
                .is_none()
        );
        assert!(
            parse_and_verify_script_path(&key_path_with_annex, &output_key)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_an_output_key_mismatch() {
        let script = [0x51];
        let commitment = single_leaf_commitment(&script).unwrap();
        let witness = vec![hex::encode(script), hex::encode(&commitment.control_block)];
        let wrong_output_key = [0x22; 32];

        let error = parse_and_verify_script_path(&witness, &wrong_output_key)
            .unwrap_err()
            .to_string();

        assert!(error.contains("does not commit to prevout output key"));
    }

    #[test]
    fn rejects_an_invalid_control_block_length() {
        let witness = vec!["51".to_owned(), "c0".to_owned()];

        let error = parse_and_verify_script_path(&witness, &[0x22; 32])
            .unwrap_err()
            .to_string();

        assert!(error.contains("invalid control block length 1"));
    }

    #[test]
    fn rejects_a_control_block_parity_mismatch() {
        let script = [0x51];
        let commitment = single_leaf_commitment(&script).unwrap();
        let mut control_block = commitment.control_block;
        control_block[0] ^= 1;
        let witness = vec![hex::encode(script), hex::encode(control_block)];

        let error = parse_and_verify_script_path(&witness, &commitment.output_key)
            .unwrap_err()
            .to_string();

        assert!(error.contains("output-key parity mismatch"));
    }
}
