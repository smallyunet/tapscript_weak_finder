use std::{
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use tempfile::{Builder, TempDir};

use crate::{
    detection::{
        CandidateValidator, ConsensusStatus, DetectionStatus, PolicyStatus, ValidationEvidence,
    },
    rpc::{Auth, BtcAmount, RpcClient},
    taproot::single_leaf_commitment,
};

const WALLET_NAME: &str = "weak-finder-regtest";
const VALIDATOR_NAME: &str = "bitcoin_core_regtest_testmempoolaccept";
const FIXTURE_VALUE_BTC: f64 = 1.0;
const CANDIDATE_FEE_SATS: u64 = 10_000;

pub struct CoreRegtestValidator {
    node: IsolatedRegtestNode,
}

impl CoreRegtestValidator {
    pub fn start(bitcoind: &Path) -> Result<Self> {
        Ok(Self {
            node: IsolatedRegtestNode::start(bitcoind)?,
        })
    }
}

impl CandidateValidator for CoreRegtestValidator {
    fn name(&self) -> &str {
        VALIDATOR_NAME
    }

    fn validate(&mut self, script: &[u8], witness: &[Vec<u8>]) -> Result<ValidationEvidence> {
        self.node.validate_candidate(script, witness)
    }
}

struct IsolatedRegtestNode {
    _data_dir: TempDir,
    process: ChildProcess,
    rpc: RpcClient,
    wallet_rpc: RpcClient,
}

struct ChildProcess {
    child: Child,
}

impl ChildProcess {
    fn new(child: Child) -> Self {
        Self { child }
    }

    fn terminate(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        self.terminate();
    }
}

impl IsolatedRegtestNode {
    fn start(bitcoind: &Path) -> Result<Self> {
        let data_dir = Builder::new()
            .prefix("tapscript-weak-finder-regtest-")
            .tempdir()
            .context("create isolated regtest data directory")?;
        let rpc_port = unused_local_port()?;
        let child = Command::new(bitcoind)
            .arg(format!("-datadir={}", data_dir.path().display()))
            .args([
                "-regtest=1",
                "-server=1",
                "-listen=0",
                "-discover=0",
                "-dnsseed=0",
                "-fallbackfee=0.00001000",
                "-printtoconsole=0",
                "-rpcbind=127.0.0.1",
            ])
            .arg(format!("-rpcport={rpc_port}"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("start Bitcoin Core at {}", bitcoind.display()))?;
        let mut process = ChildProcess::new(child);

        let cookie = data_dir.path().join("regtest").join(".cookie");
        let url = format!("http://127.0.0.1:{rpc_port}");
        wait_for_cookie_or_exit(&cookie, &mut process.child)?;
        let rpc = RpcClient::new(url.clone(), Auth::CookieFile(cookie.clone()))?;
        wait_for_rpc(&rpc, &mut process.child)?;

        let _: Value = rpc
            .call("createwallet", json!([WALLET_NAME]))
            .context("create isolated regtest wallet")?;
        let wallet_rpc = RpcClient::new(
            format!("{url}/wallet/{WALLET_NAME}"),
            Auth::CookieFile(cookie),
        )?;
        let mining_address: String = wallet_rpc.call("getnewaddress", json!([]))?;
        let _: Vec<String> = wallet_rpc
            .call("generatetoaddress", json!([101, mining_address]))
            .context("mature isolated regtest coinbase funds")?;

        Ok(Self {
            _data_dir: data_dir,
            process,
            rpc,
            wallet_rpc,
        })
    }

    fn validate_candidate(&self, script: &[u8], witness: &[Vec<u8>]) -> Result<ValidationEvidence> {
        let commitment = single_leaf_commitment(script)?;
        let descriptor = format!("rawtr({})", hex::encode(commitment.output_key));
        let descriptor_info: DescriptorInfo =
            self.rpc.call("getdescriptorinfo", json!([descriptor]))?;
        let addresses: Vec<String> = self
            .rpc
            .call("deriveaddresses", json!([descriptor_info.descriptor]))?;
        let fixture_address = addresses
            .first()
            .context("Bitcoin Core returned no address for rawtr descriptor")?;

        let funding_txid: String = self
            .wallet_rpc
            .call("sendtoaddress", json!([fixture_address, FIXTURE_VALUE_BTC]))
            .context("fund synthetic Taproot fixture")?;
        let mining_address: String = self.wallet_rpc.call("getnewaddress", json!([]))?;
        let _: Vec<String> = self
            .wallet_rpc
            .call("generatetoaddress", json!([1, mining_address]))
            .context("confirm synthetic Taproot fixture")?;

        let funding: DecodedTransaction = self
            .wallet_rpc
            .call("gettransaction", json!([funding_txid, true, true]))
            .context("load synthetic funding transaction")?;
        let decoded: DecodedRawTransaction = self
            .rpc
            .call("decoderawtransaction", json!([funding.hex]))
            .context("decode synthetic funding transaction")?;
        let fixture = decoded
            .vout
            .iter()
            .find(|output| output.script_pub_key.address.as_deref() == Some(fixture_address))
            .context("locate synthetic Taproot fixture output")?;
        if fixture.value.0 <= CANDIDATE_FEE_SATS {
            bail!("synthetic fixture value is too small for candidate fee");
        }

        let destination: String = self.wallet_rpc.call("getnewaddress", json!([]))?;
        let destination_info: AddressInfo = self
            .wallet_rpc
            .call("getaddressinfo", json!([destination]))?;
        let transaction = serialize_candidate_transaction(
            &decoded.txid,
            fixture.n,
            fixture.value.0 - CANDIDATE_FEE_SATS,
            &hex::decode(&destination_info.script_pub_key)?,
            witness,
            script,
            &commitment.control_block,
        )?;
        let results: Vec<MempoolAcceptResult> = self
            .rpc
            .call("testmempoolaccept", json!([[hex::encode(transaction)], 0]))
            .context("validate candidate with Bitcoin Core testmempoolaccept")?;
        let result = results
            .first()
            .context("Bitcoin Core returned no testmempoolaccept result")?;

        Ok(evidence_for_mempool_result(result))
    }
}

fn evidence_for_mempool_result(result: &MempoolAcceptResult) -> ValidationEvidence {
    if result.allowed {
        return ValidationEvidence {
            detection_status: DetectionStatus::ConfirmedWeak,
            consensus_status: ConsensusStatus::ConfirmedValid,
            policy_status: PolicyStatus::Accepted,
            validator: VALIDATOR_NAME.to_owned(),
            details: Some(
                "Synthetic spend accepted by Bitcoin Core testmempoolaccept on isolated regtest; candidate transaction was not broadcast"
                    .to_owned(),
            ),
        };
    }

    let reason = result
        .reject_reason
        .as_deref()
        .unwrap_or("reason not returned");
    let reason_code = reason.split_once(" (").map_or(reason, |(code, _)| code);
    if reason_code.starts_with("non-mandatory-script-verify-flag") {
        return ValidationEvidence {
            detection_status: DetectionStatus::PolicyRejected,
            consensus_status: ConsensusStatus::ConfirmedValid,
            policy_status: PolicyStatus::Rejected,
            validator: VALIDATOR_NAME.to_owned(),
            details: Some(format!(
                "Bitcoin Core rejected the synthetic candidate under standard mempool policy only ({reason}). Mandatory script checks passed, so the spend is consensus-valid on this regtest. The candidate transaction was not broadcast"
            )),
        };
    }
    if reason_code.starts_with("mandatory-script-verify-flag") {
        return ValidationEvidence {
            detection_status: DetectionStatus::ConsensusInvalid,
            consensus_status: ConsensusStatus::Invalid,
            policy_status: PolicyStatus::NotChecked,
            validator: VALIDATOR_NAME.to_owned(),
            details: Some(format!(
                "Bitcoin Core rejected the synthetic candidate under consensus script rules ({reason}). This witness is not consensus-valid. The candidate transaction was not broadcast"
            )),
        };
    }
    ValidationEvidence {
        detection_status: DetectionStatus::CandidateWeak,
        consensus_status: ConsensusStatus::Inconclusive,
        policy_status: PolicyStatus::Inconclusive,
        validator: VALIDATOR_NAME.to_owned(),
        details: Some(format!(
            "Bitcoin Core rejected the synthetic candidate under combined consensus and mempool-policy evaluation: {reason}. This reason does not separate the two layers"
        )),
    }
}

impl Drop for IsolatedRegtestNode {
    fn drop(&mut self) {
        let _ = self.rpc.call::<Value>("stop", json!([]));
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if self.process.child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        self.process.terminate();
    }
}

#[derive(Deserialize)]
struct DescriptorInfo {
    descriptor: String,
}

#[derive(Deserialize)]
struct DecodedTransaction {
    hex: String,
}

#[derive(Deserialize)]
struct DecodedRawTransaction {
    txid: String,
    vout: Vec<DecodedVout>,
}

#[derive(Deserialize)]
struct DecodedVout {
    value: BtcAmount,
    n: u32,
    #[serde(rename = "scriptPubKey")]
    script_pub_key: DecodedScriptPubKey,
}

#[derive(Deserialize)]
struct DecodedScriptPubKey {
    address: Option<String>,
}

#[derive(Deserialize)]
struct AddressInfo {
    #[serde(rename = "scriptPubKey")]
    script_pub_key: String,
}

#[derive(Deserialize)]
struct MempoolAcceptResult {
    allowed: bool,
    #[serde(rename = "reject-reason")]
    reject_reason: Option<String>,
}

fn unused_local_port() -> Result<u16> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .context("reserve local regtest RPC port")?;
    Ok(listener.local_addr()?.port())
}

fn wait_for_cookie_or_exit(cookie: &Path, child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if cookie.is_file() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            bail!("Bitcoin Core exited before RPC startup with status {status}");
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("timed out waiting for isolated Bitcoin Core RPC cookie")
}

fn wait_for_rpc(rpc: &RpcClient, child: &mut Child) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if rpc.blockchain_info().is_ok() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            bail!("Bitcoin Core exited during RPC startup with status {status}");
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("timed out waiting for isolated Bitcoin Core RPC")
}

fn serialize_candidate_transaction(
    previous_txid: &str,
    previous_vout: u32,
    output_value: u64,
    output_script: &[u8],
    witness: &[Vec<u8>],
    tapscript: &[u8],
    control_block: &[u8],
) -> Result<Vec<u8>> {
    let mut txid = hex::decode(previous_txid).context("decode synthetic funding txid")?;
    if txid.len() != 32 {
        bail!("synthetic funding txid must be 32 bytes");
    }
    txid.reverse();

    let mut transaction = Vec::new();
    transaction.extend_from_slice(&2i32.to_le_bytes());
    transaction.extend_from_slice(&[0x00, 0x01]);
    transaction.push(1);
    transaction.extend_from_slice(&txid);
    transaction.extend_from_slice(&previous_vout.to_le_bytes());
    transaction.push(0);
    transaction.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    transaction.push(1);
    transaction.extend_from_slice(&output_value.to_le_bytes());
    write_compact_size(&mut transaction, output_script.len() as u64);
    transaction.extend_from_slice(output_script);
    write_compact_size(&mut transaction, (witness.len() + 2) as u64);
    for item in witness {
        write_compact_size(&mut transaction, item.len() as u64);
        transaction.extend_from_slice(item);
    }
    write_compact_size(&mut transaction, tapscript.len() as u64);
    transaction.extend_from_slice(tapscript);
    write_compact_size(&mut transaction, control_block.len() as u64);
    transaction.extend_from_slice(control_block);
    transaction.extend_from_slice(&0u32.to_le_bytes());
    Ok(transaction)
}

fn write_compact_size(output: &mut Vec<u8>, value: u64) {
    match value {
        0..=0xfc => output.push(value as u8),
        0xfd..=0xffff => {
            output.push(0xfd);
            output.extend_from_slice(&(value as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            output.push(0xfe);
            output.extend_from_slice(&(value as u32).to_le_bytes());
        }
        _ => {
            output.push(0xff);
            output.extend_from_slice(&value.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::{AnalysisStatus, analyze_script};

    #[test]
    fn serializes_a_single_input_tapscript_candidate() {
        let transaction = serialize_candidate_transaction(
            &"11".repeat(32),
            3,
            90_000,
            &[0x51, 0x20],
            &[vec![1], vec![]],
            &[0x51],
            &[0xc0; 33],
        )
        .unwrap();
        assert_eq!(&transaction[..6], &[2, 0, 0, 0, 0, 1]);
        assert_eq!(transaction[6], 1);
        assert_eq!(&transaction[7..39], &[0x11; 32]);
        assert_eq!(&transaction[transaction.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    #[ignore = "requires a locally installed Bitcoin Core executable"]
    fn bitcoin_core_confirms_the_motivating_signatureless_path() {
        let script = hex::decode(concat!(
            "20",
            "fa9b5ec193f735c41b804fc6ace1d28e81a299fc815c0f5009dd2dd7d0293c3b",
            "ac63",
            "20",
            "ff1275b635cd160914cfe1bc516f521abde0fc8ae3fd92ae01ca16449e4758e9",
            "68"
        ))
        .unwrap();
        let analysis = analyze_script(&script, 4);
        assert_eq!(analysis.status, AnalysisStatus::Weak);
        let witness = analysis
            .proof_witness
            .unwrap()
            .iter()
            .map(hex::decode)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let bitcoind = std::env::var_os("BITCOIND_PATH").unwrap_or_else(|| "bitcoind".into());
        let mut validator = CoreRegtestValidator::start(Path::new(&bitcoind)).unwrap();
        let evidence = validator.validate(&script, &witness).unwrap();
        assert_eq!(evidence.detection_status, DetectionStatus::ConfirmedWeak);
        assert_eq!(evidence.consensus_status, ConsensusStatus::ConfirmedValid);
        assert_eq!(evidence.policy_status, PolicyStatus::Accepted);
    }

    #[test]
    fn non_mandatory_rejection_keeps_consensus_valid() {
        let evidence = evidence_for_mempool_result(&MempoolAcceptResult {
            allowed: false,
            reject_reason: Some("non-mandatory-script-verify-flag (OP_SUCCESS80)".to_owned()),
        });
        assert_eq!(evidence.detection_status, DetectionStatus::PolicyRejected);
        assert_eq!(evidence.consensus_status, ConsensusStatus::ConfirmedValid);
        assert_eq!(evidence.policy_status, PolicyStatus::Rejected);
    }

    #[test]
    fn mandatory_rejection_is_consensus_invalid() {
        let evidence = evidence_for_mempool_result(&MempoolAcceptResult {
            allowed: false,
            reject_reason: Some(
                "mandatory-script-verify-flag-failed (Stack size must be exactly one after execution)"
                    .to_owned(),
            ),
        });
        assert_eq!(evidence.detection_status, DetectionStatus::ConsensusInvalid);
        assert_eq!(evidence.consensus_status, ConsensusStatus::Invalid);
        assert_eq!(evidence.policy_status, PolicyStatus::NotChecked);
    }

    #[test]
    fn generic_rejection_leaves_both_layers_inconclusive() {
        let evidence = evidence_for_mempool_result(&MempoolAcceptResult {
            allowed: false,
            reject_reason: Some("min relay fee not met".to_owned()),
        });
        assert_eq!(evidence.detection_status, DetectionStatus::CandidateWeak);
        assert_eq!(evidence.consensus_status, ConsensusStatus::Inconclusive);
        assert_eq!(evidence.policy_status, PolicyStatus::Inconclusive);
    }

    #[test]
    #[ignore = "requires a locally installed Bitcoin Core executable"]
    fn bitcoin_core_marks_op_success_policy_rejected() {
        let script = vec![0x50];
        let analysis = analyze_script(&script, 1);
        assert_eq!(analysis.status, AnalysisStatus::Weak);
        let witness = decoded_proof(&analysis);
        let bitcoind = std::env::var_os("BITCOIND_PATH").unwrap_or_else(|| "bitcoind".into());
        let mut validator = CoreRegtestValidator::start(Path::new(&bitcoind)).unwrap();
        let evidence = validator.validate(&script, &witness).unwrap();
        assert_eq!(evidence.detection_status, DetectionStatus::PolicyRejected);
        assert_eq!(evidence.consensus_status, ConsensusStatus::ConfirmedValid);
        assert_eq!(evidence.policy_status, PolicyStatus::Rejected);
    }

    #[test]
    #[ignore = "requires a locally installed Bitcoin Core executable"]
    fn bitcoin_core_marks_unknown_pubkey_policy_rejected() {
        let script = vec![0x51, 0xac];
        let analysis = analyze_script(&script, 1);
        assert_eq!(analysis.status, AnalysisStatus::Weak);
        assert_eq!(
            analysis.vulnerability_class.as_deref(),
            Some("upgradable_pubkey_type")
        );
        let witness = decoded_proof(&analysis);
        let bitcoind = std::env::var_os("BITCOIND_PATH").unwrap_or_else(|| "bitcoind".into());
        let mut validator = CoreRegtestValidator::start(Path::new(&bitcoind)).unwrap();
        let evidence = validator.validate(&script, &witness).unwrap();
        assert_eq!(
            evidence.detection_status,
            DetectionStatus::PolicyRejected,
            "{:?}",
            evidence.details
        );
        assert_eq!(evidence.consensus_status, ConsensusStatus::ConfirmedValid);
        assert_eq!(evidence.policy_status, PolicyStatus::Rejected);
    }

    fn decoded_proof(analysis: &crate::analyzer::AnalysisResult) -> Vec<Vec<u8>> {
        analysis
            .proof_witness
            .as_ref()
            .unwrap()
            .iter()
            .map(|item| hex::decode(item).unwrap())
            .collect()
    }
}
