use ripemd::Ripemd160;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

pub const ANALYZER_VERSION: &str = concat!("tapscript-weak-finder/", env!("CARGO_PKG_VERSION"));
pub const SEARCH_WITNESS_ATOMS: &[&str] = &["empty", "01"];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisStatus {
    Weak,
    NoProofFound,
    Inconclusive,
    InvalidScript,
}

impl AnalysisStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Weak => "weak",
            Self::NoProofFound => "no_proof_found",
            Self::Inconclusive => "inconclusive",
            Self::InvalidScript => "invalid_script",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AnalysisResult {
    pub status: AnalysisStatus,
    pub vulnerability_class: Option<String>,
    pub proof_witness: Option<Vec<String>>,
    pub execution_trace: Vec<TraceStep>,
    pub valid_signatures_required: u32,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TraceStep {
    pub offset: usize,
    pub opcode: String,
    pub stack: Vec<String>,
}

#[derive(Clone, Debug)]
struct Instruction {
    offset: usize,
    opcode: u8,
    pushed: Option<Vec<u8>>,
}

enum ParseResult {
    Instructions(Vec<Instruction>),
    OpSuccess { offset: usize, opcode: u8 },
    Invalid,
}

enum RunResult {
    Success {
        trace: Vec<TraceStep>,
        unknown_pubkey_success: bool,
    },
    Failed,
    Unsupported,
}

pub fn analyze_script(script: &[u8], max_witness_items: usize) -> AnalysisResult {
    let parsed = parse_script(script);
    let instructions = match parsed {
        ParseResult::OpSuccess { offset, opcode } => {
            return AnalysisResult {
                status: AnalysisStatus::Weak,
                vulnerability_class: Some("op_success_unconditional".to_owned()),
                proof_witness: Some(Vec::new()),
                execution_trace: vec![TraceStep {
                    offset,
                    opcode: format!("OP_SUCCESS{}", opcode),
                    stack: Vec::new(),
                }],
                valid_signatures_required: 0,
                limitations: vec![
                    "Consensus-valid today but normally rejected by standard relay policy"
                        .to_owned(),
                    "Semantics may be restricted by a future soft fork".to_owned(),
                ],
            };
        }
        ParseResult::Invalid => {
            return AnalysisResult {
                status: AnalysisStatus::InvalidScript,
                vulnerability_class: None,
                proof_witness: None,
                execution_trace: Vec::new(),
                valid_signatures_required: 0,
                limitations: Vec::new(),
            };
        }
        ParseResult::Instructions(instructions) => instructions,
    };

    let max_items = max_witness_items.min(12);
    let mut saw_unsupported = false;
    for depth in 0..=max_items {
        let candidate_count = 1usize << depth;
        for mask in 0..candidate_count {
            let witness = (0..depth)
                .map(|index| {
                    if mask & (1 << index) == 0 {
                        Vec::new()
                    } else {
                        vec![1]
                    }
                })
                .collect::<Vec<_>>();
            match execute(&instructions, witness.clone()) {
                RunResult::Success {
                    trace,
                    unknown_pubkey_success,
                } => {
                    return AnalysisResult {
                        status: AnalysisStatus::Weak,
                        vulnerability_class: Some(
                            if unknown_pubkey_success {
                                "upgradable_pubkey_type"
                            } else {
                                "signatureless_satisfaction"
                            }
                            .to_owned(),
                        ),
                        proof_witness: Some(witness.iter().map(hex::encode).collect()),
                        execution_trace: trace,
                        valid_signatures_required: 0,
                        limitations: if unknown_pubkey_success {
                            vec![
                                "Consensus-valid today but normally rejected by standard relay policy"
                                    .to_owned(),
                                "Semantics may be restricted by a future soft fork".to_owned(),
                            ]
                        } else {
                            Vec::new()
                        },
                    };
                }
                RunResult::Unsupported => saw_unsupported = true,
                RunResult::Failed => {}
            }
        }
    }

    AnalysisResult {
        status: if saw_unsupported {
            AnalysisStatus::Inconclusive
        } else {
            AnalysisStatus::NoProofFound
        },
        vulnerability_class: None,
        proof_witness: None,
        execution_trace: Vec::new(),
        valid_signatures_required: 0,
        limitations: vec![format!(
            "Bounded search uses only empty and minimally true witness atoms, up to {max_items} items"
        )],
    }
}

fn parse_script(script: &[u8]) -> ParseResult {
    let mut instructions = Vec::new();
    let mut offset = 0;
    while offset < script.len() {
        let start = offset;
        let opcode = script[offset];
        offset += 1;
        if is_op_success(opcode) {
            return ParseResult::OpSuccess {
                offset: start,
                opcode,
            };
        }
        let push_len = match opcode {
            0x01..=0x4b => Some(opcode as usize),
            0x4c => {
                let Some(byte) = script.get(offset) else {
                    return ParseResult::Invalid;
                };
                offset += 1;
                Some(*byte as usize)
            }
            0x4d => {
                let Some(bytes) = script.get(offset..offset + 2) else {
                    return ParseResult::Invalid;
                };
                offset += 2;
                Some(u16::from_le_bytes([bytes[0], bytes[1]]) as usize)
            }
            0x4e => {
                let Some(bytes) = script.get(offset..offset + 4) else {
                    return ParseResult::Invalid;
                };
                offset += 4;
                let value = u32::from_le_bytes(bytes.try_into().expect("fixed slice"));
                let Ok(value) = usize::try_from(value) else {
                    return ParseResult::Invalid;
                };
                Some(value)
            }
            _ => None,
        };
        let pushed = if let Some(length) = push_len {
            let Some(data) = script.get(offset..offset.saturating_add(length)) else {
                return ParseResult::Invalid;
            };
            offset += length;
            Some(data.to_vec())
        } else {
            None
        };
        instructions.push(Instruction {
            offset: start,
            opcode,
            pushed,
        });
    }
    ParseResult::Instructions(instructions)
}

fn is_op_success(opcode: u8) -> bool {
    matches!(
        opcode,
        0x50
            | 0x62
            | 0x7e..=0x81
            | 0x83..=0x86
            | 0x89..=0x8a
            | 0x8d..=0x8e
            | 0x95..=0x99
            | 0xbb..=0xfe
    )
}

fn execute(instructions: &[Instruction], initial_stack: Vec<Vec<u8>>) -> RunResult {
    if initial_stack.len() > 1000 || initial_stack.iter().any(|item| item.len() > 520) {
        return RunResult::Failed;
    }
    let mut stack = initial_stack;
    let mut altstack = Vec::new();
    let mut conditions: Vec<bool> = Vec::new();
    let mut trace = Vec::new();
    let mut unknown_pubkey_success = false;

    for instruction in instructions {
        let executing = conditions.iter().all(|value| *value);
        let opcode = instruction.opcode;

        if matches!(opcode, 0x63 | 0x64) {
            if executing {
                let Some(value) = stack.pop() else {
                    return RunResult::Failed;
                };
                if !value.is_empty() && value.as_slice() != [1] {
                    return RunResult::Failed;
                }
                let condition = cast_to_bool(&value);
                conditions.push(if opcode == 0x64 {
                    !condition
                } else {
                    condition
                });
            } else {
                conditions.push(false);
            }
        } else if opcode == 0x67 {
            let parent_executing = conditions
                .iter()
                .take(conditions.len().saturating_sub(1))
                .all(|value| *value);
            let Some(last) = conditions.last_mut() else {
                return RunResult::Failed;
            };
            if parent_executing {
                *last = !*last;
            }
        } else if opcode == 0x68 {
            if conditions.pop().is_none() {
                return RunResult::Failed;
            }
        } else if executing {
            if let Some(pushed) = &instruction.pushed {
                if pushed.len() > 520 {
                    return RunResult::Failed;
                }
                stack.push(pushed.clone());
            } else {
                let outcome = execute_opcode(
                    opcode,
                    &mut stack,
                    &mut altstack,
                    &mut unknown_pubkey_success,
                );
                match outcome {
                    OpcodeResult::Continue => {}
                    OpcodeResult::Fail => return RunResult::Failed,
                    OpcodeResult::Unsupported => return RunResult::Unsupported,
                }
            }
        }

        if stack.len() + altstack.len() > 1000 {
            return RunResult::Failed;
        }
        trace.push(TraceStep {
            offset: instruction.offset,
            opcode: opcode_name(opcode),
            stack: stack.iter().map(short_hex).collect(),
        });
    }

    if !conditions.is_empty() {
        return RunResult::Failed;
    }
    if stack.len() == 1 && cast_to_bool(&stack[0]) {
        RunResult::Success {
            trace,
            unknown_pubkey_success,
        }
    } else {
        RunResult::Failed
    }
}

enum OpcodeResult {
    Continue,
    Fail,
    Unsupported,
}

fn execute_opcode(
    opcode: u8,
    stack: &mut Vec<Vec<u8>>,
    altstack: &mut Vec<Vec<u8>>,
    unknown_pubkey_success: &mut bool,
) -> OpcodeResult {
    macro_rules! pop {
        () => {
            match stack.pop() {
                Some(value) => value,
                None => return OpcodeResult::Fail,
            }
        };
    }
    macro_rules! number {
        () => {
            match decode_script_num(&pop!()) {
                Some(value) => value,
                None => return OpcodeResult::Fail,
            }
        };
    }

    match opcode {
        0x00 => stack.push(Vec::new()),
        0x4f => stack.push(encode_script_num(-1)),
        0x51..=0x60 => stack.push(encode_script_num((opcode - 0x50) as i64)),
        0x61 | 0xb0 | 0xb3..=0xb9 => {}
        0x69 => {
            if !cast_to_bool(&pop!()) {
                return OpcodeResult::Fail;
            }
        }
        0x6a | 0xae | 0xaf => return OpcodeResult::Fail,
        0x6b => {
            let value = pop!();
            altstack.push(value);
        }
        0x6c => {
            let Some(value) = altstack.pop() else {
                return OpcodeResult::Fail;
            };
            stack.push(value);
        }
        0x6d => {
            pop!();
            pop!();
        }
        0x6e => {
            if stack.len() < 2 {
                return OpcodeResult::Fail;
            }
            let len = stack.len();
            stack.extend_from_within(len - 2..len);
        }
        0x6f => {
            if stack.len() < 3 {
                return OpcodeResult::Fail;
            }
            let len = stack.len();
            stack.extend_from_within(len - 3..len);
        }
        0x70 => {
            if stack.len() < 4 {
                return OpcodeResult::Fail;
            }
            let len = stack.len();
            stack.push(stack[len - 4].clone());
            stack.push(stack[len - 3].clone());
        }
        0x71 => {
            if stack.len() < 6 {
                return OpcodeResult::Fail;
            }
            let len = stack.len();
            let values = stack.drain(len - 6..len - 4).collect::<Vec<_>>();
            stack.extend(values);
        }
        0x72 => {
            if stack.len() < 4 {
                return OpcodeResult::Fail;
            }
            let len = stack.len();
            stack.swap(len - 4, len - 2);
            stack.swap(len - 3, len - 1);
        }
        0x73 => {
            let Some(value) = stack.last().cloned() else {
                return OpcodeResult::Fail;
            };
            if cast_to_bool(&value) {
                stack.push(value);
            }
        }
        0x74 => stack.push(encode_script_num(stack.len() as i64)),
        0x75 => {
            pop!();
        }
        0x76 => {
            let Some(value) = stack.last().cloned() else {
                return OpcodeResult::Fail;
            };
            stack.push(value);
        }
        0x77 => {
            if stack.len() < 2 {
                return OpcodeResult::Fail;
            }
            let len = stack.len();
            stack.remove(len - 2);
        }
        0x78 => {
            if stack.len() < 2 {
                return OpcodeResult::Fail;
            }
            stack.push(stack[stack.len() - 2].clone());
        }
        0x79 | 0x7a => {
            let index = number!();
            let Ok(index) = usize::try_from(index) else {
                return OpcodeResult::Fail;
            };
            if index >= stack.len() {
                return OpcodeResult::Fail;
            }
            let position = stack.len() - 1 - index;
            let value = if opcode == 0x7a {
                stack.remove(position)
            } else {
                stack[position].clone()
            };
            stack.push(value);
        }
        0x7b => {
            if stack.len() < 3 {
                return OpcodeResult::Fail;
            }
            let len = stack.len();
            let value = stack.remove(len - 3);
            stack.push(value);
        }
        0x7c => {
            if stack.len() < 2 {
                return OpcodeResult::Fail;
            }
            let len = stack.len();
            stack.swap(len - 1, len - 2);
        }
        0x7d => {
            if stack.len() < 2 {
                return OpcodeResult::Fail;
            }
            let value = stack[stack.len() - 1].clone();
            let position = stack.len() - 2;
            stack.insert(position, value);
        }
        0x82 => {
            let Some(value) = stack.last() else {
                return OpcodeResult::Fail;
            };
            stack.push(encode_script_num(value.len() as i64));
        }
        0x87 | 0x88 => {
            let a = pop!();
            let b = pop!();
            let equal = a == b;
            if opcode == 0x88 {
                if !equal {
                    return OpcodeResult::Fail;
                }
            } else {
                stack.push(bool_bytes(equal));
            }
        }
        0x8b..=0x92 => {
            let value = number!();
            let result = match opcode {
                0x8b => value.checked_add(1),
                0x8c => value.checked_sub(1),
                0x8f => value.checked_neg(),
                0x90 => value.checked_abs(),
                0x91 => Some((value == 0) as i64),
                0x92 => Some((value != 0) as i64),
                _ => return OpcodeResult::Unsupported,
            };
            let Some(result) = result else {
                return OpcodeResult::Fail;
            };
            stack.push(encode_script_num(result));
        }
        0x93 | 0x94 | 0x9a..=0xa5 => {
            let b = number!();
            let a = number!();
            let result = match opcode {
                0x93 => a.checked_add(b),
                0x94 => a.checked_sub(b),
                0x9a => Some((a != 0 && b != 0) as i64),
                0x9b => Some((a != 0 || b != 0) as i64),
                0x9c | 0x9d => Some((a == b) as i64),
                0x9e => Some((a != b) as i64),
                0x9f => Some((a < b) as i64),
                0xa0 => Some((a > b) as i64),
                0xa1 => Some((a <= b) as i64),
                0xa2 => Some((a >= b) as i64),
                0xa3 => Some(a.min(b)),
                0xa4 => Some(a.max(b)),
                0xa5 => {
                    let max = b;
                    let min = a;
                    let x = number!();
                    Some((x >= min && x < max) as i64)
                }
                _ => None,
            };
            let Some(result) = result else {
                return OpcodeResult::Fail;
            };
            if opcode == 0x9d {
                if result == 0 {
                    return OpcodeResult::Fail;
                }
            } else {
                stack.push(encode_script_num(result));
            }
        }
        0xa6..=0xaa => {
            let value = pop!();
            let digest = match opcode {
                0xa6 => Ripemd160::digest(value).to_vec(),
                0xa7 => Sha1::digest(value).to_vec(),
                0xa8 => Sha256::digest(value).to_vec(),
                0xa9 => Ripemd160::digest(Sha256::digest(value)).to_vec(),
                0xaa => Sha256::digest(Sha256::digest(value)).to_vec(),
                _ => unreachable!(),
            };
            stack.push(digest);
        }
        0xab => {}
        0xac | 0xad => {
            let pubkey = pop!();
            let signature = pop!();
            let Some(success) = signature_result(&pubkey, &signature, unknown_pubkey_success)
            else {
                return OpcodeResult::Fail;
            };
            if opcode == 0xad {
                if !success {
                    return OpcodeResult::Fail;
                }
            } else {
                stack.push(bool_bytes(success));
            }
        }
        0xb1 | 0xb2 => return OpcodeResult::Unsupported,
        0xba => {
            let pubkey = pop!();
            let n = number!();
            let signature = pop!();
            let Some(success) = signature_result(&pubkey, &signature, unknown_pubkey_success)
            else {
                return OpcodeResult::Fail;
            };
            let Some(result) = n.checked_add(success as i64) else {
                return OpcodeResult::Fail;
            };
            stack.push(encode_script_num(result));
        }
        _ => return OpcodeResult::Unsupported,
    }
    OpcodeResult::Continue
}

fn signature_result(
    pubkey: &[u8],
    signature: &[u8],
    unknown_pubkey_success: &mut bool,
) -> Option<bool> {
    if pubkey.is_empty() {
        return None;
    }
    if signature.is_empty() {
        return Some(false);
    }
    if pubkey.len() == 32 {
        return None;
    }
    *unknown_pubkey_success = true;
    Some(true)
}

fn cast_to_bool(value: &[u8]) -> bool {
    for (index, byte) in value.iter().enumerate() {
        if *byte != 0 {
            return !(index == value.len() - 1 && *byte == 0x80);
        }
    }
    false
}

fn decode_script_num(value: &[u8]) -> Option<i64> {
    if value.len() > 4 {
        return None;
    }
    if value.is_empty() {
        return Some(0);
    }
    let mut result = 0u64;
    for (index, byte) in value.iter().enumerate() {
        result |= (*byte as u64) << (8 * index);
    }
    let negative = value.last().is_some_and(|byte| byte & 0x80 != 0);
    if negative {
        result &= !(0x80u64 << (8 * (value.len() - 1)));
    }
    let result = i64::try_from(result).ok()?;
    Some(if negative { -result } else { result })
}

fn encode_script_num(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let negative = value < 0;
    let mut absolute = value.unsigned_abs();
    let mut result = Vec::new();
    while absolute > 0 {
        result.push((absolute & 0xff) as u8);
        absolute >>= 8;
    }
    if result.last().is_some_and(|byte| byte & 0x80 != 0) {
        result.push(if negative { 0x80 } else { 0 });
    } else if negative {
        *result.last_mut().expect("non-empty") |= 0x80;
    }
    result
}

fn bool_bytes(value: bool) -> Vec<u8> {
    if value { vec![1] } else { Vec::new() }
}

fn short_hex(value: &Vec<u8>) -> String {
    if value.len() <= 16 {
        hex::encode(value)
    } else {
        format!("{}…({}b)", hex::encode(&value[..16]), value.len())
    }
}

fn opcode_name(opcode: u8) -> String {
    match opcode {
        0x00 => "OP_0".to_owned(),
        0x4f => "OP_1NEGATE".to_owned(),
        0x51..=0x60 => format!("OP_{}", opcode - 0x50),
        0x63 => "OP_IF".to_owned(),
        0x64 => "OP_NOTIF".to_owned(),
        0x67 => "OP_ELSE".to_owned(),
        0x68 => "OP_ENDIF".to_owned(),
        0x69 => "OP_VERIFY".to_owned(),
        0x75 => "OP_DROP".to_owned(),
        0x76 => "OP_DUP".to_owned(),
        0x87 => "OP_EQUAL".to_owned(),
        0x88 => "OP_EQUALVERIFY".to_owned(),
        0xa8 => "OP_SHA256".to_owned(),
        0xa9 => "OP_HASH160".to_owned(),
        0xac => "OP_CHECKSIG".to_owned(),
        0xad => "OP_CHECKSIGVERIFY".to_owned(),
        0xba => "OP_CHECKSIGADD".to_owned(),
        value if value <= 0x4e => "PUSHDATA".to_owned(),
        value => format!("OP_{value:02x}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_forum_case_minimal_proof() {
        let script = hex::decode(concat!(
            "20",
            "fa9b5ec193f735c41b804fc6ace1d28e81a299fc815c0f5009dd2dd7d0293c3b",
            "ac63",
            "20",
            "ff1275b635cd160914cfe1bc516f521abde0fc8ae3fd92ae01ca16449e4758e9",
            "68"
        ))
        .unwrap();
        let result = analyze_script(&script, 4);
        assert!(matches!(result.status, AnalysisStatus::Weak));
        assert_eq!(result.proof_witness.unwrap(), vec!["01", ""]);
        assert_eq!(result.valid_signatures_required, 0);
    }

    #[test]
    fn finds_fixed_mainnet_reveal_minimal_proof() {
        let script = hex::decode(concat!(
            "20",
            "fa9b5ec193f735c41b804fc6ace1d28e81a299fc815c0f5009dd2dd7d0293c3b",
            "ac63",
            "20",
            "51bb73b4a36470cca81fba01fb52a5706052e7240c8d51f4d8085feaa4230839",
            "68"
        ))
        .unwrap();

        let result = analyze_script(&script, 4);

        assert!(matches!(result.status, AnalysisStatus::Weak));
        assert_eq!(result.proof_witness.unwrap(), vec!["01", ""]);
        assert_eq!(result.valid_signatures_required, 0);
    }

    #[test]
    fn normal_checksig_has_no_signatureless_proof() {
        let script = hex::decode(format!("20{}ac", "11".repeat(32))).unwrap();
        let result = analyze_script(&script, 2);
        assert!(matches!(result.status, AnalysisStatus::NoProofFound));
    }

    #[test]
    fn op_success_is_detected_before_trailing_parse_error() {
        let result = analyze_script(&[0x50, 0x4c], 0);
        assert!(matches!(result.status, AnalysisStatus::Weak));
    }

    #[test]
    fn script_num_negative_zero_is_false() {
        assert!(!cast_to_bool(&[0x80]));
        assert!(cast_to_bool(&[0x01]));
    }
}
