use anyhow::Result;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionStatus {
    ConfirmedWeak,
    CandidateWeak,
    NoProofFound,
    Inconclusive,
    InvalidScript,
}

impl DetectionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfirmedWeak => "confirmed_weak",
            Self::CandidateWeak => "candidate_weak",
            Self::NoProofFound => "no_proof_found",
            Self::Inconclusive => "inconclusive",
            Self::InvalidScript => "invalid_script",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsensusStatus {
    ConfirmedValid,
    NotChecked,
    Inconclusive,
}

impl ConsensusStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfirmedValid => "confirmed_valid",
            Self::NotChecked => "not_checked",
            Self::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyStatus {
    Accepted,
    Inconclusive,
    NotChecked,
}

impl PolicyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Inconclusive => "inconclusive",
            Self::NotChecked => "not_checked",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidationEvidence {
    pub detection_status: DetectionStatus,
    pub consensus_status: ConsensusStatus,
    pub policy_status: PolicyStatus,
    pub validator: String,
    pub details: Option<String>,
}

impl ValidationEvidence {
    pub fn candidate_without_authoritative_validation() -> Self {
        Self {
            detection_status: DetectionStatus::CandidateWeak,
            consensus_status: ConsensusStatus::NotChecked,
            policy_status: PolicyStatus::NotChecked,
            validator: "none".to_owned(),
            details: Some(
                "Candidate produced by the bounded analyzer; Bitcoin Core validation was not requested"
                    .to_owned(),
            ),
        }
    }

    pub fn validation_failed(validator: &str, error: &anyhow::Error) -> Self {
        Self {
            detection_status: DetectionStatus::CandidateWeak,
            consensus_status: ConsensusStatus::Inconclusive,
            policy_status: PolicyStatus::NotChecked,
            validator: validator.to_owned(),
            details: Some(format!("Authoritative validation failed: {}", error)),
        }
    }
}

pub trait CandidateValidator {
    fn name(&self) -> &str;

    fn validate(&mut self, script: &[u8], witness: &[Vec<u8>]) -> Result<ValidationEvidence>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_states_have_stable_storage_names() {
        assert_eq!(DetectionStatus::ConfirmedWeak.as_str(), "confirmed_weak");
        assert_eq!(DetectionStatus::CandidateWeak.as_str(), "candidate_weak");
        assert_eq!(ConsensusStatus::ConfirmedValid.as_str(), "confirmed_valid");
        assert_eq!(PolicyStatus::Inconclusive.as_str(), "inconclusive");
    }
}
