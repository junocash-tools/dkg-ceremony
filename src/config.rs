use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::roster::{AssignedOperator, RosterError, RosterV1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Mainnet => "mainnet",
            Network::Testnet => "testnet",
            Network::Regtest => "regtest",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CeremonyConfigV1 {
    pub config_version: u32,
    pub ceremony_id: String,

    pub threshold: u16,
    pub max_signers: u16,
    pub network: Network,

    pub roster: RosterV1,
    pub roster_hash_hex: String,

    #[serde(default = "default_out_dir")]
    pub out_dir: PathBuf,

    #[serde(default = "default_transcript_dir")]
    pub transcript_dir: PathBuf,
}

fn default_out_dir() -> PathBuf {
    PathBuf::from("out")
}

fn default_transcript_dir() -> PathBuf {
    PathBuf::from("transcript")
}

#[derive(Debug, Clone)]
pub struct ValidatedCeremonyConfig {
    pub cfg: CeremonyConfigV1,
    pub canonical_operators: Vec<AssignedOperator>,
    pub ceremony_id_uuid: uuid::Uuid,
}

impl CeremonyConfigV1 {
    pub fn from_path(path: &Path) -> Result<Self, ConfigError> {
        let bytes = std::fs::read(path).map_err(|e| ConfigError::ReadFailed {
            path: path.to_path_buf(),
            source: e,
        })?;
        serde_json::from_slice(&bytes).map_err(|e| ConfigError::ParseFailed {
            path: path.to_path_buf(),
            source: e,
        })
    }

    pub fn validate(self) -> Result<ValidatedCeremonyConfig, ConfigError> {
        if self.config_version != 1 {
            return Err(ConfigError::ConfigVersionUnsupported(self.config_version));
        }

        let ceremony_id = self.ceremony_id.trim();
        if ceremony_id.is_empty() {
            return Err(ConfigError::CeremonyIdEmpty);
        }
        let ceremony_id_uuid =
            uuid::Uuid::parse_str(ceremony_id).map_err(|_| ConfigError::CeremonyIdInvalid)?;

        if !(1 < self.threshold && self.threshold <= self.max_signers) {
            return Err(ConfigError::ThresholdInvalid {
                threshold: self.threshold,
                max_signers: self.max_signers,
            });
        }

        let roster_hash = self
            .roster
            .roster_hash_hex()
            .map_err(ConfigError::Roster)?;
        if roster_hash != self.roster_hash_hex.trim() {
            return Err(ConfigError::RosterHashMismatch {
                expected: self.roster_hash_hex,
                got: roster_hash,
            });
        }

        let canonical_operators = self
            .roster
            .canonical_operators()
            .map_err(ConfigError::Roster)?;
        if canonical_operators.len() != self.max_signers as usize {
            return Err(ConfigError::MaxSignersMismatch {
                expected: self.max_signers,
                got: canonical_operators.len() as u16,
            });
        }

        Ok(ValidatedCeremonyConfig {
            cfg: CeremonyConfigV1 {
                ceremony_id: ceremony_id.to_string(),
                roster_hash_hex: self.roster_hash_hex.trim().to_string(),
                ..self
            },
            canonical_operators,
            ceremony_id_uuid,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("read_failed: {path}: {source}")]
    ReadFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse_failed: {path}: {source}")]
    ParseFailed {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("config_version_unsupported: {0}")]
    ConfigVersionUnsupported(u32),
    #[error("ceremony_id_empty")]
    CeremonyIdEmpty,
    #[error("ceremony_id_invalid")]
    CeremonyIdInvalid,
    #[error("threshold_invalid: threshold={threshold} max_signers={max_signers}")]
    ThresholdInvalid { threshold: u16, max_signers: u16 },
    #[error("max_signers_mismatch: expected={expected} got={got}")]
    MaxSignersMismatch { expected: u16, got: u16 },
    #[error("roster_hash_mismatch: expected={expected} got={got}")]
    RosterHashMismatch { expected: String, got: String },
    #[error("{0}")]
    Roster(#[from] RosterError),
}
