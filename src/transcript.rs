use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::{CeremonyConfigV1, ValidatedCeremonyConfig};
use crate::hash;

const TRANSCRIPT_HASH_DOMAIN_V1: &[u8] = b"junocash_dkg_transcript_v1";

pub fn transcript_hash_hex_v1(
    ceremony_hash_hex: &str,
    max_signers: u16,
    round1_packages_by_sender: &BTreeMap<u16, Vec<u8>>,
    round2_hashes_by_sender_receiver: &BTreeMap<(u16, u16), [u8; 32]>,
) -> Result<String, TranscriptError> {
    Ok(hex::encode(transcript_hash_v1(
        ceremony_hash_hex,
        max_signers,
        round1_packages_by_sender,
        round2_hashes_by_sender_receiver,
    )?))
}

pub fn transcript_hash_v1(
    ceremony_hash_hex: &str,
    max_signers: u16,
    round1_packages_by_sender: &BTreeMap<u16, Vec<u8>>,
    round2_hashes_by_sender_receiver: &BTreeMap<(u16, u16), [u8; 32]>,
) -> Result<[u8; 32], TranscriptError> {
    let ceremony_hash_bytes =
        hex::decode(ceremony_hash_hex.trim()).map_err(|_| TranscriptError::CeremonyHashHexInvalid)?;
    if ceremony_hash_bytes.len() != 32 {
        return Err(TranscriptError::CeremonyHashLenInvalid(
            ceremony_hash_bytes.len(),
        ));
    }

    let mut buf = Vec::with_capacity(
        TRANSCRIPT_HASH_DOMAIN_V1.len()
            + ceremony_hash_bytes.len()
            + (max_signers as usize) * 32
            + (max_signers as usize) * ((max_signers as usize) - 1) * 32,
    );
    buf.extend_from_slice(TRANSCRIPT_HASH_DOMAIN_V1);
    buf.extend_from_slice(&ceremony_hash_bytes);

    for sender in 1..=max_signers {
        let r1 = round1_packages_by_sender
            .get(&sender)
            .ok_or(TranscriptError::Round1PackageMissing(sender))?;
        buf.extend_from_slice(&hash::sha256(r1));
    }

    for sender in 1..=max_signers {
        for receiver in 1..=max_signers {
            if receiver == sender {
                continue;
            }
            let h = round2_hashes_by_sender_receiver
                .get(&(sender, receiver))
                .ok_or(TranscriptError::Round2HashMissing { sender, receiver })?;
            buf.extend_from_slice(h);
        }
    }

    Ok(hash::sha256(&buf))
}

pub fn write_transcript_dir_v1(
    validated_cfg: &ValidatedCeremonyConfig,
    ceremony_hash_hex: &str,
    round1_packages_by_sender: &BTreeMap<u16, Vec<u8>>,
    round2_hashes_by_sender_receiver: &BTreeMap<(u16, u16), [u8; 32]>,
    public_key_package_hash: [u8; 32],
    ak_bytes: [u8; 32],
) -> Result<String, TranscriptError> {
    let dir = &validated_cfg.cfg.transcript_dir;
    ensure_dir(dir).map_err(|e| TranscriptError::TranscriptDirCreateFailed {
        path: dir.clone(),
        source: e,
    })?;

    // Copy the ceremony config into the transcript.
    let cfg_bytes = serde_json::to_vec_pretty(&validated_cfg.cfg).map_err(|_| TranscriptError::ConfigSerializeFailed)?;
    write_file(dir.join("config.json"), &cfg_bytes)
        .map_err(|e| TranscriptError::TranscriptWriteFailed {
            path: dir.join("config.json"),
            source: e,
        })?;

    write_file(dir.join("roster_hash.hex"), validated_cfg.cfg.roster_hash_hex.as_bytes())
        .map_err(|e| TranscriptError::TranscriptWriteFailed {
            path: dir.join("roster_hash.hex"),
            source: e,
        })?;
    write_file(dir.join("ceremony_hash.hex"), ceremony_hash_hex.as_bytes())
        .map_err(|e| TranscriptError::TranscriptWriteFailed {
            path: dir.join("ceremony_hash.hex"),
            source: e,
        })?;

    // Operators list (stable ordering).
    let ops = validated_cfg
        .canonical_operators
        .iter()
        .map(|o| TranscriptOperatorV1 {
            operator_id: o.operator_id.clone(),
            identifier: o.identifier.0,
        })
        .collect::<Vec<_>>();
    let ops_bytes = serde_json::to_vec_pretty(&ops).map_err(|_| TranscriptError::OperatorsSerializeFailed)?;
    write_file(dir.join("operators.json"), &ops_bytes)
        .map_err(|e| TranscriptError::TranscriptWriteFailed {
            path: dir.join("operators.json"),
            source: e,
        })?;

    for (sender, bytes) in round1_packages_by_sender {
        let p = dir.join(format!("round1_{sender}.bin"));
        write_file(p.clone(), bytes).map_err(|e| TranscriptError::TranscriptWriteFailed {
            path: p,
            source: e,
        })?;
    }

    let round2_entries = build_round2_hash_entries(
        validated_cfg.cfg.max_signers,
        round2_hashes_by_sender_receiver,
    )?;
    let round2_bytes =
        serde_json::to_vec_pretty(&round2_entries).map_err(|_| TranscriptError::Round2HashSerializeFailed)?;
    write_file(dir.join("round2_hashes.json"), &round2_bytes)
        .map_err(|e| TranscriptError::TranscriptWriteFailed {
            path: dir.join("round2_hashes.json"),
            source: e,
        })?;

    write_file(
        dir.join("public_key_package_hash.hex"),
        hex::encode(public_key_package_hash).as_bytes(),
    )
    .map_err(|e| TranscriptError::TranscriptWriteFailed {
        path: dir.join("public_key_package_hash.hex"),
        source: e,
    })?;
    write_file(dir.join("ak_bytes.hex"), hex::encode(ak_bytes).as_bytes()).map_err(|e| {
        TranscriptError::TranscriptWriteFailed {
            path: dir.join("ak_bytes.hex"),
            source: e,
        }
    })?;

    let transcript_hash_hex = transcript_hash_hex_v1(
        ceremony_hash_hex,
        validated_cfg.cfg.max_signers,
        round1_packages_by_sender,
        round2_hashes_by_sender_receiver,
    )?;

    write_file(dir.join("transcript_hash.hex"), transcript_hash_hex.as_bytes())
        .map_err(|e| TranscriptError::TranscriptWriteFailed {
            path: dir.join("transcript_hash.hex"),
            source: e,
        })?;

    Ok(transcript_hash_hex)
}

fn build_round2_hash_entries(
    max_signers: u16,
    round2_hashes_by_sender_receiver: &BTreeMap<(u16, u16), [u8; 32]>,
) -> Result<Vec<TranscriptRound2HashV1>, TranscriptError> {
    let mut out = Vec::with_capacity(max_signers as usize * (max_signers as usize - 1));
    for sender in 1..=max_signers {
        for receiver in 1..=max_signers {
            if receiver == sender {
                continue;
            }
            let h = round2_hashes_by_sender_receiver
                .get(&(sender, receiver))
                .ok_or(TranscriptError::Round2HashMissing { sender, receiver })?;
            out.push(TranscriptRound2HashV1 {
                sender_identifier: sender,
                receiver_identifier: receiver,
                package_hash_hex: hex::encode(h),
            });
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct TranscriptOperatorV1 {
    operator_id: String,
    identifier: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct TranscriptRound2HashV1 {
    sender_identifier: u16,
    receiver_identifier: u16,
    package_hash_hex: String,
}

fn ensure_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

fn write_file(path: PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

#[derive(Debug, thiserror::Error)]
pub enum TranscriptError {
    #[error("ceremony_hash_hex_invalid")]
    CeremonyHashHexInvalid,
    #[error("ceremony_hash_len_invalid: {0}")]
    CeremonyHashLenInvalid(usize),
    #[error("round1_package_missing: {0}")]
    Round1PackageMissing(u16),
    #[error("round2_hash_missing: sender={sender} receiver={receiver}")]
    Round2HashMissing { sender: u16, receiver: u16 },
    #[error("config_serialize_failed")]
    ConfigSerializeFailed,
    #[error("operators_serialize_failed")]
    OperatorsSerializeFailed,
    #[error("round2_hashes_serialize_failed")]
    Round2HashSerializeFailed,
    #[error("transcript_dir_create_failed: {path}: {source}")]
    TranscriptDirCreateFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("transcript_write_failed: {path}: {source}")]
    TranscriptWriteFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

// Ensures future changes are explicit about what gets committed to the roster hash.
#[allow(dead_code)]
fn _assert_transcript_has_config_fields(_cfg: &CeremonyConfigV1) {}

