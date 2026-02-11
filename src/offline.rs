use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use base64::Engine as _;
use reddsa::frost::redpallas;
use time::format_description::well_known::Rfc3339;

use crate::ceremony_hash::ceremony_hash_hex_v1;
use crate::config::ValidatedCeremonyConfig;
use crate::crypto;
use crate::derive;
use crate::manifest::{self, KeysetManifestV1};
use crate::transcript;
use crate::zip316;

pub struct OfflineFinalizeOutput {
    pub manifest_path: PathBuf,
    pub transcript_dir: PathBuf,
}

/// Stage 1 (offline): bundle Round 1 packages for delivery to each operator.
///
/// Input: `round1_dir` containing `round1_<id>.bin` for all participants.
/// Output: `deliver_dir/round1_to_<id>/round1_<sender>.bin` for each recipient.
pub fn bundle_round1(
    validated_cfg: &ValidatedCeremonyConfig,
    round1_dir: &Path,
    deliver_dir: &Path,
) -> anyhow::Result<()> {
    let round1 = read_round1_dir_all(validated_cfg.cfg.max_signers, round1_dir)?;

    for receiver in 1..=validated_cfg.cfg.max_signers {
        let out_dir = deliver_dir.join(format!("round1_to_{receiver}"));
        std::fs::create_dir_all(&out_dir)
            .with_context(|| format!("create {}", out_dir.display()))?;

        for sender in 1..=validated_cfg.cfg.max_signers {
            if sender == receiver {
                continue;
            }
            let bytes = round1
                .get(&sender)
                .ok_or_else(|| anyhow!("round1_missing_sender: {sender}"))?;
            let path = out_dir.join(format!("round1_{sender}.bin"));
            std::fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
        }
    }

    Ok(())
}

/// Stage 2 (offline): bundle Round 2 encrypted packages for delivery to each operator.
///
/// Input: `round2_dir` containing all `round2_to_<recv>_from_<sender>.age` files.
/// Output: `deliver_dir/round2_to_<id>/round2_to_<id>_from_<sender>.age` for each recipient.
pub fn bundle_round2(
    validated_cfg: &ValidatedCeremonyConfig,
    round2_dir: &Path,
    deliver_dir: &Path,
) -> anyhow::Result<()> {
    let round2 = read_round2_dir_all(validated_cfg.cfg.max_signers, round2_dir)?;

    // Copy files into per-recipient delivery directories.
    for ((sender, receiver), ct) in &round2 {
        let out_dir = deliver_dir.join(format!("round2_to_{receiver}"));
        std::fs::create_dir_all(&out_dir)
            .with_context(|| format!("create {}", out_dir.display()))?;

        let path = out_dir.join(format!("round2_to_{receiver}_from_{sender}.age"));
        std::fs::write(&path, ct).with_context(|| format!("write {}", path.display()))?;
    }

    Ok(())
}

/// Offline finalization: compute and write the public manifest and non-secret transcript.
///
/// This reconstructs the public key package from the Round 1 commitments and commits to
/// the hashes of all Round 2 package bytes provided to the coordinator.
pub fn finalize(
    validated_cfg: ValidatedCeremonyConfig,
    round1_dir: &Path,
    round2_dir: &Path,
) -> anyhow::Result<OfflineFinalizeOutput> {
    let ceremony_hash = ceremony_hash_hex_v1(
        validated_cfg.cfg.network,
        validated_cfg.cfg.threshold,
        validated_cfg.cfg.max_signers,
        &validated_cfg.cfg.roster_hash_hex,
        &validated_cfg.ceremony_id_uuid,
    )
    .context("ceremony_hash")?;

    let round1_by_sender = read_round1_dir_all(validated_cfg.cfg.max_signers, round1_dir)?;
    let round2_ct = read_round2_dir_all(validated_cfg.cfg.max_signers, round2_dir)?;

    // Hash all Round 2 bytes (ciphertext in offline mode).
    let mut round2_hashes_by_sender_receiver = BTreeMap::<(u16, u16), [u8; 32]>::new();
    for ((sender, receiver), bytes) in &round2_ct {
        round2_hashes_by_sender_receiver.insert((*sender, *receiver), crate::hash::sha256(bytes));
    }

    // Reconstruct PublicKeyPackage from Round 1 commitments.
    let public_key_package = public_key_package_from_round1(
        validated_cfg.cfg.max_signers,
        validated_cfg.cfg.threshold,
        &round1_by_sender,
    )?;
    let public_key_package = crypto::canonicalize_public_key_package(public_key_package);

    let public_key_package_bytes = public_key_package
        .serialize()
        .map_err(|e| anyhow!("public_key_package_serialize_failed: {e}"))?;

    let ak_bytes = crypto::ak_bytes_from_public_key_package(&public_key_package)
        .map_err(|e| anyhow!(e))?;
    if !crypto::is_canonical_ak_bytes(&ak_bytes) {
        return Err(anyhow!("ak_bytes_non_canonical"));
    }

    let pk_hash = crypto::public_key_package_hash(&public_key_package, validated_cfg.cfg.max_signers)
        .map_err(|e| anyhow!(e))?;

    // Derive Orchard viewing keys deterministically from ak_bytes.
    let derived = derive::derive_nk_rivk_from_ak_bytes(&ak_bytes);
    let mut orchard_fvk_bytes = [0u8; 96];
    orchard_fvk_bytes[0..32].copy_from_slice(&ak_bytes);
    orchard_fvk_bytes[32..64].copy_from_slice(&derived.nk_bytes);
    orchard_fvk_bytes[64..96].copy_from_slice(&derived.rivk_bytes);

    let fvk = orchard::keys::FullViewingKey::from_bytes(&orchard_fvk_bytes)
        .ok_or_else(|| anyhow!("orchard_fvk_invalid"))?;

    let ufvk = zip316::encode_ufvk_orchard(validated_cfg.cfg.network, orchard_fvk_bytes)
        .map_err(|e| anyhow!(e))?;

    let oaddr = fvk.address_at(0u32, orchard::keys::Scope::External);
    let owallet_ua =
        zip316::encode_ua_orchard(validated_cfg.cfg.network, oaddr.to_raw_address_bytes())
            .map_err(|e| anyhow!(e))?;

    let transcript_hash = transcript::write_transcript_dir_v1(
        &validated_cfg,
        &ceremony_hash,
        &round1_by_sender,
        &round2_hashes_by_sender_receiver,
        pk_hash,
        ak_bytes,
    )
    .map_err(|e| anyhow!(e))?;

    let created_at = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|e| anyhow!("created_at_format_failed: {e}"))?;

    let manifest = KeysetManifestV1 {
        manifest_version: 1,
        network: manifest::network_str(validated_cfg.cfg.network),
        created_at,
        max_signers: validated_cfg.cfg.max_signers,
        threshold: validated_cfg.cfg.threshold,
        operators: manifest::operators_from_config(&validated_cfg),
        ak_bytes_hex: hex::encode(ak_bytes),
        nk_bytes_hex: hex::encode(derived.nk_bytes),
        rivk_bytes_hex: hex::encode(derived.rivk_bytes),
        orchard_fvk_bytes_hex: hex::encode(orchard_fvk_bytes),
        ufvk,
        owallet_ua,
        public_key_package: base64::engine::general_purpose::STANDARD.encode(&public_key_package_bytes),
        public_key_package_hash: hex::encode(pk_hash),
        transcript_hash,
    };

    let manifest_path = KeysetManifestV1::output_path(&validated_cfg.cfg.out_dir);
    manifest
        .write_to_path(&manifest_path)
        .with_context(|| format!("write {}", manifest_path.display()))?;

    Ok(OfflineFinalizeOutput {
        manifest_path,
        transcript_dir: validated_cfg.cfg.transcript_dir,
    })
}

fn read_round1_dir_all(max_signers: u16, round1_dir: &Path) -> anyhow::Result<BTreeMap<u16, Vec<u8>>> {
    let mut map = BTreeMap::<u16, Vec<u8>>::new();
    for entry in std::fs::read_dir(round1_dir).with_context(|| format!("read_dir {}", round1_dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("round1_") || !name.ends_with(".bin") {
            continue;
        }
        let id_str = name.trim_start_matches("round1_").trim_end_matches(".bin");
        let id: u16 = id_str.parse().context("parse round1 id")?;
        if id == 0 || id > max_signers {
            return Err(anyhow!("round1_sender_identifier_out_of_range: {id}"));
        }
        let bytes = std::fs::read(entry.path())
            .with_context(|| format!("read {}", entry.path().display()))?;
        map.insert(id, bytes);
    }
    for id in 1..=max_signers {
        if !map.contains_key(&id) {
            return Err(anyhow!("round1_dir_incomplete: missing={id}"));
        }
    }
    Ok(map)
}

fn read_round2_dir_all(
    max_signers: u16,
    round2_dir: &Path,
) -> anyhow::Result<BTreeMap<(u16, u16), Vec<u8>>> {
    let mut map = BTreeMap::<(u16, u16), Vec<u8>>::new();
    for entry in std::fs::read_dir(round2_dir).with_context(|| format!("read_dir {}", round2_dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("round2_to_") || !name.ends_with(".age") {
            continue;
        }
        // round2_to_<recv>_from_<sender>.age
        let name = name.trim_end_matches(".age");
        let rest = name.strip_prefix("round2_to_").unwrap_or("");
        let parts: Vec<&str> = rest.split("_from_").collect();
        if parts.len() != 2 {
            continue;
        }
        let receiver: u16 = parts[0].parse().context("parse round2 recv")?;
        let sender: u16 = parts[1].parse().context("parse round2 sender")?;
        if receiver == 0 || receiver > max_signers {
            return Err(anyhow!("round2_receiver_identifier_out_of_range: {receiver}"));
        }
        if sender == 0 || sender > max_signers || sender == receiver {
            return Err(anyhow!("round2_sender_identifier_invalid: {sender}"));
        }
        let bytes = std::fs::read(entry.path())
            .with_context(|| format!("read {}", entry.path().display()))?;
        if map.insert((sender, receiver), bytes).is_some() {
            return Err(anyhow!("round2_duplicate: sender={sender} receiver={receiver}"));
        }
    }

    let expected = (max_signers as usize) * ((max_signers as usize) - 1);
    if map.len() != expected {
        return Err(anyhow!("round2_dir_incomplete: expected={expected} got={}", map.len()));
    }

    Ok(map)
}

fn public_key_package_from_round1(
    max_signers: u16,
    threshold: u16,
    round1_by_sender: &BTreeMap<u16, Vec<u8>>,
) -> anyhow::Result<redpallas::keys::PublicKeyPackage> {
    // Parse all packages and collect commitments.
    let mut commitments_owned = BTreeMap::<redpallas::Identifier, redpallas::keys::VerifiableSecretSharingCommitment>::new();
    let mut ids = BTreeSet::<redpallas::Identifier>::new();

    for sender_u16 in 1..=max_signers {
        let bytes = round1_by_sender
            .get(&sender_u16)
            .ok_or_else(|| anyhow!("round1_missing_sender: {sender_u16}"))?;
        let pkg = redpallas::keys::dkg::round1::Package::deserialize(bytes)
            .map_err(|e| anyhow!("round1_deserialize_failed: sender={sender_u16}: {e}"))?;

        // Basic sanity: commitment length matches threshold.
        if pkg.commitment().coefficients().len() != threshold as usize {
            return Err(anyhow!("round1_commitment_len_invalid: sender={sender_u16}"));
        }

        let sender: redpallas::Identifier = sender_u16
            .try_into()
            .map_err(|_| anyhow!("sender_identifier_invalid: {sender_u16}"))?;
        ids.insert(sender);
        commitments_owned.insert(sender, pkg.commitment().clone());
    }

    let commitments_ref: BTreeMap<_, _> = commitments_owned.iter().map(|(id, c)| (*id, c)).collect();
    redpallas::keys::PublicKeyPackage::from_dkg_commitments(&commitments_ref)
        .map_err(|e| anyhow!("public_key_package_from_commitments_failed: {e}"))
}
