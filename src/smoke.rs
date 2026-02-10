use std::collections::BTreeMap;

use reddsa::frost::redpallas;

pub const SMOKE_MESSAGE_V1: &[u8] = b"junocash_dkg_smoke_test_v1";

pub fn alpha_bytes_standard() -> Vec<u8> {
    vec![]
}

pub fn alpha_bytes_randomized_fixed() -> Vec<u8> {
    // Deterministic, auditable alpha for the built-in smoke test.
    //
    // Use a non-zero value to exercise randomized verification key derivation.
    let alpha_scalar = pasta_curves::pallas::Scalar::one();
    let alpha = redpallas::Randomizer::from_scalar(alpha_scalar);
    alpha.serialize()
}

pub fn make_signing_package(
    commitments_by_signer: BTreeMap<u16, Vec<u8>>,
    message: &[u8],
) -> Result<Vec<u8>, SmokeError> {
    let mut commitments = BTreeMap::new();
    for (id_u16, bytes) in commitments_by_signer {
        let id: redpallas::Identifier = id_u16
            .try_into()
            .map_err(|_| SmokeError::IdentifierInvalid(id_u16))?;
        let c = redpallas::round1::SigningCommitments::deserialize(&bytes).map_err(SmokeError::Frost)?;
        commitments.insert(id, c);
    }
    let signing_package = redpallas::SigningPackage::new(commitments, message);
    signing_package.serialize().map_err(SmokeError::Frost)
}

pub fn aggregate_and_verify(
    public_key_package: &redpallas::keys::PublicKeyPackage,
    signing_package_bytes: &[u8],
    signature_shares_by_signer: BTreeMap<u16, Vec<u8>>,
    alpha_bytes: &[u8],
) -> Result<(), SmokeError> {
    let signing_package =
        redpallas::SigningPackage::deserialize(signing_package_bytes).map_err(SmokeError::Frost)?;

    let mut sig_shares = BTreeMap::new();
    for (id_u16, bytes) in signature_shares_by_signer {
        let id: redpallas::Identifier = id_u16
            .try_into()
            .map_err(|_| SmokeError::IdentifierInvalid(id_u16))?;
        let s =
            redpallas::round2::SignatureShare::deserialize(&bytes).map_err(SmokeError::Frost)?;
        sig_shares.insert(id, s);
    }

    let randomizer = parse_randomizer(alpha_bytes)?;
    let randomized_params =
        redpallas::RandomizedParams::from_randomizer(public_key_package.verifying_key(), randomizer);

    let sig =
        redpallas::aggregate(&signing_package, &sig_shares, public_key_package, &randomized_params)
            .map_err(SmokeError::Frost)?;

    randomized_params
        .randomized_verifying_key()
        .verify(signing_package.message(), &sig)
        .map_err(SmokeError::Frost)?;

    Ok(())
}

fn parse_randomizer(alpha_bytes: &[u8]) -> Result<redpallas::Randomizer, SmokeError> {
    if alpha_bytes.is_empty() {
        return redpallas::Randomizer::deserialize(&[0u8; 32]).map_err(SmokeError::Frost);
    }
    if alpha_bytes.len() != 32 {
        return Err(SmokeError::AlphaLenInvalid(alpha_bytes.len()));
    }
    redpallas::Randomizer::deserialize(alpha_bytes).map_err(SmokeError::Frost)
}

#[derive(Debug, thiserror::Error)]
pub enum SmokeError {
    #[error("identifier_invalid: {0}")]
    IdentifierInvalid(u16),
    #[error("alpha_len_invalid: {0}")]
    AlphaLenInvalid(usize),
    #[error("frost_error: {0}")]
    Frost(redpallas::Error),
}

