use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::{Network, ValidatedCeremonyConfig};

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeysetManifestV1 {
    pub manifest_version: u32,
    pub network: String,
    pub created_at: String,

    pub max_signers: u16,
    pub threshold: u16,

    pub operators: Vec<KeysetOperatorV1>,

    pub ak_bytes_hex: String,
    pub nk_bytes_hex: String,
    pub rivk_bytes_hex: String,
    pub orchard_fvk_bytes_hex: String,
    pub ufvk: String,
    pub owallet_ua: String,

    /// Stable bytes encoding of the `PublicKeyPackage` (base64).
    pub public_key_package: String,
    pub public_key_package_hash: String,

    pub transcript_hash: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KeysetOperatorV1 {
    pub operator_id: String,
    pub identifier: u16,
}

impl KeysetManifestV1 {
    pub fn output_path(out_dir: &Path) -> PathBuf {
        out_dir.join("KeysetManifest.json")
    }

    pub fn write_to_path(&self, path: &Path) -> Result<(), std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(path, bytes)
    }
}

pub fn network_str(network: Network) -> String {
    match network {
        Network::Mainnet => "mainnet".to_string(),
        Network::Testnet => "testnet".to_string(),
        Network::Regtest => "regtest".to_string(),
    }
}

pub fn operators_from_config(validated_cfg: &ValidatedCeremonyConfig) -> Vec<KeysetOperatorV1> {
    validated_cfg
        .canonical_operators
        .iter()
        .map(|o| KeysetOperatorV1 {
            operator_id: o.operator_id.clone(),
            identifier: o.identifier.0,
        })
        .collect()
}
