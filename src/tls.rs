use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::ValidatedCeremonyConfig;

#[derive(Debug, Clone)]
pub struct TlsInitOptions {
    pub out_dir: PathBuf,
    pub coordinator_common_name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsInitOutput {
    pub material_version: u32,
    pub ca_cert_pem_path: PathBuf,
    pub ca_key_pem_path: PathBuf,
    pub coordinator_cert_pem_path: PathBuf,
    pub coordinator_key_pem_path: PathBuf,
    pub coordinator_cert_sha256_hex_path: PathBuf,
    pub coordinator_cert_sha256_hex: String,
    pub operators: Vec<OperatorTlsMaterialV1>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorTlsMaterialV1 {
    pub operator_id: String,
    pub identifier: u16,
    pub endpoint_host: String,
    pub server_cert_pem_path: PathBuf,
    pub server_key_pem_path: PathBuf,
}

pub fn init(validated_cfg: &ValidatedCeremonyConfig, opts: TlsInitOptions) -> anyhow::Result<TlsInitOutput> {
    std::fs::create_dir_all(&opts.out_dir)
        .with_context(|| format!("create {}", opts.out_dir.display()))?;

    let ca = make_ca()?;
    let ca_cert_path = opts.out_dir.join("ca.pem");
    let ca_key_path = opts.out_dir.join("ca.key");
    write_file(&ca_cert_path, ca.cert_pem.as_bytes())?;
    write_file(&ca_key_path, ca.key_pem.as_bytes())?;

    let coordinator = make_coordinator_client_cert(&ca, &opts.coordinator_common_name)?;
    let coordinator_cert_path = opts.out_dir.join("coordinator-client.pem");
    let coordinator_key_path = opts.out_dir.join("coordinator-client.key");
    write_file(&coordinator_cert_path, coordinator.cert_pem.as_bytes())?;
    write_file(&coordinator_key_path, coordinator.key_pem.as_bytes())?;

    let mut hasher = Sha256::new();
    hasher.update(&coordinator.cert_der);
    let coordinator_cert_sha256_hex = hex::encode(hasher.finalize());
    let coordinator_fingerprint_path = opts.out_dir.join("coordinator_client_cert_sha256.hex");
    write_file(
        &coordinator_fingerprint_path,
        format!("{coordinator_cert_sha256_hex}\n").as_bytes(),
    )?;

    let mut operators = Vec::with_capacity(validated_cfg.canonical_operators.len());
    for assigned in &validated_cfg.canonical_operators {
        let roster_op = validated_cfg
            .cfg
            .roster
            .operators
            .iter()
            .find(|o| o.operator_id.trim() == assigned.operator_id)
            .ok_or_else(|| anyhow!("operator_missing_in_roster: {}", assigned.operator_id))?;
        let endpoint = roster_op
            .grpc_endpoint
            .as_ref()
            .ok_or_else(|| anyhow!("grpc_endpoint_missing_for_operator: {}", assigned.operator_id))?;
        let endpoint_uri = endpoint
            .parse::<http::Uri>()
            .map_err(|e| anyhow!("endpoint_uri_parse_failed: {endpoint}: {e}"))?;
        let host = endpoint_uri
            .host()
            .ok_or_else(|| anyhow!("endpoint_host_missing: {endpoint}"))?;

        let server = make_operator_server_cert(&ca, host, &assigned.operator_id)?;
        let op_slug = sanitize_for_path(&assigned.operator_id);
        let op_dir = opts
            .out_dir
            .join("operators")
            .join(format!("{:02}_{}", assigned.identifier.0, op_slug));
        std::fs::create_dir_all(&op_dir)
            .with_context(|| format!("create {}", op_dir.display()))?;
        let cert_path = op_dir.join("server.pem");
        let key_path = op_dir.join("server.key");
        write_file(&cert_path, server.cert_pem.as_bytes())?;
        write_file(&key_path, server.key_pem.as_bytes())?;

        operators.push(OperatorTlsMaterialV1 {
            operator_id: assigned.operator_id.clone(),
            identifier: assigned.identifier.0,
            endpoint_host: host.to_string(),
            server_cert_pem_path: cert_path,
            server_key_pem_path: key_path,
        });
    }

    let out = TlsInitOutput {
        material_version: 1,
        ca_cert_pem_path: ca_cert_path,
        ca_key_pem_path: ca_key_path,
        coordinator_cert_pem_path: coordinator_cert_path,
        coordinator_key_pem_path: coordinator_key_path,
        coordinator_cert_sha256_hex_path: coordinator_fingerprint_path,
        coordinator_cert_sha256_hex,
        operators,
    };

    let inventory_path = opts.out_dir.join("tls_material.json");
    let inventory_bytes =
        serde_json::to_vec_pretty(&out).map_err(|_| anyhow!("tls_material_serialize_failed"))?;
    write_file(&inventory_path, &inventory_bytes)?;

    Ok(out)
}

struct SignedCert {
    cert_pem: String,
    key_pem: String,
    cert_der: Vec<u8>,
}

struct CertAuthority {
    cert: rcgen::Certificate,
    key: KeyPair,
    cert_pem: String,
    key_pem: String,
}

fn make_ca() -> anyhow::Result<CertAuthority> {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "junocash-dkg-ca");

    let ca_key = KeyPair::generate().context("ca_key_generate_failed")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("ca_cert_sign_failed")?;
    let ca_cert_pem = ca_cert.pem();
    let ca_key_pem = ca_key.serialize_pem();

    Ok(CertAuthority {
        cert: ca_cert,
        key: ca_key,
        cert_pem: ca_cert_pem,
        key_pem: ca_key_pem,
    })
}

fn make_coordinator_client_cert(ca: &CertAuthority, common_name: &str) -> anyhow::Result<SignedCert> {
    let mut params = CertificateParams::new(vec![common_name.to_string()])
        .map_err(|_| anyhow!("coordinator_params_invalid"))?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let key = KeyPair::generate().context("coordinator_key_generate_failed")?;
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .context("coordinator_cert_sign_failed")?;
    Ok(SignedCert {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert_der: cert.der().to_vec(),
    })
}

fn make_operator_server_cert(
    ca: &CertAuthority,
    endpoint_host: &str,
    operator_id: &str,
) -> anyhow::Result<SignedCert> {
    let mut params = CertificateParams::new(vec![endpoint_host.to_string()])
        .map_err(|_| anyhow!("operator_server_params_invalid"))?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params
        .distinguished_name
        .push(DnType::CommonName, format!("dkg-operator-{operator_id}"));
    let key = KeyPair::generate().context("operator_server_key_generate_failed")?;
    let cert = params
        .signed_by(&key, &ca.cert, &ca.key)
        .context("operator_server_cert_sign_failed")?;

    Ok(SignedCert {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
        cert_der: cert.der().to_vec(),
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))
}

fn sanitize_for_path(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "operator".to_string()
    } else {
        out
    }
}
