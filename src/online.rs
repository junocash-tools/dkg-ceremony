use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use base64::Engine as _;
use reddsa::frost::redpallas;
use time::format_description::well_known::Rfc3339;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use zeroize::Zeroize;

use crate::ceremony_hash::ceremony_hash_hex_v1;
use crate::config::ValidatedCeremonyConfig;
use crate::crypto;
use crate::derive;
use crate::manifest::{self, KeysetManifestV1};
use crate::proto::v1 as pb;
use crate::smoke;
use crate::transcript;
use crate::zip316;

#[derive(Debug, Clone)]
pub struct OnlineTlsConfig {
    pub tls_ca_cert_pem_path: PathBuf,
    pub tls_client_cert_pem_path: PathBuf,
    pub tls_client_key_pem_path: PathBuf,

    /// Optional override for TLS domain name / SNI.
    pub tls_domain_name_override: Option<String>,

    /// gRPC connect timeout.
    pub connect_timeout: Duration,

    /// Per-RPC timeout.
    pub rpc_timeout: Duration,
}

impl Default for OnlineTlsConfig {
    fn default() -> Self {
        Self {
            tls_ca_cert_pem_path: PathBuf::from("ca.pem"),
            tls_client_cert_pem_path: PathBuf::from("client.pem"),
            tls_client_key_pem_path: PathBuf::from("client.key"),
            tls_domain_name_override: None,
            connect_timeout: Duration::from_secs(10),
            rpc_timeout: Duration::from_secs(30),
        }
    }
}

pub struct OnlineRunOutput {
    pub manifest_path: PathBuf,
    pub transcript_dir: PathBuf,
}

pub async fn run(validated_cfg: ValidatedCeremonyConfig, tls: OnlineTlsConfig) -> anyhow::Result<OnlineRunOutput> {
    let ceremony_hash = ceremony_hash_hex_v1(
        validated_cfg.cfg.network,
        validated_cfg.cfg.threshold,
        validated_cfg.cfg.max_signers,
        &validated_cfg.cfg.roster_hash_hex,
    )
    .context("ceremony_hash")?;

    let tls_material = load_tls_material(&tls).await?;

    let roster_ops = &validated_cfg.cfg.roster.operators;
    let mut clients = vec![];
    for op in &validated_cfg.canonical_operators {
        let roster_op = roster_ops
            .iter()
            .find(|o| o.operator_id.trim() == op.operator_id)
            .ok_or_else(|| anyhow!("operator_missing_in_roster: {}", op.operator_id))?;
        let grpc_endpoint = roster_op
            .grpc_endpoint
            .clone()
            .ok_or_else(|| anyhow!("grpc_endpoint_missing_for_operator: {}", op.operator_id))?;
        let client = connect_admin(&grpc_endpoint, &tls, &tls_material).await?;
        clients.push(OperatorClient {
            operator_id: op.operator_id.clone(),
            identifier: op.identifier.0,
            client,
        });
    }

    // Round 1: fetch packages (public).
    let mut round1_by_sender = BTreeMap::<u16, Vec<u8>>::new();
    for op in clients.iter_mut() {
        let resp = op
            .client
            .get_round1_package(with_timeout(
                tls.rpc_timeout,
                pb::GetRound1PackageRequest {
                    ceremony_hash: ceremony_hash.clone(),
                },
            ))
            .await
            .with_context(|| format!("get_round1_package: {}", op.operator_id))?
            .into_inner();

        if resp.round1_package_hash.len() != 32 {
            return Err(anyhow!("round1_package_hash_len_invalid: {}", op.operator_id));
        }
        let got_hash = crate::hash::sha256(&resp.round1_package);
        if got_hash.as_slice() != resp.round1_package_hash.as_slice() {
            return Err(anyhow!("round1_package_hash_mismatch: {}", op.operator_id));
        }

        round1_by_sender.insert(op.identifier, resp.round1_package);
    }

    // Round 2: ask each participant to compute all encrypted shares for others, then route them.
    //
    // Confidential: we never persist these bytes, only their hashes.
    let mut round2_by_receiver = BTreeMap::<u16, Vec<pb::Round2PackageToMe>>::new();
    let mut round2_hashes_by_sender_receiver = BTreeMap::<(u16, u16), [u8; 32]>::new();
    for op in clients.iter_mut() {
        let mut r1_pkgs = Vec::with_capacity((validated_cfg.cfg.max_signers - 1) as usize);
        for (sender_id, sender_bytes) in &round1_by_sender {
            if *sender_id == op.identifier {
                continue;
            }
            r1_pkgs.push(pb::Round1Package {
                sender_identifier: *sender_id as u32,
                package: sender_bytes.clone(),
                package_hash: crate::hash::sha256(sender_bytes).to_vec(),
            });
        }

        let resp = op
            .client
            .part2(with_timeout(
                tls.rpc_timeout,
                pb::Part2Request {
                    ceremony_hash: ceremony_hash.clone(),
                    round1_packages: r1_pkgs,
                },
            ))
            .await
            .with_context(|| format!("part2: {}", op.operator_id))?
            .into_inner();

        // Validate and route.
        let mut seen = std::collections::BTreeSet::<u16>::new();
        for mut out in resp.round2_packages {
            let receiver: u16 = out
                .receiver_identifier
                .try_into()
                .map_err(|_| anyhow!("round2_receiver_identifier_invalid: {}", out.receiver_identifier))?;
            if receiver == 0 || receiver > validated_cfg.cfg.max_signers {
                return Err(anyhow!("round2_receiver_identifier_out_of_range: {receiver}"));
            }
            if receiver == op.identifier {
                return Err(anyhow!("round2_receiver_is_sender_self: {}", op.operator_id));
            }
            if !seen.insert(receiver) {
                return Err(anyhow!("round2_receiver_duplicate: sender={}", op.operator_id));
            }

            if out.package_hash.len() != 32 {
                return Err(anyhow!("round2_package_hash_len_invalid: sender={}", op.operator_id));
            }
            let got_hash = crate::hash::sha256(&out.package);
            if got_hash.as_slice() != out.package_hash.as_slice() {
                return Err(anyhow!("round2_package_hash_mismatch: sender={}", op.operator_id));
            }

            round2_hashes_by_sender_receiver.insert((op.identifier, receiver), got_hash);

            // Route to recipient.
            let entry = round2_by_receiver.entry(receiver).or_default();
            entry.push(pb::Round2PackageToMe {
                sender_identifier: op.identifier as u32,
                package: std::mem::take(&mut out.package),
                package_hash: std::mem::take(&mut out.package_hash),
            });

            // Best-effort: clear the temporary response buffer.
            out.package.zeroize();
            out.package_hash.zeroize();
        }

        for recv in 1..=validated_cfg.cfg.max_signers {
            if recv == op.identifier {
                continue;
            }
            if !seen.contains(&recv) {
                return Err(anyhow!("round2_package_missing_receiver: sender={} recv={recv}", op.operator_id));
            }
        }
    }

    // Round 3: finalize for each participant, verifying consistent public output.
    let mut public_key_package_bytes: Option<Vec<u8>> = None;
    let mut public_key_package_hash: Option<[u8; 32]> = None;
    let mut ak_bytes: Option<[u8; 32]> = None;

    for op in clients.iter_mut() {
        let mut r1_pkgs = Vec::with_capacity((validated_cfg.cfg.max_signers - 1) as usize);
        for (sender_id, sender_bytes) in &round1_by_sender {
            if *sender_id == op.identifier {
                continue;
            }
            r1_pkgs.push(pb::Round1Package {
                sender_identifier: *sender_id as u32,
                package: sender_bytes.clone(),
                package_hash: crate::hash::sha256(sender_bytes).to_vec(),
            });
        }

        let r2_pkgs = round2_by_receiver
            .remove(&op.identifier)
            .ok_or_else(|| anyhow!("round2_packages_missing_for_receiver: {}", op.operator_id))?;

        let resp = op
            .client
            .part3(with_timeout(
                tls.rpc_timeout,
                pb::Part3Request {
                    ceremony_hash: ceremony_hash.clone(),
                    round1_packages: r1_pkgs,
                    round2_packages: r2_pkgs,
                },
            ))
            .await
            .with_context(|| format!("part3: {}", op.operator_id))?
            .into_inner();

        if resp.public_key_package_hash.len() != 32 {
            return Err(anyhow!("public_key_package_hash_len_invalid: {}", op.operator_id));
        }
        if resp.ak_bytes.len() != 32 {
            return Err(anyhow!("ak_bytes_len_invalid: {}", op.operator_id));
        }

        let pk_hash: [u8; 32] = resp
            .public_key_package_hash
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("public_key_package_hash_len_invalid: {}", op.operator_id))?;
        let ak: [u8; 32] = resp
            .ak_bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("ak_bytes_len_invalid: {}", op.operator_id))?;

        if !crypto::is_canonical_ak_bytes(&ak) {
            return Err(anyhow!("ak_bytes_non_canonical: {}", op.operator_id));
        }

        if let Some(prev) = public_key_package_hash {
            if prev != pk_hash {
                return Err(anyhow!("public_key_package_hash_mismatch: {}", op.operator_id));
            }
        } else {
            public_key_package_hash = Some(pk_hash);
        }

        if let Some(prev) = ak_bytes {
            if prev != ak {
                return Err(anyhow!("ak_bytes_mismatch: {}", op.operator_id));
            }
        } else {
            ak_bytes = Some(ak);
        }

        if let Some(prev) = &public_key_package_bytes {
            if *prev != resp.public_key_package {
                return Err(anyhow!("public_key_package_bytes_mismatch: {}", op.operator_id));
            }
        } else {
            public_key_package_bytes = Some(resp.public_key_package);
        }
    }

    let public_key_package_bytes =
        public_key_package_bytes.ok_or_else(|| anyhow!("public_key_package_missing"))?;
    let mut public_key_package =
        redpallas::keys::PublicKeyPackage::deserialize(&public_key_package_bytes)
            .map_err(|e| anyhow!("public_key_package_deserialize_failed: {e}"))?;
    public_key_package = crypto::canonicalize_public_key_package(public_key_package);
    let public_key_package_bytes = public_key_package
        .serialize()
        .map_err(|e| anyhow!("public_key_package_serialize_failed: {e}"))?;

    let ak_bytes =
        crypto::ak_bytes_from_public_key_package(&public_key_package).map_err(|e| anyhow!(e))?;
    if !crypto::is_canonical_ak_bytes(&ak_bytes) {
        return Err(anyhow!("ak_bytes_non_canonical_after_canonicalization"));
    }

    let pk_hash = crypto::public_key_package_hash(&public_key_package, validated_cfg.cfg.max_signers)
        .map_err(|e| anyhow!(e))?;
    if let Some(prev) = public_key_package_hash {
        if prev != pk_hash {
            return Err(anyhow!("public_key_package_hash_inconsistent"));
        }
    }

    // Smoke test (standard + randomized) using live gRPC signers.
    run_smoke_tests_online(&mut clients, &ceremony_hash, &public_key_package).await?;

    // Derive Orchard viewing keys deterministically from ak_bytes.
    let derived = derive::derive_nk_rivk_from_ak_bytes(&ak_bytes);
    let mut orchard_fvk_bytes = [0u8; 96];
    orchard_fvk_bytes[0..32].copy_from_slice(&ak_bytes);
    orchard_fvk_bytes[32..64].copy_from_slice(&derived.nk_bytes);
    orchard_fvk_bytes[64..96].copy_from_slice(&derived.rivk_bytes);

    let _fvk = orchard::keys::FullViewingKey::from_bytes(&orchard_fvk_bytes)
        .ok_or_else(|| anyhow!("orchard_fvk_invalid"))?;

    let ufvk = zip316::encode_ufvk_orchard(validated_cfg.cfg.network, orchard_fvk_bytes)
        .map_err(|e| anyhow!(e))?;

    let oaddr = _fvk.address_at(0u32, orchard::keys::Scope::External);
    let owallet_ua = zip316::encode_ua_orchard(validated_cfg.cfg.network, oaddr.to_raw_address_bytes())
        .map_err(|e| anyhow!(e))?;

    // Write transcript + manifest.
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

    Ok(OnlineRunOutput {
        manifest_path,
        transcript_dir: validated_cfg.cfg.transcript_dir,
    })
}

async fn run_smoke_tests_online(
    clients: &mut [OperatorClient],
    ceremony_hash: &str,
    public_key_package: &redpallas::keys::PublicKeyPackage,
) -> anyhow::Result<()> {
    // Standard signing.
    smoke_sign_round(clients, ceremony_hash, public_key_package, smoke::SMOKE_MESSAGE_V1, &smoke::alpha_bytes_standard())
        .await
        .context("smoke_standard")?;

    // Randomized signing with deterministic alpha.
    let alpha = smoke::alpha_bytes_randomized_fixed();
    smoke_sign_round(clients, ceremony_hash, public_key_package, smoke::SMOKE_MESSAGE_V1, &alpha)
        .await
        .context("smoke_randomized")?;

    Ok(())
}

async fn smoke_sign_round(
    clients: &mut [OperatorClient],
    ceremony_hash: &str,
    public_key_package: &redpallas::keys::PublicKeyPackage,
    message: &[u8],
    alpha: &[u8],
) -> anyhow::Result<()> {
    let mut commitments = BTreeMap::<u16, Vec<u8>>::new();
    for op in clients.iter_mut() {
        let resp = op
            .client
            .smoke_sign_commit(with_timeout(
                Duration::from_secs(30),
                pb::SmokeSignCommitRequest {
                    ceremony_hash: ceremony_hash.to_string(),
                    message: message.to_vec(),
                    alpha: alpha.to_vec(),
                },
            ))
            .await
            .with_context(|| format!("smoke_sign_commit: {}", op.operator_id))?
            .into_inner();
        commitments.insert(op.identifier, resp.signing_commitments);
    }

    let signing_package_bytes =
        smoke::make_signing_package(commitments, message).map_err(|e| anyhow!(e))?;

    let mut sigshares = BTreeMap::<u16, Vec<u8>>::new();
    for op in clients.iter_mut() {
        let resp = op
            .client
            .smoke_sign_share(with_timeout(
                Duration::from_secs(30),
                pb::SmokeSignShareRequest {
                    ceremony_hash: ceremony_hash.to_string(),
                    signing_package: signing_package_bytes.clone(),
                    alpha: alpha.to_vec(),
                },
            ))
            .await
            .with_context(|| format!("smoke_sign_share: {}", op.operator_id))?
            .into_inner();
        sigshares.insert(op.identifier, resp.signature_share);
    }

    smoke::aggregate_and_verify(public_key_package, &signing_package_bytes, sigshares, alpha)
        .map_err(|e| anyhow!(e))?;

    Ok(())
}

struct OperatorClient {
    operator_id: String,
    identifier: u16,
    client: pb::dkg_admin_client::DkgAdminClient<Channel>,
}

#[derive(Clone)]
struct TlsMaterial {
    ca_cert_pem: Vec<u8>,
    client_cert_pem: Vec<u8>,
    client_key_pem: Vec<u8>,
}

async fn load_tls_material(tls: &OnlineTlsConfig) -> anyhow::Result<TlsMaterial> {
    let ca_pem = tokio::fs::read(&tls.tls_ca_cert_pem_path)
        .await
        .with_context(|| format!("read {}", tls.tls_ca_cert_pem_path.display()))?;
    let client_cert_pem = tokio::fs::read(&tls.tls_client_cert_pem_path)
        .await
        .with_context(|| format!("read {}", tls.tls_client_cert_pem_path.display()))?;
    let client_key_pem = tokio::fs::read(&tls.tls_client_key_pem_path)
        .await
        .with_context(|| format!("read {}", tls.tls_client_key_pem_path.display()))?;
    Ok(TlsMaterial {
        ca_cert_pem: ca_pem,
        client_cert_pem,
        client_key_pem,
    })
}

async fn connect_admin(
    grpc_endpoint: &str,
    tls: &OnlineTlsConfig,
    mat: &TlsMaterial,
) -> anyhow::Result<pb::dkg_admin_client::DkgAdminClient<Channel>> {
    let ca = Certificate::from_pem(mat.ca_cert_pem.clone());
    let ident = Identity::from_pem(mat.client_cert_pem.clone(), mat.client_key_pem.clone());

    let mut endpoint = Endpoint::from_shared(grpc_endpoint.to_string())
        .map_err(|e| anyhow!("endpoint_invalid: {grpc_endpoint}: {e}"))?
        .connect_timeout(tls.connect_timeout)
        .timeout(tls.rpc_timeout)
        .tcp_nodelay(true);

    let uri = grpc_endpoint
        .parse::<http::Uri>()
        .map_err(|e| anyhow!("endpoint_uri_parse_failed: {grpc_endpoint}: {e}"))?;
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("endpoint_host_missing: {grpc_endpoint}"))?;
    let domain_name = tls
        .tls_domain_name_override
        .clone()
        .unwrap_or_else(|| host.to_string());

    let tls_cfg = ClientTlsConfig::new()
        .ca_certificate(ca)
        .identity(ident)
        .domain_name(domain_name);

    endpoint = endpoint.tls_config(tls_cfg).context("tls_config")?;

    let channel = endpoint.connect().await.context("connect")?;
    Ok(pb::dkg_admin_client::DkgAdminClient::new(channel))
}

fn with_timeout<T>(timeout: Duration, msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.set_timeout(timeout);
    req
}
