use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use rand_chacha::rand_core::SeedableRng as _;
use reddsa::frost::redpallas;
use tokio::sync::Mutex;
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use dkg_ceremony::proto::v1 as pb;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn online_ceremony_5_of_3_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();

    let (ca_pem, client_cert_pem, client_key_pem, server_identity_pem) = gen_test_mtls_material();

    let n: u16 = 5;
    let t: u16 = 3;

    // Spin up N simulated admins with mTLS.
    let mut admins = vec![];
    for identifier in 1..=n {
        let admin = spawn_sim_admin(
            identifier,
            n,
            t,
            ca_pem.clone(),
            server_identity_pem.cert_pem.clone(),
            server_identity_pem.key_pem.clone(),
        )
        .await;
        admins.push(admin);
    }

    // Build a roster/config that matches the identifier assignment rule:
    // sort operator_id ascending and assign identifiers 1..=n.
    admins.sort_by_key(|a| a.identifier);
    let ops = admins
        .iter()
        .map(|a| dkg_ceremony::roster::RosterOperatorV1 {
            operator_id: format!("op{:02}", a.identifier),
            grpc_endpoint: Some(a.endpoint.clone()),
            age_recipient: None,
        })
        .collect::<Vec<_>>();
    let roster = dkg_ceremony::roster::RosterV1 {
        roster_version: 1,
        operators: ops,
        coordinator_age_recipient: None,
    };
    let roster_hash_hex = roster.roster_hash_hex().unwrap();

    let cfg = dkg_ceremony::config::CeremonyConfigV1 {
        config_version: 1,
        ceremony_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
        threshold: t,
        max_signers: n,
        network: dkg_ceremony::config::Network::Regtest,
        roster,
        roster_hash_hex,
        out_dir: tmp.path().join("out"),
        transcript_dir: tmp.path().join("transcript"),
    };
    let validated = cfg.validate().unwrap();

    let ceremony_hash = dkg_ceremony::ceremony_hash::ceremony_hash_hex_v1(
        validated.cfg.network,
        validated.cfg.threshold,
        validated.cfg.max_signers,
        &validated.cfg.roster_hash_hex,
        &validated.ceremony_id_uuid,
    )
    .unwrap();

    // Tell each simulated admin what to expect.
    for a in &admins {
        *a.expected_ceremony_hash.lock().await = Some(ceremony_hash.clone());
    }

    // Write TLS material to disk to match OnlineTlsConfig inputs.
    let ca_path = tmp.path().join("ca.pem");
    let client_cert_path = tmp.path().join("client.pem");
    let client_key_path = tmp.path().join("client.key");
    std::fs::write(&ca_path, &ca_pem).unwrap();
    std::fs::write(&client_cert_path, &client_cert_pem).unwrap();
    std::fs::write(&client_key_path, &client_key_pem).unwrap();

    let tls = dkg_ceremony::online::OnlineTlsConfig {
        tls_ca_cert_pem_path: ca_path,
        tls_client_cert_pem_path: client_cert_path,
        tls_client_key_pem_path: client_key_path,
        tls_domain_name_override: Some("localhost".to_string()),
        ..Default::default()
    };

    let out = dkg_ceremony::online::run(validated, tls).await.unwrap();

    // Validate manifest basics.
    let manifest_bytes = std::fs::read(&out.manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["manifest_version"], 1);
    assert_eq!(manifest["network"], "regtest");
    assert_eq!(manifest["max_signers"], n);
    assert_eq!(manifest["threshold"], t);

    // Validate ufvk + ua decode.
    let ufvk = manifest["ufvk"].as_str().unwrap();
    let (_net, fvk_bytes) = dkg_ceremony::zip316::decode_ufvk_orchard(ufvk).unwrap();
    let ua = manifest["owallet_ua"].as_str().unwrap();
    let (_net, _addr_bytes) = dkg_ceremony::zip316::decode_ua_orchard(ua).unwrap();

    // Validate derived nk/rivk match ak_bytes.
    let ak_bytes_hex = manifest["ak_bytes_hex"].as_str().unwrap();
    let ak_bytes_vec = hex::decode(ak_bytes_hex).unwrap();
    let ak_bytes: [u8; 32] = ak_bytes_vec.as_slice().try_into().unwrap();
    let derived = dkg_ceremony::derive::derive_nk_rivk_from_ak_bytes(&ak_bytes);
    assert_eq!(manifest["nk_bytes_hex"], hex::encode(derived.nk_bytes));
    assert_eq!(manifest["rivk_bytes_hex"], hex::encode(derived.rivk_bytes));

    // Validate public key package hash matches bytes.
    let pkp_b64 = manifest["public_key_package"].as_str().unwrap();
    let pkp_bytes =
        base64::engine::general_purpose::STANDARD.decode(pkp_b64).unwrap();
    let pkp = redpallas::keys::PublicKeyPackage::deserialize(&pkp_bytes).unwrap();
    let pk_hash = dkg_ceremony::crypto::public_key_package_hash(&pkp, n).unwrap();
    assert_eq!(manifest["public_key_package_hash"], hex::encode(pk_hash));

    // Validate transcript hash matches transcript file.
    let transcript_hash = manifest["transcript_hash"].as_str().unwrap();
    let transcript_hash_file = std::fs::read_to_string(out.transcript_dir.join("transcript_hash.hex")).unwrap();
    assert_eq!(transcript_hash_file.trim(), transcript_hash);

    // Ensure orchard_fvk_bytes matches decoded UFVK (orchard-only).
    let orchard_fvk_bytes_hex = manifest["orchard_fvk_bytes_hex"].as_str().unwrap();
    assert_eq!(hex::encode(fvk_bytes), orchard_fvk_bytes_hex);

    for a in admins {
        a.handle.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn online_ceremony_rejects_corrupt_round1_hash() {
    let tmp = tempfile::tempdir().unwrap();
    let (ca_pem, client_cert_pem, client_key_pem, server_identity_pem) = gen_test_mtls_material();

    let n: u16 = 5;
    let t: u16 = 3;

    let mut admins = vec![];
    for identifier in 1..=n {
        let behavior = if identifier == 3 {
            SimBehavior {
                corrupt_round1_hash: true,
                ..Default::default()
            }
        } else {
            SimBehavior::default()
        };
        let admin = spawn_sim_admin_with_behavior(
            identifier,
            n,
            t,
            behavior,
            ca_pem.clone(),
            server_identity_pem.cert_pem.clone(),
            server_identity_pem.key_pem.clone(),
        )
        .await;
        admins.push(admin);
    }

    admins.sort_by_key(|a| a.identifier);
    let ops = admins
        .iter()
        .map(|a| dkg_ceremony::roster::RosterOperatorV1 {
            operator_id: format!("op{:02}", a.identifier),
            grpc_endpoint: Some(a.endpoint.clone()),
            age_recipient: None,
        })
        .collect::<Vec<_>>();
    let roster = dkg_ceremony::roster::RosterV1 {
        roster_version: 1,
        operators: ops,
        coordinator_age_recipient: None,
    };
    let roster_hash_hex = roster.roster_hash_hex().unwrap();

    let cfg = dkg_ceremony::config::CeremonyConfigV1 {
        config_version: 1,
        ceremony_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
        threshold: t,
        max_signers: n,
        network: dkg_ceremony::config::Network::Regtest,
        roster,
        roster_hash_hex,
        out_dir: tmp.path().join("out"),
        transcript_dir: tmp.path().join("transcript"),
    };
    let validated = cfg.validate().unwrap();

    let ceremony_hash = dkg_ceremony::ceremony_hash::ceremony_hash_hex_v1(
        validated.cfg.network,
        validated.cfg.threshold,
        validated.cfg.max_signers,
        &validated.cfg.roster_hash_hex,
        &validated.ceremony_id_uuid,
    )
    .unwrap();

    for a in &admins {
        *a.expected_ceremony_hash.lock().await = Some(ceremony_hash.clone());
    }

    let ca_path = tmp.path().join("ca.pem");
    let client_cert_path = tmp.path().join("client.pem");
    let client_key_path = tmp.path().join("client.key");
    std::fs::write(&ca_path, &ca_pem).unwrap();
    std::fs::write(&client_cert_path, &client_cert_pem).unwrap();
    std::fs::write(&client_key_path, &client_key_pem).unwrap();

    let tls = dkg_ceremony::online::OnlineTlsConfig {
        tls_ca_cert_pem_path: ca_path,
        tls_client_cert_pem_path: client_cert_path,
        tls_client_key_pem_path: client_key_path,
        tls_domain_name_override: Some("localhost".to_string()),
        ..Default::default()
    };

    let err = match dkg_ceremony::online::run(validated, tls).await {
        Ok(_) => panic!("expected error"),
        Err(e) => e,
    };
    assert!(format!("{err:#}").contains("round1_package_hash_mismatch"));

    for a in admins {
        a.handle.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn online_ceremony_resume_after_partial_part3_checkpoint() {
    let tmp = tempfile::tempdir().unwrap();
    let mut behaviors = BTreeMap::<u16, SimBehavior>::new();
    behaviors.insert(
        5,
        SimBehavior {
            fail_part3_once: true,
            ..Default::default()
        },
    );

    let (mut admins, validated, tls) = setup_cluster(&tmp, behaviors).await;

    let first = dkg_ceremony::online::run_with_options(
        validated.clone(),
        tls.clone(),
        dkg_ceremony::online::OnlineRunOptions {
            state_dir: tmp.path().join("online-state"),
            resume: false,
            retry: dkg_ceremony::online::RetryPolicy {
                max_retries: 0,
                ..Default::default()
            },
            report_json_path: Some(tmp.path().join("report-first.json")),
        },
    )
    .await;
    assert!(first.is_err(), "expected first run to fail");

    let second = dkg_ceremony::online::run_with_options(
        validated,
        tls,
        dkg_ceremony::online::OnlineRunOptions {
            state_dir: tmp.path().join("online-state"),
            resume: true,
            retry: dkg_ceremony::online::RetryPolicy::default(),
            report_json_path: Some(tmp.path().join("report-second.json")),
        },
    )
    .await
    .unwrap();

    let manifest_bytes = std::fs::read(&second.manifest_path).unwrap();
    let manifest: serde_json::Value = serde_json::from_slice(&manifest_bytes).unwrap();
    assert_eq!(manifest["manifest_version"], 1);

    for a in &admins {
        let st = a.state.lock().await;
        if st.identifier == 5 {
            assert_eq!(st.part3_calls, 2, "identifier=5 should be retried");
        } else {
            assert_eq!(st.part3_calls, 1, "identifier={} should not rerun part3", st.identifier);
        }
    }

    for a in admins.drain(..) {
        a.handle.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn online_ceremony_retries_transient_unavailable_part2() {
    let tmp = tempfile::tempdir().unwrap();
    let mut behaviors = BTreeMap::<u16, SimBehavior>::new();
    behaviors.insert(
        3,
        SimBehavior {
            fail_part2_unavailable_once: true,
            ..Default::default()
        },
    );

    let (admins, validated, tls) = setup_cluster(&tmp, behaviors).await;
    let report_path = tmp.path().join("report.json");
    let out = dkg_ceremony::online::run_with_options(
        validated,
        tls,
        dkg_ceremony::online::OnlineRunOptions {
            state_dir: tmp.path().join("online-state"),
            resume: false,
            retry: dkg_ceremony::online::RetryPolicy {
                max_retries: 3,
                ..Default::default()
            },
            report_json_path: Some(report_path.clone()),
        },
    )
    .await
    .unwrap();
    assert!(out.manifest_path.exists());

    let report_raw = std::fs::read(&report_path).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&report_raw).unwrap();
    let ops = report["operator_reports"].as_array().unwrap();
    let op3 = ops
        .iter()
        .find(|v| v["identifier"].as_u64() == Some(3))
        .unwrap();
    let retries = op3["phase_retries"]["part2"].as_u64().unwrap();
    assert!(retries >= 1, "expected at least one part2 retry for operator 3");

    for a in admins {
        a.handle.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn online_preflight_reports_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let (admins, validated, tls) = setup_cluster(&tmp, BTreeMap::new()).await;

    // Intentionally break one expected ceremony hash to trigger a mismatch report.
    *admins[0].expected_ceremony_hash.lock().await = Some("ff".repeat(32));

    let report = dkg_ceremony::online::preflight(&validated, &tls, &dkg_ceremony::online::RetryPolicy::default())
        .await
        .unwrap();
    assert!(!report.ready);
    assert!(report.operators.iter().any(|op| !op.ready));

    for a in admins {
        a.handle.abort();
    }
}

async fn setup_cluster(
    tmp: &tempfile::TempDir,
    behaviors: BTreeMap<u16, SimBehavior>,
) -> (
    Vec<SpawnedAdmin>,
    dkg_ceremony::config::ValidatedCeremonyConfig,
    dkg_ceremony::online::OnlineTlsConfig,
) {
    let (ca_pem, client_cert_pem, client_key_pem, server_identity_pem) = gen_test_mtls_material();
    let n: u16 = 5;
    let t: u16 = 3;

    let mut admins = vec![];
    for identifier in 1..=n {
        let behavior = behaviors.get(&identifier).cloned().unwrap_or_default();
        let admin = spawn_sim_admin_with_behavior(
            identifier,
            n,
            t,
            behavior,
            ca_pem.clone(),
            server_identity_pem.cert_pem.clone(),
            server_identity_pem.key_pem.clone(),
        )
        .await;
        admins.push(admin);
    }

    admins.sort_by_key(|a| a.identifier);
    let ops = admins
        .iter()
        .map(|a| dkg_ceremony::roster::RosterOperatorV1 {
            operator_id: format!("op{:02}", a.identifier),
            grpc_endpoint: Some(a.endpoint.clone()),
            age_recipient: None,
        })
        .collect::<Vec<_>>();
    let roster = dkg_ceremony::roster::RosterV1 {
        roster_version: 1,
        operators: ops,
        coordinator_age_recipient: None,
    };
    let roster_hash_hex = roster.roster_hash_hex().unwrap();

    let cfg = dkg_ceremony::config::CeremonyConfigV1 {
        config_version: 1,
        ceremony_id: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
        threshold: t,
        max_signers: n,
        network: dkg_ceremony::config::Network::Regtest,
        roster,
        roster_hash_hex,
        out_dir: tmp.path().join("out"),
        transcript_dir: tmp.path().join("transcript"),
    };
    let validated = cfg.validate().unwrap();

    let ceremony_hash = dkg_ceremony::ceremony_hash::ceremony_hash_hex_v1(
        validated.cfg.network,
        validated.cfg.threshold,
        validated.cfg.max_signers,
        &validated.cfg.roster_hash_hex,
        &validated.ceremony_id_uuid,
    )
    .unwrap();
    for a in &admins {
        *a.expected_ceremony_hash.lock().await = Some(ceremony_hash.clone());
    }

    let ca_path = tmp.path().join("ca.pem");
    let client_cert_path = tmp.path().join("client.pem");
    let client_key_path = tmp.path().join("client.key");
    std::fs::write(&ca_path, &ca_pem).unwrap();
    std::fs::write(&client_cert_path, &client_cert_pem).unwrap();
    std::fs::write(&client_key_path, &client_key_pem).unwrap();

    let tls = dkg_ceremony::online::OnlineTlsConfig {
        tls_ca_cert_pem_path: ca_path,
        tls_client_cert_pem_path: client_cert_path,
        tls_client_key_pem_path: client_key_path,
        tls_domain_name_override: Some("localhost".to_string()),
        ..Default::default()
    };

    (admins, validated, tls)
}

#[derive(Clone, Debug, Default)]
struct SimBehavior {
    corrupt_round1_hash: bool,
    fail_part2_unavailable_once: bool,
    fail_part3_once: bool,
}

struct SpawnedAdmin {
    identifier: u16,
    endpoint: String,
    expected_ceremony_hash: Arc<Mutex<Option<String>>>,
    state: Arc<Mutex<SimState>>,
    handle: tokio::task::JoinHandle<()>,
}

#[derive(Clone)]
struct SimAdmin {
    expected_ceremony_hash: Arc<Mutex<Option<String>>>,
    behavior: SimBehavior,
    state: Arc<Mutex<SimState>>,
}

struct SimState {
    identifier: u16,
    max_signers: u16,
    threshold: u16,
    part2_failures_remaining: u32,
    part3_failures_remaining: u32,
    part3_calls: u32,

    round1_secret: Option<redpallas::keys::dkg::round1::SecretPackage>,
    round1_package: Option<Vec<u8>>,

    round2_secret: Option<redpallas::keys::dkg::round2::SecretPackage>,
    round2_out: Option<Vec<pb::Round2PackageOut>>,

    key_package: Option<redpallas::keys::KeyPackage>,
    public_key_package: Option<redpallas::keys::PublicKeyPackage>,

    smoke_session: Option<SmokeSession>,
}

struct SmokeSession {
    alpha: Vec<u8>,
    message_hash: [u8; 32],
    nonces: redpallas::round1::SigningNonces,
}

impl SimAdmin {
    fn new(identifier: u16, max_signers: u16, threshold: u16, behavior: SimBehavior) -> Self {
        Self {
            expected_ceremony_hash: Arc::new(Mutex::new(None)),
            state: Arc::new(Mutex::new(SimState {
                identifier,
                max_signers,
                threshold,
                part2_failures_remaining: if behavior.fail_part2_unavailable_once { 1 } else { 0 },
                part3_failures_remaining: if behavior.fail_part3_once { 1 } else { 0 },
                part3_calls: 0,
                round1_secret: None,
                round1_package: None,
                round2_secret: None,
                round2_out: None,
                key_package: None,
                public_key_package: None,
                smoke_session: None,
            })),
            behavior,
        }
    }

    async fn validate(&self, ceremony_hash: &str) -> Result<(), tonic::Status> {
        let exp = self.expected_ceremony_hash.lock().await;
        if let Some(exp) = exp.as_deref() {
            if exp != ceremony_hash {
                return Err(tonic::Status::invalid_argument("ceremony_hash_mismatch"));
            }
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl pb::dkg_admin_server::DkgAdmin for SimAdmin {
    async fn get_status(
        &self,
        request: tonic::Request<pb::GetStatusRequest>,
    ) -> Result<tonic::Response<pb::GetStatusResponse>, tonic::Status> {
        self.validate(&request.get_ref().ceremony_hash).await?;

        let st = self.state.lock().await;
        let phase = if st.key_package.is_some() && st.public_key_package.is_some() {
            pb::CeremonyPhase::Part3 as i32
        } else if st.round2_secret.is_some() {
            pb::CeremonyPhase::Round2 as i32
        } else if st.round1_package.is_some() {
            pb::CeremonyPhase::Round1 as i32
        } else {
            pb::CeremonyPhase::Empty as i32
        };
        let round1_hash = st
            .round1_package
            .as_ref()
            .map(|b| dkg_ceremony::hash::sha256(b).to_vec())
            .unwrap_or_default();

        Ok(tonic::Response::new(pb::GetStatusResponse {
            operator_id: format!("op{:02}", st.identifier),
            identifier: st.identifier as u32,
            ceremony_hash: request.get_ref().ceremony_hash.clone(),
            phase,
            round1_package_hash: round1_hash,
            part2_input_hash: vec![],
            part3_input_hash: vec![],
            binary_version: "sim".to_string(),
            binary_commit: "sim".to_string(),
        }))
    }

    async fn get_round1_package(
        &self,
        request: tonic::Request<pb::GetRound1PackageRequest>,
    ) -> Result<tonic::Response<pb::GetRound1PackageResponse>, tonic::Status> {
        self.validate(&request.get_ref().ceremony_hash).await?;

        let mut st = self.state.lock().await;
        if st.round1_secret.is_none() {
            let id: redpallas::Identifier = st
                .identifier
                .try_into()
                .map_err(|_| tonic::Status::invalid_argument("identifier_invalid"))?;
            let mut rng = rand_chacha::ChaCha20Rng::from_seed([st.identifier as u8; 32]);
            let (secret, pkg) = redpallas::keys::dkg::part1(id, st.max_signers, st.threshold, &mut rng)
                .map_err(|_| tonic::Status::internal("dkg_part1_failed"))?;
            st.round1_secret = Some(secret);
            st.round1_package = Some(pkg.serialize().map_err(|_| tonic::Status::internal("round1_serialize_failed"))?);
        }

        let pkg = st.round1_package.clone().unwrap();
        let mut hash = dkg_ceremony::hash::sha256(&pkg).to_vec();
        if self.behavior.corrupt_round1_hash {
            hash[0] ^= 0x01;
        }
        Ok(tonic::Response::new(pb::GetRound1PackageResponse {
            round1_package: pkg,
            round1_package_hash: hash,
        }))
    }

    async fn part2(
        &self,
        request: tonic::Request<pb::Part2Request>,
    ) -> Result<tonic::Response<pb::Part2Response>, tonic::Status> {
        self.validate(&request.get_ref().ceremony_hash).await?;
        let mut st = self.state.lock().await;
        if st.part2_failures_remaining > 0 {
            st.part2_failures_remaining -= 1;
            return Err(tonic::Status::unavailable("transient_part2_unavailable"));
        }
        if let Some(cached) = &st.round2_out {
            return Ok(tonic::Response::new(pb::Part2Response {
                round2_packages: cached.clone(),
            }));
        }
        let secret = st
            .round1_secret
            .take()
            .ok_or_else(|| tonic::Status::failed_precondition("round1_missing"))?;

        let mut r1_map = BTreeMap::new();
        for p in &request.get_ref().round1_packages {
            let sender_u16: u16 = p
                .sender_identifier
                .try_into()
                .map_err(|_| tonic::Status::invalid_argument("sender_identifier_invalid"))?;
            if sender_u16 == 0 || sender_u16 > st.max_signers || sender_u16 == st.identifier {
                return Err(tonic::Status::invalid_argument("sender_identifier_out_of_range"));
            }
            if p.package_hash.len() != 32 {
                return Err(tonic::Status::invalid_argument("round1_package_hash_len_invalid"));
            }
            let got = dkg_ceremony::hash::sha256(&p.package);
            if got.as_slice() != p.package_hash.as_slice() {
                return Err(tonic::Status::invalid_argument("round1_package_hash_mismatch"));
            }
            let sender: redpallas::Identifier = sender_u16
                .try_into()
                .map_err(|_| tonic::Status::invalid_argument("sender_identifier_invalid"))?;
            let pkg = redpallas::keys::dkg::round1::Package::deserialize(&p.package)
                .map_err(|_| tonic::Status::invalid_argument("round1_package_deserialize_failed"))?;
            r1_map.insert(sender, pkg);
        }

        let (r2_secret, r2_out) = redpallas::keys::dkg::part2(secret, &r1_map)
            .map_err(|_| tonic::Status::internal("dkg_part2_failed"))?;
        st.round2_secret = Some(r2_secret);

        let mut out = vec![];
        for (recv_id, pkg) in r2_out {
            // Filter out "to self" package.
            let recv_u16 = identifier_to_u16(&recv_id, st.max_signers)
                .map_err(|_| tonic::Status::internal("identifier_not_u16"))?;
            if recv_u16 == st.identifier {
                continue;
            }
            let bytes = pkg.serialize().map_err(|_| tonic::Status::internal("round2_serialize_failed"))?;
            out.push(pb::Round2PackageOut {
                receiver_identifier: recv_u16 as u32,
                package: bytes.clone(),
                package_hash: dkg_ceremony::hash::sha256(&bytes).to_vec(),
            });
        }
        st.round2_out = Some(out.clone());

        Ok(tonic::Response::new(pb::Part2Response { round2_packages: out }))
    }

    async fn part3(
        &self,
        request: tonic::Request<pb::Part3Request>,
    ) -> Result<tonic::Response<pb::Part3Response>, tonic::Status> {
        self.validate(&request.get_ref().ceremony_hash).await?;
        let mut st = self.state.lock().await;
        st.part3_calls += 1;
        if st.part3_failures_remaining > 0 {
            st.part3_failures_remaining -= 1;
            return Err(tonic::Status::aborted("transient_part3_failure"));
        }
        let r2_secret = st
            .round2_secret
            .as_ref()
            .ok_or_else(|| tonic::Status::failed_precondition("round2_missing"))?;

        let mut r1_map = BTreeMap::new();
        for p in &request.get_ref().round1_packages {
            let sender_u16: u16 = p
                .sender_identifier
                .try_into()
                .map_err(|_| tonic::Status::invalid_argument("sender_identifier_invalid"))?;
            let sender: redpallas::Identifier = sender_u16
                .try_into()
                .map_err(|_| tonic::Status::invalid_argument("sender_identifier_invalid"))?;
            let pkg = redpallas::keys::dkg::round1::Package::deserialize(&p.package)
                .map_err(|_| tonic::Status::invalid_argument("round1_package_deserialize_failed"))?;
            r1_map.insert(sender, pkg);
        }

        let mut r2_map = BTreeMap::new();
        for p in &request.get_ref().round2_packages {
            let sender_u16: u16 = p
                .sender_identifier
                .try_into()
                .map_err(|_| tonic::Status::invalid_argument("sender_identifier_invalid"))?;
            let sender: redpallas::Identifier = sender_u16
                .try_into()
                .map_err(|_| tonic::Status::invalid_argument("sender_identifier_invalid"))?;
            let pkg = redpallas::keys::dkg::round2::Package::deserialize(&p.package)
                .map_err(|_| tonic::Status::invalid_argument("round2_package_deserialize_failed"))?;
            r2_map.insert(sender, pkg);
        }

        let (key_package, public_key_package) =
            redpallas::keys::dkg::part3(r2_secret, &r1_map, &r2_map)
                .map_err(|_| tonic::Status::internal("dkg_part3_failed"))?;

        let pk_bytes = public_key_package
            .serialize()
            .map_err(|_| tonic::Status::internal("public_key_package_serialize_failed"))?;
        let pk_hash =
            dkg_ceremony::crypto::public_key_package_hash(&public_key_package, st.max_signers)
                .map_err(|_| tonic::Status::internal("public_key_package_hash_failed"))?;
        let ak_bytes =
            dkg_ceremony::crypto::ak_bytes_from_public_key_package(&public_key_package)
                .map_err(|_| tonic::Status::internal("ak_bytes_failed"))?;
        if !dkg_ceremony::crypto::is_canonical_ak_bytes(&ak_bytes) {
            return Err(tonic::Status::internal("ak_bytes_non_canonical"));
        }

        st.key_package = Some(key_package);
        st.public_key_package = Some(public_key_package);

        Ok(tonic::Response::new(pb::Part3Response {
            public_key_package: pk_bytes,
            public_key_package_hash: pk_hash.to_vec(),
            ak_bytes: ak_bytes.to_vec(),
            canonicalized: true,
        }))
    }

    async fn smoke_sign_commit(
        &self,
        request: tonic::Request<pb::SmokeSignCommitRequest>,
    ) -> Result<tonic::Response<pb::SmokeSignCommitResponse>, tonic::Status> {
        self.validate(&request.get_ref().ceremony_hash).await?;

        let mut st = self.state.lock().await;
        let key_package = st
            .key_package
            .as_ref()
            .ok_or_else(|| tonic::Status::failed_precondition("key_package_missing"))?;

        let alpha = request.get_ref().alpha.clone();
        if !alpha.is_empty() && alpha.len() != 32 {
            return Err(tonic::Status::invalid_argument("alpha_len_invalid"));
        }

        let message_hash = dkg_ceremony::hash::sha256(&request.get_ref().message);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([st.identifier as u8; 32]);
        let (nonces, commitments) = redpallas::round1::commit(key_package.signing_share(), &mut rng);
        let commitments_bytes = commitments
            .serialize()
            .map_err(|_| tonic::Status::internal("commitments_serialize_failed"))?;

        st.smoke_session = Some(SmokeSession {
            alpha,
            message_hash,
            nonces,
        });

        Ok(tonic::Response::new(pb::SmokeSignCommitResponse {
            signing_commitments: commitments_bytes,
        }))
    }

    async fn smoke_sign_share(
        &self,
        request: tonic::Request<pb::SmokeSignShareRequest>,
    ) -> Result<tonic::Response<pb::SmokeSignShareResponse>, tonic::Status> {
        self.validate(&request.get_ref().ceremony_hash).await?;

        let mut st = self.state.lock().await;
        let key_package = st
            .key_package
            .as_ref()
            .cloned()
            .ok_or_else(|| tonic::Status::failed_precondition("key_package_missing"))?;

        let session = st
            .smoke_session
            .take()
            .ok_or_else(|| tonic::Status::failed_precondition("smoke_session_missing"))?;
        drop(st);

        if session.alpha != request.get_ref().alpha {
            return Err(tonic::Status::invalid_argument("alpha_mismatch"));
        }

        let signing_package = redpallas::SigningPackage::deserialize(&request.get_ref().signing_package)
            .map_err(|_| tonic::Status::invalid_argument("signing_package_deserialize_failed"))?;
        if session.message_hash != dkg_ceremony::hash::sha256(signing_package.message()) {
            return Err(tonic::Status::invalid_argument("message_mismatch"));
        }

        let randomizer = if session.alpha.is_empty() {
            redpallas::Randomizer::deserialize(&[0u8; 32])
        } else {
            redpallas::Randomizer::deserialize(&session.alpha)
        }
        .map_err(|_| tonic::Status::invalid_argument("alpha_deserialize_failed"))?;

        let sig_share =
            redpallas::round2::sign(&signing_package, &session.nonces, &key_package, randomizer)
                .map_err(|_| tonic::Status::internal("sign_failed"))?;

        Ok(tonic::Response::new(pb::SmokeSignShareResponse {
            signature_share: sig_share.serialize(),
        }))
    }

    async fn export_encrypted_key_package(
        &self,
        _request: tonic::Request<pb::ExportEncryptedKeyPackageRequest>,
    ) -> Result<tonic::Response<pb::ExportEncryptedKeyPackageResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("export_not_implemented_in_sim"))
    }

    async fn destroy(
        &self,
        _request: tonic::Request<pb::DestroyRequest>,
    ) -> Result<tonic::Response<pb::DestroyResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("destroy_not_implemented_in_sim"))
    }
}

async fn spawn_sim_admin(
    identifier: u16,
    max_signers: u16,
    threshold: u16,
    ca_pem: Vec<u8>,
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
) -> SpawnedAdmin {
    spawn_sim_admin_with_behavior(
        identifier,
        max_signers,
        threshold,
        SimBehavior::default(),
        ca_pem,
        server_cert_pem,
        server_key_pem,
    )
    .await
}

async fn spawn_sim_admin_with_behavior(
    identifier: u16,
    max_signers: u16,
    threshold: u16,
    behavior: SimBehavior,
    ca_pem: Vec<u8>,
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
) -> SpawnedAdmin {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let endpoint = format!("https://localhost:{}", addr.port());

    let identity = Identity::from_pem(server_cert_pem, server_key_pem);
    let client_ca = Certificate::from_pem(ca_pem);
    let tls = ServerTlsConfig::new()
        .identity(identity)
        .client_ca_root(client_ca);

    let admin = SimAdmin::new(identifier, max_signers, threshold, behavior);
    let expected_ceremony_hash = admin.expected_ceremony_hash.clone();
    let state = admin.state.clone();
    let svc = pb::dkg_admin_server::DkgAdminServer::new(admin);

    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let handle = tokio::spawn(async move {
        let _ = Server::builder()
            .tls_config(tls)
            .unwrap()
            .serve_with_incoming(svc, incoming)
            .await;
    });

    SpawnedAdmin {
        identifier,
        endpoint,
        expected_ceremony_hash,
        state,
        handle,
    }
}

struct IdentityPem {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

fn gen_test_mtls_material() -> (Vec<u8>, Vec<u8>, Vec<u8>, IdentityPem) {
    use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    ca_params.distinguished_name.push(DnType::CommonName, "junocash-test-ca");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem().into_bytes();

    let mut server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    server_params.distinguished_name.push(DnType::CommonName, "junocash-test-server");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .unwrap();

    let mut client_params = CertificateParams::new(vec!["coordinator".to_string()]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    client_params.distinguished_name.push(DnType::CommonName, "junocash-test-client");
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params
        .signed_by(&client_key, &ca_cert, &ca_key)
        .unwrap();

    let client_cert_pem = client_cert.pem().into_bytes();
    let client_key_pem = client_key.serialize_pem().into_bytes();

    (
        ca_pem,
        client_cert_pem,
        client_key_pem,
        IdentityPem {
            cert_pem: server_cert.pem().into_bytes(),
            key_pem: server_key.serialize_pem().into_bytes(),
        },
    )
}

fn identifier_to_u16(id: &redpallas::Identifier, max_signers: u16) -> anyhow::Result<u16> {
    let serialized = id.serialize();
    for n in 1u16..=max_signers {
        let cand: redpallas::Identifier = n.try_into()?;
        if cand.serialize() == serialized {
            return Ok(n);
        }
    }
    anyhow::bail!("identifier_not_u16");
}
