use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context as _};
use base64::Engine as _;
use rand::Rng as _;
use reddsa::frost::redpallas;
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tonic::Code;
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

const ONLINE_STATE_VERSION: u32 = 1;
const ONLINE_STATE_FILE: &str = "online_state.json";

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

#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub backoff_start: Duration,
    pub backoff_max: Duration,
    pub jitter: Duration,
    pub retryable_codes: Vec<tonic::Code>,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            backoff_start: Duration::from_millis(250),
            backoff_max: Duration::from_secs(3),
            jitter: Duration::from_millis(100),
            retryable_codes: vec![tonic::Code::Unavailable, tonic::Code::DeadlineExceeded],
        }
    }
}

#[derive(Debug, Clone)]
pub struct OnlineRunOptions {
    pub state_dir: PathBuf,
    pub resume: bool,
    pub retry: RetryPolicy,
    pub report_json_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OnlineRunReportV1 {
    pub report_version: u32,
    pub ceremony_hash: String,
    pub success: bool,
    pub operator_reports: Vec<OperatorRunReportV1>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRunReportV1 {
    pub operator_id: String,
    pub identifier: u16,
    pub phase_timings_ms: BTreeMap<String, u64>,
    pub phase_retries: BTreeMap<String, u32>,
    pub phase_error_codes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnlineStateV1 {
    state_version: u32,
    ceremony_hash: String,
    round1_packages: BTreeMap<u16, String>, // base64(package bytes)
    round2_hashes: BTreeMap<String, String>, // "<sender>:<receiver>" => hex(hash)
    part3_completed: BTreeMap<u16, OnlinePart3ResultV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnlinePart3ResultV1 {
    public_key_package_b64: String,
    public_key_package_hash_hex: String,
    ak_bytes_hex: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightReportV1 {
    pub report_version: u32,
    pub ceremony_hash: String,
    pub ready: bool,
    pub operators: Vec<PreflightOperatorReportV1>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PreflightOperatorReportV1 {
    pub operator_id: String,
    pub expected_identifier: u16,
    pub endpoint: String,
    pub ready: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub status: Option<OperatorStatusSnapshotV1>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorStatusSnapshotV1 {
    pub reported_operator_id: String,
    pub reported_identifier: u16,
    pub ceremony_hash: String,
    pub phase: String,
    pub round1_package_hash_hex: Option<String>,
    pub part2_input_hash_hex: Option<String>,
    pub part3_input_hash_hex: Option<String>,
    pub binary_version: String,
    pub binary_commit: String,
}

#[derive(Debug, Clone)]
pub enum ExportEncryption {
    Age { recipients: Vec<String> },
    AwsKms { kms_key_id: String },
}

#[derive(Debug, Clone)]
pub enum ExportTarget {
    RemoteFilePrefix { remote_file_prefix: String },
    S3 {
        bucket: String,
        key_prefix: String,
        sse_kms_key_id: String,
    },
}

#[derive(Debug, Clone)]
pub struct ExportKeyPackagesOptions {
    pub retry: RetryPolicy,
    pub manifest_path: PathBuf,
    pub receipts_dir: PathBuf,
    pub report_json_path: Option<PathBuf>,
    pub encryption: ExportEncryption,
    pub target: ExportTarget,
}

#[derive(Debug, Clone)]
pub struct ExportKeyPackagesOutput {
    pub receipts_dir: PathBuf,
    pub report_json_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportReportV1 {
    pub report_version: u32,
    pub ceremony_hash: String,
    pub success: bool,
    pub operators: Vec<ExportOperatorReportV1>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExportOperatorReportV1 {
    pub operator_id: String,
    pub identifier: u16,
    pub remote_target: String,
    pub retries: u32,
    pub elapsed_ms: u64,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

pub struct OnlineRunOutput {
    pub manifest_path: PathBuf,
    pub transcript_dir: PathBuf,
    pub report_json_path: Option<PathBuf>,
}

pub fn parse_retryable_codes_csv(input: &str) -> anyhow::Result<Vec<Code>> {
    let mut codes = Vec::<Code>::new();
    for raw in input.split(',') {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let code = parse_tonic_code(token)
            .ok_or_else(|| anyhow!("retryable_code_invalid: {token}"))?;
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    if codes.is_empty() {
        return Err(anyhow!("retryable_codes_empty"));
    }
    Ok(codes)
}

pub async fn run(validated_cfg: ValidatedCeremonyConfig, tls: OnlineTlsConfig) -> anyhow::Result<OnlineRunOutput> {
    let default_opts = OnlineRunOptions {
        state_dir: validated_cfg.cfg.out_dir.join("online-state"),
        resume: false,
        retry: RetryPolicy::default(),
        report_json_path: None,
    };
    run_with_options(validated_cfg, tls, default_opts).await
}

pub async fn run_with_options(
    validated_cfg: ValidatedCeremonyConfig,
    tls: OnlineTlsConfig,
    options: OnlineRunOptions,
) -> anyhow::Result<OnlineRunOutput> {
    let ceremony_hash = ceremony_hash_hex_v1(
        validated_cfg.cfg.network,
        validated_cfg.cfg.threshold,
        validated_cfg.cfg.max_signers,
        &validated_cfg.cfg.roster_hash_hex,
        &validated_cfg.ceremony_id_uuid,
    )
    .context("ceremony_hash")?;

    let mut operator_reports = init_operator_reports(&validated_cfg);

    let run_res = run_online_inner(
        &validated_cfg,
        &tls,
        &options,
        &ceremony_hash,
        &mut operator_reports,
    )
    .await;

    let report = OnlineRunReportV1 {
        report_version: 1,
        ceremony_hash: ceremony_hash.clone(),
        success: run_res.is_ok(),
        operator_reports: operator_reports.into_values().collect(),
    };
    if let Some(path) = &options.report_json_path {
        write_json_report(path, &report)?;
    }

    let mut out = run_res?;
    out.report_json_path = options.report_json_path;
    Ok(out)
}

pub async fn preflight(
    validated_cfg: &ValidatedCeremonyConfig,
    tls: &OnlineTlsConfig,
    retry: &RetryPolicy,
) -> anyhow::Result<PreflightReportV1> {
    let ceremony_hash = ceremony_hash_hex_v1(
        validated_cfg.cfg.network,
        validated_cfg.cfg.threshold,
        validated_cfg.cfg.max_signers,
        &validated_cfg.cfg.roster_hash_hex,
        &validated_cfg.ceremony_id_uuid,
    )
    .context("ceremony_hash")?;

    let tls_material = load_tls_material(tls).await?;
    let mut out = Vec::with_capacity(validated_cfg.canonical_operators.len());
    let mut all_ready = true;

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
            .clone()
            .ok_or_else(|| anyhow!("grpc_endpoint_missing_for_operator: {}", assigned.operator_id))?;

        let mut report = PreflightOperatorReportV1 {
            operator_id: assigned.operator_id.clone(),
            expected_identifier: assigned.identifier.0,
            endpoint: endpoint.clone(),
            ready: false,
            error_code: None,
            error_message: None,
            status: None,
        };

        let connect_res = connect_admin_with_retry(&endpoint, tls, &tls_material, retry).await;
        let (mut client, _) = match connect_res {
            Ok(v) => v,
            Err(e) => {
                all_ready = false;
                report.error_code = Some("connect_failed".to_string());
                report.error_message = Some(format!("{e:#}"));
                out.push(report);
                continue;
            }
        };

        let rpc_timeout = tls.rpc_timeout;
        let ceremony_hash_for_status = ceremony_hash.clone();
        let status_call = call_with_retry_client(retry, &mut client, |client| {
            let ceremony_hash_value = ceremony_hash_for_status.clone();
            Box::pin(async move {
                client
                    .get_status(with_timeout(
                        rpc_timeout,
                        pb::GetStatusRequest {
                            ceremony_hash: ceremony_hash_value,
                        },
                    ))
                    .await
                    .map(|resp| resp.into_inner())
            })
        })
        .await;

        let status = match status_call {
            Ok(v) => v.value,
            Err(e) => {
                all_ready = false;
                report.error_code = Some(status_code_string(e.status.code()));
                report.error_message = Some(e.status.message().to_string());
                out.push(report);
                continue;
            }
        };

        let phase_name = phase_name(status.phase);
        let snapshot = OperatorStatusSnapshotV1 {
            reported_operator_id: status.operator_id.clone(),
            reported_identifier: u16::try_from(status.identifier)
                .map_err(|_| anyhow!("status_identifier_invalid: {}", status.identifier))?,
            ceremony_hash: status.ceremony_hash.clone(),
            phase: phase_name.to_string(),
            round1_package_hash_hex: opt_hash_hex(&status.round1_package_hash)?,
            part2_input_hash_hex: opt_hash_hex(&status.part2_input_hash)?,
            part3_input_hash_hex: opt_hash_hex(&status.part3_input_hash)?,
            binary_version: status.binary_version.clone(),
            binary_commit: status.binary_commit.clone(),
        };

        let mut mismatch: Option<(&str, String)> = None;
        if snapshot.reported_operator_id.trim() != assigned.operator_id {
            mismatch = Some((
                "operator_id_mismatch",
                format!(
                    "expected={} got={}",
                    assigned.operator_id, snapshot.reported_operator_id
                ),
            ));
        } else if snapshot.reported_identifier != assigned.identifier.0 {
            mismatch = Some((
                "identifier_mismatch",
                format!(
                    "expected={} got={}",
                    assigned.identifier.0, snapshot.reported_identifier
                ),
            ));
        } else if snapshot.ceremony_hash != ceremony_hash {
            mismatch = Some((
                "ceremony_hash_mismatch",
                format!("expected={} got={}", ceremony_hash, snapshot.ceremony_hash),
            ));
        } else if status.phase == 0 {
            mismatch = Some((
                "phase_unspecified",
                "operator phase is CEREMONY_PHASE_UNSPECIFIED".to_string(),
            ));
        } else if status.phase >= 3 && status.part2_input_hash.len() != 32 {
            mismatch = Some((
                "part2_input_hash_invalid",
                "phase>=ROUND2 but part2_input_hash is absent/invalid".to_string(),
            ));
        } else if status.phase >= 4 && status.part3_input_hash.len() != 32 {
            mismatch = Some((
                "part3_input_hash_invalid",
                "phase>=PART3 but part3_input_hash is absent/invalid".to_string(),
            ));
        }

        report.status = Some(snapshot);
        if let Some((code, msg)) = mismatch {
            all_ready = false;
            report.error_code = Some(code.to_string());
            report.error_message = Some(msg);
        } else {
            report.ready = true;
        }
        out.push(report);
    }

    Ok(PreflightReportV1 {
        report_version: 1,
        ceremony_hash,
        ready: all_ready,
        operators: out,
    })
}

pub async fn export_key_packages(
    validated_cfg: ValidatedCeremonyConfig,
    tls: OnlineTlsConfig,
    options: ExportKeyPackagesOptions,
) -> anyhow::Result<ExportKeyPackagesOutput> {
    let ceremony_hash = ceremony_hash_hex_v1(
        validated_cfg.cfg.network,
        validated_cfg.cfg.threshold,
        validated_cfg.cfg.max_signers,
        &validated_cfg.cfg.roster_hash_hex,
        &validated_cfg.ceremony_id_uuid,
    )
    .context("ceremony_hash")?;

    let expected_public_key_package_hash = read_manifest_public_key_package_hash(&options.manifest_path)?;
    let tls_material = load_tls_material(&tls).await?;

    let mut reports = Vec::with_capacity(validated_cfg.canonical_operators.len());
    let mut all_ok = true;

    std::fs::create_dir_all(&options.receipts_dir)
        .with_context(|| format!("create {}", options.receipts_dir.display()))?;

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
            .clone()
            .ok_or_else(|| anyhow!("grpc_endpoint_missing_for_operator: {}", assigned.operator_id))?;

        let remote_target = match &options.target {
            ExportTarget::RemoteFilePrefix { remote_file_prefix } => {
                format!("{remote_file_prefix}_{:02}.json", assigned.identifier.0)
            }
            ExportTarget::S3 {
                bucket,
                key_prefix,
                ..
            } => {
                let key = format!(
                    "{}/operator_{:02}.json",
                    key_prefix.trim_end_matches('/'),
                    assigned.identifier.0
                );
                format!("s3://{bucket}/{key}")
            }
        };

        let mut op_report = ExportOperatorReportV1 {
            operator_id: assigned.operator_id.clone(),
            identifier: assigned.identifier.0,
            remote_target: remote_target.clone(),
            retries: 0,
            elapsed_ms: 0,
            error_code: None,
            error_message: None,
        };

        let connect_res = connect_admin_with_retry(&endpoint, &tls, &tls_material, &options.retry).await;
        let (mut client, connect_stats) = match connect_res {
            Ok(v) => v,
            Err(e) => {
                all_ok = false;
                op_report.error_code = Some("connect_failed".to_string());
                op_report.error_message = Some(format!("{e:#}"));
                reports.push(op_report);
                continue;
            }
        };
        op_report.retries = op_report.retries.saturating_add(connect_stats.retries);
        op_report.elapsed_ms = op_report.elapsed_ms.saturating_add(connect_stats.elapsed_ms);

        let req = build_export_request(&ceremony_hash, assigned.identifier.0, &options)?;
        let req_template = req.clone();
        let rpc_timeout = tls.rpc_timeout;
        let rpc_res = call_with_retry_client(&options.retry, &mut client, |client| {
            let req_value = req_template.clone();
            Box::pin(async move {
                client
                    .export_encrypted_key_package(with_timeout(rpc_timeout, req_value))
                    .await
                    .map(|r| r.into_inner())
            })
        })
        .await;

        let rpc = match rpc_res {
            Ok(v) => v,
            Err(e) => {
                all_ok = false;
                op_report.retries = op_report.retries.saturating_add(e.retries);
                op_report.elapsed_ms = op_report.elapsed_ms.saturating_add(e.elapsed_ms);
                op_report.error_code = Some(status_code_string(e.status.code()));
                op_report.error_message = Some(e.status.message().to_string());
                reports.push(op_report);
                continue;
            }
        };
        op_report.retries = op_report.retries.saturating_add(rpc.retries);
        op_report.elapsed_ms = op_report.elapsed_ms.saturating_add(rpc.elapsed_ms);

        let receipt_bytes = rpc.value.receipt_json;
        let validate_res = validate_export_receipt(
            &receipt_bytes,
            &validated_cfg,
            assigned.identifier.0,
            &assigned.operator_id,
            &expected_public_key_package_hash,
        );
        if let Err(e) = validate_res {
            all_ok = false;
            op_report.error_code = Some("receipt_validation_failed".to_string());
            op_report.error_message = Some(format!("{e:#}"));
            reports.push(op_report);
            continue;
        }

        let local_receipt_path = options
            .receipts_dir
            .join(format!("operator_{:02}.KeyImportReceipt.json", assigned.identifier.0));
        std::fs::write(&local_receipt_path, &receipt_bytes)
            .with_context(|| format!("write {}", local_receipt_path.display()))?;
        reports.push(op_report);
    }

    let report = ExportReportV1 {
        report_version: 1,
        ceremony_hash,
        success: all_ok,
        operators: reports,
    };

    if let Some(path) = &options.report_json_path {
        write_json_report(path, &report)?;
    }

    if !report.success {
        return Err(anyhow!("export_key_packages_failed"));
    }

    Ok(ExportKeyPackagesOutput {
        receipts_dir: options.receipts_dir,
        report_json_path: options.report_json_path,
    })
}

async fn run_online_inner(
    validated_cfg: &ValidatedCeremonyConfig,
    tls: &OnlineTlsConfig,
    options: &OnlineRunOptions,
    ceremony_hash: &str,
    operator_reports: &mut BTreeMap<u16, OperatorRunReportV1>,
) -> anyhow::Result<OnlineRunOutput> {
    let state_path = options.state_dir.join(ONLINE_STATE_FILE);
    let mut state = load_or_init_state(&state_path, ceremony_hash, options.resume)?;

    let tls_material = load_tls_material(tls).await?;
    let mut clients = connect_all(validated_cfg, tls, &tls_material, &options.retry, operator_reports).await?;

    // Round 1: fetch packages unless already present in state.
    let mut round1_by_sender = read_round1_from_state(validated_cfg.cfg.max_signers, &state)?;
    for op in clients.iter_mut() {
        if round1_by_sender.contains_key(&op.identifier) {
            continue;
        }

        let rpc_timeout = tls.rpc_timeout;
        let ceremony_hash_for_round1 = ceremony_hash.to_string();
        let call = call_with_retry_client(&options.retry, &mut op.client, |client| {
            let ceremony_hash_value = ceremony_hash_for_round1.clone();
            Box::pin(async move {
                client
                    .get_round1_package(with_timeout(
                        rpc_timeout,
                        pb::GetRound1PackageRequest {
                            ceremony_hash: ceremony_hash_value,
                        },
                    ))
                    .await
                    .map(|resp| resp.into_inner())
            })
        })
        .await;

        let resp = match call {
            Ok(v) => {
                record_phase_success(
                    operator_reports,
                    op.identifier,
                    "round1",
                    v.elapsed_ms,
                    v.retries,
                );
                v.value
            }
            Err(e) => {
                record_phase_failure(
                    operator_reports,
                    op.identifier,
                    "round1",
                    e.elapsed_ms,
                    e.retries,
                    &status_code_string(e.status.code()),
                );
                return Err(anyhow!("round1_failed: {}: {}", op.operator_id, e.status.message()));
            }
        };

        if resp.round1_package_hash.len() != 32 {
            return Err(anyhow!("round1_package_hash_len_invalid: {}", op.operator_id));
        }
        let got_hash = crate::hash::sha256(&resp.round1_package);
        if got_hash.as_slice() != resp.round1_package_hash.as_slice() {
            return Err(anyhow!("round1_package_hash_mismatch: {}", op.operator_id));
        }

        state
            .round1_packages
            .insert(op.identifier, base64::engine::general_purpose::STANDARD.encode(&resp.round1_package));
        save_state(&state_path, &state)?;
        round1_by_sender.insert(op.identifier, resp.round1_package);
    }

    // Round 2: ask each participant to compute encrypted shares for others, then route in-memory.
    // Confidential: payload bytes are never persisted.
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

        let rpc_timeout = tls.rpc_timeout;
        let ceremony_hash_for_part2 = ceremony_hash.to_string();
        let round1_for_part2 = r1_pkgs.clone();
        let call = call_with_retry_client(&options.retry, &mut op.client, |client| {
            let ceremony_hash_value = ceremony_hash_for_part2.clone();
            let round1_packages = round1_for_part2.clone();
            Box::pin(async move {
                client
                    .part2(with_timeout(
                        rpc_timeout,
                        pb::Part2Request {
                            ceremony_hash: ceremony_hash_value,
                            round1_packages,
                        },
                    ))
                    .await
                    .map(|resp| resp.into_inner())
            })
        })
        .await;

        let resp = match call {
            Ok(v) => {
                record_phase_success(
                    operator_reports,
                    op.identifier,
                    "part2",
                    v.elapsed_ms,
                    v.retries,
                );
                v.value
            }
            Err(e) => {
                record_phase_failure(
                    operator_reports,
                    op.identifier,
                    "part2",
                    e.elapsed_ms,
                    e.retries,
                    &status_code_string(e.status.code()),
                );
                return Err(anyhow!("part2_failed: {}: {}", op.operator_id, e.status.message()));
            }
        };

        let mut seen = BTreeSet::<u16>::new();
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
            state
                .round2_hashes
                .insert(round2_key(op.identifier, receiver), hex::encode(got_hash));

            let entry = round2_by_receiver.entry(receiver).or_default();
            entry.push(pb::Round2PackageToMe {
                sender_identifier: op.identifier as u32,
                package: std::mem::take(&mut out.package),
                package_hash: std::mem::take(&mut out.package_hash),
            });

            out.package.zeroize();
            out.package_hash.zeroize();
        }

        for recv in 1..=validated_cfg.cfg.max_signers {
            if recv == op.identifier {
                continue;
            }
            if !seen.contains(&recv) {
                return Err(anyhow!(
                    "round2_package_missing_receiver: sender={} recv={recv}",
                    op.operator_id
                ));
            }
        }
        save_state(&state_path, &state)?;
    }

    // Round 3: finalize each participant, skipping those already checkpointed as complete.
    let mut public_key_package_bytes: Option<Vec<u8>> = None;
    let mut public_key_package_hash: Option<[u8; 32]> = None;
    let mut ak_bytes: Option<[u8; 32]> = None;

    for (identifier, done) in &state.part3_completed {
        let pk_hash = decode_hex_32(&done.public_key_package_hash_hex, "public_key_package_hash_hex")?;
        let ak = decode_hex_32(&done.ak_bytes_hex, "ak_bytes_hex")?;
        if !crypto::is_canonical_ak_bytes(&ak) {
            return Err(anyhow!("ak_bytes_non_canonical_checkpointed: identifier={identifier}"));
        }
        let pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(done.public_key_package_b64.as_bytes())
            .map_err(|_| anyhow!("part3_checkpoint_public_key_package_b64_invalid"))?;

        if let Some(prev) = public_key_package_hash {
            if prev != pk_hash {
                return Err(anyhow!("checkpoint_public_key_package_hash_mismatch"));
            }
        } else {
            public_key_package_hash = Some(pk_hash);
        }

        if let Some(prev) = ak_bytes {
            if prev != ak {
                return Err(anyhow!("checkpoint_ak_bytes_mismatch"));
            }
        } else {
            ak_bytes = Some(ak);
        }

        if let Some(prev) = &public_key_package_bytes {
            if *prev != pk_bytes {
                return Err(anyhow!("checkpoint_public_key_package_bytes_mismatch"));
            }
        } else {
            public_key_package_bytes = Some(pk_bytes);
        }
    }

    for op in clients.iter_mut() {
        if state.part3_completed.contains_key(&op.identifier) {
            continue;
        }

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

        let rpc_timeout = tls.rpc_timeout;
        let ceremony_hash_for_part3 = ceremony_hash.to_string();
        let round1_for_part3 = r1_pkgs.clone();
        let round2_for_part3 = r2_pkgs.clone();
        let call = call_with_retry_client(&options.retry, &mut op.client, |client| {
            let ceremony_hash_value = ceremony_hash_for_part3.clone();
            let round1_packages = round1_for_part3.clone();
            let round2_packages = round2_for_part3.clone();
            Box::pin(async move {
                client
                    .part3(with_timeout(
                        rpc_timeout,
                        pb::Part3Request {
                            ceremony_hash: ceremony_hash_value,
                            round1_packages,
                            round2_packages,
                        },
                    ))
                    .await
                    .map(|resp| resp.into_inner())
            })
        })
        .await;

        let resp = match call {
            Ok(v) => {
                record_phase_success(
                    operator_reports,
                    op.identifier,
                    "part3",
                    v.elapsed_ms,
                    v.retries,
                );
                v.value
            }
            Err(e) => {
                record_phase_failure(
                    operator_reports,
                    op.identifier,
                    "part3",
                    e.elapsed_ms,
                    e.retries,
                    &status_code_string(e.status.code()),
                );
                return Err(anyhow!("part3_failed: {}: {}", op.operator_id, e.status.message()));
            }
        };

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
            public_key_package_bytes = Some(resp.public_key_package.clone());
        }

        state.part3_completed.insert(
            op.identifier,
            OnlinePart3ResultV1 {
                public_key_package_b64: base64::engine::general_purpose::STANDARD
                    .encode(&resp.public_key_package),
                public_key_package_hash_hex: hex::encode(pk_hash),
                ak_bytes_hex: hex::encode(ak),
            },
        );
        save_state(&state_path, &state)?;
    }

    for pkgs in round2_by_receiver.values_mut() {
        for pkg in pkgs.iter_mut() {
            pkg.package.zeroize();
            pkg.package_hash.zeroize();
        }
    }

    let public_key_package_bytes =
        public_key_package_bytes.ok_or_else(|| anyhow!("public_key_package_missing"))?;
    let mut public_key_package = redpallas::keys::PublicKeyPackage::deserialize(&public_key_package_bytes)
        .map_err(|e| anyhow!("public_key_package_deserialize_failed: {e}"))?;
    public_key_package = crypto::canonicalize_public_key_package(public_key_package);
    let public_key_package_bytes = public_key_package
        .serialize()
        .map_err(|e| anyhow!("public_key_package_serialize_failed: {e}"))?;

    let ak_bytes = crypto::ak_bytes_from_public_key_package(&public_key_package).map_err(|e| anyhow!(e))?;
    if !crypto::is_canonical_ak_bytes(&ak_bytes) {
        return Err(anyhow!("ak_bytes_non_canonical_after_canonicalization"));
    }

    let pk_hash =
        crypto::public_key_package_hash(&public_key_package, validated_cfg.cfg.max_signers)
            .map_err(|e| anyhow!(e))?;
    if let Some(prev) = public_key_package_hash {
        if prev != pk_hash {
            return Err(anyhow!("public_key_package_hash_inconsistent"));
        }
    }

    run_smoke_tests_online(
        &mut clients,
        ceremony_hash,
        &public_key_package,
        tls.rpc_timeout,
        &options.retry,
        operator_reports,
    )
    .await?;

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
    let owallet_ua = zip316::encode_ua_orchard(
        validated_cfg.cfg.network,
        oaddr.to_raw_address_bytes(),
    )
    .map_err(|e| anyhow!(e))?;

    let transcript_hash = transcript::write_transcript_dir_v1(
        validated_cfg,
        ceremony_hash,
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
        operators: manifest::operators_from_config(validated_cfg),
        ak_bytes_hex: hex::encode(ak_bytes),
        nk_bytes_hex: hex::encode(derived.nk_bytes),
        rivk_bytes_hex: hex::encode(derived.rivk_bytes),
        orchard_fvk_bytes_hex: hex::encode(orchard_fvk_bytes),
        ufvk,
        owallet_ua,
        public_key_package: base64::engine::general_purpose::STANDARD
            .encode(&public_key_package_bytes),
        public_key_package_hash: hex::encode(pk_hash),
        transcript_hash,
    };

    let manifest_path = KeysetManifestV1::output_path(&validated_cfg.cfg.out_dir);
    manifest
        .write_to_path(&manifest_path)
        .with_context(|| format!("write {}", manifest_path.display()))?;

    Ok(OnlineRunOutput {
        manifest_path,
        transcript_dir: validated_cfg.cfg.transcript_dir.clone(),
        report_json_path: None,
    })
}

async fn run_smoke_tests_online(
    clients: &mut [OperatorClient],
    ceremony_hash: &str,
    public_key_package: &redpallas::keys::PublicKeyPackage,
    rpc_timeout: Duration,
    retry: &RetryPolicy,
    operator_reports: &mut BTreeMap<u16, OperatorRunReportV1>,
) -> anyhow::Result<()> {
    smoke_sign_round(
        clients,
        ceremony_hash,
        public_key_package,
        smoke::SMOKE_MESSAGE_V1,
        &smoke::alpha_bytes_standard(),
        rpc_timeout,
        retry,
        operator_reports,
        "smoke_standard",
    )
    .await
    .context("smoke_standard")?;

    let alpha = smoke::alpha_bytes_randomized_fixed();
    smoke_sign_round(
        clients,
        ceremony_hash,
        public_key_package,
        smoke::SMOKE_MESSAGE_V1,
        &alpha,
        rpc_timeout,
        retry,
        operator_reports,
        "smoke_randomized",
    )
    .await
    .context("smoke_randomized")?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn smoke_sign_round(
    clients: &mut [OperatorClient],
    ceremony_hash: &str,
    public_key_package: &redpallas::keys::PublicKeyPackage,
    message: &[u8],
    alpha: &[u8],
    rpc_timeout: Duration,
    retry: &RetryPolicy,
    operator_reports: &mut BTreeMap<u16, OperatorRunReportV1>,
    phase_name_prefix: &str,
) -> anyhow::Result<()> {
    let mut commitments = BTreeMap::<u16, Vec<u8>>::new();
    for op in clients.iter_mut() {
        let phase = format!("{phase_name_prefix}_commit");
        let ceremony_hash_for_commit = ceremony_hash.to_string();
        let message_for_commit = message.to_vec();
        let alpha_for_commit = alpha.to_vec();
        let call = call_with_retry_client(retry, &mut op.client, |client| {
            let ceremony_hash_value = ceremony_hash_for_commit.clone();
            let message_value = message_for_commit.clone();
            let alpha_value = alpha_for_commit.clone();
            Box::pin(async move {
                client
                    .smoke_sign_commit(with_timeout(
                        rpc_timeout,
                        pb::SmokeSignCommitRequest {
                            ceremony_hash: ceremony_hash_value,
                            message: message_value,
                            alpha: alpha_value,
                        },
                    ))
                    .await
                    .map(|resp| resp.into_inner())
            })
        })
        .await;

        match call {
            Ok(v) => {
                record_phase_success(operator_reports, op.identifier, &phase, v.elapsed_ms, v.retries);
                commitments.insert(op.identifier, v.value.signing_commitments);
            }
            Err(e) => {
                record_phase_failure(
                    operator_reports,
                    op.identifier,
                    &phase,
                    e.elapsed_ms,
                    e.retries,
                    &status_code_string(e.status.code()),
                );
                return Err(anyhow!("smoke_sign_commit_failed: {}: {}", op.operator_id, e.status.message()));
            }
        }
    }

    let signing_package_bytes =
        smoke::make_signing_package(commitments, message).map_err(|e| anyhow!(e))?;

    let mut sigshares = BTreeMap::<u16, Vec<u8>>::new();
    for op in clients.iter_mut() {
        let phase = format!("{phase_name_prefix}_share");
        let ceremony_hash_for_share = ceremony_hash.to_string();
        let signing_package_for_share = signing_package_bytes.clone();
        let alpha_for_share = alpha.to_vec();
        let call = call_with_retry_client(retry, &mut op.client, |client| {
            let ceremony_hash_value = ceremony_hash_for_share.clone();
            let signing_package_value = signing_package_for_share.clone();
            let alpha_value = alpha_for_share.clone();
            Box::pin(async move {
                client
                    .smoke_sign_share(with_timeout(
                        rpc_timeout,
                        pb::SmokeSignShareRequest {
                            ceremony_hash: ceremony_hash_value,
                            signing_package: signing_package_value,
                            alpha: alpha_value,
                        },
                    ))
                    .await
                    .map(|resp| resp.into_inner())
            })
        })
        .await;

        match call {
            Ok(v) => {
                record_phase_success(operator_reports, op.identifier, &phase, v.elapsed_ms, v.retries);
                sigshares.insert(op.identifier, v.value.signature_share);
            }
            Err(e) => {
                record_phase_failure(
                    operator_reports,
                    op.identifier,
                    &phase,
                    e.elapsed_ms,
                    e.retries,
                    &status_code_string(e.status.code()),
                );
                return Err(anyhow!("smoke_sign_share_failed: {}: {}", op.operator_id, e.status.message()));
            }
        }
    }

    smoke::aggregate_and_verify(public_key_package, &signing_package_bytes, sigshares, alpha)
        .map_err(|e| anyhow!(e))?;

    Ok(())
}

fn init_operator_reports(
    validated_cfg: &ValidatedCeremonyConfig,
) -> BTreeMap<u16, OperatorRunReportV1> {
    let mut reports = BTreeMap::new();
    for assigned in &validated_cfg.canonical_operators {
        reports.insert(
            assigned.identifier.0,
            OperatorRunReportV1 {
                operator_id: assigned.operator_id.clone(),
                identifier: assigned.identifier.0,
                phase_timings_ms: BTreeMap::new(),
                phase_retries: BTreeMap::new(),
                phase_error_codes: BTreeMap::new(),
            },
        );
    }
    reports
}

fn record_phase_success(
    reports: &mut BTreeMap<u16, OperatorRunReportV1>,
    identifier: u16,
    phase: &str,
    elapsed_ms: u64,
    retries: u32,
) {
    if let Some(op) = reports.get_mut(&identifier) {
        let t = op.phase_timings_ms.entry(phase.to_string()).or_insert(0);
        *t = t.saturating_add(elapsed_ms);
        let r = op.phase_retries.entry(phase.to_string()).or_insert(0);
        *r = r.saturating_add(retries);
    }
}

fn record_phase_failure(
    reports: &mut BTreeMap<u16, OperatorRunReportV1>,
    identifier: u16,
    phase: &str,
    elapsed_ms: u64,
    retries: u32,
    code: &str,
) {
    if let Some(op) = reports.get_mut(&identifier) {
        let t = op.phase_timings_ms.entry(phase.to_string()).or_insert(0);
        *t = t.saturating_add(elapsed_ms);
        let r = op.phase_retries.entry(phase.to_string()).or_insert(0);
        *r = r.saturating_add(retries);
        op.phase_error_codes
            .insert(phase.to_string(), code.to_string());
    }
}

#[derive(Debug)]
struct RetryCallOk<T> {
    value: T,
    retries: u32,
    elapsed_ms: u64,
}

#[derive(Debug)]
struct RetryCallErr {
    status: tonic::Status,
    retries: u32,
    elapsed_ms: u64,
}

async fn call_with_retry_client<C, T, F>(
    retry: &RetryPolicy,
    client: &mut C,
    mut f: F,
) -> Result<RetryCallOk<T>, RetryCallErr>
where
    F: for<'a> FnMut(
        &'a mut C,
    ) -> Pin<Box<dyn Future<Output = Result<T, tonic::Status>> + Send + 'a>>,
{
    let started = Instant::now();
    let mut attempt: u32 = 0;

    loop {
        match f(client).await {
            Ok(value) => {
                return Ok(RetryCallOk {
                    value,
                    retries: attempt,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                })
            }
            Err(status) => {
                let retryable = retry.retryable_codes.contains(&status.code());
                if !retryable || attempt >= retry.max_retries {
                    return Err(RetryCallErr {
                        status,
                        retries: attempt,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        let delay_ms = retry_delay_ms(retry, attempt);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        attempt = attempt.saturating_add(1);
    }
}

fn retry_delay_ms(retry: &RetryPolicy, attempt: u32) -> u64 {
    let base = retry.backoff_start.as_millis() as u64;
    let cap = retry.backoff_max.as_millis() as u64;
    let exp = 1u64 << attempt.min(20);
    let mut delay = base.saturating_mul(exp);
    if cap > 0 {
        delay = delay.min(cap);
    }

    let jitter_max = retry.jitter.as_millis() as u64;
    let jitter = if jitter_max == 0 {
        0
    } else {
        rand::thread_rng().gen_range(0..=jitter_max)
    };
    delay.saturating_add(jitter)
}

async fn connect_all(
    validated_cfg: &ValidatedCeremonyConfig,
    tls: &OnlineTlsConfig,
    tls_material: &TlsMaterial,
    retry: &RetryPolicy,
    operator_reports: &mut BTreeMap<u16, OperatorRunReportV1>,
) -> anyhow::Result<Vec<OperatorClient>> {
    let mut clients = vec![];
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
            .clone()
            .ok_or_else(|| anyhow!("grpc_endpoint_missing_for_operator: {}", assigned.operator_id))?;

        let connect = connect_admin_with_retry(&endpoint, tls, tls_material, retry).await;
        let (client, call) = match connect {
            Ok(v) => v,
            Err(e) => {
                record_phase_failure(
                    operator_reports,
                    assigned.identifier.0,
                    "connect",
                    0,
                    0,
                    "connect_failed",
                );
                return Err(e);
            }
        };
        record_phase_success(
            operator_reports,
            assigned.identifier.0,
            "connect",
            call.elapsed_ms,
            call.retries,
        );
        clients.push(OperatorClient {
            operator_id: assigned.operator_id.clone(),
            identifier: assigned.identifier.0,
            client,
        });
    }
    Ok(clients)
}

async fn connect_admin_with_retry(
    grpc_endpoint: &str,
    tls: &OnlineTlsConfig,
    mat: &TlsMaterial,
    retry: &RetryPolicy,
) -> anyhow::Result<(pb::dkg_admin_client::DkgAdminClient<Channel>, RetryCallOk<()>)> {
    let mut attempt: u32 = 0;
    let started = Instant::now();
    loop {
        match connect_admin(grpc_endpoint, tls, mat).await {
            Ok(client) => {
                return Ok((
                    client,
                    RetryCallOk {
                        value: (),
                        retries: attempt,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    },
                ))
            }
            Err(e) => {
                if !retry.retryable_codes.contains(&Code::Unavailable) || attempt >= retry.max_retries {
                    return Err(anyhow!("connect_failed: endpoint={grpc_endpoint}: {e:#}"));
                }
            }
        }
        let delay_ms = retry_delay_ms(retry, attempt);
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        attempt = attempt.saturating_add(1);
    }
}

fn round2_key(sender: u16, receiver: u16) -> String {
    format!("{sender}:{receiver}")
}

fn load_or_init_state(path: &Path, ceremony_hash: &str, resume: bool) -> anyhow::Result<OnlineStateV1> {
    if !path.exists() {
        if resume {
            return Err(anyhow!("resume_state_missing: {}", path.display()));
        }
        let state = OnlineStateV1 {
            state_version: ONLINE_STATE_VERSION,
            ceremony_hash: ceremony_hash.to_string(),
            round1_packages: BTreeMap::new(),
            round2_hashes: BTreeMap::new(),
            part3_completed: BTreeMap::new(),
        };
        save_state(path, &state)?;
        return Ok(state);
    }

    if !resume {
        let state = OnlineStateV1 {
            state_version: ONLINE_STATE_VERSION,
            ceremony_hash: ceremony_hash.to_string(),
            round1_packages: BTreeMap::new(),
            round2_hashes: BTreeMap::new(),
            part3_completed: BTreeMap::new(),
        };
        save_state(path, &state)?;
        return Ok(state);
    }

    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let state: OnlineStateV1 =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("online_state_parse_failed"))?;
    if state.state_version != ONLINE_STATE_VERSION {
        return Err(anyhow!("online_state_version_invalid"));
    }
    if state.ceremony_hash != ceremony_hash {
        return Err(anyhow!("online_state_ceremony_hash_mismatch"));
    }
    Ok(state)
}

fn save_state(path: &Path, state: &OnlineStateV1) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(state).map_err(|_| anyhow!("online_state_serialize_failed"))?;
    let tmp_path = path.with_extension("json.tmp");
    std::fs::write(&tmp_path, &bytes).with_context(|| format!("write {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), path.display()))?;
    Ok(())
}

fn read_round1_from_state(
    max_signers: u16,
    state: &OnlineStateV1,
) -> anyhow::Result<BTreeMap<u16, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for (sender, b64) in &state.round1_packages {
        if *sender == 0 || *sender > max_signers {
            return Err(anyhow!("round1_state_identifier_out_of_range: {sender}"));
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| anyhow!("round1_state_b64_invalid"))?;
        out.insert(*sender, bytes);
    }
    Ok(out)
}

fn decode_hex_32(value: &str, label: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(value.trim()).map_err(|_| anyhow!("{label}_hex_invalid"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("{label}_len_invalid"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn phase_name(phase: i32) -> &'static str {
    match phase {
        1 => "empty",
        2 => "round1",
        3 => "round2",
        4 => "part3",
        _ => "unspecified",
    }
}

fn opt_hash_hex(bytes: &[u8]) -> anyhow::Result<Option<String>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != 32 {
        return Err(anyhow!("status_hash_len_invalid"));
    }
    Ok(Some(hex::encode(bytes)))
}

fn parse_tonic_code(input: &str) -> Option<Code> {
    let token = input.trim().to_ascii_lowercase().replace('-', "_");
    match token.as_str() {
        "ok" => Some(Code::Ok),
        "cancelled" => Some(Code::Cancelled),
        "unknown" => Some(Code::Unknown),
        "invalid_argument" => Some(Code::InvalidArgument),
        "deadline_exceeded" => Some(Code::DeadlineExceeded),
        "not_found" => Some(Code::NotFound),
        "already_exists" => Some(Code::AlreadyExists),
        "permission_denied" => Some(Code::PermissionDenied),
        "resource_exhausted" => Some(Code::ResourceExhausted),
        "failed_precondition" => Some(Code::FailedPrecondition),
        "aborted" => Some(Code::Aborted),
        "out_of_range" => Some(Code::OutOfRange),
        "unimplemented" => Some(Code::Unimplemented),
        "internal" => Some(Code::Internal),
        "unavailable" => Some(Code::Unavailable),
        "data_loss" => Some(Code::DataLoss),
        "unauthenticated" => Some(Code::Unauthenticated),
        _ => None,
    }
}

fn status_code_string(code: Code) -> String {
    format!("grpc_{}", tonic_code_label(code))
}

fn tonic_code_label(code: Code) -> &'static str {
    match code {
        Code::Ok => "ok",
        Code::Cancelled => "cancelled",
        Code::Unknown => "unknown",
        Code::InvalidArgument => "invalid_argument",
        Code::DeadlineExceeded => "deadline_exceeded",
        Code::NotFound => "not_found",
        Code::AlreadyExists => "already_exists",
        Code::PermissionDenied => "permission_denied",
        Code::ResourceExhausted => "resource_exhausted",
        Code::FailedPrecondition => "failed_precondition",
        Code::Aborted => "aborted",
        Code::OutOfRange => "out_of_range",
        Code::Unimplemented => "unimplemented",
        Code::Internal => "internal",
        Code::Unavailable => "unavailable",
        Code::DataLoss => "data_loss",
        Code::Unauthenticated => "unauthenticated",
    }
}

fn write_json_report(path: &Path, report: &impl Serialize) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(report).map_err(|_| anyhow!("report_serialize_failed"))?;
    std::fs::write(path, bytes).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn read_manifest_public_key_package_hash(path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| anyhow!("manifest_parse_failed"))?;
    let hash = value
        .get("public_key_package_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("manifest_public_key_package_hash_missing"))?
        .trim()
        .to_ascii_lowercase();
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("manifest_public_key_package_hash_invalid"));
    }
    Ok(hash)
}

fn build_export_request(
    ceremony_hash: &str,
    identifier: u16,
    options: &ExportKeyPackagesOptions,
) -> anyhow::Result<pb::ExportEncryptedKeyPackageRequest> {
    let encryption = match &options.encryption {
        ExportEncryption::Age { recipients } => pb::EncryptionConfig {
            backend: Some(pb::encryption_config::Backend::Age(pb::AgeEncryption {
                recipients: recipients.clone(),
            })),
        },
        ExportEncryption::AwsKms { kms_key_id } => pb::EncryptionConfig {
            backend: Some(pb::encryption_config::Backend::AwsKms(pb::AwsKmsEncryption {
                kms_key_id: kms_key_id.clone(),
            })),
        },
    };

    let target = match &options.target {
        ExportTarget::RemoteFilePrefix { remote_file_prefix } => {
            let path = format!("{remote_file_prefix}_{identifier:02}.json");
            pb::ExportTarget {
                target: Some(pb::export_target::Target::File(pb::FileTarget { path })),
            }
        }
        ExportTarget::S3 {
            bucket,
            key_prefix,
            sse_kms_key_id,
        } => {
            let key = format!(
                "{}/operator_{identifier:02}.json",
                key_prefix.trim_end_matches('/')
            );
            pb::ExportTarget {
                target: Some(pb::export_target::Target::S3(pb::S3Target {
                    bucket: bucket.clone(),
                    key,
                    sse_kms_key_id: sse_kms_key_id.clone(),
                })),
            }
        }
    };

    Ok(pb::ExportEncryptedKeyPackageRequest {
        ceremony_hash: ceremony_hash.to_string(),
        encryption: Some(encryption),
        target: Some(target),
    })
}

fn validate_export_receipt(
    receipt_bytes: &[u8],
    validated_cfg: &ValidatedCeremonyConfig,
    expected_identifier: u16,
    expected_operator_id: &str,
    expected_public_key_package_hash: &str,
) -> anyhow::Result<()> {
    let v: serde_json::Value =
        serde_json::from_slice(receipt_bytes).map_err(|_| anyhow!("receipt_parse_failed"))?;

    let receipt_version = v
        .get("receipt_version")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("receipt_version_missing"))?;
    if receipt_version != "key_import_receipt_v1" {
        return Err(anyhow!("receipt_version_invalid"));
    }

    let operator_id = v
        .get("operator_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("receipt_operator_id_missing"))?;
    if operator_id.trim() != expected_operator_id {
        return Err(anyhow!("receipt_operator_id_mismatch"));
    }

    let identifier = v
        .get("identifier")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| anyhow!("receipt_identifier_missing"))?;
    if identifier != expected_identifier as u64 {
        return Err(anyhow!("receipt_identifier_mismatch"));
    }

    let threshold = v
        .get("threshold")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| anyhow!("receipt_threshold_missing"))?;
    if threshold != validated_cfg.cfg.threshold as u64 {
        return Err(anyhow!("receipt_threshold_mismatch"));
    }

    let max_signers = v
        .get("max_signers")
        .and_then(|x| x.as_u64())
        .ok_or_else(|| anyhow!("receipt_max_signers_missing"))?;
    if max_signers != validated_cfg.cfg.max_signers as u64 {
        return Err(anyhow!("receipt_max_signers_mismatch"));
    }

    let network = v
        .get("network")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("receipt_network_missing"))?;
    if network != validated_cfg.cfg.network.as_str() {
        return Err(anyhow!("receipt_network_mismatch"));
    }

    let roster_hash_hex = v
        .get("roster_hash_hex")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("receipt_roster_hash_missing"))?;
    if roster_hash_hex.trim() != validated_cfg.cfg.roster_hash_hex {
        return Err(anyhow!("receipt_roster_hash_mismatch"));
    }

    let pk_hash_hex = v
        .get("public_key_package_hash_hex")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("receipt_public_key_package_hash_missing"))?
        .to_ascii_lowercase();
    if pk_hash_hex != expected_public_key_package_hash {
        return Err(anyhow!("receipt_public_key_package_hash_mismatch"));
    }

    let keyset_id = v
        .get("keyset_id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("receipt_keyset_id_missing"))?
        .to_ascii_lowercase();
    if keyset_id != expected_public_key_package_hash {
        return Err(anyhow!("receipt_keyset_id_mismatch"));
    }

    let blob_hash = v
        .get("encrypted_blob_sha256_hex")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow!("receipt_encrypted_blob_sha256_hex_missing"))?;
    if blob_hash.len() != 64 || !blob_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("receipt_encrypted_blob_sha256_hex_invalid"));
    }

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
