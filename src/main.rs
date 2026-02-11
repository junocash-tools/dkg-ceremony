use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use clap::{ArgGroup, Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::EnvFilter;

use dkg_ceremony::config::CeremonyConfigV1;
use dkg_ceremony::offline;
use dkg_ceremony::online::{self, OnlineTlsConfig, RetryPolicy};

const LONG_VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    "\ncommit=",
    env!("DKG_CEREMONY_GIT_COMMIT")
);

#[derive(Debug, Parser)]
#[command(name = "dkg-ceremony", version, long_version = LONG_VERSION, about)]
struct Cli {
    /// Path to the ceremony config JSON.
    #[arg(long, default_value = "config.json")]
    config: PathBuf,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a full online ceremony as coordinator over mTLS gRPC to each operator's dkg-admin.
    Online(OnlineArgs),

    /// Preflight checks for online transport/readiness.
    Preflight(PreflightArgs),

    /// Trigger operator-side encrypted key package export after DKG and validate receipts.
    ExportKeyPackages(ExportKeyPackagesArgs),

    /// TLS bootstrap helpers.
    Tls {
        #[command(subcommand)]
        cmd: TlsCommand,
    },

    /// Offline ceremony transport helpers (file routing, and public transcript/manifest generation).
    Offline {
        #[command(subcommand)]
        cmd: OfflineCommand,
    },
}

#[derive(Debug, Clone, clap::Args)]
struct TransportArgs {
    /// CA certificate PEM used to validate operator server certificates.
    #[arg(long)]
    tls_ca_cert_pem_path: PathBuf,

    /// Coordinator client certificate PEM for mTLS.
    #[arg(long)]
    tls_client_cert_pem_path: PathBuf,

    /// Coordinator client private key PEM for mTLS.
    #[arg(long)]
    tls_client_key_pem_path: PathBuf,

    /// Optional TLS domain name (SNI) override to use for all endpoints.
    #[arg(long)]
    tls_domain_name_override: Option<String>,

    /// gRPC connect timeout in milliseconds.
    #[arg(long, default_value_t = 10_000)]
    connect_timeout_ms: u64,

    /// Per-RPC timeout in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    rpc_timeout_ms: u64,

    /// Retry count after the first attempt.
    #[arg(long, default_value_t = 3)]
    max_retries: u32,

    /// Initial backoff in milliseconds.
    #[arg(long, default_value_t = 250)]
    backoff_start_ms: u64,

    /// Max backoff in milliseconds.
    #[arg(long, default_value_t = 3_000)]
    backoff_max_ms: u64,

    /// Retry jitter cap in milliseconds.
    #[arg(long, default_value_t = 100)]
    jitter_ms: u64,

    /// Comma-separated gRPC status codes that are retryable.
    /// Example: unavailable,deadline_exceeded
    #[arg(long, default_value = "unavailable,deadline_exceeded")]
    retryable_codes: String,
}

impl TransportArgs {
    fn to_tls_and_retry(&self) -> anyhow::Result<(OnlineTlsConfig, RetryPolicy)> {
        let retryable_codes = online::parse_retryable_codes_csv(&self.retryable_codes)?;
        let tls = OnlineTlsConfig {
            tls_ca_cert_pem_path: self.tls_ca_cert_pem_path.clone(),
            tls_client_cert_pem_path: self.tls_client_cert_pem_path.clone(),
            tls_client_key_pem_path: self.tls_client_key_pem_path.clone(),
            tls_domain_name_override: self.tls_domain_name_override.clone(),
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
            rpc_timeout: Duration::from_millis(self.rpc_timeout_ms),
        };
        let retry = RetryPolicy {
            max_retries: self.max_retries,
            backoff_start: Duration::from_millis(self.backoff_start_ms),
            backoff_max: Duration::from_millis(self.backoff_max_ms),
            jitter: Duration::from_millis(self.jitter_ms),
            retryable_codes,
        };
        Ok((tls, retry))
    }
}

#[derive(Debug, clap::Args)]
struct OnlineArgs {
    #[command(flatten)]
    transport: TransportArgs,

    /// Directory for resumable online coordinator state.
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// Resume from persisted online coordinator state.
    #[arg(long, default_value_t = false)]
    resume: bool,

    /// Optional JSON report output path.
    #[arg(long)]
    report_json: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
struct PreflightArgs {
    #[command(flatten)]
    transport: TransportArgs,

    /// Optional JSON report output path.
    #[arg(long)]
    report_json: Option<PathBuf>,
}

#[derive(Debug, clap::Args)]
#[command(group(
    ArgGroup::new("encryption")
        .required(true)
        .args(["age_recipient", "kms_key_id"])
))]
#[command(group(
    ArgGroup::new("target")
        .required(true)
        .args(["remote_file_prefix", "s3_bucket"])
))]
struct ExportKeyPackagesArgs {
    #[command(flatten)]
    transport: TransportArgs,

    /// Path to the KeysetManifest.json from the completed ceremony.
    #[arg(long)]
    manifest_path: PathBuf,

    /// Local directory to write receipt copies.
    #[arg(long, default_value = "out/export-receipts")]
    receipts_dir: PathBuf,

    /// Optional JSON report output path.
    #[arg(long)]
    report_json: Option<PathBuf>,

    /// age recipients (age1...) used for each operator export.
    #[arg(long, value_name = "AGE_RECIPIENT", num_args = 1..)]
    age_recipient: Vec<String>,

    /// AWS KMS key id/arn used for each operator export.
    #[arg(long, value_name = "KMS_KEY_ID")]
    kms_key_id: Option<String>,

    /// Remote file path prefix; coordinator appends `_<identifier>.json`.
    #[arg(long)]
    remote_file_prefix: Option<String>,

    /// S3 bucket for operator export target.
    #[arg(long)]
    s3_bucket: Option<String>,
    /// S3 key prefix; coordinator appends `/operator_<identifier>.json`.
    #[arg(long)]
    s3_key_prefix: Option<String>,
    /// S3 SSE-KMS key id for storage encryption.
    #[arg(long)]
    s3_sse_kms_key_id: Option<String>,
}

#[derive(Debug, Subcommand)]
enum TlsCommand {
    /// Generate ceremony CA, coordinator cert, and per-operator SAN-valid server certs.
    Init {
        /// Output directory for generated TLS materials.
        #[arg(long)]
        out_dir: PathBuf,

        /// Coordinator certificate common name.
        #[arg(long, default_value = "dkg-coordinator")]
        coordinator_common_name: String,
    },
}

#[derive(Debug, Subcommand)]
enum OfflineCommand {
    /// Bundle Round 1 packages for delivery to each operator.
    BundleRound1 {
        /// Directory containing `round1_<id>.bin` for all participants.
        #[arg(long)]
        round1_dir: PathBuf,

        /// Output directory for per-operator bundles (`round1_to_<id>/...`).
        #[arg(long)]
        deliver_dir: PathBuf,
    },

    /// Bundle Round 2 encrypted packages for delivery to each operator.
    BundleRound2 {
        /// Directory containing all `round2_to_<recv>_from_<sender>.age` files.
        #[arg(long)]
        round2_dir: PathBuf,

        /// Output directory for per-operator bundles (`round2_to_<id>/...`).
        #[arg(long)]
        deliver_dir: PathBuf,
    },

    /// Generate the public `KeysetManifest.json` and non-secret transcript directory.
    Finalize {
        /// Directory containing `round1_<id>.bin` for all participants.
        #[arg(long)]
        round1_dir: PathBuf,

        /// Directory containing all `round2_to_<recv>_from_<sender>.age` files.
        #[arg(long)]
        round2_dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let cfg = CeremonyConfigV1::from_path(&cli.config)
        .context("read config")?
        .validate()
        .context("validate config")?;

    match cli.cmd {
        Command::Online(args) => {
            let (tls, retry) = args.transport.to_tls_and_retry()?;
            let opts = online::OnlineRunOptions {
                state_dir: args
                    .state_dir
                    .unwrap_or_else(|| cfg.cfg.out_dir.join("online-state")),
                resume: args.resume,
                retry,
                report_json_path: args.report_json,
            };
            let out = online::run_with_options(cfg, tls, opts).await?;
            tracing::info!("wrote {}", out.manifest_path.display());
            tracing::info!("transcript {}", out.transcript_dir.display());
            if let Some(report_json_path) = out.report_json_path {
                tracing::info!("report {}", report_json_path.display());
            }
            Ok(())
        }
        Command::Preflight(args) => {
            let (tls, retry) = args.transport.to_tls_and_retry()?;
            let report = online::preflight(&cfg, &tls, &retry).await?;
            if let Some(path) = args.report_json {
                let bytes = serde_json::to_vec_pretty(&report).context("preflight_report_serialize_failed")?;
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("create {}", parent.display()))?;
                }
                std::fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
                tracing::info!("preflight_report {}", path.display());
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report)
                        .context("preflight_report_serialize_failed")?
                );
            }

            if !report.ready {
                anyhow::bail!("preflight_not_ready");
            }
            Ok(())
        }
        Command::ExportKeyPackages(args) => {
            let (tls, retry) = args.transport.to_tls_and_retry()?;
            let encryption = if !args.age_recipient.is_empty() {
                online::ExportEncryption::Age {
                    recipients: args.age_recipient,
                }
            } else if let Some(kms_key_id) = args.kms_key_id {
                online::ExportEncryption::AwsKms { kms_key_id }
            } else {
                anyhow::bail!("export_encryption_missing");
            };

            let target = if let Some(remote_file_prefix) = args.remote_file_prefix {
                online::ExportTarget::RemoteFilePrefix { remote_file_prefix }
            } else if let Some(bucket) = args.s3_bucket {
                let key_prefix = args
                    .s3_key_prefix
                    .ok_or_else(|| anyhow::anyhow!("s3_key_prefix_missing"))?;
                let sse_kms_key_id = args
                    .s3_sse_kms_key_id
                    .ok_or_else(|| anyhow::anyhow!("s3_sse_kms_key_id_missing"))?;
                online::ExportTarget::S3 {
                    bucket,
                    key_prefix,
                    sse_kms_key_id,
                }
            } else {
                anyhow::bail!("export_target_missing");
            };

            let out = online::export_key_packages(
                cfg,
                tls,
                online::ExportKeyPackagesOptions {
                    retry,
                    manifest_path: args.manifest_path,
                    receipts_dir: args.receipts_dir,
                    report_json_path: args.report_json,
                    encryption,
                    target,
                },
            )
            .await?;
            tracing::info!("exported receipts {}", out.receipts_dir.display());
            if let Some(report_json_path) = out.report_json_path {
                tracing::info!("report {}", report_json_path.display());
            }
            Ok(())
        }
        Command::Tls { cmd } => match cmd {
            TlsCommand::Init {
                out_dir,
                coordinator_common_name,
            } => {
                let out = dkg_ceremony::tls::init(
                    &cfg,
                    dkg_ceremony::tls::TlsInitOptions {
                        out_dir,
                        coordinator_common_name,
                    },
                )?;
                tracing::info!("wrote {}", out.ca_cert_pem_path.display());
                tracing::info!("wrote {}", out.coordinator_cert_pem_path.display());
                tracing::info!(
                    "coordinator_client_cert_sha256={}",
                    out.coordinator_cert_sha256_hex
                );
                Ok(())
            }
        },
        Command::Offline { cmd } => match cmd {
            OfflineCommand::BundleRound1 {
                round1_dir,
                deliver_dir,
            } => {
                offline::bundle_round1(&cfg, &round1_dir, &deliver_dir)?;
                Ok(())
            }
            OfflineCommand::BundleRound2 {
                round2_dir,
                deliver_dir,
            } => {
                offline::bundle_round2(&cfg, &round2_dir, &deliver_dir)?;
                Ok(())
            }
            OfflineCommand::Finalize { round1_dir, round2_dir } => {
                let out = offline::finalize(cfg, &round1_dir, &round2_dir)?;
                tracing::info!("wrote {}", out.manifest_path.display());
                tracing::info!("transcript {}", out.transcript_dir.display());
                Ok(())
            }
        },
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{}=info", env!("CARGO_PKG_NAME"))));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_level(true)
        .with_max_level(Level::INFO)
        .init();
}
