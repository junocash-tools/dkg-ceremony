use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::EnvFilter;

use dkg_ceremony::config::CeremonyConfigV1;
use dkg_ceremony::offline;
use dkg_ceremony::online::{self, OnlineTlsConfig};

#[derive(Debug, Parser)]
#[command(name = "dkg-ceremony", version, about)]
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

    /// Offline ceremony transport helpers (file routing, and public transcript/manifest generation).
    Offline {
        #[command(subcommand)]
        cmd: OfflineCommand,
    },
}

#[derive(Debug, clap::Args)]
struct OnlineArgs {
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
            let tls = OnlineTlsConfig {
                tls_ca_cert_pem_path: args.tls_ca_cert_pem_path,
                tls_client_cert_pem_path: args.tls_client_cert_pem_path,
                tls_client_key_pem_path: args.tls_client_key_pem_path,
                tls_domain_name_override: args.tls_domain_name_override,
                ..OnlineTlsConfig::default()
            };
            let out = online::run(cfg, tls).await?;
            tracing::info!("wrote {}", out.manifest_path.display());
            tracing::info!("transcript {}", out.transcript_dir.display());
            Ok(())
        }
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
