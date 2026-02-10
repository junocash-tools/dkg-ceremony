use std::path::PathBuf;

use anyhow::Context as _;
use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::EnvFilter;

use dkg_ceremony::config::CeremonyConfigV1;
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

