//! Command-line entry point for `ndp-responder-lite`.

#[cfg(not(target_os = "linux"))]
compile_error!("ndp-responder-lite supports Linux only");

use clap::Parser;
use ndp_responder_lite::config::Config;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

/// Command-line arguments accepted by the daemon.
#[derive(Parser)]
#[command(version, about = "Linux static IPv6 neighbor discovery responder.")]
struct Args {
    /// Path to TOML configuration file.
    #[arg(short, long, default_value = "/etc/ndp-responder-lite.toml")]
    config: PathBuf,
    /// Validate configuration and exit without starting network operations.
    #[arg(long)]
    check: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let config = Config::load_from_path(&args.config)?;
    if args.check {
        println!("configuration valid");
        return Ok(());
    }
    ndp_responder_lite::linux::run_daemon(config).await
}
