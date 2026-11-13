//! `via-agent` -- the viaos device agent.
//!
//! Runs on the host, outside the stack it manages. `mcp` serves the device's
//! tools over stdio, so `ssh device via-agent mcp` is a complete management
//! connection with no control plane involved.

mod config;
mod deploy;
mod env;
mod host;
mod link;
mod metrics;
mod os;
mod proxy;
mod ready;
mod shell;
mod system;
mod tools;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};
use rmcp::ServiceExt;

use tools::Device;

#[derive(Parser)]
#[command(name = "via-agent", version, about = "viaos device agent")]
struct Cli {
    /// Where release state is kept.
    #[arg(long, env = "VIA_DATA_DIR", default_value = "/var/lib/via")]
    data_dir: PathBuf,

    /// The device configuration file.
    #[arg(long, env = "VIA_CONFIG", default_value = "/boot/viaos.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as the device daemon: apply viaos.toml, then stay up.
    Run,
    /// Apply viaos.toml's Wi-Fi, network, time and proxy settings. Runs
    /// once per boot, before the network and Docker start.
    System,
    /// Serve this device's MCP tools on stdin/stdout.
    Mcp,
    /// Print device health as JSON.
    Health,
    /// Wait until this boot is good: Docker answers and, with a control
    /// plane configured, the agent has reached it. Marks the boot entry
    /// good or bad; see ready.rs.
    Ready {
        #[arg(long, default_value_t = 300)]
        timeout_secs: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logs go to stderr: on `mcp`, stdout is the protocol.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,rmcp=warn".into()),
        )
        .init();

    let cli = Cli::parse();
    let cfg = config::Config::load(&cli.config)?;
    // Before the trust policy: a bad key there is no reason to stay offline.
    if let Command::System = cli.command {
        system::apply(&cfg.system, &system::Paths::system(&cli.data_dir));
        return Ok(());
    }
    let device = Device::new(cli.data_dir.clone(), cfg.trust_policy()?);
    match cli.command {
        Command::Run => {
            cfg.apply(&cli.data_dir);
            if deploy::recover(&cli.data_dir).await {
                device.retry_env();
            }
            // Not waited for: reaching the control plane is what marks a new OS
            // good, and a slow app shouldn't hold that up.
            let data_dir = cli.data_dir.clone();
            tokio::spawn(async move { deploy::reconcile(&data_dir).await });
            tracing::info!(hostname = ?cfg.hostname, control = cfg.control.is_some(), "configured");
            device.start_metrics(cli.data_dir.clone());
            match cfg.control {
                Some(control) => link::run(control, cli.data_dir, device).await,
                // No control plane: the device runs its containers and
                // answers MCP over SSH. Nothing else to do but stay up.
                None => std::future::pending::<()>().await,
            }
        }
        Command::Mcp => {
            device
                .serve(rmcp::transport::stdio())
                .await?
                .waiting()
                .await?;
        }
        Command::System => unreachable!("applied above"),
        Command::Health => {
            println!("{}", serde_json::to_string_pretty(&device.health().await)?);
        }
        Command::Ready { timeout_secs } => {
            ready::run(
                cfg.control.is_some(),
                std::time::Duration::from_secs(timeout_secs),
            )
            .await?;
        }
    }
    Ok(())
}
