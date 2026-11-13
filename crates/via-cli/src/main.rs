//! `via` -- viaos tools for the operator's own machine.
//!
//! `via mcp` serves the tools that only make sense where the operator is:
//! writing a provisioning image to an SD card or USB disk plugged in here,
//! and building an app release from a compose file on this machine.
//! Anything that talks to the control plane needs `VIA_SERVER` and
//! `VIA_TOKEN`; signing takes a key from `via keygen`.
//! The fleet's tools live on the control plane; Claude uses both, e.g.
//! `create_provisioning_image` there, then `flash_image` here.

mod build;
mod flash;
mod keys;
mod remote;
mod secureboot;

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::{ErrorData, ServerHandler, ServiceExt, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Parser)]
#[command(name = "via", version, about = "viaos operator tools")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve local tools (disk flashing) over MCP on stdin/stdout.
    Mcp,
    /// List disks and whether `flash_image` would write to them.
    Disks,
    /// Build an app release from a compose file and upload it.
    Release {
        /// Compose file.
        #[arg(short, long, default_value = "compose.yaml")]
        file: std::path::PathBuf,
        /// Application name. Defaults to the compose file's directory name.
        #[arg(short, long)]
        app: Option<String>,
        /// Release number. Releases are immutable; use a new number each time.
        #[arg(short, long)]
        release: u64,
        /// Architectures to build for.
        #[arg(long, default_value = "x86_64")]
        arch: Vec<String>,
        /// Use images already present locally instead of `docker build`.
        #[arg(long)]
        no_build: bool,
        /// A key to sign it with, for servers that set VIA_TRUSTED_KEYS.
        /// Without one it goes out unsigned.
        #[arg(long, env = "VIA_SIGNING_KEY")]
        sign_key: Option<PathBuf>,
    },
    /// Make a signing key for OS updates and app releases.
    Keygen {
        /// Where to write it; the public key goes beside it as `<path>.pub`.
        path: PathBuf,
    },
    /// Sign and upload an OS update: the output of `nix build .#updates.<arch>`.
    OsRelease {
        dir: PathBuf,
        /// A key to sign it with, for servers that set VIA_TRUSTED_KEYS.
        /// Without one it goes out unsigned.
        #[arg(long, env = "VIA_SIGNING_KEY")]
        sign_key: Option<PathBuf>,
        /// Secure Boot keys to sign it with. Without them, Secure Boot is off.
        #[arg(long, env = "VIA_SECURE_BOOT_KEYS")]
        secure_boot: Option<PathBuf>,
    },
    /// Upload a raw image (`nix build .#images.<arch>`) as the base that
    /// provisioning images are made from.
    BaseImage {
        raw: PathBuf,
        /// A device type on the server, or an architecture to share the image
        /// among all its device types.
        #[arg(long = "device-type", visible_alias = "arch")]
        arch: String,
        /// Secure Boot keys to sign it with, which devices in setup mode then
        /// enroll. Without them, Secure Boot is off.
        #[arg(long, env = "VIA_SECURE_BOOT_KEYS")]
        secure_boot: Option<PathBuf>,
    },
    /// Secure Boot keys.
    #[command(subcommand)]
    SecureBoot(SecureBoot),
    /// Carry a TCP stream to a port on a device over stdin/stdout. For
    /// `ssh -o ProxyCommand='via tunnel %n 22'`.
    Tunnel { device: String, port: u16 },
    /// SSH to a device through the control plane, wherever it is.
    Ssh {
        device: String,
        /// Arguments passed to ssh after the destination, e.g. a command.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Listen on a local port and forward each connection to a port on a
    /// device, e.g. `via forward line-07 8080 8080`.
    Forward {
        device: String,
        port: u16,
        local_port: u16,
    },
}

#[derive(Subcommand)]
enum SecureBoot {
    /// Make a PK, KEK and db for a fleet's devices to enroll.
    Keygen { dir: PathBuf },
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReleaseArgs {
    /// Path to the compose file on this machine.
    compose_file: String,
    /// Application name. Defaults to the compose file's directory name.
    #[serde(default)]
    app: Option<String>,
    /// Release number. Releases are immutable: use the next unused number,
    /// which `list_releases` on the control plane shows.
    release: u64,
    /// Architectures to build for: `x86_64` and/or `aarch64`. Build for every
    /// architecture the fleet has. Defaults to x86_64.
    #[serde(default)]
    archs: Vec<String>,
    /// Use images already present locally instead of running `docker build`.
    #[serde(default)]
    no_build: bool,
}

/// Build a bundle per architecture and upload each to the control plane.
fn release(
    file: PathBuf,
    app: Option<String>,
    number: u64,
    archs: Vec<String>,
    no_build: bool,
    sign_key: Option<PathBuf>,
) -> Result<Value> {
    let remote = remote::Remote::from_env()?;
    let archs = if archs.is_empty() {
        vec!["x86_64".to_string()]
    } else {
        archs
    };
    let out_dir = std::env::temp_dir().join(format!("via-release-{}", std::process::id()));
    std::fs::create_dir_all(&out_dir)?;

    let mut results = Vec::new();
    let mut app_name = String::new();
    for arch in &archs {
        let platform = match arch.as_str() {
            "x86_64" => "linux/amd64",
            "aarch64" => "linux/arm64",
            other => anyhow::bail!("unknown arch {other:?}; use x86_64 or aarch64"),
        };
        let built = build::build(build::BuildArgs {
            file: Some(file.clone()),
            app: app.clone(),
            release: number,
            platform: Some(platform.into()),
            output: Some(out_dir.join(format!("{arch}.bundle"))),
            profile: Vec::new(),
            strict: false,
            no_build,
            compression: 3,
            sign_key: sign_key.clone(),
        })?;
        let uploaded = remote.put_file(
            &format!("/v1/releases/{}/{number}/{arch}", built.app),
            &built.path,
        );
        let _ = std::fs::remove_file(&built.path);
        uploaded.with_context(|| format!("uploading the {arch} build"))?;
        app_name = built.app.clone();
        results.push(json!({
            "arch": arch,
            "sha256": built.sha256,
            "size_mb": built.size_bytes / 1_048_576,
            "signed": built.signed,
            "warnings": built.warnings,
        }));
    }
    let _ = std::fs::remove_dir_all(&out_dir);
    Ok(
        json!({ "app": app_name, "release": number, "uploaded": results,
               "next": "Deploy it with `deploy` on the control plane (dry_run first)." }),
    )
}

#[derive(Clone)]
struct Local {
    flasher: flash::Flasher,
    tool_router: ToolRouter<Self>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FlashArgs {
    /// Image to write: the `download` URL from `create_provisioning_image`,
    /// or a local file. zstd-compressed images are decompressed on the fly.
    source: String,
    /// Disk path from `list_disks`, e.g. /dev/sdb. Must be writable there.
    disk: String,
    /// The disk's `size_bytes` from `list_disks`. Writing is refused if it
    /// no longer matches, which catches a card swapped in the meantime.
    size_bytes: u64,
}

fn rendered(value: Value) -> CallToolResult {
    let text = serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string());
    let mut r = CallToolResult::structured(value);
    r.content = vec![ContentBlock::text(text)];
    r
}

fn reported(result: Result<Value>) -> Result<CallToolResult, ErrorData> {
    Ok(match result {
        Ok(v) => rendered(v),
        Err(e) => CallToolResult::error(vec![ContentBlock::text(format!("{e:#}"))]),
    })
}

#[tool_router(router = tool_router)]
impl Local {
    #[tool(
        description = "Disks attached to this machine: path, size, model, transport, and \
                       whether flash_image will write to it. Only unmounted removable or USB \
                       disks are writable. Show the user the model and size before flashing. \
                       Reads only.",
        annotations(title = "List disks", read_only_hint = true, open_world_hint = false)
    )]
    async fn list_disks(&self) -> Result<CallToolResult, ErrorData> {
        reported(flash::list().map(|d| json!({ "disks": d })))
    }

    #[tool(
        description = "ERASE a removable disk and write a viaos image to it. Everything on the \
                       disk is lost. Confirm the disk's model and size with the user first. Runs \
                       in the background; `flash_status` reports progress. When it is done, put \
                       the card or disk in the device and power it on.",
        annotations(title = "Flash image", read_only_hint = false, destructive_hint = true)
    )]
    async fn flash_image(
        &self,
        Parameters(a): Parameters<FlashArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        reported(
            self.flasher
                .start(a.source, a.disk.clone(), a.size_bytes)
                .map(|()| json!({ "disk": a.disk, "state": "writing" })),
        )
    }

    #[tool(
        description = "Build an app release from a compose file on this machine and upload it \
                       to the control plane: images are built or taken from the local Docker, \
                       packed into one self-contained bundle per architecture, and uploaded. \
                       Devices need no registry. Can take minutes. Then use `deploy` on the \
                       control plane.",
        annotations(
            title = "Release app",
            read_only_hint = false,
            destructive_hint = false
        )
    )]
    async fn release_app(
        &self,
        Parameters(a): Parameters<ReleaseArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let r = tokio::task::spawn_blocking(move || {
            let key = std::env::var_os("VIA_SIGNING_KEY").map(PathBuf::from);
            release(
                a.compose_file.into(),
                a.app,
                a.release,
                a.archs,
                a.no_build,
                key,
            )
        })
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;
        reported(r)
    }

    #[tool(
        description = "Progress of the current or last flash_image. Reads only.",
        annotations(title = "Flash status", read_only_hint = true, open_world_hint = false)
    )]
    async fn flash_status(&self) -> Result<CallToolResult, ErrorData> {
        reported(Ok(json!({ "job": self.flasher.status() })))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for Local {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("via-local", env!("CARGO_PKG_VERSION")))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    match Cli::parse().command {
        Command::Mcp => {
            let local = Local {
                flasher: Default::default(),
                tool_router: Local::tool_router(),
            };
            local
                .serve(rmcp::transport::stdio())
                .await?
                .waiting()
                .await?;
        }
        Command::Disks => println!("{}", serde_json::to_string_pretty(&flash::list()?)?),
        Command::Release {
            file,
            app,
            release: number,
            arch,
            no_build,
            sign_key,
        } => {
            let r = tokio::task::spawn_blocking(move || {
                release(
                    file,
                    app,
                    number,
                    arch,
                    no_build,
                    keys::signing_key(sign_key)?,
                )
            })
            .await??;
            print_json(&r)?;
        }
        Command::Keygen { path } => print_json(&remote::keygen(&path)?)?,
        Command::OsRelease {
            dir,
            sign_key,
            secure_boot,
        } => {
            let remote = remote::Remote::from_env()?;
            let r = tokio::task::spawn_blocking(move || {
                let sign_key = keys::signing_key(sign_key)?;
                let sign_key = sign_key.as_deref();
                match keys::secure_boot_keys(secure_boot)? {
                    Some(boot_keys) => {
                        let signed = secureboot::sign_update(&boot_keys, &dir)?;
                        let r = remote::os_release(&remote, &signed, sign_key);
                        let _ = std::fs::remove_dir_all(&signed);
                        r
                    }
                    None => remote::os_release(&remote, &dir, sign_key),
                }
            })
            .await??;
            print_json(&r)?;
        }
        Command::BaseImage {
            raw,
            arch,
            secure_boot,
        } => {
            let remote = remote::Remote::from_env()?;
            let r = tokio::task::spawn_blocking(move || {
                let boot_keys = keys::secure_boot_keys(secure_boot)?;
                remote::base_image(&remote, &raw, &arch, boot_keys.as_deref())
            })
            .await??;
            print_json(&r)?;
        }
        Command::SecureBoot(SecureBoot::Keygen { dir }) => print_json(&secureboot::keygen(&dir)?)?,
        Command::Tunnel { device, port } => {
            let stdio = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
            remote::Remote::from_env()?
                .tunnel(&device, port, stdio)
                .await?;
        }
        Command::Ssh { device, args } => {
            remote::Remote::from_env()?;
            let me = std::env::current_exe()?;
            // The host key is remembered under the device's name, not under
            // whatever address the tunnel happens to go through.
            let err = std::os::unix::process::CommandExt::exec(
                std::process::Command::new("ssh")
                    .arg("-o")
                    .arg(format!("ProxyCommand={} tunnel {device} 22", me.display()))
                    .arg("-o")
                    .arg(format!("HostKeyAlias=via-{device}"))
                    .arg(format!("root@{device}"))
                    .args(args),
            );
            return Err(err).context("running ssh");
        }
        Command::Forward {
            device,
            port,
            local_port,
        } => {
            let remote = std::sync::Arc::new(remote::Remote::from_env()?);
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port)).await?;
            eprintln!("forwarding 127.0.0.1:{local_port} to {device}:{port}");
            loop {
                let (conn, _) = listener.accept().await?;
                let (remote, device) = (remote.clone(), device.clone());
                tokio::spawn(async move {
                    if let Err(e) = remote.tunnel(&device, port, conn).await {
                        eprintln!("{e:#}");
                    }
                });
            }
        }
    }
    Ok(())
}

fn print_json(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}
