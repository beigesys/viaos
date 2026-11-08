//! The device's connection to a control plane.
//!
//! Outbound only. The device enrolls once with the token from viaos.toml,
//! keeps the credential it is issued, and from then on holds one WebSocket
//! open, reconnecting with backoff. Every stream the control plane opens on
//! it is served here; `mcp` streams get the same tools `via-agent mcp` serves.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures::{SinkExt, StreamExt};
use rmcp::ServiceExt;
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use via_link::{Incoming, Mux, Side};

use crate::config::Control;
use crate::tools::Device;

/// What the device keeps after enrolling. Root-only: the credential is the
/// device's identity to the control plane.
#[derive(Debug, Serialize, Deserialize)]
struct Identity {
    url: String,
    device: String,
    credential: String,
}

#[derive(Deserialize)]
struct Enrolled {
    device: EnrolledDevice,
    credential: String,
}

#[derive(Deserialize)]
struct EnrolledDevice {
    id: String,
    name: String,
    fleet: String,
}

/// Exists once this boot has connected to the control plane. On tmpfs, so
/// every boot starts without it.
pub const CONNECTED: &str = "/run/via/connected";

fn identity_path(data_dir: &Path) -> PathBuf {
    data_dir.join("identity.json")
}

/// The device's control-plane credential, once enrolled.
pub fn credential(data_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(identity_path(data_dir)).ok()?;
    Some(serde_json::from_str::<Identity>(&text).ok()?.credential)
}

/// Stay connected to the control plane for as long as the agent runs.
pub async fn run(control: Control, data_dir: PathBuf, device: Device) {
    let identity = loop {
        match identity(&control, &data_dir).await {
            Ok(id) => break id,
            Err(e) => {
                tracing::error!("enrollment failed, retrying in 60s: {e:#}");
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        }
    };

    let mut backoff = Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        match session(&identity, &device).await {
            Ok(()) => tracing::info!("control plane closed the connection"),
            Err(e) => tracing::warn!("connection failed: {e:#}"),
        }
        // A connection that lasted resets the backoff; one that failed at
        // once grows it, so a down control plane is not hammered.
        if started.elapsed() > Duration::from_secs(60) {
            backoff = Duration::from_secs(1);
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(60));
    }
}

/// The saved identity, or a new one from spending the enrollment token.
async fn identity(control: &Control, data_dir: &Path) -> Result<Identity> {
    let path = identity_path(data_dir);
    if let Ok(text) = std::fs::read_to_string(&path) {
        let id: Identity = serde_json::from_str(&text).context("reading identity")?;
        // A changed URL is a move to another control plane: the credential
        // is worthless there, so enroll again if there is a token to do it.
        if id.url == control.url || control.token.is_none() {
            return Ok(id);
        }
    }
    let Some(token) = &control.token else {
        bail!("not enrolled and viaos.toml has no [control] token");
    };

    let http = http_url(&control.url)?;
    let body = serde_json::json!({
        "token": token,
        "hostname": crate::host::read().hostname,
        "arch": std::env::consts::ARCH,
        "os_version": os_version(),
        "agent_version": env!("CARGO_PKG_VERSION"),
    });
    let resp = reqwest::Client::new()
        .post(format!("{http}/v1/enroll"))
        .json(&body)
        .send()
        .await
        .context("reaching the control plane")?;
    if !resp.status().is_success() {
        bail!(
            "enrollment refused: {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    let e: Enrolled = resp.json().await?;
    tracing::info!(device = %e.device.id, name = %e.device.name, fleet = %e.device.fleet, "enrolled");

    let id = Identity {
        url: control.url.clone(),
        device: e.device.id,
        credential: e.credential,
    };
    write_private(&path, &serde_json::to_vec_pretty(&id)?)?;
    Ok(id)
}

async fn session(identity: &Identity, device: &Device) -> Result<()> {
    let mut url = format!(
        "{}/v1/connect?agent_version={}",
        identity.url,
        env!("CARGO_PKG_VERSION")
    );
    if let Some(v) = os_version() {
        url += &format!("&os_version={v}");
    }
    let mut req = url.into_client_request()?;
    req.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {}", identity.credential))?,
    );
    let (ws, _) = tokio_tungstenite::connect_async(req).await?;
    tracing::info!("connected to {}", identity.url);
    // What `via-agent ready` waits for: this boot reached the control plane.
    let _ = std::fs::create_dir_all(CONNECTED.rsplit_once('/').map_or("/run", |(d, _)| d));
    let _ = std::fs::write(CONNECTED, b"");

    let (mux, mut outgoing, mut incoming) = Mux::new(Side::Device);
    let (mut tx, mut rx) = ws.split();

    let send = tokio::spawn(async move {
        while let Some(frame) = outgoing.recv().await {
            if tx.send(Message::Binary(frame.into())).await.is_err() {
                break;
            }
        }
    });
    let serve = {
        let device = device.clone();
        tokio::spawn(async move {
            while let Some(Incoming { service, stream }) = incoming.recv().await {
                match service.as_str() {
                    "mcp" => {
                        let device = device.clone();
                        tokio::spawn(async move {
                            match device.serve(stream).await {
                                Ok(running) => {
                                    let _ = running.waiting().await;
                                }
                                Err(e) => tracing::warn!("mcp session failed: {e}"),
                            }
                        });
                    }
                    // A TCP stream to a port on this device, for SSH and
                    // other local services behind NAT. Only loopback: the
                    // device is not a hop into the network it sits on.
                    tcp if tcp.starts_with("tcp:") => match tcp[4..].parse::<u16>() {
                        Ok(port) => {
                            tokio::spawn(forward(port, stream));
                        }
                        Err(_) => tracing::warn!("refusing stream for bad port {tcp:?}"),
                    },
                    // A terminal on the device, or in one of its containers.
                    shell if shell == "shell" || shell.starts_with("shell:") => {
                        let container = shell.strip_prefix("shell:").map(str::to_string);
                        tokio::spawn(async move {
                            if let Err(e) = crate::shell::serve(container, stream).await {
                                tracing::warn!("shell ended: {e:#}");
                            }
                        });
                    }
                    // Dropping the stream closes it: unknown services are
                    // refused, not left hanging.
                    other => tracing::warn!("refusing stream for unknown service {other:?}"),
                }
            }
        })
    };

    let result = async {
        while let Some(msg) = rx.next().await {
            match msg? {
                Message::Binary(b) => mux.receive(&b),
                Message::Close(_) => break,
                _ => {}
            }
        }
        Ok(())
    }
    .await;
    send.abort();
    serve.abort();
    result
}

async fn forward(port: u16, mut stream: tokio::io::DuplexStream) {
    match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
        Ok(mut tcp) => {
            tracing::info!(port, "tunnel opened");
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
            tracing::info!(port, "tunnel closed");
        }
        Err(e) => tracing::warn!(port, "tunnel refused: {e}"),
    }
}

fn http_url(ws: &str) -> Result<String> {
    let base = if let Some(rest) = ws.strip_prefix("wss://") {
        format!("https://{rest}")
    } else if let Some(rest) = ws.strip_prefix("ws://") {
        format!("http://{rest}")
    } else {
        bail!("control url must start with wss:// or ws://");
    };
    Ok(base.trim_end_matches('/').to_string())
}

fn os_version() -> Option<String> {
    image_version(&std::fs::read_to_string("/etc/os-release").ok()?)
}

/// IMAGE_VERSION wherever it is in the file, else VERSION_ID. A distribution's
/// os-release usually has VERSION_ID near the top and an image build adds
/// IMAGE_VERSION after it, so taking whichever comes first would report the
/// distribution's version, and an OS update would never look finished.
fn image_version(os_release: &str) -> Option<String> {
    let field = |key: &str| {
        os_release
            .lines()
            .find_map(|l| l.strip_prefix(key))
            .map(|v| v.trim_matches('"').to_string())
    };
    field("IMAGE_VERSION=").or_else(|| field("VERSION_ID="))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_urls_map_to_http() {
        assert_eq!(
            http_url("wss://via.example.com/").unwrap(),
            "https://via.example.com"
        );
        assert_eq!(
            http_url("ws://10.0.2.2:8080").unwrap(),
            "http://10.0.2.2:8080"
        );
        assert!(http_url("https://x").is_err());
    }

    #[test]
    fn the_image_version_wins_wherever_it_is() {
        let ubuntu = "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nIMAGE_VERSION=7\n";
        assert_eq!(image_version(ubuntu).as_deref(), Some("7"));
        assert_eq!(
            image_version("IMAGE_VERSION=\"3\"\nVERSION_ID=1\n").as_deref(),
            Some("3")
        );
        assert_eq!(
            image_version("VERSION_ID=\"24.04\"\n").as_deref(),
            Some("24.04")
        );
        assert_eq!(image_version("NAME=x\n"), None);
    }
}
