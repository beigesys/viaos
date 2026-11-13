//! Talking to the control plane from the operator's machine: uploads,
//! signing, and TCP tunnels into devices.
//!
//! `VIA_SERVER` is the control plane's URL and `VIA_TOKEN` an API token from
//! `via-server token create` (`VIA_ADMIN_TOKEN` is accepted too).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use via_bundle::SigningKey;

pub struct Remote {
    server: String,
    token: String,
}

impl Remote {
    pub fn from_env() -> Result<Self> {
        let server =
            std::env::var("VIA_SERVER").context("set VIA_SERVER to the control plane URL")?;
        let token = std::env::var("VIA_TOKEN")
            .or_else(|_| std::env::var("VIA_ADMIN_TOKEN"))
            .context("set VIA_TOKEN to an API token from `via-server token create`")?;
        Ok(Self {
            server: server.trim_end_matches('/').to_string(),
            token,
        })
    }

    /// PUT a file to `path` on the control plane and return its JSON reply.
    pub fn put_file(&self, path: &str, file: &Path) -> Result<Value> {
        let body =
            std::fs::File::open(file).with_context(|| format!("opening {}", file.display()))?;
        let resp = reqwest::blocking::Client::builder()
            .timeout(None)
            .build()?
            .put(format!("{}{path}", self.server))
            .bearer_auth(&self.token)
            .body(body)
            .send()?;
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        if !status.is_success() {
            bail!("{path}: {status} {text}");
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::Null))
    }

    fn ws_url(&self, path: &str) -> Result<String> {
        let base = if let Some(rest) = self.server.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = self.server.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            bail!("VIA_SERVER must start with http:// or https://");
        };
        Ok(format!("{base}{path}"))
    }

    /// Carry one TCP stream to `port` on `device` between `local` and the
    /// control plane, until either side closes.
    pub async fn tunnel<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        device: &str,
        port: u16,
        local: S,
    ) -> Result<()> {
        let mut req = self
            .ws_url(&format!("/v1/devices/{device}/tunnel/{port}"))?
            .into_client_request()?;
        req.headers_mut().insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {}", self.token))?,
        );
        let (ws, _) = tokio_tungstenite::connect_async(req)
            .await
            .with_context(|| format!("opening a tunnel to {device}:{port}"))?;
        let (mut ws_tx, mut ws_rx) = ws.split();
        let (mut r, mut w) = tokio::io::split(local);
        let up = async {
            let mut buf = vec![0u8; 32 * 1024];
            loop {
                match r.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if ws_tx
                            .send(Message::Binary(buf[..n].to_vec().into()))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
            let _ = ws_tx.send(Message::Close(None)).await;
            // The local side closing leaves the reply to drain.
            std::future::pending::<()>().await
        };
        let down = async {
            while let Some(Ok(m)) = ws_rx.next().await {
                match m {
                    Message::Binary(b) => {
                        if w.write_all(&b).await.is_err() || w.flush().await.is_err() {
                            break;
                        }
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
            let _ = w.shutdown().await;
        };
        // The device closing ends the session.
        tokio::select! {
            () = up => {}
            () = down => {}
        }
        Ok(())
    }
}

/// Write a new signing key to `path` (owner-only) and its public half to
/// `path.pub`.
pub fn keygen(path: &Path) -> Result<Value> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if path.exists() {
        bail!(
            "{} exists; refusing to overwrite a signing key",
            path.display()
        );
    }
    let key = SigningKey::generate();
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    writeln!(f, "{}", key.to_hex())?;
    let public = key.public().to_hex();
    let pub_path = PathBuf::from(format!("{}.pub", path.display()));
    std::fs::write(&pub_path, format!("{public}\n"))?;
    Ok(json!({
        "key": path,
        "public_key": public,
        "key_id": key.key_id().to_string(),
        "next": "Give the public key to via-server as VIA_TRUSTED_KEYS: devices provisioned \
                 after that accept only OS updates and releases signed with this key.",
    }))
}

/// Upload an OS update (the output of `nix build .#updates.<arch>`), signed
/// if there's a key. The manifest goes last: it is what publishes the version.
pub fn os_release(remote: &Remote, dir: &Path, key: Option<&Path>) -> Result<Value> {
    let manifest_path = dir.join("manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    let version = manifest["version"]
        .as_str()
        .context("manifest has no version")?;
    let arch = manifest["arch"].as_str().context("manifest has no arch")?;
    let base = format!("/v1/os/{arch}/{version}");

    for f in manifest["files"]
        .as_array()
        .context("manifest has no files")?
    {
        let name = f["name"].as_str().context("manifest file has no name")?;
        eprintln!("uploading {name}");
        remote.put_file(&format!("{base}/{name}"), &dir.join(name))?;
    }
    let mut signed = None;
    if let Some(key) = key {
        let signer =
            SigningKey::read_from(key).with_context(|| format!("reading {}", key.display()))?;
        let sig = serde_json::to_vec(&signer.sign_manifest(&manifest_bytes))?;
        let tmp = std::env::temp_dir().join(format!("via-os-sig-{}", std::process::id()));
        std::fs::write(&tmp, sig)?;
        let r = remote.put_file(&format!("{base}/manifest.json.sig"), &tmp);
        let _ = std::fs::remove_file(&tmp);
        r?;
        signed = Some(signer.key_id().to_string());
    }
    remote.put_file(&format!("{base}/manifest.json"), &manifest_path)?;
    Ok(json!({
        "arch": arch,
        "version": version,
        "signed_by": signed,
        "next": "`list_os_versions` on the control plane shows it; `update_os` installs it.",
    }))
}

/// Upload a raw viaos image as the base that provisioning images are made
/// from, compressed on the way. With Secure Boot keys, a copy of it is
/// signed for Secure Boot first.
pub fn base_image(
    remote: &Remote,
    raw: &Path,
    arch: &str,
    secure_boot: Option<&Path>,
) -> Result<Value> {
    let tmp = std::env::temp_dir().join(format!("via-base-{}.raw.zst", std::process::id()));
    let signed = std::env::temp_dir().join(format!("via-base-{}.raw", std::process::id()));
    let result = (|| {
        let status = std::process::Command::new("cp")
            .args(["--reflink=auto", "--sparse=always", "--no-preserve=mode"])
            .arg(raw)
            .arg(&signed)
            .status()?;
        anyhow::ensure!(status.success(), "copying {} failed", raw.display());
        if let Some(keys) = secure_boot {
            crate::secureboot::sign_image(keys, &signed)?;
        }
        let mut src = std::fs::File::open(&signed)
            .with_context(|| format!("opening {}", signed.display()))?;
        let mut enc = zstd::Encoder::new(std::fs::File::create(&tmp)?, 3)?;
        enc.multithread(std::thread::available_parallelism().map_or(1, |n| n.get() as u32))?;
        std::io::copy(&mut src, &mut enc)?;
        enc.finish()?;
        remote.put_file(&format!("/v1/base/{arch}"), &tmp)
    })();
    let _ = std::fs::remove_file(&tmp);
    let _ = std::fs::remove_file(&signed);
    result
}
