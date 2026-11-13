//! Talking to the control plane from the operator's machine: uploads,
//! signing, and TCP tunnels into devices.
//!
//! `VIA_SERVER` is the control plane's URL and `VIA_TOKEN` an API token from
//! `via-server token create` (`VIA_ADMIN_TOKEN` is accepted too). In GitHub
//! Actions with no token set, the run's own OIDC token is used instead, which
//! the server accepts for uploading releases of the apps the repository
//! publishes.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use via_bundle::SigningKey;

/// Percent-encode everything but the characters a URL never needs escaped.
fn escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn server() -> Result<String> {
    let server = std::env::var("VIA_SERVER").context("set VIA_SERVER to the control plane URL")?;
    Ok(server.trim_end_matches('/').to_string())
}

pub struct Remote {
    server: String,
    auth: Auth,
}

enum Auth {
    Token(String),
    /// Asked for afresh before each request: GitHub's tokens last minutes,
    /// and a multi-arch build can take longer.
    GithubOidc {
        url: String,
        token: String,
    },
}

impl Remote {
    pub fn from_env() -> Result<Self> {
        let server = server()?;
        match std::env::var("VIA_TOKEN").or_else(|_| std::env::var("VIA_ADMIN_TOKEN")) {
            Ok(token) => Ok(Self {
                server,
                auth: Auth::Token(token),
            }),
            Err(_) if std::env::var_os("ACTIONS_ID_TOKEN_REQUEST_URL").is_some() => {
                Self::github_oidc()
            }
            Err(_) => bail!("set VIA_TOKEN to an API token from `via-server token create`"),
        }
    }

    /// Authenticate with the GitHub Actions run's OIDC token, made for
    /// `VIA_SERVER`. The workflow needs `permissions: id-token: write`.
    pub fn github_oidc() -> Result<Self> {
        let var = |name: &str| {
            std::env::var(name).with_context(|| {
                format!("{name} is not set: this needs GitHub Actions with `permissions: id-token: write`")
            })
        };
        Ok(Self {
            server: server()?,
            auth: Auth::GithubOidc {
                url: var("ACTIONS_ID_TOKEN_REQUEST_URL")?,
                token: var("ACTIONS_ID_TOKEN_REQUEST_TOKEN")?,
            },
        })
    }

    /// What to send as the bearer token. Blocking.
    fn bearer(&self) -> Result<String> {
        match &self.auth {
            Auth::Token(t) => Ok(t.clone()),
            Auth::GithubOidc { url, token } => {
                #[derive(serde::Deserialize)]
                struct Issued {
                    value: String,
                }
                let sep = if url.contains('?') { '&' } else { '?' };
                let resp = reqwest::blocking::Client::new()
                    .get(format!("{url}{sep}audience={}", escape(&self.server)))
                    .bearer_auth(token)
                    .send()
                    .context("asking GitHub for an OIDC token")?;
                let status = resp.status();
                if !status.is_success() {
                    bail!("asking GitHub for an OIDC token: {status}");
                }
                Ok(resp.json::<Issued>()?.value)
            }
        }
    }

    /// The API token, for what only a person's token can do.
    fn token(&self) -> Result<&str> {
        match &self.auth {
            Auth::Token(t) => Ok(t),
            Auth::GithubOidc { .. } => {
                bail!("a GitHub Actions token can only upload releases; set VIA_TOKEN")
            }
        }
    }

    /// Take the next release number of `app` from the server. Each call
    /// gets a new one, so a build that is run again never meets an old one.
    pub fn next_release(&self, app: &str) -> Result<u64> {
        let resp = reqwest::blocking::Client::new()
            .post(format!("{}/v1/releases/{app}", self.server))
            .bearer_auth(self.bearer()?)
            .send()?;
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        if !status.is_success() {
            bail!("taking a release number for {app}: {status} {text}");
        }
        let v: Value = serde_json::from_str(&text)?;
        v["release"]
            .as_u64()
            .context("the server gave no release number")
    }

    /// PUT a file to `path` on the control plane and return its JSON reply.
    pub fn put_file(&self, path: &str, file: &Path) -> Result<Value> {
        let body =
            std::fs::File::open(file).with_context(|| format!("opening {}", file.display()))?;
        let resp = reqwest::blocking::Client::builder()
            .timeout(None)
            .build()?
            .put(format!("{}{path}", self.server))
            .bearer_auth(self.bearer()?)
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
            HeaderValue::from_str(&format!("Bearer {}", self.token()?))?,
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

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};

    use super::*;

    /// GitHub's token endpoint, for one request: answers with a token and
    /// says what it was asked.
    fn github(reply: &'static str) -> (String, std::thread::JoinHandle<Vec<String>>) {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/token?api-version=2.0", l.local_addr().unwrap());
        let seen = std::thread::spawn(move || {
            let (mut conn, _) = l.accept().unwrap();
            let mut lines = Vec::new();
            for line in BufReader::new(conn.try_clone().unwrap()).lines() {
                let line = line.unwrap();
                if line.is_empty() {
                    break;
                }
                lines.push(line);
            }
            write!(
                conn,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{reply}",
                reply.len()
            )
            .unwrap();
            lines
        });
        (url, seen)
    }

    #[test]
    fn a_run_asks_github_for_a_token_for_this_server() {
        let (url, seen) = github(r#"{"count":1,"value":"eyJ.a.b"}"#);
        let remote = Remote {
            server: "https://via.example.com".into(),
            auth: Auth::GithubOidc {
                url,
                token: "request-token".into(),
            },
        };
        assert_eq!(remote.bearer().unwrap(), "eyJ.a.b");
        let seen = seen.join().unwrap();
        assert_eq!(
            seen[0],
            "GET /token?api-version=2.0&audience=https%3A%2F%2Fvia.example.com HTTP/1.1"
        );
        assert!(
            seen.iter()
                .any(|h| h.eq_ignore_ascii_case("authorization: Bearer request-token"))
        );
        // Not for anything else.
        assert!(remote.token().is_err());
    }
}
