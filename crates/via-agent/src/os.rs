//! OS updates: fetch a version's files, check them, hand them to
//! systemd-sysupdate, reboot.
//!
//! The agent does the fetching so updates travel the same path as everything
//! else and need no update URL baked into the image. sysupdate does the
//! writing: it fills the idle store slot, installs the UKI with boot
//! counting, and leaves the running slot alone. If the new version does not
//! reach boot-complete.target three times, the boot loader goes back to the
//! old one and the device reports its old version again.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use via_bundle::TrustPolicy;

/// Where sysupdate's transfers look for sources; see nix/sysupdate.nix.
const SOURCE_DIR: &str = "os-update";

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub arch: String,
    /// The build of viaos it is, e.g. `nvidia`; empty for the plain one.
    #[serde(default)]
    pub variant: String,
    pub files: Vec<ManifestFile>,
    /// Set by `via os-release --secure-boot`: the UKI is signed for the
    /// fleet's Secure Boot keys.
    #[serde(default)]
    pub secure_boot: bool,
}

#[derive(Debug, Deserialize)]
pub struct ManifestFile {
    pub name: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct UpdateStatus {
    pub version: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_percent: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The update in flight, if any. Shared by every MCP session on the device.
#[derive(Clone, Default)]
pub struct Updater {
    status: Arc<Mutex<Option<UpdateStatus>>>,
}

impl Updater {
    pub fn status(&self) -> Option<UpdateStatus> {
        self.status.lock().unwrap().clone()
    }

    fn set(&self, version: &str, state: &str, progress: Option<u8>, error: Option<String>) {
        *self.status.lock().unwrap() = Some(UpdateStatus {
            version: version.into(),
            state: state.into(),
            progress_percent: progress,
            error,
        });
    }

    /// Start updating to `version` from `source` (a URL or directory holding
    /// manifest.json and the files it names). Returns at once; progress shows
    /// in [`Updater::status`].
    pub fn start(
        &self,
        data_dir: PathBuf,
        source: String,
        version: String,
        bearer: Option<String>,
        reboot: bool,
        trust: TrustPolicy,
    ) -> Result<()> {
        if let Some(s) = self.status() {
            if !matches!(s.state.as_str(), "failed" | "installed") {
                bail!("an update to {} is already {}", s.version, s.state);
            }
        }
        if current_version().as_deref() == Some(version.as_str()) {
            bail!("already running version {version}");
        }
        self.set(&version, "downloading", Some(0), None);
        let this = self.clone();
        tokio::spawn(async move {
            match this
                .run(&data_dir, &source, &version, bearer.as_deref(), &trust)
                .await
            {
                Ok(()) => {
                    if reboot {
                        this.set(&version, "rebooting", None, None);
                        tracing::info!(%version, "installed; rebooting");
                        // Long enough for the caller to read the status.
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        let _ = tokio::process::Command::new("systemctl")
                            .arg("reboot")
                            .status()
                            .await;
                    } else {
                        this.set(&version, "installed", None, None);
                    }
                }
                Err(e) => {
                    tracing::error!(%version, "update failed: {e:#}");
                    this.set(&version, "failed", None, Some(format!("{e:#}")));
                }
            }
        });
        Ok(())
    }

    async fn run(
        &self,
        data_dir: &Path,
        source: &str,
        version: &str,
        bearer: Option<&str>,
        trust: &TrustPolicy,
    ) -> Result<()> {
        let dir = data_dir.join(SOURCE_DIR);
        // Only this version's files: sysupdate installs the newest it sees.
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await?;

        let fetch = Fetch::new(source, bearer)?;
        let manifest_bytes = fetch.bytes("manifest.json").await?;
        // The manifest holds every file's sha256, so a signature over it
        // covers the whole update, checked before anything is downloaded.
        if trust.requires_signature() {
            let sig = fetch
                .bytes("manifest.json.sig")
                .await
                .context("the update is not signed")?;
            let sig: via_bundle::BundleSignature =
                serde_json::from_slice(&sig).context("reading manifest.json.sig")?;
            trust
                .verify(&manifest_bytes, Some(&sig))
                .context("checking the update's signature")?;
        }
        let manifest: Manifest =
            serde_json::from_slice(&manifest_bytes).context("reading manifest.json")?;
        if manifest.version != version {
            bail!("source holds version {}, not {version}", manifest.version);
        }
        if manifest.arch != std::env::consts::ARCH {
            bail!(
                "update is for {}, this device is {}",
                manifest.arch,
                std::env::consts::ARCH
            );
        }
        // An update to another variant would drop what this device was
        // flashed for, its GPU driver, say. Moving variant is a reflash.
        let variant = current_variant();
        if manifest.variant != variant {
            let name = |v: &str| {
                if v.is_empty() {
                    "plain viaos".to_string()
                } else {
                    format!("the {v} variant")
                }
            };
            bail!(
                "update is {}, this device runs {}",
                name(&manifest.variant),
                name(&variant)
            );
        }
        // Firmware would refuse the UKI three times, then boot the old
        // version: an update that cannot work. Say so now instead.
        if secure_boot() && !manifest.secure_boot {
            bail!(
                "this device enforces Secure Boot and version {version} is not signed for it; \
                 publish it with `via os-release --secure-boot`"
            );
        }

        let total: u64 = manifest.files.iter().map(|f| f.size).sum::<u64>().max(1);
        let mut done = 0u64;
        for file in &manifest.files {
            if file.name.contains('/') || file.name.starts_with('.') {
                bail!("refusing file name {:?}", file.name);
            }
            let path = dir.join(&file.name);
            let digest = fetch
                .to_file(&file.name, &path, |n| {
                    let pct = ((done + n) * 100 / total).min(99) as u8;
                    self.set(version, "downloading", Some(pct), None);
                })
                .await
                .with_context(|| format!("fetching {}", file.name))?;
            if digest != file.sha256 {
                bail!(
                    "{} is corrupt: sha256 {digest}, expected {}",
                    file.name,
                    file.sha256
                );
            }
            done += file.size;
        }

        self.set(version, "installing", None, None);
        // Not on PATH on NixOS; the unit says where it is.
        let sysupdate =
            std::env::var("VIA_SYSUPDATE").unwrap_or_else(|_| "systemd-sysupdate".into());
        install(&sysupdate, version).await?;
        let _ = tokio::fs::remove_dir_all(&dir).await;
        Ok(())
    }
}

/// What sysupdate says when an earlier install of this version died partway,
/// from a disk error or a power cut. It won't touch it until it's cleared.
const PARTIAL_INSTALL: &str = "Vacuum it to try installing again";

/// Install `version`. Left alone, one interrupted install would refuse every
/// retry for good on a device nobody can reach. Vacuuming removes only partial
/// and surplus instances, never the running one.
async fn install(sysupdate: &str, version: &str) -> Result<()> {
    let run = |args: Vec<&str>| {
        let mut command = tokio::process::Command::new(sysupdate);
        command.args(args);
        async move { command.output().await.context("running systemd-sysupdate") }
    };
    let mut out = run(vec!["update", version]).await?;
    if !out.status.success() && String::from_utf8_lossy(&out.stderr).contains(PARTIAL_INSTALL) {
        tracing::warn!(version, "clearing an interrupted install of this version");
        let vacuum = run(vec!["vacuum"]).await?;
        if !vacuum.status.success() {
            bail!(
                "systemd-sysupdate vacuum failed: {}",
                String::from_utf8_lossy(&vacuum.stderr).trim()
            );
        }
        out = run(vec!["update", version]).await?;
    }
    if !out.status.success() {
        bail!(
            "systemd-sysupdate failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Whether the firmware is enforcing Secure Boot. The EFI variable is four
/// bytes of attributes, then 1 or 0.
pub fn secure_boot() -> bool {
    std::fs::read("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
        .is_ok_and(|v| v.get(4) == Some(&1))
}

/// The running OS version, from os-release.
pub fn current_version() -> Option<String> {
    let text = std::fs::read_to_string("/etc/os-release").ok()?;
    text.lines()
        .find_map(|l| l.strip_prefix("IMAGE_VERSION="))
        .map(|v| v.trim_matches('"').to_string())
}

/// The variant of viaos running, from os-release: empty for the plain one.
pub fn current_variant() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .as_deref()
        .and_then(variant_of)
        .unwrap_or_default()
}

fn variant_of(os_release: &str) -> Option<String> {
    os_release
        .lines()
        .find_map(|l| l.strip_prefix("VARIANT_ID="))
        .map(|v| v.trim_matches('"').to_string())
}

/// Reads an update source: an http(s) URL or a local directory.
enum Fetch {
    Http {
        base: String,
        client: reqwest::Client,
        bearer: Option<String>,
    },
    Dir(PathBuf),
}

impl Fetch {
    fn new(source: &str, bearer: Option<&str>) -> Result<Self> {
        if source.starts_with("http://") || source.starts_with("https://") {
            Ok(Self::Http {
                base: source.trim_end_matches('/').into(),
                client: reqwest::Client::new(),
                bearer: bearer.map(Into::into),
            })
        } else {
            Ok(Self::Dir(PathBuf::from(source)))
        }
    }

    async fn get(&self, name: &str) -> Result<reqwest::Response> {
        let Self::Http {
            base,
            client,
            bearer,
        } = self
        else {
            unreachable!()
        };
        let mut req = client.get(format!("{base}/{name}"));
        if let Some(b) = bearer {
            req = req.bearer_auth(b);
        }
        let resp = req.send().await?;
        if !resp.status().is_success() {
            bail!("{name}: {}", resp.status());
        }
        Ok(resp)
    }

    async fn bytes(&self, name: &str) -> Result<Vec<u8>> {
        match self {
            Self::Http { .. } => Ok(self.get(name).await?.bytes().await?.to_vec()),
            Self::Dir(dir) => Ok(tokio::fs::read(dir.join(name)).await?),
        }
    }

    /// Copy `name` to `path`, returning its sha256 in hex.
    async fn to_file(
        &self,
        name: &str,
        path: &Path,
        mut progress: impl FnMut(u64),
    ) -> Result<String> {
        let mut hash = Sha256::new();
        let mut out = tokio::fs::File::create(path).await?;
        let mut written = 0u64;
        match self {
            Self::Http { .. } => {
                let mut resp = self.get(name).await?;
                while let Some(chunk) = resp.chunk().await? {
                    hash.update(&chunk);
                    out.write_all(&chunk).await?;
                    written += chunk.len() as u64;
                    progress(written);
                }
            }
            Self::Dir(dir) => {
                use tokio::io::AsyncReadExt;
                let mut src = tokio::fs::File::open(dir.join(name)).await?;
                let mut buf = vec![0u8; 1 << 20];
                loop {
                    let n = src.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    hash.update(&buf[..n]);
                    out.write_all(&buf[..n]).await?;
                    written += n as u64;
                    progress(written);
                }
            }
        }
        out.sync_all().await?;
        Ok(hex::encode(hash.finalize()))
    }
}

#[cfg(test)]
mod install_tests {
    use super::*;

    /// A stand-in sysupdate that logs its arguments. `update` runs `on_update`.
    fn sysupdate(dir: &Path, on_update: &str) -> String {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join("sysupdate");
        let log = dir.join("log");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\necho \"$*\" >> {}\nif [ \"$1\" = update ]; then\n{on_update}\nfi\n",
                log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// [`super::install`], allowing for the kernel refusing to run a script
    /// that a test on another thread forked with open for writing. That fails
    /// before the script does anything, so trying again changes nothing it logs.
    async fn install(script: &str, version: &str) -> Result<()> {
        for _ in 0..50 {
            match super::install(script, version).await {
                Err(e) if format!("{e:#}").contains("Text file busy") => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                other => return other,
            }
        }
        super::install(script, version).await
    }

    fn log(dir: &Path) -> String {
        std::fs::read_to_string(dir.join("log")).unwrap()
    }

    #[tokio::test]
    async fn an_interrupted_install_is_cleared_and_tried_again() {
        let d = tempfile::tempdir().unwrap();
        // The message a real device gave after a disk error during an install.
        let script = sysupdate(
            d.path(),
            &format!(
                "if ! grep -q vacuum {log}; then\n\
                 echo \"Selected update '2' is already acquired and partially installed. \
                 Vacuum it to try installing again.\" >&2\nexit 1\nfi",
                log = d.path().join("log").display()
            ),
        );
        install(&script, "2").await.unwrap();
        assert_eq!(log(d.path()), "update 2\nvacuum\nupdate 2\n");
    }

    #[tokio::test]
    async fn any_other_failure_is_reported_and_nothing_is_vacuumed() {
        let d = tempfile::tempdir().unwrap();
        let script = sysupdate(d.path(), "echo 'no space' >&2\nexit 1");
        let err = install(&script, "2").await.unwrap_err().to_string();
        assert!(err.contains("no space"), "{err}");
        assert_eq!(log(d.path()), "update 2\n");
    }

    #[tokio::test]
    async fn a_clean_install_runs_once() {
        let d = tempfile::tempdir().unwrap();
        let script = sysupdate(d.path(), "exit 0");
        install(&script, "2").await.unwrap();
        assert_eq!(log(d.path()), "update 2\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variant_comes_from_os_release() {
        assert_eq!(
            variant_of("NAME=viaos\nVARIANT_ID=nvidia\nIMAGE_VERSION=3\n").as_deref(),
            Some("nvidia")
        );
        assert_eq!(
            variant_of("NAME=viaos\nVARIANT_ID=\"nvidia\"\n").as_deref(),
            Some("nvidia")
        );
        assert_eq!(variant_of("NAME=viaos\nIMAGE_VERSION=3\n"), None);
    }
}
