//! OS versions available to devices: `<os_dir>/<platform>/<version>/`, each
//! the output of `nix build .#updates.<platform>`.
//!
//! A platform is an architecture, `x86_64`, or an architecture and a variant
//! of viaos built for it, `x86_64-nvidia`. Each is its own line of versions: a
//! device updates only within the one it runs.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct Release {
    pub arch: String,
    /// E.g. `nvidia`; empty for the plain OS.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub variant: String,
    pub version: String,
    #[serde(skip)]
    pub dir: PathBuf,
    pub files: Vec<String>,
    pub size_mb: u64,
}

#[derive(Deserialize)]
struct Manifest {
    version: String,
    arch: String,
    #[serde(default)]
    variant: String,
    files: Vec<ManifestFile>,
    #[serde(default)]
    secure_boot: bool,
}

#[derive(Deserialize)]
struct ManifestFile {
    name: String,
    size: u64,
    #[serde(default)]
    sha256: Option<String>,
}

/// Where a device running `variant` of viaos on `arch` gets its updates.
pub fn platform(arch: &str, variant: &str) -> String {
    if variant.is_empty() {
        arch.to_string()
    } else {
        format!("{arch}-{variant}")
    }
}

impl Manifest {
    fn platform(&self) -> String {
        platform(&self.arch, &self.variant)
    }
}

fn safe(part: &str) -> bool {
    !part.is_empty()
        && part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        && !part.starts_with('.')
}

pub fn find(os_dir: &Path, platform: &str, version: &str) -> Result<Release> {
    if !safe(platform) || !safe(version) {
        bail!("bad platform or version");
    }
    let dir = os_dir.join(platform).join(version);
    let text = std::fs::read_to_string(dir.join("manifest.json")).with_context(|| {
        format!("no OS version {version} for {platform}; `list_os_versions` shows them")
    })?;
    let m: Manifest = serde_json::from_str(&text).context("reading manifest.json")?;
    if m.version != version || m.platform() != platform {
        bail!(
            "{} holds {} for {}, not {version} for {platform}",
            dir.display(),
            m.version,
            m.platform()
        );
    }
    Ok(Release {
        variant: m.variant.clone(),
        arch: m.arch,
        version: m.version,
        size_mb: m.files.iter().map(|f| f.size).sum::<u64>() / 1_048_576,
        files: m.files.into_iter().map(|f| f.name).collect(),
        dir,
    })
}

/// Where an uploaded file of a not-yet-published version goes. A version
/// with a manifest is published, and published versions do not change.
pub fn upload_dir(os_dir: &Path, arch: &str, version: &str, file: &str) -> Result<PathBuf> {
    if !safe(arch) || !safe(version) || !safe(file) {
        bail!("bad arch, version or file name");
    }
    let dir = os_dir.join(arch).join(version);
    if dir.join("manifest.json").exists() {
        bail!("OS version {version} for {arch} is already published; versions are immutable");
    }
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Check a staged manifest against the files uploaded beside it.
pub fn check_complete(dir: &Path, manifest: &Path, platform: &str, version: &str) -> Result<()> {
    let m: Manifest =
        serde_json::from_slice(&std::fs::read(manifest)?).context("manifest.json is not valid")?;
    if m.version != version || m.platform() != platform {
        bail!(
            "manifest is for {} on {}, uploaded as {version} on {platform}",
            m.version,
            m.platform()
        );
    }
    // So there's no such thing here as a version some devices would refuse.
    if !m.secure_boot {
        bail!("this OS version isn't signed; publish it with `via os-release`, which signs it");
    }
    for f in &m.files {
        if !safe(&f.name) {
            bail!("manifest names a bad file {:?}", f.name);
        }
        let size = std::fs::metadata(dir.join(&f.name)).map(|m| m.len()).ok();
        if size != Some(f.size) {
            bail!(
                "{} is missing or the wrong size; upload it before the manifest",
                f.name
            );
        }
    }
    Ok(())
}

/// What a version is on each platform it was published for.
pub fn details(os_dir: &Path, version: &str) -> Result<serde_json::Value> {
    use serde_json::json;
    let mut builds = Vec::new();
    for platform in read_names(os_dir) {
        let Ok(r) = find(os_dir, &platform, version) else {
            continue;
        };
        let path = r.dir.join("manifest.json");
        let m: Manifest = serde_json::from_slice(&std::fs::read(&path)?)?;
        let published_at = std::fs::metadata(&path)?
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let files: Vec<serde_json::Value> = m
            .files
            .iter()
            .map(|f| json!({ "name": f.name, "size_mb": f.size / 1_048_576, "sha256": f.sha256 }))
            .collect();
        builds.push(json!({ "arch": r.arch, "variant": r.variant, "published_at": published_at, "size_mb": r.size_mb, "files": files }));
    }
    anyhow::ensure!(
        !builds.is_empty(),
        "no OS version {version}; `list_os_versions` shows them"
    );
    Ok(json!({ "version": version, "builds": builds }))
}

/// Check a staged manifest's signature against the keys devices trust, so a
/// version every device would refuse never reaches the picker. With no trusted
/// keys configured, devices check nothing either.
pub fn check_signature(dir: &Path, manifest: &Path, trusted: &[String]) -> Result<()> {
    if trusted.is_empty() {
        return Ok(());
    }
    let keys = trusted
        .iter()
        .map(|k| via_bundle::PublicKey::from_hex(k))
        .collect::<Result<Vec<_>, _>>()?;
    let sig = std::fs::read(dir.join("manifest.json.sig"))
        .context("upload manifest.json.sig first: devices here require signed updates")?;
    let sig: via_bundle::BundleSignature =
        serde_json::from_slice(&sig).context("manifest.json.sig isn't a signature")?;
    via_bundle::TrustPolicy::from_keys(keys)
        .verify(&std::fs::read(manifest)?, Some(&sig))
        .context("devices here wouldn't accept this signature")?;
    Ok(())
}

pub fn list(os_dir: &Path) -> Vec<Release> {
    let mut out = Vec::new();
    for platform in read_names(os_dir) {
        for version in read_names(&os_dir.join(&platform)) {
            if let Ok(r) = find(os_dir, &platform, &version) {
                out.push(r);
            }
        }
    }
    out
}

fn read_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    fn staged(secure_boot: bool) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("a.efi"), "abc").unwrap();
        let m = d.path().join("manifest.json.upload");
        let body = serde_json::json!({
            "version": "2", "arch": "x86_64", "secure_boot": secure_boot,
            "files": [{ "name": "a.efi", "size": 3 }],
        });
        std::fs::write(&m, body.to_string()).unwrap();
        (d, m)
    }

    #[test]
    fn a_signature_devices_would_refuse_cannot_be_published() {
        let (d, m) = staged(true);
        let key = via_bundle::SigningKey::generate();
        let trusted = [key.public().to_hex()];
        let sig_path = d.path().join("manifest.json.sig");

        assert!(
            check_signature(d.path(), &m, &trusted).is_err(),
            "no signature"
        );
        std::fs::write(&sig_path, "garbage").unwrap();
        assert!(check_signature(d.path(), &m, &trusted).is_err(), "garbage");

        let bytes = std::fs::read(&m).unwrap();
        let other = via_bundle::SigningKey::generate();
        std::fs::write(
            &sig_path,
            serde_json::to_vec(&other.sign_manifest(&bytes)).unwrap(),
        )
        .unwrap();
        assert!(
            check_signature(d.path(), &m, &trusted).is_err(),
            "someone else's key"
        );

        std::fs::write(
            &sig_path,
            serde_json::to_vec(&key.sign_manifest(b"other")).unwrap(),
        )
        .unwrap();
        assert!(
            check_signature(d.path(), &m, &trusted).is_err(),
            "another manifest's"
        );

        std::fs::write(
            &sig_path,
            serde_json::to_vec(&key.sign_manifest(&bytes)).unwrap(),
        )
        .unwrap();
        check_signature(d.path(), &m, &trusted).unwrap();

        std::fs::remove_file(&sig_path).unwrap();
        check_signature(d.path(), &m, &[]).unwrap();
    }

    #[test]
    fn a_variant_is_its_own_line_of_versions() {
        let d = tempfile::tempdir().unwrap();
        let publish = |platform: &str, variant: Option<&str>| {
            let dir = d.path().join(platform).join("2");
            std::fs::create_dir_all(&dir).unwrap();
            let mut m = serde_json::json!({
                "version": "2", "arch": "x86_64", "files": [{ "name": "a.efi", "size": 3 }],
            });
            if let Some(v) = variant {
                m["variant"] = v.into();
            }
            std::fs::write(dir.join("manifest.json"), m.to_string()).unwrap();
        };
        publish("x86_64-nvidia", Some("nvidia"));
        assert_eq!(
            find(d.path(), &platform("x86_64", "nvidia"), "2")
                .unwrap()
                .variant,
            "nvidia"
        );
        // A plain device finds nothing to install, not the NVIDIA build.
        assert!(find(d.path(), &platform("x86_64", ""), "2").is_err());
        publish("x86_64", None);
        assert_eq!(find(d.path(), "x86_64", "2").unwrap().variant, "");
        // A variant's manifest under the plain name is refused, and the other
        // way round.
        publish("x86_64", Some("nvidia"));
        assert!(find(d.path(), "x86_64", "2").is_err());
        publish("x86_64-nvidia", None);
        assert!(find(d.path(), "x86_64-nvidia", "2").is_err());
    }

    #[test]
    fn an_unsigned_version_cannot_be_published() {
        let (d, m) = staged(false);
        let e = check_complete(d.path(), &m, "x86_64", "2").unwrap_err();
        assert!(e.to_string().contains("via os-release"), "{e}");
        let (d, m) = staged(true);
        check_complete(d.path(), &m, "x86_64", "2").unwrap();
    }
}
