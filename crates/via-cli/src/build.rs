//! Building a release bundle from a compose file.
//!
//! `docker compose` reads the project, builds it and fetches its images. A
//! bundle then carries what `docker compose up` needs on a device with no
//! registry: the flattened file, the local files it reads, and the images.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use via_bundle::{BundleWriter, SigningKey};
use via_compose::Project;
use via_core::{AppName, Platform, ReleaseId};

pub struct BuildArgs {
    /// Compose file. Defaults to compose.yaml in the current directory.
    pub file: Option<PathBuf>,
    /// Application name. Defaults to the directory name.
    pub app: Option<String>,
    pub release: u64,
    /// Target platform, e.g. linux/arm64. Defaults to this machine's.
    pub platform: Option<String>,
    pub output: Option<PathBuf>,
    pub profile: Vec<String>,
    pub strict: bool,
    /// Skip `docker build`; use images already present locally.
    pub no_build: bool,
    pub compression: i32,
    pub sign_key: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
pub struct Built {
    pub app: String,
    pub release: u64,
    pub platform: String,
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
    pub signed: bool,
    pub warnings: Vec<String>,
}

pub fn build(args: BuildArgs) -> Result<Built> {
    let compose_path = match args.file {
        Some(f) => f,
        None => via_compose::discover(".").context(
            "no compose file found. Looked for compose.yaml, compose.yml, docker-compose.yaml, docker-compose.yml",
        )?,
    };
    let platform = match &args.platform {
        Some(p) => Platform::parse(p)?,
        None => Platform::host(),
    };
    let app = match args.app {
        Some(a) => AppName::parse(a)?,
        None => AppName::parse(default_app_name(&compose_path)?)?,
    };
    let release = ReleaseId(args.release);

    eprintln!("Building {app} release {release} for {platform}");

    let project = Project::open(
        &compose_path,
        app.to_string(),
        platform.clone(),
        args.profile.clone(),
        &release.to_string(),
    )?;
    let (deployment, mut warnings) = project.deployment()?;
    let (files, file_warnings) = project.files()?;
    warnings.extend(file_warnings);
    let compose = project.device_compose()?;

    for w in &warnings {
        eprintln!("  warning: {w}");
    }
    if args.strict && !warnings.is_empty() {
        bail!("{} warning(s) and --strict was given", warnings.len());
    }

    if !args.no_build {
        project.build()?;
        project.pull_missing()?;
    }

    // Every image the release names, whether built here or pulled earlier.
    let references: Vec<String> = deployment
        .required_images()
        .iter()
        .map(|i| i.reference.clone())
        .collect();
    ensure_images_present(&references, args.no_build)?;

    eprintln!("  packaging {} image(s)", references.len());
    let mut writer = BundleWriter::new(app.clone(), release, platform.clone())?
        .compression(args.compression)
        .builder(concat!("via/", env!("CARGO_PKG_VERSION")));
    for file in &files {
        writer.add_project_file(&file.path, &file.source)?;
    }
    if let Some(path) = &args.sign_key {
        let key = SigningKey::read_from(path)
            .with_context(|| format!("reading signing key {}", path.display()))?;
        eprintln!("  signing with key {}", key.key_id());
        writer = writer.sign_with(key);
    }

    // One platform only. Saving a multi-platform image from Docker's
    // containerd store exports its whole index while holding content for
    // only some platforms, and the device's Docker then cannot resolve it.
    let mut save = Command::new(via_core::docker_program())
        .arg("save")
        .arg("--platform")
        .arg(platform.to_string())
        .args(&references)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("running `docker save`")?;
    let stdout = save.stdout.take().expect("stdout was piped");
    writer.add_docker_archive(stdout, |name| {
        // Match what Docker recorded against what the deployment asks for, so
        // an image saved under a different spelling still lands correctly.
        let name = name?;
        references
            .iter()
            .find(|r| r.as_str() == name || normalize_reference(r) == normalize_reference(name))
            .cloned()
    })?;
    let status = save.wait().context("waiting for `docker save`")?;
    if !status.success() {
        bail!("`docker save` failed with {status}");
    }

    // Record content digests into the manifest so the release identifies its
    // images by content, not by a tag someone upstream could move.
    let deployment = writer.digest_deployment(&deployment);

    let output = args.output.unwrap_or_else(|| {
        PathBuf::from(
            via_core::ReleaseRef::new(app.clone(), release)
                .artifact(platform.clone())
                .file_name(),
        )
    });
    let file =
        std::fs::File::create(&output).with_context(|| format!("creating {}", output.display()))?;
    writer.finish(file, &deployment, Some(&compose))?;

    let size_bytes = std::fs::metadata(&output)?.len();
    // The artifact's identity: what a device verifies a transfer against.
    let sha256 = via_deploy::digest_file(&output)?;
    Ok(Built {
        app: app.to_string(),
        release: release.0,
        platform: platform.to_string(),
        path: std::fs::canonicalize(&output)?,
        sha256: sha256.to_string(),
        size_bytes,
        signed: args.sign_key.is_some(),
        warnings: warnings.iter().map(|w| w.to_string()).collect(),
    })
}

/// Fail early, with a useful message, if an image the release needs is absent.
fn ensure_images_present(references: &[String], no_build: bool) -> Result<()> {
    let mut missing = Vec::new();
    for r in references {
        let out = Command::new(via_core::docker_program())
            .args(["image", "inspect", r])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if !matches!(out, Ok(s) if s.success()) {
            missing.push(r.clone());
        }
    }
    if missing.is_empty() {
        return Ok(());
    }
    let hint = if no_build {
        "\n  --no-build was given, so nothing was built or fetched. Remove it, or `docker pull` these first."
    } else {
        ""
    };
    bail!("image(s) not present locally: {}{hint}", missing.join(", "));
}

/// Compare image references ignoring the implicit `docker.io/library` prefix
/// and the implicit `:latest` tag.
fn normalize_reference(r: &str) -> String {
    let r = r.strip_prefix("docker.io/library/").unwrap_or(r);
    let r = r.strip_prefix("docker.io/").unwrap_or(r);
    if r.contains(':') || r.contains('@') {
        r.to_string()
    } else {
        format!("{r}:latest")
    }
}

pub fn default_app_name(compose_path: &Path) -> Result<String> {
    let dir = compose_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or(std::env::current_dir()?);
    let dir = if dir.as_os_str() == "." {
        std::env::current_dir()?
    } else {
        dir
    };
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .context("could not infer an application name; pass --app")?;
    Ok(name.to_lowercase().replace([' ', '.'], "-"))
}
