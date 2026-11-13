//! Base images from where viaos is published, so a new server can make
//! provisioning images without anyone uploading one. Each architecture's is
//! fetched once, when the server has none; `via base-image` still replaces it.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;

use crate::State;

/// Where a GitHub release keeps its files: `<source>/viaos-<arch>.raw.zst`.
pub const DEFAULT_SOURCE: &str = "https://github.com/beigesys/viaos/releases/latest/download";

/// Fetch every missing base image now, and look again each hour for any that
/// weren't published yet.
pub async fn run(state: Arc<State>, source: String) {
    loop {
        if let Err(e) = missing(&state, &source).await {
            tracing::warn!("fetching base images from {source}: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn missing(state: &State, source: &str) -> Result<()> {
    let mut arches: Vec<String> = state
        .db
        .device_types()?
        .into_iter()
        .map(|t| t.arch)
        .collect();
    arches.sort();
    arches.dedup();
    for arch in arches {
        let types = state.db.device_types()?;
        let has = types
            .iter()
            .filter(|t| t.arch == arch)
            .all(|t| crate::image::base_image(&state.images_dir, t).is_ok());
        if has {
            continue;
        }
        let url = format!("{}/viaos-{arch}.raw.zst", source.trim_end_matches('/'));
        match fetch(&url, &state.images_dir, &arch).await {
            Ok(true) => tracing::info!(%arch, %url, "fetched base image"),
            Ok(false) => tracing::info!(%arch, %url, "no published base image yet"),
            Err(e) => tracing::warn!(%arch, %url, "fetching base image: {e:#}"),
        }
    }
    Ok(())
}

/// Download and unpack one; `false` if there's nothing at `url`.
async fn fetch(url: &str, dir: &Path, arch: &str) -> Result<bool> {
    let client = reqwest::Client::builder()
        .user_agent("via-server")
        .connect_timeout(Duration::from_secs(30))
        .build()?;
    let mut res = client.get(url).send().await?;
    if res.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(false);
    }
    let res_status = res.status();
    anyhow::ensure!(res_status.is_success(), "{res_status}");
    tokio::fs::create_dir_all(dir).await?;
    let part = dir.join(format!("viaos-{arch}.raw.zst.part"));
    let mut file = tokio::fs::File::create(&part).await?;
    while let Some(chunk) = res.chunk().await.context("downloading")? {
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    drop(file);
    let raw = dir.join(format!("viaos-{arch}.raw"));
    let p = part.clone();
    let unpacked = tokio::task::spawn_blocking(move || crate::image::decompress(&p, &raw)).await?;
    let _ = tokio::fs::remove_file(&part).await;
    unpacked?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_published_image_is_fetched_and_unpacked() {
        let packed = zstd::encode_all(&b"a whole disk"[..], 3).unwrap();
        let router = axum::Router::new().route(
            "/viaos-aarch64.raw.zst",
            axum::routing::get(move || {
                let p = packed.clone();
                async move { p }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, router).await });
        let dir = tempfile::tempdir().unwrap();
        assert!(
            fetch(
                &format!("{url}/viaos-aarch64.raw.zst"),
                dir.path(),
                "aarch64"
            )
            .await
            .unwrap()
        );
        assert_eq!(
            std::fs::read(dir.path().join("viaos-aarch64.raw")).unwrap(),
            b"a whole disk"
        );
        assert!(!dir.path().join("viaos-aarch64.raw.zst.part").exists());
        assert!(
            !fetch(&format!("{url}/viaos-x86_64.raw.zst"), dir.path(), "x86_64")
                .await
                .unwrap()
        );
    }
}
