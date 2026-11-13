//! Base images from where viaos is published, so a new server can make
//! provisioning images without anyone uploading one. Each architecture's is
//! fetched once, when the server has none, and so is a device type's own
//! (`viaos-pc-nvidia.raw.zst`) where the release has one; `via base-image`
//! still replaces either.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::AsyncWriteExt;

use crate::State;

/// Where a GitHub release keeps its files: `<source>/viaos-<arch>.raw.zst`,
/// and `<source>/viaos-<device type>.raw.zst` for a type with its own.
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
    let source = source.trim_end_matches('/');
    let types = state.db.device_types()?;
    // A type's own first: it's the one `base_image` prefers. Most types have
    // none published, and that's no news.
    for t in &types {
        if state
            .images_dir
            .join(format!("viaos-{}.raw", t.id))
            .exists()
        {
            continue;
        }
        let url = format!("{source}/viaos-{}.raw.zst", t.id);
        match fetch(&url, &state.images_dir, &t.id).await {
            Ok(true) => tracing::info!(device_type = %t.id, %url, "fetched base image"),
            Ok(false) if !crate::image::shares_arch_image(t) => {
                tracing::info!(device_type = %t.id, %url, "no published base image yet")
            }
            Ok(false) => {}
            Err(e) => tracing::warn!(device_type = %t.id, %url, "fetching base image: {e:#}"),
        }
    }
    let mut arches: Vec<&str> = types
        .iter()
        .filter(|t| crate::image::shares_arch_image(t))
        .filter(|t| crate::image::base_image(&state.images_dir, t).is_err())
        .map(|t| t.arch.as_str())
        .collect();
    arches.sort();
    arches.dedup();
    for arch in arches {
        let url = format!("{source}/viaos-{arch}.raw.zst");
        match fetch(&url, &state.images_dir, arch).await {
            Ok(true) => tracing::info!(%arch, %url, "fetched base image"),
            Ok(false) => tracing::info!(%arch, %url, "no published base image yet"),
            Err(e) => tracing::warn!(%arch, %url, "fetching base image: {e:#}"),
        }
    }
    Ok(())
}

/// Download and unpack one, as `viaos-<name>.raw`; `false` if there's
/// nothing at `url`.
async fn fetch(url: &str, dir: &Path, name: &str) -> Result<bool> {
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
    let part = dir.join(format!("viaos-{name}.raw.zst.part"));
    let mut file = tokio::fs::File::create(&part).await?;
    while let Some(chunk) = res.chunk().await.context("downloading")? {
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    drop(file);
    let raw = dir.join(format!("viaos-{name}.raw"));
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

    #[tokio::test]
    async fn a_variant_type_gets_its_own_image_never_the_plain_one() {
        let serve = |names: &'static [&'static str]| async move {
            let mut router = axum::Router::new();
            for name in names {
                let packed = zstd::encode_all(name.as_bytes(), 3).unwrap();
                router = router.route(
                    &format!("/viaos-{name}.raw.zst"),
                    axum::routing::get(move || {
                        let p = packed.clone();
                        async move { p }
                    }),
                );
            }
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", l.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(l, router).await });
            url
        };
        let dir = tempfile::tempdir().unwrap();
        let state = crate::test_state(dir.path(), "http://localhost", None);
        let types = state.db.device_types().unwrap();
        let of = |id: &str| types.iter().find(|t| t.id == id).unwrap().clone();
        let base = |id: &str| {
            crate::image::base_image(&state.images_dir, &of(id))
                .map(|p| std::fs::read_to_string(p).unwrap())
        };

        // A release from before the variant: plain PCs are covered, NVIDIA
        // ones are not, rather than getting an image without the driver.
        missing(&state, &serve(&["x86_64", "aarch64"]).await)
            .await
            .unwrap();
        assert_eq!(base("pc").unwrap(), "x86_64");
        assert_eq!(base("raspberry-pi").unwrap(), "aarch64");
        assert!(base("pc-nvidia").is_err());

        missing(&state, &serve(&["x86_64", "aarch64", "pc-nvidia"]).await)
            .await
            .unwrap();
        assert_eq!(base("pc-nvidia").unwrap(), "pc-nvidia");
        assert_eq!(base("pc").unwrap(), "x86_64");
    }
}
