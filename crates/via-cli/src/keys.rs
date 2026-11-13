//! Keys to sign with, when asked for. By default nothing is signed: images
//! and releases are plain, and no key lives on whatever machine ran `via`.

use std::path::PathBuf;

use anyhow::{Result, ensure};

/// The key to sign OS updates and app releases with, if one was asked for.
/// Signing is for servers and devices that set trusted keys; without them
/// a release goes out unsigned. Keys are never made up here.
pub fn signing_key(given: Option<PathBuf>) -> Result<Option<PathBuf>> {
    let Some(path) = given else { return Ok(None) };
    ensure!(path.exists(), "no signing key at {}", path.display());
    Ok(Some(path))
}

/// The Secure Boot keys to sign with, if any were asked for. Secure Boot is
/// off unless they are: images and updates go out unsigned for it, and boot
/// on any device whose firmware doesn't enforce it. Keys are never made up
/// here, so nothing depends on the machine a release happens to come from;
/// make them once with `via secure-boot keygen` and keep them with the
/// release secrets.
pub fn secure_boot_keys(given: Option<PathBuf>) -> Result<Option<PathBuf>> {
    let Some(dir) = given else { return Ok(None) };
    ensure!(
        dir.join("db.key").exists(),
        "no Secure Boot keys in {}",
        dir.display()
    );
    Ok(Some(dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_that_was_asked_for_is_never_made_up() {
        let d = tempfile::tempdir().unwrap();
        assert!(signing_key(Some(d.path().join("nope"))).is_err());
        assert!(secure_boot_keys(Some(d.path().join("nope"))).is_err());
        assert!(secure_boot_keys(None).unwrap().is_none());
    }
}
