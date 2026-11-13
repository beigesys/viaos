//! Provisioning images: a generic viaos image with one file written into it.
//!
//! The base image for each architecture is built once. Provisioning copies it
//! and writes `viaos.toml` -- control plane URL, enrollment token, hostname --
//! onto its FAT boot partition. Nothing is rebuilt, so this takes as long as
//! the copy and the compression, and needs no Nix where the control plane
//! runs.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// The architectures images exist for, as `uname -m` spells them.
pub const ARCHES: &[&str] = &["x86_64", "i686", "aarch64", "armv7l"];

/// Device types that run a variant of viaos, not their architecture's plain
/// OS. Only their own image will do: the plain one would boot, without what
/// the type is for.
const VARIANTS: &[&str] = &["pc-nvidia"];

/// Whether a device type can make do with its architecture's image.
pub fn shares_arch_image(t: &crate::db::DeviceType) -> bool {
    !VARIANTS.contains(&t.id.as_str())
}

/// A device type's own base image, or else its architecture's.
pub fn base_image(dir: &Path, t: &crate::db::DeviceType) -> Result<PathBuf> {
    let names = if shares_arch_image(t) {
        vec![&t.id, &t.arch]
    } else {
        vec![&t.id]
    };
    for name in &names {
        let path = dir.join(format!("viaos-{name}.raw"));
        if path.exists() {
            return Ok(path);
        }
    }
    let names: Vec<String> = names.iter().map(|n| format!("viaos-{n}.raw")).collect();
    bail!(
        "no base image for {}: upload one with `via base-image`, as {}",
        t.name,
        names.join(" or ")
    );
}

/// Copy `base` to `out` (zstd-compressed), with `config` as `/viaos.toml` on
/// its boot partition.
pub fn provision(base: &Path, out: &Path, config: &str) -> Result<()> {
    let work = out.with_extension("work");
    // Reflink when the filesystem can, so the multi-gigabyte copy is free.
    let status = std::process::Command::new("cp")
        .args(["--reflink=auto", "--sparse=always"])
        .arg(base)
        .arg(&work)
        .status()
        .context("running cp")?;
    anyhow::ensure!(status.success(), "copying base image failed");
    // Base images often come from the Nix store, read-only; the copy is ours.
    std::fs::set_permissions(&work, std::os::unix::fs::PermissionsExt::from_mode(0o644))?;

    let result = write_config(&work, config).and_then(|()| compress(&work, out));
    let _ = std::fs::remove_file(&work);
    result
}

fn write_config(image: &Path, config: &str) -> Result<()> {
    let fs = via_image::open_esp(image)?;
    let mut f = fs.root_dir().create_file("viaos.toml")?;
    f.truncate()?;
    f.write_all(config.as_bytes())?;
    f.flush()?;
    drop(f);
    fs.unmount()?;
    Ok(())
}

fn compress(input: &Path, out: &Path) -> Result<()> {
    let mut src = File::open(input)?;
    let dst = File::create(out)?;
    let mut enc = zstd_encoder(dst)?;
    io::copy(&mut src, &mut enc)?;
    enc.finish()?;
    Ok(())
}

/// Unpack a zstd-compressed image to `out`, leaving runs of zeros as holes:
/// most of a base image is empty partitions.
pub fn decompress(input: &Path, out: &Path) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let tmp = out.with_extension("unpack");
    let mut dec = zstd::Decoder::new(File::open(input)?)?;
    let mut dst = File::create(&tmp)?;
    let mut buf = vec![0u8; 1 << 16];
    let mut len = 0u64;
    loop {
        let mut n = 0;
        while n < buf.len() {
            match dec.read(&mut buf[n..])? {
                0 => break,
                k => n += k,
            }
        }
        if n == 0 {
            break;
        }
        if buf[..n].iter().all(|&b| b == 0) {
            dst.seek(SeekFrom::Current(n as i64))?;
        } else {
            dst.write_all(&buf[..n])?;
        }
        len += n as u64;
    }
    dst.set_len(len)?;
    dst.sync_all()?;
    std::fs::rename(tmp, out)?;
    Ok(())
}

fn zstd_encoder(dst: File) -> Result<zstd::Encoder<'static, File>> {
    let mut enc = zstd::Encoder::new(dst, 3)?;
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get() as u32);
    enc.multithread(threads)?;
    Ok(enc)
}
