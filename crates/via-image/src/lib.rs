//! The boot partition of a raw viaos image, opened in place.
//!
//! Images are GPT disks whose first partition, `esp`, is FAT. The control
//! plane writes `viaos.toml` there when it provisions; `via` signs the EFI
//! binaries there for Secure Boot. Both go through [`open_esp`].

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

const SECTOR: u64 = 512;
const ESP_LABEL: &str = "esp";
/// The EFI System Partition type, C12A7328-F81F-11D2-BA4B-00A0C93EC93B, as
/// GPT stores it (the first three fields little-endian).
const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];

/// The FAT filesystem on an image's boot partition. Changes are written to
/// the image when it is unmounted (`fs.unmount()`).
pub type Esp = fatfs::FileSystem<Slice>;

pub fn open_esp(image: &Path) -> Result<Esp> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(image)
        .with_context(|| format!("opening {}", image.display()))?;
    // An image that names its boot partition differently (another OS run by
    // via-agent) is still provisioned: its one EFI System Partition will do.
    let (start, len) = match find_partition(&mut file, ESP_LABEL) {
        Ok(found) => found,
        Err(by_label) => find_esp_by_type(&mut file).map_err(|_| by_label)?,
    };
    fatfs::FileSystem::new(Slice::new(file, start, len)?, fatfs::FsOptions::new())
        .context("boot partition is not FAT")
}

/// One GPT entry: its name, type GUID, and byte offset and length.
struct Entry {
    name: String,
    kind: [u8; 16],
    start: u64,
    len: u64,
}

fn entries(file: &mut File) -> Result<Vec<Entry>> {
    let mut header = [0u8; 92];
    file.seek(SeekFrom::Start(SECTOR))?;
    file.read_exact(&mut header)?;
    if &header[..8] != b"EFI PART" {
        bail!("no GPT partition table");
    }
    let entries_lba = u64::from_le_bytes(header[72..80].try_into()?);
    let count = u32::from_le_bytes(header[80..84].try_into()?);
    let size = u32::from_le_bytes(header[84..88].try_into()?) as usize;

    let mut table = vec![0u8; count as usize * size];
    file.seek(SeekFrom::Start(entries_lba * SECTOR))?;
    file.read_exact(&mut table)?;
    let mut out = Vec::new();
    for entry in table.chunks(size) {
        if entry[..16].iter().all(|&b| b == 0) {
            continue;
        }
        let name: Vec<u16> = entry[56..128]
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let first = u64::from_le_bytes(entry[32..40].try_into()?);
        let last = u64::from_le_bytes(entry[40..48].try_into()?);
        out.push(Entry {
            name: String::from_utf16_lossy(&name),
            kind: entry[..16].try_into()?,
            start: first * SECTOR,
            len: (last - first + 1) * SECTOR,
        });
    }
    Ok(out)
}

/// Byte offset and length of the GPT partition named `label`.
pub fn find_partition(file: &mut File, label: &str) -> Result<(u64, u64)> {
    match entries(file)?.into_iter().find(|e| e.name == label) {
        Some(e) => Ok((e.start, e.len)),
        None => bail!("no partition labelled {label:?}"),
    }
}

/// Byte offset and length of the image's EFI System Partition, when it has
/// exactly one.
fn find_esp_by_type(file: &mut File) -> Result<(u64, u64)> {
    let esps: Vec<Entry> = entries(file)?
        .into_iter()
        .filter(|e| e.kind == ESP_TYPE)
        .collect();
    match esps.as_slice() {
        [e] => Ok((e.start, e.len)),
        [] => bail!("no EFI System Partition"),
        _ => bail!("{} EFI System Partitions", esps.len()),
    }
}

/// A window onto part of a file, so the FAT driver sees only the partition.
pub struct Slice {
    file: File,
    start: u64,
    len: u64,
    pos: u64,
}

impl Slice {
    fn new(mut file: File, start: u64, len: u64) -> io::Result<Self> {
        file.seek(SeekFrom::Start(start))?;
        Ok(Self {
            file,
            start,
            len,
            pos: 0,
        })
    }

    fn room(&self, want: usize) -> usize {
        want.min(self.len.saturating_sub(self.pos) as usize)
    }
}

impl Read for Slice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.room(buf.len());
        let n = self.file.read(&mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Write for Slice {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.room(buf.len());
        if n == 0 && !buf.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "past end of partition",
            ));
        }
        let n = self.file.write(&buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Seek for Slice {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(n) => n as i64,
            SeekFrom::End(n) => self.len as i64 + n,
            SeekFrom::Current(n) => self.pos as i64 + n,
        };
        if target < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = target as u64;
        self.file.seek(SeekFrom::Start(self.start + self.pos))?;
        Ok(self.pos)
    }
}

/// A directory on the boot partition.
pub type Dir<'a> = fatfs::Dir<'a, Slice>;

#[cfg(test)]
mod tests {
    use super::*;

    const LINUX: [u8; 16] = [
        0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d,
        0xe4,
    ];

    /// A disk holding only a GPT: the header and these entries, `(type, name, first LBA, last LBA)`.
    fn gpt(parts: &[([u8; 16], &str, u64, u64)]) -> tempfile::NamedTempFile {
        let mut disk = vec![0u8; 34 * SECTOR as usize];
        let header = &mut disk[SECTOR as usize..];
        header[..8].copy_from_slice(b"EFI PART");
        header[72..80].copy_from_slice(&2u64.to_le_bytes());
        header[80..84].copy_from_slice(&128u32.to_le_bytes());
        header[84..88].copy_from_slice(&128u32.to_le_bytes());
        for (i, (kind, name, first, last)) in parts.iter().enumerate() {
            let e = &mut disk[2 * SECTOR as usize + i * 128..][..128];
            e[..16].copy_from_slice(kind);
            e[16] = 1; // a partition GUID that isn't all zero
            e[32..40].copy_from_slice(&first.to_le_bytes());
            e[40..48].copy_from_slice(&last.to_le_bytes());
            for (j, c) in name.encode_utf16().enumerate() {
                e[56 + 2 * j..58 + 2 * j].copy_from_slice(&c.to_le_bytes());
            }
        }
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&disk).unwrap();
        f
    }

    fn open(f: &tempfile::NamedTempFile) -> File {
        File::open(f.path()).unwrap()
    }

    #[test]
    fn a_partition_is_found_by_its_name() {
        let disk = gpt(&[(ESP_TYPE, "esp", 2048, 4095), (LINUX, "root", 4096, 8191)]);
        let found = find_partition(&mut open(&disk), "root").unwrap();
        assert_eq!(found, (4096 * SECTOR, 4096 * SECTOR));
    }

    #[test]
    fn an_esp_named_otherwise_is_found_by_its_type() {
        let disk = gpt(&[
            (ESP_TYPE, "caseos-esp", 2048, 4095),
            (LINUX, "caseos-a", 4096, 8191),
        ]);
        assert!(find_partition(&mut open(&disk), ESP_LABEL).is_err());
        let found = find_esp_by_type(&mut open(&disk)).unwrap();
        assert_eq!(found, (2048 * SECTOR, 2048 * SECTOR));
    }

    #[test]
    fn two_esps_or_none_are_not_guessed_between() {
        let two = gpt(&[(ESP_TYPE, "a", 2048, 4095), (ESP_TYPE, "b", 4096, 8191)]);
        assert!(find_esp_by_type(&mut open(&two)).is_err());
        let none = gpt(&[(LINUX, "root", 2048, 4095)]);
        assert!(find_esp_by_type(&mut open(&none)).is_err());
    }
}
