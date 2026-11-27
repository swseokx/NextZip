//! NextZip self-extracting archives.
//!
//! Layout of an SFX `.exe`:
//!
//! ```text
//! [stub .exe (this crate's binary, x64 or ARM64)]
//! [7z archive]
//! [trailer: b"NZSFX\0\x01\0" + payload offset as u64 LE]   (16 bytes)
//! ```
//!
//! The trailer lets the stub find its payload without scanning; other
//! tools (7-Zip, NextZip itself) find the 7z signature after the stub as
//! with any 7z SFX. Extraction follows the reader policy of spec 9: an
//! archive with an absolute, drive-relative or `..` member is refused as a
//! whole, and symbolic links are never created (7z SFX payloads made by
//! NextZip hold none).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use nz_front::{tr, trf};

/// First 8 bytes of the trailer.
pub const TRAILER_MAGIC: [u8; 8] = *b"NZSFX\0\x01\0";
pub const TRAILER_LEN: u64 = 16;

/// Offset of the 7z payload inside an SFX file, from its trailer.
pub fn payload_offset(f: &mut File) -> Result<u64> {
    let len = f.metadata()?.len();
    if len < TRAILER_LEN {
        bail!(tr("이 프로그램에 붙은 압축 파일이 없습니다"));
    }
    let mut t = [0u8; 16];
    f.seek(SeekFrom::Start(len - TRAILER_LEN))?;
    f.read_exact(&mut t)?;
    if t[..8] != TRAILER_MAGIC {
        bail!(tr("이 프로그램에 붙은 압축 파일이 없습니다"));
    }
    let off = u64::from_le_bytes(t[8..].try_into().unwrap());
    if off >= len - TRAILER_LEN {
        bail!(tr(
            "자동 압축 풀기 파일이 손상되었습니다 (잘못된 데이터 위치)"
        ));
    }
    Ok(off)
}

/// A read-only window `[start, end)` of a file, seen from offset 0.
pub struct Window {
    f: File,
    start: u64,
    len: u64,
    pos: u64,
}

impl Window {
    pub fn new(f: File, start: u64, end: u64) -> Window {
        Window {
            f,
            start,
            len: end.saturating_sub(start),
            pos: 0,
        }
    }
}

impl Read for Window {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.len.saturating_sub(self.pos);
        let n = (buf.len() as u64).min(left) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.f.seek(SeekFrom::Start(self.start + self.pos))?;
        let got = self.f.read(&mut buf[..n])?;
        self.pos += got as u64;
        Ok(got)
    }
}

impl Seek for Window {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let p = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::End(d) => self.len.checked_add_signed(d),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
        };
        self.pos = p.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad seek"))?;
        Ok(self.pos)
    }
}

/// `name` (a 7z member path) as a relative path under the output folder,
/// or an error when it could escape it.
pub fn safe_relative(name: &str) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    if name.starts_with(['/', '\\']) {
        bail!(trf(
            "압축 파일에 안전하지 않은 경로가 있습니다: {}",
            &[&name]
        ));
    }
    for part in name.split(['/', '\\']) {
        if part.is_empty() || part == "." {
            continue;
        }
        let bad_char = part
            .chars()
            .any(|c| c < ' ' || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'));
        if part == ".." || bad_char || part.ends_with(['.', ' ']) {
            bail!(trf(
                "압축 파일에 안전하지 않은 경로가 있습니다: {}",
                &[&name]
            ));
        }
        out.push(part);
    }
    if out.as_os_str().is_empty() {
        bail!(tr("압축 파일에 빈 경로가 있습니다"));
    }
    Ok(out)
}

/// What [`extract`] wrote.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
}

/// Extract the 7z archive in `payload` into `dest` (created if missing).
/// Existing files are replaced only when `overwrite` is set.
pub fn extract<R: Read + Seek>(payload: R, dest: &Path, overwrite: bool) -> Result<Stats> {
    let mut reader = sevenz_rust2::ArchiveReader::new(payload, sevenz_rust2::Password::empty())
        .context(tr("붙어 있는 압축 파일이 손상되었습니다"))?;
    // Check every name before writing anything.
    for e in &reader.archive().files {
        safe_relative(e.name())?;
    }
    std::fs::create_dir_all(dest)
        .with_context(|| trf("{}을(를) 만들 수 없습니다", &[&dest.display()]))?;
    let mut stats = Stats::default();
    let mut failure: Option<anyhow::Error> = None;
    reader
        .for_each_entries(|e, r| {
            let step = (|| -> Result<()> {
                if e.is_anti_item() {
                    return Ok(());
                }
                let p = dest.join(safe_relative(e.name())?);
                if e.is_directory() {
                    std::fs::create_dir_all(&p)?;
                    stats.dirs += 1;
                    return Ok(());
                }
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                if !overwrite && p.exists() {
                    bail!(trf("{}이(가) 이미 있습니다", &[&p.display()]));
                }
                let mut f = File::create(&p)
                    .with_context(|| trf("{}을(를) 만들 수 없습니다", &[&p.display()]))?;
                stats.bytes += io::copy(r, &mut f)?;
                if e.has_last_modified_date {
                    let _ = f.set_modified(e.last_modified_date().into());
                }
                stats.files += 1;
                Ok(())
            })();
            match step {
                Ok(()) => Ok(true),
                Err(err) => {
                    failure = Some(err);
                    Ok(false)
                }
            }
        })
        .context(tr("붙어 있는 압축 파일이 손상되었습니다"))?;
    if let Some(e) = failure {
        return Err(e);
    }
    Ok(stats)
}

/// Extract the archive attached to the SFX file at `exe`.
pub fn extract_sfx(exe: &Path, dest: &Path, overwrite: bool) -> Result<Stats> {
    let mut f =
        File::open(exe).with_context(|| trf("{}을(를) 열 수 없습니다", &[&exe.display()]))?;
    let off = payload_offset(&mut f)?;
    let end = f.metadata()?.len() - TRAILER_LEN;
    extract(Window::new(f, off, end), dest, overwrite)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsafe_names_are_refused() {
        for bad in [
            "/etc/x", "\\x", "C:/x", "C:x", "a/../b", "..", "a/b:c", "nul\u{1}", "a/b.", "a/b ",
        ] {
            assert!(safe_relative(bad).is_err(), "{bad}");
        }
        assert_eq!(safe_relative("a/./b\\c").unwrap(), PathBuf::from("a/b/c"));
    }
}
