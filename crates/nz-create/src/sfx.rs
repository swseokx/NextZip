//! Self-extracting `.exe` (spec 3.1): the `nz-sfx` stub for x64 or ARM64,
//! then a 7z archive written by `nz-core`, then a 16-byte trailer holding
//! the archive offset (layout in the `nz-sfx` crate).
//!
//! The payload uses only coders the stub carries: LZMA2 (with BCJ x86 for
//! code), Deflate for the fast class, Copy. Zstandard folders, which
//! `nz-core` writes for ZIP-like inputs by default, are switched to LZMA2.

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::{Options, Stats};

/// Trailer magic; must match `nz_sfx::TRAILER_MAGIC` (checked in tests).
pub const TRAILER_MAGIC: [u8; 8] = *b"NZSFX\0\x01\0";

/// Which stub to put in front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X64,
    Arm64,
}

impl Arch {
    pub fn native() -> Arch {
        if cfg!(target_arch = "aarch64") {
            Arch::Arm64
        } else {
            Arch::X64
        }
    }

    pub fn parse(s: &str) -> Option<Arch> {
        Some(match s.to_ascii_lowercase().as_str() {
            "x64" | "amd64" | "x86_64" => Arch::X64,
            "arm64" | "aarch64" => Arch::Arm64,
            _ => return None,
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::Arm64 => "ARM64",
        }
    }

    /// File name of the stub as installed next to `nz.exe` / `nextzip.exe`.
    pub fn stub_name(self) -> &'static str {
        match self {
            Arch::X64 => "nz-sfx-x64.exe",
            Arch::Arm64 => "nz-sfx-arm64.exe",
        }
    }
}

/// The stub for `arch`: `opt.sfx_stub` if given, else the installed copy
/// beside the running program.
pub fn stub_path(arch: Arch, opt: &Options) -> Result<PathBuf> {
    if let Some(p) = &opt.sfx_stub {
        return Ok(p.clone());
    }
    let exe = std::env::current_exe().context("cannot locate the running program")?;
    let p = exe.with_file_name(arch.stub_name());
    if !p.is_file() {
        bail!(nz_front::trf(
            "{} 자동 압축 풀기 모듈({})을 찾을 수 없습니다",
            &[&arch.label(), &arch.stub_name()],
        ));
    }
    Ok(p)
}

/// A PE file for `arch` (checks the COFF machine field).
fn check_stub(stub: &[u8], arch: Arch) -> Result<()> {
    let pe = stub
        .get(0x3C..0x40)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize);
    let machine = pe
        .and_then(|o| stub.get(o..o + 6))
        .filter(|h| &h[..4] == b"PE\0\0")
        .map(|h| u16::from_le_bytes([h[4], h[5]]));
    let want = match arch {
        Arch::X64 => 0x8664,
        Arch::Arm64 => 0xAA64,
    };
    if !stub.starts_with(b"MZ") || machine != Some(want) {
        bail!("SFX stub is not a {} Windows program", arch.label());
    }
    Ok(())
}

pub fn create(arch: Arch, sources: &[PathBuf], out: &Path, opt: &Options) -> Result<Stats> {
    let stub_file = stub_path(arch, opt)?;
    let stub = std::fs::read(&stub_file)
        .with_context(|| format!("cannot read {}", stub_file.display()))?;
    check_stub(&stub, arch)?;

    // The 7z goes to a temp file beside the output, then is appended.
    let tmp = out.with_extension("nzsfx.7z.tmp");
    let level = opt.level.min(9) as u8;
    let mut co = nz_core::CompressOptions::new(nz_core::Format::SevenZ, level, crate::threads(opt));
    co.sevenz.zip_codec = nz_core::sevenz::ZipCodec::Lzma2;
    let r = (|| -> Result<Stats> {
        let w = nz_core::compress(sources, &tmp, &co)?;
        let mut o = io::BufWriter::new(File::create(out)?);
        o.write_all(&stub)?;
        let off = stub.len() as u64;
        let mut a = File::open(&tmp)?;
        io::copy(&mut a, &mut o)?;
        o.write_all(&TRAILER_MAGIC)?;
        o.write_all(&off.to_le_bytes())?;
        o.flush()?;
        drop(o);
        Ok(Stats {
            files: w.files,
            dirs: w.dirs,
            bytes_in: w.input_bytes,
            bytes_out: std::fs::metadata(out)?.len(),
        })
    })();
    let _ = std::fs::remove_file(&tmp);
    r
}
