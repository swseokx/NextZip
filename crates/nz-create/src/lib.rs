//! Writers for the formats NextZip 1.0 adds on top of `nz-core`
//! (spec 3.1): single-file compressed streams (GZ, XZ, BZ2, ZST, LZ4),
//! ZIPX (ZIP with Zstandard, LZMA, PPMd, XZ or BZip2 members), ISO 9660
//! images with Joliet names and self-extracting `.exe` files (x64, ARM64).
//!
//! Inputs are enumerated with [`nz_core::walk::collect`], so member order
//! and naming match the other writers: a directory source contributes its
//! contents, a file source itself.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

pub mod iso;
pub mod sfx;
pub mod stream;
pub mod zipx;

/// What to create.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// One file compressed as a raw stream.
    Stream(stream::Codec),
    Zipx(zipx::Method),
    Iso,
    /// Self-extracting `.exe` with a 7z payload.
    Sfx(sfx::Arch),
}

impl Kind {
    /// The kind for an explicit `-fmt:` name, if it is one of ours.
    pub fn parse(name: &str) -> Option<Kind> {
        let n = name.to_ascii_lowercase();
        Some(match n.as_str() {
            "zipx" => Kind::Zipx(zipx::Method::Zstd),
            "iso" => Kind::Iso,
            "exe" | "sfx" => Kind::Sfx(sfx::Arch::native()),
            "sfx-x64" => Kind::Sfx(sfx::Arch::X64),
            "sfx-arm64" => Kind::Sfx(sfx::Arch::Arm64),
            _ => Kind::Stream(stream::Codec::parse(&n)?),
        })
    }

    /// The kind implied by an output file name (`x.gz`, `x.zipx`, `x.iso`).
    /// `.tar.gz` and friends are left to `nz-core`.
    pub fn from_name(out: &Path) -> Option<Kind> {
        let name = out.file_name()?.to_string_lossy().to_ascii_lowercase();
        if name.contains(".tar.") {
            return None;
        }
        let ext = name.rsplit_once('.')?.1;
        Kind::parse(ext)
    }

    pub fn label(self) -> &'static str {
        match self {
            Kind::Stream(c) => c.label(),
            Kind::Zipx(_) => "ZIPX",
            Kind::Iso => "ISO",
            Kind::Sfx(sfx::Arch::X64) => "SFX x64",
            Kind::Sfx(sfx::Arch::Arm64) => "SFX ARM64",
        }
    }
}

/// Options shared by the writers.
#[derive(Debug, Clone)]
pub struct Options {
    /// Compression level 0..=9 (mapped onto each codec's own scale).
    pub level: u32,
    /// Worker threads for codecs that have them (0: all logical CPUs).
    pub threads: usize,
    /// ISO volume label (default: the output file stem).
    pub volume: Option<String>,
    /// SFX stub to use instead of the installed `nz-sfx-<arch>.exe`.
    pub sfx_stub: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            level: 5,
            threads: 0,
            volume: None,
            sfx_stub: None,
        }
    }
}

/// Result of [`create`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub files: usize,
    pub dirs: usize,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// Create `out` from `sources`.
pub fn create(kind: Kind, sources: &[PathBuf], out: &Path, opt: &Options) -> Result<Stats> {
    if sources.is_empty() {
        bail!(nz_front::tr("추가할 파일이 없습니다"));
    }
    let r = match kind {
        Kind::Stream(c) => stream::create(c, sources, out, opt),
        Kind::Zipx(m) => zipx::create(m, sources, out, opt),
        Kind::Iso => iso::create(sources, out, opt),
        Kind::Sfx(a) => sfx::create(a, sources, out, opt),
    };
    if r.is_err() {
        let _ = std::fs::remove_file(out);
    }
    r
}

pub(crate) fn threads(opt: &Options) -> usize {
    if opt.threads == 0 {
        nz_core::default_threads()
    } else {
        opt.threads
    }
}
