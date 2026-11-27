//! NextZip engine (M1 prototype).
//!
//! * [`deflate`]: block-parallel raw Deflate on libdeflate (pigz-style splice)
//! * [`zip`]: standard ZIP writer and parallel extractor
//! * [`tarzst`]: tar.zst with multithreaded zstd
//! * [`tarfam`]: tar, tar.gz, tar.xz, tar.bz2, tar.lz4 (PAX names, links) and the shared tar reader
//! * [`cpu`]: processor groups (> 64 logical CPUs on Windows) and the Rayon pool
//! * [`sevenz`]: standard 7z with per-type solid blocks (LZMA2, BCJ x86 + LZMA2, Deflate, Copy)
//! * [`lzma`]: liblzma raw LZMA/LZMA2 with parallel spliced LZMA2 segments
//! * [`bcj`]: x86 BCJ filter
//! * [`planner`]: LZ4 sampling and content classification
//! * [`walk`]: deterministic input enumeration
//! * [`parzst`]: parallel decoding of multi-frame zstd streams
//! * [`mem`]: memory budget (limits concurrent encoders, never the output)
//!
//! Every writer is deterministic: identical input and options produce
//! identical bytes regardless of the number of threads.

pub mod bcj;
pub mod cpu;
pub mod deflate;
pub mod hdeflate;
pub mod lzma;
pub mod mem;
pub mod parzst;
pub mod planner;
pub mod sevenz;
pub mod tarfam;
mod tarfix;
pub mod tarzst;
pub mod walk;
pub mod zip;

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

pub use sevenz::SevenZOptions;
pub use tarzst::{ZstdOptions, default_threads};
pub use zip::{ExtractStats, WriteStats, ZipOptions};

/// Archive formats supported by the prototype.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Format {
    Zip,
    TarZst,
    SevenZ,
    Tar,
    TarGz,
    TarXz,
    TarBz2,
    TarLz4,
}

impl Format {
    pub fn parse(s: &str) -> Result<Self> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "zip" => Self::Zip,
            "tar.zst" | "tzst" | "zst" => Self::TarZst,
            "7z" => Self::SevenZ,
            "tar" => Self::Tar,
            "tar.gz" | "tgz" | "gz" => Self::TarGz,
            "tar.xz" | "txz" | "xz" => Self::TarXz,
            "tar.bz2" | "tbz2" | "tbz" | "bz2" => Self::TarBz2,
            "tar.lz4" | "tlz4" | "lz4" => Self::TarLz4,
            other => bail!(
                "unsupported format '{other}' (use zip, 7z, tar, tar.gz, tar.xz, tar.bz2, tar.lz4 or tar.zst)"
            ),
        })
    }
    pub fn extension(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::TarZst => "tar.zst",
            Self::SevenZ => "7z",
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
            Self::TarXz => "tar.xz",
            Self::TarBz2 => "tar.bz2",
            Self::TarLz4 => "tar.lz4",
        }
    }
    /// Every extension recognised for this format (lower case, longest first).
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Zip => &["zip"],
            Self::TarZst => &["tar.zst", "tzst"],
            Self::SevenZ => &["7z"],
            Self::Tar => &["tar"],
            Self::TarGz => &["tar.gz", "tgz"],
            Self::TarXz => &["tar.xz", "txz"],
            Self::TarBz2 => &["tar.bz2", "tbz2", "tbz"],
            Self::TarLz4 => &["tar.lz4", "tlz4"],
        }
    }
    /// All formats.
    pub const ALL: [Format; 8] = [
        Self::Zip,
        Self::SevenZ,
        Self::Tar,
        Self::TarGz,
        Self::TarXz,
        Self::TarBz2,
        Self::TarLz4,
        Self::TarZst,
    ];
    /// Format implied by a file name's extension, if any.
    pub fn from_name(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        Self::ALL.into_iter().find(|f| {
            f.extensions()
                .iter()
                .any(|x| lower.ends_with(&format!(".{x}")))
        })
    }
    /// The tar codec of a tar-family format.
    pub fn tar_codec(self) -> Option<tarfam::TarCodec> {
        use tarfam::TarCodec as C;
        Some(match self {
            Self::Tar => C::None,
            Self::TarGz => C::Gzip,
            Self::TarXz => C::Xz,
            Self::TarBz2 => C::Bzip2,
            Self::TarLz4 => C::Lz4,
            Self::TarZst => C::Zstd,
            Self::Zip | Self::SevenZ => return None,
        })
    }
    /// Detect from the first bytes of an archive.
    pub fn sniff(path: &Path) -> Result<Self> {
        use std::io::Read;
        let mut head = Vec::with_capacity(512);
        std::fs::File::open(path)?
            .take(512)
            .read_to_end(&mut head)?;
        use tarfam::TarCodec as C;
        Ok(match head.as_slice() {
            [b'P', b'K', 3, 4, ..] | [b'P', b'K', 5, 6, ..] => Self::Zip,
            [b'7', b'z', 0xBC, 0xAF, ..] => Self::SevenZ,
            h => match C::sniff(h) {
                Some(C::Zstd) => Self::TarZst,
                Some(C::None) => Self::Tar,
                Some(C::Gzip) => Self::TarGz,
                Some(C::Xz) => Self::TarXz,
                Some(C::Bzip2) => Self::TarBz2,
                Some(C::Lz4) => Self::TarLz4,
                None => bail!("{}: unknown archive format", path.display()),
            },
        })
    }
}

/// Options for [`compress`].
#[derive(Debug, Clone)]
pub struct CompressOptions {
    pub format: Format,
    pub zip: ZipOptions,
    pub zstd: ZstdOptions,
    pub sevenz: SevenZOptions,
    /// Worker threads (Rayon pool and zstd workers).
    pub threads: usize,
}

impl CompressOptions {
    pub fn new(format: Format, level: u8, threads: usize) -> Self {
        let threads = threads.max(1);
        Self {
            format,
            zip: ZipOptions {
                level,
                ..Default::default()
            },
            zstd: ZstdOptions {
                level,
                workers: threads as u32,
                ..Default::default()
            },
            sevenz: SevenZOptions::for_level(level),
            threads,
        }
    }
}
/// Print a timing line to stderr when `NZ_TRACE` is set.
pub fn trace(msg: &str) {
    if std::env::var_os("NZ_TRACE").is_some() {
        eprintln!("[nz] {msg}");
    }
}

fn pool(threads: usize) -> Result<rayon::ThreadPool> {
    cpu::pool(threads)
}

/// Archive `sources` into `out`.
pub fn compress(sources: &[PathBuf], out: &Path, opt: &CompressOptions) -> Result<WriteStats> {
    pool(opt.threads)?.install(|| {
        // The walk enumerates subdirectories in parallel on the same pool.
        let t0 = std::time::Instant::now();
        if let Some(codec) = opt.format.tar_codec() {
            // tar keeps symbolic links as links.
            let items = walk::collect_items(sources, true)?;
            trace(&format!(
                "walk {} entries {:.1} ms",
                items.len(),
                t0.elapsed().as_secs_f64() * 1e3
            ));
            let mut t = tarfam::TarOptions::new(codec, opt.zip.level);
            t.zstd = opt.zstd.clone();
            return tarfam::write_tar(&items, out, &t);
        }
        let entries = walk::collect(sources)?;
        trace(&format!(
            "walk {} entries {:.1} ms",
            entries.len(),
            t0.elapsed().as_secs_f64() * 1e3
        ));
        match opt.format {
            Format::Zip => zip::write_zip(&entries, out, &opt.zip),
            Format::SevenZ => sevenz::write_7z(&entries, out, &opt.sevenz),
            _ => unreachable!("tar formats handled above"),
        }
    })
}

/// Extract `archive` into `out_dir` (format detected from content).
pub fn extract(archive: &Path, out_dir: &Path, threads: usize) -> Result<ExtractStats> {
    let opt = ExtractOptions {
        symlinks: true,
        ..Default::default()
    };
    extract_with(archive, out_dir, threads, &opt)
}

/// Callback for [`ExtractOptions::on_name`]: member name, sanitised path.
pub type NameHook<'a> = dyn Fn(&str, &Path) + Sync + 'a;

/// Guards for extracting untrusted archives (used by `nz-archive`).
/// ZIP and 7z sizes are checked against their headers before extraction
/// by the caller; these apply to the tar family, whose size is only known
/// while the stream is decoded.
#[derive(Default)]
pub struct ExtractOptions<'a> {
    /// Most bytes all members together may produce (`None`: no limit).
    pub max_total: Option<u64>,
    /// Most members (files, directories, links) an archive may have.
    pub max_entries: Option<u64>,
    /// Called with every member name and the relative path it is written
    /// to (after `walk::safe_relative`), so callers can report renames.
    pub on_name: Option<&'a NameHook<'a>>,
    /// Recreate symbolic links as links. Off (the default, spec 9): a link
    /// becomes a small text file holding its target path. Either way a
    /// link pointing outside the output folder is not extracted.
    pub symlinks: bool,
}

/// An [`ExtractOptions`] limit was hit (a probable decompression bomb).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitExceeded {
    Total,
    Entries,
}

impl std::fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LimitExceeded::Total => "extracted size exceeds the limit",
            LimitExceeded::Entries => "number of members exceeds the limit",
        })
    }
}

impl std::error::Error for LimitExceeded {}

/// [`extract`] with limits, a name hook and the link mode (tar family;
/// see [`ExtractOptions`]). Plain [`extract`] keeps creating real links,
/// as it always did, for the round-trip tools built on it.
pub fn extract_with(
    archive: &Path,
    out_dir: &Path,
    threads: usize,
    opt: &ExtractOptions<'_>,
) -> Result<ExtractStats> {
    let fmt = Format::sniff(archive)?;
    pool(threads)?.install(|| match fmt {
        Format::Zip => zip::extract_zip(archive, out_dir),
        Format::SevenZ => sevenz::extract_7z(archive, out_dir),
        _ => tarfam::extract_tar_with(archive, out_dir, opt),
    })
}
