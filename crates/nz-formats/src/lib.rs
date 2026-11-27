//! Readers for NextZip's 1.0 format expansion (spec 3.2: disk images,
//! installers and packages, legacy archivers, extra single streams).
//!
//! Everything here parses untrusted input, so the facade (`nz-archive`)
//! runs these readers inside the isolated, low-privilege decoder process
//! (`nz-decode.exe`, see `nz-sandbox`). Readers never touch the file system
//! beyond reading the archive (and its sibling volumes): member data goes to
//! a [`Sink`], and the parent process decides what is written where.
//!
//! Every reader follows one contract:
//! * [`list`] returns members in a stable order;
//! * [`extract`] calls the sink with indices into that same order;
//! * sizes from headers are never trusted for allocation (see [`limits`]).

pub mod ar;
pub mod asar;
pub mod cpio;
pub mod fuzzing;
pub mod iso;
pub mod legacy;
pub mod limits;
pub mod lzw;
pub mod msi;
pub mod rpm;
pub mod stream;
pub mod tar;
pub mod util;
pub mod uu;
pub mod vdisk;
pub mod xar;
pub mod xml;

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::Result;

/// Formats this crate reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Format {
    // Legacy archivers (unarc-rs).
    Ace,
    Arc,
    Arj,
    Zoo,
    Lha,
    Ha,
    Uc2,
    Sq,
    Sqz,
    Hyp,
    Jar32,
    Cab,
    AmigaLzx,
    Dms,
    Adf,
    Hdf,
    D64,
    T64,
    Lynx,
    Atr,
    PackIce,
    Ice,
    Fat,
    // Single streams (spec 3.2 "단일 스트림").
    Gz,
    Bz2,
    Xz,
    Lzma,
    Lzip,
    Zst,
    Lz4,
    Br,
    Z,
    // Packages and installers.
    Cpio,
    Ar,
    Deb,
    Rpm,
    Asar,
    Xar,
    Msi,
    // Disk images.
    Iso,
    Vhd,
    Vhdx,
    Vmdk,
    Qcow2,
    // Text encodings.
    Uue,
    Xxe,
    // Full readers used as a fallback by nz-archive for what its fast
    // in-process readers do not cover (never returned by `detect`).
    /// ZIP with Deflate64, BZip2, LZMA, PPMd, XZ, zstd, WinZip AES.
    ZipFull,
    /// 7z with every standard coder and filter (sevenz-rust2).
    SevenZ,
}

impl Format {
    /// Every format, in the order used by listings and reports.
    pub const ALL: &'static [Format] = &[
        Format::Ace,
        Format::Arc,
        Format::Arj,
        Format::Zoo,
        Format::Lha,
        Format::Ha,
        Format::Uc2,
        Format::Sq,
        Format::Sqz,
        Format::Hyp,
        Format::Jar32,
        Format::Cab,
        Format::AmigaLzx,
        Format::Dms,
        Format::Adf,
        Format::Hdf,
        Format::D64,
        Format::T64,
        Format::Lynx,
        Format::Atr,
        Format::PackIce,
        Format::Ice,
        Format::Fat,
        Format::Gz,
        Format::Bz2,
        Format::Xz,
        Format::Lzma,
        Format::Lzip,
        Format::Zst,
        Format::Lz4,
        Format::Br,
        Format::Z,
        Format::Cpio,
        Format::Ar,
        Format::Deb,
        Format::Rpm,
        Format::Asar,
        Format::Xar,
        Format::Msi,
        Format::Iso,
        Format::Vhd,
        Format::Vhdx,
        Format::Vmdk,
        Format::Qcow2,
        Format::Uue,
        Format::Xxe,
    ];

    /// Short upper-case label for file lists.
    pub fn label(self) -> &'static str {
        match self {
            Format::Ace => "ACE",
            Format::Arc => "ARC",
            Format::Arj => "ARJ",
            Format::Zoo => "ZOO",
            Format::Lha => "LZH",
            Format::Ha => "HA",
            Format::Uc2 => "UC2",
            Format::Sq => "SQ",
            Format::Sqz => "SQZ",
            Format::Hyp => "HYP",
            Format::Jar32 => "JAR (ARJ Software)",
            Format::Cab => "CAB",
            Format::AmigaLzx => "LZX (Amiga)",
            Format::Dms => "DMS",
            Format::Adf => "ADF",
            Format::Hdf => "HDF",
            Format::D64 => "D64",
            Format::T64 => "T64",
            Format::Lynx => "LNX",
            Format::Atr => "ATR",
            Format::PackIce => "Pack-Ice",
            Format::Ice => "ICE (LHice)",
            Format::Fat => "IMG (FAT)",
            Format::Gz => "GZ",
            Format::Bz2 => "BZ2",
            Format::Xz => "XZ",
            Format::Lzma => "LZMA",
            Format::Lzip => "LZ",
            Format::Zst => "ZST",
            Format::Lz4 => "LZ4",
            Format::Br => "BR",
            Format::Z => "Z",
            Format::Cpio => "CPIO",
            Format::Ar => "AR",
            Format::Deb => "DEB",
            Format::Rpm => "RPM",
            Format::Asar => "ASAR",
            Format::Xar => "XAR",
            Format::Msi => "MSI",
            Format::Iso => "ISO",
            Format::Vhd => "VHD",
            Format::Vhdx => "VHDX",
            Format::Vmdk => "VMDK",
            Format::Qcow2 => "QCOW2",
            Format::Uue => "UUE",
            Format::Xxe => "XXE",
            Format::ZipFull => "ZIP",
            Format::SevenZ => "7Z",
        }
    }

    /// File extensions (lower case, without the dot).
    pub fn extensions(self) -> &'static [&'static str] {
        match self {
            Format::Ace => &["ace"],
            Format::Arc => &["arc", "pak", "ark"],
            Format::Arj => &["arj"],
            Format::Zoo => &["zoo"],
            Format::Lha => &["lzh", "lha", "lzs"],
            Format::Ha => &["ha"],
            Format::Uc2 => &["uc2"],
            Format::Sq => &["sq", "qqq"],
            Format::Sqz => &["sqz"],
            Format::Hyp => &["hyp"],
            Format::Jar32 => &["j"],
            Format::Cab => &["cab"],
            Format::AmigaLzx => &["lzx"],
            Format::Dms => &["dms"],
            Format::Adf => &["adf"],
            Format::Hdf => &["hdf"],
            Format::D64 => &["d64"],
            Format::T64 => &["t64"],
            Format::Lynx => &["lnx"],
            Format::Atr => &["atr"],
            Format::PackIce => &["pi9"],
            Format::Ice => &["ice"],
            Format::Fat => &["img", "ima", "st"],
            Format::Gz => &["gz", "gzip"],
            Format::Bz2 => &["bz2", "bzip2"],
            Format::Xz => &["xz"],
            Format::Lzma => &["lzma", "tlzma"],
            Format::Lzip => &["lz", "tlz"],
            Format::Zst => &["zst", "zstd"],
            Format::Lz4 => &["lz4"],
            Format::Br => &["br"],
            Format::Z => &["z", "taz"],
            Format::Cpio => &["cpio"],
            Format::Ar => &["a", "ar", "lib"],
            Format::Deb => &["deb", "udeb", "ipk"],
            Format::Rpm => &["rpm", "srpm"],
            Format::Asar => &["asar"],
            Format::Xar => &["xar", "pkg", "xip"],
            Format::Msi => &["msi", "msp", "mst", "msm"],
            Format::Iso => &["iso"],
            Format::Vhd => &["vhd"],
            Format::Vhdx => &["vhdx", "avhdx"],
            Format::Vmdk => &["vmdk"],
            Format::Qcow2 => &["qcow2", "qcow", "img"],
            Format::Uue => &["uue", "uu"],
            Format::Xxe => &["xxe", "xx"],
            Format::ZipFull => &["zipx"],
            Format::SevenZ => &["7z"],
        }
    }
}

/// One member of an archive.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Member {
    /// `/`-separated path inside the archive (not yet sanitised).
    pub name: String,
    pub is_dir: bool,
    /// Uncompressed size from the header (a hint, never trusted).
    pub size: u64,
    /// Compressed size (0 when unknown).
    pub csize: u64,
    /// Modification time, seconds since the Unix epoch.
    pub mtime: Option<i64>,
    pub method: String,
    pub crc: Option<u32>,
    pub encrypted: bool,
    /// Symbolic or hard link target; such members are not extracted.
    pub link: Option<String>,
    /// The stored name bytes when they are not UTF-8 (a legacy code page
    /// such as CP949 or Shift-JIS); `name` is then a lossy rendering and the
    /// caller decodes this with its code page detection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_name: Option<Vec<u8>>,
}

/// A member name from stored bytes: UTF-8 as is, anything else lossy with
/// the raw bytes kept for code page detection.
pub fn name_from_bytes(raw: &[u8]) -> (String, Option<Vec<u8>>) {
    match std::str::from_utf8(raw) {
        Ok(s) => (s.to_string(), None),
        Err(_) => (
            String::from_utf8_lossy(raw).into_owned(),
            Some(raw.to_vec()),
        ),
    }
}

/// Result of [`list`].
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Listing {
    pub members: Vec<Member>,
    pub solid: bool,
    pub volumes: Vec<PathBuf>,
}

/// Reader options.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub password: Option<String>,
}

/// Receives extracted member data.
pub trait Sink {
    /// Member `index` (into the listing) begins; return `false` to skip it.
    fn start(&mut self, index: usize, member: &Member) -> Result<bool>;
    /// A chunk of the current member's data.
    fn data(&mut self, data: &[u8]) -> Result<()>;
    /// The current member is complete and verified.
    fn finish(&mut self) -> Result<()>;
}

/// Errors front ends react to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    PasswordRequired,
    WrongPassword,
    Unsupported(String),
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::PasswordRequired => f.write_str(nz_front::tr("암호가 필요합니다")),
            FormatError::WrongPassword => f.write_str(nz_front::tr("암호가 틀렸습니다")),
            FormatError::Unsupported(w) => {
                f.write_str(&nz_front::trf("지원하지 않는 기능: {}", &[w]))
            }
        }
    }
}

impl std::error::Error for FormatError {}

/// Recognise a format from the file's first bytes, its size and its name.
pub fn detect(path: &Path) -> Option<Format> {
    let mut head = Vec::with_capacity(limits::SNIFF);
    std::fs::File::open(path)
        .ok()?
        .take(limits::SNIFF as u64)
        .read_to_end(&mut head)
        .ok()?;
    if let Some(f) = stream::sniff(path, &head) {
        return Some(f);
    }
    if rpm::sniff(&head) {
        return Some(Format::Rpm);
    }
    if ar::sniff(&head) {
        let deb = head.get(8..21) == Some(b"debian-binary".as_slice());
        return Some(if deb { Format::Deb } else { Format::Ar });
    }
    if cpio::sniff(&head) {
        return Some(Format::Cpio);
    }
    if xar::sniff(&head) {
        return Some(Format::Xar);
    }
    if msi::sniff(&head) {
        return Some(Format::Msi);
    }
    if asar::sniff(&head) {
        return Some(Format::Asar);
    }
    if let Ok(src) = util::Src::open(path) {
        if let Some(f) = vdisk::sniff(&src, &head) {
            return Some(f);
        }
        if iso::sniff(&src) {
            return Some(Format::Iso);
        }
    }
    if let Some(f) = legacy::detect(path, &head) {
        return Some(f);
    }
    uu::sniff(&head)
}

/// List the members of `path`.
pub fn list(format: Format, path: &Path, opt: &Options) -> Result<Listing> {
    guard(|| list_inner(format, path, opt))
}

/// Run a reader, turning a panic in it (or in a third-party decoder under
/// it) into an error: damaged input must never take the caller down. The
/// isolated worker adds its own process boundary on top of this.
fn guard<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(p) => {
            let msg = p
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| p.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            Err(anyhow::anyhow!("damaged archive (decoder fault: {msg})"))
        }
    }
}

fn list_inner(format: Format, path: &Path, opt: &Options) -> Result<Listing> {
    match format {
        f if stream::codec(f).is_some() => stream::list(f, path, opt),
        Format::Cpio => {
            let mut l = cpio::list(&mut std::io::BufReader::new(std::fs::File::open(path)?))?;
            l.volumes = vec![path.to_path_buf()];
            Ok(l)
        }
        Format::Ar | Format::Deb => ar::list(path, opt),
        Format::Rpm => rpm::list(path, opt),
        Format::Asar => asar::list(path, opt),
        Format::Xar => xar::list(path, opt),
        Format::Msi => msi::list(path, opt),
        Format::Iso => iso::list(path, opt),
        Format::Vhd | Format::Vhdx | Format::Vmdk | Format::Qcow2 => vdisk::list(format, path, opt),
        Format::Uue | Format::Xxe => uu::list(format, path, opt),
        _ => legacy::list(format, path, opt),
    }
}

/// Extract members of `path` into `sink`.
pub fn extract(format: Format, path: &Path, opt: &Options, sink: &mut dyn Sink) -> Result<()> {
    guard(|| extract_inner(format, path, opt, sink))
}

fn extract_inner(format: Format, path: &Path, opt: &Options, sink: &mut dyn Sink) -> Result<()> {
    match format {
        f if stream::codec(f).is_some() => stream::extract(f, path, opt, sink),
        Format::Cpio => cpio::extract(
            &mut std::io::BufReader::new(std::fs::File::open(path)?),
            sink,
        ),
        Format::Ar | Format::Deb => ar::extract(path, opt, sink),
        Format::Rpm => rpm::extract(path, opt, sink),
        Format::Asar => asar::extract(path, opt, sink),
        Format::Xar => xar::extract(path, opt, sink),
        Format::Msi => msi::extract(path, opt, sink),
        Format::Iso => iso::extract(path, opt, sink),
        Format::Vhd | Format::Vhdx | Format::Vmdk | Format::Qcow2 => {
            vdisk::extract(format, path, opt, sink)
        }
        Format::Uue | Format::Xxe => uu::extract(format, path, opt, sink),
        _ => legacy::extract(format, path, opt, sink),
    }
}

/// Seconds since the Unix epoch for a local DOS date/time, treated as UTC.
pub(crate) fn dos_to_unix(year: i64, month: i64, day: i64, h: i64, mi: i64, s: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || h > 23 || mi > 59 || s > 61 {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + h * 3600 + mi * 60 + s)
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
pub(crate) fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A sink that collects members in memory (tests and tools).
#[derive(Debug, Default)]
pub struct VecSink {
    /// `(member name, data)` per extracted file, in order.
    pub files: Vec<(String, Vec<u8>)>,
    cur: Option<(String, Vec<u8>)>,
}

impl Sink for VecSink {
    fn start(&mut self, _index: usize, member: &Member) -> Result<bool> {
        self.cur = Some((member.name.clone(), Vec::new()));
        Ok(true)
    }
    fn data(&mut self, data: &[u8]) -> Result<()> {
        if let Some((_, v)) = &mut self.cur {
            v.extend_from_slice(data);
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        if let Some(c) = self.cur.take() {
            self.files.push(c);
        }
        Ok(())
    }
}
