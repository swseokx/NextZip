//! tar family: tar, tar.gz, tar.xz, tar.bz2, tar.lz4 (and the tar layer of
//! tar.zst).
//!
//! # tar layer
//! POSIX ustar headers. A PAX extended header (`x`) is added when a name or
//! link target does not fit ustar (longer than 100 bytes, or 255 with the
//! prefix field) or is not ASCII: PAX `path=` is UTF-8 by definition, so
//! Korean names survive readers that would decode raw ustar bytes in the
//! local code page (libarchive / Windows `tar.exe`). Empty directories and
//! symbolic links are stored. Headers carry only mode, size and mtime
//! (uid/gid 0, no user names), so the archive depends only on the input.
//!
//! # compression layer
//! * gzip, bzip2, lz4: the tar stream is cut into fixed-size chunks that are
//!   compressed in parallel on the Rayon pool, batch after batch, while the
//!   calling thread keeps reading files (double buffering).
//!   - gzip: one member; chunks are spliced pigz-style ([`crate::deflate`]).
//!   - bzip2: one bzip2 stream per chunk (pbzip2-style multi-stream).
//!   - lz4: one frame of independent blocks, one block per chunk.
//! * xz: liblzma's multithreaded encoder with a block size fixed from the
//!   input size (`total / PLAN_SPLIT`, clamped), so the output does not depend
//!   on the thread count.
//! * zstd: [`crate::tarzst`] (zstd MT plus the planner's fast frame).
//!
//! Chunk boundaries depend only on the chunk size, never on the thread count
//! or batch size, so every format is deterministic.
//!
//! # extraction
//! The format is sniffed from the first bytes. Decoding runs on its own
//! thread (read-ahead pipe), and small files are written by Rayon workers
//! while the next members are decoded; links are created last.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use rayon::prelude::*;

use crate::walk::{self, Item, Kind};
use crate::zip::{ExtractStats, WriteStats};

/// Compression applied to the tar stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TarCodec {
    None,
    Gzip,
    Xz,
    Bzip2,
    Lz4,
    Zstd,
}

impl TarCodec {
    /// Detect from the first bytes of a file (`None` = plain tar).
    pub fn sniff(head: &[u8]) -> Option<Self> {
        Some(match head {
            [0x1F, 0x8B, ..] => Self::Gzip,
            [0xFD, b'7', b'z', b'X', b'Z', 0, ..] => Self::Xz,
            [b'B', b'Z', b'h', b'1'..=b'9', ..] => Self::Bzip2,
            [0x04, 0x22, 0x4D, 0x18, ..] => Self::Lz4,
            [0x28, 0xB5, 0x2F, 0xFD, ..] => Self::Zstd,
            _ if is_tar_header(head) => Self::None,
            _ => return None,
        })
    }
}

/// True if `head` starts with a valid tar header (checksum matches).
pub fn is_tar_header(head: &[u8]) -> bool {
    if head.len() < 512 {
        return false;
    }
    let h = &head[..512];
    let Some(stored) = parse_octal(&h[148..156]) else {
        return false;
    };
    let sum: u64 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                32
            } else {
                b as u64
            }
        })
        .sum();
    sum == stored && h[..100].iter().any(|&b| b != 0)
}

fn parse_octal(f: &[u8]) -> Option<u64> {
    let s: Vec<u8> = f
        .iter()
        .copied()
        .skip_while(|&b| b == b' ')
        .take_while(|&b| (b'0'..=b'7').contains(&b))
        .collect();
    if s.is_empty() {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(&s).ok()?, 8).ok()
}

// ---------------------------------------------------------------------------
// tar headers

const BLOCK: usize = 512;
/// Archives are padded to a whole 10 KiB record like GNU tar and bsdtar do.
const RECORD: u64 = 10240;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderKind {
    File,
    Dir,
    Symlink,
    /// Symlink to a directory: Windows has separate file and directory links.
    DirSymlink,
}

fn put_octal(field: &mut [u8], v: u64) {
    // width-1 zero-padded octal digits + NUL.
    let digits = field.len() - 1;
    let s = format!("{v:0digits$o}");
    debug_assert!(s.len() == digits);
    field[..digits].copy_from_slice(s.as_bytes());
    field[digits] = 0;
}

/// Split `name` into ustar (prefix, name) fields, if it fits as is.
fn ustar_split(name: &str) -> Option<(&str, &str)> {
    if !name.is_ascii() {
        return None;
    }
    if name.len() <= 100 {
        return Some(("", name));
    }
    // Split at a '/' so that prefix <= 155 and rest <= 100 (rest non-empty).
    let bytes = name.as_bytes();
    let lo = name.len().saturating_sub(101);
    (lo..name.len().min(156))
        .find(|&i| bytes[i] == b'/' && name.len() - i - 1 <= 100 && i + 1 < name.len())
        .map(|i| (&name[..i], &name[i + 1..]))
}

/// ASCII stand-in for a name stored in PAX: non-ASCII bytes become `_`,
/// truncated to `max` bytes (readers that understand PAX ignore it).
fn ascii_fallback(name: &str, max: usize) -> String {
    let s: String = name
        .chars()
        .map(|c| if c.is_ascii() && c != '\0' { c } else { '_' })
        .collect();
    if s.len() <= max {
        s
    } else {
        // Keep the tail: it holds the file name.
        s[s.len() - max..].to_string()
    }
}

fn pax_record(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    // "<len> <key>=<value>\n", len counts itself.
    let rest = 3 + key.len() + value.len();
    let mut len = rest + 1;
    while len != rest + len.to_string().len() {
        len = rest + len.to_string().len();
    }
    out.extend_from_slice(format!("{len} {key}=").as_bytes());
    out.extend_from_slice(value);
    out.push(b'\n');
}

fn raw_header(
    name: &str,
    prefix: &str,
    typeflag: u8,
    mode: u32,
    size: u64,
    mtime: u64,
    link: &str,
) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    h[..name.len()].copy_from_slice(name.as_bytes());
    put_octal(&mut h[100..108], mode as u64);
    put_octal(&mut h[108..116], 0);
    put_octal(&mut h[116..124], 0);
    put_octal(&mut h[124..136], size);
    put_octal(&mut h[136..148], mtime);
    h[156] = typeflag;
    h[157..157 + link.len()].copy_from_slice(link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    put_octal(&mut h[329..337], 0);
    put_octal(&mut h[337..345], 0);
    h[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    let s = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(s.as_bytes());
    h
}

/// Largest size/mtime an 11-digit octal field holds.
const OCTAL11_MAX: u64 = (1 << 33) - 1;

/// Header block(s) for one member: an optional PAX `x` header + its data,
/// then the ustar header.
fn member_header(
    name: &str,
    kind: HeaderKind,
    size: u64,
    mtime: u64,
    link: Option<&str>,
) -> Vec<u8> {
    let name = match kind {
        HeaderKind::Dir => format!("{name}/"),
        _ => name.to_string(),
    };
    let mut pax = Vec::new();
    let split = ustar_split(&name);
    if split.is_none() {
        pax_record(&mut pax, "path", name.as_bytes());
    }
    let link = link.unwrap_or("");
    let link_fits = link.is_ascii() && link.len() <= 100;
    if !link_fits {
        pax_record(&mut pax, "linkpath", link.as_bytes());
    }
    if size > OCTAL11_MAX {
        pax_record(&mut pax, "size", size.to_string().as_bytes());
    }
    if kind == HeaderKind::DirSymlink {
        // libarchive (Windows tar.exe) creates a directory link from this
        // even when the target does not exist yet at extraction time.
        pax_record(&mut pax, "LIBARCHIVE.symlinktype", b"dir");
    }
    let mtime = mtime.min(OCTAL11_MAX);
    let mut out = Vec::with_capacity(BLOCK * 3);
    if !pax.is_empty() {
        let pname = ascii_fallback(&format!("PaxHeaders/{name}"), 100);
        let pname = pname.trim_end_matches('/');
        out.extend_from_slice(&raw_header(
            pname,
            "",
            b'x',
            0o644,
            pax.len() as u64,
            mtime,
            "",
        ));
        let padded = pax.len().div_ceil(BLOCK) * BLOCK;
        pax.resize(padded, 0);
        out.extend_from_slice(&pax);
    }
    let (prefix, short) = split.unwrap_or_default();
    let fallback;
    let short = if split.is_none() {
        fallback = ascii_fallback(&name, 100);
        fallback.as_str()
    } else {
        short
    };
    let link_field = if link_fits {
        link.to_string()
    } else {
        ascii_fallback(link, 100)
    };
    let (typeflag, mode) = match kind {
        HeaderKind::File => (b'0', 0o644),
        HeaderKind::Dir => (b'5', 0o755),
        HeaderKind::Symlink | HeaderKind::DirSymlink => (b'2', 0o777),
    };
    let size_field = if kind == HeaderKind::File {
        size.min(OCTAL11_MAX)
    } else {
        0
    };
    out.extend_from_slice(&raw_header(
        short,
        prefix,
        typeflag,
        mode,
        size_field,
        mtime,
        &link_field,
    ));
    out
}

/// True for a symbolic link to a directory (Windows: a directory link).
fn is_dir_link(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileTypeExt;
        std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink_dir())
    }
    #[cfg(not(windows))]
    {
        std::fs::metadata(path).is_ok_and(|m| m.is_dir())
    }
}

fn mtime_secs(t: std::time::SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Small files are read in parallel ahead of the (sequential) tar stream.
const PREFETCH_MAX_FILE: u64 = 1 << 20;
/// Bytes of small files prefetched per window.
const PREFETCH_WINDOW: u64 = 32 << 20;

/// Incremental tar stream writer: members in any number of calls, then
/// [`TarStream::finish`] for the end-of-archive blocks.
#[derive(Debug, Default)]
pub(crate) struct TarStream {
    written: u64,
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
}

impl TarStream {
    /// Append `items` (in the given order).
    pub fn members<W: Write + ?Sized>(&mut self, items: &[&Item], w: &mut W) -> Result<()> {
        let mut i = 0;
        while i < items.len() {
            // Window of items whose small regular files are read in parallel.
            let mut j = i;
            let mut win = 0u64;
            while j < items.len() && win < PREFETCH_WINDOW && j - i < 4096 {
                let e = &items[j].entry;
                if e.kind == Kind::File && items[j].link.is_none() && e.size <= PREFETCH_MAX_FILE {
                    win += e.size;
                }
                j += 1;
            }
            let pre: Vec<Option<Vec<u8>>> = items[i..j]
                .par_iter()
                .map(|it| -> Result<Option<Vec<u8>>> {
                    let e = &it.entry;
                    if e.kind != Kind::File || it.link.is_some() || e.size > PREFETCH_MAX_FILE {
                        return Ok(None);
                    }
                    let data = std::fs::read(&e.path)
                        .with_context(|| format!("cannot read {}", e.path.display()))?;
                    if data.len() as u64 != e.size {
                        bail!("{}: file changed while archiving", e.path.display());
                    }
                    Ok(Some(data))
                })
                .collect::<Result<_>>()?;
            for (it, data) in items[i..j].iter().zip(pre) {
                self.member(it, data, w)?;
            }
            i = j;
        }
        Ok(())
    }

    fn member<W: Write + ?Sized>(
        &mut self,
        it: &Item,
        data: Option<Vec<u8>>,
        w: &mut W,
    ) -> Result<()> {
        let e = &it.entry;
        let mtime = mtime_secs(e.mtime);
        if let Some(target) = &it.link {
            let kind = if is_dir_link(&e.path) {
                HeaderKind::DirSymlink
            } else {
                HeaderKind::Symlink
            };
            let h = member_header(&e.name, kind, 0, mtime, Some(target));
            w.write_all(&h)?;
            self.written += h.len() as u64;
            self.files += 1;
            return Ok(());
        }
        match e.kind {
            Kind::Dir => {
                let h = member_header(&e.name, HeaderKind::Dir, 0, mtime, None);
                w.write_all(&h)?;
                self.written += h.len() as u64;
                self.dirs += 1;
            }
            Kind::File => {
                let h = member_header(&e.name, HeaderKind::File, e.size, mtime, None);
                w.write_all(&h)?;
                self.written += h.len() as u64;
                match data {
                    Some(d) => w.write_all(&d)?,
                    None => {
                        let f = File::open(&e.path)
                            .with_context(|| format!("cannot open {}", e.path.display()))?;
                        let mut r = BufReader::with_capacity(1 << 20, f).take(e.size);
                        let n = io::copy(&mut r, w)?;
                        if n != e.size {
                            bail!("{}: file changed while archiving", e.path.display());
                        }
                    }
                }
                let pad = (BLOCK - (e.size as usize % BLOCK)) % BLOCK;
                w.write_all(&[0u8; BLOCK][..pad])?;
                self.written += e.size + pad as u64;
                self.files += 1;
                self.bytes += e.size;
            }
        }
        Ok(())
    }

    /// End of archive: two zero blocks, then padding to a whole record.
    pub fn finish<W: Write + ?Sized>(&mut self, w: &mut W) -> Result<()> {
        let end = self.written + 2 * BLOCK as u64;
        let total = end.div_ceil(RECORD) * RECORD;
        w.write_all(&vec![0u8; (total - self.written) as usize])?;
        self.written = total;
        Ok(())
    }
}

/// Write a whole tar stream for `items` (in the given order) into `w`.
fn write_tar_stream<W: Write>(items: &[&Item], w: &mut W) -> Result<TarStream> {
    let mut ts = TarStream::default();
    ts.members(items, w)?;
    ts.finish(w)?;
    Ok(ts)
}

// ---------------------------------------------------------------------------
// chunk-parallel compression (gzip, bzip2, lz4)

/// One chunk codec: compresses a chunk independently of the others.
trait ChunkCodec: Send + Sync + 'static {
    /// Bytes written before the first chunk.
    fn header(&self) -> Vec<u8>;
    fn compress(&self, data: &[u8], last: bool) -> io::Result<Vec<u8>>;
    /// Bytes written after the last chunk; `crc`/`len` cover all input.
    fn trailer(&self, crc: u32, xxh: u32, len: u64) -> Vec<u8>;
}

struct GzipCodec {
    level: i32,
}

impl ChunkCodec for GzipCodec {
    fn header(&self) -> Vec<u8> {
        // ID1 ID2 CM=8 FLG=0 MTIME=0 XFL=0 OS=255 (unknown): no time stamp,
        // so the bytes depend only on the input.
        vec![0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 255]
    }
    fn compress(&self, data: &[u8], last: bool) -> io::Result<Vec<u8>> {
        crate::deflate::deflate_chunk(self.level, data, last).map_err(io::Error::other)
    }
    fn trailer(&self, crc: u32, _xxh: u32, len: u64) -> Vec<u8> {
        let mut t = crc.to_le_bytes().to_vec();
        t.extend_from_slice(&(len as u32).to_le_bytes());
        t
    }
}

struct Bzip2Codec {
    level: u32,
}

impl ChunkCodec for Bzip2Codec {
    fn header(&self) -> Vec<u8> {
        Vec::new()
    }
    fn compress(&self, data: &[u8], _last: bool) -> io::Result<Vec<u8>> {
        let mut e = bzip2::write::BzEncoder::new(
            Vec::with_capacity(data.len() / 3),
            bzip2::Compression::new(self.level),
        );
        e.write_all(data)?;
        e.finish()
    }
    fn trailer(&self, _crc: u32, _xxh: u32, _len: u64) -> Vec<u8> {
        Vec::new()
    }
}

/// LZ4 frame block size id 7 = 4 MiB.
const LZ4_BLOCK: usize = 4 << 20;

struct Lz4Codec {
    mode: Option<lz4::block::CompressionMode>,
}

impl ChunkCodec for Lz4Codec {
    fn header(&self) -> Vec<u8> {
        // FLG: version 01, block independence, content checksum.
        let flg = 0b0110_0100u8;
        let bd = 7 << 4; // 4 MiB blocks
        let hc = (xxhash_rust::xxh32::xxh32(&[flg, bd], 0) >> 8) as u8;
        vec![0x04, 0x22, 0x4D, 0x18, flg, bd, hc]
    }
    fn compress(&self, data: &[u8], _last: bool) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(data.len() + 8);
        if data.is_empty() {
            return Ok(out);
        }
        let c = lz4::block::compress(data, self.mode, false)?;
        if c.len() < data.len() {
            out.extend_from_slice(&(c.len() as u32).to_le_bytes());
            out.extend_from_slice(&c);
        } else {
            // Uncompressed block: high bit of the size set.
            out.extend_from_slice(&(data.len() as u32 | 0x8000_0000).to_le_bytes());
            out.extend_from_slice(data);
        }
        Ok(out)
    }
    fn trailer(&self, _crc: u32, xxh: u32, _len: u64) -> Vec<u8> {
        let mut t = 0u32.to_le_bytes().to_vec(); // EndMark
        t.extend_from_slice(&xxh.to_le_bytes());
        t
    }
}

type BatchResult = io::Result<Vec<Vec<u8>>>;

/// `Write` sink that compresses fixed-size chunks in parallel batches.
struct ChunkPipe<W: Write> {
    out: W,
    codec: Arc<dyn ChunkCodec>,
    chunk: usize,
    batch_len: usize,
    cur: Vec<u8>,
    batch: Vec<Vec<u8>>,
    pending: Option<mpsc::Receiver<BatchResult>>,
    crc: crc32fast::Hasher,
    xxh: xxhash_rust::xxh32::Xxh32,
    len: u64,
}

impl<W: Write> ChunkPipe<W> {
    fn new(mut out: W, codec: Arc<dyn ChunkCodec>, chunk: usize) -> io::Result<Self> {
        out.write_all(&codec.header())?;
        let threads = rayon::current_num_threads();
        let batch_len = (2 * threads).clamp(2, ((256usize << 20) / chunk).max(2));
        Ok(Self {
            out,
            codec,
            chunk,
            batch_len,
            cur: Vec::with_capacity(chunk),
            batch: Vec::new(),
            pending: None,
            crc: crc32fast::Hasher::new(),
            xxh: xxhash_rust::xxh32::Xxh32::new(0),
            len: 0,
        })
    }

    /// Write the results of the batch in flight, if any.
    fn drain(&mut self) -> io::Result<()> {
        if let Some(rx) = self.pending.take() {
            for c in wait(&rx)? {
                self.out.write_all(&c)?;
            }
        }
        Ok(())
    }

    /// Hand the full batch to the pool; the previous one is written first,
    /// so at most two batches are in memory.
    fn dispatch(&mut self) -> io::Result<()> {
        self.drain()?;
        let chunks = std::mem::take(&mut self.batch);
        let codec = Arc::clone(&self.codec);
        let (tx, rx) = mpsc::sync_channel(1);
        rayon::spawn(move || {
            let r: BatchResult = chunks
                .par_iter()
                .map(|c| codec.compress(c, false))
                .collect();
            let _ = tx.send(r);
        });
        self.pending = Some(rx);
        Ok(())
    }

    fn finish(mut self) -> io::Result<W> {
        if !self.batch.is_empty() {
            self.dispatch()?;
        }
        self.drain()?;
        // The last (possibly partial or empty) chunk carries the final flag.
        let last = self.codec.compress(&self.cur, true)?;
        self.out.write_all(&last)?;
        let crc = self.crc.clone().finalize();
        let xxh = self.xxh.digest();
        self.out
            .write_all(&self.codec.trailer(crc, xxh, self.len))?;
        self.out.flush()?;
        Ok(self.out)
    }
}

/// Wait for a batch without blocking the pool: with one worker the batch
/// job may be queued behind this very thread, so run pending work meanwhile.
fn wait(rx: &mpsc::Receiver<BatchResult>) -> io::Result<Vec<Vec<u8>>> {
    loop {
        match rx.try_recv() {
            Ok(r) => return r,
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err(io::Error::other("compression worker failed"));
            }
            Err(mpsc::TryRecvError::Empty) => match rayon::yield_now() {
                Some(rayon::Yield::Executed) => {}
                _ => {
                    if let Ok(r) = rx.recv_timeout(Duration::from_millis(1)) {
                        return r;
                    }
                }
            },
        }
    }
}

impl<W: Write> Write for ChunkPipe<W> {
    fn write(&mut self, mut buf: &[u8]) -> io::Result<usize> {
        let n = buf.len();
        self.crc.update(buf);
        self.xxh.update(buf);
        self.len += n as u64;
        while !buf.is_empty() {
            if self.cur.len() == self.chunk {
                // More data follows, so the full chunk is not the last one.
                let full = std::mem::replace(&mut self.cur, Vec::with_capacity(self.chunk));
                self.batch.push(full);
                if self.batch.len() == self.batch_len {
                    self.dispatch()?;
                }
            }
            let take = (self.chunk - self.cur.len()).min(buf.len());
            self.cur.extend_from_slice(&buf[..take]);
            buf = &buf[take..];
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// writer

/// Parameters for [`write_tar`].
#[derive(Debug, Clone)]
pub struct TarOptions {
    pub codec: TarCodec,
    /// NextZip level 0..=9.
    pub level: u8,
    /// Group files by extension (better ratio for solid codecs).
    pub sort_by_ext: bool,
    /// zstd settings for [`TarCodec::Zstd`].
    pub zstd: crate::tarzst::ZstdOptions,
}

impl TarOptions {
    pub fn new(codec: TarCodec, level: u8) -> Self {
        Self {
            codec,
            level,
            sort_by_ext: matches!(codec, TarCodec::Xz | TarCodec::Zstd),
            zstd: crate::tarzst::ZstdOptions {
                level,
                ..Default::default()
            },
        }
    }

    /// Chunk size of the parallel codecs (gzip, bzip2, lz4).
    pub fn chunk(&self) -> usize {
        match self.codec {
            // 1 MiB: the missing 32 KiB dictionary at chunk starts costs
            // well under 0.1 pp at this size.
            TarCodec::Gzip => 1 << 20,
            // Four full 900 kB bzip2 blocks per stream.
            TarCodec::Bzip2 => 4 * 900_000,
            TarCodec::Lz4 => LZ4_BLOCK,
            _ => 0,
        }
    }

    /// libdeflate level for gzip (same map as ZIP).
    pub fn gzip_level(&self) -> i32 {
        crate::zip::ZipOptions {
            level: self.level,
            ..Default::default()
        }
        .deflate_level()
    }

    /// xz preset (0..=9).
    pub fn xz_preset(&self) -> u32 {
        self.level.min(9) as u32
    }

    /// bzip2 block size in 100 kB (1..=9).
    pub fn bzip2_level(&self) -> u32 {
        const MAP: [u32; 10] = [1, 1, 3, 5, 7, 9, 9, 9, 9, 9];
        MAP[self.level.min(9) as usize]
    }

    fn lz4_mode(&self) -> Option<lz4::block::CompressionMode> {
        use lz4::block::CompressionMode::*;
        match self.level {
            0..=3 => Some(DEFAULT),
            4 => Some(HIGHCOMPRESSION(3)),
            5 => Some(HIGHCOMPRESSION(6)),
            6 => Some(HIGHCOMPRESSION(8)),
            7 => Some(HIGHCOMPRESSION(9)),
            8 => Some(HIGHCOMPRESSION(10)),
            _ => Some(HIGHCOMPRESSION(12)),
        }
    }
}

/// xz block size: `total / PLAN_SPLIT`, clamped to [1 MiB, 3 x dictionary].
/// Depends only on the input size and preset.
pub fn xz_block_size(total: u64, preset: u32) -> u64 {
    const DICT: [u64; 10] = [
        256 << 10,
        1 << 20,
        2 << 20,
        4 << 20,
        4 << 20,
        8 << 20,
        8 << 20,
        16 << 20,
        32 << 20,
        64 << 20,
    ];
    let max = 3 * DICT[preset.min(9) as usize];
    (total / crate::sevenz::PLAN_SPLIT).clamp(1 << 20, max.max(1 << 20))
}

/// Ordering of tar members: walk order, or directories first and files
/// grouped by extension (stable, so ties keep walk order).
pub(crate) fn ordered(mut v: Vec<&Item>, by_ext: bool) -> Vec<&Item> {
    if by_ext {
        v.sort_by_key(|it| {
            let e = &it.entry;
            let ext = match (e.kind, &it.link) {
                (Kind::File, None) => e
                    .name
                    .rsplit_once('.')
                    .filter(|(_, x)| !x.contains('/'))
                    .map(|(_, x)| x.to_ascii_lowercase())
                    .unwrap_or_default(),
                _ => String::new(),
            };
            (e.kind == Kind::File, ext)
        });
    }
    // Links last (stable), so their targets exist when extractors that look
    // at the target (directory or file link on Windows) create them.
    v.sort_by_key(|it| it.link.is_some());
    v
}

/// Create a tar-family archive from `items` (see [`walk::collect_items`]).
pub fn write_tar(items: &[Item], out: &Path, opt: &TarOptions) -> Result<WriteStats> {
    if opt.codec == TarCodec::Zstd {
        return crate::tarzst::write_tar_zst_items(items, out, &opt.zstd);
    }
    let file = File::create(out).with_context(|| format!("cannot create {}", out.display()))?;
    let bw = BufWriter::with_capacity(1 << 20, file);
    let order = ordered(items.iter().collect(), opt.sort_by_ext);
    let ts = match opt.codec {
        TarCodec::None => {
            let mut w = bw;
            let r = write_tar_stream(&order, &mut w)?;
            w.flush()?;
            r
        }
        TarCodec::Gzip | TarCodec::Bzip2 | TarCodec::Lz4 => {
            let codec: Arc<dyn ChunkCodec> = match opt.codec {
                TarCodec::Gzip => Arc::new(GzipCodec {
                    level: opt.gzip_level(),
                }),
                TarCodec::Bzip2 => Arc::new(Bzip2Codec {
                    level: opt.bzip2_level(),
                }),
                _ => Arc::new(Lz4Codec {
                    mode: opt.lz4_mode(),
                }),
            };
            let mut w = ChunkPipe::new(bw, codec, opt.chunk())?;
            let r = write_tar_stream(&order, &mut w)?;
            w.finish()?;
            r
        }
        TarCodec::Xz => {
            let total: u64 = items.iter().map(|i| i.entry.size).sum();
            let preset = opt.xz_preset();
            let threads = rayon::current_num_threads().max(1) as u32;
            let stream = liblzma::stream::MtStreamBuilder::new()
                .preset(preset)
                .threads(threads)
                .block_size(xz_block_size(total, preset))
                .check(liblzma::stream::Check::Crc64)
                .encoder()
                .map_err(|e| anyhow!("xz encoder: {e}"))?;
            let mut w = liblzma::write::XzEncoder::new_stream(bw, stream);
            let r = write_tar_stream(&order, &mut w)?;
            w.finish()?.flush()?;
            r
        }
        TarCodec::Zstd => unreachable!(),
    };
    Ok(WriteStats {
        files: ts.files,
        dirs: ts.dirs,
        input_bytes: ts.bytes,
        output_bytes: std::fs::metadata(out)?.len(),
        ..Default::default()
    })
}

// ---------------------------------------------------------------------------
// reader

/// Reader over concatenated LZ4 frames.
struct MultiLz4<R: BufRead> {
    dec: Option<lz4::Decoder<R>>,
}

impl<R: BufRead> Read for MultiLz4<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let Some(dec) = self.dec.as_mut() else {
                return Ok(0);
            };
            let n = dec.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            // End of a frame: lz4's decoder never reads past it, so the
            // inner reader sits at the next frame (if any).
            let (mut r, res) = self.dec.take().expect("decoder").finish();
            res?;
            if r.fill_buf()?.is_empty() {
                return Ok(0);
            }
            self.dec = Some(lz4::Decoder::new(r)?);
        }
    }
}

/// Decompressing reader for an archive file. Single-threaded decoders are
/// wrapped in a [`ReadAhead`] so decoding overlaps extraction; the parallel
/// zstd decoder already decodes on its own threads, and an extra copy stage
/// behind it cost K6 time (2.1 GB member).
fn open_decoder(archive: &Path, threads: usize) -> Result<Box<dyn Read + Send>> {
    let dec = open_decoder_raw(archive, threads)?;
    Ok(if dec.1 {
        dec.0
    } else {
        Box::new(ReadAhead::new(dec.0))
    })
}

/// The decoder for `archive` and whether it decodes on its own threads.
fn open_decoder_raw(archive: &Path, threads: usize) -> Result<(Box<dyn Read + Send>, bool)> {
    let f = File::open(archive).with_context(|| format!("cannot open {}", archive.display()))?;
    let mut r = BufReader::with_capacity(1 << 20, f);
    let head = r.fill_buf()?.to_vec();
    let codec = TarCodec::sniff(&head)
        .with_context(|| format!("{}: not a tar archive", archive.display()))?;
    Ok(match codec {
        TarCodec::None => (Box::new(r), false),
        TarCodec::Gzip => (Box::new(flate2::bufread::MultiGzDecoder::new(r)), false),
        TarCodec::Bzip2 => (Box::new(bzip2::bufread::MultiBzDecoder::new(r)), false),
        TarCodec::Lz4 => (
            Box::new(MultiLz4 {
                dec: Some(lz4::Decoder::new(r)?),
            }),
            false,
        ),
        TarCodec::Zstd => {
            // Frames are decoded in parallel (K6); memory: in-flight frames
            // of up to FRAME_BYTES each within half the budget.
            drop(r);
            let f = File::open(archive)?;
            let per = crate::tarzst::FRAME_BYTES * 3 / 2;
            let inflight = (crate::mem::default_budget() / 2 / per).clamp(1, threads.max(1) as u64);
            (
                Box::new(crate::parzst::ParZstd::new(f, threads, inflight as usize)),
                true,
            )
        }
        TarCodec::Xz => {
            let stream = liblzma::stream::MtStreamBuilder::new()
                .threads(threads.clamp(1, 64) as u32)
                .memlimit_threading(1 << 30)
                .memlimit_stop(u64::MAX)
                .decoder()
                .map_err(|e| anyhow!("xz decoder: {e}"))?;
            (
                Box::new(liblzma::bufread::XzDecoder::new_stream(r, stream)),
                false,
            )
        }
    })
}

/// Read-ahead pipe: `src` is decoded on its own thread in 1 MiB pieces.
struct ReadAhead {
    rx: mpsc::Receiver<io::Result<Vec<u8>>>,
    /// Spent buffers go back to the reading thread (fresh 1 MiB buffers
    /// fault their pages in again for every piece).
    back: mpsc::Sender<Vec<u8>>,
    cur: Vec<u8>,
    pos: usize,
    done: bool,
}

impl ReadAhead {
    fn new(mut src: Box<dyn Read + Send>) -> Self {
        let (tx, rx) = mpsc::sync_channel::<io::Result<Vec<u8>>>(16);
        let (back, spent) = mpsc::channel::<Vec<u8>>();
        std::thread::spawn(move || {
            loop {
                let mut buf = spent.try_recv().unwrap_or_default();
                buf.resize(1 << 20, 0);
                let mut n = 0;
                let r = loop {
                    match src.read(&mut buf[n..]) {
                        Ok(0) => break Ok(()),
                        Ok(k) => {
                            n += k;
                            if n == buf.len() {
                                break Ok(());
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => break Err(e),
                    }
                };
                if let Err(e) = r {
                    let _ = tx.send(Err(e));
                    return;
                }
                if n == 0 {
                    return; // EOF: dropping tx ends the stream
                }
                buf.truncate(n);
                if tx.send(Ok(buf)).is_err() {
                    return;
                }
            }
        });
        Self {
            rx,
            back,
            cur: Vec::new(),
            pos: 0,
            done: false,
        }
    }
}

impl Read for ReadAhead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.pos == self.cur.len() {
            if self.done {
                return Ok(0);
            }
            match self.rx.recv() {
                Ok(Ok(b)) => {
                    let old = std::mem::replace(&mut self.cur, b);
                    self.pos = 0;
                    if old.capacity() > 0 {
                        let _ = self.back.send(old);
                    }
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    self.done = true;
                    return Ok(0);
                }
            }
        }
        let n = buf.len().min(self.cur.len() - self.pos);
        buf[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Files up to this size are handed to a worker thread to write.
const ASYNC_WRITE_MAX: u64 = 8 << 20;
/// Bytes of pending asynchronous writes before the reader waits.
const ASYNC_WRITE_LIMIT: u64 = 256 << 20;
/// Piece size for the parallel positional writes of large members.
const PIECE: u64 = 8 << 20;

/// Window of a large member mapped at a time (a multiple of
/// [`nz_sys::VIEW_ALIGN`]). At most two windows are mapped at once (one
/// filling, one being unmapped), which bounds the file pages counted in the
/// process working set (K9).
const MAP_WINDOW: u64 = 128 << 20;

/// Write a large member of `size` bytes read from `src` to a new file at
/// `dest`: through a file mapping filled by the Rayon pool when the system
/// supports it, else with a sequential writer thread.
fn write_large<R: Read>(src: &mut R, dest: &Path, size: u64) -> Result<File> {
    let out = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(dest)
        .with_context(|| format!("cannot create {}", dest.display()))?;
    if nz_sys::MAPPING_SUPPORTED {
        match nz_sys::FileMapping::new(&out, size) {
            Ok(map) => {
                write_mapped(src, &map, size, MAP_WINDOW, dest)?;
                return Ok(out);
            }
            Err(e) => crate::trace(&format!(
                "{}: mapping failed ({e}), writing sequentially",
                dest.display()
            )),
        }
    }
    write_streamed(src, out, size, dest)
}

/// K6 (2.1 GB member): one writer thread spent ~96% of the run in
/// `WriteFile`. Here the file is mapped window by window; each window is
/// filled by [`fill_prefault`] and unmapped on a helper thread (~10 ms per
/// 128 MiB window) while the next one fills.
fn write_mapped<R: Read>(
    src: &mut R,
    map: &nz_sys::FileMapping,
    size: u64,
    window: u64,
    dest: &Path,
) -> Result<()> {
    let t0 = std::time::Instant::now();
    let mut off = 0u64;
    let join = |h: std::thread::JoinHandle<io::Result<()>>| -> Result<()> {
        h.join()
            .map_err(|_| anyhow!("unmap thread panicked"))?
            .with_context(|| format!("cannot write {}", dest.display()))
    };
    let mut unmapping: Option<std::thread::JoinHandle<io::Result<()>>> = None;
    while off < size {
        let wlen = (size - off).min(window) as usize;
        let mut view = map
            .view(off, wlen)
            .with_context(|| format!("cannot map {}", dest.display()))?;
        fill_prefault(src, view.as_mut_slice(), dest)?;
        if let Some(h) = unmapping.take() {
            join(h)?;
        }
        unmapping = Some(std::thread::spawn(move || view.finish()));
        off += wlen as u64;
    }
    if let Some(h) = unmapping {
        join(h)?;
    }
    crate::trace(&format!(
        "mapped write {} bytes {:.0} ms",
        size,
        t0.elapsed().as_secs_f64() * 1e3
    ));
    Ok(())
}

/// Fill `win` from `src`: the pool touches each page of a piece (zero-fill
/// fault) while this thread reads earlier pieces straight into the mapping,
/// so the data is copied once, by this thread, into resident pages.
fn fill_prefault<R: Read>(src: &mut R, win: &mut [u8], dest: &Path) -> Result<()> {
    rayon::in_place_scope(|s| -> Result<()> {
        let (tx, rx) = mpsc::channel::<(usize, &mut [u8])>();
        for (i, piece) in win.chunks_mut(PIECE as usize).enumerate() {
            let tx = tx.clone();
            s.spawn(move |_| {
                for page in piece.chunks_mut(4096) {
                    page[0] = 0;
                }
                let _ = tx.send((i, piece));
            });
        }
        drop(tx);
        let mut ready = std::collections::BTreeMap::new();
        let mut next = 0usize;
        loop {
            let piece = loop {
                if let Some(p) = ready.remove(&next) {
                    break Some(p);
                }
                match rx.try_recv() {
                    Ok((i, p)) => {
                        ready.insert(i, p);
                    }
                    Err(mpsc::TryRecvError::Disconnected) => break None,
                    Err(mpsc::TryRecvError::Empty) => {
                        if rayon::yield_now() != Some(rayon::Yield::Executed) {
                            std::thread::sleep(Duration::from_micros(20));
                        }
                    }
                }
            };
            let Some(piece) = piece else {
                return Ok(());
            };
            src.read_exact(piece).map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    anyhow!("{}: tar member truncated", dest.display())
                } else {
                    e.into()
                }
            })?;
            next += 1;
        }
    })
}

/// Large member without a mapping: a writer thread writes PIECE-byte buffers
/// in order while this thread reads the stream on. Writes stay sequential:
/// out-of-order writes past NTFS's valid data length make it zero-fill the
/// gap first (measured slower).
fn write_streamed<R: Read>(src: &mut R, out: File, size: u64, dest: &Path) -> Result<File> {
    out.set_len(size)?;
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(4);
    let (back_tx, back_rx) = mpsc::channel::<Vec<u8>>();
    let writer = std::thread::spawn(move || -> io::Result<File> {
        let mut out = out;
        for buf in rx {
            out.write_all(&buf)?;
            let _ = back_tx.send(buf);
        }
        Ok(out)
    });
    let mut off = 0u64;
    let mut failed = false;
    while off < size {
        let want = (size - off).min(PIECE);
        let mut buf = back_rx.try_recv().unwrap_or_default();
        buf.clear();
        (&mut *src).take(want).read_to_end(&mut buf)?;
        if (buf.len() as u64) < want {
            bail!("{}: tar member truncated", dest.display());
        }
        if tx.send(buf).is_err() {
            failed = true;
            break;
        }
        off += want;
    }
    drop(tx);
    let out = writer
        .join()
        .map_err(|_| anyhow!("writer thread panicked"))?
        .with_context(|| format!("cannot write {}", dest.display()))?;
    if failed {
        bail!("cannot write {}", dest.display());
    }
    Ok(out)
}

/// Set a file's modification time to `secs` after the Unix epoch. Values the
/// platform cannot represent (a corrupt or negative header time read as a huge
/// unsigned number) are skipped instead of overflowing `SystemTime`.
fn set_mtime(f: &File, secs: u64) {
    if let Some(t) = file_time(secs) {
        let _ = f.set_modified(t);
    }
}

/// `UNIX_EPOCH + secs`, or None when it does not fit (Windows FILETIME ends in
/// the year 30828; anything later is not a real timestamp).
fn file_time(secs: u64) -> Option<std::time::SystemTime> {
    const MAX_SECS: u64 = 910_692_730_085; // 30828-09-14, FILETIME limit
    if secs > MAX_SECS {
        return None;
    }
    UNIX_EPOCH.checked_add(Duration::from_secs(secs))
}

fn write_file(dest: &Path, data: &[u8], mtime: Option<u64>) -> Result<()> {
    let out = File::create(dest).with_context(|| format!("cannot create {}", dest.display()))?;
    if data.len() > 64 * 1024 {
        out.set_len(data.len() as u64)?;
    }
    (&out).write_all(data)?;
    if let Some(t) = mtime {
        set_mtime(&out, t);
    }
    Ok(())
}

/// Member name as text: UTF-8 (PAX names always are), else the system ANSI
/// code page (some Windows archivers write CP949 on Korean Windows), else lossy UTF-8.
fn name_of(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_string(),
        Err(_) => nz_sys::decode_ansi(bytes)
            .unwrap_or_else(|| String::from_utf8_lossy(bytes).into_owned()),
    }
}

fn ensure_dir(d: &Path, made: &mut HashSet<PathBuf>) -> Result<()> {
    if !made.contains(d) {
        std::fs::create_dir_all(d).with_context(|| format!("cannot create {}", d.display()))?;
        made.insert(d.to_path_buf());
    }
    Ok(())
}

/// A link to create after all regular files exist.
struct PendingLink {
    rel: PathBuf,
    target: String,
    hard: bool,
}

/// True if `out_dir/rel` or a folder on the way to it is a symbolic link.
/// Lexical `..` handling is only sound on real folders: a path through a
/// link (`p/q/up -> ..`, then `p/q/up/../..`) can leave the output folder
/// (M5 security review).
fn through_link(out_dir: &Path, rel: &Path) -> bool {
    let mut p = out_dir.to_path_buf();
    rel.iter().any(|c| {
        p.push(c);
        std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink())
    })
}

/// Normalise `base/target` (both relative, `/` or `\` separated) and
/// return it if it stays inside the output directory without passing
/// through a symbolic link already extracted there.
fn resolve_inside(out_dir: &Path, base: &Path, target: &str) -> Option<PathBuf> {
    if target.starts_with('/') || target.starts_with('\\') || target.contains(':') {
        return None;
    }
    let mut parts: Vec<std::ffi::OsString> =
        base.iter().map(|p| p.to_os_string()).collect::<Vec<_>>();
    for p in target.split(['/', '\\']) {
        // Windows trims trailing dots and spaces (`.. ` is `..`).
        if p != ".." && p.contains("..") && p.chars().all(|c| c == '.' || c == ' ') {
            return None;
        }
        match p {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            x => {
                parts.push(x.into());
                let so_far: PathBuf = parts.iter().collect();
                if through_link(out_dir, &so_far) {
                    return None;
                }
            }
        }
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.iter().collect())
}

fn make_link(out_dir: &Path, l: &PendingLink, symlinks: bool) -> Result<bool> {
    let dest = out_dir.join(&l.rel);
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p)?;
    }
    if l.hard {
        // Hard link targets are archive paths.
        let src = walk::safe_relative(&l.target)
            .with_context(|| format!("unsafe link target {}", l.target))?;
        let src = out_dir.join(src);
        let _ = std::fs::remove_file(&dest);
        if std::fs::hard_link(&src, &dest).is_err() {
            std::fs::copy(&src, &dest)
                .with_context(|| format!("cannot link {} -> {}", dest.display(), l.target))?;
        }
        return Ok(true);
    }
    // Symbolic link: the target is relative to the link's directory and must
    // stay inside the output directory. A link is never created inside a
    // folder that is itself a link (its real location would differ from
    // the one checked).
    let base = l.rel.parent().unwrap_or(Path::new(""));
    let inside = if through_link(out_dir, base) {
        None
    } else {
        resolve_inside(out_dir, base, &l.target)
    };
    let Some(inside) = inside else {
        eprintln!(
            "nz: warning: skipped symbolic link {} -> {} (points outside the archive)",
            l.rel.display(),
            l.target
        );
        return Ok(false);
    };
    let resolved = out_dir.join(&inside);
    let _ = std::fs::remove_file(&dest);
    if !symlinks {
        // Spec 9 default: the link as a regular file holding its target.
        std::fs::write(&dest, l.target.as_bytes())
            .with_context(|| format!("cannot create {}", dest.display()))?;
        return Ok(true);
    }
    let target_os = l.target.replace(['/', '\\'], std::path::MAIN_SEPARATOR_STR);
    if symlink(&target_os, &dest, resolved.is_dir()).is_ok() {
        return Ok(true);
    }
    // No symlink privilege (Windows without Developer Mode): keep the data
    // by copying a file target.
    if resolved.is_file() {
        std::fs::copy(&resolved, &dest)?;
        eprintln!(
            "nz: warning: cannot create symbolic link {}; copied its target instead",
            l.rel.display()
        );
        return Ok(true);
    }
    eprintln!(
        "nz: warning: cannot create symbolic link {} -> {}",
        l.rel.display(),
        l.target
    );
    Ok(false)
}

#[cfg(windows)]
fn symlink(target: &str, link: &Path, dir: bool) -> io::Result<()> {
    if dir {
        std::os::windows::fs::symlink_dir(target, link)
    } else {
        std::os::windows::fs::symlink_file(target, link)
    }
}

#[cfg(unix)]
fn symlink(target: &str, link: &Path, _dir: bool) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(any(windows, unix)))]
fn symlink(_target: &str, _link: &Path, _dir: bool) -> io::Result<()> {
    Err(io::Error::other("symbolic links are not supported"))
}

/// Extract any tar-family archive (format detected from content).
pub fn extract_tar(archive: &Path, out_dir: &Path) -> Result<ExtractStats> {
    let opt = crate::ExtractOptions {
        symlinks: true,
        ..Default::default()
    };
    extract_tar_with(archive, out_dir, &opt)
}

/// [`extract_tar`] with limits (see [`crate::ExtractOptions`]).
pub fn extract_tar_with(
    archive: &Path,
    out_dir: &Path,
    opt: &crate::ExtractOptions<'_>,
) -> Result<ExtractStats> {
    let threads = rayon::current_num_threads();
    let src = open_decoder(archive, threads)?;
    extract_tar_stream(src, out_dir, opt)
}

/// Extract a decoded tar stream.
pub(crate) fn extract_tar_stream(
    src: Box<dyn Read + Send>,
    out_dir: &Path,
    opt: &crate::ExtractOptions<'_>,
) -> Result<ExtractStats> {
    let max_total = opt.max_total.unwrap_or(u64::MAX);
    let max_entries = opt.max_entries.unwrap_or(u64::MAX);
    let mut total = 0u64;
    let mut entries = 0u64;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    std::fs::create_dir_all(out_dir)?;
    let mut ar = tar::Archive::new(crate::tarfix::TarFix::new(src));
    let mut stats = ExtractStats::default();
    let mut made: HashSet<PathBuf> = HashSet::new();
    let mut dir_times: Vec<(PathBuf, u64)> = Vec::new();
    let mut links: Vec<PendingLink> = Vec::new();
    let inflight = AtomicU64::new(0);
    let err: Mutex<Option<anyhow::Error>> = Mutex::new(None);
    let written = AtomicU64::new(0);
    let async_files = AtomicU64::new(0);
    let mut long_name: Option<Vec<u8>> = None;
    let mut long_link: Option<Vec<u8>> = None;

    rayon::scope(|s| -> Result<()> {
        for item in ar.entries()? {
            if err.lock().expect("lock").is_some() {
                break;
            }
            let mut item = item?;
            let kind = item.header().entry_type();
            if matches!(
                kind,
                tar::EntryType::XGlobalHeader | tar::EntryType::XHeader
            ) {
                continue;
            }
            if matches!(
                kind,
                tar::EntryType::GNULongName | tar::EntryType::GNULongLink
            ) {
                // GNU long name / link headers the tar crate did not apply
                // itself: some archivers write them without the GNU magic.
                let mut v = Vec::new();
                item.read_to_end(&mut v)?;
                while v.last() == Some(&0) {
                    v.pop();
                }
                if kind == tar::EntryType::GNULongName {
                    long_name = Some(v);
                } else {
                    long_link = Some(v);
                }
                continue;
            }
            let name = match long_name.take() {
                Some(v) => name_of(&v),
                None => name_of(&item.path_bytes()),
            };
            let long_target = long_link.take();
            // `./` (the archive root, common in `tar -C dir .` archives).
            if kind == tar::EntryType::Directory
                && name.split(['/', '\\']).all(|p| p.is_empty() || p == ".")
            {
                continue;
            }
            let rel = walk::safe_relative(&name).with_context(|| format!("unsafe path {name}"))?;
            entries += 1;
            if entries > max_entries {
                return Err(crate::LimitExceeded::Entries.into());
            }
            if let Some(f) = opt.on_name {
                f(&name, &rel);
            }
            let dest = out_dir.join(&rel);
            let mtime = item.header().mtime().ok();
            match kind {
                tar::EntryType::Directory => {
                    ensure_dir(&dest, &mut made)?;
                    if let Some(t) = mtime {
                        dir_times.push((dest, t));
                    }
                    stats.dirs += 1;
                }
                tar::EntryType::Regular
                | tar::EntryType::Continuous
                | tar::EntryType::GNUSparse => {
                    if let Some(parent) = dest.parent() {
                        ensure_dir(parent, &mut made)?;
                    }
                    let size = item.size();
                    total = total.saturating_add(size);
                    if total > max_total {
                        return Err(crate::LimitExceeded::Total.into());
                    }
                    if size <= ASYNC_WRITE_MAX {
                        let mut data = Vec::with_capacity(size as usize);
                        item.read_to_end(&mut data)?;
                        let n = data.len() as u64;
                        inflight.fetch_add(n, Ordering::Relaxed);
                        let (inflight, err, written, async_files) =
                            (&inflight, &err, &written, &async_files);
                        s.spawn(move |_| {
                            if let Err(e) = write_file(&dest, &data, mtime) {
                                err.lock().expect("lock").get_or_insert(e);
                            }
                            written.fetch_add(n, Ordering::Relaxed);
                            async_files.fetch_add(1, Ordering::Relaxed);
                            inflight.fetch_sub(n, Ordering::Relaxed);
                        });
                        while inflight.load(Ordering::Relaxed) > ASYNC_WRITE_LIMIT {
                            if rayon::yield_now() != Some(rayon::Yield::Executed) {
                                std::thread::sleep(Duration::from_micros(200));
                            }
                        }
                    } else {
                        let out = write_large(&mut item, &dest, size)?;
                        if let Some(t) = mtime {
                            set_mtime(&out, t);
                        }
                        stats.bytes += size;
                        stats.files += 1;
                    }
                }
                tar::EntryType::Symlink | tar::EntryType::Link => {
                    let target = long_target
                        .map(|v| name_of(&v))
                        .or_else(|| item.link_name_bytes().map(|b| name_of(&b)))
                        .with_context(|| format!("{name}: link without target"))?;
                    links.push(PendingLink {
                        rel,
                        target,
                        hard: kind == tar::EntryType::Link,
                    });
                }
                _ => {
                    crate::trace(&format!("skipped special member {name} ({kind:?})"));
                }
            }
        }
        Ok(())
    })?;
    if let Some(e) = err.into_inner().expect("lock") {
        return Err(e);
    }
    stats.bytes += written.into_inner();
    stats.files += async_files.into_inner() as usize;
    for l in &links {
        if make_link(out_dir, l, opt.symlinks)? {
            stats.files += 1;
        }
    }
    // Directory mtimes last (children bump them), deepest first.
    for (d, t) in dir_times.iter().rev() {
        if let Ok(f) = File::open(d) {
            set_mtime(&f, *t);
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(name: &str, kind: Kind, path: PathBuf, size: u64, link: Option<&str>) -> Item {
        Item {
            entry: walk::Entry {
                name: name.into(),
                path,
                kind,
                size,
                mtime: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            },
            link: link.map(Into::into),
        }
    }

    #[test]
    fn ustar_split_rules() {
        assert_eq!(ustar_split("a/b.txt"), Some(("", "a/b.txt")));
        let long = format!("{}/{}", "d".repeat(120), "f".repeat(90));
        let (p, n) = ustar_split(&long).unwrap();
        assert_eq!((p.len(), n.len()), (120, 90));
        assert!(ustar_split(&"x".repeat(101)).is_none());
        assert!(ustar_split("\u{d55c}.txt").is_none());
        assert!(ustar_split(&format!("{}/{}", "d".repeat(200), "f".repeat(10))).is_none());
    }

    #[test]
    fn pax_record_length_counts_itself() {
        for len in [1usize, 5, 80, 95, 96, 97, 990, 994, 995, 1000] {
            let mut v = Vec::new();
            pax_record(&mut v, "path", &vec![b'a'; len]);
            let (n, _) = std::str::from_utf8(&v).unwrap().split_once(' ').unwrap();
            assert_eq!(n.parse::<usize>().unwrap(), v.len(), "len {len}");
        }
    }

    #[test]
    fn headers_are_valid_ustar() {
        let h = member_header("dir", HeaderKind::Dir, 0, 1, None);
        assert_eq!(h.len(), 512);
        assert!(is_tar_header(&h));
        assert_eq!(&h[..4], b"dir/");
        let h = member_header("\u{d55c}\u{ae00}.txt", HeaderKind::File, 3, 1, None);
        assert_eq!(h.len(), 3 * 512); // pax header + data block + ustar
        assert_eq!(h[156], b'x');
        assert!(is_tar_header(&h[1024..]));
    }

    /// Round trip through every codec with PAX names, an empty directory and
    /// links, read back with the `tar` crate and with our extractor.
    #[test]
    fn roundtrip_all_codecs() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(src.join("empty")).unwrap();
        let long_dir = "d".repeat(150);
        let long_name = format!("{long_dir}/{}.txt", "n".repeat(120));
        std::fs::create_dir_all(src.join(&long_dir)).unwrap();
        let text: Vec<u8> = (0..300_000u32)
            .flat_map(|i| format!("{i} \u{d55c}\u{ae00}\n").into_bytes())
            .collect();
        std::fs::write(src.join(&long_name), &text).unwrap();
        std::fs::write(src.join("\u{d30c}\u{c77c}.txt"), b"hangul").unwrap();
        let items = vec![
            item("empty", Kind::Dir, src.join("empty"), 0, None),
            item(&long_dir, Kind::Dir, src.join(&long_dir), 0, None),
            item(
                &long_name,
                Kind::File,
                src.join(&long_name),
                text.len() as u64,
                None,
            ),
            item(
                "\u{d30c}\u{c77c}.txt",
                Kind::File,
                src.join("\u{d30c}\u{c77c}.txt"),
                6,
                None,
            ),
            item(
                "link.txt",
                Kind::File,
                src.join("x"),
                0,
                Some("\u{d30c}\u{c77c}.txt"),
            ),
            item("evil", Kind::File, src.join("x"), 0, Some("../../outside")),
        ];
        for codec in [
            TarCodec::None,
            TarCodec::Gzip,
            TarCodec::Xz,
            TarCodec::Bzip2,
            TarCodec::Lz4,
            TarCodec::Zstd,
        ] {
            for threads in [1, 4] {
                let arc = tmp.path().join(format!("a{codec:?}{threads}"));
                let pool = crate::cpu::pool(threads).unwrap();
                pool.install(|| write_tar(&items, &arc, &TarOptions::new(codec, 5)))
                    .unwrap();
                let head = std::fs::read(&arc).unwrap();
                assert_eq!(TarCodec::sniff(&head), Some(codec));
                // tar crate sees PAX names and the link.
                let dec = open_decoder(&arc, 2).unwrap();
                let mut ar = tar::Archive::new(dec);
                let names: Vec<(String, Option<String>)> = ar
                    .entries()
                    .unwrap()
                    .map(|e| {
                        let e = e.unwrap();
                        (
                            name_of(&e.path_bytes()),
                            e.link_name_bytes().map(|b| name_of(&b)),
                        )
                    })
                    .collect();
                assert!(names.contains(&(long_name.clone(), None)), "{codec:?}");
                assert!(names.contains(&("link.txt".into(), Some("\u{d30c}\u{c77c}.txt".into()))));
                let out = tmp.path().join(format!("x{codec:?}{threads}"));
                pool.install(|| extract_tar(&arc, &out)).unwrap();
                assert_eq!(std::fs::read(out.join(&long_name)).unwrap(), text);
                assert!(out.join("empty").is_dir());
                // Either a real link or (no privilege) a copy of the target.
                assert_eq!(std::fs::read(out.join("link.txt")).unwrap(), b"hangul");
                assert!(!out.join("evil").exists());
                assert!(!tmp.path().join("outside").exists());
            }
            // Same bytes for 1 and 4 threads.
            let a = std::fs::read(tmp.path().join(format!("a{codec:?}1"))).unwrap();
            let b = std::fs::read(tmp.path().join(format!("a{codec:?}4"))).unwrap();
            assert!(a == b, "{codec:?} depends on thread count");
        }
    }

    fn noisy(n: usize) -> Vec<u8> {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        (0..n)
            .map(|i| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                if i % 3 == 0 { b'a' } else { x as u8 }
            })
            .collect()
    }

    /// Large members go through the mapped writer: several windows, the last
    /// one partial, and a source that ends early is an error.
    #[test]
    fn mapped_large_member_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let data = noisy(11 * 1024 * 1024 + 4321);
        let p = tmp.path().join("big.bin");
        let pool = crate::cpu::pool(3).unwrap();
        pool.install(|| {
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&p)
                .unwrap();
            if !nz_sys::MAPPING_SUPPORTED {
                return;
            }
            let map = nz_sys::FileMapping::new(&f, data.len() as u64).unwrap();
            let window = 3 * nz_sys::VIEW_ALIGN * 16;
            let mut src = &data[..];
            write_mapped(&mut src, &map, data.len() as u64, window, &p).unwrap();
            drop(map);
            drop(f);
            assert!(std::fs::read(&p).unwrap() == data);
            // Truncated source.
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&p)
                .unwrap();
            let map = nz_sys::FileMapping::new(&f, data.len() as u64).unwrap();
            let mut short = &data[..data.len() - 10];
            let err = write_mapped(&mut short, &map, data.len() as u64, window, &p).unwrap_err();
            assert!(err.to_string().contains("truncated"), "{err}");
        });
        // End to end: a tar.zst whose member is above ASYNC_WRITE_MAX.
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("big.bin"), &data).unwrap();
        let items = vec![item(
            "big.bin",
            Kind::File,
            src.join("big.bin"),
            data.len() as u64,
            None,
        )];
        for threads in [1, 4] {
            let pool = crate::cpu::pool(threads).unwrap();
            let arc = tmp.path().join(format!("b{threads}.tar.zst"));
            pool.install(|| write_tar(&items, &arc, &TarOptions::new(TarCodec::Zstd, 3)))
                .unwrap();
            let out = tmp.path().join(format!("x{threads}"));
            pool.install(|| extract_tar(&arc, &out)).unwrap();
            assert!(std::fs::read(out.join("big.bin")).unwrap() == data);
        }
    }

    #[test]
    fn chunk_pipe_many_batches() {
        // Exercise several batches and the final-chunk logic with tiny chunks.
        let data: Vec<u8> = (0..200_000u32)
            .flat_map(|i| (i % 251).to_le_bytes())
            .collect();
        let pool = crate::cpu::pool(1).unwrap();
        let gz = pool.install(|| {
            let mut p = ChunkPipe::new(Vec::new(), Arc::new(GzipCodec { level: 6 }), 4096).unwrap();
            for c in data.chunks(1000) {
                p.write_all(c).unwrap();
            }
            p.finish().unwrap()
        });
        let mut back = Vec::new();
        flate2::read::MultiGzDecoder::new(&gz[..])
            .read_to_end(&mut back)
            .unwrap();
        assert!(back == data);
        // Exactly a multiple of the chunk size.
        let gz = pool.install(|| {
            let mut p = ChunkPipe::new(Vec::new(), Arc::new(GzipCodec { level: 1 }), 4096).unwrap();
            p.write_all(&data[..4096 * 8]).unwrap();
            p.finish().unwrap()
        });
        let mut back = Vec::new();
        flate2::read::GzDecoder::new(&gz[..])
            .read_to_end(&mut back)
            .unwrap();
        assert!(back[..] == data[..4096 * 8]);
    }

    #[test]
    fn multi_frame_lz4_and_bz2() {
        let a = b"first frame ".repeat(1000);
        let b = b"second frame".repeat(1000);
        let mut lz = Vec::new();
        for part in [&a, &b] {
            let mut e = lz4::EncoderBuilder::new().build(Vec::new()).unwrap();
            e.write_all(part).unwrap();
            lz.extend(e.finish().0);
        }
        let mut back = Vec::new();
        MultiLz4 {
            dec: Some(lz4::Decoder::new(BufReader::new(&lz[..])).unwrap()),
        }
        .read_to_end(&mut back)
        .unwrap();
        assert_eq!(back, [a.clone(), b.clone()].concat());
    }

    #[test]
    fn xz_block_size_is_bounded() {
        assert_eq!(xz_block_size(0, 5), 1 << 20);
        assert_eq!(xz_block_size(120 << 20, 5), 10 << 20);
        assert_eq!(xz_block_size(10 << 30, 5), 24 << 20);
    }

    #[test]
    fn resolve_inside_rules() {
        assert_eq!(
            resolve_inside(Path::new("nz-no-such-out"), Path::new("a/b"), "../c"),
            Some(PathBuf::from("a").join("c"))
        );
        assert_eq!(
            resolve_inside(Path::new("nz-no-such-out"), Path::new("a"), "../../x"),
            None
        );
        assert_eq!(
            resolve_inside(Path::new("nz-no-such-out"), Path::new(""), "/etc/passwd"),
            None
        );
        assert_eq!(
            resolve_inside(Path::new("nz-no-such-out"), Path::new(""), "C:/x"),
            None
        );
    }

    #[test]
    fn out_of_range_mtimes_do_not_panic() {
        // libarchive test_read_format_tar_pax_negative_time: a negative time
        // read as a huge unsigned value overflowed `SystemTime` and panicked.
        assert!(file_time(u64::MAX).is_none());
        assert!(file_time(910_692_730_086).is_none());
        assert!(file_time(1_700_000_000).is_some());
        let tmp = tempfile::tempdir().unwrap();
        let mut b = tar::Builder::new(Vec::new());
        for (name, kind) in [
            ("d/", tar::EntryType::Directory),
            ("d/f.txt", tar::EntryType::Regular),
        ] {
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(kind);
            h.set_size(if kind.is_dir() { 0 } else { 3 });
            h.set_mode(0o644);
            h.set_mtime(u64::MAX);
            h.set_cksum();
            let data: &[u8] = if kind.is_dir() { b"" } else { b"abc" };
            b.append_data(&mut h, name, data).unwrap();
        }
        let tar = tmp.path().join("t.tar");
        std::fs::write(&tar, b.into_inner().unwrap()).unwrap();
        let out = tmp.path().join("out");
        let st = extract_tar(&tar, &out).unwrap();
        assert_eq!(st.files, 1);
        assert_eq!(std::fs::read(out.join("d/f.txt")).unwrap(), b"abc");
    }
}
