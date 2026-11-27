//! Creating archives and appending backup snapshots.
//!
//! Pipeline: a reader thread walks the files in data order, chunks them
//! (FastCDC) and sends batches; the caller's thread hashes a batch in
//! parallel, deduplicates in order, packs new chunks into blocks and
//! compresses sealed blocks in parallel. Block contents, block numbers and
//! nonces depend only on the input, never on the thread count.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, Result, bail, ensure};
use rayon::prelude::*;

use crate::cdc::Chunker;
use crate::codec::{self, BlockKind, Method};
use crate::crypto::{self, KdfParams, Keys};
use crate::fmt::{
    Aead, BlockHeader, Codec, CryptoHeader, FLAG_ENCRYPTED, FLAG_RECOVERY, HEADER_LEN, Header,
    IndexHeader,
};
use crate::index::{BlockRef, Chunk, Entry, Index, Kind, STREAM_ADS, Snapshot, Stream};
use crate::read::{Archive, OpenOptions as ReadOptions};
use crate::rr::{self, Layout};
use crate::source::FileSource;
use nz_core::planner::Class;

/// Options for [`create`] and [`backup`].
#[derive(Debug, Clone)]
pub struct WriteOptions {
    pub method: Method,
    /// Recovery record size in basis points (300 = 3 %, 0 = none, max 3000).
    pub recovery_bp: u16,
    pub password: Option<String>,
    pub aead: Aead,
    pub kdf: KdfParams,
    /// Snapshot label.
    pub label: String,
    /// Snapshot time (ns since the Unix epoch). `None`: newest entry mtime
    /// for `create`, current time for `backup`.
    pub time_ns: Option<i64>,
    /// Group data by file extension (better ratio; on by default).
    pub sort_by_ext: bool,
    /// Store NTFS alternate data streams of files (Windows; on by default).
    pub keep_streams: bool,
    /// Store file attributes / mode bits (off: stored as 0).
    pub keep_attrs: bool,
}

impl Default for WriteOptions {
    fn default() -> Self {
        Self {
            method: Method::for_level(5),
            recovery_bp: 300,
            password: None,
            aead: Aead::Aes256Gcm,
            kdf: KdfParams::default(),
            label: String::new(),
            time_ns: None,
            sort_by_ext: true,
            keep_streams: true,
            keep_attrs: true,
        }
    }
}

/// What a write did.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct WriteStats {
    pub files: usize,
    pub dirs: usize,
    pub links: usize,
    /// Alternate data streams stored.
    pub streams: usize,
    pub input_bytes: u64,
    /// Bytes stored as new chunks (after deduplication).
    pub new_bytes: u64,
    pub new_chunks: usize,
    pub dedup_chunks: usize,
    pub blocks: usize,
    pub output_bytes: u64,
    /// Bytes appended by this run (backup) or the archive size (create).
    pub written_bytes: u64,
    pub recovery_bytes: u64,
    pub snapshot: usize,
    /// Files that could not be read (skipped): (path, error).
    pub skipped: Vec<(String, String)>,
}

fn ns_of(t: SystemTime) -> i64 {
    match t.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_nanos()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_nanos()).unwrap_or(i64::MAX),
    }
}

#[cfg(windows)]
fn attrs_of(m: &std::fs::Metadata) -> (u32, u32) {
    use std::os::windows::fs::MetadataExt;
    (m.file_attributes(), 0)
}
#[cfg(unix)]
fn attrs_of(m: &std::fs::Metadata) -> (u32, u32) {
    use std::os::unix::fs::PermissionsExt;
    (0, m.permissions().mode())
}

/// A small file read whole: its bytes, chunk boundaries and chunk hashes.
struct Loaded {
    data: Vec<u8>,
    cuts: Vec<(usize, usize)>,
    hashes: Vec<[u8; 32]>,
    class: Class,
}

/// Files at least this large are streamed instead of read whole.
const BIG_FILE: u64 = 32 << 20;
/// Bytes of small files read in parallel per window.
const WINDOW: u64 = 128 << 20;

fn load_small(path: &Path, keys: Option<&Keys>, classify: bool) -> std::io::Result<Loaded> {
    let data = std::fs::read(path)?;
    let mut cuts = Vec::new();
    let mut at = 0;
    while at < data.len() {
        let n = crate::cdc::cut(&data[at..]);
        cuts.push((at, at + n));
        at += n;
    }
    let hashes = cuts
        .iter()
        .map(|&(a, b)| crypto::content_hash(keys, &data[a..b]))
        .collect();
    let class = if classify {
        nz_core::planner::classify_data(&data).0
    } else {
        Class::Text
    };
    Ok(Loaded {
        data,
        cuts,
        hashes,
        class,
    })
}

/// (raw length, frame header, stored payload) of a compressed block.
type Frame = (u32, Vec<u8>, Vec<u8>);

/// A block being filled: its raw bytes and the chunks in it (their block
/// number is set when the block is sealed).
#[derive(Default)]
struct Open {
    raw: Vec<u8>,
    ids: Vec<u32>,
}

struct Packer<'k> {
    method: Method,
    keys: Option<&'k Keys>,
    index: Index,
    dedup: HashMap<[u8; 32], u32>,
    /// One block being filled per [`BlockKind`].
    open: [Open; 4],
    sealed: Vec<(BlockKind, Vec<u8>)>,
    nonce_prefix: [u8; 8],
    run_blocks: u32,
    out: BufWriter<File>,
    pos: u64,
    threads: usize,
    stats: WriteStats,
}

impl Packer<'_> {
    /// Whether files need a content class (only when blocks are split by it).
    fn classify(&self) -> bool {
        self.method.codec != crate::fmt::Codec::Store
    }

    /// Hash `chunks` in parallel, then deduplicate and pack them in order.
    fn add_chunks(&mut self, chunks: &[&[u8]], kind: BlockKind) -> Vec<u32> {
        let hashes: Vec<[u8; 32]> = chunks
            .par_iter()
            .map(|c| crypto::content_hash(self.keys, c))
            .collect();
        self.add_hashed(chunks, &hashes, kind)
    }

    fn add_hashed(&mut self, chunks: &[&[u8]], hashes: &[[u8; 32]], kind: BlockKind) -> Vec<u32> {
        let mut ids = Vec::with_capacity(chunks.len());
        for (c, &h) in chunks.iter().zip(hashes) {
            self.stats.input_bytes += c.len() as u64;
            if let Some(&id) = self.dedup.get(&h) {
                self.stats.dedup_chunks += 1;
                ids.push(id);
                continue;
            }
            let id = self.index.chunks.len() as u32;
            let o = &mut self.open[kind as usize];
            self.index.chunks.push(Chunk {
                block: u32::MAX,
                offset: o.raw.len() as u32,
                len: c.len() as u32,
                hash: h,
            });
            o.raw.extend_from_slice(c);
            o.ids.push(id);
            self.dedup.insert(h, id);
            self.stats.new_chunks += 1;
            self.stats.new_bytes += c.len() as u64;
            ids.push(id);
            if self.open[kind as usize].raw.len() >= self.method.target(kind) {
                self.seal(kind);
            }
        }
        ids
    }

    /// Number the block of `kind` and queue it for compression.
    fn seal(&mut self, kind: BlockKind) {
        let o = std::mem::take(&mut self.open[kind as usize]);
        if o.raw.is_empty() {
            return;
        }
        let n = (self.index.blocks.len() + self.sealed.len()) as u32;
        for id in o.ids {
            self.index.chunks[id as usize].block = n;
        }
        self.sealed.push((kind, o.raw));
    }

    fn seal_all(&mut self) {
        for k in BlockKind::ALL {
            self.seal(k);
        }
    }

    /// Compress and write sealed blocks (all of them, or only when enough
    /// are waiting to keep every thread busy).
    fn flush(&mut self, all: bool) -> Result<()> {
        if self.sealed.is_empty() || (!all && self.sealed.len() < self.threads) {
            return Ok(());
        }
        let sealed = std::mem::take(&mut self.sealed);
        let first_run = self.run_blocks;
        let frames: Vec<Result<Frame>> = sealed
            .par_iter()
            .enumerate()
            .map(|(k, (kind, raw))| {
                let (codec, filter, payload) = codec::compress(raw, &self.method, *kind)?;
                let mut nonce = [0u8; 12];
                let mut h = BlockHeader {
                    codec,
                    filter,
                    encrypted: self.keys.is_some(),
                    raw_len: raw.len() as u32,
                    stored_len: 0,
                    hash: crypto::content_hash(self.keys, raw),
                    nonce,
                };
                let stored = match self.keys {
                    Some(key) => {
                        nonce[..8].copy_from_slice(&self.nonce_prefix);
                        nonce[8..].copy_from_slice(&(first_run + k as u32).to_le_bytes());
                        h.nonce = nonce;
                        h.stored_len = (payload.len() + crypto::TAG) as u32;
                        let aad = h.encode();
                        crypto::seal(key.aead, &key.block, &nonce, &aad[..48], &payload)?
                    }
                    None => {
                        h.stored_len = payload.len() as u32;
                        payload
                    }
                };
                Ok((raw.len() as u32, h.encode().to_vec(), stored))
            })
            .collect();
        for f in frames {
            let (raw_len, hdr, stored) = f?;
            self.index.blocks.push(BlockRef {
                offset: self.pos,
                raw_len,
            });
            self.out.write_all(&hdr)?;
            self.out.write_all(&stored)?;
            self.pos += (hdr.len() + stored.len()) as u64;
            self.stats.blocks += 1;
            self.run_blocks += 1;
        }
        Ok(())
    }
}

/// Encode an index frame (header + payload).
fn index_frame(idx: &Index, keys: Option<&Keys>) -> Result<Vec<u8>> {
    let raw = idx.encode();
    let comp = zstd::bulk::compress(&raw, 9)?;
    let (codec, payload) = if comp.len() < raw.len() {
        (Codec::Zstd, comp)
    } else {
        (Codec::Store, raw.clone())
    };
    let mut h = IndexHeader {
        codec,
        encrypted: keys.is_some(),
        raw_len: raw.len() as u64,
        stored_len: payload.len() as u64,
        hash: crypto::content_hash(keys, &raw),
        nonce: [0; 12],
    };
    let stored = match keys {
        Some(k) => {
            h.nonce = crypto::random::<12>()?;
            h.stored_len += crypto::TAG as u64;
            let aad = h.encode();
            crypto::seal(k.aead, &k.index, &h.nonce, &aad[..56], &payload)?
        }
        None => payload,
    };
    let mut out = h.encode().to_vec();
    out.extend_from_slice(&stored);
    Ok(out)
}

/// Write everything after the data: primary index at `pos`, then the
/// header at 0, recovery record, index copy and trailer. Returns
/// (archive size, recovery bytes).
fn finish(
    file: &mut File,
    path: &Path,
    pos: u64,
    flags: u16,
    idx_frame: &[u8],
    bp: u16,
) -> Result<(u64, u64)> {
    file.seek(SeekFrom::Start(pos))?;
    file.write_all(idx_frame)?;
    let covered = pos + idx_frame.len() as u64;
    let layout = if bp > 0 {
        Some(Layout::for_writer(covered, bp)?)
    } else {
        None
    };
    let rr_len = layout.map_or(0, |l| l.rr_len);
    let copy_off = covered + rr_len;
    let size = copy_off + idx_frame.len() as u64 + HEADER_LEN as u64;
    let h = Header {
        flags: if layout.is_some() {
            flags | FLAG_RECOVERY
        } else {
            flags & !FLAG_RECOVERY
        },
        index_offset: pos,
        index_copy_offset: copy_off,
        recovery_offset: if layout.is_some() { covered } else { 0 },
        archive_size: size,
        rr_sector_size: layout.map_or(0, |l| l.sector_size),
        rr_basis_points: layout.map_or(0, |l| l.basis_points),
        rr_group_sectors: layout.map_or(0, |l| l.group_sectors),
    };
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&h.encode(false))?;
    file.flush()?;
    file.seek(SeekFrom::Start(covered))?;
    if let Some(l) = layout {
        let src = FileSource::open(path)?;
        ensure!(src.len >= covered, "archive shorter than expected");
        let t = std::time::Instant::now();
        let rec = rr::build(&src, &l)?;
        nz_core::trace(&format!(
            "nz recovery build {:.1} ms",
            t.elapsed().as_secs_f64() * 1e3
        ));
        file.write_all(&rec)?;
    }
    file.write_all(idx_frame)?;
    file.write_all(&h.encode(true))?;
    file.set_len(size)?;
    file.sync_all()?;
    Ok((size, rr_len))
}

/// An entry to archive and, for a file, its path and walked size.
type Input = (Entry, Option<(PathBuf, u64)>);

/// Alternate data streams of a regular file (sizes from the directory
/// listing; chunks are filled in while packing). Errors mean "none".
fn file_streams(path: &Path) -> Vec<Stream> {
    nz_sys::alternate_streams(path)
        .unwrap_or_default()
        .into_iter()
        .filter(|(name, _)| crate::index::valid_stream_name(name))
        .map(|(name, size)| Stream {
            kind: STREAM_ADS,
            name,
            size,
            chunks: Vec::new(),
        })
        .collect()
}

/// `path:name`, the Win32 path of a named stream.
pub(crate) fn stream_path(path: &Path, name: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(":");
    s.push(name);
    PathBuf::from(s)
}

/// Entries to archive.
fn scan_sources(sources: &[PathBuf], keep_attrs: bool, keep_streams: bool) -> Result<Vec<Input>> {
    let items = nz_core::walk::collect_items(sources, true)?;
    // One directory query per file, in parallel; the order stays the walk order.
    let streams: Vec<Vec<Stream>> = if keep_streams && cfg!(windows) {
        items
            .par_iter()
            .map(|it| {
                if it.link.is_none() && it.entry.kind == nz_core::walk::Kind::File {
                    file_streams(&it.entry.path)
                } else {
                    Vec::new()
                }
            })
            .collect()
    } else {
        vec![Vec::new(); items.len()]
    };
    let mut out = Vec::with_capacity(items.len());
    for (it, streams) in items.into_iter().zip(streams) {
        let e = &it.entry;
        let meta = std::fs::symlink_metadata(&e.path).ok();
        let (attrs, mode) = match &meta {
            Some(m) if keep_attrs => attrs_of(m),
            _ => (0, 0),
        };
        let kind = if it.link.is_some() {
            Kind::Symlink
        } else if e.kind == nz_core::walk::Kind::Dir {
            Kind::Dir
        } else {
            Kind::File
        };
        out.push((
            Entry {
                path: e.name.clone(),
                kind,
                attrs,
                mode,
                mtime_ns: ns_of(e.mtime),
                size: 0,
                chunks: Vec::new(),
                target: it.link.clone().unwrap_or_default(),
                streams,
            },
            (kind == Kind::File).then(|| (e.path.clone(), e.size)),
        ));
    }
    Ok(out)
}

fn ext_key(name: &str) -> String {
    let base = name.rsplit('/').next().unwrap_or(name);
    match base.rsplit_once('.') {
        Some((b, x)) if !b.is_empty() => x.to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// Read, chunk and pack all files; returns the snapshot entries.
fn pack(p: &mut Packer<'_>, list: Vec<Input>, sort_by_ext: bool) -> Result<Vec<Entry>> {
    let mut order: Vec<usize> = (0..list.len()).filter(|&i| list[i].1.is_some()).collect();
    if sort_by_ext {
        order.sort_by_cached_key(|&i| (ext_key(&list[i].0.path), i));
    }
    let files: Vec<(usize, PathBuf, u64)> = order
        .iter()
        .map(|&i| {
            let (path, size) = list[i].1.clone().unwrap();
            (i, path, size)
        })
        .collect();
    let (mut entries, _): (Vec<Entry>, Vec<_>) = list.into_iter().unzip();
    let mut keep = vec![true; entries.len()];
    let mut k = 0;
    while k < files.len() {
        if files[k].2 >= BIG_FILE {
            let (i, path, _) = &files[k];
            if let Err(e) = pack_big(p, &mut entries[*i], path) {
                keep[*i] = false;
                p.stats
                    .skipped
                    .push((entries[*i].path.clone(), format!("{e:#}")));
            } else {
                pack_streams(p, &mut entries[*i], path);
            }
            k += 1;
            continue;
        }
        // A window of small files, read and chunked in parallel.
        let mut j = k;
        let mut bytes = 0;
        while j < files.len() && files[j].2 < BIG_FILE && (j == k || bytes + files[j].2 <= WINDOW) {
            bytes += files[j].2;
            j += 1;
        }
        let keys = p.keys;
        let classify = p.classify();
        let loaded: Vec<std::io::Result<Loaded>> = files[k..j]
            .par_iter()
            .map(|(_, path, _)| load_small(path, keys, classify))
            .collect();
        for ((i, path, _), r) in files[k..j].iter().zip(loaded) {
            match r {
                Ok(l) => {
                    let slices: Vec<&[u8]> = l.cuts.iter().map(|&(a, b)| &l.data[a..b]).collect();
                    let kind = p.method.kind_for(l.class);
                    let ids = p.add_hashed(&slices, &l.hashes, kind);
                    entries[*i].size = l.data.len() as u64;
                    entries[*i].chunks = ids;
                    if !entries[*i].streams.is_empty() {
                        pack_streams(p, &mut entries[*i], path);
                    }
                }
                Err(e) => {
                    keep[*i] = false;
                    p.stats
                        .skipped
                        .push((entries[*i].path.clone(), e.to_string()));
                }
            }
        }
        p.flush(false)?;
        k = j;
    }
    p.seal_all();
    p.flush(true)?;
    let mut out = Vec::with_capacity(entries.len());
    for (e, k) in entries.into_iter().zip(keep) {
        if !k {
            continue;
        }
        match e.kind {
            Kind::File => p.stats.files += 1,
            Kind::Dir => p.stats.dirs += 1,
            Kind::Symlink => p.stats.links += 1,
        }
        out.push(e);
    }
    Ok(out)
}

/// Stream a large file: read in 16 MiB pieces, chunk, hash in parallel.
/// On a read error the chunks already added stay (unreferenced).
fn pack_big(p: &mut Packer<'_>, e: &mut Entry, path: &Path) -> Result<()> {
    let kind = if p.classify() {
        let len = std::fs::metadata(path)?.len();
        p.method
            .kind_for(nz_core::planner::classify_path(path, len).0)
    } else {
        BlockKind::Normal
    };
    let (size, ids) = pack_reader(p, File::open(path)?, 16 << 20, kind)?;
    e.size = size;
    e.chunks = ids;
    Ok(())
}

/// Chunk and add everything `r` yields, reading `piece` bytes at a time;
/// returns (size, chunk ids).
fn pack_reader(
    p: &mut Packer<'_>,
    mut r: impl Read,
    piece: usize,
    kind: BlockKind,
) -> Result<(u64, Vec<u32>)> {
    let mut ch = Chunker::default();
    let mut buf = vec![0u8; piece.max(1)];
    let mut ids = Vec::new();
    let mut size = 0u64;
    loop {
        let mut n = 0;
        while n < buf.len() {
            let k = r.read(&mut buf[n..])?;
            if k == 0 {
                break;
            }
            n += k;
        }
        let mut chunks = Vec::new();
        if n == 0 {
            ch.finish(&mut chunks);
        } else {
            ch.push(&buf[..n], &mut chunks);
        }
        let slices: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
        size += slices.iter().map(|c| c.len() as u64).sum::<u64>();
        ids.extend(p.add_chunks(&slices, kind));
        p.flush(false)?;
        if n == 0 {
            break;
        }
    }
    Ok((size, ids))
}

/// Add the alternate data streams of file `path` after its content, in name
/// order. A stream that cannot be read is dropped and reported.
fn pack_streams(p: &mut Packer<'_>, e: &mut Entry, path: &Path) {
    let mut kept = Vec::with_capacity(e.streams.len());
    for mut st in std::mem::take(&mut e.streams) {
        let sp = stream_path(path, &st.name);
        let piece = (st.size.saturating_add(1)).min(16 << 20) as usize;
        match File::open(&sp)
            .map_err(anyhow::Error::from)
            .and_then(|f| pack_reader(p, f, piece, BlockKind::Normal))
        {
            Ok((size, ids)) => {
                st.size = size;
                st.chunks = ids;
                p.stats.streams += 1;
                kept.push(st);
            }
            Err(err) => p
                .stats
                .skipped
                .push((format!("{}:{}", e.path, st.name), format!("{err:#}"))),
        }
    }
    e.streams = kept;
}
fn threads() -> usize {
    rayon::current_num_threads().max(1)
}

/// Create a new archive at `out` (overwrites).
pub fn create(sources: &[PathBuf], out: &Path, opt: &WriteOptions) -> Result<WriteStats> {
    ensure!(
        opt.recovery_bp <= 3000,
        "recovery record is limited to 30 %"
    );
    let t0 = std::time::Instant::now();
    let list = scan_sources(sources, opt.keep_attrs, opt.keep_streams)?;
    nz_core::trace(&format!(
        "nz walk {} entries {:.1} ms",
        list.len(),
        t0.elapsed().as_secs_f64() * 1e3
    ));
    let (keys, crypto_hdr) = match &opt.password {
        Some(pw) => {
            let (k, h) = crypto::create(pw, opt.aead, opt.kdf)?;
            (Some(k), Some(h))
        }
        None => (None, None),
    };
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(out)
        .with_context(|| format!("cannot create {}", out.display()))?;
    let flags = if keys.is_some() { FLAG_ENCRYPTED } else { 0 };
    let prov = Header {
        flags,
        ..Default::default()
    };
    file.write_all(&prov.encode(false))?;
    let mut pos = HEADER_LEN as u64;
    if let Some(c) = &crypto_hdr {
        file.write_all(&c.encode())?;
        pos += crate::fmt::CRYPTO_LEN as u64;
    }
    let time = opt
        .time_ns
        .unwrap_or_else(|| list.iter().map(|(e, _)| e.mtime_ns).max().unwrap_or(0));
    let mut p = Packer {
        method: opt.method,
        keys: keys.as_ref(),
        index: Index::default(),
        dedup: HashMap::new(),
        open: Default::default(),
        sealed: Vec::new(),
        nonce_prefix: if keys.is_some() {
            crypto::random::<8>()?
        } else {
            [0; 8]
        },
        run_blocks: 0,
        out: BufWriter::with_capacity(4 << 20, file),
        pos,
        threads: threads(),
        stats: WriteStats::default(),
    };
    let entries = pack(&mut p, list, opt.sort_by_ext)?;
    nz_core::trace(&format!(
        "nz pack {:.1} ms",
        t0.elapsed().as_secs_f64() * 1e3
    ));
    p.index.snapshots.push(Snapshot {
        time_ns: time,
        label: opt.label.clone(),
        entries,
    });
    let frame = index_frame(&p.index, p.keys)?;
    let pos = p.pos;
    let mut stats = std::mem::take(&mut p.stats);
    let mut file = p.out.into_inner().map_err(|e| e.into_error())?;
    let (size, rr) = finish(&mut file, out, pos, flags, &frame, opt.recovery_bp)?;
    nz_core::trace(&format!(
        "nz finish {:.1} ms",
        t0.elapsed().as_secs_f64() * 1e3
    ));
    stats.output_bytes = size;
    stats.written_bytes = size;
    stats.recovery_bytes = rr;
    stats.snapshot = 1;
    Ok(stats)
}

/// Append a snapshot of `sources` to the backup archive `archive` (created
/// when missing). Only chunks not already stored are written.
pub fn backup(archive: &Path, sources: &[PathBuf], opt: &WriteOptions) -> Result<WriteStats> {
    if !archive.exists() {
        let mut o = opt.clone();
        if o.time_ns.is_none() {
            o.time_ns = Some(ns_of(SystemTime::now()));
        }
        o.sort_by_ext = false;
        return create(sources, archive, &o);
    }
    ensure!(
        opt.recovery_bp <= 3000,
        "recovery record is limited to 30 %"
    );
    // Read the current state (repairing it in place first if needed).
    let src = FileSource::open(archive)?;
    let ro = ReadOptions {
        password: opt.password.clone(),
        verify: false,
    };
    let a =
        Archive::open(&src, &ro).with_context(|| format!("cannot open {}", archive.display()))?;
    if let Some(r) = &a.repair {
        ensure!(
            r.ok(),
            "archive is damaged beyond its recovery record; run `nz repair` first"
        );
    }
    let patches: Vec<(u64, Vec<u8>)> = a
        .view
        .patches
        .iter()
        .map(|(&k, v)| (k, v.clone()))
        .collect();
    let header = a.header;
    let index = a.index.clone();
    let keys = a.keys.as_ref().map(|k| Keys {
        aead: k.aead,
        block: k.block,
        index: k.index,
        hash: k.hash,
    });
    let crypto_hdr: Option<CryptoHeader> = a.crypto;
    drop(a);
    drop(src);
    ensure!(
        opt.password.is_none() || crypto_hdr.is_some(),
        "the archive is not encrypted; remove the password option"
    );
    // The primary index frame end is where new data goes.
    let src = FileSource::open(archive)?;
    let mut view = crate::source::View::new(&src);
    for (o, d) in &patches {
        view.patch(*o, d.clone());
    }
    let (_, ilen) = crate::read::read_index(&view, keys.as_ref(), header.index_offset)?;
    let start = header.index_offset + ilen;
    drop(view);
    drop(src);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(archive)
        .with_context(|| format!("cannot open {} for writing", archive.display()))?;
    for (o, d) in &patches {
        file.seek(SeekFrom::Start(*o))?;
        file.write_all(d)?;
    }
    // Interim state: old index, no recovery record, no copy, no trailer.
    // An interrupted run leaves a readable archive with the old snapshots.
    let interim = Header {
        flags: header.flags & !FLAG_RECOVERY,
        index_offset: header.index_offset,
        index_copy_offset: 0,
        recovery_offset: 0,
        archive_size: start,
        ..Default::default()
    };
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&interim.encode(false))?;
    file.set_len(start)?;
    file.sync_all()?;
    file.seek(SeekFrom::Start(start))?;

    let dedup = index
        .chunks
        .iter()
        .enumerate()
        .map(|(i, c)| (c.hash, i as u32))
        .collect();
    let list = scan_sources(sources, opt.keep_attrs, opt.keep_streams)?;
    let mut p = Packer {
        method: opt.method,
        keys: keys.as_ref(),
        index,
        dedup,
        open: Default::default(),
        sealed: Vec::new(),
        nonce_prefix: if keys.is_some() {
            crypto::random::<8>()?
        } else {
            [0; 8]
        },
        run_blocks: 0,
        out: BufWriter::with_capacity(4 << 20, file),
        pos: start,
        threads: threads(),
        stats: WriteStats::default(),
    };
    let entries = pack(&mut p, list, false)?;
    p.index.snapshots.push(Snapshot {
        time_ns: opt.time_ns.unwrap_or_else(|| ns_of(SystemTime::now())),
        label: opt.label.clone(),
        entries,
    });
    let frame = index_frame(&p.index, p.keys)?;
    let pos = p.pos;
    let mut stats = std::mem::take(&mut p.stats);
    stats.snapshot = p.index.snapshots.len();
    let mut file = p.out.into_inner().map_err(|e| e.into_error())?;
    let (size, rr) = finish(
        &mut file,
        archive,
        pos,
        header.flags & FLAG_ENCRYPTED,
        &frame,
        opt.recovery_bp,
    )?;
    stats.output_bytes = size;
    stats.written_bytes = size - start;
    stats.recovery_bytes = rr;
    Ok(stats)
}

/// Rewrite a damaged archive repaired: covered bytes from the recovery
/// record, then a fresh index copy, recovery record and trailer.
pub fn repair_to(
    archive: &Path,
    out: &Path,
    password: Option<String>,
    bp: Option<u16>,
) -> Result<crate::rr::RepairReport> {
    let src = FileSource::open(archive)?;
    let ro = ReadOptions {
        password,
        verify: true,
    };
    let a = Archive::open(&src, &ro)?;
    let rep = a.repair.clone().unwrap_or_default();
    if !rep.ok() {
        bail!(
            "damage exceeds the recovery record: {} byte range(s) lost",
            rep.unrecoverable.len()
        );
    }
    let h = a.header;
    let keys = a.keys.as_ref();
    let (_, ilen) = crate::read::read_index(&a.view, keys, h.index_offset)?;
    let pos = h.index_offset;
    let frame = a.view.read(pos, ilen as usize)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(out)?;
    // Data area (everything before the primary index).
    let mut off = 0u64;
    while off < pos {
        let n = (pos - off).min(8 << 20) as usize;
        file.write_all(&a.view.read(off, n)?)?;
        off += n as u64;
    }
    let bp = bp.unwrap_or(if h.has_recovery() {
        h.rr_basis_points
    } else {
        0
    });
    drop(a);
    finish(&mut file, out, pos, h.flags & FLAG_ENCRYPTED, &frame, bp)?;
    Ok(rep)
}
