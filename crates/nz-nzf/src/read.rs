//! Opening, listing, testing and extracting `.nz` archives, with automatic
//! repair from the recovery record.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail, ensure};
use rayon::prelude::*;

use crate::codec;
use crate::crypto::{self, Keys};
use crate::fmt::{
    BLOCK_HEADER_LEN, BlockHeader, CRYPTO_LEN, CryptoHeader, HEADER_LEN, Header, INDEX_HEADER_LEN,
    IndexHeader,
};
use crate::index::{BlockRef, Entry, Index, Kind, STREAM_ADS, valid_stream_name};
use crate::rr::{self, Layout, Located, RepairReport};
use crate::source::{Source, View};

#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    pub password: Option<String>,
    /// Check every sector against the recovery record before reading.
    pub verify: bool,
}

/// An open archive.
pub struct Archive<'a> {
    pub view: View<'a>,
    pub header: Header,
    pub crypto: Option<CryptoHeader>,
    pub keys: Option<Keys>,
    pub index: Index,
    /// Set once the recovery record has been applied.
    pub repair: Option<RepairReport>,
    /// Where the recovery record is, if any could be found.
    pub recovery: Option<Located>,
    /// Which structures were taken from a backup copy.
    pub notes: Vec<String>,
    password: Option<String>,
}

fn read_header(v: &View<'_>, trailer: bool) -> Option<Header> {
    let off = if trailer {
        v.len().checked_sub(HEADER_LEN as u64)?
    } else {
        0
    };
    let b = v.read(off, HEADER_LEN).ok()?;
    Header::decode(&b, trailer).ok()
}

/// The recovery record named by a header (its geometry is in the header).
fn locate_from(h: &Header) -> Option<Located> {
    if !h.has_recovery() || h.recovery_offset == 0 {
        return None;
    }
    let layout = Layout::new(
        h.recovery_offset,
        h.rr_sector_size,
        h.rr_group_sectors,
        h.rr_basis_points,
    )
    .ok()?;
    Some(Located {
        offset: h.recovery_offset,
        layout,
    })
}

fn read_frame_payload(v: &View<'_>, off: u64, len: u64) -> Result<Vec<u8>> {
    ensure!(len <= v.len(), "frame longer than the archive");
    v.read(off, len as usize)
}

/// Load and decode the index frame at `off`.
pub fn read_index(v: &View<'_>, keys: Option<&Keys>, off: u64) -> Result<(Index, u64)> {
    let hb = v.read(off, INDEX_HEADER_LEN)?;
    let h = IndexHeader::decode(&hb)?;
    ensure!(
        h.encrypted == keys.is_some(),
        "index encryption flag mismatch"
    );
    let stored = read_frame_payload(v, off + INDEX_HEADER_LEN as u64, h.stored_len)?;
    let payload = match keys {
        Some(k) => crypto::open_sealed(k.aead, &k.index, &h.nonce, &hb[..56], &stored)?,
        None => stored,
    };
    let raw = codec::decompress(
        h.codec,
        crate::fmt::Filter::None,
        &payload,
        h.raw_len as usize,
    )?;
    ensure!(
        crypto::content_hash(keys, &raw) == h.hash,
        "index hash mismatch"
    );
    let idx = Index::decode(&raw)?;
    Ok((idx, INDEX_HEADER_LEN as u64 + h.stored_len))
}

/// Read, authenticate, decompress and hash-check one block.
pub fn read_block(v: &View<'_>, keys: Option<&Keys>, b: &BlockRef) -> Result<Vec<u8>> {
    let hb = v.read(b.offset, BLOCK_HEADER_LEN)?;
    let h = BlockHeader::decode(&hb)?;
    ensure!(h.raw_len == b.raw_len, "block size differs from the index");
    ensure!(
        h.encrypted == keys.is_some(),
        "block encryption flag mismatch"
    );
    let stored = read_frame_payload(
        v,
        b.offset + BLOCK_HEADER_LEN as u64,
        u64::from(h.stored_len),
    )?;
    let payload = match keys {
        Some(k) => crypto::open_sealed(k.aead, &k.block, &h.nonce, &hb[..48], &stored)?,
        None => stored,
    };
    let raw = codec::decompress(h.codec, h.filter, &payload, h.raw_len as usize)?;
    ensure!(
        crypto::content_hash(keys, &raw) == h.hash,
        "block hash mismatch"
    );
    Ok(raw)
}

impl<'a> Archive<'a> {
    pub fn open(src: &'a dyn Source, opt: &OpenOptions) -> Result<Self> {
        let mut a = Self {
            view: View::new(src),
            header: Header::default(),
            crypto: None,
            keys: None,
            index: Index::default(),
            repair: None,
            recovery: None,
            notes: Vec::new(),
            password: opt.password.clone(),
        };
        let h0 = read_header(&a.view, false);
        let ht = read_header(&a.view, true);
        a.recovery = h0
            .as_ref()
            .and_then(locate_from)
            .or_else(|| ht.as_ref().and_then(locate_from));
        if opt.verify {
            a.apply_recovery()?;
            a.load()?;
            return Ok(a);
        }
        match a.load() {
            Ok(()) => Ok(a),
            Err(e) if is_password_error(&e) => Err(e),
            Err(first) => {
                if a.repair.is_some() {
                    return Err(first);
                }
                if let Err(e) = a.apply_recovery() {
                    return Err(e.context(format!("{first:#}")));
                }
                a.load().map_err(|e| {
                    e.context(format!(
                        "archive is damaged beyond repair (first error: {first:#})"
                    ))
                })?;
                Ok(a)
            }
        }
    }

    /// Locate the recovery record (header, trailer or scan) and rebuild
    /// damaged sectors into the view.
    pub fn apply_recovery(&mut self) -> Result<&RepairReport> {
        if self.repair.is_none() {
            let loc = match self.recovery {
                Some(l) => l,
                None => match rr::scan(self.view.src) {
                    Some(l) => {
                        self.notes.push("recovery record found by scanning".into());
                        l
                    }
                    None => bail!("no usable recovery record"),
                },
            };
            self.recovery = Some(loc);
            let rep = rr::repair(&mut self.view, &loc)?;
            self.repair = Some(rep);
        }
        Ok(self.repair.as_ref().unwrap())
    }

    fn load(&mut self) -> Result<()> {
        let mut errs = Vec::new();
        let mut cands = Vec::new();
        if let Some(h) = read_header(&self.view, false) {
            cands.push((h, "header"));
        }
        if let Some(h) = read_header(&self.view, true) {
            cands.push((h, "trailer"));
        }
        if cands.is_empty() {
            bail!("not a .nz archive or both the header and the trailer are damaged");
        }
        for (h, from) in cands {
            match self.load_with(&h) {
                Ok(()) => {
                    if from != "header" {
                        self.notes.push(format!("structure read from the {from}"));
                    }
                    self.header = h;
                    if self.recovery.is_none() {
                        self.recovery = locate_from(&h);
                    }
                    return Ok(());
                }
                Err(e) if is_password_error(&e) => return Err(e),
                Err(e) => errs.push(format!("{from}: {e:#}")),
            }
        }
        bail!("{}", errs.join("; "))
    }

    fn load_with(&mut self, h: &Header) -> Result<()> {
        self.keys = None;
        self.crypto = None;
        if h.encrypted() {
            let b = self.view.read(HEADER_LEN as u64, CRYPTO_LEN)?;
            let c = CryptoHeader::decode(&b)?;
            let Some(pw) = self.password.as_deref() else {
                bail!(PasswordError(
                    "archive is encrypted: a password is required"
                ));
            };
            let keys = crypto::open(pw, &c).map_err(|_| PasswordError("wrong password"))?;
            self.keys = Some(keys);
            self.crypto = Some(c);
        }
        let mut errs = Vec::new();
        for (off, what) in [
            (h.index_offset, "index"),
            (h.index_copy_offset, "index copy"),
        ] {
            if off == 0 {
                continue;
            }
            match read_index(&self.view, self.keys.as_ref(), off) {
                Ok((idx, _)) => {
                    if what != "index" {
                        self.notes.push(format!("{what} used"));
                    }
                    self.index = idx;
                    return Ok(());
                }
                Err(e) => errs.push(format!("{what}: {e:#}")),
            }
        }
        bail!("{}", errs.join("; "))
    }

    pub fn snapshot(&self, which: Option<usize>) -> Result<usize> {
        let n = self.index.snapshots.len();
        ensure!(n > 0, "archive has no snapshots");
        match which {
            None => Ok(n - 1),
            Some(i) if i < n => Ok(i),
            Some(i) => bail!("no snapshot #{} (archive has {n})", i + 1),
        }
    }

    /// Bytes stored for each block (frame header + payload), from block headers.
    pub fn stored_size(&self) -> u64 {
        self.view.len()
    }
}

/// A missing or wrong password (see [`password_error`]).
#[derive(Debug)]
struct PasswordError(&'static str);
impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for PasswordError {}

fn is_password_error(e: &anyhow::Error) -> bool {
    password_error(e).is_some()
}

/// `Some(true)` when `e` says a password is required, `Some(false)` when the
/// given password is wrong, `None` for any other error.
pub fn password_error(e: &anyhow::Error) -> Option<bool> {
    e.chain()
        .find_map(|c| c.downcast_ref::<PasswordError>())
        .map(|p| p.0.contains("required"))
}

// ------------------------------------------------------------ extraction

/// Outcome of an extraction.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ExtractReport {
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
    /// Alternate data streams restored.
    pub streams: usize,
    /// Streams that could not be written (their file was restored): (path:stream, reason).
    pub stream_errors: Vec<(String, String)>,
    /// Entries that could not be restored: (path, reason).
    pub failed: Vec<(String, String)>,
    pub repair: Option<RepairReport>,
    pub notes: Vec<String>,
}

/// Decoded-once block cache; a block is dropped when its last piece is used.
struct Cache<'v, 'a> {
    view: &'v View<'a>,
    keys: Option<&'v Keys>,
    blocks: &'v [BlockRef],
    slots: Vec<Mutex<Slot>>,
}

#[derive(Default)]
struct Slot {
    data: Option<Arc<Vec<u8>>>,
    err: Option<String>,
    remaining: usize,
}

impl Cache<'_, '_> {
    fn get(&self, b: u32) -> std::result::Result<Arc<Vec<u8>>, String> {
        let mut s = self.slots[b as usize].lock().unwrap();
        if let Some(d) = &s.data {
            return Ok(d.clone());
        }
        if let Some(e) = &s.err {
            return Err(e.clone());
        }
        match read_block(self.view, self.keys, &self.blocks[b as usize]) {
            Ok(d) => {
                let d = Arc::new(d);
                s.data = Some(d.clone());
                Ok(d)
            }
            Err(e) => {
                let m = format!("block {b}: {e:#}");
                s.err = Some(m.clone());
                Err(m)
            }
        }
    }
    fn release(&self, b: u32) {
        let mut s = self.slots[b as usize].lock().unwrap();
        s.remaining = s.remaining.saturating_sub(1);
        if s.remaining == 0 {
            s.data = None;
        }
    }
    /// Release every remaining piece of `ids` (after a failure).
    fn release_all(&self, idx: &Index, ids: &[u32]) {
        for &c in ids {
            self.release(idx.chunks[c as usize].block);
        }
    }
}

pub fn to_systime(ns: i64) -> Option<SystemTime> {
    if ns >= 0 {
        UNIX_EPOCH.checked_add(Duration::from_nanos(ns as u64))
    } else {
        UNIX_EPOCH.checked_sub(Duration::from_nanos(ns.unsigned_abs()))
    }
}

/// Why copying chunks stopped: damaged data (the entry fails and may be
/// retried after a repair) or an output error.
enum CopyErr {
    Data(String),
    Io(String),
}

/// Write the chunks `ids` to `out`. Every piece of `ids` is released, also
/// on failure.
fn copy_chunks(
    cache: &Cache<'_, '_>,
    idx: &Index,
    ids: &[u32],
    out: &mut impl Write,
) -> std::result::Result<u64, CopyErr> {
    let mut written = 0u64;
    for (k, &c) in ids.iter().enumerate() {
        let ch = idx.chunks[c as usize];
        let data = match cache.get(ch.block) {
            Ok(d) => d,
            Err(m) => {
                cache.release_all(idx, &ids[k..]);
                return Err(CopyErr::Data(m));
            }
        };
        let piece = &data[ch.offset as usize..(ch.offset + ch.len) as usize];
        let r = out.write_all(piece);
        drop(data);
        cache.release(ch.block);
        if let Err(x) = r {
            cache.release_all(idx, &ids[k + 1..]);
            return Err(CopyErr::Io(format!("write: {x}")));
        }
        written += u64::from(ch.len);
    }
    out.flush()
        .map_err(|x| CopyErr::Io(format!("write: {x}")))?;
    Ok(written)
}

/// What writing one file entry did.
struct Written {
    bytes: u64,
    streams: usize,
    /// Streams that could not be written (the file itself is fine).
    stream_errors: Vec<(String, String)>,
}

/// Write one file entry from its chunks, then its alternate data streams
/// (`dest:name`), then its time and read-only attribute.
fn write_file(
    cache: &Cache<'_, '_>,
    idx: &Index,
    e: &Entry,
    dest: &Path,
) -> std::result::Result<Written, String> {
    let all: Vec<u32> = entry_chunks(e).collect();
    let (content, mut rest) = all.split_at(e.chunks.len());
    let file = match File::create(dest) {
        Ok(f) => f,
        Err(x) => {
            cache.release_all(idx, &all);
            return Err(format!("create: {x}"));
        }
    };
    let mut out = std::io::BufWriter::with_capacity(1 << 20, file);
    let bytes = copy_chunks(cache, idx, content, &mut out).map_err(|x| {
        cache.release_all(idx, rest);
        match x {
            CopyErr::Data(m) | CopyErr::Io(m) => m,
        }
    })?;
    let f = out.into_inner().map_err(|x| {
        cache.release_all(idx, rest);
        format!("write: {x}")
    })?;
    let mut w = Written {
        bytes,
        streams: 0,
        stream_errors: Vec::new(),
    };
    for st in e
        .streams
        .iter()
        .filter(|s| RESTORE_STREAMS && s.kind == STREAM_ADS)
    {
        let (ids, tail) = rest.split_at(st.chunks.len());
        rest = tail;
        let sf = match File::create(crate::write::stream_path(dest, &st.name)) {
            Ok(sf) => sf,
            Err(x) => {
                cache.release_all(idx, ids);
                w.stream_errors
                    .push((st.name.clone(), format!("create: {x}")));
                continue;
            }
        };
        match copy_chunks(cache, idx, ids, &mut std::io::BufWriter::new(sf)) {
            Ok(_) => w.streams += 1,
            Err(CopyErr::Io(m)) => w.stream_errors.push((st.name.clone(), m)),
            Err(CopyErr::Data(m)) => {
                cache.release_all(idx, rest);
                return Err(format!("stream {}: {m}", st.name));
            }
        }
    }
    if let Some(t) = to_systime(e.mtime_ns) {
        let _ = f.set_modified(t);
    }
    if e.attrs & 1 != 0 {
        drop(f);
        if let Ok(m) = std::fs::metadata(dest) {
            let mut p = m.permissions();
            p.set_readonly(true);
            let _ = std::fs::set_permissions(dest, p);
        }
    }
    Ok(w)
}

/// Check that every entry name stays inside the output directory and that
/// every alternate data stream name is a plain stream name; the whole
/// archive is rejected otherwise (same policy as the other formats).
pub fn checked_paths(entries: &[Entry]) -> Result<Vec<PathBuf>> {
    entries
        .iter()
        .map(|e| {
            if let Some(st) = e
                .streams
                .iter()
                .find(|s| s.kind == STREAM_ADS && !valid_stream_name(&s.name))
            {
                bail!(
                    "unsafe stream name '{}' on '{}': archive rejected",
                    st.name,
                    e.path
                );
            }
            nz_core::walk::safe_relative(&e.path)
                .ok_or_else(|| anyhow!("unsafe member name '{}': archive rejected", e.path))
        })
        .collect()
}

/// The chunks a file entry needs on extraction: its content, then its
/// alternate data streams (only where they can be restored).
fn entry_chunks(e: &Entry) -> impl Iterator<Item = u32> + '_ {
    let streams = e
        .streams
        .iter()
        .filter(|s| RESTORE_STREAMS && s.kind == STREAM_ADS)
        .flat_map(|s| s.chunks.iter().copied());
    e.chunks.iter().copied().chain(streams)
}

/// Alternate data streams exist on Windows only.
const RESTORE_STREAMS: bool = cfg!(windows);

/// Extract snapshot `which` (default: latest) into `out_dir`. Damaged
/// entries are reported, not fatal; if a block fails and a recovery record
/// exists, the record is applied and the failed entries are retried.
pub fn extract(a: &mut Archive<'_>, which: Option<usize>, out_dir: &Path) -> Result<ExtractReport> {
    let si = a.snapshot(which)?;
    let paths = checked_paths(&a.index.snapshots[si].entries)?;
    std::fs::create_dir_all(out_dir)
        .with_context(|| format!("cannot create {}", out_dir.display()))?;
    let mut rep = ExtractReport::default();
    let all: Vec<usize> = (0..paths.len()).collect();
    let mut failed = extract_some(a, si, &paths, out_dir, &all, &mut rep)?;
    if !failed.is_empty() && a.repair.is_none() && a.recovery.is_some() {
        let ok = a.apply_recovery().is_ok();
        if ok {
            let retry: Vec<usize> = failed.iter().map(|(i, _)| *i).collect();
            failed = extract_some(a, si, &paths, out_dir, &retry, &mut rep)?;
        }
    }
    let entries = &a.index.snapshots[si].entries;
    rep.failed = failed
        .into_iter()
        .map(|(i, m)| (entries[i].path.clone(), m))
        .collect();
    rep.repair = a.repair.clone();
    rep.notes = a.notes.clone();
    // Directory times last.
    for (e, p) in entries.iter().zip(&paths) {
        if e.kind == Kind::Dir
            && let (Some(t), Ok(d)) = (to_systime(e.mtime_ns), File::open(out_dir.join(p)))
        {
            let _ = d.set_modified(t);
        }
    }
    Ok(rep)
}

fn extract_some(
    a: &Archive<'_>,
    si: usize,
    paths: &[PathBuf],
    out_dir: &Path,
    which: &[usize],
    rep: &mut ExtractReport,
) -> Result<Vec<(usize, String)>> {
    let idx = &a.index;
    let entries = &idx.snapshots[si].entries;
    let cache = Cache {
        view: &a.view,
        keys: a.keys.as_ref(),
        blocks: &idx.blocks,
        slots: (0..idx.blocks.len()).map(|_| Mutex::default()).collect(),
    };
    for &i in which {
        if entries[i].kind != Kind::File {
            continue;
        }
        for c in entry_chunks(&entries[i]) {
            cache.slots[idx.chunks[c as usize].block as usize]
                .lock()
                .unwrap()
                .remaining += 1;
        }
    }
    // Directories (and parents) first, sequentially.
    for &i in which {
        let e = &entries[i];
        let dest = out_dir.join(&paths[i]);
        let dir = if e.kind == Kind::Dir {
            Some(dest.as_path())
        } else {
            dest.parent()
        };
        if let Some(d) = dir {
            std::fs::create_dir_all(d).with_context(|| format!("cannot create {}", d.display()))?;
        }
        if e.kind == Kind::Dir {
            rep.dirs += 1;
        }
    }
    let results: Vec<(usize, std::result::Result<Written, String>)> = which
        .par_iter()
        .filter(|&&i| entries[i].kind != Kind::Dir)
        .map(|&i| {
            let e = &entries[i];
            let dest = out_dir.join(&paths[i]);
            let r = match e.kind {
                // Links are restored as regular files holding the target.
                Kind::Symlink => std::fs::write(&dest, e.target.as_bytes())
                    .map(|_| Written {
                        bytes: 0,
                        streams: 0,
                        stream_errors: Vec::new(),
                    })
                    .map_err(|x| format!("write: {x}")),
                _ => write_file(&cache, idx, e, &dest),
            };
            (i, r)
        })
        .collect();
    let mut failed = Vec::new();
    for (i, r) in results {
        match r {
            Ok(w) => {
                rep.files += 1;
                rep.bytes += w.bytes;
                rep.streams += w.streams;
                for (name, m) in w.stream_errors {
                    rep.stream_errors
                        .push((format!("{}:{name}", entries[i].path), m));
                }
            }
            Err(m) => {
                let _ = std::fs::remove_file(out_dir.join(&paths[i]));
                failed.push((i, m));
            }
        }
    }
    Ok(failed)
}

// ------------------------------------------------------------ test / list

/// Result of `test`: sector check, then every block decoded and every
/// chunk hash compared.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TestReport {
    pub blocks: usize,
    pub bad_blocks: Vec<(usize, String)>,
    pub chunks: usize,
    pub bad_chunks: usize,
    pub repair: Option<RepairReport>,
    pub notes: Vec<String>,
}

impl TestReport {
    pub fn ok(&self) -> bool {
        self.bad_blocks.is_empty()
            && self.bad_chunks == 0
            && self.repair.as_ref().is_none_or(|r| r.ok())
    }
}

pub fn test(a: &mut Archive<'_>) -> Result<TestReport> {
    if a.recovery.is_some() || a.header.has_recovery() {
        let _ = a.apply_recovery();
    }
    let idx = &a.index;
    let keys = a.keys.as_ref();
    let mut by_block: Vec<Vec<usize>> = vec![Vec::new(); idx.blocks.len()];
    for (i, c) in idx.chunks.iter().enumerate() {
        by_block[c.block as usize].push(i);
    }
    let res: Vec<(usize, std::result::Result<usize, String>)> = idx
        .blocks
        .par_iter()
        .enumerate()
        .map(|(bi, b)| {
            let r = read_block(&a.view, keys, b).map(|raw| {
                by_block[bi]
                    .iter()
                    .filter(|&&ci| {
                        let c = idx.chunks[ci];
                        let piece = &raw[c.offset as usize..(c.offset + c.len) as usize];
                        crypto::content_hash(keys, piece) != c.hash
                    })
                    .count()
            });
            (bi, r.map_err(|e| format!("{e:#}")))
        })
        .collect();
    let mut rep = TestReport {
        blocks: idx.blocks.len(),
        chunks: idx.chunks.len(),
        ..Default::default()
    };
    for (bi, r) in res {
        match r {
            Ok(n) => rep.bad_chunks += n,
            Err(m) => rep.bad_blocks.push((bi, m)),
        }
    }
    rep.repair = a.repair.clone();
    rep.notes = a.notes.clone();
    Ok(rep)
}

/// Write the repaired archive bytes to `out`.
pub fn write_repaired(a: &Archive<'_>, out: &Path) -> Result<u64> {
    let mut f = std::io::BufWriter::new(File::create(out)?);
    let len = a.view.len();
    let mut off = 0u64;
    while off < len {
        let n = (len - off).min(8 << 20) as usize;
        let b = match a.view.read(off, n) {
            Ok(b) => b,
            Err(_) => {
                // Unrecoverable tail beyond the file: keep what exists.
                let mut b = vec![0u8; n];
                let got = a.view.src.read_at(off, &mut b)?;
                b.truncate(got);
                if got == 0 {
                    break;
                }
                b
            }
        };
        f.write_all(&b)?;
        off += b.len() as u64;
    }
    f.flush()?;
    Ok(off)
}
