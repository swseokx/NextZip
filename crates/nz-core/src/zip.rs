//! Standard ZIP (PKWARE APPNOTE 6.3) writer and parallel extractor.
//!
//! Writer: files are compressed in parallel (Rayon, file level plus 128 KiB
//! chunk level) and written strictly in input order, so the archive bytes
//! depend only on the input and the options. Methods 0 (Store) and 8
//! (Deflate), UTF-8 names (flag bit 11), Extended Timestamp extra (0x5455),
//! ZIP64 when sizes, offsets or entry counts require it.

use std::fs::File;
use std::io::{self, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Datelike, Local, TimeZone, Timelike};
use rayon::prelude::*;

use crate::deflate::{self, DEFAULT_CHUNK};
use crate::planner::{self, Plan};
use crate::walk::{self, Entry, Kind};

const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_EOCD64: u32 = 0x0606_4b50;
const SIG_LOC64: u32 = 0x0706_4b50;
const FLAG_UTF8: u16 = 1 << 11;
const MAX32: u64 = 0xFFFF_FFFF;
/// Files above this size are streamed in segments instead of read whole.
const BIG_FILE: u64 = 64 << 20;
/// Input bytes compressed per parallel batch (bounds memory use).
const BATCH_BYTES: u64 = 128 << 20;
/// Files of at most batch bytes / WHOLE_SPLIT are not split into chunks.
const WHOLE_SPLIT: u64 = 24;

/// ZIP writer options.
#[derive(Debug, Clone)]
pub struct ZipOptions {
    /// NextZip level 0..=9 (0 = store everything).
    pub level: u8,
    /// Raw libdeflate level override (1..=12).
    pub raw_level: Option<i32>,
    /// Intra-file chunk size for parallel Deflate.
    pub chunk: usize,
    /// Use the LZ4 sampling planner to store incompressible files.
    pub planner: bool,
    /// libdeflate level for non-text data (x86 executables and other binary
    /// files); None = the normal level.
    pub bin_level: Option<i32>,
}

impl Default for ZipOptions {
    fn default() -> Self {
        Self {
            level: 5,
            raw_level: None,
            chunk: DEFAULT_CHUNK,
            planner: true,
            bin_level: None,
        }
    }
}

impl ZipOptions {
    /// libdeflate level used for a NextZip level.
    pub fn deflate_level(&self) -> i32 {
        if let Some(l) = self.raw_level {
            return l.clamp(1, 12);
        }
        // libdeflate 1..12; NextZip 5 targets zlib -6 ratio at libdeflate speed.
        const MAP: [i32; 10] = [0, 1, 2, 4, 5, 6, 7, 8, 10, 12];
        MAP[self.level.min(9) as usize]
    }
}

impl ZipOptions {
    /// libdeflate level for [`Plan::Fast`] files.
    pub fn fast_level(&self) -> i32 {
        self.deflate_level().min(2)
    }

    /// libdeflate level for a file with the given plan. ZIP-family containers
    /// get level 1: on the M1 mixed set level 1 instead of 2 cut ZIP time
    /// about 10% for +0.05 pp (their members are already Deflate streams).
    fn plan_level(&self, plan: Plan, head: &[u8]) -> i32 {
        match plan {
            Plan::Fast if is_container(head) => self.fast_level().min(1),
            Plan::Fast => self.fast_level(),
            Plan::Compress if is_binary(head) => self
                .bin_level
                .map_or_else(|| self.deflate_level(), |l| l.clamp(1, 12)),
            _ => self.deflate_level(),
        }
    }
}

/// Summary of a write.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct WriteStats {
    pub files: usize,
    pub dirs: usize,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub stored_by_planner: usize,
}

struct Central {
    name: Vec<u8>,
    is_dir: bool,
    method: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    offset: u64,
    dos_time: u16,
    dos_date: u16,
    unix_mtime: u32,
}

struct Prepared {
    method: u16,
    crc: u32,
    usize: u64,
    data: Vec<u8>,
    planner_store: bool,
}

/// Create a ZIP archive at `out` from `entries`.
pub fn write_zip(entries: &[Entry], out: &Path, opt: &ZipOptions) -> Result<WriteStats> {
    let file = File::create(out).with_context(|| format!("cannot create {}", out.display()))?;
    let mut w = CountingWriter {
        inner: BufWriter::with_capacity(1 << 20, file),
        pos: 0,
    };
    let mut central: Vec<Central> = Vec::with_capacity(entries.len());
    let mut stats = WriteStats::default();

    // Split into batches of directories and small files (bounded by
    // BATCH_BYTES); a big file forms its own streamed step. Batch k+1 is
    // compressed while batch k is written.
    let mut steps: Vec<std::ops::Range<usize>> = Vec::new();
    let mut i = 0;
    while i < entries.len() {
        let start = i;
        if entries[i].kind == Kind::File && entries[i].size > BIG_FILE {
            steps.push(start..start + 1);
            i += 1;
            continue;
        }
        let mut bytes = 0u64;
        while i < entries.len()
            && !(entries[i].kind == Kind::File && entries[i].size > BIG_FILE)
            && (i == start || bytes + entries[i].size <= BATCH_BYTES)
        {
            bytes += entries[i].size;
            i += 1;
        }
        steps.push(start..i);
    }
    let is_big = |r: &std::ops::Range<usize>| {
        r.len() == 1 && entries[r.start].kind == Kind::File && entries[r.start].size > BIG_FILE
    };
    // Each batch is streamed: the Rayon pool compresses files in parallel
    // while a separate writer thread (outside the pool, so it costs no
    // compression worker) writes them in input order as soon as each one is
    // ready. M1: the whole 100 MB mixed set is one batch, and writing it only
    // after compressing cost ~10% of the run.
    for r in &steps {
        if is_big(r) {
            let c = write_big_file(&mut w, &entries[r.start], opt, &mut stats)?;
            central.push(c);
            continue;
        }
        let batch = &entries[r.clone()];
        // Files up to 1/24 of the batch are compressed as one Deflate stream:
        // file-level parallelism already fills the pool, and a single stream
        // needs no chunk splicing (block scan) and keeps its 32 KiB window.
        // A fixed divisor (not the thread count) keeps the output
        // independent of `-t`.
        let batch_bytes: u64 = batch.iter().map(|e| e.size).sum();
        let whole = usize::try_from(batch_bytes / WHOLE_SPLIT).unwrap_or(usize::MAX);
        let slots: Vec<std::sync::Mutex<Option<Result<Option<Prepared>>>>> =
            batch.iter().map(|_| std::sync::Mutex::new(None)).collect();
        let ready = std::sync::Mutex::new(());
        let cv = std::sync::Condvar::new();
        let (w_ref, central_ref, stats_ref) = (&mut w, &mut central, &mut stats);
        let t_batch = std::time::Instant::now();
        let written = std::thread::scope(|s| {
            let writer = s.spawn(|| -> Result<()> {
                let mut result = Ok(());
                for (i, e) in batch.iter().enumerate() {
                    let p = {
                        let mut g = ready.lock().expect("ready lock");
                        loop {
                            if let Some(p) = slots[i].lock().expect("slot lock").take() {
                                break p;
                            }
                            g = cv.wait(g).expect("ready wait");
                        }
                    };
                    if result.is_ok() {
                        result = write_prepared(w_ref, e, p, central_ref, stats_ref);
                    }
                }
                result
            });
            // Largest files first (longest jobs), so none is left running alone
            // at the end; the writer still emits input order.
            let mut order: Vec<usize> = (0..batch.len()).collect();
            order.sort_by_key(|&i| std::cmp::Reverse(batch[i].size));
            order.par_iter().with_max_len(1).for_each(|&i| {
                let e = &batch[i];
                let p = if e.kind == Kind::Dir {
                    Ok(None)
                } else {
                    prepare(e, opt, whole).map(Some)
                };
                *slots[i].lock().expect("slot lock") = Some(p);
                let _g = ready.lock().expect("ready lock");
                cv.notify_all();
            });
            crate::trace(&format!(
                "batch {} entries compressed at {:.1} ms",
                batch.len(),
                t_batch.elapsed().as_secs_f64() * 1e3
            ));
            let r = writer.join().expect("zip writer thread panicked");
            crate::trace(&format!(
                "batch written at {:.1} ms",
                t_batch.elapsed().as_secs_f64() * 1e3
            ));
            r
        });
        written?;
    }

    let t0 = std::time::Instant::now();
    write_central(&mut w, &central)?;
    w.inner.flush()?;
    crate::trace(&format!(
        "central+flush {:.1} ms",
        t0.elapsed().as_secs_f64() * 1e3
    ));
    stats.output_bytes = w.pos;
    Ok(stats)
}

/// Write one prepared entry (local header + data) and record it.
fn write_prepared<W: Write>(
    w: &mut CountingWriter<W>,
    e: &Entry,
    p: Result<Option<Prepared>>,
    central: &mut Vec<Central>,
    stats: &mut WriteStats,
) -> Result<()> {
    let (t, d) = dos_datetime(e.mtime);
    let offset = w.pos;
    let Some(p) = p? else {
        let name = format!("{}/", e.name).into_bytes();
        write_local(w, &name, 0, 0, 0, 0, t, d, unix_time(e.mtime), false)?;
        central.push(Central {
            name,
            is_dir: true,
            method: 0,
            crc: 0,
            csize: 0,
            usize: 0,
            offset,
            dos_time: t,
            dos_date: d,
            unix_mtime: unix_time(e.mtime),
        });
        stats.dirs += 1;
        return Ok(());
    };
    let name = e.name.clone().into_bytes();
    let csize = p.data.len() as u64;
    let z64 = p.usize >= MAX32 || csize >= MAX32;
    write_local(
        w,
        &name,
        p.method,
        p.crc,
        csize,
        p.usize,
        t,
        d,
        unix_time(e.mtime),
        z64,
    )?;
    w.write_all(&p.data)?;
    stats.files += 1;
    stats.input_bytes += p.usize;
    stats.stored_by_planner += usize::from(p.planner_store);
    central.push(Central {
        name,
        is_dir: false,
        method: p.method,
        crc: p.crc,
        csize,
        usize: p.usize,
        offset,
        dos_time: t,
        dos_date: d,
        unix_mtime: unix_time(e.mtime),
    });
    Ok(())
}

/// Non-text data: x86 executables, or a head sample that fails the text test.
fn is_binary(head: &[u8]) -> bool {
    planner::is_x86_exec(head) || !planner::is_text(&head[..head.len().min(4096)])
}

/// A ZIP-family container (JAR, ZIP, APK, OOXML) starts with a local header.
fn is_container(head: &[u8]) -> bool {
    head.starts_with(b"PK\x03\x04")
}

/// ZIP-family containers (JAR, ZIP, APK, OOXML) hold Deflate streams that a
/// higher level barely shrinks (M1 mixed set: 53 MB of JAR/ZIP), so they get
/// the fast level like other mostly-compressed data.
fn container_plan(head: &[u8], plan: Plan, opt: &ZipOptions) -> Plan {
    if opt.planner && plan == Plan::Compress && is_container(head) {
        Plan::Fast
    } else {
        plan
    }
}

fn prepare(e: &Entry, opt: &ZipOptions, whole: usize) -> Result<Prepared> {
    let data =
        std::fs::read(&e.path).with_context(|| format!("cannot read {}", e.path.display()))?;
    let usize = data.len() as u64;
    let plan = if opt.planner {
        planner::plan(&data)
    } else {
        Plan::Compress
    };
    let plan = container_plan(&data, plan, opt);
    let planner_store = plan == Plan::Store;
    if opt.level == 0 || planner_store || data.is_empty() {
        let crc = crc32fast::hash(&data);
        return Ok(Prepared {
            method: 0,
            crc,
            usize,
            data,
            planner_store,
        });
    }
    let level = opt.plan_level(plan, &data);
    let chunk = if data.len() <= whole {
        data.len()
    } else {
        opt.chunk
    };
    // ZIP-family containers: own encoder for headers and member data,
    // libdeflate (normal level) for larger stored members and the central
    // directory. M1 mixed set: JAR/ZIP CPU 405 -> 140 ms single-threaded.
    let d = if plan == Plan::Fast && is_container(&data) {
        deflate::deflate_container(&data, opt.deflate_level(), opt.chunk, data.len() > whole)?
    } else {
        deflate::deflate_parallel(&data, level, chunk)?
    };
    if d.data.len() >= data.len() {
        return Ok(Prepared {
            method: 0,
            crc: d.crc32,
            usize,
            data,
            planner_store: false,
        });
    }
    Ok(Prepared {
        method: 8,
        crc: d.crc32,
        usize,
        data: d.data,
        planner_store: false,
    })
}

fn read_full(f: &mut File, buf: &mut Vec<u8>, want: usize) -> io::Result<()> {
    buf.clear();
    f.take(want as u64).read_to_end(buf)?;
    Ok(())
}

/// Stream a large file in segments; the local header is patched afterwards.
fn write_big_file<W: Write + Seek>(
    w: &mut CountingWriter<W>,
    e: &Entry,
    opt: &ZipOptions,
    stats: &mut WriteStats,
) -> Result<Central> {
    let mut f = File::open(&e.path).with_context(|| format!("cannot open {}", e.path.display()))?;
    let chunk = opt.chunk.max(4096);
    let seg_len = chunk * 64;
    let mut cur = Vec::with_capacity(seg_len);
    let mut next = Vec::with_capacity(seg_len);
    read_full(&mut f, &mut cur, seg_len)?;
    let plan = if opt.planner {
        planner::plan_path(&e.path, e.size)
    } else {
        Plan::Compress
    };
    let plan = container_plan(&cur, plan, opt);
    let store = opt.level == 0 || plan == Plan::Store;
    let method: u16 = if store { 0 } else { 8 };
    let (t, d) = dos_datetime(e.mtime);
    let name = e.name.clone().into_bytes();
    let offset = w.pos;
    let z64 = e.size >= MAX32 - (MAX32 >> 6);
    write_local(w, &name, method, 0, 0, 0, t, d, unix_time(e.mtime), z64)?;
    let data_start = w.pos;
    let mut crc = crc32fast::Hasher::new();
    let mut usize = 0u64;
    let level = opt.plan_level(plan, &cur);
    loop {
        read_full(&mut f, &mut next, seg_len)?;
        let last_seg = next.is_empty();
        usize += cur.len() as u64;
        if store {
            crc.update(&cur);
            w.write_all(&cur)?;
        } else {
            let n = cur.len().div_ceil(chunk).max(1);
            let parts: Vec<Result<(Vec<u8>, u32, usize)>> = if cur.is_empty() {
                vec![deflate::deflate_chunk(level, &[], true).map(|c| (c, 0, 0))]
            } else {
                cur.par_chunks(chunk)
                    .enumerate()
                    .map(|(i, p)| {
                        let c = deflate::deflate_chunk(level, p, last_seg && i + 1 == n)?;
                        Ok((c, crc32fast::hash(p), p.len()))
                    })
                    .collect()
            };
            for p in parts {
                let (c, h, len) = p?;
                crc.combine(&crc32fast::Hasher::new_with_initial_len(h, len as u64));
                w.write_all(&c)?;
            }
        }
        if last_seg {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
    }
    let csize = w.pos - data_start;
    let crc = crc.finalize();
    if !z64 && (usize >= MAX32 || csize >= MAX32) {
        bail!("{}: file grew past 4 GiB while archiving", e.path.display());
    }
    // Patch CRC and sizes in the local header.
    let end = w.pos;
    let hdr_crc = offset + 14;
    w.inner.seek(SeekFrom::Start(hdr_crc))?;
    w.inner.write_all(&crc.to_le_bytes())?;
    if z64 {
        let extra = offset + 30 + name.len() as u64 + 4;
        w.inner.seek(SeekFrom::Start(extra))?;
        w.inner.write_all(&usize.to_le_bytes())?;
        w.inner.write_all(&csize.to_le_bytes())?;
    } else {
        w.inner.write_all(&(csize as u32).to_le_bytes())?;
        w.inner.write_all(&(usize as u32).to_le_bytes())?;
    }
    w.inner.seek(SeekFrom::Start(end))?;
    stats.files += 1;
    stats.input_bytes += usize;
    stats.stored_by_planner += usize::from(store && opt.level != 0);
    Ok(Central {
        name,
        is_dir: false,
        method,
        crc,
        csize,
        usize,
        offset,
        dos_time: t,
        dos_date: d,
        unix_mtime: unix_time(e.mtime),
    })
}

struct CountingWriter<W: Write> {
    inner: W,
    pos: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn put16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn put64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn timestamp_extra(v: &mut Vec<u8>, mtime: u32) {
    put16(v, 0x5455);
    put16(v, 5);
    v.push(1);
    put32(v, mtime);
}

#[allow(clippy::too_many_arguments)]
fn write_local<W: Write>(
    w: &mut W,
    name: &[u8],
    method: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    t: u16,
    d: u16,
    mtime: u32,
    zip64: bool,
) -> io::Result<()> {
    let mut extra = Vec::with_capacity(32);
    if zip64 {
        put16(&mut extra, 0x0001);
        put16(&mut extra, 16);
        put64(&mut extra, usize);
        put64(&mut extra, csize);
    }
    timestamp_extra(&mut extra, mtime);
    let mut h = Vec::with_capacity(30 + name.len() + extra.len());
    put32(&mut h, SIG_LOCAL);
    put16(&mut h, if zip64 { 45 } else { 20 });
    put16(&mut h, FLAG_UTF8);
    put16(&mut h, method);
    put16(&mut h, t);
    put16(&mut h, d);
    put32(&mut h, crc);
    put32(&mut h, if zip64 { u32::MAX } else { csize as u32 });
    put32(&mut h, if zip64 { u32::MAX } else { usize as u32 });
    put16(&mut h, name.len() as u16);
    put16(&mut h, extra.len() as u16);
    h.extend_from_slice(name);
    h.extend_from_slice(&extra);
    w.write_all(&h)
}

fn write_central<W: Write>(w: &mut CountingWriter<W>, cd: &[Central]) -> io::Result<()> {
    let cd_start = w.pos;
    let mut buf = Vec::with_capacity(cd.len() * 80);
    for c in cd {
        let need_u = c.usize >= MAX32;
        let need_c = c.csize >= MAX32;
        let need_o = c.offset >= MAX32;
        let mut extra = Vec::new();
        if need_u || need_c || need_o {
            let mut z = Vec::new();
            if need_u {
                put64(&mut z, c.usize);
            }
            if need_c {
                put64(&mut z, c.csize);
            }
            if need_o {
                put64(&mut z, c.offset);
            }
            put16(&mut extra, 0x0001);
            put16(&mut extra, z.len() as u16);
            extra.extend_from_slice(&z);
        }
        timestamp_extra(&mut extra, c.unix_mtime);
        let z64 = !extra.is_empty() && (need_u || need_c || need_o);
        put32(&mut buf, SIG_CENTRAL);
        put16(&mut buf, 0x003F); // made by: MS-DOS/FAT attributes, spec 6.3
        put16(&mut buf, if z64 { 45 } else { 20 });
        put16(&mut buf, FLAG_UTF8);
        put16(&mut buf, c.method);
        put16(&mut buf, c.dos_time);
        put16(&mut buf, c.dos_date);
        put32(&mut buf, c.crc);
        put32(&mut buf, if need_c { u32::MAX } else { c.csize as u32 });
        put32(&mut buf, if need_u { u32::MAX } else { c.usize as u32 });
        put16(&mut buf, c.name.len() as u16);
        put16(&mut buf, extra.len() as u16);
        put16(&mut buf, 0); // comment
        put16(&mut buf, 0); // disk
        put16(&mut buf, 0); // internal attrs
        put32(&mut buf, if c.is_dir { 0x10 } else { 0x20 });
        put32(&mut buf, if need_o { u32::MAX } else { c.offset as u32 });
        buf.extend_from_slice(&c.name);
        buf.extend_from_slice(&extra);
    }
    w.write_all(&buf)?;
    let cd_size = w.pos - cd_start;
    let n = cd.len() as u64;
    let mut tail = Vec::with_capacity(98);
    let z64 = n >= 0xFFFF || cd_size >= MAX32 || cd_start >= MAX32;
    if z64 {
        let eocd64 = w.pos;
        put32(&mut tail, SIG_EOCD64);
        put64(&mut tail, 44);
        put16(&mut tail, 45);
        put16(&mut tail, 45);
        put32(&mut tail, 0);
        put32(&mut tail, 0);
        put64(&mut tail, n);
        put64(&mut tail, n);
        put64(&mut tail, cd_size);
        put64(&mut tail, cd_start);
        put32(&mut tail, SIG_LOC64);
        put32(&mut tail, 0);
        put64(&mut tail, eocd64);
        put32(&mut tail, 1);
    }
    put32(&mut tail, SIG_EOCD);
    put16(&mut tail, 0);
    put16(&mut tail, 0);
    put16(&mut tail, if z64 { 0xFFFF } else { n as u16 });
    put16(&mut tail, if z64 { 0xFFFF } else { n as u16 });
    put32(&mut tail, if z64 { u32::MAX } else { cd_size as u32 });
    put32(&mut tail, if z64 { u32::MAX } else { cd_start as u32 });
    put16(&mut tail, 0);
    w.write_all(&tail)
}

fn unix_time(t: SystemTime) -> u32 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().min(u64::from(u32::MAX)) as u32)
        .unwrap_or(0)
}

/// MS-DOS time and date in local time, clamped to 1980..=2107.
fn dos_datetime(t: SystemTime) -> (u16, u16) {
    let dt: DateTime<Local> = t.into();
    let year = dt.year();
    if year < 1980 {
        return (0, (1 << 5) | 1);
    }
    if year > 2107 {
        return ((23 << 11) | (59 << 5) | 29, (127 << 9) | (12 << 5) | 31);
    }
    let time = ((dt.hour() << 11) | (dt.minute() << 5) | (dt.second() / 2)) as u16;
    let date = ((((year - 1980) as u32) << 9) | (dt.month() << 5) | dt.day()) as u16;
    (time, date)
}

fn dos_to_system(time: u16, date: u16) -> Option<SystemTime> {
    let y = 1980 + i32::from(date >> 9);
    let mo = u32::from((date >> 5) & 15);
    let d = u32::from(date & 31);
    let h = u32::from(time >> 11);
    let mi = u32::from((time >> 5) & 63);
    let s = u32::from(time & 31) * 2;
    let dt = Local.with_ymd_and_hms(y, mo, d, h, mi, s).earliest()?;
    Some(dt.into())
}

// ---------------------------------------------------------------- reading

/// One member as described by the central directory.
#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub is_dir: bool,
    pub method: u16,
    pub crc: u32,
    pub csize: u64,
    pub usize: u64,
    pub local_offset: u64,
    pub mtime: Option<SystemTime>,
    /// General purpose flags (bit 0: encrypted, bit 11: UTF-8 name).
    pub flags: u16,
    /// Name bytes exactly as stored in the central directory.
    pub raw_name: Vec<u8>,
    /// True when `name` was decoded as CP437 because neither the UTF-8 flag
    /// nor a valid 0x7075 Unicode Path field was present; callers may then
    /// re-decode `raw_name` with a detected code page.
    pub legacy_name: bool,
}

fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().expect("4 bytes"))
}
fn le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"))
}

/// Positional read that does not move a shared cursor (safe across threads).
pub fn read_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let mut done = 0;
        while done < buf.len() {
            let n = f.seek_read(&mut buf[done..], off + done as u64)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            done += n;
        }
        Ok(())
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.read_exact_at(buf, off)
    }
}

/// Parse the central directory.
pub fn read_central(f: &File) -> Result<Vec<ZipEntry>> {
    let len = f.metadata()?.len();
    let tail_len = len.min(65_557) as usize;
    let mut tail = vec![0u8; tail_len];
    read_at(f, &mut tail, len - tail_len as u64)?;
    let eocd = (0..tail_len.saturating_sub(21))
        .rev()
        .find(|&i| le32(&tail, i) == SIG_EOCD)
        .context("not a ZIP archive (no end of central directory)")?;
    let mut count = u64::from(le16(&tail, eocd + 10));
    let mut cd_size = u64::from(le32(&tail, eocd + 12));
    let mut cd_off = u64::from(le32(&tail, eocd + 16));
    if eocd >= 20 && le32(&tail, eocd - 20) == SIG_LOC64 {
        let off64 = le64(&tail, eocd - 20 + 8);
        let mut rec = [0u8; 56];
        read_at(f, &mut rec, off64)?;
        if le32(&rec, 0) != SIG_EOCD64 {
            bail!("bad ZIP64 end of central directory");
        }
        count = le64(&rec, 32);
        cd_size = le64(&rec, 40);
        cd_off = le64(&rec, 48);
    }
    // Sizes come from the file: check them against its length before
    // allocating (a forged EOCD asked for a 4 GB buffer under fuzzing).
    if cd_off.checked_add(cd_size).is_none_or(|end| end > len) {
        bail!("corrupt central directory (outside the file)");
    }
    let mut cd = vec![0u8; cd_size as usize];
    read_at(f, &mut cd, cd_off)?;
    // Each central record is at least 46 bytes.
    let mut out = Vec::with_capacity(count.min(cd_size / 46) as usize);
    let mut p = 0usize;
    for _ in 0..count {
        if p + 46 > cd.len() || le32(&cd, p) != SIG_CENTRAL {
            bail!("corrupt central directory");
        }
        let flags = le16(&cd, p + 8);
        let method = le16(&cd, p + 10);
        let time = le16(&cd, p + 12);
        let date = le16(&cd, p + 14);
        let crc = le32(&cd, p + 16);
        let mut csize = u64::from(le32(&cd, p + 20));
        let mut usize = u64::from(le32(&cd, p + 24));
        let nlen = le16(&cd, p + 28) as usize;
        let xlen = le16(&cd, p + 30) as usize;
        let clen = le16(&cd, p + 32) as usize;
        let attrs = le32(&cd, p + 38);
        let mut local = u64::from(le32(&cd, p + 42));
        let end = p + 46 + nlen + xlen + clen;
        if end > cd.len() {
            bail!("corrupt central directory entry");
        }
        let raw_name = &cd[p + 46..p + 46 + nlen];
        let mut legacy_name = flags & FLAG_UTF8 == 0;
        let mut name = if flags & FLAG_UTF8 != 0 {
            String::from_utf8_lossy(raw_name).into_owned()
        } else {
            // Legacy names are CP437 per APPNOTE. Writers that use a local code
            // page (e.g. CP949) add a 0x7075 Unicode Path field, below.
            raw_name.iter().map(|&b| cp437(b)).collect()
        };
        let mut mtime = dos_to_system(time, date);
        let extra = &cd[p + 46 + nlen..p + 46 + nlen + xlen];
        let mut x = 0;
        while x + 4 <= extra.len() {
            let id = le16(extra, x);
            let sz = le16(extra, x + 2) as usize;
            let body = &extra[x + 4..(x + 4 + sz).min(extra.len())];
            if id == 0x0001 {
                let mut q = 0;
                if usize == MAX32 && q + 8 <= body.len() {
                    usize = le64(body, q);
                    q += 8;
                }
                if csize == MAX32 && q + 8 <= body.len() {
                    csize = le64(body, q);
                    q += 8;
                }
                if local == MAX32 && q + 8 <= body.len() {
                    local = le64(body, q);
                }
            } else if id == 0x7075 && body.len() >= 5 && body[0] == 1 {
                // Info-ZIP Unicode Path: valid only if it matches the header name.
                if le32(body, 1) == crc32fast::hash(raw_name)
                    && let Ok(u) = std::str::from_utf8(&body[5..])
                {
                    name = u.to_string();
                    legacy_name = false;
                }
            } else if id == 0x5455 && body.len() >= 5 && body[0] & 1 != 0 {
                mtime = Some(UNIX_EPOCH + Duration::from_secs(u64::from(le32(body, 1))));
            }
            x += 4 + sz;
        }
        let is_dir = name.ends_with('/') || name.ends_with('\\') || attrs & 0x10 != 0 && usize == 0;
        out.push(ZipEntry {
            name,
            is_dir,
            method,
            crc,
            csize,
            usize,
            local_offset: local,
            mtime,
            flags,
            raw_name: raw_name.to_vec(),
            legacy_name,
        });
        p = end;
    }
    Ok(out)
}

/// IBM PC code page 437, the APPNOTE default for names without flag bit 11.
fn cp437(b: u8) -> char {
    const HIGH: [char; 128] = [
        'Ç', 'ü', 'é', 'â', 'ä', 'à', 'å', 'ç', 'ê', 'ë', 'è', 'ï', 'î', 'ì', 'Ä', 'Å', //
        'É', 'æ', 'Æ', 'ô', 'ö', 'ò', 'û', 'ù', 'ÿ', 'Ö', 'Ü', '¢', '£', '¥', '₧', 'ƒ', //
        'á', 'í', 'ó', 'ú', 'ñ', 'Ñ', 'ª', 'º', '¿', '⌐', '¬', '½', '¼', '¡', '«', '»', //
        '░', '▒', '▓', '│', '┤', '╡', '╢', '╖', '╕', '╣', '║', '╗', '╝', '╜', '╛', '┐', //
        '└', '┴', '┬', '├', '─', '┼', '╞', '╟', '╚', '╔', '╩', '╦', '╠', '═', '╬', '╧', //
        '╨', '╤', '╥', '╙', '╘', '╒', '╓', '╫', '╪', '┘', '┌', '█', '▄', '▌', '▐', '▀', //
        'α', 'ß', 'Γ', 'π', 'Σ', 'σ', 'µ', 'τ', 'Φ', 'Θ', 'Ω', 'δ', '∞', 'φ', 'ε', '∩', //
        '≡', '±', '≥', '≤', '⌠', '⌡', '÷', '≈', '°', '∙', '·', '√', 'ⁿ', '²', '■', '\u{a0}',
    ];
    if b < 0x80 {
        char::from(b)
    } else {
        HIGH[usize::from(b - 0x80)]
    }
}

/// Read and decompress one member's bytes, verifying the CRC.
pub fn read_entry(f: &File, e: &ZipEntry) -> Result<Vec<u8>> {
    let mut lh = [0u8; 30];
    read_at(f, &mut lh, e.local_offset)?;
    if le32(&lh, 0) != SIG_LOCAL {
        bail!("{}: bad local header", e.name);
    }
    let data_off = e.local_offset + 30 + u64::from(le16(&lh, 26)) + u64::from(le16(&lh, 28));
    let mut comp = vec![0u8; e.csize as usize];
    read_at(f, &mut comp, data_off)?;
    let data = match e.method {
        0 => comp,
        8 => deflate::inflate_exact(&comp, e.usize as usize)?,
        m => bail!("{}: unsupported compression method {m}", e.name),
    };
    if crc32fast::hash(&data) != e.crc {
        bail!("{}: CRC mismatch", e.name);
    }
    Ok(data)
}

/// Summary of an extraction.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ExtractStats {
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
}

/// Per-phase CPU time (decode, create, write, close) in microseconds, summed
/// over all extraction threads; printed with `NZ_TRACE=1`. M0 showed that
/// extraction is file-system bound, so these counters stay for M1 work.
static TIMES: [std::sync::atomic::AtomicU64; 4] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 4];

/// Extract every member into `out_dir` in parallel.
pub fn extract_zip(archive: &Path, out_dir: &Path) -> Result<ExtractStats> {
    let f = File::open(archive).with_context(|| format!("cannot open {}", archive.display()))?;
    let entries = read_central(&f)?;
    let t_dirs = std::time::Instant::now();
    std::fs::create_dir_all(out_dir)?;
    let mut stats = ExtractStats::default();
    // Create every directory once up front (explicit entries and implied
    // parents), so the parallel phase only creates files.
    let mut dirs = std::collections::BTreeSet::new();
    for e in &entries {
        let rel =
            walk::safe_relative(&e.name).with_context(|| format!("unsafe path {}", e.name))?;
        if e.is_dir {
            stats.dirs += 1;
            dirs.insert(rel);
        } else if let Some(parent) = rel.parent().filter(|p| !p.as_os_str().is_empty()) {
            dirs.insert(parent.to_path_buf());
        }
    }
    // BTreeSet order puts parents before children; leaves suffice for create_dir_all.
    let dirs: Vec<_> = dirs.into_iter().collect();
    let leaves: Vec<_> = dirs
        .iter()
        .enumerate()
        .filter(|(i, d)| dirs.get(i + 1).is_none_or(|n| !n.starts_with(d)))
        .map(|(_, d)| out_dir.join(d))
        .collect();
    leaves.par_iter().try_for_each(std::fs::create_dir_all)?;
    crate::trace(&format!(
        "extract dirs created {} ms",
        t_dirs.elapsed().as_millis()
    ));
    let files: Vec<&ZipEntry> = entries.iter().filter(|e| !e.is_dir).collect();
    let bytes: Result<Vec<u64>> = files
        .par_iter()
        .map(|e| {
            let rel =
                walk::safe_relative(&e.name).with_context(|| format!("unsafe path {}", e.name))?;
            let dest = out_dir.join(rel);
            let t0 = std::time::Instant::now();
            let data = read_entry(&f, e)?;
            let t1 = std::time::Instant::now();
            let out =
                File::create(&dest).with_context(|| format!("cannot create {}", dest.display()))?;
            let t2 = std::time::Instant::now();
            if data.len() > 64 * 1024 {
                out.set_len(data.len() as u64)?;
            }
            (&out).write_all(&data)?;
            if let Some(t) = e.mtime {
                let _ = out.set_modified(t);
            }
            let t3 = std::time::Instant::now();
            drop(out);
            let t4 = std::time::Instant::now();
            for (slot, d) in TIMES.iter().zip([t1 - t0, t2 - t1, t3 - t2, t4 - t3]) {
                slot.fetch_add(d.as_micros() as u64, std::sync::atomic::Ordering::Relaxed);
            }
            Ok(data.len() as u64)
        })
        .collect();
    let bytes = bytes?;
    crate::trace(&format!(
        "extract cpu-ms: decode {} create {} write {} close {}",
        TIMES[0].load(std::sync::atomic::Ordering::Relaxed) / 1000,
        TIMES[1].load(std::sync::atomic::Ordering::Relaxed) / 1000,
        TIMES[2].load(std::sync::atomic::Ordering::Relaxed) / 1000,
        TIMES[3].load(std::sync::atomic::Ordering::Relaxed) / 1000
    ));
    stats.files = bytes.len();
    stats.bytes = bytes.iter().sum();
    // Directory mtimes are restored last so file creation does not bump them.
    for e in entries.iter().filter(|e| e.is_dir) {
        if let (Some(t), Some(rel)) = (e.mtime, walk::safe_relative(&e.name))
            && let Ok(d) = File::open(out_dir.join(rel))
        {
            let _ = d.set_modified(t);
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A forged end-of-central-directory record that claims a ~4 GB central
    /// directory must be rejected before anything is allocated (fuzz OOM).
    #[test]
    fn rejects_central_directory_outside_file() {
        let mut z = vec![0u8; 64];
        z.extend_from_slice(&SIG_EOCD.to_le_bytes());
        z.extend_from_slice(&[0, 0, 0, 0]); // disk numbers
        z.extend_from_slice(&0xa753u16.to_le_bytes()); // entries on disk
        z.extend_from_slice(&0xa753u16.to_le_bytes()); // entries
        z.extend_from_slice(&0xec85_0a14u32.to_le_bytes()); // cd size
        z.extend_from_slice(&10u32.to_le_bytes()); // cd offset
        z.extend_from_slice(&[0, 0]);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("forged.zip");
        std::fs::write(&p, &z).unwrap();
        let err = read_central(&File::open(&p).unwrap()).unwrap_err();
        assert!(err.to_string().contains("outside the file"), "{err}");
    }

    #[test]
    fn dos_time_roundtrip() {
        let t = Local.with_ymd_and_hms(2026, 11, 19, 13, 37, 42).unwrap();
        let (tm, dt) = dos_datetime(t.into());
        let back: DateTime<Local> = dos_to_system(tm, dt).unwrap().into();
        assert_eq!(back, t);
        assert_eq!(dos_datetime(UNIX_EPOCH), (0, 33));
    }

    #[test]
    fn level_map_is_monotonic() {
        let mut prev = -1;
        for l in 0..=9 {
            let o = ZipOptions {
                level: l,
                ..Default::default()
            };
            assert!(o.deflate_level() >= prev);
            prev = o.deflate_level();
        }
    }
}
