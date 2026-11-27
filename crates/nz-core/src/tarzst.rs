//! tar.zst writer (multithreaded zstd); the tar layer and the reader are
//! shared with the other tar formats in [`crate::tarfam`].
//!
//! Layout: the tar stream is split into at most two zstd frames. Frame 1
//! holds all directories and the files the planner considers compressible,
//! compressed at the requested level. Frame 2 holds files that look mostly or
//! fully compressed already ([`Plan::Fast`], [`Plan::Store`]), encoded at a
//! fast level so little time is spent on them.
//! Concatenated frames are a valid zstd stream (`zstd -d`, `tar --zstd`).
//!
//! 1.0 (K6): every frame is further cut after [`FRAME_BYTES`] of tar stream,
//! so a large archive is a series of independent frames that the reader
//! decodes in parallel ([`crate::tarfam`]). The cut points depend only on the
//! tar stream, never on the thread count.
//!
//! zstd multithreading (`nbWorkers >= 1`) produces identical bytes for any
//! worker count, so the archive does not depend on the thread count.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};
use rayon::prelude::*;

use crate::planner::{self, Plan};
use crate::tarfam::{self, TarStream};
use crate::walk::{Entry, Item, Kind};
use crate::zip::{ExtractStats, WriteStats};

/// tar.zst options.
#[derive(Debug, Clone)]
pub struct ZstdOptions {
    /// NextZip level 1..=9.
    pub level: u8,
    /// Raw zstd level override (1..=22).
    pub raw_level: Option<i32>,
    /// Long-distance matching window log (0 = off).
    pub window_log: u32,
    /// zstd worker threads (>= 1).
    pub workers: u32,
    /// Put incompressible files into a fast second frame.
    pub planner: bool,
    /// zstd MT job size in MiB (0 = zstd default for the level).
    pub job_mib: u32,
    /// zstd MT overlap log 1..=9 (0 = level default).
    pub overlap_log: u32,
    /// Order compressible files by extension (7-Zip style) for better ratio.
    pub sort_by_ext: bool,
    /// Uncompressed tar bytes per independent frame ([`FRAME_BYTES`]).
    pub frame_bytes: u64,
}

impl Default for ZstdOptions {
    fn default() -> Self {
        Self {
            level: 5,
            raw_level: None,
            window_log: 0,
            workers: default_threads() as u32,
            planner: true,
            job_mib: 0,
            overlap_log: 0,
            sort_by_ext: true,
            frame_bytes: FRAME_BYTES,
        }
    }
}

/// Number of logical CPUs over all processor groups (see [`crate::cpu`]).
pub fn default_threads() -> usize {
    crate::cpu::logical_cpus()
}

impl ZstdOptions {
    /// zstd level used for a NextZip level.
    pub fn zstd_level(&self) -> i32 {
        if let Some(l) = self.raw_level {
            return l.clamp(1, 22);
        }
        // M0: level 5 = zstd 9 (zstd 12 buys 0.1 pp for +40% time on the
        // benchmark sets; 13..15 are slower than 16+ with tuned MT jobs).
        const MAP: [i32; 10] = [1, 1, 3, 5, 7, 9, 12, 16, 19, 22];
        MAP[self.level.min(9) as usize]
    }
}

impl ZstdOptions {
    /// zstd level for the frame holding already-compressed files.
    pub fn fast_level(&self) -> i32 {
        self.zstd_level().min(3)
    }
}

type Enc = zstd::stream::write::Encoder<'static, BufWriter<File>>;

/// Uncompressed tar bytes per zstd frame (independently decodable unit).
pub const FRAME_BYTES: u64 = 64 << 20;

struct FrameWriter {
    enc: Option<Enc>,
    opt: ZstdOptions,
    level: i32,
    /// Uncompressed bytes in the current frame.
    in_frame: u64,
}

impl FrameWriter {
    fn new(out: BufWriter<File>, level: i32, opt: &ZstdOptions) -> io::Result<Self> {
        Ok(Self {
            enc: Some(make_encoder(out, level, opt)?),
            opt: opt.clone(),
            level,
            in_frame: 0,
        })
    }
    fn next_frame(&mut self, level: i32) -> io::Result<()> {
        let out = self.enc.take().expect("encoder present").finish()?;
        self.enc = Some(make_encoder(out, level, &self.opt)?);
        self.level = level;
        self.in_frame = 0;
        Ok(())
    }
    fn finish(mut self) -> io::Result<BufWriter<File>> {
        self.enc.take().expect("encoder present").finish()
    }
}

impl Write for FrameWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let limit = self.opt.frame_bytes.max(1 << 16);
        if self.in_frame >= limit {
            self.next_frame(self.level)?;
        }
        let room = usize::try_from(limit - self.in_frame).unwrap_or(usize::MAX);
        let n = self
            .enc
            .as_mut()
            .expect("encoder present")
            .write(&buf[..buf.len().min(room)])?;
        self.in_frame += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.enc.as_mut().expect("encoder present").flush()
    }
}

fn make_encoder(out: BufWriter<File>, level: i32, opt: &ZstdOptions) -> io::Result<Enc> {
    let mut e = zstd::stream::write::Encoder::new(out, level)?;
    e.multithread(opt.workers.max(1))?;
    e.include_checksum(true)?;
    // zstd's default job size at high levels is 4x the window (32+ MiB),
    // which leaves 12 cores idle on typical inputs, and each job re-reads a
    // full window of overlap. M0 measurement on the text set: level 19 with
    // 2 MiB jobs and overlap log 6 runs 4x faster for +0.05 pp ratio.
    // Below 16 the default job (4x the window) would leave a 64 MiB frame
    // with only a few jobs; 4 MiB jobs keep 12+ workers busy per frame.
    let (job, ovl) = match (opt.job_mib, opt.overlap_log) {
        (0, 0) if level >= 16 => (2, 6),
        (0, o) => (4, o),
        other => other,
    };
    if job > 0 {
        e.set_parameter(zstd::stream::raw::CParameter::JobSize(job << 20))?;
    }
    if ovl > 0 {
        e.set_parameter(zstd::stream::raw::CParameter::OverlapSizeLog(ovl))?;
    }
    if opt.window_log > 0 {
        e.long_distance_matching(true)?;
        e.window_log(opt.window_log)?;
    }
    Ok(e)
}

/// Create a tar.zst archive.
pub fn write_tar_zst(entries: &[Entry], out: &Path, opt: &ZstdOptions) -> Result<WriteStats> {
    let items: Vec<Item> = entries
        .iter()
        .map(|e| Item {
            entry: e.clone(),
            link: None,
        })
        .collect();
    write_tar_zst_items(&items, out, opt)
}

/// Create a tar.zst archive from walk items (links included).
pub(crate) fn write_tar_zst_items(
    items: &[Item],
    out: &Path,
    opt: &ZstdOptions,
) -> Result<WriteStats> {
    // Plan in parallel: sample the head of every file.
    let plans: Vec<Plan> = items
        .par_iter()
        .map(|it| {
            let e = &it.entry;
            if !opt.planner || e.kind == Kind::Dir || it.link.is_some() {
                return Plan::Compress;
            }
            planner::plan_path(&e.path, e.size)
        })
        .collect();

    let file = File::create(out).with_context(|| format!("cannot create {}", out.display()))?;
    let mut fw = FrameWriter::new(
        BufWriter::with_capacity(1 << 20, file),
        opt.zstd_level(),
        opt,
    )?;
    let mut ts = TarStream::default();
    let compress: Vec<&Item> = items
        .iter()
        .zip(&plans)
        .filter(|(_, p)| **p == Plan::Compress)
        .map(|(it, _)| it)
        .collect();
    ts.members(&tarfam::ordered(compress, opt.sort_by_ext), &mut fw)?;
    // Fast tier first, then fully incompressible files, each in walk order.
    let fast: Vec<&Item> = [Plan::Fast, Plan::Store]
        .iter()
        .flat_map(|tier| {
            items
                .iter()
                .zip(&plans)
                .filter(move |(_, p)| *p == tier)
                .map(|(it, _)| it)
        })
        .collect();
    let mut stats = WriteStats::default();
    if !fast.is_empty() {
        fw.next_frame(opt.fast_level())?;
        ts.members(&fast, &mut fw)?;
        stats.stored_by_planner = fast.len();
    }
    ts.finish(&mut fw)?;
    let mut w = fw.finish()?;
    w.flush()?;
    stats.files = ts.files;
    stats.dirs = ts.dirs;
    stats.input_bytes = ts.bytes;
    stats.output_bytes = std::fs::metadata(out)?.len();
    Ok(stats)
}

/// Extract a tar.zst archive (any tar-family archive is accepted).
pub fn extract_tar_zst(archive: &Path, out_dir: &Path) -> Result<ExtractStats> {
    tarfam::extract_tar(archive, out_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_streams_are_cut_into_parallel_frames() {
        let src = tempfile::tempdir().unwrap();
        for i in 0..6u32 {
            let text: String = (0..40_000u32)
                .map(|j| {
                    format!(
                        "{i} {} {}
",
                        j % 101,
                        j / 7
                    )
                })
                .collect();
            std::fs::write(src.path().join(format!("f{i}.txt")), text).unwrap();
        }
        let entries = crate::walk::collect(&[src.path().to_path_buf()]).unwrap();
        let out = tempfile::tempdir().unwrap();
        let arc = out.path().join("a.tar.zst");
        let opt = ZstdOptions {
            frame_bytes: 256 << 10,
            workers: 3,
            ..Default::default()
        };
        write_tar_zst(&entries, &arc, &opt).unwrap();
        // Several frames, found from headers alone, cover the file exactly.
        let f = File::open(&arc).unwrap();
        let len = f.metadata().unwrap().len();
        let (mut off, mut frames) = (0, 0);
        while off < len {
            off += crate::parzst::frame_size_at(&f, off, len).unwrap();
            frames += 1;
        }
        assert_eq!(off, len);
        assert!(frames >= 6, "{frames} frames");
        // Same bytes for another worker count.
        let arc1 = out.path().join("b.tar.zst");
        write_tar_zst(&entries, &arc1, &ZstdOptions { workers: 1, ..opt }).unwrap();
        assert_eq!(std::fs::read(&arc).unwrap(), std::fs::read(&arc1).unwrap());
        // Round trip through the parallel decoder.
        let x = out.path().join("x");
        crate::pool(4)
            .unwrap()
            .install(|| extract_tar_zst(&arc, &x))
            .unwrap();
        let name = src.path().file_name().unwrap();
        let root = if x.join(name).is_dir() {
            x.join(name)
        } else {
            x.clone()
        };
        for i in 0..6u32 {
            let p = format!("f{i}.txt");
            assert_eq!(
                std::fs::read(root.join(&p)).unwrap(),
                std::fs::read(src.path().join(&p)).unwrap()
            );
        }
    }
}
