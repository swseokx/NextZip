//! Parallel decoding of multi-frame zstd streams (1.0 KPI K6).
//!
//! A zstd stream made of several frames (NextZip's tar.zst cuts a frame every
//! [`crate::tarzst::FRAME_BYTES`]) can be decoded frame by frame in parallel.
//! [`ParZstd`] is a `Read` over the decoded stream:
//!
//! * a scanner thread finds the frames by reading only their headers and
//!   block headers (3 bytes per block of at most 128 KiB) with positional
//!   reads, and queues the byte ranges in stream order;
//! * `workers` threads take ranges from that FIFO, read their frame with a
//!   positional read into a recycled buffer, and decode it into a bounded
//!   chunk channel of its own;
//! * the consumer reads the frames' channels in order.
//!
//! 1.0 measurement (2.1 GB file, 32 frames): a single reader thread that
//! copied frames out of a read buffer capped decoding at about 2.5 GB/s;
//! reading the frames in the workers removes that serial step. Chunk and
//! frame buffers are recycled because fresh pages fault in serially on
//! Windows.
//!
//! At most `inflight` frames are queued or decoding, which bounds memory to
//! about `inflight * (decoded frame + compressed frame)`. Workers take frames
//! in order, so the frame the consumer waits for always has a worker and the
//! bounded channels cannot deadlock.
//!
//! Anything that does not split well (a frame larger than
//! [`MAX_FRAME_BUFFER`], e.g. one huge frame written by another tool, or a
//! header the scanner does not understand) is handed from that offset to one
//! streaming decoder, so memory stays bounded and errors are reported by
//! zstd itself.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Condvar, Mutex};

use crate::zip::read_at;

/// Decoded bytes per chunk sent to the consumer.
const CHUNK: usize = 4 << 20;
/// Chunks a frame may buffer ahead of the consumer (covers a 64 MiB frame).
const CHUNKS_PER_FRAME: usize = 24;
/// Frames whose compressed size exceeds this are decoded as a stream.
pub const MAX_FRAME_BUFFER: u64 = 96 << 20;

const MAGIC: u32 = 0xFD2F_B528;

type Chunk = io::Result<Vec<u8>>;

/// One unit of work: a frame's byte range, or the rest of the stream.
enum Job {
    Frame(u64, usize),
    Tail(u64),
}

/// Pending jobs in stream order, and whether the scanner is done.
type Jobs = (VecDeque<(Job, SyncSender<Chunk>)>, bool);

struct Queue {
    file: File,
    jobs: Mutex<Jobs>,
    cv: Condvar,
    /// Decoded-chunk buffers handed back by the consumer.
    chunks: Mutex<Vec<Vec<u8>>>,
    /// Compressed-frame buffers handed back by the workers.
    frames: Mutex<Vec<Vec<u8>>>,
}

fn take(pool: &Mutex<Vec<Vec<u8>>>) -> Vec<u8> {
    pool.lock().expect("pool lock").pop().unwrap_or_default()
}

fn give(pool: &Mutex<Vec<Vec<u8>>>, v: Vec<u8>) {
    let mut p = pool.lock().expect("pool lock");
    if p.len() < 64 {
        p.push(v);
    }
}

/// Parallel multi-frame zstd decoder (see the module docs).
pub struct ParZstd {
    queue: Arc<Queue>,
    order: Receiver<Receiver<Chunk>>,
    cur: Option<Receiver<Chunk>>,
    buf: Vec<u8>,
    pos: usize,
}

impl ParZstd {
    /// Decode `file` (the zstd stream starts at offset 0) with `workers`
    /// threads and at most `inflight` frames in flight.
    pub fn new(file: File, workers: usize, inflight: usize) -> Self {
        let workers = workers.max(1);
        let inflight = inflight.max(1);
        let (order_tx, order_rx) = sync_channel::<Receiver<Chunk>>(inflight);
        let queue = Arc::new(Queue {
            file,
            jobs: Mutex::new((VecDeque::new(), false)),
            cv: Condvar::new(),
            chunks: Mutex::new(Vec::new()),
            frames: Mutex::new(Vec::new()),
        });
        for _ in 0..workers {
            let q = Arc::clone(&queue);
            std::thread::spawn(move || worker(&q));
        }
        let q = Arc::clone(&queue);
        std::thread::spawn(move || scanner(&order_tx, &q));
        Self {
            queue,
            order: order_rx,
            cur: None,
            buf: Vec::new(),
            pos: 0,
        }
    }
}

fn push(q: &Queue, job: Job, order: &SyncSender<Receiver<Chunk>>) -> bool {
    let (tx, rx) = sync_channel::<Chunk>(CHUNKS_PER_FRAME);
    // The bounded order channel is the in-flight limit: wait here first.
    if order.send(rx).is_err() {
        return false;
    }
    let mut g = q.jobs.lock().expect("queue lock");
    g.0.push_back((job, tx));
    q.cv.notify_one();
    true
}

fn close(q: &Queue) {
    let mut g = q.jobs.lock().expect("queue lock");
    g.1 = true;
    q.cv.notify_all();
}

/// Compressed size of the zstd (or skippable) frame at `off` of a `len`-byte
/// file, from its headers alone. None when the bytes there are not a
/// complete, well-formed frame.
pub fn frame_size_at(f: &File, off: u64, len: u64) -> Option<u64> {
    let need = |at: u64, buf: &mut [u8]| -> Option<()> {
        (at.checked_add(buf.len() as u64)? <= len).then_some(())?;
        read_at(f, buf, at).ok()
    };
    let mut b4 = [0u8; 4];
    need(off, &mut b4)?;
    let magic = u32::from_le_bytes(b4);
    if magic & 0xFFFF_FFF0 == 0x184D_2A50 {
        need(off + 4, &mut b4)?;
        let n = 8 + u64::from(u32::from_le_bytes(b4));
        return (off + n <= len).then_some(n);
    }
    if magic != MAGIC {
        return None;
    }
    let mut fhd = [0u8; 1];
    need(off + 4, &mut fhd)?;
    let fhd = fhd[0];
    let single = fhd & 0x20 != 0;
    let dict = [0u64, 1, 2, 4][usize::from(fhd & 3)];
    let fcs = match fhd >> 6 {
        0 => u64::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let checksum = if fhd & 4 != 0 { 4 } else { 0 };
    let mut pos = off + 5 + u64::from(!single) + dict + fcs;
    let mut bh = [0u8; 3];
    loop {
        need(pos, &mut bh)?;
        let h = u32::from(bh[0]) | u32::from(bh[1]) << 8 | u32::from(bh[2]) << 16;
        let size = u64::from(h >> 3);
        pos += 3 + match (h >> 1) & 3 {
            0 | 2 => size, // raw, compressed
            1 => 1,        // RLE
            _ => return None,
        };
        if h & 1 != 0 {
            break;
        }
    }
    let end = pos + checksum;
    (end <= len).then_some(end - off)
}

fn scanner(order: &SyncSender<Receiver<Chunk>>, q: &Queue) {
    let len = q.file.metadata().map_or(0, |m| m.len());
    let mut off = 0u64;
    while off < len {
        match frame_size_at(&q.file, off, len) {
            Some(n) if n <= MAX_FRAME_BUFFER => {
                if !push(q, Job::Frame(off, n as usize), order) {
                    break;
                }
                off += n;
            }
            // Oversized, malformed or truncated: one stream decoder takes
            // the rest and reports any error.
            _ => {
                push(q, Job::Tail(off), order);
                break;
            }
        }
    }
    close(q);
}

fn worker(q: &Queue) {
    loop {
        let (job, tx) = {
            let mut g = q.jobs.lock().expect("queue lock");
            loop {
                if let Some(j) = g.0.pop_front() {
                    break j;
                }
                if g.1 {
                    return;
                }
                g = q.cv.wait(g).expect("queue wait");
            }
        };
        match job {
            Job::Frame(off, n) => {
                let mut v = take(&q.frames);
                v.resize(n, 0);
                match read_at(&q.file, &mut v, off) {
                    Ok(()) => decode_into(&v[..], &tx, q),
                    Err(e) => {
                        let _ = tx.send(Err(e));
                    }
                }
                give(&q.frames, v);
            }
            Job::Tail(off) => {
                let r = q.file.try_clone().and_then(|mut f| {
                    f.seek(SeekFrom::Start(off))?;
                    Ok(f)
                });
                match r {
                    Ok(f) => decode_into(io::BufReader::with_capacity(1 << 20, f), &tx, q),
                    Err(e) => {
                        let _ = tx.send(Err(e));
                    }
                }
            }
        }
    }
}

/// Stream-decode `src` into `tx` in CHUNK pieces (errors are forwarded).
fn decode_into<R: Read>(src: R, tx: &SyncSender<Chunk>, q: &Queue) {
    let mut dec = match zstd::stream::read::Decoder::new(src) {
        Ok(d) => d,
        Err(e) => {
            let _ = tx.send(Err(e));
            return;
        }
    };
    if let Err(e) = dec.window_log_max(31) {
        let _ = tx.send(Err(e));
        return;
    }
    loop {
        let mut out = take(&q.chunks);
        out.resize(CHUNK, 0);
        let mut n = 0;
        while n < CHUNK {
            match dec.read(&mut out[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) => {
                    let _ = tx.send(Err(e));
                    return;
                }
            }
        }
        out.truncate(n);
        let last = n < CHUNK;
        if n > 0 && tx.send(Ok(out)).is_err() {
            return;
        }
        if last {
            return;
        }
    }
}

impl Read for ParZstd {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pos < self.buf.len() {
                let n = out.len().min(self.buf.len() - self.pos);
                out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            if self.cur.is_none() {
                match self.order.recv() {
                    Ok(rx) => self.cur = Some(rx),
                    Err(_) => return Ok(0),
                }
            }
            match self.cur.as_ref().expect("current frame").recv() {
                Ok(chunk) => {
                    let old = std::mem::replace(&mut self.buf, chunk?);
                    self.pos = 0;
                    if old.capacity() >= CHUNK {
                        give(&self.queue.chunks, old);
                    }
                }
                // The frame's worker is done.
                Err(_) => self.cur = None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn data(n: usize) -> Vec<u8> {
        (0..n as u32)
            .flat_map(|i| format!("{} {}\n", i % 977, i / 13).into_bytes())
            .take(n)
            .collect()
    }

    fn decode_file(bytes: &[u8], workers: usize, inflight: usize) -> io::Result<Vec<u8>> {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.zst");
        std::fs::write(&p, bytes).unwrap();
        let mut out = Vec::new();
        ParZstd::new(File::open(&p).unwrap(), workers, inflight).read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn many_frames_decode_in_order() {
        let d = data(3_000_000);
        let mut z = Vec::new();
        for (i, part) in d.chunks(100_000).enumerate() {
            z.extend(zstd::bulk::compress(part, 3).unwrap());
            if i == 3 {
                // A skippable frame in between is ignored.
                z.extend_from_slice(&0x184D_2A53u32.to_le_bytes());
                z.extend_from_slice(&5u32.to_le_bytes());
                z.extend_from_slice(b"hello");
            }
        }
        for (w, f) in [(1, 1), (4, 2), (8, 16)] {
            assert_eq!(decode_file(&z, w, f).unwrap(), d);
        }
    }

    #[test]
    fn frame_sizes_match_zstd() {
        let d = data(2_000_000);
        for level in [1, 9, 19] {
            let mut e = zstd::stream::write::Encoder::new(Vec::new(), level).unwrap();
            e.include_checksum(level == 9).unwrap();
            e.write_all(&d).unwrap();
            let mut z = e.finish().unwrap();
            let one = z.len();
            z.extend(zstd::bulk::compress(&d[..1000], 1).unwrap());
            let dir = tempfile::tempdir().unwrap();
            let p = dir.path().join("s.zst");
            std::fs::write(&p, &z).unwrap();
            let f = File::open(&p).unwrap();
            assert_eq!(frame_size_at(&f, 0, z.len() as u64), Some(one as u64));
            assert_eq!(
                zstd::zstd_safe::find_frame_compressed_size(&z).unwrap(),
                one
            );
            let mut want = d.clone();
            want.extend_from_slice(&d[..1000]);
            assert_eq!(decode_file(&z, 3, 2).unwrap(), want);
        }
    }

    #[test]
    fn streamed_frame_and_empty_input() {
        let d = data(1_000_000);
        let mut e = zstd::stream::write::Encoder::new(Vec::new(), 5).unwrap();
        e.write_all(&d).unwrap();
        let z = e.finish().unwrap();
        assert_eq!(decode_file(&z, 3, 2).unwrap(), d);
        assert!(decode_file(&[], 2, 2).unwrap().is_empty());
    }

    #[test]
    fn corrupt_or_truncated_input_is_an_error() {
        let d = data(500_000);
        let mut z = zstd::bulk::compress(&d, 3).unwrap();
        z.truncate(z.len() / 2);
        assert!(decode_file(&z, 2, 2).is_err());
        assert!(decode_file(b"not zstd at all", 2, 2).is_err());
    }
}
