//! A virtual file made of byte ranges of one or more volume files, so split
//! archives (ALZ `.alz/.a00/.a01`, EGG `vol1.egg/vol2.egg`) parse as one stream.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;

/// One volume's usable region.
pub struct Segment {
    pub path: PathBuf,
    pub file: File,
    /// Physical offset of the region in `file`.
    pub start: u64,
    pub len: u64,
}

pub struct MultiReader {
    segs: Vec<Segment>,
    /// Virtual start offset of each segment.
    starts: Vec<u64>,
    total: u64,
    pos: u64,
}

impl MultiReader {
    pub fn new(segs: Vec<Segment>) -> Self {
        let mut starts = Vec::with_capacity(segs.len());
        let mut total = 0u64;
        for s in &segs {
            starts.push(total);
            total += s.len;
        }
        MultiReader {
            segs,
            starts,
            total,
            pos: 0,
        }
    }
    pub fn len(&self) -> u64 {
        self.total
    }
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }
    pub fn volumes(&self) -> usize {
        self.segs.len()
    }
    pub fn paths(&self) -> Vec<PathBuf> {
        self.segs.iter().map(|s| s.path.clone()).collect()
    }
    pub fn position(&self) -> u64 {
        self.pos
    }

    /// Read exactly `buf.len()` bytes at virtual offset `off` without moving
    /// the cursor.
    pub fn read_exact_at(&self, mut off: u64, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            if off >= self.total {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            let i = self.starts.partition_point(|&s| s <= off) - 1;
            let seg = &self.segs[i];
            let within = off - self.starts[i];
            let n = ((seg.len - within) as usize).min(buf.len());
            read_at(&seg.file, &mut buf[..n], seg.start + within)?;
            buf = &mut buf[n..];
            off += n as u64;
        }
        Ok(())
    }

    pub fn read_vec_at(&self, off: u64, len: u64) -> io::Result<Vec<u8>> {
        if off.checked_add(len).is_none_or(|end| end > self.total) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "member data runs past the end of the archive",
            ));
        }
        let mut v = vec![0u8; len as usize];
        self.read_exact_at(off, &mut v)?;
        Ok(v)
    }
}

impl Read for MultiReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = (self.total.saturating_sub(self.pos) as usize).min(buf.len());
        if n == 0 {
            return Ok(0);
        }
        self.read_exact_at(self.pos, &mut buf[..n])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for MultiReader {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let p = match to {
            SeekFrom::Start(p) => Some(p),
            SeekFrom::Current(d) => self.pos.checked_add_signed(d),
            SeekFrom::End(d) => self.total.checked_add_signed(d),
        };
        match p {
            Some(p) => {
                self.pos = p;
                Ok(p)
            }
            None => Err(io::ErrorKind::InvalidInput.into()),
        }
    }
}

fn read_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    nz_core::zip::read_at(f, buf, off)
}

/// Little-endian readers over a cursor.
pub trait ReadLe: Read {
    fn u8(&mut self) -> io::Result<u8> {
        let mut b = [0u8; 1];
        self.read_exact(&mut b)?;
        Ok(b[0])
    }
    fn u16(&mut self) -> io::Result<u16> {
        let mut b = [0u8; 2];
        self.read_exact(&mut b)?;
        Ok(u16::from_le_bytes(b))
    }
    fn u32(&mut self) -> io::Result<u32> {
        let mut b = [0u8; 4];
        self.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn u64(&mut self) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    /// Little-endian integer of `n` (0..=8) bytes.
    fn uint(&mut self, n: usize) -> io::Result<u64> {
        let mut b = [0u8; 8];
        self.read_exact(&mut b[..n])?;
        Ok(u64::from_le_bytes(b))
    }
    fn read_bytes(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut v = vec![0u8; n];
        self.read_exact(&mut v)?;
        Ok(v)
    }
}

impl<R: Read + ?Sized> ReadLe for R {}
