//! Positional byte sources (a file, a memory buffer) and the repaired view
//! that overlays sectors rebuilt from the recovery record.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;

use anyhow::{Result, ensure};

/// Random-access read-only bytes.
pub trait Source: Sync {
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Read up to `buf.len()` bytes at `off`; returns the count (short only at the end).
    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<usize>;
}

fn slice_read(s: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let l = s.len() as u64;
    if off >= l {
        return 0;
    }
    let n = buf.len().min((l - off) as usize);
    buf[..n].copy_from_slice(&s[off as usize..off as usize + n]);
    n
}

impl Source for &[u8] {
    fn len(&self) -> u64 {
        <[u8]>::len(self) as u64
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        Ok(slice_read(self, off, buf))
    }
}

impl Source for Vec<u8> {
    fn len(&self) -> u64 {
        self.as_slice().len() as u64
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        Ok(slice_read(self, off, buf))
    }
}

/// A file with its length taken once at open time.
pub struct FileSource {
    pub file: File,
    pub len: u64,
}

impl FileSource {
    pub fn open(path: &std::path::Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self { file, len })
    }
}

impl Source for FileSource {
    fn len(&self) -> u64 {
        self.len
    }
    fn read_at(&self, off: u64, buf: &mut [u8]) -> io::Result<usize> {
        if off >= self.len {
            return Ok(0);
        }
        let want = buf.len().min((self.len - off) as usize);
        let mut done = 0;
        while done < want {
            #[cfg(windows)]
            let n = {
                use std::os::windows::fs::FileExt;
                self.file
                    .seek_read(&mut buf[done..want], off + done as u64)?
            };
            #[cfg(unix)]
            let n = {
                use std::os::unix::fs::FileExt;
                self.file.read_at(&mut buf[done..want], off + done as u64)?
            };
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }
}

/// A source with repaired sectors laid over it.
pub struct View<'a> {
    pub src: &'a dyn Source,
    /// Sector start offset -> repaired bytes.
    pub patches: BTreeMap<u64, Vec<u8>>,
    len: u64,
}

impl<'a> View<'a> {
    pub fn new(src: &'a dyn Source) -> Self {
        Self {
            src,
            patches: BTreeMap::new(),
            len: src.len(),
        }
    }
    pub fn patch(&mut self, off: u64, data: Vec<u8>) {
        self.len = self.len.max(off + data.len() as u64);
        self.patches.insert(off, data);
    }
    /// Logical length: at least the covered length after a repair.
    pub fn set_min_len(&mut self, l: u64) {
        self.len = self.len.max(l);
    }
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn is_patched(&self) -> bool {
        !self.patches.is_empty()
    }
    /// Read exactly `n` bytes at `off`.
    pub fn read(&self, off: u64, n: usize) -> Result<Vec<u8>> {
        let end = off
            .checked_add(n as u64)
            .ok_or_else(|| anyhow::anyhow!("offset overflow"))?;
        ensure!(end <= self.len, "read past the end of the archive");
        let mut buf = vec![0u8; n];
        let got = self.src.read_at(off, &mut buf)?;
        let mut valid = got;
        // Patches: sectors are disjoint and sorted.
        let first = self
            .patches
            .range(..=off)
            .next_back()
            .map(|(&k, _)| k)
            .unwrap_or(off);
        for (&po, pd) in self.patches.range(first..end) {
            let pe = po + pd.len() as u64;
            if pe <= off {
                continue;
            }
            let s = po.max(off);
            let e = pe.min(end);
            buf[(s - off) as usize..(e - off) as usize]
                .copy_from_slice(&pd[(s - po) as usize..(e - po) as usize]);
            if s - off <= valid as u64 {
                valid = valid.max((e - off) as usize);
            }
        }
        ensure!(valid >= n, "archive truncated");
        Ok(buf)
    }
}
