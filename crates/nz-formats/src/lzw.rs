//! Unix `compress` (.Z) LZW decoder: 9 to 16-bit codes, block mode.

use std::io::{self, Read};

pub struct Decoder<R: Read> {
    r: R,
    maxbits: u32,
    block: bool,
    bits: u32,
    /// Code buffer: codes are read in groups of `bits` bytes (8 codes).
    group: Vec<u8>,
    gpos: usize,
    glen: usize,
    prefix: Vec<u16>,
    suffix: Vec<u8>,
    next: u32,
    prev: Option<u16>,
    first: u8,
    out: Vec<u8>,
    opos: usize,
    done: bool,
}

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_string())
}

impl<R: Read> Decoder<R> {
    pub fn new(mut r: R) -> io::Result<Self> {
        let mut h = [0u8; 3];
        r.read_exact(&mut h)?;
        if h[0] != 0x1F || h[1] != 0x9D {
            return Err(bad("not a .Z file"));
        }
        let maxbits = u32::from(h[2] & 0x1F);
        if !(9..=16).contains(&maxbits) {
            return Err(bad("bad .Z code width"));
        }
        let block = h[2] & 0x80 != 0;
        let size = 1usize << maxbits;
        let mut suffix = vec![0u8; size];
        for (i, s) in suffix.iter_mut().take(256).enumerate() {
            *s = i as u8;
        }
        Ok(Decoder {
            r,
            maxbits,
            block,
            bits: 9,
            group: vec![0u8; 16],
            gpos: 0,
            glen: 0,
            prefix: vec![0u16; size],
            suffix,
            next: if block { 257 } else { 256 },
            prev: None,
            first: 0,
            out: Vec::new(),
            opos: 0,
            done: false,
        })
    }

    /// Fill a new group of up to `bits` bytes (8 codes).
    fn fill(&mut self) -> io::Result<bool> {
        let want = self.bits as usize;
        let mut got = 0;
        while got < want {
            match self.r.read(&mut self.group[got..want]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        self.gpos = 0;
        self.glen = got * 8;
        Ok(got > 0)
    }

    fn code(&mut self) -> io::Result<Option<u32>> {
        if self.gpos + self.bits as usize > self.glen
            && (!self.fill()? || self.glen < self.bits as usize)
        {
            return Ok(None);
        }
        let mut v = 0u32;
        for i in 0..self.bits as usize {
            let bit = self.gpos + i;
            if self.group[bit / 8] >> (bit % 8) & 1 != 0 {
                v |= 1 << i;
            }
        }
        self.gpos += self.bits as usize;
        Ok(Some(v))
    }

    fn step(&mut self) -> io::Result<()> {
        self.out.clear();
        self.opos = 0;
        let Some(code) = self.code()? else {
            self.done = true;
            return Ok(());
        };
        if self.block && code == 256 {
            // CLEAR: reset the table and skip the rest of this group.
            self.bits = 9;
            self.next = 257;
            self.prev = None;
            self.gpos = self.glen;
            return Ok(());
        }
        let Some(prev) = self.prev else {
            if code > 255 {
                return Err(bad("bad first .Z code"));
            }
            self.out.push(code as u8);
            self.first = code as u8;
            self.prev = Some(code as u16);
            return Ok(());
        };
        let mut c = code;
        let mut stack = Vec::new();
        if c >= self.next {
            if c > self.next {
                return Err(bad("bad .Z code"));
            }
            stack.push(self.first);
            c = u32::from(prev);
        }
        while c > 255 {
            stack.push(self.suffix[c as usize]);
            c = u32::from(self.prefix[c as usize]);
            if stack.len() > 1 << 17 {
                return Err(bad("bad .Z chain"));
            }
        }
        self.first = c as u8;
        stack.push(self.first);
        stack.reverse();
        self.out = stack;
        if self.next < 1 << self.maxbits {
            self.prefix[self.next as usize] = prev;
            self.suffix[self.next as usize] = self.first;
            self.next += 1;
            if self.next >= 1 << self.bits && self.bits < self.maxbits {
                // Width changes at group boundaries.
                self.bits += 1;
                self.gpos = self.glen;
            }
        }
        self.prev = Some(code as u16);
        Ok(())
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while self.opos == self.out.len() {
            if self.done {
                return Ok(0);
            }
            self.step()?;
        }
        let n = (self.out.len() - self.opos).min(buf.len());
        buf[..n].copy_from_slice(&self.out[self.opos..self.opos + n]);
        self.opos += n;
        Ok(n)
    }
}
