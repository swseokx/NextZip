//! The index: block table, chunk table and snapshots with their entries.

use anyhow::{Result, bail, ensure};

use crate::fmt::{MAX_BLOCK_RAW, Rd, put_str, put_varint, unzigzag, zigzag};

pub const INDEX_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef {
    /// Absolute offset of the block frame.
    pub offset: u64,
    pub raw_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub block: u32,
    pub offset: u32,
    pub len: u32,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

/// [`Stream::kind`] of an NTFS alternate data stream.
pub const STREAM_ADS: u8 = 0;
/// [`Stream::kind`] of an extended attribute (reserved: the reference
/// writer does not store them and the extractor skips them).
pub const STREAM_XATTR: u8 = 1;

/// An alternate data stream name that is safe to append to a path as
/// `path:name`: 1..=255 UTF-16 units, no `:` (which would select a stream
/// type such as `$INDEX_ALLOCATION`), no path separators, no control
/// characters and none of `<>"|?*`.
pub fn valid_stream_name(name: &str) -> bool {
    let units = name.encode_utf16().count();
    (1..=255).contains(&units)
        && !name
            .chars()
            .any(|c| c < ' ' || matches!(c, ':' | '/' | '\\' | '<' | '>' | '"' | '|' | '?' | '*'))
}

/// An alternate data stream (Windows) or extended attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stream {
    /// 0 = NTFS alternate data stream, 1 = extended attribute.
    pub kind: u8,
    pub name: String,
    pub size: u64,
    pub chunks: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// UTF-8, `/`-separated, relative.
    pub path: String,
    pub kind: Kind,
    /// Windows file attributes (0 = unknown).
    pub attrs: u32,
    /// Unix mode bits (0 = unknown).
    pub mode: u32,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: i64,
    pub size: u64,
    pub chunks: Vec<u32>,
    /// Symbolic link target (`/`-separated).
    pub target: String,
    pub streams: Vec<Stream>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub time_ns: i64,
    pub label: String,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Index {
    pub blocks: Vec<BlockRef>,
    pub chunks: Vec<Chunk>,
    pub snapshots: Vec<Snapshot>,
}

fn put_chunks(out: &mut Vec<u8>, ids: &[u32]) {
    put_varint(out, ids.len() as u64);
    let mut prev: i64 = -1;
    for &id in ids {
        put_varint(out, zigzag(i64::from(id) - (prev + 1)));
        prev = i64::from(id);
    }
}

fn get_chunks(r: &mut Rd<'_>, nchunks: usize, size: u64, chunks: &[Chunk]) -> Result<Vec<u32>> {
    let n = r.count(1)?;
    let mut ids = Vec::with_capacity(n);
    let mut prev: i64 = -1;
    let mut total: u64 = 0;
    for _ in 0..n {
        let d = unzigzag(r.varint()?);
        let id = (prev + 1).checked_add(d).unwrap_or(-1);
        ensure!(
            (0..nchunks as i64).contains(&id),
            "chunk reference out of range"
        );
        prev = id;
        ids.push(id as u32);
        total += u64::from(chunks[id as usize].len);
    }
    ensure!(total == size, "chunk lengths do not add up to the size");
    Ok(ids)
}

impl Index {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = vec![INDEX_VERSION];
        put_varint(&mut o, self.blocks.len() as u64);
        for b in &self.blocks {
            put_varint(&mut o, b.offset);
            put_varint(&mut o, u64::from(b.raw_len));
        }
        put_varint(&mut o, self.chunks.len() as u64);
        for c in &self.chunks {
            put_varint(&mut o, u64::from(c.block));
            put_varint(&mut o, u64::from(c.offset));
            put_varint(&mut o, u64::from(c.len));
            o.extend_from_slice(&c.hash);
        }
        put_varint(&mut o, self.snapshots.len() as u64);
        for s in &self.snapshots {
            put_varint(&mut o, zigzag(s.time_ns));
            put_str(&mut o, &s.label);
            put_varint(&mut o, s.entries.len() as u64);
            for e in &s.entries {
                put_str(&mut o, &e.path);
                o.push(match e.kind {
                    Kind::File => 0,
                    Kind::Dir => 1,
                    Kind::Symlink => 2,
                });
                put_varint(&mut o, u64::from(e.attrs));
                put_varint(&mut o, u64::from(e.mode));
                put_varint(&mut o, zigzag(e.mtime_ns));
                match e.kind {
                    Kind::File => {
                        put_varint(&mut o, e.size);
                        put_chunks(&mut o, &e.chunks);
                    }
                    Kind::Dir => {}
                    Kind::Symlink => put_str(&mut o, &e.target),
                }
                put_varint(&mut o, e.streams.len() as u64);
                for st in &e.streams {
                    o.push(st.kind);
                    put_str(&mut o, &st.name);
                    put_varint(&mut o, st.size);
                    put_chunks(&mut o, &st.chunks);
                }
            }
        }
        o
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        let mut r = Rd::new(b);
        ensure!(r.u8()? == INDEX_VERSION, "unknown index version");
        let nb = r.count(2)?;
        let mut blocks = Vec::with_capacity(nb);
        for _ in 0..nb {
            let offset = r.varint()?;
            let raw_len = r.varint()?;
            ensure!(raw_len <= u64::from(MAX_BLOCK_RAW), "block too large");
            blocks.push(BlockRef {
                offset,
                raw_len: raw_len as u32,
            });
        }
        let nc = r.count(35)?;
        let mut chunks = Vec::with_capacity(nc);
        for _ in 0..nc {
            let block = r.varint()?;
            let offset = r.varint()?;
            let len = r.varint()?;
            ensure!(block < nb as u64, "chunk block out of range");
            let bl = u64::from(blocks[block as usize].raw_len);
            ensure!(
                offset <= bl && len <= bl - offset,
                "chunk outside its block"
            );
            chunks.push(Chunk {
                block: block as u32,
                offset: offset as u32,
                len: len as u32,
                hash: r.bytes(32)?.try_into().unwrap(),
            });
        }
        let ns = r.count(3)?;
        let mut snapshots = Vec::with_capacity(ns);
        for _ in 0..ns {
            let time_ns = unzigzag(r.varint()?);
            let label = r.string()?;
            let ne = r.count(6)?;
            let mut entries = Vec::with_capacity(ne);
            for _ in 0..ne {
                let path = r.string()?;
                ensure!(!path.is_empty(), "empty entry path");
                let kind = match r.u8()? {
                    0 => Kind::File,
                    1 => Kind::Dir,
                    2 => Kind::Symlink,
                    k => bail!("unknown entry kind {k}"),
                };
                let attrs = r.varint()?;
                let mode = r.varint()?;
                ensure!(
                    attrs <= u64::from(u32::MAX) && mode <= u64::from(u32::MAX),
                    "attribute out of range"
                );
                let mtime_ns = unzigzag(r.varint()?);
                let (mut size, mut ids, mut target) = (0, Vec::new(), String::new());
                match kind {
                    Kind::File => {
                        size = r.varint()?;
                        ids = get_chunks(&mut r, nc, size, &chunks)?;
                    }
                    Kind::Dir => {}
                    Kind::Symlink => target = r.string()?,
                }
                let nst = r.count(4)?;
                let mut streams = Vec::with_capacity(nst);
                for _ in 0..nst {
                    let k = r.u8()?;
                    ensure!(k <= 1, "unknown stream kind {k}");
                    let name = r.string()?;
                    let sz = r.varint()?;
                    let ch = get_chunks(&mut r, nc, sz, &chunks)?;
                    streams.push(Stream {
                        kind: k,
                        name,
                        size: sz,
                        chunks: ch,
                    });
                }
                entries.push(Entry {
                    path,
                    kind,
                    attrs: attrs as u32,
                    mode: mode as u32,
                    mtime_ns,
                    size,
                    chunks: ids,
                    target,
                    streams,
                });
            }
            snapshots.push(Snapshot {
                time_ns,
                label,
                entries,
            });
        }
        ensure!(r.done(), "trailing bytes after the index");
        Ok(Self {
            blocks,
            chunks,
            snapshots,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let idx = Index {
            blocks: vec![BlockRef {
                offset: 64,
                raw_len: 100,
            }],
            chunks: vec![
                Chunk {
                    block: 0,
                    offset: 0,
                    len: 60,
                    hash: [1; 32],
                },
                Chunk {
                    block: 0,
                    offset: 60,
                    len: 40,
                    hash: [2; 32],
                },
            ],
            snapshots: vec![Snapshot {
                time_ns: -5,
                label: "s".into(),
                entries: vec![
                    Entry {
                        path: "a/b.txt".into(),
                        kind: Kind::File,
                        attrs: 32,
                        mode: 0o644,
                        mtime_ns: 1_700_000_000_000_000_000,
                        size: 160,
                        chunks: vec![0, 1, 0],
                        target: String::new(),
                        streams: vec![Stream {
                            kind: 0,
                            name: "Zone.Identifier".into(),
                            size: 40,
                            chunks: vec![1],
                        }],
                    },
                    Entry {
                        path: "a".into(),
                        kind: Kind::Dir,
                        attrs: 16,
                        mode: 0,
                        mtime_ns: 0,
                        size: 0,
                        chunks: vec![],
                        target: String::new(),
                        streams: vec![],
                    },
                    Entry {
                        path: "l".into(),
                        kind: Kind::Symlink,
                        attrs: 0,
                        mode: 0,
                        mtime_ns: 0,
                        size: 0,
                        chunks: vec![],
                        target: "a/b.txt".into(),
                        streams: vec![],
                    },
                ],
            }],
        };
        let b = idx.encode();
        assert_eq!(Index::decode(&b).unwrap(), idx);
        let mut bad = b.clone();
        bad.push(0);
        assert!(Index::decode(&bad).is_err());
    }
}
