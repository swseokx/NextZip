//! Byte-level structures of `.nz` v1 (see `docs/nz-format-v1.md`).
//!
//! Every multi-byte integer is little-endian. `H8(x)` / `H4(x)` are the
//! first 8 / 4 bytes of `BLAKE3(x)`.

use anyhow::{Result, bail, ensure};

pub const MAGIC: [u8; 4] = [b'N', b'Z', 0x1A, 0x01];
pub const TRAILER_MAGIC: [u8; 4] = [b'N', b'Z', 0x1A, 0xFE];
pub const CRYPTO_MAGIC: [u8; 4] = *b"NZCK";
pub const BLOCK_MAGIC: [u8; 4] = *b"NZBK";
pub const INDEX_MAGIC: [u8; 4] = *b"NZIX";
pub const RR_MAGIC: [u8; 4] = *b"NZRR";

pub const HEADER_LEN: usize = 64;
pub const CRYPTO_LEN: usize = 64;
pub const BLOCK_HEADER_LEN: usize = 64;
pub const INDEX_HEADER_LEN: usize = 72;
pub const RR_HEADER_LEN: usize = 64;

pub const VERSION_MAJOR: u8 = 1;
pub const VERSION_MINOR: u8 = 0;

pub const FLAG_ENCRYPTED: u16 = 1;
pub const FLAG_RECOVERY: u16 = 2;
const KNOWN_FLAGS: u16 = FLAG_ENCRYPTED | FLAG_RECOVERY;

/// Largest raw block a reader accepts (256 MiB).
pub const MAX_BLOCK_RAW: u32 = 256 << 20;
/// Largest raw index a reader accepts (1 GiB).
pub const MAX_INDEX_RAW: u64 = 1 << 30;

pub fn h8(data: &[u8]) -> [u8; 8] {
    let h = blake3::hash(data);
    h.as_bytes()[..8].try_into().unwrap()
}

pub fn h4(data: &[u8]) -> [u8; 4] {
    let h = blake3::hash(data);
    h.as_bytes()[..4].try_into().unwrap()
}

pub fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
pub fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
pub fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// Main header (offset 0) and trailer (last 64 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    pub flags: u16,
    /// Offset of the primary index frame.
    pub index_offset: u64,
    /// Offset of the index copy frame (0 = none).
    pub index_copy_offset: u64,
    /// Offset of the recovery record (0 = none).
    pub recovery_offset: u64,
    /// Total archive length including the trailer.
    pub archive_size: u64,
    /// Recovery sector size in bytes (0 when there is no recovery record).
    pub rr_sector_size: u32,
    /// Recovery parity in basis points (300 = 3 %).
    pub rr_basis_points: u16,
    /// Data sectors per recovery group.
    pub rr_group_sectors: u32,
}

impl Header {
    pub fn encrypted(&self) -> bool {
        self.flags & FLAG_ENCRYPTED != 0
    }
    pub fn has_recovery(&self) -> bool {
        self.flags & FLAG_RECOVERY != 0
    }
    pub fn encode(&self, trailer: bool) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[..4].copy_from_slice(if trailer { &TRAILER_MAGIC } else { &MAGIC });
        b[4] = VERSION_MAJOR;
        b[5] = VERSION_MINOR;
        b[6..8].copy_from_slice(&self.flags.to_le_bytes());
        b[8..16].copy_from_slice(&self.index_offset.to_le_bytes());
        b[16..24].copy_from_slice(&self.index_copy_offset.to_le_bytes());
        b[24..32].copy_from_slice(&self.recovery_offset.to_le_bytes());
        b[32..40].copy_from_slice(&self.archive_size.to_le_bytes());
        b[40..44].copy_from_slice(&self.rr_sector_size.to_le_bytes());
        b[44..46].copy_from_slice(&self.rr_basis_points.to_le_bytes());
        b[48..52].copy_from_slice(&self.rr_group_sectors.to_le_bytes());
        let c = h8(&b[..56]);
        b[56..].copy_from_slice(&c);
        b
    }
    pub fn decode(b: &[u8], trailer: bool) -> Result<Self> {
        ensure!(b.len() >= HEADER_LEN, "short header");
        let magic = if trailer { TRAILER_MAGIC } else { MAGIC };
        ensure!(b[..4] == magic, "bad magic");
        ensure!(h8(&b[..56]) == b[56..64], "header checksum mismatch");
        ensure!(
            b[4] == VERSION_MAJOR,
            "unsupported .nz major version {}",
            b[4]
        );
        let flags = u16_at(b, 6);
        ensure!(flags & !KNOWN_FLAGS == 0, "unknown header flags {flags:#x}");
        ensure!(
            u16_at(b, 46) == 0 && u32_at(b, 52) == 0,
            "reserved header bytes set"
        );
        Ok(Self {
            flags,
            index_offset: u64_at(b, 8),
            index_copy_offset: u64_at(b, 16),
            recovery_offset: u64_at(b, 24),
            archive_size: u64_at(b, 32),
            rr_sector_size: u32_at(b, 40),
            rr_basis_points: u16_at(b, 44),
            rr_group_sectors: u32_at(b, 48),
        })
    }
}

/// Codec of a block or index payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Store = 0,
    Zstd = 1,
    Lz4 = 2,
    Lzma2 = 3,
}

impl Codec {
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::Store,
            1 => Self::Zstd,
            2 => Self::Lz4,
            3 => Self::Lzma2,
            _ => bail!("unknown codec id {v}"),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Store => "store",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
            Self::Lzma2 => "lzma2",
        }
    }
}

/// Filter applied to a block's raw bytes before compression (byte 6 of the
/// block header).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Filter {
    #[default]
    None = 0,
    /// x86 BCJ (E8/E9 branch conversion) over the whole block, start offset 0.
    X86 = 1,
}

impl Filter {
    pub fn from_u8(v: u8) -> Result<Self> {
        Ok(match v {
            0 => Self::None,
            1 => Self::X86,
            _ => bail!("unknown block filter {v}"),
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::X86 => "x86",
        }
    }
}

/// Header of a data block frame (64 bytes, followed by `stored_len` bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub codec: Codec,
    pub filter: Filter,
    pub encrypted: bool,
    pub raw_len: u32,
    pub stored_len: u32,
    pub hash: [u8; 32],
    pub nonce: [u8; 12],
}

impl BlockHeader {
    pub fn encode(&self) -> [u8; BLOCK_HEADER_LEN] {
        let mut b = [0u8; BLOCK_HEADER_LEN];
        b[..4].copy_from_slice(&BLOCK_MAGIC);
        b[4] = self.codec as u8;
        b[5] = u8::from(self.encrypted);
        b[6] = self.filter as u8;
        b[8..12].copy_from_slice(&self.raw_len.to_le_bytes());
        b[12..16].copy_from_slice(&self.stored_len.to_le_bytes());
        b[16..48].copy_from_slice(&self.hash);
        b[48..60].copy_from_slice(&self.nonce);
        let c = h4(&b[..60]);
        b[60..].copy_from_slice(&c);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(b.len() >= BLOCK_HEADER_LEN, "short block header");
        ensure!(b[..4] == BLOCK_MAGIC, "bad block magic");
        ensure!(h4(&b[..60]) == b[60..64], "block header checksum mismatch");
        ensure!(b[5] <= 1 && b[7] == 0, "bad block flags");
        let raw_len = u32_at(b, 8);
        ensure!(raw_len <= MAX_BLOCK_RAW, "block too large");
        Ok(Self {
            codec: Codec::from_u8(b[4])?,
            filter: Filter::from_u8(b[6])?,
            encrypted: b[5] == 1,
            raw_len,
            stored_len: u32_at(b, 12),
            hash: b[16..48].try_into().unwrap(),
            nonce: b[48..60].try_into().unwrap(),
        })
    }
}

/// Header of an index frame (72 bytes, followed by `stored_len` bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexHeader {
    pub codec: Codec,
    pub encrypted: bool,
    pub raw_len: u64,
    pub stored_len: u64,
    pub hash: [u8; 32],
    pub nonce: [u8; 12],
}

impl IndexHeader {
    pub fn encode(&self) -> [u8; INDEX_HEADER_LEN] {
        let mut b = [0u8; INDEX_HEADER_LEN];
        b[..4].copy_from_slice(&INDEX_MAGIC);
        b[4] = self.codec as u8;
        b[5] = u8::from(self.encrypted);
        b[8..16].copy_from_slice(&self.raw_len.to_le_bytes());
        b[16..24].copy_from_slice(&self.stored_len.to_le_bytes());
        b[24..56].copy_from_slice(&self.hash);
        b[56..68].copy_from_slice(&self.nonce);
        let c = h4(&b[..68]);
        b[68..].copy_from_slice(&c);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(b.len() >= INDEX_HEADER_LEN, "short index header");
        ensure!(b[..4] == INDEX_MAGIC, "bad index magic");
        ensure!(h4(&b[..68]) == b[68..72], "index header checksum mismatch");
        ensure!(b[5] <= 1 && b[6] == 0 && b[7] == 0, "bad index flags");
        let codec = Codec::from_u8(b[4])?;
        ensure!(
            matches!(codec, Codec::Store | Codec::Zstd),
            "index codec must be store or zstd"
        );
        let raw_len = u64_at(b, 8);
        ensure!(raw_len <= MAX_INDEX_RAW, "index too large");
        Ok(Self {
            codec,
            encrypted: b[5] == 1,
            raw_len,
            stored_len: u64_at(b, 16),
            hash: b[24..56].try_into().unwrap(),
            nonce: b[56..68].try_into().unwrap(),
        })
    }
}

/// Encryption descriptor (64 bytes at offset 64 when the archive is encrypted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoHeader {
    pub aead: Aead,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: [u8; 16],
    pub check: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    Aes256Gcm = 1,
    ChaCha20Poly1305 = 2,
}

/// Reader limits on Argon2id parameters (memory 1 GiB, 64 passes, 16 lanes).
pub const MAX_M_COST_KIB: u32 = 1 << 20;
pub const MAX_T_COST: u32 = 64;
pub const MAX_P_COST: u32 = 16;

impl CryptoHeader {
    pub fn encode(&self) -> [u8; CRYPTO_LEN] {
        let mut b = [0u8; CRYPTO_LEN];
        b[..4].copy_from_slice(&CRYPTO_MAGIC);
        b[4] = self.aead as u8;
        b[5] = 1; // Argon2id v0x13
        b[8..12].copy_from_slice(&self.m_cost_kib.to_le_bytes());
        b[12..16].copy_from_slice(&self.t_cost.to_le_bytes());
        b[16..20].copy_from_slice(&self.p_cost.to_le_bytes());
        b[20..36].copy_from_slice(&self.salt);
        b[36..52].copy_from_slice(&self.check);
        let c = h8(&b[..56]);
        b[56..].copy_from_slice(&c);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(b.len() >= CRYPTO_LEN, "short crypto header");
        ensure!(b[..4] == CRYPTO_MAGIC, "bad crypto header magic");
        ensure!(h8(&b[..56]) == b[56..64], "crypto header checksum mismatch");
        let aead = match b[4] {
            1 => Aead::Aes256Gcm,
            2 => Aead::ChaCha20Poly1305,
            v => bail!("unknown AEAD id {v}"),
        };
        ensure!(b[5] == 1, "unknown key derivation id {}", b[5]);
        ensure!(
            b[6] == 0 && b[7] == 0 && b[52..56].iter().all(|&x| x == 0),
            "reserved crypto bytes set"
        );
        let (m, t, p) = (u32_at(b, 8), u32_at(b, 12), u32_at(b, 16));
        ensure!(
            (8..=MAX_M_COST_KIB).contains(&m)
                && (1..=MAX_T_COST).contains(&t)
                && (1..=MAX_P_COST).contains(&p)
                && m >= 8 * p,
            "Argon2id parameters out of range (m={m} KiB, t={t}, p={p})"
        );
        Ok(Self {
            aead,
            m_cost_kib: m,
            t_cost: t,
            p_cost: p,
            salt: b[20..36].try_into().unwrap(),
            check: b[36..52].try_into().unwrap(),
        })
    }
}

/// Recovery record header (64 bytes, stored at both ends of the record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RrHeader {
    pub basis_points: u16,
    pub sector_size: u32,
    pub group_sectors: u32,
    /// Bytes `[0, covered_len)` of the archive are protected.
    pub covered_len: u64,
    pub group_count: u32,
    pub parity_sectors: u32,
    /// Total length of the record, both headers included.
    pub rr_len: u64,
}

impl RrHeader {
    pub fn encode(&self) -> [u8; RR_HEADER_LEN] {
        let mut b = [0u8; RR_HEADER_LEN];
        b[..4].copy_from_slice(&RR_MAGIC);
        b[4] = 1;
        b[6..8].copy_from_slice(&self.basis_points.to_le_bytes());
        b[8..12].copy_from_slice(&self.sector_size.to_le_bytes());
        b[12..16].copy_from_slice(&self.group_sectors.to_le_bytes());
        b[16..24].copy_from_slice(&self.covered_len.to_le_bytes());
        b[24..28].copy_from_slice(&self.group_count.to_le_bytes());
        b[28..32].copy_from_slice(&self.parity_sectors.to_le_bytes());
        b[32..40].copy_from_slice(&self.rr_len.to_le_bytes());
        let c = h8(&b[..56]);
        b[56..].copy_from_slice(&c);
        b
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        ensure!(b.len() >= RR_HEADER_LEN, "short recovery header");
        ensure!(b[..4] == RR_MAGIC, "bad recovery magic");
        ensure!(
            h8(&b[..56]) == b[56..64],
            "recovery header checksum mismatch"
        );
        ensure!(b[4] == 1, "unknown recovery record version {}", b[4]);
        let h = Self {
            basis_points: u16_at(b, 6),
            sector_size: u32_at(b, 8),
            group_sectors: u32_at(b, 12),
            covered_len: u64_at(b, 16),
            group_count: u32_at(b, 24),
            parity_sectors: u32_at(b, 28),
            rr_len: u64_at(b, 32),
        };
        let expect = crate::rr::Layout::new(
            h.covered_len,
            h.sector_size,
            h.group_sectors,
            h.basis_points,
        )?;
        ensure!(
            expect.header() == h,
            "recovery header fields are inconsistent"
        );
        Ok(h)
    }
}

// ---------------------------------------------------------------- varints

pub fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

pub fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

pub fn put_str(out: &mut Vec<u8>, s: &str) {
    put_varint(out, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// Cursor over an index body.
pub struct Rd<'a> {
    pub b: &'a [u8],
    pub p: usize,
}

impl<'a> Rd<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    pub fn u8(&mut self) -> Result<u8> {
        let Some(&v) = self.b.get(self.p) else {
            bail!("index truncated")
        };
        self.p += 1;
        Ok(v)
    }
    /// Unsigned LEB128, at most 10 bytes, canonical (no redundant zero groups).
    pub fn varint(&mut self) -> Result<u64> {
        let mut v: u64 = 0;
        for i in 0..10 {
            let b = self.u8()?;
            if i == 9 && b > 1 {
                bail!("varint overflow");
            }
            v |= u64::from(b & 0x7F) << (7 * i);
            if b & 0x80 == 0 {
                if b == 0 && i > 0 {
                    bail!("non-canonical varint");
                }
                return Ok(v);
            }
        }
        bail!("varint too long")
    }
    pub fn count(&mut self, min_bytes_each: usize) -> Result<usize> {
        let n = self.varint()?;
        // Each item needs at least `min_bytes_each` bytes: cheap bound that
        // stops absurd counts before allocation.
        ensure!(
            n.saturating_mul(min_bytes_each as u64) <= (self.b.len() - self.p) as u64,
            "count {n} exceeds the remaining index bytes"
        );
        Ok(n as usize)
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.b.len() - self.p >= n, "index truncated");
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    pub fn string(&mut self) -> Result<String> {
        let n = self.varint()?;
        ensure!(n <= 65535, "string too long");
        let s = self.bytes(n as usize)?;
        Ok(std::str::from_utf8(s)
            .map_err(|_| anyhow::anyhow!("string is not UTF-8"))?
            .to_owned())
    }
    pub fn done(&self) -> bool {
        self.p == self.b.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for v in [0u64, 1, 127, 128, 300, u32::MAX as u64, u64::MAX] {
            let mut b = Vec::new();
            put_varint(&mut b, v);
            assert_eq!(Rd::new(&b).varint().unwrap(), v);
        }
        assert!(Rd::new(&[0x80, 0x00]).varint().is_err());
        assert!(Rd::new(&[0xFF; 11]).varint().is_err());
        for v in [0i64, -1, 1, i64::MIN, i64::MAX] {
            assert_eq!(unzigzag(zigzag(v)), v);
        }
    }

    #[test]
    fn header_round_trip() {
        let h = Header {
            flags: 3,
            index_offset: 1234,
            index_copy_offset: 99999,
            recovery_offset: 5678,
            archive_size: 100000,
            rr_sector_size: 4096,
            rr_basis_points: 300,
            rr_group_sectors: 32768,
        };
        assert_eq!(Header::decode(&h.encode(false), false).unwrap(), h);
        assert_eq!(Header::decode(&h.encode(true), true).unwrap(), h);
        let mut b = h.encode(false);
        b[10] ^= 1;
        assert!(Header::decode(&b, false).is_err());
    }
}
