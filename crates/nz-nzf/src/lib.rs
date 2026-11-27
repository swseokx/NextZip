//! NextZip native container `.nz` v1 (specification: `docs/nz-format-v1.md`).
//!
//! * content-defined chunks (FastCDC) deduplicated by BLAKE3 hash, packed
//!   into independently decodable blocks (zstd, LZ4, LZMA2 or stored)
//! * an index with snapshots (one per `create`, one more per `backup` run)
//! * optional encryption: Argon2id + AES-256-GCM or ChaCha20-Poly1305,
//!   names included
//! * optional recovery record: Reed-Solomon parity over sectors, applied
//!   automatically when a structure fails its check
//!
//! This crate is the reference implementation and is MIT licensed.

pub mod cdc;
pub mod codec;
pub mod crypto;
pub mod fmt;
pub mod index;
pub mod read;
pub mod rr;
pub mod source;
pub mod write;

pub use codec::Method;
pub use crypto::KdfParams;
pub use fmt::Aead;
pub use read::{Archive, ExtractReport, OpenOptions, TestReport};
pub use source::{FileSource, Source};
pub use write::{WriteOptions, WriteStats, backup, create, repair_to};

use std::path::Path;

/// True when `head` starts with the `.nz` magic.
pub fn is_nz(head: &[u8]) -> bool {
    head.starts_with(&fmt::MAGIC)
}

/// True when the file at `path` is a `.nz` archive (header or trailer magic).
pub fn sniff(path: &Path) -> bool {
    let Ok(src) = FileSource::open(path) else {
        return false;
    };
    let mut b = [0u8; 4];
    if src.read_at(0, &mut b).ok() == Some(4) && b == fmt::MAGIC {
        return true;
    }
    src.len >= 64 && src.read_at(src.len - 64, &mut b).ok() == Some(4) && b == fmt::TRAILER_MAGIC
}

/// Entry points for fuzz targets: open an in-memory archive, list it,
/// test it and extract it into a temporary directory. Must never panic.
///
/// Both run on a private one-thread Rayon pool: waking the global pool's
/// workers for every small input cost about 20x the throughput under
/// libFuzzer + ASAN (M4b report), and a fuzzer process is one worker anyway.
pub mod fuzzing {
    use super::*;

    fn one_thread<R: Send>(f: impl FnOnce() -> R + Send) -> R {
        static POOL: std::sync::OnceLock<Option<rayon::ThreadPool>> = std::sync::OnceLock::new();
        match POOL.get_or_init(|| rayon::ThreadPoolBuilder::new().num_threads(1).build().ok()) {
            Some(p) => p.install(f),
            None => f(),
        }
    }

    /// Seeds are encrypted with password "fuzz" and cheap Argon2 settings
    /// (64 KiB, 1 pass); master keys are cached by salt and parameters, so
    /// mutations of a seed skip Argon2. Inputs asking for more expensive key
    /// derivation are opened without a password (the KDF cost is bounded by
    /// the format, but not small).
    pub fn open_and_test(data: &[u8], verify: bool) {
        crypto::enable_fuzz_kdf_cache();
        let cheap = data
            .get(64..128)
            .and_then(|b| fmt::CryptoHeader::decode(b).ok())
            .is_none_or(|c| c.m_cost_kib <= 256 && c.t_cost <= 2 && c.p_cost <= 2);
        let opt = OpenOptions {
            password: cheap.then(|| "fuzz".into()),
            verify,
        };
        one_thread(|| {
            if let Ok(mut a) = Archive::open(&data, &opt) {
                let _ = read::test(&mut a);
                for s in &a.index.snapshots {
                    let _ = read::checked_paths(&s.entries);
                }
            }
        });
    }

    /// Recovery path only: locate and apply the recovery record.
    pub fn recovery(data: &[u8]) {
        one_thread(|| {
            let mut v = source::View::new(&data);
            if let Some(loc) = rr::scan(&data) {
                let _ = rr::repair(&mut v, &loc);
            }
        });
    }
}
