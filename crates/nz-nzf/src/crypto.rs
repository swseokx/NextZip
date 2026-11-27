//! Password-based encryption: Argon2id master key, BLAKE3-derived subkeys,
//! AES-256-GCM or ChaCha20-Poly1305 per block / index.

use aes_gcm::aead::{Aead as _, KeyInit, Payload};
use anyhow::{Result, anyhow, ensure};
use zeroize::Zeroize;

use crate::fmt::{Aead, CryptoHeader};

pub const CTX_BLOCK: &str = "NextZip .nz v1 block key";
pub const CTX_INDEX: &str = "NextZip .nz v1 index key";
pub const CTX_HASH: &str = "NextZip .nz v1 hash key";
pub const CTX_CHECK: &str = "NextZip .nz v1 key check";

/// AEAD tag length (both ciphers).
pub const TAG: usize = 16;

/// Argon2id cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 1 lane.
    fn default() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

/// Derived keys; wiped on drop.
pub struct Keys {
    pub aead: Aead,
    pub block: [u8; 32],
    pub index: [u8; 32],
    pub hash: [u8; 32],
}

impl Drop for Keys {
    fn drop(&mut self) {
        self.block.zeroize();
        self.index.zeroize();
        self.hash.zeroize();
    }
}

/// Master key cache, enabled only by the fuzz entry points
/// ([`crate::fuzzing`]): mutated copies of one seed share its salt and cost
/// parameters, so most executions skip Argon2. Never enabled otherwise.
type CacheKey = (String, [u8; 16], KdfParams);
type KdfCache = std::sync::Mutex<Option<Vec<(CacheKey, [u8; 32])>>>;
static FUZZ_KDF_CACHE: KdfCache = std::sync::Mutex::new(None);
const FUZZ_KDF_CACHE_LEN: usize = 64;

/// Turn the master key cache on (fuzzing only).
pub(crate) fn enable_fuzz_kdf_cache() {
    let mut c = FUZZ_KDF_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    c.get_or_insert_with(Vec::new);
}

fn master_key(password: &str, salt: &[u8; 16], p: KdfParams) -> Result<[u8; 32]> {
    let key = (password.to_owned(), *salt, p);
    if let Some(c) = FUZZ_KDF_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        && let Some((_, k)) = c.iter().find(|(x, _)| *x == key)
    {
        return Ok(*k);
    }
    let out = argon2_key(password, salt, p)?;
    if let Some(c) = FUZZ_KDF_CACHE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
    {
        if c.len() >= FUZZ_KDF_CACHE_LEN {
            c.remove(0);
        }
        c.push((key, out));
    }
    Ok(out)
}

fn argon2_key(password: &str, salt: &[u8; 16], p: KdfParams) -> Result<[u8; 32]> {
    let params = argon2::Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(32))
        .map_err(|e| anyhow!("Argon2id parameters: {e}"))?;
    let a = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    a.hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|e| anyhow!("Argon2id: {e}"))?;
    Ok(out)
}

fn derive(aead: Aead, mut master: [u8; 32]) -> (Keys, [u8; 16]) {
    let keys = Keys {
        aead,
        block: blake3::derive_key(CTX_BLOCK, &master),
        index: blake3::derive_key(CTX_INDEX, &master),
        hash: blake3::derive_key(CTX_HASH, &master),
    };
    let check: [u8; 16] = blake3::derive_key(CTX_CHECK, &master)[..16]
        .try_into()
        .unwrap();
    master.zeroize();
    (keys, check)
}

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| anyhow!("OS random generator: {e}"))?;
    Ok(b)
}

/// New keys and the descriptor to store in the archive.
pub fn create(password: &str, aead: Aead, kdf: KdfParams) -> Result<(Keys, CryptoHeader)> {
    ensure!(!password.is_empty(), "empty password");
    let salt = random::<16>()?;
    let (keys, check) = derive(aead, master_key(password, &salt, kdf)?);
    Ok((
        keys,
        CryptoHeader {
            aead,
            m_cost_kib: kdf.m_cost_kib,
            t_cost: kdf.t_cost,
            p_cost: kdf.p_cost,
            salt,
            check,
        },
    ))
}

/// Keys for an existing archive; fails on a wrong password.
pub fn open(password: &str, h: &CryptoHeader) -> Result<Keys> {
    let kdf = KdfParams {
        m_cost_kib: h.m_cost_kib,
        t_cost: h.t_cost,
        p_cost: h.p_cost,
    };
    let (keys, check) = derive(h.aead, master_key(password, &h.salt, kdf)?);
    ensure!(check == h.check, "wrong password");
    Ok(keys)
}

pub fn seal(
    aead: Aead,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>> {
    let payload = Payload { msg: pt, aad };
    let r = match aead {
        Aead::Aes256Gcm => aes_gcm::Aes256Gcm::new(key.into()).encrypt(nonce.into(), payload),
        Aead::ChaCha20Poly1305 => {
            chacha20poly1305::ChaCha20Poly1305::new(key.into()).encrypt(nonce.into(), payload)
        }
    };
    r.map_err(|_| anyhow!("encryption failed"))
}

pub fn open_sealed(
    aead: Aead,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let payload = Payload { msg: ct, aad };
    let r = match aead {
        Aead::Aes256Gcm => aes_gcm::Aes256Gcm::new(key.into()).decrypt(nonce.into(), payload),
        Aead::ChaCha20Poly1305 => {
            chacha20poly1305::ChaCha20Poly1305::new(key.into()).decrypt(nonce.into(), payload)
        }
    };
    r.map_err(|_| anyhow!("authentication failed (damaged data or wrong key)"))
}

/// Content hash: BLAKE3, keyed with the hash key when encrypted.
pub fn content_hash(keys: Option<&Keys>, data: &[u8]) -> [u8; 32] {
    match keys {
        Some(k) => *blake3::keyed_hash(&k.hash, data).as_bytes(),
        None => *blake3::hash(data).as_bytes(),
    }
}
