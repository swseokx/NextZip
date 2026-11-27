//! Decryption used by ALZ, EGG and ZIP: PKWARE traditional encryption
//! (ZipCrypto) and WinZip-style AES-CTR with PBKDF2-HMAC-SHA1 keys.

use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroize;

fn crc_table() -> &'static [u32; 256] {
    static T: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    T.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, e) in t.iter_mut().enumerate() {
            let mut c = i as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *e = c;
        }
        t
    })
}

/// PKWARE traditional ("ZipCrypto") stream cipher state (wiped on drop:
/// the keys are derived from the password).
#[derive(Clone)]
pub struct ZipCrypto {
    k: [u32; 3],
}

impl Drop for ZipCrypto {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

impl ZipCrypto {
    pub fn new(password: &[u8]) -> Self {
        let mut z = ZipCrypto {
            k: [0x1234_5678, 0x2345_6789, 0x3456_7890],
        };
        for &b in password {
            z.update(b);
        }
        z
    }
    fn update(&mut self, b: u8) {
        let t = crc_table();
        self.k[0] = t[((self.k[0] ^ u32::from(b)) & 0xFF) as usize] ^ (self.k[0] >> 8);
        self.k[1] = self.k[1]
            .wrapping_add(self.k[0] & 0xFF)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        self.k[2] = t[((self.k[2] ^ (self.k[1] >> 24)) & 0xFF) as usize] ^ (self.k[2] >> 8);
    }
    fn stream_byte(&self) -> u8 {
        let t = (self.k[2] | 2) & 0xFFFF;
        ((t * (t ^ 1)) >> 8) as u8
    }
    pub fn decrypt(&mut self, buf: &mut [u8]) {
        for b in buf {
            let c = *b ^ self.stream_byte();
            self.update(c);
            *b = c;
        }
    }
    pub fn encrypt(&mut self, buf: &mut [u8]) {
        for b in buf {
            let c = *b;
            *b ^= self.stream_byte();
            self.update(c);
        }
    }
    /// Decrypt the 12-byte header and return its last byte (the check byte).
    pub fn check_header(&mut self, header: &[u8; 12]) -> u8 {
        let mut h = *header;
        self.decrypt(&mut h);
        h[11]
    }
}

/// AES key sizes used by EGG and WinZip AE-x.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesBits {
    Aes128,
    Aes256,
}

impl AesBits {
    pub fn key_len(self) -> usize {
        match self {
            AesBits::Aes128 => 16,
            AesBits::Aes256 => 32,
        }
    }
    pub fn salt_len(self) -> usize {
        match self {
            AesBits::Aes128 => 8,
            AesBits::Aes256 => 16,
        }
    }
}

enum Cipher {
    A128(Box<aes::Aes128>),
    A256(Box<aes::Aes256>),
}

/// AES-CTR with a little-endian counter starting at 1 (WinZip AE-2 style)
/// plus the HMAC-SHA1 authentication over the ciphertext.
pub struct AesCtr {
    cipher: Cipher,
    counter: [u8; 16],
    ks: [u8; 16],
    used: usize,
    mac: Hmac<Sha1>,
}

/// Derived key material (wiped on drop).
pub struct AesKeys {
    pub enc: Vec<u8>,
    pub auth: Vec<u8>,
    pub verifier: [u8; 2],
}

impl Drop for AesKeys {
    fn drop(&mut self) {
        self.enc.zeroize();
        self.auth.zeroize();
        self.verifier.zeroize();
    }
}

pub fn derive_aes(password: &[u8], salt: &[u8], bits: AesBits) -> AesKeys {
    let n = bits.key_len();
    let mut dk = vec![0u8; n * 2 + 2];
    pbkdf2::pbkdf2_hmac::<Sha1>(password, salt, 1000, &mut dk);
    let keys = AesKeys {
        enc: dk[..n].to_vec(),
        auth: dk[n..2 * n].to_vec(),
        verifier: [dk[2 * n], dk[2 * n + 1]],
    };
    dk.zeroize();
    keys
}

impl Drop for AesCtr {
    fn drop(&mut self) {
        // The cipher's key schedule is wiped by `aes` (feature zeroize).
        self.ks.zeroize();
        self.counter.zeroize();
    }
}

impl AesCtr {
    pub fn new(keys: &AesKeys) -> Self {
        let cipher = if keys.enc.len() == 16 {
            Cipher::A128(Box::new(aes::Aes128::new(GenericArray::from_slice(
                &keys.enc,
            ))))
        } else {
            Cipher::A256(Box::new(aes::Aes256::new(GenericArray::from_slice(
                &keys.enc,
            ))))
        };
        AesCtr {
            cipher,
            counter: [0; 16],
            ks: [0; 16],
            used: 16,
            mac: <Hmac<Sha1> as Mac>::new_from_slice(&keys.auth).expect("any key length"),
        }
    }
    fn next_block(&mut self) {
        for b in self.counter.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        let mut blk = GenericArray::clone_from_slice(&self.counter);
        match &self.cipher {
            Cipher::A128(c) => c.encrypt_block(&mut blk),
            Cipher::A256(c) => c.encrypt_block(&mut blk),
        }
        self.ks.copy_from_slice(&blk);
        self.used = 0;
    }
    fn xor(&mut self, buf: &mut [u8]) {
        for b in buf {
            if self.used == 16 {
                self.next_block();
            }
            *b ^= self.ks[self.used];
            self.used += 1;
        }
    }
    pub fn decrypt(&mut self, buf: &mut [u8]) {
        self.mac.update(buf);
        self.xor(buf);
    }
    pub fn encrypt(&mut self, buf: &mut [u8]) {
        self.xor(buf);
        self.mac.update(buf);
    }
    /// First 10 bytes of the HMAC over all ciphertext seen so far.
    pub fn tag(&self) -> [u8; 10] {
        let full = self.mac.clone().finalize().into_bytes();
        let mut t = [0u8; 10];
        t.copy_from_slice(&full[..10]);
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zipcrypto_roundtrip() {
        let mut data = b"hello hello hello".to_vec();
        ZipCrypto::new(b"pw").encrypt(&mut data);
        assert_ne!(&data, b"hello hello hello");
        ZipCrypto::new(b"pw").decrypt(&mut data);
        assert_eq!(&data, b"hello hello hello");
    }

    #[test]
    fn aes_roundtrip_and_tag() {
        let k = derive_aes(b"secret", &[1; 16], AesBits::Aes256);
        let mut data = vec![7u8; 100];
        let mut e = AesCtr::new(&k);
        e.encrypt(&mut data[..33]);
        e.encrypt(&mut data[33..]);
        let mut d = AesCtr::new(&k);
        d.decrypt(&mut data);
        assert_eq!(data, vec![7u8; 100]);
        assert_eq!(e.tag(), d.tag());
    }

    /// RFC 6070 PBKDF2-HMAC-SHA1 vector (4096 iterations).
    #[test]
    fn pbkdf2_reference() {
        let mut out = [0u8; 20];
        pbkdf2::pbkdf2_hmac::<Sha1>(b"password", b"salt", 4096, &mut out);
        assert_eq!(
            out,
            [
                0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7,
                0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1
            ]
        );
    }
}
