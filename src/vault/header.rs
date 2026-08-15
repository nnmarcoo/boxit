//! The `.vault-header` file (§5.4).
//!
//! Stores everything needed to turn a passphrase back into the master key:
//! format version, KDF salt and parameters, and the master key wrapped by the
//! passphrase-derived key.
//!
//! The header is plaintext apart from the wrapped key. It has to be — it holds
//! the parameters required to derive the key that would decrypt it. Nothing
//! secret goes in it.
//!
//! Wrapping rather than deriving the master key directly means a passphrase
//! change rewrites only this file, not the whole vault (§9.6).
//!
//! ```text
//! magic    8   b"BOXITVLT"
//! version  2   u16 little-endian
//! salt    16   Argon2id salt
//! m_cost   4   u32 le
//! t_cost   4   u32 le
//! p_cost   4   u32 le
//! wrapped 67   19-byte stream nonce + 32-byte key + 16-byte tag
//! ```

use std::io::{Read, Write};

use crate::crypto::CryptoError;
use crate::crypto::kdf::{KEY_LEN, KdfParams, Key, SALT_LEN, derive_wrapping_key, generate_salt};
use crate::crypto::stream::{self, ciphertext_len};

const MAGIC: &[u8; 8] = b"BOXITVLT";

/// Format version. Present from v1 and non-negotiable (§5.4): without it, a
/// future format change cannot be detected, only misread.
pub const FORMAT_VERSION: u16 = 1;

/// The wrapped master key is a single-chunk STREAM ciphertext:
/// 19-byte stream nonce + 32-byte key + one 16-byte tag.
const WRAPPED_LEN: usize = 67;

/// Name of the header file. Excluded from encryption (§6.1).
pub const HEADER_FILENAME: &str = ".vault-header";

pub struct Header {
    pub version: u16,
    pub salt: [u8; SALT_LEN],
    pub params: KdfParams,
    wrapped_master: Vec<u8>,
}

impl Header {
    /// Create a header for a new vault, wrapping `master` under `passphrase`.
    pub fn create(
        passphrase: &[u8],
        master: &Key,
        params: KdfParams,
    ) -> Result<Self, CryptoError> {
        let salt = generate_salt()?;
        let wrapping = derive_wrapping_key(passphrase, &salt, params)?;

        let mut wrapped_master = Vec::with_capacity(WRAPPED_LEN);
        stream::encrypt(&wrapping, master.as_bytes().as_slice(), &mut wrapped_master)?;

        Ok(Self {
            version: FORMAT_VERSION,
            salt,
            params,
            wrapped_master,
        })
    }

    /// Recover the master key.
    ///
    /// The AEAD tag on the wrapped key doubles as the key check value (§5.4): a
    /// wrong passphrase fails here, immediately and unambiguously, rather than
    /// producing a master key that decrypts everything into garbage.
    pub fn unwrap_master(&self, passphrase: &[u8]) -> Result<Key, CryptoError> {
        let wrapping = derive_wrapping_key(passphrase, &self.salt, self.params)?;

        let mut out = Vec::with_capacity(KEY_LEN);
        stream::decrypt(&wrapping, self.wrapped_master.as_slice(), &mut out)?;

        let bytes: [u8; KEY_LEN] = out
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Decrypt)?;
        Ok(Key::from_bytes(bytes))
    }

    /// Re-wrap the master key under a new passphrase (§9.6).
    ///
    /// Only the header changes; file contents are untouched, because they are
    /// encrypted under subkeys of the master key rather than the passphrase.
    pub fn change_passphrase(
        &mut self,
        old: &[u8],
        new: &[u8],
        params: KdfParams,
    ) -> Result<(), CryptoError> {
        let master = self.unwrap_master(old)?;

        // A fresh salt on every change: reusing it would let someone who
        // captured the old header attack both passphrases with one derivation.
        let salt = generate_salt()?;
        let wrapping = derive_wrapping_key(new, &salt, params)?;

        let mut wrapped = Vec::with_capacity(WRAPPED_LEN);
        stream::encrypt(&wrapping, master.as_bytes().as_slice(), &mut wrapped)?;

        self.salt = salt;
        self.params = params;
        self.wrapped_master = wrapped;
        Ok(())
    }

    pub fn write<W: Write>(&self, mut w: W) -> Result<(), CryptoError> {
        w.write_all(MAGIC)?;
        w.write_all(&self.version.to_le_bytes())?;
        w.write_all(&self.salt)?;
        w.write_all(&self.params.m_cost.to_le_bytes())?;
        w.write_all(&self.params.t_cost.to_le_bytes())?;
        w.write_all(&self.params.p_cost.to_le_bytes())?;
        w.write_all(&self.wrapped_master)?;
        w.flush()?;
        Ok(())
    }

    pub fn read<R: Read>(mut r: R) -> Result<Self, CryptoError> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)
            .map_err(|_| CryptoError::BadHeader)?;
        if &magic != MAGIC {
            return Err(CryptoError::BadHeader);
        }

        let version = u16::from_le_bytes(read_array(&mut r)?);
        // Refuse rather than guess: a newer vault may have a layout this build
        // would misparse into plausible-looking nonsense.
        if version != FORMAT_VERSION {
            return Err(CryptoError::UnsupportedVersion(version));
        }

        let salt: [u8; SALT_LEN] = read_array(&mut r)?;
        let params = KdfParams {
            m_cost: u32::from_le_bytes(read_array(&mut r)?),
            t_cost: u32::from_le_bytes(read_array(&mut r)?),
            p_cost: u32::from_le_bytes(read_array(&mut r)?),
        };

        // Reject absurd parameters before handing them to Argon2: a corrupt
        // m_cost would otherwise try to allocate its way through all of RAM.
        if !params.is_sane() {
            return Err(CryptoError::BadHeader);
        }

        let mut wrapped_master = vec![0u8; WRAPPED_LEN];
        r.read_exact(&mut wrapped_master)
            .map_err(|_| CryptoError::BadHeader)?;

        Ok(Self {
            version,
            salt,
            params,
            wrapped_master,
        })
    }
}

fn read_array<const N: usize, R: Read>(r: &mut R) -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    r.read_exact(&mut buf).map_err(|_| CryptoError::BadHeader)?;
    Ok(buf)
}

/// Compile-time check that `WRAPPED_LEN` matches what the stream actually
/// produces, so a change to chunking or tag size fails the build rather than
/// silently writing short headers.
const _: () = assert!(WRAPPED_LEN as u64 == ciphertext_len(KEY_LEN as u64));

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> KdfParams {
        // Minimum cost: these tests exercise format logic, not KDF hardness.
        KdfParams {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[test]
    fn roundtrip_through_bytes() {
        let master = Key::generate().unwrap();
        let h = Header::create(b"open sesame", &master, params()).unwrap();

        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        let back = Header::read(buf.as_slice()).unwrap();

        assert_eq!(back.version, FORMAT_VERSION);
        assert_eq!(back.salt, h.salt);
        assert_eq!(back.params, h.params);
        assert_eq!(
            back.unwrap_master(b"open sesame").unwrap().as_bytes(),
            master.as_bytes()
        );
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let master = Key::generate().unwrap();
        let h = Header::create(b"correct", &master, params()).unwrap();
        assert!(h.unwrap_master(b"wrong").is_err());
    }

    #[test]
    fn header_size_is_fixed() {
        let master = Key::generate().unwrap();
        let h = Header::create(b"pw", &master, params()).unwrap();
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        assert_eq!(buf.len(), 8 + 2 + SALT_LEN + 12 + WRAPPED_LEN);
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut buf = vec![0u8; 128];
        buf[..8].copy_from_slice(b"NOTAVLT!");
        assert!(matches!(
            Header::read(buf.as_slice()),
            Err(CryptoError::BadHeader)
        ));
    }

    #[test]
    fn future_version_is_rejected() {
        let master = Key::generate().unwrap();
        let h = Header::create(b"pw", &master, params()).unwrap();
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        buf[8..10].copy_from_slice(&99u16.to_le_bytes());

        assert!(matches!(
            Header::read(buf.as_slice()),
            Err(CryptoError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn truncated_header_is_rejected() {
        let master = Key::generate().unwrap();
        let h = Header::create(b"pw", &master, params()).unwrap();
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();

        for cut in [0, 4, 8, 20, 40, buf.len() - 1] {
            assert!(Header::read(&buf[..cut]).is_err(), "accepted {cut} bytes");
        }
    }

    #[test]
    fn absurd_kdf_params_are_rejected() {
        let master = Key::generate().unwrap();
        let h = Header::create(b"pw", &master, params()).unwrap();
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();
        // m_cost = u32::MAX would ask Argon2 for terabytes of memory.
        buf[26..30].copy_from_slice(&u32::MAX.to_le_bytes());

        assert!(Header::read(buf.as_slice()).is_err());
    }

    #[test]
    fn tampered_wrapped_key_is_rejected() {
        let master = Key::generate().unwrap();
        let h = Header::create(b"pw", &master, params()).unwrap();
        let mut buf = Vec::new();
        h.write(&mut buf).unwrap();

        let last = buf.len() - 1;
        buf[last] ^= 1;

        let back = Header::read(buf.as_slice()).unwrap();
        assert!(back.unwrap_master(b"pw").is_err());
    }

    #[test]
    fn passphrase_change_preserves_master_key() {
        let master = Key::generate().unwrap();
        let mut h = Header::create(b"old pw", &master, params()).unwrap();
        let old_salt = h.salt;

        h.change_passphrase(b"old pw", b"new pw", params()).unwrap();

        assert_eq!(
            h.unwrap_master(b"new pw").unwrap().as_bytes(),
            master.as_bytes(),
            "master key must survive a passphrase change"
        );
        assert!(h.unwrap_master(b"old pw").is_err());
        assert_ne!(h.salt, old_salt, "salt must be refreshed on rotation");
    }

    #[test]
    fn passphrase_change_requires_the_old_passphrase() {
        let master = Key::generate().unwrap();
        let mut h = Header::create(b"old pw", &master, params()).unwrap();

        assert!(h.change_passphrase(b"guess", b"new pw", params()).is_err());
        assert_eq!(
            h.unwrap_master(b"old pw").unwrap().as_bytes(),
            master.as_bytes(),
            "a failed change must leave the header usable"
        );
    }
}
