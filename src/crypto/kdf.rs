//! Key derivation and key material handling (§5.1).
//!
//! A random master key is wrapped by a passphrase-derived key rather than being
//! derived from the passphrase directly. Rotating a passphrase then rewrites
//! only the header instead of re-encrypting the whole vault (§9.6).
//!
//! Subkeys are separated by domain so the content key and the filename key are
//! never the same bytes (§5.1).

use argon2::{Algorithm, Argon2, Params, Version};
use rand::TryRngCore;
use rand::rngs::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::CryptoError;

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;

/// Domain separation for subkey derivation. Distinct labels must never collide.
const LABEL_CONTENT: &[u8] = b"boxit:v1:content";
const LABEL_NAMES: &[u8] = b"boxit:v1:names";

/// 32 bytes of secret key material, wiped on drop.
///
/// Deliberately not `Clone`: every copy is another buffer that has to be wiped,
/// and the compiler is better at enforcing that than review is.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh random key from the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0u8; KEY_LEN];
        OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| CryptoError::Rng)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Derive the content-encryption subkey (§5.2).
    pub fn content_key(&self) -> Result<Key, CryptoError> {
        self.subkey(LABEL_CONTENT)
    }

    /// Derive the filename-encryption subkey (§5.3).
    pub fn names_key(&self) -> Result<Key, CryptoError> {
        self.subkey(LABEL_NAMES)
    }

    /// Derive a labelled subkey from this key.
    ///
    /// Argon2id is used here in its keyed-hash capacity with minimum cost
    /// parameters: the input is already a full-entropy 32-byte key, so there is
    /// no brute-force search to slow down. The expensive parameters belong on
    /// the passphrase path in [`derive_wrapping_key`], not here.
    fn subkey(&self, label: &[u8]) -> Result<Key, CryptoError> {
        let params = Params::new(Params::MIN_M_COST, Params::MIN_T_COST, 1, Some(KEY_LEN))
            .map_err(|_| CryptoError::KeyDerivation)?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        let mut out = [0u8; KEY_LEN];
        argon
            .hash_password_into(&self.0, &pad_salt(label), &mut out)
            .map_err(|_| CryptoError::KeyDerivation)?;

        let key = Key(out);
        out.zeroize();
        Ok(key)
    }
}

/// Argon2 requires a salt of at least 8 bytes; labels are short and fixed, so
/// pad rather than reject. Distinct labels stay distinct after padding.
fn pad_salt(label: &[u8]) -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    let n = label.len().min(SALT_LEN);
    salt[..n].copy_from_slice(&label[..n]);
    salt
}

/// Argon2id cost parameters, stored in the vault header so they can be raised
/// later without breaking existing vaults (§5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// ~64 MiB, 3 passes, 1 lane. Interactive-login territory: costly enough to
    /// hurt an offline guesser, fast enough that unlocking is not annoying.
    fn default() -> Self {
        Self {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 1,
        }
    }
}

impl KdfParams {
    fn to_argon2(self) -> Result<Argon2<'static>, CryptoError> {
        let params = Params::new(self.m_cost, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|_| CryptoError::KeyDerivation)?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }
}

/// Generate a random salt for a new vault.
pub fn generate_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|_| CryptoError::Rng)?;
    Ok(salt)
}

/// Stretch a passphrase into the key that wraps the master key.
///
/// This is the deliberately slow step, and the only place the passphrase is
/// used. It never encrypts file data directly.
pub fn derive_wrapping_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<Key, CryptoError> {
    let mut out = [0u8; KEY_LEN];
    params
        .to_argon2()?
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| CryptoError::KeyDerivation)?;

    let key = Key(out);
    out.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_passphrase_and_salt_gives_same_key() {
        let salt = [3u8; SALT_LEN];
        let p = KdfParams::default();
        let a = derive_wrapping_key(b"correct horse", &salt, p).unwrap();
        let b = derive_wrapping_key(b"correct horse", &salt, p).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_passphrase_gives_different_key() {
        let salt = [3u8; SALT_LEN];
        let p = KdfParams::default();
        let a = derive_wrapping_key(b"correct horse", &salt, p).unwrap();
        let b = derive_wrapping_key(b"correct hoarse", &salt, p).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_gives_different_key() {
        let p = KdfParams::default();
        let a = derive_wrapping_key(b"same passphrase", &[1u8; SALT_LEN], p).unwrap();
        let b = derive_wrapping_key(b"same passphrase", &[2u8; SALT_LEN], p).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn subkeys_differ_from_master_and_each_other() {
        let master = Key::generate().unwrap();
        let content = master.content_key().unwrap();
        let names = master.names_key().unwrap();

        assert_ne!(content.as_bytes(), names.as_bytes());
        assert_ne!(content.as_bytes(), master.as_bytes());
        assert_ne!(names.as_bytes(), master.as_bytes());
    }

    #[test]
    fn subkey_derivation_is_deterministic() {
        let master = Key::from_bytes([9u8; KEY_LEN]);
        assert_eq!(
            master.content_key().unwrap().as_bytes(),
            master.content_key().unwrap().as_bytes()
        );
    }

    #[test]
    fn generated_keys_and_salts_are_not_all_zero() {
        assert_ne!(Key::generate().unwrap().as_bytes(), &[0u8; KEY_LEN]);
        assert_ne!(generate_salt().unwrap(), [0u8; SALT_LEN]);
    }

    #[test]
    fn generated_keys_are_distinct() {
        let a = Key::generate().unwrap();
        let b = Key::generate().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
