//! Deterministic filename encryption (§5.3, scheme (a)).
//!
//! AES-SIV over the filename with a dedicated subkey, base32-encoded for
//! filesystem safety. Deterministic on purpose: listing a directory is then
//! `readdir` plus a decrypt per name, with no index to corrupt or keep in sync.
//!
//! The parent directory ID is mixed in as associated data, so the same name in
//! two directories encrypts to two different ciphertexts (§5.3). Without that,
//! `readdir` on the encrypted tree would reveal which directories share
//! filenames.
//!
//! What this leaks, by construction: name lengths, and the shape of the
//! directory tree (§6.4).

use aes_siv::aead::{Aead, Payload};
use aes_siv::{Aes256SivAead, KeyInit, Nonce};
use base32::Alphabet;

use super::CryptoError;
use super::kdf::Key;

/// Lowercase RFC4648 base32-hex, unpadded.
///
/// Lowercase and case-insensitive-safe: Windows and macOS filesystems are
/// case-insensitive, so a mixed-case alphabet could collide two distinct
/// ciphertexts onto one filename. base32 also avoids the `+` and `/` that
/// base64 would produce, neither of which is safe in a path.
const ALPHABET: Alphabet = Alphabet::Rfc4648HexLower { padding: false };

/// AES-SIV is nonce-reuse resistant and we *want* determinism here, so the
/// nonce is fixed. Uniqueness comes from the parent ID in the associated data.
/// Do not reuse this pattern for file contents — see `stream.rs` for that.
const FIXED_NONCE: [u8; 16] = [0u8; 16];

/// SIV tag overhead added to every encrypted name.
const SIV_OVERHEAD: usize = 16;

/// Longest plaintext filename that still fits a 255-byte filesystem limit after
/// SIV overhead and base32 expansion: `ceil((143 + 16) * 8 / 5) == 255`.
pub const MAX_NAME_LEN: usize = 143;

/// Identifies a directory for associated-data separation.
///
/// The vault root is the empty ID; every other directory uses its own encrypted
/// name, which is already unique among its siblings and stable across runs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DirId(Vec<u8>);

impl DirId {
    /// The vault root.
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// The ID of a subdirectory, given its encrypted name.
    ///
    /// Built from the *encrypted* name so it can be recomputed while walking
    /// the on-disk tree without decrypting anything first.
    pub fn child(encrypted_name: &str) -> Self {
        Self(encrypted_name.as_bytes().to_vec())
    }

    fn as_aad(&self) -> &[u8] {
        &self.0
    }
}

fn cipher(key: &Key) -> Result<Aes256SivAead, CryptoError> {
    // Aes256SivAead takes a 64-byte key; expand our 32-byte subkey into the two
    // halves SIV needs (S2V key and CTR key) rather than truncating a hash.
    let mut material = [0u8; 64];
    material[..32].copy_from_slice(key.as_bytes());
    material[32..].copy_from_slice(key.names_half()?.as_bytes());

    let c = Aes256SivAead::new_from_slice(&material).map_err(|_| CryptoError::KeyDerivation)?;
    Ok(c)
}

/// Encrypt a single path component.
///
/// `parent` binds the result to its directory, so identical names in different
/// directories do not produce identical ciphertext.
pub fn encrypt_name(key: &Key, parent: &DirId, name: &str) -> Result<String, CryptoError> {
    if name.is_empty() {
        return Err(CryptoError::InvalidName);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(CryptoError::NameTooLong);
    }
    // `.` and `..` are not real entries and must never reach the filesystem.
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(CryptoError::InvalidName);
    }

    let ct = cipher(key)?
        .encrypt(
            &Nonce::from(FIXED_NONCE),
            Payload {
                msg: name.as_bytes(),
                aad: parent.as_aad(),
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;

    Ok(base32::encode(ALPHABET, &ct))
}

/// Decrypt a single path component produced by [`encrypt_name`].
///
/// Fails if the name was encrypted under a different parent, which also means a
/// file moved between directories on disk will not silently decrypt.
pub fn decrypt_name(key: &Key, parent: &DirId, encrypted: &str) -> Result<String, CryptoError> {
    let ct = base32::decode(ALPHABET, encrypted).ok_or(CryptoError::InvalidName)?;
    if ct.len() < SIV_OVERHEAD {
        return Err(CryptoError::InvalidName);
    }

    let pt = cipher(key)?
        .decrypt(
            &Nonce::from(FIXED_NONCE),
            Payload {
                msg: ct.as_slice(),
                aad: parent.as_aad(),
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;

    String::from_utf8(pt).map_err(|_| CryptoError::InvalidName)
}

/// Encrypted length of a plaintext name, for length-limit checks.
pub fn encrypted_name_len(plaintext_len: usize) -> usize {
    // Unpadded base32: 8 output chars per 5 input bytes, with a partial final
    // group emitting only the characters it needs rather than padding out.
    ((plaintext_len + SIV_OVERHEAD) * 8).div_ceil(5)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::from_bytes([17u8; 32])
    }

    #[test]
    fn roundtrip() {
        let k = key();
        let p = DirId::root();
        for name in ["a", "notes.txt", "Some File (1).tar.gz", "ünïcödé — файл.md"] {
            let enc = encrypt_name(&k, &p, name).unwrap();
            assert_eq!(decrypt_name(&k, &p, &enc).unwrap(), name);
        }
    }

    #[test]
    fn deterministic_across_calls() {
        let k = key();
        let p = DirId::root();
        assert_eq!(
            encrypt_name(&k, &p, "stable.txt").unwrap(),
            encrypt_name(&k, &p, "stable.txt").unwrap()
        );
    }

    #[test]
    fn same_name_differs_between_directories() {
        let k = key();
        let a = encrypt_name(&k, &DirId::child("dir-a"), "notes.txt").unwrap();
        let b = encrypt_name(&k, &DirId::child("dir-b"), "notes.txt").unwrap();
        assert_ne!(a, b, "parent id is not being mixed into the SIV aad");
    }

    #[test]
    fn wrong_parent_fails_to_decrypt() {
        let k = key();
        let enc = encrypt_name(&k, &DirId::child("dir-a"), "notes.txt").unwrap();
        assert!(decrypt_name(&k, &DirId::child("dir-b"), &enc).is_err());
    }

    #[test]
    fn wrong_key_fails_to_decrypt() {
        let p = DirId::root();
        let enc = encrypt_name(&key(), &p, "secret.txt").unwrap();
        let other = Key::from_bytes([18u8; 32]);
        assert!(decrypt_name(&other, &p, &enc).is_err());
    }

    #[test]
    fn tampered_name_fails() {
        let k = key();
        let p = DirId::root();
        let enc = encrypt_name(&k, &p, "notes.txt").unwrap();

        let mut chars: Vec<char> = enc.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        let bad: String = chars.into_iter().collect();

        assert!(decrypt_name(&k, &p, &bad).is_err());
    }

    #[test]
    fn output_is_filesystem_safe() {
        let k = key();
        let p = DirId::root();
        // Legal on POSIX, illegal on Windows: the codec must launder these into
        // a name that is writable on every platform.
        let enc = encrypt_name(&k, &p, "a:b*c?d\"e<f>g|h.txt").unwrap();
        assert!(
            enc.chars().all(|c| c.is_ascii_alphanumeric()),
            "unsafe chars in {enc}"
        );
        assert!(enc.chars().all(|c| !c.is_ascii_uppercase()));
    }

    #[test]
    fn rejects_path_separators_and_dot_entries() {
        let k = key();
        let p = DirId::root();
        for bad in ["", ".", "..", "a/b", "a\\b"] {
            assert!(encrypt_name(&k, &p, bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn rejects_overlong_names() {
        let k = key();
        let p = DirId::root();
        let ok = "a".repeat(MAX_NAME_LEN);
        let too_long = "a".repeat(MAX_NAME_LEN + 1);

        let enc = encrypt_name(&k, &p, &ok).unwrap();
        assert!(enc.len() <= 255, "encoded name exceeds fs limit: {}", enc.len());
        assert!(encrypt_name(&k, &p, &too_long).is_err());
    }

    #[test]
    fn encrypted_len_matches_prediction() {
        let k = key();
        let p = DirId::root();
        for n in [1usize, 9, 50, 143] {
            let name = "a".repeat(n);
            let enc = encrypt_name(&k, &p, &name).unwrap();
            assert_eq!(enc.len(), encrypted_name_len(n), "for {n}-byte name");
        }
    }

    #[test]
    fn malformed_base32_is_rejected() {
        let k = key();
        let p = DirId::root();
        for bad in ["", "!!!!", "zzzz"] {
            assert!(decrypt_name(&k, &p, bad).is_err(), "accepted {bad:?}");
        }
    }
}
