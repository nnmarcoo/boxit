//! Crypto layer (§7.1) — KDF, STREAM AEAD, key management.
//!
//! This layer knows nothing about the filesystem, the vault format, or the UI.
//! Everything here is testable headlessly, which is the point of milestone 1.

pub mod kdf;
pub mod stream;

use std::fmt;

/// Errors from the crypto layer.
///
/// Authentication failures deliberately do not report *which* chunk failed or
/// why. That detail is useful to an attacker probing a vault and useless to a
/// user, who can only act on "this file is corrupt or the passphrase is wrong".
#[derive(Debug)]
pub enum CryptoError {
    /// The OS random number generator failed.
    Rng,
    /// Argon2 rejected the parameters or failed to derive.
    KeyDerivation,
    /// AEAD encryption failed.
    Encrypt,
    /// Authentication failed: wrong key, corruption, or tampering.
    Decrypt,
    /// The stream ended before a complete chunk was available.
    Truncated,
    Io(std::io::Error),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rng => write!(f, "the system random number generator failed"),
            Self::KeyDerivation => write!(f, "key derivation failed"),
            Self::Encrypt => write!(f, "encryption failed"),
            Self::Decrypt => write!(
                f,
                "decryption failed: wrong passphrase, or the data is corrupt or has been modified"
            ),
            Self::Truncated => write!(f, "the encrypted data is incomplete"),
            Self::Io(e) => write!(f, "i/o error: {e}"),
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
