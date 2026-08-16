//! Streaming file content encryption (§5.2).
//!
//! XChaCha20-Poly1305 under the STREAM construction from `aead-stream`. STREAM
//! supplies per-chunk nonce derivation and last-chunk marking, which is what
//! makes truncation detectable. The chunking is deliberately *not* hand-rolled
//! — that is where nonce reuse gets introduced (§5.2).
//!
//! Wire format of an encrypted stream:
//!
//! ```text
//! [19-byte stream nonce][chunk 0][chunk 1]...[final chunk]
//! ```
//!
//! Each chunk is `CHUNK_SIZE` plaintext bytes (the last may be shorter) plus a
//! 16-byte Poly1305 tag. The final chunk is marked as such by STREAM, so a
//! truncated file fails to authenticate rather than decrypting to a short file.

use std::io::{Read, Write};

use aead_stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::Key as AeadKey;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use rand::TryRngCore;
use rand::rngs::OsRng;

use super::CryptoError;
use super::kdf::Key;

/// Plaintext bytes per chunk (§5.2).
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Poly1305 authentication tag appended to every chunk.
pub const TAG_LEN: usize = 16;

/// BE32 reserves 5 of XChaCha20's 24 nonce bytes for the 32-bit chunk counter
/// and the last-chunk flag, leaving 19 bytes of random stream nonce.
pub const STREAM_NONCE_LEN: usize = 19;

fn cipher(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&AeadKey::<XChaCha20Poly1305>::from(*key.as_bytes()))
}

/// Encrypt everything readable from `plaintext` into `ciphertext`.
///
/// A fresh random stream nonce is generated per call and written as a prefix.
/// Reusing a nonce across two streams under the same key would be fatal, so
/// callers are given no way to supply one.
pub fn encrypt<R: Read, W: Write>(
    key: &Key,
    mut plaintext: R,
    mut ciphertext: W,
) -> Result<(), CryptoError> {
    let mut nonce = [0u8; STREAM_NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| CryptoError::Rng)?;
    ciphertext.write_all(&nonce)?;

    let mut encryptor = EncryptorBE32::from_aead(cipher(key), &nonce.into());
    let mut buf = vec![0u8; CHUNK_SIZE];

    // One chunk is held back so the stream can be closed with `encrypt_last`.
    // Without that marker a truncated file would decrypt cleanly.
    let mut pending = read_chunk(&mut plaintext, &mut buf)?;

    loop {
        let chunk = buf[..pending].to_vec();
        let next = read_chunk(&mut plaintext, &mut buf)?;

        if next == 0 {
            let out = encryptor
                .encrypt_last(chunk.as_slice())
                .map_err(|_| CryptoError::Encrypt)?;
            ciphertext.write_all(&out)?;
            break;
        }

        let out = encryptor
            .encrypt_next(chunk.as_slice())
            .map_err(|_| CryptoError::Encrypt)?;
        ciphertext.write_all(&out)?;
        pending = next;
    }

    ciphertext.flush()?;
    Ok(())
}

/// Decrypt a stream produced by [`encrypt`].
///
/// Fails on any tampering, truncation, or wrong key. Output is only written for
/// chunks that authenticate, but callers must still treat partial output as
/// untrusted if this returns an error — see the note in `vault::fs` about
/// writing to a temp file and renaming only on success (§5.5).
pub fn decrypt<R: Read, W: Write>(
    key: &Key,
    mut ciphertext: R,
    mut plaintext: W,
) -> Result<(), CryptoError> {
    let mut nonce = [0u8; STREAM_NONCE_LEN];
    ciphertext
        .read_exact(&mut nonce)
        .map_err(|_| CryptoError::Truncated)?;

    let mut decryptor = DecryptorBE32::from_aead(cipher(key), &nonce.into());
    let encrypted_chunk = CHUNK_SIZE + TAG_LEN;
    let mut buf = vec![0u8; encrypted_chunk];

    let mut pending = read_chunk(&mut ciphertext, &mut buf)?;
    if pending == 0 {
        // A valid stream always has at least one chunk, even for empty input.
        return Err(CryptoError::Truncated);
    }

    loop {
        let chunk = buf[..pending].to_vec();
        let next = read_chunk(&mut ciphertext, &mut buf)?;

        if next == 0 {
            let out = decryptor
                .decrypt_last(chunk.as_slice())
                .map_err(|_| CryptoError::Decrypt)?;
            plaintext.write_all(&out)?;
            break;
        }

        let out = decryptor
            .decrypt_next(chunk.as_slice())
            .map_err(|_| CryptoError::Decrypt)?;
        plaintext.write_all(&out)?;
        pending = next;
    }

    plaintext.flush()?;
    Ok(())
}

/// Fill `buf` until it is full or the reader is exhausted.
///
/// `Read::read` may return fewer bytes than requested for reasons unrelated to
/// EOF, so a short read must not be mistaken for the end of the stream: that
/// would silently change the chunk boundaries.
fn read_chunk<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, CryptoError> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(CryptoError::Io(e)),
        }
    }
    Ok(filled)
}

/// Ciphertext length for a given plaintext length, for progress reporting and
/// preallocation.
pub const fn ciphertext_len(plaintext_len: u64) -> u64 {
    let chunk = CHUNK_SIZE as u64;
    // Chunks are only emitted for data that exists, so an exact multiple of
    // CHUNK_SIZE produces no trailing empty chunk. An empty plaintext is the
    // one exception: it still produces a single empty, authenticated chunk.
    let chunks = if plaintext_len == 0 {
        1
    } else {
        plaintext_len.div_ceil(chunk)
    };
    STREAM_NONCE_LEN as u64 + plaintext_len + chunks * TAG_LEN as u64
}

/// Plaintext length for a given ciphertext length — the inverse of
/// [`ciphertext_len`].
///
/// Used to size progress bars from on-disk file sizes without decrypting
/// anything. Returns 0 for lengths too short to be a valid stream.
pub const fn plaintext_len(ciphertext_len: u64) -> u64 {
    let overhead = STREAM_NONCE_LEN as u64;
    if ciphertext_len <= overhead {
        return 0;
    }

    let body = ciphertext_len - overhead;
    let chunk = (CHUNK_SIZE + TAG_LEN) as u64;

    // Every full chunk carries one tag; the trailing partial chunk carries one
    // more unless it is exactly empty.
    let full = body / chunk;
    let rest = body % chunk;
    let tags = if rest == 0 { full } else { full + 1 };

    body.saturating_sub(tags * TAG_LEN as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> Key {
        Key::from_bytes([42u8; 32])
    }

    fn roundtrip(data: &[u8]) -> Vec<u8> {
        let mut ct = Vec::new();
        encrypt(&key(), data, &mut ct).unwrap();
        let mut pt = Vec::new();
        decrypt(&key(), ct.as_slice(), &mut pt).unwrap();
        pt
    }

    #[test]
    fn roundtrip_empty() {
        assert_eq!(roundtrip(b""), b"");
    }

    #[test]
    fn roundtrip_small() {
        assert_eq!(roundtrip(b"hello vault"), b"hello vault");
    }

    #[test]
    fn roundtrip_exactly_one_chunk() {
        let data = vec![7u8; CHUNK_SIZE];
        assert_eq!(roundtrip(&data), data);
    }

    #[test]
    fn roundtrip_multi_chunk() {
        let data: Vec<u8> = (0..CHUNK_SIZE * 3 + 1234).map(|i| (i % 251) as u8).collect();
        assert_eq!(roundtrip(&data), data);
    }

    #[test]
    fn ciphertext_length_matches_prediction() {
        // Exact multiples of CHUNK_SIZE matter: they emit no trailing chunk.
        for len in [
            0usize,
            1,
            1000,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            CHUNK_SIZE * 2,
            CHUNK_SIZE * 2 + 1,
        ] {
            let data = vec![1u8; len];
            let mut ct = Vec::new();
            encrypt(&key(), data.as_slice(), &mut ct).unwrap();
            assert_eq!(ct.len() as u64, ciphertext_len(len as u64), "len {len}");
        }
    }

    #[test]
    fn plaintext_len_inverts_ciphertext_len() {
        for len in [
            0u64,
            1,
            1000,
            CHUNK_SIZE as u64 - 1,
            CHUNK_SIZE as u64,
            CHUNK_SIZE as u64 + 1,
            CHUNK_SIZE as u64 * 3,
            CHUNK_SIZE as u64 * 3 + 77,
        ] {
            assert_eq!(
                plaintext_len(ciphertext_len(len)),
                len,
                "round trip failed for plaintext length {len}"
            );
        }
    }

    #[test]
    fn plaintext_len_handles_garbage_lengths() {
        // Shorter than a nonce: not a valid stream, must not underflow.
        for len in [0u64, 1, STREAM_NONCE_LEN as u64] {
            assert_eq!(plaintext_len(len), 0);
        }
    }

    #[test]
    fn wrong_key_fails() {
        let mut ct = Vec::new();
        encrypt(&key(), b"secret".as_slice(), &mut ct).unwrap();

        let mut pt = Vec::new();
        let wrong = Key::from_bytes([43u8; 32]);
        assert!(decrypt(&wrong, ct.as_slice(), &mut pt).is_err());
    }

    #[test]
    fn tamper_in_body_is_detected() {
        let mut ct = Vec::new();
        encrypt(&key(), b"secret payload".as_slice(), &mut ct).unwrap();

        for i in 0..ct.len() {
            let mut bad = ct.clone();
            bad[i] ^= 0x01;
            let mut pt = Vec::new();
            assert!(
                decrypt(&key(), bad.as_slice(), &mut pt).is_err(),
                "flipping byte {i} was not detected"
            );
        }
    }

    #[test]
    fn truncation_is_detected() {
        let data = vec![5u8; CHUNK_SIZE * 2];
        let mut ct = Vec::new();
        encrypt(&key(), data.as_slice(), &mut ct).unwrap();

        // Dropping the final chunk must not decrypt to a valid shorter file.
        let cut = STREAM_NONCE_LEN + CHUNK_SIZE + TAG_LEN;
        let mut pt = Vec::new();
        assert!(decrypt(&key(), &ct[..cut], &mut pt).is_err());
    }

    #[test]
    fn truncated_nonce_is_detected() {
        let mut ct = Vec::new();
        encrypt(&key(), b"data".as_slice(), &mut ct).unwrap();
        let mut pt = Vec::new();
        assert!(decrypt(&key(), &ct[..10], &mut pt).is_err());
    }

    #[test]
    fn empty_ciphertext_is_rejected() {
        let mut pt = Vec::new();
        assert!(decrypt(&key(), b"".as_slice(), &mut pt).is_err());
    }

    #[test]
    fn chunk_reorder_is_detected() {
        let data: Vec<u8> = (0..CHUNK_SIZE * 2).map(|i| (i % 251) as u8).collect();
        let mut ct = Vec::new();
        encrypt(&key(), data.as_slice(), &mut ct).unwrap();

        // Swap the two full chunks; STREAM's counter must reject this.
        let size = CHUNK_SIZE + TAG_LEN;
        let mut swapped = ct.clone();
        let (a, b) = (STREAM_NONCE_LEN, STREAM_NONCE_LEN + size);
        swapped[a..a + size].copy_from_slice(&ct[b..b + size]);
        swapped[b..b + size].copy_from_slice(&ct[a..a + size]);

        let mut pt = Vec::new();
        assert!(decrypt(&key(), swapped.as_slice(), &mut pt).is_err());
    }

    #[test]
    fn nonce_differs_between_encryptions() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        encrypt(&key(), b"same".as_slice(), &mut a).unwrap();
        encrypt(&key(), b"same".as_slice(), &mut b).unwrap();
        assert_ne!(a, b, "identical ciphertexts imply a reused nonce");
    }
}
