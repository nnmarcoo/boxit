//! Property tests for the crypto core (§8, milestone 1).
//!
//! The three properties the handoff calls out by name: round-trip fidelity,
//! tamper detection, truncation detection. Chunk boundaries are the interesting
//! region, so the generators deliberately straddle `CHUNK_SIZE`.

use boxit::crypto::kdf::{Key, KdfParams, SALT_LEN, derive_wrapping_key};
use boxit::crypto::stream::{CHUNK_SIZE, STREAM_NONCE_LEN, TAG_LEN, decrypt, encrypt};
use proptest::prelude::*;

fn key() -> Key {
    Key::from_bytes([42u8; 32])
}

fn enc(data: &[u8]) -> Vec<u8> {
    let mut ct = Vec::new();
    encrypt(&key(), data, &mut ct).unwrap();
    ct
}

fn dec(ct: &[u8]) -> Result<Vec<u8>, boxit::crypto::CryptoError> {
    let mut pt = Vec::new();
    decrypt(&key(), ct, &mut pt)?;
    Ok(pt)
}

/// Sizes near chunk boundaries, where off-by-one chunking bugs live.
fn boundary_sizes() -> impl Strategy<Value = usize> {
    prop_oneof![
        Just(0usize),
        Just(1),
        Just(CHUNK_SIZE - 1),
        Just(CHUNK_SIZE),
        Just(CHUNK_SIZE + 1),
        Just(CHUNK_SIZE * 2 - 1),
        Just(CHUNK_SIZE * 2),
        Just(CHUNK_SIZE * 2 + 1),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Round-trip fidelity: decrypt(encrypt(x)) == x, for arbitrary bytes.
    #[test]
    fn roundtrip_preserves_arbitrary_data(data in prop::collection::vec(any::<u8>(), 0..5000)) {
        prop_assert_eq!(dec(&enc(&data)).unwrap(), data);
    }

    /// Round-trip fidelity across chunk boundaries.
    #[test]
    fn roundtrip_at_chunk_boundaries(size in boundary_sizes()) {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        prop_assert_eq!(dec(&enc(&data)).unwrap(), data);
    }

    /// Tamper detection: flipping any single bit anywhere must fail the AEAD.
    #[test]
    fn any_single_bit_flip_is_detected(
        data in prop::collection::vec(any::<u8>(), 1..3000),
        bit in 0usize..8,
    ) {
        let ct = enc(&data);
        let idx = bit % ct.len().max(1);
        let mut bad = ct.clone();
        bad[idx] ^= 1 << bit;
        prop_assert!(dec(&bad).is_err(), "bit {bit} of byte {idx} not detected");
    }

    /// Tamper detection at an arbitrary offset.
    #[test]
    fn tamper_at_arbitrary_offset_is_detected(
        data in prop::collection::vec(any::<u8>(), 1..3000),
        offset in any::<prop::sample::Index>(),
    ) {
        let ct = enc(&data);
        let idx = offset.index(ct.len());
        let mut bad = ct.clone();
        bad[idx] = bad[idx].wrapping_add(1);
        prop_assert!(dec(&bad).is_err(), "tamper at byte {idx} not detected");
    }

    /// Truncation detection: any proper prefix must fail, never decrypt to a
    /// shorter file. This is the property STREAM's last-chunk marker buys us.
    #[test]
    fn any_truncation_is_detected(
        data in prop::collection::vec(any::<u8>(), 1..3000),
        cut in any::<prop::sample::Index>(),
    ) {
        let ct = enc(&data);
        let at = cut.index(ct.len());
        prop_assert!(dec(&ct[..at]).is_err(), "truncation to {at} bytes not detected");
    }

    /// Truncation at exact chunk boundaries, the case most likely to slip past.
    #[test]
    fn chunk_aligned_truncation_is_detected(chunks in 1usize..3) {
        let data = vec![9u8; CHUNK_SIZE * 3];
        let ct = enc(&data);
        let at = STREAM_NONCE_LEN + chunks * (CHUNK_SIZE + TAG_LEN);
        prop_assert!(dec(&ct[..at]).is_err(), "aligned truncation at {chunks} chunks not detected");
    }

    /// Appending data must not be accepted: the stream ended at `encrypt_last`.
    #[test]
    fn extension_is_detected(
        data in prop::collection::vec(any::<u8>(), 1..2000),
        extra in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        let mut ct = enc(&data);
        ct.extend_from_slice(&extra);
        prop_assert!(dec(&ct).is_err(), "appended data not detected");
    }

    /// Any key other than the encrypting one must fail.
    #[test]
    fn wrong_key_never_decrypts(
        data in prop::collection::vec(any::<u8>(), 1..2000),
        k in any::<[u8; 32]>(),
    ) {
        prop_assume!(k != [42u8; 32]);
        let ct = enc(&data);
        let mut pt = Vec::new();
        prop_assert!(decrypt(&Key::from_bytes(k), ct.as_slice(), &mut pt).is_err());
    }

    /// Encryption is randomized: the same plaintext twice must differ, or a
    /// nonce is being reused.
    #[test]
    fn encryption_is_randomized(data in prop::collection::vec(any::<u8>(), 1..500)) {
        prop_assert_ne!(enc(&data), enc(&data));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    /// Distinct passphrases must not collide under the same salt. Few cases:
    /// Argon2id at default cost is intentionally slow.
    #[test]
    fn distinct_passphrases_give_distinct_keys(
        a in "\\PC{1,32}",
        b in "\\PC{1,32}",
    ) {
        prop_assume!(a != b);
        let salt = [7u8; SALT_LEN];
        let p = KdfParams::default();
        let ka = derive_wrapping_key(a.as_bytes(), &salt, p).unwrap();
        let kb = derive_wrapping_key(b.as_bytes(), &salt, p).unwrap();
        prop_assert_ne!(ka.as_bytes(), kb.as_bytes());
    }
}
