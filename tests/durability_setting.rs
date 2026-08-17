//! The durability setting: an explicit trade of power-failure safety for speed.
//!
//! Correctness must be identical in both modes — the only difference is whether
//! writes wait for the drive. What is tested here is that `Fast` changes no
//! observable behaviour short of pulling the plug, and that the setting is
//! persisted and defaults safely.

use std::fs;

use boxit::crypto::kdf::KdfParams;
use boxit::vault::fs::Durability;
use boxit::vault::path::VirtualPath;
use boxit::vault::settings::Settings;
use boxit::vault::{Vault, VaultState};
use tempfile::TempDir;

fn params() -> KdfParams {
    KdfParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

const PW: &[u8] = b"durability test passphrase";

fn new_vault() -> (TempDir, Vault) {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();
    let v = Vault::unlock(dir.path(), PW).unwrap();
    (dir, v)
}

fn root() -> VirtualPath {
    VirtualPath::root()
}

#[test]
fn defaults_to_full_durability() {
    let (_dir, v) = new_vault();
    assert_eq!(
        v.durability(),
        Durability::Full,
        "a new vault must default to the safe setting"
    );
}

#[test]
fn fast_mode_round_trips_files_identically() {
    let (dir, v) = new_vault();
    let v = v.with_durability(Durability::Fast);

    fs::create_dir_all(dir.path().join("sub")).unwrap();
    let data: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    fs::write(dir.path().join("big.bin"), &data).unwrap();
    fs::write(dir.path().join("sub/note.txt"), b"hello").unwrap();

    v.encrypt_plaintext(&root()).unwrap();
    assert_eq!(v.state().unwrap(), VaultState::Locked);

    v.decrypt_all(&root()).unwrap();
    assert_eq!(fs::read(dir.path().join("big.bin")).unwrap(), data);
    assert_eq!(fs::read(dir.path().join("sub/note.txt")).unwrap(), b"hello");
}

#[test]
fn originals_are_still_removed_in_fast_mode() {
    let (dir, v) = new_vault();
    let v = v.with_durability(Durability::Fast);
    fs::write(dir.path().join("f.txt"), b"data").unwrap();

    v.encrypt_plaintext(&root()).unwrap();

    assert!(
        !dir.path().join("f.txt").exists(),
        "fast mode must still delete the plaintext, just without waiting"
    );
}

#[test]
fn setting_is_persisted_across_unlocks() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();

    let mut v = Vault::unlock(dir.path(), PW).unwrap();
    v.set_durability(Durability::Fast).unwrap();
    v.close().unwrap();

    let v = Vault::unlock(dir.path(), PW).unwrap();
    assert_eq!(v.durability(), Durability::Fast, "setting did not persist");
    v.close().unwrap();
}

#[test]
fn setting_can_be_turned_back_off() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();

    let mut v = Vault::unlock(dir.path(), PW).unwrap();
    v.set_durability(Durability::Fast).unwrap();
    v.set_durability(Durability::Full).unwrap();
    v.close().unwrap();

    let v = Vault::unlock(dir.path(), PW).unwrap();
    assert_eq!(v.durability(), Durability::Full);
    v.close().unwrap();
}

#[test]
fn settings_file_is_not_encrypted_by_a_lock() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();
    let mut v = Vault::unlock(dir.path(), PW).unwrap();
    v.set_durability(Durability::Fast).unwrap();

    fs::write(dir.path().join("f.txt"), b"data").unwrap();
    v.encrypt_plaintext(&root()).unwrap();

    // Swallowing the settings file would lose the preference silently; the
    // header would be far worse, and both live in the same place.
    assert!(
        dir.path().join(".vault-settings").exists(),
        "the settings file was encrypted by the lock"
    );
    assert!(dir.path().join(".vault-header").exists());

    // And it must still be readable as settings, not ciphertext.
    assert_eq!(Settings::load(dir.path()).durability, Durability::Fast);
}

#[test]
fn settings_file_is_not_listed_as_user_data() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();
    let mut v = Vault::unlock(dir.path(), PW).unwrap();
    v.set_durability(Durability::Fast).unwrap();

    assert!(
        v.list(&root()).unwrap().is_empty(),
        "vault metadata leaked into the listing"
    );
    // And it must not make an otherwise-empty vault look half-locked.
    assert_eq!(v.state().unwrap(), VaultState::Empty);
    v.close().unwrap();
}

#[test]
fn corrupt_settings_fall_back_to_safe() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();
    fs::write(dir.path().join(".vault-settings"), b"\x00\x01garbage\xff").unwrap();

    let v = Vault::unlock(dir.path(), PW).unwrap();
    assert_eq!(
        v.durability(),
        Durability::Full,
        "a damaged preferences file must never silently disable durability"
    );
    v.close().unwrap();
}

#[test]
fn failures_are_still_reported_in_fast_mode() {
    let (dir, v) = new_vault();
    let v = v.with_durability(Durability::Fast);

    // Too long to encrypt: must fail cleanly and keep the plaintext, exactly as
    // it does at full durability.
    let long = format!("{}.txt", "x".repeat(200));
    fs::write(dir.path().join(&long), b"must survive").unwrap();

    let report = v.encrypt_plaintext(&root()).unwrap();

    assert_eq!(report.files, 0);
    assert_eq!(report.failed.len(), 1);
    assert!(dir.path().join(&long).exists());
}
