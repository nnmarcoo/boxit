//! Tests for the lock/unlock model: the vault folder toggles between "all
//! ciphertext" and "all real files".
//!
//! The property that matters is that a full cycle is lossless. Files go in,
//! come back out byte-identical, with names and directory structure intact.

use std::fs;

use boxit::crypto::kdf::KdfParams;
use boxit::vault::path::VirtualPath;
use boxit::vault::{Vault, VaultState};
use tempfile::TempDir;

fn params() -> KdfParams {
    KdfParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

const PW: &[u8] = b"cycle test passphrase";

fn new_vault() -> (TempDir, Vault) {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();
    let v = Vault::unlock(dir.path(), PW).unwrap();
    (dir, v)
}

fn root() -> VirtualPath {
    VirtualPath::root()
}

/// Snapshot of a directory tree: relative path -> contents.
fn snapshot(dir: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    fn walk(base: &std::path::Path, dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == ".vault-header" || name == ".vault-lock" {
                continue;
            }
            let path = entry.path();
            if path.is_dir() {
                walk(base, &path, out);
            } else {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, fs::read(&path).unwrap()));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[test]
fn full_cycle_is_lossless() {
    let (dir, v) = new_vault();

    fs::create_dir_all(dir.path().join("photos/2026")).unwrap();
    fs::write(dir.path().join("notes.txt"), b"top level notes").unwrap();
    fs::write(dir.path().join("photos/a.jpg"), b"\xff\xd8\xff\xe0 fake jpeg").unwrap();
    fs::write(dir.path().join("photos/2026/b.png"), b"\x89PNG fake").unwrap();

    let before = snapshot(dir.path());
    assert_eq!(before.len(), 3);

    v.encrypt_plaintext(&root()).unwrap();
    v.decrypt_all(&root()).unwrap();

    assert_eq!(
        snapshot(dir.path()),
        before,
        "a lock/unlock cycle changed the files"
    );
}

#[test]
fn locking_then_unlocking_preserves_large_binary_files() {
    let (dir, v) = new_vault();
    // Multi-chunk, non-text, with bytes that would break a naive text path.
    let data: Vec<u8> = (0..300_000).map(|i| (i % 256) as u8).collect();
    fs::write(dir.path().join("video.mp4"), &data).unwrap();

    v.encrypt_plaintext(&root()).unwrap();
    assert!(!dir.path().join("video.mp4").exists(), "still plaintext after lock");

    v.decrypt_all(&root()).unwrap();
    assert_eq!(fs::read(dir.path().join("video.mp4")).unwrap(), data);
}

#[test]
fn state_reports_locked_and_unlocked() {
    let (dir, v) = new_vault();
    assert_eq!(v.state().unwrap(), VaultState::Empty);

    fs::write(dir.path().join("f.txt"), b"data").unwrap();
    assert_eq!(v.state().unwrap(), VaultState::Unlocked);

    v.encrypt_plaintext(&root()).unwrap();
    assert_eq!(v.state().unwrap(), VaultState::Locked);

    v.decrypt_all(&root()).unwrap();
    assert_eq!(v.state().unwrap(), VaultState::Unlocked);
}

#[test]
fn unlocking_leaves_no_ciphertext_behind() {
    let (dir, v) = new_vault();
    fs::create_dir_all(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    fs::write(dir.path().join("sub/b.txt"), b"b").unwrap();

    v.encrypt_plaintext(&root()).unwrap();
    v.decrypt_all(&root()).unwrap();

    // Every surviving entry should be a readable name, not base32.
    assert!(dir.path().join("a.txt").exists());
    assert!(dir.path().join("sub/b.txt").exists());
    assert_eq!(v.state().unwrap(), VaultState::Unlocked);
}

#[test]
fn nested_directory_names_are_restored() {
    let (dir, v) = new_vault();
    fs::create_dir_all(dir.path().join("Documents/Tax Returns/2026")).unwrap();
    fs::write(
        dir.path().join("Documents/Tax Returns/2026/return.pdf"),
        b"%PDF fake",
    )
    .unwrap();

    v.encrypt_plaintext(&root()).unwrap();
    v.decrypt_all(&root()).unwrap();

    assert!(
        dir.path()
            .join("Documents/Tax Returns/2026/return.pdf")
            .exists(),
        "nested directory names were not restored"
    );
}

#[test]
fn unicode_names_survive_a_cycle() {
    let (dir, v) = new_vault();
    fs::create_dir_all(dir.path().join("документы")).unwrap();
    fs::write(dir.path().join("документы/файл — copy.txt"), b"unicode").unwrap();

    v.encrypt_plaintext(&root()).unwrap();
    v.decrypt_all(&root()).unwrap();

    assert_eq!(
        fs::read(dir.path().join("документы/файл — copy.txt")).unwrap(),
        b"unicode"
    );
}

#[test]
fn unlock_is_idempotent() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("f.txt"), b"data").unwrap();
    v.encrypt_plaintext(&root()).unwrap();

    let first = v.decrypt_all(&root()).unwrap();
    let second = v.decrypt_all(&root()).unwrap();

    assert_eq!(first.files, 1);
    assert!(second.is_empty(), "second unlock did work: {second:?}");
    assert_eq!(fs::read(dir.path().join("f.txt")).unwrap(), b"data");
}

#[test]
fn header_survives_both_directions() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("f.txt"), b"data").unwrap();

    v.encrypt_plaintext(&root()).unwrap();
    assert!(dir.path().join(".vault-header").exists());

    v.decrypt_all(&root()).unwrap();
    assert!(
        dir.path().join(".vault-header").exists(),
        "the header was destroyed; the vault could never be locked again"
    );
}

#[test]
fn relocking_after_unlock_still_works() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("f.txt"), b"round two").unwrap();

    // Three full cycles: catches state that only breaks on reuse.
    for _ in 0..3 {
        v.encrypt_plaintext(&root()).unwrap();
        assert_eq!(v.state().unwrap(), VaultState::Locked);
        v.decrypt_all(&root()).unwrap();
        assert_eq!(v.state().unwrap(), VaultState::Unlocked);
    }

    assert_eq!(fs::read(dir.path().join("f.txt")).unwrap(), b"round two");
}

#[test]
fn a_file_edited_while_unlocked_is_captured_on_relock() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("doc.txt"), b"version one").unwrap();
    v.encrypt_plaintext(&root()).unwrap();
    v.decrypt_all(&root()).unwrap();

    // The whole point of this design: edit with a real program, then re-lock.
    fs::write(dir.path().join("doc.txt"), b"version two, edited externally").unwrap();
    v.encrypt_plaintext(&root()).unwrap();
    v.decrypt_all(&root()).unwrap();

    assert_eq!(
        fs::read(dir.path().join("doc.txt")).unwrap(),
        b"version two, edited externally"
    );
}

#[test]
fn new_files_added_while_unlocked_are_locked_too() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("original.txt"), b"first").unwrap();
    v.encrypt_plaintext(&root()).unwrap();
    v.decrypt_all(&root()).unwrap();

    fs::write(dir.path().join("added.txt"), b"second").unwrap();
    v.encrypt_plaintext(&root()).unwrap();

    assert_eq!(v.state().unwrap(), VaultState::Locked);
    assert!(!dir.path().join("added.txt").exists());

    v.decrypt_all(&root()).unwrap();
    assert_eq!(fs::read(dir.path().join("added.txt")).unwrap(), b"second");
}

#[test]
fn empty_files_survive_a_cycle() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("empty.bin"), b"").unwrap();

    v.encrypt_plaintext(&root()).unwrap();
    v.decrypt_all(&root()).unwrap();

    assert_eq!(fs::read(dir.path().join("empty.bin")).unwrap(), b"");
}
