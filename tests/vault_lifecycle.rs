//! End-to-end vault tests (§8, milestone 2).
//!
//! Exercises the layer the way the UI eventually will: init, unlock, write,
//! list, read, delete. Plus the atomicity guarantees from §5.5 — the point of
//! milestone 2 is that a crash mid-operation never loses data.

use std::fs;

use boxit::crypto::CryptoError;
use boxit::crypto::kdf::KdfParams;
use boxit::vault::path::VirtualPath;
use boxit::vault::{Entry, Vault};
use tempfile::TempDir;

/// Minimum KDF cost: these tests exercise vault logic, not Argon2 hardness.
/// Default parameters would add ~100ms to every unlock in this file.
fn params() -> KdfParams {
    KdfParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

const PW: &[u8] = b"a test passphrase";

fn new_vault() -> (TempDir, Vault) {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();
    let v = Vault::unlock(dir.path(), PW).unwrap();
    (dir, v)
}

fn vpath(s: &str) -> VirtualPath {
    VirtualPath::parse(s).unwrap()
}

#[test]
fn init_unlock_write_read() {
    let (_dir, v) = new_vault();
    let p = vpath("notes.txt");

    v.write_file(&p, b"hello vault").unwrap();
    assert_eq!(v.read_file(&p).unwrap(), b"hello vault");
}

#[test]
fn wrong_passphrase_fails_to_unlock() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();

    assert!(Vault::unlock(dir.path(), b"wrong").is_err());
}

#[test]
fn cannot_init_twice() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();

    assert!(matches!(
        Vault::init(dir.path(), PW, params()),
        Err(CryptoError::AlreadyInitialized)
    ));
}

#[test]
fn plaintext_never_appears_on_disk() {
    let (dir, v) = new_vault();
    v.write_file(&vpath("secret-name.txt"), b"SECRET-CONTENTS")
        .unwrap();

    // Neither the name nor the contents may be recoverable by reading the
    // directory the way an attacker with the drive would.
    for entry in fs::read_dir(dir.path()).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        assert!(!name.contains("secret-name"), "plaintext name on disk: {name}");

        if entry.metadata().unwrap().is_file() {
            let bytes = fs::read(entry.path()).unwrap();
            let hay = String::from_utf8_lossy(&bytes);
            assert!(!hay.contains("SECRET-CONTENTS"), "plaintext contents in {name}");
        }
    }
}

#[test]
fn listing_shows_decrypted_names() {
    let (_dir, v) = new_vault();
    v.create_dir(&vpath("docs")).unwrap();
    v.write_file(&vpath("a.txt"), b"a").unwrap();
    v.write_file(&vpath("b.txt"), b"b").unwrap();

    let listing = v.list(&VirtualPath::root()).unwrap();
    let names: Vec<&str> = listing.iter().map(|e| e.name.as_str()).collect();

    // Directories sort first, then names ascending.
    assert_eq!(names, ["docs", "a.txt", "b.txt"]);
    assert!(listing[0].is_dir);
}

#[test]
fn listing_excludes_header_and_lock() {
    let (_dir, v) = new_vault();
    let listing = v.list(&VirtualPath::root()).unwrap();
    assert!(listing.is_empty(), "vault metadata leaked into listing: {listing:?}");
}

#[test]
fn nested_directories_round_trip() {
    let (_dir, v) = new_vault();
    v.create_dir(&vpath("a/b/c")).unwrap();
    v.write_file(&vpath("a/b/c/deep.txt"), b"deep contents")
        .unwrap();

    assert_eq!(v.read_file(&vpath("a/b/c/deep.txt")).unwrap(), b"deep contents");

    let listing = v.list(&vpath("a/b/c")).unwrap();
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].name, "deep.txt");
}

#[test]
fn same_name_in_different_directories_differs_on_disk() {
    let (dir, v) = new_vault();
    v.create_dir(&vpath("one")).unwrap();
    v.create_dir(&vpath("two")).unwrap();
    v.write_file(&vpath("one/same.txt"), b"x").unwrap();
    v.write_file(&vpath("two/same.txt"), b"y").unwrap();

    // Collect the encrypted leaf names from both directories.
    let mut encrypted = Vec::new();
    for sub in fs::read_dir(dir.path()).unwrap() {
        let sub = sub.unwrap();
        if sub.metadata().unwrap().is_dir() {
            for f in fs::read_dir(sub.path()).unwrap() {
                encrypted.push(f.unwrap().file_name().to_string_lossy().into_owned());
            }
        }
    }

    assert_eq!(encrypted.len(), 2);
    assert_ne!(
        encrypted[0], encrypted[1],
        "identical names in different directories produced identical ciphertext"
    );
}

#[test]
fn large_multi_chunk_file_round_trips() {
    let (_dir, v) = new_vault();
    let data: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    let p = vpath("big.bin");

    v.write_file(&p, &data).unwrap();
    assert_eq!(v.read_file(&p).unwrap(), data);
}

#[test]
fn empty_file_round_trips() {
    let (_dir, v) = new_vault();
    let p = vpath("empty.txt");

    v.write_file(&p, b"").unwrap();
    assert_eq!(v.read_file(&p).unwrap(), b"");
}

#[test]
fn unicode_names_round_trip() {
    let (_dir, v) = new_vault();
    let p = vpath("документы/файл — copy (1).txt");

    v.create_dir(&vpath("документы")).unwrap();
    v.write_file(&p, b"unicode").unwrap();

    let listing = v.list(&vpath("документы")).unwrap();
    assert_eq!(listing[0].name, "файл — copy (1).txt");
}

#[test]
fn delete_removes_file_and_directory() {
    let (_dir, v) = new_vault();
    v.create_dir(&vpath("tree/sub")).unwrap();
    v.write_file(&vpath("tree/sub/f.txt"), b"x").unwrap();
    v.write_file(&vpath("loose.txt"), b"y").unwrap();

    v.remove_file(&vpath("loose.txt")).unwrap();
    assert!(!v.exists(&vpath("loose.txt")).unwrap());

    v.remove_dir_all(&vpath("tree")).unwrap();
    assert!(!v.exists(&vpath("tree")).unwrap());
}

#[test]
fn cannot_delete_the_vault_root() {
    let (_dir, v) = new_vault();
    assert!(v.remove_dir_all(&VirtualPath::root()).is_err());
}

#[test]
fn rename_file_preserves_contents() {
    let (_dir, v) = new_vault();
    v.write_file(&vpath("before.txt"), b"stable").unwrap();

    v.rename(&vpath("before.txt"), "after.txt").unwrap();

    assert!(!v.exists(&vpath("before.txt")).unwrap());
    assert_eq!(v.read_file(&vpath("after.txt")).unwrap(), b"stable");
}

#[test]
fn corrupt_file_is_detected_not_silently_returned() {
    let (dir, v) = new_vault();
    let p = vpath("important.txt");
    v.write_file(&p, b"original contents").unwrap();

    // Flip a byte in the ciphertext, the way bit rot or tampering would.
    let target = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.metadata().unwrap().is_file() && e.file_name().to_string_lossy().len() > 20)
        .unwrap()
        .path();

    let mut bytes = fs::read(&target).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&target, &bytes).unwrap();

    assert!(
        v.read_file(&p).is_err(),
        "corrupt file must fail loudly, never return damaged plaintext"
    );
}

#[test]
fn second_instance_cannot_unlock_while_first_holds_lock() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();

    let first = Vault::unlock(dir.path(), PW).unwrap();
    assert!(
        Vault::unlock(dir.path(), PW).is_err(),
        "two instances must not hold one vault at once"
    );

    first.close().unwrap();
    Vault::unlock(dir.path(), PW).unwrap().close().unwrap();
}

#[test]
fn passphrase_change_keeps_files_readable() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();

    let v = Vault::unlock(dir.path(), PW).unwrap();
    v.write_file(&vpath("kept.txt"), b"survives rotation").unwrap();
    v.close().unwrap();

    Vault::change_passphrase(dir.path(), PW, b"the new passphrase", params()).unwrap();

    assert!(Vault::unlock(dir.path(), PW).is_err(), "old passphrase still works");

    let v = Vault::unlock(dir.path(), b"the new passphrase").unwrap();
    assert_eq!(
        v.read_file(&vpath("kept.txt")).unwrap(),
        b"survives rotation",
        "rotation must not require re-encrypting file contents"
    );
}

#[test]
fn failed_write_does_not_destroy_existing_file() {
    let (_dir, v) = new_vault();
    let p = vpath("precious.txt");
    v.write_file(&p, b"the original data").unwrap();

    // A name too long to encrypt fails after the target already exists.
    let doomed = vpath(&"x".repeat(200));
    assert!(v.write_file(&doomed, b"never lands").is_err());

    assert_eq!(
        v.read_file(&p).unwrap(),
        b"the original data",
        "an unrelated failure must not touch existing files"
    );
}

#[test]
fn overwrite_is_atomic() {
    let (_dir, v) = new_vault();
    let p = vpath("doc.txt");

    v.write_file(&p, b"version one").unwrap();
    v.write_file(&p, b"version two is considerably longer").unwrap();

    // Never a mix of the two: the rename swaps the whole file at once.
    assert_eq!(v.read_file(&p).unwrap(), b"version two is considerably longer");
}

#[test]
fn no_temp_files_remain_after_operations() {
    let (dir, v) = new_vault();
    for i in 0..10 {
        v.write_file(&vpath(&format!("f{i}.txt")), b"data").unwrap();
    }

    let strays: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".tmp"))
        .collect();

    assert!(strays.is_empty(), "temp files left behind: {strays:?}");
}

#[test]
fn stale_temp_files_are_swept_on_unlock() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();

    // Debris a crashed process would leave behind.
    fs::write(dir.path().join(".tmpCRASHED"), b"partial").unwrap();

    let v = Vault::unlock(dir.path(), PW).unwrap();
    assert!(!dir.path().join(".tmpCRASHED").exists());

    // And the sweep must not have eaten the vault itself.
    assert!(v.list(&VirtualPath::root()).is_ok());
}

#[test]
fn traversal_paths_are_unrepresentable() {
    for bad in ["../outside", "a/../../etc/passwd", "..", "a\\..\\b"] {
        assert!(
            VirtualPath::parse(bad).is_err(),
            "traversal path accepted: {bad}"
        );
    }
}

#[test]
fn listing_survives_a_foreign_file_in_the_tree() {
    let (dir, v) = new_vault();
    v.write_file(&vpath("real.txt"), b"x").unwrap();

    // Something not written by us — a stray file, or a name we cannot decrypt.
    fs::write(dir.path().join("not-ours.txt"), b"foreign").unwrap();

    let listing: Vec<Entry> = v.list(&VirtualPath::root()).unwrap();
    let names: Vec<&str> = listing.iter().map(|e| e.name.as_str()).collect();

    assert_eq!(
        names,
        ["real.txt"],
        "undecryptable entries should be skipped, not abort the listing"
    );
}
