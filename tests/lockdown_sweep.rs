//! Tests for the lockdown-folder behaviour: plaintext dropped into the vault
//! directory gets encrypted, and the originals are removed.
//!
//! The property that matters most here is ordering. A file may briefly exist as
//! both plaintext and ciphertext (recoverable), but must never exist as
//! neither (not recoverable). Every test that deletes an original checks the
//! encrypted copy is readable first.

use std::fs;

use boxit::crypto::kdf::KdfParams;
use boxit::vault::path::VirtualPath;
use boxit::vault::Vault;
use tempfile::TempDir;

fn params() -> KdfParams {
    KdfParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

const PW: &[u8] = b"lockdown test passphrase";

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
fn plaintext_file_is_encrypted_and_original_removed() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("dropped.txt"), b"plaintext contents").unwrap();

    let report = v.encrypt_plaintext(&root()).unwrap();

    assert_eq!(report.files, 1);
    assert!(report.failed.is_empty());
    assert!(
        !dir.path().join("dropped.txt").exists(),
        "original plaintext still on disk"
    );

    let listing = v.list(&root()).unwrap();
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].name, "dropped.txt");
    assert_eq!(
        v.read_file(&VirtualPath::parse("dropped.txt").unwrap()).unwrap(),
        b"plaintext contents"
    );
}

#[test]
fn contents_survive_the_sweep_byte_for_byte() {
    let (dir, v) = new_vault();
    // Spans several STREAM chunks, so this exercises the chunked path.
    let data: Vec<u8> = (0..200_000).map(|i| (i % 251) as u8).collect();
    fs::write(dir.path().join("big.bin"), &data).unwrap();

    v.encrypt_plaintext(&root()).unwrap();

    assert_eq!(
        v.read_file(&VirtualPath::parse("big.bin").unwrap()).unwrap(),
        data
    );
}

#[test]
fn plaintext_directory_tree_is_swallowed_whole() {
    let (dir, v) = new_vault();
    let tree = dir.path().join("docs");
    fs::create_dir_all(tree.join("nested")).unwrap();
    fs::write(tree.join("a.txt"), b"alpha").unwrap();
    fs::write(tree.join("nested").join("b.txt"), b"beta").unwrap();

    let report = v.encrypt_plaintext(&root()).unwrap();

    assert_eq!(report.files, 2);
    assert!(!tree.exists(), "plaintext directory still on disk");

    assert_eq!(
        v.read_file(&VirtualPath::parse("docs/a.txt").unwrap()).unwrap(),
        b"alpha"
    );
    assert_eq!(
        v.read_file(&VirtualPath::parse("docs/nested/b.txt").unwrap())
            .unwrap(),
        b"beta"
    );
}

#[test]
fn already_encrypted_files_are_left_alone() {
    let (_dir, v) = new_vault();
    let p = VirtualPath::parse("existing.txt").unwrap();
    v.write_file(&p, b"already encrypted").unwrap();

    let report = v.encrypt_plaintext(&root()).unwrap();

    assert!(report.is_empty(), "re-encrypted an existing file: {report:?}");
    assert_eq!(v.read_file(&p).unwrap(), b"already encrypted");
}

#[test]
fn sweep_is_idempotent() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("once.txt"), b"data").unwrap();

    let first = v.encrypt_plaintext(&root()).unwrap();
    let second = v.encrypt_plaintext(&root()).unwrap();

    assert_eq!(first.files, 1);
    assert!(second.is_empty(), "second sweep did work: {second:?}");
    assert_eq!(v.list(&root()).unwrap().len(), 1);
}

#[test]
fn header_and_lock_are_never_swallowed() {
    let (dir, v) = new_vault();
    v.encrypt_plaintext(&root()).unwrap();

    assert!(
        dir.path().join(".vault-header").exists(),
        "the header was encrypted; the vault would be unopenable"
    );
    assert!(dir.path().join(".vault-lock").exists(), "the lock was eaten");
}

#[test]
fn plaintext_dropped_into_an_encrypted_subdirectory_is_found() {
    let (dir, v) = new_vault();
    let sub = VirtualPath::parse("folder").unwrap();
    v.create_dir(&sub).unwrap();
    v.write_file(&VirtualPath::parse("folder/a.txt").unwrap(), b"a")
        .unwrap();

    // Drop a plaintext file inside the *encrypted* directory on disk.
    let real_sub = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.metadata().unwrap().is_dir())
        .unwrap()
        .path();
    fs::write(real_sub.join("dropped-inside.txt"), b"nested plaintext").unwrap();

    let report = v.encrypt_plaintext(&root()).unwrap();

    assert_eq!(report.files, 1, "did not recurse into encrypted directories");
    assert_eq!(
        v.read_file(&VirtualPath::parse("folder/dropped-inside.txt").unwrap())
            .unwrap(),
        b"nested plaintext"
    );
}

#[test]
fn overlong_name_fails_without_destroying_the_original() {
    let (dir, v) = new_vault();
    // Longer than the 143-byte ceiling imposed by base32 expansion.
    let long = format!("{}.txt", "x".repeat(200));
    let path = dir.path().join(&long);
    fs::write(&path, b"must survive").unwrap();

    let report = v.encrypt_plaintext(&root()).unwrap();

    assert_eq!(report.files, 0);
    assert_eq!(report.failed.len(), 1, "failure was not reported");
    assert!(
        path.exists(),
        "plaintext deleted even though encryption failed — data loss"
    );
    assert_eq!(fs::read(&path).unwrap(), b"must survive");
}

#[test]
fn temp_debris_is_not_mistaken_for_plaintext() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join(".tmpLEFTOVER"), b"crash debris").unwrap();

    let report = v.encrypt_plaintext(&root()).unwrap();

    assert!(report.is_empty(), "swallowed crash debris: {report:?}");
}

#[test]
fn empty_plaintext_file_round_trips() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("empty.txt"), b"").unwrap();

    v.encrypt_plaintext(&root()).unwrap();

    assert_eq!(
        v.read_file(&VirtualPath::parse("empty.txt").unwrap()).unwrap(),
        b""
    );
}

#[test]
fn unicode_plaintext_names_survive() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("файл — notes.txt"), b"unicode").unwrap();

    v.encrypt_plaintext(&root()).unwrap();

    let listing = v.list(&root()).unwrap();
    assert_eq!(listing[0].name, "файл — notes.txt");
}

#[test]
fn mixed_plaintext_and_encrypted_sweeps_only_the_plaintext() {
    let (dir, v) = new_vault();
    v.write_file(&VirtualPath::parse("already.txt").unwrap(), b"encrypted")
        .unwrap();
    fs::write(dir.path().join("new.txt"), b"plain").unwrap();

    let report = v.encrypt_plaintext(&root()).unwrap();

    assert_eq!(report.files, 1);
    let mut names: Vec<String> = v.list(&root()).unwrap().into_iter().map(|e| e.name).collect();
    names.sort();
    assert_eq!(names, ["already.txt", "new.txt"]);
}

#[test]
fn nothing_plaintext_left_in_the_vault_after_a_sweep() {
    let (dir, v) = new_vault();
    fs::create_dir_all(dir.path().join("d")).unwrap();
    fs::write(dir.path().join("a.txt"), b"a").unwrap();
    fs::write(dir.path().join("d").join("b.txt"), b"b").unwrap();

    v.encrypt_plaintext(&root()).unwrap();

    // Every remaining entry must be either vault metadata or an encrypted name.
    for entry in fs::read_dir(dir.path()).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        if name == ".vault-header" || name == ".vault-lock" {
            continue;
        }
        assert!(
            name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
            "plaintext-looking entry survived the sweep: {name}"
        );
    }
}
