//! Progress reporting during lock and unlock.
//!
//! The bar has to be trustworthy: monotonic, never over 100%, and ending at
//! exactly the work that was actually done. A bar that jumps backwards or
//! stalls at 99% is worse than no bar.

use std::fs;
use std::sync::{Arc, Mutex};

use boxit::crypto::kdf::KdfParams;
use boxit::vault::path::VirtualPath;
use boxit::vault::{Progress, Vault};
use tempfile::TempDir;

fn params() -> KdfParams {
    KdfParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

const PW: &[u8] = b"progress test passphrase";

fn new_vault() -> (TempDir, Vault) {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();
    let v = Vault::unlock(dir.path(), PW).unwrap();
    (dir, v)
}

fn root() -> VirtualPath {
    VirtualPath::root()
}

/// Collect every progress update an operation emits.
fn collect<F>(op: F) -> Vec<Progress>
where
    F: FnOnce(&mut (dyn FnMut(Progress) + Send)),
{
    let seen = Arc::new(Mutex::new(Vec::new()));
    {
        // Scoped so the closure's Arc clone is dropped before we read the data.
        let sink = seen.clone();
        let mut cb = move |p: Progress| sink.lock().unwrap().push(p);
        op(&mut cb);
    }
    let guard = seen.lock().unwrap();
    guard.clone()
}

#[test]
fn lock_reports_one_update_per_file() {
    let (dir, v) = new_vault();
    for i in 0..5 {
        fs::write(dir.path().join(format!("f{i}.txt")), vec![b'x'; 100]).unwrap();
    }

    let updates = collect(|cb| {
        v.encrypt_plaintext_with_progress(&root(), cb).unwrap();
    });

    assert_eq!(updates.len(), 5, "expected one update per file");
    assert_eq!(updates.last().unwrap().files_done, 5);
}

#[test]
fn progress_is_monotonic_and_bounded() {
    let (dir, v) = new_vault();
    fs::create_dir_all(dir.path().join("sub")).unwrap();
    for i in 0..4 {
        fs::write(dir.path().join(format!("a{i}.bin")), vec![b'x'; 5000]).unwrap();
        fs::write(dir.path().join("sub").join(format!("b{i}.bin")), vec![b'y'; 3000]).unwrap();
    }

    let updates = collect(|cb| {
        v.encrypt_plaintext_with_progress(&root(), cb).unwrap();
    });

    let mut last_bytes = 0;
    let mut last_files = 0;
    for p in &updates {
        assert!(p.bytes_done >= last_bytes, "byte count went backwards");
        assert!(p.files_done >= last_files, "file count went backwards");
        assert!(
            p.fraction() >= 0.0 && p.fraction() <= 1.0,
            "fraction out of range: {}",
            p.fraction()
        );
        assert!(
            p.files_done <= p.files_total,
            "done {} exceeds total {}",
            p.files_done,
            p.files_total
        );
        last_bytes = p.bytes_done;
        last_files = p.files_done;
    }
}

#[test]
fn progress_reaches_completion() {
    let (dir, v) = new_vault();
    for i in 0..3 {
        fs::write(dir.path().join(format!("f{i}.txt")), vec![b'z'; 1000]).unwrap();
    }

    let updates = collect(|cb| {
        v.encrypt_plaintext_with_progress(&root(), cb).unwrap();
    });

    let last = updates.last().unwrap();
    assert_eq!(last.files_done, last.files_total);
    assert_eq!(last.bytes_done, last.bytes_total);
    assert_eq!(last.fraction(), 1.0, "bar did not reach 100%");
}

#[test]
fn plan_matches_what_the_lock_actually_does() {
    let (dir, v) = new_vault();
    fs::create_dir_all(dir.path().join("d")).unwrap();
    fs::write(dir.path().join("one.txt"), vec![b'a'; 1234]).unwrap();
    fs::write(dir.path().join("d").join("two.txt"), vec![b'b'; 5678]).unwrap();

    let plan = v.plan_lock(&root()).unwrap();
    let report = v.encrypt_plaintext(&root()).unwrap();

    assert_eq!(plan.files, report.files, "planned file count was wrong");
    assert_eq!(plan.bytes, report.bytes, "planned byte count was wrong");
}

#[test]
fn unlock_reports_progress_too() {
    let (dir, v) = new_vault();
    for i in 0..4 {
        fs::write(dir.path().join(format!("f{i}.txt")), vec![b'q'; 2000]).unwrap();
    }
    v.encrypt_plaintext(&root()).unwrap();

    let updates = collect(|cb| {
        v.decrypt_all_with_progress(&root(), cb).unwrap();
    });

    assert_eq!(updates.len(), 4);
    assert_eq!(updates.last().unwrap().fraction(), 1.0);
}

#[test]
fn plan_unlock_matches_the_unlock() {
    let (dir, v) = new_vault();
    fs::create_dir_all(dir.path().join("nested/deep")).unwrap();
    fs::write(dir.path().join("a.txt"), vec![b'a'; 500]).unwrap();
    fs::write(dir.path().join("nested/b.txt"), vec![b'b'; 700]).unwrap();
    fs::write(dir.path().join("nested/deep/c.txt"), vec![b'c'; 900]).unwrap();
    v.encrypt_plaintext(&root()).unwrap();

    let plan = v.plan_unlock(&root()).unwrap();
    let report = v.decrypt_all(&root()).unwrap();

    assert_eq!(plan.files, report.files);
    assert_eq!(plan.files, 3);
}

#[test]
fn progress_names_the_file_being_processed() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("distinctive-name.txt"), b"data").unwrap();

    let updates = collect(|cb| {
        v.encrypt_plaintext_with_progress(&root(), cb).unwrap();
    });

    assert_eq!(updates[0].current, "distinctive-name.txt");
}

#[test]
fn empty_vault_emits_no_updates() {
    let (_dir, v) = new_vault();

    let updates = collect(|cb| {
        v.encrypt_plaintext_with_progress(&root(), cb).unwrap();
    });

    assert!(updates.is_empty());
}

#[test]
fn nested_directories_are_counted_in_the_plan() {
    let (dir, v) = new_vault();
    fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
    fs::write(dir.path().join("a/b/c/deep.txt"), vec![b'x'; 42]).unwrap();
    fs::write(dir.path().join("a/top.txt"), vec![b'y'; 58]).unwrap();

    let plan = v.plan_lock(&root()).unwrap();

    assert_eq!(plan.files, 2, "pre-walk missed files in nested directories");
    assert_eq!(plan.bytes, 100);
}

#[test]
fn fraction_handles_zero_byte_files() {
    let (dir, v) = new_vault();
    fs::write(dir.path().join("empty.txt"), b"").unwrap();

    let updates = collect(|cb| {
        v.encrypt_plaintext_with_progress(&root(), cb).unwrap();
    });

    // A vault of nothing but empty files still has to report completion.
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].fraction(), 1.0);
}
