//! Crash safety (§8, milestone 2): "kill the process mid-operation and verify
//! no data loss."
//!
//! An in-process test cannot prove this — a simulated error unwinds politely,
//! which is the case that was always going to work. So these tests spawn a real
//! child process that starts writing to a vault and is killed partway through,
//! then reopen the vault from the parent and check what survived.
//!
//! The guarantee under test is the §5.5 one: after a crash, every file is
//! either its old contents or its new contents, never a blend or a truncation.

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use boxit::crypto::kdf::KdfParams;
use boxit::vault::Vault;
use boxit::vault::path::VirtualPath;
use tempfile::TempDir;

fn params() -> KdfParams {
    KdfParams {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

const PW: &[u8] = b"crash test passphrase";

fn vpath(s: &str) -> VirtualPath {
    VirtualPath::parse(s).unwrap()
}

/// Path to the helper binary that does the writing and gets killed.
fn helper_bin() -> std::path::PathBuf {
    // The integration test binary lives in target/<profile>/deps/, so the
    // helper built alongside it is one directory up.
    let mut p = std::env::current_exe().expect("test exe path");
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(format!("crash_helper{}", std::env::consts::EXE_SUFFIX))
}

/// Spawn the helper, let it get going, then kill it hard.
///
/// SIGKILL-equivalent: no destructors, no flush, no cleanup — exactly what a
/// power loss looks like to the filesystem.
fn spawn_and_kill(vault_dir: &Path, millis: u64) {
    let mut child = Command::new(helper_bin())
        .arg(vault_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn crash helper; is it built?");

    std::thread::sleep(std::time::Duration::from_millis(millis));
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn crash_during_write_never_corrupts_an_existing_file() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();

    // Seed a file the helper will repeatedly overwrite.
    let v = Vault::unlock(dir.path(), PW).unwrap();
    v.write_file(&vpath("target.txt"), b"ORIGINAL").unwrap();
    v.close().unwrap();

    // Kill at several points, to land inside different phases of the write.
    for delay in [30, 60, 90, 120] {
        spawn_and_kill(dir.path(), delay);

        // The helper died holding the lock; clear it as a user would.
        let _ = fs::remove_file(dir.path().join(".vault-lock"));

        let v = Vault::unlock(dir.path(), PW).unwrap();
        let contents = v
            .read_file(&vpath("target.txt"))
            .expect("file unreadable after crash — atomicity violated");

        // Either value is correct. A blend, a truncation, or an empty file is
        // not, and read_file would have failed the AEAD check on a partial one.
        assert!(
            contents == b"ORIGINAL" || contents == b"REWRITTEN BY THE HELPER PROCESS",
            "file was neither old nor new after crash: {:?}",
            String::from_utf8_lossy(&contents)
        );
        v.close().unwrap();
    }
}

#[test]
fn vault_remains_usable_after_repeated_crashes() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();

    for delay in [25, 50, 75] {
        spawn_and_kill(dir.path(), delay);
        let _ = fs::remove_file(dir.path().join(".vault-lock"));
    }

    // The header must still parse and the tree must still list.
    let v = Vault::unlock(dir.path(), PW).unwrap();
    let listing = v.list(&VirtualPath::root()).unwrap();

    // Every file that survived must decrypt cleanly — no half-written entries.
    for entry in &listing {
        if !entry.is_dir {
            let p = vpath(&entry.name);
            assert!(
                v.read_file(&p).is_ok(),
                "surviving file {} does not decrypt after crashes",
                entry.name
            );
        }
    }

    // And the vault must still accept new writes.
    v.write_file(&vpath("after-recovery.txt"), b"still works")
        .unwrap();
    assert_eq!(
        v.read_file(&vpath("after-recovery.txt")).unwrap(),
        b"still works"
    );
    v.close().unwrap();
}

#[test]
fn temp_debris_from_crashes_is_swept_on_next_unlock() {
    let dir = TempDir::new().unwrap();
    Vault::init(dir.path(), PW, params()).unwrap();

    for delay in [40, 80] {
        spawn_and_kill(dir.path(), delay);
        let _ = fs::remove_file(dir.path().join(".vault-lock"));
        Vault::unlock(dir.path(), PW).unwrap().close().unwrap();
    }

    let strays: Vec<String> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".tmp"))
        .collect();

    assert!(strays.is_empty(), "crash debris not swept: {strays:?}");
}
