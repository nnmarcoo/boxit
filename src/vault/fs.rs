//! Atomic filesystem writes (§5.5) — non-negotiable.
//!
//! Every write goes: temp file in the same directory → write → fsync → rename
//! over the target. A crash at any point leaves either the old file intact or
//! the new file complete, never a half-written one.
//!
//! Same-directory temp files matter because `rename` is only atomic within a
//! filesystem; a temp in the system temp dir may be on a different mount, which
//! silently downgrades the rename to copy-then-delete.
//!
//! Note that `panic = "abort"` in the release profile skips destructors, so
//! this cannot rely on `Drop` for cleanup. Crash safety comes from the ordering
//! above, not from unwinding. A crash may leave a stray temp file, which is
//! recoverable; it must never leave a corrupt target, which is not.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

/// Write `contents` to `path` atomically.
pub fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    atomic_write_with(path, |f| f.write_all(contents))
}

/// Build a file at `path` atomically via a caller-supplied writer.
///
/// The closure receives the temp file. If it returns an error, the temp file is
/// removed and `path` is left untouched — this is what makes a failed encrypt
/// non-destructive.
pub fn atomic_write_with<F>(path: &Path, write: F) -> io::Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    atomic_write_inner(path, write, true)
}

/// As [`atomic_write_with`], but with the durability level chosen by the caller.
///
/// With [`Durability::Full`] this is exactly [`atomic_write_with`]. With
/// [`Durability::Fast`] the fsync is skipped: the file is written and renamed
/// into place, so it is visible immediately, but its contents may still be in
/// the OS page cache and would be lost to a power failure.
///
/// Only for callers that have made that trade deliberately — see
/// [`Durability`].
pub fn atomic_write_durability<F>(
    path: &Path,
    durability: Durability,
    write: F,
) -> io::Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    atomic_write_inner(path, write, durability.syncs())
}

/// How hard to work at making a write survive a power failure.
///
/// This is the only real speed lever in a lock or unlock. fsync is ~80% of the
/// cost, and it cannot be optimised away in software: flushing is limited by
/// what the drive can physically commit per second, so no amount of batching or
/// pipelining moves it. Measured on a 16-core machine with an SSD, an 80 MB
/// lock runs at ~150 MB/s with `Full` and ~690 MB/s with `Fast`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Durability {
    /// Wait for the drive to confirm each file before deleting what it
    /// replaces (§5.5). A power failure mid-operation can leave both copies of
    /// a file, never neither.
    #[default]
    Full,
    /// Trust the operating system's page cache and do not wait.
    ///
    /// Roughly 4.5x faster, and what archivers like 7-Zip do — but they only
    /// ever *copy*, leaving the originals in place. This tool deletes the
    /// original once the replacement is written, so with `Fast` a power failure
    /// or kernel panic during a lock can destroy the files that were in flight:
    /// the plaintext is gone and the ciphertext never reached the drive.
    ///
    /// An application crash is *not* enough to trigger this — the OS still
    /// flushes its cache. It takes losing power or a kernel-level failure.
    Fast,
}

impl Durability {
    /// Whether writes at this level wait for the drive.
    pub fn syncs(self) -> bool {
        matches!(self, Self::Full)
    }
}

fn atomic_write_inner<F>(path: &Path, write: F, sync: bool) -> io::Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    fs::create_dir_all(dir)?;

    let mut temp = NamedTempFile::new_in(dir)?;

    if let Err(e) = write(temp.as_file_mut()) {
        // Explicit cleanup rather than relying on Drop, for the reason above.
        let _ = temp.close();
        return Err(e);
    }

    if sync {
        // fsync the file before the rename: the rename may otherwise be durable
        // while the contents it points at are not, which is the worst outcome —
        // a file that exists and is empty.
        temp.as_file().sync_all()?;
    }

    // `persist` is rename(2) on Unix and a replacing MoveFileEx on Windows.
    temp.persist(path).map_err(|e| e.error)?;

    if sync {
        // fsync the directory so the rename itself survives a crash. Not
        // available on Windows, where the replace is already ordered.
        sync_dir(dir)?;
    }
    Ok(())
}

/// Free space available on the filesystem holding `path`, in bytes.
///
/// Returns `None` if it cannot be determined, in which case callers should
/// proceed rather than refusing to work.
pub fn available_space(path: &Path) -> Option<u64> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        // GetDiskFreeSpaceExW wants a directory path; a wide, NUL-terminated
        // string is what the API expects.
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut free: u64 = 0;
        // SAFETY: `wide` is a NUL-terminated UTF-16 path that outlives the
        // call, and `free` is a valid writable u64. The other two out-params
        // are optional and passed as null.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                wide.as_ptr(),
                &mut free,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some(free)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        // No portable std API for this; skipping the check is safe because the
        // operation still fails per-file if the disk fills.
        None
    }
}

#[cfg(windows)]
unsafe extern "system" {
    fn GetDiskFreeSpaceExW(
        directory: *const u16,
        free_bytes_available_to_caller: *mut u64,
        total_bytes: *mut u64,
        total_free_bytes: *mut u64,
    ) -> i32;
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

/// Remove any leftover temp files in `dir` from an interrupted write.
///
/// Safe to run at unlock: temp files are only ever live during a single write
/// call, so anything still present is debris from a crash.
pub fn sweep_temps(dir: &Path) -> io::Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // tempfile's default prefix.
        if name.starts_with(".tmp") && entry.file_type()?.is_file() {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// A vault-wide lock preventing two instances from writing at once (§9.5).
///
/// Deliberately advisory and simple: the lock file's presence is the lock. A
/// stale lock after a crash is a visible, explainable problem the user can
/// clear, which is preferable to silent concurrent mutation of an encrypted
/// tree.
pub struct VaultLock {
    path: PathBuf,
}

/// Name of the lock file. Excluded from encryption, like the header.
pub const LOCK_FILENAME: &str = ".vault-lock";

impl VaultLock {
    /// Take the lock, or fail if another instance holds it.
    pub fn acquire(vault_dir: &Path) -> io::Result<Self> {
        let path = vault_dir.join(LOCK_FILENAME);

        // create_new is atomic: exactly one caller can win this race.
        match File::options().write(true).create_new(true).open(&path) {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", std::process::id());
                let _ = f.sync_all();
                Ok(Self { path })
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "this vault is already open in another window; \
                 if no other copy is running, delete .vault-lock and try again",
            )),
            Err(e) => Err(e),
        }
    }

    /// Release the lock explicitly.
    ///
    /// Prefer this over relying on `Drop`: with `panic = "abort"` the
    /// destructor will not run.
    pub fn release(self) -> io::Result<()> {
        fs::remove_file(&self.path)
    }
}

impl Drop for VaultLock {
    fn drop(&mut self) {
        // Best-effort for the ordinary unwinding path; see `release`.
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_new_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.bin");

        atomic_write(&path, b"hello").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn replaces_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.bin");

        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn creates_missing_parent_directories() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("a").join("b").join("out.bin");

        atomic_write(&path, b"nested").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"nested");
    }

    #[test]
    fn failed_write_leaves_original_intact() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.bin");
        atomic_write(&path, b"original").unwrap();

        let r = atomic_write_with(&path, |_| {
            Err(io::Error::other("simulated failure mid-write"))
        });

        assert!(r.is_err());
        assert_eq!(
            fs::read(&path).unwrap(),
            b"original",
            "a failed write must not damage the existing file"
        );
    }

    #[test]
    fn failed_write_leaves_no_temp_files() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("out.bin");

        let _ = atomic_write_with(&path, |_| Err(io::Error::other("boom")));

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    }

    #[test]
    fn sweep_removes_stray_temps() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".tmpABCD"), b"debris").unwrap();
        fs::write(dir.path().join("real-file"), b"keep").unwrap();

        assert_eq!(sweep_temps(dir.path()).unwrap(), 1);
        assert!(dir.path().join("real-file").exists());
    }

    #[test]
    fn lock_is_exclusive() {
        let dir = tempdir().unwrap();

        let first = VaultLock::acquire(dir.path()).unwrap();
        assert!(
            VaultLock::acquire(dir.path()).is_err(),
            "a second instance must not be able to take the lock"
        );

        first.release().unwrap();
        VaultLock::acquire(dir.path()).unwrap().release().unwrap();
    }
}
