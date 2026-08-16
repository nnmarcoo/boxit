//! The vault layer (§7.1).
//!
//! Owns the mapping between the decrypted namespace the user browses and the
//! encrypted tree on disk. Depends on `crypto` and the standard library only —
//! no iced, no UI. That is what keeps it testable headlessly and leaves the
//! door open for a FUSE front end later (§6.2).

pub mod fs;
pub mod header;
pub mod path;

use std::fs as stdfs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

use crate::crypto::CryptoError;
use crate::crypto::kdf::{KdfParams, Key};
use crate::crypto::names::{DirId, decrypt_name, encrypt_name};
use crate::crypto::stream;

use self::fs::{VaultLock, atomic_write_with};
use self::header::{HEADER_FILENAME, Header};
use self::path::VirtualPath;

/// One entry in a directory listing.
///
/// Deliberately cheap to produce: building this decrypts the *name* only, never
/// the contents (§6.3). Size is the on-disk ciphertext size, so it is slightly
/// larger than the plaintext and needs no decryption to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub encrypted_size: u64,
}

/// Whether the vault folder currently holds ciphertext or real files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultState {
    /// Nothing in the folder yet.
    Empty,
    /// Everything encrypted. This is the protected state.
    Locked,
    /// Everything decrypted and readable by any program. Not protected.
    Unlocked,
    /// Both kinds present, meaning a lock or unlock was interrupted. Re-running
    /// either operation resolves it.
    Mixed,
}

/// Accumulates progress and forwards it to the caller's callback.
///
/// Boxed as a `&mut dyn FnMut` so the recursive sweep functions do not each get
/// monomorphised per closure type, which would bloat the binary for no gain.
struct Tracker<'a> {
    plan: Plan,
    files_done: usize,
    bytes_done: u64,
    on_progress: &'a mut dyn FnMut(Progress),
}

impl<'a> Tracker<'a> {
    fn new(plan: Plan, on_progress: &'a mut dyn FnMut(Progress)) -> Self {
        Self {
            plan,
            files_done: 0,
            bytes_done: 0,
            on_progress,
        }
    }

    /// Record one finished file and emit an update.
    fn advance(&mut self, name: &str, bytes: u64) {
        self.files_done += 1;
        self.bytes_done += bytes;

        (self.on_progress)(Progress {
            current: name.to_string(),
            files_done: self.files_done,
            // The pre-walk can undercount if files appear mid-operation; keep
            // the total at least as large as what has actually been done so the
            // bar never reports more than 100%.
            files_total: self.plan.files.max(self.files_done),
            bytes_done: self.bytes_done,
            bytes_total: self.plan.bytes.max(self.bytes_done),
        });
    }
}

/// Count files under a plaintext directory that is not yet in the vault.
fn plan_plain_dir(dir: &Path, plan: &mut Plan) -> Result<(), CryptoError> {
    for entry in stdfs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            plan_plain_dir(&entry.path(), plan)?;
        } else {
            plan.files += 1;
            plan.bytes += entry.metadata()?.len();
        }
    }
    Ok(())
}

/// A progress update from a lock or unlock in flight.
///
/// Emitted after each file, so a long operation can show that it is alive and
/// roughly how far along it is. Totals come from a metadata-only pre-walk, so
/// they are known before any crypto starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    /// The file just finished, for display.
    pub current: String,
    pub files_done: usize,
    pub files_total: usize,
    pub bytes_done: u64,
    pub bytes_total: u64,
}

impl Progress {
    /// Completion in the range 0.0..=1.0, by bytes.
    ///
    /// Bytes rather than file count: a vault of one 4 GB video and 200 small
    /// notes would otherwise sit at 99% for the entire actual wait.
    pub fn fraction(&self) -> f32 {
        if self.bytes_total == 0 {
            return 1.0;
        }
        (self.bytes_done as f32 / self.bytes_total as f32).clamp(0.0, 1.0)
    }
}

/// What work an upcoming lock or unlock will do.
///
/// Produced by a metadata-only walk — no decryption — so it is cheap even on a
/// large vault.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Plan {
    pub files: usize,
    pub bytes: u64,
}

/// What a sweep did, for reporting in the UI.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SweepReport {
    pub files: usize,
    pub directories: usize,
    pub bytes: u64,
    /// Entries that could not be encrypted, with the reason. Their plaintext is
    /// left untouched rather than deleted.
    pub failed: Vec<(String, String)>,
}

impl SweepReport {
    pub fn is_empty(&self) -> bool {
        self.files == 0 && self.directories == 0 && self.failed.is_empty()
    }
}

/// An unlocked vault.
///
/// Holds the master key in memory; dropping it zeroizes the key material.
///
/// The `Debug` impl deliberately omits the key — a stray `{:?}` in a log line
/// must never be able to print key material.
pub struct Vault {
    root: PathBuf,
    master: Key,
    lock: Option<VaultLock>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("root", &self.root)
            .field("master", &"<redacted>")
            .finish()
    }
}

impl Vault {
    /// Create a new vault in `dir`, which must not already contain one.
    pub fn init(dir: &Path, passphrase: &[u8], params: KdfParams) -> Result<(), CryptoError> {
        let header_path = dir.join(HEADER_FILENAME);
        if header_path.exists() {
            return Err(CryptoError::AlreadyInitialized);
        }
        stdfs::create_dir_all(dir)?;

        let master = Key::generate()?;
        let h = Header::create(passphrase, &master, params)?;

        let mut buf = Vec::new();
        h.write(&mut buf)?;
        atomic_write_with(&header_path, |f| std::io::Write::write_all(f, &buf))?;
        Ok(())
    }

    /// Unlock the vault in `dir`, taking the instance lock (§9.5).
    pub fn unlock(dir: &Path, passphrase: &[u8]) -> Result<Self, CryptoError> {
        let file = stdfs::File::open(dir.join(HEADER_FILENAME))
            .map_err(|_| CryptoError::BadHeader)?;
        let header = Header::read(file)?;
        let master = header.unwrap_master(passphrase)?;

        let lock = VaultLock::acquire(dir)?;

        // Clear debris from any previous crash before touching the tree.
        let _ = fs::sweep_temps(dir);

        Ok(Self {
            root: dir.to_path_buf(),
            master,
            lock: Some(lock),
        })
    }

    /// Release the instance lock explicitly.
    ///
    /// Needed because `panic = "abort"` skips destructors (§5.5).
    pub fn close(mut self) -> Result<(), CryptoError> {
        if let Some(lock) = self.lock.take() {
            lock.release()?;
        }
        Ok(())
    }

    /// Change the passphrase, rewriting only the header (§9.6).
    pub fn change_passphrase(
        dir: &Path,
        old: &[u8],
        new: &[u8],
        params: KdfParams,
    ) -> Result<(), CryptoError> {
        let path = dir.join(HEADER_FILENAME);
        let mut header = Header::read(stdfs::File::open(&path).map_err(|_| CryptoError::BadHeader)?)?;
        header.change_passphrase(old, new, params)?;

        let mut buf = Vec::new();
        header.write(&mut buf)?;
        atomic_write_with(&path, |f| std::io::Write::write_all(f, &buf))?;
        Ok(())
    }

    /// Translate a virtual path to its on-disk location.
    ///
    /// Walks component by component, because each name is encrypted under its
    /// parent's ID and so cannot be computed independently.
    fn resolve(&self, vpath: &VirtualPath) -> Result<PathBuf, CryptoError> {
        let names = self.master.names_key()?;
        let mut real = self.root.clone();
        let mut parent = DirId::root();

        for component in vpath.components() {
            let enc = encrypt_name(&names, &parent, component)?;
            real.push(&enc);
            parent = DirId::child(&enc);
        }
        Ok(real)
    }

    /// The `DirId` of a virtual directory, for encrypting names inside it.
    fn dir_id(&self, vpath: &VirtualPath) -> Result<DirId, CryptoError> {
        let names = self.master.names_key()?;
        let mut parent = DirId::root();

        for component in vpath.components() {
            let enc = encrypt_name(&names, &parent, component)?;
            parent = DirId::child(&enc);
        }
        Ok(parent)
    }

    /// List a directory.
    ///
    /// Decrypts names only — never contents (§6.3). Entries whose names fail to
    /// decrypt are skipped rather than aborting the listing: one corrupt name
    /// should not make a directory unbrowsable.
    pub fn list(&self, vpath: &VirtualPath) -> Result<Vec<Entry>, CryptoError> {
        let real = self.resolve(vpath)?;
        let names = self.master.names_key()?;
        let parent = self.dir_id(vpath)?;

        let mut entries = Vec::new();
        for entry in stdfs::read_dir(&real)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let encrypted = file_name.to_string_lossy();

            // Header and lock live in the root and are not encrypted (§6.1).
            if encrypted == HEADER_FILENAME || encrypted == fs::LOCK_FILENAME {
                continue;
            }

            let Ok(name) = decrypt_name(&names, &parent, &encrypted) else {
                continue;
            };

            let meta = entry.metadata()?;
            entries.push(Entry {
                name,
                is_dir: meta.is_dir(),
                encrypted_size: meta.len(),
            });
        }

        entries.sort_by(|a, b| (b.is_dir, &a.name).cmp(&(a.is_dir, &b.name)));
        Ok(entries)
    }

    /// Encrypt every plaintext file found inside the vault directory.
    ///
    /// This is the "lockdown folder" behaviour: drop files into the vault, and
    /// they get swallowed. An entry is treated as plaintext when its name does
    /// not decrypt under its parent's key — the same test [`list`] uses to
    /// decide what to show, so anything invisible in the UI is exactly what
    /// gets encrypted here.
    ///
    /// **The originals are deleted** once the encrypted copy is written and
    /// verified. Ordering matters: encrypt to a new name, read it back, and
    /// only then unlink the plaintext. A crash mid-sweep can leave both copies
    /// (recoverable) but never neither (not).
    ///
    /// A caveat worth stating plainly, since this design chooses convenience
    /// over the stronger guarantee: plaintext genuinely exists in the vault
    /// directory until this runs, and deleting a file does not reliably erase
    /// it from an SSD (§6.2). This narrows the exposure window; it does not
    /// eliminate it.
    pub fn encrypt_plaintext(&self, vpath: &VirtualPath) -> Result<SweepReport, CryptoError> {
        self.encrypt_plaintext_with_progress(vpath, |_| {})
    }

    /// As [`encrypt_plaintext`], reporting progress after each file.
    pub fn encrypt_plaintext_with_progress<F: FnMut(Progress)>(
        &self,
        vpath: &VirtualPath,
        mut on_progress: F,
    ) -> Result<SweepReport, CryptoError> {
        let plan = self.plan_lock(vpath)?;
        let mut report = SweepReport::default();
        let mut tracker = Tracker::new(plan, &mut on_progress);

        self.sweep_dir(vpath, &mut report, &mut tracker)?;
        Ok(report)
    }

    /// Count the plaintext files a lock would encrypt, without encrypting.
    ///
    /// Metadata only — no file contents are read, so this stays fast on a large
    /// vault and can run before the progress bar appears.
    pub fn plan_lock(&self, vpath: &VirtualPath) -> Result<Plan, CryptoError> {
        let mut plan = Plan::default();
        self.plan_dir(vpath, false, &mut plan)?;
        Ok(plan)
    }

    /// Count the encrypted files an unlock would decrypt.
    pub fn plan_unlock(&self, vpath: &VirtualPath) -> Result<Plan, CryptoError> {
        let mut plan = Plan::default();
        self.plan_dir(vpath, true, &mut plan)?;
        Ok(plan)
    }

    /// Walk the tree counting work. `encrypted` selects which kind of entry
    /// counts: encrypted names for an unlock, plaintext names for a lock.
    fn plan_dir(
        &self,
        vpath: &VirtualPath,
        encrypted: bool,
        plan: &mut Plan,
    ) -> Result<(), CryptoError> {
        let real = self.resolve(vpath)?;
        let names = self.master.names_key()?;
        let parent = self.dir_id(vpath)?;

        let Ok(listing) = stdfs::read_dir(&real) else {
            return Ok(());
        };

        for entry in listing {
            let entry = entry?;
            let on_disk = entry.file_name().to_string_lossy().into_owned();

            if on_disk == HEADER_FILENAME || on_disk == fs::LOCK_FILENAME {
                continue;
            }
            if on_disk.starts_with(".tmp") {
                continue;
            }

            let decrypted = decrypt_name(&names, &parent, &on_disk).ok();
            let is_dir = entry.file_type()?.is_dir();

            match (&decrypted, encrypted) {
                // An encrypted directory: recurse under its plaintext name.
                (Some(plain), _) if is_dir => {
                    if let Ok(child) = vpath.join(plain) {
                        self.plan_dir(&child, encrypted, plan)?;
                    }
                }
                // A plaintext directory: walk it on disk directly, since it has
                // no place in the virtual namespace yet.
                (None, false) if is_dir => {
                    plan_plain_dir(&entry.path(), plan)?;
                }
                (None, true) if is_dir => {}
                // An encrypted file, counted for an unlock. Progress is measured
                // in plaintext bytes as files are written, so the on-disk
                // ciphertext size has to be converted back — otherwise the
                // denominator is permanently too large and the bar stalls just
                // short of complete.
                (Some(_), true) => {
                    plan.files += 1;
                    plan.bytes += stream::plaintext_len(entry.metadata()?.len());
                }
                // A plaintext file, counted for a lock. Already the right unit.
                (None, false) => {
                    plan.files += 1;
                    plan.bytes += entry.metadata()?.len();
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Decrypt the whole vault in place, leaving real files on the filesystem.
    ///
    /// The inverse of [`encrypt_plaintext`]. Every encrypted entry is rewritten
    /// under its plaintext name and the ciphertext removed, so the folder
    /// becomes ordinary files that any program can open.
    ///
    /// **This is the weak state, by design.** While unlocked the files have no
    /// protection at all: anything on the machine can read them, and backup or
    /// sync software will happily copy them. Protection exists only while
    /// locked. That is the trade this tool makes in exchange for working with
    /// every file type instead of only the ones it can render itself.
    ///
    /// Ordering mirrors the encrypt path: write the plaintext, verify it reads
    /// back, and only then remove the ciphertext. A crash can leave both copies
    /// but never neither.
    pub fn decrypt_all(&self, vpath: &VirtualPath) -> Result<SweepReport, CryptoError> {
        self.decrypt_all_with_progress(vpath, |_| {})
    }

    /// As [`decrypt_all`], reporting progress after each file.
    pub fn decrypt_all_with_progress<F: FnMut(Progress)>(
        &self,
        vpath: &VirtualPath,
        mut on_progress: F,
    ) -> Result<SweepReport, CryptoError> {
        let plan = self.plan_unlock(vpath)?;
        let mut report = SweepReport::default();
        let mut tracker = Tracker::new(plan, &mut on_progress);

        self.unsweep_dir(vpath, &mut report, &mut tracker)?;
        Ok(report)
    }

    fn unsweep_dir(
        &self,
        vpath: &VirtualPath,
        report: &mut SweepReport,
        tracker: &mut Tracker<'_>,
    ) -> Result<(), CryptoError> {
        let real = self.resolve(vpath)?;
        let names = self.master.names_key()?;
        let parent = self.dir_id(vpath)?;

        let listing: Vec<_> = stdfs::read_dir(&real)?.collect::<Result<Vec<_>, _>>()?;

        for entry in listing {
            let file_name = entry.file_name();
            let on_disk = file_name.to_string_lossy().into_owned();

            if on_disk == HEADER_FILENAME || on_disk == fs::LOCK_FILENAME {
                continue;
            }
            if on_disk.starts_with(".tmp") {
                continue;
            }

            // Only encrypted entries are touched. Anything already plaintext is
            // left as-is, so an interrupted unlock can simply be re-run.
            let Ok(plain_name) = decrypt_name(&names, &parent, &on_disk) else {
                continue;
            };

            let vchild = vpath
                .join(&plain_name)
                .map_err(|_| CryptoError::InvalidName)?;

            if entry.file_type()?.is_dir() {
                // Recurse first: the directory must still exist under its
                // encrypted name while its contents are being decrypted.
                self.unsweep_dir(&vchild, report, tracker)?;

                let plain_dir = real.join(&plain_name);
                stdfs::rename(entry.path(), &plain_dir)?;
                report.directories += 1;
            } else if let Err(e) = self.spill(&vchild, &real.join(&plain_name), &entry.path(), report, tracker)
            {
                report.failed.push((plain_name, e.to_string()));
            }
        }
        Ok(())
    }

    /// Decrypt one file to `plain_path`, then remove the ciphertext.
    fn spill(
        &self,
        vpath: &VirtualPath,
        plain_path: &Path,
        cipher_path: &Path,
        report: &mut SweepReport,
        tracker: &mut Tracker<'_>,
    ) -> Result<(), CryptoError> {
        let contents = self.read_file(vpath)?;

        atomic_write_with(plain_path, |f| std::io::Write::write_all(f, &contents))?;

        // Verify before destroying the only encrypted copy.
        let check = stdfs::read(plain_path)?;
        if check != contents {
            return Err(CryptoError::Decrypt);
        }

        stdfs::remove_file(cipher_path)?;
        report.files += 1;
        report.bytes += contents.len() as u64;
        tracker.advance(
            vpath.name().unwrap_or_default(),
            contents.len() as u64,
        );
        Ok(())
    }

    fn sweep_dir(
        &self,
        vpath: &VirtualPath,
        report: &mut SweepReport,
        tracker: &mut Tracker<'_>,
    ) -> Result<(), CryptoError> {
        let real = self.resolve(vpath)?;
        let names = self.master.names_key()?;
        let parent = self.dir_id(vpath)?;

        // Collected up front: encrypting renames entries, and mutating a
        // directory while iterating it has platform-dependent behaviour.
        let listing: Vec<_> = stdfs::read_dir(&real)?.collect::<Result<Vec<_>, _>>()?;

        for entry in listing {
            let file_name = entry.file_name();
            let on_disk = file_name.to_string_lossy().into_owned();

            if on_disk == HEADER_FILENAME || on_disk == fs::LOCK_FILENAME {
                continue;
            }
            // Debris from an interrupted write, not user data.
            if on_disk.starts_with(".tmp") {
                continue;
            }

            let is_dir = entry.file_type()?.is_dir();

            match decrypt_name(&names, &parent, &on_disk) {
                // Already encrypted. Recurse to catch plaintext dropped into an
                // existing vault subdirectory.
                Ok(plain) => {
                    if is_dir {
                        let child = vpath.join(&plain).map_err(|_| CryptoError::InvalidName)?;
                        self.sweep_dir(&child, report, tracker)?;
                    }
                }
                // Plaintext: swallow it.
                Err(_) => {
                    if let Err(e) = self.swallow(vpath, &on_disk, is_dir, report, tracker) {
                        report.failed.push((on_disk, e.to_string()));
                    }
                }
            }
        }
        Ok(())
    }

    /// Encrypt one plaintext entry in place, then remove the original.
    fn swallow(
        &self,
        parent_vpath: &VirtualPath,
        plain_name: &str,
        is_dir: bool,
        report: &mut SweepReport,
        tracker: &mut Tracker<'_>,
    ) -> Result<(), CryptoError> {
        // A name too long to encrypt would otherwise fail after the plaintext
        // was already gone. Check before touching anything.
        let target = parent_vpath
            .join(plain_name)
            .map_err(|_| CryptoError::InvalidName)?;

        let real_parent = self.resolve(parent_vpath)?;
        let plain_path = real_parent.join(plain_name);

        if is_dir {
            // Create the encrypted directory, then sweep the plaintext contents
            // into it before removing the now-empty original.
            self.create_dir(&target)?;
            self.move_tree_in(&plain_path, &target, report, tracker)?;
            stdfs::remove_dir_all(&plain_path)?;
            report.directories += 1;
            return Ok(());
        }

        let contents = stdfs::read(&plain_path)?;
        self.write_file(&target, &contents)?;

        // Read back before deleting the original: if this file cannot be
        // recovered, the plaintext is the only copy and must survive.
        let check = self.read_file(&target)?;
        if check != contents {
            return Err(CryptoError::Decrypt);
        }

        stdfs::remove_file(&plain_path)?;
        report.files += 1;
        report.bytes += contents.len() as u64;
        tracker.advance(plain_name, contents.len() as u64);
        Ok(())
    }

    /// Recursively encrypt a plaintext directory's contents into the vault.
    fn move_tree_in(
        &self,
        plain_dir: &Path,
        dest: &VirtualPath,
        report: &mut SweepReport,
        tracker: &mut Tracker<'_>,
    ) -> Result<(), CryptoError> {
        for entry in stdfs::read_dir(plain_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let target = dest.join(&name).map_err(|_| CryptoError::InvalidName)?;

            if entry.file_type()?.is_dir() {
                self.create_dir(&target)?;
                self.move_tree_in(&entry.path(), &target, report, tracker)?;
                report.directories += 1;
            } else {
                let contents = stdfs::read(entry.path())?;
                self.write_file(&target, &contents)?;
                report.files += 1;
                report.bytes += contents.len() as u64;
                tracker.advance(&name, contents.len() as u64);
            }
        }
        Ok(())
    }

    /// Create a directory.
    pub fn create_dir(&self, vpath: &VirtualPath) -> Result<(), CryptoError> {
        stdfs::create_dir_all(self.resolve(vpath)?)?;
        Ok(())
    }

    /// Encrypt `plaintext` to `vpath`, atomically (§5.5).
    pub fn write_file(&self, vpath: &VirtualPath, plaintext: &[u8]) -> Result<(), CryptoError> {
        let real = self.resolve(vpath)?;
        let content = self.master.content_key()?;

        atomic_write_with(&real, |f| {
            let mut w = BufWriter::new(f);
            stream::encrypt(&content, plaintext, &mut w).map_err(std::io::Error::other)?;
            std::io::Write::flush(&mut w)
        })?;
        Ok(())
    }

    /// Decrypt the file at `vpath`.
    pub fn read_file(&self, vpath: &VirtualPath) -> Result<Vec<u8>, CryptoError> {
        let real = self.resolve(vpath)?;
        let content = self.master.content_key()?;
        let file = stdfs::File::open(&real)?;

        let mut out = Vec::new();
        stream::decrypt(&content, std::io::BufReader::new(file), &mut out)?;
        Ok(out)
    }

    /// Delete a file.
    pub fn remove_file(&self, vpath: &VirtualPath) -> Result<(), CryptoError> {
        stdfs::remove_file(self.resolve(vpath)?)?;
        Ok(())
    }

    /// Delete a directory and everything under it.
    pub fn remove_dir_all(&self, vpath: &VirtualPath) -> Result<(), CryptoError> {
        if vpath.is_root() {
            return Err(CryptoError::InvalidName);
        }
        stdfs::remove_dir_all(self.resolve(vpath)?)?;
        Ok(())
    }

    /// The vault directory on disk.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether anything exists at `vpath`.
    pub fn exists(&self, vpath: &VirtualPath) -> Result<bool, CryptoError> {
        Ok(self.resolve(vpath)?.exists())
    }

    /// What state the vault folder is currently in.
    ///
    /// Determined by looking at the root only, which is enough: the lock and
    /// unlock operations are all-or-nothing, so a mixture means one of them was
    /// interrupted and re-running it will finish the job.
    pub fn state(&self) -> Result<VaultState, CryptoError> {
        let names = self.master.names_key()?;
        let parent = DirId::root();

        let mut encrypted = 0usize;
        let mut plaintext = 0usize;

        for entry in stdfs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();

            if name == HEADER_FILENAME || name == fs::LOCK_FILENAME || name.starts_with(".tmp") {
                continue;
            }

            if decrypt_name(&names, &parent, &name).is_ok() {
                encrypted += 1;
            } else {
                plaintext += 1;
            }
        }

        Ok(match (encrypted, plaintext) {
            (0, 0) => VaultState::Empty,
            (_, 0) => VaultState::Locked,
            (0, _) => VaultState::Unlocked,
            _ => VaultState::Mixed,
        })
    }

    /// Rename an entry within its directory.
    ///
    /// Renaming a *directory* changes its encrypted name, which changes the
    /// `DirId` its children were encrypted under — so every child name would
    /// have to be re-encrypted recursively. Refused for now rather than done
    /// halfway; see the note in the milestone 3 handoff.
    pub fn rename(&self, from: &VirtualPath, to_name: &str) -> Result<(), CryptoError> {
        let real_from = self.resolve(from)?;
        if real_from.is_dir() {
            return Err(CryptoError::UnsupportedOperation);
        }

        let parent = from.parent().ok_or(CryptoError::InvalidName)?;
        let to = parent.join(to_name).map_err(|_| CryptoError::InvalidName)?;

        stdfs::rename(real_from, self.resolve(&to)?)?;
        Ok(())
    }
}
