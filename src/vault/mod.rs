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

/// How much data may be written before flushing and deleting the originals.
///
/// This bounds the extra disk space an operation needs: at any moment only one
/// batch exists in both encrypted and plaintext form. Larger batches mean fewer
/// flushes and more speed, at the cost of more temporary space and more work to
/// redo if the machine loses power mid-batch.
///
/// A single file larger than this still gets its own batch — the bound cannot
/// be smaller than one file.
const BATCH_BYTES: u64 = 256 * 1024 * 1024;

/// One file to convert, queued during the sequential walk and executed in
/// parallel afterwards.
///
/// For a lock, `source` is the plaintext on disk and `target` is where it
/// lands in the vault. For an unlock the roles invert: `target` is the
/// encrypted file to read and `source` is the plaintext destination.
struct Job {
    source: PathBuf,
    target: VirtualPath,
    /// Plaintext name, for progress display and error reporting.
    label: String,
    /// Approximate plaintext size, used only to bound batches.
    size_hint: u64,
}

/// A file successfully written, whose predecessor can now be removed.
struct Written {
    /// The file it replaces, deleted only once the replacement is durable.
    remove_path: PathBuf,
    /// Plaintext byte count, for progress and reporting.
    bytes: u64,
    label: String,
}

/// Split jobs into batches bounded by total bytes.
///
/// A file bigger than the cap forms its own batch: the bound cannot be smaller
/// than a single file, since both copies of it exist while it is converted.
fn batches(jobs: &[Job]) -> Vec<&[Job]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut acc = 0u64;

    for (i, job) in jobs.iter().enumerate() {
        let size = job.size_hint;

        // Close the current batch before adding a job that would overflow it,
        // unless the batch is empty and this job alone exceeds the cap.
        if acc > 0 && acc + size > BATCH_BYTES {
            out.push(&jobs[start..i]);
            start = i;
            acc = 0;
        }
        acc += size;
    }

    if start < jobs.len() {
        out.push(&jobs[start..]);
    }
    out
}

/// Remove a directory tree, but only the parts that are empty.
///
/// Anything left behind is a file that failed to encrypt, which must survive
/// along with the directories holding it.
fn remove_if_empty_recursive(dir: &Path) -> Result<(), CryptoError> {
    for entry in stdfs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_if_empty_recursive(&entry.path())?;
        }
    }
    // Fails harmlessly if anything remains, which is the intended behaviour.
    let _ = stdfs::remove_dir(dir);
    Ok(())
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
    /// **The originals are deleted** once the encrypted copy is durably on
    /// disk. Ordering matters: write the ciphertext, fsync it, check its length,
    /// and only then unlink the plaintext. A crash mid-sweep can leave both
    /// copies (recoverable) but never neither (not).
    ///
    /// Files are processed in parallel; directory structure is created first,
    /// sequentially, so every target directory exists before any file lands.
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
    ///
    /// `on_progress` is called from worker threads, so it must be `Send`. It is
    /// serialised behind a mutex, so it never runs concurrently with itself.
    pub fn encrypt_plaintext_with_progress<F: FnMut(Progress) + Send>(
        &self,
        vpath: &VirtualPath,
        on_progress: F,
    ) -> Result<SweepReport, CryptoError> {
        let plan = self.plan_lock(vpath)?;

        // Phase 1, sequential: create the encrypted directory tree and collect
        // the files to convert. Directories must exist before files land in
        // them, and building the tree touches shared parent state.
        let mut jobs = Vec::new();
        let mut report = SweepReport::default();
        self.collect_lock_jobs(vpath, &mut jobs, &mut report)?;
        self.check_space(&jobs)?;

        // Phase 2, parallel: files are independent — separate sources, separate
        // targets, separate atomic writes. Nothing is shared but the key.
        let report = self.run_jobs(jobs, plan, report, on_progress, |job| {
            let bytes = self.encrypt_file_from(&job.source, &job.target)?;
            Ok(Written {
                // The plaintext original, deleted once the ciphertext is
                // durable.
                remove_path: job.source.clone(),
                bytes,
                label: job.label.clone(),
            })
        })?;

        // Phase 3: the plaintext directories are empty now that their files
        // have been encrypted out of them, so they can be removed. Deepest
        // first, since a parent cannot go before its children.
        self.remove_empty_plain_dirs(vpath)?;
        Ok(report)
    }

    /// Remove plaintext directories left empty by a lock.
    ///
    /// Only empties are removed, so a directory still holding a file that
    /// failed to encrypt survives along with its contents.
    fn remove_empty_plain_dirs(&self, vpath: &VirtualPath) -> Result<(), CryptoError> {
        let real = self.resolve(vpath)?;
        let names = self.master.names_key()?;
        let parent = self.dir_id(vpath)?;

        let listing: Vec<_> = stdfs::read_dir(&real)?.collect::<Result<Vec<_>, _>>()?;

        for entry in listing {
            let on_disk = entry.file_name().to_string_lossy().into_owned();
            if on_disk == HEADER_FILENAME || on_disk == fs::LOCK_FILENAME {
                continue;
            }
            if !entry.file_type()?.is_dir() {
                continue;
            }

            match decrypt_name(&names, &parent, &on_disk) {
                // Encrypted directory: descend, in case plaintext was dropped
                // inside it and has just been swallowed.
                Ok(plain) => {
                    if let Ok(child) = vpath.join(&plain) {
                        self.remove_empty_plain_dirs(&child)?;
                    }
                }
                // Plaintext directory: clear it bottom-up.
                Err(_) => {
                    remove_if_empty_recursive(&entry.path())?;
                }
            }
        }
        Ok(())
    }

    /// Walk the tree creating directories and listing files that need work.
    fn collect_lock_jobs(
        &self,
        vpath: &VirtualPath,
        jobs: &mut Vec<Job>,
        report: &mut SweepReport,
    ) -> Result<(), CryptoError> {
        let real = self.resolve(vpath)?;
        let names = self.master.names_key()?;
        let parent = self.dir_id(vpath)?;

        let listing: Vec<_> = stdfs::read_dir(&real)?.collect::<Result<Vec<_>, _>>()?;

        for entry in listing {
            let on_disk = entry.file_name().to_string_lossy().into_owned();

            if on_disk == HEADER_FILENAME || on_disk == fs::LOCK_FILENAME {
                continue;
            }
            if on_disk.starts_with(".tmp") {
                continue;
            }

            let is_dir = entry.file_type()?.is_dir();

            match decrypt_name(&names, &parent, &on_disk) {
                // Already encrypted: recurse to catch plaintext dropped inside.
                Ok(plain) if is_dir => {
                    let child = vpath.join(&plain).map_err(|_| CryptoError::InvalidName)?;
                    self.collect_lock_jobs(&child, jobs, report)?;
                }
                Ok(_) => {}
                // Plaintext directory: mirror it into the vault, then descend.
                Err(_) if is_dir => {
                    let Ok(target) = vpath.join(&on_disk) else {
                        report.failed.push((on_disk, "invalid name".into()));
                        continue;
                    };
                    if let Err(e) = self.create_dir(&target) {
                        report.failed.push((on_disk, e.to_string()));
                        continue;
                    }
                    self.collect_plain_tree(&entry.path(), &target, jobs, report)?;
                    report.directories += 1;
                }
                // Plaintext file: queue it.
                Err(_) => match vpath.join(&on_disk) {
                    Ok(target) => jobs.push(Job {
                        size_hint: entry.metadata().map(|m| m.len()).unwrap_or(0),
                        source: entry.path(),
                        target,
                        label: on_disk,
                    }),
                    Err(_) => report.failed.push((on_disk, "invalid name".into())),
                },
            }
        }
        Ok(())
    }

    /// Mirror a plaintext directory into the vault, queueing its files.
    ///
    /// The plaintext directory itself is removed later, once its files have
    /// been encrypted out of it.
    fn collect_plain_tree(
        &self,
        plain_dir: &Path,
        dest: &VirtualPath,
        jobs: &mut Vec<Job>,
        report: &mut SweepReport,
    ) -> Result<(), CryptoError> {
        for entry in stdfs::read_dir(plain_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();

            let Ok(target) = dest.join(&name) else {
                report.failed.push((name, "invalid name".into()));
                continue;
            };

            if entry.file_type()?.is_dir() {
                self.create_dir(&target)?;
                self.collect_plain_tree(&entry.path(), &target, jobs, report)?;
                report.directories += 1;
            } else {
                jobs.push(Job {
                    size_hint: entry.metadata().map(|m| m.len()).unwrap_or(0),
                    source: entry.path(),
                    target,
                    label: name,
                });
            }
        }
        Ok(())
    }

    /// Run queued file jobs in parallel, in batches.
    ///
    /// Each batch is: write every file (no flush), flush the batch once, then
    /// delete the sources. Flushing once per batch instead of once per file is
    /// worth roughly 4x, because fsync dominates the cost of both directions.
    ///
    /// The ordering that matters is preserved: nothing is deleted until the
    /// data replacing it is durably on disk. A crash mid-batch leaves duplicate
    /// copies of that batch — recoverable — never a gap.
    ///
    /// Batches are capped by bytes rather than file count so a handful of large
    /// files cannot blow past the disk-space bound.
    fn run_jobs<F, W>(
        &self,
        jobs: Vec<Job>,
        plan: Plan,
        mut report: SweepReport,
        on_progress: F,
        work: W,
    ) -> Result<SweepReport, CryptoError>
    where
        F: FnMut(Progress) + Send,
        W: Fn(&Job) -> Result<Written, CryptoError> + Sync + Send,
    {
        use rayon::prelude::*;
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

        let files_done = AtomicUsize::new(0);
        let bytes_done = AtomicU64::new(0);
        let progress = Mutex::new(on_progress);
        let failures = Mutex::new(Vec::new());

        for batch in batches(&jobs) {
            // Phase 1: write everything in this batch, in parallel, unflushed.
            let done: Vec<Written> = batch
                .par_iter()
                .filter_map(|job| match work(job) {
                    Ok(written) => Some(written),
                    Err(e) => {
                        // A failure leaves this file in its previous state; the
                        // rest of the batch still proceeds.
                        if let Ok(mut f) = failures.lock() {
                            f.push((job.label.clone(), e.to_string()));
                        }
                        None
                    }
                })
                .collect();

            // Each file was fsynced as it was written, so the batch is already
            // durable here. Deferring the flushes was measured and did not pay:
            // fsync cost tracks bytes written, not the number of calls, so
            // batching saved ~6% while costing a reopen per file.
            //
            // Phase 2: the replacements are on the drive, so the sources can go.
            for w in &done {
                if let Err(e) = stdfs::remove_file(&w.remove_path) {
                    if let Ok(mut f) = failures.lock() {
                        f.push((w.label.clone(), e.to_string()));
                    }
                    continue;
                }

                report.files += 1;
                report.bytes += w.bytes;

                let files = files_done.fetch_add(1, Ordering::Relaxed) + 1;
                let bytes = bytes_done.fetch_add(w.bytes, Ordering::Relaxed) + w.bytes;

                if let Ok(mut cb) = progress.lock() {
                    cb(Progress {
                        current: w.label.clone(),
                        files_done: files,
                        files_total: plan.files.max(files),
                        bytes_done: bytes,
                        bytes_total: plan.bytes.max(bytes),
                    });
                }
            }
        }

        report
            .failed
            .extend(failures.into_inner().unwrap_or_default());

        Ok(report)
    }

    /// Refuse to start if the drive lacks room for the conversion.
    ///
    /// Both directions write the replacement before deleting what it replaces,
    /// so the peak requirement is one batch plus the largest single file. Better
    /// to say so up front than to fill the disk halfway through and leave the
    /// vault in the [`VaultState::Mixed`] state.
    fn check_space(&self, jobs: &[Job]) -> Result<(), CryptoError> {
        let Some(available) = fs::available_space(&self.root) else {
            // Cannot tell — proceed. Individual writes still fail safely.
            return Ok(());
        };

        let largest = jobs.iter().map(|j| j.size_hint).max().unwrap_or(0);
        let batch = jobs
            .iter()
            .map(|j| j.size_hint)
            .take_while(|_| true)
            .sum::<u64>()
            .min(BATCH_BYTES);

        // A margin over the theoretical need: encryption adds tags, and a drive
        // at literally zero free space misbehaves in other ways.
        let needed = largest.max(batch) + largest / 10 + 16 * 1024 * 1024;

        if available < needed {
            return Err(CryptoError::NotEnoughSpace {
                needed,
                available,
            });
        }
        Ok(())
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
    pub fn decrypt_all_with_progress<F: FnMut(Progress) + Send>(
        &self,
        vpath: &VirtualPath,
        on_progress: F,
    ) -> Result<SweepReport, CryptoError> {
        let plan = self.plan_unlock(vpath)?;

        // Files first, in parallel, while the encrypted directory names still
        // resolve. Renaming a directory would invalidate the paths of every
        // file beneath it, so that has to come afterwards.
        let mut jobs = Vec::new();
        let mut report = SweepReport::default();
        self.collect_unlock_jobs(vpath, &mut jobs, &mut report)?;
        self.check_space(&jobs)?;

        let mut report = self.run_jobs(jobs, plan, report, on_progress, |job| {
            let bytes = self.decrypt_file_to(&job.target, &job.source)?;
            Ok(Written {
                // The ciphertext, deleted once the plaintext is durable.
                remove_path: self.resolve(&job.target)?,
                bytes,
                label: job.label.clone(),
            })
        })?;

        // Now rename directories bottom-up, so children are renamed before the
        // parents whose names they were encrypted under.
        self.rename_dirs_to_plaintext(vpath, &mut report)?;
        Ok(report)
    }

    /// Queue every encrypted file for decryption, deepest first.
    fn collect_unlock_jobs(
        &self,
        vpath: &VirtualPath,
        jobs: &mut Vec<Job>,
        report: &mut SweepReport,
    ) -> Result<(), CryptoError> {
        let real = self.resolve(vpath)?;
        let names = self.master.names_key()?;
        let parent = self.dir_id(vpath)?;

        let listing: Vec<_> = stdfs::read_dir(&real)?.collect::<Result<Vec<_>, _>>()?;

        for entry in listing {
            let on_disk = entry.file_name().to_string_lossy().into_owned();

            if on_disk == HEADER_FILENAME || on_disk == fs::LOCK_FILENAME {
                continue;
            }
            if on_disk.starts_with(".tmp") {
                continue;
            }

            // Anything already plaintext is left alone, so an interrupted
            // unlock can simply be re-run.
            let Ok(plain_name) = decrypt_name(&names, &parent, &on_disk) else {
                continue;
            };
            let Ok(vchild) = vpath.join(&plain_name) else {
                report.failed.push((plain_name, "invalid name".into()));
                continue;
            };

            if entry.file_type()?.is_dir() {
                self.collect_unlock_jobs(&vchild, jobs, report)?;
            } else {
                jobs.push(Job {
                    // Ciphertext size is close enough to bound a batch.
                    size_hint: entry.metadata().map(|m| m.len()).unwrap_or(0),
                    // For an unlock, `source` is where the plaintext will land.
                    source: real.join(&plain_name),
                    target: vchild,
                    label: plain_name,
                });
            }
        }
        Ok(())
    }

    /// Rename encrypted directories to their plaintext names, depth-first.
    fn rename_dirs_to_plaintext(
        &self,
        vpath: &VirtualPath,
        report: &mut SweepReport,
    ) -> Result<(), CryptoError> {
        let real = self.resolve(vpath)?;
        let names = self.master.names_key()?;
        let parent = self.dir_id(vpath)?;

        let listing: Vec<_> = stdfs::read_dir(&real)?.collect::<Result<Vec<_>, _>>()?;

        for entry in listing {
            let on_disk = entry.file_name().to_string_lossy().into_owned();
            if on_disk == HEADER_FILENAME || on_disk == fs::LOCK_FILENAME {
                continue;
            }
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let Ok(plain_name) = decrypt_name(&names, &parent, &on_disk) else {
                continue;
            };
            let Ok(vchild) = vpath.join(&plain_name) else {
                continue;
            };

            // Depth-first: rename the contents before the container.
            self.rename_dirs_to_plaintext(&vchild, report)?;

            stdfs::rename(entry.path(), real.join(&plain_name))?;
            report.directories += 1;
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

    /// Encrypt a file on disk straight into the vault, without buffering it.
    ///
    /// Streams plaintext → ciphertext in 64 KiB chunks, so a 4 GB video costs a
    /// couple of buffers rather than 4 GB of RAM. That matters more once
    /// several files are in flight at once.
    ///
    /// Returns the plaintext byte count, for progress accounting.
    fn encrypt_file_from(&self, src: &Path, vpath: &VirtualPath) -> Result<u64, CryptoError> {
        let real = self.resolve(vpath)?;
        let content = self.master.content_key()?;

        let plaintext_len = stdfs::metadata(src)?.len();
        let source = stdfs::File::open(src)?;

        atomic_write_with(&real, |f| {
            let mut w = BufWriter::new(f);
            stream::encrypt(&content, std::io::BufReader::new(source), &mut w)
                .map_err(std::io::Error::other)?;
            std::io::Write::flush(&mut w)
        })?;

        // Cheap integrity check in place of a full read-back: a short file means
        // the write was truncated. The AEAD tag already covers corruption of the
        // bytes themselves, so decrypting the whole file again would cost a
        // second pass to learn almost nothing.
        let written = stdfs::metadata(&real)?.len();
        let expected = stream::ciphertext_len(plaintext_len);
        if written != expected {
            let _ = stdfs::remove_file(&real);
            return Err(CryptoError::Truncated);
        }

        Ok(plaintext_len)
    }

    /// Decrypt a file from the vault straight to disk, without buffering it.
    ///
    /// Returns the plaintext byte count.
    fn decrypt_file_to(&self, vpath: &VirtualPath, dest: &Path) -> Result<u64, CryptoError> {
        let real = self.resolve(vpath)?;
        let content = self.master.content_key()?;
        let source = stdfs::File::open(&real)?;

        atomic_write_with(dest, |f| {
            let mut w = BufWriter::new(f);
            stream::decrypt(&content, std::io::BufReader::new(source), &mut w)
                .map_err(std::io::Error::other)?;
            std::io::Write::flush(&mut w)
        })?;

        Ok(stdfs::metadata(dest)?.len())
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
