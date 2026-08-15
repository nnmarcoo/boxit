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
        let mut report = SweepReport::default();
        self.sweep_dir(vpath, &mut report)?;
        Ok(report)
    }

    fn sweep_dir(
        &self,
        vpath: &VirtualPath,
        report: &mut SweepReport,
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
                        self.sweep_dir(&child, report)?;
                    }
                }
                // Plaintext: swallow it.
                Err(_) => {
                    if let Err(e) = self.swallow(vpath, &on_disk, is_dir, report) {
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
            self.move_tree_in(&plain_path, &target, report)?;
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
        Ok(())
    }

    /// Recursively encrypt a plaintext directory's contents into the vault.
    fn move_tree_in(
        &self,
        plain_dir: &Path,
        dest: &VirtualPath,
        report: &mut SweepReport,
    ) -> Result<(), CryptoError> {
        for entry in stdfs::read_dir(plain_dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let target = dest.join(&name).map_err(|_| CryptoError::InvalidName)?;

            if entry.file_type()?.is_dir() {
                self.create_dir(&target)?;
                self.move_tree_in(&entry.path(), &target, report)?;
                report.directories += 1;
            } else {
                let contents = stdfs::read(entry.path())?;
                self.write_file(&target, &contents)?;
                report.files += 1;
                report.bytes += contents.len() as u64;
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

    /// Whether anything exists at `vpath`.
    pub fn exists(&self, vpath: &VirtualPath) -> Result<bool, CryptoError> {
        Ok(self.resolve(vpath)?.exists())
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
