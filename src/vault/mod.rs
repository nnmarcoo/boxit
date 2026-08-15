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

/// An unlocked vault.
///
/// Holds the master key in memory; dropping it zeroizes the key material.
pub struct Vault {
    root: PathBuf,
    master: Key,
    lock: Option<VaultLock>,
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
