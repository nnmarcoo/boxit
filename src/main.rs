//! CLI harness for the headless vault (§8, milestone 2).
//!
//! Exists to drive the vault without a UI — both as the milestone-2 deliverable
//! and as standing proof that the vault layer has no UI dependency (§7.1). The
//! iced front end lands in milestone 3 and will call the same API.
//!
//! Passphrases are read from the `BOXIT_PASSPHRASE` environment variable. That
//! is deliberate and temporary: a real prompt with echo disabled belongs in the
//! UI milestone, and taking one as an argv parameter would leak it to every
//! process listing on the machine.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use boxit::crypto::kdf::KdfParams;
use boxit::vault::path::VirtualPath;
use boxit::vault::{Entry, Vault};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let result = match args.as_slice() {
        ["init", dir] => cmd_init(Path::new(dir)),
        ["list", dir] => cmd_list(Path::new(dir), "/"),
        ["list", dir, path] => cmd_list(Path::new(dir), path),
        ["import", dir, src, dest] => cmd_import(Path::new(dir), Path::new(src), dest),
        ["export", dir, path, dest] => cmd_export(Path::new(dir), path, Path::new(dest)),
        ["cat", dir, path] => cmd_cat(Path::new(dir), path),
        _ => {
            usage();
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!(
        "boxit — encrypted vault (milestone 2: headless)

usage:
  boxit init   <vault-dir>
  boxit list   <vault-dir> [path]
  boxit import <vault-dir> <src-file|src-dir> <vault-path>
  boxit export <vault-dir> <vault-path> <dest-file>
  boxit cat    <vault-dir> <vault-path>

The passphrase is read from BOXIT_PASSPHRASE."
    );
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn passphrase() -> Result<String> {
    std::env::var("BOXIT_PASSPHRASE")
        .map_err(|_| "BOXIT_PASSPHRASE is not set".into())
}

fn open(dir: &Path) -> Result<Vault> {
    Ok(Vault::unlock(dir, passphrase()?.as_bytes())?)
}

fn cmd_init(dir: &Path) -> Result<()> {
    Vault::init(dir, passphrase()?.as_bytes(), KdfParams::default())?;
    println!("initialized vault at {}", dir.display());
    Ok(())
}

fn cmd_list(dir: &Path, path: &str) -> Result<()> {
    let vault = open(dir)?;
    let vpath = VirtualPath::parse(path)?;

    let entries = vault.list(&vpath)?;
    for Entry {
        name,
        is_dir,
        encrypted_size,
    } in &entries
    {
        // Size shown is the on-disk ciphertext size: reporting the plaintext
        // size would mean decrypting every file just to render a listing (§6.3).
        if *is_dir {
            println!("  {name}/");
        } else {
            println!("  {name}  ({encrypted_size} bytes on disk)");
        }
    }
    if entries.is_empty() {
        println!("  (empty)");
    }

    vault.close()?;
    Ok(())
}

fn cmd_import(dir: &Path, src: &Path, dest: &str) -> Result<()> {
    let vault = open(dir)?;
    let base = VirtualPath::parse(dest)?;

    let count = if src.is_dir() {
        import_tree(&vault, src, &base)?
    } else {
        let contents = std::fs::read(src)?;
        vault.write_file(&base, &contents)?;
        1
    };

    println!("imported {count} file(s)");
    vault.close()?;
    Ok(())
}

/// Recursively encrypt a plaintext tree into the vault.
fn import_tree(vault: &Vault, src: &Path, dest: &VirtualPath) -> Result<usize> {
    vault.create_dir(dest)?;
    let mut count = 0;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let target = dest.join(&name)?;

        if entry.file_type()?.is_dir() {
            count += import_tree(vault, &entry.path(), &target)?;
        } else {
            vault.write_file(&target, &std::fs::read(entry.path())?)?;
            count += 1;
        }
    }
    Ok(count)
}

fn cmd_export(dir: &Path, path: &str, dest: &Path) -> Result<()> {
    let vault = open(dir)?;
    let contents = vault.read_file(&VirtualPath::parse(path)?)?;

    // Writing plaintext outside the vault is the §6.2 boundary. The CLI does it
    // only because the caller asked for it by name.
    std::fs::write(dest, &contents)?;
    println!("exported {} bytes to {}", contents.len(), dest.display());

    vault.close()?;
    Ok(())
}

fn cmd_cat(dir: &Path, path: &str) -> Result<()> {
    let vault = open(dir)?;
    let contents = vault.read_file(&VirtualPath::parse(path)?)?;

    use std::io::Write;
    std::io::stdout().write_all(&contents)?;

    vault.close()?;
    Ok(())
}

/// Locate the vault relative to the executable, not the working directory.
///
/// Unused by the CLI, which takes an explicit path, but this is the rule the
/// GUI must follow in milestone 3 (§6.1): `current_dir()` is "whatever
/// directory the user launched from", which is not the same thing at all.
#[allow(dead_code)]
fn vault_dir_from_exe() -> std::io::Result<PathBuf> {
    let exe = std::env::current_exe()?.canonicalize()?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| std::io::Error::other("executable has no parent directory"))
}
