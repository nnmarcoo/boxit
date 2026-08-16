//! GUI entry point (§7.2).
//!
//! The vault is a `vault/` folder beside the executable, located from
//! `current_exe()` rather than the working directory (§6.1): the two diverge
//! constantly, and the difference is "the folder this tool ships in" versus
//! "whatever directory the user launched from".
//!
//! Rendering is tiny-skia only — wgpu is compiled out, not merely a fallback
//! (§2.1), so this window opens on a machine with no graphics driver at all.

// Release builds detach from the console on Windows; debug keeps it so panics
// and logging remain visible while developing.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use boxit::ui::app::App;

fn main() -> iced::Result {
    let vault_dir = match vault_dir() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("cannot determine vault location: {e}");
            std::process::exit(1);
        }
    };

    iced::application(
        move || App::new(vault_dir.clone()),
        App::update,
        App::view,
    )
    .title(App::title)
    .subscription(App::subscription)
    // The app closes the window itself, after re-locking the vault. Without
    // this, iced would exit immediately and leave the files decrypted.
    .exit_on_close_request(false)
    .window_size((640.0, 480.0))
    .run()
}

/// Name of the vault directory beside the executable.
const VAULT_DIR_NAME: &str = "vault";

/// A `vault/` folder next to the executable (§6.1).
///
/// Located from `current_exe()` rather than `current_dir()`: those diverge
/// constantly, and the difference is "the folder this tool ships in" versus
/// "whatever directory the user happened to launch from".
///
/// The vault is a *subdirectory* rather than the executable's own folder. That
/// keeps the encrypted tree from sharing a directory with the binary, the
/// header, and the lock file, so there is nothing to accidentally encrypt and
/// no exclusion list to get wrong. It also means running the debug build does
/// not target `target/debug` and eat the build artifacts.
///
/// Created on demand, so a freshly copied executable just works.
fn vault_dir() -> std::io::Result<PathBuf> {
    if let Some(dir) = std::env::var_os("BOXIT_VAULT_DIR") {
        return Ok(PathBuf::from(dir));
    }

    let exe = std::env::current_exe()?.canonicalize()?;
    let parent = exe
        .parent()
        .ok_or_else(|| std::io::Error::other("executable has no parent directory"))?;

    let dir = parent.join(VAULT_DIR_NAME);
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
