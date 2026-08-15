//! Test helper for `tests/crash_safety.rs`. Not part of the shipped tool.
//!
//! Opens the vault given as argv[1] and writes to it in a tight loop until the
//! parent kills it. The point is to be killed at an arbitrary instant, so it
//! never exits on its own and cleans up nothing.

use boxit::vault::Vault;
use boxit::vault::path::VirtualPath;

fn main() {
    let dir = std::env::args().nth(1).expect("usage: crash_helper <vault dir>");

    let vault = match Vault::unlock(std::path::Path::new(&dir), b"crash test passphrase") {
        Ok(v) => v,
        // The parent may have killed a previous run while it held the lock.
        Err(_) => {
            let _ = std::fs::remove_file(std::path::Path::new(&dir).join(".vault-lock"));
            Vault::unlock(std::path::Path::new(&dir), b"crash test passphrase")
                .expect("unlock failed in crash helper")
        }
    };

    // A payload big enough that a write spans several chunks, widening the
    // window in which the kill can land mid-operation.
    let payload = b"REWRITTEN BY THE HELPER PROCESS";
    let bulk = vec![b'x'; 300_000];

    let mut counter = 0u64;
    loop {
        let target = VirtualPath::parse("target.txt").unwrap();
        let _ = vault.write_file(&target, payload);

        // Churn other files too, so crashes land in varied places.
        let name = format!("churn-{}.bin", counter % 5);
        if let Ok(p) = VirtualPath::parse(&name) {
            let _ = vault.write_file(&p, &bulk);
        }

        counter += 1;
    }
}
