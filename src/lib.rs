//! boxit — a portable encrypted vault.
//!
//! Layered so the vault is usable without the UI (§7.1): the crypto layer sits
//! at the bottom and depends on nothing above it. Milestones 1 and 2 are
//! headless by design — no iced window until both pass their tests (§8).

pub mod crypto;
pub mod ui;
pub mod vault;
