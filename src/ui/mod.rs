//! UI layer (§7.1) — iced, tiny-skia only.
//!
//! Everything below this module is UI-independent by design: this layer may
//! depend on `vault`, but never the other way round.

pub mod app;
pub mod tab;
pub mod unlock;
