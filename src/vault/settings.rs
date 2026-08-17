//! Per-vault settings that are not part of the format.
//!
//! Stored in plaintext beside the header, deliberately: these are preferences,
//! not secrets, and reading them must not require the passphrase — the UI needs
//! to know the durability setting before the vault is unlocked.
//!
//! The file is optional. A missing or unparseable settings file falls back to
//! defaults rather than failing, so a corrupt preference can never stop a user
//! reaching their data.

use std::path::Path;

use super::fs::{Durability, atomic_write};

/// Name of the settings file. Excluded from encryption, like the header.
pub const SETTINGS_FILENAME: &str = ".vault-settings";

/// Preferences for one vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Settings {
    pub durability: Durability,
}

impl Settings {
    /// Read settings from `dir`, falling back to defaults.
    pub fn load(dir: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(dir.join(SETTINGS_FILENAME)) else {
            return Self::default();
        };
        Self::parse(&text)
    }

    /// Write settings to `dir`.
    ///
    /// Full durability regardless of the setting being written: a torn
    /// preferences file is not worth saving milliseconds on.
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        atomic_write(&dir.join(SETTINGS_FILENAME), self.render().as_bytes())
    }

    /// A tiny `key = value` format, to avoid a serde dependency for two fields.
    fn parse(text: &str) -> Self {
        let mut settings = Self::default();

        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };

            if key.trim() == "durability" {
                settings.durability = match value.trim() {
                    "fast" => Durability::Fast,
                    // Anything unrecognised means the safe option: a typo must
                    // never silently downgrade someone's data safety.
                    _ => Durability::Full,
                };
            }
        }
        settings
    }

    fn render(&self) -> String {
        let durability = match self.durability {
            Durability::Full => "full",
            Durability::Fast => "fast",
        };
        format!(
            "# boxit vault settings\n\
             # durability = full | fast\n\
             #   full: wait for the drive before deleting the original (safe)\n\
             #   fast: ~4.5x quicker, but a power failure during a lock can\n\
             #         destroy the files being converted\n\
             durability = {durability}\n"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn defaults_to_full_durability() {
        assert_eq!(Settings::default().durability, Durability::Full);
    }

    #[test]
    fn missing_file_gives_defaults() {
        let dir = tempdir().unwrap();
        assert_eq!(Settings::load(dir.path()), Settings::default());
    }

    #[test]
    fn round_trips_through_a_file() {
        let dir = tempdir().unwrap();
        let s = Settings {
            durability: Durability::Fast,
        };
        s.save(dir.path()).unwrap();

        assert_eq!(Settings::load(dir.path()), s);
    }

    #[test]
    fn round_trips_full() {
        let dir = tempdir().unwrap();
        let s = Settings {
            durability: Durability::Full,
        };
        s.save(dir.path()).unwrap();
        assert_eq!(Settings::load(dir.path()).durability, Durability::Full);
    }

    #[test]
    fn garbage_falls_back_to_safe() {
        // A corrupt or hand-edited file must not silently turn off durability.
        for text in ["", "nonsense", "durability = wat", "durability=", "# only a comment"] {
            assert_eq!(
                Settings::parse(text).durability,
                Durability::Full,
                "unsafe fallback for {text:?}"
            );
        }
    }

    #[test]
    fn tolerates_whitespace_and_comments() {
        let s = Settings::parse("# comment\n\n  durability   =   fast  \n");
        assert_eq!(s.durability, Durability::Fast);
    }
}
