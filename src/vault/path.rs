//! Virtual paths (§4).
//!
//! A `VirtualPath` is a location in the *decrypted* namespace: what the user
//! sees. It is not a `PathBuf` and deliberately cannot be used as one — the
//! whole point is that the on-disk path is a different, encrypted thing, and
//! confusing the two is how plaintext names end up written to disk.
//!
//! Translating virtual → real requires the key, because each component is
//! encrypted under its parent's ID. That translation lives in `vault::mod`.

use std::fmt;

/// A path within the vault's decrypted namespace, as a list of components.
///
/// Always relative to the vault root; there is no way to express a location
/// outside the vault, which is the property that keeps `..` traversal from
/// being representable at all.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct VirtualPath {
    components: Vec<String>,
}

impl VirtualPath {
    /// The vault root.
    pub fn root() -> Self {
        Self::default()
    }

    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// Parse a `/`-separated path.
    ///
    /// Rejects `.` and `..` rather than resolving them: a vault path is not a
    /// filesystem path, and silently normalising traversal is how a bug becomes
    /// an escape. Empty components (`a//b`, leading and trailing slashes) are
    /// skipped as insignificant.
    pub fn parse(s: &str) -> Result<Self, PathError> {
        let mut components = Vec::new();
        for part in s.split('/') {
            match part {
                "" => continue,
                "." | ".." => return Err(PathError::Traversal),
                _ if part.contains('\\') => return Err(PathError::Traversal),
                // A component like `C:` means a host path leaked in where a
                // vault path was expected. Git Bash does exactly this, rewriting
                // a leading `/` into a Windows path. Silently accepting it would
                // create a junk entry named after somebody's drive letter.
                _ if is_drive_letter(part) => return Err(PathError::HostPath),
                _ => components.push(part.to_string()),
            }
        }
        Ok(Self { components })
    }

    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// The final component, or `None` at the root.
    pub fn name(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    /// The containing directory, or `None` at the root.
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        Some(Self {
            components: self.components[..self.components.len() - 1].to_vec(),
        })
    }

    /// Append a component.
    pub fn join(&self, name: &str) -> Result<Self, PathError> {
        if name.is_empty() || name == "." || name == ".." {
            return Err(PathError::Traversal);
        }
        if name.contains('/') || name.contains('\\') {
            return Err(PathError::Traversal);
        }

        let mut components = self.components.clone();
        components.push(name.to_string());
        Ok(Self { components })
    }

    pub fn depth(&self) -> usize {
        self.components.len()
    }

    /// Whether `self` is `other` or lies beneath it.
    ///
    /// Used to stop an operation from moving a directory into itself.
    pub fn starts_with(&self, other: &Self) -> bool {
        other.components.len() <= self.components.len()
            && self.components[..other.components.len()] == other.components[..]
    }
}

impl fmt::Display for VirtualPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "/{}", self.components.join("/"))
    }
}

/// Whether a component looks like a Windows drive specifier (`C:`, `d:`).
fn is_drive_letter(part: &str) -> bool {
    let b = part.as_bytes();
    b.len() == 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

#[derive(Debug, PartialEq, Eq)]
pub enum PathError {
    /// A component was empty, `.`, `..`, or contained a separator.
    Traversal,
    /// A host filesystem path was passed where a vault path was expected.
    HostPath,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Traversal => write!(f, "invalid path component"),
            Self::HostPath => write!(
                f,
                "this looks like a path on your computer, not a path inside the vault \
                 (if you are using Git Bash, set MSYS_NO_PATHCONV=1)"
            ),
        }
    }
}

impl std::error::Error for PathError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_has_no_name_or_parent() {
        let r = VirtualPath::root();
        assert!(r.is_root());
        assert_eq!(r.name(), None);
        assert_eq!(r.parent(), None);
        assert_eq!(r.to_string(), "/");
    }

    #[test]
    fn parses_and_displays() {
        let p = VirtualPath::parse("docs/notes/today.txt").unwrap();
        assert_eq!(p.components(), ["docs", "notes", "today.txt"]);
        assert_eq!(p.name(), Some("today.txt"));
        assert_eq!(p.to_string(), "/docs/notes/today.txt");
        assert_eq!(p.depth(), 3);
    }

    #[test]
    fn ignores_redundant_separators() {
        assert_eq!(
            VirtualPath::parse("/docs//notes/").unwrap(),
            VirtualPath::parse("docs/notes").unwrap()
        );
    }

    #[test]
    fn rejects_traversal() {
        for bad in ["..", "a/../b", "./a", "a/./b", "a\\b"] {
            assert_eq!(
                VirtualPath::parse(bad),
                Err(PathError::Traversal),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn join_rejects_traversal() {
        let p = VirtualPath::root();
        for bad in ["", ".", "..", "a/b", "a\\b"] {
            assert!(p.join(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn parent_walks_up() {
        let p = VirtualPath::parse("a/b/c").unwrap();
        let up = p.parent().unwrap();
        assert_eq!(up, VirtualPath::parse("a/b").unwrap());
        assert_eq!(up.parent().unwrap(), VirtualPath::parse("a").unwrap());
        assert!(up.parent().unwrap().parent().unwrap().is_root());
    }

    #[test]
    fn starts_with_detects_containment() {
        let root = VirtualPath::root();
        let a = VirtualPath::parse("a").unwrap();
        let ab = VirtualPath::parse("a/b").unwrap();
        let c = VirtualPath::parse("c").unwrap();

        assert!(ab.starts_with(&a));
        assert!(ab.starts_with(&root));
        assert!(a.starts_with(&a));
        assert!(!a.starts_with(&ab));
        assert!(!c.starts_with(&a));
    }

    #[test]
    fn rejects_host_paths() {
        // Git Bash rewrites a leading `/` into a Windows path; catching it here
        // turns a silently-wrong filename into a clear error.
        for bad in ["C:/Program Files/Git/f.txt", "d:/data", "C:"] {
            assert_eq!(
                VirtualPath::parse(bad),
                Err(PathError::HostPath),
                "accepted host path {bad:?}"
            );
        }
    }

    #[test]
    fn colon_names_that_are_not_drive_letters_are_fine() {
        // Only a bare two-character `X:` is a drive specifier.
        let p = VirtualPath::parse("notes:2026/ab:c").unwrap();
        assert_eq!(p.components(), ["notes:2026", "ab:c"]);
    }

    #[test]
    fn unicode_names_survive() {
        let p = VirtualPath::parse("документы/файл.txt").unwrap();
        assert_eq!(p.name(), Some("файл.txt"));
    }
}
