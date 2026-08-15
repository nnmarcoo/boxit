//! Browsing state (§7.2), modelled on cosmic-files' `Tab` (§4).
//!
//! The `Location` enum is the piece §4 calls out as day-one-critical: browsing
//! is expressed as "where am I", not as a bare path. Right now the only variant
//! is `Path`, but having the enum in place means search, recents, or a second
//! vault slot in later without a `PathBuf` special-case in every function.

use std::sync::Arc;

use iced::widget::{Column, button, column, container, row, scrollable, text};
use iced::{Alignment, Element, Length, Task};

use crate::vault::path::VirtualPath;
use crate::vault::{Entry, SweepReport, Vault};

/// Where the tab is currently pointed.
///
/// Deliberately an enum with one variant rather than a bare `VirtualPath`:
/// see the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// A directory in the vault's decrypted namespace.
    Path(VirtualPath),
}

impl Location {
    pub fn path(&self) -> &VirtualPath {
        match self {
            Self::Path(p) => p,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Message {
    /// Navigate into a directory, or open a file.
    Activate(String),
    /// Go to a specific location, e.g. from the breadcrumb.
    Navigate(Location),
    Back,
    Up,
    /// A listing finished loading on a worker thread.
    Listed(Result<Vec<Entry>, String>),
    /// A file's contents finished loading.
    Opened(Result<Preview, String>),
    ClosePreview,
    /// Encrypt any plaintext sitting in the vault folder.
    LockNewFiles,
    /// A sweep finished on a worker thread.
    Swept(Result<SweepReport, String>),
    DismissSweepReport,
}

/// An in-app preview of a file (§6.2, v1 scope: text only).
#[derive(Debug, Clone)]
pub struct Preview {
    pub name: String,
    pub body: PreviewBody,
}

#[derive(Debug, Clone)]
pub enum PreviewBody {
    Text(String),
    /// Not something we can show in-app yet. Deliberately *not* extracted to a
    /// temp file: that is the §6.2 fork in the road and it needs the honest
    /// warning UI that comes with milestone 6.
    Unsupported { bytes: usize },
}

pub struct Tab {
    vault: Arc<Vault>,
    location: Location,
    entries: Vec<Entry>,
    history: Vec<Location>,
    preview: Option<Preview>,
    error: Option<String>,
    loading: bool,
    /// Result of the most recent sweep, shown until dismissed.
    sweep: Option<SweepReport>,
    sweeping: bool,
}

impl Tab {
    pub fn new(vault: Arc<Vault>) -> (Self, Task<Message>) {
        let mut tab = Self {
            vault,
            location: Location::Path(VirtualPath::root()),
            entries: Vec::new(),
            history: Vec::new(),
            preview: None,
            error: None,
            loading: true,
            sweep: None,
            sweeping: false,
        };
        // Sweep before the first listing: anything dropped into the folder
        // while the app was closed should already be encrypted by the time the
        // user sees the file list, not sitting there invisible.
        let task = tab.sweep();
        (tab, task)
    }

    pub fn location(&self) -> &Location {
        &self.location
    }

    /// Load the current directory's listing off the UI thread (§7.3).
    ///
    /// Listing decrypts filenames only, never contents (§6.3), so this is cheap
    /// — but it is still filesystem I/O and still does not belong inline.
    fn reload(&mut self) -> Task<Message> {
        self.loading = true;
        self.error = None;

        let vault = self.vault.clone();
        let path = self.location.path().clone();

        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    vault.list(&path).map_err(|e| e.to_string())
                })
                .await
                .unwrap_or_else(|e| Err(format!("listing task failed: {e}")))
            },
            Message::Listed,
        )
    }

    /// Encrypt plaintext sitting in the vault folder, off the UI thread (§7.3).
    ///
    /// Always sweeps from the root rather than the current directory: files get
    /// dropped into the vault folder itself, which is usually not wherever the
    /// user has browsed to.
    fn sweep(&mut self) -> Task<Message> {
        self.sweeping = true;
        self.error = None;

        let vault = self.vault.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    vault
                        .encrypt_plaintext(&VirtualPath::root())
                        .map_err(|e| e.to_string())
                })
                .await
                .unwrap_or_else(|e| Err(format!("sweep task failed: {e}")))
            },
            Message::Swept,
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::LockNewFiles => {
                if !self.sweeping {
                    return self.sweep();
                }
            }
            Message::Swept(Ok(report)) => {
                self.sweeping = false;
                // Only surface a report when something actually happened;
                // "encrypted 0 files" on every launch is noise.
                self.sweep = (!report.is_empty()).then_some(report);
                return self.reload();
            }
            Message::Swept(Err(e)) => {
                self.sweeping = false;
                self.error = Some(e);
                return self.reload();
            }
            Message::DismissSweepReport => self.sweep = None,
            Message::Listed(Ok(entries)) => {
                self.entries = entries;
                self.loading = false;
            }
            Message::Listed(Err(e)) => {
                self.entries.clear();
                self.error = Some(e);
                self.loading = false;
            }
            Message::Activate(name) => {
                let Some(entry) = self.entries.iter().find(|e| e.name == name) else {
                    return Task::none();
                };
                let Ok(target) = self.location.path().join(&name) else {
                    return Task::none();
                };

                if entry.is_dir {
                    self.history.push(self.location.clone());
                    self.location = Location::Path(target);
                    return self.reload();
                }
                return self.open_file(target, name);
            }
            Message::Navigate(loc) => {
                if loc != self.location {
                    self.history.push(self.location.clone());
                    self.location = loc;
                    return self.reload();
                }
            }
            Message::Back => {
                if let Some(prev) = self.history.pop() {
                    self.location = prev;
                    return self.reload();
                }
            }
            Message::Up => {
                if let Some(parent) = self.location.path().parent() {
                    self.history.push(self.location.clone());
                    self.location = Location::Path(parent);
                    return self.reload();
                }
            }
            Message::Opened(Ok(preview)) => self.preview = Some(preview),
            Message::Opened(Err(e)) => self.error = Some(e),
            Message::ClosePreview => self.preview = None,
        }
        Task::none()
    }

    fn open_file(&mut self, path: VirtualPath, name: String) -> Task<Message> {
        let vault = self.vault.clone();
        self.error = None;

        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let bytes = vault.read_file(&path).map_err(|e| e.to_string())?;

                    // Only text is shown in-app for now. Anything else would
                    // mean a temp file on disk, which is the §6.2 problem and
                    // needs its own honest warning before we do it.
                    let body = match String::from_utf8(bytes.clone()) {
                        Ok(s) if !s.contains('\0') => PreviewBody::Text(s),
                        _ => PreviewBody::Unsupported { bytes: bytes.len() },
                    };
                    Ok(Preview { name, body })
                })
                .await
                .unwrap_or_else(|e| Err(format!("open task failed: {e}")))
            },
            Message::Opened,
        )
    }

    pub fn view(&self) -> Element<'_, Message> {
        if let Some(preview) = &self.preview {
            return self.view_preview(preview);
        }

        let toolbar = row![
            button(text("←"))
                .on_press_maybe((!self.history.is_empty()).then_some(Message::Back))
                .padding([4, 12]),
            button(text("↑"))
                .on_press_maybe(
                    self.location
                        .path()
                        .parent()
                        .is_some()
                        .then_some(Message::Up)
                )
                .padding([4, 12]),
            self.breadcrumb(),
            iced::widget::Space::new().width(Length::Fill),
            button(text(if self.sweeping {
                "Locking…"
            } else {
                "Lock new files"
            }))
            .on_press_maybe((!self.sweeping).then_some(Message::LockNewFiles))
            .padding([4, 12]),
        ]
        .spacing(8)
        .align_y(Alignment::Center);

        let body: Element<'_, Message> = if self.loading {
            text("Loading…").size(14).into()
        } else if let Some(err) = &self.error {
            text(format!("Could not read this folder: {err}"))
                .size(14)
                .into()
        } else if self.entries.is_empty() {
            text("This folder is empty.").size(14).into()
        } else {
            let mut list = Column::new().spacing(2);
            for entry in &self.entries {
                list = list.push(self.entry_row(entry));
            }
            scrollable(list).height(Length::Fill).into()
        };

        let mut screen = column![toolbar].spacing(8);
        if let Some(report) = &self.sweep {
            screen = screen.push(self.sweep_banner(report));
        }
        screen = screen.push(container(body).height(Length::Fill).padding([12, 0]));

        screen.padding(16).into()
    }

    /// Report what the sweep did.
    ///
    /// Shown because files silently vanishing from a folder is alarming, and
    /// because failures leave plaintext behind — the user needs to know which.
    fn sweep_banner<'a>(&self, report: &'a SweepReport) -> Element<'a, Message> {
        let summary = format!(
            "Encrypted {} file{} ({}){}.",
            report.files,
            if report.files == 1 { "" } else { "s" },
            human_size(report.bytes),
            if report.directories > 0 {
                format!(" in {} folder(s)", report.directories)
            } else {
                String::new()
            }
        );

        let mut banner = column![row![
            text(summary).size(13).width(Length::Fill),
            button(text("Dismiss").size(12))
                .on_press(Message::DismissSweepReport)
                .padding([2, 8]),
        ]
        .spacing(8)
        .align_y(Alignment::Center)]
        .spacing(4);

        for (name, why) in &report.failed {
            // These files are still plaintext on disk, so say so explicitly.
            banner = banner.push(
                text(format!("Could not encrypt {name}: {why} — it is still unencrypted."))
                    .size(12),
            );
        }

        container(banner).padding([8, 12]).into()
    }

    fn entry_row<'a>(&self, entry: &'a Entry) -> Element<'a, Message> {
        let icon = if entry.is_dir { "📁" } else { "📄" };

        // The size shown is the ciphertext size on disk. Showing the plaintext
        // size would mean decrypting every file just to draw a listing (§6.3),
        // so the column is labelled "on disk" rather than quietly lying.
        let size = if entry.is_dir {
            String::new()
        } else {
            format!("{} on disk", human_size(entry.encrypted_size))
        };

        button(
            row![
                text(icon).size(15),
                text(&entry.name).size(14).width(Length::Fill),
                text(size).size(12),
            ]
            .spacing(10)
            .align_y(Alignment::Center),
        )
        .on_press(Message::Activate(entry.name.clone()))
        .width(Length::Fill)
        .padding([6, 10])
        .into()
    }

    fn breadcrumb(&self) -> Element<'_, Message> {
        let path = self.location.path();
        let mut trail = row![
            button(text("vault").size(13))
                .on_press(Message::Navigate(Location::Path(VirtualPath::root())))
                .padding([2, 6])
        ]
        .spacing(2)
        .align_y(Alignment::Center);

        let mut acc = VirtualPath::root();
        for component in path.components() {
            let Ok(next) = acc.join(component) else { break };
            acc = next;

            trail = trail.push(text("/").size(13));
            trail = trail.push(
                button(text(component).size(13))
                    .on_press(Message::Navigate(Location::Path(acc.clone())))
                    .padding([2, 6]),
            );
        }
        trail.into()
    }

    fn view_preview<'a>(&self, preview: &'a Preview) -> Element<'a, Message> {
        let body: Element<'_, Message> = match &preview.body {
            PreviewBody::Text(s) => scrollable(text(s).size(13)).height(Length::Fill).into(),
            PreviewBody::Unsupported { bytes } => column![
                text("No in-app viewer for this file type yet.").size(14),
                text(format!("{} of decrypted data.", human_size(*bytes as u64))).size(13),
                // Being explicit rather than silently writing a temp file: see
                // §6.2 on why extraction is the imperfect part of this design.
                text("Opening it externally would write it to disk unencrypted.").size(12),
            ]
            .spacing(8)
            .into(),
        };

        column![
            row![
                button(text("← Back")).on_press(Message::ClosePreview).padding([4, 12]),
                text(&preview.name).size(15),
            ]
            .spacing(10)
            .align_y(Alignment::Center),
            container(body).height(Length::Fill).padding([12, 0]),
        ]
        .spacing(8)
        .padding(16)
        .into()
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_size_formats_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1024), "1.0 KB");
        assert_eq!(human_size(1536), "1.5 KB");
        assert_eq!(human_size(1024 * 1024), "1.0 MB");
    }

    #[test]
    fn location_exposes_its_path() {
        let p = VirtualPath::parse("a/b").unwrap();
        let loc = Location::Path(p.clone());
        assert_eq!(loc.path(), &p);
    }
}
