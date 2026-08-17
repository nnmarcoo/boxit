//! The main screen: one button that toggles the vault between locked and
//! unlocked.
//!
//! This replaces the file-explorer design. The explorer had to render every
//! file type itself, which meant either writing viewers for images, video, PDFs
//! and everything else, or extracting to a temp file anyway. Decrypting the
//! folder in place sidesteps all of it: while unlocked, the files are real
//! files, and the operating system is already an excellent file explorer.
//!
//! The trade is explicit and is stated in the UI rather than buried: while
//! unlocked there is no protection at all. Protection exists in the locked
//! state only.

use std::sync::Arc;
use std::sync::mpsc;

use iced::widget::{button, column, container, progress_bar, row, text};
use iced::{Alignment, Element, Length, Subscription, Task};

use crate::vault::path::VirtualPath;
use crate::vault::fs::Durability;
use crate::vault::{Progress, SweepReport, Vault, VaultState};

#[derive(Debug, Clone)]
pub enum Message {
    Lock,
    Unlock,
    /// A lock or unlock finished on a worker thread.
    Finished(Result<(SweepReport, VaultState), String>),
    /// The current state was re-read from disk.
    StateLoaded(Result<VaultState, String>),
    /// A progress update from the operation in flight.
    Progress(Progress),
    OpenFolder,
    DismissReport,
    /// Toggle whether writes wait for the drive.
    ToggleFastMode(bool),
}

/// Carries the progress receiver into the subscription.
///
/// `run_with` requires `Hash` on its data so it can tell subscriptions apart;
/// identity here is the channel's address, which is exactly the right notion —
/// a new operation allocates a new channel and therefore a new subscription.
#[derive(Clone)]
struct ProgressChannel(Arc<std::sync::Mutex<mpsc::Receiver<Progress>>>);

impl std::hash::Hash for ProgressChannel {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (Arc::as_ptr(&self.0) as usize).hash(state);
    }
}

pub struct VaultScreen {
    vault: Arc<Vault>,
    state: VaultState,
    busy: bool,
    report: Option<SweepReport>,
    error: Option<String>,
    /// Latest progress update, if an operation is running.
    progress: Option<Progress>,
    /// Mirrors the vault's setting so the checkbox can render before any
    /// operation has run.
    fast_mode: bool,
    /// Receiver for the running operation's progress updates.
    ///
    /// Held in an `Arc<Mutex<..>>` because the subscription that drains it is
    /// recreated on every view, and must reattach to the same channel.
    progress_rx: Option<Arc<std::sync::Mutex<mpsc::Receiver<Progress>>>>,
}

impl VaultScreen {
    pub fn new(vault: Arc<Vault>) -> (Self, Task<Message>) {
        let screen = Self {
            vault: vault.clone(),
            state: VaultState::Empty,
            busy: true,
            report: None,
            error: None,
            progress: None,
            progress_rx: None,
            fast_mode: vault.durability() == Durability::Fast,
        };
        (screen, Self::load_state(vault))
    }

    pub fn state(&self) -> VaultState {
        self.state
    }

    pub fn is_busy(&self) -> bool {
        self.busy
    }

    fn load_state(vault: Arc<Vault>) -> Task<Message> {
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || vault.state().map_err(|e| e.to_string()))
                    .await
                    .unwrap_or_else(|e| Err(format!("state task failed: {e}")))
            },
            Message::StateLoaded,
        )
    }

    /// Run a lock or unlock off the UI thread (§7.3).
    ///
    /// Both directions walk the whole tree and do real crypto, so neither can
    /// run inline without freezing the window for the duration.
    fn run(&mut self, lock: bool) -> Task<Message> {
        self.busy = true;
        self.error = None;
        self.report = None;
        self.progress = None;

        // The worker sends progress through this channel; the subscription
        // below drains it and turns each update into a message.
        let (tx, rx) = mpsc::channel();
        self.progress_rx = Some(Arc::new(std::sync::Mutex::new(rx)));

        let vault = self.vault.clone();
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let root = VirtualPath::root();
                    let send = |p: Progress| {
                        // A closed receiver just means the UI moved on; the
                        // operation itself must still finish.
                        let _ = tx.send(p);
                    };

                    let report = if lock {
                        vault.encrypt_plaintext_with_progress(&root, send)
                    } else {
                        vault.decrypt_all_with_progress(&root, send)
                    }
                    .map_err(|e| e.to_string())?;

                    let state = vault.state().map_err(|e| e.to_string())?;
                    Ok((report, state))
                })
                .await
                .unwrap_or_else(|e| Err(format!("task failed: {e}")))
            },
            Message::Finished,
        )
    }

    /// Stream progress updates from the running operation into the UI.
    ///
    /// Polls rather than blocking: the vault worker is on a blocking thread and
    /// the channel is synchronous, so this bridges it to the async runtime
    /// without holding the UI.
    pub fn subscription(&self) -> Subscription<Message> {
        let Some(rx) = self.progress_rx.clone() else {
            return Subscription::none();
        };
        if !self.busy {
            return Subscription::none();
        }

        // `run_with` takes a fn pointer, so the receiver travels in the data
        // argument rather than being captured. The pointer address doubles as
        // the subscription identity, so a new operation gets a new stream.
        let id = Arc::as_ptr(&rx) as usize;
        Subscription::run_with(
            (id, ProgressChannel(rx)),
            |(_, channel): &(usize, ProgressChannel)| {
                let rx = channel.0.clone();
                iced::stream::channel(64, move |mut output| async move {
                    loop {
                        let update = {
                            let Ok(guard) = rx.lock() else { break };
                            guard.try_recv()
                        };

                        match update {
                            Ok(p) => {
                                if iced::futures::SinkExt::send(&mut output, Message::Progress(p))
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(mpsc::TryRecvError::Empty) => {
                                // Nothing yet; yield so the UI stays responsive.
                                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            }
                            Err(mpsc::TryRecvError::Disconnected) => break,
                        }
                    }
                })
            },
        )
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::Lock => {
                if !self.busy {
                    return self.run(true);
                }
            }
            Message::Unlock => {
                if !self.busy {
                    return self.run(false);
                }
            }
            Message::Progress(p) => self.progress = Some(p),
            Message::Finished(Ok((report, state))) => {
                self.busy = false;
                self.state = state;
                self.progress = None;
                self.progress_rx = None;
                self.report = (!report.is_empty()).then_some(report);
            }
            Message::Finished(Err(e)) => {
                self.busy = false;
                self.progress = None;
                self.progress_rx = None;
                self.error = Some(e);
                return Self::load_state(self.vault.clone());
            }
            Message::StateLoaded(Ok(state)) => {
                self.busy = false;
                self.state = state;
            }
            Message::StateLoaded(Err(e)) => {
                self.busy = false;
                self.error = Some(e);
            }
            Message::DismissReport => self.report = None,
            Message::ToggleFastMode(on) => {
                self.fast_mode = on;
                // Persisted to the vault folder, so the choice survives a
                // restart. A failure to save is not worth interrupting for.
                if let Some(vault) = Arc::get_mut(&mut self.vault) {
                    let _ = vault.set_durability(if on {
                        Durability::Fast
                    } else {
                        Durability::Full
                    });
                }
            }
            Message::OpenFolder => {
                // Best effort: opening the folder is a convenience, and a
                // failure here should not interrupt anything.
                let _ = open_in_file_manager(self.vault.root());
            }
        }
        Task::none()
    }

    pub fn view(&self) -> Element<'_, Message> {
        let (headline, detail) = match (self.busy, self.state) {
            (true, _) => ("Working…", "Encrypting or decrypting your files."),
            (false, VaultState::Locked) => (
                "Locked",
                "Your files are encrypted. Unlock to open them with any program.",
            ),
            (false, VaultState::Unlocked) => (
                "Unlocked",
                "Your files are readable by any program on this computer. \
                 Lock when you are finished.",
            ),
            (false, VaultState::Empty) => (
                "Empty",
                "Put files in the vault folder, then lock it.",
            ),
            (false, VaultState::Mixed) => (
                "Partly locked",
                "A previous lock or unlock did not finish. Run it again to complete it.",
            ),
        };

        let action: Element<'_, Message> = if self.busy {
            match &self.progress {
                Some(p) => Element::from(
                    column![
                        container(progress_bar(0.0..=1.0, p.fraction())).width(360),
                        text(format!(
                            "{} of {} files — {}",
                            p.files_done,
                            p.files_total,
                            human_size(p.bytes_done)
                        ))
                        .size(12),
                        // Truncated: a long filename would otherwise stretch the
                        // window mid-operation.
                        text(truncate(&p.current, 48)).size(12),
                    ]
                    .spacing(6)
                    .align_x(Alignment::Center),
                ),
                // Between starting and the first file finishing — usually the
                // pre-walk, which has no per-file granularity to report.
                None => Element::from(text("Scanning…").size(14)),
            }
        } else {
            let (label, msg) = match self.state {
                // Mixed resolves by locking: it is the safe direction, and
                // re-running it finishes whatever was interrupted.
                VaultState::Unlocked | VaultState::Mixed | VaultState::Empty => {
                    ("Lock", Message::Lock)
                }
                VaultState::Locked => ("Unlock", Message::Unlock),
            };

            Element::from(
                button(text(label).size(20))
                    .on_press(msg)
                    .padding([18, 64]),
            )
        };

        let mut content = column![
            text(headline).size(34),
            text(detail).size(14),
            container(action).padding([18, 0]),
        ]
        .spacing(10)
        .max_width(520)
        .align_x(Alignment::Center);

        if !self.busy {
            content = content.push(
                button(text("Open vault folder").size(13))
                    .on_press(Message::OpenFolder)
                    .padding([6, 14]),
            );

            content = content.push(
                row![
                    iced::widget::checkbox(self.fast_mode)
                        .on_toggle(Message::ToggleFastMode)
                        .size(15),
                    text("Fast mode").size(13),
                ]
                .spacing(8)
                .align_y(Alignment::Center),
            );

            // The consequence, next to the control rather than in a manual.
            // Only shown when the option is on, so the warning appears exactly
            // when it is true.
            content = content.push(
                text(if self.fast_mode {
                    "About 4x quicker. If the computer loses power during a lock or unlock, \
                     the files being converted at that moment can be lost."
                } else {
                    "Waits for the drive before removing each original, so a power cut \
                     cannot lose a file."
                })
                .size(11),
            );
        }

        if let Some(report) = &self.report {
            content = content.push(self.report_line(report));
        }

        if let Some(err) = &self.error {
            content = content.push(text(format!("Something went wrong: {err}")).size(13));
        }

        // The honest warning (§6.2). Shown while unlocked, when it is true,
        // rather than as a one-time notice the user has already dismissed.
        if !self.busy && self.state == VaultState::Unlocked {
            content = content.push(
                text(
                    "While unlocked, anything on this computer can read these files, \
                     including backup and sync software.",
                )
                .size(12),
            );
        }

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .align_x(Alignment::Center)
            .align_y(Alignment::Center)
            .padding(24)
            .into()
    }

    fn report_line<'a>(&self, report: &'a SweepReport) -> Element<'a, Message> {
        let summary = format!(
            "{} file{} ({})",
            report.files,
            if report.files == 1 { "" } else { "s" },
            human_size(report.bytes)
        );

        let mut block = column![row![
            text(summary).size(13),
            button(text("Dismiss").size(12))
                .on_press(Message::DismissReport)
                .padding([2, 8]),
        ]
        .spacing(10)
        .align_y(Alignment::Center)]
        .spacing(4)
        .align_x(Alignment::Center);

        for (name, why) in &report.failed {
            // A failure here means a file is still in its previous state, which
            // the user needs to know about specifically.
            block = block.push(text(format!("{name}: {why}")).size(12));
        }

        block.into()
    }
}

/// Shorten a filename for display, keeping the end where the extension is.
fn truncate(s: &str, max: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_string();
    }
    let tail: String = chars[chars.len() - (max - 1)..].iter().collect();
    format!("…{tail}")
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

/// Open the vault folder in the system file manager.
fn open_in_file_manager(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        std::process::Command::new("explorer").arg(path).spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(path).spawn()?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open").arg(path).spawn()?;
    }
    Ok(())
}
