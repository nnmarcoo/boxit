//! The unlock screen (§7.2).
//!
//! Shown before anything else. Turns a passphrase into an unlocked [`Vault`],
//! or explains why it could not.
//!
//! Unlocking runs off the UI thread (§7.3). Argon2id at the default cost takes
//! ~100ms by design, and doing that inline would freeze the window on every
//! keystroke-to-submit — the one moment a user is most likely to think the tool
//! has crashed.

use std::path::PathBuf;
use std::sync::Arc;

use iced::widget::{button, column, container, row, text, text_input};
use iced::{Alignment, Element, Length, Task};

use crate::crypto::kdf::KdfParams;
use crate::vault::Vault;

#[derive(Debug, Clone)]
pub enum Message {
    PassphraseChanged(String),
    ConfirmChanged(String),
    Submit,
    /// Unlock finished on a worker thread.
    ///
    /// `Arc` because iced messages must be `Clone` and a `Vault` is not — it
    /// owns key material that deliberately cannot be copied.
    Finished(Result<Arc<Vault>, String>),
}

/// What the unlock screen is currently doing.
enum State {
    /// Vault exists; asking for the passphrase.
    Unlocking,
    /// No vault here; asking for a new passphrase twice.
    Creating,
    /// Work in flight on a worker thread.
    Busy,
}

pub struct Unlock {
    vault_dir: PathBuf,
    state: State,
    passphrase: String,
    confirm: String,
    error: Option<String>,
}

impl Unlock {
    pub fn new(vault_dir: PathBuf) -> Self {
        let exists = vault_dir.join(crate::vault::header::HEADER_FILENAME).exists();
        Self {
            vault_dir,
            state: if exists {
                State::Unlocking
            } else {
                State::Creating
            },
            passphrase: String::new(),
            confirm: String::new(),
            error: None,
        }
    }

    /// Handle a message. Returns the unlocked vault once there is one.
    pub fn update(&mut self, message: Message) -> (Task<Message>, Option<Arc<Vault>>) {
        match message {
            Message::PassphraseChanged(v) => {
                self.passphrase = v;
                self.error = None;
            }
            Message::ConfirmChanged(v) => {
                self.confirm = v;
                self.error = None;
            }
            Message::Submit => return (self.submit(), None),
            Message::Finished(Ok(vault)) => return (Task::none(), Some(vault)),
            Message::Finished(Err(e)) => {
                self.state = if self
                    .vault_dir
                    .join(crate::vault::header::HEADER_FILENAME)
                    .exists()
                {
                    State::Unlocking
                } else {
                    State::Creating
                };
                self.error = Some(e);
                self.passphrase.clear();
                self.confirm.clear();
            }
        }
        (Task::none(), None)
    }

    fn submit(&mut self) -> Task<Message> {
        if self.passphrase.is_empty() {
            self.error = Some("Enter a passphrase.".into());
            return Task::none();
        }
        if matches!(self.state, State::Creating) && self.passphrase != self.confirm {
            self.error = Some("The two passphrases do not match.".into());
            return Task::none();
        }
        if matches!(self.state, State::Busy) {
            return Task::none();
        }

        let dir = self.vault_dir.clone();
        let passphrase = self.passphrase.clone();
        let creating = matches!(self.state, State::Creating);

        self.state = State::Busy;
        self.error = None;

        // Off the UI thread: Argon2 is intentionally slow (§7.3).
        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    if creating {
                        Vault::init(&dir, passphrase.as_bytes(), KdfParams::default())
                            .map_err(|e| e.to_string())?;
                    }
                    Vault::unlock(&dir, passphrase.as_bytes())
                        .map(Arc::new)
                        .map_err(|e| e.to_string())
                })
                .await
                .unwrap_or_else(|e| Err(format!("unlock task failed: {e}")))
            },
            Message::Finished,
        )
    }

    pub fn view(&self) -> Element<'_, Message> {
        let heading = match self.state {
            State::Creating => "Create a vault",
            _ => "Unlock vault",
        };

        let subtitle = match self.state {
            State::Creating => format!(
                "No vault found in {}. Choose a passphrase to create one.",
                self.vault_dir.display()
            ),
            _ => format!("{}", self.vault_dir.display()),
        };

        let busy = matches!(self.state, State::Busy);

        let mut fields = column![
            text_input("Passphrase", &self.passphrase)
                .secure(true)
                .on_input_maybe((!busy).then_some(Message::PassphraseChanged))
                .on_submit(Message::Submit)
                .padding(10),
        ]
        .spacing(10);

        if matches!(self.state, State::Creating) {
            fields = fields.push(
                text_input("Confirm passphrase", &self.confirm)
                    .secure(true)
                    .on_input_maybe((!busy).then_some(Message::ConfirmChanged))
                    .on_submit(Message::Submit)
                    .padding(10),
            );
        }

        let action = if busy {
            // Deriving takes long enough to need saying out loud, or it reads
            // as a hang.
            Element::from(text("Deriving key…").size(14))
        } else {
            Element::from(
                button(text(match self.state {
                    State::Creating => "Create vault",
                    _ => "Unlock",
                }))
                .on_press(Message::Submit)
                .padding([8, 20]),
            )
        };

        let mut content = column![
            text(heading).size(28),
            text(subtitle).size(13),
            fields,
            row![action].spacing(10),
        ]
        .spacing(16)
        .max_width(460);

        if let Some(err) = &self.error {
            content = content.push(text(err).size(13));
        }

        // A vault with no backup and a forgotten passphrase is unrecoverable
        // data (§9.7). Say so before it matters, not after.
        if matches!(self.state, State::Creating) {
            content = content.push(
                text("If you forget this passphrase, the files cannot be recovered.").size(12),
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
}
