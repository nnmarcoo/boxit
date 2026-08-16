//! Application shell (§7.2).
//!
//! Owns the screen the user is on and routes messages to it. Orchestration
//! only — the vault work lives below the UI layer (§7.1), which is what keeps
//! this file from turning into the whole program.

use std::path::PathBuf;
use std::sync::Arc;

use iced::widget::{column, container, row, text};
use iced::{Element, Length, Subscription, Task, window};

use super::unlock::{self, Unlock};
use super::vault_screen::{self, VaultScreen};
use crate::vault::path::VirtualPath;
use crate::vault::{Vault, VaultState};

#[derive(Debug, Clone)]
pub enum Message {
    Unlock(unlock::Message),
    Vault(vault_screen::Message),
    /// The window's close button was pressed.
    CloseRequested(window::Id),
    /// Auto-lock finished; safe to exit.
    LockedForExit(window::Id),
}

enum Screen {
    Unlock(Unlock),
    Vault(VaultScreen),
}

pub struct App {
    vault_dir: PathBuf,
    screen: Screen,
    vault: Option<Arc<Vault>>,
    /// Set once auto-lock has run, so the close handler does not loop.
    exiting: bool,
}

impl App {
    pub fn new(vault_dir: PathBuf) -> (Self, Task<Message>) {
        (
            Self {
                screen: Screen::Unlock(Unlock::new(vault_dir.clone())),
                vault_dir,
                vault: None,
                exiting: false,
            },
            Task::none(),
        )
    }

    pub fn title(&self) -> String {
        match &self.screen {
            Screen::Unlock(_) => "boxit".to_string(),
            Screen::Vault(screen) => match screen.state() {
                VaultState::Locked => "boxit — locked".to_string(),
                VaultState::Unlocked => "boxit — unlocked".to_string(),
                _ => "boxit".to_string(),
            },
        }
    }

    /// Close requests, plus progress from any operation in flight.
    pub fn subscription(&self) -> Subscription<Message> {
        let closes = window::close_requests().map(Message::CloseRequested);

        match &self.screen {
            Screen::Vault(screen) => {
                Subscription::batch([closes, screen.subscription().map(Message::Vault)])
            }
            Screen::Unlock(_) => closes,
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::CloseRequested(id) => self.handle_close(id),
            Message::LockedForExit(id) => window::close(id),
            Message::Unlock(msg) => {
                let Screen::Unlock(unlock) = &mut self.screen else {
                    return Task::none();
                };
                let (task, unlocked) = unlock.update(msg);

                if let Some(vault) = unlocked {
                    self.vault = Some(vault.clone());
                    let (screen, load) = VaultScreen::new(vault);
                    self.screen = Screen::Vault(screen);
                    return Task::batch([task.map(Message::Unlock), load.map(Message::Vault)]);
                }
                task.map(Message::Unlock)
            }
            Message::Vault(msg) => {
                let Screen::Vault(screen) = &mut self.screen else {
                    return Task::none();
                };
                screen.update(msg).map(Message::Vault)
            }
        }
    }

    /// Re-encrypt before exiting, so closing the window never leaves the vault
    /// sitting in plaintext.
    ///
    /// The common mistake with a lock/unlock tool is forgetting to lock, and
    /// the cost of that mistake is the entire protection the tool offers.
    fn handle_close(&mut self, id: window::Id) -> Task<Message> {
        if self.exiting {
            return window::close(id);
        }
        self.exiting = true;

        let Some(vault) = self.vault.clone() else {
            return window::close(id);
        };

        // Nothing to do if it is already locked, or if a lock is mid-flight.
        if let Screen::Vault(screen) = &self.screen
            && (screen.state() == VaultState::Locked || screen.is_busy())
        {
            return window::close(id);
        }

        Task::perform(
            async move {
                tokio::task::spawn_blocking(move || {
                    let _ = vault.encrypt_plaintext(&VirtualPath::root());
                })
                .await
                .ok();
            },
            move |()| Message::LockedForExit(id),
        )
    }

    pub fn view(&self) -> Element<'_, Message> {
        let content: Element<'_, Message> = match &self.screen {
            Screen::Unlock(unlock) => unlock.view().map(Message::Unlock),
            Screen::Vault(screen) => screen.view().map(Message::Vault),
        };

        let status = row![text(self.vault_dir.display().to_string()).size(11)].spacing(12);

        column![
            container(content).height(Length::Fill),
            container(status).padding([6, 16]),
        ]
        .into()
    }
}
