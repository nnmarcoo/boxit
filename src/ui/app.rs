//! Application shell (§7.2).
//!
//! Owns the screen the user is on and routes messages to it. Orchestration
//! only — the vault work lives below the UI layer (§7.1), which is what keeps
//! this file from turning into the whole program.

use std::path::PathBuf;
use std::sync::Arc;

use iced::widget::{column, container, row, text};
use iced::{Element, Length, Task};

use super::tab::{self, Tab};
use super::unlock::{self, Unlock};
use crate::vault::Vault;

#[derive(Debug, Clone)]
pub enum Message {
    Unlock(unlock::Message),
    Tab(tab::Message),
}

enum Screen {
    Unlock(Unlock),
    Browse(Tab),
}

pub struct App {
    vault_dir: PathBuf,
    screen: Screen,
    /// Kept so the vault outlives the tab and can be locked on exit.
    vault: Option<Arc<Vault>>,
}

impl App {
    pub fn new(vault_dir: PathBuf) -> (Self, Task<Message>) {
        (
            Self {
                screen: Screen::Unlock(Unlock::new(vault_dir.clone())),
                vault_dir,
                vault: None,
            },
            Task::none(),
        )
    }

    pub fn title(&self) -> String {
        match &self.screen {
            Screen::Unlock(_) => "boxit".to_string(),
            Screen::Browse(tab) => format!("boxit — {}", tab.location().path()),
        }
    }

    pub fn update(&mut self, message: Message) -> Task<Message> {
        match (message, &mut self.screen) {
            (Message::Unlock(msg), Screen::Unlock(unlock)) => {
                let (task, unlocked) = unlock.update(msg);

                if let Some(vault) = unlocked {
                    // Unlocked: hand the vault to a fresh tab and switch.
                    self.vault = Some(vault.clone());
                    let (tab, load) = Tab::new(vault);
                    self.screen = Screen::Browse(tab);
                    return Task::batch([task.map(Message::Unlock), load.map(Message::Tab)]);
                }
                task.map(Message::Unlock)
            }
            (Message::Tab(msg), Screen::Browse(tab)) => tab.update(msg).map(Message::Tab),
            // A message for a screen we have already left. Dropping it is
            // correct: an in-flight task that finishes after a screen change
            // has nothing left to update.
            _ => Task::none(),
        }
    }

    pub fn view(&self) -> Element<'_, Message> {
        let content: Element<'_, Message> = match &self.screen {
            Screen::Unlock(unlock) => unlock.view().map(Message::Unlock),
            Screen::Browse(tab) => tab.view().map(Message::Tab),
        };

        let status = row![
            text(self.vault_dir.display().to_string()).size(11),
            text(if self.vault.is_some() {
                "unlocked"
            } else {
                "locked"
            })
            .size(11),
        ]
        .spacing(12);

        column![
            container(content).height(Length::Fill),
            container(status).padding([6, 16]),
        ]
        .into()
    }
}
