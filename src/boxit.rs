use std::{env, thread};
use std::path::Path;

use crate::files_window::render_files_window;
use crate::folder::Folder;
use crate::title_bar::render_title_bar;
use eframe::{
    egui::{CentralPanel, Context},
    App, CreationContext, Frame,
};

pub struct Boxit {
    pub files: Folder,
    pub search_query: String,
    pub busy: bool,
}

impl Default for Boxit {
    fn default() -> Self {
        Self {
            files: Folder::new( // lmao
                env::current_dir()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string(),
            ),
            search_query: String::new(),
            busy: false,
        }
    }
}

impl Boxit {
    pub fn new(_cc: &CreationContext<'_>) -> Self {
        Self::default()
    }

    fn get_files_if_needed(&mut self) {
        if self.files.is_empty() {
            self.files.build(Path::new("."));
        }
    }
}

impl App for Boxit {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        self.get_files_if_needed();

        render_title_bar(self, ctx);
        CentralPanel::default().show(ctx, |ui| {
            render_files_window(self, ctx);
            if ui.button("compress test").clicked() {
                let _ = self.files.compress(Path::new("."), Path::new("test.tar.gz"));
            }
        });
    }
}
