use crate::title_bar::render_title_bar;
use crate::utils::get_files;
use eframe::egui::{Label, TextEdit, TextWrapMode, Window};
use eframe::{
    egui::{CentralPanel, Context, ScrollArea},
    App, CreationContext, Frame,
};
use std::collections::HashMap;

pub struct Boxit {
    pub files: HashMap<String, String>,
    search_query: String,
    pub busy: bool,
}

impl Default for Boxit {
    fn default() -> Self {
        Self {
            files: HashMap::new(),
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
            self.files = get_files();
        }
    }
}

impl App for Boxit {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        self.get_files_if_needed();
        render_title_bar(self, ctx);

        CentralPanel::default().show(ctx, |ui| {
            Window::new("Files")
                .default_open(false)
                .max_size([ui.available_width(), 200.])
                .vscroll(false)
                .resizable(true)
                .default_size([250., 200.])
                .min_size([250., 200.])
                .default_pos([100., 40.])
                .show(ctx, |ui| {
                    let mut search_query = self.search_query.clone();

                    TextEdit::singleline(&mut search_query)
                        .desired_width(ui.available_width())
                        .hint_text("Search files")
                        .show(ui);
                    self.search_query = search_query;

                    ScrollArea::vertical().stick_to_right(true).show(ui, |ui| {
                        let filtered_files: Vec<(&String, &String)> = self
                            .files
                            .iter()
                            .filter(|(key, _value)| key.contains(&self.search_query))
                            .collect();

                        for (key, value) in filtered_files {
                            ui.add(Label::new(key).wrap_mode(TextWrapMode::Truncate))
                                .on_hover_text(value);
                        }
                    });

                    ui.allocate_space(ui.available_size());
                });
        });
    }
}
