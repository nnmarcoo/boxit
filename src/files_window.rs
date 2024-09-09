use eframe::egui::{Context, ScrollArea, TextEdit, Window};

use crate::boxit::Boxit;

pub fn render_files_window(app: &mut Boxit, ctx: &Context) {
  Window::new("Files")
  .default_open(false)
  .vscroll(false)
  .resizable(true)
  .default_size([250., 200.])
  .default_pos([100., 40.])
  .show(ctx, |ui| {
      let mut search_query = app.search_query.clone();

      TextEdit::singleline(&mut search_query)
          .desired_width(ui.available_width())
          .hint_text(format!("Search {} files", app.files.file_count()))
          .show(ui);
      app.search_query = search_query;

      ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
          app.files.render(ui, &app.search_query);
      });
  });
}