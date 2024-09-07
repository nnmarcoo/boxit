use crate::title_bar::render_title_bar;
use crate::utils::load_embedded_image;
use eframe::{
    egui::{CentralPanel, Context, TextureHandle},
    App, CreationContext, Frame,
};

pub struct Boxit {
    pub texture: Option<TextureHandle>,
}

impl Default for Boxit {
    fn default() -> Self {
        Self { texture: None }
    }
}

impl Boxit {
    pub fn new(_cc: &CreationContext<'_>) -> Self {
        Self::default()
    }

    fn load_texture_if_needed(&mut self, ctx: &Context) {
        if self.texture.is_none() {
            self.texture = Some(load_embedded_image(ctx));
        }
    }
}

impl App for Boxit {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        self.load_texture_if_needed(ctx);
        render_title_bar(self, ctx);

        CentralPanel::default().show(ctx, |ui| {
            ui.heading("Hello World!");
        });
    }
}
