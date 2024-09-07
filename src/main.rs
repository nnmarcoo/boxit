#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use eframe::{
    egui::{
        menu, Align, Button, CentralPanel, ColorImage, Context, ImageButton, Layout, PointerButton, RichText, Sense, TextureHandle, TopBottomPanel, ViewportBuilder, ViewportCommand
    },
    Frame,
};
use image::{self, load_from_memory};
use webbrowser::open;

#[derive(Default)]
struct Boxit {
    texture: Option<TextureHandle>,
}

impl Boxit {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }

    fn load_embedded_image(ctx: &Context) -> TextureHandle {
        let image_data = include_bytes!("../assets/logo_gray_small.png");

        let img = load_from_memory(image_data).expect("Failed to load embedded image");
        let img = img.to_rgba8();
        let size = [img.width() as usize, img.height() as usize];
        let pixels = img.into_raw();

        let color_image = ColorImage::from_rgba_unmultiplied(size, &pixels);
        ctx.load_texture("embedded_image", color_image, Default::default())
    }

    fn render_title_bar(&self, ctx: &Context) {
        TopBottomPanel::top("title_bar").show(ctx, |ui| {
            if ui
                .interact(ui.max_rect(), ui.id(), Sense::click_and_drag())
                .drag_started_by(PointerButton::Primary)
            {
                ui.ctx().send_viewport_cmd(ViewportCommand::StartDrag);
            }

            ui.add_space(4.);
            menu::bar(ui, |ui| {
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                    if let Some(texture) = &self.texture {
                        if ui
                            .add(ImageButton::new(texture).rounding(3.))
                            .on_hover_text("v0.1.0")
                            .clicked()
                        {
                            open("https://github.com/nnmarcoo/boxit").unwrap();
                        }
                    }
                });

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui
                        .add(Button::new(RichText::new("\u{1F5D9}").size(20.)).rounding(3.))
                        .on_hover_text("Close")
                        .clicked()
                    {
                        ui.ctx().send_viewport_cmd(ViewportCommand::Close);
                    }
                });
            });
            ui.add_space(2.);
        });
    }
}

impl eframe::App for Boxit {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        if self.texture.is_none() {
            self.texture = Some(Self::load_embedded_image(ctx));
        }

        self.render_title_bar(ctx);
        CentralPanel::default().show(ctx, |ui| {
            ui.heading("Hello World!");
        });
    }
}

fn main() -> eframe::Result<(), eframe::Error> {
    let native_options = eframe::NativeOptions {
        viewport: ViewportBuilder::default()
            .with_decorations(false)
            .with_inner_size([400.0, 300.0]),

        ..Default::default()
    };
    eframe::run_native(
        "Boxit",
        native_options,
        Box::new(|cc| Ok(Box::new(Boxit::new(cc)))),
    )
}
