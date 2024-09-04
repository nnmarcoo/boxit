use eframe::{egui::{menu, Align, Button, Context, Label, Layout, TopBottomPanel, ViewportCommand, CentralPanel, ViewportBuilder}, Frame};

#[derive(Default)]
struct Boxit {}

impl Boxit {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }
    
    fn render_title_bar(&self, ctx: &Context) {
        TopBottomPanel::top("title_bar").show(ctx, |ui| {
            ui.add_space(5.);
            menu::bar(ui, |ui| {
                ui.with_layout(Layout::left_to_right(Align::Center), |ui| {
                ui.add(Label::new("❏"));
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.add(Button::new("✖")).clicked() {
                        ui.ctx().send_viewport_cmd(ViewportCommand::Close);
                    }
                });
            });
            ui.add_space(5.);
        });
    }
}

impl eframe::App for Boxit {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
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
    eframe::run_native("Boxit", native_options, Box::new(|cc| Ok(Box::new(Boxit::new(cc)))))
}
