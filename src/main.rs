use eframe::egui;

#[derive(Default)]
struct Boxit {}

impl Boxit {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }
}

impl eframe::App for Boxit {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default()
            .show(ctx, |ui| {
                ui.heading("Hello World!");
            });
    }
}

fn main() -> eframe::Result<(), eframe::Error> {
    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_decorations(true) // change later
            .with_inner_size([400.0, 300.0]),

        ..Default::default()
    };
    eframe::run_native("Boxit", native_options, Box::new(|cc| Ok(Box::new(Boxit::new(cc)))))
}
