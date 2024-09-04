use eframe::egui;

#[derive(Default)]
struct Boxit {}

impl Boxit {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // Customize egui here with cc.egui_ctx.set_fonts and cc.egui_ctx.set_visuals.
        // Restore app state using cc.storage (requires the "persistence" feature).
        // Use the cc.gl (a glow::Context) to create graphics shaders and buffers that you can use
        // for e.g. egui::PaintCallback.
        Self::default()
    }
}

impl eframe::App for Boxit {
   fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
       egui::CentralPanel::default().show(ctx, |ui| {
           ui.heading("Hello World!");
       });
   }
}

fn main() -> eframe::Result<(), eframe::Error> {
    let native_options = eframe::NativeOptions::default();
    eframe::run_native("Boxit", native_options, Box::new(|cc| Ok(Box::new(Boxit::new(cc)))))
}
