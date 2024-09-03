use eframe::*;
use egui::CentralPanel;

struct Boxit {}

impl eframe::App for Boxit {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        CentralPanel::default().show(ctx, |ui| {
            ui.label("Hello, World!");
        });
    }
}

fn main() -> eframe::Result<(), eframe::Error> {
    run_native(
        "Boxit", 
        NativeOptions::default(), 
        Box::new(|_cc| {
            Ok(Box::new(Boxit {}))
        })
    )
}
