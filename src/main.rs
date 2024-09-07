#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod boxit;
mod logo;
mod title_bar;
mod utils;

use boxit::Boxit;
use eframe::{egui::ViewportBuilder, run_native, Error, NativeOptions, Result};

fn main() -> Result<(), Error> {
    let native_options = NativeOptions {
        viewport: ViewportBuilder::default()
            .with_decorations(false)
            .with_inner_size([800.0, 600.0])
            .with_title("Boxit")
            .with_always_on_top(),
        ..Default::default()
    };
    run_native(
        "Boxit",
        native_options,
        Box::new(|cc| Ok(Box::new(Boxit::new(cc)))),
    )
}
