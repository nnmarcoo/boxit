#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod boxit;
mod files_window;
mod folder;
mod logo;
mod title_bar;
mod util;

use boxit::Boxit;
use eframe::{egui::ViewportBuilder, run_native, Error, NativeOptions, Result};
use util::load_icon;

fn main() -> Result<(), Error> {

    let native_options = NativeOptions {
        viewport: ViewportBuilder::default()
            .with_decorations(false)
            .with_inner_size([400.0, 300.0])
            .with_title("")
            .with_always_on_top()
            .with_icon(load_icon()),
        ..Default::default()
    };
    run_native(
        "Boxit",
        native_options,
        Box::new(|cc| Ok(Box::new(Boxit::new(cc)))),
    )
}
