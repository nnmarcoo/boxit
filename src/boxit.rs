use crate::compress::{compress_tar, compress};
use std::thread;
use std::time::Instant;

use crate::title_bar::render_title_bar;
use eframe::{
    egui::{CentralPanel, Context},
    App, CreationContext, Frame,
};

pub struct Boxit {
    pub busy: bool,
}

impl Default for Boxit {
    fn default() -> Self {
        Self { busy: false }
    }
}

impl Boxit {
    pub fn new(_cc: &CreationContext<'_>) -> Self {
        Self::default()
    }
}

impl App for Boxit {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        render_title_bar(self, ctx);
        CentralPanel::default().show(ctx, |ui| {
            if ui.button("Compress").clicked() {
                thread::spawn(|| {
                    let start = Instant::now(); // Start timer
                    let _ = compress_tar();
                    let duration = start.elapsed(); // Measure elapsed time
                    println!("Compression took: {:?}", duration);
                });
            }
        });
    }
}
