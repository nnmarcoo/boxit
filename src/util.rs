use std::fs::{self};
use std::io;
use std::path::Path;

use eframe::egui::IconData;
use image::load_from_memory;

pub fn load_icon() -> IconData {
    let (icon_rgba, icon_width, icon_height) = {
        let icon = include_bytes!("../assets/icon_128.png");
        let image = load_from_memory(icon)
            .expect("Failed to open icon path")
            .into_rgba8();
        let (width, height) = image.dimensions();
        let rgba = image.into_raw();
        (rgba, width, height)
    };

    IconData {
        rgba: icon_rgba,
        width: icon_width,
        height: icon_height,
    }
}

pub fn count_files<P: AsRef<Path>>(path: P) -> io::Result<usize> {
    let mut count = 0;

    fn count_files_in_dir(path: &Path, count: &mut usize) -> io::Result<()> {
        let entries = fs::read_dir(path)?;

        for entry in entries {
            let entry = entry?;
            let entry_path = entry.path();

            if entry_path.is_dir() {
                count_files_in_dir(&entry_path, count)?;
            } else {
                *count += 1;
            }
        }
        Ok(())
    }

    count_files_in_dir(path.as_ref(), &mut count)?;
    Ok(count - 1)
}
