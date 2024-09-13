use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use eframe::egui::IconData;
use flate2::write::GzEncoder;
use flate2::Compression;
use image::load_from_memory;
use tar::Builder;

pub fn compress() -> io::Result<()> {
    let current_dir = std::env::current_dir()?;
    let output_archive = current_dir.join("files.box");

    compress_dir(&current_dir, &output_archive)
}

fn compress_dir(src: &Path, dest: &Path) -> io::Result<()> {
    let tar_gz = File::create(dest)?;
    let enc = GzEncoder::new(tar_gz, Compression::best());
    let mut tar = Builder::new(enc);

    add_directory_to_tar(&mut tar, src, &PathBuf::new(), &src)?;

    tar.finish()?;
    Ok(())
}

fn add_directory_to_tar<W: io::Write>(tar: &mut Builder<W>, base_dir: &Path, base_path: &Path, current_dir: &Path) -> io::Result<()> {
    for entry in fs::read_dir(current_dir)? {
        let entry = entry?;
        let path = entry.path();
        let relative_path = base_path.join(entry.file_name());

        if path.is_file() {
            if path.ends_with(std::env::current_exe()?) {
                continue;
            }
            tar.append_path_with_name(&path, &relative_path)?;
        } else if path.is_dir() {
            tar.append_dir(&relative_path, &path)?;
            add_directory_to_tar(tar, base_dir, &relative_path, &path)?;
        }
    }
    Ok(())
}

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