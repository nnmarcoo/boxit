use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{read_dir, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tar::Builder;
use rayon::prelude::*;

pub fn compress_tar() -> io::Result<()> {
    let output = File::create("box.tar.gz")?;
    let encoder = GzEncoder::new(output, Compression::none());
    let mut builder = Builder::new(encoder);

    add_to_tar(&PathBuf::from("."), &mut builder).expect("Directory is accessible");

    builder.finish()?;
    Ok(())
}

fn add_to_tar<W: Write>(path: &Path, tar: &mut Builder<W>) -> io::Result<()> {
    let entries = read_dir(path)?;

    let current_exe = std::env::current_exe()?;
    let current_exe_name = current_exe.file_name().unwrap();
    let archive_name = "box.tar.gz";

    for entry in entries {
        let entry = entry?;
        let entry_path = entry.path();

        if entry_path.is_dir() {
            add_to_tar(&entry_path, tar)?;
        } else {
            let file_name = entry_path.file_name().unwrap();
            if file_name == current_exe_name || file_name == archive_name {
                continue;
            }
            tar.append_path_with_name(&entry_path, entry_path.strip_prefix("./").unwrap())?;
        }
    }
    Ok(())
}

pub fn compress() -> io::Result<()> {
    let current_exe = std::env::current_exe()?;
    let current_exe_name = current_exe.file_name().unwrap().to_owned();
    let archive_name = "box.tar.gz".to_string();

    compress_files_in_dir(PathBuf::from("."), current_exe_name, archive_name)?;

    Ok(())
}

fn compress_files_in_dir(
    path: PathBuf,
    current_exe_name: std::ffi::OsString,
    archive_name: String,
) -> io::Result<()> {
    let entries: Vec<PathBuf> = read_dir(&path)?
        .filter_map(Result::ok) // Skip any erroneous directory entries
        .map(|entry| entry.path())
        .collect();

    entries.par_iter().try_for_each(|entry_path| -> io::Result<()> {
        if entry_path.is_dir() {
            compress_files_in_dir(entry_path.clone(), current_exe_name.clone(), archive_name.clone())?;
        } else {
            let file_name = entry_path.file_name().unwrap();
            if file_name != current_exe_name && file_name.to_string_lossy() != archive_name {
                compress_file(entry_path)?;
            }
        }
        Ok(())
    })?;

    Ok(())
}

fn compress_file(path: &Path) -> io::Result<()> {
    let input_file = File::open(path)?;
    let output_file = File::create(format!("{}.gz", path.display()))?;
    let mut encoder = GzEncoder::new(output_file, Compression::default());
    io::copy(&mut &input_file, &mut encoder)?;

    encoder.finish()?;
    println!("Compressed: {}", path.display());
    Ok(())
}