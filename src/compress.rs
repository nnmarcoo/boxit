use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{read_dir, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tar::Builder;

pub fn compress() -> io::Result<()> {
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
