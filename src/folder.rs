use std::{env, io};
use std::{collections::HashMap, fs::File};
use std::path::Path;

use eframe::egui::{CollapsingHeader, Label, Ui};
use flate2::write::GzEncoder;
use flate2::Compression;
use tar::Builder;

#[derive(Debug)]
pub struct Folder {
    name: String,
    files: Vec<String>,
    subfolders: HashMap<String, Folder>,
    file_count: usize,
}

impl Folder {
    pub fn new(name: String) -> Self {
        Folder {
            name,
            files: vec![],
            subfolders: HashMap::new(),
            file_count: 0,
        }
    }

    pub fn file_count(&mut self) -> usize {
        self.file_count
    }

    pub fn build(&mut self, path: &Path) {
        if let Ok(entries) = path.read_dir() {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let folder_name = entry.file_name().to_string_lossy().into_owned();
                    let mut subfolder = Folder::new(folder_name.clone());
                    subfolder.build(&path);
                    self.subfolders.insert(subfolder.name.clone(), subfolder);
                } else if path.is_file() {
                    let file_name = entry.file_name().to_string_lossy().into_owned();
                    self.add_file(file_name);
                }
            }
        }
        self.file_count = self.files.len()
            + self
                .subfolders
                .values()
                .map(|f| f.file_count)
                .sum::<usize>();
    }

    pub fn render(&self, ui: &mut Ui, filter: &str) {
        if self.name.contains(filter)
            || self.files.iter().any(|file| file.contains(filter))
            || self
                .subfolders
                .values()
                .any(|folder| folder.contains(filter))
        {
            CollapsingHeader::new(&self.name)
                .default_open(true)
                .show(ui, |ui| {
                    for file in &self.files {
                        if file.contains(filter) {
                            ui.add(Label::new(file).truncate());
                        }
                    }

                    for (_name, subfolder) in &self.subfolders {
                        subfolder.render(ui, filter);
                    }
                });
        }
    }

    pub fn compress(&self, src: &Path, dest: &Path) -> io::Result<()> {
        let tar_gz = File::create(dest)?; // Destination .tar.gz file
        let enc = GzEncoder::new(tar_gz, Compression::default()); // GZip encoder
        let mut tar = Builder::new(enc); // Create a tar builder with the encoder

        self.add_to_tar(&mut tar, src, &Path::new(""))?;

        tar.finish()?;
        Ok(())
    }

    fn add_to_tar<W: io::Write>(&self, tar: &mut Builder<W>, src: &Path, base_path: &Path) -> io::Result<()> {
        for file in &self.files {
            let file_path = src.join(base_path).join(file);

            if file_path.ends_with(std::env::current_exe()?) {
                continue; 
            }

            let mut file_handle = File::open(&file_path)?;
            tar.append_path_with_name(&file_path, base_path.join(file))?;
        }

        for (folder_name, subfolder) in &self.subfolders {
            let folder_path = base_path.join(folder_name);
            tar.append_dir(&folder_path, src.join(&folder_path))?;
            subfolder.add_to_tar(tar, src, &folder_path)?;
        }

        Ok(())
    }

    pub fn build_tar() -> io::Result<()> {
        let current_dir = std::env::current_dir()?;
        let mut folder = Folder::new(current_dir.to_string_lossy().into_owned());
        folder.build(&current_dir);
        let output_archive = current_dir.join("archive.tar.gz");
        folder.compress(&current_dir, &output_archive)
    }

    fn contains(&self, filter: &str) -> bool {
        self.name.contains(filter)
            || self.files.iter().any(|file| file.contains(filter))
            || self
                .subfolders
                .values()
                .any(|folder| folder.contains(filter))
    }

    pub fn is_empty(&self) -> bool {
        self.file_count == 0
    }

    fn add_file(&mut self, file_name: String) {
        self.files.push(file_name);
        self.file_count += 1;
    }
}
