use std::collections::HashMap;
use walkdir::WalkDir;

pub fn get_files() -> HashMap<String, String> {
    let mut files: HashMap<String, String> = HashMap::new();
    for entry in WalkDir::new(".") {
        let entry = entry.unwrap();
        if entry.file_name() == "." {
            continue;
        }

        let file_name = entry.file_name().to_string_lossy().into();
        let mut path = entry.path().to_string_lossy().into_owned();
        path.remove(0);

        files.insert(file_name, path);
    }
    files
}
