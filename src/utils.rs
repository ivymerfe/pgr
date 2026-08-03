use std::error::Error;
use std::path::{self, Path, PathBuf};

pub fn try_open<P: AsRef<Path>>(path: P) -> Result<(PathBuf, std::fs::File), Box<dyn Error>> {
    let abs_path = path::absolute(&path)?;
    let file = std::fs::File::open(&abs_path).map_err(|err| {
        format!(
            "Failed to open file: '{}'\n\
             ├─ OS Error: {}",
            abs_path.display(),
            err,
        )
    })?;
    Ok((abs_path, file))
}

pub fn try_create<P: AsRef<Path>>(
    path: P,
    ext: &str,
) -> Result<(PathBuf, std::fs::File), Box<dyn Error>> {
    let mut abs_path = path::absolute(&path)?;
    if abs_path.extension().is_none() {
        abs_path.set_extension(ext);
    }
    let file = std::fs::File::create(&abs_path).map_err(|err| {
        format!(
            "Failed to create file: '{}'\n\
             ├─ OS Error: {}",
            abs_path.display(),
            err,
        )
    })?;
    Ok((abs_path, file))
}

pub async fn try_create_a<P: AsRef<Path>>(
    path: P,
    ext: &str,
) -> Result<(PathBuf, tokio::fs::File), Box<dyn Error>> {
    let mut abs_path = path::absolute(&path)?;
    if abs_path.extension().is_none() {
        abs_path.set_extension(ext);
    }
    let file = tokio::fs::File::create(&abs_path).await.map_err(|err| {
        format!(
            "Failed to open file: '{}'\n\
             ├─ OS Error: {}",
            abs_path.display(),
            err,
        )
    })?;
    Ok((abs_path, file))
}
