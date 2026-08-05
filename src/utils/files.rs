use std::path::{self, Path, PathBuf};

use anyhow::Context;

pub fn try_open<P: AsRef<Path>>(path: P) -> anyhow::Result<(PathBuf, std::fs::File)> {
    let abs_path = path::absolute(&path)?;
    let file = std::fs::File::open(&abs_path)
        .with_context(|| format!("Failed to open file: '{}'", abs_path.display(),))?;
    Ok((abs_path, file))
}

pub fn try_create<P: AsRef<Path>>(path: P, ext: &str) -> anyhow::Result<(PathBuf, std::fs::File)> {
    let mut abs_path = path::absolute(&path)?;
    if abs_path.extension().is_none() {
        abs_path.set_extension(ext);
    }
    let file = std::fs::File::create(&abs_path)
        .with_context(|| format!("Failed to create file: '{}'", abs_path.display(),))?;
    Ok((abs_path, file))
}

pub async fn try_create_a<P: AsRef<Path>>(
    path: P,
    ext: &str,
) -> anyhow::Result<(PathBuf, tokio::fs::File)> {
    let mut abs_path = path::absolute(&path)?;
    if abs_path.extension().is_none() {
        abs_path.set_extension(ext);
    }
    let file = tokio::fs::File::create(&abs_path)
        .await
        .with_context(|| format!("Failed to open file: '{}'", abs_path.display(),))?;
    Ok((abs_path, file))
}
