use std::path::PathBuf;

use anyhow::Context;

pub fn try_open(path: &PathBuf) -> anyhow::Result<std::fs::File> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open file: '{}'", path.display(),))?;
    Ok(file)
}

pub fn try_create(path: &PathBuf, ext: &str) -> anyhow::Result<std::fs::File> {
    let path = if path.extension().is_none() {
        &path.with_extension(ext)
    } else {
        path
    };
    let file = std::fs::File::create(&path)
        .with_context(|| format!("Failed to create file: '{}'", path.display(),))?;
    Ok(file)
}

pub async fn try_create_a(path: &PathBuf, ext: &str) -> anyhow::Result<tokio::fs::File> {
    let path = if path.extension().is_none() {
        &path.with_extension(ext)
    } else {
        path
    };
    let file = tokio::fs::File::create(&path)
        .await
        .with_context(|| format!("Failed to open file: '{}'", path.display(),))?;
    Ok(file)
}
