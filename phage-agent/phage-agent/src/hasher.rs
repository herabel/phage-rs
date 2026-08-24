use blake3;
use std::fs::File;
use std::path::{Path};

pub fn hash(path: &Path) -> Result<[u8;32], std::io::Error> {
    let file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(&file)?;

    Ok(*hasher.finalize().as_bytes())
}