use std::collections::HashSet;
use std::io::{Error, Write};
use std::sync::LazyLock;
use std::time::Duration;
use crate::cache::*;
pub struct ScanOutput {
    pub(crate) files_scanned: u64,
    pub(crate) cache_hits: u64,
    pub(crate) elapsed: Duration,
    pub(crate) threats: u64,
}

static BAD_HASHES: LazyLock<HashSet<[u8; 32]>> = LazyLock::new(|| {
    let mut set = HashSet::new();
    set.insert(*blake3::Hash::from_hex("dc39b7139cde6c966e740dbe54e2a8a6f9fad6d422cc19b9dd8b2cbe18926ab7").unwrap().as_bytes());
    set.insert(*blake3::Hash::from_hex("a782cb8be4981bd3194ad8740328433e11ef070e93479458432056cbdb0f35b8").unwrap().as_bytes());
    set
});

pub async fn scan_directory(args: &Vec<String>, path: &str, cache: &mut FileCache) -> Result<ScanOutput,Error> {
    let start = std::time::Instant::now();

    let mut output: ScanOutput = ScanOutput {
        files_scanned: 0,
        cache_hits: 0,
        elapsed: Duration::from_secs(0),
        threats: 0,
    };

    let mut stack = vec![std::path::PathBuf::from(path)];
    while let Some(current_dir) = stack.pop() {
        if let Ok(entries) = std::fs::read_dir(&current_dir) {
            for entry in entries.flatten() {
                if let Ok(ft) = entry.file_type() {
                    if ft.is_symlink() {
                        continue;
                    }
                }
                let p = entry.path();
                if p.is_file() {
                    if let Ok((hash, is_cached)) = cache.get_or_hash(&p) {
                        output.files_scanned += 1;
                        if is_cached {
                            output.cache_hits += 1;
                        }
                        if BAD_HASHES.contains(&hash) {
                            output.threats += 1;
                            let hash_hex = blake3::Hash::from(hash).to_hex();
                            println!("\n🔴 [THREAT FOUND] File: {:?} | Hash: {} 🔴", p, hash_hex);
                        }
                    }
                    if output.files_scanned % 207 == 0 {
                        print!("\rFiles scanned: {}", output.files_scanned);
                        std::io::stdout().flush().expect("error while print during scanning");
                    }
                } else if p.is_dir() {
                    let p_str = p.to_string_lossy();
                    if !p_str.starts_with("/proc") && !p_str.starts_with("/sys") && !p_str.starts_with("/dev") {
                        stack.push(p);
                    }
                }
            }
        }
    }
    println!();

    output.elapsed = start.elapsed();

    Ok(output)
}