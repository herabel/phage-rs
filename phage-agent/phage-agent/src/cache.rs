use std::io::Error;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use lru;
use lru::LruCache;
use crate::hasher;
use std::os::unix::fs::MetadataExt;

#[derive(serde::Serialize, serde::Deserialize)]
#[derive(Clone)]
struct CacheEntry {
    pub hash: [u8;32],
    pub ctime: i64,
    pub size: u64,
    pub inode: u64,
}

pub struct FileCache {
    inner: LruCache<PathBuf, CacheEntry>,
}

impl FileCache {
    pub fn get_or_hash(&mut self, path: &Path) -> Result<([u8;32], bool), Error> {
        let metadata = path.metadata()?;
        let current_ctime = metadata.ctime();
        let current_size = metadata.len();
        let current_inode = metadata.ino();

        if let Some(entry) = self.inner.get(path) {
            if entry.ctime == current_ctime && entry.size == current_size && entry.inode == current_inode {
                return Ok((entry.hash, true))
            } else {
                self.invalidate(path);
            }
        }

        let hash = hasher::hash(path)?;

        let new_cache = CacheEntry{
            hash,
            ctime: current_ctime,
            size: current_size,
            inode: current_inode,
        };
        self.inner.put(path.to_owned(), new_cache);
        Ok((hash, false))
    }

    pub fn new(size: usize) -> Self {
        Self {
            inner: LruCache::new(NonZeroUsize::new(size).unwrap_or(NonZeroUsize::MIN)),
        }
    }

    pub fn invalidate(&mut self, path: &Path) {
        self.inner.pop(path);
    }

    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let entries: Vec<(&PathBuf, &CacheEntry)> = self.inner.iter().collect();

        if let Ok(bytes) = postcard::to_stdvec(&entries) {
            std::fs::write(path, bytes)?;
        }
        Ok(())
    }

    pub fn new_or_load(path: &str, capacity: usize) -> FileCache {
        let mut cache = FileCache::new(capacity);
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(entries) = postcard::from_bytes::<Vec<(PathBuf, CacheEntry)>>(&bytes) {
                for (p, entry) in entries {
                    cache.inner.put(p, entry);
                }
            }
        }
        cache
    }
}