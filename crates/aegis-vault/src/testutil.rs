//! Helpers shared by unit and integration tests. Not part of the vault's interface.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// A fresh directory under the system temp dir, mode 0700, removed on drop.
#[derive(Debug)]
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        use std::os::unix::fs::DirBuilderExt;
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        // Short, since a Unix socket path inside it must stay under 108 bytes.
        let unique = format!(
            "aegis-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("create temp dir");
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// This process's effective uid: the owner of a file it just created.
pub fn current_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    let dir = TempDir::new("uid");
    std::fs::metadata(dir.path()).expect("stat temp dir").uid()
}
