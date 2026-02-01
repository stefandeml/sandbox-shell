use crate::types::FileSnapshot;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Persistent scan state for resumable scanning.
///
/// Tracks which files have been scanned and their metadata at scan time,
/// so unchanged files can be skipped on subsequent runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The directory this checkpoint covers.
    pub watch_path: PathBuf,
    /// Set of files already scanned with their size/mtime at scan time.
    pub scanned: HashSet<FileSnapshot>,
}

impl Checkpoint {
    pub fn new(watch_path: impl Into<PathBuf>) -> Self {
        Self {
            watch_path: watch_path.into(),
            scanned: HashSet::new(),
        }
    }

    /// Check if a file has already been scanned with the same metadata.
    pub fn is_unchanged(&self, snapshot: &FileSnapshot) -> bool {
        self.scanned.contains(snapshot)
    }

    /// Record a file as scanned.
    pub fn mark_scanned(&mut self, snapshot: FileSnapshot) {
        // Remove old entry for same path (different mtime/size)
        self.scanned.retain(|s| s.path != snapshot.path);
        self.scanned.insert(snapshot);
    }

    /// Remove a file from the checkpoint (e.g. when it is deleted).
    pub fn remove(&mut self, path: &Path) {
        self.scanned.retain(|s| s.path != path);
    }

    /// Save checkpoint to a JSON file.
    pub fn save(&self, checkpoint_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(checkpoint_dir)
            .context("failed to create checkpoint directory")?;

        let filename = self.checkpoint_filename();
        let path = checkpoint_dir.join(filename);
        let json = serde_json::to_string_pretty(self)
            .context("failed to serialize checkpoint")?;
        std::fs::write(&path, json)
            .with_context(|| format!("failed to write checkpoint to {}", path.display()))?;
        Ok(())
    }

    /// Load checkpoint from a JSON file, or return a fresh one if not found.
    pub fn load(checkpoint_dir: &Path, watch_path: &Path) -> Self {
        let candidate = Self::new(watch_path);
        let path = checkpoint_dir.join(candidate.checkpoint_filename());

        match std::fs::read_to_string(&path) {
            Ok(json) => serde_json::from_str(&json).unwrap_or_else(|_| candidate),
            Err(_) => candidate,
        }
    }

    /// Derive a stable filename from the watch path.
    fn checkpoint_filename(&self) -> String {
        // Use a simple hash of the watch path for uniqueness
        let hash = {
            let bytes = self.watch_path.to_string_lossy();
            let mut h: u64 = 5381;
            for b in bytes.bytes() {
                h = h.wrapping_mul(33).wrapping_add(b as u64);
            }
            h
        };
        format!("checkpoint_{:016x}.json", hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(path: &str, size: u64, mtime: i64) -> FileSnapshot {
        FileSnapshot {
            path: PathBuf::from(path),
            size,
            modified_epoch: mtime,
        }
    }

    #[test]
    fn test_checkpoint_mark_and_check() {
        let mut cp = Checkpoint::new("/tmp/test");

        let snap = snapshot("/tmp/test/a.md", 100, 1000);
        assert!(!cp.is_unchanged(&snap));

        cp.mark_scanned(snap.clone());
        assert!(cp.is_unchanged(&snap));
    }

    #[test]
    fn test_checkpoint_detects_changed_file() {
        let mut cp = Checkpoint::new("/tmp/test");

        let snap_v1 = snapshot("/tmp/test/a.md", 100, 1000);
        cp.mark_scanned(snap_v1);

        // Same path, different mtime
        let snap_v2 = snapshot("/tmp/test/a.md", 100, 2000);
        assert!(!cp.is_unchanged(&snap_v2));
    }

    #[test]
    fn test_checkpoint_mark_replaces_old_entry() {
        let mut cp = Checkpoint::new("/tmp/test");

        cp.mark_scanned(snapshot("/tmp/test/a.md", 100, 1000));
        cp.mark_scanned(snapshot("/tmp/test/a.md", 200, 2000));

        assert_eq!(cp.scanned.len(), 1);
        assert!(cp.is_unchanged(&snapshot("/tmp/test/a.md", 200, 2000)));
    }

    #[test]
    fn test_checkpoint_remove() {
        let mut cp = Checkpoint::new("/tmp/test");
        cp.mark_scanned(snapshot("/tmp/test/a.md", 100, 1000));
        cp.remove(Path::new("/tmp/test/a.md"));
        assert!(cp.scanned.is_empty());
    }

    #[test]
    fn test_checkpoint_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let watch_path = Path::new("/tmp/test-watch");

        let mut cp = Checkpoint::new(watch_path);
        cp.mark_scanned(snapshot("/tmp/test-watch/a.md", 100, 1000));
        cp.mark_scanned(snapshot("/tmp/test-watch/b.md", 200, 2000));
        cp.save(dir.path()).unwrap();

        let loaded = Checkpoint::load(dir.path(), watch_path);
        assert_eq!(loaded.scanned.len(), 2);
        assert!(loaded.is_unchanged(&snapshot("/tmp/test-watch/a.md", 100, 1000)));
        assert!(loaded.is_unchanged(&snapshot("/tmp/test-watch/b.md", 200, 2000)));
    }

    #[test]
    fn test_checkpoint_load_missing_returns_fresh() {
        let dir = tempfile::tempdir().unwrap();
        let cp = Checkpoint::load(dir.path(), Path::new("/nonexistent"));
        assert!(cp.scanned.is_empty());
    }

    #[test]
    fn test_checkpoint_filename_is_stable() {
        let cp = Checkpoint::new("/tmp/test");
        let f1 = cp.checkpoint_filename();
        let f2 = cp.checkpoint_filename();
        assert_eq!(f1, f2);
    }

    #[test]
    fn test_checkpoint_filename_differs_for_different_paths() {
        let cp1 = Checkpoint::new("/tmp/a");
        let cp2 = Checkpoint::new("/tmp/b");
        assert_ne!(cp1.checkpoint_filename(), cp2.checkpoint_filename());
    }
}
