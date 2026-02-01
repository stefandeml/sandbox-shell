use crate::checkpoint::Checkpoint;
use crate::policy::engine::PolicyEngine;
use crate::types::{FileSnapshot, ScanSummary};
use anyhow::Result;
use std::fs;
use std::io::Read;
use std::path::Path;

/// Maximum bytes to read from each file for magic byte / content analysis.
const HEADER_SIZE: usize = 8192;

/// Perform a full scan of a directory, evaluating all files against the policy engine.
///
/// Files that haven't changed since the last checkpoint are skipped.
/// The checkpoint is updated with newly scanned files.
pub fn scan_directory(
    dir: &Path,
    engine: &PolicyEngine,
    checkpoint: &mut Checkpoint,
) -> Result<ScanSummary> {
    let mut summary = ScanSummary::default();

    let walker = ignore::WalkBuilder::new(dir)
        .hidden(false) // scan hidden files too
        .git_ignore(false) // don't skip gitignored files
        .build();

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("walk error: {}", e);
                continue;
            }
        };

        // Skip directories
        if entry.file_type().map_or(true, |ft| !ft.is_file()) {
            continue;
        }

        let path = entry.path();

        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("cannot stat {}: {}", path.display(), e);
                continue;
            }
        };

        let modified_epoch = metadata_mtime_epoch(&metadata);
        let snapshot = FileSnapshot {
            path: path.to_path_buf(),
            size: metadata.len(),
            modified_epoch,
        };

        // Skip unchanged files
        if checkpoint.is_unchanged(&snapshot) {
            summary.files_skipped += 1;
            continue;
        }

        // Read header bytes for content analysis
        let header = read_header(path, HEADER_SIZE);

        // Evaluate policies
        match engine.evaluate(path, &metadata, &header) {
            Ok(()) => {
                // Passed all policies
                checkpoint.mark_scanned(snapshot);
            }
            Err(violation) => {
                summary.violations.push(violation);
            }
        }

        summary.files_scanned += 1;
    }

    Ok(summary)
}

/// Read up to `max` bytes from the beginning of a file.
pub fn read_header(path: &Path, max: usize) -> Vec<u8> {
    let mut buf = vec![0u8; max];
    match fs::File::open(path) {
        Ok(mut f) => match f.read(&mut buf) {
            Ok(n) => {
                buf.truncate(n);
                buf
            }
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    }
}

/// Extract mtime as epoch seconds from metadata.
fn metadata_mtime_epoch(metadata: &fs::Metadata) -> i64 {
    use std::time::UNIX_EPOCH;
    metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::builtin::{AllowedExtensions, MaxFileSize, NoExecutables, TextOnly};
    use std::io::Write;

    fn setup_engine_markdown_only() -> PolicyEngine {
        let mut engine = PolicyEngine::new();
        engine.add(AllowedExtensions::markdown_only());
        engine
    }

    fn write_file(dir: &Path, name: &str, content: &[u8]) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
    }

    #[test]
    fn test_scan_all_allowed() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "readme.md", b"# Hello");
        write_file(dir.path(), "notes.md", b"# Notes");

        let engine = setup_engine_markdown_only();
        let mut checkpoint = Checkpoint::new(dir.path());

        let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();
        assert_eq!(summary.files_scanned, 2);
        assert_eq!(summary.violations.len(), 0);
    }

    #[test]
    fn test_scan_detects_violations() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "readme.md", b"# Hello");
        write_file(dir.path(), "script.py", b"print('hi')");
        write_file(dir.path(), "data.json", b"{}");

        let engine = setup_engine_markdown_only();
        let mut checkpoint = Checkpoint::new(dir.path());

        let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();
        assert_eq!(summary.files_scanned, 3);
        assert_eq!(summary.violations.len(), 2); // .py and .json
    }

    #[test]
    fn test_scan_skips_unchanged_files() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "readme.md", b"# Hello");

        let engine = setup_engine_markdown_only();
        let mut checkpoint = Checkpoint::new(dir.path());

        // First scan
        let summary1 = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();
        assert_eq!(summary1.files_scanned, 1);
        assert_eq!(summary1.files_skipped, 0);

        // Second scan — file unchanged, should be skipped
        let summary2 = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();
        assert_eq!(summary2.files_scanned, 0);
        assert_eq!(summary2.files_skipped, 1);
    }

    #[test]
    fn test_scan_rescans_modified_file() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "readme.md", b"# V1");

        let engine = setup_engine_markdown_only();
        let mut checkpoint = Checkpoint::new(dir.path());

        scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();

        // Modify the file (change size so snapshot differs)
        write_file(dir.path(), "readme.md", b"# V2 with more content");

        let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();
        assert_eq!(summary.files_scanned, 1);
    }

    #[test]
    fn test_scan_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let engine = setup_engine_markdown_only();
        let mut checkpoint = Checkpoint::new(dir.path());

        let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();
        assert_eq!(summary.files_scanned, 0);
        assert_eq!(summary.violations.len(), 0);
    }

    #[test]
    fn test_scan_nested_directories() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "docs/readme.md", b"# Docs");
        write_file(dir.path(), "docs/deep/nested.md", b"# Deep");
        write_file(dir.path(), "src/main.rs", b"fn main() {}");

        let engine = setup_engine_markdown_only();
        let mut checkpoint = Checkpoint::new(dir.path());

        let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();
        assert_eq!(summary.files_scanned, 3);
        assert_eq!(summary.violations.len(), 1); // main.rs
    }

    #[test]
    fn test_scan_with_multiple_policies() {
        let dir = tempfile::tempdir().unwrap();
        write_file(dir.path(), "readme.md", b"# Hello");
        write_file(dir.path(), "script.sh", b"#!/bin/bash\necho hi");

        let mut engine = PolicyEngine::new();
        engine.add(AllowedExtensions::markdown_only());
        engine.add(NoExecutables);
        engine.add(TextOnly);
        engine.add(MaxFileSize::mb(1));

        let mut checkpoint = Checkpoint::new(dir.path());
        let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();

        // script.sh fails on first policy (allowed-extensions), fail-fast
        assert_eq!(summary.violations.len(), 1);
        assert_eq!(summary.violations[0].policy_name, "markdown-only");
    }

    #[test]
    fn test_read_header_limits_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let big_content = vec![b'x'; 50_000];
        write_file(dir.path(), "big.txt", &big_content);

        let header = read_header(&dir.path().join("big.txt"), HEADER_SIZE);
        assert_eq!(header.len(), HEADER_SIZE);
    }

    #[test]
    fn test_read_header_missing_file() {
        let header = read_header(Path::new("/nonexistent/file.txt"), HEADER_SIZE);
        assert!(header.is_empty());
    }
}
