use file_guardian::checkpoint::Checkpoint;
use file_guardian::config::{build_policies_from_names, default_config_template, GuardianConfig};
use file_guardian::policy::builtin::*;
use file_guardian::policy::engine::PolicyEngine;
use file_guardian::scanner::scan_directory;
use file_guardian::types::VerdictKind;
use std::fs;
use std::io::Write;
use std::path::Path;

fn write_file(dir: &Path, name: &str, content: &[u8]) {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(content).unwrap();
}

// --- Full pipeline: scan directory with multiple policies ---

#[test]
fn test_full_scan_markdown_only_directory() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "readme.md", b"# Readme");
    write_file(dir.path(), "changelog.md", b"# Changes");
    write_file(dir.path(), "notes.markdown", b"# Notes");
    write_file(dir.path(), "script.py", b"print('hello')");
    write_file(dir.path(), "data.json", b"{}");

    let mut engine = PolicyEngine::new();
    engine.add(AllowedExtensions::markdown_only());

    let mut checkpoint = Checkpoint::new(dir.path());
    let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();

    assert_eq!(summary.files_scanned, 5);
    assert_eq!(summary.violations.len(), 2); // .py and .json

    let violation_paths: Vec<_> = summary
        .violations
        .iter()
        .map(|v| v.file_path.file_name().unwrap().to_string_lossy().to_string())
        .collect();
    assert!(violation_paths.contains(&"script.py".to_string()));
    assert!(violation_paths.contains(&"data.json".to_string()));
}

#[test]
fn test_full_scan_with_all_builtin_policies() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "good.md", b"# Good markdown file");
    write_file(dir.path(), "binary.bin", b"hello\x00world");
    write_file(dir.path(), "script.sh", b"#!/bin/bash\necho hi");
    write_file(dir.path(), "huge.md", &vec![b'x'; 2_000_000]);

    let mut engine = PolicyEngine::new();
    engine.add(AllowedExtensions::markdown_only());
    engine.add(TextOnly);
    engine.add(NoExecutables);
    engine.add(MaxFileSize::mb(1));

    let mut checkpoint = Checkpoint::new(dir.path());
    let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();

    // good.md: passes extension but over 1MB? No, it's small. Should pass all.
    // binary.bin: fails extension (not .md)
    // script.sh: fails extension (not .md)
    // huge.md: passes extension, TextOnly passes (no null bytes), NoExecutables passes, but fails MaxFileSize
    assert_eq!(summary.violations.len(), 3);
}

// --- Checkpoint round-trip through scan ---

#[test]
fn test_scan_with_checkpoint_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let checkpoint_dir = tempfile::tempdir().unwrap();

    write_file(dir.path(), "a.md", b"# A");
    write_file(dir.path(), "b.md", b"# B");

    let mut engine = PolicyEngine::new();
    engine.add(AllowedExtensions::markdown_only());

    // First scan
    let mut cp = Checkpoint::load(checkpoint_dir.path(), dir.path());
    let summary1 = scan_directory(dir.path(), &engine, &mut cp).unwrap();
    assert_eq!(summary1.files_scanned, 2);
    cp.save(checkpoint_dir.path()).unwrap();

    // Load checkpoint from disk and scan again
    let mut cp2 = Checkpoint::load(checkpoint_dir.path(), dir.path());
    let summary2 = scan_directory(dir.path(), &engine, &mut cp2).unwrap();
    assert_eq!(summary2.files_scanned, 0);
    assert_eq!(summary2.files_skipped, 2);
}

// --- Config-driven policy building ---

#[test]
fn test_build_policies_from_config() {
    let config_str = r#"
[general]
checkpoint_dir = "/tmp/test-cp"
quarantine_dir = "/tmp/test-q"

[[watch]]
path = "/tmp/docs"
policies = ["markdown-only", "text-only", "max-size-50MB"]
"#;

    let config: GuardianConfig = toml::from_str(config_str).unwrap();
    assert_eq!(config.watch.len(), 1);

    let policies = build_policies_from_names(&config.watch[0].policies);
    assert_eq!(policies.len(), 3);
}

#[test]
fn test_config_template_produces_valid_config() {
    let template = default_config_template();
    let config: GuardianConfig = toml::from_str(template).unwrap();
    assert_eq!(config.watch.len(), 1);
    assert_eq!(config.watch[0].policies.len(), 2);
}

// --- Nested directory scanning ---

#[test]
fn test_scan_deeply_nested_structure() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "root.md", b"# Root");
    write_file(dir.path(), "docs/guide.md", b"# Guide");
    write_file(dir.path(), "docs/api/reference.md", b"# API");
    write_file(dir.path(), "docs/api/openapi.yaml", b"openapi: 3.0");
    write_file(dir.path(), "src/lib.rs", b"pub fn hello() {}");

    let mut engine = PolicyEngine::new();
    engine.add(AllowedExtensions::markdown_only());

    let mut checkpoint = Checkpoint::new(dir.path());
    let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();

    assert_eq!(summary.files_scanned, 5);
    assert_eq!(summary.violations.len(), 2); // .yaml and .rs
}

// --- Policy combinator: custom extension whitelist ---

#[test]
fn test_custom_extension_whitelist() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "app.rs", b"fn main() {}");
    write_file(dir.path(), "lib.rs", b"pub mod foo;");
    write_file(dir.path(), "Cargo.toml", b"[package]");
    write_file(dir.path(), "build.py", b"print('build')");

    let policies = build_policies_from_names(&["allowed-ext:rs,toml".into()]);
    let mut engine = PolicyEngine::new();
    for p in policies {
        engine.add_boxed(p);
    }

    let mut checkpoint = Checkpoint::new(dir.path());
    let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();

    assert_eq!(summary.violations.len(), 1); // .py
    assert!(summary.violations[0]
        .file_path
        .to_string_lossy()
        .contains("build.py"));
}

// --- Quarantine verdict for executables ---

#[test]
fn test_executable_detection_quarantine_verdict() {
    let dir = tempfile::tempdir().unwrap();

    // ELF header
    let elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00";
    write_file(dir.path(), "suspicious", elf);

    let mut engine = PolicyEngine::new();
    engine.add(NoExecutables);

    let mut checkpoint = Checkpoint::new(dir.path());
    let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();

    assert_eq!(summary.violations.len(), 1);
    assert_eq!(summary.violations[0].verdict, VerdictKind::Quarantine);
}

// --- Empty and edge cases ---

#[test]
fn test_scan_empty_files() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), "empty.md", b"");
    write_file(dir.path(), "also_empty.md", b"");

    let mut engine = PolicyEngine::new();
    engine.add(AllowedExtensions::markdown_only());
    engine.add(TextOnly);

    let mut checkpoint = Checkpoint::new(dir.path());
    let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();

    assert_eq!(summary.files_scanned, 2);
    assert_eq!(summary.violations.len(), 0);
}

#[test]
fn test_scan_hidden_files() {
    let dir = tempfile::tempdir().unwrap();
    write_file(dir.path(), ".hidden.md", b"# Hidden");
    write_file(dir.path(), ".config", b"key=value");

    let mut engine = PolicyEngine::new();
    engine.add(AllowedExtensions::markdown_only());

    let mut checkpoint = Checkpoint::new(dir.path());
    let summary = scan_directory(dir.path(), &engine, &mut checkpoint).unwrap();

    assert_eq!(summary.files_scanned, 2);
    assert_eq!(summary.violations.len(), 1); // .config has no .md extension
}
