use super::Policy;
use crate::types::Verdict;
use std::collections::HashSet;
use std::fs::Metadata;
use std::path::Path;

/// Only allow files with specific extensions.
///
/// Any file whose extension is not in the allowed set is denied.
/// Missing extensions are also denied.
#[derive(Debug)]
pub struct AllowedExtensions {
    name: String,
    extensions: HashSet<String>,
}

impl AllowedExtensions {
    pub fn new(name: impl Into<String>, extensions: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            name: name.into(),
            extensions: extensions.into_iter().map(|e| {
                let s: String = e.into();
                // Normalize: strip leading dot if present
                if let Some(stripped) = s.strip_prefix('.') {
                    stripped.to_lowercase()
                } else {
                    s.to_lowercase()
                }
            }).collect(),
        }
    }

    /// Convenience: only allow markdown files.
    pub fn markdown_only() -> Self {
        Self::new("markdown-only", ["md", "markdown"])
    }
}

impl Policy for AllowedExtensions {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, path: &Path, _metadata: &Metadata, _header: &[u8]) -> Verdict {
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) if self.extensions.contains(&ext.to_lowercase()) => Verdict::Allow,
            Some(ext) => Verdict::Deny {
                reason: format!(
                    "extension '.{}' is not in allowed set: [{}]",
                    ext,
                    self.extensions.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
            },
            None => Verdict::Deny {
                reason: "file has no extension".into(),
            },
        }
    }
}

/// Reject files that contain executable content (ELF, PE, Mach-O, scripts).
#[derive(Debug)]
pub struct NoExecutables;

impl Policy for NoExecutables {
    fn name(&self) -> &str {
        "no-executables"
    }

    fn evaluate(&self, path: &Path, _metadata: &Metadata, header: &[u8]) -> Verdict {
        // Check magic bytes via infer
        if let Some(kind) = infer::get(header) {
            let mime = kind.mime_type();
            if mime.starts_with("application/x-executable")
                || mime.starts_with("application/x-mach-binary")
                || mime.starts_with("application/x-elf")
                || mime == "application/vnd.microsoft.portable-executable"
                || mime == "application/x-dosexec"
                || mime == "application/x-sharedlib"
            {
                return Verdict::Quarantine {
                    reason: format!("executable content detected: {}", mime),
                };
            }
        }

        // Direct magic byte check for common executables
        if header.len() >= 4 {
            // ELF
            if &header[..4] == b"\x7fELF" {
                return Verdict::Quarantine {
                    reason: "ELF executable detected".into(),
                };
            }
            // Mach-O (32 and 64-bit, both endiannesses)
            let magic32 = [header[0], header[1], header[2], header[3]];
            if magic32 == [0xFE, 0xED, 0xFA, 0xCE]
                || magic32 == [0xCE, 0xFA, 0xED, 0xFE]
                || magic32 == [0xFE, 0xED, 0xFA, 0xCF]
                || magic32 == [0xCF, 0xFA, 0xED, 0xFE]
            {
                return Verdict::Quarantine {
                    reason: "Mach-O executable detected".into(),
                };
            }
        }
        // PE (MZ header)
        if header.len() >= 2 && &header[..2] == b"MZ" {
            return Verdict::Quarantine {
                reason: "PE executable detected (MZ header)".into(),
            };
        }

        // Check for shebang
        if header.len() >= 2 && &header[..2] == b"#!" {
            return Verdict::Deny {
                reason: "file starts with shebang (#!)".into(),
            };
        }

        // Check for suspicious extensions even if magic bytes don't match
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            let ext_lower = ext.to_lowercase();
            if matches!(
                ext_lower.as_str(),
                "exe" | "bat" | "cmd" | "com" | "scr" | "pif" | "sh" | "bash" | "ps1" | "dll" | "so" | "dylib"
            ) {
                return Verdict::Deny {
                    reason: format!("executable extension: .{}", ext_lower),
                };
            }
        }

        Verdict::Allow
    }
}

/// Reject files above a size threshold.
#[derive(Debug)]
pub struct MaxFileSize {
    name: String,
    max_bytes: u64,
}

impl MaxFileSize {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            name: format!("max-size-{}", humanize_bytes(max_bytes)),
            max_bytes,
        }
    }

    pub fn mb(megabytes: u64) -> Self {
        Self::new(megabytes * 1024 * 1024)
    }
}

impl Policy for MaxFileSize {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&self, _path: &Path, metadata: &Metadata, _header: &[u8]) -> Verdict {
        let size = metadata.len();
        if size > self.max_bytes {
            Verdict::Deny {
                reason: format!(
                    "file size {} exceeds maximum {}",
                    humanize_bytes(size),
                    humanize_bytes(self.max_bytes)
                ),
            }
        } else {
            Verdict::Allow
        }
    }
}

/// Reject files that appear to be binary (non-UTF-8 content).
#[derive(Debug)]
pub struct TextOnly;

impl Policy for TextOnly {
    fn name(&self) -> &str {
        "text-only"
    }

    fn evaluate(&self, _path: &Path, _metadata: &Metadata, header: &[u8]) -> Verdict {
        if header.is_empty() {
            return Verdict::Allow;
        }
        // Check if content is valid UTF-8 or at least has no null bytes
        // (null bytes are a strong indicator of binary content)
        if header.contains(&0) {
            return Verdict::Deny {
                reason: "file contains null bytes (binary content)".into(),
            };
        }
        Verdict::Allow
    }
}

fn humanize_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn metadata_for(path: &Path) -> Metadata {
        std::fs::metadata(path).unwrap()
    }

    fn write_temp_file(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    // --- AllowedExtensions ---

    #[test]
    fn test_allowed_extensions_accepts_matching() {
        let policy = AllowedExtensions::markdown_only();
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp_file(dir.path(), "readme.md", b"# Hello");
        let meta = metadata_for(&path);

        assert!(policy.evaluate(&path, &meta, b"# Hello").is_allow());
    }

    #[test]
    fn test_allowed_extensions_rejects_non_matching() {
        let policy = AllowedExtensions::markdown_only();
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp_file(dir.path(), "script.py", b"print('hi')");
        let meta = metadata_for(&path);

        assert!(policy.evaluate(&path, &meta, b"print('hi')").is_deny());
    }

    #[test]
    fn test_allowed_extensions_rejects_no_extension() {
        let policy = AllowedExtensions::markdown_only();
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp_file(dir.path(), "Makefile", b"all:");
        let meta = metadata_for(&path);

        let verdict = policy.evaluate(&path, &meta, b"all:");
        assert!(verdict.is_deny());
    }

    #[test]
    fn test_allowed_extensions_case_insensitive() {
        let policy = AllowedExtensions::markdown_only();
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp_file(dir.path(), "notes.MD", b"# Notes");
        let meta = metadata_for(&path);

        assert!(policy.evaluate(&path, &meta, b"# Notes").is_allow());
    }

    #[test]
    fn test_allowed_extensions_normalizes_dots() {
        let policy = AllowedExtensions::new("test", [".md", "txt"]);
        let dir = tempfile::tempdir().unwrap();

        let md = write_temp_file(dir.path(), "a.md", b"");
        let txt = write_temp_file(dir.path(), "b.txt", b"");

        assert!(policy.evaluate(&md, &metadata_for(&md), b"").is_allow());
        assert!(policy.evaluate(&txt, &metadata_for(&txt), b"").is_allow());
    }

    // --- NoExecutables ---

    #[test]
    fn test_no_executables_allows_text() {
        let policy = NoExecutables;
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp_file(dir.path(), "readme.md", b"# Hello");
        let meta = metadata_for(&path);

        assert!(policy.evaluate(&path, &meta, b"# Hello").is_allow());
    }

    #[test]
    fn test_no_executables_denies_shebang() {
        let policy = NoExecutables;
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp_file(dir.path(), "script.sh", b"#!/bin/bash\necho hi");
        let meta = metadata_for(&path);

        let verdict = policy.evaluate(&path, &meta, b"#!/bin/bash\necho hi");
        assert!(verdict.is_deny());
    }

    #[test]
    fn test_no_executables_denies_exe_extension() {
        let policy = NoExecutables;
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp_file(dir.path(), "malware.exe", b"not actually PE");
        let meta = metadata_for(&path);

        let verdict = policy.evaluate(&path, &meta, b"not actually PE");
        assert!(verdict.is_deny());
    }

    #[test]
    fn test_no_executables_quarantines_elf() {
        let policy = NoExecutables;
        let dir = tempfile::tempdir().unwrap();
        // ELF magic bytes
        let elf_header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00>\x00";
        let path = write_temp_file(dir.path(), "binary", elf_header);
        let meta = metadata_for(&path);

        let verdict = policy.evaluate(&path, &meta, elf_header);
        assert!(matches!(verdict, Verdict::Quarantine { .. }));
    }

    // --- MaxFileSize ---

    #[test]
    fn test_max_file_size_allows_under_limit() {
        let policy = MaxFileSize::new(1024);
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp_file(dir.path(), "small.txt", b"hello");
        let meta = metadata_for(&path);

        assert!(policy.evaluate(&path, &meta, b"hello").is_allow());
    }

    #[test]
    fn test_max_file_size_denies_over_limit() {
        let policy = MaxFileSize::new(10);
        let dir = tempfile::tempdir().unwrap();
        let content = vec![b'x'; 100];
        let path = write_temp_file(dir.path(), "big.txt", &content);
        let meta = metadata_for(&path);

        let verdict = policy.evaluate(&path, &meta, &content);
        assert!(verdict.is_deny());
    }

    #[test]
    fn test_max_file_size_name() {
        let policy = MaxFileSize::mb(100);
        assert_eq!(policy.name(), "max-size-100.0MB");
    }

    // --- TextOnly ---

    #[test]
    fn test_text_only_allows_utf8() {
        let policy = TextOnly;
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp_file(dir.path(), "text.txt", b"hello world");
        let meta = metadata_for(&path);

        assert!(policy.evaluate(&path, &meta, b"hello world").is_allow());
    }

    #[test]
    fn test_text_only_denies_binary() {
        let policy = TextOnly;
        let dir = tempfile::tempdir().unwrap();
        let content = b"hello\x00world";
        let path = write_temp_file(dir.path(), "binary.bin", content);
        let meta = metadata_for(&path);

        let verdict = policy.evaluate(&path, &meta, content);
        assert!(verdict.is_deny());
    }

    #[test]
    fn test_text_only_allows_empty() {
        let policy = TextOnly;
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp_file(dir.path(), "empty.txt", b"");
        let meta = metadata_for(&path);

        assert!(policy.evaluate(&path, &meta, b"").is_allow());
    }
}
