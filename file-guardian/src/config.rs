use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Top-level configuration for file-guardian.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardianConfig {
    pub general: GeneralConfig,
    pub watch: Vec<WatchTarget>,
}

impl Default for GuardianConfig {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            watch: Vec::new(),
        }
    }
}

/// General settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Directory to store checkpoint files.
    pub checkpoint_dir: String,
    /// Directory to move quarantined files to.
    pub quarantine_dir: String,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            checkpoint_dir: "~/.local/share/file-guardian/checkpoints".into(),
            quarantine_dir: "~/.local/share/file-guardian/quarantine".into(),
        }
    }
}

/// A directory to watch and the policies to enforce on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchTarget {
    /// Path to watch (supports ~ expansion).
    pub path: String,
    /// Policy names to apply. Built-in policies:
    /// - "markdown-only": only .md/.markdown files
    /// - "no-executables": reject executables
    /// - "text-only": reject binary files
    /// - "max-size-NMB": reject files over N MB (e.g. "max-size-100MB")
    /// - "allowed-ext:ext1,ext2": custom extension whitelist
    pub policies: Vec<String>,
}

impl GuardianConfig {
    /// Load config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config: {}", path.display()))?;
        let config: Self = toml::from_str(&content)
            .with_context(|| format!("failed to parse config: {}", path.display()))?;
        Ok(config)
    }

    /// Expand ~ in configured paths.
    pub fn resolve_paths(&self) -> ResolvedConfig {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"));

        ResolvedConfig {
            checkpoint_dir: expand_tilde(&self.general.checkpoint_dir, &home),
            quarantine_dir: expand_tilde(&self.general.quarantine_dir, &home),
            watch: self
                .watch
                .iter()
                .map(|w| ResolvedWatchTarget {
                    path: expand_tilde(&w.path, &home),
                    policies: w.policies.clone(),
                })
                .collect(),
        }
    }
}

/// Config with all paths resolved to absolute paths.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub checkpoint_dir: PathBuf,
    pub quarantine_dir: PathBuf,
    pub watch: Vec<ResolvedWatchTarget>,
}

#[derive(Debug, Clone)]
pub struct ResolvedWatchTarget {
    pub path: PathBuf,
    pub policies: Vec<String>,
}

/// Build a policy engine from a list of policy name strings.
///
/// Parses policy names like "markdown-only", "no-executables", "text-only",
/// "max-size-100MB", and "allowed-ext:md,txt".
pub fn build_policies_from_names(
    names: &[String],
) -> Vec<Box<dyn crate::policy::Policy>> {
    use crate::policy::builtin::*;

    let mut policies: Vec<Box<dyn crate::policy::Policy>> = Vec::new();

    for name in names {
        match name.as_str() {
            "markdown-only" => {
                policies.push(Box::new(AllowedExtensions::markdown_only()));
            }
            "no-executables" => {
                policies.push(Box::new(NoExecutables));
            }
            "text-only" => {
                policies.push(Box::new(TextOnly));
            }
            s if s.starts_with("max-size-") => {
                if let Some(mb) = parse_max_size(s) {
                    policies.push(Box::new(MaxFileSize::mb(mb)));
                } else {
                    tracing::warn!("invalid max-size policy: {}", s);
                }
            }
            s if s.starts_with("allowed-ext:") => {
                let exts: Vec<&str> = s["allowed-ext:".len()..].split(',').collect();
                policies.push(Box::new(AllowedExtensions::new(
                    s.to_string(),
                    exts.iter().map(|e| e.trim().to_string()),
                )));
            }
            other => {
                tracing::warn!("unknown policy: {}", other);
            }
        }
    }

    policies
}

/// Parse "max-size-100MB" into 100.
fn parse_max_size(s: &str) -> Option<u64> {
    let suffix = &s["max-size-".len()..];
    let suffix_upper = suffix.to_uppercase();
    if let Some(num_str) = suffix_upper.strip_suffix("MB") {
        num_str.parse().ok()
    } else if let Some(num_str) = suffix_upper.strip_suffix("GB") {
        num_str.parse::<u64>().ok().map(|n| n * 1024)
    } else {
        suffix.parse().ok()
    }
}

fn expand_tilde(path: &str, home: &Path) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        home.join(rest)
    } else if path == "~" {
        home.to_path_buf()
    } else {
        PathBuf::from(path)
    }
}

/// Generate a default config file template.
pub fn default_config_template() -> &'static str {
    r#"# file-guardian configuration

[general]
checkpoint_dir = "~/.local/share/file-guardian/checkpoints"
quarantine_dir = "~/.local/share/file-guardian/quarantine"

# Watch directories and their policies.
# Available policies:
#   markdown-only       — only allow .md/.markdown files
#   no-executables      — reject executables (ELF, PE, shebang, etc.)
#   text-only           — reject binary files (null byte detection)
#   max-size-100MB      — reject files over 100 MB
#   allowed-ext:md,txt  — custom extension whitelist

[[watch]]
path = "~/Documents/notes"
policies = ["markdown-only", "text-only"]

# [[watch]]
# path = "~/Downloads"
# policies = ["no-executables", "max-size-100MB"]
"#
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_default_template() {
        let template = default_config_template();
        let config: GuardianConfig = toml::from_str(template).unwrap();
        assert_eq!(config.watch.len(), 1);
        assert_eq!(config.watch[0].policies, vec!["markdown-only", "text-only"]);
    }

    #[test]
    fn test_expand_tilde() {
        let home = Path::new("/home/user");
        assert_eq!(expand_tilde("~/docs", home), PathBuf::from("/home/user/docs"));
        assert_eq!(expand_tilde("~", home), PathBuf::from("/home/user"));
        assert_eq!(expand_tilde("/absolute", home), PathBuf::from("/absolute"));
    }

    #[test]
    fn test_parse_max_size() {
        assert_eq!(parse_max_size("max-size-100MB"), Some(100));
        assert_eq!(parse_max_size("max-size-2GB"), Some(2048));
        assert_eq!(parse_max_size("max-size-invalid"), None);
    }

    #[test]
    fn test_build_policies_from_names() {
        let names = vec![
            "markdown-only".into(),
            "no-executables".into(),
            "text-only".into(),
            "max-size-50MB".into(),
            "allowed-ext:rs,toml".into(),
        ];
        let policies = build_policies_from_names(&names);
        assert_eq!(policies.len(), 5);
    }

    #[test]
    fn test_build_policies_unknown_skipped() {
        let names = vec!["nonexistent-policy".into()];
        let policies = build_policies_from_names(&names);
        assert_eq!(policies.len(), 0);
    }

    #[test]
    fn test_resolve_paths() {
        let config = GuardianConfig {
            general: GeneralConfig {
                checkpoint_dir: "~/.local/share/fg".into(),
                quarantine_dir: "~/quarantine".into(),
            },
            watch: vec![WatchTarget {
                path: "~/Documents".into(),
                policies: vec!["markdown-only".into()],
            }],
        };

        let resolved = config.resolve_paths();
        // Paths should not start with ~
        assert!(!resolved.checkpoint_dir.to_string_lossy().starts_with('~'));
        assert!(!resolved.quarantine_dir.to_string_lossy().starts_with('~'));
        assert!(!resolved.watch[0].path.to_string_lossy().starts_with('~'));
    }

    #[test]
    fn test_config_load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, default_config_template()).unwrap();

        let config = GuardianConfig::load(&path).unwrap();
        assert_eq!(config.watch.len(), 1);
    }

    #[test]
    fn test_default_config() {
        let config = GuardianConfig::default();
        assert!(config.watch.is_empty());
    }
}
