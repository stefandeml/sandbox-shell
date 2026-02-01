use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Describes how a file changed on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileEvent {
    Created(PathBuf),
    Modified(PathBuf),
    Deleted(PathBuf),
    Renamed { from: PathBuf, to: PathBuf },
}

impl FileEvent {
    /// The primary path associated with this event.
    pub fn path(&self) -> &PathBuf {
        match self {
            FileEvent::Created(p)
            | FileEvent::Modified(p)
            | FileEvent::Deleted(p) => p,
            FileEvent::Renamed { to, .. } => to,
        }
    }
}

/// Result of evaluating a file against a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// File is allowed.
    Allow,
    /// File violates a policy.
    Deny { reason: String },
    /// File should be moved to quarantine.
    Quarantine { reason: String },
}

impl Verdict {
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny { .. })
    }
}

/// A recorded policy violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyViolation {
    pub policy_name: String,
    pub file_path: PathBuf,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
    pub verdict: VerdictKind,
}

/// Serializable verdict kind (without the reason payload, which is stored separately).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictKind {
    Deny,
    Quarantine,
}

/// Metadata snapshot of a file used for checkpoint comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileSnapshot {
    pub path: PathBuf,
    pub size: u64,
    pub modified_epoch: i64,
}

/// Summary returned after a scan completes.
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub violations: Vec<PolicyViolation>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_event_path() {
        let ev = FileEvent::Created(PathBuf::from("/tmp/test.md"));
        assert_eq!(ev.path(), &PathBuf::from("/tmp/test.md"));

        let ev = FileEvent::Renamed {
            from: PathBuf::from("/tmp/old.md"),
            to: PathBuf::from("/tmp/new.md"),
        };
        assert_eq!(ev.path(), &PathBuf::from("/tmp/new.md"));
    }

    #[test]
    fn test_verdict_checks() {
        assert!(Verdict::Allow.is_allow());
        assert!(!Verdict::Allow.is_deny());

        let deny = Verdict::Deny {
            reason: "bad".into(),
        };
        assert!(deny.is_deny());
        assert!(!deny.is_allow());
    }
}
