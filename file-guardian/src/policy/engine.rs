use super::Policy;
use crate::types::{PolicyViolation, Verdict, VerdictKind};
use chrono::Utc;
use std::fs::Metadata;
use std::path::Path;

/// Registry of policies that are evaluated against files.
///
/// Policies are evaluated in order. The first `Deny` or `Quarantine`
/// verdict stops evaluation (fail-fast).
#[derive(Default)]
pub struct PolicyEngine {
    policies: Vec<Box<dyn Policy>>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a policy.
    pub fn add(&mut self, policy: impl Policy + 'static) {
        self.policies.push(Box::new(policy));
    }

    /// Register a pre-boxed policy.
    pub fn add_boxed(&mut self, policy: Box<dyn Policy>) {
        self.policies.push(policy);
    }

    /// Number of registered policies.
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Evaluate a file against all registered policies.
    ///
    /// Returns `Ok(())` if all policies allow, or the first violation.
    pub fn evaluate(
        &self,
        path: &Path,
        metadata: &Metadata,
        header: &[u8],
    ) -> Result<(), PolicyViolation> {
        for policy in &self.policies {
            match policy.evaluate(path, metadata, header) {
                Verdict::Allow => continue,
                Verdict::Deny { reason } => {
                    return Err(PolicyViolation {
                        policy_name: policy.name().to_string(),
                        file_path: path.to_path_buf(),
                        reason,
                        timestamp: Utc::now(),
                        verdict: VerdictKind::Deny,
                    });
                }
                Verdict::Quarantine { reason } => {
                    return Err(PolicyViolation {
                        policy_name: policy.name().to_string(),
                        file_path: path.to_path_buf(),
                        reason,
                        timestamp: Utc::now(),
                        verdict: VerdictKind::Quarantine,
                    });
                }
            }
        }
        Ok(())
    }

    /// Evaluate all policies and collect *all* violations (does not fail-fast).
    pub fn evaluate_all(
        &self,
        path: &Path,
        metadata: &Metadata,
        header: &[u8],
    ) -> Vec<PolicyViolation> {
        let mut violations = Vec::new();
        for policy in &self.policies {
            match policy.evaluate(path, metadata, header) {
                Verdict::Allow => {}
                Verdict::Deny { reason } => {
                    violations.push(PolicyViolation {
                        policy_name: policy.name().to_string(),
                        file_path: path.to_path_buf(),
                        reason,
                        timestamp: Utc::now(),
                        verdict: VerdictKind::Deny,
                    });
                }
                Verdict::Quarantine { reason } => {
                    violations.push(PolicyViolation {
                        policy_name: policy.name().to_string(),
                        file_path: path.to_path_buf(),
                        reason,
                        timestamp: Utc::now(),
                        verdict: VerdictKind::Quarantine,
                    });
                }
            }
        }
        violations
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::builtin::{AllowedExtensions, MaxFileSize, NoExecutables, TextOnly};
    use std::io::Write;

    fn write_temp(dir: &Path, name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    #[test]
    fn test_engine_empty_allows_everything() {
        let engine = PolicyEngine::new();
        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(dir.path(), "anything.exe", b"\x7fELF");
        let meta = std::fs::metadata(&path).unwrap();

        assert!(engine.evaluate(&path, &meta, b"\x7fELF").is_ok());
    }

    #[test]
    fn test_engine_single_policy_deny() {
        let mut engine = PolicyEngine::new();
        engine.add(AllowedExtensions::markdown_only());

        let dir = tempfile::tempdir().unwrap();
        let path = write_temp(dir.path(), "code.py", b"print('hi')");
        let meta = std::fs::metadata(&path).unwrap();

        let result = engine.evaluate(&path, &meta, b"print('hi')");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.policy_name, "markdown-only");
    }

    #[test]
    fn test_engine_multiple_policies_fail_fast() {
        let mut engine = PolicyEngine::new();
        engine.add(AllowedExtensions::markdown_only());
        engine.add(MaxFileSize::new(10));

        let dir = tempfile::tempdir().unwrap();
        // Fails both: wrong extension AND too big
        let content = vec![b'x'; 100];
        let path = write_temp(dir.path(), "big.py", &content);
        let meta = std::fs::metadata(&path).unwrap();

        // fail-fast: only first violation
        let result = engine.evaluate(&path, &meta, &content);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().policy_name, "markdown-only");
    }

    #[test]
    fn test_engine_evaluate_all_collects_everything() {
        let mut engine = PolicyEngine::new();
        engine.add(AllowedExtensions::markdown_only());
        engine.add(MaxFileSize::new(10));

        let dir = tempfile::tempdir().unwrap();
        let content = vec![b'x'; 100];
        let path = write_temp(dir.path(), "big.py", &content);
        let meta = std::fs::metadata(&path).unwrap();

        let violations = engine.evaluate_all(&path, &meta, &content);
        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn test_engine_all_policies_pass() {
        let mut engine = PolicyEngine::new();
        engine.add(AllowedExtensions::markdown_only());
        engine.add(MaxFileSize::mb(1));
        engine.add(TextOnly);
        engine.add(NoExecutables);

        let dir = tempfile::tempdir().unwrap();
        let content = b"# My Document\n\nHello world.\n";
        let path = write_temp(dir.path(), "readme.md", content);
        let meta = std::fs::metadata(&path).unwrap();

        assert!(engine.evaluate(&path, &meta, content).is_ok());
    }

    #[test]
    fn test_engine_len() {
        let mut engine = PolicyEngine::new();
        assert!(engine.is_empty());
        engine.add(TextOnly);
        engine.add(NoExecutables);
        assert_eq!(engine.len(), 2);
    }
}
