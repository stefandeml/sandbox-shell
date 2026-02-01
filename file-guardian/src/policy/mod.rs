pub mod builtin;
pub mod engine;

use crate::types::Verdict;
use std::fmt;
use std::fs::Metadata;
use std::path::Path;

/// A policy that evaluates whether a file is allowed.
///
/// Implementations inspect the file path, metadata, and optionally
/// the first bytes of content to decide whether to allow, deny, or
/// quarantine the file.
pub trait Policy: fmt::Debug + Send + Sync {
    /// Human-readable name of this policy.
    fn name(&self) -> &str;

    /// Evaluate a file against this policy.
    ///
    /// `header` contains the first bytes of the file (up to 8 KB),
    /// which is enough for magic byte detection. For deleted files
    /// the header will be empty.
    fn evaluate(&self, path: &Path, metadata: &Metadata, header: &[u8]) -> Verdict;
}
