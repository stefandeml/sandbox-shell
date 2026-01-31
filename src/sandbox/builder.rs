//! Builder API for programmatic sandbox construction.
//!
//! Provides an ergonomic interface for library consumers to configure and
//! execute sandboxed commands without going through CLI argument parsing.
//!
//! # Example
//!
//! ```no_run
//! use sx::Sandbox;
//! use sx::NetworkMode;
//!
//! let result = Sandbox::new("/path/to/workdir")
//!     .network(NetworkMode::Offline)
//!     .allow_read("/usr")
//!     .allow_read("/bin")
//!     .deny_read("/home/user/.ssh")
//!     .allow_write("/tmp/output")
//!     .profile("rust")
//!     .execute(&["cargo", "build"])
//!     .unwrap();
//!
//! assert_eq!(result.exit_code, 0);
//! ```

use std::path::PathBuf;

use crate::config::profile::{compose_profiles, load_profiles};
use crate::config::schema::NetworkMode;
use crate::sandbox::executor::{
    execute_sandboxed, execute_sandboxed_captured, ExecutionError, ExecutionResult,
};
use crate::sandbox::seatbelt::{generate_seatbelt_profile, SandboxParams, SeatbeltError};
use crate::utils::paths::expand_paths;

/// Builder for configuring and executing sandboxed commands.
///
/// Uses a deny-by-default security model: filesystem and network access
/// are blocked unless explicitly allowed.
#[derive(Debug, Clone)]
pub struct Sandbox {
    working_dir: PathBuf,
    home_dir: PathBuf,
    network_mode: NetworkMode,
    allow_read: Vec<String>,
    deny_read: Vec<String>,
    allow_write: Vec<String>,
    profile_names: Vec<String>,
    raw_rules: Vec<String>,
    inherit_base: bool,
    shell: Option<String>,
    custom_profile_dir: Option<PathBuf>,
}

impl Sandbox {
    /// Create a new sandbox builder for the given working directory.
    ///
    /// The working directory gets full read/write access inside the sandbox.
    /// All other filesystem access is denied by default.
    pub fn new(working_dir: impl Into<PathBuf>) -> Self {
        Self {
            working_dir: working_dir.into(),
            home_dir: dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")),
            network_mode: NetworkMode::Offline,
            allow_read: Vec::new(),
            deny_read: Vec::new(),
            allow_write: Vec::new(),
            profile_names: Vec::new(),
            raw_rules: Vec::new(),
            inherit_base: true,
            shell: None,
            custom_profile_dir: None,
        }
    }

    /// Set the network access mode.
    ///
    /// Defaults to `NetworkMode::Offline` (no network access).
    pub fn network(mut self, mode: NetworkMode) -> Self {
        self.network_mode = mode;
        self
    }

    /// Override the home directory used for path expansion.
    ///
    /// Defaults to the current user's home directory.
    pub fn home_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.home_dir = path.into();
        self
    }

    /// Allow read access to a filesystem path.
    ///
    /// Supports glob patterns (e.g., `/private/tmp/zsh*`).
    /// Paths with `~` are expanded to the home directory.
    pub fn allow_read(mut self, path: impl Into<String>) -> Self {
        self.allow_read.push(path.into());
        self
    }

    /// Allow read access to multiple filesystem paths.
    pub fn allow_reads(mut self, paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.allow_read.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Deny read access to a path, overriding any allow rules.
    ///
    /// Uses Seatbelt last-match-wins semantics: deny rules placed after
    /// allow rules take precedence for nested paths.
    pub fn deny_read(mut self, path: impl Into<String>) -> Self {
        self.deny_read.push(path.into());
        self
    }

    /// Deny read access to multiple paths.
    pub fn deny_reads(mut self, paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.deny_read.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Allow write access to a filesystem path beyond the working directory.
    ///
    /// The working directory always has full write access.
    pub fn allow_write(mut self, path: impl Into<String>) -> Self {
        self.allow_write.push(path.into());
        self
    }

    /// Allow write access to multiple paths.
    pub fn allow_writes(mut self, paths: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.allow_write.extend(paths.into_iter().map(Into::into));
        self
    }

    /// Apply a named profile (builtin or custom).
    ///
    /// Built-in profiles: `base`, `online`, `localhost`, `rust`, `claude`, `gpg`.
    /// Custom profiles are loaded from `~/.config/sx/profiles/` or from
    /// [`custom_profile_dir`](Self::custom_profile_dir).
    pub fn profile(mut self, name: impl Into<String>) -> Self {
        self.profile_names.push(name.into());
        self
    }

    /// Apply multiple profiles.
    pub fn profiles(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.profile_names.extend(names.into_iter().map(Into::into));
        self
    }

    /// Set a custom directory to search for profile TOML files.
    pub fn custom_profile_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.custom_profile_dir = Some(path.into());
        self
    }

    /// Whether to include the `base` profile automatically.
    ///
    /// Defaults to `true`. Set to `false` for full custom control over
    /// allowed paths (advanced usage).
    pub fn inherit_base(mut self, inherit: bool) -> Self {
        self.inherit_base = inherit;
        self
    }

    /// Set the shell to use for interactive sessions (when no command is given).
    pub fn shell(mut self, shell: impl Into<String>) -> Self {
        self.shell = Some(shell.into());
        self
    }

    /// Add a raw Seatbelt rule to include verbatim in the generated profile.
    ///
    /// This is an escape hatch for advanced sandbox configurations that
    /// aren't covered by the builder API.
    pub fn raw_rule(mut self, rule: impl Into<String>) -> Self {
        self.raw_rules.push(rule.into());
        self
    }

    /// Build the `SandboxParams` from the current configuration.
    ///
    /// This resolves profiles, expands paths, and produces the final
    /// parameters used for seatbelt profile generation.
    pub fn build_params(&self) -> SandboxParams {
        // Collect profile names
        let mut all_profiles = Vec::new();
        if self.inherit_base {
            all_profiles.push("base".to_string());
        }
        for name in &self.profile_names {
            if !all_profiles.contains(name) {
                all_profiles.push(name.clone());
            }
        }

        // Load and compose profiles
        let profiles = load_profiles(&all_profiles, self.custom_profile_dir.as_deref());
        let composed = compose_profiles(&profiles);

        // Determine network mode (explicit setting takes precedence over profiles)
        let network_mode = if self.network_mode != NetworkMode::Offline
            || composed.network_mode.is_none()
        {
            self.network_mode
        } else {
            composed.network_mode.unwrap_or(self.network_mode)
        };

        // Collect and expand paths
        let mut allow_read: Vec<String> = composed.filesystem.allow_read.clone();
        allow_read.extend(self.allow_read.iter().cloned());

        let mut deny_read: Vec<String> = composed.filesystem.deny_read.clone();
        deny_read.extend(self.deny_read.iter().cloned());

        let mut allow_write: Vec<String> = composed.filesystem.allow_write.clone();
        allow_write.extend(self.allow_write.iter().cloned());

        // Expand paths (~ and $VAR)
        let allow_read = expand_paths(&allow_read)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        let deny_read = expand_paths(&deny_read)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        let allow_write = expand_paths(&allow_write)
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        // Build raw rules
        let mut raw_rules = composed
            .seatbelt
            .as_ref()
            .and_then(|s| s.raw.clone())
            .unwrap_or_default();
        for rule in &self.raw_rules {
            if !raw_rules.is_empty() {
                raw_rules.push('\n');
            }
            raw_rules.push_str(rule);
        }

        SandboxParams {
            working_dir: self.working_dir.clone(),
            home_dir: self.home_dir.clone(),
            network_mode,
            allow_read: allow_read.into_iter().map(PathBuf::from).collect(),
            deny_read: deny_read.into_iter().map(PathBuf::from).collect(),
            allow_write: allow_write.into_iter().map(PathBuf::from).collect(),
            raw_rules: if raw_rules.is_empty() {
                None
            } else {
                Some(raw_rules)
            },
        }
    }

    /// Generate the Seatbelt profile string without executing anything.
    ///
    /// Useful for inspection, debugging, or writing the profile to a file
    /// for use with `sandbox-exec` directly.
    pub fn generate_profile(&self) -> Result<String, SeatbeltError> {
        let params = self.build_params();
        generate_seatbelt_profile(&params)
    }

    /// Execute a command inside the sandbox.
    ///
    /// The command is run via `sandbox-exec` with the generated Seatbelt profile.
    /// Returns the exit code of the sandboxed process.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use sx::Sandbox;
    ///
    /// let result = Sandbox::new("/tmp/workdir")
    ///     .execute(&["echo", "hello"])
    ///     .unwrap();
    /// ```
    pub fn execute(&self, command: &[&str]) -> Result<ExecutionResult, ExecutionError> {
        let params = self.build_params();
        let cmd: Vec<String> = command.iter().map(|s| s.to_string()).collect();
        execute_sandboxed(&params, &cmd, self.shell.as_deref())
    }

    /// Execute a command and capture its stdout and stderr.
    ///
    /// Unlike [`execute`](Self::execute), this does not inherit stdio,
    /// making it suitable for programmatic use where you need the output.
    ///
    /// Returns `(exit_status, stdout_bytes, stderr_bytes)`.
    pub fn execute_captured(
        &self,
        command: &[&str],
    ) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), ExecutionError> {
        let params = self.build_params();
        let cmd: Vec<String> = command.iter().map(|s| s.to_string()).collect();
        execute_sandboxed_captured(&params, &cmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let sb = Sandbox::new("/tmp/test");
        let params = sb.build_params();

        assert_eq!(params.working_dir, PathBuf::from("/tmp/test"));
        assert_eq!(params.network_mode, NetworkMode::Offline);
        // Base profile is included by default
        assert!(!params.allow_read.is_empty(), "base profile should add read paths");
    }

    #[test]
    fn test_builder_network_mode() {
        let sb = Sandbox::new("/tmp/test").network(NetworkMode::Online);
        let params = sb.build_params();
        assert_eq!(params.network_mode, NetworkMode::Online);
    }

    #[test]
    fn test_builder_no_base_profile() {
        let sb = Sandbox::new("/tmp/test").inherit_base(false);
        let params = sb.build_params();
        // Without base profile, allow_read should be empty (no profile paths added)
        assert!(params.allow_read.is_empty());
    }

    #[test]
    fn test_builder_custom_paths() {
        let sb = Sandbox::new("/tmp/test")
            .inherit_base(false)
            .allow_read("/usr")
            .allow_read("/bin")
            .deny_read("/usr/secret")
            .allow_write("/tmp/output");

        let params = sb.build_params();

        assert!(params.allow_read.contains(&PathBuf::from("/usr")));
        assert!(params.allow_read.contains(&PathBuf::from("/bin")));
        assert!(params.deny_read.contains(&PathBuf::from("/usr/secret")));
        assert!(params.allow_write.contains(&PathBuf::from("/tmp/output")));
    }

    #[test]
    fn test_builder_raw_rules() {
        let sb = Sandbox::new("/tmp/test")
            .inherit_base(false)
            .raw_rule("(allow network-outbound (to ip \"localhost:8080\"))");

        let params = sb.build_params();
        assert!(params.raw_rules.is_some());
        assert!(params.raw_rules.unwrap().contains("localhost:8080"));
    }

    #[test]
    fn test_builder_profile_loading() {
        let sb = Sandbox::new("/tmp/test").profile("online");
        let params = sb.build_params();
        assert_eq!(params.network_mode, NetworkMode::Online);
    }

    #[test]
    fn test_builder_generates_valid_profile() {
        let sb = Sandbox::new("/tmp/test")
            .network(NetworkMode::Offline)
            .allow_read("/usr")
            .deny_read("/usr/secret");

        let profile = sb.generate_profile().unwrap();
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow file-read* (subpath \"/usr\"))"));
        assert!(profile.contains("(deny file-read* (subpath \"/usr/secret\"))"));
    }

    #[test]
    fn test_builder_batch_paths() {
        let sb = Sandbox::new("/tmp/test")
            .inherit_base(false)
            .allow_reads(["/usr", "/bin", "/lib"])
            .deny_reads(["/usr/secret"])
            .allow_writes(["/tmp/a", "/tmp/b"]);

        let params = sb.build_params();
        assert_eq!(params.allow_read.len(), 3);
        assert_eq!(params.deny_read.len(), 1);
        assert_eq!(params.allow_write.len(), 2);
    }

    #[test]
    fn test_builder_profiles_dedup() {
        let sb = Sandbox::new("/tmp/test")
            .profile("base")
            .profile("online")
            .profile("base"); // duplicate

        // base is already added by inherit_base, so only "online" should be unique
        let params = sb.build_params();
        // Just verify it builds without error and has online mode from profile
        assert_eq!(params.network_mode, NetworkMode::Online);
    }

    #[test]
    fn test_builder_clone() {
        let base = Sandbox::new("/tmp/test")
            .network(NetworkMode::Offline)
            .allow_read("/usr");

        let variant = base.clone().network(NetworkMode::Online);

        let params_base = base.build_params();
        let params_variant = variant.build_params();

        assert_eq!(params_base.network_mode, NetworkMode::Offline);
        assert_eq!(params_variant.network_mode, NetworkMode::Online);
    }
}
