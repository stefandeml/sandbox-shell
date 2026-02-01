//! Launcher binary — sets up the sandbox and executes the worker.
//!
//! This binary is the user-facing entry point. It reads the config,
//! determines which directories to watch, and runs the worker binary
//! inside an sx sandbox with minimal permissions.

use anyhow::{Context, Result};
use file_guardian::config::GuardianConfig;
use std::env;
use std::path::PathBuf;
use sx::{NetworkMode, Sandbox};

fn main() -> Result<()> {
    // Find config file
    let config_path = find_config()?;
    let config = GuardianConfig::load(&config_path)
        .with_context(|| format!("failed to load config from {}", config_path.display()))?;
    let resolved = config.resolve_paths();

    // Find the worker binary (next to us in the same directory)
    let exe = env::current_exe().context("failed to get current executable path")?;
    let worker = exe
        .parent()
        .context("executable has no parent directory")?
        .join("guardian-worker");

    if !worker.exists() {
        anyhow::bail!(
            "worker binary not found at {}. Build with `cargo build`.",
            worker.display()
        );
    }

    eprintln!("[guardian] config: {}", config_path.display());
    eprintln!("[guardian] worker: {}", worker.display());

    // Build the sandbox
    let mut sandbox = Sandbox::new(env::current_dir()?)
        .network(NetworkMode::Offline)
        .allow_read("/usr")
        .allow_read("/bin")
        .allow_read("/lib")
        .allow_read("/etc")
        .allow_read(worker.to_string_lossy().as_ref())
        .allow_read(config_path.to_string_lossy().as_ref())
        // Allow reading/writing checkpoint and quarantine dirs
        .allow_write(resolved.checkpoint_dir.to_string_lossy().as_ref())
        .allow_write(resolved.quarantine_dir.to_string_lossy().as_ref());

    // Allow read access to each watch target
    for target in &resolved.watch {
        sandbox = sandbox.allow_read(target.path.to_string_lossy().as_ref());
    }

    // Deny sensitive paths
    sandbox = sandbox
        .deny_read("~/.ssh")
        .deny_read("~/.aws")
        .deny_read("~/.gnupg");

    eprintln!("[guardian] starting sandboxed worker...");
    eprintln!("[guardian] watching {} directories", resolved.watch.len());
    for target in &resolved.watch {
        eprintln!(
            "[guardian]   {} [{}]",
            target.path.display(),
            target.policies.join(", ")
        );
    }

    let result = sandbox.execute(&[
        worker.to_str().unwrap(),
        "--config",
        config_path.to_str().unwrap(),
    ])?;

    std::process::exit(result.exit_code);
}

/// Find the config file, checking (in order):
/// 1. --config <path> argument
/// 2. ./guardian.toml
/// 3. ~/.config/file-guardian/config.toml
fn find_config() -> Result<PathBuf> {
    let args: Vec<String> = env::args().collect();

    // Check for --config flag
    for (i, arg) in args.iter().enumerate() {
        if arg == "--config" {
            if let Some(path) = args.get(i + 1) {
                let p = PathBuf::from(path);
                if p.exists() {
                    return Ok(p);
                }
                anyhow::bail!("config file not found: {}", p.display());
            }
        }
    }

    // Check current directory
    let local = PathBuf::from("guardian.toml");
    if local.exists() {
        return Ok(local);
    }

    // Check XDG config directory
    if let Some(config_dir) = dirs::config_dir() {
        let global = config_dir.join("file-guardian/config.toml");
        if global.exists() {
            return Ok(global);
        }
    }

    anyhow::bail!(
        "no config found. Create guardian.toml or ~/.config/file-guardian/config.toml"
    )
}
