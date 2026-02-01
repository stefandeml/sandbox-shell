//! Worker binary — the actual scanner and watcher.
//!
//! This binary runs inside the sandbox. It:
//! 1. Loads configuration
//! 2. Performs an initial scan of all watched directories
//! 3. Starts watching for live filesystem changes
//! 4. Evaluates all files against their configured policies

use anyhow::Result;
use file_guardian::checkpoint::Checkpoint;
use file_guardian::config::{build_policies_from_names, GuardianConfig};
use file_guardian::policy::engine::PolicyEngine;
use file_guardian::scanner::scan_directory;
use file_guardian::types::VerdictKind;
use file_guardian::watcher::{WatcherConfig, watch};
use std::env;
use std::path::PathBuf;

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("file_guardian=info".parse().unwrap()),
        )
        .init();

    let config_path = parse_config_arg()?;
    let config = GuardianConfig::load(&config_path)?;
    let resolved = config.resolve_paths();

    eprintln!("[worker] loaded config from {}", config_path.display());

    // Phase 1: Initial scan of all watch targets
    eprintln!("[worker] starting initial scan...");
    let mut total_scanned = 0;
    let mut total_violations = 0;

    for target in &resolved.watch {
        if !target.path.exists() {
            eprintln!(
                "[worker] warning: watch path does not exist: {}",
                target.path.display()
            );
            continue;
        }

        let policies = build_policies_from_names(&target.policies);
        let mut engine = PolicyEngine::new();
        for policy in policies {
            engine.add_boxed(policy);
        }

        let mut checkpoint = Checkpoint::load(&resolved.checkpoint_dir, &target.path);

        match scan_directory(&target.path, &engine, &mut checkpoint) {
            Ok(summary) => {
                total_scanned += summary.files_scanned;
                total_violations += summary.violations.len();

                for violation in &summary.violations {
                    let marker = match violation.verdict {
                        VerdictKind::Deny => "DENY",
                        VerdictKind::Quarantine => "QUARANTINE",
                    };
                    eprintln!(
                        "[worker] [{}] {} — {} ({})",
                        marker,
                        violation.file_path.display(),
                        violation.reason,
                        violation.policy_name
                    );
                }

                // Save checkpoint after scan
                if let Err(e) = checkpoint.save(&resolved.checkpoint_dir) {
                    eprintln!("[worker] warning: failed to save checkpoint: {}", e);
                }
            }
            Err(e) => {
                eprintln!(
                    "[worker] error scanning {}: {}",
                    target.path.display(),
                    e
                );
            }
        }
    }

    eprintln!(
        "[worker] initial scan complete: {} files scanned, {} violations",
        total_scanned, total_violations
    );

    // Phase 2: Watch for live changes
    eprintln!("[worker] starting file watcher...");

    // Build a combined engine with all policies from all targets
    // (In a more sophisticated version, each target would have its own engine)
    let mut combined_engine = PolicyEngine::new();
    let mut watch_paths = Vec::new();

    for target in &resolved.watch {
        if !target.path.exists() {
            continue;
        }
        watch_paths.push(target.path.clone());
        let policies = build_policies_from_names(&target.policies);
        for policy in policies {
            combined_engine.add_boxed(policy);
        }
    }

    if watch_paths.is_empty() {
        eprintln!("[worker] no valid watch paths, exiting");
        return Ok(());
    }

    let watcher_config = WatcherConfig {
        watch_paths,
        engine: combined_engine,
        checkpoint_dir: resolved.checkpoint_dir.clone(),
        quarantine_dir: Some(resolved.quarantine_dir.clone()),
        on_violation: Some(Box::new(|v| {
            let marker = match v.verdict {
                VerdictKind::Deny => "DENY",
                VerdictKind::Quarantine => "QUARANTINE",
            };
            eprintln!(
                "[watcher] [{}] {} — {} ({})",
                marker,
                v.file_path.display(),
                v.reason,
                v.policy_name
            );
        })),
    };

    watch(watcher_config)?;

    Ok(())
}

fn parse_config_arg() -> Result<PathBuf> {
    let args: Vec<String> = env::args().collect();
    for (i, arg) in args.iter().enumerate() {
        if arg == "--config" {
            if let Some(path) = args.get(i + 1) {
                return Ok(PathBuf::from(path));
            }
        }
    }
    anyhow::bail!("usage: guardian-worker --config <path>");
}
