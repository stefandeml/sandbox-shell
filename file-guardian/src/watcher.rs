use crate::checkpoint::Checkpoint;
use crate::policy::engine::PolicyEngine;
use crate::scanner::read_header;
use crate::types::{FileEvent, PolicyViolation, VerdictKind};
use anyhow::{Context, Result};
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Debounce window: events for the same path within this interval are merged.
const DEBOUNCE_MS: u64 = 200;

/// Callback type for handling policy violations discovered by the watcher.
pub type ViolationHandler = Box<dyn Fn(&PolicyViolation) + Send>;

/// Configuration for the file watcher.
pub struct WatcherConfig {
    pub watch_paths: Vec<PathBuf>,
    pub engine: PolicyEngine,
    pub checkpoint_dir: PathBuf,
    pub quarantine_dir: Option<PathBuf>,
    pub on_violation: Option<ViolationHandler>,
}

/// Run the file watcher loop.
///
/// This blocks the current thread, watching for file changes and evaluating
/// them against the policy engine. Call this from the worker binary's main.
///
/// Returns when the watcher channel is disconnected or an unrecoverable error occurs.
pub fn watch(config: WatcherConfig) -> Result<()> {
    let (tx, rx) = mpsc::channel();

    let mut watcher = RecommendedWatcher::new(
        move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        },
        Config::default(),
    )
    .context("failed to create filesystem watcher")?;

    // Load checkpoints for each watch path
    let mut checkpoints: HashMap<PathBuf, Checkpoint> = HashMap::new();
    for path in &config.watch_paths {
        let cp = Checkpoint::load(&config.checkpoint_dir, path);
        checkpoints.insert(path.clone(), cp);

        watcher
            .watch(path, RecursiveMode::Recursive)
            .with_context(|| format!("failed to watch {}", path.display()))?;

        tracing::info!("watching: {}", path.display());
    }

    // Debounce state: path -> last event time
    let mut pending: HashMap<PathBuf, (Instant, FileEvent)> = HashMap::new();

    loop {
        // Drain events with a timeout
        match rx.recv_timeout(Duration::from_millis(DEBOUNCE_MS)) {
            Ok(event) => {
                for file_event in translate_event(&event) {
                    let path = file_event.path().clone();
                    pending.insert(path, (Instant::now(), file_event));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                tracing::info!("watcher channel disconnected, stopping");
                break;
            }
        }

        // Process debounced events
        let now = Instant::now();
        let debounce = Duration::from_millis(DEBOUNCE_MS);
        let ready: Vec<(PathBuf, FileEvent)> = pending
            .iter()
            .filter(|(_, (when, _))| now.duration_since(*when) >= debounce)
            .map(|(path, (_, event))| (path.clone(), event.clone()))
            .collect();

        for (path, event) in ready {
            pending.remove(&path);
            process_event(
                &event,
                &config.engine,
                &mut checkpoints,
                config.quarantine_dir.as_deref(),
                config.on_violation.as_deref(),
            );
        }

        // Periodically save checkpoints
        for (watch_path, cp) in &checkpoints {
            if let Err(e) = cp.save(&config.checkpoint_dir) {
                tracing::warn!(
                    "failed to save checkpoint for {}: {}",
                    watch_path.display(),
                    e
                );
            }
        }
    }

    // Final checkpoint save
    for cp in checkpoints.values() {
        let _ = cp.save(&config.checkpoint_dir);
    }

    Ok(())
}

/// Translate a notify event into our FileEvent types.
fn translate_event(event: &notify::Event) -> Vec<FileEvent> {
    let mut events = Vec::new();

    for path in &event.paths {
        // Skip directories
        if path.is_dir() {
            continue;
        }

        match event.kind {
            EventKind::Create(_) => {
                events.push(FileEvent::Created(path.clone()));
            }
            EventKind::Modify(_) => {
                events.push(FileEvent::Modified(path.clone()));
            }
            EventKind::Remove(_) => {
                events.push(FileEvent::Deleted(path.clone()));
            }
            _ => {}
        }
    }

    events
}

/// Process a single debounced file event.
fn process_event(
    event: &FileEvent,
    engine: &PolicyEngine,
    checkpoints: &mut HashMap<PathBuf, Checkpoint>,
    quarantine_dir: Option<&Path>,
    on_violation: Option<&(dyn Fn(&PolicyViolation) + Send)>,
) {
    match event {
        FileEvent::Deleted(path) => {
            tracing::debug!("file deleted: {}", path.display());
            for cp in checkpoints.values_mut() {
                cp.remove(path);
            }
        }
        FileEvent::Created(path) | FileEvent::Modified(path) => {
            let metadata = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!("cannot stat {}: {}", path.display(), e);
                    return;
                }
            };

            let header = read_header(path, 8192);

            match engine.evaluate(path, &metadata, &header) {
                Ok(()) => {
                    tracing::debug!("allowed: {}", path.display());
                }
                Err(violation) => {
                    tracing::warn!(
                        "violation: {} — {} ({})",
                        path.display(),
                        violation.reason,
                        violation.policy_name
                    );

                    // Quarantine if configured
                    if violation.verdict == VerdictKind::Quarantine {
                        if let Some(qdir) = quarantine_dir {
                            quarantine_file(path, qdir);
                        }
                    }

                    if let Some(handler) = on_violation {
                        handler(&violation);
                    }
                }
            }
        }
        FileEvent::Renamed { from, to } => {
            // Treat as delete + create
            for cp in checkpoints.values_mut() {
                cp.remove(from);
            }
            // Re-evaluate the new path
            let create_event = FileEvent::Created(to.clone());
            process_event(&create_event, engine, checkpoints, quarantine_dir, on_violation);
        }
    }
}

/// Move a file to the quarantine directory.
fn quarantine_file(path: &Path, quarantine_dir: &Path) {
    if let Err(e) = std::fs::create_dir_all(quarantine_dir) {
        tracing::error!("failed to create quarantine dir: {}", e);
        return;
    }

    if let Some(filename) = path.file_name() {
        let dest = quarantine_dir.join(filename);
        match std::fs::rename(path, &dest) {
            Ok(()) => tracing::info!("quarantined: {} -> {}", path.display(), dest.display()),
            Err(e) => tracing::error!("failed to quarantine {}: {}", path.display(), e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_translate_create_event() {
        let event = notify::Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![PathBuf::from("/tmp/new.md")],
            attrs: Default::default(),
        };

        let events = translate_event(&event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], FileEvent::Created(p) if p == Path::new("/tmp/new.md")));
    }

    #[test]
    fn test_translate_modify_event() {
        let event = notify::Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![PathBuf::from("/tmp/changed.md")],
            attrs: Default::default(),
        };

        let events = translate_event(&event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], FileEvent::Modified(_)));
    }

    #[test]
    fn test_translate_remove_event() {
        let event = notify::Event {
            kind: EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![PathBuf::from("/tmp/gone.md")],
            attrs: Default::default(),
        };

        let events = translate_event(&event);
        assert_eq!(events.len(), 1);
        assert!(matches!(&events[0], FileEvent::Deleted(_)));
    }

    #[test]
    fn test_translate_ignores_access_events() {
        let event = notify::Event {
            kind: EventKind::Access(notify::event::AccessKind::Read),
            paths: vec![PathBuf::from("/tmp/read.md")],
            attrs: Default::default(),
        };

        let events = translate_event(&event);
        assert!(events.is_empty());
    }

    #[test]
    fn test_quarantine_file_moves_file() {
        let dir = tempfile::tempdir().unwrap();
        let quarantine = dir.path().join("quarantine");

        let file_path = dir.path().join("malware.exe");
        std::fs::write(&file_path, b"bad content").unwrap();

        quarantine_file(&file_path, &quarantine);

        assert!(!file_path.exists());
        assert!(quarantine.join("malware.exe").exists());
    }

    #[test]
    fn test_process_deleted_event_removes_from_checkpoint() {
        let mut checkpoints = HashMap::new();
        let watch_path = PathBuf::from("/tmp/watch");
        let mut cp = Checkpoint::new(&watch_path);
        cp.mark_scanned(crate::types::FileSnapshot {
            path: PathBuf::from("/tmp/watch/file.md"),
            size: 100,
            modified_epoch: 1000,
        });
        checkpoints.insert(watch_path, cp);

        let engine = PolicyEngine::new();
        let event = FileEvent::Deleted(PathBuf::from("/tmp/watch/file.md"));

        process_event(&event, &engine, &mut checkpoints, None, None);

        let cp = checkpoints.get(&PathBuf::from("/tmp/watch")).unwrap();
        assert!(cp.scanned.is_empty());
    }
}
