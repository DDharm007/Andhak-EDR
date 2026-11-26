use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use globset::{Glob, GlobSet, GlobSetBuilder};
use notify::event::{ModifyKind, RenameMode};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::AgentError;
use crate::models::{
    compute_dedup_hash, FilesystemPayload, SensorState, Severity, SignatureStatus,
    TelemetryCategory, TelemetryEventIn, TelemetryOrigin,
};

const MAX_HASH_BYTES: u64 = 25 * 1024 * 1024;
const DEDUP_WINDOW: Duration = Duration::from_millis(750);

pub struct FilesystemWatcher {
    _watcher: RecommendedWatcher,
    rx: Arc<Mutex<Receiver<notify::Result<notify::Event>>>>,
    exclusions: GlobSet,
    recent: HashMap<(String, String), Instant>,
    state: SensorState,
}

impl FilesystemWatcher {
    pub fn start(watch_paths: &[PathBuf], exclusion_globs: &[String]) -> Result<Self, AgentError> {
        let mut builder = GlobSetBuilder::new();
        for pat in exclusion_globs {
            if let Ok(glob) = Glob::new(pat) {
                builder.add(glob);
            }
        }
        let exclusions = builder
            .build()
            .map_err(|e| AgentError::Config(format!("invalid exclusion glob: {e}")))?;

        let (tx, rx) = mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = tx.send(res);
        })
        .map_err(|e| AgentError::Collector(format!("failed to start fs watcher: {e}")))?;

        let mut watched_any = false;
        for path in watch_paths {
            if path.exists() {
                if let Err(err) = watcher.watch(path, RecursiveMode::Recursive) {
                    tracing::warn!(path = %path.display(), error = %err, "Failed to watch path");
                } else {
                    watched_any = true;
                }
            }
        }

        let state = if watched_any {
            SensorState::Ready
        } else if watch_paths.is_empty() {
            SensorState::Unavailable
        } else {
            SensorState::Partial
        };

        Ok(Self {
            _watcher: watcher,
            rx: Arc::new(Mutex::new(rx)),
            exclusions,
            recent: HashMap::new(),
            state,
        })
    }

    pub fn health(&self) -> SensorState {
        self.state
    }

    pub fn drain_events(&mut self) -> Vec<TelemetryEventIn> {
        let now = Instant::now();
        self.recent
            .retain(|_, ts| now.duration_since(*ts) < DEDUP_WINDOW);

        let mut raw_events = Vec::new();
        if let Ok(rx) = self.rx.lock() {
            while let Ok(item) = rx.try_recv() {
                if let Ok(evt) = item {
                    raw_events.push(evt);
                }
            }
        }

        let mut out = Vec::new();
        for evt in raw_events {
            let Some(event_type) = map_event_kind(&evt.kind) else {
                continue;
            };
            if evt.paths.is_empty() {
                continue;
            }
            let primary_path = &evt.paths[0];
            if self.is_excluded(primary_path) {
                continue;
            }
            let path_str = primary_path.to_string_lossy().to_string();
            let dedup_pair = (event_type.to_string(), path_str.clone());
            if let Some(prev) = self.recent.get(&dedup_pair) {
                if now.duration_since(*prev) < DEDUP_WINDOW {
                    continue;
                }
            }
            self.recent.insert(dedup_pair, now);

            let previous_path = if event_type == "file_renamed" && evt.paths.len() > 1 {
                Some(evt.paths[0].to_string_lossy().to_string())
            } else {
                None
            };
            let target_path = if event_type == "file_renamed" && evt.paths.len() > 1 {
                &evt.paths[1]
            } else {
                primary_path
            };
            let target_str = target_path.to_string_lossy().to_string();

            let (sha256, size_bytes, modified_at) = if event_type == "file_deleted" {
                (None, None, None)
            } else {
                inspect_file_metadata(target_path)
            };

            let signature_status = if event_type == "file_deleted" {
                SignatureStatus::Unknown
            } else {
                probe_signature_if_pe(target_path)
            };

            let occurred_at = Utc::now().to_rfc3339();
            let bucket = Utc::now().timestamp().to_string();
            let dedup_hash = compute_dedup_hash(&[
                "filesystem",
                event_type,
                &target_str,
                sha256.as_deref().unwrap_or("none"),
                &bucket,
            ]);

            out.push(TelemetryEventIn {
                event_id: format!("fs-{}", Uuid::new_v4()),
                telemetry_origin: TelemetryOrigin::RealEndpoint,
                category: TelemetryCategory::Filesystem,
                event_type: event_type.to_string(),
                severity: Severity::Info,
                occurred_at,
                dedup_hash,
                process: None,
                network: None,
                filesystem: Some(FilesystemPayload {
                    file_path: target_str,
                    previous_path,
                    sha256,
                    size_bytes,
                    signature_status,
                    modified_at,
                }),
                system: None,
                extra: serde_json::json!({}),
            });
        }
        out
    }

    fn is_excluded(&self, path: &Path) -> bool {
        let full = path.to_string_lossy();
        if self.exclusions.is_match(full.as_ref()) {
            return true;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if self.exclusions.is_match(name) {
                return true;
            }
        }
        false
    }
}

fn map_event_kind(kind: &EventKind) -> Option<&'static str> {
    match kind {
        EventKind::Create(_) => Some("file_created"),
        EventKind::Remove(_) => Some("file_deleted"),
        EventKind::Modify(ModifyKind::Name(
            RenameMode::Both | RenameMode::To | RenameMode::Any,
        )) => Some("file_renamed"),
        EventKind::Modify(_) => Some("file_modified"),
        _ => None,
    }
}

pub fn sha256_file(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 32 * 1024];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

fn inspect_file_metadata(path: &Path) -> (Option<String>, Option<u64>, Option<String>) {
    let Ok(meta) = std::fs::metadata(path) else {
        return (None, None, None);
    };
    if !meta.is_file() {
        return (None, None, None);
    }
    let size = Some(meta.len());
    let modified_at = meta
        .modified()
        .ok()
        .map(|t| DateTime::<Utc>::from(t).to_rfc3339());
    let hash = sha256_file(path);
    (hash, size, modified_at)
}

#[cfg(windows)]
fn probe_signature_if_pe(path: &Path) -> SignatureStatus {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_default();
    if matches!(ext.as_str(), "exe" | "dll" | "sys" | "ps1" | "msi") {
        crate::collectors::windows::verify_authenticode(path).0
    } else {
        SignatureStatus::Unknown
    }
}

#[cfg(not(windows))]
fn probe_signature_if_pe(_path: &Path) -> SignatureStatus {
    SignatureStatus::Unknown
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn hashes_files_and_filters_exclusions() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("sample.txt");
        std::fs::write(&file_path, b"andhak-edr-test").unwrap();

        let hash = sha256_file(&file_path).unwrap();
        assert_eq!(hash.len(), 64);

        let watcher =
            FilesystemWatcher::start(&[dir.path().to_path_buf()], &["*.tmp".into()]).unwrap();
        assert!(watcher.is_excluded(Path::new("C:\\Temp\\noise.tmp")));
        assert!(!watcher.is_excluded(&file_path));
    }
}
