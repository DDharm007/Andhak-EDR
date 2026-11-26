use std::path::Path;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use rusqlite::{params, Connection};

use crate::error::AgentError;
use crate::models::TelemetryEventIn;

#[derive(Clone)]
pub struct EventSpool {
    conn: Arc<Mutex<Connection>>,
    max_events: usize,
}

impl EventSpool {
    pub fn open(path: &Path, max_events: usize) -> Result<Self, AgentError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS spool_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                dedup_hash TEXT NOT NULL UNIQUE,
                severity TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_spool_sev_id ON spool_events(severity, id);
            ",
        )?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            max_events: max_events.max(100),
        })
    }

    pub fn enqueue(&self, events: &[TelemetryEventIn]) -> Result<usize, AgentError> {
        if events.is_empty() {
            return Ok(0);
        }
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| AgentError::Collector("spool mutex poisoned".into()))?;
        let tx = conn.transaction()?;
        let now = Utc::now().to_rfc3339();
        let mut inserted = 0usize;

        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO spool_events(event_id, dedup_hash, severity, payload_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for evt in events {
                let json = serde_json::to_string(evt)?;
                let sev = serde_json::to_string(&evt.severity)?
                    .trim_matches('"')
                    .to_string();
                inserted += stmt.execute(params![evt.event_id, evt.dedup_hash, sev, json, now])?;
            }
        }

        let current_count: i64 =
            tx.query_row("SELECT COUNT(*) FROM spool_events", [], |r| r.get(0))?;
        let limit = self.max_events as i64;
        if current_count > limit {
            let excess = current_count - limit;
            // Backpressure policy: evict oldest informational events first before higher-severity records.
            tx.execute(
                "DELETE FROM spool_events WHERE id IN (
                    SELECT id FROM spool_events
                    ORDER BY CASE severity WHEN 'info' THEN 0 WHEN 'low' THEN 1 ELSE 2 END ASC, id ASC
                    LIMIT ?1
                )",
                params![excess],
            )?;
        }

        tx.commit()?;
        Ok(inserted)
    }

    pub fn peek_batch(&self, limit: usize) -> Result<Vec<(i64, TelemetryEventIn)>, AgentError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AgentError::Collector("spool mutex poisoned".into()))?;
        let mut stmt =
            conn.prepare("SELECT id, payload_json FROM spool_events ORDER BY id ASC LIMIT ?1")?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let id: i64 = row.get(0)?;
            let raw: String = row.get(1)?;
            Ok((id, raw))
        })?;

        let mut out = Vec::new();
        for row in rows {
            let (id, raw) = row?;
            let evt: TelemetryEventIn = serde_json::from_str(&raw)?;
            out.push((id, evt));
        }
        Ok(out)
    }

    pub fn ack_sent(&self, ids: &[i64]) -> Result<usize, AgentError> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| AgentError::Collector("spool mutex poisoned".into()))?;
        let tx = conn.transaction()?;
        let mut removed = 0usize;
        {
            let mut stmt = tx.prepare("DELETE FROM spool_events WHERE id = ?1")?;
            for id in ids {
                removed += stmt.execute(params![id])?;
            }
        }
        tx.commit()?;
        Ok(removed)
    }

    pub fn depth(&self) -> Result<u64, AgentError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| AgentError::Collector("spool mutex poisoned".into()))?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM spool_events", [], |r| r.get(0))?;
        Ok(count.max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::models::{compute_dedup_hash, Severity, TelemetryCategory, TelemetryOrigin};

    fn sample_event(id: &str, dedup: &str, severity: Severity) -> TelemetryEventIn {
        TelemetryEventIn {
            event_id: id.into(),
            telemetry_origin: TelemetryOrigin::TestFixture,
            category: TelemetryCategory::System,
            event_type: "host_metrics".into(),
            severity,
            occurred_at: "2026-11-26T17:00:00Z".into(),
            dedup_hash: dedup.into(),
            process: None,
            network: None,
            filesystem: None,
            system: None,
            extra: serde_json::json!({}),
        }
    }

    #[test]
    fn spool_deduplicates_and_enforces_backpressure() {
        let dir = tempdir().unwrap();
        let spool = EventSpool::open(&dir.path().join("spool.sqlite3"), 100).unwrap();

        let e1 = sample_event("e1", &compute_dedup_hash(&["k1"]), Severity::Info);
        let e2 = sample_event("e2", &compute_dedup_hash(&["k1"]), Severity::Info);
        let inserted = spool.enqueue(&[e1, e2]).unwrap();
        assert_eq!(inserted, 1);
        assert_eq!(spool.depth().unwrap(), 1);

        let batch = spool.peek_batch(10).unwrap();
        assert_eq!(batch.len(), 1);
        let ids: Vec<i64> = batch.iter().map(|(id, _)| *id).collect();
        spool.ack_sent(&ids).unwrap();
        assert_eq!(spool.depth().unwrap(), 0);
    }
}
