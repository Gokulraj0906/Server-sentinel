//! Bounded in-memory history buffer (FR-009).
//!
//! Keeps roughly the last `retention` worth of snapshots so the
//! investigation engine can answer "what happened immediately before the
//! incident?" without continuously writing to disk.

use crate::core::models::Snapshot;
use chrono::Duration;
use std::collections::VecDeque;

pub struct RingBuffer {
    retention: Duration,
    buf: VecDeque<Snapshot>,
}

#[allow(dead_code)] // snapshots()/last() are public API for future consumers (dashboard, tests)
impl RingBuffer {
    pub fn new(retention_seconds: u64) -> Self {
        Self {
            retention: Duration::seconds(retention_seconds as i64),
            buf: VecDeque::new(),
        }
    }

    pub fn push(&mut self, snapshot: Snapshot) {
        let cutoff = snapshot.timestamp - self.retention;
        self.buf.push_back(snapshot);
        while let Some(front) = self.buf.front() {
            if front.timestamp < cutoff {
                self.buf.pop_front();
            } else {
                break;
            }
        }
    }

    pub fn snapshots(&self) -> impl Iterator<Item = &Snapshot> {
        self.buf.iter()
    }

    pub fn last(&self) -> Option<&Snapshot> {
        self.buf.back()
    }

    /// Snapshots strictly before `at`, useful for grabbing pre-incident
    /// baseline context once an incident has been declared.
    pub fn before(&self, at: chrono::DateTime<chrono::Utc>) -> Vec<Snapshot> {
        self.buf.iter().filter(|s| s.timestamp < at).cloned().collect()
    }
}
