//! Detection engine (FR-005, FR-006, FR-007).
//!
//! Turns a stream of snapshots into alert levels per resource, and decides
//! when sustained CRITICAL activity should become a declared incident
//! ("continuously for N seconds", not just a single noisy sample).

use crate::core::config::ThresholdsConfig;
use crate::core::models::{AlertLevel, ResourceKind, Snapshot};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

/// Tracks, per resource, how long the metric has been continuously at or
/// above the CRITICAL threshold. A single sample below CRITICAL resets the
/// counter (FR-007 debounce example).
#[derive(Default)]
pub struct DetectionEngine {
    critical_since: HashMap<ResourceKind, DateTime<Utc>>,
}

pub struct DetectionResult {
    pub alert_levels: HashMap<ResourceKind, AlertLevel>,
    /// Resources that just crossed from "not yet triggered" to
    /// "sustained critical long enough to declare an incident" on this
    /// tick.
    pub newly_triggered: Vec<ResourceKind>,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self::default()
    }

    fn level_for(value: f32, warning: f32, critical: f32) -> AlertLevel {
        if value >= critical {
            AlertLevel::Critical
        } else if value >= warning {
            AlertLevel::Warning
        } else {
            AlertLevel::Normal
        }
    }

    pub fn evaluate(
        &mut self,
        snapshot: &Snapshot,
        thresholds: &ThresholdsConfig,
        trigger_duration_seconds: u64,
    ) -> DetectionResult {
        let mut alert_levels = HashMap::new();
        let mut newly_triggered = Vec::new();

        let readings = [
            (
                ResourceKind::Cpu,
                snapshot.cpu.usage_percent,
                thresholds.cpu_warning,
                thresholds.cpu_critical,
            ),
            (
                ResourceKind::Memory,
                snapshot.memory.used_percent,
                thresholds.memory_warning,
                thresholds.memory_critical,
            ),
            (
                ResourceKind::Disk,
                snapshot.disk.max_used_percent,
                thresholds.disk_warning,
                thresholds.disk_critical,
            ),
        ];

        for (kind, value, warning, critical) in readings {
            let level = Self::level_for(value, warning, critical);
            alert_levels.insert(kind, level);

            match level {
                AlertLevel::Critical => {
                    let since = *self
                        .critical_since
                        .entry(kind)
                        .or_insert(snapshot.timestamp);
                    let sustained = snapshot
                        .timestamp
                        .signed_duration_since(since)
                        .num_seconds();
                    if sustained >= trigger_duration_seconds as i64 {
                        // Only report "newly triggered" once, the caller
                        // clears the entry when it opens an incident so we
                        // don't re-fire every tick.
                        newly_triggered.push(kind);
                    }
                }
                _ => {
                    self.critical_since.remove(&kind);
                }
            }
        }

        DetectionResult {
            alert_levels,
            newly_triggered,
        }
    }

    /// Called by the incident manager once it has opened (or decided not
    /// to re-open) an incident for `kind`, so the same sustained condition
    /// doesn't immediately re-trigger on the next tick.
    pub fn acknowledge(&mut self, kind: ResourceKind) {
        self.critical_since.remove(&kind);
    }
}
