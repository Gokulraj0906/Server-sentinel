//! Incident timeline construction (FR-015).

use crate::core::models::{AlertLevel, ResourceKind, Snapshot, TimelineEvent};

fn metric_for(kind: ResourceKind, snap: &Snapshot) -> f32 {
    snap.resource_value(kind)
}

pub fn build_timeline(
    kind: ResourceKind,
    pre_incident: &[Snapshot],
    during_incident: &[Snapshot],
    post_recovery: &[Snapshot],
) -> Vec<TimelineEvent> {
    let mut events = Vec::new();

    if let Some(first) = pre_incident.first() {
        events.push(TimelineEvent {
            timestamp: first.timestamp,
            description: "Server normal".to_string(),
        });
    }

    // Walk the combined, chronologically ordered snapshot list and record
    // alert-level transitions plus the peak of the triggering metric.
    let mut all: Vec<&Snapshot> = pre_incident.iter().chain(during_incident.iter()).chain(post_recovery.iter()).collect();
    all.sort_by_key(|s| s.timestamp);

    let mut last_level = AlertLevel::Normal;
    let mut peak: Option<&Snapshot> = None;
    let mut investigation_marked = false;

    for snap in &all {
        let level = snap
            .alert_levels
            .get(&kind)
            .copied()
            .unwrap_or(AlertLevel::Normal);

        if level != last_level {
            let description = match level {
                AlertLevel::Warning if last_level == AlertLevel::Normal => "Resource warning",
                AlertLevel::Critical => "Critical threshold crossed",
                AlertLevel::Warning => "Resource level decreased to warning",
                AlertLevel::Normal => "Recovery started",
            };
            events.push(TimelineEvent {
                timestamp: snap.timestamp,
                description: description.to_string(),
            });
            if level == AlertLevel::Critical && !investigation_marked {
                events.push(TimelineEvent {
                    timestamp: snap.timestamp,
                    description: "Investigation started".to_string(),
                });
                investigation_marked = true;
            }
        }
        last_level = level;

        let value = metric_for(kind, snap);
        let is_new_peak = match peak {
            None => true,
            Some(p) => value > metric_for(kind, p),
        };
        if is_new_peak {
            peak = Some(snap);
        }
    }

    if let Some(peak_snap) = peak {
        events.push(TimelineEvent {
            timestamp: peak_snap.timestamp,
            description: "Peak activity".to_string(),
        });
    }

    if let Some(last) = post_recovery.last().or_else(|| during_incident.last()) {
        events.push(TimelineEvent {
            timestamp: last.timestamp,
            description: "Server normal".to_string(),
        });
        events.push(TimelineEvent {
            timestamp: last.timestamp,
            description: "Investigation completed".to_string(),
        });
    }

    events.sort_by_key(|e| e.timestamp);
    events
}
