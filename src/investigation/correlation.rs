//! Correlation engine (FR-011).
//!
//! Given the pre-incident baseline, the incident window itself, and the
//! post-recovery window, ranks candidate processes by how well their
//! activity lines up with the triggering resource: did it ramp up before
//! the incident, dominate the contention during it, and fall back off
//! after recovery? That shape of evidence is what turns "disk = 100%"
//! into "Process-A, 91% confidence" (Section 12 / FR-011 example).

use crate::core::models::{ProcessSample, ResourceKind, RootCauseCandidate, RootCauseCategory, Snapshot};
use std::collections::HashMap;

fn metric_value(kind: ResourceKind, p: &ProcessSample) -> f64 {
    match kind {
        ResourceKind::Cpu => p.cpu_percent as f64,
        ResourceKind::Memory => p.memory_bytes as f64,
        ResourceKind::Disk => p.read_bytes_per_sec + p.write_bytes_per_sec,
        ResourceKind::Network => 0.0, // no per-process network accounting in the MVP
    }
}

fn average_by_name(snapshots: &[Snapshot], kind: ResourceKind) -> HashMap<String, f64> {
    let mut sums: HashMap<String, (f64, u32)> = HashMap::new();
    for snap in snapshots {
        // A process absent from a snapshot's top_processes list contributes
        // zero for that tick; we approximate this by only summing over
        // ticks where it actually appears and dividing by total tick count
        // captured in the caller, so silence still drags the average down.
        for p in &snap.top_processes {
            let v = metric_value(kind, p);
            let entry = sums.entry(p.name.clone()).or_insert((0.0, 0));
            entry.0 += v;
        }
    }
    let tick_count = snapshots.len().max(1) as f64;
    sums.into_iter()
        .map(|(name, (sum, _))| (name, sum / tick_count))
        .collect()
}

pub struct CorrelationInput<'a> {
    pub kind: ResourceKind,
    pub pre_incident: &'a [Snapshot],
    pub during_incident: &'a [Snapshot],
    pub post_recovery: &'a [Snapshot],
}

/// Returns candidates sorted best-first.
pub fn correlate(input: CorrelationInput<'_>) -> Vec<RootCauseCandidate> {
    if matches!(input.kind, ResourceKind::Network) {
        // No per-process network telemetry yet (documented adapter gap);
        // fall back to an empty candidate list so the root-cause engine
        // reports UNKNOWN with LOW evidence quality rather than guessing.
        return Vec::new();
    }

    let baseline = average_by_name(input.pre_incident, input.kind);
    let incident = average_by_name(input.during_incident, input.kind);
    let post = average_by_name(input.post_recovery, input.kind);

    let total_incident_activity: f64 = incident.values().sum::<f64>().max(1e-9);
    // A process contributing a sliver of a percent of total contention is
    // noise, not a candidate root cause — without this floor, a process
    // that merely went from "not observed" to "0.1% CPU" scores an
    // unearned ramp-up bonus that can outrank the process actually
    // responsible for the bulk of the incident.
    const MIN_SHARE_TO_CONSIDER: f64 = 0.02;

    let mut candidates: Vec<RootCauseCandidate> = incident
        .iter()
        .filter(|(_, v)| **v / total_incident_activity >= MIN_SHARE_TO_CONSIDER)
        .map(|(name, incident_avg)| {
            let baseline_avg = baseline.get(name).copied().unwrap_or(0.0);
            let post_avg = post.get(name).copied().unwrap_or(0.0);

            let increase_ratio = if baseline_avg > 1e-9 {
                (incident_avg - baseline_avg) / baseline_avg
            } else if *incident_avg > 0.0 {
                2.0 // no measurable baseline activity at all -> treat as a strong ramp-up
            } else {
                0.0
            };
            let recovered_ratio = if *incident_avg > 1e-9 {
                ((incident_avg - post_avg) / incident_avg).clamp(0.0, 1.0)
            } else {
                0.0
            };
            let share = (incident_avg / total_incident_activity).clamp(0.0, 1.0);

            let ramp_score = (increase_ratio / 2.0).clamp(0.0, 1.0) * 100.0;
            let recovery_score = recovered_ratio * 100.0;
            let share_score = share * 100.0;

            // Share of total contention is the most robust signal (it's
            // hard to fake being 98% of the load); ramp-up and recovery
            // shape are corroborating evidence, weighted lower.
            let score = (0.55 * share_score + 0.25 * ramp_score + 0.20 * recovery_score) as f32;

            let mut reasons = Vec::new();
            reasons.push(format!(
                "{name} activity averaged {incident_avg:.1} during the incident window versus {baseline_avg:.1} beforehand."
            ));
            if recovered_ratio > 0.3 {
                reasons.push(format!(
                    "{name} activity dropped by {:.0}% after the resource recovered.",
                    recovered_ratio * 100.0
                ));
            }
            reasons.push(format!(
                "{name} accounted for {:.0}% of total contention observed during the incident.",
                share * 100.0
            ));

            RootCauseCandidate {
                label: name.clone(),
                category: RootCauseCategory::Process,
                score: score.clamp(0.0, 100.0),
                reasons,
            }
        })
        .collect();

    candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    candidates.truncate(5);
    candidates
}
