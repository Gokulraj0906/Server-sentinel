//! Evidence list assembly for the final report.
//!
//! Combines the correlation engine's reasoning about the winning candidate
//! with a few cross-resource sanity checks (Section 30 example report:
//! "No significant CPU or memory anomaly was detected").

use crate::core::models::{AlertLevel, EvidenceItem, ResourceKind, RootCauseConclusion, Snapshot};

pub fn build_evidence(
    kind: ResourceKind,
    conclusion: &RootCauseConclusion,
    during_incident: &[Snapshot],
) -> Vec<EvidenceItem> {
    let mut evidence = Vec::new();

    if let Some(best) = conclusion.candidates_considered.first() {
        for reason in &best.reasons {
            evidence.push(EvidenceItem {
                description: reason.clone(),
            });
        }
    }

    if let Some(reason) = &conclusion.reason_if_unknown {
        evidence.push(EvidenceItem {
            description: reason.clone(),
        });
    }

    // Cross-check the other resources during the same window: if they
    // stayed normal, that's evidence in its own right (it narrows the
    // investigation and rules out a system-wide overload).
    let other_kinds = [
        ResourceKind::Cpu,
        ResourceKind::Memory,
        ResourceKind::Disk,
        ResourceKind::Network,
    ];
    for other in other_kinds {
        if other == kind {
            continue;
        }
        let stayed_normal = during_incident.iter().all(|s| {
            s.alert_levels.get(&other).copied().unwrap_or(AlertLevel::Normal) == AlertLevel::Normal
        });
        if stayed_normal && !during_incident.is_empty() {
            evidence.push(EvidenceItem {
                description: format!("No significant {other} anomaly was detected during the incident window."),
            });
        }
    }

    evidence
}
