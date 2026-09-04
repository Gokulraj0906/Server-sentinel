//! Root cause engine (FR-012, FR-013, FR-014).
//!
//! Deliberately conservative: if the evidence doesn't clearly point at one
//! candidate, this reports UNKNOWN with LOW evidence quality rather than
//! guessing. "The system should not pretend to know something it cannot
//! prove" (FR-014).

use crate::core::models::{
    EvidenceQuality, ResourceKind, RootCauseCandidate, RootCauseCategory, RootCauseConclusion,
};

const MIN_CONFIDENCE_FOR_CONCLUSION: f32 = 40.0;

fn general_category_for(kind: ResourceKind) -> RootCauseCategory {
    match kind {
        ResourceKind::Cpu => RootCauseCategory::Cpu,
        ResourceKind::Memory => RootCauseCategory::Memory,
        ResourceKind::Disk => RootCauseCategory::Storage,
        ResourceKind::Network => RootCauseCategory::Network,
    }
}

pub fn conclude(kind: ResourceKind, candidates: &[RootCauseCandidate]) -> RootCauseConclusion {
    let best = candidates.first();

    match best {
        Some(candidate) if candidate.score >= MIN_CONFIDENCE_FOR_CONCLUSION => {
            let evidence_quality = if candidate.score >= 80.0 {
                EvidenceQuality::High
            } else if candidate.score >= 55.0 {
                EvidenceQuality::Medium
            } else {
                EvidenceQuality::Low
            };

            RootCauseConclusion {
                probable_cause: candidate.label.clone(),
                category: candidate.category,
                confidence_percent: candidate.score,
                evidence_quality,
                reason_if_unknown: None,
                candidates_considered: candidates.to_vec(),
            }
        }
        Some(candidate) => {
            // Some signal, but not enough for a specific process-level
            // conclusion: attribute to the resource itself rather than a
            // single process the evidence doesn't clearly support.
            RootCauseConclusion {
                probable_cause: format!(
                    "Unknown — no single process clearly dominated {kind} contention"
                ),
                category: general_category_for(kind),
                confidence_percent: candidate.score,
                evidence_quality: EvidenceQuality::Low,
                reason_if_unknown: Some(
                    "Multiple processes contributed without a clearly dominant contributor; \
                     insufficient telemetry to isolate a single root cause."
                        .to_string(),
                ),
                candidates_considered: candidates.to_vec(),
            }
        }
        None => RootCauseConclusion {
            probable_cause: "Unknown".to_string(),
            category: RootCauseCategory::Unknown,
            confidence_percent: 0.0,
            evidence_quality: EvidenceQuality::Low,
            reason_if_unknown: Some(
                "Insufficient telemetry was available during the incident window.".to_string(),
            ),
            candidates_considered: Vec::new(),
        },
    }
}
