//! Links performance incidents to the security/change timeline.
//!
//! This is the question nobody's monitoring answers out of the box: the
//! CPU incident at 14:05 is useful; "and at 14:02 alice edited
//! nginx.conf over SSH and restarted nginx" is the actual root cause.

use crate::core::models::{EvidenceItem, IncidentReport, RelatedActivity};
use crate::events::Category;
use crate::storage::event_store::EventStore;
use crate::util::truncate;
use chrono::Duration;

/// How far back before an incident's onset changes are considered.
pub const LOOKBACK_MINUTES: i64 = 30;

pub fn attach(report: &mut IncidentReport, store: &EventStore) {
    let from = report.start_time - Duration::minutes(LOOKBACK_MINUTES);
    let to = report.end_time.unwrap_or(report.start_time);
    let events = match store.related_activity(from, to, 60) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "could not load change history for incident correlation");
            return;
        }
    };
    report.related_activity = events
        .iter()
        .map(|ev| {
            let who = ev.user.as_deref().map(|u| format!(" by {u}")).unwrap_or_default();
            let summary = match ev.category {
                Category::File | Category::Package | Category::Service => format!("{}{who}", ev.message),
                _ => ev.message.clone(),
            };
            RelatedActivity {
                ts: ev.ts,
                event_id: ev.id,
                action: ev.action.clone(),
                user: ev.user.clone(),
                session_id: ev.session_id.clone(),
                summary: truncate(&summary, 300),
                offset_seconds: (ev.ts - report.start_time).num_seconds(),
            }
        })
        .collect();

    let is_change = |a: &str| a.starts_with("file.") || a.starts_with("package.") || a.starts_with("service.");

    // A change that names the suspected culprit is strong corroboration:
    // "nginx upgraded 2m before nginx saturated the CPU". Nearest first.
    let culprit = report.root_cause.probable_cause.to_ascii_lowercase();
    let culprit_stem = culprit.trim_end_matches(".exe");
    let mut evidence = Vec::new();
    if culprit_stem.len() >= 3 && !culprit.starts_with("unknown") {
        let mut hits: Vec<&RelatedActivity> = report
            .related_activity
            .iter()
            .filter(|r| r.offset_seconds <= 0 && is_change(&r.action))
            .filter(|r| r.summary.to_ascii_lowercase().contains(culprit_stem))
            .collect();
        hits.sort_by_key(|r| -r.offset_seconds);
        for r in hits.into_iter().take(3) {
            evidence.push(EvidenceItem {
                description: format!(
                    "Change involving {} {} before onset: {}",
                    report.root_cause.probable_cause,
                    human_offset(-r.offset_seconds),
                    truncate(&r.summary, 200)
                ),
            });
        }
    }
    let changes: Vec<&RelatedActivity> = report
        .related_activity
        .iter()
        .filter(|r| r.offset_seconds <= 0 && is_change(&r.action))
        .collect();
    let changes_before = changes.len();
    if let Some(latest) = changes.iter().max_by_key(|r| r.offset_seconds) {
        evidence.push(EvidenceItem {
            description: format!(
                "Most recent change before onset ({} earlier): {}",
                human_offset(-latest.offset_seconds),
                truncate(&latest.summary, 200)
            ),
        });
    }
    if changes_before > 0 {
        evidence.push(EvidenceItem {
            description: format!(
                "{changes_before} configuration/package/service change(s) were recorded in the {LOOKBACK_MINUTES} minutes before onset (see \"What changed before this incident\")."
            ),
        });
    }
    // Put change evidence first: it's the most actionable.
    evidence.append(&mut report.evidence);
    report.evidence = evidence;
}

fn human_offset(secs: i64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m {}s", s / 60, s % 60),
        s => format!("{}h {}m", s / 3600, (s % 3600) / 60),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::*;
    use crate::events::{Category, Event, Severity};
    use chrono::Utc;

    fn report(cause: &str) -> IncidentReport {
        let now = Utc::now();
        IncidentReport {
            incident_id: "INC-2026-000009".into(),
            server_name: "web1".into(),
            operating_system: "Linux".into(),
            environment: "production".into(),
            incident_type: ResourceKind::Cpu,
            severity: AlertLevel::Critical,
            start_time: now,
            end_time: Some(now + Duration::seconds(60)),
            duration_seconds: Some(60),
            root_cause: RootCauseConclusion {
                probable_cause: cause.into(),
                category: RootCauseCategory::Process,
                confidence_percent: 80.0,
                evidence_quality: EvidenceQuality::High,
                reason_if_unknown: None,
                candidates_considered: vec![],
            },
            evidence: vec![EvidenceItem { description: "original evidence".into() }],
            timeline: vec![],
            impact: ImpactSummary {
                affected_resources: vec![],
                affected_applications: vec![],
                potential_downtime: String::new(),
                performance_impact: String::new(),
            },
            recommendations: Recommendations {
                recommended_investigation: vec![],
                recommended_corrective_action: vec![],
            },
            related_activity: vec![],
            generated_at: now,
        }
    }

    #[test]
    fn links_preceding_changes_and_names_the_culprit() {
        let mut store = EventStore::open_in_memory().unwrap();
        let mut rep = report("nginx");
        let t0 = rep.start_time;
        store
            .write_batch(|w| {
                let mut evs = [
                    Event::new(Category::Package, "package.upgraded", "Upgraded package nginx 1.22 -> 1.24")
                        .at(t0 - Duration::minutes(3)),
                    Event::new(Category::File, "file.modified", "Modified /etc/nginx/nginx.conf (+1 -1)")
                        .at(t0 - Duration::seconds(40))
                        .user("alice"),
                    // Alerts aren't changes and must not become culprit evidence.
                    Event::new(Category::Alert, "alert.x", "nginx something suspicious")
                        .at(t0 - Duration::minutes(1))
                        .severity(Severity::High),
                    // Outside the lookback window.
                    Event::new(Category::File, "file.modified", "Modified /etc/nginx/old.conf").at(t0 - Duration::hours(2)),
                ];
                for e in evs.iter_mut() {
                    w.insert_event(e)?;
                }
                Ok(())
            })
            .unwrap();
        attach(&mut rep, &store);
        assert_eq!(rep.related_activity.len(), 3);
        let ev: Vec<&str> = rep.evidence.iter().map(|e| e.description.as_str()).collect();
        assert!(ev[0].starts_with("Change involving nginx 40s before onset: Modified /etc/nginx/nginx.conf"), "{ev:?}");
        assert!(ev[1].starts_with("Change involving nginx 3m 0s before onset: Upgraded package nginx"), "{ev:?}");
        assert!(ev.iter().any(|e| e.starts_with("Most recent change before onset (40s earlier)")));
        assert!(!ev.iter().any(|e| e.contains("suspicious")));
        assert_eq!(*ev.last().unwrap(), "original evidence");
    }
}
