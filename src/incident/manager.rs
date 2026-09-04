//! Incident manager (FR-008, FR-009, FR-016).
//!
//! Owns the incident state machine:
//!
//! ```text
//! Normal -> [sustained critical] -> Investigation -> [sustained recovery
//!   + post-recovery window elapsed] -> Report -> Normal
//! ```
//!
//! It does not decide *whether* a resource is currently critical (that's
//! `detection::engine`) or *who* is to blame (that's `investigation` +
//! `rootcause`) — it only owns the window bookkeeping and stitches those
//! two together into a finished `IncidentReport`.

use crate::core::models::{
    AgentMode, ImpactSummary, IncidentReport, Recommendations, ResourceKind, Snapshot,
};
use crate::incident::evidence::build_evidence;
use crate::incident::timeline::build_timeline;
use crate::investigation::engine::{investigate, InvestigationWindow};
use crate::rootcause::scoring::conclude;
use chrono::Utc;
use uuid::Uuid;

struct ActiveIncident {
    id: String,
    kind: ResourceKind,
    critical_threshold: f32,
    start_time: chrono::DateTime<Utc>,
    pre_incident: Vec<Snapshot>,
    during_incident: Vec<Snapshot>,
    post_recovery: Vec<Snapshot>,
    recovering_since: Option<chrono::DateTime<Utc>>,
    recovered_at: Option<chrono::DateTime<Utc>>,
}

pub enum FeedOutcome {
    StillInvestigating,
    Finalized(Box<IncidentReport>),
}

pub struct IncidentManager {
    active: Option<ActiveIncident>,
    server_name: String,
    os_label: String,
    environment: String,
    incident_sequence: u32,
}

#[allow(dead_code)] // mode()/active_kind() are public API for future consumers (dashboard, tests)
impl IncidentManager {
    pub fn new(server_name: String, os_label: String, environment: String) -> Self {
        Self {
            active: None,
            server_name,
            os_label,
            environment,
            incident_sequence: 0,
        }
    }

    pub fn mode(&self) -> AgentMode {
        if self.active.is_some() {
            AgentMode::Investigation
        } else {
            AgentMode::Normal
        }
    }

    pub fn is_active(&self) -> bool {
        self.active.is_some()
    }

    pub fn active_kind(&self) -> Option<ResourceKind> {
        self.active.as_ref().map(|a| a.kind)
    }

    /// Opens a new incident. `pre_incident` should be the ring-buffer
    /// contents strictly before `trigger_snapshot.timestamp` (FR-009).
    pub fn open(
        &mut self,
        kind: ResourceKind,
        critical_threshold: f32,
        trigger_snapshot: Snapshot,
        pre_incident: Vec<Snapshot>,
    ) {
        self.incident_sequence += 1;
        let id = format!(
            "INC-{}-{:06}",
            Utc::now().format("%Y"),
            self.incident_sequence
        );
        tracing::warn!(incident_id = %id, resource = %kind, "incident detected, entering investigation mode");
        self.active = Some(ActiveIncident {
            id,
            kind,
            critical_threshold,
            start_time: trigger_snapshot.timestamp,
            pre_incident,
            during_incident: vec![trigger_snapshot],
            post_recovery: Vec::new(),
            recovering_since: None,
            recovered_at: None,
        });
    }

    /// Feeds one more snapshot into the active incident. Returns
    /// `Finalized` once the post-recovery window has fully elapsed.
    pub fn feed(
        &mut self,
        snapshot: Snapshot,
        recovery_duration_seconds: u64,
        post_recovery_seconds: u64,
    ) -> FeedOutcome {
        let Some(active) = self.active.as_mut() else {
            return FeedOutcome::StillInvestigating;
        };

        let value = snapshot.resource_value(active.kind);
        let now = snapshot.timestamp;

        if active.recovered_at.is_none() {
            if value < active.critical_threshold {
                let since = *active.recovering_since.get_or_insert(now);
                if now.signed_duration_since(since).num_seconds() >= recovery_duration_seconds as i64
                {
                    active.recovered_at = Some(since);
                    tracing::info!(incident_id = %active.id, "resource recovered, entering post-recovery evidence window");
                }
            } else {
                active.recovering_since = None;
            }
            active.during_incident.push(snapshot);
        } else {
            active.post_recovery.push(snapshot);
        }

        let ready_to_finalize = active
            .recovered_at
            .map(|recovered_at| {
                now.signed_duration_since(recovered_at).num_seconds()
                    >= post_recovery_seconds as i64
            })
            .unwrap_or(false);

        if !ready_to_finalize {
            return FeedOutcome::StillInvestigating;
        }

        let finished = self.active.take().expect("checked Some above");
        FeedOutcome::Finalized(Box::new(self.build_report(finished)))
    }

    fn build_report(&self, incident: ActiveIncident) -> IncidentReport {
        let window = InvestigationWindow {
            pre_incident: incident.pre_incident.clone(),
            during_incident: incident.during_incident.clone(),
            post_recovery: incident.post_recovery.clone(),
        };
        let candidates = investigate(incident.kind, &window);
        let root_cause = conclude(incident.kind, &candidates);
        let evidence = build_evidence(incident.kind, &root_cause, &incident.during_incident);
        let timeline = build_timeline(
            incident.kind,
            &incident.pre_incident,
            &incident.during_incident,
            &incident.post_recovery,
        );

        let end_time = incident
            .post_recovery
            .last()
            .or_else(|| incident.during_incident.last())
            .map(|s| s.timestamp);
        let duration_seconds =
            end_time.map(|end| end.signed_duration_since(incident.start_time).num_seconds());

        let severity = incident
            .during_incident
            .iter()
            .filter_map(|s| s.alert_levels.get(&incident.kind).copied())
            .max()
            .unwrap_or(crate::core::models::AlertLevel::Critical);

        let impact = ImpactSummary {
            affected_resources: vec![incident.kind.to_string()],
            affected_applications: root_cause
                .candidates_considered
                .first()
                .map(|c| vec![c.label.clone()])
                .unwrap_or_default(),
            potential_downtime: "No downtime confirmed; performance degradation only.".to_string(),
            performance_impact: format!(
                "Server experienced a {} incident lasting approximately {} seconds.",
                incident.kind,
                duration_seconds.unwrap_or(0)
            ),
        };

        let recommendations = Recommendations {
            recommended_investigation: vec![format!(
                "Review {} activity, scheduled operations, and associated application/service events around {}.",
                root_cause.probable_cause,
                incident.start_time.format("%Y-%m-%d %H:%M:%S UTC")
            )],
            recommended_corrective_action: vec![
                "No automatic remediation was taken (out of scope for this release); \
                 investigate manually before making changes."
                    .to_string(),
            ],
        };

        IncidentReport {
            incident_id: incident.id,
            server_name: self.server_name.clone(),
            operating_system: self.os_label.clone(),
            environment: self.environment.clone(),
            incident_type: incident.kind,
            severity,
            start_time: incident.start_time,
            end_time,
            duration_seconds,
            root_cause,
            evidence,
            timeline,
            impact,
            recommendations,
            generated_at: Utc::now(),
        }
    }
}

// Re-export so callers don't need to depend on `uuid` directly for the
// (currently unused, reserved for future central-platform correlation ID)
// incident correlation UUID.
#[allow(dead_code)]
pub fn new_correlation_id() -> Uuid {
    Uuid::new_v4()
}
