//! Investigation engine (FR-010).
//!
//! Its job is narrow: once an incident is open, decide what counts as
//! "the incident window" (pre / during / post) and hand that window to the
//! correlation engine. The state-machine for *when* an incident opens and
//! closes lives in `incident::manager`; this module is purely the evidence
//! assembly step.

use crate::core::models::{ResourceKind, Snapshot};
use crate::investigation::correlation::{correlate, CorrelationInput};
use crate::core::models::RootCauseCandidate;

pub struct InvestigationWindow {
    pub pre_incident: Vec<Snapshot>,
    pub during_incident: Vec<Snapshot>,
    pub post_recovery: Vec<Snapshot>,
}

pub fn investigate(kind: ResourceKind, window: &InvestigationWindow) -> Vec<RootCauseCandidate> {
    correlate(CorrelationInput {
        kind,
        pre_incident: &window.pre_incident,
        during_incident: &window.during_incident,
        post_recovery: &window.post_recovery,
    })
}
