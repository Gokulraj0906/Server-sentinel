//! JSON serialization of the incident report (FR-016, FR-019).

use crate::core::models::IncidentReport;
use anyhow::Result;

pub fn to_json_pretty(report: &IncidentReport) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}
