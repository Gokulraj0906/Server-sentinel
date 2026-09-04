use crate::core::models::IncidentReport;
use crate::notification::Notifier;
use anyhow::Result;

pub struct ConsoleNotifier;

impl Notifier for ConsoleNotifier {
    fn notify(&self, report: &IncidentReport) -> Result<()> {
        println!(
            "\n🚨 {} INCIDENT\nServer: {}\nProblem: {} saturation\nDuration: {}\nProbable Cause: {}\nConfidence: {:.0}%\nIncident: {}\n",
            report.severity,
            report.server_name,
            report.incident_type,
            report
                .duration_seconds
                .map(|d| format!("{d} seconds"))
                .unwrap_or_else(|| "in progress".to_string()),
            report.root_cause.probable_cause,
            report.root_cause.confidence_percent,
            report.incident_id
        );
        Ok(())
    }
}
