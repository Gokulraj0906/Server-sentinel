use crate::core::models::IncidentReport;
use crate::notification::{AlertNotice, Notifier};
use anyhow::Result;

pub struct ConsoleNotifier;

impl Notifier for ConsoleNotifier {
    fn name(&self) -> &'static str {
        "console"
    }

    fn notify(&self, report: &IncidentReport) -> Result<()> {
        let related = if report.related_activity.is_empty() {
            String::new()
        } else {
            format!("Changes/access just before: {} (see report)\n", report.related_activity.len())
        };
        println!(
            "\n🚨 {} INCIDENT\nServer: {}\nProblem: {} saturation\nDuration: {}\nProbable Cause: {}\nConfidence: {:.0}%\n{}Incident: {}\n",
            report.severity,
            report.server_name,
            report.incident_type,
            report
                .duration_seconds
                .map(|d| format!("{d} seconds"))
                .unwrap_or_else(|| "in progress".to_string()),
            report.root_cause.probable_cause,
            report.root_cause.confidence_percent,
            related,
            report.incident_id
        );
        Ok(())
    }

    fn notify_alert(&self, alert: &AlertNotice) -> Result<()> {
        println!("\n🔐 SECURITY ALERT\n{}\n", alert.text_body());
        Ok(())
    }
}
