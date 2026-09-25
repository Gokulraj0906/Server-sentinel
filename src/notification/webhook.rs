//! Webhook notifier: Slack / Discord incoming webhooks, Microsoft Teams
//! Workflows, or any endpoint that accepts JSON (PagerDuty Events via a
//! relay, n8n, Zapier, your own API).

use crate::core::config::WebhookNotificationConfig;
use crate::core::models::IncidentReport;
use crate::notification::http::post_json;
use crate::notification::{AlertNotice, Notifier};
use anyhow::{anyhow, Result};
use serde_json::json;

pub struct WebhookNotifier {
    config: WebhookNotificationConfig,
}

impl WebhookNotifier {
    pub fn new(config: WebhookNotificationConfig) -> Self {
        Self { config }
    }

    fn post(&self, text: String, generic: serde_json::Value) -> Result<()> {
        if self.config.url.is_empty() {
            return Err(anyhow!("notification.webhook.url is empty (or set SENTINEL_WEBHOOK_URL)"));
        }
        let body = match self.config.format.as_str() {
            "slack" | "teams" => json!({ "text": text }),
            "discord" => json!({ "content": crate::util::truncate(&text, 1900) }),
            _ => generic,
        };
        let (code, status) = post_json(&self.config.url, &[], &body.to_string())?;
        if !(200..300).contains(&code) {
            return Err(anyhow!("webhook returned {status}"));
        }
        Ok(())
    }
}

impl Notifier for WebhookNotifier {
    fn name(&self) -> &'static str {
        "webhook"
    }

    fn notify(&self, report: &IncidentReport) -> Result<()> {
        let text = format!(
            "🚨 *{} {} incident on {}* — probable cause: {} ({:.0}% confidence){}",
            report.severity,
            report.incident_type,
            report.server_name,
            report.root_cause.probable_cause,
            report.root_cause.confidence_percent,
            if report.related_activity.is_empty() {
                String::new()
            } else {
                format!(
                    "\nPreceded by: {}",
                    report
                        .related_activity
                        .iter()
                        .take(3)
                        .map(|r| r.summary.clone())
                        .collect::<Vec<_>>()
                        .join("; ")
                )
            }
        );
        self.post(text, json!({ "type": "incident", "incident": report }))
    }

    fn notify_alert(&self, alert: &AlertNotice) -> Result<()> {
        let icon = match alert.severity {
            crate::events::Severity::Critical => "🔴",
            crate::events::Severity::High => "🟠",
            _ => "🟡",
        };
        let text = format!("{icon} *ServerSentinel* {}", alert.text_body());
        self.post(text, json!({ "type": "alert", "alert": alert }))
    }
}
