//! Notifications (FR-017).
//!
//! Console output is always on (so the agent is useful standalone with
//! zero configuration). Email is an optional, config-gated adapter — the
//! `Notifier` trait is the extension point future channels (Teams, Slack,
//! Telegram, webhooks, mobile push) plug into.

pub mod console;
pub mod email;

use crate::core::models::IncidentReport;
use anyhow::Result;

pub trait Notifier: Send {
    fn notify(&self, report: &IncidentReport) -> Result<()>;
}

pub struct NotificationDispatcher {
    notifiers: Vec<Box<dyn Notifier>>,
}

impl NotificationDispatcher {
    pub fn new(notifiers: Vec<Box<dyn Notifier>>) -> Self {
        Self { notifiers }
    }

    pub fn dispatch(&self, report: &IncidentReport) {
        for notifier in &self.notifiers {
            if let Err(e) = notifier.notify(report) {
                tracing::error!(error = %e, "notifier failed");
            }
        }
    }
}
