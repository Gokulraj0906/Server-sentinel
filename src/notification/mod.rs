//! Notifications (FR-017).
//!
//! Console output is always on (so the agent is useful standalone with
//! zero configuration). Email and webhooks (Slack / Discord / Teams /
//! generic JSON) are opt-in. Delivery runs on its own worker thread: a
//! slow SMTP server must never stall event ingestion or the monitoring
//! loop.

pub mod console;
pub mod email;
pub mod http;
pub mod webhook;

use crate::core::models::IncidentReport;
use crate::events::{Event, Severity};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A security alert, flattened for humans and webhook payloads.
#[derive(Debug, Clone, Serialize)]
pub struct AlertNotice {
    pub ts: DateTime<Utc>,
    pub host: String,
    pub rule: String,
    pub severity: Severity,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<i64>,
}

impl AlertNotice {
    pub fn from_event(ev: &Event) -> Self {
        Self {
            ts: ev.ts,
            host: ev.host.clone(),
            rule: ev.detail_str("rule").unwrap_or(&ev.action).to_string(),
            severity: ev.severity,
            title: ev.message.clone(),
            user: ev.user.clone(),
            src_ip: ev.src_ip.clone(),
            session_id: ev.session_id.clone(),
            target: ev.target.clone(),
            command_line: ev.command_line().map(String::from),
            event_id: ev.id,
        }
    }

    /// Plain-text body shared by the email and chat notifiers.
    pub fn text_body(&self) -> String {
        let mut lines = vec![
            format!("[{}] {}", self.severity.as_str().to_uppercase(), self.title),
            format!("Host: {}", self.host),
            format!("Time: {}", self.ts.format("%Y-%m-%d %H:%M:%S UTC")),
        ];
        if let Some(u) = &self.user {
            lines.push(format!("User: {u}"));
        }
        if let Some(ip) = &self.src_ip {
            lines.push(format!("Source: {ip}"));
        }
        if let Some(t) = &self.target {
            lines.push(format!("Target: {t}"));
        }
        if let Some(c) = &self.command_line {
            lines.push(format!("Command: {c}"));
        }
        if let Some(s) = &self.session_id {
            lines.push(format!("Session: {s}   (on the host: server-sentinel session {s})"));
        }
        lines.push(format!("Rule: {}", self.rule));
        lines.join("\n")
    }
}

pub trait Notifier: Send {
    fn name(&self) -> &'static str;
    fn notify(&self, report: &IncidentReport) -> Result<()>;
    fn notify_alert(&self, _alert: &AlertNotice) -> Result<()> {
        Ok(())
    }
}

enum Job {
    Incident(Box<IncidentReport>),
    Alert(Box<AlertNotice>),
}

/// Cloneable, non-blocking handle to the notification worker.
#[derive(Clone)]
pub struct NotifyHandle {
    tx: SyncSender<Job>,
}

impl NotifyHandle {
    pub fn incident(&self, report: &IncidentReport) {
        self.send(Job::Incident(Box::new(report.clone())));
    }

    pub fn alert(&self, alert: AlertNotice) {
        self.send(Job::Alert(Box::new(alert)));
    }

    fn send(&self, job: Job) {
        match self.tx.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                tracing::warn!("notification queue full; dropping notification (it is still stored and searchable)")
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

pub struct NotificationDispatcher {
    handle: NotifyHandle,
    worker: Option<JoinHandle<()>>,
}

/// Hard ceiling on alert notifications per hour. Beyond it alerts are
/// still stored and searchable; people just stop getting paged, and get a
/// summary instead. An attack that generates 500 pages is a DoS on the
/// on-call human.
const MAX_ALERT_NOTIFICATIONS_PER_HOUR: usize = 30;

impl NotificationDispatcher {
    pub fn spawn(notifiers: Vec<Box<dyn Notifier>>) -> Self {
        let (tx, rx) = sync_channel(256);
        let worker = std::thread::Builder::new()
            .name("notify".into())
            .spawn(move || run_worker(notifiers, rx))
            .expect("spawning notification worker");
        Self {
            handle: NotifyHandle { tx },
            worker: Some(worker),
        }
    }

    pub fn handle(&self) -> NotifyHandle {
        self.handle.clone()
    }

    pub fn dispatch(&self, report: &IncidentReport) {
        self.handle.incident(report);
    }

    /// Drains queued notifications (bounded wait) before exit.
    pub fn shutdown(mut self) {
        let NotificationDispatcher { handle, worker } = &mut self;
        let (dead_tx, _) = sync_channel(1);
        *handle = NotifyHandle { tx: dead_tx };
        if let Some(w) = worker.take() {
            let deadline = Instant::now() + Duration::from_secs(20);
            while !w.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
            if w.is_finished() {
                let _ = w.join();
            } else {
                tracing::warn!("notification worker still busy at shutdown; exiting anyway");
            }
        }
    }
}

fn run_worker(notifiers: Vec<Box<dyn Notifier>>, rx: Receiver<Job>) {
    let mut sent_this_hour: Vec<Instant> = Vec::new();
    let mut suppressed = 0usize;
    for job in rx {
        match job {
            Job::Incident(report) => {
                for n in &notifiers {
                    if let Err(e) = n.notify(&report) {
                        tracing::error!(notifier = n.name(), error = %e, "incident notification failed");
                    }
                }
            }
            Job::Alert(alert) => {
                sent_this_hour.retain(|t| t.elapsed() < Duration::from_secs(3600));
                if sent_this_hour.len() >= MAX_ALERT_NOTIFICATIONS_PER_HOUR {
                    suppressed += 1;
                    continue;
                }
                let alert = if suppressed > 0 {
                    let mut a = *alert;
                    a.title = format!("{} (+{suppressed} more alerts suppressed by rate limit; see `server-sentinel alerts`)", a.title);
                    suppressed = 0;
                    a
                } else {
                    *alert
                };
                sent_this_hour.push(Instant::now());
                for n in &notifiers {
                    if let Err(e) = n.notify_alert(&alert) {
                        tracing::error!(notifier = n.name(), error = %e, "alert notification failed");
                    }
                }
            }
        }
    }
}
