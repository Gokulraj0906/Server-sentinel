//! Unified security/audit event model.
//!
//! Every audit collector (auth logs, Windows event log, process exec,
//! file integrity, services, packages) emits the same `Event` shape, so
//! storage, search, session attribution, rules and forwarding never need
//! to know which OS or source an event came from. Field names follow the
//! spirit of the Elastic Common Schema (`user`, `source.ip`, `process.*`,
//! `event.action`) so forwarded NDJSON drops into an existing SIEM with
//! minimal mapping.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::mpsc::SyncSender;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn as_i64(self) -> i64 {
        self as i64
    }

    pub fn from_i64(v: i64) -> Self {
        match v {
            i64::MIN..=0 => Severity::Info,
            1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            _ => Severity::Critical,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "info" | "0" => Some(Severity::Info),
            "low" | "1" => Some(Severity::Low),
            "medium" | "med" | "2" => Some(Severity::Medium),
            "high" | "3" => Some(Severity::High),
            "critical" | "crit" | "4" => Some(Severity::Critical),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Authentication attempts that don't (by themselves) open an
    /// interactive session: failures, network logons, unlocks.
    Auth,
    /// Interactive access: SSH, RDP, console. Start/end/disconnect.
    Session,
    /// Process executions.
    Process,
    /// sudo / su / elevation.
    Privilege,
    /// User and group management.
    Account,
    /// File integrity: created / modified / deleted / permissions.
    File,
    Service,
    Package,
    /// Produced by the rule engine, never by a collector.
    Alert,
    /// Performance incident lifecycle (from the incident engine).
    Incident,
    /// The agent's own health / tamper signals.
    Agent,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Auth => "auth",
            Category::Session => "session",
            Category::Process => "process",
            Category::Privilege => "privilege",
            Category::Account => "account",
            Category::File => "file",
            Category::Service => "service",
            Category::Package => "package",
            Category::Alert => "alert",
            Category::Incident => "incident",
            Category::Agent => "agent",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "auth" => Category::Auth,
            "session" => Category::Session,
            "process" => Category::Process,
            "privilege" => Category::Privilege,
            "account" => Category::Account,
            "file" => Category::File,
            "service" => Category::Service,
            "package" => Category::Package,
            "alert" => Category::Alert,
            "incident" => Category::Incident,
            "agent" => Category::Agent,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Failure,
    Unknown,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Success => "success",
            Outcome::Failure => "failure",
            Outcome::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "success" => Outcome::Success,
            "failure" => Outcome::Failure,
            _ => Outcome::Unknown,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u32>,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_name: Option<String>,
    /// The account the process actually runs as (effective user). The
    /// event-level `user` is the *human* responsible (e.g. the login user
    /// behind a sudo), which is what investigations care about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_as: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub ts: DateTime<Utc>,
    #[serde(default)]
    pub host: String,
    pub category: Category,
    pub action: String,
    pub outcome: Outcome,
    pub severity: Severity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInfo>,
    /// What was acted on: a file path, account, service, package...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub message: String,
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub details: serde_json::Value,
    /// Content-addressed blobs holding the file content before / after a
    /// file change (so an investigator can see what it *was*).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_sha: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,

    /// Session-lookup keys ("pid:1234", "ksid:7", "tty:pts/0",
    /// "logon:0x3e7", "ts:2"). The pipeline resolves these to a session;
    /// they are never persisted.
    #[serde(skip)]
    pub keys: Vec<String>,
    /// Keys to *add* to whichever session this event resolves to, so its
    /// descendants resolve too (e.g. a new shell's own pid).
    #[serde(skip)]
    pub learn: Vec<String>,
}

impl Event {
    pub fn new(category: Category, action: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: None,
            ts: Utc::now(),
            host: String::new(),
            category,
            action: action.into(),
            outcome: Outcome::Unknown,
            severity: Severity::Info,
            user: None,
            src_ip: None,
            session_id: None,
            process: None,
            target: None,
            message: message.into(),
            details: serde_json::Value::Null,
            before_sha: None,
            after_sha: None,
            hash: None,
            keys: Vec::new(),
            learn: Vec::new(),
        }
    }

    pub fn at(mut self, ts: DateTime<Utc>) -> Self {
        self.ts = ts;
        self
    }

    pub fn outcome(mut self, o: Outcome) -> Self {
        self.outcome = o;
        self
    }

    pub fn severity(mut self, s: Severity) -> Self {
        self.severity = s;
        self
    }

    pub fn user(mut self, u: impl Into<String>) -> Self {
        let u = u.into();
        if !u.is_empty() {
            self.user = Some(u);
        }
        self
    }

    pub fn src_ip(mut self, ip: impl Into<String>) -> Self {
        let ip = ip.into();
        if !ip.is_empty() && ip != "-" {
            self.src_ip = Some(ip);
        }
        self
    }

    pub fn target(mut self, t: impl Into<String>) -> Self {
        let t = t.into();
        if !t.is_empty() {
            self.target = Some(t);
        }
        self
    }

    pub fn process(mut self, p: ProcessInfo) -> Self {
        self.process = Some(p);
        self
    }

    pub fn key(mut self, k: impl Into<String>) -> Self {
        self.keys.push(k.into());
        self
    }

    /// Sets one field of the JSON `details` object, creating it if needed.
    pub fn detail(mut self, k: &str, v: impl Into<serde_json::Value>) -> Self {
        self.set_detail(k, v);
        self
    }

    pub fn set_detail(&mut self, k: &str, v: impl Into<serde_json::Value>) {
        if !self.details.is_object() {
            self.details = serde_json::Value::Object(Default::default());
        }
        if let Some(map) = self.details.as_object_mut() {
            map.insert(k.to_string(), v.into());
        }
    }

    pub fn detail_str(&self, k: &str) -> Option<&str> {
        self.details.get(k).and_then(|v| v.as_str())
    }

    pub fn command_line(&self) -> Option<&str> {
        self.process.as_ref().and_then(|p| p.command_line.as_deref())
    }
}

/// Everything collectors send to the pipeline.
pub enum Signal {
    Event(Box<Event>),
    /// Durable collector position (log offset, event-log record id,
    /// journald cursor). The pipeline persists it in the same transaction
    /// as every event that arrived before it, so a crash can neither lose
    /// nor duplicate events on restart.
    Checkpoint { key: String, value: String },
}

/// Cheap, cloneable handle collectors use to emit into the pipeline.
#[derive(Clone)]
pub struct EventBus {
    tx: SyncSender<Signal>,
}

impl EventBus {
    pub fn new(tx: SyncSender<Signal>) -> Self {
        Self { tx }
    }

    /// Blocks if the pipeline is backed up (bounded channel =
    /// backpressure rather than unbounded memory growth). Returns false
    /// once the pipeline has shut down.
    pub fn emit(&self, event: Event) -> bool {
        self.tx.send(Signal::Event(Box::new(event))).is_ok()
    }

    pub fn checkpoint(&self, key: impl Into<String>, value: impl Into<String>) -> bool {
        self.tx
            .send(Signal::Checkpoint {
                key: key.into(),
                value: value.into(),
            })
            .is_ok()
    }
}
