//! The security event pipeline.
//!
//! ```text
//! collectors ──Signal──► hold buffer (re-order by timestamp)
//!                          │
//!                          ▼
//!   redact ─► session attribution ─► file-change attribution ─► rules
//!                          │
//!                          ▼   one SQLite transaction per batch:
//!        events + alerts + session updates + collector checkpoints
//!                          │
//!                          ▼
//!             forwarders (NDJSON / syslog) and notifications
//! ```
//!
//! Single-threaded by design: the session tracker and rule state have one
//! owner, so there are no locks and the ordering is deterministic.

use crate::events::{Category, Event, EventBus, Outcome, Severity, Signal};
use crate::forward::Forwarder;
use crate::notification::{AlertNotice, NotifyHandle};
use crate::security::attribution::{attribute, RecentProcess, RecentProcesses};
use crate::security::redact::Redactor;
use crate::security::rules::RuleEngine;
use crate::security::sessions::{SessionStart, SessionStatus, SessionTracker};
use crate::storage::event_store::{EventStore, Writer};
use anyhow::Result;
use chrono::Utc;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_COMMAND_LINE: usize = 8192;
/// Upper bound on buffering an event whose timestamp is in the future
/// (clock skew in a log source).
const MAX_HOLD: Duration = Duration::from_secs(10);

pub struct PipelineConfig {
    pub host: String,
    pub hold: Duration,
    pub capture_command_lines: bool,
    pub min_notify_severity: Severity,
    pub retention_days: u32,
    pub ignore_process_names: Vec<String>,
    pub process_sessions_only: bool,
}

pub struct Pipeline {
    store: EventStore,
    tracker: SessionTracker,
    rules: RuleEngine,
    redactor: Redactor,
    recent: RecentProcesses,
    forwarders: Vec<Box<dyn Forwarder>>,
    notify: Option<NotifyHandle>,
    cfg: PipelineConfig,
    buffer: VecDeque<(Instant, Signal)>,
}

struct Ctx<'a> {
    tracker: &'a mut SessionTracker,
    rules: &'a mut RuleEngine,
    redactor: &'a Redactor,
    recent: &'a mut RecentProcesses,
    cfg: &'a PipelineConfig,
}

impl Pipeline {
    pub fn new(
        store: EventStore,
        rules: RuleEngine,
        redactor: Redactor,
        forwarders: Vec<Box<dyn Forwarder>>,
        notify: Option<NotifyHandle>,
        cfg: PipelineConfig,
    ) -> Result<Self> {
        let mut tracker = SessionTracker::new();
        tracker.load(store.live_sessions()?);
        Ok(Self {
            store,
            tracker,
            rules,
            redactor,
            recent: RecentProcesses::default(),
            forwarders,
            notify,
            cfg,
            buffer: VecDeque::new(),
        })
    }

    pub fn run(mut self, rx: Receiver<Signal>, running: Arc<AtomicBool>) {
        self.record_agent_start();
        let mut last_prune = Instant::now() - Duration::from_secs(3000);
        let mut last_reap = Instant::now();
        let mut last_alive = Instant::now() - Duration::from_secs(120);
        let mut stopping_since: Option<Instant> = None;
        loop {
            // Normally we exit when every collector has dropped its bus
            // handle; don't let one stuck collector hold shutdown hostage.
            if !running.load(Ordering::SeqCst) {
                let since = *stopping_since.get_or_insert_with(Instant::now);
                if since.elapsed() > Duration::from_secs(15) {
                    tracing::warn!("collectors did not stop within 15s; flushing and exiting");
                    break;
                }
            }
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(sig) => {
                    self.buffer.push_back((Instant::now(), sig));
                    // Drain whatever else is queued without blocking.
                    while let Ok(sig) = rx.try_recv() {
                        self.buffer.push_back((Instant::now(), sig));
                        if self.buffer.len() >= 20_000 {
                            break;
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            // During shutdown, don't sit on buffered events.
            let flush_all = !running.load(Ordering::SeqCst);
            self.flush(flush_all);

            if last_alive.elapsed() >= Duration::from_secs(60) {
                last_alive = Instant::now();
                let _ = self.store.set_state("agent.last_alive", &Utc::now().to_rfc3339());
            }
            if last_reap.elapsed() >= Duration::from_secs(60) {
                last_reap = Instant::now();
                self.reap_sessions();
            }
            if last_prune.elapsed() >= Duration::from_secs(3600) {
                last_prune = Instant::now();
                match self.store.prune(self.cfg.retention_days) {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(deleted = n, retention_days = self.cfg.retention_days, "pruned old events"),
                    Err(e) => tracing::warn!(error = %e, "retention pruning failed"),
                }
            }
        }
        self.flush(true);
        let _ = self.store.set_state("agent.clean_stop", &Utc::now().to_rfc3339());
        for f in &mut self.forwarders {
            f.flush();
        }
        tracing::info!("security pipeline stopped");
    }

    /// Records the start, and whether the agent was down / killed — gaps
    /// in coverage are themselves security-relevant.
    fn record_agent_start(&mut self) {
        let last_alive = self.store.get_state("agent.last_alive").ok().flatten();
        let clean_stop = self.store.get_state("agent.clean_stop").ok().flatten();
        let mut ev = Event::new(
            Category::Agent,
            "agent.started",
            format!("ServerSentinel {} started", env!("CARGO_PKG_VERSION")),
        )
        .outcome(Outcome::Success)
        .detail("version", env!("CARGO_PKG_VERSION"));
        if let Some(last) = last_alive.as_deref().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok()) {
            let last = last.with_timezone(&Utc);
            let clean = clean_stop
                .as_deref()
                .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                .map(|c| c.with_timezone(&Utc) >= last)
                .unwrap_or(false);
            let gap = (Utc::now() - last).num_seconds().max(0);
            ev.set_detail("previous_last_alive", last.to_rfc3339());
            ev.set_detail("offline_seconds", gap);
            ev.set_detail("clean_shutdown", clean);
            if !clean && gap > 600 {
                ev.severity = Severity::Medium;
                ev.message = format!(
                    "ServerSentinel started after being offline ~{} min without a clean shutdown (killed, crashed, or host lost power) — activity in that window was only partially recorded",
                    gap / 60
                );
            }
        }
        let _ = self.store.set_state("agent.clean_stop", "");
        self.process_batch(vec![Signal::Event(Box::new(ev))]);
    }

    /// Releases events by *event timestamp*, not arrival: an event is
    /// processed once it's older than the hold window, so a source that
    /// delivers late (the auth log is polled every 500 ms; sudo logs its
    /// line before the file it edits changes) still sorts ahead of the
    /// FIM event it explains. Checkpoints are released only once every
    /// event that arrived before them has been, so a crash can't record
    /// a collector position past events that were never stored.
    fn flush(&mut self, all: bool) {
        if self.buffer.is_empty() {
            return;
        }
        let now = Instant::now();
        let watermark = Utc::now() - chrono::Duration::from_std(self.cfg.hold).unwrap_or_default();
        let mut due = Vec::new();
        let mut keep = VecDeque::with_capacity(self.buffer.len());
        let mut blocked = false;
        for (arrived, sig) in self.buffer.drain(..) {
            let ready = match &sig {
                Signal::Event(e) => all || e.ts <= watermark || now.duration_since(arrived) >= MAX_HOLD,
                Signal::Checkpoint { .. } => all || !blocked,
            };
            if ready {
                due.push(sig);
            } else {
                if matches!(sig, Signal::Event(_)) {
                    blocked = true;
                }
                keep.push_back((arrived, sig));
            }
        }
        self.buffer = keep;
        if !due.is_empty() {
            self.process_batch(due);
        }
    }

    fn process_batch(&mut self, signals: Vec<Signal>) {
        let mut events = Vec::new();
        let mut checkpoints = Vec::new();
        for s in signals {
            match s {
                Signal::Event(e) => events.push(*e),
                Signal::Checkpoint { key, value } => checkpoints.push((key, value)),
            }
        }
        // Stable sort: same-timestamp events keep arrival order.
        events.sort_by_key(|e| e.ts);

        let Pipeline {
            store,
            tracker,
            rules,
            redactor,
            recent,
            cfg,
            ..
        } = self;
        let host = cfg.host.clone();
        let mut ctx = Ctx {
            tracker,
            rules,
            redactor,
            recent,
            cfg,
        };
        let result = store.write_batch(|w| {
            let mut stored = Vec::with_capacity(events.len());
            for ev in events {
                match handle_event(ev, w, &mut ctx) {
                    Ok(mut out) => stored.append(&mut out),
                    Err(e) => tracing::warn!(error = %e, "failed to process event"),
                }
            }
            for s in ctx.tracker.take_dirty() {
                w.upsert_session(&s, &host)?;
            }
            for (k, v) in &checkpoints {
                w.set_state(k, v)?;
            }
            Ok(stored)
        });

        let stored = match result {
            Ok(s) => s,
            Err(e) => {
                // Checkpoints weren't saved either, so on restart the
                // collectors re-read this span: nothing is lost.
                tracing::error!(error = %e, "event store write failed; batch dropped");
                return;
            }
        };

        for ev in &stored {
            for f in &mut self.forwarders {
                if let Err(e) = f.forward(ev) {
                    tracing::warn!(forwarder = f.name(), error = %e, "forwarding failed");
                }
            }
            if ev.category == Category::Alert {
                tracing::warn!(severity = %ev.severity, rule = ev.detail_str("rule").unwrap_or(""), "{}", ev.message);
                let wants_notify = ev.details.get("notify").and_then(|v| v.as_bool()).unwrap_or(true);
                if wants_notify && ev.severity >= self.cfg.min_notify_severity {
                    if let Some(n) = &self.notify {
                        n.alert(AlertNotice::from_event(ev));
                    }
                }
            }
        }
    }

    fn reap_sessions(&mut self) {
        let ended = self.tracker.reap(session_still_present, Utc::now());
        if ended.is_empty() {
            return;
        }
        let events: Vec<Signal> = ended
            .iter()
            .filter_map(|id| self.tracker.get(id))
            .map(|s| {
                let mut ev = Event::new(
                    Category::Session,
                    "session.ended_unobserved",
                    format!("Session of {} ended (logoff not observed; its processes are gone)", s.user),
                )
                .user(s.user.clone());
                ev.session_id = Some(s.id.clone());
                ev.src_ip = s.src_ip.clone();
                Signal::Event(Box::new(ev))
            })
            .collect();
        self.process_batch(events);
    }

    /// For tests and the CLI: a bus wired into a fresh channel.
    #[allow(dead_code)]
    pub fn channel(capacity: usize) -> (EventBus, Receiver<Signal>) {
        let (tx, rx) = std::sync::mpsc::sync_channel(capacity);
        (EventBus::new(tx), rx)
    }
}

/// A session anchored on process ids (Linux sshd/login) is gone once none
/// of its base pids exist. Sessions keyed only on Windows logon / TS ids
/// are closed by their logoff events instead.
fn session_still_present(s: &crate::security::sessions::Session) -> bool {
    let pids: Vec<u32> = s.keys[..s.base_keys.min(s.keys.len())]
        .iter()
        .filter_map(|k| k.strip_prefix("pid:"))
        .filter_map(|p| p.parse().ok())
        .collect();
    if pids.is_empty() || !cfg!(target_os = "linux") {
        return true;
    }
    pids.iter().any(|p| std::path::Path::new(&format!("/proc/{p}")).exists())
}

fn handle_event(mut ev: Event, w: &mut Writer<'_>, ctx: &mut Ctx<'_>) -> Result<Vec<Event>> {
    ev.host = ctx.cfg.host.clone();

    if let Some(p) = ev.process.as_mut() {
        p.command_line = if ctx.cfg.capture_command_lines {
            // Bounded: some tools pass 30 KB+ encoded scripts on the
            // command line; the head is what identifies them.
            p.command_line.as_deref().map(|c| crate::util::truncate(&ctx.redactor.redact(c), MAX_COMMAND_LINE))
        } else {
            None
        };
    }
    ev.message = crate::util::truncate(&ctx.redactor.redact(&ev.message), MAX_COMMAND_LINE);
    if !ctx.cfg.capture_command_lines && ev.category == Category::Process {
        ev.message = format!("Executed {}", ev.process.as_ref().map(|p| p.name.as_str()).unwrap_or("process"));
    }

    match ev.action.as_str() {
        "session.snapshot" => return close_absent_sessions(&ev, w, ctx),
        "session.start" => open_session(&mut ev, ctx),
        "session.end" => match ctx.tracker.close(&ev.keys, ev.ts, "logoff") {
            Some(id) => fill_from_session(&mut ev, &id, ctx),
            // Logoff for something that was never an interactive session
            // (e.g. Windows network logons): not worth storing.
            None => return Ok(Vec::new()),
        },
        "session.disconnect" => match ctx.tracker.set_status(&ev.keys, SessionStatus::Disconnected, ev.ts) {
            Some(id) => fill_from_session(&mut ev, &id, ctx),
            None => return Ok(Vec::new()),
        },
        "session.reconnect" => {
            let reconnect_ip = ev.src_ip.clone();
            match ctx.tracker.set_status(&ev.keys, SessionStatus::Active, ev.ts) {
                Some(id) => {
                    let original_ip = ctx.tracker.get(&id).and_then(|s| s.src_ip.clone());
                    fill_from_session(&mut ev, &id, ctx);
                    if reconnect_ip.is_some() && reconnect_ip != original_ip {
                        ev.src_ip = reconnect_ip;
                        ev.set_detail("original_src_ip", original_ip.unwrap_or_default());
                        ev.severity = ev.severity.max(Severity::Low);
                        ev.message = format!("{} (from a different address than the original logon)", ev.message);
                    }
                }
                // A session that began before the agent was installed.
                None => {
                    ev.action = "session.start".into();
                    ev.set_detail("note", "first observed on reconnect");
                    open_session(&mut ev, ctx);
                }
            }
        }
        _ => {
            if ev.session_id.is_none() {
                if let Some(s) = ctx.tracker.resolve(&ev.keys) {
                    let id = s.id.clone();
                    fill_from_session(&mut ev, &id, ctx);
                }
            }
            if ev.session_id.is_none() && ev.category == Category::Privilege {
                if let Some(u) = ev.user.clone() {
                    let live = ctx.tracker.live_for_user(&u);
                    if live.len() == 1 {
                        let id = live[0].id.clone();
                        ev.set_detail("attribution", "only live session for this user");
                        fill_from_session(&mut ev, &id, ctx);
                    }
                }
            }
            if let Some(id) = ev.session_id.clone() {
                if !ev.learn.is_empty() {
                    let learn = std::mem::take(&mut ev.learn);
                    ctx.tracker.learn(&id, &learn);
                }
            }
        }
    }

    // No human identified (no session, no loginuid): the OS account the
    // process runs as is the best answer.
    if ev.user.is_none() {
        ev.user = ev.process.as_ref().and_then(|p| p.run_as.clone());
    }

    if ev.category == Category::Process {
        if let Some(p) = &ev.process {
            let name = p.name.to_ascii_lowercase();
            if ctx.cfg.ignore_process_names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                return Ok(Vec::new());
            }
            if ctx.cfg.process_sessions_only && ev.session_id.is_none() {
                return Ok(Vec::new());
            }
            ctx.recent.push(RecentProcess {
                ts: ev.ts,
                session_id: ev.session_id.clone(),
                user: ev.user.clone(),
                pid: p.pid,
                name: p.name.clone(),
                command_line: p.command_line.clone().unwrap_or_default(),
                cwd: p.cwd.clone(),
            });
        }
    }
    // Commands run through sudo are just as much "what they did".
    if ev.action == "privilege.sudo" {
        if let Some(cmd) = ev.command_line() {
            ctx.recent.push(RecentProcess {
                ts: ev.ts,
                session_id: ev.session_id.clone(),
                user: ev.user.clone(),
                pid: ev.process.as_ref().map(|p| p.pid).unwrap_or(0),
                name: "sudo".into(),
                command_line: cmd.to_string(),
                cwd: ev.process.as_ref().and_then(|p| p.cwd.clone()),
            });
        }
    }

    if matches!(ev.category, Category::File | Category::Package | Category::Account) && ev.session_id.is_none() && ev.user.is_none() {
        if let Some(path) = ev.target.clone() {
            let a = attribute(&path, ev.ts, ctx.recent, ctx.tracker);
            if matches!(a.confidence, "high" | "medium") {
                ev.session_id = a.session_id.clone();
                ev.user = a.user.clone();
            }
            ev.set_detail("attribution", serde_json::to_value(&a)?);
        }
    }

    if let Some(id) = ev.session_id.clone() {
        if let Some(s) = ctx.tracker.get_mut(&id) {
            s.last_activity = s.last_activity.max(ev.ts);
            match ev.category {
                Category::Process if ev.action == "process.start" => s.commands += 1,
                Category::Privilege => s.privileged += 1,
                Category::File => s.file_changes += 1,
                _ => {}
            }
            s.max_severity = s.max_severity.max(ev.severity);
        }
    }

    let alerts = ctx.rules.evaluate(&ev, w)?;
    w.insert_event(&mut ev)?;
    let mut out = Vec::with_capacity(1 + alerts.len());
    let trigger_id = ev.id;
    out.push(ev);
    for mut a in alerts {
        a.host = ctx.cfg.host.clone();
        if let Some(id) = trigger_id {
            a.set_detail("trigger_event_id", id);
        }
        w.insert_event(&mut a)?;
        if let Some(sid) = a.session_id.clone() {
            if let Some(s) = ctx.tracker.get_mut(&sid) {
                s.alerts += 1;
                s.max_severity = s.max_severity.max(a.severity);
            }
        }
        out.push(a);
    }
    Ok(out)
}

/// Startup snapshot of live sessions (Windows TS ids): anything we still
/// consider open under that key kind but the OS doesn't list has ended
/// while we weren't watching.
fn close_absent_sessions(snapshot: &Event, w: &mut Writer<'_>, ctx: &mut Ctx<'_>) -> Result<Vec<Event>> {
    let kind = format!("{}:", snapshot.detail_str("key_kind").unwrap_or(""));
    let live: std::collections::HashSet<&str> = snapshot
        .details
        .get("keys")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|k| k.as_str()).collect())
        .unwrap_or_default();
    let stale: Vec<(String, String, Option<String>)> = ctx
        .tracker
        .live_sessions()
        .filter(|s| s.keys[..s.base_keys.min(s.keys.len())].iter().any(|k| k.starts_with(&kind)))
        .filter(|s| !s.keys.iter().any(|k| live.contains(k.as_str())))
        .map(|s| (s.id.clone(), s.user.clone(), s.src_ip.clone()))
        .collect();
    let mut out = Vec::new();
    for (id, user, src_ip) in stale {
        ctx.tracker.end_session(&id, snapshot.ts, "not present when the agent started (logoff not observed)");
        let mut ev = Event::new(
            Category::Session,
            "session.ended_unobserved",
            format!("Session of {user} ended while the agent was not running"),
        )
        .at(snapshot.ts)
        .user(user);
        ev.host = ctx.cfg.host.clone();
        ev.session_id = Some(id);
        ev.src_ip = src_ip;
        w.insert_event(&mut ev)?;
        out.push(ev);
    }
    Ok(out)
}

fn open_session(ev: &mut Event, ctx: &mut Ctx<'_>) {
    let start = SessionStart {
        ts: ev.ts,
        user: ev.user.clone().unwrap_or_else(|| "unknown".into()),
        protocol: ev.detail_str("protocol").unwrap_or("unknown").to_string(),
        src_ip: ev.src_ip.clone(),
        src_port: ev.details.get("src_port").and_then(|v| v.as_u64()).map(|p| p as u16),
        auth_method: ev.detail_str("auth_method").map(String::from),
        key_fingerprint: ev.detail_str("key_fingerprint").map(String::from),
        keys: ev.keys.clone(),
    };
    let (id, merged) = ctx.tracker.open_ex(start);
    if merged {
        // A second record of the same logon (e.g. Security 4624 + RDP
        // session 21): keep it as auth evidence, not a second session.
        ev.category = Category::Auth;
        ev.action = "auth.success".into();
        ev.set_detail("linked_session", id.clone());
    }
    ev.session_id = Some(id);
}

fn fill_from_session(ev: &mut Event, id: &str, ctx: &Ctx<'_>) {
    ev.session_id = Some(id.to_string());
    if let Some(s) = ctx.tracker.get(id) {
        if ev.user.is_none() {
            ev.user = Some(s.user.clone());
        }
        if ev.src_ip.is_none() {
            ev.src_ip = s.src_ip.clone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::RulesConfig;
    use crate::events::ProcessInfo;
    use crate::query::Query;

    fn pipeline() -> Pipeline {
        Pipeline::new(
            EventStore::open_in_memory().unwrap(),
            RuleEngine::new(RulesConfig::default()),
            Redactor::new(true),
            Vec::new(),
            None,
            PipelineConfig {
                host: "web1".into(),
                hold: Duration::from_secs(0),
                capture_command_lines: true,
                min_notify_severity: Severity::High,
                retention_days: 30,
                ignore_process_names: vec!["ignored-helper".into()],
                process_sessions_only: false,
            },
        )
        .unwrap()
    }

    fn sig(e: Event) -> Signal {
        Signal::Event(Box::new(e))
    }

    #[test]
    fn ssh_session_end_to_end() {
        let mut p = pipeline();
        let t0 = Utc::now();
        let login = Event::new(Category::Session, "session.start", "Accepted publickey for alice")
            .at(t0)
            .user("alice")
            .src_ip("203.0.113.9")
            .detail("protocol", "ssh")
            .key("pid:4000");
        // The shell exec arrives with its ancestry, *before* the login line
        // in arrival order — the hold buffer's timestamp sort fixes that.
        let mut shell = Event::new(Category::Process, "process.start", "bash")
            .at(t0 + chrono::Duration::milliseconds(50))
            .process(ProcessInfo {
                pid: 4010,
                name: "bash".into(),
                command_line: Some("-bash".into()),
                ..Default::default()
            })
            .key("pid:4001")
            .key("pid:4000")
            .key("ksid:12");
        shell.learn = vec!["pid:4010".into(), "ksid:12".into(), "tty:pts/0".into()];
        let mut vim = Event::new(Category::Process, "process.start", "vim /etc/ssh/sshd_config")
            .at(t0 + chrono::Duration::seconds(5))
            .process(ProcessInfo {
                pid: 4020,
                name: "vim".into(),
                command_line: Some("vim /etc/ssh/sshd_config".into()),
                cwd: Some("/home/alice".into()),
                ..Default::default()
            })
            .key("pid:4010")
            .key("ksid:12");
        vim.learn = vec!["pid:4020".into()];
        let edit = Event::new(Category::File, "file.modified", "Modified /etc/ssh/sshd_config")
            .at(t0 + chrono::Duration::seconds(30))
            .target("/etc/ssh/sshd_config");
        let sudo = Event::new(Category::Privilege, "privilege.sudo", "alice ran systemctl restart ssh as root")
            .at(t0 + chrono::Duration::seconds(40))
            .user("alice")
            .key("tty:pts/0")
            .process(ProcessInfo {
                pid: 4030,
                name: "sudo".into(),
                command_line: Some("systemctl restart ssh".into()),
                ..Default::default()
            });
        let logout = Event::new(Category::Session, "session.end", "closed")
            .at(t0 + chrono::Duration::seconds(60))
            .key("pid:4000");

        p.process_batch(vec![sig(shell), sig(login), sig(vim), sig(edit), sig(sudo), sig(logout)]);

        let sessions = p.store.sessions(None, false, None, 10).unwrap();
        assert_eq!(sessions.len(), 1);
        let s = &sessions[0];
        assert_eq!(s.status, SessionStatus::Ended);
        assert_eq!((s.commands, s.file_changes, s.privileged), (2, 1, 1));
        assert!(s.alerts >= 1, "sshd_config edit is a sensitive-file alert");

        let evs = p.store.session_events(&s.id, 100).unwrap();
        let file = evs.iter().find(|e| e.action == "file.modified").expect("attributed file change");
        assert_eq!(file.user.as_deref(), Some("alice"));
        assert_eq!(file.details["attribution"]["confidence"], "high");
        let alert = evs.iter().find(|e| e.action == "alert.sensitive_file").unwrap();
        assert!(alert.message.contains("by alice"));
        assert!(evs.iter().any(|e| e.action == "privilege.sudo" && e.session_id.as_deref() == Some(s.id.as_str())));
        assert!(p.store.verify_chain().unwrap().problems.is_empty());
    }

    #[test]
    fn late_arriving_source_still_sorts_first_and_checkpoints_wait() {
        let mut p = pipeline();
        p.cfg.hold = Duration::from_secs(2);
        let now = Utc::now();
        p.tracker.open_ex(SessionStart {
            ts: now - chrono::Duration::seconds(60),
            user: "sstest".into(),
            protocol: "ssh".into(),
            src_ip: Some("172.24.1.2".into()),
            src_port: None,
            auth_method: None,
            key_fingerprint: None,
            keys: vec!["tty:pts/3".into()],
        });
        // FIM noticed the change first (fresh timestamp)...
        let edit = Event::new(Category::File, "file.modified", "Modified /etc/app.conf")
            .at(now)
            .target("/etc/app.conf");
        // ...the sudo line that caused it arrives later but is older.
        let sudo = Event::new(Category::Privilege, "privilege.sudo", "sstest ran as root: sed -i s/a/b/ app.conf")
            .at(now - chrono::Duration::milliseconds(300))
            .user("sstest")
            .key("tty:pts/3")
            .process(ProcessInfo {
                pid: 0,
                name: "sudo".into(),
                command_line: Some("/usr/bin/sed -i s/a/b/ app.conf".into()),
                cwd: Some("/etc".into()),
                ..Default::default()
            });
        p.buffer.push_back((Instant::now(), sig(edit)));
        p.buffer.push_back((Instant::now(), sig(sudo)));
        p.buffer.push_back((Instant::now(), Signal::Checkpoint { key: "tail:x".into(), value: "1".into() }));

        p.flush(false);
        // Neither event is older than the hold window yet: nothing stored,
        // and the checkpoint must not overtake them.
        assert_eq!(p.store.event_count().unwrap(), 0);
        assert!(p.store.get_state("tail:x").unwrap().is_none());

        p.flush(true);
        let file = p
            .store
            .query(&Query::parse("action=file.modified").unwrap())
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(file.details["attribution"]["confidence"], "high", "{}", file.details);
        assert_eq!(file.user.as_deref(), Some("sstest"));
        assert_eq!(p.store.get_state("tail:x").unwrap().as_deref(), Some("1"));
    }

    #[test]
    fn redaction_ignores_and_orphan_logoffs() {
        let mut p = pipeline();
        let cmd = Event::new(Category::Process, "process.start", "mysql -u root -pHunter2 prod").process(ProcessInfo {
            pid: 1,
            name: "mysql".into(),
            command_line: Some("mysql -u root -pHunter2 prod".into()),
            ..Default::default()
        });
        let ignored = Event::new(Category::Process, "process.start", "x").process(ProcessInfo {
            pid: 2,
            name: "ignored-helper".into(),
            ..Default::default()
        });
        let orphan_logoff = Event::new(Category::Session, "session.end", "4634").key("logon:0xdead");
        p.process_batch(vec![sig(cmd), sig(ignored), sig(orphan_logoff)]);
        let all = p.store.query(&Query::parse("").unwrap()).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].command_line(), Some("mysql -u root -p*** prod"));
        assert!(!all[0].message.contains("Hunter2"));
    }

    #[test]
    fn windows_logon_seen_twice_is_one_session() {
        let mut p = pipeline();
        let t0 = Utc::now();
        let sec = Event::new(Category::Session, "session.start", "4624")
            .at(t0)
            .user("HOST\\bob")
            .src_ip("198.51.100.4")
            .detail("protocol", "rdp")
            .key("logon:0x1f2e");
        let lsm = Event::new(Category::Session, "session.start", "21")
            .at(t0 + chrono::Duration::seconds(2))
            .user("HOST\\bob")
            .src_ip("198.51.100.4")
            .detail("protocol", "rdp")
            .key("ts:2");
        let cmd = Event::new(Category::Process, "process.start", "powershell").process(ProcessInfo {
            pid: 7,
            name: "powershell.exe".into(),
            ..Default::default()
        })
        .at(t0 + chrono::Duration::seconds(10))
        .key("ts:2");
        let logoff = Event::new(Category::Session, "session.end", "23")
            .at(t0 + chrono::Duration::seconds(20))
            .key("logon:0x1f2e");
        p.process_batch(vec![sig(sec), sig(lsm), sig(cmd), sig(logoff)]);
        let sessions = p.store.sessions(None, false, None, 10).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].commands, 1);
        assert_eq!(sessions[0].status, SessionStatus::Ended);
    }
}
