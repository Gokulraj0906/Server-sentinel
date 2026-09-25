//! Interactive access sessions (SSH, RDP, console) and attribution of
//! everything that happens inside them.
//!
//! A session is opened by a login event and carries a set of lookup keys
//! that later events can be resolved against:
//!
//! | key            | where it comes from                                  |
//! |----------------|------------------------------------------------------|
//! | `pid:N`        | sshd/login pid from the auth log; any process's own  |
//! |                | pid once it has been attributed (so children resolve)|
//! | `ksid:N`       | Linux kernel audit session id (`/proc/N/sessionid`), |
//! |                | inherited by every descendant, survives daemonizing  |
//! | `tty:pts/N`    | controlling terminal (sudo log lines carry TTY=)     |
//! | `logon:0x..`   | Windows logon id (4624 -> 4688/4634)                 |
//! | `ts:N`         | Windows Terminal Services session id (RDP/console)   |
//!
//! Keys are only ever matched against *active* sessions, which is what
//! makes pid / tty / TS-session-id reuse safe in practice.

use crate::events::Severity;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    Active,
    /// RDP session disconnected but not logged off: its processes keep
    /// running, so it still participates in attribution.
    Disconnected,
    Ended,
}

impl SessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionStatus::Active => "active",
            SessionStatus::Disconnected => "disconnected",
            SessionStatus::Ended => "ended",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "active" => SessionStatus::Active,
            "disconnected" => SessionStatus::Disconnected,
            _ => SessionStatus::Ended,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user: String,
    /// "ssh", "rdp", "console"
    pub protocol: String,
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub auth_method: Option<String>,
    pub key_fingerprint: Option<String>,
    pub start: DateTime<Utc>,
    pub end: Option<DateTime<Utc>>,
    pub last_activity: DateTime<Utc>,
    pub status: SessionStatus,
    pub end_reason: Option<String>,
    pub keys: Vec<String>,
    /// How many of `keys` came from the login itself (never evicted).
    pub base_keys: usize,
    pub commands: u32,
    pub privileged: u32,
    pub file_changes: u32,
    pub alerts: u32,
    pub max_severity: Severity,
}

impl Session {
    pub fn is_live(&self) -> bool {
        self.status != SessionStatus::Ended
    }

    /// Rough 0-100 risk score for triage ordering. Deliberately simple and
    /// explainable rather than clever.
    pub fn risk_score(&self) -> u32 {
        let sev = match self.max_severity {
            Severity::Critical => 60,
            Severity::High => 45,
            Severity::Medium => 25,
            Severity::Low => 10,
            Severity::Info => 0,
        };
        let score = sev
            + (self.privileged.min(10) * 2)
            + (self.file_changes.min(10) * 2)
            + (self.alerts.min(5) * 4);
        score.min(100)
    }
}

pub struct SessionStart {
    pub ts: DateTime<Utc>,
    pub user: String,
    pub protocol: String,
    pub src_ip: Option<String>,
    pub src_port: Option<u16>,
    pub auth_method: Option<String>,
    pub key_fingerprint: Option<String>,
    pub keys: Vec<String>,
}

/// Two login records for the same user/protocol this close together are
/// the same session reported by two sources (e.g. Windows Security 4624
/// and TerminalServices 21 for one RDP logon; or the linked elevated +
/// filtered token pair Windows logs for an admin).
const MERGE_WINDOW_SECONDS: i64 = 60;
const MAX_LEARNED_KEYS: usize = 2000;

#[derive(Default)]
pub struct SessionTracker {
    sessions: HashMap<String, Session>,
    index: HashMap<String, String>,
    dirty: HashSet<String>,
}

fn norm_user(u: &str) -> String {
    u.trim().to_ascii_lowercase()
}

impl SessionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restores still-live sessions persisted before a restart.
    pub fn load(&mut self, sessions: Vec<Session>) {
        for s in sessions.into_iter().filter(|s| s.is_live()) {
            for k in &s.keys {
                self.index.insert(k.clone(), s.id.clone());
            }
            self.sessions.insert(s.id.clone(), s);
        }
    }

    /// Opens a session, or merges into an existing one that is clearly the
    /// same logon seen from a second source. Returns the session id.
    #[cfg(test)]
    pub fn open(&mut self, start: SessionStart) -> String {
        self.open_ex(start).0
    }

    /// Like `open`, also reporting whether the login merged into an
    /// existing session (true) or started a new one (false).
    pub fn open_ex(&mut self, start: SessionStart) -> (String, bool) {
        let user_n = norm_user(&start.user);
        let merge_target = self
            .sessions
            .values()
            .filter(|s| s.is_live())
            .filter(|s| norm_user(&s.user) == user_n && s.protocol == start.protocol)
            .filter(|s| (s.start - start.ts).num_seconds().abs() <= MERGE_WINDOW_SECONDS)
            .filter(|s| match (&s.src_ip, &start.src_ip) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            })
            .map(|s| s.id.clone())
            .next();

        if let Some(id) = merge_target {
            let s = self.sessions.get_mut(&id).expect("id from map");
            s.src_ip = s.src_ip.clone().or(start.src_ip);
            s.src_port = s.src_port.or(start.src_port);
            s.auth_method = s.auth_method.clone().or(start.auth_method);
            s.key_fingerprint = s.key_fingerprint.clone().or(start.key_fingerprint);
            if start.ts < s.start {
                s.start = start.ts;
            }
            for k in start.keys {
                if !s.keys.contains(&k) {
                    // Keys from a login record are base keys: move them
                    // ahead of any learned ones so they're never evicted.
                    s.keys.insert(s.base_keys, k.clone());
                    s.base_keys += 1;
                    self.index.insert(k, id.clone());
                }
            }
            self.dirty.insert(id.clone());
            return (id, true);
        }

        let id = format!(
            "S{}-{}",
            start.ts.format("%y%m%d"),
            &uuid::Uuid::new_v4().simple().to_string()[..6]
        );
        for k in &start.keys {
            // A fresh login claiming a key (e.g. a reused TS session id
            // whose logoff we missed) takes it over from the stale owner.
            self.index.insert(k.clone(), id.clone());
        }
        let base_keys = start.keys.len();
        let session = Session {
            id: id.clone(),
            user: start.user,
            protocol: start.protocol,
            src_ip: start.src_ip,
            src_port: start.src_port,
            auth_method: start.auth_method,
            key_fingerprint: start.key_fingerprint,
            start: start.ts,
            end: None,
            last_activity: start.ts,
            status: SessionStatus::Active,
            end_reason: None,
            keys: start.keys,
            base_keys,
            commands: 0,
            privileged: 0,
            file_changes: 0,
            alerts: 0,
            max_severity: Severity::Info,
        };
        self.sessions.insert(id.clone(), session);
        self.dirty.insert(id.clone());
        (id, false)
    }

    pub fn resolve(&self, keys: &[String]) -> Option<&Session> {
        keys.iter()
            .filter_map(|k| self.index.get(k))
            .filter_map(|id| self.sessions.get(id))
            .find(|s| s.is_live())
    }

    pub fn get(&self, id: &str) -> Option<&Session> {
        self.sessions.get(id)
    }

    /// Mutable access; marks the session for persistence.
    pub fn get_mut(&mut self, id: &str) -> Option<&mut Session> {
        let s = self.sessions.get_mut(id)?;
        self.dirty.insert(id.to_string());
        Some(s)
    }

    pub fn learn(&mut self, id: &str, keys: &[String]) {
        let Some(s) = self.sessions.get_mut(id) else {
            return;
        };
        let mut changed = false;
        for k in keys {
            if self.index.get(k).map(|owner| owner == id).unwrap_or(false) {
                continue;
            }
            self.index.insert(k.clone(), id.to_string());
            s.keys.push(k.clone());
            changed = true;
        }
        while s.keys.len() > s.base_keys + MAX_LEARNED_KEYS {
            let evicted = s.keys.remove(s.base_keys);
            if self.index.get(&evicted).map(|o| o == id).unwrap_or(false) {
                self.index.remove(&evicted);
            }
        }
        if changed {
            self.dirty.insert(id.to_string());
        }
    }

    pub fn set_status(&mut self, keys: &[String], status: SessionStatus, ts: DateTime<Utc>) -> Option<String> {
        let id = self.resolve(keys)?.id.clone();
        let s = self.sessions.get_mut(&id)?;
        s.status = status;
        s.last_activity = ts;
        self.dirty.insert(id.clone());
        Some(id)
    }

    /// Ends the session any of `keys` resolves to. Returns its id, or None
    /// if no live session matched (e.g. a Windows network-logon 4634,
    /// which never opened an interactive session).
    pub fn close(&mut self, keys: &[String], ts: DateTime<Utc>, reason: &str) -> Option<String> {
        let id = self.resolve(keys)?.id.clone();
        self.end_session(&id, ts, reason);
        Some(id)
    }

    pub fn end_session(&mut self, id: &str, ts: DateTime<Utc>, reason: &str) {
        if let Some(s) = self.sessions.get_mut(id) {
            s.status = SessionStatus::Ended;
            s.end = Some(ts.max(s.start));
            s.end_reason = Some(reason.to_string());
            for k in &s.keys {
                if self.index.get(k).map(|o| o == id).unwrap_or(false) {
                    self.index.remove(k);
                }
            }
        }
        self.dirty.insert(id.to_string());
    }

    /// Closes sessions whose anchor processes no longer exist (logoff
    /// happened while the agent was down and the log rotated away).
    pub fn reap<F: Fn(&Session) -> bool>(&mut self, still_alive: F, now: DateTime<Utc>) -> Vec<String> {
        let dead: Vec<String> = self
            .sessions
            .values()
            .filter(|s| s.is_live() && !still_alive(s))
            .map(|s| s.id.clone())
            .collect();
        for id in &dead {
            self.end_session(id, now, "session no longer present (logoff not observed)");
        }
        dead
    }

    pub fn live_sessions(&self) -> impl Iterator<Item = &Session> {
        self.sessions.values().filter(|s| s.is_live())
    }

    pub fn live_for_user(&self, user: &str) -> Vec<&Session> {
        let u = norm_user(user);
        self.live_sessions().filter(|s| norm_user(&s.user) == u).collect()
    }

    /// Live sessions that were open at `ts` (used for file-change
    /// attribution, which happens a moment after the fact).
    pub fn live_at(&self, ts: DateTime<Utc>) -> Vec<&Session> {
        self.sessions
            .values()
            .filter(|s| s.start <= ts + Duration::seconds(5))
            .filter(|s| s.is_live() || s.end.map(|e| e >= ts).unwrap_or(false))
            .collect()
    }

    /// Sessions changed since the last call, for persistence. Ended
    /// sessions are dropped from memory once handed over.
    pub fn take_dirty(&mut self) -> Vec<Session> {
        let ids: Vec<String> = self.dirty.drain().collect();
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            if let Some(s) = self.sessions.get(&id) {
                out.push(s.clone());
                if !s.is_live() {
                    self.sessions.remove(&id);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn start(user: &str, proto: &str, ip: Option<&str>, keys: &[&str], ts: DateTime<Utc>) -> SessionStart {
        SessionStart {
            ts,
            user: user.into(),
            protocol: proto.into(),
            src_ip: ip.map(String::from),
            src_port: None,
            auth_method: None,
            key_fingerprint: None,
            keys: keys.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn open_resolve_learn_close() {
        let mut t = SessionTracker::new();
        let now = Utc::now();
        let id = t.open(start("alice", "ssh", Some("10.0.0.5"), &["pid:100"], now));
        assert_eq!(t.resolve(&["pid:100".into()]).unwrap().id, id);
        t.learn(&id, &["pid:200".into(), "ksid:7".into()]);
        assert_eq!(t.resolve(&["pid:999".into(), "ksid:7".into()]).unwrap().id, id);
        assert_eq!(t.close(&["pid:100".into()], now, "logout").as_deref(), Some(id.as_str()));
        assert!(t.resolve(&["ksid:7".into()]).is_none());
        let dirty = t.take_dirty();
        assert_eq!(dirty[0].status, SessionStatus::Ended);
    }

    #[test]
    fn same_logon_from_two_sources_merges() {
        let mut t = SessionTracker::new();
        let now = Utc::now();
        let a = t.open(start("HOST\\bob", "rdp", Some("203.0.113.9"), &["logon:0x1a2b"], now));
        let b = t.open(start("host\\BOB", "rdp", Some("203.0.113.9"), &["ts:2"], now + Duration::seconds(3)));
        assert_eq!(a, b);
        assert_eq!(t.resolve(&["ts:2".into()]).unwrap().id, a);
        // Different IP -> genuinely different session.
        let c = t.open(start("host\\bob", "rdp", Some("198.51.100.1"), &["ts:3"], now));
        assert_ne!(a, c);
    }

    #[test]
    fn learned_keys_are_capped_but_base_keys_survive() {
        let mut t = SessionTracker::new();
        let id = t.open(start("carol", "ssh", None, &["pid:1"], Utc::now()));
        let keys: Vec<String> = (0..(MAX_LEARNED_KEYS + 50)).map(|i| format!("pid:{}", i + 10)).collect();
        t.learn(&id, &keys);
        assert!(t.resolve(&["pid:1".into()]).is_some());
        assert!(t.resolve(&["pid:10".into()]).is_none(), "oldest learned key evicted");
        assert!(t.resolve(&[format!("pid:{}", MAX_LEARNED_KEYS + 59)]).is_some());
    }
}
