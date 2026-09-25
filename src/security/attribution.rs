//! "Who changed this file?"
//!
//! File-change notifications (inotify / ReadDirectoryChangesW) say *what*
//! changed, not *who*. Exact attribution needs kernel audit hooks
//! (auditd/fanotify/eBPF on Linux, SACL object-access auditing on
//! Windows). Without them, the practical answer comes from correlating
//! the change with recent commands, which is right far more often than
//! not: people change files with `vim /etc/x`, `sed -i ... x`, `cp a x`,
//! `notepad x`. Every attribution carries an explicit confidence and the
//! reasoning, so a guess is never presented as proof.

use crate::security::sessions::SessionTracker;
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct RecentProcess {
    pub ts: DateTime<Utc>,
    pub session_id: Option<String>,
    pub user: Option<String>,
    pub pid: u32,
    pub name: String,
    pub command_line: String,
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Attribution {
    pub confidence: &'static str,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub candidate_sessions: Vec<String>,
}

const LOOKBACK_MINUTES: i64 = 15;
const PACKAGE_MANAGERS: &[&str] = &[
    "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "zypper", "apk", "pacman", "snap", "unattended-upgr",
    "msiexec.exe", "trustedinstaller.exe", "tiworker.exe", "wusa.exe", "choco.exe", "winget.exe",
];
/// Config management agents make most unattended changes on managed
/// fleets; naming them beats "unattributed".
const AUTOMATION: &[&str] = &[
    "ansible", "ansible-playbook", "puppet", "chef-client", "salt-minion", "salt-call", "cloud-init",
    "terraform", "cfn-init",
];

pub struct RecentProcesses {
    buf: VecDeque<RecentProcess>,
    cap: usize,
}

impl Default for RecentProcesses {
    fn default() -> Self {
        Self {
            buf: VecDeque::new(),
            cap: 20_000,
        }
    }
}

impl RecentProcesses {
    pub fn push(&mut self, p: RecentProcess) {
        let cutoff = p.ts - Duration::minutes(LOOKBACK_MINUTES);
        while self.buf.front().map(|f| f.ts < cutoff).unwrap_or(false) || self.buf.len() >= self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(p);
    }

    pub fn iter_recent_first(&self) -> impl Iterator<Item = &RecentProcess> {
        self.buf.iter().rev()
    }
}

fn split_path(path: &str) -> (&str, &str) {
    match path.rfind(['/', '\\']) {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

fn eq_path(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn contains_path(haystack: &str, needle: &str) -> bool {
    if cfg!(windows) {
        haystack.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
    } else {
        haystack.contains(needle)
    }
}

/// Does `cmd` mention `name` as its own token (not as part of another
/// word)? `vim nginx.conf` yes; `vim nginx.conf.bak` no.
fn mentions_token(cmd: &str, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let cmd_cmp = if cfg!(windows) { cmd.to_ascii_lowercase() } else { cmd.to_string() };
    let name_cmp = if cfg!(windows) { name.to_ascii_lowercase() } else { name.to_string() };
    let boundary = |c: Option<char>| c.map(|c| c.is_whitespace() || "/\\'\"=<>|;&(),:".contains(c)).unwrap_or(true);
    let mut start = 0;
    while let Some(i) = cmd_cmp[start..].find(&name_cmp) {
        let at = start + i;
        let before = cmd_cmp[..at].chars().last();
        let after = cmd_cmp[at + name_cmp.len()..].chars().next();
        if boundary(before) && boundary(after) {
            return true;
        }
        start = at + name_cmp.len().max(1);
    }
    false
}

/// `target` is a file path, or the name of what changed for account and
/// package events ("ssmallory", "nginx"): `useradd` and `apt` log what
/// happened but not who asked for it; the `sudo useradd ssmallory` or
/// `apt install nginx` that did is in the recent commands.
pub fn attribute(target: &str, ts: DateTime<Utc>, recent: &RecentProcesses, sessions: &SessionTracker) -> Attribution {
    let path = target;
    let is_path = path.contains('/') || path.contains('\\');
    let (dir, name) = split_path(path);
    let window_start = ts - Duration::minutes(LOOKBACK_MINUTES);
    let candidates: Vec<&RecentProcess> = recent
        .iter_recent_first()
        .filter(|p| p.ts <= ts + Duration::seconds(5) && p.ts >= window_start)
        .collect();

    let hit = |p: &RecentProcess, confidence: &'static str, reason: String| Attribution {
        confidence,
        reason,
        session_id: p.session_id.clone(),
        user: p.user.clone(),
        pid: Some(p.pid),
        command_line: Some(p.command_line.clone()),
        candidate_sessions: Vec::new(),
    };

    // 1. The command line names the full path (or, for a bare name like an
    // account, names it as a whole word: "bob" must not match "bobby").
    if let Some(p) = candidates.iter().find(|p| {
        if is_path {
            contains_path(&p.command_line, path)
        } else {
            mentions_token(&p.command_line, path)
        }
    }) {
        return hit(p, "high", format!("`{}` referenced {path}", p.name));
    }
    // 2. Relative path: file name as a token, run from the file's directory.
    if let Some(p) = candidates.iter().find(|p| {
        mentions_token(&p.command_line, name) && p.cwd.as_deref().map(|c| eq_path(c, dir)).unwrap_or(false)
    }) {
        return hit(p, "high", format!("`{}` referenced {name} from {dir}", p.name));
    }
    // 3. File name mentioned somewhere else (another dir, or cwd unknown).
    if name.len() >= 4 {
        if let Some(p) = candidates.iter().find(|p| mentions_token(&p.command_line, name)) {
            return hit(p, "medium", format!("`{}` referenced a file named {name}", p.name));
        }
    }
    // 4. A package manager or config-management run.
    let near: Vec<&&RecentProcess> = candidates.iter().filter(|p| ts - p.ts <= Duration::minutes(5)).collect();
    if let Some(p) = near.iter().find(|p| PACKAGE_MANAGERS.contains(&p.name.to_ascii_lowercase().as_str())) {
        return hit(p, "medium", format!("package manager `{}` was running", p.name));
    }
    if let Some(p) = near.iter().find(|p| AUTOMATION.contains(&p.name.to_ascii_lowercase().as_str())) {
        return hit(p, "medium", format!("configuration management `{}` was running", p.name));
    }
    // 5. Fall back to who was logged in.
    let live = sessions.live_at(ts);
    match live.len() {
        0 => Attribution {
            confidence: "none",
            reason: "no interactive session was open; likely a service, scheduled job or package hook".into(),
            session_id: None,
            user: None,
            pid: None,
            command_line: None,
            candidate_sessions: Vec::new(),
        },
        1 => Attribution {
            confidence: "low",
            reason: format!("only interactive session open at the time ({} via {})", live[0].user, live[0].protocol),
            session_id: Some(live[0].id.clone()),
            user: Some(live[0].user.clone()),
            pid: None,
            command_line: None,
            candidate_sessions: Vec::new(),
        },
        n => Attribution {
            confidence: "none",
            reason: format!("{n} interactive sessions were open; not enough evidence to pick one"),
            session_id: None,
            user: None,
            pid: None,
            command_line: None,
            candidate_sessions: live.iter().map(|s| format!("{} ({})", s.id, s.user)).collect(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::sessions::SessionStart;

    fn proc(ts: DateTime<Utc>, sid: &str, name: &str, cmd: &str, cwd: &str) -> RecentProcess {
        RecentProcess {
            ts,
            session_id: Some(sid.into()),
            user: Some("alice".into()),
            pid: 100,
            name: name.into(),
            command_line: cmd.into(),
            cwd: Some(cwd.into()),
        }
    }

    #[test]
    fn full_path_relative_and_name_only() {
        let now = Utc::now();
        let sessions = SessionTracker::new();
        let mut r = RecentProcesses::default();
        r.push(proc(now - Duration::seconds(30), "S1", "vim", "vim /etc/nginx/nginx.conf", "/home/alice"));
        let a = attribute("/etc/nginx/nginx.conf", now, &r, &sessions);
        assert_eq!((a.confidence, a.session_id.as_deref()), ("high", Some("S1")));

        let mut r = RecentProcesses::default();
        r.push(proc(now, "S2", "sed", "sed -i s/80/8080/ nginx.conf", "/etc/nginx"));
        assert_eq!(attribute("/etc/nginx/nginx.conf", now, &r, &sessions).confidence, "high");

        let mut r = RecentProcesses::default();
        r.push(proc(now, "S3", "nano", "nano nginx.conf", "/tmp"));
        assert_eq!(attribute("/etc/nginx/nginx.conf", now, &r, &sessions).confidence, "medium");

        // A different file that merely starts with the same name is not a match.
        let mut r = RecentProcesses::default();
        r.push(proc(now, "S4", "cat", "cat nginx.conf.bak", "/tmp"));
        assert_eq!(attribute("/etc/nginx/nginx.conf", now, &r, &sessions).confidence, "none");
    }

    #[test]
    fn account_names_match_whole_words_only() {
        let now = Utc::now();
        let sessions = SessionTracker::new();
        let mut r = RecentProcesses::default();
        r.push(proc(now - Duration::seconds(1), "S9", "sudo", "/usr/sbin/useradd -m ssmallory", "/etc"));
        let a = attribute("ssmallory", now, &r, &sessions);
        assert_eq!((a.confidence, a.session_id.as_deref()), ("high", Some("S9")));
        assert_eq!(attribute("ssmall", now, &r, &sessions).confidence, "none", "substring of another name");
    }

    #[test]
    fn falls_back_to_package_manager_then_sessions() {
        let now = Utc::now();
        let mut sessions = SessionTracker::new();
        let mut r = RecentProcesses::default();
        r.push(proc(now - Duration::seconds(60), "S1", "dpkg", "dpkg --configure -a", "/"));
        assert_eq!(attribute("/etc/ssl/openssl.cnf", now, &r, &sessions).confidence, "medium");

        let empty = RecentProcesses::default();
        sessions.open(SessionStart {
            ts: now - Duration::minutes(10),
            user: "bob".into(),
            protocol: "ssh".into(),
            src_ip: None,
            src_port: None,
            auth_method: None,
            key_fingerprint: None,
            keys: vec!["pid:1".into()],
        });
        let a = attribute("/etc/hosts", now, &empty, &sessions);
        assert_eq!((a.confidence, a.user.as_deref()), ("low", Some("bob")));
    }
}
