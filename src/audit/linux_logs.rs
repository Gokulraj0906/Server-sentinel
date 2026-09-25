//! Linux log sources: auth log (file or journald) and package-manager
//! logs.
//!
//! Source selection (`security.auth.source = "auto"`):
//! 1. `/var/log/auth.log` (Debian/Ubuntu with rsyslog)
//! 2. `/var/log/secure` (RHEL family)
//! 3. journald via `journalctl -f -o json` (Debian 12+, minimal images —
//!    anything without rsyslog)
//!
//! Compiled on every platform so the logic is type-checked and unit-tested
//! everywhere; only started on Linux.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::audit::authlog::{parse_auth_message, parse_syslog_line};
use crate::audit::packages::{parse_dnf_rpm_line, parse_dpkg_line};
use crate::audit::tail::FileTailer;
use crate::core::config::AuthSourceConfig;
use crate::events::{Category, Event, EventBus, Severity};
use crate::storage::event_store::EventStore;
use anyhow::Result;
use chrono::{DateTime, Local, Utc};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Auth,
    Dpkg,
    Dnf,
}

#[derive(Debug, PartialEq)]
pub enum AuthSource {
    File(PathBuf),
    Journald,
    None,
}

fn journalctl_available() -> bool {
    ["/usr/bin/journalctl", "/bin/journalctl"].iter().any(|p| Path::new(p).exists())
}

pub fn select_auth_source(cfg: &AuthSourceConfig) -> AuthSource {
    let explicit = (!cfg.log_path.is_empty()).then(|| PathBuf::from(&cfg.log_path));
    match cfg.source.as_str() {
        "journald" => AuthSource::Journald,
        "file" => explicit
            .or_else(|| ["/var/log/auth.log", "/var/log/secure"].iter().map(PathBuf::from).find(|p| p.exists()))
            .map(AuthSource::File)
            .unwrap_or(AuthSource::None),
        _ => {
            if let Some(p) = explicit {
                return AuthSource::File(p);
            }
            if let Some(p) = ["/var/log/auth.log", "/var/log/secure"].iter().map(PathBuf::from).find(|p| p.exists()) {
                return AuthSource::File(p);
            }
            if journalctl_available() {
                AuthSource::Journald
            } else {
                AuthSource::None
            }
        }
    }
}

fn parse_line(kind: Kind, line: &str, now: DateTime<Local>) -> Vec<Event> {
    match kind {
        Kind::Auth => match parse_syslog_line(line, now) {
            Some(l) => parse_auth_message(l.ts, l.ident, l.pid, l.msg),
            None => Vec::new(),
        },
        Kind::Dpkg => parse_dpkg_line(line).into_iter().collect(),
        Kind::Dnf => parse_dnf_rpm_line(line).into_iter().collect(),
    }
}

pub fn spawn(cfg: &AuthSourceConfig, store: &EventStore, bus: EventBus, running: Arc<AtomicBool>) -> Result<Vec<JoinHandle<()>>> {
    let mut handles = Vec::new();
    let mut files: Vec<(Kind, PathBuf)> = Vec::new();

    let source = if cfg.enabled { select_auth_source(cfg) } else { AuthSource::None };
    match &source {
        AuthSource::File(p) => {
            tracing::info!(path = %p.display(), "auth events: tailing log file");
            files.push((Kind::Auth, p.clone()));
        }
        AuthSource::Journald => tracing::info!("auth events: following journald (auth/authpriv facilities)"),
        AuthSource::None if cfg.enabled => tracing::warn!(
            "no auth log source found (no /var/log/auth.log, /var/log/secure, or journalctl); SSH/sudo activity will not be recorded"
        ),
        AuthSource::None => {}
    }
    for (kind, p) in [(Kind::Dpkg, "/var/log/dpkg.log"), (Kind::Dnf, "/var/log/dnf.rpm.log")] {
        if Path::new(p).exists() {
            files.push((kind, PathBuf::from(p)));
        }
    }

    if !files.is_empty() {
        let mut tailers = Vec::new();
        for (kind, path) in files {
            let key = format!("tail:{}", path.display());
            let cp = store.get_state(&key)?;
            tailers.push((kind, key, FileTailer::open(&path, cp.as_deref(), cfg.backfill)));
        }
        let bus = bus.clone();
        let running = running.clone();
        handles.push(
            std::thread::Builder::new()
                .name("audit-logs".into())
                .spawn(move || run_file_tailers(tailers, bus, running))?,
        );
    }

    if source == AuthSource::Journald {
        let cursor = store.get_state("journald:auth")?;
        let backfill = cfg.backfill;
        handles.push(
            std::thread::Builder::new()
                .name("audit-journald".into())
                .spawn(move || run_journald(cursor, backfill, bus, running))?,
        );
    }
    Ok(handles)
}

fn run_file_tailers(mut tailers: Vec<(Kind, String, FileTailer)>, bus: EventBus, running: Arc<AtomicBool>) {
    let mut last_error = Instant::now() - Duration::from_secs(3600);
    while running.load(Ordering::SeqCst) {
        let now = Local::now();
        for (kind, key, t) in tailers.iter_mut() {
            let batch = match t.poll() {
                Ok(b) => b,
                Err(e) => {
                    if last_error.elapsed() > Duration::from_secs(300) {
                        tracing::warn!(path = %t.path().display(), error = %e, "log tail failed");
                        last_error = Instant::now();
                    }
                    continue;
                }
            };
            if batch.truncated && *kind == Kind::Auth {
                let ev = Event::new(
                    Category::Agent,
                    "log.truncated",
                    format!("{} was truncated in place (not rotated) — possible log tampering", t.path().display()),
                )
                .severity(Severity::High)
                .target(t.path().display().to_string());
                if !bus.emit(ev) {
                    return;
                }
            }
            for line in &batch.lines {
                for ev in parse_line(*kind, line, now) {
                    if !bus.emit(ev) {
                        return;
                    }
                }
            }
            if !batch.lines.is_empty() || batch.truncated || batch.rotated {
                bus.checkpoint(key.clone(), t.checkpoint());
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

pub struct JournalEntry {
    pub ts: DateTime<Utc>,
    pub ident: String,
    pub pid: Option<u32>,
    pub msg: String,
    pub cursor: Option<String>,
}

/// One line of `journalctl -o json`.
pub fn parse_journal_entry(line: &str) -> Option<JournalEntry> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let msg = match v.get("MESSAGE")? {
        serde_json::Value::String(s) => s.clone(),
        // Non-UTF-8 messages are emitted as byte arrays.
        serde_json::Value::Array(bytes) => {
            let b: Vec<u8> = bytes.iter().filter_map(|x| x.as_u64()).map(|x| x as u8).collect();
            String::from_utf8_lossy(&b).into_owned()
        }
        _ => return None,
    };
    let ident = v
        .get("SYSLOG_IDENTIFIER")
        .or_else(|| v.get("_COMM"))
        .and_then(|s| s.as_str())?
        .to_string();
    let pid = v
        .get("SYSLOG_PID")
        .or_else(|| v.get("_PID"))
        .and_then(|s| s.as_str())
        .and_then(|s| s.parse().ok());
    let micros: i64 = v.get("__REALTIME_TIMESTAMP").and_then(|s| s.as_str()).and_then(|s| s.parse().ok())?;
    let ts = DateTime::<Utc>::from_timestamp(micros / 1_000_000, ((micros % 1_000_000) * 1000) as u32)?;
    Some(JournalEntry {
        ts,
        ident,
        pid,
        msg,
        cursor: v.get("__CURSOR").and_then(|s| s.as_str()).map(String::from),
    })
}

fn run_journald(mut cursor: Option<String>, backfill: bool, bus: EventBus, running: Arc<AtomicBool>) {
    let mut first_start = cursor.is_none();
    while running.load(Ordering::SeqCst) {
        let mut cmd = Command::new("journalctl");
        cmd.args(["-f", "-o", "json", "--no-pager", "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"]);
        match (&cursor, first_start && backfill) {
            (Some(c), _) => {
                cmd.arg(format!("--after-cursor={c}"));
            }
            (None, true) => {
                cmd.args(["-n", "all"]);
            }
            (None, false) => {
                cmd.args(["-n", "0"]);
            }
        }
        first_start = false;
        let mut child = match cmd.stdout(Stdio::piped()).stderr(Stdio::null()).stdin(Stdio::null()).spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "could not start journalctl; retrying in 30s");
                sleep_while_running(&running, Duration::from_secs(30));
                continue;
            }
        };
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = sync_channel::<String>(10_000);
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        let mut since_checkpoint = 0usize;
        let mut last_checkpoint = Instant::now();
        loop {
            if !running.load(Ordering::SeqCst) {
                let _ = child.kill();
                break;
            }
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(line) => {
                    if let Some(entry) = parse_journal_entry(&line) {
                        for ev in parse_auth_message(entry.ts, &entry.ident, entry.pid, &entry.msg) {
                            if !bus.emit(ev) {
                                let _ = child.kill();
                                return;
                            }
                        }
                        if entry.cursor.is_some() {
                            cursor = entry.cursor;
                            since_checkpoint += 1;
                        }
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    tracing::warn!("journalctl exited; restarting in 5s");
                    break;
                }
            }
            if since_checkpoint > 0 && (since_checkpoint >= 100 || last_checkpoint.elapsed() >= Duration::from_secs(2)) {
                if let Some(c) = &cursor {
                    bus.checkpoint("journald:auth", c.clone());
                }
                since_checkpoint = 0;
                last_checkpoint = Instant::now();
            }
        }
        let _ = child.wait();
        let _ = reader.join();
        if let Some(c) = &cursor {
            bus.checkpoint("journald:auth", c.clone());
        }
        sleep_while_running(&running, Duration::from_secs(5));
    }
}

pub(crate) fn sleep_while_running(running: &AtomicBool, total: Duration) {
    let deadline = Instant::now() + total;
    while running.load(Ordering::SeqCst) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journald_json_entries() {
        let line = r#"{"__CURSOR":"s=abc;i=1f","__REALTIME_TIMESTAMP":"1790000000123456","SYSLOG_IDENTIFIER":"sshd-session","_PID":"4242","MESSAGE":"Accepted publickey for alice from 10.0.0.9 port 51000 ssh2: ED25519 SHA256:xyz"}"#;
        let e = parse_journal_entry(line).unwrap();
        assert_eq!((e.ident.as_str(), e.pid, e.cursor.as_deref()), ("sshd-session", Some(4242), Some("s=abc;i=1f")));
        assert_eq!(e.ts.timestamp_subsec_micros(), 123456);
        let evs = parse_auth_message(e.ts, &e.ident, e.pid, &e.msg);
        assert_eq!(evs[0].action, "session.start");

        let binary = r#"{"__REALTIME_TIMESTAMP":"1790000000000000","SYSLOG_IDENTIFIER":"sudo","MESSAGE":[104,105]}"#;
        assert_eq!(parse_journal_entry(binary).unwrap().msg, "hi");
        assert!(parse_journal_entry("{}").is_none());
    }

    #[test]
    fn explicit_file_source_wins() {
        let cfg = AuthSourceConfig {
            log_path: "/custom/auth.log".into(),
            ..Default::default()
        };
        assert_eq!(select_auth_source(&cfg), AuthSource::File(PathBuf::from("/custom/auth.log")));
        let cfg = AuthSourceConfig {
            source: "journald".into(),
            ..Default::default()
        };
        assert_eq!(select_auth_source(&cfg), AuthSource::Journald);
    }
}
