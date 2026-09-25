//! Investigation commands: `search`, `sessions`, `session`, `changes`,
//! `diff`, `alerts`, `verify`, `doctor`.
//!
//! All read-only against the local event store, so they're safe to run
//! on a live host while the agent is writing.

use crate::audit::fim::unified_diff;
use crate::core::config::Config;
use crate::events::{Category, Event, Severity};
use crate::query::Query;
use crate::reporting::session_html::{duration_str, render_session_html};
use crate::security::sessions::Session;
use crate::storage::event_store::EventStore;
use crate::util::{parse_duration, truncate};
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Local, Utc};
use std::path::Path;

fn open(cfg: &Config) -> Result<EventStore> {
    let path = cfg.event_db_path();
    if !path.exists() {
        bail!(
            "no event store at {} — start the agent first (`server-sentinel run`), or pass the same --config the service uses",
            path.display()
        );
    }
    EventStore::open_readonly(&path)
}

fn since(s: &str) -> Result<DateTime<Utc>> {
    if let Ok(d) = DateTime::parse_from_rfc3339(s) {
        return Ok(d.with_timezone(&Utc));
    }
    parse_duration(s)
        .map(|d| Utc::now() - d)
        .ok_or_else(|| anyhow!("invalid time '{s}' (use e.g. 30m, 24h, 7d, or an RFC 3339 timestamp)"))
}

fn local(ts: &DateTime<Utc>) -> String {
    ts.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string()
}

fn pad(s: &str, w: usize) -> String {
    let t = truncate_plain(s, w);
    format!("{t:<w$}")
}

fn truncate_plain(s: &str, w: usize) -> String {
    if s.chars().count() <= w {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(w.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn sev_tag(s: Severity) -> &'static str {
    match s {
        Severity::Info => "    ",
        Severity::Low => "LOW ",
        Severity::Medium => "MED ",
        Severity::High => "HIGH",
        Severity::Critical => "CRIT",
    }
}

fn print_events(events: &[Event], json: bool) -> Result<()> {
    if json {
        for e in events {
            println!("{}", serde_json::to_string(e)?);
        }
        return Ok(());
    }
    if events.is_empty() {
        println!("No matching events.");
        return Ok(());
    }
    println!(
        "{:>7}  {:<19}  SEV   {:<24}  {:<18}  {:<15}  {:<14}  SUMMARY",
        "ID", "TIME", "ACTION", "USER", "SOURCE", "SESSION"
    );
    for e in events {
        println!(
            "{:>7}  {}  {}  {}  {}  {}  {}  {}",
            e.id.unwrap_or(0),
            local(&e.ts),
            sev_tag(e.severity),
            pad(&e.action, 24),
            pad(e.user.as_deref().unwrap_or("-"), 18),
            pad(e.src_ip.as_deref().unwrap_or("-"), 15),
            pad(e.session_id.as_deref().unwrap_or("-"), 14),
            truncate_plain(&e.message, 140)
        );
    }
    Ok(())
}

pub fn search(cfg: &Config, query: &[String], since_s: &str, until_s: Option<&str>, limit: usize, json: bool) -> Result<()> {
    let store = open(cfg)?;
    let mut q = Query::parse(&query.join(" "))?;
    q.since = Some(since(since_s)?);
    q.until = until_s.map(since).transpose()?;
    q.limit = limit;
    let mut events = store.query(&q)?;
    events.reverse(); // newest N, shown chronologically
    print_events(&events, json)?;
    if !json && events.len() == limit {
        eprintln!("(showing the most recent {limit}; use --limit or narrow the query/--since)");
    }
    Ok(())
}

pub fn alerts(cfg: &Config, since_s: &str, min: &str, limit: usize, json: bool) -> Result<()> {
    let store = open(cfg)?;
    let mut q = Query::parse("category=alert")?;
    q.since = Some(since(since_s)?);
    q.min_severity = Some(Severity::parse(min).ok_or_else(|| anyhow!("unknown severity '{min}'"))?);
    q.limit = limit;
    let mut events = store.query(&q)?;
    events.reverse();
    print_events(&events, json)
}

fn session_line(s: &Session) -> String {
    let from = s.src_ip.clone().unwrap_or_else(|| "local".into());
    format!(
        "{}  {}  {}  {}  {}  {:>8}  {}  {:>4} {:>4} {:>5} {:>6}  {:>3}",
        pad(&s.id, 14),
        pad(&s.user, 20),
        pad(&s.protocol, 7),
        pad(&from, 18),
        local(&s.start),
        duration_str(s),
        pad(s.status.as_str(), 12),
        s.commands,
        s.privileged,
        s.file_changes,
        s.alerts,
        s.risk_score()
    )
}

pub fn sessions(cfg: &Config, since_s: &str, live: bool, user: Option<&str>, limit: usize, json: bool) -> Result<()> {
    let store = open(cfg)?;
    let list = store.sessions(Some(since(since_s)?), live, user, limit)?;
    if json {
        for s in &list {
            println!("{}", serde_json::to_string(s)?);
        }
        return Ok(());
    }
    if list.is_empty() {
        println!("No sessions in that window.");
        return Ok(());
    }
    println!(
        "{}  {}  {}  {}  {:<19}  {:>8}  {}  {:>4} {:>4} {:>5} {:>6}  {:>3}",
        pad("SESSION", 14),
        pad("USER", 20),
        pad("VIA", 7),
        pad("FROM", 18),
        "START",
        "DURATION",
        pad("STATUS", 12),
        "CMDS",
        "SUDO",
        "FILES",
        "ALERTS",
        "RISK"
    );
    for s in &list {
        println!("{}", session_line(s));
    }
    println!("\nDrill in with: server-sentinel session <SESSION>");
    Ok(())
}

pub fn session(cfg: &Config, id: &str, html: Option<&Path>, json: bool, show_diffs: bool) -> Result<()> {
    let store = open(cfg)?;
    let s = store.session(id)?.ok_or_else(|| anyhow!("no session '{id}' (list them with `server-sentinel sessions`)"))?;
    let events = store.session_events(id, 20_000)?;

    if let Some(path) = html {
        std::fs::write(path, render_session_html(&s, &events, &cfg.server.name)).with_context(|| format!("writing {}", path.display()))?;
        println!("Session report written to {}", path.display());
        return Ok(());
    }
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "session": s, "events": events }))?);
        return Ok(());
    }

    let from = match (&s.src_ip, s.src_port) {
        (Some(ip), Some(p)) if p > 0 => format!("{ip} port {p}"),
        (Some(ip), _) => ip.clone(),
        _ => "local".into(),
    };
    println!("Session {}  —  {} via {} from {}", s.id, s.user, s.protocol.to_uppercase(), from);
    if s.auth_method.is_some() || s.key_fingerprint.is_some() {
        println!(
            "  Auth:      {}{}",
            s.auth_method.as_deref().unwrap_or("?"),
            s.key_fingerprint.as_deref().map(|k| format!("  key {k}")).unwrap_or_default()
        );
    }
    println!(
        "  When:      {} → {}  ({})  {}{}",
        local(&s.start),
        s.end.map(|e| local(&e)).unwrap_or_else(|| "still open".into()),
        duration_str(&s),
        s.status.as_str(),
        s.end_reason.as_deref().map(|r| format!(" — {r}")).unwrap_or_default()
    );
    println!(
        "  Activity:  {} commands, {} privileged, {} file changes, {} alerts   risk {}/100\n",
        s.commands,
        s.privileged,
        s.file_changes,
        s.alerts,
        s.risk_score()
    );
    for ev in &events {
        let t = ev.ts.with_timezone(&Local).format("%H:%M:%S");
        let marker = match ev.category {
            Category::Session => "●",
            Category::Process => "$",
            Category::Privilege => "#",
            Category::File => "✎",
            Category::Alert => "!",
            Category::Account => "@",
            _ => "·",
        };
        let mut line = match ev.category {
            Category::Process => ev.command_line().unwrap_or(&ev.message).to_string(),
            Category::Alert => format!("{} ALERT: {}", ev.severity.as_str().to_uppercase(), ev.message),
            _ => ev.message.clone(),
        };
        if let Some(p) = &ev.process {
            if let Some(cwd) = &p.cwd {
                line.push_str(&format!("   (in {cwd})"));
            }
            if ev.details.get("elevated").is_some() {
                line.push_str(&format!("   [as {}]", p.run_as.as_deref().unwrap_or("root")));
            }
        }
        println!("  {t}  {marker} {}   #{}", truncate(&line, 400), ev.id.unwrap_or(0));
        if ev.category == Category::File {
            if let Some(a) = ev.details.get("attribution") {
                println!(
                    "            attribution: {} — {}",
                    a.get("confidence").and_then(|v| v.as_str()).unwrap_or("?"),
                    a.get("reason").and_then(|v| v.as_str()).unwrap_or("")
                );
            }
            if show_diffs {
                if let Some(d) = ev.detail_str("diff") {
                    for l in d.lines() {
                        println!("            {l}");
                    }
                }
            }
        }
    }
    if !show_diffs && events.iter().any(|e| e.detail_str("diff").is_some()) {
        println!("\n(add --diffs to show file diffs inline, or `server-sentinel diff <#id>` for one change)");
    }
    Ok(())
}

pub fn changes(cfg: &Config, path: Option<&str>, since_s: &str, limit: usize, json: bool) -> Result<()> {
    let store = open(cfg)?;
    let mut text = String::from("category=file");
    if let Some(p) = path {
        let pat = if p.contains('*') { p.to_string() } else { format!("*{p}*") };
        text.push_str(&format!(" path=\"{pat}\""));
    }
    let mut q = Query::parse(&text)?;
    q.since = Some(since(since_s)?);
    q.limit = limit;
    let mut events = store.query(&q)?;
    events.reverse();
    if json {
        return print_events(&events, true);
    }
    if events.is_empty() {
        println!("No file changes in that window.");
        return Ok(());
    }
    for ev in &events {
        let who = match (ev.user.as_deref(), ev.details.get("attribution")) {
            (Some(u), Some(a)) => format!("{u} ({} confidence)", a.get("confidence").and_then(|c| c.as_str()).unwrap_or("?")),
            (Some(u), None) => u.to_string(),
            (None, Some(a)) => format!("unattributed — {}", a.get("reason").and_then(|c| c.as_str()).unwrap_or("")),
            (None, None) => "unattributed".into(),
        };
        println!("#{:<7} {}  {}", ev.id.unwrap_or(0), local(&ev.ts), ev.message);
        println!("          by {who}{}", ev.session_id.as_deref().map(|s| format!("  [session {s}]")).unwrap_or_default());
    }
    println!("\nSee a change in full: server-sentinel diff <#id>   (--before / --after for the whole file)");
    Ok(())
}

pub fn diff(cfg: &Config, id: i64, before: bool, after: bool) -> Result<()> {
    let store = open(cfg)?;
    let ev = store.get_event(id)?.ok_or_else(|| anyhow!("no event #{id}"))?;
    if ev.category != Category::File {
        bail!("event #{id} is {} — not a file change", ev.action);
    }
    let load = |sha: &Option<String>| -> Result<Option<String>> {
        Ok(match sha {
            Some(s) => store.get_blob(s)?.map(|b| String::from_utf8_lossy(&b).into_owned()),
            None => None,
        })
    };
    let old = load(&ev.before_sha)?;
    let new = load(&ev.after_sha)?;
    let path = ev.target.clone().unwrap_or_default();
    if before || after {
        let (which, content) = if before { ("before", old) } else { ("after", new) };
        match content {
            Some(c) => print!("{c}"),
            None => bail!("the {which} version of {path} was not stored (secret, binary, too large, or didn't exist)"),
        }
        return Ok(());
    }
    println!("#{id}  {}  {}", local(&ev.ts), ev.message);
    if let Some(u) = &ev.user {
        println!("by {u}{}", ev.session_id.as_deref().map(|s| format!(" in session {s}")).unwrap_or_default());
    }
    println!();
    match (old, new) {
        (Some(o), Some(n)) => print!("{}", unified_diff(&o, &n, &path).text),
        (None, Some(n)) if ev.action == "file.created" => print!("{}", unified_diff("", &n, &path).text),
        (Some(o), None) if ev.action == "file.deleted" => print!("{}", unified_diff(&o, "", &path).text),
        _ => println!(
            "No content stored for this change ({}). Hashes: {} -> {}",
            ev.detail_str("content").unwrap_or("hash-only file"),
            ev.detail_str("sha256_before").unwrap_or("-"),
            ev.detail_str("sha256_after").unwrap_or("-")
        ),
    }
    Ok(())
}

pub fn verify(cfg: &Config) -> Result<bool> {
    let store = open(cfg)?;
    let r = store.verify_chain()?;
    if r.rows_checked == 0 {
        println!("Event store is empty; nothing to verify.");
        return Ok(true);
    }
    println!(
        "Checked {} events (#{} .. #{}).",
        r.rows_checked,
        r.first_id.unwrap_or(0),
        r.last_id.unwrap_or(0)
    );
    if r.problems.is_empty() {
        println!("✓ Hash chain intact: no event has been modified or removed since it was written.");
        Ok(true)
    } else {
        println!("✗ INTEGRITY FAILURE — the audit trail has been altered:");
        for p in r.problems.iter().take(50) {
            println!("  - {p}");
        }
        if r.problems.len() > 50 {
            println!("  ... and {} more", r.problems.len() - 50);
        }
        Ok(false)
    }
}

fn check(ok: bool, what: &str, hint: &str) {
    if ok {
        println!("  ✓ {what}");
    } else {
        println!("  ✗ {what}\n      → {hint}");
    }
}

fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc_geteuid() == 0 }
    }
    #[cfg(windows)]
    {
        // Reading the Security log requires elevation; a cheap, reliable probe.
        std::process::Command::new("wevtutil")
            .args(["gli", "Security"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(any(unix, windows)))]
    false
}

#[cfg(unix)]
unsafe fn libc_geteuid() -> u32 {
    extern "C" {
        fn geteuid() -> u32;
    }
    geteuid()
}

/// Self-diagnosis: what this agent can and can't see on this host, and
/// how to fix each gap.
pub fn doctor(cfg: &Config, config_path: &Path) -> Result<()> {
    println!("ServerSentinel {} — {}\n", env!("CARGO_PKG_VERSION"), crate::platform::current_os_label());
    println!("Configuration ({})", config_path.display());
    let warnings = cfg.warnings(config_path);
    check(warnings.is_empty(), "configuration", &warnings.join("\n      → "));
    check(
        is_elevated(),
        "running with administrative privileges",
        if cfg!(windows) {
            "run as Administrator / install as a service (LocalSystem) to read the Security log"
        } else {
            "run as root (the systemd unit does) to read auth logs, /proc of other users and the kernel proc connector"
        },
    );

    println!("\nEvent store");
    let db = cfg.event_db_path();
    match EventStore::open_readonly(&db) {
        Ok(store) => {
            let n = store.event_count().unwrap_or(0);
            check(true, &format!("{} ({n} events)", db.display()), "");
            let last = store.get_state("agent.last_alive").ok().flatten();
            check(
                last.is_some(),
                &format!("agent heartbeat: {}", last.as_deref().unwrap_or("never")),
                "the agent hasn't written a heartbeat yet — is the service running?",
            );
        }
        Err(_) => check(false, &format!("{} not found", db.display()), "start the agent once: `server-sentinel run`"),
    }

    println!("\nAccess & command auditing");
    #[cfg(target_os = "linux")]
    {
        use crate::audit::linux_logs::{select_auth_source, AuthSource};
        match select_auth_source(&cfg.security.auth) {
            AuthSource::File(p) => check(
                std::fs::File::open(&p).is_ok(),
                &format!("auth log {} readable", p.display()),
                "needs root (or membership of the adm group)",
            ),
            AuthSource::Journald => check(true, "auth events via journald", ""),
            AuthSource::None => check(false, "auth log source", "install rsyslog, or make sure journalctl is available"),
        }
        check(
            std::path::Path::new("/proc/self/loginuid").exists(),
            "kernel audit identity (loginuid / sessionid) available",
            "kernel built without CONFIG_AUDIT; commands are attributed by process ancestry only",
        );
        check(
            is_elevated(),
            "kernel proc connector usable (every exec captured)",
            "requires root in the host network namespace; otherwise /proc polling is used",
        );
    }
    #[cfg(windows)]
    {
        for (name, r) in crate::audit::windows::channel_status() {
            match r {
                Ok(_) => check(true, &format!("event log: {name}"), ""),
                Err(e) if name.starts_with("OpenSSH") => println!("  - event log: {name}: {e} (fine if OpenSSH Server isn't installed)"),
                Err(e) => check(false, &format!("event log: {name}"), &e.to_string()),
            }
        }
        check(
            crate::audit::windows::process_creation_auditing_enabled(),
            "process creation auditing (Security 4688) enabled",
            "optional but recommended — catches every process, even sub-second ones:\n        \
             auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable\n        \
             and enable GPO 'Include command line in process creation events'. Without it, processes are polled.",
        );
    }

    println!("\nFile integrity monitoring");
    if !cfg.security.fim.enabled {
        println!("  - disabled (security.fim.enabled = false)");
    }
    for p in &cfg.security.fim.paths {
        let found = crate::util::expand_path_pattern(p);
        if found.is_empty() {
            println!("  - {p} (not present on this host)");
        } else {
            check(true, &format!("{p} ({} path{})", found.len(), if found.len() == 1 { "" } else { "s" }), "");
        }
    }

    println!("\nOutputs");
    let n = &cfg.notification;
    println!(
        "  - notifications: console{}{} (alerts at or above '{}')",
        if n.email.enabled { ", email" } else { "" },
        if n.webhook.enabled { ", webhook" } else { "" },
        n.min_alert_severity
    );
    println!(
        "  - forwarding: {}{}",
        if cfg.forward.ndjson.enabled { "ndjson file " } else { "" },
        if cfg.forward.syslog.enabled { format!("syslog {}", cfg.forward.syslog.address) } else { String::new() }
    );
    if !cfg.forward.ndjson.enabled && !cfg.forward.syslog.enabled {
        println!("      → consider forwarding off-box: someone with root can delete the local store, but not what already left the host");
    }
    Ok(())
}
