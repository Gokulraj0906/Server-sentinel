//! Windows audit collectors.
//!
//! **Event log**: polls each channel with `wevtutil qe` using an XPath
//! filter on `EventRecordID > watermark`, so every event is read exactly
//! once — including across agent restarts (the watermark is a pipeline
//! checkpoint). `wevtutil` ships with every Windows version since Vista
//! and needs no extra runtime.
//!
//! **Processes**: when "Audit Process Creation" is enabled, Security 4688
//! gives every process with its creator logon id. Otherwise the process
//! table is polled and each new process is tagged with its Terminal
//! Services session id (`ProcessIdToSessionId`), which maps it onto the
//! RDP/console session from TerminalServices event 21.

#![cfg_attr(not(windows), allow(dead_code))]

use crate::audit::linux_logs::sleep_while_running;
use crate::audit::winevent::{map_event, parse_events};
use crate::core::config::{AuthSourceConfig, ProcessAuditConfig};
use crate::events::{Category, Event, EventBus, Outcome, ProcessInfo};
use crate::storage::event_store::EventStore;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

struct Channel {
    name: &'static str,
    /// XPath System-level filter (without the record id clause).
    filter: String,
    watermark: u64,
    disabled_until: Option<Instant>,
    warned: bool,
}

const PAGE: usize = 250;
const MAX_PAGES_PER_POLL: usize = 40;

fn id_filter(ids: &[u32]) -> String {
    ids.iter().map(|i| format!("EventID={i}")).collect::<Vec<_>>().join(" or ")
}

fn channel_specs(include_process_creation: bool) -> Vec<(&'static str, String)> {
    let mut security = vec![
        4624, 4625, 4634, 4647, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4740, 4756, 4698, 1102,
    ];
    if include_process_creation {
        security.push(4688);
    }
    vec![
        ("Security", format!("({})", id_filter(&security))),
        ("System", format!("({})", id_filter(&[7045, 104]))),
        (
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            format!("({})", id_filter(&[21, 23, 24, 25])),
        ),
        ("OpenSSH/Operational", String::new()),
        ("Application", format!("Provider[@Name='MsiInstaller'] and ({})", id_filter(&[1033, 1034]))),
    ]
}

fn xpath(filter: &str, after: u64) -> String {
    if filter.is_empty() {
        format!("*[System[EventRecordID > {after}]]")
    } else {
        format!("*[System[{filter} and EventRecordID > {after}]]")
    }
}

#[derive(Debug)]
enum WevError {
    NotFound,
    AccessDenied,
    Other(String),
}

fn hidden_command(program: &str) -> Command {
    #[allow(unused_mut)]
    let mut cmd = Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

fn decode_utf16(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes);
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16_lossy(&units)
}

fn wevtutil(args: &[String]) -> Result<String, WevError> {
    let out = hidden_command("wevtutil")
        .args(args)
        .arg("/uni:true")
        .output()
        .map_err(|e| WevError::Other(e.to_string()))?;
    match out.status.code() {
        Some(0) => Ok(decode_utf16(&out.stdout)),
        Some(15007) => Err(WevError::NotFound),
        Some(5) => Err(WevError::AccessDenied),
        _ => Err(WevError::Other(
            String::from_utf8_lossy(&out.stderr).trim().to_string() + &decode_utf16(&out.stderr),
        )),
    }
}

fn latest_record_id(channel: &str) -> Result<u64, WevError> {
    let xml = wevtutil(&[
        "qe".into(),
        channel.into(),
        "/c:1".into(),
        "/rd:true".into(),
        "/f:xml".into(),
        "/e:Events".into(),
    ])?;
    Ok(parse_events(&xml).first().map(|e| e.record_id).unwrap_or(0))
}

/// Security 4688 is only logged if process-creation auditing is enabled
/// (Advanced Audit Policy > Detailed Tracking > Audit Process Creation).
pub fn process_creation_auditing_enabled() -> bool {
    // GUID instead of the subcategory name: names are localized.
    hidden_command("auditpol")
        .args(["/get", "/subcategory:{0CCE922B-69AE-11D9-BED3-505054503030}", "/r"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            let text = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
            text.lines().skip(1).any(|l| l.contains("success"))
        })
        .unwrap_or(false)
}

pub fn spawn_eventlog(
    cfg: &AuthSourceConfig,
    include_process_creation: bool,
    store: &EventStore,
    bus: EventBus,
    running: Arc<AtomicBool>,
) -> Result<JoinHandle<()>> {
    let mut channels = Vec::new();
    for (name, filter) in channel_specs(include_process_creation) {
        let key = format!("winlog:{name}");
        let saved: Option<u64> = store.get_state(&key)?.and_then(|v| v.parse().ok());
        let watermark = match saved {
            Some(w) => w,
            None => match latest_record_id(name) {
                // First start: begin at "now", or (backfill) include the
                // most recent history.
                Ok(latest) if cfg.backfill => latest.saturating_sub(5000),
                Ok(latest) => latest,
                Err(_) => 0,
            },
        };
        channels.push(Channel {
            name,
            filter,
            watermark,
            disabled_until: None,
            warned: false,
        });
    }
    let interval = Duration::from_secs(cfg.poll_interval_seconds.max(1));
    let self_pid = std::process::id();
    Ok(std::thread::Builder::new().name("audit-eventlog".into()).spawn(move || {
        while running.load(Ordering::SeqCst) {
            for ch in channels.iter_mut() {
                if ch.disabled_until.map(|t| Instant::now() < t).unwrap_or(false) {
                    continue;
                }
                if !poll_channel(ch, self_pid, &bus) {
                    return;
                }
            }
            sleep_while_running(&running, interval);
        }
    })?)
}

/// Returns false once the pipeline has gone away.
fn poll_channel(ch: &mut Channel, self_pid: u32, bus: &EventBus) -> bool {
    for _ in 0..MAX_PAGES_PER_POLL {
        let args = vec![
            "qe".to_string(),
            ch.name.to_string(),
            format!("/q:{}", xpath(&ch.filter, ch.watermark)),
            "/f:xml".into(),
            format!("/c:{PAGE}"),
            "/e:Events".into(),
        ];
        let xml = match wevtutil(&args) {
            Ok(x) => x,
            Err(e) => {
                let (retry, msg) = match &e {
                    WevError::NotFound => (Duration::from_secs(600), "channel not present on this host".to_string()),
                    WevError::AccessDenied => (
                        Duration::from_secs(300),
                        "access denied — run the agent as LocalSystem / an administrator".to_string(),
                    ),
                    WevError::Other(m) => (Duration::from_secs(60), m.clone()),
                };
                if !ch.warned {
                    // A missing OpenSSH channel is the normal case.
                    if matches!(e, WevError::NotFound) && ch.name.starts_with("OpenSSH") {
                        tracing::debug!(channel = ch.name, "{msg}");
                    } else {
                        tracing::warn!(channel = ch.name, "event log channel unavailable: {msg}");
                    }
                    ch.warned = true;
                }
                ch.disabled_until = Some(Instant::now() + retry);
                return true;
            }
        };
        if ch.warned {
            tracing::info!(channel = ch.name, "event log channel is readable again");
            ch.warned = false;
        }
        let events = parse_events(&xml);
        let n = events.len();
        let mut max_id = ch.watermark;
        for we in &events {
            max_id = max_id.max(we.record_id);
            for ev in map_event(we, self_pid) {
                if !bus.emit(ev) {
                    return false;
                }
            }
        }
        if max_id > ch.watermark {
            ch.watermark = max_id;
            bus.checkpoint(format!("winlog:{}", ch.name), max_id.to_string());
        }
        if n < PAGE {
            break;
        }
    }
    true
}

#[cfg(windows)]
fn ts_session_id(pid: u32) -> Option<u32> {
    let mut sid: u32 = 0;
    // SAFETY: ProcessIdToSessionId writes one u32 through the pointer.
    let ok = unsafe { windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(pid, &mut sid) };
    (ok != 0).then_some(sid)
}

#[cfg(not(windows))]
fn ts_session_id(_pid: u32) -> Option<u32> {
    None
}

pub fn spawn_process_poll(cfg: &ProcessAuditConfig, bus: EventBus, running: Arc<AtomicBool>) -> Result<JoinHandle<()>> {
    use sysinfo::{ProcessRefreshKind, System, UpdateKind, Users};
    let interval = Duration::from_millis(cfg.poll_interval_ms.max(250));
    Ok(std::thread::Builder::new().name("audit-procpoll".into()).spawn(move || {
        let kind = ProcessRefreshKind::new()
            .with_cmd(UpdateKind::OnlyIfNotSet)
            .with_exe(UpdateKind::OnlyIfNotSet)
            .with_cwd(UpdateKind::OnlyIfNotSet)
            .with_user(UpdateKind::OnlyIfNotSet);
        let mut sys = System::new();
        sys.refresh_processes_specifics(kind);
        let mut users = Users::new_with_refreshed_list();
        let mut users_refreshed = Instant::now();
        let self_pid = std::process::id();
        let mut known: HashMap<u32, u64> = sys.processes().iter().map(|(p, pr)| (p.as_u32(), pr.start_time())).collect();
        tracing::info!(interval_ms = interval.as_millis() as u64, "process auditing: process table polling");

        while running.load(Ordering::SeqCst) {
            std::thread::sleep(interval);
            sys.refresh_processes_specifics(kind);
            let parent_of: HashMap<u32, u32> = sys
                .processes()
                .iter()
                .filter_map(|(p, pr)| pr.parent().map(|pp| (p.as_u32(), pp.as_u32())))
                .collect();
            let mut fresh: Vec<(u64, u32)> = Vec::new();
            let mut next = HashMap::with_capacity(known.len());
            for (pid, p) in sys.processes() {
                let pid = pid.as_u32();
                next.insert(pid, p.start_time());
                if known.get(&pid) != Some(&p.start_time()) {
                    fresh.push((p.start_time(), pid));
                }
            }
            known = next;
            fresh.sort_unstable();
            for (_, pid) in fresh {
                let Some(p) = sys.process(sysinfo::Pid::from_u32(pid)) else { continue };
                let mut ancestors = Vec::new();
                let mut cur = parent_of.get(&pid).copied();
                while let Some(a) = cur {
                    if ancestors.len() >= 16 || ancestors.contains(&a) {
                        break;
                    }
                    ancestors.push(a);
                    cur = parent_of.get(&a).copied();
                }
                if pid == self_pid || ancestors.contains(&self_pid) {
                    continue;
                }
                // Every console program gets a conhost.exe host; recording
                // them doubles the volume and adds nothing. Matched by full
                // path so a lookalike dropped elsewhere is still recorded.
                if p.exe().map(|e| e.to_string_lossy().eq_ignore_ascii_case(r"C:\Windows\System32\conhost.exe")).unwrap_or(false) {
                    continue;
                }
                let run_as = p.user_id().and_then(|uid| {
                    if users.get_user_by_id(uid).is_none() && users_refreshed.elapsed() > Duration::from_secs(60) {
                        users.refresh_list();
                        users_refreshed = Instant::now();
                    }
                    users.get_user_by_id(uid).map(|u| u.name().to_string())
                });
                let cmd = p.cmd().join(" ");
                let parent_name = p.parent().and_then(|pp| sys.process(pp)).map(|pp| pp.name().to_string());
                let mut ev = Event::new(
                    Category::Process,
                    "process.start",
                    if cmd.is_empty() { p.name().to_string() } else { crate::util::truncate(&cmd, 1000) },
                )
                .outcome(Outcome::Success)
                .process(ProcessInfo {
                    pid,
                    ppid: p.parent().map(|pp| pp.as_u32()),
                    name: p.name().to_string(),
                    exe: p.exe().map(|e| e.display().to_string()),
                    command_line: (!cmd.is_empty()).then_some(cmd),
                    cwd: p.cwd().map(|c| c.display().to_string()).filter(|c| !c.is_empty()),
                    parent_name,
                    run_as,
                });
                if let Some(sid) = ts_session_id(pid) {
                    ev.set_detail("ts_session", sid);
                    if sid != 0 {
                        ev.keys.push(format!("ts:{sid}"));
                    }
                }
                for a in &ancestors {
                    ev.keys.push(format!("pid:{a}"));
                }
                ev.learn.push(format!("pid:{pid}"));
                if !bus.emit(ev) {
                    return;
                }
            }
        }
    })?)
}

/// Doctor check: can we read each channel?
pub fn channel_status() -> Vec<(&'static str, Result<u64>)> {
    channel_specs(false)
        .into_iter()
        .map(|(name, _)| {
            let r = latest_record_id(name).map_err(|e| match e {
                WevError::NotFound => anyhow!("not present on this host"),
                WevError::AccessDenied => anyhow!("access denied (run as administrator / LocalSystem)"),
                WevError::Other(m) => anyhow!(m),
            });
            (name, r)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xpath_and_utf16() {
        assert_eq!(xpath("(EventID=21 or EventID=23)", 10), "*[System[(EventID=21 or EventID=23) and EventRecordID > 10]]");
        assert_eq!(xpath("", 0), "*[System[EventRecordID > 0]]");
        assert_eq!(decode_utf16(&[0xff, 0xfe, b'<', 0, b'E', 0, 0xe9, 0]), "<Eé");
    }

    #[cfg(windows)]
    #[test]
    fn reads_a_real_channel() {
        // The RDP session log is readable without elevation on Windows 10/11.
        let id = latest_record_id("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational");
        assert!(id.is_ok(), "{id:?}");
        assert!(matches!(latest_record_id("No-Such-Channel/Operational"), Err(WevError::NotFound)));
    }
}
