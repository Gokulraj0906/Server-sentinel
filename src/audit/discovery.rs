//! Startup discovery of sessions that are already open.
//!
//! Log-based collectors only see logins that happen after they start. On
//! a freshly installed agent — or after a restart that missed a logoff —
//! the people *currently* logged in would otherwise be invisible and
//! their commands unattributed. At startup we enumerate live sessions
//! (utmp via `who -u` on Linux; Terminal Services on Windows) and emit
//! `session.start` events for them (merged with any session already
//! known), plus a snapshot so sessions that ended while we were down get
//! closed.

#![cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]

use crate::events::{Category, Event, Outcome};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};

/// Snapshot of which session keys are live right now; the pipeline ends
/// tracked sessions (of the same key kind) that aren't in it. (Linux
/// sessions are reaped by pid liveness instead.)
#[cfg_attr(not(windows), allow(dead_code))]
pub fn snapshot_event(kind: &str, keys: Vec<String>) -> Event {
    let mut e = Event::new(Category::Session, "session.snapshot", "live session snapshot").detail("key_kind", kind);
    e.set_detail("keys", keys);
    e
}

/// Parses `who -u` output:
/// `alice    pts/0        2026-09-25 10:00   .          4242 (203.0.113.9)`
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_who_u(text: &str, now: DateTime<Local>) -> Vec<Event> {
    let mut out = Vec::new();
    for line in text.lines() {
        // The comment is the *first* " (" — it can itself contain
        // parentheses, e.g. "(tmux(4242).%1)".
        let (main, host) = match line.find(" (") {
            Some(i) if line.trim_end().ends_with(')') => {
                let inner = line[i + 2..].trim_end();
                (&line[..i], Some(inner[..inner.len() - 1].to_string()))
            }
            _ => (line, None),
        };
        let f: Vec<&str> = main.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let (user, tty) = (f[0], f[1]);
        // Two date layouts: ISO ("2026-09-25 10:00") or locale ("Sep 25 10:00").
        let (ts, rest) = if f[2].contains('-') {
            let ts = NaiveDateTime::parse_from_str(&format!("{} {}", f[2], f[3]), "%Y-%m-%d %H:%M").ok();
            (ts, &f[4..])
        } else if f.len() >= 6 {
            let ts = NaiveDateTime::parse_from_str(&format!("{} {} {} {}", now.format("%Y"), f[2], f[3], f[4]), "%Y %b %d %H:%M").ok();
            (ts, &f[5..])
        } else {
            continue;
        };
        // rest = [idle, pid, ...]
        let Some(pid) = rest.get(1).and_then(|p| p.parse::<u32>().ok()) else { continue };
        let ts = ts
            .and_then(|n| Local.from_local_datetime(&n).earliest())
            .map(|d| d.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);
        let remote = host.as_deref().filter(|h| !h.is_empty() && !h.starts_with(':') && !h.starts_with("tmux") && !h.contains("screen"));
        let protocol = if remote.is_some() {
            "ssh"
        } else if tty.starts_with("tty") || tty == "console" {
            "console"
        } else {
            // A pts without a remote host is a terminal emulator / tmux
            // pane inside some other session, not a login of its own.
            continue;
        };
        let mut e = Event::new(
            Category::Session,
            "session.start",
            match remote {
                Some(h) => format!("{user} logged in via SSH from {h} (already logged in when the agent started)"),
                None => format!("{user} logged in on {tty} (already logged in when the agent started)"),
            },
        )
        .at(ts)
        .outcome(Outcome::Success)
        .user(user)
        .detail("protocol", protocol)
        .detail("observed_at_startup", true)
        .key(format!("pid:{pid}"))
        .key(format!("tty:{tty}"));
        if let Some(h) = remote {
            e = e.src_ip(h);
        }
        out.push(e);
    }
    out
}

#[cfg(target_os = "linux")]
pub fn discover() -> Vec<Event> {
    let Ok(out) = std::process::Command::new("who").arg("-u").output() else {
        return Vec::new();
    };
    parse_who_u(&String::from_utf8_lossy(&out.stdout), Local::now())
}

#[cfg(windows)]
pub fn discover() -> Vec<Event> {
    use windows_sys::Win32::System::RemoteDesktop::*;

    fn wide(buf: &[u16]) -> String {
        let end = buf.iter().position(|c| *c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }
    fn filetime(ft: i64) -> Option<DateTime<Utc>> {
        // 100ns ticks since 1601-01-01.
        (ft > 0).then(|| DateTime::<Utc>::from_timestamp((ft - 116_444_736_000_000_000) / 10_000_000, 0)).flatten()
    }

    let mut events = Vec::new();
    let mut live_keys = Vec::new();
    // SAFETY: WTS* calls with the documented out-pointer contracts; every
    // buffer they allocate is released with WTSFreeMemory, and struct
    // reads stay within the returned counts/sizes.
    unsafe {
        let mut list: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        if WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut list, &mut count) == 0 {
            return events;
        }
        for i in 0..count as usize {
            let s = &*list.add(i);
            if s.SessionId == 0 || !(s.State == WTSActive || s.State == WTSDisconnected) {
                continue;
            }
            let mut info_ptr: windows_sys::core::PWSTR = std::ptr::null_mut();
            let mut bytes = 0u32;
            if WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, s.SessionId, WTSSessionInfo, &mut info_ptr, &mut bytes) == 0 {
                continue;
            }
            let info = &*(info_ptr as *const WTSINFOW);
            let user = wide(&info.UserName);
            let domain = wide(&info.Domain);
            let station = wide(&info.WinStationName);
            let logon = filetime(info.LogonTime).unwrap_or_else(Utc::now);
            WTSFreeMemory(info_ptr as *mut _);
            if user.is_empty() {
                continue;
            }

            let mut addr_ptr: windows_sys::core::PWSTR = std::ptr::null_mut();
            let mut ip = None;
            if WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, s.SessionId, WTSClientAddress, &mut addr_ptr, &mut bytes) != 0 {
                let a = &*(addr_ptr as *const WTS_CLIENT_ADDRESS);
                // AF_INET = 2: the IPv4 address sits at bytes 2..6.
                if a.AddressFamily == 2 && a.Address[2..6] != [0, 0, 0, 0] {
                    ip = Some(format!("{}.{}.{}.{}", a.Address[2], a.Address[3], a.Address[4], a.Address[5]));
                }
                WTSFreeMemory(addr_ptr as *mut _);
            }
            let rdp = station.to_ascii_lowercase().starts_with("rdp") || ip.is_some();
            let who = if domain.is_empty() { user.clone() } else { format!("{domain}\\{user}") };
            let key = format!("ts:{}", s.SessionId);
            live_keys.push(key.clone());
            let mut e = Event::new(
                Category::Session,
                "session.start",
                if rdp {
                    format!("{who} logged in via RDP{} (already logged in when the agent started)", ip.as_deref().map(|i| format!(" from {i}")).unwrap_or_default())
                } else {
                    format!("{who} logged in on the console (already logged in when the agent started)")
                },
            )
            .at(logon)
            .outcome(Outcome::Success)
            .user(who.clone())
            .detail("protocol", if rdp { "rdp" } else { "console" })
            .detail("observed_at_startup", true)
            .detail("ts_session", s.SessionId)
            .key(key.clone());
            if let Some(ip) = ip {
                e = e.src_ip(ip);
            }
            events.push(e);
            if s.State == WTSDisconnected {
                events.push(
                    Event::new(Category::Session, "session.disconnect", format!("{who} is disconnected (session kept running)"))
                        .at(logon + chrono::Duration::milliseconds(1))
                        .key(key),
                );
            }
        }
        WTSFreeMemory(list as *mut _);
    }
    events.insert(0, snapshot_event("ts", live_keys));
    events
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn discover() -> Vec<Event> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_who_u() {
        let text = "\
alice    pts/0        2026-09-25 10:00   .          4242 (203.0.113.9)
bob      tty1         2026-09-25 08:12  01:20        901
carol    pts/3        2026-09-25 11:05   .          5555 (tmux(4242).%1)
dave     pts/4        Sep 25 11:30   .          6001 (10.0.0.7)
";
        let evs = parse_who_u(text, Local::now());
        assert_eq!(evs.len(), 3, "tmux pane is not a login");
        assert_eq!((evs[0].user.as_deref(), evs[0].src_ip.as_deref()), (Some("alice"), Some("203.0.113.9")));
        assert_eq!(evs[0].keys, vec!["pid:4242", "tty:pts/0"]);
        assert_eq!(evs[1].detail_str("protocol"), Some("console"));
        assert_eq!((evs[2].user.as_deref(), evs[2].keys[0].as_str()), (Some("dave"), "pid:6001"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_discovery_runs() {
        // CI runners may have no interactive session at all, so only the
        // snapshot is guaranteed; on a desktop this also lists the user.
        let evs = discover();
        assert_eq!(evs[0].action, "session.snapshot");
        for e in &evs[1..] {
            assert!(e.action.starts_with("session."), "{}", e.action);
            assert!(e.keys[0].starts_with("ts:"));
        }
    }
}
