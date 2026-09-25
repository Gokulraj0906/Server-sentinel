//! Windows Event Log XML -> events.
//!
//! Parsing and mapping are pure functions compiled on every platform (so
//! they're unit-tested everywhere against real event XML); the collector
//! that queries the log lives in `audit::windows`.
//!
//! | Channel | IDs | Meaning |
//! |---|---|---|
//! | Security | 4624 / 4625 | logon success / failure (type 10 = RDP, 2 = console, 3 = network) |
//! | Security | 4634 / 4647 | logoff |
//! | Security | 4688 | process creation (when "Audit Process Creation" is on) |
//! | Security | 4720-4726, 4728/4732/4756, 4740 | account and group changes, lockouts |
//! | Security | 4698 | scheduled task created |
//! | Security | 1102 | **audit log cleared** |
//! | System | 7045 / 104 | service installed / event log cleared |
//! | TerminalServices-LocalSessionManager/Operational | 21/23/24/25 | RDP logon/logoff/disconnect/reconnect |
//! | OpenSSH/Operational | * | Win32-OpenSSH (same messages as Linux sshd) |
//! | Application (MsiInstaller) | 1033 / 1034 | product installed / removed |

use crate::audit::authlog::parse_auth_message;
use crate::events::{Category, Event, Outcome, ProcessInfo, Severity};
use crate::util::is_meaningful_remote_ip;
use chrono::{DateTime, Utc};
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct WinEvent {
    pub provider: String,
    pub event_id: u32,
    pub record_id: u64,
    pub ts: DateTime<Utc>,
    pub computer: String,
    pub channel: String,
    pub pid: Option<u32>,
    pub user_sid: Option<String>,
    pub data: HashMap<String, String>,
    pub unnamed: Vec<String>,
}

impl WinEvent {
    fn get(&self, k: &str) -> &str {
        self.data.get(k).map(|s| s.as_str()).unwrap_or("")
    }
}

fn resolve_entity(name: &str) -> String {
    match name {
        "amp" => "&".into(),
        "lt" => "<".into(),
        "gt" => ">".into(),
        "quot" => "\"".into(),
        "apos" => "'".into(),
        n if n.starts_with("#x") || n.starts_with("#X") => u32::from_str_radix(&n[2..], 16)
            .ok()
            .and_then(char::from_u32)
            .map(String::from)
            .unwrap_or_default(),
        n if n.starts_with('#') => n[1..].parse().ok().and_then(char::from_u32).map(String::from).unwrap_or_default(),
        n => format!("&{n};"),
    }
}

fn attr(e: &quick_xml::events::BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.local_name().as_ref() == name)
        .and_then(|a| a.normalized_value(quick_xml::XmlVersion::Implicit1_0).ok().map(|v| v.into_owned()))
}

/// Parses `wevtutil qe ... /f:xml` output: any number of `<Event>`
/// elements, optionally wrapped in a root element.
pub fn parse_events(xml: &str) -> Vec<WinEvent> {
    let mut reader = Reader::from_str(xml);
    // No trim_text: it trims around entity references too, turning
    // "a &amp;&amp; b" into "a&&b". Leaf values are trimmed at their end tag.
    reader.config_mut().trim_text(false);
    let mut out = Vec::new();
    let mut cur: Option<WinEvent> = None;
    // (local name, has child elements)
    let mut stack: Vec<(String, bool)> = Vec::new();
    let mut text = String::new();
    let mut data_name: Option<String> = None;
    let mut in_user_data = false;

    let on_attrs = |cur: &mut Option<WinEvent>, name: &str, e: &quick_xml::events::BytesStart<'_>| {
        let Some(ev) = cur.as_mut() else { return };
        match name {
            "Provider" => ev.provider = attr(e, "Name").unwrap_or_default(),
            "TimeCreated" => {
                if let Some(t) = attr(e, "SystemTime").and_then(|s| DateTime::parse_from_rfc3339(&s).ok()) {
                    ev.ts = t.with_timezone(&Utc);
                }
            }
            "Execution" => ev.pid = attr(e, "ProcessID").and_then(|p| p.parse().ok()),
            "Security" => ev.user_sid = attr(e, "UserID"),
            _ => {}
        }
    };

    loop {
        match reader.read_event() {
            Ok(XmlEvent::Start(e)) => {
                let name = e.local_name().as_ref().to_string();
                if let Some(parent) = stack.last_mut() {
                    parent.1 = true;
                }
                if name == "Event" {
                    cur = Some(WinEvent::default());
                    in_user_data = false;
                }
                if name == "UserData" {
                    in_user_data = true;
                }
                if name == "Data" {
                    data_name = attr(&e, "Name");
                }
                on_attrs(&mut cur, &name, &e);
                stack.push((name, false));
                text.clear();
            }
            Ok(XmlEvent::Empty(e)) => {
                let name = e.local_name().as_ref().to_string();
                if let Some(parent) = stack.last_mut() {
                    parent.1 = true;
                }
                on_attrs(&mut cur, &name, &e);
                if let Some(ev) = cur.as_mut() {
                    if name == "Data" {
                        match attr(&e, "Name") {
                            Some(n) => {
                                ev.data.insert(n, String::new());
                            }
                            None => ev.unnamed.push(String::new()),
                        }
                    } else if in_user_data {
                        ev.data.insert(name, String::new());
                    }
                }
            }
            Ok(XmlEvent::Text(t)) => text.push_str(&t.xml10_content()),
            Ok(XmlEvent::CData(t)) => text.push_str(&t.xml10_content()),
            Ok(XmlEvent::GeneralRef(r)) => text.push_str(&resolve_entity(&r)),
            Ok(XmlEvent::End(_)) => {
                let Some((name, had_children)) = stack.pop() else { continue };
                if let Some(ev) = cur.as_mut() {
                    let value = std::mem::take(&mut text).trim().to_string();
                    match name.as_str() {
                        "EventID" => ev.event_id = value.parse().unwrap_or(0),
                        "EventRecordID" => ev.record_id = value.parse().unwrap_or(0),
                        "Computer" => ev.computer = value,
                        "Channel" => ev.channel = value,
                        "Data" => match data_name.take() {
                            Some(n) => {
                                ev.data.insert(n, value);
                            }
                            None => ev.unnamed.push(value),
                        },
                        "UserData" => in_user_data = false,
                        "Event" => {
                            if let Some(done) = cur.take() {
                                out.push(done);
                            }
                        }
                        n if in_user_data && !had_children => {
                            ev.data.insert(n.to_string(), value);
                        }
                        _ => {}
                    }
                }
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                tracing::debug!(error = %e, "malformed event XML; keeping events parsed so far");
                break;
            }
        }
    }
    out
}

fn is_service_account(domain: &str, user: &str) -> bool {
    let u = user.to_ascii_uppercase();
    let d = domain.to_ascii_uppercase();
    user.is_empty()
        || user == "-"
        || user.ends_with('$')
        || matches!(u.as_str(), "SYSTEM" | "LOCAL SERVICE" | "NETWORK SERVICE" | "ANONYMOUS LOGON")
        || u.starts_with("DWM-")
        || u.starts_with("UMFD-")
        || matches!(d.as_str(), "NT AUTHORITY" | "WINDOW MANAGER" | "FONT DRIVER HOST" | "NT SERVICE")
}

fn fmt_user(domain: &str, user: &str) -> String {
    if domain.is_empty() || domain == "-" {
        user.to_string()
    } else {
        format!("{domain}\\{user}")
    }
}

fn hex_u32(s: &str) -> Option<u32> {
    let s = s.trim();
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map_or_else(|| s.parse().ok(), |h| u32::from_str_radix(h, 16).ok())
}

fn logon_key(id: &str) -> Option<String> {
    let id = id.trim().to_ascii_lowercase();
    (!id.is_empty() && id != "0x0" && id != "-").then(|| format!("logon:{id}"))
}

fn basename(p: &str) -> String {
    p.rsplit(['\\', '/']).next().unwrap_or(p).to_string()
}

/// NTSTATUS sub-status codes worth naming in 4625s.
fn failure_reason(ev: &WinEvent) -> String {
    let code = if ev.get("SubStatus").is_empty() || ev.get("SubStatus") == "0x0" {
        ev.get("Status")
    } else {
        ev.get("SubStatus")
    };
    match code.to_ascii_lowercase().as_str() {
        "0xc000006a" => "wrong password",
        "0xc0000064" => "no such user",
        "0xc0000234" => "account locked out",
        "0xc0000072" => "account disabled",
        "0xc000006f" => "outside allowed hours",
        "0xc0000070" => "workstation restriction",
        "0xc0000071" => "password expired",
        "0xc0000193" => "account expired",
        "0xc0000224" => "password must change",
        "0xc000015b" => "logon type not granted",
        "" => "unknown",
        other => return format!("status {other}"),
    }
    .to_string()
}

/// Maps one event to zero or more normalized events. `self_pid` lets us
/// ignore processes the agent itself spawns (wevtutil, powershell).
pub fn map_event(ev: &WinEvent, self_pid: u32) -> Vec<Event> {
    let out: Option<Event> = match (ev.provider.as_str(), ev.event_id) {
        ("Microsoft-Windows-Security-Auditing", id) => map_security(ev, id, self_pid),
        ("Microsoft-Windows-Eventlog", 1102) => Some(
            Event::new(
                Category::Agent,
                "log.cleared",
                format!("Windows Security log was CLEARED by {}", fmt_user(ev.get("SubjectDomainName"), ev.get("SubjectUserName"))),
            )
            .severity(Severity::High)
            .user(fmt_user(ev.get("SubjectDomainName"), ev.get("SubjectUserName")))
            .target("Security"),
        ),
        ("Microsoft-Windows-Eventlog", 104) => Some(
            Event::new(
                Category::Agent,
                "log.cleared",
                format!("Windows event log '{}' was cleared by {}", ev.get("Channel"), fmt_user(ev.get("SubjectDomainName"), ev.get("SubjectUserName"))),
            )
            .severity(Severity::High)
            .user(fmt_user(ev.get("SubjectDomainName"), ev.get("SubjectUserName")))
            .target(ev.get("Channel")),
        ),
        ("Service Control Manager", 7045) => Some(
            Event::new(
                Category::Service,
                "service.installed",
                format!("Service installed: {} ({})", ev.get("ServiceName"), ev.get("ImagePath")),
            )
            .outcome(Outcome::Success)
            .target(ev.get("ServiceName"))
            .detail("image_path", ev.get("ImagePath"))
            .detail("start_type", ev.get("StartType"))
            .detail("account", ev.get("AccountName")),
        ),
        ("Microsoft-Windows-TerminalServices-LocalSessionManager", id) => map_lsm(ev, id),
        ("OpenSSH", _) => {
            let payload = ev
                .data
                .get("payload")
                .cloned()
                .or_else(|| ev.unnamed.last().cloned())
                .unwrap_or_default();
            // Win32-OpenSSH payloads look like "sshd: Accepted ..." on
            // some versions; strip a leading "<ident>: ".
            let msg = match payload.split_once(": ") {
                Some((ident, rest)) if ident.starts_with("sshd") && !ident.contains(' ') => rest.to_string(),
                _ => payload,
            };
            return parse_auth_message(ev.ts, "sshd", ev.pid, &msg);
        }
        ("MsiInstaller", 1033 | 1034) => {
            let name = ev.unnamed.first().cloned().unwrap_or_default();
            let version = ev.unnamed.get(1).cloned().unwrap_or_default();
            let status = ev.unnamed.get(3).cloned().unwrap_or_default();
            let (action, verb) = if ev.event_id == 1033 {
                ("package.installed", "Installed")
            } else {
                ("package.removed", "Removed")
            };
            Some(
                Event::new(Category::Package, action, format!("{verb} {name} {version}"))
                    .outcome(if status == "0" { Outcome::Success } else { Outcome::Failure })
                    .target(name)
                    .detail("version", version)
                    .detail("status", status),
            )
        }
        _ => None,
    };
    out.map(|e| {
        let mut e = e.at(ev.ts);
        e.set_detail("win_event_id", ev.event_id);
        e
    })
    .into_iter()
    .collect()
}

fn map_security(ev: &WinEvent, id: u32, self_pid: u32) -> Option<Event> {
    let subject = fmt_user(ev.get("SubjectDomainName"), ev.get("SubjectUserName"));
    let subject_key = logon_key(ev.get("SubjectLogonId"));
    let target_user = fmt_user(ev.get("TargetDomainName"), ev.get("TargetUserName"));
    let with_subject = |mut e: Event| {
        if !is_service_account(ev.get("SubjectDomainName"), ev.get("SubjectUserName")) {
            e = e.user(subject.clone());
        }
        if let Some(k) = &subject_key {
            e.keys.push(k.clone());
        }
        e
    };
    match id {
        4624 => {
            if is_service_account(ev.get("TargetDomainName"), ev.get("TargetUserName")) {
                return None;
            }
            let logon_type: u32 = ev.get("LogonType").parse().unwrap_or(0);
            let ip = ev.get("IpAddress").to_string();
            let process = ev.get("LogonProcessName").trim().to_string();
            let mut keys: Vec<String> = [ev.get("TargetLogonId"), ev.get("TargetLinkedLogonId")]
                .iter()
                .filter_map(|k| logon_key(k))
                .collect();
            keys.dedup();
            let mut e = match logon_type {
                2 | 10 | 11 | 12 if process.eq_ignore_ascii_case("User32") => {
                    let protocol = if matches!(logon_type, 10 | 12) { "rdp" } else { "console" };
                    Event::new(
                        Category::Session,
                        "session.start",
                        if protocol == "rdp" {
                            format!("{target_user} logged in via RDP from {ip}")
                        } else {
                            format!("{target_user} logged in on the console")
                        },
                    )
                    .detail("protocol", protocol)
                }
                7 => Event::new(Category::Auth, "auth.unlock", format!("{target_user} unlocked the workstation")).detail("protocol", "console"),
                3 | 8 if is_meaningful_remote_ip(&ip) => Event::new(
                    Category::Auth,
                    "auth.success",
                    format!("{target_user} authenticated over the network from {ip} ({})", ev.get("AuthenticationPackageName")),
                )
                .detail("protocol", "network"),
                _ => return None,
            }
            .outcome(Outcome::Success)
            .user(target_user)
            .detail("logon_type", logon_type)
            .detail("auth_method", ev.get("AuthenticationPackageName"));
            if is_meaningful_remote_ip(&ip) {
                e = e.src_ip(ip);
                if let Ok(port) = ev.get("IpPort").parse::<u64>() {
                    e.set_detail("src_port", port);
                }
            }
            if !ev.get("WorkstationName").is_empty() && ev.get("WorkstationName") != "-" {
                e.set_detail("workstation", ev.get("WorkstationName"));
            }
            if ev.get("ElevatedToken").contains("1842") {
                e.set_detail("elevated_token", true);
            }
            e.keys = keys;
            Some(e)
        }
        4625 => {
            let logon_type: u32 = ev.get("LogonType").parse().unwrap_or(0);
            let protocol = match logon_type {
                10 | 12 => "rdp",
                2 | 11 => "console",
                _ => "network",
            };
            let ip = ev.get("IpAddress");
            let reason = failure_reason(ev);
            Some(
                Event::new(
                    Category::Auth,
                    "auth.failure",
                    format!("Failed {protocol} logon for {target_user}{} ({reason})", if is_meaningful_remote_ip(ip) { format!(" from {ip}") } else { String::new() }),
                )
                .outcome(Outcome::Failure)
                .user(target_user)
                .src_ip(if is_meaningful_remote_ip(ip) { ip } else { "" })
                .detail("protocol", protocol)
                .detail("logon_type", logon_type)
                .detail("reason", reason)
                .detail("workstation", ev.get("WorkstationName")),
            )
        }
        4634 | 4647 => {
            let key = logon_key(ev.get("TargetLogonId"))?;
            Some(Event::new(Category::Session, "session.end", format!("{target_user} logged off")).key(key))
        }
        4688 => {
            let creator = hex_u32(ev.get("ProcessId"));
            if creator == Some(self_pid) {
                return None;
            }
            let pid = hex_u32(ev.get("NewProcessId")).unwrap_or(0);
            let path = ev.get("NewProcessName").to_string();
            let cmd = ev.get("CommandLine").to_string();
            let mut e = with_subject(
                Event::new(Category::Process, "process.start", if cmd.is_empty() { path.clone() } else { cmd.clone() })
                    .outcome(Outcome::Success)
                    .process(ProcessInfo {
                        pid,
                        ppid: creator,
                        name: basename(&path),
                        exe: Some(path.clone()),
                        command_line: (!cmd.is_empty()).then_some(cmd),
                        parent_name: Some(basename(ev.get("ParentProcessName"))).filter(|s| !s.is_empty()),
                        run_as: Some(subject.clone()),
                        ..Default::default()
                    }),
            );
            if let Some(k) = logon_key(ev.get("TargetLogonId")) {
                e.keys.push(k);
            }
            if let Some(c) = creator {
                e.keys.push(format!("pid:{c}"));
            }
            e.learn.push(format!("pid:{pid}"));
            Some(e)
        }
        4720 | 4722 | 4725 | 4726 | 4723 | 4724 | 4740 => {
            let (action, verb) = match id {
                4720 => ("account.user_created", "created"),
                4722 => ("account.user_enabled", "enabled"),
                4725 => ("account.user_disabled", "disabled"),
                4726 => ("account.user_deleted", "deleted"),
                4723 => ("account.password_changed", "password changed"),
                4724 => ("account.password_reset", "password reset"),
                _ => ("account.locked_out", "locked out"),
            };
            let mut e = with_subject(
                Event::new(Category::Account, action, format!("User account {target_user} {verb} by {subject}"))
                    .outcome(Outcome::Success)
                    .target(target_user.clone()),
            );
            if id == 4740 {
                e.message = format!("User account {target_user} locked out (caller: {})", ev.get("TargetDomainName"));
                e.severity = Severity::Low;
            }
            Some(e)
        }
        4728 | 4732 | 4756 => {
            let group = ev.get("TargetUserName").to_string();
            let member = match ev.get("MemberName") {
                "" | "-" => ev.get("MemberSid").to_string(),
                dn => dn.split(',').next().unwrap_or(dn).trim_start_matches("CN=").to_string(),
            };
            Some(with_subject(
                Event::new(Category::Account, "account.group_member_added", format!("{member} added to group {group} by {subject}"))
                    .outcome(Outcome::Success)
                    .target(member.clone())
                    .detail("group", group)
                    .detail("member", member),
            ))
        }
        4698 => Some(with_subject(
            Event::new(Category::Service, "persistence.scheduled_task", format!("Scheduled task created: {} by {subject}", ev.get("TaskName")))
                .outcome(Outcome::Success)
                .target(ev.get("TaskName")),
        )),
        _ => None,
    }
}

fn map_lsm(ev: &WinEvent, id: u32) -> Option<Event> {
    let session = ev.get("SessionID");
    if session.is_empty() || session == "0" {
        return None;
    }
    let key = format!("ts:{session}");
    let user = ev.get("User").to_string();
    let addr = ev.get("Address");
    let remote = is_meaningful_remote_ip(addr);
    let protocol = if remote { "rdp" } else { "console" };
    let e = match id {
        21 => Event::new(
            Category::Session,
            "session.start",
            if remote {
                format!("{user} logged in via RDP from {addr}")
            } else {
                format!("{user} logged in on the console")
            },
        )
        .outcome(Outcome::Success)
        .detail("protocol", protocol),
        23 => Event::new(Category::Session, "session.end", format!("{user} logged off")),
        24 => Event::new(Category::Session, "session.disconnect", format!("{user} disconnected{}", if remote { format!(" (from {addr})") } else { String::new() })),
        25 => Event::new(
            Category::Session,
            "session.reconnect",
            format!("{user} reconnected{}", if remote { format!(" from {addr}") } else { String::new() }),
        )
        .detail("protocol", protocol),
        _ => return None,
    };
    let mut e = e.user(user).key(key).detail("ts_session", session);
    if remote {
        e = e.src_ip(addr);
    }
    Some(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real events captured from a Windows 11 host.
    const LSM: &str = r#"<Events><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager' Guid='{5d896912-022d-40aa-a3a8-4fa5515c76d7}'/><EventID>21</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x1000000000000000</Keywords><TimeCreated SystemTime='2026-09-25T17:59:52.0295141Z'/><EventRecordID>4484</EventRecordID><Correlation ActivityID='{f481c0b9-876b-4e50-89e4-06f173170000}'/><Execution ProcessID='1564' ThreadID='22696'/><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Gokulraj</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>GOKULRAJ\ABCOM</User><SessionID>2</SessionID><Address>LOCAL</Address></EventXML></UserData></Event><Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TerminalServices-LocalSessionManager' Guid='{5d896912-022d-40aa-a3a8-4fa5515c76d7}'/><EventID>23</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x1000000000000000</Keywords><TimeCreated SystemTime='2026-09-25T14:01:11.4582606Z'/><EventRecordID>4463</EventRecordID><Correlation ActivityID='{f4808c1a-90e8-4c94-ac52-f42141280000}'/><Execution ProcessID='1564' ThreadID='22696'/><Channel>Microsoft-Windows-TerminalServices-LocalSessionManager/Operational</Channel><Computer>Gokulraj</Computer><Security UserID='S-1-5-18'/></System><UserData><EventXML xmlns='Event_NS'><User>GOKULRAJ\ABCOM</User><SessionID>1</SessionID></EventXML></UserData></Event></Events>"#;

    fn security(id: u32, data: &[(&str, &str)]) -> String {
        let fields: String = data.iter().map(|(k, v)| format!("<Data Name='{k}'>{v}</Data>")).collect();
        format!(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/><EventID>{id}</EventID><TimeCreated SystemTime='2026-09-25T10:00:00.1234567Z'/><EventRecordID>{}</EventRecordID><Execution ProcessID='812' ThreadID='1'/><Channel>Security</Channel><Computer>WEB01</Computer><Security/></System><EventData>{fields}</EventData></Event>",
            90000 + id
        )
    }

    #[test]
    fn parses_real_rdp_session_events() {
        let evs = parse_events(LSM);
        assert_eq!(evs.len(), 2);
        assert_eq!((evs[0].event_id, evs[0].record_id, evs[0].pid), (21, 4484, Some(1564)));
        assert_eq!(evs[0].data.get("User").map(String::as_str), Some("GOKULRAJ\\ABCOM"));
        assert_eq!(evs[0].ts.to_rfc3339(), "2026-09-25T17:59:52.029514100+00:00");

        let start = &map_event(&evs[0], 1)[0];
        assert_eq!((start.action.as_str(), start.detail_str("protocol")), ("session.start", Some("console")));
        assert_eq!(start.keys, vec!["ts:2"]);
        assert_eq!(start.src_ip, None, "LOCAL is not a source address");
        let end = &map_event(&evs[1], 1)[0];
        assert_eq!((end.action.as_str(), end.keys[0].as_str()), ("session.end", "ts:1"));
    }

    #[test]
    fn rdp_logon_and_failures() {
        let xml = security(4624, &[
            ("SubjectUserSid", "S-1-5-18"), ("SubjectUserName", "WEB01$"), ("SubjectDomainName", "CORP"),
            ("TargetUserName", "alice"), ("TargetDomainName", "CORP"), ("TargetLogonId", "0x1A2B3C"),
            ("LogonType", "10"), ("LogonProcessName", "User32 "), ("AuthenticationPackageName", "Negotiate"),
            ("WorkstationName", "LAPTOP7"), ("IpAddress", "203.0.113.9"), ("IpPort", "0"),
            ("TargetLinkedLogonId", "0x1A2B40"), ("ElevatedToken", "%%1842"),
        ]);
        let e = &map_event(&parse_events(&xml)[0], 1)[0];
        assert_eq!((e.action.as_str(), e.detail_str("protocol")), ("session.start", Some("rdp")));
        assert_eq!((e.user.as_deref(), e.src_ip.as_deref()), (Some("CORP\\alice"), Some("203.0.113.9")));
        assert_eq!(e.keys, vec!["logon:0x1a2b3c", "logon:0x1a2b40"]);

        // Service logons are noise.
        let svc = security(4624, &[("TargetUserName", "SYSTEM"), ("TargetDomainName", "NT AUTHORITY"), ("LogonType", "5")]);
        assert!(map_event(&parse_events(&svc)[0], 1).is_empty());

        let fail = security(4625, &[
            ("TargetUserName", "administrator"), ("TargetDomainName", "WEB01"), ("LogonType", "3"),
            ("Status", "0xc000006d"), ("SubStatus", "0xc000006a"), ("IpAddress", "198.51.100.7"),
        ]);
        let e = &map_event(&parse_events(&fail)[0], 1)[0];
        assert_eq!((e.action.as_str(), e.detail_str("reason")), ("auth.failure", Some("wrong password")));
        assert_eq!(e.src_ip.as_deref(), Some("198.51.100.7"));
    }

    #[test]
    fn process_creation_with_escaped_command_line() {
        let xml = security(4688, &[
            ("SubjectUserName", "alice"), ("SubjectDomainName", "CORP"), ("SubjectLogonId", "0x1a2b3c"),
            ("NewProcessId", "0x1f40"), ("NewProcessName", r"C:\Windows\System32\cmd.exe"),
            ("ProcessId", "0x10"), ("CommandLine", "cmd.exe /c echo a &amp;&amp; whoami &gt; out.txt"),
            ("ParentProcessName", r"C:\Windows\explorer.exe"),
        ]);
        let e = &map_event(&parse_events(&xml)[0], 1)[0];
        let p = e.process.as_ref().unwrap();
        assert_eq!((p.pid, p.name.as_str(), p.parent_name.as_deref()), (8000, "cmd.exe", Some("explorer.exe")));
        assert_eq!(p.command_line.as_deref(), Some("cmd.exe /c echo a && whoami > out.txt"));
        assert!(e.keys.contains(&"logon:0x1a2b3c".to_string()) && e.keys.contains(&"pid:16".to_string()));
        assert_eq!(e.learn, vec!["pid:8000"]);
        assert!(map_event(&parse_events(&xml)[0], 0x10).is_empty(), "agent's own children are skipped");
    }

    #[test]
    fn tampering_accounts_services_and_openssh() {
        let cleared = "<Event><System><Provider Name='Microsoft-Windows-Eventlog'/><EventID>1102</EventID><TimeCreated SystemTime='2026-09-25T10:00:00Z'/><EventRecordID>5</EventRecordID></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>mallory</SubjectUserName><SubjectDomainName>WEB01</SubjectDomainName><SubjectLogonId>0x99</SubjectLogonId></LogFileCleared></UserData></Event>";
        let e = &map_event(&parse_events(cleared)[0], 1)[0];
        assert_eq!((e.action.as_str(), e.user.as_deref()), ("log.cleared", Some("WEB01\\mallory")));

        let grp = security(4732, &[
            ("MemberName", "-"), ("MemberSid", "S-1-5-21-1-1005"), ("TargetUserName", "Administrators"),
            ("TargetDomainName", "Builtin"), ("SubjectUserName", "alice"), ("SubjectDomainName", "CORP"),
            ("SubjectLogonId", "0x1a2b3c"),
        ]);
        let e = &map_event(&parse_events(&grp)[0], 1)[0];
        assert_eq!((e.action.as_str(), e.detail_str("group")), ("account.group_member_added", Some("Administrators")));

        let svc = "<Event><System><Provider Name='Service Control Manager'/><EventID>7045</EventID><TimeCreated SystemTime='2026-09-25T10:00:00Z'/></System><EventData><Data Name='ServiceName'>updater</Data><Data Name='ImagePath'>C:\\Users\\Public\\u.exe</Data><Data Name='ServiceType'>user mode service</Data><Data Name='StartType'>auto start</Data><Data Name='AccountName'>LocalSystem</Data></EventData></Event>";
        let e = &map_event(&parse_events(svc)[0], 1)[0];
        assert_eq!((e.action.as_str(), e.target.as_deref()), ("service.installed", Some("updater")));

        let ssh = "<Event><System><Provider Name='OpenSSH'/><EventID>4</EventID><TimeCreated SystemTime='2026-09-25T10:00:00Z'/><Execution ProcessID='3000' ThreadID='1'/></System><EventData><Data Name='process'>sshd</Data><Data Name='payload'>Accepted password for alice from 10.0.0.9 port 50000 ssh2</Data></EventData></Event>";
        let e = &map_event(&parse_events(ssh)[0], 1)[0];
        assert_eq!((e.action.as_str(), e.keys[0].as_str()), ("session.start", "pid:3000"));

        let msi = "<Event><System><Provider Name='MsiInstaller'/><EventID>1033</EventID><TimeCreated SystemTime='2026-09-25T10:00:00Z'/></System><EventData><Data>7-Zip 24.08 (x64)</Data><Data>24.08.00.0</Data><Data>1033</Data><Data>0</Data><Data>Igor Pavlov</Data><Data>(NULL)</Data><Data></Data></EventData></Event>";
        let e = &map_event(&parse_events(msi)[0], 1)[0];
        assert_eq!((e.action.as_str(), e.target.as_deref(), e.outcome), ("package.installed", Some("7-Zip 24.08 (x64)"), Outcome::Success));
    }
}
