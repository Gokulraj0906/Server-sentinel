//! Parser for authentication / account messages from sshd, sudo, su,
//! login and the shadow-utils tools.
//!
//! Pure string -> `Event` logic with no I/O, shared by every source that
//! carries these messages: `/var/log/auth.log`, `/var/log/secure`,
//! journald, and — because Win32-OpenSSH logs the same sshd messages —
//! the Windows `OpenSSH/Operational` event log.

use crate::events::{Category, Event, Outcome, ProcessInfo, Severity};
use chrono::{DateTime, Datelike, Local, NaiveDateTime, TimeZone, Utc};
use regex::Regex;
use std::sync::LazyLock;

pub struct LogLine<'a> {
    pub ts: DateTime<Utc>,
    pub ident: &'a str,
    pub pid: Option<u32>,
    pub msg: &'a str,
}

/// Parses one syslog-format line, either RFC 3339 (modern rsyslog
/// default: `2026-09-25T18:13:29.735967+00:00 host sshd[12]: msg`) or
/// the classic BSD format (`Sep 25 18:13:29 host sshd[12]: msg`, local
/// time, no year).
pub fn parse_syslog_line(line: &str, now: DateTime<Local>) -> Option<LogLine<'_>> {
    let line = line.trim_end_matches(['\r', '\n']);
    let (ts, rest) = if line.as_bytes().first().map(|b| b.is_ascii_digit()).unwrap_or(false) {
        let (tok, rest) = line.split_once(' ')?;
        (DateTime::parse_from_rfc3339(tok).ok()?.with_timezone(&Utc), rest)
    } else {
        if line.len() < 16 || !line.is_char_boundary(15) {
            return None;
        }
        let (stamp, rest) = line.split_at(15);
        let parse = |year: i32| {
            NaiveDateTime::parse_from_str(&format!("{year} {stamp}"), "%Y %b %e %H:%M:%S")
                .ok()
                .and_then(|n| Local.from_local_datetime(&n).earliest())
        };
        let mut local = parse(now.year())?;
        // Logs from late December read in early January belong to last year.
        if local > now + chrono::Duration::days(1) {
            local = parse(now.year() - 1)?;
        }
        (local.with_timezone(&Utc), rest)
    };
    let rest = rest.trim_start();
    let (_host, rest) = rest.split_once(' ')?;
    let (tag, msg) = rest.split_once(": ")?;
    let (ident, pid) = split_tag(tag);
    Some(LogLine { ts, ident, pid, msg })
}

/// "sshd[1234]" -> ("sshd", Some(1234)); "/usr/sbin/sshd" -> ("sshd", None)
pub fn split_tag(tag: &str) -> (&str, Option<u32>) {
    let (name, pid) = match tag.find('[') {
        Some(i) => (&tag[..i], tag[i + 1..].trim_end_matches(']').parse().ok()),
        None => (tag, None),
    };
    (name.rsplit('/').next().unwrap_or(name), pid)
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect("static regex"));
    };
}

re!(SSH_ACCEPTED, r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?(?:: (?P<ktype>\S+) (?P<fp>\S+))?");
re!(SSH_FAILED, r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)");
re!(SSH_INVALID, r"^Invalid user (?P<user>.*?) from (?P<ip>\S+?)(?: port (?P<port>\d+))?$");
re!(SSH_MAXAUTH, r"^(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)");
re!(SSH_DISCONNECTED, r"^Disconnected from user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)");
re!(PAM_SESSION, r"^pam_unix\((?P<svc>[\w-]+):session\): session (?P<state>opened|closed) for user (?P<user>[^\s(]+)(?:\(uid=\d+\))?(?: by (?P<by>[^\s(]*)(?:\(uid=\d+\))?)?");
re!(PAM_AUTH_FAIL, r"^pam_unix\((?P<svc>[\w-]+):auth\): authentication failure;.*?\bruser=(?P<ruser>\S*).*?\buser=(?P<user>\S+)");
re!(PAM_AUTH_FAIL_TTY, r"\btty=(?P<tty>\S+)");
re!(SUDO, r"^\s*(?P<user>\S+) : (?:(?P<fail>[^;]*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; USER=(?P<runas>\S+) ;(?: [A-Z]+=\S* ;)*? COMMAND=(?P<cmd>.*)$");
re!(PASSWD_CHANGED, r"^pam_unix\((?:passwd|chpasswd):chauthtok\): password changed for (?P<user>\S+)");
re!(NEW_USER, r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)(?:.*?from=(?P<from>\S+))?");
re!(NEW_GROUP, r"^new group: name=(?P<group>[^,]+), GID=(?P<gid>\d+)");
re!(DEL_USER, r"^delete user '(?P<user>[^']+)'");
re!(USERMOD_ADD, r"^add '(?P<user>[^']+)' to group '(?P<group>[^']+)'");
re!(GPASSWD_ADD, r"^user (?P<user>\S+) added by (?P<by>\S+) to group (?P<group>\S+)");

fn tty_key(tty: &str) -> Option<String> {
    let t = tty.trim_start_matches("/dev/");
    if t.is_empty() || t == "unknown" || t == "(none)" || t == "none" || t == "ssh" {
        None
    } else {
        Some(format!("tty:{t}"))
    }
}

fn with_pid(mut ev: Event, pid: Option<u32>) -> Event {
    if let Some(p) = pid {
        ev.keys.push(format!("pid:{p}"));
    }
    ev
}

/// Turns one message into zero or more events. Unrecognised messages
/// yield nothing — they're noise for our purposes.
pub fn parse_auth_message(ts: DateTime<Utc>, ident: &str, pid: Option<u32>, msg: &str) -> Vec<Event> {
    let msg = msg.trim();
    let ev = match ident {
        "sshd" | "sshd-session" | "sshd.exe" => parse_sshd(msg),
        "sudo" => parse_sudo(msg, pid),
        "su" => parse_pam(msg, "su"),
        "login" => parse_pam(msg, "login"),
        "passwd" | "chpasswd" => PASSWD_CHANGED.captures(msg).map(|c| {
            Event::new(Category::Account, "account.password_changed", format!("Password changed for {}", &c["user"]))
                .outcome(Outcome::Success)
                .target(&c["user"])
        }),
        "useradd" | "adduser" => NEW_USER
            .captures(msg)
            .map(|c| {
                let mut e = Event::new(Category::Account, "account.user_created", format!("User account created: {}", &c["user"]))
                    .outcome(Outcome::Success)
                    .target(&c["user"])
                    .detail("uid", c["uid"].parse::<u64>().unwrap_or(0));
                if let Some(k) = c.name("from").and_then(|f| tty_key(f.as_str())) {
                    e.keys.push(k);
                }
                e
            })
            .or_else(|| {
                NEW_GROUP.captures(msg).map(|c| {
                    Event::new(Category::Account, "account.group_created", format!("Group created: {}", &c["group"]))
                        .outcome(Outcome::Success)
                        .target(&c["group"])
                })
            }),
        "groupadd" => NEW_GROUP.captures(msg).map(|c| {
            Event::new(Category::Account, "account.group_created", format!("Group created: {}", &c["group"]))
                .outcome(Outcome::Success)
                .target(&c["group"])
        }),
        "userdel" | "deluser" => DEL_USER.captures(msg).map(|c| {
            Event::new(Category::Account, "account.user_deleted", format!("User account deleted: {}", &c["user"]))
                .outcome(Outcome::Success)
                .target(&c["user"])
        }),
        "usermod" => USERMOD_ADD.captures(msg).map(|c| group_add(&c["user"], &c["group"])),
        "gpasswd" => GPASSWD_ADD.captures(msg).map(|c| group_add(&c["user"], &c["group"])),
        _ => None,
    };
    match ev {
        Some(e) => vec![with_pid(e.at(ts), pid)],
        None => Vec::new(),
    }
}

fn group_add(user: &str, group: &str) -> Event {
    Event::new(Category::Account, "account.group_member_added", format!("{user} added to group {group}"))
        .outcome(Outcome::Success)
        .target(user)
        .detail("group", group)
        .detail("member", user)
}

fn parse_sshd(msg: &str) -> Option<Event> {
    if let Some(c) = SSH_ACCEPTED.captures(msg) {
        let method = &c["method"];
        let mut e = Event::new(
            Category::Session,
            "session.start",
            format!("{} logged in via SSH from {} ({method})", &c["user"], &c["ip"]),
        )
        .outcome(Outcome::Success)
        .user(&c["user"])
        .src_ip(&c["ip"])
        .detail("protocol", "ssh")
        .detail("auth_method", method)
        .detail("src_port", c["port"].parse::<u64>().unwrap_or(0));
        if let (Some(kt), Some(fp)) = (c.name("ktype"), c.name("fp")) {
            e.set_detail("key_type", kt.as_str());
            e.set_detail("key_fingerprint", fp.as_str());
        }
        return Some(e);
    }
    if let Some(c) = SSH_FAILED.captures(msg) {
        // "Failed password for invalid user X" always follows an
        // "Invalid user X" line we already counted.
        if c.name("invalid").is_some() {
            return None;
        }
        return Some(
            Event::new(
                Category::Auth,
                "auth.failure",
                format!("Failed SSH {} for {} from {}", &c["method"], &c["user"], &c["ip"]),
            )
            .outcome(Outcome::Failure)
            .user(&c["user"])
            .src_ip(&c["ip"])
            .detail("protocol", "ssh")
            .detail("auth_method", &c["method"]),
        );
    }
    if let Some(c) = SSH_INVALID.captures(msg) {
        let user = c.name("user").map(|m| m.as_str()).unwrap_or("");
        return Some(
            Event::new(Category::Auth, "auth.failure", format!("SSH login attempt for nonexistent user '{user}' from {}", &c["ip"]))
                .outcome(Outcome::Failure)
                .user(user)
                .src_ip(&c["ip"])
                .detail("protocol", "ssh")
                .detail("reason", "invalid user"),
        );
    }
    if let Some(c) = SSH_MAXAUTH.captures(msg) {
        return Some(
            Event::new(Category::Auth, "auth.lockout", format!("Too many SSH authentication attempts for {} from {}", &c["user"], &c["ip"]))
                .outcome(Outcome::Failure)
                .severity(Severity::Low)
                .user(&c["user"])
                .src_ip(&c["ip"])
                .detail("protocol", "ssh"),
        );
    }
    if let Some(c) = SSH_DISCONNECTED.captures(msg) {
        return Some(
            Event::new(Category::Session, "session.end", format!("{} disconnected (SSH)", &c["user"]))
                .user(&c["user"])
                .src_ip(&c["ip"]),
        );
    }
    if let Some(c) = PAM_SESSION.captures(msg) {
        if &c["svc"] == "sshd" && &c["state"] == "closed" {
            return Some(Event::new(Category::Session, "session.end", format!("SSH session closed for {}", &c["user"])).user(&c["user"]));
        }
    }
    None
}

fn parse_sudo(msg: &str, pid: Option<u32>) -> Option<Event> {
    let c = SUDO.captures(msg)?;
    let user = &c["user"];
    let runas = &c["runas"];
    let cmd = c["cmd"].trim();
    let failure = c.name("fail").map(|f| f.as_str().trim().to_string());
    let (outcome, severity, message) = match &failure {
        Some(reason) => (Outcome::Failure, Severity::Low, format!("{user} was denied sudo ({reason}): {cmd}")),
        None => (Outcome::Success, Severity::Info, format!("{user} ran as {runas}: {cmd}")),
    };
    let mut e = Event::new(Category::Privilege, "privilege.sudo", message)
        .outcome(outcome)
        .severity(severity)
        .user(user)
        .detail("run_as", runas)
        .process(ProcessInfo {
            pid: pid.unwrap_or(0),
            name: "sudo".into(),
            command_line: Some(cmd.to_string()),
            cwd: Some(c["pwd"].to_string()),
            run_as: Some(runas.to_string()),
            ..Default::default()
        });
    if let Some(reason) = failure {
        e.set_detail("reason", reason);
    }
    if let Some(k) = tty_key(&c["tty"]) {
        e.keys.push(k);
    }
    Some(e)
}

fn parse_pam(msg: &str, svc_family: &str) -> Option<Event> {
    if let Some(c) = PAM_SESSION.captures(msg) {
        let svc = &c["svc"];
        let opened = &c["state"] == "opened";
        let user = &c["user"];
        if svc_family == "su" && (svc == "su" || svc == "su-l") && opened {
            let by = c.name("by").map(|b| b.as_str()).unwrap_or("");
            return Some(
                Event::new(Category::Privilege, "privilege.su", format!("{by} switched to {user} (su)"))
                    .outcome(Outcome::Success)
                    .user(by)
                    .detail("run_as", user),
            );
        }
        if svc_family == "login" && svc == "login" {
            return Some(if opened {
                Event::new(Category::Session, "session.start", format!("{user} logged in on the console"))
                    .outcome(Outcome::Success)
                    .user(user)
                    .detail("protocol", "console")
            } else {
                Event::new(Category::Session, "session.end", format!("Console session closed for {user}")).user(user)
            });
        }
        return None;
    }
    if let Some(c) = PAM_AUTH_FAIL.captures(msg) {
        let svc = &c["svc"];
        let target = &c["user"];
        let ruser = c.name("ruser").map(|m| m.as_str()).unwrap_or("");
        let mut e = match (svc_family, svc) {
            ("su", "su" | "su-l") => Event::new(
                Category::Privilege,
                "privilege.su",
                format!("{} failed to su to {target}", if ruser.is_empty() { "someone" } else { ruser }),
            )
            .outcome(Outcome::Failure)
            .severity(Severity::Low)
            .user(ruser)
            .detail("run_as", target)
            .detail("reason", "authentication failure"),
            ("login", "login") => Event::new(Category::Auth, "auth.failure", format!("Failed console login for {target}"))
                .outcome(Outcome::Failure)
                .user(target)
                .detail("protocol", "console"),
            _ => return None,
        };
        if let Some(k) = PAM_AUTH_FAIL_TTY.captures(msg).and_then(|t| tty_key(&t["tty"])) {
            e.keys.push(k);
        }
        return Some(e);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &str) -> Vec<Event> {
        let l = parse_syslog_line(line, Local::now()).expect("line parses");
        parse_auth_message(l.ts, l.ident, l.pid, l.msg)
    }

    #[test]
    fn both_timestamp_formats() {
        let l = parse_syslog_line(
            "2026-09-25T18:13:29.735967+00:00 Gokulraj login: pam_unix(login:session): session opened for user gokul(uid=1000) by gokul(uid=0)",
            Local::now(),
        )
        .unwrap();
        assert_eq!((l.ident, l.pid), ("login", None));
        assert_eq!(l.ts.to_rfc3339(), "2026-09-25T18:13:29.735967+00:00");
        let l = parse_syslog_line("Sep  5 07:01:02 web1 sshd[811]: Invalid user x from 1.2.3.4 port 22", Local::now()).unwrap();
        assert_eq!((l.ident, l.pid), ("sshd", Some(811)));
        assert!(parse_syslog_line("garbage", Local::now()).is_none());
    }

    #[test]
    fn ssh_lifecycle() {
        let e = parse("Sep 25 10:00:00 web1 sshd[4000]: Accepted publickey for alice from 203.0.113.9 port 50122 ssh2: ED25519 SHA256:AbCdEf0123");
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].action, "session.start");
        assert_eq!(e[0].user.as_deref(), Some("alice"));
        assert_eq!(e[0].src_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(e[0].detail_str("key_fingerprint"), Some("SHA256:AbCdEf0123"));
        assert_eq!(e[0].keys, vec!["pid:4000"]);

        // OpenSSH >= 9.8 logs from sshd-session
        let e = parse("2026-09-25T10:00:00+00:00 web1 sshd-session[77]: Accepted password for bob from 2001:db8::1 port 2222 ssh2");
        assert_eq!((e[0].action.as_str(), e[0].src_ip.as_deref()), ("session.start", Some("2001:db8::1")));

        let e = parse("Sep 25 10:30:00 web1 sshd[4000]: pam_unix(sshd:session): session closed for user alice");
        assert_eq!((e[0].action.as_str(), e[0].keys[0].as_str()), ("session.end", "pid:4000"));
        let e = parse("Sep 25 10:30:00 web1 sshd[4000]: Disconnected from user alice 203.0.113.9 port 50122");
        assert_eq!(e[0].action, "session.end");
    }

    #[test]
    fn ssh_failures_are_counted_once() {
        let e = parse("Sep 25 10:00:00 web1 sshd[1]: Failed password for root from 198.51.100.7 port 4444 ssh2");
        assert_eq!((e[0].action.as_str(), e[0].user.as_deref()), ("auth.failure", Some("root")));
        let e = parse("Sep 25 10:00:00 web1 sshd[1]: Invalid user oracle from 198.51.100.7 port 4445");
        assert_eq!((e[0].action.as_str(), e[0].user.as_deref()), ("auth.failure", Some("oracle")));
        assert!(parse("Sep 25 10:00:00 web1 sshd[1]: Failed password for invalid user oracle from 198.51.100.7 port 4445 ssh2").is_empty());
        let e = parse("Sep 25 10:00:00 web1 sshd[1]: Invalid user  from 198.51.100.7 port 4446");
        assert_eq!(e[0].action, "auth.failure");
        assert!(parse("Sep 25 10:00:00 web1 sshd[1]: Connection closed by 198.51.100.7 port 4446 [preauth]").is_empty());
    }

    #[test]
    fn sudo_success_and_denials() {
        let e = parse("Sep 25 10:05:00 web1 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx");
        let ev = &e[0];
        assert_eq!((ev.action.as_str(), ev.outcome), ("privilege.sudo", Outcome::Success));
        assert_eq!(ev.command_line(), Some("/usr/bin/systemctl restart nginx"));
        assert_eq!(ev.process.as_ref().unwrap().cwd.as_deref(), Some("/home/alice"));
        assert!(ev.keys.contains(&"tty:pts/0".to_string()));

        let e = parse("Sep 25 10:05:00 web1 sudo[99]:   alice : TTY=pts/1 ; PWD=/tmp ; USER=root ; TSID=000001 ; COMMAND=/bin/bash");
        assert_eq!(e[0].command_line(), Some("/bin/bash"));
        assert!(e[0].keys.contains(&"pid:99".to_string()));

        let e = parse("Sep 25 10:06:00 web1 sudo:      bob : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/cat /etc/shadow");
        assert_eq!(e[0].outcome, Outcome::Failure);
        assert_eq!(e[0].detail_str("reason"), Some("user NOT in sudoers"));
        let e = parse("Sep 25 10:06:00 web1 sudo:      bob : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/home/bob ; USER=root ; COMMAND=/bin/id");
        assert_eq!(e[0].outcome, Outcome::Failure);
    }

    #[test]
    fn su_console_and_accounts() {
        let e = parse("Sep 25 10:07:00 web1 su[500]: pam_unix(su-l:session): session opened for user root(uid=0) by alice(uid=1000)");
        assert_eq!((e[0].action.as_str(), e[0].user.as_deref()), ("privilege.su", Some("alice")));
        let e = parse("Sep 25 10:07:00 web1 su[501]: pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=root");
        assert_eq!((e[0].outcome, e[0].user.as_deref()), (Outcome::Failure, Some("alice")));
        assert!(e[0].keys.contains(&"tty:pts/0".to_string()));

        let e = parse("2026-09-25T18:14:00.047684+00:00 Gokulraj login: pam_unix(login:session): session opened for user gokul(uid=1000) by gokul(uid=0)");
        assert_eq!((e[0].action.as_str(), e[0].detail_str("protocol")), ("session.start", Some("console")));

        let e = parse("Sep 25 10:08:00 web1 useradd[600]: new user: name=mallory, UID=1002, GID=1002, home=/home/mallory, shell=/bin/bash, from=/dev/pts/0");
        assert_eq!((e[0].action.as_str(), e[0].target.as_deref()), ("account.user_created", Some("mallory")));
        assert!(e[0].keys.contains(&"tty:pts/0".to_string()));
        let e = parse("Sep 25 10:08:01 web1 usermod[601]: add 'mallory' to group 'sudo'");
        assert_eq!((e[0].action.as_str(), e[0].detail_str("group")), ("account.group_member_added", Some("sudo")));
        assert!(parse("Sep 25 10:08:01 web1 usermod[601]: add 'mallory' to shadow group 'sudo'").is_empty());
        let e = parse("Sep 25 10:08:02 web1 passwd[602]: pam_unix(passwd:chauthtok): password changed for mallory");
        assert_eq!(e[0].action, "account.password_changed");
        let e = parse("Sep 25 10:08:03 web1 userdel[603]: delete user 'mallory'");
        assert_eq!(e[0].action, "account.user_deleted");
        assert!(parse("Sep 25 10:09:00 web1 CRON[700]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)").is_empty());
    }
}
