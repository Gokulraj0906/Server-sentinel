//! Package install / upgrade / removal from package-manager logs.
//!
//! "What changed?" is half of every outage investigation, and package
//! upgrades (unattended or not) are the most common change nobody
//! remembers making.

use crate::events::{Category, Event, Outcome};
use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};

fn pkg_event(ts: DateTime<Utc>, action: &str, name: &str, version: &str, old: Option<&str>) -> Event {
    let verb = match action {
        "package.installed" => "Installed",
        "package.upgraded" => "Upgraded",
        "package.removed" => "Removed",
        _ => "Changed",
    };
    let msg = match old {
        Some(o) if !o.is_empty() && o != "<none>" => format!("{verb} package {name} {o} -> {version}"),
        _ if action == "package.removed" => format!("{verb} package {name}"),
        _ => format!("{verb} package {name} {version}"),
    };
    let mut e = Event::new(Category::Package, action, msg)
        .at(ts)
        .outcome(Outcome::Success)
        .target(name);
    if !version.is_empty() && version != "<none>" {
        e.set_detail("version", version);
    }
    if let Some(o) = old.filter(|o| !o.is_empty() && *o != "<none>") {
        e.set_detail("previous_version", o);
    }
    e
}

/// `/var/log/dpkg.log`:
/// `2026-09-25 10:00:00 upgrade nginx:amd64 1.22.1-9 1.24.0-2`
pub fn parse_dpkg_line(line: &str) -> Option<Event> {
    let mut it = line.split_whitespace();
    let date = it.next()?;
    let time = it.next()?;
    let op = it.next()?;
    let action = match op {
        "install" => "package.installed",
        "upgrade" => "package.upgraded",
        "remove" | "purge" => "package.removed",
        _ => return None,
    };
    let pkg = it.next()?;
    let old = it.next()?;
    let new = it.next().unwrap_or("");
    let naive = NaiveDateTime::parse_from_str(&format!("{date} {time}"), "%Y-%m-%d %H:%M:%S").ok()?;
    let ts = Local.from_local_datetime(&naive).earliest()?.with_timezone(&Utc);
    let name = pkg.split(':').next().unwrap_or(pkg);
    let (version, previous) = match action {
        "package.removed" => (old, None),
        "package.installed" => (new, None),
        _ => (new, Some(old)),
    };
    Some(pkg_event(ts, action, name, version, previous))
}

/// `/var/log/dnf.rpm.log` (RHEL/Rocky/Alma/Fedora 8+):
/// `2026-09-25T10:00:00+0000 SUBDEBUG Upgrade: nginx-1:1.24.0-1.el9.x86_64`
pub fn parse_dnf_rpm_line(line: &str) -> Option<Event> {
    let (stamp, rest) = line.split_once(' ')?;
    let ts = DateTime::parse_from_str(stamp, "%Y-%m-%dT%H:%M:%S%z").ok()?.with_timezone(&Utc);
    let rest = rest.trim_start().strip_prefix("SUBDEBUG ")?.trim();
    let (op, nevra) = rest.split_once(": ")?;
    let action = match op {
        "Installed" | "Install" => "package.installed",
        "Upgrade" | "Downgrade" | "Reinstall" => "package.upgraded",
        "Erase" | "Obsoleted" => "package.removed",
        // "Upgraded:" / "Downgraded:" name the *old* package; the paired
        // "Upgrade:" line already recorded the change.
        _ => return None,
    };
    let (name, version) = split_nevra(nevra.trim());
    Some(pkg_event(ts, action, name, version, None))
}

/// "nginx-1:1.24.0-1.el9.x86_64" -> ("nginx", "1:1.24.0-1.el9.x86_64")
fn split_nevra(s: &str) -> (&str, &str) {
    // name-version-release.arch: name is everything before the
    // second-to-last '-'.
    let dashes: Vec<usize> = s.match_indices('-').map(|(i, _)| i).collect();
    if dashes.len() >= 2 {
        let i = dashes[dashes.len() - 2];
        (&s[..i], &s[i + 1..])
    } else {
        (s, "")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpkg() {
        let e = parse_dpkg_line("2026-09-25 10:00:00 upgrade nginx:amd64 1.22.1-9 1.24.0-2").unwrap();
        assert_eq!((e.action.as_str(), e.target.as_deref()), ("package.upgraded", Some("nginx")));
        assert_eq!(e.detail_str("previous_version"), Some("1.22.1-9"));
        assert_eq!(e.message, "Upgraded package nginx 1.22.1-9 -> 1.24.0-2");
        let e = parse_dpkg_line("2026-09-25 10:00:00 install htop:amd64 <none> 3.3.0-4").unwrap();
        assert_eq!((e.action.as_str(), e.detail_str("version")), ("package.installed", Some("3.3.0-4")));
        let e = parse_dpkg_line("2026-09-25 10:00:00 remove telnet:amd64 0.17-44 <none>").unwrap();
        assert_eq!(e.action, "package.removed");
        assert!(parse_dpkg_line("2026-09-25 10:00:00 status installed nginx:amd64 1.24.0-2").is_none());
        assert!(parse_dpkg_line("2026-09-25 10:00:00 startup archives unpack").is_none());
    }

    #[test]
    fn dnf() {
        let e = parse_dnf_rpm_line("2026-09-25T10:00:00+0000 SUBDEBUG Upgrade: nginx-1:1.24.0-1.el9.x86_64").unwrap();
        assert_eq!((e.action.as_str(), e.target.as_deref()), ("package.upgraded", Some("nginx")));
        assert_eq!(e.detail_str("version"), Some("1:1.24.0-1.el9.x86_64"));
        let e = parse_dnf_rpm_line("2026-09-25T10:00:00+0000 SUBDEBUG Installed: python3-requests-2.25.1-8.el9.noarch").unwrap();
        assert_eq!(e.target.as_deref(), Some("python3-requests"));
        assert!(parse_dnf_rpm_line("2026-09-25T10:00:00+0000 SUBDEBUG Upgraded: nginx-1:1.20.1-14.el9.x86_64").is_none());
        assert!(parse_dnf_rpm_line("2026-09-25T10:00:00+0000 INFO --- logging initialized ---").is_none());
    }
}
