# ServerSentinel

**A flight recorder for your servers.** One 6 MB binary per host, no central server, no
cluster to run. It answers the four questions every incident review and every audit comes back to:

1. **Who got in?** SSH, RDP and console sessions: user, source IP, auth method, key fingerprint,
   start/end. Brute force, password spraying, and the one that matters most: *a login that
   succeeded after failures*.
2. **What did they run?** Every command, attributed to the session and the *human* who ran it,
   including through `sudo`/`su`. Linux uses the kernel's exec notifications, so sub-second
   commands aren't missed.
3. **What did they change, and what was it before?** File integrity monitoring that keeps the
   previous content of every config, with diffs, plus package installs/upgrades, service changes,
   and new accounts and admins.
4. **Did it break something?** When CPU, memory or disk saturates, ServerSentinel investigates
   the culprit process, then looks back through the change history and tells you what changed
   right before.

Example (illustrative data):

```text
$ server-sentinel sessions
SESSION         USER     VIA   FROM           START                DURATION  STATUS  CMDS SUDO FILES ALERTS RISK
S260925-3fa9c2  alice    ssh   203.0.113.9    2026-09-25 14:02:11    29m 4s  ended     23    3     1      1   40

$ server-sentinel session S260925-3fa9c2
Session S260925-3fa9c2  —  alice via SSH from 203.0.113.9 port 50122
  Auth:      publickey  key SHA256:AbCdEf0123…
  When:      2026-09-25 14:02:11 → 14:31:15  (29m 4s)  ended — logoff
  Activity:  23 commands, 3 privileged, 1 file changes, 1 alerts   risk 40/100

  14:02:11  ● alice logged in via SSH from 203.0.113.9 (publickey)            #8812
  14:02:30  $ vim /etc/nginx/nginx.conf   (in /home/alice)                     #8815
  14:03:02  ✎ Modified /etc/nginx/nginx.conf (+1 -1)                          #8821
            attribution: high — `vim` referenced this path
  14:03:10  # alice ran as root: /usr/bin/systemctl reload nginx               #8823
  …

$ server-sentinel diff 8821
-    worker_connections 1024;
+    worker_connections 64;
```

…and four minutes later, the incident report for the CPU spike says:

> **What changed before this incident.** 3m 58s before onset: *Modified /etc/nginx/nginx.conf
> (+1 −1) by alice* (session S260925-3fa9c2).

## Why another tool?

| | ServerSentinel | Wazuh / OSSEC | Splunk / Elastic | Teleport | osquery |
|---|---|---|---|---|---|
| Infrastructure to run | none (1 binary per host) | manager + indexer + dashboard | cluster, or per-GB SaaS | proxy + auth service | fleet manager to be useful at scale |
| Direct SSH/RDP logins (not via a proxy) | ✅ | ✅ | if you build the parsing | ❌ only sessions through its proxy | partial (`last`, event tables) |
| Commands grouped into the *human's* session | ✅ out of the box | with auditd rules you write | if you build it | ✅ for proxied sessions | per-process (`process_events`), no session view |
| File changes with previous content and diffs | ✅ by default | opt-in (`report_changes`) | ❌ | ❌ | ❌ hashes/paths only |
| "What changed right before this outage?" | ✅ in every incident report | ❌ | manual correlation | ❌ | ❌ |
| Linux and Windows, one data model | ✅ | ✅ | ✅ | ✅ (Windows via RDP proxy) | ✅ |
| Before it's useful | install, run `doctor` | rule tuning to cut noise | build parsing, dashboards, alerts | route all access through it | write queries |

ServerSentinel doesn't replace your SIEM. It gives your SIEM its best-structured source (see
[Forwarding](#forwarding-to-your-siem)), and if you don't have a SIEM, it's the part of one a small
team actually uses.

## Install

**Linux** (`.deb` / `.rpm`, systemd):

```bash
sudo dpkg -i server-sentinel_0.2.0_amd64.deb      # or: sudo rpm -i server-sentinel-0.2.0-1.x86_64.rpm
sudo systemctl enable --now server-sentinel
sudo server-sentinel doctor                       # what this host can and can't be audited for
```

**Windows** (run from an elevated prompt; the Security event log needs LocalSystem):

```powershell
server-sentinel.exe --config "C:\Program Files\server-sentinel\server-sentinel.toml" service install
server-sentinel.exe doctor
```

The service starts automatically, restarts on failure, and logs to
`C:\ProgramData\ServerSentinel\logs\server-sentinel.log`. On Windows, enable
*Audit Process Creation* to capture every process, even sub-second ones; `doctor` prints the exact
`auditpol` command. Without it, the agent polls the process table and ties each process to its
RDP/console session.

**From source:** `cargo build --release` (Rust 1.86+). No OpenSSL or system libraries needed;
SQLite is compiled in.

## Investigating

Every command reads the local store, so it's safe to run on a live host while the agent writes.

```bash
server-sentinel sessions [--active] [--user alice] [--since 7d]
server-sentinel session <ID> [--diffs] [--html report.html] [--json]
server-sentinel changes [--path nginx] [--since 24h]
server-sentinel diff <EVENT_ID> [--before | --after]      # the diff, or the whole file as it was
server-sentinel alerts [--min high] [--since 7d]
server-sentinel search <QUERY> [--since 24h] [--json]
server-sentinel verify                                     # tamper check, exit code 1 on failure
server-sentinel doctor
```

**Search** takes `field=value` terms (wildcards with `*`, `!=` to exclude) plus free text, which is
matched as a substring against messages, command lines and paths:

```bash
server-sentinel search user=alice action=file.*
server-sentinel search ip=203.0.113.9 --since 30d
server-sentinel search category=process "curl" sev>=medium
server-sentinel search session=S260925-3fa9c2 path!=/tmp/*
```

Fields: `user`, `ip`, `action`, `category`, `session`, `path`/`target`, `process`, `command`, `pid`,
`host`, `outcome`, `id`, `sev>=`.

## What's recorded

| | Linux | Windows |
|---|---|---|
| Access | sshd (incl. OpenSSH ≥ 9.8 `sshd-session`), console `login`, from `auth.log`/`secure`/journald | Security 4624/4625/4634/4647, TerminalServices 21/23/24/25 (RDP connect/disconnect/reconnect), Win32-OpenSSH log |
| Already-open sessions at startup | `who -u` (utmp) | Terminal Services session enumeration |
| Commands | kernel proc connector (every `exec`), falling back to `/proc` polling; `loginuid`, audit session, TTY and pid ancestry for attribution | Security 4688 when enabled, else process polling + TS session id |
| Privilege | `sudo` (incl. denials), `su` | linked/elevated logons |
| Accounts | `useradd`, `userdel`, `usermod`/`gpasswd` group adds, `passwd` | 4720–4726, 4728/4732/4756, 4740 |
| Files | inotify + startup/periodic rescans, content history | ReadDirectoryChangesW + rescans, content history |
| Packages | `dpkg.log`, `dnf.rpm.log` | MsiInstaller 1033/1034 |
| Services / persistence | systemd state changes | SCM state changes, 7045 service installed, 4698 scheduled task |
| Tampering | auth log truncated in place, agent downtime | 1102 Security log cleared, 104 |

Changes made **while the agent was stopped** are still caught: the file baseline is re-verified at
startup, and log and event-log positions resume where they left off.

## Detection

Built-in rules, each firing once per cooldown window rather than once per event, and each saying
why it fired:

- **Brute force** and **password spraying** per source address
- **Login succeeded after failures** from the same address (*critical*)
- **Login from a new address** for an account (after a baseline is established)
- **Direct root / Administrator login** over SSH/RDP
- **Off-hours logins** (opt-in: `business_hours = "08:00-19:00"`)
- **Web server spawned a shell** (nginx/apache/php-fpm/w3wp → sh/bash/cmd/powershell)
- **Suspicious commands**: download-and-execute, reverse shells, encoded PowerShell, history
  wiping, disabling security tools, credential dumping (mimikatz, LSASS dumps), shadow-copy
  deletion, miners
- **Sensitive files**: `sudoers`, `authorized_keys`, `sshd_config`, `/etc/passwd`, PAM, cron,
  systemd units, `ld.so.preload`, Windows Startup folder, `hosts`…
- **Account changes**: new users, users added to admin groups
- **Log tampering**: Security log cleared, auth log truncated, `wevtutil cl`

Your own rules and suppressions are plain field matches in the config, with no DSL:

```toml
[[security.rules.custom]]
id = "prod-db-config"
description = "Production database configuration changed"
severity = "high"
action = "file.*"
target = "/etc/postgresql/*"

[[security.rules.suppress]]      # the events are still recorded; only the alert is silenced
rule = "encoded_exec"
parent = "ansible*"
reason = "Ansible uses encoded PowerShell over WinRM"
```

Alerts go to the console, email (SMTP/Gmail/SES/Resend) and webhooks (Slack, Discord, Teams
Workflows, generic JSON) at or above `notification.min_alert_severity`. Notifications are capped at
30 per hour, so an attack can't flood your pager, and every alert stays searchable.

## Forwarding to your SIEM

```toml
[forward.ndjson]       # one JSON event per line, rotated; point Splunk UF / Filebeat / Vector / Fluent Bit at it
enabled = true

[forward.syslog]       # RFC 5424 over UDP or TCP (octet-counted), JSON body
enabled = true
address = "tcp://siem.internal:6514"
min_severity = "info"
```

Forwarding also protects the audit trail: root can delete the local database, but not what has
already left the host.

## Trust and privacy

The agent records what people type, so it's built not to become the most valuable file on the box:

- **Secrets are redacted before storage**: passwords and tokens in command lines (`mysql -p…`,
  `--password`, `API_KEY=`, `https://user:pass@`, bearer tokens, cloud keys) and in captured config
  content. Private keys, `shadow` and `.env` files are tracked by hash only (`content_exclude`).
- **Tamper evidence**: every event is hash-chained; `server-sentinel verify` detects any edited or
  deleted row. This proves the trail wasn't quietly altered. It can't stop root from deleting the
  whole database, which is what forwarding is for.
- **Coverage gaps are reported**: if the agent was killed or offline, the next start records
  roughly how long, and whether it stopped cleanly.
- **Least privilege where it's free**: the systemd unit is read-everything / write-only-its-own-dir
  (`ProtectSystem=strict`), and memory and CPU are capped. The database and config are root-only
  (0600/0700).
- **Command capture can be turned off** (`capture_command_lines = false`) where policy requires it.

## Footprint

Measured on an 8-core Windows 11 desktop with 314 running processes, with process-table polling every second (the Windows fallback when 4688 auditing is off) and metrics every 2 s: **6.3 MB** release binary, **~23 MB** private memory (35 MB working set), **~4.6% of one core**. On Linux with the kernel proc connector there is no process polling at all. Not yet measured on a busy production server; the systemd unit caps the agent at 512 MB and 50% of a core regardless. Everything is bounded: the event channel, alert
state, learned session keys, stored command lines (8 KB), file content (256 KB per file) and
retention (30 days by default).

## Architecture

```text
                      ┌──────────── performance ─────────────┐
metrics collectors ──►│ detection → investigation → report   │──┐  "what changed
                      └──────────────────────────────────────┘  │   before this?"
audit collectors ───► security pipeline ───► event store (SQLite) ◄┘
 auth logs / journald   hold & reorder,        hash chain, FTS,
 Windows event log      redaction, sessions,   file history
 exec (netlink/proc)    attribution, rules  ──► NDJSON / syslog
 FIM, packages                              ──► console / email / webhook
```

```text
src/
  events/        unified event model (ECS-style fields) + bus
  audit/         collectors: authlog, journald, tail, linux_proc, windows, winevent, fim, packages, discovery
  security/      pipeline, sessions (attribution keys), rules, attribution, redaction
  storage/       event_store (SQLite: events, sessions, blobs, FIM baseline), incident_store
  incident/      performance incident state machine + related (change correlation)
  detection/, investigation/, rootcause/   performance detection and root-cause scoring
  notification/  console, email, webhook (async worker, rate-limited)
  forward/       NDJSON, syslog
  cli.rs, query.rs   investigation commands and search language
```

Session attribution works through lookup keys. A login opens a session carrying keys such as the
sshd pid, or a Windows logon or Terminal Services session ID. Each process carries its ancestor
pids, Linux audit session ID, TTY or TS session. The pipeline matches them, and a resolved process
teaches the session its own pid, so its children resolve too. Events are held for two seconds and
processed in timestamp order, because the exec notification for a shell usually arrives *before*
the sshd log line that created its session.

## Known limitations

Documented rather than hidden:

- **File-change attribution is inferred, not proven.** inotify and ReadDirectoryChangesW don't say
  which process wrote a file. Attribution comes from correlating recent commands (`vim /etc/x`,
  `sed -i … x`) and is always labelled `high` / `medium` / `low` / `none` with the reason. Exact
  attribution needs kernel audit hooks (fanotify/eBPF, or Windows SACL auditing), which are on the
  roadmap.
- **Linux without root, in a container, or under WSL** can't use the proc connector (the kernel
  only delivers exec notifications to the host network namespace). The agent detects this at
  startup and falls back to 1-second `/proc` polling, which misses very short commands. `sudo`
  commands are still captured in full from the auth log. The proc connector path itself has been
  unit-tested against the kernel wire format but not yet run on a bare-metal or VM host.
- **Windows without 4688 auditing** also polls, so sub-second processes can be missed. `doctor`
  shows how to enable it.
- **Windows event log is read by polling `wevtutil`** every 2 s, not through a push subscription.
  Nothing is lost (it resumes by record ID), but latency is seconds.
- **RDP client IPv6 addresses** aren't shown for sessions discovered at startup; logons seen live
  via event 4624/21 include them.
- **The MSI doesn't register the service yet.** Run `service install` after installing (see
  [Install](#install)).
- **No central console yet.** Every host is self-contained; aggregate with forwarding for now.
- **Retention is by age only** (default 30 days), not by size.

## Editions

ServerSentinel is open core. The agent — everything in this repository — is and stays **GPL-3.0**
open source: all collectors, rules, the local store and CLI, forwarding and notifications. A hosted
fleet console (multi-host search, long retention, SSO/RBAC, compliance evidence exports) is planned
as a paid, separately licensed service built on the same event format.

---

## Packaging

**Linux (`.deb` / `.rpm`):**

```bash
bash packaging/build-deb.sh   # -> pkg/deb/server-sentinel_<ver>_amd64.deb
bash packaging/build-rpm.sh   # -> pkg/rpm/server-sentinel-<ver>-1.x86_64.rpm
```

Both install `/usr/bin/server-sentinel`, the config at `/etc/server-sentinel/server-sentinel.toml`
(mode 0600, preserved on upgrade), a hardened systemd unit, and `/var/lib/server-sentinel`
(mode 0700).

**Windows (`.msi` / `.exe`):** built in CI on `windows-latest` (`.github/workflows/release.yml`),
with an installer page that asks for email settings (`wix/main.wxs`). The MSI has not been
click-tested on a real machine; test-install it before a real release.

```bash
git tag v0.2.0 && git push origin v0.2.0   # triggers the release workflow
```

## Email notifications

`[notification.email] provider`:

- **`smtp`**: STARTTLS + AUTH LOGIN. Gmail: `smtp.gmail.com:587`, your address, and an
  [App Password](https://myaccount.google.com/apppasswords) (requires 2-Step Verification). AWS
  SES: `email-smtp.<region>.amazonaws.com:587` with the SES-generated SMTP credentials, *not*
  your AWS access keys.
- **`resend`**: Resend's HTTPS API with `resend_api_key`.

Prefer environment variables over the config file for secrets: `SENTINEL_SMTP_PASSWORD`,
`SENTINEL_RESEND_API_KEY`, `SENTINEL_WEBHOOK_URL`. The agent warns at startup if a config file
containing credentials is readable by other users.

## Code signing (fixes "Unknown publisher" / SmartScreen)

The release workflow signs the `.exe` and `.msi` when `WINDOWS_CERTIFICATE_BASE64` and
`WINDOWS_CERTIFICATE_PASSWORD` secrets are set, and skips signing cleanly otherwise. Options:
self-signed (only for machines you control), [SignPath.io OSS](https://signpath.io/oss) (free for
accepted open-source projects), OV certificate (~$100–400/yr, SmartScreen reputation builds over
weeks), EV certificate (~$300–600/yr, immediate trust).

## Development

```bash
cargo test                     # 58 tests on Windows and Linux; parsers use real log and event fixtures
cargo clippy --all-targets
cargo run -- --config config/server-sentinel.toml run
```

## License

GPL-3.0-or-later. See [LICENSE.txt](LICENSE.txt).
