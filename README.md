# ServerSentinel — Agent (MVP)

Lightweight Linux monitoring agent that watches CPU, memory and disk, and
when a resource sustains a critical level, automatically switches into a
faster-sampling **investigation mode**, correlates the culprit process,
scores a root cause, and writes a JSON + HTML incident report — with zero
manual triage. This is the MVP scope recommended by the FRD (section 41):
one full, working investigation cycle end-to-end, architected so the rest
of the roadmap (Windows collectors, a central server/dashboard, a
database backend, more notification channels) slots in without a rewrite.

## What's implemented

| FRD requirement | Status |
|---|---|
| FR-001–004 CPU/Memory/Disk/Process telemetry | ✅ (Linux, via `sysinfo`) |
| Network telemetry | ✅ collected; not yet used in correlation (see Limitations) |
| FR-005–007 Threshold detection + debounce | ✅ |
| FR-008 Investigation mode (faster sampling) | ✅ |
| FR-009 Pre-incident ring buffer + post-recovery window | ✅ |
| FR-010 Investigation engine | ✅ |
| FR-011 Process correlation | ✅ |
| FR-012–014 Root cause scoring, confidence, evidence quality | ✅ |
| FR-015 Timeline | ✅ |
| FR-016 Incident report (JSON + HTML) | ✅ |
| FR-017 Notifications | ✅ console; ✅ email (plain SMTP, no STARTTLS/AUTH — see below) |
| FR-018 TOML configuration | ✅ |
| FR-019 Local file storage (`incidents/*.json`, `reports/*.html`) | ✅ |
| FR-020 Platform abstraction (trait-based collectors) | ✅ Linux **and** Windows both shipped |
| FR-023 Graceful degradation per failing collector | ✅ |
| Central server, dashboard, DB backend, AI layer | ❌ out of scope for this build — see Roadmap |

## Architecture

```
src/
  core/          shared models, TOML config, ring buffer
  collectors/    trait definitions only (platform-agnostic)
  platform/
    common.rs    CPU/memory/disk/network/process collectors — OS-agnostic,
                 backed by `sysinfo` (which abstracts Linux/Windows itself)
    linux/       Linux-only piece: service state via `systemctl`
    windows/     Windows-only piece: service state via PowerShell `Get-Service`
  detection/     threshold + debounce -> alert levels, trigger decisions
  incident/      the incident state machine, timeline, evidence assembly
  investigation/ evidence-window assembly + process correlation
  rootcause/     confidence scoring (conservative: reports UNKNOWN rather
                 than guessing when evidence is weak)
  reporting/     JSON serialization + hand-written HTML report renderer
  storage/       writes incidents/*.json and reports/*.html
  notification/  Notifier trait; console (always on) + email (opt-in)
  main.rs        wires it all into the monitor/detect/investigate loop
```

The state machine implemented in `incident::manager`:

```
Normal (sampling every normal_interval_seconds)
   │  resource sustains >= critical threshold for trigger_duration_seconds
   ▼
Investigation (sampling every investigation_interval_seconds)
   │  resource drops below critical threshold for recovery_duration_seconds
   ▼
Post-recovery evidence window (post_recovery_seconds)
   │
   ▼
Correlation -> Root cause scoring -> Report (JSON + HTML) -> Notify -> Normal
```

## Packaging

**Linux (`.deb` / `.rpm`) — built and verified in this repo's own dev
environment**: installed the `.deb` with `dpkg -i`, confirmed the binary
runs from `/usr/bin`, and purged it cleanly with `dpkg -P`.

```bash
bash packaging/build-deb.sh   # -> pkg/deb/server-sentinel_<ver>_amd64.deb
bash packaging/build-rpm.sh   # -> pkg/rpm/server-sentinel-<ver>-1.x86_64.rpm
```

Both install the binary to `/usr/bin/server-sentinel`, config to
`/etc/server-sentinel/server-sentinel.toml` (preserved on upgrade,
removed only on `dpkg -P` / full `rpm -e`), a systemd unit, and create
`/var/lib/server-sentinel/{incidents,reports}`.

**Windows (`.msi` / `.exe`) — not build-able in this sandbox (no Windows
toolchain here), wired up via CI instead.** `.github/workflows/release.yml`
builds a raw `.exe` (zipped with the README and a sample config) and an
`.msi` installer (via `cargo-wix` + WiX Toolset v3) on a real
`windows-latest` GitHub Actions runner, and attaches both — plus the
`.deb`/`.rpm` — to a GitHub Release whenever you push a `v*` tag.

**Important**: unlike the `.deb`/`.rpm`, I could not actually run and
verify the Windows/MSI leg of that workflow — I wrote it against the
standard `cargo-wix` recipe used by other Rust CLI projects, but you
should do one test run (`workflow_dispatch` or a throwaway `v0.0.0-test`
tag) and check the generated `.msi` actually installs before relying on
it for a real release.

```bash
git push origin main
git tag v0.1.0 && git push origin v0.1.0   # triggers the release workflow
```

## Building

Requires a Rust toolchain (edition 2021). Tested against rustc 1.75+.

```bash
cargo build --release
./target/release/server-sentinel --config config/server-sentinel.toml
```

> **Note on `Cargo.toml` version pins.** This was built in a sandbox
> limited to rustc 1.75 (no newer toolchain available via `apt`), while
> several transitive crates (`clap`, `uuid`, `indexmap`/`hashbrown`,
> `getrandom`) have since bumped their MSRV to require Rust's 2024
> edition. The pins in `Cargo.toml` (`clap = "=4.5.20"`, `uuid =
> "=1.10.0"`, `indexmap = "=2.2.6"`, `hashbrown = "=0.14.5"`,
> `getrandom = "=0.2.15"`) keep the build working on 1.75. **On a
> current toolchain (1.85+) these pins can simply be deleted** to pick up
> the latest versions.

## Configuration

`config/server-sentinel.toml` is created with defaults on first run if it
doesn't exist. Key sections:

```toml
[thresholds]
cpu_warning = 80.0
cpu_critical = 90.0
memory_warning = 80.0
memory_critical = 90.0
disk_warning = 80.0
disk_critical = 90.0

[incident]
trigger_duration_seconds = 10   # sustained-critical debounce (FR-007)
pre_incident_seconds = 120      # ring buffer retention before an incident
post_recovery_seconds = 30      # extra evidence collected after recovery
recovery_duration_seconds = 5   # sustained-recovered debounce

[notification.email]
enabled = false                 # opt-in; see Limitations below
```

## Running as a service

```ini
# /etc/systemd/system/server-sentinel.service
[Unit]
Description=ServerSentinel monitoring agent
After=network.target

[Service]
Type=simple
ExecStart=/opt/server-sentinel/server-sentinel --config /opt/server-sentinel/config/server-sentinel.toml
WorkingDirectory=/opt/server-sentinel
Restart=on-failure
RestartSec=5
User=root
# journald captures stdout/stderr (agent logs there); use `journalctl -u
# server-sentinel` for rotation/retention rather than a file appender.

[Install]
WantedBy=multi-user.target
```

## Known limitations (be aware of these before calling this "done")

- **Windows service collector needs PowerShell on PATH** (standard on
  every supported Windows Server release). Per-process disk I/O via
  `sysinfo` on Windows may read as zero unless the agent runs elevated —
  a documented `sysinfo`/Windows API limitation, not specific to this code.
- **No per-process network attribution.** Network incidents are detected
  (interfaces are collected) but correlation currently only scores
  process-level CPU/memory/disk I/O; a network incident will report
  UNKNOWN with LOW evidence quality rather than guessing.
- **Per-volume disk throughput is approximated.** The OS doesn't expose
  portable per-mount-point read/write rates; `total_read_bytes_per_sec`
  is a system-wide sum of process I/O deltas, which is accurate in
  aggregate but not split by volume.
- **Email notifier speaks plain SMTP** (connect + `MAIL FROM`/`RCPT
  TO`/`DATA`, no STARTTLS/AUTH). Fine for an internal relay; for Gmail/SES
  swap in the `lettre` crate behind the same `Notifier` trait.
- **No central server, dashboard, or database.** Storage is local
  files (FR-019's Phase 1 architecture). Multi-server aggregation and a
  web UI are explicitly later-phase items in the FRD, not attempted here.
- **No AI/LLM-assisted root cause.** Root cause is deterministic
  statistical correlation (ramp-up + recovery decay + contention share),
  intentionally conservative — it says UNKNOWN rather than fabricating a
  cause when the evidence is thin.
- **Container/quota disk-usage quirk.** In a containerized environment
  with a storage quota, `statvfs`-reported `total_space` can reflect the
  underlying filesystem rather than the quota, making `used_percent`
  look inflated. This does not occur on a normal (non-quota'd) Linux
  server — the formula matches how `df` and most Linux monitoring tools
  compute usage.
- **No automated tests yet.** The system was validated by hand (see
  below) rather than a `#[test]` suite — worth adding before production
  rollout.

## Validation performed

Built and ran in this sandbox end-to-end: started the agent with an
aggressive CPU threshold, generated real CPU load with `yes`, and
confirmed the full cycle — detection → investigation mode → correlation
→ root-cause scoring → JSON/HTML report → console notification — fires
correctly and identifies the actual culprit process with an honest
confidence score. An earlier version of the correlation formula
mis-attributed the incident to an unrelated near-zero-activity process;
this was caught during testing and fixed (see `investigation/correlation.rs`,
`MIN_SHARE_TO_CONSIDER`) by requiring a minimum contention share before a
process is considered a candidate at all.

## Roadmap (not attempted here — see Limitations)

1. Central API server + multi-agent aggregation + web dashboard
2. Database backend (Postgres/etc.) replacing local file storage
3. Additional notification channels (Slack/Teams/webhooks) behind the
   existing `Notifier` trait
4. Automated remediation / runbooks
5. Broader correlation inputs (per-process network, container/cgroup
   awareness, log correlation)
6. Windows: richer service metadata (start type, recovery actions) and
   elevated-mode per-process disk I/O
