//! Configuration model & loader (FR-018).
//!
//! ServerSentinel is configured through a single TOML file. Every value has
//! a sane default so the agent can start with zero configuration, but every
//! value can be overridden.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub name: String,
    pub environment: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: hostname_fallback(),
            environment: "production".to_string(),
        }
    }
}

fn hostname_fallback() -> String {
    sysinfo::System::host_name().unwrap_or_else(|| "unknown-host".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitoringConfig {
    pub normal_interval_seconds: u64,
    pub investigation_interval_seconds: u64,
    pub top_process_count: usize,
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            normal_interval_seconds: 10,
            investigation_interval_seconds: 1,
            top_process_count: 8,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ThresholdsConfig {
    pub cpu_warning: f32,
    pub cpu_critical: f32,
    pub memory_warning: f32,
    pub memory_critical: f32,
    pub disk_warning: f32,
    pub disk_critical: f32,
}

impl Default for ThresholdsConfig {
    fn default() -> Self {
        Self {
            cpu_warning: 80.0,
            cpu_critical: 90.0,
            memory_warning: 80.0,
            memory_critical: 90.0,
            disk_warning: 80.0,
            disk_critical: 90.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IncidentConfig {
    /// How long a metric must remain continuously above its critical
    /// threshold before an incident is declared (FR-007 debounce).
    pub trigger_duration_seconds: u64,
    /// How much ring-buffer history to keep before an incident (FR-009).
    pub pre_incident_seconds: u64,
    /// How long to keep investigating after the metric recovers (FR-009).
    pub post_recovery_seconds: u64,
    /// How long a metric must remain continuously below its critical
    /// threshold before the incident is considered recovered.
    pub recovery_duration_seconds: u64,
}

impl Default for IncidentConfig {
    fn default() -> Self {
        Self {
            trigger_duration_seconds: 10,
            pre_incident_seconds: 120,
            post_recovery_seconds: 30,
            recovery_duration_seconds: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    pub base_dir: PathBuf,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            base_dir: PathBuf::from("./data"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EmailNotificationConfig {
    pub enabled: bool,
    /// "smtp" (authenticated SMTP+STARTTLS — works for Gmail app
    /// passwords *and* the AWS SES SMTP interface, since they're the same
    /// protocol) or "resend" (Resend's HTTPS API).
    pub provider: String,

    // --- provider = "smtp" ---
    /// e.g. "smtp.gmail.com" or "email-smtp.us-east-1.amazonaws.com"
    pub smtp_host: String,
    pub smtp_port: u16,
    /// Gmail: your full address. SES: the SMTP username from the SES
    /// console's "SMTP settings" — NOT your AWS access key ID.
    pub smtp_username: String,
    /// Gmail: an App Password (not your account password — Google
    /// requires 2FA + a generated app password for SMTP). SES: the SMTP
    /// password from the same "SMTP settings" page — NOT your AWS secret
    /// access key.
    pub smtp_password: String,

    // --- provider = "resend" ---
    pub resend_api_key: String,

    pub from_address: String,
    pub to_addresses: Vec<String>,
}

impl Default for EmailNotificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "smtp".to_string(),
            smtp_host: String::new(),
            smtp_port: 587,
            smtp_username: String::new(),
            smtp_password: String::new(),
            resend_api_key: String::new(),
            from_address: String::new(),
            to_addresses: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WebhookNotificationConfig {
    pub enabled: bool,
    /// Incoming-webhook URL (Slack, Discord, Teams Workflows, or any
    /// endpoint accepting JSON). May also be set via SENTINEL_WEBHOOK_URL
    /// so the secret URL needn't live in the config file.
    pub url: String,
    /// "generic" (full JSON payload), "slack" ({"text"}), "discord"
    /// ({"content"}).
    pub format: String,
}

impl Default for WebhookNotificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            format: "generic".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationConfig {
    /// Security alerts below this severity are stored and searchable but
    /// don't page anyone. (Performance incidents always notify.)
    pub min_alert_severity: String,
    pub email: EmailNotificationConfig,
    pub webhook: WebhookNotificationConfig,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            min_alert_severity: "high".to_string(),
            email: EmailNotificationConfig::default(),
            webhook: WebhookNotificationConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------
// Security / audit
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub enabled: bool,
    /// Event store location. Empty = `<storage.base_dir>/sentinel.db`.
    pub database: String,
    pub retention_days: u32,
    /// Collectors see the same activity through different paths with
    /// different latency (e.g. an exec notification arrives before the
    /// sshd log line that opened its session). Events are held this long
    /// and processed in timestamp order so attribution isn't order-racy.
    pub hold_seconds: u64,
    pub capture_command_lines: bool,
    pub redact_secrets: bool,
    pub auth: AuthSourceConfig,
    pub process: ProcessAuditConfig,
    pub fim: FimConfig,
    pub rules: RulesConfig,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            database: String::new(),
            retention_days: 30,
            hold_seconds: 2,
            capture_command_lines: true,
            redact_secrets: true,
            auth: AuthSourceConfig::default(),
            process: ProcessAuditConfig::default(),
            fim: FimConfig::default(),
            rules: RulesConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthSourceConfig {
    pub enabled: bool,
    /// Linux: "auto" (auth.log / secure if present, else journald),
    /// "file", or "journald". Windows: always the event log.
    pub source: String,
    /// Linux "file" source override; empty = auto-detect.
    pub log_path: String,
    /// On the very first start, ingest the existing log instead of only
    /// new lines. Later starts always resume from the saved position.
    pub backfill: bool,
    /// Windows event-log poll interval.
    pub poll_interval_seconds: u64,
}

impl Default for AuthSourceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            source: "auto".to_string(),
            log_path: String::new(),
            backfill: false,
            poll_interval_seconds: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessAuditConfig {
    pub enabled: bool,
    /// Linux: "auto" (kernel proc connector, falling back to /proc
    /// polling), "netlink", "poll". Windows: "auto" (Security 4688 if
    /// process-creation auditing is on, else polling), "eventlog", "poll".
    pub mode: String,
    pub poll_interval_ms: u64,
    /// Process names never recorded (exact, case-insensitive), e.g.
    /// chatty monitoring helpers.
    pub ignore_names: Vec<String>,
    /// Only record processes attributable to an interactive session.
    /// Off by default: a web server spawning a shell has no session and is
    /// exactly what you want to see.
    pub sessions_only: bool,
}

impl Default for ProcessAuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: "auto".to_string(),
            poll_interval_ms: 1000,
            ignore_names: Vec::new(),
            sessions_only: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FimConfig {
    pub enabled: bool,
    /// Directories / files to watch. `*` expands one path segment
    /// ("/home/*/.ssh").
    pub paths: Vec<String>,
    /// Never tracked at all.
    pub exclude: Vec<String>,
    /// Tracked by hash only — content (and therefore diffs) is never
    /// stored. Secrets and private keys belong here.
    pub content_exclude: Vec<String>,
    /// Text files up to this size keep their content for diffs.
    pub max_content_bytes: u64,
    /// Files larger than this are tracked by size/mtime only.
    pub max_hash_bytes: u64,
    pub max_files: usize,
    pub rescan_interval_seconds: u64,
    pub debounce_ms: u64,
}

fn default_fim_paths() -> Vec<String> {
    if cfg!(windows) {
        vec![
            r"C:\Windows\System32\drivers\etc".to_string(),
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp".to_string(),
            r"C:\ProgramData\ssh".to_string(),
            r"C:\Users\*\.ssh".to_string(),
            r"C:\inetpub\wwwroot".to_string(),
        ]
    } else {
        vec![
            "/etc".to_string(),
            "/root/.ssh".to_string(),
            "/home/*/.ssh".to_string(),
            "/var/spool/cron".to_string(),
            "/usr/local/bin".to_string(),
        ]
    }
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            paths: default_fim_paths(),
            exclude: [
                "*.swp", "*.swx", "*.swo", "*~", "*.tmp", "*/4913", "*/.#*", "*.dpkg-tmp", "*/.pwd.lock",
                "/etc/mtab", "/etc/ld.so.cache", "/etc/adjtime", "*/.lock", "*.log",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            content_exclude: [
                "*/shadow", "*/shadow-", "*/gshadow", "*/gshadow-", "*/security/opasswd", "*.key", "*.pem",
                "*.p12", "*.pfx", "*/id_rsa", "*/id_ecdsa", "*/id_ed25519", "*/id_dsa", "*/ssh_host_*_key",
                "*/.env", "*.keytab", "*/ssl/private/*",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            max_content_bytes: 256 * 1024,
            max_hash_bytes: 64 * 1024 * 1024,
            max_files: 200_000,
            rescan_interval_seconds: 3600,
            debounce_ms: 1500,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomRule {
    pub id: String,
    pub description: String,
    pub severity: String,
    /// Every non-empty field must match (`*` wildcards). At least one
    /// field must be set.
    pub action: String,
    pub user: String,
    pub src_ip: String,
    pub target: String,
    pub command: String,
    pub process: String,
    pub notify: bool,
}

impl Default for CustomRule {
    fn default() -> Self {
        Self {
            id: String::new(),
            description: String::new(),
            severity: "medium".to_string(),
            action: String::new(),
            user: String::new(),
            src_ip: String::new(),
            target: String::new(),
            command: String::new(),
            process: String::new(),
            notify: true,
        }
    }
}

/// Silences alerts from known-good activity (e.g. Ansible / SCCM running
/// encoded PowerShell, a backup job touching /etc). Every non-empty
/// field must match (`*` wildcards); `rule` matches the rule id
/// ("encoded_exec", "custom.my-rule", "*"). The underlying events are
/// still recorded — only the alert is suppressed.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SuppressRule {
    pub rule: String,
    pub user: String,
    pub src_ip: String,
    pub target: String,
    pub command: String,
    pub process: String,
    pub parent: String,
    /// Why this exists — shows up nowhere but the config, which is the
    /// point: suppressions without a reason rot.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    /// Failed logins from one source within the window before alerting.
    pub bruteforce_threshold: u32,
    pub bruteforce_window_seconds: u64,
    /// Distinct usernames tried from one source within the window.
    pub spray_distinct_users: u32,
    /// Suppress repeats of the same alert (same rule + same key) for this
    /// long, so a 10,000-attempt brute force is one page, not 2,000.
    pub alert_cooldown_seconds: u64,
    pub new_source_login: bool,
    pub privileged_account_login: bool,
    pub suspicious_commands: bool,
    pub webserver_shell: bool,
    pub sensitive_files: bool,
    pub account_changes: bool,
    pub log_tampering: bool,
    /// Local-time window considered normal for interactive logins, e.g.
    /// "08:00-19:00". Empty disables the off-hours rule.
    pub business_hours: String,
    /// Source addresses that never trigger new-source / off-hours alerts
    /// (jump hosts, VPN egress). `*` wildcards.
    pub trusted_sources: Vec<String>,
    pub custom: Vec<CustomRule>,
    pub suppress: Vec<SuppressRule>,
}

impl Default for RulesConfig {
    fn default() -> Self {
        Self {
            bruteforce_threshold: 8,
            bruteforce_window_seconds: 120,
            spray_distinct_users: 5,
            alert_cooldown_seconds: 900,
            new_source_login: true,
            privileged_account_login: true,
            suspicious_commands: true,
            webserver_shell: true,
            sensitive_files: true,
            account_changes: true,
            log_tampering: true,
            business_hours: String::new(),
            trusted_sources: Vec::new(),
            custom: Vec::new(),
            suppress: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------
// Forwarding to an existing SIEM / log pipeline
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NdjsonForwardConfig {
    pub enabled: bool,
    /// Empty = `<storage.base_dir>/export/events.ndjson`. Point Splunk UF,
    /// Filebeat, Vector or Fluent Bit at it.
    pub path: String,
    pub max_file_mb: u64,
    pub keep_files: u32,
}

impl Default for NdjsonForwardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: String::new(),
            max_file_mb: 100,
            keep_files: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SyslogForwardConfig {
    pub enabled: bool,
    /// "udp://host:514" or "tcp://host:514". RFC 5424, JSON message body.
    pub address: String,
    /// Only forward events at or above this severity ("info" = all).
    pub min_severity: String,
}

impl Default for SyslogForwardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: String::new(),
            min_severity: "info".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ForwardConfig {
    pub ndjson: NdjsonForwardConfig,
    pub syslog: SyslogForwardConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub monitoring: MonitoringConfig,
    #[serde(default)]
    pub thresholds: ThresholdsConfig,
    #[serde(default)]
    pub incident: IncidentConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub notification: NotificationConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub forward: ForwardConfig,
}

impl Config {
    /// Load configuration from `path`. If the file does not exist, a
    /// default configuration is written there and returned, so the agent
    /// always has a config file to inspect / edit on next run.
    ///
    /// Secrets can be supplied via environment instead of the file
    /// (SENTINEL_SMTP_PASSWORD, SENTINEL_RESEND_API_KEY,
    /// SENTINEL_WEBHOOK_URL) — preferable for anything checked into
    /// config management.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        let mut cfg = Self::load_or_create_file(path)?;
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    fn apply_env_overrides(&mut self) {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        if let Some(v) = env("SENTINEL_SMTP_PASSWORD") {
            self.notification.email.smtp_password = v;
        }
        if let Some(v) = env("SENTINEL_RESEND_API_KEY") {
            self.notification.email.resend_api_key = v;
        }
        if let Some(v) = env("SENTINEL_WEBHOOK_URL") {
            self.notification.webhook.url = v;
        }
    }

    pub fn event_db_path(&self) -> PathBuf {
        if self.security.database.is_empty() {
            self.storage.base_dir.join("sentinel.db")
        } else {
            PathBuf::from(&self.security.database)
        }
    }

    /// Problems worth warning about at startup (not fatal).
    pub fn warnings(&self, path: &Path) -> Vec<String> {
        let mut out = Vec::new();
        let has_secret = !self.notification.email.smtp_password.is_empty()
            || !self.notification.email.resend_api_key.is_empty();
        #[cfg(unix)]
        if has_secret {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                if meta.permissions().mode() & 0o044 != 0 {
                    out.push(format!(
                        "{} contains credentials and is readable by other users; run `chmod 600 {}` \
                         or move secrets to SENTINEL_SMTP_PASSWORD / SENTINEL_RESEND_API_KEY",
                        path.display(),
                        path.display()
                    ));
                }
            }
        }
        #[cfg(not(unix))]
        let _ = (path, has_secret);
        if crate::events::Severity::parse(&self.notification.min_alert_severity).is_none() {
            out.push(format!(
                "notification.min_alert_severity '{}' is not one of info/low/medium/high/critical; using 'high'",
                self.notification.min_alert_severity
            ));
        }
        for rule in &self.security.rules.custom {
            if rule.id.is_empty() {
                out.push("a [[security.rules.custom]] entry has no id and will be ignored".to_string());
            }
        }
        out
    }

    fn load_or_create_file(path: &Path) -> Result<Self> {
        if path.exists() {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading config file {}", path.display()))?;
            let cfg: Config = toml::from_str(&raw)
                .with_context(|| format!("parsing config file {}", path.display()))?;
            Ok(cfg)
        } else {
            let cfg = Config::default();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            let raw = toml::to_string_pretty(&cfg)?;
            std::fs::write(path, raw)
                .with_context(|| format!("writing default config to {}", path.display()))?;
            Ok(cfg)
        }
    }
}
