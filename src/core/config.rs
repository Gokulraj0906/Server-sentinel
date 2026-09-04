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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EmailNotificationConfig {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub from_address: String,
    pub to_addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationConfig {
    pub email: EmailNotificationConfig,
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
}

impl Config {
    /// Load configuration from `path`. If the file does not exist, a
    /// default configuration is written there and returned, so the agent
    /// always has a config file to inspect / edit on next run.
    pub fn load_or_create(path: &Path) -> Result<Self> {
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
