//! Windows-specific pieces of the collector set (FR-020).
//!
//! CPU/memory/disk/network/process collectors are OS-agnostic and live in
//! `platform::common` (backed by `sysinfo`, which already supports
//! Windows natively via Performance Counters / WMI under the hood). The
//! only thing genuinely specific to Windows here is reading service state,
//! done via `Get-Service` through PowerShell rather than `systemctl`.

use crate::collectors::{CollectorSet, ServiceCollector};
use crate::core::models::{ServiceSample, ServiceState};
use crate::platform::common::{
    CpuCollectorImpl, DiskCollectorImpl, MemoryCollectorImpl, NetworkCollectorImpl,
    ProcessCollectorImpl,
};
use anyhow::Result;
use std::process::Command;

/// Reads Windows service state via PowerShell's `Get-Service`. If
/// PowerShell is unavailable for any reason, degrades gracefully to an
/// empty list per FR-023 rather than failing the whole agent.
pub struct WindowsServiceCollector;

impl WindowsServiceCollector {
    pub fn new() -> Self {
        Self
    }
}

fn map_status(status: &str) -> ServiceState {
    match status {
        "Running" => ServiceState::Running,
        "Stopped" => ServiceState::Stopped,
        _ => ServiceState::Unknown,
    }
}

impl ServiceCollector for WindowsServiceCollector {
    fn collect(&mut self) -> Result<Vec<ServiceSample>> {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-Service | Select-Object Name,Status,DisplayName | ConvertTo-Json -Compress",
            ])
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => {
                tracing::debug!(
                    "powershell Get-Service unavailable; service collector returning empty list"
                );
                return Ok(Vec::new());
            }
        };

        let text = String::from_utf8_lossy(&output.stdout);
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse Get-Service JSON output");
                return Ok(Vec::new());
            }
        };

        // ConvertTo-Json returns a bare object (not wrapped in an array)
        // when there's exactly one service; normalize both shapes.
        let entries: Vec<&serde_json::Value> = match &value {
            serde_json::Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };

        let services = entries
            .into_iter()
            .filter_map(|entry| {
                let name = entry.get("Name")?.as_str()?.to_string();
                let status = entry.get("Status").and_then(|s| s.as_str()).unwrap_or("");
                let description = entry
                    .get("DisplayName")
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string());
                Some(ServiceSample {
                    name,
                    state: map_status(status),
                    description,
                })
            })
            .collect();

        Ok(services)
    }
}

/// Builds a complete Windows `CollectorSet`.
pub fn build_collectors() -> CollectorSet {
    CollectorSet {
        cpu: Box::new(CpuCollectorImpl::new()),
        memory: Box::new(MemoryCollectorImpl::new()),
        disk: Box::new(DiskCollectorImpl::new()),
        network: Box::new(NetworkCollectorImpl::new()),
        process: Box::new(ProcessCollectorImpl::new()),
        service: Box::new(WindowsServiceCollector::new()),
    }
}
