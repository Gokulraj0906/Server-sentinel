//! Linux-specific pieces of the collector set (FR-020).
//!
//! CPU/memory/disk/network/process collectors are OS-agnostic and live in
//! `platform::common`; the only thing genuinely specific to Linux here is
//! reading service state via `systemctl`.

use crate::collectors::{CollectorSet, ServiceCollector};
use crate::core::models::{ServiceSample, ServiceState};
use crate::platform::common::{
    CpuCollectorImpl, DiskCollectorImpl, MemoryCollectorImpl, NetworkCollectorImpl,
    ProcessCollectorImpl,
};
use anyhow::Result;
use std::process::Command;

/// Reads service state via `systemctl`. If systemd is not present (common
/// inside minimal containers), this degrades gracefully to an empty list
/// per FR-023 rather than failing the whole agent.
pub struct LinuxServiceCollector;

impl LinuxServiceCollector {
    pub fn new() -> Self {
        Self
    }
}

impl ServiceCollector for LinuxServiceCollector {
    fn collect(&mut self) -> Result<Vec<ServiceSample>> {
        let output = Command::new("systemctl")
            .args([
                "list-units",
                "--type=service",
                "--all",
                "--no-legend",
                "--no-pager",
                "--plain",
            ])
            .output();

        let output = match output {
            Ok(o) if o.status.success() => o,
            _ => {
                tracing::debug!("systemctl unavailable; service collector returning empty list");
                return Ok(Vec::new());
            }
        };

        let text = String::from_utf8_lossy(&output.stdout);
        let mut services = Vec::new();
        for line in text.lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 4 {
                continue;
            }
            let name = cols[0].trim_end_matches(".service").to_string();
            let active = cols[2];
            let sub = cols[3];
            let state = match (active, sub) {
                (_, "failed") | ("failed", _) => ServiceState::Failed,
                ("active", "running") => ServiceState::Running,
                ("inactive", _) => ServiceState::Stopped,
                _ => ServiceState::Unknown,
            };
            let description = if cols.len() > 4 {
                Some(cols[4..].join(" "))
            } else {
                None
            };
            services.push(ServiceSample {
                name,
                state,
                description,
            });
        }
        Ok(services)
    }
}

/// Builds a complete Linux `CollectorSet`.
pub fn build_collectors() -> CollectorSet {
    CollectorSet {
        cpu: Box::new(CpuCollectorImpl::new()),
        memory: Box::new(MemoryCollectorImpl::new()),
        disk: Box::new(DiskCollectorImpl::new()),
        network: Box::new(NetworkCollectorImpl::new()),
        process: Box::new(ProcessCollectorImpl::new()),
        service: Box::new(LinuxServiceCollector::new()),
    }
}
