//! OS-agnostic collector implementations, shared by every platform
//! (FR-020).
//!
//! CPU, memory, disk capacity, network, and process telemetry are all
//! sourced through `sysinfo`, which already abstracts Linux/Windows/macOS
//! internally — so there is nothing platform-specific about these five
//! collectors. The only genuinely OS-specific collector is services
//! (`systemctl` on Linux vs the Service Control Manager on Windows), which
//! lives in `platform::linux` / `platform::windows` respectively.

use crate::collectors::{CpuCollector, DiskCollector, MemoryCollector, NetworkCollector, ProcessCollector};
use crate::core::models::{
    CpuMetrics, DiskMetrics, DiskVolumeMetrics, MemoryMetrics, NetworkInterfaceMetrics,
    NetworkMetrics, ProcessSample,
};
use anyhow::Result;
use std::time::Instant;
use sysinfo::{Disks, Networks, Pid, System};

pub struct CpuCollectorImpl {
    sys: System,
}

impl CpuCollectorImpl {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_cpu();
        Self { sys }
    }
}

impl CpuCollector for CpuCollectorImpl {
    fn collect(&mut self) -> Result<CpuMetrics> {
        self.sys.refresh_cpu();
        let per_core_percent = self.sys.cpus().iter().map(|c| c.cpu_usage()).collect();
        Ok(CpuMetrics {
            usage_percent: self.sys.global_cpu_info().cpu_usage(),
            per_core_percent,
        })
    }
}

pub struct MemoryCollectorImpl {
    sys: System,
}

impl MemoryCollectorImpl {
    pub fn new() -> Self {
        Self {
            sys: System::new_all(),
        }
    }
}

impl MemoryCollector for MemoryCollectorImpl {
    fn collect(&mut self) -> Result<MemoryMetrics> {
        self.sys.refresh_memory();
        let total = self.sys.total_memory();
        let used = self.sys.used_memory();
        let available = self.sys.available_memory();
        let used_percent = if total > 0 {
            (used as f64 / total as f64 * 100.0) as f32
        } else {
            0.0
        };
        Ok(MemoryMetrics {
            total_bytes: total,
            used_bytes: used,
            available_bytes: available,
            used_percent,
        })
    }
}

pub struct DiskCollectorImpl {
    disks: Disks,
    /// A dedicated process table used purely to sum system-wide disk I/O
    /// throughput as a proxy for volume-level read/write rates, since the
    /// OS does not expose per-volume throughput through a portable API.
    io_sys: System,
    last_tick: Instant,
}

impl DiskCollectorImpl {
    pub fn new() -> Self {
        Self {
            disks: Disks::new_with_refreshed_list(),
            io_sys: System::new_all(),
            last_tick: Instant::now(),
        }
    }
}

impl DiskCollector for DiskCollectorImpl {
    fn collect(&mut self) -> Result<DiskMetrics> {
        self.disks.refresh();

        // Pseudo/virtual filesystems don't represent real storage capacity
        // (tmpfs lives in RAM, fuse.* network mounts often report
        // nonsensical multi-petabyte "capacity", etc.) and would otherwise
        // pollute both the max-used-percent signal and the report.
        const IGNORED_FILESYSTEMS: &[&str] = &[
            "tmpfs", "devtmpfs", "proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue",
            "debugfs", "tracefs", "pstore", "squashfs",
        ];

        let mut volumes = Vec::new();
        let mut max_used_percent: f32 = 0.0;
        for disk in self.disks.list() {
            let fs = disk.file_system().to_string_lossy().to_string();
            if IGNORED_FILESYSTEMS.contains(&fs.as_str()) || fs.starts_with("fuse.") {
                continue;
            }
            let total = disk.total_space();
            let available = disk.available_space();
            let used_percent = if total > 0 {
                ((total - available) as f64 / total as f64 * 100.0) as f32
            } else {
                0.0
            };
            max_used_percent = max_used_percent.max(used_percent);
            volumes.push(DiskVolumeMetrics {
                mount_point: disk.mount_point().to_string_lossy().to_string(),
                file_system: disk.file_system().to_string_lossy().to_string(),
                total_bytes: total,
                available_bytes: available,
                used_percent,
                // Per-volume throughput is not portably available; system
                // total throughput below is a reliable aggregate proxy.
                read_bytes_per_sec: 0.0,
                write_bytes_per_sec: 0.0,
            });
        }

        self.io_sys.refresh_processes();
        let elapsed = self.last_tick.elapsed().as_secs_f64().max(0.001);
        self.last_tick = Instant::now();

        let mut read_bytes = 0u64;
        let mut write_bytes = 0u64;
        for (_, process) in self.io_sys.processes() {
            let usage = process.disk_usage();
            read_bytes += usage.read_bytes;
            write_bytes += usage.written_bytes;
        }

        Ok(DiskMetrics {
            volumes,
            max_used_percent,
            total_read_bytes_per_sec: read_bytes as f64 / elapsed,
            total_write_bytes_per_sec: write_bytes as f64 / elapsed,
        })
    }
}

pub struct NetworkCollectorImpl {
    networks: Networks,
    last_tick: Instant,
}

impl NetworkCollectorImpl {
    pub fn new() -> Self {
        Self {
            networks: Networks::new_with_refreshed_list(),
            last_tick: Instant::now(),
        }
    }
}

impl NetworkCollector for NetworkCollectorImpl {
    fn collect(&mut self) -> Result<NetworkMetrics> {
        self.networks.refresh();
        let elapsed = self.last_tick.elapsed().as_secs_f64().max(0.001);
        self.last_tick = Instant::now();

        let mut interfaces = Vec::new();
        let mut total_rx = 0.0;
        let mut total_tx = 0.0;
        for (name, data) in self.networks.list() {
            let rx = data.received() as f64 / elapsed;
            let tx = data.transmitted() as f64 / elapsed;
            total_rx += rx;
            total_tx += tx;
            interfaces.push(NetworkInterfaceMetrics {
                interface: name.clone(),
                rx_bytes_per_sec: rx,
                tx_bytes_per_sec: tx,
                errors: data.errors_on_received() + data.errors_on_transmitted(),
            });
        }

        Ok(NetworkMetrics {
            interfaces,
            total_rx_bytes_per_sec: total_rx,
            total_tx_bytes_per_sec: total_tx,
        })
    }
}

pub struct ProcessCollectorImpl {
    sys: System,
    last_tick: Instant,
}

impl ProcessCollectorImpl {
    pub fn new() -> Self {
        Self {
            sys: System::new_all(),
            last_tick: Instant::now(),
        }
    }
}

impl ProcessCollector for ProcessCollectorImpl {
    fn collect(&mut self, limit: usize) -> Result<Vec<ProcessSample>> {
        self.sys.refresh_processes();
        let elapsed = self.last_tick.elapsed().as_secs_f64().max(0.001);
        self.last_tick = Instant::now();

        let mut samples: Vec<ProcessSample> = self
            .sys
            .processes()
            .iter()
            .map(|(pid, p)| {
                let usage = p.disk_usage();
                ProcessSample {
                    pid: pid.as_u32(),
                    parent_pid: p.parent().map(|p: Pid| p.as_u32()),
                    name: p.name().to_string(),
                    exe_path: p.exe().map(|e| e.to_string_lossy().to_string()),
                    start_time_epoch_secs: p.start_time(),
                    status: p.status().to_string(),
                    cpu_percent: p.cpu_usage(),
                    memory_bytes: p.memory(),
                    read_bytes_per_sec: usage.read_bytes as f64 / elapsed,
                    write_bytes_per_sec: usage.written_bytes as f64 / elapsed,
                }
            })
            .collect();

        // Rank by a blended relevance score: CPU % plus a normalized I/O
        // contribution, so a disk-bound or network-bound culprit process
        // is retained even if its CPU usage looks unremarkable.
        samples.sort_by(|a, b| {
            let score_a = a.cpu_percent as f64 + (a.read_bytes_per_sec + a.write_bytes_per_sec) / 1_000_000.0;
            let score_b = b.cpu_percent as f64 + (b.read_bytes_per_sec + b.write_bytes_per_sec) / 1_000_000.0;
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });
        samples.truncate(limit);
        Ok(samples)
    }
}

