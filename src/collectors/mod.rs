//! Collector trait definitions.
//!
//! FR-020 requires the core system to have no platform-specific
//! assumptions. Every collector is defined here purely as a trait; the
//! `platform` module supplies the concrete implementations (Linux today,
//! Windows as a future adapter) that the rest of the codebase never needs
//! to know about.

use crate::core::models::{
    CpuMetrics, DiskMetrics, MemoryMetrics, NetworkMetrics, ProcessSample, ServiceSample,
};
use anyhow::Result;

pub trait CpuCollector: Send {
    fn collect(&mut self) -> Result<CpuMetrics>;
}

pub trait MemoryCollector: Send {
    fn collect(&mut self) -> Result<MemoryMetrics>;
}

pub trait DiskCollector: Send {
    fn collect(&mut self) -> Result<DiskMetrics>;
}

pub trait NetworkCollector: Send {
    fn collect(&mut self) -> Result<NetworkMetrics>;
}

/// `limit` bounds how many processes are returned, ranked by the
/// implementation's notion of relevance (highest CPU+I/O first). During
/// investigation mode the caller passes a larger limit.
pub trait ProcessCollector: Send {
    fn collect(&mut self, limit: usize) -> Result<Vec<ProcessSample>>;
}

/// Best-effort: platforms without a service manager (or a sandboxed
/// container without systemd) should return an empty list rather than
/// erroring, per FR-023 (one failing collector must not take the agent
/// down).
pub trait ServiceCollector: Send {
    fn collect(&mut self) -> Result<Vec<ServiceSample>>;
}

/// Bundles every collector the scheduler needs for one platform. Keeping
/// them behind one struct (rather than free functions) is what lets
/// `platform::linux` and a future `platform::windows` be swapped in from
/// a single call site.
pub struct CollectorSet {
    pub cpu: Box<dyn CpuCollector>,
    pub memory: Box<dyn MemoryCollector>,
    pub disk: Box<dyn DiskCollector>,
    pub network: Box<dyn NetworkCollector>,
    pub process: Box<dyn ProcessCollector>,
    pub service: Box<dyn ServiceCollector>,
}
