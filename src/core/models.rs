//! Core data models shared across the whole agent.
//!
//! These types are the common vocabulary used by collectors, the detection
//! engine, the investigation/correlation engine, root-cause scoring and
//! reporting. Keeping them in one place is what lets every other module stay
//! platform-agnostic (FR-020).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Alert level for a single resource at a single point in time (FR-006).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertLevel {
    Normal,
    Warning,
    Critical,
}

impl std::fmt::Display for AlertLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AlertLevel::Normal => "NORMAL",
            AlertLevel::Warning => "WARNING",
            AlertLevel::Critical => "CRITICAL",
        };
        write!(f, "{s}")
    }
}

/// Which resource a detection rule fired on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceKind {
    Cpu,
    Memory,
    Disk,
    Network,
}

impl std::fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ResourceKind::Cpu => "CPU",
            ResourceKind::Memory => "MEMORY",
            ResourceKind::Disk => "DISK",
            ResourceKind::Network => "NETWORK",
        };
        write!(f, "{s}")
    }
}

/// Root-cause category (FR-013).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RootCauseCategory {
    Process,
    Service,
    Application,
    Database,
    Storage,
    Cpu,
    Memory,
    Network,
    OperatingSystem,
    Configuration,
    ExternalDependency,
    Unknown,
}

impl std::fmt::Display for RootCauseCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            RootCauseCategory::Process => "PROCESS",
            RootCauseCategory::Service => "SERVICE",
            RootCauseCategory::Application => "APPLICATION",
            RootCauseCategory::Database => "DATABASE",
            RootCauseCategory::Storage => "STORAGE",
            RootCauseCategory::Cpu => "CPU",
            RootCauseCategory::Memory => "MEMORY",
            RootCauseCategory::Network => "NETWORK",
            RootCauseCategory::OperatingSystem => "OPERATING_SYSTEM",
            RootCauseCategory::Configuration => "CONFIGURATION",
            RootCauseCategory::ExternalDependency => "EXTERNAL_DEPENDENCY",
            RootCauseCategory::Unknown => "UNKNOWN",
        };
        write!(f, "{s}")
    }
}

/// Evidence quality classification (FR-014).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceQuality {
    High,
    Medium,
    Low,
}

impl std::fmt::Display for EvidenceQuality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            EvidenceQuality::High => "HIGH",
            EvidenceQuality::Medium => "MEDIUM",
            EvidenceQuality::Low => "LOW",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentMode {
    Normal,
    Investigation,
}

// ---------------------------------------------------------------------
// Telemetry (what collectors produce every tick)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuMetrics {
    pub usage_percent: f32,
    pub per_core_percent: Vec<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMetrics {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub used_percent: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskVolumeMetrics {
    pub mount_point: String,
    pub file_system: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_percent: f32,
    pub read_bytes_per_sec: f64,
    pub write_bytes_per_sec: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiskMetrics {
    pub volumes: Vec<DiskVolumeMetrics>,
    /// Highest used_percent across all volumes - what the detection engine
    /// evaluates against the disk thresholds.
    pub max_used_percent: f32,
    pub total_read_bytes_per_sec: f64,
    pub total_write_bytes_per_sec: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterfaceMetrics {
    pub interface: String,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkMetrics {
    pub interfaces: Vec<NetworkInterfaceMetrics>,
    pub total_rx_bytes_per_sec: f64,
    pub total_tx_bytes_per_sec: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSample {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub exe_path: Option<String>,
    pub start_time_epoch_secs: u64,
    pub status: String,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub read_bytes_per_sec: f64,
    pub write_bytes_per_sec: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Running,
    Stopped,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSample {
    pub name: String,
    pub state: ServiceState,
    pub description: Option<String>,
}

/// One full telemetry sample: everything the agent knows about the server
/// at a single instant. This is the unit stored in the ring buffer and
/// referenced throughout the incident timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub timestamp: DateTime<Utc>,
    pub cpu: CpuMetrics,
    pub memory: MemoryMetrics,
    pub disk: DiskMetrics,
    pub network: NetworkMetrics,
    /// Only populated with the top-N processes by relevance to keep the
    /// ring buffer bounded (FR-009); during investigation mode this is
    /// widened by the investigation engine.
    pub top_processes: Vec<ProcessSample>,
    pub services: Vec<ServiceSample>,
    pub alert_levels: HashMap<ResourceKind, AlertLevel>,
}

#[allow(dead_code)] // worst_alert_level() is public API for future consumers
impl Snapshot {
    pub fn worst_alert_level(&self) -> AlertLevel {
        self.alert_levels
            .values()
            .copied()
            .max()
            .unwrap_or(AlertLevel::Normal)
    }

    /// The raw metric value the detection engine evaluates thresholds
    /// against for a given resource (percent used, in all current cases).
    pub fn resource_value(&self, kind: ResourceKind) -> f32 {
        match kind {
            ResourceKind::Cpu => self.cpu.usage_percent,
            ResourceKind::Memory => self.memory.used_percent,
            ResourceKind::Disk => self.disk.max_used_percent,
            ResourceKind::Network => 0.0,
        }
    }
}

// ---------------------------------------------------------------------
// Incident / investigation
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCauseCandidate {
    pub label: String,
    pub category: RootCauseCategory,
    pub score: f32,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCauseConclusion {
    pub probable_cause: String,
    pub category: RootCauseCategory,
    pub confidence_percent: f32,
    pub evidence_quality: EvidenceQuality,
    pub reason_if_unknown: Option<String>,
    pub candidates_considered: Vec<RootCauseCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactSummary {
    pub affected_resources: Vec<String>,
    pub affected_applications: Vec<String>,
    pub potential_downtime: String,
    pub performance_impact: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendations {
    pub recommended_investigation: Vec<String>,
    pub recommended_corrective_action: Vec<String>,
}

/// The final artifact ServerSentinel produces for a single incident
/// (FR-016 / Section 30 example report).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentReport {
    pub incident_id: String,
    pub server_name: String,
    pub operating_system: String,
    pub environment: String,

    pub incident_type: ResourceKind,
    pub severity: AlertLevel,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub duration_seconds: Option<i64>,

    pub root_cause: RootCauseConclusion,
    pub evidence: Vec<EvidenceItem>,
    pub timeline: Vec<TimelineEvent>,
    pub impact: ImpactSummary,
    pub recommendations: Recommendations,

    pub generated_at: DateTime<Utc>,
}
