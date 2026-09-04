//! ServerSentinel agent entrypoint.
//!
//! ```text
//! SERVER -> Lightweight Agent -> Telemetry Collection -> Detection Engine
//!   -> [Normal loop] or [Investigation Mode -> Evidence -> Correlation
//!      -> Root Cause -> Report -> Storage + Notification] -> back to Normal
//! ```
//! (Section 13 / 4 of the BRD/FRD.)

mod collectors;
mod core;
mod detection;
mod incident;
mod investigation;
mod notification;
mod platform;
mod reporting;
mod rootcause;
mod storage;

use crate::core::models::{ResourceKind, ServiceState, Snapshot};
use crate::core::ring_buffer::RingBuffer;
use crate::detection::engine::{DetectionEngine, DetectionResult};
use crate::incident::manager::{FeedOutcome, IncidentManager};
use crate::notification::console::ConsoleNotifier;
use crate::notification::email::EmailNotifier;
use crate::notification::{NotificationDispatcher, Notifier};
use crate::storage::incident_store::IncidentStore;
use crate::core::config::Config;
use anyhow::Result;
use chrono::Utc;
use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "server-sentinel",
    about = "Lightweight infrastructure monitoring & automated incident investigation agent"
)]
struct Cli {
    /// Path to the TOML configuration file. Created with defaults if missing.
    #[arg(short, long, default_value = "config/server-sentinel.toml")]
    config: PathBuf,
}

fn init_logging() {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .init();
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = Config::load_or_create(&cli.config)?;
    init_logging();

    tracing::info!(
        server = %config.server.name,
        environment = %config.server.environment,
        "ServerSentinel starting"
    );

    let running = Arc::new(AtomicBool::new(true));
    {
        let running = running.clone();
        ctrlc::set_handler(move || {
            tracing::warn!("shutdown signal received, finishing current cycle then exiting");
            running.store(false, Ordering::SeqCst);
        })?;
    }

    let os_label = platform::current_os_label();
    let mut collectors = platform::build_collectors();

    let mut ring_buffer = RingBuffer::new(config.incident.pre_incident_seconds);
    let mut detection_engine = DetectionEngine::new();
    let mut incident_manager = IncidentManager::new(
        config.server.name.clone(),
        os_label.clone(),
        config.server.environment.clone(),
    );
    let store = IncidentStore::new(&config.storage.base_dir)?;

    let mut notifiers: Vec<Box<dyn Notifier>> = vec![Box::new(ConsoleNotifier)];
    if config.notification.email.enabled {
        notifiers.push(Box::new(EmailNotifier::new(config.notification.email.clone())));
    }
    let dispatcher = NotificationDispatcher::new(notifiers);

    tracing::info!(
        normal_interval = config.monitoring.normal_interval_seconds,
        investigation_interval = config.monitoring.investigation_interval_seconds,
        "monitoring loop starting"
    );

    while running.load(Ordering::SeqCst) {
        let investigating = incident_manager.is_active();
        let process_limit = if investigating {
            (config.monitoring.top_process_count * 4).max(20)
        } else {
            config.monitoring.top_process_count
        };

        let (mut snapshot, services_snapshot) = collect_raw_snapshot(&mut collectors, process_limit);
        let detection: DetectionResult = detection_engine.evaluate(
            &snapshot,
            &config.thresholds,
            config.incident.trigger_duration_seconds,
        );
        snapshot.alert_levels = detection.alert_levels.clone();

        let failed_services: Vec<&str> = services_snapshot
            .iter()
            .filter(|s| s.state == ServiceState::Failed)
            .map(|s| s.name.as_str())
            .collect();
        if !failed_services.is_empty() {
            tracing::warn!(services = ?failed_services, "failed services detected");
        }

        ring_buffer.push(snapshot.clone());

        if incident_manager.is_active() {
            match incident_manager.feed(
                snapshot.clone(),
                config.incident.recovery_duration_seconds,
                config.incident.post_recovery_seconds,
            ) {
                FeedOutcome::StillInvestigating => {}
                FeedOutcome::Finalized(report) => {
                    tracing::info!(
                        incident_id = %report.incident_id,
                        confidence = report.root_cause.confidence_percent,
                        cause = %report.root_cause.probable_cause,
                        "incident investigation complete"
                    );
                    match store.save(&report) {
                        Ok((json_path, html_path)) => {
                            tracing::info!(json = %json_path.display(), html = %html_path.display(), "incident report saved");
                        }
                        Err(e) => tracing::error!(error = %e, "failed to save incident report"),
                    }
                    dispatcher.dispatch(&report);
                    // Make sure the debounce timer for this resource starts
                    // fresh in the next normal-mode tick.
                    detection_engine.acknowledge(report.incident_type);
                }
            }
        } else if let Some(&kind) = detection.newly_triggered.first() {
            let critical_threshold = critical_threshold_for(kind, &config.thresholds);
            let pre_incident = ring_buffer.before(snapshot.timestamp);
            incident_manager.open(kind, critical_threshold, snapshot.clone(), pre_incident);
            detection_engine.acknowledge(kind);
        }

        let interval = if incident_manager.is_active() {
            config.monitoring.investigation_interval_seconds
        } else {
            config.monitoring.normal_interval_seconds
        };
        std::thread::sleep(Duration::from_secs(interval.max(1)));
    }

    tracing::info!("ServerSentinel stopped");
    Ok(())
}

fn critical_threshold_for(kind: ResourceKind, thresholds: &core::config::ThresholdsConfig) -> f32 {
    match kind {
        ResourceKind::Cpu => thresholds.cpu_critical,
        ResourceKind::Memory => thresholds.memory_critical,
        ResourceKind::Disk => thresholds.disk_critical,
        ResourceKind::Network => 100.0,
    }
}

/// Runs every collector for this tick, tolerating individual collector
/// failures per FR-023 ("continue operation if an individual collector
/// fails") by substituting an empty/default reading and logging a
/// warning rather than crashing the agent. Alert levels are left empty;
/// the caller fills them in via the (single, authoritative) call to
/// `DetectionEngine::evaluate`.
fn collect_raw_snapshot(
    collectors: &mut collectors::CollectorSet,
    process_limit: usize,
) -> (Snapshot, Vec<core::models::ServiceSample>) {
    let cpu = collectors.cpu.collect().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "cpu collector failed");
        core::models::CpuMetrics {
            usage_percent: 0.0,
            per_core_percent: Vec::new(),
        }
    });
    let memory = collectors.memory.collect().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "memory collector failed");
        core::models::MemoryMetrics {
            total_bytes: 0,
            used_bytes: 0,
            available_bytes: 0,
            used_percent: 0.0,
        }
    });
    let disk = collectors.disk.collect().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "disk collector failed");
        core::models::DiskMetrics::default()
    });
    let network = collectors.network.collect().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "network collector failed");
        core::models::NetworkMetrics::default()
    });
    let top_processes = collectors.process.collect(process_limit).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "process collector failed");
        Vec::new()
    });
    let services = collectors.service.collect().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "service collector failed");
        Vec::new()
    });

    let snapshot = Snapshot {
        timestamp: Utc::now(),
        cpu,
        memory,
        disk,
        network,
        top_processes,
        services: services.clone(),
        alert_levels: HashMap::new(),
    };

    (snapshot, services)
}
