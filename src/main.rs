//! ServerSentinel agent entrypoint.
//!
//! ```text
//!                       ┌──────────── performance ────────────┐
//! metrics collectors ──►│ detection -> investigation -> report │──┐
//!                       └──────────────────────────────────────┘  │ "what changed
//!                                                                  │  before this?"
//! audit collectors ──► security pipeline ──► event store ◄─────────┘
//!  (auth / exec / FIM /     (sessions, rules,     │
//!   eventlog / packages)     redaction)           ├──► forwarders (NDJSON, syslog)
//!                                                 └──► notifications (console, email, webhook)
//! ```

mod audit;
mod cli;
mod collectors;
mod core;
mod detection;
mod events;
mod forward;
mod incident;
mod investigation;
mod notification;
mod platform;
mod query;
mod reporting;
mod rootcause;
mod security;
mod storage;
mod util;

use crate::core::config::Config;
use crate::core::models::{AlertLevel, ResourceKind, ServiceState, Snapshot};
use crate::core::ring_buffer::RingBuffer;
use crate::detection::engine::{DetectionEngine, DetectionResult};
use crate::events::{Category, Event, EventBus, Outcome, Severity};
use crate::forward::{Forwarder, NdjsonForwarder, SyslogForwarder};
use crate::incident::manager::{FeedOutcome, IncidentManager};
use crate::notification::console::ConsoleNotifier;
use crate::notification::email::EmailNotifier;
use crate::notification::webhook::WebhookNotifier;
use crate::notification::{NotificationDispatcher, Notifier};
use crate::security::pipeline::{Pipeline, PipelineConfig};
use crate::security::redact::Redactor;
use crate::security::rules::RuleEngine;
use crate::storage::event_store::EventStore;
use crate::storage::incident_store::IncidentStore;
use anyhow::Result;
use chrono::{Datelike, Utc};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(
    name = "server-sentinel",
    version,
    about = "Server flight recorder: who got in, what they ran, what they changed — and whether it broke something",
    long_about = None
)]
struct Cli {
    /// Config file. Default: $SENTINEL_CONFIG, ./config/server-sentinel.toml,
    /// /etc/server-sentinel/server-sentinel.toml, or next to the executable.
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the agent in the foreground (the default)
    Run,
    /// Search events: `search user=alice action=file.* nginx.conf`
    Search {
        /// Query terms: field=value (user, ip, action, category, session, path, process, command, pid, sev>=high) and free text
        query: Vec<String>,
        #[arg(long, default_value = "24h")]
        since: String,
        #[arg(long)]
        until: Option<String>,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        /// NDJSON output
        #[arg(long)]
        json: bool,
    },
    /// List access sessions (SSH, RDP, console)
    Sessions {
        #[arg(long, default_value = "7d")]
        since: String,
        /// Only sessions that are still open
        #[arg(long)]
        active: bool,
        #[arg(long)]
        user: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Everything one session did: commands, sudo, file changes, alerts
    Session {
        id: String,
        /// Write a standalone HTML report instead
        #[arg(long)]
        html: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        /// Show file diffs inline
        #[arg(long)]
        diffs: bool,
    },
    /// File changes, with who made them
    Changes {
        /// Path substring or wildcard, e.g. nginx or /etc/ssh/*
        #[arg(long)]
        path: Option<String>,
        #[arg(long, default_value = "7d")]
        since: String,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Show a file change: the diff, or the full previous/new version
    Diff {
        /// Event id (the #number shown by `changes` / `session`)
        id: i64,
        /// Print the complete file as it was before the change
        #[arg(long)]
        before: bool,
        /// Print the complete file as it was after the change
        #[arg(long, conflicts_with = "before")]
        after: bool,
    },
    /// Security alerts
    Alerts {
        #[arg(long, default_value = "7d")]
        since: String,
        #[arg(long, default_value = "low")]
        min: String,
        #[arg(long, default_value_t = 200)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Verify the audit trail's hash chain (exit code 1 if tampered)
    Verify,
    /// Check what this agent can observe on this host, and how to fix gaps
    Doctor,
    /// Manage the Windows service
    #[cfg(windows)]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Entry point used by the Windows Service Control Manager
    #[cfg(windows)]
    #[command(hide = true)]
    ServiceRun,
}

#[cfg(windows)]
#[derive(Subcommand, Debug)]
enum ServiceAction {
    /// Register as an auto-start LocalSystem service and start it
    Install,
    /// Stop and remove the service
    Uninstall,
}

fn resolve_config_path(explicit: Option<PathBuf>) -> PathBuf {
    if let Some(p) = explicit {
        return p;
    }
    if let Some(p) = std::env::var_os("SENTINEL_CONFIG") {
        return PathBuf::from(p);
    }
    let mut candidates = vec![PathBuf::from("config/server-sentinel.toml")];
    if cfg!(unix) {
        candidates.push(PathBuf::from("/etc/server-sentinel/server-sentinel.toml"));
    }
    if let Some(dir) = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)) {
        candidates.push(dir.join("server-sentinel.toml"));
    }
    candidates
        .iter()
        .find(|p| p.exists())
        .cloned()
        .unwrap_or_else(|| PathBuf::from("config/server-sentinel.toml"))
}

fn init_logging(default_level: &str, log_file: Option<PathBuf>) {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));
    let builder = tracing_subscriber::fmt().with_env_filter(env_filter).with_target(false);
    match log_file.and_then(|p| {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Keep one previous log; a service runs for months.
        if std::fs::metadata(&p).map(|m| m.len() > 50 * 1024 * 1024).unwrap_or(false) {
            let _ = std::fs::rename(&p, p.with_extension("log.1"));
        }
        std::fs::OpenOptions::new().create(true).append(true).open(p).ok()
    }) {
        Some(file) => builder.with_ansi(false).with_writer(std::sync::Mutex::new(file)).init(),
        None => builder.with_writer(std::io::stderr).init(),
    }
}

fn main() {
    let cli = Cli::parse();
    let config_path = resolve_config_path(cli.config.clone());
    let code = match dispatch(cli.command, &config_path) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            2
        }
    };
    std::process::exit(code);
}

/// Loads config for read-only commands without creating anything.
fn load_existing(path: &Path) -> Result<Config> {
    if path.exists() {
        Config::load_or_create(path)
    } else {
        eprintln!("note: {} not found; using defaults", path.display());
        let mut cfg = Config::default();
        cfg.storage.base_dir = default_base_dir();
        Ok(cfg)
    }
}

fn default_base_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\ProgramData\ServerSentinel")
    } else if Path::new("/var/lib/server-sentinel").exists() {
        PathBuf::from("/var/lib/server-sentinel")
    } else {
        PathBuf::from("./data")
    }
}

fn dispatch(command: Option<Command>, config_path: &Path) -> Result<i32> {
    match command.unwrap_or(Command::Run) {
        Command::Run => {
            let config = Config::load_or_create(config_path)?;
            init_logging("info", None);
            let running = Arc::new(AtomicBool::new(true));
            {
                let running = running.clone();
                ctrlc::set_handler(move || {
                    tracing::warn!("shutdown signal received, finishing current cycle then exiting");
                    running.store(false, Ordering::SeqCst);
                })?;
            }
            run_agent(config, config_path, running)?;
            Ok(0)
        }
        #[cfg(windows)]
        Command::ServiceRun => {
            let config = Config::load_or_create(config_path)?;
            init_logging("info", Some(config.storage.base_dir.join("logs").join("server-sentinel.log")));
            let path = config_path.to_path_buf();
            platform::win_service::run_as_service(move |running| run_agent(config.clone(), &path, running))?;
            Ok(0)
        }
        #[cfg(windows)]
        Command::Service { action } => {
            match action {
                ServiceAction::Install => {
                    // Make sure a config exists for the service to use.
                    Config::load_or_create(config_path)?;
                    platform::win_service::install(config_path)?
                }
                ServiceAction::Uninstall => platform::win_service::uninstall()?,
            }
            Ok(0)
        }
        other => {
            init_logging("warn", None);
            let cfg = load_existing(config_path)?;
            match other {
                Command::Search { query, since, until, limit, json } => cli::search(&cfg, &query, &since, until.as_deref(), limit, json)?,
                Command::Sessions { since, active, user, limit, json } => cli::sessions(&cfg, &since, active, user.as_deref(), limit, json)?,
                Command::Session { id, html, json, diffs } => cli::session(&cfg, &id, html.as_deref(), json, diffs)?,
                Command::Changes { path, since, limit, json } => cli::changes(&cfg, path.as_deref(), &since, limit, json)?,
                Command::Diff { id, before, after } => cli::diff(&cfg, id, before, after)?,
                Command::Alerts { since, min, limit, json } => cli::alerts(&cfg, &since, &min, limit, json)?,
                Command::Verify => return Ok(if cli::verify(&cfg)? { 0 } else { 1 }),
                Command::Doctor => cli::doctor(&cfg, config_path)?,
                _ => unreachable!("handled above"),
            }
            Ok(0)
        }
    }
}

fn build_notifiers(config: &Config) -> Vec<Box<dyn Notifier>> {
    let mut notifiers: Vec<Box<dyn Notifier>> = vec![Box::new(ConsoleNotifier)];
    if config.notification.email.enabled {
        notifiers.push(Box::new(EmailNotifier::new(config.notification.email.clone())));
    }
    if config.notification.webhook.enabled {
        notifiers.push(Box::new(WebhookNotifier::new(config.notification.webhook.clone())));
    }
    notifiers
}

fn build_forwarders(config: &Config) -> Vec<Box<dyn Forwarder>> {
    let mut out: Vec<Box<dyn Forwarder>> = Vec::new();
    if config.forward.ndjson.enabled {
        let default = config.storage.base_dir.join("export").join("events.ndjson");
        match NdjsonForwarder::new(&config.forward.ndjson, default) {
            Ok(f) => out.push(Box::new(f)),
            Err(e) => tracing::error!(error = %e, "NDJSON forwarding disabled"),
        }
    }
    if config.forward.syslog.enabled {
        match SyslogForwarder::new(&config.forward.syslog, config.server.name.clone()) {
            Ok(f) => out.push(Box::new(f)),
            Err(e) => tracing::error!(error = %e, "syslog forwarding disabled"),
        }
    }
    out
}

struct Security {
    bus: EventBus,
    reader: Option<EventStore>,
    collectors: Vec<std::thread::JoinHandle<()>>,
    pipeline: std::thread::JoinHandle<()>,
}

fn start_security(config: &Config, notify: notification::NotifyHandle, running: Arc<AtomicBool>) -> Result<Security> {
    let db = config.event_db_path();
    let store = EventStore::open(&db)?;
    let sec = &config.security;
    let pipeline = Pipeline::new(
        store,
        RuleEngine::new(sec.rules.clone()),
        Redactor::new(sec.redact_secrets),
        build_forwarders(config),
        Some(notify),
        PipelineConfig {
            host: config.server.name.clone(),
            hold: Duration::from_secs(sec.hold_seconds),
            capture_command_lines: sec.capture_command_lines,
            min_notify_severity: Severity::parse(&config.notification.min_alert_severity).unwrap_or(Severity::High),
            retention_days: sec.retention_days.max(1),
            ignore_process_names: sec.process.ignore_names.clone(),
            process_sessions_only: sec.process.sessions_only,
        },
    )?;
    let (tx, rx) = std::sync::mpsc::sync_channel(50_000);
    let bus = EventBus::new(tx);
    let state = EventStore::open(&db)?;
    let collectors = audit::start(config, &state, bus.clone(), running.clone());
    let pipeline = std::thread::Builder::new()
        .name("pipeline".into())
        .spawn(move || pipeline.run(rx, running))?;
    tracing::info!(database = %db.display(), collectors = collectors.len(), "security auditing started");
    Ok(Security {
        bus,
        reader: EventStore::open_readonly(&db).ok(),
        collectors,
        pipeline,
    })
}

fn run_agent(config: Config, config_path: &Path, running: Arc<AtomicBool>) -> Result<()> {
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        server = %config.server.name,
        environment = %config.server.environment,
        config = %config_path.display(),
        "ServerSentinel starting"
    );
    for w in config.warnings(config_path) {
        tracing::warn!("{w}");
    }

    let dispatcher = NotificationDispatcher::spawn(build_notifiers(&config));
    let security = if config.security.enabled {
        match start_security(&config, dispatcher.handle(), running.clone()) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!(error = %e, "security auditing failed to start; continuing with performance monitoring only");
                None
            }
        }
    } else {
        tracing::info!("security auditing disabled (security.enabled = false)");
        None
    };

    let result = run_metrics_loop(&config, &dispatcher, security.as_ref(), &running);

    running.store(false, Ordering::SeqCst);
    if let Some(sec) = security {
        let Security { bus, reader, collectors, pipeline } = sec;
        drop(reader);
        let deadline = Instant::now() + Duration::from_secs(10);
        for h in collectors {
            while !h.is_finished() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
            }
            if h.is_finished() {
                let _ = h.join();
            }
        }
        drop(bus);
        let _ = pipeline.join();
    }
    dispatcher.shutdown();
    tracing::info!("ServerSentinel stopped");
    result
}

fn service_event(name: &str, from: ServiceState, to: ServiceState) -> Option<Event> {
    let (action, verb, severity) = match to {
        ServiceState::Running => ("service.started", "started", Severity::Info),
        ServiceState::Stopped => ("service.stopped", "stopped", Severity::Info),
        ServiceState::Failed => ("service.failed", "FAILED", Severity::Low),
        ServiceState::Unknown => return None,
    };
    if from == ServiceState::Unknown {
        return None;
    }
    Some(
        Event::new(Category::Service, action, format!("Service {name} {verb}"))
            .outcome(if to == ServiceState::Failed { Outcome::Failure } else { Outcome::Success })
            .severity(severity)
            .target(name)
            .detail("previous_state", format!("{from:?}").to_ascii_lowercase()),
    )
}

fn run_metrics_loop(
    config: &Config,
    dispatcher: &NotificationDispatcher,
    security: Option<&Security>,
    running: &AtomicBool,
) -> Result<()> {
    let os_label = platform::current_os_label();
    let mut collectors = platform::build_collectors();

    let mut ring_buffer = RingBuffer::new(config.incident.pre_incident_seconds);
    let mut detection_engine = DetectionEngine::new();
    let store = IncidentStore::new(&config.storage.base_dir)?;
    let mut incident_manager = IncidentManager::new(
        config.server.name.clone(),
        os_label.clone(),
        config.server.environment.clone(),
        store.last_sequence(Utc::now().year()),
    );
    let mut previous_services: Option<HashMap<String, ServiceState>> = None;

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
        if !failed_services.is_empty() && previous_services.is_none() {
            tracing::warn!(services = ?failed_services, "failed services detected");
        }
        // Service state transitions go to the audit trail: "nginx was
        // restarted 2 minutes before the incident" is key context.
        let current: HashMap<String, ServiceState> =
            services_snapshot.iter().map(|s| (s.name.clone(), s.state)).collect();
        if let (Some(prev), Some(sec)) = (&previous_services, security) {
            for (name, state) in &current {
                if let Some(old) = prev.get(name) {
                    if old != state {
                        if let Some(ev) = service_event(name, *old, *state) {
                            sec.bus.emit(ev);
                        }
                    }
                }
            }
        }
        if !services_snapshot.is_empty() {
            previous_services = Some(current);
        }

        ring_buffer.push(snapshot.clone());

        if incident_manager.is_active() {
            match incident_manager.feed(
                snapshot.clone(),
                config.incident.recovery_duration_seconds,
                config.incident.post_recovery_seconds,
            ) {
                FeedOutcome::StillInvestigating => {}
                FeedOutcome::Finalized(mut report) => {
                    if let Some(reader) = security.and_then(|s| s.reader.as_ref()) {
                        incident::related::attach(&mut report, reader);
                    }
                    tracing::info!(
                        incident_id = %report.incident_id,
                        confidence = report.root_cause.confidence_percent,
                        cause = %report.root_cause.probable_cause,
                        related_changes = report.related_activity.len(),
                        "incident investigation complete"
                    );
                    match store.save(&report) {
                        Ok((json_path, html_path)) => {
                            tracing::info!(json = %json_path.display(), html = %html_path.display(), "incident report saved");
                        }
                        Err(e) => tracing::error!(error = %e, "failed to save incident report"),
                    }
                    if let Some(sec) = security {
                        let ev = Event::new(
                            Category::Incident,
                            "incident.report",
                            format!(
                                "{} incident {}: probable cause {} ({:.0}% confidence)",
                                report.incident_type,
                                report.incident_id,
                                report.root_cause.probable_cause,
                                report.root_cause.confidence_percent
                            ),
                        )
                        .at(report.start_time)
                        .severity(if report.severity == AlertLevel::Critical { Severity::High } else { Severity::Medium })
                        .target(report.incident_id.clone())
                        .detail("duration_seconds", report.duration_seconds.unwrap_or(0))
                        .detail("related_changes", report.related_activity.len());
                        sec.bus.emit(ev);
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
        // Sleep in slices so shutdown is prompt.
        let wake = Instant::now() + Duration::from_secs(interval.max(1));
        while running.load(Ordering::SeqCst) && Instant::now() < wake {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
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
