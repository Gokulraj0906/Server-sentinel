//! Security / audit telemetry collectors.
//!
//! Everything here produces `events::Event`s onto the `EventBus`; none of
//! it knows about storage, sessions or rules. Parsers are pure functions
//! compiled on every platform so they're tested everywhere; only the
//! collectors that touch OS facilities are started per-platform.
//!
//! | | Linux | Windows |
//! |---|---|---|
//! | Access (SSH/RDP/console) | auth.log / secure / journald | Security 4624/4625/4634, TerminalServices 21-25, OpenSSH log |
//! | Commands | kernel proc connector (every exec) or /proc polling | Security 4688 or process polling + TS session id |
//! | Privilege | sudo / su | (UAC elevation shows as linked logon) |
//! | Accounts | useradd/usermod/gpasswd/passwd | Security 4720-4740 |
//! | Files | inotify + rescans, content history | ReadDirectoryChangesW + rescans, content history |
//! | Packages | dpkg.log / dnf.rpm.log | MsiInstaller 1033/1034 |
//! | Persistence / tampering | log truncation, sensitive files | 7045, 4698, 1102, 104 |

pub mod authlog;
pub mod discovery;
pub mod fim;
pub mod linux_logs;
pub mod linux_proc;
pub mod packages;
pub mod tail;
pub mod windows;
pub mod winevent;

use crate::core::config::Config;
use crate::events::EventBus;
use crate::storage::event_store::EventStore;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::thread::JoinHandle;

pub fn start(cfg: &Config, store: &EventStore, bus: EventBus, running: Arc<AtomicBool>) -> Vec<JoinHandle<()>> {
    let sec = &cfg.security;
    let mut handles = Vec::new();

    // People already logged in before the agent started.
    if sec.auth.enabled {
        let found = discovery::discover();
        let n = found.iter().filter(|e| e.action == "session.start").count();
        for ev in found {
            bus.emit(ev);
        }
        tracing::info!(sessions = n, "discovered sessions already open at startup");
    }

    let mut started = |name: &str, r: anyhow::Result<JoinHandle<()>>| match r {
        Ok(h) => handles.push(h),
        Err(e) => tracing::warn!(collector = name, error = %e, "collector failed to start; continuing without it"),
    };

    #[cfg(target_os = "linux")]
    {
        match linux_logs::spawn(&sec.auth, store, bus.clone(), running.clone()) {
            Ok(hs) => {
                for h in hs {
                    started("logs", Ok(h));
                }
            }
            Err(e) => started("logs", Err(e)),
        }
        if sec.process.enabled {
            started("exec", linux_proc::spawn(&sec.process, bus.clone(), running.clone()));
        }
    }

    #[cfg(windows)]
    {
        let use_4688 = sec.process.enabled
            && match sec.process.mode.as_str() {
                "eventlog" => true,
                "poll" => false,
                _ => windows::process_creation_auditing_enabled(),
            };
        if sec.auth.enabled || use_4688 {
            started("eventlog", windows::spawn_eventlog(&sec.auth, use_4688, store, bus.clone(), running.clone()));
        }
        if use_4688 {
            tracing::info!("process auditing: Security event 4688 (process creation auditing is enabled)");
        } else if sec.process.enabled {
            started("procpoll", windows::spawn_process_poll(&sec.process, bus.clone(), running.clone()));
        }
    }

    #[cfg(not(any(target_os = "linux", windows)))]
    let _ = store;

    if sec.fim.enabled {
        started(
            "fim",
            fim::spawn(sec.fim.clone(), cfg.event_db_path(), sec.redact_secrets, bus, running),
        );
    }
    handles
}
