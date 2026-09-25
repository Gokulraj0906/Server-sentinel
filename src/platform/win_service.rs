//! Windows service integration.
//!
//! A security agent on Windows has to run as a service (LocalSystem) to
//! read the Security log and see every user's processes, and has to speak
//! the Service Control Manager protocol — a plain console exe registered
//! as a service is killed by the SCM after 30 seconds.
//!
//! `server-sentinel service install` registers the agent (auto start,
//! restart on failure); the SCM then launches
//! `server-sentinel.exe --config <path> service-run`, which lands here.

use anyhow::{Context, Result};
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl,
    ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState,
    ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE_NAME: &str = "ServerSentinel";

type AgentFn = Box<dyn Fn(Arc<AtomicBool>) -> Result<()> + Send + Sync>;
static AGENT: OnceLock<AgentFn> = OnceLock::new();

define_windows_service!(ffi_service_main, service_main);

/// Blocks until the SCM stops the service.
pub fn run_as_service(agent: impl Fn(Arc<AtomicBool>) -> Result<()> + Send + Sync + 'static) -> Result<()> {
    let _ = AGENT.set(Box::new(agent));
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("connecting to the Service Control Manager (`service-run` is only meant to be launched by Windows; use `run` interactively)")?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    let running = Arc::new(AtomicBool::new(true));
    let flag = running.clone();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            flag.store(false, Ordering::SeqCst);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let Ok(status) = service_control_handler::register(SERVICE_NAME, handler) else {
        return;
    };
    let set = |state: ServiceState, accept: ServiceControlAccept, code: u32| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        });
    };
    set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0);
    let result = AGENT.get().map(|agent| agent(running)).unwrap_or(Ok(()));
    let code = match result {
        Ok(()) => 0,
        Err(e) => {
            tracing::error!(error = %e, "agent exited with an error");
            1
        }
    };
    set(ServiceState::Stopped, ServiceControlAccept::empty(), code);
}

pub fn install(config: &Path) -> Result<()> {
    let config = std::fs::canonicalize(config)
        .with_context(|| format!("config file {} must exist before installing the service", config.display()))?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
        .context("opening the Service Control Manager (run this from an elevated / Administrator prompt)")?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: "ServerSentinel Agent".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments: vec!["--config".into(), config.clone().into_os_string(), "service-run".into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager
        .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
        .context("creating the service (already installed? try `service uninstall` first)")?;
    service.set_description(
        "Records who accessed this server (RDP/SSH/console), what they ran and changed, and investigates performance incidents.",
    )?;
    let restart = ServiceAction {
        action_type: ServiceActionType::Restart,
        delay: Duration::from_secs(10),
    };
    service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![restart.clone(), restart.clone(), restart]),
    })?;
    service.set_failure_actions_on_non_crash_failures(true)?;
    service.start(&[] as &[&OsStr]).context("starting the service")?;
    println!("Installed and started service '{SERVICE_NAME}' (config: {}).", config.display());
    Ok(())
}

pub fn uninstall() -> Result<()> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("opening the Service Control Manager (run this from an elevated / Administrator prompt)")?;
    let service = manager
        .open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)
        .context("the service is not installed")?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
        for _ in 0..30 {
            if service.query_status()?.current_state == ServiceState::Stopped {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    service.delete()?;
    println!("Service '{SERVICE_NAME}' stopped and removed. Data in the storage directory was left in place.");
    Ok(())
}
