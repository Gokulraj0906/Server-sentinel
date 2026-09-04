//! Platform dispatch (FR-020).
//!
//! This is the *only* place in the codebase that is allowed to know which
//! operating system the agent is running on. Everything above this module
//! talks exclusively to the `collectors` traits.
//!
//! `common` holds the OS-agnostic collectors (CPU/memory/disk/network/
//! process — all backed by `sysinfo`, which already abstracts the OS
//! internally). `linux` and `windows` each add just the one genuinely
//! OS-specific piece: reading service state.

pub mod common;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use linux::build_collectors;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::build_collectors;

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
pub fn build_collectors() -> crate::collectors::CollectorSet {
    compile_error!(
        "ServerSentinel ships Linux and Windows collectors only. Add a platform module for \
         this OS implementing the collectors:: traits (CpuCollector, MemoryCollector, \
         DiskCollector, ProcessCollector, NetworkCollector, ServiceCollector; the first five \
         can likely reuse platform::common as-is since they're backed by `sysinfo`)."
    );
}

pub fn current_os_label() -> String {
    format!(
        "{} {}",
        sysinfo::System::name().unwrap_or_else(|| "Unknown".to_string()),
        sysinfo::System::os_version().unwrap_or_default()
    )
}
