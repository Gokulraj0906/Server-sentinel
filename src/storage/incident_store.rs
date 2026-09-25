//! Incident storage (FR-019).
//!
//! Initial architecture, per the FRD:
//! ```text
//! ServerSentinel/
//!   ├── config/
//!   ├── logs/
//!   ├── incidents/*.json
//!   └── reports/*.html
//! ```
//! A central database is future scope (Phase 10 / FR-019).

use crate::core::models::IncidentReport;
use crate::reporting::{html::render_html, report::to_json_pretty};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

pub struct IncidentStore {
    incidents_dir: PathBuf,
    reports_dir: PathBuf,
}

impl IncidentStore {
    pub fn new(base_dir: &Path) -> Result<Self> {
        let incidents_dir = base_dir.join("incidents");
        let reports_dir = base_dir.join("reports");
        std::fs::create_dir_all(&incidents_dir)
            .with_context(|| format!("creating {}", incidents_dir.display()))?;
        std::fs::create_dir_all(&reports_dir)
            .with_context(|| format!("creating {}", reports_dir.display()))?;
        Ok(Self {
            incidents_dir,
            reports_dir,
        })
    }

    /// Highest `INC-<year>-NNNNNN` sequence number already saved.
    pub fn last_sequence(&self, year: i32) -> u32 {
        let prefix = format!("INC-{year}-");
        std::fs::read_dir(&self.incidents_dir)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        name.strip_prefix(&prefix)?.strip_suffix(".json")?.parse::<u32>().ok()
                    })
                    .max()
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    }

    /// Persists both the JSON and HTML artifacts for an incident and
    /// returns their paths.
    pub fn save(&self, report: &IncidentReport) -> Result<(PathBuf, PathBuf)> {
        let json_path = self.incidents_dir.join(format!("{}.json", report.incident_id));
        let html_path = self.reports_dir.join(format!("{}.html", report.incident_id));

        std::fs::write(&json_path, to_json_pretty(report)?)
            .with_context(|| format!("writing {}", json_path.display()))?;
        std::fs::write(&html_path, render_html(report))
            .with_context(|| format!("writing {}", html_path.display()))?;

        Ok((json_path, html_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_resumes_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let store = IncidentStore::new(dir.path()).unwrap();
        assert_eq!(store.last_sequence(2026), 0);
        for name in ["INC-2026-000001.json", "INC-2026-000007.json", "INC-2025-000099.json", "notes.txt"] {
            std::fs::write(dir.path().join("incidents").join(name), "{}").unwrap();
        }
        assert_eq!(store.last_sequence(2026), 7);
    }
}
