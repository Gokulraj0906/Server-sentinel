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
