//! HTML incident report renderer.
//!
//! Deliberately dependency-free (no template engine) — this is a small,
//! fixed layout so hand-written `format!` is clearer than pulling in a
//! templating crate for a single view.

use crate::core::models::{AlertLevel, EvidenceQuality, IncidentReport};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn severity_color(level: AlertLevel) -> &'static str {
    match level {
        AlertLevel::Critical => "#dc2626",
        AlertLevel::Warning => "#d97706",
        AlertLevel::Normal => "#16a34a",
    }
}

fn quality_color(q: EvidenceQuality) -> &'static str {
    match q {
        EvidenceQuality::High => "#16a34a",
        EvidenceQuality::Medium => "#d97706",
        EvidenceQuality::Low => "#dc2626",
    }
}

pub fn render_html(report: &IncidentReport) -> String {
    let severity_c = severity_color(report.severity);
    let quality_c = quality_color(report.root_cause.evidence_quality);

    let timeline_rows = report
        .timeline
        .iter()
        .map(|e| {
            format!(
                "<tr><td class=\"ts\">{}</td><td>{}</td></tr>",
                e.timestamp.format("%H:%M:%S"),
                esc(&e.description)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let evidence_items = report
        .evidence
        .iter()
        .enumerate()
        .map(|(i, ev)| format!("<li><span class=\"ev-num\">{}</span>{}</li>", i + 1, esc(&ev.description)))
        .collect::<Vec<_>>()
        .join("\n");

    let candidate_rows = report
        .root_cause
        .candidates_considered
        .iter()
        .map(|c| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{:.0}%</td></tr>",
                esc(&c.label),
                c.category,
                c.score
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let investigation_bullets = report
        .recommendations
        .recommended_investigation
        .iter()
        .map(|r| format!("<li>{}</li>", esc(r)))
        .collect::<Vec<_>>()
        .join("\n");

    let action_bullets = report
        .recommendations
        .recommended_corrective_action
        .iter()
        .map(|r| format!("<li>{}</li>", esc(r)))
        .collect::<Vec<_>>()
        .join("\n");

    let affected_apps = if report.impact.affected_applications.is_empty() {
        "None identified".to_string()
    } else {
        report.impact.affected_applications.join(", ")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ServerSentinel Incident Report — {incident_id}</title>
<style>
  :root {{
    --bg: #0b0d12; --panel: #12151c; --border: #232733; --text: #e6e8ee;
    --muted: #9aa2b1; --accent: {severity_c};
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 40px 24px; background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    line-height: 1.5;
  }}
  .wrap {{ max-width: 860px; margin: 0 auto; }}
  .header {{
    border: 1px solid var(--border); border-left: 6px solid var(--accent);
    background: var(--panel); border-radius: 10px; padding: 24px 28px; margin-bottom: 20px;
  }}
  .kicker {{ color: var(--muted); font-size: 13px; letter-spacing: .08em; text-transform: uppercase; }}
  h1 {{ margin: 4px 0 12px 0; font-size: 26px; }}
  .badges {{ display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }}
  .badge {{
    display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px;
    border-radius: 999px; font-size: 13px; font-weight: 600; background: #1a1e28; border: 1px solid var(--border);
  }}
  .dot {{ width: 8px; height: 8px; border-radius: 50%; background: currentColor; }}
  .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 20px 0; }}
  .stat {{ background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }}
  .stat .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }}
  .stat .value {{ font-size: 20px; font-weight: 700; margin-top: 4px; }}
  section {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 22px 26px; margin-bottom: 18px;
  }}
  section h2 {{
    margin: 0 0 14px 0; font-size: 15px; text-transform: uppercase; letter-spacing: .06em;
    color: var(--muted); border-bottom: 1px solid var(--border); padding-bottom: 10px;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  td {{ padding: 6px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  td.ts {{ color: var(--muted); font-variant-numeric: tabular-nums; white-space: nowrap; width: 90px; }}
  ol, ul {{ margin: 0; padding-left: 0; list-style: none; }}
  li {{ padding: 6px 0; border-bottom: 1px solid var(--border); }}
  li:last-child {{ border-bottom: none; }}
  .ev-num {{
    display: inline-block; width: 20px; height: 20px; line-height: 20px; text-align: center;
    background: #1a1e28; border-radius: 50%; font-size: 11px; margin-right: 10px; color: var(--muted);
  }}
  .rec-list li {{ padding-left: 20px; position: relative; border-bottom: none; padding-top: 4px; padding-bottom: 4px; }}
  .rec-list li::before {{ content: "→"; position: absolute; left: 0; color: var(--accent); }}
  .confidence-bar {{ height: 8px; background: #1a1e28; border-radius: 4px; overflow: hidden; margin-top: 8px; }}
  .confidence-fill {{ height: 100%; background: {quality_c}; width: {confidence}%; }}
  .footer {{ color: var(--muted); font-size: 12px; text-align: center; margin-top: 28px; }}
</style>
</head>
<body>
<div class="wrap">
  <div class="header">
    <div class="kicker">ServerSentinel · Automated Incident Investigation</div>
    <h1>{incident_type} Incident — {server_name}</h1>
    <div class="badges">
      <span class="badge" style="color:{severity_c}"><span class="dot"></span>{severity}</span>
      <span class="badge">ID: {incident_id}</span>
      <span class="badge">{os}</span>
      <span class="badge">{environment}</span>
    </div>
  </div>

  <div class="grid">
    <div class="stat"><div class="label">Start</div><div class="value">{start}</div></div>
    <div class="stat"><div class="label">End</div><div class="value">{end}</div></div>
    <div class="stat"><div class="label">Duration</div><div class="value">{duration}</div></div>
    <div class="stat"><div class="label">Confidence</div><div class="value">{confidence:.0}%</div></div>
  </div>

  <section>
    <h2>Probable Root Cause</h2>
    <div style="font-size:22px; font-weight:700;">{probable_cause}</div>
    <div style="color: var(--muted); margin-top: 4px;">
      Category: {category} &nbsp;·&nbsp; Evidence Quality:
      <span style="color:{quality_c}; font-weight:600;">{evidence_quality}</span>
    </div>
    <div class="confidence-bar"><div class="confidence-fill"></div></div>
    {reason_if_unknown}
  </section>

  {candidates_section}

  <section>
    <h2>Evidence</h2>
    <ol>
      {evidence_items}
    </ol>
  </section>

  <section>
    <h2>Timeline</h2>
    <table>{timeline_rows}</table>
  </section>

  <section>
    <h2>Impact</h2>
    <table>
      <tr><td style="width:220px;color:var(--muted)">Affected resource</td><td>{affected_resources}</td></tr>
      <tr><td style="color:var(--muted)">Affected applications</td><td>{affected_apps}</td></tr>
      <tr><td style="color:var(--muted)">Potential downtime</td><td>{downtime}</td></tr>
      <tr><td style="color:var(--muted)">Performance impact</td><td>{perf_impact}</td></tr>
    </table>
  </section>

  <section>
    <h2>Recommendations</h2>
    <div style="color: var(--muted); font-size: 13px; margin-bottom: 6px;">Investigate next</div>
    <ul class="rec-list">{investigation_bullets}</ul>
    <div style="color: var(--muted); font-size: 13px; margin: 14px 0 6px 0;">Corrective action</div>
    <ul class="rec-list">{action_bullets}</ul>
  </section>

  <div class="footer">Generated by ServerSentinel at {generated_at} UTC · Report format v1</div>
</div>
</body>
</html>"#,
        incident_id = esc(&report.incident_id),
        severity_c = severity_c,
        quality_c = quality_c,
        confidence = report.root_cause.confidence_percent,
        incident_type = report.incident_type,
        server_name = esc(&report.server_name),
        severity = report.severity,
        os = esc(&report.operating_system),
        environment = esc(&report.environment),
        start = report.start_time.format("%Y-%m-%d %H:%M:%S UTC"),
        end = report
            .end_time
            .map(|e| e.format("%H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "—".to_string()),
        duration = report
            .duration_seconds
            .map(|d| format!("{d}s"))
            .unwrap_or_else(|| "—".to_string()),
        probable_cause = esc(&report.root_cause.probable_cause),
        category = report.root_cause.category,
        evidence_quality = report.root_cause.evidence_quality,
        reason_if_unknown = report
            .root_cause
            .reason_if_unknown
            .as_ref()
            .map(|r| format!("<div style=\"margin-top:10px; color:var(--muted); font-size:13px;\">Reason: {}</div>", esc(r)))
            .unwrap_or_default(),
        candidates_section = if candidate_rows.is_empty() {
            String::new()
        } else {
            format!(
                "<section><h2>Candidates Considered</h2><table><tr><td style=\"color:var(--muted)\">Candidate</td><td style=\"color:var(--muted)\">Category</td><td style=\"color:var(--muted)\">Score</td></tr>{candidate_rows}</table></section>"
            )
        },
        evidence_items = if evidence_items.is_empty() { "<li>No evidence recorded.</li>".to_string() } else { evidence_items },
        timeline_rows = timeline_rows,
        affected_resources = esc(&report.impact.affected_resources.join(", ")),
        affected_apps = esc(&affected_apps),
        downtime = esc(&report.impact.potential_downtime),
        perf_impact = esc(&report.impact.performance_impact),
        investigation_bullets = investigation_bullets,
        action_bullets = action_bullets,
        generated_at = report.generated_at.format("%Y-%m-%d %H:%M:%S"),
    )
}
