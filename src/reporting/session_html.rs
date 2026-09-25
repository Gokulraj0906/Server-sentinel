//! Standalone HTML report for one access session: who, from where, and
//! everything they did — commands, privilege use, file changes with
//! diffs, alerts. Meant to be attached to an audit request or incident
//! ticket as-is.

use crate::events::{Category, Event, Severity};
use crate::reporting::html::esc;
use crate::security::sessions::Session;

fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "#dc2626",
        Severity::High => "#ea580c",
        Severity::Medium => "#d97706",
        Severity::Low => "#2563eb",
        Severity::Info => "#64748b",
    }
}

fn icon(ev: &Event) -> &'static str {
    match ev.category {
        Category::Session => "●",
        Category::Process => "$",
        Category::Privilege => "#",
        Category::File => "✎",
        Category::Alert => "!",
        Category::Account => "👤",
        Category::Package => "📦",
        _ => "·",
    }
}

pub fn duration_str(s: &Session) -> String {
    let end = s.end.unwrap_or_else(chrono::Utc::now);
    let secs = (end - s.start).num_seconds().max(0);
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m {}s", s / 60, s % 60),
        s => format!("{}h {}m", s / 3600, (s % 3600) / 60),
    }
}

pub fn render_session_html(s: &Session, events: &[Event], host: &str) -> String {
    let rows: String = events
        .iter()
        .map(|ev| {
            let mut body = esc(&ev.message);
            if let Some(p) = &ev.process {
                if let Some(cwd) = &p.cwd {
                    body.push_str(&format!(" <span class=\"muted\">in {}</span>", esc(cwd)));
                }
                if let Some(r) = &p.run_as {
                    if ev.category == Category::Privilege || ev.details.get("elevated").is_some() {
                        body.push_str(&format!(" <span class=\"muted\">as {}</span>", esc(r)));
                    }
                }
            }
            if let Some(a) = ev.details.get("attribution") {
                if let (Some(c), Some(r)) = (a.get("confidence").and_then(|v| v.as_str()), a.get("reason").and_then(|v| v.as_str())) {
                    body.push_str(&format!("<div class=\"muted small\">attribution: {} — {}</div>", esc(c), esc(r)));
                }
            }
            if let Some(d) = ev.detail_str("diff") {
                let lines: String = d
                    .lines()
                    .map(|l| {
                        let class = if l.starts_with("+++") || l.starts_with("---") {
                            "h"
                        } else if l.starts_with('+') {
                            "add"
                        } else if l.starts_with('-') {
                            "del"
                        } else if l.starts_with("@@") {
                            "h"
                        } else {
                            ""
                        };
                        format!("<span class=\"{class}\">{}</span>\n", esc(l))
                    })
                    .collect();
                body.push_str(&format!("<pre class=\"diff\">{lines}</pre>"));
            }
            format!(
                "<tr class=\"{}\"><td class=\"ts\">{}</td><td class=\"ic\" style=\"color:{}\">{}</td><td class=\"act\">{}</td><td>{}</td><td class=\"ts\">#{}</td></tr>",
                if ev.category == Category::Alert { "alert" } else { "" },
                ev.ts.with_timezone(&chrono::Local).format("%H:%M:%S"),
                sev_color(ev.severity),
                icon(ev),
                esc(&ev.action),
                body,
                ev.id.unwrap_or(0)
            )
        })
        .collect();

    let from = match (&s.src_ip, s.src_port) {
        (Some(ip), Some(p)) if p > 0 => format!("{ip}:{p}"),
        (Some(ip), _) => ip.clone(),
        _ => "local".to_string(),
    };
    let auth = [s.auth_method.clone(), s.key_fingerprint.clone()]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" · ");

    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Session {id} — {user}@{host}</title>
<style>
:root {{ --bg:#0b0d12; --panel:#12151c; --border:#232733; --text:#e6e8ee; --muted:#9aa2b1; }}
@media (prefers-color-scheme: light) {{ :root {{ --bg:#f7f7f9; --panel:#fff; --border:#e3e5ea; --text:#15171c; --muted:#5d6472; }} }}
body {{ margin:0; padding:32px 20px; background:var(--bg); color:var(--text); font:14px/1.5 -apple-system,"Segoe UI",Roboto,sans-serif; }}
.wrap {{ max-width:1000px; margin:0 auto; }}
.head {{ background:var(--panel); border:1px solid var(--border); border-left:6px solid {accent}; border-radius:10px; padding:20px 24px; }}
.kicker {{ color:var(--muted); font-size:12px; letter-spacing:.08em; text-transform:uppercase; }}
h1 {{ margin:4px 0 10px; font-size:22px; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin:16px 0; }}
.stat {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:10px 14px; }}
.stat .l {{ color:var(--muted); font-size:11px; text-transform:uppercase; }} .stat .v {{ font-size:18px; font-weight:700; }}
table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:10px; overflow:hidden; }}
td {{ padding:6px 10px; border-bottom:1px solid var(--border); vertical-align:top; }}
td.ts {{ color:var(--muted); white-space:nowrap; font-variant-numeric:tabular-nums; }}
td.ic {{ font-weight:700; width:18px; text-align:center; }} td.act {{ color:var(--muted); white-space:nowrap; font-size:12px; }}
tr.alert td {{ background:rgba(220,38,38,.08); }}
.muted {{ color:var(--muted); }} .small {{ font-size:12px; }}
pre.diff {{ margin:6px 0 0; padding:8px 10px; background:var(--bg); border:1px solid var(--border); border-radius:6px; overflow-x:auto; font:12px/1.4 ui-monospace,Consolas,monospace; }}
.add {{ color:#16a34a; }} .del {{ color:#dc2626; }} .h {{ color:var(--muted); }}
.foot {{ color:var(--muted); font-size:12px; text-align:center; margin-top:20px; }}
</style></head><body><div class="wrap">
<div class="head"><div class="kicker">ServerSentinel · Session Report · {host}</div>
<h1>{user} via {protocol} from {from}</h1>
<div class="muted">{start} → {end} ({duration}) · {status}{reason}{auth}</div></div>
<div class="grid">
<div class="stat"><div class="l">Commands</div><div class="v">{commands}</div></div>
<div class="stat"><div class="l">Privileged</div><div class="v">{privileged}</div></div>
<div class="stat"><div class="l">File changes</div><div class="v">{files}</div></div>
<div class="stat"><div class="l">Alerts</div><div class="v">{alerts}</div></div>
<div class="stat"><div class="l">Risk</div><div class="v" style="color:{accent}">{risk}/100</div></div>
</div>
<table>{rows}</table>
<div class="foot">Session {id} · generated {generated} · events are hash-chained; verify with <code>server-sentinel verify</code></div>
</div></body></html>"#,
        id = esc(&s.id),
        user = esc(&s.user),
        host = esc(host),
        protocol = esc(&s.protocol.to_uppercase()),
        from = esc(&from),
        start = s.start.with_timezone(&chrono::Local).format("%Y-%m-%d %H:%M:%S"),
        end = s
            .end
            .map(|e| e.with_timezone(&chrono::Local).format("%H:%M:%S").to_string())
            .unwrap_or_else(|| "now".into()),
        duration = duration_str(s),
        status = s.status.as_str(),
        reason = s.end_reason.as_ref().map(|r| format!(" ({})", esc(r))).unwrap_or_default(),
        auth = if auth.is_empty() { String::new() } else { format!(" · {}", esc(&auth)) },
        commands = s.commands,
        privileged = s.privileged,
        files = s.file_changes,
        alerts = s.alerts,
        risk = s.risk_score(),
        accent = sev_color(s.max_severity),
        rows = if rows.is_empty() { "<tr><td>No activity recorded.</td></tr>".to_string() } else { rows },
        generated = chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
    )
}
