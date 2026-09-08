//! Email notifier (FR-017).
//!
//! Two real providers, chosen by `[notification.email] provider`:
//!
//! - `"smtp"` — authenticated SMTP with STARTTLS + AUTH LOGIN. This is
//!   the *same protocol* for Gmail (an App Password as `smtp_password`)
//!   and AWS SES's SMTP interface (SES-generated SMTP credentials, NOT
//!   your AWS access key/secret) — only the host/port/credentials differ.
//! - `"resend"` — Resend's HTTPS API (`POST api.resend.com/emails`),
//!   authenticated with a Bearer API key.
//!
//! TLS is hand-rolled on top of `rustls` (no OpenSSL dependency, so this
//! keeps working the same way across the .deb/.rpm/.msi builds without
//! relying on whatever TLS library happens to be installed on the host).

use crate::core::config::EmailNotificationConfig;
use crate::core::models::IncidentReport;
use crate::notification::Notifier;
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::Serialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

pub struct EmailNotifier {
    config: EmailNotificationConfig,
}

impl EmailNotifier {
    pub fn new(config: EmailNotificationConfig) -> Self {
        Self { config }
    }
}

impl Notifier for EmailNotifier {
    fn notify(&self, report: &IncidentReport) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let subject = format!(
            "[ServerSentinel] {} INCIDENT on {} — {}",
            report.severity, report.server_name, report.incident_type
        );
        let body = format!(
            "ServerSentinel automated incident report\n\n\
             Server: {}\nIncident: {}\nSeverity: {}\nDuration: {}\n\n\
             Probable cause: {}\nConfidence: {:.0}%\nEvidence quality: {}\n\n\
             Full JSON/HTML report is on the agent host under the configured\n\
             storage directory (incidents/{}.json, reports/{}.html).\n",
            report.server_name,
            report.incident_id,
            report.severity,
            report
                .duration_seconds
                .map(|d| format!("{d}s"))
                .unwrap_or_else(|| "in progress".to_string()),
            report.root_cause.probable_cause,
            report.root_cause.confidence_percent,
            report.root_cause.evidence_quality,
            report.incident_id,
            report.incident_id,
        );

        match self.config.provider.as_str() {
            "resend" => send_via_resend(&self.config, &subject, &body),
            "smtp" | "" => send_via_smtp(&self.config, &subject, &body),
            other => Err(anyhow!(
                "unknown notification.email.provider '{other}' (expected \"smtp\" or \"resend\")"
            )),
        }
    }
}

// ---------------------------------------------------------------------
// Shared TLS plumbing
// ---------------------------------------------------------------------

fn tls_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    Arc::new(
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Wraps an already-connected `TcpStream` in TLS. Used both for a
/// straight-to-TLS connection (Resend's HTTPS) and for a STARTTLS
/// upgrade partway through an SMTP session (Gmail/SES).
fn start_tls(tcp: TcpStream, host: &str) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let server_name = rustls::ServerName::try_from(host)
        .map_err(|_| anyhow!("'{host}' is not a valid DNS name for TLS"))?;
    let conn = rustls::ClientConnection::new(tls_config(), server_name)
        .context("starting TLS handshake")?;
    Ok(rustls::StreamOwned::new(conn, tcp))
}

/// Reads one line at a time without over-buffering past a protocol phase
/// boundary (important for SMTP: a `BufReader` could greedily read bytes
/// belonging to the *next* phase — e.g. the TLS handshake right after
/// STARTTLS — off the wire before we're ready for them).
fn read_line<R: Read>(stream: &mut R) -> Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).context("reading from socket")?;
        if n == 0 {
            break; // connection closed
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&line).trim_end().to_string())
}

/// Reads a full (possibly multi-line, "250-...\r\n250 ...\r\n") SMTP
/// reply and returns its status code.
fn read_smtp_reply<R: Read>(stream: &mut R) -> Result<u16> {
    loop {
        let line = read_line(stream)?;
        if line.len() < 4 {
            return Err(anyhow!("malformed SMTP reply: '{line}'"));
        }
        let code: u16 = line[..3]
            .parse()
            .with_context(|| format!("malformed SMTP status code in '{line}'"))?;
        let is_final_line = line.as_bytes()[3] != b'-';
        if is_final_line {
            return Ok(code);
        }
        // else: continuation line, keep reading
    }
}

fn expect_smtp<R: Read>(stream: &mut R, expected: u16, step: &str) -> Result<()> {
    let code = read_smtp_reply(stream)?;
    if code != expected {
        return Err(anyhow!("SMTP server rejected {step} (got {code}, expected {expected})"));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// provider = "smtp" — STARTTLS + AUTH LOGIN
// (identical protocol for Gmail app passwords and AWS SES SMTP creds)
// ---------------------------------------------------------------------

fn send_via_smtp(config: &EmailNotificationConfig, subject: &str, body: &str) -> Result<()> {
    if config.smtp_host.is_empty() {
        return Err(anyhow!("notification.email.smtp_host is empty"));
    }

    let addr = format!("{}:{}", config.smtp_host, config.smtp_port);
    let mut tcp = TcpStream::connect(&addr).with_context(|| format!("connecting to {addr}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))?;

    // --- plaintext phase: greeting, EHLO, STARTTLS ---
    expect_smtp(&mut tcp, 220, "connection greeting")?;
    tcp.write_all(b"EHLO server-sentinel\r\n")?;
    expect_smtp(&mut tcp, 250, "EHLO")?;
    tcp.write_all(b"STARTTLS\r\n")?;
    expect_smtp(&mut tcp, 220, "STARTTLS")?;

    // --- upgrade to TLS, then redo EHLO + AUTH over the encrypted channel ---
    let mut tls = start_tls(tcp, &config.smtp_host)?;
    tls.write_all(b"EHLO server-sentinel\r\n")?;
    expect_smtp(&mut tls, 250, "post-STARTTLS EHLO")?;

    tls.write_all(b"AUTH LOGIN\r\n")?;
    expect_smtp(&mut tls, 334, "AUTH LOGIN")?;
    tls.write_all(format!("{}\r\n", BASE64.encode(&config.smtp_username)).as_bytes())?;
    expect_smtp(&mut tls, 334, "AUTH username")?;
    tls.write_all(format!("{}\r\n", BASE64.encode(&config.smtp_password)).as_bytes())?;
    expect_smtp(&mut tls, 235, "AUTH password (check your app password / SMTP credentials)")?;

    tls.write_all(format!("MAIL FROM:<{}>\r\n", config.from_address).as_bytes())?;
    expect_smtp(&mut tls, 250, "MAIL FROM")?;
    for to in &config.to_addresses {
        tls.write_all(format!("RCPT TO:<{to}>\r\n").as_bytes())?;
        expect_smtp(&mut tls, 250, "RCPT TO")?;
    }

    tls.write_all(b"DATA\r\n")?;
    expect_smtp(&mut tls, 354, "DATA")?;
    let to_header = config.to_addresses.join(", ");
    let message = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n.\r\n",
        config.from_address, to_header, subject, body
    );
    tls.write_all(message.as_bytes())?;
    expect_smtp(&mut tls, 250, "message body")?;

    tls.write_all(b"QUIT\r\n")?;
    Ok(())
}

// ---------------------------------------------------------------------
// provider = "resend" — HTTPS API
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct ResendPayload<'a> {
    from: &'a str,
    to: &'a [String],
    subject: &'a str,
    text: &'a str,
}

fn send_via_resend(config: &EmailNotificationConfig, subject: &str, body: &str) -> Result<()> {
    if config.resend_api_key.is_empty() {
        return Err(anyhow!("notification.email.resend_api_key is empty"));
    }

    let payload = ResendPayload {
        from: &config.from_address,
        to: &config.to_addresses,
        subject,
        text: body,
    };
    let json = serde_json::to_string(&payload)?;

    let host = "api.resend.com";
    let tcp = TcpStream::connect((host, 443)).with_context(|| format!("connecting to {host}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut tls = start_tls(tcp, host)?;

    let request = format!(
        "POST /emails HTTP/1.1\r\n\
         Host: {host}\r\n\
         Authorization: Bearer {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        config.resend_api_key,
        json.len(),
        json
    );
    tls.write_all(request.as_bytes())?;

    let mut response = String::new();
    tls.read_to_string(&mut response)
        .context("reading Resend response")?;

    let status_line = response.lines().next().unwrap_or("");
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if !(200..300).contains(&status_code) {
        let snippet: String = response.chars().take(500).collect();
        return Err(anyhow!("Resend API returned {status_code}: {snippet}"));
    }
    Ok(())
}
