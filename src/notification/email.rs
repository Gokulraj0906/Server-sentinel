//! Minimal SMTP email notifier (FR-017).
//!
//! Deliberately dependency-light: speaks plain RFC 5321 SMTP over a raw
//! TCP socket (no STARTTLS/AUTH). That's enough for an internal relay on
//! the same network, which is a common on-prem setup. For public SMTP
//! providers (Gmail, SES, etc.) that require STARTTLS + AUTH, swap this
//! implementation for the `lettre` crate — the `Notifier` trait is the
//! extension point, nothing else needs to change.

use crate::core::config::EmailNotificationConfig;
use crate::core::models::IncidentReport;
use crate::notification::Notifier;
use anyhow::{anyhow, Result};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

pub struct EmailNotifier {
    config: EmailNotificationConfig,
}

impl EmailNotifier {
    pub fn new(config: EmailNotificationConfig) -> Self {
        Self { config }
    }

    fn read_response(reader: &mut BufReader<TcpStream>) -> Result<String> {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        Ok(line)
    }

    fn send(&self, subject: &str, body: &str) -> Result<()> {
        let addr = format!("{}:{}", self.config.smtp_host, self.config.smtp_port);
        let stream = TcpStream::connect(&addr)?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let mut writer = stream.try_clone()?;
        let mut reader = BufReader::new(stream);

        Self::read_response(&mut reader)?; // greeting
        writer.write_all(format!("EHLO servesentinel-agent\r\n").as_bytes())?;
        Self::read_response(&mut reader)?;

        writer.write_all(format!("MAIL FROM:<{}>\r\n", self.config.from_address).as_bytes())?;
        Self::read_response(&mut reader)?;

        for to in &self.config.to_addresses {
            writer.write_all(format!("RCPT TO:<{to}>\r\n").as_bytes())?;
            Self::read_response(&mut reader)?;
        }

        writer.write_all(b"DATA\r\n")?;
        Self::read_response(&mut reader)?;

        let to_header = self.config.to_addresses.join(", ");
        let message = format!(
            "From: {}\r\nTo: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}\r\n.\r\n",
            self.config.from_address, to_header, subject, body
        );
        writer.write_all(message.as_bytes())?;
        let resp = Self::read_response(&mut reader)?;
        if !resp.starts_with('2') {
            return Err(anyhow!("SMTP server rejected message: {resp}"));
        }

        writer.write_all(b"QUIT\r\n")?;
        Ok(())
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
             See attached JSON/HTML report on the agent host under the configured storage directory\n\
             (incidents/{}.json, reports/{}.html).\n",
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
        self.send(&subject, &body)
    }
}
