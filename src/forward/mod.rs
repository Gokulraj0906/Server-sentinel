//! Forwarding events to wherever the customer already looks.
//!
//! ServerSentinel is useful standalone, but it should never be a data
//! island: a team with Splunk / Elastic / Graylog / Loki / Sentinel keeps
//! it, and ServerSentinel becomes the best-structured source feeding it.
//! Forwarding also defends the audit trail — an attacker with root can
//! delete the local database, but not what already left the box.
//!
//! - `ndjson`: one JSON event per line in a rotating file (point Splunk
//!   UF, Filebeat, Vector, Fluent Bit or the Datadog agent at it).
//! - `syslog`: RFC 5424 over UDP or TCP with a JSON message body.

use crate::core::config::{NdjsonForwardConfig, SyslogForwardConfig};
use crate::events::{Event, Severity};
use anyhow::{anyhow, bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{TcpStream, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub trait Forwarder: Send {
    fn name(&self) -> &'static str;
    fn forward(&mut self, ev: &Event) -> Result<()>;
    fn flush(&mut self) {}
}

pub struct NdjsonForwarder {
    path: PathBuf,
    max_bytes: u64,
    keep: u32,
    out: Option<BufWriter<File>>,
    written: u64,
    last_flush: Instant,
}

impl NdjsonForwarder {
    pub fn new(cfg: &NdjsonForwardConfig, default_path: PathBuf) -> Result<Self> {
        let path = if cfg.path.is_empty() { default_path } else { PathBuf::from(&cfg.path) };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut f = Self {
            path,
            max_bytes: cfg.max_file_mb.max(1) * 1024 * 1024,
            keep: cfg.keep_files.max(1),
            out: None,
            written: 0,
            last_flush: Instant::now(),
        };
        f.open()?;
        Ok(f)
    }

    fn open(&mut self) -> Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("opening {}", self.path.display()))?;
        self.written = file.metadata().map(|m| m.len()).unwrap_or(0);
        self.out = Some(BufWriter::new(file));
        Ok(())
    }

    /// events.ndjson -> events.ndjson.1 -> ... -> .N (oldest dropped).
    /// Rename-based so tailing shippers (which track by inode) finish the
    /// old file and pick up the new one.
    fn rotate(&mut self) -> Result<()> {
        if let Some(mut out) = self.out.take() {
            out.flush()?;
        }
        let numbered = |n: u32| PathBuf::from(format!("{}.{n}", self.path.display()));
        let _ = std::fs::remove_file(numbered(self.keep));
        for n in (1..self.keep).rev() {
            let _ = std::fs::rename(numbered(n), numbered(n + 1));
        }
        std::fs::rename(&self.path, numbered(1)).ok();
        self.open()
    }
}

impl Forwarder for NdjsonForwarder {
    fn name(&self) -> &'static str {
        "ndjson"
    }

    fn forward(&mut self, ev: &Event) -> Result<()> {
        let mut line = serde_json::to_string(ev)?;
        line.push('\n');
        if self.written + line.len() as u64 > self.max_bytes {
            self.rotate()?;
        }
        let out = self.out.as_mut().ok_or_else(|| anyhow!("ndjson output not open"))?;
        out.write_all(line.as_bytes())?;
        self.written += line.len() as u64;
        if self.last_flush.elapsed() >= Duration::from_secs(1) {
            out.flush()?;
            self.last_flush = Instant::now();
        }
        Ok(())
    }

    fn flush(&mut self) {
        if let Some(out) = self.out.as_mut() {
            let _ = out.flush();
        }
    }
}

enum SyslogTransport {
    Udp(UdpSocket, String),
    Tcp { addr: String, stream: Option<TcpStream>, retry_after: Instant },
}

pub struct SyslogForwarder {
    transport: SyslogTransport,
    min_severity: Severity,
    hostname: String,
}

impl SyslogForwarder {
    pub fn new(cfg: &SyslogForwardConfig, hostname: String) -> Result<Self> {
        let min_severity = Severity::parse(&cfg.min_severity).unwrap_or(Severity::Info);
        let transport = if let Some(addr) = cfg.address.strip_prefix("udp://") {
            let sock = UdpSocket::bind("0.0.0.0:0").context("binding UDP socket for syslog")?;
            SyslogTransport::Udp(sock, addr.to_string())
        } else if let Some(addr) = cfg.address.strip_prefix("tcp://") {
            SyslogTransport::Tcp {
                addr: addr.to_string(),
                stream: None,
                retry_after: Instant::now(),
            }
        } else {
            bail!("forward.syslog.address must be udp://host:port or tcp://host:port");
        };
        Ok(Self {
            transport,
            min_severity,
            hostname,
        })
    }

    /// RFC 5424: <PRI>1 TIMESTAMP HOST APP PROCID MSGID - MSG
    fn format(&self, ev: &Event) -> Result<String> {
        // facility 13 (log audit); map our severity onto syslog levels.
        let level = match ev.severity {
            Severity::Critical => 2,
            Severity::High => 3,
            Severity::Medium => 4,
            Severity::Low => 5,
            Severity::Info => 6,
        };
        let pri = 13 * 8 + level;
        Ok(format!(
            "<{pri}>1 {} {} server-sentinel {} {} - {}",
            ev.ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            if self.hostname.is_empty() { "-" } else { &self.hostname },
            std::process::id(),
            ev.action.replace(' ', "_"),
            serde_json::to_string(ev)?
        ))
    }
}

impl Forwarder for SyslogForwarder {
    fn name(&self) -> &'static str {
        "syslog"
    }

    fn forward(&mut self, ev: &Event) -> Result<()> {
        if ev.severity < self.min_severity {
            return Ok(());
        }
        let msg = self.format(ev)?;
        match &mut self.transport {
            SyslogTransport::Udp(sock, addr) => {
                // Keep datagrams under typical MTU-safe syslog limits.
                let bytes = msg.as_bytes();
                sock.send_to(&bytes[..bytes.len().min(8192)], addr.as_str())?;
            }
            SyslogTransport::Tcp { addr, stream, retry_after } => {
                if stream.is_none() {
                    if Instant::now() < *retry_after {
                        return Err(anyhow!("syslog TCP endpoint unavailable; retrying shortly"));
                    }
                    match TcpStream::connect(addr.as_str()) {
                        Ok(s) => {
                            s.set_write_timeout(Some(Duration::from_secs(5)))?;
                            *stream = Some(s);
                        }
                        Err(e) => {
                            *retry_after = Instant::now() + Duration::from_secs(30);
                            return Err(e.into());
                        }
                    }
                }
                // RFC 6587 octet-counting framing.
                let framed = format!("{} {}", msg.len(), msg);
                if let Err(e) = stream.as_mut().expect("connected above").write_all(framed.as_bytes()) {
                    *stream = None;
                    return Err(e.into());
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::Category;

    #[test]
    fn ndjson_rotates() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = NdjsonForwardConfig {
            enabled: true,
            path: dir.path().join("events.ndjson").display().to_string(),
            max_file_mb: 1,
            keep_files: 2,
        };
        let mut f = NdjsonForwarder::new(&cfg, PathBuf::new()).unwrap();
        let big = "x".repeat(300 * 1024);
        for _ in 0..8 {
            f.forward(&Event::new(Category::Agent, "agent.test", big.clone())).unwrap();
        }
        f.flush();
        assert!(dir.path().join("events.ndjson.1").exists());
        assert!(dir.path().join("events.ndjson.2").exists());
        assert!(!dir.path().join("events.ndjson.3").exists());
        let current = std::fs::read_to_string(dir.path().join("events.ndjson")).unwrap();
        let first: serde_json::Value = serde_json::from_str(current.lines().next().unwrap()).unwrap();
        assert_eq!(first["action"], "agent.test");
    }

    #[test]
    fn syslog_udp_rfc5424() {
        let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
        rx.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let cfg = SyslogForwardConfig {
            enabled: true,
            address: format!("udp://{}", rx.local_addr().unwrap()),
            min_severity: "low".into(),
        };
        let mut f = SyslogForwarder::new(&cfg, "web1".into()).unwrap();
        f.forward(&Event::new(Category::Auth, "auth.failure", "ignored: below min severity")).unwrap();
        f.forward(&Event::new(Category::Alert, "alert.bruteforce", "Brute force").severity(Severity::High)).unwrap();
        let mut buf = [0u8; 8192];
        let n = rx.recv(&mut buf).unwrap();
        let msg = String::from_utf8_lossy(&buf[..n]);
        assert!(msg.starts_with("<107>1 "), "{msg}");
        assert!(msg.contains(" web1 server-sentinel ") && msg.contains("alert.bruteforce"));
    }
}
