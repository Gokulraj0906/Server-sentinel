//! Minimal HTTP(S) client plumbing shared by the email (SMTP STARTTLS,
//! Resend) and webhook notifiers.
//!
//! TLS is rustls with the Mozilla root store compiled in — no OpenSSL, no
//! dependency on whatever certificate store the host happens to have, so
//! it behaves identically in the .deb/.rpm/.msi builds.

use anyhow::{anyhow, bail, Context, Result};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

pub(crate) fn tls_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
    }));
    Arc::new(
        rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// Wraps an already-connected `TcpStream` in TLS. Used both for a
/// straight-to-TLS connection (HTTPS) and for a STARTTLS upgrade partway
/// through an SMTP session.
pub(crate) fn start_tls(tcp: TcpStream, host: &str) -> Result<rustls::StreamOwned<rustls::ClientConnection, TcpStream>> {
    let server_name =
        rustls::ServerName::try_from(host).map_err(|_| anyhow!("'{host}' is not a valid DNS name for TLS"))?;
    let conn = rustls::ClientConnection::new(tls_config(), server_name).context("starting TLS handshake")?;
    Ok(rustls::StreamOwned::new(conn, tcp))
}

/// Reads one line at a time without over-buffering past a protocol phase
/// boundary (important for SMTP: a `BufReader` could greedily read bytes
/// belonging to the *next* phase — e.g. the TLS handshake right after
/// STARTTLS — off the wire before we're ready for them).
pub(crate) fn read_line<R: Read>(stream: &mut R) -> Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).context("reading from socket")?;
        if n == 0 {
            break; // connection closed
        }
        line.push(byte[0]);
        if byte[0] == b'\n' || line.len() > 64 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&line).trim_end().to_string())
}

pub(crate) fn connect(host: &str, port: u16) -> Result<TcpStream> {
    let addr = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {host}"))?
        .next()
        .ok_or_else(|| anyhow!("{host} did not resolve"))?;
    let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(10)).with_context(|| format!("connecting to {host}:{port}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(15)))?;
    Ok(tcp)
}

struct Url<'a> {
    tls: bool,
    host: &'a str,
    port: u16,
    path: &'a str,
}

fn parse_url(url: &str) -> Result<Url<'_>> {
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        bail!("URL must start with http:// or https://");
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h, p.parse().context("invalid port")?)
        }
        _ => (authority, if tls { 443 } else { 80 }),
    };
    if host.is_empty() {
        bail!("URL has no host");
    }
    Ok(Url { tls, host, port, path })
}

/// POSTs a JSON body and returns the HTTP status code. Only the status
/// line is read; notifiers don't need response bodies.
pub fn post_json(url: &str, extra_headers: &[(&str, &str)], body: &str) -> Result<(u16, String)> {
    let u = parse_url(url)?;
    let mut request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: server-sentinel/{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        u.path,
        u.host,
        env!("CARGO_PKG_VERSION"),
        body.len()
    );
    for (k, v) in extra_headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);

    let tcp = connect(u.host, u.port)?;
    let status_line = if u.tls {
        let mut tls = start_tls(tcp, u.host)?;
        tls.write_all(request.as_bytes())?;
        read_line(&mut tls)?
    } else {
        let mut tcp = tcp;
        tcp.write_all(request.as_bytes())?;
        read_line(&mut tcp)?
    };
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("malformed HTTP response: '{status_line}'"))?;
    Ok((code, status_line))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        let u = parse_url("https://hooks.slack.com/services/T/B/X").unwrap();
        assert!(u.tls);
        assert_eq!((u.host, u.port, u.path), ("hooks.slack.com", 443, "/services/T/B/X"));
        let u = parse_url("http://10.0.0.5:8080").unwrap();
        assert_eq!((u.host, u.port, u.path), ("10.0.0.5", 8080, "/"));
        assert!(parse_url("ftp://x").is_err());
    }

    #[test]
    fn post_to_local_http_server() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).unwrap();
            s.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
            String::from_utf8_lossy(&buf[..n]).to_string()
        });
        let (code, _) = post_json(&format!("http://127.0.0.1:{port}/hook"), &[("X-Test", "1")], r#"{"a":1}"#).unwrap();
        assert_eq!(code, 204);
        let req = server.join().unwrap();
        assert!(req.starts_with("POST /hook HTTP/1.1"));
        assert!(req.contains("X-Test: 1") && req.ends_with(r#"{"a":1}"#));
    }
}
