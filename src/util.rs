//! Small shared helpers: wildcard matching, durations, hashing.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Glob-style match where `*` matches any run of characters (including
/// path separators) and `?` matches exactly one. Case-sensitive, except
/// on Windows where paths and account names are case-insensitive anyway.
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    if cfg!(windows) {
        wildcard_match_bytes(
            pattern.to_ascii_lowercase().as_bytes(),
            text.to_ascii_lowercase().as_bytes(),
        )
    } else {
        wildcard_match_bytes(pattern.as_bytes(), text.as_bytes())
    }
}

/// Always case-insensitive; used for user-supplied search queries.
pub fn wildcard_match_ci(pattern: &str, text: &str) -> bool {
    wildcard_match_bytes(
        pattern.to_ascii_lowercase().as_bytes(),
        text.to_ascii_lowercase().as_bytes(),
    )
}

fn wildcard_match_bytes(p: &[u8], t: &[u8]) -> bool {
    // Iterative two-pointer matcher with single-star backtracking: O(p*t)
    // worst case, no recursion, no allocation.
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_t = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            star_t = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            star_t += 1;
            ti = star_t;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

/// Parses "90s", "15m", "24h", "7d", "2w" (and bare seconds).
pub fn parse_duration(s: &str) -> Option<chrono::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num, unit) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => (&s[..i], &s[i..]),
        None => (s, "s"),
    };
    let n: i64 = num.parse().ok()?;
    let secs = match unit.trim() {
        "s" | "sec" | "secs" => n,
        "m" | "min" | "mins" => n * 60,
        "h" | "hr" | "hrs" => n * 3600,
        "d" | "day" | "days" => n * 86_400,
        "w" | "wk" | "weeks" => n * 7 * 86_400,
        _ => return None,
    };
    Some(chrono::Duration::seconds(secs))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Expands `*` wildcards segment-by-segment against the real filesystem
/// ("/home/*/.ssh" -> every user's .ssh). Paths without wildcards are
/// returned as-is if they exist.
pub fn expand_path_pattern(pattern: &str) -> Vec<PathBuf> {
    if !pattern.contains('*') && !pattern.contains('?') {
        let p = PathBuf::from(pattern);
        return if p.exists() { vec![p] } else { Vec::new() };
    }
    let path = Path::new(pattern);
    let mut current: Vec<PathBuf> = vec![PathBuf::new()];
    for comp in path.components() {
        let comp_str = comp.as_os_str().to_string_lossy().to_string();
        let mut next = Vec::new();
        for base in &current {
            if comp_str.contains('*') || comp_str.contains('?') {
                if let Ok(rd) = std::fs::read_dir(if base.as_os_str().is_empty() { Path::new(".") } else { base }) {
                    for entry in rd.flatten() {
                        let name = entry.file_name().to_string_lossy().to_string();
                        if wildcard_match(&comp_str, &name) {
                            next.push(base.join(name));
                        }
                    }
                }
            } else {
                next.push(base.join(comp.as_os_str()));
            }
        }
        current = next;
    }
    current.into_iter().filter(|p| p.exists()).collect()
}

/// True if the bytes look like human-editable text we can meaningfully
/// diff: valid UTF-8 with no NUL bytes.
pub fn is_text(data: &[u8]) -> bool {
    !data.iter().take(8192).any(|&b| b == 0) && std::str::from_utf8(data).is_ok()
}

/// Truncates on a char boundary, appending a marker if anything was cut.
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[truncated {} bytes]", &s[..end], s.len() - end)
}

/// Loopback / unspecified addresses don't identify a remote party.
pub fn is_meaningful_remote_ip(ip: &str) -> bool {
    !matches!(ip, "" | "-" | "127.0.0.1" | "::1" | "0.0.0.0" | "::" | "LOCAL")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_basics() {
        assert!(wildcard_match_ci("/etc/*", "/etc/nginx/nginx.conf"));
        assert!(wildcard_match_ci("*.conf", "/etc/nginx/nginx.conf"));
        assert!(wildcard_match_ci("auth.*", "auth.failure"));
        assert!(wildcard_match_ci("a?c", "abc"));
        assert!(!wildcard_match_ci("a?c", "abbc"));
        assert!(wildcard_match_ci("*", ""));
        assert!(!wildcard_match_ci("/etc/*.conf", "/var/x.conf"));
        assert!(wildcard_match_ci("*id_rsa*", "/root/.ssh/id_rsa.pub"));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap().num_seconds(), 90);
        assert_eq!(parse_duration("15m").unwrap().num_seconds(), 900);
        assert_eq!(parse_duration("24h").unwrap().num_seconds(), 86_400);
        assert_eq!(parse_duration("7d").unwrap().num_seconds(), 604_800);
        assert!(parse_duration("abc").is_none());
    }

    #[test]
    fn text_detection_and_truncation() {
        assert!(is_text(b"server_name example.com;\n"));
        assert!(!is_text(b"\x7fELF\x00\x01"));
        assert_eq!(truncate("héllo", 2), "h…[truncated 5 bytes]");
    }
}
