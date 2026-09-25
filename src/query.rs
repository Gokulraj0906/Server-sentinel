//! Search query language for `server-sentinel search`.
//!
//! Deliberately tiny, so there's nothing to learn:
//!
//! ```text
//! user=alice action=file.* nginx.conf          # fields AND free text
//! ip=203.0.113.9 sev>=high                      # severity threshold
//! category=process command=*curl*|*wget*        # (no OR: run two searches)
//! session=S260925-3fa9c2 target!=/etc/hosts
//! "systemctl restart"                           # quoted phrase
//! ```
//!
//! Free-text terms are substring matches over the message, command line
//! and target. `*` in a field value is a wildcard. Field matches are
//! case-insensitive.

use crate::events::Severity;
use anyhow::{bail, Result};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    User,
    SrcIp,
    Action,
    Category,
    Session,
    Target,
    Host,
    Process,
    Command,
    Outcome,
    Pid,
    Id,
}

impl Field {
    fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "user" | "u" => Field::User,
            "ip" | "src_ip" | "src" | "source" => Field::SrcIp,
            "action" | "a" => Field::Action,
            "category" | "cat" => Field::Category,
            "session" | "sid" => Field::Session,
            "target" | "path" | "file" => Field::Target,
            "host" => Field::Host,
            "process" | "proc" => Field::Process,
            "command" | "cmd" => Field::Command,
            "outcome" => Field::Outcome,
            "pid" => Field::Pid,
            "id" => Field::Id,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    Eq,
    Ne,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Filter {
    pub field: Field,
    pub op: FilterOp,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct Query {
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub filters: Vec<Filter>,
    pub text: Vec<String>,
    pub min_severity: Option<Severity>,
    pub limit: usize,
    pub oldest_first: bool,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            since: None,
            until: None,
            filters: Vec::new(),
            text: Vec::new(),
            min_severity: None,
            limit: 200,
            oldest_first: false,
        }
    }
}

/// Splits on whitespace, keeping "quoted phrases" (and key="quoted
/// values") together.
fn tokenize(input: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    for c in input.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if in_quotes {
        bail!("unterminated quote in query");
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    Ok(tokens)
}

impl Query {
    pub fn parse(input: &str) -> Result<Self> {
        let mut q = Query::default();
        for tok in tokenize(input)? {
            if let Some(rest) = tok
                .strip_prefix("sev>=")
                .or_else(|| tok.strip_prefix("severity>="))
            {
                q.min_severity = Some(
                    Severity::parse(rest).ok_or_else(|| anyhow::anyhow!("unknown severity '{rest}'"))?,
                );
                continue;
            }
            let (key, op, value) = if let Some((k, v)) = tok.split_once("!=") {
                (k, FilterOp::Ne, v)
            } else if let Some((k, v)) = tok.split_once('=') {
                (k, FilterOp::Eq, v)
            } else {
                q.text.push(tok);
                continue;
            };
            if key.eq_ignore_ascii_case("sev") || key.eq_ignore_ascii_case("severity") {
                let s = Severity::parse(value).ok_or_else(|| anyhow::anyhow!("unknown severity '{value}'"))?;
                q.min_severity = Some(s);
                continue;
            }
            match Field::parse(key) {
                Some(field) => q.filters.push(Filter {
                    field,
                    op,
                    value: value.to_string(),
                }),
                None => bail!(
                    "unknown field '{key}' (fields: user, ip, action, category, session, target/path, host, \
                     process, command, outcome, pid, id, sev)"
                ),
            }
        }
        Ok(q)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fields_text_and_severity() {
        let q = Query::parse(r#"user=alice action!=auth.failure "systemctl restart" nginx sev>=high"#).unwrap();
        assert_eq!(q.filters.len(), 2);
        assert_eq!(q.filters[0].field, Field::User);
        assert_eq!(q.filters[1].op, FilterOp::Ne);
        assert_eq!(q.text, vec!["systemctl restart", "nginx"]);
        assert_eq!(q.min_severity, Some(Severity::High));
    }

    #[test]
    fn quoted_values_and_errors() {
        let q = Query::parse(r#"path="/srv/my app/config.yml""#).unwrap();
        assert_eq!(q.filters[0].value, "/srv/my app/config.yml");
        assert!(Query::parse("bogus=1").is_err());
        assert!(Query::parse("\"open").is_err());
        assert!(Query::parse("sev=nope").is_err());
    }
}
