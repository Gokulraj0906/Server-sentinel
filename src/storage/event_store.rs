//! Embedded security event store (SQLite).
//!
//! One local database per host holds every audit event, access session,
//! file-integrity baseline and the *previous content* of monitored files.
//! Design points:
//!
//! - **WAL mode**: the pipeline writes while CLI commands and the incident
//!   engine read concurrently, without blocking each other.
//! - **Hash chain**: every event row stores `hash = sha256(prev_hash ||
//!   row)`. `server-sentinel verify` recomputes the chain, so editing or
//!   deleting a row after the fact is detectable. (It can't stop someone
//!   with root from deleting the whole file — forward events off-box for
//!   that; see `forward`.)
//! - **Trigram FTS**: substring search over messages, command lines and
//!   paths ("nginx.conf", "curl http") without a query language to learn.
//! - **Content-addressed blobs**: file versions are stored once per unique
//!   content (deflate-compressed), so an unchanged 10 KB config costs
//!   nothing no matter how often it's rescanned.

use crate::events::{Category, Event, Outcome, ProcessInfo, Severity};
use crate::query::{Field, Filter, FilterOp, Query};
use crate::security::sessions::{Session, SessionStatus};
use crate::util::sha256_hex;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, params_from_iter, Connection, OpenFlags, OptionalExtension, Row, Transaction};
use std::io::{Read, Write};
use std::path::Path;

const SCHEMA_VERSION: i64 = 1;
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY,
    ts           TEXT NOT NULL,
    host         TEXT NOT NULL,
    category     TEXT NOT NULL,
    action       TEXT NOT NULL,
    outcome      TEXT NOT NULL,
    severity     INTEGER NOT NULL,
    user         TEXT,
    src_ip       TEXT,
    session_id   TEXT,
    pid          INTEGER,
    process_name TEXT,
    command_line TEXT,
    process      TEXT,
    target       TEXT,
    message      TEXT NOT NULL,
    details      TEXT,
    before_sha   TEXT,
    after_sha    TEXT,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts       ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_cat_ts   ON events(category, ts);
CREATE INDEX IF NOT EXISTS idx_events_action   ON events(action, ts);
CREATE INDEX IF NOT EXISTS idx_events_user     ON events(user, ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip   ON events(src_ip, ts);
CREATE INDEX IF NOT EXISTS idx_events_session  ON events(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_target   ON events(target, ts);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    message, command_line, target,
    content='events', content_rowid='id', tokenize='trigram'
);
CREATE TRIGGER IF NOT EXISTS events_ai AFTER INSERT ON events BEGIN
    INSERT INTO events_fts(rowid, message, command_line, target)
    VALUES (new.id, new.message, new.command_line, new.target);
END;
CREATE TRIGGER IF NOT EXISTS events_ad AFTER DELETE ON events BEGIN
    INSERT INTO events_fts(events_fts, rowid, message, command_line, target)
    VALUES ('delete', old.id, old.message, old.command_line, old.target);
END;

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    host            TEXT NOT NULL,
    user            TEXT NOT NULL,
    protocol        TEXT NOT NULL,
    src_ip          TEXT,
    src_port        INTEGER,
    auth_method     TEXT,
    key_fingerprint TEXT,
    start_ts        TEXT NOT NULL,
    end_ts          TEXT,
    last_activity   TEXT NOT NULL,
    status          TEXT NOT NULL,
    end_reason      TEXT,
    keys            TEXT NOT NULL,
    base_keys       INTEGER NOT NULL,
    commands        INTEGER NOT NULL,
    privileged      INTEGER NOT NULL,
    file_changes    INTEGER NOT NULL,
    alerts          INTEGER NOT NULL,
    max_severity    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_start ON sessions(start_ts);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

CREATE TABLE IF NOT EXISTS blobs (
    sha256     TEXT PRIMARY KEY,
    size       INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    data       BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS fim_files (
    path     TEXT PRIMARY KEY,
    sha256   TEXT,
    size     INTEGER NOT NULL,
    mtime    INTEGER NOT NULL,
    mode     INTEGER,
    uid      INTEGER,
    blob_sha TEXT
);

CREATE TABLE IF NOT EXISTS known_sources (
    user       TEXT NOT NULL,
    src_ip     TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    count      INTEGER NOT NULL,
    PRIMARY KEY (user, src_ip)
);

CREATE TABLE IF NOT EXISTS state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

pub fn fmt_ts(ts: &DateTime<Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

pub fn parse_ts(s: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(|_| DateTime::<Utc>::from_timestamp(0, 0).expect("epoch"))
}

#[derive(Debug, Clone, PartialEq)]
pub struct FimRecord {
    pub path: String,
    pub sha256: Option<String>,
    pub size: u64,
    pub mtime: i64,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub blob_sha: Option<String>,
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub rows_checked: u64,
    pub first_id: Option<i64>,
    pub last_id: Option<i64>,
    pub problems: Vec<String>,
}

/// Answers "has this user logged in from this address before?" for the
/// new-source rule. Implemented by the store's write transaction (so the
/// answer and the event land atomically) and by a map in tests.
pub trait SourceHistory {
    /// Records a successful login. Returns `Some(prior_distinct_sources)`
    /// if this source is new for the user, `None` if it's been seen.
    fn record_login(&mut self, user: &str, src_ip: &str, ts: DateTime<Utc>) -> Result<Option<usize>>;
}

pub struct EventStore {
    conn: Connection,
    last_hash: String,
}

fn hash_row(prev: &str, cols: &[&str]) -> String {
    let mut buf = String::with_capacity(prev.len() + cols.iter().map(|c| c.len() + 1).sum::<usize>());
    buf.push_str(prev);
    for c in cols {
        buf.push('\u{1f}');
        buf.push_str(c);
    }
    sha256_hex(buf.as_bytes())
}

struct EventRow {
    ts: String,
    host: String,
    category: String,
    action: String,
    outcome: String,
    severity: i64,
    user: Option<String>,
    src_ip: Option<String>,
    session_id: Option<String>,
    process: Option<String>,
    target: Option<String>,
    message: String,
    details: Option<String>,
    before_sha: Option<String>,
    after_sha: Option<String>,
}

impl EventRow {
    fn from_event(ev: &Event) -> Result<Self> {
        Ok(Self {
            ts: fmt_ts(&ev.ts),
            host: ev.host.clone(),
            category: ev.category.as_str().to_string(),
            action: ev.action.clone(),
            outcome: ev.outcome.as_str().to_string(),
            severity: ev.severity.as_i64(),
            user: ev.user.clone(),
            src_ip: ev.src_ip.clone(),
            session_id: ev.session_id.clone(),
            process: ev.process.as_ref().map(serde_json::to_string).transpose()?,
            target: ev.target.clone(),
            message: ev.message.clone(),
            details: if ev.details.is_null() {
                None
            } else {
                Some(serde_json::to_string(&ev.details)?)
            },
            before_sha: ev.before_sha.clone(),
            after_sha: ev.after_sha.clone(),
        })
    }

    fn hash(&self, prev: &str) -> String {
        let sev = self.severity.to_string();
        let o = |v: &Option<String>| v.clone().unwrap_or_default();
        hash_row(
            prev,
            &[
                &self.ts,
                &self.host,
                &self.category,
                &self.action,
                &self.outcome,
                &sev,
                &o(&self.user),
                &o(&self.src_ip),
                &o(&self.session_id),
                &o(&self.process),
                &o(&self.target),
                &self.message,
                &o(&self.details),
                &o(&self.before_sha),
                &o(&self.after_sha),
            ],
        )
    }
}

const EVENT_COLS: &str = "id, ts, host, category, action, outcome, severity, user, src_ip, session_id, \
     process, target, message, details, before_sha, after_sha, hash";

fn row_to_event(r: &Row<'_>) -> rusqlite::Result<Event> {
    let process: Option<String> = r.get(10)?;
    let details: Option<String> = r.get(13)?;
    Ok(Event {
        id: Some(r.get(0)?),
        ts: parse_ts(&r.get::<_, String>(1)?),
        host: r.get(2)?,
        category: Category::parse(&r.get::<_, String>(3)?).unwrap_or(Category::Agent),
        action: r.get(4)?,
        outcome: Outcome::parse(&r.get::<_, String>(5)?),
        severity: Severity::from_i64(r.get(6)?),
        user: r.get(7)?,
        src_ip: r.get(8)?,
        session_id: r.get(9)?,
        process: process.and_then(|p| serde_json::from_str::<ProcessInfo>(&p).ok()),
        target: r.get(11)?,
        message: r.get(12)?,
        details: details
            .and_then(|d| serde_json::from_str(&d).ok())
            .unwrap_or(serde_json::Value::Null),
        before_sha: r.get(14)?,
        after_sha: r.get(15)?,
        hash: r.get(16)?,
        keys: Vec::new(),
        learn: Vec::new(),
    })
}

const SESSION_COLS: &str = "id, user, protocol, src_ip, src_port, auth_method, key_fingerprint, start_ts, \
     end_ts, last_activity, status, end_reason, keys, base_keys, commands, privileged, file_changes, alerts, max_severity";

fn row_to_session(r: &Row<'_>) -> rusqlite::Result<Session> {
    let keys: String = r.get(12)?;
    let end: Option<String> = r.get(8)?;
    Ok(Session {
        id: r.get(0)?,
        user: r.get(1)?,
        protocol: r.get(2)?,
        src_ip: r.get(3)?,
        src_port: r.get::<_, Option<i64>>(4)?.map(|p| p as u16),
        auth_method: r.get(5)?,
        key_fingerprint: r.get(6)?,
        start: parse_ts(&r.get::<_, String>(7)?),
        end: end.map(|e| parse_ts(&e)),
        last_activity: parse_ts(&r.get::<_, String>(9)?),
        status: SessionStatus::parse(&r.get::<_, String>(10)?),
        end_reason: r.get(11)?,
        keys: serde_json::from_str(&keys).unwrap_or_default(),
        base_keys: r.get::<_, i64>(13)? as usize,
        commands: r.get::<_, i64>(14)? as u32,
        privileged: r.get::<_, i64>(15)? as u32,
        file_changes: r.get::<_, i64>(16)? as u32,
        alerts: r.get::<_, i64>(17)? as u32,
        max_severity: Severity::from_i64(r.get(18)?),
    })
}

fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data)?;
    Ok(enc.finish()?)
}

fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    flate2::read::DeflateDecoder::new(data).read_to_end(&mut out)?;
    Ok(out)
}

impl EventStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let conn = Connection::open(path).with_context(|| format!("opening event store {}", path.display()))?;
        restrict_permissions(path);
        Self::init(conn)
    }

    /// Read-only handle for CLI commands: never creates or migrates.
    pub fn open_readonly(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .with_context(|| {
                format!(
                    "opening event store {} (has the agent run yet on this host, and do you have permission to read it?)",
                    path.display()
                )
            })?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        let last_hash = Self::read_last_hash(&conn)?;
        Ok(Self { conn, last_hash })
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Self> {
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            anyhow::bail!(
                "event store schema v{version} is newer than this agent understands (v{SCHEMA_VERSION}); upgrade the agent"
            );
        }
        conn.execute_batch(SCHEMA).context("creating event store schema")?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        let last_hash = Self::read_last_hash(&conn)?;
        Ok(Self { conn, last_hash })
    }

    fn read_last_hash(conn: &Connection) -> Result<String> {
        let h: Option<String> = conn
            .query_row("SELECT hash FROM events ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
            .optional()?;
        Ok(h.unwrap_or_else(|| GENESIS_HASH.to_string()))
    }

    /// Runs `f` inside one transaction. Either everything in the batch
    /// (events, alerts, sessions, collector checkpoints) is committed, or
    /// nothing is — and the in-memory chain head only advances on commit.
    pub fn write_batch<T>(&mut self, f: impl FnOnce(&mut Writer<'_>) -> Result<T>) -> Result<T> {
        let tx = self.conn.transaction()?;
        let mut writer = Writer {
            tx,
            last_hash: self.last_hash.clone(),
        };
        let out = f(&mut writer)?;
        let Writer { tx, last_hash } = writer;
        tx.commit()?;
        self.last_hash = last_hash;
        Ok(out)
    }

    // ------------------------------------------------------------------
    // Reads
    // ------------------------------------------------------------------

    pub fn query(&self, q: &Query) -> Result<Vec<Event>> {
        let mut sql = format!("SELECT {EVENT_COLS} FROM events WHERE 1=1");
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(since) = q.since {
            sql.push_str(" AND ts >= ?");
            args.push(fmt_ts(&since).into());
        }
        if let Some(until) = q.until {
            sql.push_str(" AND ts <= ?");
            args.push(fmt_ts(&until).into());
        }
        if let Some(sev) = q.min_severity {
            sql.push_str(" AND severity >= ?");
            args.push(sev.as_i64().into());
        }
        for f in &q.filters {
            push_filter(&mut sql, &mut args, f);
        }
        for term in &q.text {
            // Trigram FTS needs >= 3 chars; shorter terms fall back to LIKE.
            if term.chars().count() >= 3 {
                sql.push_str(" AND id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)");
                args.push(format!("\"{}\"", term.replace('"', "\"\"")).into());
            } else {
                sql.push_str(
                    " AND (message LIKE ? ESCAPE '\\' OR command_line LIKE ? ESCAPE '\\' OR target LIKE ? ESCAPE '\\')",
                );
                let like = format!("%{}%", escape_like(term));
                args.push(like.clone().into());
                args.push(like.clone().into());
                args.push(like.into());
            }
        }
        sql.push_str(if q.oldest_first {
            " ORDER BY ts ASC, id ASC"
        } else {
            " ORDER BY ts DESC, id DESC"
        });
        sql.push_str(" LIMIT ?");
        args.push((q.limit as i64).into());

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), row_to_event)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn get_event(&self, id: i64) -> Result<Option<Event>> {
        Ok(self
            .conn
            .query_row(&format!("SELECT {EVENT_COLS} FROM events WHERE id = ?"), [id], row_to_event)
            .optional()?)
    }

    pub fn session_events(&self, session_id: &str, limit: usize) -> Result<Vec<Event>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {EVENT_COLS} FROM events WHERE session_id = ? ORDER BY ts ASC, id ASC LIMIT ?"
        ))?;
        let rows = stmt.query_map(params![session_id, limit as i64], row_to_event)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Changes and access around a window — used to explain performance
    /// incidents ("what changed right before this broke?").
    pub fn related_activity(&self, from: DateTime<Utc>, to: DateTime<Utc>, limit: usize) -> Result<Vec<Event>> {
        let mut stmt = self.conn.prepare(&format!(
            "SELECT {EVENT_COLS} FROM events
             WHERE ts >= ? AND ts <= ?
               AND (category IN ('file','service','package','account','alert')
                    OR action IN ('session.start','privilege.sudo','privilege.su'))
             ORDER BY ts ASC LIMIT ?"
        ))?;
        let rows = stmt.query_map(params![fmt_ts(&from), fmt_ts(&to), limit as i64], row_to_event)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn sessions(&self, since: Option<DateTime<Utc>>, live_only: bool, user: Option<&str>, limit: usize) -> Result<Vec<Session>> {
        let mut sql = format!("SELECT {SESSION_COLS} FROM sessions WHERE 1=1");
        let mut args: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(s) = since {
            // A session that started before `since` but is still open (or
            // ended after it) is still relevant to the window.
            sql.push_str(" AND (start_ts >= ? OR end_ts IS NULL OR end_ts >= ?)");
            args.push(fmt_ts(&s).into());
            args.push(fmt_ts(&s).into());
        }
        if live_only {
            sql.push_str(" AND status != 'ended'");
        }
        if let Some(u) = user {
            sql.push_str(" AND lower(user) LIKE ? ESCAPE '\\'");
            args.push(format!("%{}%", escape_like(&u.to_ascii_lowercase())).into());
        }
        sql.push_str(" ORDER BY start_ts DESC LIMIT ?");
        args.push((limit as i64).into());
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_from_iter(args), row_to_session)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn session(&self, id: &str) -> Result<Option<Session>> {
        Ok(self
            .conn
            .query_row(&format!("SELECT {SESSION_COLS} FROM sessions WHERE id = ?"), [id], row_to_session)
            .optional()?)
    }

    pub fn live_sessions(&self) -> Result<Vec<Session>> {
        self.sessions(None, true, None, 10_000)
    }

    pub fn get_state(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM state WHERE key = ?", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn set_state(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO state(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    pub fn event_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?)
    }

    // ------------------------------------------------------------------
    // Blobs and file-integrity baseline (used by the FIM collector on its
    // own connection)
    // ------------------------------------------------------------------

    pub fn put_blob(&self, data: &[u8]) -> Result<String> {
        let sha = sha256_hex(data);
        let exists: bool = self
            .conn
            .query_row("SELECT 1 FROM blobs WHERE sha256 = ?", [&sha], |_| Ok(true))
            .optional()?
            .unwrap_or(false);
        if !exists {
            self.conn.execute(
                "INSERT OR IGNORE INTO blobs(sha256, size, created_at, data) VALUES (?, ?, ?, ?)",
                params![sha, data.len() as i64, fmt_ts(&Utc::now()), compress(data)?],
            )?;
        }
        Ok(sha)
    }

    pub fn get_blob(&self, sha: &str) -> Result<Option<Vec<u8>>> {
        let data: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT data FROM blobs WHERE sha256 = ?", [sha], |r| r.get(0))
            .optional()?;
        data.map(|d| decompress(&d)).transpose()
    }

    pub fn fim_get(&self, path: &str) -> Result<Option<FimRecord>> {
        Ok(self
            .conn
            .query_row(
                "SELECT path, sha256, size, mtime, mode, uid, blob_sha FROM fim_files WHERE path = ?",
                [path],
                |r| {
                    Ok(FimRecord {
                        path: r.get(0)?,
                        sha256: r.get(1)?,
                        size: r.get::<_, i64>(2)? as u64,
                        mtime: r.get(3)?,
                        mode: r.get::<_, Option<i64>>(4)?.map(|v| v as u32),
                        uid: r.get::<_, Option<i64>>(5)?.map(|v| v as u32),
                        blob_sha: r.get(6)?,
                    })
                },
            )
            .optional()?)
    }

    pub fn fim_put(&self, rec: &FimRecord) -> Result<()> {
        self.conn.execute(
            "INSERT INTO fim_files(path, sha256, size, mtime, mode, uid, blob_sha) VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256, size=excluded.size, mtime=excluded.mtime,
               mode=excluded.mode, uid=excluded.uid, blob_sha=excluded.blob_sha",
            params![
                rec.path,
                rec.sha256,
                rec.size as i64,
                rec.mtime,
                rec.mode.map(|v| v as i64),
                rec.uid.map(|v| v as i64),
                rec.blob_sha
            ],
        )?;
        Ok(())
    }

    pub fn fim_delete(&self, path: &str) -> Result<()> {
        self.conn.execute("DELETE FROM fim_files WHERE path = ?", [path])?;
        Ok(())
    }

    pub fn fim_paths(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT path FROM fim_files")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn fim_begin(&self) -> Result<()> {
        self.conn.execute_batch("BEGIN")?;
        Ok(())
    }

    pub fn fim_commit(&self) -> Result<()> {
        self.conn.execute_batch("COMMIT")?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Integrity and retention
    // ------------------------------------------------------------------

    pub fn verify_chain(&self) -> Result<VerifyReport> {
        let anchor = self.get_state("chain.anchor")?;
        let mut report = VerifyReport::default();
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, host, category, action, outcome, severity, user, src_ip, session_id, process, target,
                    message, details, before_sha, after_sha, prev_hash, hash
             FROM events ORDER BY id ASC",
        )?;
        let mut rows = stmt.query([])?;
        let mut expected_prev: Option<String> = None;
        let mut last_id: Option<i64> = None;
        while let Some(r) = rows.next()? {
            let id: i64 = r.get(0)?;
            let row = EventRow {
                ts: r.get(1)?,
                host: r.get(2)?,
                category: r.get(3)?,
                action: r.get(4)?,
                outcome: r.get(5)?,
                severity: r.get(6)?,
                user: r.get(7)?,
                src_ip: r.get(8)?,
                session_id: r.get(9)?,
                process: r.get(10)?,
                target: r.get(11)?,
                message: r.get(12)?,
                details: r.get(13)?,
                before_sha: r.get(14)?,
                after_sha: r.get(15)?,
            };
            let prev: String = r.get(16)?;
            let stored: String = r.get(17)?;

            match &expected_prev {
                None => {
                    report.first_id = Some(id);
                    let ok_start = prev == GENESIS_HASH || anchor.as_deref() == Some(prev.as_str());
                    if !ok_start {
                        report.problems.push(format!(
                            "event {id}: chain does not start at genesis or the recorded retention anchor \
                             (rows before it were removed outside of retention pruning)"
                        ));
                    }
                }
                Some(exp) if *exp != prev => {
                    report.problems.push(format!(
                        "event {id}: previous-hash link broken (a row before it was deleted or altered)"
                    ));
                }
                _ => {}
            }
            if let Some(l) = last_id {
                if id != l + 1 && report.problems.len() < 50 {
                    report.problems.push(format!("events {}..{} are missing", l + 1, id - 1));
                }
            }
            let recomputed = row.hash(&prev);
            if recomputed != stored {
                report.problems.push(format!("event {id}: content does not match its hash (row was modified)"));
            }
            expected_prev = Some(stored);
            last_id = Some(id);
            report.rows_checked += 1;
        }
        report.last_id = last_id;
        Ok(report)
    }

    /// Deletes events and ended sessions older than the retention window,
    /// and file-content blobs nothing references any more. Records the
    /// chain anchor so `verify` still passes after pruning.
    pub fn prune(&mut self, retention_days: u32) -> Result<usize> {
        let cutoff = fmt_ts(&(Utc::now() - chrono::Duration::days(retention_days as i64)));
        let tx = self.conn.transaction()?;
        let boundary: Option<(i64, String)> = tx
            .query_row(
                "SELECT id, hash FROM events WHERE ts < ? ORDER BY id DESC LIMIT 1",
                [&cutoff],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let mut deleted = 0;
        if let Some((max_id, hash)) = boundary {
            // Prune by id (not ts) so the surviving rows are a contiguous
            // suffix of the chain even if clocks jumped.
            deleted = tx.execute("DELETE FROM events WHERE id <= ?", [max_id])?;
            tx.execute(
                "INSERT INTO state(key, value) VALUES ('chain.anchor', ?)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [&hash],
            )?;
        }
        tx.execute("DELETE FROM sessions WHERE status = 'ended' AND end_ts < ?", [&cutoff])?;
        let blob_cutoff = fmt_ts(&(Utc::now() - chrono::Duration::days(1)));
        tx.execute(
            "DELETE FROM blobs WHERE created_at < ?
               AND sha256 NOT IN (SELECT blob_sha FROM fim_files WHERE blob_sha IS NOT NULL)
               AND sha256 NOT IN (SELECT before_sha FROM events WHERE before_sha IS NOT NULL)
               AND sha256 NOT IN (SELECT after_sha FROM events WHERE after_sha IS NOT NULL)",
            [&blob_cutoff],
        )?;
        tx.commit()?;
        Ok(deleted)
    }
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

fn push_filter(sql: &mut String, args: &mut Vec<rusqlite::types::Value>, f: &Filter) {
    let col = match f.field {
        Field::User => "user",
        Field::SrcIp => "src_ip",
        Field::Action => "action",
        Field::Category => "category",
        Field::Session => "session_id",
        Field::Target => "target",
        Field::Host => "host",
        Field::Process => "process_name",
        Field::Command => "command_line",
        Field::Outcome => "outcome",
        Field::Pid => "pid",
        Field::Id => "id",
    };
    let numeric = matches!(f.field, Field::Pid | Field::Id);
    let wildcard = f.value.contains('*');
    match (&f.op, numeric, wildcard) {
        (FilterOp::Eq, true, _) | (FilterOp::Ne, true, _) => {
            let op = if f.op == FilterOp::Eq { "=" } else { "!=" };
            sql.push_str(&format!(" AND {col} {op} ?"));
            args.push(f.value.parse::<i64>().unwrap_or(-1).into());
        }
        (FilterOp::Eq, false, false) => {
            sql.push_str(&format!(" AND lower({col}) = lower(?)"));
            args.push(f.value.clone().into());
        }
        (FilterOp::Ne, false, false) => {
            sql.push_str(&format!(" AND ({col} IS NULL OR lower({col}) != lower(?))"));
            args.push(f.value.clone().into());
        }
        (op, false, true) => {
            let like = escape_like(&f.value).replace('*', "%");
            if *op == FilterOp::Eq {
                sql.push_str(&format!(" AND {col} LIKE ? ESCAPE '\\'"));
            } else {
                sql.push_str(&format!(" AND ({col} IS NULL OR {col} NOT LIKE ? ESCAPE '\\')"));
            }
            args.push(like.into());
        }
    }
}

/// The database holds command lines and file contents: owner-only.
fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        // On Windows the data directory inherits ProgramData ACLs from the
        // installer (Administrators/SYSTEM only).
        let _ = path;
    }
}

/// Write handle valid for one `write_batch` transaction.
pub struct Writer<'a> {
    tx: Transaction<'a>,
    last_hash: String,
}

impl Writer<'_> {
    pub fn insert_event(&mut self, ev: &mut Event) -> Result<i64> {
        let row = EventRow::from_event(ev)?;
        let hash = row.hash(&self.last_hash);
        self.tx.execute(
            "INSERT INTO events(ts, host, category, action, outcome, severity, user, src_ip, session_id, pid,
                 process_name, command_line, process, target, message, details, before_sha, after_sha, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
            params![
                row.ts,
                row.host,
                row.category,
                row.action,
                row.outcome,
                row.severity,
                row.user,
                row.src_ip,
                row.session_id,
                ev.process.as_ref().map(|p| p.pid as i64),
                ev.process.as_ref().map(|p| p.name.clone()),
                ev.command_line(),
                row.process,
                row.target,
                row.message,
                row.details,
                row.before_sha,
                row.after_sha,
                self.last_hash,
                hash
            ],
        )?;
        let id = self.tx.last_insert_rowid();
        ev.id = Some(id);
        ev.hash = Some(hash.clone());
        self.last_hash = hash;
        Ok(id)
    }

    pub fn upsert_session(&mut self, s: &Session, host: &str) -> Result<()> {
        self.tx.execute(
            &format!(
                "INSERT INTO sessions(host, {SESSION_COLS}) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
                 ON CONFLICT(id) DO UPDATE SET user=excluded.user, protocol=excluded.protocol, src_ip=excluded.src_ip,
                   src_port=excluded.src_port, auth_method=excluded.auth_method, key_fingerprint=excluded.key_fingerprint,
                   start_ts=excluded.start_ts, end_ts=excluded.end_ts, last_activity=excluded.last_activity,
                   status=excluded.status, end_reason=excluded.end_reason, keys=excluded.keys, base_keys=excluded.base_keys,
                   commands=excluded.commands, privileged=excluded.privileged, file_changes=excluded.file_changes,
                   alerts=excluded.alerts, max_severity=excluded.max_severity"
            ),
            params![
                host,
                s.id,
                s.user,
                s.protocol,
                s.src_ip,
                s.src_port.map(|p| p as i64),
                s.auth_method,
                s.key_fingerprint,
                fmt_ts(&s.start),
                s.end.as_ref().map(fmt_ts),
                fmt_ts(&s.last_activity),
                s.status.as_str(),
                s.end_reason,
                serde_json::to_string(&s.keys)?,
                s.base_keys as i64,
                s.commands as i64,
                s.privileged as i64,
                s.file_changes as i64,
                s.alerts as i64,
                s.max_severity.as_i64()
            ],
        )?;
        Ok(())
    }

    pub fn set_state(&mut self, key: &str, value: &str) -> Result<()> {
        self.tx.execute(
            "INSERT INTO state(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

impl SourceHistory for Writer<'_> {
    fn record_login(&mut self, user: &str, src_ip: &str, ts: DateTime<Utc>) -> Result<Option<usize>> {
        let user = user.to_ascii_lowercase();
        let updated = self.tx.execute(
            "UPDATE known_sources SET last_seen = ?, count = count + 1 WHERE user = ? AND src_ip = ?",
            params![fmt_ts(&ts), user, src_ip],
        )?;
        if updated > 0 {
            return Ok(None);
        }
        let prior: i64 = self
            .tx
            .query_row("SELECT COUNT(*) FROM known_sources WHERE user = ?", [&user], |r| r.get(0))?;
        self.tx.execute(
            "INSERT INTO known_sources(user, src_ip, first_seen, last_seen, count) VALUES (?, ?, ?, ?, 1)",
            params![user, src_ip, fmt_ts(&ts), fmt_ts(&ts)],
        )?;
        Ok(Some(prior as usize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::Query;

    fn ev(action: &str, msg: &str) -> Event {
        let mut e = Event::new(Category::Auth, action, msg).user("alice").src_ip("10.1.2.3");
        e.host = "web1".into();
        e
    }

    #[test]
    fn insert_query_and_verify_chain() {
        let mut store = EventStore::open_in_memory().unwrap();
        store
            .write_batch(|w| {
                for i in 0..5 {
                    let mut e = ev("auth.failure", &format!("Failed password attempt {i} for alice"));
                    w.insert_event(&mut e)?;
                }
                let mut e = Event::new(Category::Process, "process.start", "Executed vim /etc/nginx/nginx.conf")
                    .process(ProcessInfo {
                        pid: 42,
                        name: "vim".into(),
                        command_line: Some("vim /etc/nginx/nginx.conf".into()),
                        ..Default::default()
                    });
                e.host = "web1".into();
                w.insert_event(&mut e)?;
                Ok(())
            })
            .unwrap();

        let all = store.query(&Query::parse("").unwrap()).unwrap();
        assert_eq!(all.len(), 6);
        let fails = store.query(&Query::parse("action=auth.* user=ALICE").unwrap()).unwrap();
        assert_eq!(fails.len(), 5);
        let fts = store.query(&Query::parse("nginx.conf").unwrap()).unwrap();
        assert_eq!(fts.len(), 1);
        assert_eq!(fts[0].process.as_ref().unwrap().pid, 42);
        let by_proc = store.query(&Query::parse("process=vim").unwrap()).unwrap();
        assert_eq!(by_proc.len(), 1);

        let report = store.verify_chain().unwrap();
        assert_eq!(report.rows_checked, 6);
        assert!(report.problems.is_empty(), "{:?}", report.problems);

        // Tamper with a row: verify must notice.
        store
            .conn
            .execute("UPDATE events SET message = 'nothing to see here' WHERE id = 3", [])
            .unwrap();
        let report = store.verify_chain().unwrap();
        assert!(report.problems.iter().any(|p| p.contains("event 3")), "{:?}", report.problems);
    }

    #[test]
    fn deleting_a_row_breaks_the_chain() {
        let mut store = EventStore::open_in_memory().unwrap();
        store
            .write_batch(|w| {
                for _ in 0..4 {
                    w.insert_event(&mut ev("auth.failure", "x"))?;
                }
                Ok(())
            })
            .unwrap();
        store.conn.execute("DELETE FROM events WHERE id = 2", []).unwrap();
        let report = store.verify_chain().unwrap();
        assert!(!report.problems.is_empty());
    }

    #[test]
    fn prune_keeps_chain_verifiable() {
        let mut store = EventStore::open_in_memory().unwrap();
        store
            .write_batch(|w| {
                for i in 0..6 {
                    let mut e = ev("auth.failure", "x");
                    e.ts = Utc::now() - chrono::Duration::days(if i < 3 { 40 } else { 1 });
                    w.insert_event(&mut e)?;
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(store.prune(30).unwrap(), 3);
        let report = store.verify_chain().unwrap();
        assert_eq!(report.rows_checked, 3);
        assert!(report.problems.is_empty(), "{:?}", report.problems);
    }

    #[test]
    fn blobs_roundtrip_and_dedupe() {
        let store = EventStore::open_in_memory().unwrap();
        let a = store.put_blob(b"worker_processes 4;\n").unwrap();
        let b = store.put_blob(b"worker_processes 4;\n").unwrap();
        assert_eq!(a, b);
        assert_eq!(store.get_blob(&a).unwrap().unwrap(), b"worker_processes 4;\n");
        assert!(store.get_blob("nope").unwrap().is_none());
    }

    #[test]
    fn known_sources_detects_new_ip() {
        let mut store = EventStore::open_in_memory().unwrap();
        let (first, repeat, second) = store
            .write_batch(|w| {
                let now = Utc::now();
                Ok((
                    w.record_login("alice", "10.0.0.1", now)?,
                    w.record_login("ALICE", "10.0.0.1", now)?,
                    w.record_login("alice", "203.0.113.7", now)?,
                ))
            })
            .unwrap();
        assert_eq!(first, Some(0));
        assert_eq!(repeat, None);
        assert_eq!(second, Some(1));
    }
}
