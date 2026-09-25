//! Restart- and rotation-safe log file tailer.
//!
//! - Resumes exactly where it left off across agent restarts via a
//!   checkpoint (`dev:inode:offset`) persisted by the pipeline in the same
//!   transaction as the events it produced.
//! - Follows logrotate's rename-and-recreate: finishes reading the old
//!   file through the still-open handle, then switches to the new one.
//! - Detects in-place truncation (copytruncate, or someone running
//!   `> /var/log/auth.log`) and reports it — on an auth log that's a
//!   tampering signal, not just a rotation detail.

use anyhow::Result;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const MAX_READ_PER_POLL: usize = 8 * 1024 * 1024;
const MAX_LINE: usize = 64 * 1024;

type Identity = (u64, u64);

fn identity(meta: &std::fs::Metadata) -> Identity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (meta.dev(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        (0, 0)
    }
}

#[derive(Debug, Default)]
pub struct TailBatch {
    pub lines: Vec<String>,
    pub truncated: bool,
    pub rotated: bool,
}

pub struct FileTailer {
    path: PathBuf,
    file: Option<File>,
    ident: Identity,
    offset: u64,
    partial: Vec<u8>,
}

fn parse_checkpoint(s: &str) -> Option<(Identity, u64)> {
    let mut it = s.split(':');
    let dev = it.next()?.parse().ok()?;
    let ino = it.next()?.parse().ok()?;
    let off = it.next()?.parse().ok()?;
    Some(((dev, ino), off))
}

impl FileTailer {
    /// `checkpoint`: value previously returned by `checkpoint()`.
    /// `backfill`: with no checkpoint, read the existing content instead
    /// of starting at the end.
    pub fn open(path: &Path, checkpoint: Option<&str>, backfill: bool) -> Self {
        let mut t = Self {
            path: path.to_path_buf(),
            file: None,
            ident: (0, 0),
            offset: 0,
            partial: Vec::new(),
        };
        if let Ok(mut f) = File::open(path) {
            if let Ok(meta) = f.metadata() {
                let id = identity(&meta);
                let start = match checkpoint.and_then(parse_checkpoint) {
                    Some((cid, off)) if cid == id && off <= meta.len() => off,
                    // Rotated (or truncated) while we were down: everything
                    // in the current file is new to us.
                    Some(_) => 0,
                    None if backfill => 0,
                    None => meta.len(),
                };
                if f.seek(SeekFrom::Start(start)).is_ok() {
                    t.ident = id;
                    t.offset = start;
                    t.file = Some(f);
                }
            }
        }
        t
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn checkpoint(&self) -> String {
        // Only whole lines count as consumed.
        let off = self.offset.saturating_sub(self.partial.len() as u64);
        format!("{}:{}:{}", self.ident.0, self.ident.1, off)
    }

    fn read_available(&mut self, batch: &mut TailBatch) -> Result<()> {
        let Some(f) = self.file.as_mut() else { return Ok(()) };
        let mut buf = Vec::new();
        let n = f.by_ref().take(MAX_READ_PER_POLL as u64).read_to_end(&mut buf)?;
        self.offset += n as u64;
        self.partial.extend_from_slice(&buf);
        let mut start = 0;
        for i in 0..self.partial.len() {
            if self.partial[i] == b'\n' {
                let line = &self.partial[start..i];
                if !line.is_empty() {
                    batch.lines.push(String::from_utf8_lossy(&line[..line.len().min(MAX_LINE)]).into_owned());
                }
                start = i + 1;
            }
        }
        self.partial.drain(..start);
        if self.partial.len() > MAX_LINE {
            // A "line" this long isn't a log line; drop it rather than grow.
            self.partial.clear();
        }
        Ok(())
    }

    pub fn poll(&mut self) -> Result<TailBatch> {
        let mut batch = TailBatch::default();

        if self.file.is_none() {
            // File didn't exist yet (or vanished): anything that appears
            // now is new.
            if let Ok(f) = File::open(&self.path) {
                self.ident = f.metadata().map(|m| identity(&m)).unwrap_or((0, 0));
                self.offset = 0;
                self.partial.clear();
                self.file = Some(f);
            } else {
                return Ok(batch);
            }
        }

        if let Some(len) = self.file.as_ref().and_then(|f| f.metadata().ok()).map(|m| m.len()) {
            if len < self.offset {
                batch.truncated = true;
                self.offset = 0;
                self.partial.clear();
                if let Some(f) = self.file.as_mut() {
                    f.seek(SeekFrom::Start(0))?;
                }
            }
        }

        self.read_available(&mut batch)?;

        if cfg!(unix) {
            if let Ok(meta) = std::fs::metadata(&self.path) {
                let id = identity(&meta);
                if id != self.ident {
                    // Drain anything written to the old file between our
                    // read and the rename, then switch.
                    self.read_available(&mut batch)?;
                    if let Ok(f) = File::open(&self.path) {
                        self.file = Some(f);
                        self.ident = id;
                        self.offset = 0;
                        self.partial.clear();
                        batch.rotated = true;
                        self.read_available(&mut batch)?;
                    }
                }
            }
        }
        Ok(batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn append(p: &Path, s: &str) {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(p).unwrap();
        f.write_all(s.as_bytes()).unwrap();
    }

    #[test]
    fn follows_appends_partial_lines_and_checkpoints() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("auth.log");
        append(&p, "old line\n");
        let mut t = FileTailer::open(&p, None, false);
        assert!(t.poll().unwrap().lines.is_empty(), "starts at end without backfill");
        append(&p, "one\ntw");
        assert_eq!(t.poll().unwrap().lines, vec!["one"]);
        let cp = t.checkpoint();
        append(&p, "o\n");
        assert_eq!(t.poll().unwrap().lines, vec!["two"]);

        // Restart from the mid-line checkpoint: re-reads the partial line whole.
        let mut t2 = FileTailer::open(&p, Some(&cp), false);
        assert_eq!(t2.poll().unwrap().lines, vec!["two"]);

        let mut t3 = FileTailer::open(&p, None, true);
        assert_eq!(t3.poll().unwrap().lines, vec!["old line", "one", "two"]);
    }

    #[test]
    fn detects_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("auth.log");
        append(&p, "a\nb\n");
        let mut t = FileTailer::open(&p, None, true);
        t.poll().unwrap();
        std::fs::write(&p, "c\n").unwrap();
        let b = t.poll().unwrap();
        assert!(b.truncated);
        assert_eq!(b.lines, vec!["c"]);
    }

    #[cfg(unix)]
    #[test]
    fn follows_rename_rotation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("auth.log");
        append(&p, "");
        let mut t = FileTailer::open(&p, None, false);
        append(&p, "before-rotate\n");
        std::fs::rename(&p, dir.path().join("auth.log.1")).unwrap();
        append(&dir.path().join("auth.log.1"), "late-write-to-old\n");
        append(&p, "after-rotate\n");
        let b = t.poll().unwrap();
        assert!(b.rotated);
        assert_eq!(b.lines, vec!["before-rotate", "late-write-to-old", "after-rotate"]);
    }
}
