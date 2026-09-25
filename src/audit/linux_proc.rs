//! Linux process-execution auditing: *what people actually ran*.
//!
//! Primary source is the kernel **proc connector** (netlink
//! `NETLINK_CONNECTOR` / `CN_IDX_PROC`): the kernel pushes an event on
//! every `exec()`, so even sub-second commands (`cat`, `cp`, `sed -i`) are
//! seen — polling would miss most of them. It needs root (CAP_NET_ADMIN)
//! and the host network namespace; the monitor self-tests at startup and
//! falls back to `/proc` polling if events don't arrive.
//!
//! Each exec is enriched from `/proc/<pid>` with the fields that make it
//! attributable:
//! - `loginuid` — the *human* who logged in, preserved across sudo/su
//!   (set by pam_loginuid at login and immutable afterwards)
//! - audit `sessionid` — one per login, inherited by every descendant
//! - controlling TTY — matches the `TTY=` in sudo log lines
//! - pid ancestry — links the process to the sshd pid in the auth log
//!
//! The /proc parsing is plain file I/O and compiles/tests on every
//! platform against a fake proc tree; only the netlink socket is
//! Linux-specific.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::core::config::ProcessAuditConfig;
use crate::events::{Category, Event, EventBus, Outcome, ProcessInfo};
use anyhow::Result;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

const UNSET_ID: u32 = u32::MAX;
const MAX_ANCESTORS: usize = 16;
const MAX_CMDLINE: usize = 4096;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcSnapshot {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    pub cwd: Option<String>,
    pub uid: u32,
    pub euid: u32,
    pub loginuid: Option<u32>,
    pub audit_session: Option<u32>,
    pub tty: Option<String>,
    pub start_ticks: u64,
}

/// uid -> name from /etc/passwd, reloaded when the file changes.
pub struct UserDb {
    path: PathBuf,
    names: HashMap<u32, String>,
    mtime: Option<SystemTime>,
    checked: Instant,
}

impl UserDb {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let mut db = Self {
            path: path.into(),
            names: HashMap::new(),
            mtime: None,
            checked: Instant::now() - Duration::from_secs(3600),
        };
        db.refresh();
        db
    }

    fn refresh(&mut self) {
        self.checked = Instant::now();
        let mtime = std::fs::metadata(&self.path).and_then(|m| m.modified()).ok();
        if mtime.is_some() && mtime == self.mtime {
            return;
        }
        self.mtime = mtime;
        if let Ok(text) = std::fs::read_to_string(&self.path) {
            self.names = text
                .lines()
                .filter_map(|l| {
                    let mut f = l.split(':');
                    let name = f.next()?;
                    f.next()?;
                    let uid = f.next()?.parse().ok()?;
                    Some((uid, name.to_string()))
                })
                .collect();
        }
    }

    pub fn name(&mut self, uid: u32) -> String {
        if self.checked.elapsed() > Duration::from_secs(30) || (!self.names.contains_key(&uid) && self.checked.elapsed() > Duration::from_secs(2)) {
            self.refresh();
        }
        self.names.get(&uid).cloned().unwrap_or_else(|| uid.to_string())
    }
}

pub struct ProcReader {
    root: PathBuf,
    pub users: UserDb,
    self_pid: u32,
}

/// Linux encodes the controlling terminal as a dev_t in /proc/N/stat.
pub fn decode_tty(tty_nr: u64) -> Option<String> {
    if tty_nr == 0 {
        return None;
    }
    let major = (tty_nr >> 8) & 0xfff;
    let minor = (tty_nr & 0xff) | ((tty_nr >> 12) & 0xfff00);
    match major {
        136..=143 => Some(format!("pts/{}", minor + (major - 136) * 256)),
        4 if minor < 64 => Some(format!("tty{minor}")),
        4 => Some(format!("ttyS{}", minor - 64)),
        _ => None,
    }
}

/// Parses /proc/N/stat: `pid (comm) state ppid pgrp session tty_nr ...`.
/// comm may itself contain spaces and parentheses, so split on the *last*
/// ')'.
pub fn parse_stat(s: &str) -> Option<(String, u32, u64, u64)> {
    let open = s.find('(')?;
    let close = s.rfind(')')?;
    let comm = s.get(open + 1..close)?.to_string();
    let fields: Vec<&str> = s.get(close + 1..)?.split_whitespace().collect();
    let ppid = fields.get(1)?.parse().ok()?;
    let tty_nr = fields.get(4)?.parse().ok()?;
    let start = fields.get(19)?.parse().ok()?;
    Some((comm, ppid, tty_nr, start))
}

fn read_id(p: &Path) -> Option<u32> {
    std::fs::read_to_string(p)
        .ok()?
        .trim()
        .parse()
        .ok()
        .filter(|v| *v != UNSET_ID)
}

impl ProcReader {
    pub fn new(root: impl Into<PathBuf>, passwd: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            users: UserDb::new(passwd),
            self_pid: std::process::id(),
        }
    }

    fn p(&self, pid: u32, file: &str) -> PathBuf {
        self.root.join(pid.to_string()).join(file)
    }

    pub fn read(&self, pid: u32) -> Option<ProcSnapshot> {
        let stat = std::fs::read_to_string(self.p(pid, "stat")).ok()?;
        let (comm, ppid, tty_nr, start_ticks) = parse_stat(&stat)?;
        let status = std::fs::read_to_string(self.p(pid, "status")).unwrap_or_default();
        let (uid, euid) = status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .map(|rest| {
                let ids: Vec<u32> = rest.split_whitespace().filter_map(|v| v.parse().ok()).collect();
                (ids.first().copied().unwrap_or(0), ids.get(1).copied().unwrap_or(0))
            })
            .unwrap_or((0, 0));
        let cmdline = std::fs::read(self.p(pid, "cmdline")).ok().and_then(|raw| {
            let raw = &raw[..raw.len().min(MAX_CMDLINE)];
            let parts: Vec<String> = raw
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            (!parts.is_empty()).then(|| parts.join(" "))
        });
        let link = |f: &str| std::fs::read_link(self.p(pid, f)).ok().map(|l| l.display().to_string());
        Some(ProcSnapshot {
            pid,
            ppid,
            comm,
            exe: link("exe").map(|e| e.trim_end_matches(" (deleted)").to_string()),
            cmdline,
            cwd: link("cwd"),
            uid,
            euid,
            loginuid: read_id(&self.p(pid, "loginuid")),
            audit_session: read_id(&self.p(pid, "sessionid")),
            tty: decode_tty(tty_nr),
            start_ticks,
        })
    }

    /// (pid, comm) from the parent upwards.
    pub fn ancestors(&self, ppid: u32) -> Vec<(u32, String)> {
        let mut out = Vec::new();
        let mut cur = ppid;
        while cur > 1 && out.len() < MAX_ANCESTORS {
            let Some((comm, next, _, _)) = std::fs::read_to_string(self.p(cur, "stat")).ok().and_then(|s| parse_stat(&s)) else {
                break;
            };
            out.push((cur, comm));
            if next == cur {
                break;
            }
            cur = next;
        }
        out
    }

    /// Builds the event for a freshly exec'd process, or None if it's the
    /// agent's own helper (systemctl/journalctl we spawn) or a kernel
    /// thread.
    pub fn exec_event(&mut self, snap: &ProcSnapshot) -> Option<Event> {
        if snap.pid == self.self_pid || snap.ppid == 2 || snap.pid == 2 {
            return None;
        }
        let ancestors = self.ancestors(snap.ppid);
        if snap.ppid == self.self_pid || ancestors.iter().any(|(p, _)| *p == self.self_pid) {
            return None;
        }
        let run_as = self.users.name(snap.euid);
        let login_user = snap.loginuid.map(|u| self.users.name(u));
        let user = login_user.clone().unwrap_or_else(|| run_as.clone());
        let cmd = snap.cmdline.clone().unwrap_or_else(|| format!("[{}]", snap.comm));

        let mut ev = Event::new(Category::Process, "process.start", crate::util::truncate(&cmd, 1000))
            .outcome(Outcome::Success)
            .user(user)
            .process(ProcessInfo {
                pid: snap.pid,
                ppid: Some(snap.ppid),
                name: snap.comm.clone(),
                exe: snap.exe.clone(),
                command_line: snap.cmdline.clone(),
                cwd: snap.cwd.clone(),
                parent_name: ancestors.first().map(|(_, c)| c.clone()),
                run_as: Some(run_as),
            })
            .detail("uid", snap.uid)
            .detail("euid", snap.euid);
        if let Some(l) = snap.loginuid {
            ev.set_detail("loginuid", l);
            if snap.euid == 0 && l != 0 {
                ev.set_detail("elevated", true);
            }
        }
        for (pid, _) in &ancestors {
            ev.keys.push(format!("pid:{pid}"));
        }
        ev.learn.push(format!("pid:{}", snap.pid));
        if let Some(s) = snap.audit_session {
            ev.set_detail("audit_session", s);
            ev.keys.push(format!("ksid:{s}"));
            ev.learn.push(format!("ksid:{s}"));
        }
        if let Some(t) = &snap.tty {
            ev.set_detail("tty", t.clone());
            ev.keys.push(format!("tty:{t}"));
            ev.learn.push(format!("tty:{t}"));
        }
        Some(ev)
    }

    pub fn list_pids(&self) -> Vec<u32> {
        std::fs::read_dir(&self.root)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

pub fn spawn(cfg: &ProcessAuditConfig, bus: EventBus, running: Arc<AtomicBool>) -> Result<JoinHandle<()>> {
    let mode = cfg.mode.clone();
    let interval = Duration::from_millis(cfg.poll_interval_ms.max(200));
    Ok(std::thread::Builder::new().name("audit-exec".into()).spawn(move || {
        let mut reader = ProcReader::new("/proc", "/etc/passwd");
        #[cfg(target_os = "linux")]
        if mode == "auto" || mode == "netlink" {
            match netlink::ProcConnector::open_verified() {
                Ok(conn) => {
                    tracing::info!("process auditing: kernel proc connector (every exec, real time)");
                    run_netlink(conn, &mut reader, &bus, &running);
                    return;
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "kernel proc connector unavailable (needs root in the host network namespace); \
                     falling back to /proc polling — commands shorter than the poll interval may be missed"
                ),
            }
        }
        let _ = &mode;
        tracing::info!(interval_ms = interval.as_millis() as u64, "process auditing: /proc polling");
        run_poll(&mut reader, interval, &bus, &running);
    })?)
}

fn run_poll(reader: &mut ProcReader, interval: Duration, bus: &EventBus, running: &AtomicBool) {
    // Seed with what's already running: those started before the agent.
    let mut known: HashMap<u32, u64> = reader
        .list_pids()
        .into_iter()
        .filter_map(|p| reader.read(p).map(|s| (p, s.start_ticks)))
        .collect();
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(interval);
        let pids = reader.list_pids();
        let mut next = HashMap::with_capacity(pids.len());
        let mut fresh = Vec::new();
        for pid in pids {
            let prev = known.get(&pid).copied();
            match reader.read(pid) {
                Some(snap) => {
                    if prev != Some(snap.start_ticks) {
                        fresh.push(snap.clone());
                    }
                    next.insert(pid, snap.start_ticks);
                }
                None => continue,
            }
        }
        // Parents before children so ancestry-based attribution chains.
        fresh.sort_by_key(|s| s.start_ticks);
        for snap in fresh {
            if let Some(ev) = reader.exec_event(&snap) {
                if !bus.emit(ev) {
                    return;
                }
            }
        }
        known = next;
    }
}

#[cfg(target_os = "linux")]
fn run_netlink(conn: netlink::ProcConnector, reader: &mut ProcReader, bus: &EventBus, running: &AtomicBool) {
    let mut overruns = 0u64;
    let mut last_warn = Instant::now() - Duration::from_secs(3600);
    while running.load(Ordering::SeqCst) {
        match conn.recv_execs() {
            Ok(pids) => {
                for pid in pids {
                    // The process may already have exited; nothing to
                    // attribute then.
                    if let Some(snap) = reader.read(pid) {
                        if let Some(ev) = reader.exec_event(&snap) {
                            if !bus.emit(ev) {
                                return;
                            }
                        }
                    }
                }
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                overruns += 1;
                if last_warn.elapsed() > Duration::from_secs(300) {
                    tracing::warn!(overruns, "exec events arrived faster than they could be read; some were dropped");
                    last_warn = Instant::now();
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "proc connector read failed; switching to polling");
                run_poll(reader, Duration::from_millis(1000), bus, running);
                return;
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod netlink {
    use std::io;
    use std::mem::size_of;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    const NETLINK_CONNECTOR: libc::c_int = 11;
    const CN_IDX_PROC: u32 = 1;
    const CN_VAL_PROC: u32 = 1;
    const PROC_CN_MCAST_LISTEN: u32 = 1;
    const PROC_EVENT_EXEC: u32 = 0x0000_0002;
    const NLMSG_DONE: u16 = 3;
    const NLMSG_HDRLEN: usize = 16;
    const CN_MSG_LEN: usize = 20;

    pub struct ProcConnector {
        fd: OwnedFd,
    }

    impl ProcConnector {
        fn open() -> io::Result<Self> {
            // SAFETY: plain socket(2)/bind(2)/setsockopt(2)/send(2) calls
            // with correctly sized, initialised arguments; the fd is owned
            // by OwnedFd immediately so it can't leak.
            unsafe {
                let raw = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, NETLINK_CONNECTOR);
                if raw < 0 {
                    return Err(io::Error::last_os_error());
                }
                let fd = OwnedFd::from_raw_fd(raw);
                let mut addr: libc::sockaddr_nl = std::mem::zeroed();
                addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
                addr.nl_groups = CN_IDX_PROC;
                addr.nl_pid = 0;
                if libc::bind(fd.as_raw_fd(), &addr as *const _ as *const libc::sockaddr, size_of::<libc::sockaddr_nl>() as u32) < 0 {
                    return Err(io::Error::last_os_error());
                }
                let rcvbuf: libc::c_int = 8 * 1024 * 1024;
                // SO_RCVBUFFORCE (root) first, SO_RCVBUF as a fallback.
                if libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUFFORCE, &rcvbuf as *const _ as *const libc::c_void, 4) < 0 {
                    libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVBUF, &rcvbuf as *const _ as *const libc::c_void, 4);
                }
                let tv = libc::timeval { tv_sec: 1, tv_usec: 0 };
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const libc::c_void,
                    size_of::<libc::timeval>() as u32,
                );

                let mut msg = Vec::with_capacity(NLMSG_HDRLEN + CN_MSG_LEN + 4);
                let total = (NLMSG_HDRLEN + CN_MSG_LEN + 4) as u32;
                msg.extend_from_slice(&total.to_ne_bytes());
                msg.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
                msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
                msg.extend_from_slice(&0u32.to_ne_bytes()); // seq
                msg.extend_from_slice(&(libc::getpid() as u32).to_ne_bytes());
                msg.extend_from_slice(&CN_IDX_PROC.to_ne_bytes());
                msg.extend_from_slice(&CN_VAL_PROC.to_ne_bytes());
                msg.extend_from_slice(&0u32.to_ne_bytes()); // seq
                msg.extend_from_slice(&0u32.to_ne_bytes()); // ack
                msg.extend_from_slice(&4u16.to_ne_bytes()); // len
                msg.extend_from_slice(&0u16.to_ne_bytes()); // flags
                msg.extend_from_slice(&PROC_CN_MCAST_LISTEN.to_ne_bytes());
                if libc::send(fd.as_raw_fd(), msg.as_ptr() as *const libc::c_void, msg.len(), 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self { fd })
            }
        }

        /// Subscribes, then proves events actually flow by exec'ing a
        /// trivial child and waiting to see it. (Inside a container's own
        /// network namespace the subscription succeeds but is silent.)
        pub fn open_verified() -> io::Result<Self> {
            let conn = Self::open()?;
            let child = std::process::Command::new("/bin/true").spawn()?;
            let target = child.id();
            let mut child = child;
            let _ = child.wait();
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                match conn.recv_execs() {
                    Ok(pids) if pids.contains(&target) => return Ok(conn),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
            }
            Err(io::Error::new(io::ErrorKind::TimedOut, "subscribed but no exec events arrived"))
        }

        /// Blocks up to 1s; returns the pids that exec'd.
        pub fn recv_execs(&self) -> io::Result<Vec<u32>> {
            let mut buf = vec![0u8; 64 * 1024];
            // SAFETY: buf is valid for buf.len() bytes for the call.
            let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n < 0 {
                let err = io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(libc::EAGAIN) | Some(libc::EINTR) => Ok(Vec::new()),
                    _ => Err(err),
                };
            }
            Ok(parse_messages(&buf[..n as usize]))
        }
    }

    fn u32_at(b: &[u8], off: usize) -> Option<u32> {
        Some(u32::from_ne_bytes(b.get(off..off + 4)?.try_into().ok()?))
    }

    pub fn parse_messages(buf: &[u8]) -> Vec<u32> {
        let mut out = Vec::new();
        let mut off = 0;
        while off + NLMSG_HDRLEN <= buf.len() {
            let Some(len) = u32_at(buf, off).map(|l| l as usize) else { break };
            if len < NLMSG_HDRLEN || off + len > buf.len() {
                break;
            }
            let payload = off + NLMSG_HDRLEN;
            let ev = payload + CN_MSG_LEN;
            // proc_event: what(u32) cpu(u32) timestamp_ns(u64) then the
            // union; exec = { process_pid, process_tgid }.
            if let (Some(what), Some(pid), Some(tgid)) = (u32_at(buf, ev), u32_at(buf, ev + 16), u32_at(buf, ev + 20)) {
                if what == PROC_EVENT_EXEC && pid == tgid {
                    out.push(pid);
                }
            }
            off += (len + 3) & !3;
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// nlmsghdr + cn_msg + proc_event{what, cpu, ts, pid, tgid}, laid
        /// out exactly as the kernel sends it.
        fn frame(what: u32, pid: u32, tgid: u32) -> Vec<u8> {
            let mut m = Vec::new();
            m.extend(((NLMSG_HDRLEN + CN_MSG_LEN + 24) as u32).to_ne_bytes());
            m.extend(NLMSG_DONE.to_ne_bytes());
            m.extend(0u16.to_ne_bytes());
            m.extend(0u32.to_ne_bytes());
            m.extend(0u32.to_ne_bytes());
            m.extend(CN_IDX_PROC.to_ne_bytes());
            m.extend(CN_VAL_PROC.to_ne_bytes());
            m.extend(0u32.to_ne_bytes());
            m.extend(0u32.to_ne_bytes());
            m.extend(24u16.to_ne_bytes());
            m.extend(0u16.to_ne_bytes());
            m.extend(what.to_ne_bytes());
            m.extend(3u32.to_ne_bytes()); // cpu
            m.extend(123_456_789u64.to_ne_bytes()); // timestamp_ns
            m.extend(pid.to_ne_bytes());
            m.extend(tgid.to_ne_bytes());
            m
        }

        #[test]
        fn extracts_process_exec_events_only() {
            let mut buf = frame(PROC_EVENT_EXEC, 42, 42);
            buf.extend(frame(0x1, 43, 43)); // fork
            buf.extend(frame(PROC_EVENT_EXEC, 44, 40)); // a thread, not a process
            buf.extend(frame(PROC_EVENT_EXEC, 45, 45));
            assert_eq!(parse_messages(&buf), vec![42, 45]);
            assert!(parse_messages(&buf[..10]).is_empty(), "truncated frame is ignored");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn fake_proc(root: &Path, pid: u32, ppid: u32, comm: &str, cmd: &[&str], uid: u32, euid: u32, login: u32, ses: u32, tty_nr: u64) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("stat"),
            format!("{pid} ({comm}) S {ppid} {pid} {pid} {tty_nr} -1 4194560 100 0 0 0 0 0 0 0 20 0 1 0 {} 1000 100", 5000 + pid),
        )
        .unwrap();
        std::fs::write(d.join("status"), format!("Name:\t{comm}\nUid:\t{uid}\t{euid}\t{euid}\t{euid}\n")).unwrap();
        let mut raw = Vec::new();
        for c in cmd {
            raw.extend_from_slice(c.as_bytes());
            raw.push(0);
        }
        std::fs::write(d.join("cmdline"), raw).unwrap();
        std::fs::write(d.join("loginuid"), login.to_string()).unwrap();
        std::fs::write(d.join("sessionid"), ses.to_string()).unwrap();
    }

    #[test]
    fn stat_and_tty_parsing() {
        let (comm, ppid, tty, start) =
            parse_stat("4321 (tmux: server (1)) S 1 4321 4321 34816 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 987654 0 0").unwrap();
        assert_eq!((comm.as_str(), ppid, start), ("tmux: server (1)", 1, 987654));
        assert_eq!(decode_tty(tty).as_deref(), Some("pts/0"));
        assert_eq!(decode_tty(34817).as_deref(), Some("pts/1"));
        assert_eq!(decode_tty(1025).as_deref(), Some("tty1"));
        assert_eq!(decode_tty(0), None);
    }

    #[test]
    fn exec_event_attribution_fields() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path().join("proc");
        let passwd = dir.path().join("passwd");
        std::fs::write(&passwd, "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n").unwrap();
        // sshd(4000) -> sshd: alice@pts/0 (4001) -> bash (4010) -> sudo (4020) -> vim (4030)
        fake_proc(&proc, 4000, 1, "sshd", &["sshd: alice [priv]"], 0, 0, 1000, 7, 0);
        fake_proc(&proc, 4001, 4000, "sshd", &["sshd: alice@pts/0"], 1000, 1000, 1000, 7, 0);
        fake_proc(&proc, 4010, 4001, "bash", &["-bash"], 1000, 1000, 1000, 7, 34816);
        fake_proc(&proc, 4020, 4010, "sudo", &["sudo", "vim", "/etc/hosts"], 1000, 0, 1000, 7, 34816);
        fake_proc(&proc, 4030, 4020, "vim", &["vim", "/etc/hosts"], 0, 0, 1000, 7, 34816);
        fake_proc(&proc, 900, 1, "cron", &["/usr/sbin/cron", "-f"], 0, 0, UNSET_ID, UNSET_ID, 0);

        let mut r = ProcReader::new(&proc, &passwd);
        // The test runner's real pid must not collide with the fake tree.
        r.self_pid = u32::MAX - 1;
        let snap = r.read(4030).unwrap();
        assert_eq!(snap.cmdline.as_deref(), Some("vim /etc/hosts"));
        let ev = r.exec_event(&snap).unwrap();
        assert_eq!(ev.user.as_deref(), Some("alice"), "loginuid survives sudo");
        let p = ev.process.as_ref().unwrap();
        assert_eq!((p.run_as.as_deref(), p.parent_name.as_deref()), (Some("root"), Some("sudo")));
        assert_eq!(ev.details["elevated"], true);
        for k in ["pid:4020", "pid:4010", "pid:4001", "pid:4000", "ksid:7", "tty:pts/0"] {
            assert!(ev.keys.contains(&k.to_string()), "missing key {k}: {:?}", ev.keys);
        }
        assert!(ev.learn.contains(&"pid:4030".to_string()));

        let daemon = r.exec_event(&r.read(900).unwrap()).unwrap();
        assert_eq!(daemon.user.as_deref(), Some("root"));
        assert!(!daemon.keys.iter().any(|k| k.starts_with("ksid:")), "unset audit session is not a key");
        assert_eq!(r.list_pids().len(), 6);
    }
}
