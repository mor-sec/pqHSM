//! The open log: one numbered file per opening, group-committed appends (RULE-094, RULE-096).

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::Zeroizing;

use crate::KEY_LEN;
use crate::chain;
use crate::record::{Fields, Role, finish_line, render_body, render_params, sanitize_actor};

/// Digits in the `base.NNNNNN` suffix.
pub const SEQ_DIGITS: usize = 6;

/// `O_EXCL` collisions tolerated before `open` gives up (`src/fhsm_audit.c:476`).
const CREATE_ATTEMPTS: usize = 4096;

/// Highest `NNNNNN` among entries `<leaf>.NNNNNN` in the base's directory (`.` if the base has
/// no `/`), or 0 when none or when the directory cannot be read. Only names that are exactly
/// `<leaf>` + `.` + 6 characters that parse fully as a decimal count. "Parse" is C `strtoul`:
/// leading whitespace and a sign are accepted, and `-00001` is `u64::MAX`.
pub fn highest_seq(base: &Path) -> u64 {
    let b = base.as_os_str().as_bytes();
    let (dir, leaf) = match b.iter().rposition(|&c| c == b'/') {
        Some(i) => (&b[..i], &b[i + 1..]),
        None => (&b"."[..], b),
    };
    let Ok(entries) = fs::read_dir(OsStr::from_bytes(dir)) else {
        return 0;
    };
    entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let digits = name.as_bytes().strip_prefix(leaf)?.strip_prefix(b".")?;
            if digits.len() == SEQ_DIGITS {
                strtoul_whole(digits)
            } else {
                None
            }
        })
        .max()
        .unwrap_or(0)
}

/// C `strtoul(s, &end, 10)` that must consume all of `s`.
fn strtoul_whole(s: &[u8]) -> Option<u64> {
    let s = &s[s
        .iter()
        .position(|c| !matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))?..];
    let (neg, digits) = match s.split_first()? {
        (b'-', rest) => (true, rest),
        (b'+', rest) => (false, rest),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let v: u64 = std::str::from_utf8(digits).ok()?.parse().ok()?;
    Some(if neg { v.wrapping_neg() } else { v })
}

/// One event to append.
#[derive(Clone, Copy, Debug)]
pub struct Event<'a> {
    /// `fhsm_audit_event_t` code.
    pub code: u32,
    pub slot: i32,
    pub session: i32,
    pub role: Role,
    pub rv: u32,
    /// Raw actor for this thread; sanitised on append. `None` means no actor.
    pub actor: Option<&'a [u8]>,
    /// Raw key/value pairs; sanitised on append.
    pub params: &'a [(&'a [u8], &'a [u8])],
}

/// Why an operation on the log failed. Every variant except `ArgumentsBad` and `Open`
/// latches the module ERROR state in the C ABI layer, with [`AuditError::latch_reason`].
#[derive(Debug)]
pub enum AuditError {
    /// Key not exactly 32 bytes (DIV-003), or an unusable path.
    ArgumentsBad,
    /// No file could be created or opened.
    Open(io::Error),
    /// HMAC computation failed.
    Hmac,
    /// The MAC'd body did not fit the line buffer.
    LineTruncated,
    /// The body fit but the `hmac` suffix did not.
    SuffixTruncated,
    /// `write` failed or was short. Sticky: a partly written line breaks the chain, so every
    /// later append fails too, until the log is closed.
    Write(io::Error),
    /// A durability barrier (`fdatasync`) failed. Sticky: every later append fails too,
    /// until the log is closed.
    SyncFailed,
}

impl AuditError {
    /// The exact reason string the C module passes to `fhsm_state_latch_error`
    /// (`"audit line truncated"`, `"audit HMAC failed"`, `"audit suffix truncated"`,
    /// `"audit write failed"`, `"audit fsync failed"`), or `None` for `ArgumentsBad`/`Open`.
    pub fn latch_reason(&self) -> Option<&'static str> {
        match self {
            AuditError::ArgumentsBad | AuditError::Open(_) => None,
            AuditError::Hmac => Some("audit HMAC failed"),
            AuditError::LineTruncated => Some("audit line truncated"),
            AuditError::SuffixTruncated => Some("audit suffix truncated"),
            AuditError::Write(_) => Some("audit write failed"),
            AuditError::SyncFailed => Some("audit fsync failed"),
        }
    }
}

/// Counters for diagnostics: events written, and durability barriers taken.
/// Concurrent appends share barriers, so `barriers <= events`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub events: u64,
    pub barriers: u64,
}

#[derive(Clone, Copy)]
enum Broken {
    Write,
    Sync,
}

struct Chain {
    seq: u64,
    prev: Zeroizing<[u8; 32]>,
    /// Lines written so far; a line's ticket is the value after its write.
    written: u64,
    /// Highest ticket a completed barrier covers.
    synced: u64,
    syncing: bool,
    broken: Option<Broken>,
    stats: Stats,
}

/// An open audit log. `Sync`: appends from many threads are serialised for the chain and
/// share `fdatasync` barriers (group commit). Dropping it closes the file and zeroises the
/// key; `&mut self` on drop means no barrier can be in flight.
pub struct AuditLog {
    path: PathBuf,
    file: File,
    key: Zeroizing<[u8; KEY_LEN]>,
    chain: Mutex<Chain>,
    barrier_done: Condvar,
}

impl AuditLog {
    /// Open a log for `base` under `key` (exactly 32 bytes, DIV-003; otherwise `ArgumentsBad`).
    ///
    /// - If `base` exists and is not a regular file (FIFO, `/dev/null`, a device), it is opened
    ///   for append as given, with no numbering.
    /// - Otherwise the file is `base.NNNNNN` with `NNNNNN = highest_seq(base) + 1`, created with
    ///   `O_EXCL` and mode 0600. On `EEXIST` the next number is tried, up to 4096 attempts; any
    ///   other error stops at once.
    ///
    /// The chain starts at [`crate::chain::chain_head`]. Nothing is written by `open`.
    pub fn open(base: &Path, key: &[u8]) -> Result<Self, AuditError> {
        let key =
            Zeroizing::new(<[u8; KEY_LEN]>::try_from(key).map_err(|_| AuditError::ArgumentsBad)?);
        let (file, path) = match fs::metadata(base) {
            Ok(md) if !md.is_file() => {
                let f = OpenOptions::new()
                    .append(true)
                    .open(base)
                    .map_err(AuditError::Open)?;
                (f, base.to_path_buf())
            }
            _ => open_numbered(base)?,
        };
        let prev = Zeroizing::new(chain::chain_head(&*key).map_err(|_| AuditError::Hmac)?);
        Ok(AuditLog {
            path,
            file,
            key,
            chain: Mutex::new(Chain {
                seq: 0,
                prev,
                written: 0,
                synced: 0,
                syncing: false,
                broken: None,
                stats: Stats::default(),
            }),
            barrier_done: Condvar::new(),
        })
    }

    /// The file actually opened (`base.NNNNNN`, or `base` for a stream).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record and return only after an `fdatasync` that covers it has succeeded.
    ///
    /// `seq` increments from 1. `ts` is nanoseconds since the Unix epoch (`CLOCK_REALTIME`),
    /// sampled **after** the chain lock is taken, so `ts` never decreases as `seq` increases
    /// (DIV-002). The chain advances as soon as the line is written, before the barrier, so a
    /// concurrent writer never reuses a predecessor.
    pub fn append(&self, event: &Event<'_>) -> Result<(), AuditError> {
        let actor = sanitize_actor(event.actor);
        let params = render_params(event.params);

        let mut c = self.lock();
        match c.broken {
            Some(Broken::Sync) => return Err(AuditError::SyncFailed),
            Some(Broken::Write) => {
                return Err(AuditError::Write(io::Error::other(
                    "audit log failed earlier",
                )));
            }
            None => {}
        }
        let body = render_body(&Fields {
            seq: c.seq + 1,
            ts_ns: now_ns(),
            event: event.code,
            slot: event.slot,
            session: event.session,
            role: event.role,
            actor: &actor,
            rv: event.rv,
            params: &params,
            prev_hmac: &c.prev,
        })
        .map_err(|_| AuditError::LineTruncated)?;
        let mac =
            Zeroizing::new(chain::mac(&*self.key, body.as_bytes()).map_err(|_| AuditError::Hmac)?);
        let line = finish_line(&body, &mac).map_err(|_| AuditError::SuffixTruncated)?;
        if let Err(e) = (&self.file).write_all(line.as_bytes()) {
            c.broken = Some(Broken::Write);
            return Err(AuditError::Write(e));
        }
        c.seq += 1;
        *c.prev = *mac;
        c.stats.events += 1;
        c.written += 1;
        let ticket = c.written;

        // Group commit: one thread runs the barrier with the lock released; the others wait
        // for a barrier that covers their line.
        loop {
            if c.synced >= ticket {
                return Ok(());
            }
            if let Some(Broken::Sync) = c.broken {
                return Err(AuditError::SyncFailed);
            }
            if c.syncing {
                c = self
                    .barrier_done
                    .wait(c)
                    .unwrap_or_else(PoisonError::into_inner);
                continue;
            }
            c.syncing = true;
            c.stats.barriers += 1;
            let target = c.written;
            drop(c);
            let synced = self.file.sync_data();
            c = self.lock();
            c.syncing = false;
            match synced {
                Ok(()) => c.synced = c.synced.max(target),
                Err(_) => c.broken = Some(Broken::Sync),
            }
            self.barrier_done.notify_all();
        }
    }

    pub fn stats(&self) -> Stats {
        self.lock().stats
    }

    fn lock(&self) -> MutexGuard<'_, Chain> {
        self.chain.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn open_numbered(base: &Path) -> Result<(File, PathBuf), AuditError> {
    let mut opts = OpenOptions::new();
    opts.read(true).append(true).create_new(true).mode(0o600);
    let mut next = highest_seq(base).wrapping_add(1);
    let mut last = None;
    for _ in 0..CREATE_ATTEMPTS {
        let mut name = base.as_os_str().to_owned().into_vec();
        name.extend_from_slice(format!(".{next:0SEQ_DIGITS$}").as_bytes());
        let cand = PathBuf::from(std::ffi::OsString::from_vec(name));
        match opts.open(&cand) {
            Ok(f) => return Ok((f, cand)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => last = Some(e),
            Err(e) => return Err(AuditError::Open(e)),
        }
        next = next.wrapping_add(1);
    }
    Err(AuditError::Open(
        last.unwrap_or_else(|| io::Error::other("no attempt made")),
    ))
}

/// `CLOCK_REALTIME` in nanoseconds; negative before the epoch.
fn now_ns() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i64,
        Err(e) => -(e.duration().as_nanos() as i64),
    }
}
