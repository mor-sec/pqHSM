//! The service's shared state, C's globals (`service/fhsm_service.c:160-830`): the policy
//! (RULE-068), the session pool and the PIN login (RULE-097), the per-identity fairness table
//! and the refusal budget (RULE-068). Each table is the C's size and is searched in the C's
//! order, so which slot is reused when one is full matches too.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError, RwLock};

use pqhsm_pkiops::ops::{self, Session, Slot};

/// The pool's ceiling: the module's own cap, `FHSM_MAX_SESSIONS - 1`.
pub const POOL_MAX_LIMIT: i64 = 127;
const POLICY_MAX: usize = 512;
const IDENT_MAX: usize = POOL_MAX_LIMIT as usize + 1;
const IDENT_WINDOW_S: i64 = 30;
pub const BURST_COOLDOWN_S: i64 = 5;
const BUDGET_MAX: usize = 256;
const BUDGET_FREE: u32 = 4;
const BUDGET_DECAY_S: i64 = 600;
const BUDGET_CAP_S: i64 = 60;
use crate::http::{ACTOR_MAX, MAX_KEY_LABEL};

/// Set by SIGHUP; the next request on the private side reloads (slice 2).
pub static RELOAD: AtomicBool = AtomicBool::new(false);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// `CLOCK_MONOTONIC` seconds, as C's `mono_now`.
pub fn mono_now() -> i64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is writable.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 {
        return 0;
    }
    ts.tv_sec
}

/// The pieces `fgets(buf, cap, f)` returns over `data`, each read as C's string functions see
/// it (up to a NUL). A line longer than `cap - 1` comes back in pieces, as C's does.
fn fgets_pieces(data: &[u8], cap: usize) -> impl Iterator<Item = &[u8]> {
    let mut rest = data;
    std::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let line = rest
            .iter()
            .position(|&c| c == b'\n')
            .map_or(rest.len(), |n| n + 1);
        let n = line.min(cap - 1);
        let (piece, tail) = rest.split_at(n);
        rest = tail;
        Some(piece.split(|&c| c == 0).next().unwrap_or_default())
    })
}

// --- the policy -------------------------------------------------------------------------------

pub struct Policy {
    pub path: PathBuf,
    rules: RwLock<Vec<(Vec<u8>, Vec<u8>)>>,
}

impl Policy {
    pub fn new(path: PathBuf) -> Policy {
        Policy {
            path,
            rules: RwLock::new(Vec::new()),
        }
    }

    /// `policy_load`: every rule or none; the count, or `None` with the reason on stderr. A
    /// file that cannot be read is refused, a directory too (C read one as no rules: DIV-077).
    pub fn load(&self) -> Option<usize> {
        let data = std::fs::read(&self.path).ok()?;
        let p = self.path.display();
        let mut staged = Vec::new();
        for (k, piece) in fgets_pieces(&data, 512).enumerate() {
            let lineno = k + 1;
            let mut line = piece;
            while let [head @ .., b'\n' | b'\r'] = line {
                line = head;
            }
            if line.is_empty() || line[0] == b'#' {
                continue;
            }
            let Some(tab) = line.iter().position(|&c| c == b'\t') else {
                errln!("fhsm-service: {p}:{lineno} has no tab; a rule is SUBJECT<TAB>KEY-LABEL");
                return None;
            };
            let (subj, key) = (&line[..tab], &line[tab + 1..]);
            if subj.is_empty() || key.is_empty() || key.contains(&b'\t') {
                errln!("fhsm-service: {p}:{lineno} is malformed");
                return None;
            }
            if subj.len() >= ACTOR_MAX || key.len() >= MAX_KEY_LABEL {
                errln!("fhsm-service: {p}:{lineno} is too long");
                return None;
            }
            if staged.len() >= POLICY_MAX {
                errln!("fhsm-service: {p} has more than {POLICY_MAX} rules");
                return None;
            }
            staged.push((subj.to_vec(), key.to_vec()));
        }
        let n = staged.len();
        *self.rules.write().unwrap_or_else(PoisonError::into_inner) = staged;
        Some(n)
    }
}

// --- the session pool -------------------------------------------------------------------------

/// Sessions opened lazily up to the ceiling; slot 0 is the one the PIN logged in.
pub struct Pool {
    pub slot: Slot,
    max: usize,
    open: Mutex<Vec<(Session, bool)>>,
    cv: Condvar,
}

impl Pool {
    pub fn new(slot: Slot, max: usize, logged_in: Session) -> Pool {
        Pool {
            slot,
            max,
            open: Mutex::new(vec![(logged_in, false)]),
            cv: Condvar::new(),
        }
    }

    /// `pool_acquire`: a free session, a new one under the ceiling, or a wait for one. A
    /// session the module will not open is waited out too, as C's is.
    pub fn acquire(&self) -> Session {
        let mut open = lock(&self.open);
        loop {
            if let Some(e) = open.iter_mut().find(|e| !e.1) {
                e.1 = true;
                return e.0;
            }
            if open.len() < self.max
                && let Ok(s) = ops::session_open(self.slot)
            {
                open.push((s, true));
                return s;
            }
            open = self.cv.wait(open).unwrap_or_else(PoisonError::into_inner);
        }
    }

    pub fn release(&self, s: Session) {
        let mut open = lock(&self.open);
        if let Some(e) = open.iter_mut().find(|e| e.0 == s) {
            e.1 = false;
        }
        self.cv.notify_one();
    }

    pub fn close_all(&self) {
        for (s, _) in lock(&self.open).drain(..) {
            ops::session_close(s);
        }
    }
}

/// `login_once`: the PIN, read once from `--pin-file` or `$CREDENTIALS_DIRECTORY/fhsm-pin`,
/// one C_Login, never retried (RULE-097). The session is the pool's first.
pub fn login_once(slot: Slot, pin_file: Option<&Path>) -> Option<Session> {
    let path = match pin_file {
        Some(p) => p.to_path_buf(),
        None => match std::env::var_os("CREDENTIALS_DIRECTORY").filter(|d| !d.is_empty()) {
            Some(d) => Path::new(&d).join("fhsm-pin"),
            None => {
                errw!(
                    "fhsm-service: no PIN source. Either run under systemd with\n  LoadCredentialEncrypted=fhsm-pin:... so that\n  $CREDENTIALS_DIRECTORY/fhsm-pin exists, or pass --pin-file PATH\n  for a test rig. There is no third option, and none that reads\n  the environment: see docs/DAEMON_PIN.md.\n"
                );
                return None;
            }
        },
    };
    let mut f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            errln!(
                "fhsm-service: cannot read the PIN from {}: {}",
                path.display(),
                pqhsm_pkiops::strerror(&e)
            );
            return None;
        }
    };
    let mut pin = zeroize::Zeroizing::new([0u8; 128]);
    // One read of at most 128 bytes, as C's: a longer file is cut (RULE-097's edge case).
    let n = std::io::Read::read(&mut f, &mut pin[..]).unwrap_or(0);
    drop(f);
    if n == 0 {
        errln!("fhsm-service: the PIN file is empty.");
        return None;
    }
    let mut pin_len = n;
    while pin_len > 0 && matches!(pin[pin_len - 1], b'\n' | b'\r') {
        pin_len -= 1;
    }
    let s = match ops::session_open(slot) {
        Ok(s) => s,
        Err(rv) => {
            errln!("fhsm-service: C_OpenSession failed (0x{rv:x})");
            return None;
        }
    };
    let rv = ops::login_user(s, &pin[..pin_len]);
    drop(pin);
    if rv != 0 {
        ops::session_close(s);
        errw!(
            "fhsm-service: C_Login failed (0x{rv:x}). Not retrying: the token locks\n  after a handful of consecutive failures, and a restart loop would\n  spend them. Fix the credential and start again.\n"
        );
        return None;
    }
    Some(s)
}

// --- the per-identity fairness cap ------------------------------------------------------------

#[derive(Default, Clone)]
struct Ident {
    subject: Vec<u8>,
    in_flight: usize,
    used: bool,
    last_seen: i64,
    limited: bool,
    suppressed: u64,
    limited_since: i64,
    last_refusal: i64,
}

/// What `ident_enter` asks the caller to write: the first refusal of a burst, or its end.
#[derive(Default)]
pub struct Note {
    pub log_refusal: bool,
    pub log_resume: bool,
    pub suppressed: u64,
    pub window_s: i64,
}

pub struct Idents {
    workers: usize,
    t: Mutex<Vec<Ident>>,
}

impl Idents {
    pub fn new(workers: usize) -> Idents {
        Idents {
            workers,
            t: Mutex::new(vec![Ident::default(); IDENT_MAX]),
        }
    }

    /// `ident_enter`: `false` is a refusal (429 too_many_in_flight). While another identity is
    /// present each is held to workers - 1. A full table admits uncounted, as C's does
    /// (RULE-068's fail-open, decided in slice 2).
    pub fn enter(&self, subject: &[u8], note: &mut Note) -> bool {
        let now = mono_now();
        let mut t = lock(&self.t);
        let (mut mine, mut spare, mut others, mut oldest) = (None, None, 0, 0);
        for (i, e) in t.iter().enumerate() {
            if !e.used {
                spare.get_or_insert(i);
                continue;
            }
            let present = e.in_flight > 0 || now - e.last_seen < IDENT_WINDOW_S;
            if e.subject == subject {
                mine = Some(i);
            } else if present {
                others += 1;
            } else if e.in_flight == 0 && (spare.is_none() || e.last_seen < oldest) {
                spare = Some(i);
                oldest = e.last_seen;
            }
        }
        let cap = if others > 0 && self.workers > 1 {
            self.workers - 1
        } else {
            self.workers
        };
        match (mine, spare) {
            (Some(i), _) => {
                let e = &mut t[i];
                if e.in_flight >= cap {
                    if e.limited {
                        e.suppressed += 1;
                    } else {
                        (e.limited, e.limited_since, e.suppressed) = (true, now, 0);
                        note.log_refusal = true;
                    }
                    e.last_refusal = now;
                    return false;
                }
                if e.limited && now - e.last_refusal >= BURST_COOLDOWN_S {
                    note.log_resume = true;
                    note.suppressed = e.suppressed;
                    note.window_s = now - e.limited_since;
                    (e.limited, e.suppressed) = (false, 0);
                }
                e.in_flight += 1;
            }
            (None, Some(i)) => {
                // not present until it is served
                t[i] = Ident {
                    subject: subject.to_vec(),
                    in_flight: 1,
                    used: true,
                    ..Ident::default()
                };
            }
            (None, None) => {}
        }
        true
    }

    /// `ident_leave`.
    pub fn leave(&self, subject: &[u8], served: bool) {
        let now = mono_now();
        let mut t = lock(&self.t);
        if let Some(e) = t
            .iter_mut()
            .find(|e| e.used && e.in_flight > 0 && e.subject == subject)
        {
            e.in_flight -= 1;
            if served {
                e.last_seen = now;
            }
        }
    }

    /// `ident_flush_bursts`, at shutdown: each burst still open is closed in the log.
    pub fn flush_bursts(&self) {
        let now = mono_now();
        let mut t = lock(&self.t);
        for e in t.iter_mut().filter(|e| e.used && e.limited) {
            crate::audit::set_actor(Some(&e.subject));
            crate::audit::event(
                crate::audit::EV_IDENTITY_RESUMED,
                -1,
                -1,
                crate::audit::ROLE_NONE,
                crate::audit::RV_OK,
                &[
                    ("suppressed", e.suppressed.to_string().as_bytes()),
                    ("window_s", (now - e.limited_since).to_string().as_bytes()),
                    ("ended", b"shutdown"),
                ],
            );
            crate::audit::set_actor(None);
            e.limited = false;
        }
    }
}

// --- the refusal budget -----------------------------------------------------------------------

#[derive(Default, Clone)]
struct Owed {
    subject: Vec<u8>,
    count: u32,
    last: i64,
    used: bool,
}

/// Refusals per identity, persisted in `$FHSM_TOKENS_DIR/budget`. Charging is slice 2's.
pub struct Budget {
    t: Mutex<Vec<Owed>>,
}

/// `budget_delay_s`: four free, then 1, 2, 4... seconds, capped at 60.
fn delay_s(n: u32) -> i64 {
    if n <= BUDGET_FREE {
        return 0;
    }
    let k = n - BUDGET_FREE - 1;
    if k >= 20 {
        BUDGET_CAP_S
    } else {
        (1i64 << k).min(BUDGET_CAP_S)
    }
}

/// `budget_decayed`: one refusal forgiven per ten quiet minutes.
fn decayed(b: &Owed, now: i64) -> u32 {
    if b.count == 0 {
        return 0;
    }
    let forgiven = ((now - b.last).max(0) / BUDGET_DECAY_S) as u64;
    u64::from(b.count).saturating_sub(forgiven) as u32
}

impl Budget {
    /// `budget_load`: the entries saved in `dir/budget`, their decay restarted now. A missing
    /// file, or no directory, is an empty budget.
    pub fn load(dir: Option<&[u8]>) -> Budget {
        let mut t = vec![Owed::default(); BUDGET_MAX];
        let data = dir.filter(|d| !d.is_empty()).and_then(|d| {
            std::fs::read(Path::new(std::ffi::OsStr::from_bytes(d)).join("budget")).ok()
        });
        let now = mono_now();
        let mut slot = 0;
        for line in fgets_pieces(data.as_deref().unwrap_or_default(), 600) {
            if slot >= BUDGET_MAX {
                break;
            }
            if matches!(line.first(), Some(b'#' | b'\n')) {
                continue;
            }
            let Some(tab) = line.iter().position(|&c| c == b'\t') else {
                continue;
            };
            let mut subj = &line[tab + 1..];
            while let [head @ .., b'\n' | b'\r'] = subj {
                subj = head;
            }
            if subj.is_empty() || subj.len() >= ACTOR_MAX {
                continue;
            }
            let Ok(num) = std::ffi::CString::new(&line[..tab]) else {
                continue;
            };
            // SAFETY: a C string; no end pointer wanted.
            let c = unsafe { libc::strtoul(num.as_ptr(), std::ptr::null_mut(), 10) } as u32;
            if c == 0 {
                continue;
            }
            t[slot] = Owed {
                subject: subj.to_vec(),
                count: c,
                last: now,
                used: true,
            };
            slot += 1;
        }
        if slot > 0 {
            errln!("fhsm-service: refusal budget restored for {slot} identity(ies)");
        }
        Budget { t: Mutex::new(t) }
    }

    /// `budget_retry_after`: the seconds this identity still owes, 0 for none.
    pub fn retry_after(&self, subject: &[u8]) -> i64 {
        let now = mono_now();
        let t = lock(&self.t);
        t.iter()
            .find(|b| b.used && b.subject == subject)
            .map_or(0, |b| {
                let need = delay_s(decayed(b, now));
                let since = (now - b.last).max(0);
                (need - since).max(0)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fgets_pieces_split_as_c_reads() {
        let v: Vec<&[u8]> = fgets_pieces(b"ab\ncdefg\nh\0i\n", 4).collect();
        assert_eq!(v, [&b"ab\n"[..], b"cde", b"fg\n", b"h", b"\n"]);
    }

    #[test]
    fn the_budget_delay_doubles_after_four_and_caps() {
        let d: Vec<i64> = [0, 4, 5, 6, 7, 10, 11, 25, 4000].map(delay_s).to_vec();
        assert_eq!(d, [0, 0, 1, 2, 4, 32, 60, 60, 60]);
        let b = Owed {
            count: 3,
            last: 0,
            used: true,
            ..Owed::default()
        };
        assert_eq!(
            [decayed(&b, 599), decayed(&b, 1200), decayed(&b, 9999)],
            [3, 1, 0]
        );
    }

    #[test]
    fn a_second_identity_holds_each_to_workers_minus_one() {
        let ids = Idents::new(2);
        let mut n = Note::default();
        assert!(ids.enter(b"a", &mut n) && ids.enter(b"a", &mut n));
        assert!(!ids.enter(b"a", &mut n) && n.log_refusal);
        ids.leave(b"a", true);
        assert!(ids.enter(b"b", &mut n));
        // a is at 1 in flight and b is present: the cap is now 1
        assert!(!ids.enter(b"a", &mut n));
    }
}
