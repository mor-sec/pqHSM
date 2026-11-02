//! The C ABI of `include/fhsm_audit.h` over the safe API, and the calls back into legacy C
//! (state latch, DRBG, TPM) until Phases 2 and 3 move them.
//!
//! `fhsm_audit_event` is C-variadic, which stable Rust cannot define: `audit/shim/audit_event.c`
//! collects its key/value list and calls [`pqhsm_audit_event_v`]. The shim also keeps
//! `fhsm_audit_mandatory`, a compile-time constant of the C build.
//!
//! Two C behaviours live here rather than in the safe API, because they are module state, not
//! log state: the process-global counters of `fhsm_audit_barrier_stats`, and the ERROR-state
//! gate. `fhsm_hmac` refuses once ERROR is latched (`src/fhsm_crypto.c:508`), so in C no event
//! is written, and no log opened or verified, after any latch.

use std::cell::Cell;
use std::ffi::{CStr, CString, OsStr, c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use zeroize::Zeroizing;

use crate::key::{self, KeyEnv, KeyError};
use crate::log::{AuditError, AuditLog, Event, Stats};
use crate::record::{ACTOR_MAX, Role};
use crate::verify::{self, VerifyError};

type Rv = u32;
const RV_OK: Rv = 0x0000_0000;
const RV_FUNCTION_FAILED: Rv = 0x0000_0006;
const RV_ARGUMENTS_BAD: Rv = 0x0000_0007;
const RV_SIGNATURE_INVALID: Rv = 0x0000_00C0;
/// `FHSM_STATE_ERROR` (`include/fhsm_common.h:249`).
const STATE_ERROR: c_int = 4;
/// `fhsm_tpm_seal` output buffer, as `src/fhsm_audit.c:325`.
const BLOB_MAX: usize = 2048;

/// `fhsm_slice_t`.
#[repr(C)]
pub struct Slice {
    data: *const u8,
    len: usize,
}

unsafe extern "C" {
    fn fhsm_state_latch_error(reason: *const c_char);
    fn fhsm_state_get() -> c_int;
    fn fhsm_drbg_bytes(out: *mut u8, n: usize) -> Rv;
    fn fhsm_tpm_seal(
        secret: *const u8,
        out_blob: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> Rv;
    fn fhsm_tpm_unseal(blob: *const u8, blob_len: usize, out_secret: *mut u8) -> Rv;
    fn fhsm_token_tpm_required() -> c_int;
}

/// Held only to clone or swap the `Arc`: no lock spans a write or an `fdatasync`, so a fork
/// taken while a parent thread is inside an event cannot leave the child blocked on it.
static LOG: Mutex<Option<Arc<Opened>>> = Mutex::new(None);
/// Counters of logs already closed: C's counters are process-wide and never reset.
static CLOSED: Mutex<Stats> = Mutex::new(Stats {
    events: 0,
    barriers: 0,
});

thread_local! {
    /// The raw actor, cut to `ACTOR_MAX - 1` bytes. Plain `Copy` data: a thread-local with a
    /// destructor panics when used after TLS teardown, and `C_Finalize` from an `atexit` handler
    /// emits an event exactly then.
    static ACTOR: Cell<Option<([u8; ACTOR_MAX - 1], u8)>> = const { Cell::new(None) };
    /// Re-entry guard for an event raised while this thread is inside an event. It does not stop
    /// the latch's own event (the flag is cleared before latching, as in C): that recursion ends
    /// because `fhsm_state_latch_error` returns early once ERROR is set (`src/fhsm_state.c:136`).
    static IN_EVENT: Cell<bool> = const { Cell::new(false) };
}

fn module_in_error() -> bool {
    // SAFETY: no arguments; reads the module state.
    unsafe { fhsm_state_get() == STATE_ERROR }
}

fn latch(reason: &str) {
    let reason = CString::new(reason).expect("latch reasons are literals without NUL");
    // SAFETY: a valid NUL-terminated string, copied or used before return.
    unsafe { fhsm_state_latch_error(reason.as_ptr()) }
}

/// An open log and the process that opened it. A forked child inherits both and must not
/// append to its parent's chain (DIV-009): to the child the log is not open.
struct Opened {
    pid: u32,
    log: AuditLog,
}

impl Drop for Opened {
    /// Runs when the last in-flight event on a replaced or closed log is done. A child skips
    /// the count: the inherited chain lock may have been held at fork.
    fn drop(&mut self) {
        if self.pid == std::process::id() {
            let s = self.log.stats();
            let mut c = CLOSED.lock().unwrap_or_else(PoisonError::into_inner);
            c.events += s.events;
            c.barriers += s.barriers;
        }
    }
}

/// The open log, if this process opened it.
fn current() -> Option<Arc<Opened>> {
    LOG.lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .filter(|o| o.pid == std::process::id())
}

/// # Safety
/// `ptr` must be NULL or a valid NUL-terminated string that outlives the returned slice.
unsafe fn c_bytes<'a>(ptr: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: per this function's contract.
    (!ptr.is_null()).then(|| unsafe { CStr::from_ptr(ptr) }.to_bytes())
}

/// # Safety
/// `s.data` must be valid for `s.len` bytes, or NULL.
unsafe fn slice_bytes<'a>(s: &Slice) -> Option<&'a [u8]> {
    // SAFETY: per this function's contract.
    (!s.data.is_null() && s.len > 0).then(|| unsafe { std::slice::from_raw_parts(s.data, s.len) })
}

/// # Safety
/// `path` must be NULL or a valid C string; `key.data` valid for `key.len` bytes or NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_audit_open(path: *const c_char, key: Slice) -> Rv {
    // SAFETY: forwarded from the caller's contract.
    let (Some(path), Some(key)) = (unsafe { c_bytes(path) }, unsafe { slice_bytes(&key) }) else {
        return RV_ARGUMENTS_BAD;
    };
    let mut slot = LOG.lock().unwrap_or_else(PoisonError::into_inner);
    match AuditLog::open(Path::new(OsStr::from_bytes(path)), key) {
        // C creates the file, then fails at the chain head when ERROR is latched.
        Ok(_) if module_in_error() => RV_FUNCTION_FAILED,
        Ok(log) => {
            let pid = std::process::id();
            *slot = Some(Arc::new(Opened { pid, log }));
            RV_OK
        }
        Err(AuditError::ArgumentsBad) => RV_ARGUMENTS_BAD,
        Err(_) => RV_FUNCTION_FAILED,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_audit_close() {
    let old = LOG.lock().unwrap_or_else(PoisonError::into_inner).take();
    drop(old); // outside the lock: the drop may count a log's stats
}

/// # Safety
/// `subject` must be NULL or a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_audit_set_actor(subject: *const c_char) {
    // SAFETY: forwarded from the caller's contract.
    let cut = unsafe { c_bytes(subject) }.map(|s| {
        let n = s.len().min(ACTOR_MAX - 1);
        let mut a = [0u8; ACTOR_MAX - 1];
        a[..n].copy_from_slice(&s[..n]);
        (a, n as u8)
    });
    ACTOR.set(cut);
}

/// # Safety
/// `out` must be NULL or valid for `cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_audit_current_path(out: *mut c_char, cap: usize) -> usize {
    let open = current();
    let path = open
        .as_ref()
        .map_or(&b""[..], |o| o.log.path().as_os_str().as_bytes());
    if !out.is_null() && cap > 0 {
        let n = path.len().min(cap - 1);
        // SAFETY: `out` holds `cap` bytes and `n < cap`.
        unsafe {
            std::ptr::copy_nonoverlapping(path.as_ptr(), out.cast(), n);
            *out.add(n) = 0;
        }
    }
    path.len()
}

/// # Safety
/// Each pointer must be NULL or valid for one `u64` write.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_audit_barrier_stats(events: *mut u64, barriers: *mut u64) {
    let closed = *CLOSED.lock().unwrap_or_else(PoisonError::into_inner);
    let open = current().map(|o| o.log.stats()).unwrap_or_default();
    // SAFETY: per this function's contract.
    unsafe {
        if !events.is_null() {
            *events = closed.events + open.events;
        }
        if !barriers.is_null() {
            *barriers = closed.barriers + open.barriers;
        }
    }
}

/// The body of `fhsm_audit_event`, called by the C shim with the variadic list flattened into
/// `kv[0..2*npairs]` as key, value, key, value...
///
/// # Safety
/// `kv` must be valid for `2 * npairs` pointers; each key a valid C string, each value NULL or
/// a valid C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_audit_event_v(
    ev: c_int,
    slot: c_int,
    session: c_int,
    role: c_int,
    rv: Rv,
    kv: *const *const c_char,
    npairs: usize,
) -> Rv {
    if IN_EVENT.get() {
        return RV_FUNCTION_FAILED;
    }
    // Events before open, or after close, are dropped (src/fhsm_audit.c:590-596).
    let Some(open) = current() else { return RV_OK };
    IN_EVENT.set(true);
    let result = if module_in_error() {
        Err(AuditError::Hmac)
    } else {
        // SAFETY: per this function's contract.
        let raw = if npairs == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(kv, 2 * npairs) }
        };
        let pairs: Vec<(&[u8], &[u8])> = raw
            .as_chunks::<2>()
            .0
            .iter()
            // SAFETY: per this function's contract. A NULL value is unsafe in C
            // (safe_ascii(NULL) == 0); a lone quote renders it INVALID the same way.
            .map(|[k, v]| unsafe {
                (
                    c_bytes(*k).unwrap_or_default(),
                    c_bytes(*v).unwrap_or(b"\""),
                )
            })
            .collect();
        let actor = ACTOR.get();
        open.log.append(&Event {
            code: ev as u32,
            slot,
            session,
            role: match role {
                1 => Role::So,
                2 => Role::User,
                _ => Role::None,
            },
            rv,
            actor: actor.as_ref().map(|(a, n)| &a[..usize::from(*n)]),
            params: &pairs,
        })
    };
    // Release the log before latching: the latch emits an event of its own.
    drop(open);
    IN_EVENT.set(false);
    match result {
        Ok(()) => RV_OK,
        Err(e) => {
            if let Some(reason) = e.latch_reason() {
                latch(reason);
            }
            RV_FUNCTION_FAILED
        }
    }
}

struct LegacyEnv;

impl KeyEnv for LegacyEnv {
    fn tpm_required(&self) -> bool {
        // SAFETY: no arguments.
        unsafe { fhsm_token_tpm_required() != 0 }
    }
    fn random(&self, out: &mut [u8; 32]) -> Result<(), u32> {
        // SAFETY: `out` holds 32 bytes.
        match unsafe { fhsm_drbg_bytes(out.as_mut_ptr(), out.len()) } {
            RV_OK => Ok(()),
            rv => Err(rv),
        }
    }
    fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, u32> {
        let mut blob = vec![0u8; BLOB_MAX];
        let mut len = 0usize;
        // SAFETY: `key` holds 32 bytes, `blob` holds BLOB_MAX.
        match unsafe { fhsm_tpm_seal(key.as_ptr(), blob.as_mut_ptr(), blob.len(), &mut len) } {
            RV_OK => {
                blob.truncate(len.min(BLOB_MAX));
                Ok(blob)
            }
            rv => Err(rv),
        }
    }
    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, u32> {
        let mut key = Zeroizing::new([0u8; 32]);
        // SAFETY: `blob` is valid for its length, `key` holds 32 bytes.
        match unsafe { fhsm_tpm_unseal(blob.as_ptr(), blob.len(), key.as_mut_ptr()) } {
            RV_OK => Ok(key),
            rv => Err(rv),
        }
    }
}

/// # Safety
/// `dir` must be NULL or a valid C string; `key` NULL or valid for 32 bytes; `sealed` NULL or
/// valid for one `int`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_audit_key_provision(
    dir: *const c_char,
    key: *mut u8,
    sealed: *mut c_int,
) -> Rv {
    // SAFETY: forwarded from the caller's contract.
    let Some(dir) = (unsafe { c_bytes(dir) }) else {
        return RV_ARGUMENTS_BAD;
    };
    if key.is_null() {
        return RV_ARGUMENTS_BAD;
    }
    // SAFETY: per this function's contract.
    let (out, sealed) = unsafe { (&mut *key.cast::<[u8; 32]>(), sealed.as_mut()) };
    let r = key::provision(Path::new(OsStr::from_bytes(dir)), &LegacyEnv);
    let is_sealed = matches!(r, Ok(ref p) if p.sealed);
    if let Some(s) = sealed {
        *s = c_int::from(is_sealed);
    }
    match r {
        Ok(p) => {
            *out = *p.key;
            RV_OK
        }
        Err(e) => {
            out.fill(0);
            match e {
                KeyError::ArgumentsBad => RV_ARGUMENTS_BAD,
                KeyError::Failed => RV_FUNCTION_FAILED,
                KeyError::Env(rv) => rv,
            }
        }
    }
}

/// # Safety
/// `path` must be NULL or a valid C string; `key.data` valid for `key.len` bytes or NULL;
/// `broken_at_line` NULL or valid for one `size_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_audit_verify(
    path: *const c_char,
    key: Slice,
    broken_at_line: *mut usize,
) -> Rv {
    // SAFETY: per this function's contract.
    let broken = unsafe { broken_at_line.as_mut() };
    let broken = broken.map(|b| {
        *b = 0;
        b
    });
    // SAFETY: forwarded from the caller's contract.
    let (Some(path), Some(key)) = (unsafe { c_bytes(path) }, unsafe { slice_bytes(&key) }) else {
        return RV_ARGUMENTS_BAD;
    };
    if module_in_error() {
        return RV_FUNCTION_FAILED;
    }
    match verify::verify_file(Path::new(OsStr::from_bytes(path)), key) {
        Ok(()) => RV_OK,
        Err(VerifyError::Broken { line }) => {
            if let Some(b) = broken {
                *b = line;
            }
            RV_SIGNATURE_INVALID
        }
        Err(VerifyError::ArgumentsBad) => RV_ARGUMENTS_BAD,
        Err(VerifyError::Open | VerifyError::Hmac) => RV_FUNCTION_FAILED,
    }
}
