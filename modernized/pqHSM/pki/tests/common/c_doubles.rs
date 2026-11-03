//! Test doubles for what the OCSP responder's C ABI takes from outside under
//! `cargo test --features ffi`: the clock and the signing callback. The encoder it calls is
//! the real one (`fhsm_pki_ocsp`, Phase 3 slice 5c).
//!
//! `time()` is defined here, so libc's and libcrypto's callers in the test binary get the
//! value pinned on their thread, and the real clock otherwise; gen_rev.c pinned the same
//! clock with `--wrap=time`. The replay signer hands back C's signature and records what it
//! was asked to sign; it cannot panic (that would abort inside `extern "C"`), so the test
//! compares after the call.

use std::cell::Cell;
use std::ffi::c_void;

thread_local! {
    static PINNED: Cell<Option<libc::time_t>> = const { Cell::new(None) };
}

/// `f` with time() pinned to `now` on this thread.
pub fn pinned<T>(now: i64, f: impl FnOnce() -> T) -> T {
    PINNED.set(Some(now));
    let r = f();
    PINNED.set(None);
    r
}

/// # Safety
/// `t` is NULL or a writable time_t, as time(2) takes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn time(t: *mut libc::time_t) -> libc::time_t {
    let now = PINNED.get().unwrap_or_else(|| {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: a writable timespec; glibc's time() reads the same coarse clock
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME_COARSE, &mut ts) };
        ts.tv_sec
    });
    if !t.is_null() {
        // SAFETY: the caller's contract
        unsafe { *t = now };
    }
    now
}

/// The signature C's signer made, what the encoder asked to be signed, and how often.
pub struct Replay {
    pub sig: Vec<u8>,
    pub seen: Option<Vec<u8>>,
    pub calls: usize,
}

/// A `fhsm_composite_sign_cb` over a `Replay`.
///
/// # Safety
/// `ctx` is a `Replay`; `tbs` has `n` bytes; `sig` has `*sl` writable bytes.
pub unsafe extern "C" fn replay_sign(
    ctx: *mut c_void,
    tbs: *const u8,
    n: usize,
    sig: *mut u8,
    sl: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let r = &mut *ctx.cast::<Replay>();
        r.calls += 1;
        r.seen = Some(std::slice::from_raw_parts(tbs, n).to_vec());
        if r.sig.len() > *sl {
            return 0x150;
        }
        std::ptr::copy_nonoverlapping(r.sig.as_ptr(), sig, r.sig.len());
        *sl = r.sig.len();
    }
    0
}

/// gen_rev.c's `sign_fail`: FHSM_RV_DEVICE_ERROR, counted.
///
/// # Safety
/// `ctx` is a `Replay`.
pub unsafe extern "C" fn failing_sign(
    ctx: *mut c_void,
    _: *const u8,
    _: usize,
    _: *mut u8,
    _: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe { (*ctx.cast::<Replay>()).calls += 1 };
    0x30
}
