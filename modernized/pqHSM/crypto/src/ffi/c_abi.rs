//! The C ABI of `include/fhsm_conf.h`, the memory section of `include/fhsm_common.h` and
//! `include/fhsm_drbg.h` (`src/fhsm_conf.c`, `src/fhsm_memory.c`, `src/fhsm_drbg.c`), for the
//! hybrid build. Argument checks and results
//! are C's.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::mem::MaybeUninit;
use std::sync::{Mutex, MutexGuard, PoisonError};

use zeroize::Zeroize;

use super::entropy::OsSource;
use crate::drbg::{Drbg, Error, Stats};
use crate::{conf, mem};

const FHSM_RV_OK: u32 = 0x0;
const FHSM_RV_HOST_MEMORY: u32 = 0x2;

/// 1 and the value in `out` (NUL-terminated, cut to `outlen - 1` bytes), or 0. On 0, `out` is
/// left as it was (C wrote a NUL there when the key matched with an empty value).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_conf_lookup(
    key: *const c_char,
    out: *mut c_char,
    outlen: usize,
) -> c_int {
    if key.is_null() || out.is_null() || outlen == 0 {
        return 0;
    }
    // SAFETY: key is a C string (caller)
    let key = unsafe { CStr::from_ptr(key) }.to_bytes();
    let Some(v) = conf::lookup_in(&conf::path(), key, outlen - 1) else {
        return 0;
    };
    // SAFETY: out has outlen bytes (caller) and v.len() < outlen
    unsafe {
        std::ptr::copy_nonoverlapping(v.as_ptr(), out.cast(), v.len());
        *out.add(v.len()) = 0;
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_conf_secure_heap_bytes() -> usize {
    conf::secure_heap_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_secure_heap_init() -> u32 {
    if mem::init() {
        FHSM_RV_OK
    } else {
        FHSM_RV_HOST_MEMORY
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_secure_malloc(n: usize) -> *mut c_void {
    mem::alloc(n).cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_secure_zalloc(n: usize) -> *mut c_void {
    mem::alloc_zeroed(n).cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_secure_free(p: *mut c_void) {
    // SAFETY: p is null or from fhsm_secure_malloc/zalloc (caller)
    unsafe { mem::free(p.cast()) }
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_secure_heap_used() -> usize {
    mem::used()
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_secure_heap_total() -> usize {
    mem::total()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_zeroize(p: *mut c_void, n: usize) {
    if p.is_null() || n == 0 {
        return;
    }
    // SAFETY: p has n writable bytes (caller), possibly never initialised (review L2)
    unsafe { std::slice::from_raw_parts_mut(p.cast::<MaybeUninit<u8>>(), n) }.zeroize();
}

/// 0 when equal; otherwise the OR of the differing bits, which callers treat as a boolean.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_ct_memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    if n == 0 {
        return 0;
    }
    // SAFETY: a and b have n readable bytes (caller)
    let (a, b) = unsafe {
        (
            std::slice::from_raw_parts(a.cast::<u8>(), n),
            std::slice::from_raw_parts(b.cast::<u8>(), n),
        )
    };
    c_int::from(mem::ct_diff(a, b))
}

// ---- DRBG ---------------------------------------------------------------------------------

unsafe extern "C" {
    // src/fhsm_state.c
    fn fhsm_state_get() -> c_int;
    fn fhsm_state_latch_error(reason: *const c_char);
}

/// `FHSM_STATE_ERROR` (`include/fhsm_common.h:249`).
const STATE_ERROR: c_int = 4;

/// The module's DRBG, one per process, as C's module statics under `g_mtx`.
static DRBG: Mutex<Drbg<OsSource>> = Mutex::new(Drbg::new(OsSource));

fn drbg() -> MutexGuard<'static, Drbg<OsSource>> {
    DRBG.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Latches ERROR when the failure calls for it, and returns its code.
fn rv(result: Result<(), Error>) -> u32 {
    result.map_or_else(
        |e| {
            if let Some(reason) = e.latch_reason() {
                // SAFETY: a static C string
                unsafe { fhsm_state_latch_error(reason.as_ptr()) };
            }
            e.rv()
        },
        |()| FHSM_RV_OK,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_drbg_init() -> u32 {
    rv(drbg().init())
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_drbg_reseed() -> u32 {
    rv(drbg().reseed())
}

/// The buffer is zeroed before it is filled: Rust may not view caller memory that is possibly
/// uninitialised as bytes. Bytes a failed call never produced are therefore 0, not what was there.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_drbg_bytes(out: *mut u8, n: usize) -> u32 {
    // SAFETY: no arguments
    if unsafe { fhsm_state_get() } == STATE_ERROR {
        return Error::Halted.rv();
    }
    if out.is_null() || n == 0 {
        return Error::Arguments.rv();
    }
    let mut drbg = drbg();
    // DIV-041: again under the lock, so no output follows another thread's latch
    // SAFETY: no arguments
    if unsafe { fhsm_state_get() } == STATE_ERROR {
        return Error::Halted.rv();
    }
    // SAFETY: out has n writable bytes (caller); zeroed, they are valid u8
    let out = unsafe {
        out.write_bytes(0, n);
        std::slice::from_raw_parts_mut(out, n)
    };
    rv(drbg.bytes(out))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_drbg_get_stats(out: *mut Stats) {
    if !out.is_null() {
        // SAFETY: out points to an fhsm_drbg_stats_t (caller); Stats has its layout
        unsafe { out.write(drbg().stats()) };
    }
}
