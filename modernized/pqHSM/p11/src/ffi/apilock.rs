//! The PKCS#11 entry lock (`include/fhsm_apilock.h`; Phase 4 slice 1c, replaces
//! `src/fhsm_apilock.c`). Every `C_*` takes one module-wide read-write lock, SHARED or
//! EXCLUSIVE; a value freed under a SHARED call is parked, intact, and zeroized and freed at
//! the next moment no call is in flight. The header says why (#111-prep).
//!
//! All of it is pthread, as in C, and so all of it is here rather than in `pqhsm-core`: the
//! lock is taken in `fhsm_api_enter` and released in `fhsm_api_leave`, two C calls apart, which
//! no `std` guard can span. Kept from C: writer preference
//! (`PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP`), the per-thread mode that makes a nested
//! call take nothing, the drain at every EXCLUSIVE entry and at a SHARED exit that finds the
//! lock free (`trywrlock`), the fork-child reset, the newest-first release order, and the leak
//! when the parking list cannot grow (freeing then would be the use-after-free this prevents).
#![allow(clippy::missing_safety_doc)]

use std::cell::{Cell, UnsafeCell};
use std::ffi::{c_int, c_void};
use std::sync::Once;

/// `fhsm_api_mode_t`.
const NONE: c_int = 0;
const SHARED: c_int = 1;
const EXCLUSIVE: c_int = 2;

/// glibc's `PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP`, the third enumerator of its
/// `<pthread.h>` enum; the libc crate defines it only for uClibc.
const PREFER_WRITER_NONRECURSIVE: c_int = 2;

/// `fhsm_api_guard_t`, on the C caller's stack.
#[repr(C)]
pub struct Guard {
    taken: c_int,
}

use super::sys::fhsm_zeroize;

unsafe extern "C" {
    fn fhsm_secure_free(p: *mut c_void);
}

struct Retired {
    p: *mut c_void,
    len: usize,
    secure: bool,
}

/// The lock, and the parked values under their own mutex, as C's two statics.
struct Api {
    rw: UnsafeCell<libc::pthread_rwlock_t>,
    retire_mu: UnsafeCell<libc::pthread_mutex_t>,
    retired: UnsafeCell<Vec<Retired>>,
}

// SAFETY: `rw` and `retire_mu` are pthread objects, made for sharing; `retired` is only touched
// with `retire_mu` held, or in the fork child, where no other thread exists.
unsafe impl Sync for Api {}

static API: Api = Api {
    rw: UnsafeCell::new(libc::PTHREAD_RWLOCK_INITIALIZER),
    retire_mu: UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER),
    retired: UnsafeCell::new(Vec::new()),
};
static ONCE: Once = Once::new();

thread_local! {
    static MODE: Cell<c_int> = const { Cell::new(NONE) };
}

unsafe fn release_now(p: *mut c_void, len: usize, secure: bool) {
    if p.is_null() {
        return;
    }
    // SAFETY: the caller's contract: a live value of `len` bytes from the allocator `secure`
    // names, released once
    unsafe {
        if len != 0 {
            fhsm_zeroize(p, len);
        }
        if secure {
            fhsm_secure_free(p)
        } else {
            libc::free(p)
        }
    }
}

unsafe fn rw_init() {
    // SAFETY: the attribute is initialised before use and destroyed after; `rw` is not in use
    // (first use, or a fork child, whose other threads are gone)
    unsafe {
        let mut a = std::mem::zeroed::<libc::pthread_rwlockattr_t>();
        libc::pthread_rwlockattr_init(&mut a);
        libc::pthread_rwlockattr_setkind_np(&mut a, PREFER_WRITER_NONRECURSIVE);
        libc::pthread_rwlock_init(API.rw.get(), &a);
        libc::pthread_rwlockattr_destroy(&mut a);
    }
}

/// A fresh lock and an empty list in a forked child. The parked values are zeroized but not
/// handed to the secure heap, whose own lock may be held by a thread the child lacks.
extern "C" fn after_fork_child() {
    // SAFETY: the child has one thread, so nothing else holds or reads these
    unsafe {
        rw_init();
        libc::pthread_mutex_init(API.retire_mu.get(), std::ptr::null());
        for r in std::mem::take(&mut *API.retired.get()).into_iter().rev() {
            if r.len != 0 {
                fhsm_zeroize(r.p, r.len);
            }
            if !r.secure {
                libc::free(r.p);
            }
        }
    }
    MODE.set(NONE);
}

fn take_retired() -> Vec<Retired> {
    // SAFETY: `retired` under `retire_mu`
    unsafe {
        libc::pthread_mutex_lock(API.retire_mu.get());
        let v = std::mem::take(&mut *API.retired.get());
        libc::pthread_mutex_unlock(API.retire_mu.get());
        v
    }
}

/// Caller holds `rw` EXCLUSIVE, so no call is between an object lookup and its last use.
fn drain_retired() {
    for r in take_retired().into_iter().rev() {
        // SAFETY: parked by fhsm_api_free_value, released exactly once
        unsafe { release_now(r.p, r.len, r.secure) };
    }
}

fn retired_len() -> usize {
    // SAFETY: `retired` under `retire_mu`
    unsafe {
        libc::pthread_mutex_lock(API.retire_mu.get());
        let n = (*API.retired.get()).len();
        libc::pthread_mutex_unlock(API.retire_mu.get());
        n
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_api_enter(g: *mut Guard, mode: c_int) {
    // SAFETY: the caller's contract: g is its guard (FHSM_API_GUARD)
    let g = unsafe { &mut *g };
    g.taken = 0;
    // Nested C_ call: the outermost one holds the lock.
    if MODE.get() != NONE {
        return;
    }
    ONCE.call_once(|| {
        // SAFETY: first use of the lock; the handler only runs in a fork child
        unsafe {
            rw_init();
            libc::pthread_atfork(None, None, Some(after_fork_child));
        }
    });
    // SAFETY: an initialised lock this thread does not hold (MODE is NONE)
    unsafe {
        if mode == EXCLUSIVE {
            libc::pthread_rwlock_wrlock(API.rw.get());
            drain_retired();
        } else {
            libc::pthread_rwlock_rdlock(API.rw.get());
        }
    }
    MODE.set(mode);
    g.taken = 1;
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_api_leave(g: *mut Guard) {
    // SAFETY: the caller's contract: the guard fhsm_api_enter filled
    let g = unsafe { &mut *g };
    if g.taken == 0 {
        return;
    }
    let was = MODE.replace(NONE);
    // SAFETY: this thread holds the lock (taken)
    unsafe { libc::pthread_rwlock_unlock(API.rw.get()) };
    g.taken = 0;
    // SAFETY: trywrlock on an initialised lock; unlocked only when taken
    if was == SHARED
        && retired_len() != 0
        && unsafe { libc::pthread_rwlock_trywrlock(API.rw.get()) } == 0
    {
        drain_retired();
        unsafe { libc::pthread_rwlock_unlock(API.rw.get()) };
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_api_mode() -> c_int {
    MODE.get()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_api_free_value(p: *mut c_void, len: usize, secure: c_int) {
    if p.is_null() {
        return;
    }
    let secure = secure != 0;
    if MODE.get() != SHARED {
        // SAFETY: the caller's contract, passed on
        unsafe { release_now(p, len, secure) };
        return;
    }
    // SAFETY: `retired` under `retire_mu`
    unsafe {
        libc::pthread_mutex_lock(API.retire_mu.get());
        let v = &mut *API.retired.get();
        // Out of memory: leak it. Freeing now is the use-after-free; zeroizing would hand a
        // concurrent C_Sign a key of zeros.
        if v.try_reserve(1).is_ok() {
            v.push(Retired { p, len, secure });
        }
        libc::pthread_mutex_unlock(API.retire_mu.get());
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_api_retired_count() -> usize {
    retired_len()
}

/// `FHSM_API_SHARED()` / `FHSM_API_EXCLUSIVE()` for the Rust entry points: the lock is held
/// until the guard drops at the end of the call, after the return value is computed, as C's
/// cleanup attribute did.
pub(crate) struct Held(Guard);

impl Held {
    pub(crate) fn shared() -> Self {
        Self::enter(SHARED)
    }
    pub(crate) fn exclusive() -> Self {
        Self::enter(EXCLUSIVE)
    }
    fn enter(mode: c_int) -> Self {
        let mut g = Held(Guard { taken: 0 });
        // SAFETY: a guard of our own, left by Drop
        unsafe { fhsm_api_enter(&mut g.0, mode) };
        g
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        // SAFETY: the guard fhsm_api_enter filled
        unsafe { fhsm_api_leave(&mut self.0) }
    }
}
