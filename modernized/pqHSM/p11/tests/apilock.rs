//! legacy/tests/test_apilock.c in Rust (Phase 6 slice 5c; the C test linked the C ABI, which the
//! all-Rust module no longer exports): the deferred release of `fhsm_api_free_value`. Outside a
//! call and in an EXCLUSIVE one a value is released at once; in a SHARED one it is parked, intact,
//! until the last SHARED call leaves; a nested entry keeps the outer mode. Its own binary, since
//! the lock and the retired list are process-wide.
#![cfg(feature = "ffi")]

use std::ffi::{c_int, c_void};
use std::sync::{Arc, Barrier};

extern crate pqhsm_p11;

#[repr(C)]
struct Guard {
    taken: c_int,
}

unsafe extern "C" {
    fn fhsm_api_enter(g: *mut Guard, mode: c_int);
    fn fhsm_api_leave(g: *mut Guard);
    fn fhsm_api_mode() -> c_int;
    fn fhsm_api_free_value(p: *mut c_void, len: usize, secure: c_int);
    fn fhsm_api_retired_count() -> usize;
}

const NONE: c_int = 0;
const SHARED: c_int = 1;
const EXCLUSIVE: c_int = 2;

/// `FHSM_API_SHARED()` / `FHSM_API_EXCLUSIVE()`: entered now, left when dropped.
struct In(Guard);
impl In {
    fn new(mode: c_int) -> Self {
        let mut g = In(Guard { taken: 0 });
        // SAFETY: a guard of our own, left in drop
        unsafe { fhsm_api_enter(&mut g.0, mode) };
        g
    }
}
impl Drop for In {
    fn drop(&mut self) {
        // SAFETY: entered in new
        unsafe { fhsm_api_leave(&mut self.0) };
    }
}

/// 32 bytes of 0xA5 from malloc, as the module's values are; the lock frees them with free().
fn filled() -> *mut u8 {
    // SAFETY: a fresh allocation, filled before use
    unsafe {
        let p = libc::malloc(32).cast::<u8>();
        assert!(!p.is_null());
        p.write_bytes(0xA5, 32);
        p
    }
}

fn intact(p: *const u8) -> bool {
    // SAFETY: still allocated: the callers check only while it is parked
    unsafe { std::slice::from_raw_parts(p, 32) }.iter().all(|&b| b == 0xA5)
}

fn free(p: *mut u8) {
    // SAFETY: a malloc'd value of 32 bytes, handed over
    unsafe { fhsm_api_free_value(p.cast(), 32, 0) };
}

fn mode() -> c_int {
    // SAFETY: no arguments
    unsafe { fhsm_api_mode() }
}

fn retired() -> usize {
    // SAFETY: no arguments
    unsafe { fhsm_api_retired_count() }
}

#[test]
fn values_are_released_at_once_or_parked_until_the_last_shared_call_leaves() {
    // 1: outside any call
    free(filled());
    assert_eq!((retired(), mode()), (0, NONE), "outside any call");

    // 2-4: another SHARED call in flight
    let (inside, out) = (Arc::new(Barrier::new(2)), Arc::new(Barrier::new(2)));
    let holder = {
        let (inside, out) = (Arc::clone(&inside), Arc::clone(&out));
        std::thread::spawn(move || {
            let _g = In::new(SHARED);
            inside.wait();
            out.wait();
        })
    };
    inside.wait();
    let v = filled();
    {
        let _g = In::new(SHARED);
        assert_eq!(mode(), SHARED);
        free(v);
        assert_eq!(retired(), 1, "SHARED call: release parked");
        assert!(intact(v), "SHARED call: parked value intact");
    }
    assert_eq!(retired(), 1, "another call in flight: leaving does not drain");
    assert!(intact(v), "another call in flight: value intact");
    out.wait();
    holder.join().unwrap();
    assert_eq!(retired(), 0, "last SHARED call out: drained");

    // 5: EXCLUSIVE, and a nested entry inside it
    {
        let _g = In::new(EXCLUSIVE);
        assert_eq!(mode(), EXCLUSIVE);
        free(filled());
        assert_eq!(retired(), 0, "EXCLUSIVE call: released at once");
        {
            let _n = In::new(SHARED); // must not deadlock
            assert_eq!(mode(), EXCLUSIVE, "nested entry: outermost mode kept");
            free(filled());
            assert_eq!(retired(), 0, "nested in EXCLUSIVE: released at once");
        }
        assert_eq!(mode(), EXCLUSIVE, "nested exit: the outer call still holds the lock");
    }
    assert_eq!(mode(), NONE, "outer exit");
}
