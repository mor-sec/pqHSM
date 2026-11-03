//! The C ABI of the module state (`fhsm_state_*` in `include/fhsm_common.h`) over
//! [`pqhsm_core::state::State`] (Phase 4 slice 1b; replaces `src/fhsm_state.c`). Called by
//! `src/fhsm_pkcs11.c` and by the crypto, self-test and audit crates through their externs.
//! Each transition is audited after the lock is released, as C did: the audit subsystem
//! latches ERROR itself when a write fails, and a latch already set emits nothing.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{CString, c_char, c_int};
use std::ptr::null;

use pqhsm_core::state::State;

/// `FHSM_EV_STATE_TRANSITION`.
const EV_STATE_TRANSITION: c_int = 6;
const OK: u32 = 0;
const FUNCTION_FAILED: u32 = 0x6;

unsafe extern "C" {
    fn fhsm_audit_event(ev: c_int, slot: c_int, session: c_int, role: c_int, rv: u32, ...) -> u32;
}

static STATE: State = State::new();

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_state_get() -> c_int {
    STATE.get()
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_state_set(to: c_int) -> u32 {
    match STATE.set(to) {
        Ok(from) => {
            let (from, to) = (cnum(from), cnum(to));
            // SAFETY: NUL-terminated keys and values alive for the call; the list ends with NULL
            unsafe {
                fhsm_audit_event(
                    EV_STATE_TRANSITION,
                    -1,
                    -1,
                    0,
                    OK,
                    c"from".as_ptr(),
                    from.as_ptr(),
                    c"to".as_ptr(),
                    to.as_ptr(),
                    null::<c_char>(),
                )
            };
            OK
        }
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_state_reset_after_fork() {
    STATE.reset_after_fork()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_state_latch_error(reason: *const c_char) {
    if !STATE.latch() {
        return;
    }
    let reason = if reason.is_null() {
        c"(none)".as_ptr()
    } else {
        reason
    };
    // SAFETY: reason is "(none)" or, by the caller's contract, NUL-terminated; the list ends
    // with NULL
    unsafe {
        fhsm_audit_event(
            EV_STATE_TRANSITION,
            -1,
            -1,
            0,
            FUNCTION_FAILED,
            c"to".as_ptr(),
            c"ERROR".as_ptr(),
            c"reason".as_ptr(),
            reason,
            null::<c_char>(),
        )
    };
}

/// A state as C's `"%d"`, NUL-terminated.
fn cnum(s: c_int) -> CString {
    CString::new(s.to_string()).expect("digits have no NUL")
}
