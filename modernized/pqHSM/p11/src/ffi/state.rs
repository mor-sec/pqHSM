//! The C ABI of the module state (`fhsm_state_*` in `include/fhsm_common.h`) over
//! [`pqhsm_core::state::State`] (Phase 4 slice 1b; replaces `src/fhsm_state.c`). Called by
//! `src/fhsm_pkcs11.c` and by the crypto, self-test and audit crates through their externs.
//! Each transition is audited after the lock is released, as C did: the audit subsystem
//! latches ERROR itself when a write fails, and a latch already set emits nothing.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{CString, c_char, c_int};
use std::ptr::null;

use pqhsm_core::state::State;

use super::sys::{audit, fhsm_audit_event};

/// `FHSM_EV_STATE_TRANSITION`.
const EV_STATE_TRANSITION: c_int = 6;
const OK: u32 = 0;
const FUNCTION_FAILED: u32 = 0x6;

static STATE: State = State::new();

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_state_get() -> c_int {
    STATE.get()
}

/// The entry points' `fhsm_state_get() == FHSM_STATE_ERROR`.
pub(crate) fn in_error() -> bool {
    STATE.get() == pqhsm_core::state::ERROR
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_state_set(to: c_int) -> u32 {
    match STATE.set(to) {
        Ok(from) => {
            let (from, to) = (cnum(from), cnum(to));
            // DIV-001: a transition that cannot be recorded is 0x30 (the audit has latched ERROR)
            match audit(
                EV_STATE_TRANSITION,
                -1,
                -1,
                0,
                OK,
                &[(c"from", &from), (c"to", &to)],
            ) {
                Ok(()) => OK,
                Err(e) => e,
            }
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
    // The latch's own record: nothing to suppress, so its result is not used.
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
pub(super) fn cnum(s: c_int) -> CString {
    CString::new(s.to_string()).expect("digits have no NUL")
}
