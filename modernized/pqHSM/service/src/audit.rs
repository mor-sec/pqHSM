//! The audit log the module opened at C_Initialize, written through its own C ABI
//! (`audit/src/ffi/c_abi.rs`): the record goes to the same log, under the same thread actor.

use std::ffi::{CString, c_char, c_int};
use std::ptr::null;

unsafe extern "C" {
    fn pqhsm_audit_event_v(
        ev: c_int,
        slot: c_int,
        session: c_int,
        role: c_int,
        rv: u32,
        kv: *const *const c_char,
        npairs: usize,
    ) -> u32;
    fn fhsm_audit_set_actor(subject: *const c_char);
}

// `include/fhsm_audit.h`'s codes.
pub const EV_SERVICE_START: c_int = 80;
pub const EV_SERVICE_STOP: c_int = 81;
pub const EV_REQUEST_ACCEPTED: c_int = 82;
pub const EV_REQUEST_REFUSED: c_int = 83;
pub const EV_IDENTITY_RESUMED: c_int = 84;
pub const ROLE_NONE: c_int = 0;
pub const ROLE_USER: c_int = 2;
pub const RV_OK: u32 = 0;
pub const RV_FUNCTION_FAILED: u32 = 6;

/// `fhsm_audit_event`: the result is discarded, as each of C's call sites does (DIV-001's
/// Phase 6 part is slice 2's). Keys and values hold no NUL: every one is a constant, a
/// number, or a header value the reader checked byte by byte.
pub fn event(
    ev: c_int,
    slot: c_int,
    session: c_int,
    role: c_int,
    rv: u32,
    params: &[(&str, &[u8])],
) {
    let owned: Vec<(CString, CString)> = params
        .iter()
        .map(|(k, v)| {
            (
                CString::new(*k).unwrap_or_default(),
                CString::new(*v).unwrap_or_default(),
            )
        })
        .collect();
    let kv: Vec<*const c_char> = owned
        .iter()
        .flat_map(|(k, v)| [k.as_ptr(), v.as_ptr()])
        .collect();
    // SAFETY: 2 * npairs valid C strings, alive for the call.
    unsafe { pqhsm_audit_event_v(ev, slot, session, role, rv, kv.as_ptr(), owned.len()) };
}

/// `fhsm_audit_set_actor` for this thread; `None` clears it.
pub fn set_actor(subject: Option<&[u8]>) {
    let c = subject.map(|s| CString::new(s).unwrap_or_default());
    // SAFETY: NULL or a C string alive for the call (the log copies it).
    unsafe { fhsm_audit_set_actor(c.as_ref().map_or(null(), |c| c.as_ptr())) };
}
