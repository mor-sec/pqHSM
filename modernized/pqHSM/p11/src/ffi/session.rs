//! The C ABI of `include/fhsm_session.h` over [`pqhsm_core::session::Table`]: the eleven
//! `fhsm_session_*` functions `src/fhsm_pkcs11.c` calls (Phase 4 slice 1a; replaces
//! `src/fhsm_session.c`). The token calls go to `fhsm_token_*`, which the token crate exports.
//!
//! One difference, unreachable from C: `fhsm_session_open` with a NULL out pointer is
//! `ARGUMENTS_BAD`; C wrote through it. Its one caller, `C_OpenSession`, refuses a NULL first.
#![allow(non_camel_case_types, clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, c_ulong};
use std::ptr::NonNull;

use pqhsm_core::session::{OK, Table, Token};

const ARGUMENTS_BAD: u32 = 0x7;

/// `struct fhsm_token_s`, opaque.
#[repr(C)]
pub struct fhsm_token_t {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    fn fhsm_token_login(t: *mut fhsm_token_t, role: c_int, pin: *const c_char, len: usize) -> u32;
    fn fhsm_token_logout(t: *mut fhsm_token_t);
    fn fhsm_token_current_role(t: *const fhsm_token_t) -> c_int;
}

/// A token the slot registry owns; the table only names it, as C's pointer did.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Tok(NonNull<fhsm_token_t>);

// SAFETY: the pointer is only compared and handed to fhsm_token_*, which lock the token
// themselves; C shared the same pointers between threads.
unsafe impl Send for Tok {}

impl Token for Tok {
    type Pin = (*const c_char, usize);
    fn login(self, role: c_int, (pin, len): Self::Pin) -> u32 {
        // SAFETY: a token the registry attached; pin and len are the caller's, passed on as C did
        unsafe { fhsm_token_login(self.0.as_ptr(), role, pin, len) }
    }
    fn logout(self) {
        // SAFETY: as above
        unsafe { fhsm_token_logout(self.0.as_ptr()) }
    }
    fn role(self) -> c_int {
        // SAFETY: as above
        unsafe { fhsm_token_current_role(self.0.as_ptr()) }
    }
}

static TABLE: Table<Tok> = Table::new();

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_session_open(
    slot: c_ulong,
    flags: c_ulong,
    out: *mut c_ulong,
) -> u32 {
    if out.is_null() {
        return ARGUMENTS_BAD;
    }
    match TABLE.open(slot, flags) {
        Ok(h) => {
            // SAFETY: non-NULL, and the caller's contract: writable
            unsafe { *out = h };
            OK
        }
        Err(rv) => rv,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_session_close(h: c_ulong) -> u32 {
    TABLE.close(h)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_session_login(
    h: c_ulong,
    role: c_int,
    pin: *const c_char,
    len: usize,
) -> u32 {
    TABLE.login(h, role, (pin, len))
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_session_logout(h: c_ulong) -> u32 {
    TABLE.logout(h)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_session_attach_token(h: c_ulong, t: *mut fhsm_token_t) -> u32 {
    TABLE.attach(h, NonNull::new(t).map(Tok))
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_session_token(h: c_ulong) -> *mut fhsm_token_t {
    TABLE
        .token(h)
        .map_or(std::ptr::null_mut(), |t| t.0.as_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_session_role(h: c_ulong) -> c_int {
    TABLE.role(h)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_session_ro_exists(t: *const fhsm_token_t) -> c_int {
    TABLE.ro_exists(NonNull::new(t.cast_mut()).map(Tok)) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_session_exists_on_slot(slot: c_ulong) -> c_int {
    TABLE.exists_on_slot(slot) as c_int
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_session_reset_all() {
    TABLE.reset_all()
}

/// Any out pointer may be NULL; none is written on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_session_info(
    h: c_ulong,
    out_slot: *mut c_ulong,
    out_flags: *mut c_ulong,
    out_role: *mut c_int,
) -> u32 {
    match TABLE.info(h) {
        Ok((slot, flags, role)) => {
            // SAFETY: each is NULL or, by the caller's contract, writable
            unsafe {
                if let Some(p) = out_slot.as_mut() {
                    *p = slot;
                }
                if let Some(p) = out_flags.as_mut() {
                    *p = flags;
                }
                if let Some(p) = out_role.as_mut() {
                    *p = role;
                }
            }
            OK
        }
        Err(rv) => rv,
    }
}
