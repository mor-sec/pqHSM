//! `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`, `C_Login`,
//! `C_Logout`, `C_InitPIN` and `C_SetPIN` (`src/fhsm_pkcs11.c:755-981`, `:603-613`,
//! `:1736-1789`; Phase 4 slice 1d), over the session table and the slot registry. The checks
//! run in C's order, so each bad call gets C's code.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{CString, c_char, c_int, c_ulong, c_void};

use pqhsm_core::p11::{self, MAX_SLOTS, ROLE_USER};
use pqhsm_core::session::{MAX, ROLE_NONE, ROLE_SO};

use super::apilock::Held;
use super::session::{TABLE, Tok};
use super::slots::{pin_copy, slot_token};
use super::state::in_error;
use super::sys::*;

const RW_SESSION: c_ulong = 0x2;
const SERIAL_SESSION: c_ulong = 0x4;
const CKU_CONTEXT_SPECIFIC: c_ulong = 2;

fn role_of(t: Tok) -> c_int {
    // SAFETY: a token the registry holds
    unsafe { fhsm_token_current_role(t.0.as_ptr()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_OpenSession(
    slot: c_ulong,
    flags: c_ulong,
    _app: *mut c_void,
    _notify: *mut c_void,
    out: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    if in_error() {
        return FUNCTION_FAILED.into();
    }
    if out.is_null() {
        return ARGUMENTS_BAD.into();
    }
    if slot >= MAX_SLOTS {
        return SLOT_ID_INVALID.into();
    }
    if flags & SERIAL_SESSION == 0 {
        return SESSION_PARALLEL_NOT_SUPPORTED.into();
    }
    let Some(t) = slot_token(slot) else {
        return TOKEN_NOT_PRESENT.into();
    };
    // The SO works only in read-write sessions.
    if flags & RW_SESSION == 0 && role_of(t) == ROLE_SO {
        return SESSION_READ_WRITE_SO_EXISTS.into();
    }
    match TABLE.open(slot, flags) {
        Ok(h) => {
            // SAFETY: non-NULL, and by the caller's contract writable
            unsafe { *out = h };
            // A pooled handle may carry a closed session's operation state.
            // SAFETY: C's tables, under the API lock
            unsafe { pqhsm_c_session_ops_reset(h) };
            TABLE.attach(h, Some(t));
            OK.into()
        }
        Err(rv) => rv.into(),
    }
}

/// `C_CloseSession` without taking the lock, for `C_CloseAllSessions` (C's nested call took
/// nothing either).
fn close_session(h: c_ulong) -> u32 {
    if in_error() {
        return FUNCTION_FAILED;
    }
    // Before the handle returns to the pool, so its next owner inherits no operation.
    // SAFETY: C's tables, under the EXCLUSIVE lock
    unsafe { pqhsm_c_session_ops_reset(h) };
    let t = TABLE.token(h);
    if let Some(t) = t {
        // SAFETY: a token the registry holds
        unsafe { fhsm_token_destroy_session_objects(t.0.as_ptr(), h as u32) };
    }
    let before = t.map_or(ROLE_NONE, role_of);
    let rv = TABLE.close(h);
    // Closing the last session logs the token out; that is a logout, and audited as one.
    if let Some(t) = t
        && rv == OK
        && before != ROLE_NONE
        && role_of(t) == ROLE_NONE
    {
        audit(
            EV_LOGOUT,
            -1,
            h as c_int,
            before,
            rv,
            &[(c"cause", c"last-session-closed")],
        );
    }
    rv
}

#[unsafe(no_mangle)]
pub extern "C" fn pqhsm_C_CloseSession(h: c_ulong) -> c_ulong {
    let _g = Held::exclusive();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    close_session(h).into()
}

#[unsafe(no_mangle)]
pub extern "C" fn pqhsm_C_CloseAllSessions(slot: c_ulong) -> c_ulong {
    let _g = Held::exclusive();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    if in_error() {
        return FUNCTION_FAILED.into();
    }
    if slot != 0 {
        return SLOT_ID_INVALID.into();
    }
    for h in 1..MAX as c_ulong {
        if TABLE.token(h).is_some() {
            close_session(h);
        }
    }
    OK.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_GetSessionInfo(h: c_ulong, info: *mut c_void) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    if in_error() {
        return FUNCTION_FAILED.into();
    }
    if info.is_null() {
        return ARGUMENTS_BAD.into();
    }
    match TABLE.info(h) {
        Ok((slot, flags, role)) => {
            let out = info.cast::<c_ulong>();
            // SAFETY: by the caller's contract, a writable CK_SESSION_INFO (four CK_ULONGs)
            unsafe {
                *out = slot;
                *out.add(1) = p11::session_state(role, flags);
                *out.add(2) = flags;
                *out.add(3) = 0;
            }
            OK.into()
        }
        Err(rv) => rv.into(),
    }
}

/// The LOGIN_* event for a login's result.
fn login_event(rv: u32) -> c_int {
    match rv {
        OK => EV_LOGIN_OK,
        PIN_LOCKED => EV_LOGIN_LOCKED,
        PIN_THROTTLED => EV_LOGIN_THROTTLED,
        _ => EV_LOGIN_FAIL,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_Login(
    h: c_ulong,
    user_type: c_ulong,
    pin: *const c_char,
    pin_len: c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    if in_error() {
        return FUNCTION_FAILED.into();
    }
    if user_type == CKU_CONTEXT_SPECIFIC {
        return context_login(h, pin, pin_len).into();
    }
    let Some(role) = p11::role_of(user_type) else {
        return ARGUMENTS_BAD.into();
    };
    // ulPinLen, not strlen: PKCS#11 does not terminate pPin.
    let mut rv = TABLE.login(h, role, (pin, pin_len as usize));
    // RULE-083: the token answers 0x101 for a user PIN never set; PKCS#11 says 0x102.
    if rv == USER_NOT_LOGGED_IN && role == ROLE_USER {
        // SAFETY: a token the registry holds
        if let Some(t) = TABLE.token(h)
            && unsafe { fhsm_token_user_initialized(t.0.as_ptr()) } == 0
        {
            rv = USER_PIN_NOT_INITIALIZED;
        }
    }
    let name = if role == ROLE_SO { c"SO" } else { c"USER" };
    // C's char[16]: an unsigned long past 15 digits is cut.
    let digits = pin_len.to_string();
    let len = CString::new(&digits[..digits.len().min(15)]).expect("digits have no NUL");
    audit(
        login_event(rv),
        -1,
        h as c_int,
        role,
        rv,
        &[(c"role", name), (c"pin_len", &len)],
    );
    rv.into()
}

/// CKU_CONTEXT_SPECIFIC (§5.6): re-authenticates the user for this session's active
/// operations. Not the session login, which would answer ALREADY_LOGGED_IN without looking
/// at the PIN.
fn context_login(h: c_ulong, pin: *const c_char, pin_len: c_ulong) -> u32 {
    // SAFETY: C's tables, under the API lock
    match unsafe { pqhsm_c_session_has_active_op(h) } {
        a if a < 0 => return SESSION_HANDLE_INVALID,
        0 => return OPERATION_NOT_INITIALIZED,
        _ => {}
    }
    let Some(t) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID;
    };
    if role_of(t) != ROLE_USER {
        return USER_NOT_LOGGED_IN;
    }
    // SAFETY: a token the registry holds; pin and length are the caller's, passed on as C did
    let rv = unsafe { fhsm_token_verify_pin(t.0.as_ptr(), ROLE_USER, pin, pin_len as usize) };
    let len = CString::new(pin_len.to_string()).expect("digits have no NUL");
    audit(
        login_event(rv),
        -1,
        h as c_int,
        ROLE_USER,
        rv,
        &[(c"role", c"CONTEXT_SPECIFIC"), (c"pin_len", &len)],
    );
    if rv != OK {
        return rv;
    }
    // SAFETY: C's tables, under the API lock
    unsafe { pqhsm_c_session_ctx_auth_grant(h) };
    OK
}

#[unsafe(no_mangle)]
pub extern "C" fn pqhsm_C_Logout(h: c_ulong) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    if in_error() {
        return FUNCTION_FAILED.into();
    }
    let rv = TABLE.logout(h);
    audit(EV_LOGOUT, -1, h as c_int, ROLE_NONE, rv, &[]);
    rv.into()
}

/// A PIN argument's checks, in C's order: NULL, length, embedded NUL.
fn checked_pin(pin: *const c_char, len: c_ulong) -> Result<(), u32> {
    if pin.is_null() {
        return Err(ARGUMENTS_BAD);
    }
    if !p11::new_pin_len_ok(len) {
        return Err(PIN_LEN_RANGE);
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_InitPIN(
    h: c_ulong,
    pin: *const c_char,
    pin_len: c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    if in_error() {
        return FUNCTION_FAILED.into();
    }
    if let Err(rv) = checked_pin(pin, pin_len) {
        return rv.into();
    }
    let Some(mut pin_c) = pin_copy(pin, pin_len) else {
        return PIN_INVALID.into();
    };
    let t = TABLE.token(h);
    let r = TABLE.role(h);
    let rv = match t {
        None => Err(SESSION_HANDLE_INVALID),
        Some(_) if r != ROLE_SO => Err(USER_NOT_LOGGED_IN),
        // SAFETY: a token the registry holds; a NUL-terminated PIN copy
        Some(t) => Ok(unsafe { fhsm_token_init_user_pin(t.0.as_ptr(), pin_c.as_ptr().cast()) }),
    };
    zeroize(&mut pin_c);
    match rv {
        Err(rv) => rv.into(),
        Ok(rv) => {
            audit(EV_SET_PIN, -1, h as c_int, ROLE_SO, rv, &[]);
            rv.into()
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_SetPIN(
    h: c_ulong,
    old: *const c_char,
    old_len: c_ulong,
    new: *const c_char,
    new_len: c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    if in_error() {
        return FUNCTION_FAILED.into();
    }
    if old.is_null() || new.is_null() {
        return ARGUMENTS_BAD.into();
    }
    if !p11::pin_len_ok(old_len) || !p11::new_pin_len_ok(new_len) {
        return PIN_LEN_RANGE.into();
    }
    let Some(mut op) = pin_copy(old, old_len) else {
        return PIN_INVALID.into();
    };
    let Some(mut np) = pin_copy(new, new_len) else {
        zeroize(&mut op);
        return PIN_INVALID.into();
    };
    let t = TABLE.token(h);
    let r = TABLE.role(h);
    let rv = match t {
        None => Err(SESSION_HANDLE_INVALID),
        Some(_) if r == ROLE_NONE => Err(USER_NOT_LOGGED_IN),
        // SAFETY: a token the registry holds; NUL-terminated PIN copies
        Some(t) => Ok(unsafe {
            fhsm_token_set_pin(t.0.as_ptr(), r, op.as_ptr().cast(), np.as_ptr().cast())
        }),
    };
    zeroize(&mut op);
    zeroize(&mut np);
    match rv {
        Err(rv) => rv.into(),
        Ok(rv) => {
            audit(EV_SET_PIN, -1, h as c_int, r, rv, &[]);
            rv.into()
        }
    }
}
