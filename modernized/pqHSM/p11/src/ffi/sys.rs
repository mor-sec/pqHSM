//! What the entry points call outside this crate: the token, audit and crypto exports of the
//! other crates (linked into the same staticlib), and the C still in `src/fhsm_pkcs11.c`,
//! reached through `p11/shim/pkcs11_tu.c` (the operation tables, find state and OAEP tables,
//! which later slices own).
#![allow(non_camel_case_types)]

use std::ffi::{CStr, CString, c_char, c_int, c_ulong, c_void};
use std::ptr::null;

/// `struct fhsm_token_s`, opaque.
#[repr(C)]
pub struct fhsm_token_t {
    _opaque: [u8; 0],
}

/// `fhsm_slice_t`, by value.
#[repr(C)]
pub struct Slice {
    pub data: *const u8,
    pub len: usize,
}

unsafe extern "C" {
    pub fn fhsm_token_load(path: *const c_char, out: *mut *mut fhsm_token_t) -> u32;
    pub fn fhsm_token_init(
        path: *const c_char,
        so_pin: *const c_char,
        label: *const c_char,
        out: *mut *mut fhsm_token_t,
    ) -> u32;
    pub fn fhsm_token_close(t: *mut fhsm_token_t);
    pub fn fhsm_token_login(
        t: *mut fhsm_token_t,
        role: c_int,
        pin: *const c_char,
        len: usize,
    ) -> u32;
    pub fn fhsm_token_logout(t: *mut fhsm_token_t);
    pub fn fhsm_token_current_role(t: *const fhsm_token_t) -> c_int;
    pub fn fhsm_token_verify_pin(
        t: *mut fhsm_token_t,
        role: c_int,
        pin: *const c_char,
        len: usize,
    ) -> u32;
    pub fn pqhsm_token_change_pin(
        t: *mut fhsm_token_t,
        role: c_int,
        old: *const c_char,
        old_len: usize,
        new: *const c_char,
        new_len: usize,
    ) -> u32;
    pub fn fhsm_token_init_user_pin(t: *mut fhsm_token_t, pin: *const c_char) -> u32;
    pub fn fhsm_token_reinit(
        t: *mut fhsm_token_t,
        so_pin: *const c_char,
        label: *const c_char,
    ) -> u32;
    pub fn fhsm_token_label(t: *const fhsm_token_t) -> *const c_char;
    pub fn fhsm_token_serial(t: *const fhsm_token_t) -> *const c_char;
    pub fn fhsm_token_user_initialized(t: *const fhsm_token_t) -> c_int;
    pub fn fhsm_token_is_locked(t: *const fhsm_token_t, role: c_int) -> c_int;
    pub fn fhsm_token_failed_count(t: *const fhsm_token_t, role: c_int) -> u32;
    pub fn fhsm_token_destroy_session_objects(t: *mut fhsm_token_t, owner: u32) -> u32;

    pub fn fhsm_audit_event(
        ev: c_int,
        slot: c_int,
        session: c_int,
        role: c_int,
        rv: u32,
        ...
    ) -> u32;
    pub fn fhsm_audit_key_provision(dir: *const c_char, key: *mut u8, sealed: *mut c_int) -> u32;
    pub fn fhsm_audit_open(path: *const c_char, key: Slice) -> u32;
    pub fn fhsm_audit_current_path(out: *mut c_char, cap: usize) -> usize;
    pub fn fhsm_audit_close();

    pub fn fhsm_secure_heap_init() -> u32;
    pub fn fhsm_crypto_init() -> u32;
    pub fn fhsm_crypto_finalize();
    pub fn fhsm_zeroize(p: *mut c_void, n: usize);

    // p11/shim/pkcs11_tu.c: C's statics, by accessor.
    pub fn pqhsm_c_session_ops_reset(h: c_ulong);
    pub fn pqhsm_c_session_has_active_op(h: c_ulong) -> c_int;
    pub fn pqhsm_c_session_ctx_auth_grant(h: c_ulong);
    pub fn pqhsm_c_ops_forget_all();
    pub fn pqhsm_c_ops_release_all();
    pub static pqhsm_c_audit_mandatory: c_int;
}

/// The `CK_RV`s these entry points return themselves (`include/fhsm_common.h`).
pub const OK: u32 = 0;
pub const SLOT_ID_INVALID: u32 = 0x3;
pub const FUNCTION_FAILED: u32 = 0x6;
pub const ARGUMENTS_BAD: u32 = 0x7;
pub const OPERATION_NOT_INITIALIZED: u32 = 0x91;
pub const PIN_INVALID: u32 = 0xA1;
pub const PIN_LEN_RANGE: u32 = 0xA2;
pub const PIN_LOCKED: u32 = 0xA4;
pub const SESSION_HANDLE_INVALID: u32 = 0xB3;
pub const SESSION_PARALLEL_NOT_SUPPORTED: u32 = 0xB4;
pub const SESSION_READ_ONLY: u32 = 0xB5;
pub const SESSION_EXISTS: u32 = 0xB6;
pub const SESSION_READ_WRITE_SO_EXISTS: u32 = 0xB8;
pub const TOKEN_NOT_PRESENT: u32 = 0xE0;
pub const USER_NOT_LOGGED_IN: u32 = 0x101;
pub const BUFFER_TOO_SMALL: u32 = 0x150;
pub const CRYPTOKI_NOT_INITIALIZED: u32 = 0x190;
pub const CRYPTOKI_ALREADY_INITIALIZED: u32 = 0x191;
pub const USER_PIN_NOT_INITIALIZED: u32 = 0x102;

/// `fhsm_audit_event_t` values these entry points emit.
pub const EV_MODULE_INIT: c_int = 1;
pub const EV_MODULE_FINALIZE: c_int = 2;
pub const EV_TOKEN_INIT: c_int = 10;
pub const EV_LOGIN_OK: c_int = 12;
pub const EV_LOGIN_FAIL: c_int = 13;
pub const EV_LOGIN_LOCKED: c_int = 14;
pub const EV_LOGOUT: c_int = 16;
pub const EV_SET_PIN: c_int = 17;

/// One `fhsm_audit_event` call with up to two key/value pairs. The result is discarded, as C's
/// `(void)` did (DIV-001 changes that later in the phase).
pub fn audit(ev: c_int, slot: c_int, session: c_int, role: c_int, rv: u32, kv: &[(&CStr, &CStr)]) {
    let end = null::<c_char>();
    // SAFETY: NUL-terminated keys and values alive for the call; the list ends with NULL
    unsafe {
        match kv {
            [] => fhsm_audit_event(ev, slot, session, role, rv, end),
            [(k, v)] => fhsm_audit_event(ev, slot, session, role, rv, k.as_ptr(), v.as_ptr(), end),
            [(k1, v1), (k2, v2), ..] => fhsm_audit_event(
                ev,
                slot,
                session,
                role,
                rv,
                k1.as_ptr(),
                v1.as_ptr(),
                k2.as_ptr(),
                v2.as_ptr(),
                end,
            ),
        };
    }
}

/// `fhsm_zeroize` over a stack copy of a secret.
pub fn zeroize(b: &mut [u8]) {
    // SAFETY: a live, writable buffer of that length
    unsafe { fhsm_zeroize(b.as_mut_ptr().cast(), b.len()) }
}

/// C's `snprintf(buf, cap, "%s", s)`: at most `cap - 1` bytes, then the NUL.
pub fn bounded(mut s: Vec<u8>, cap: usize) -> CString {
    s.truncate(cap - 1);
    CString::new(s).expect("from an environment string or a C string: no NUL")
}

/// An environment variable's bytes when set and non-empty, as C's `env && *env`.
pub fn env_nonempty(name: &str) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStringExt;
    std::env::var_os(name)
        .map(|v| v.into_vec())
        .filter(|v| !v.is_empty())
}

/// A message on stderr, as C's `fprintf(stderr, ...)`: one write, never a panic. Parts are
/// bytes because paths are printed raw, as C's `%s` did.
pub fn say(parts: &[&[u8]]) {
    use std::io::Write;
    let _ = std::io::stderr().write_all(&parts.concat());
}
