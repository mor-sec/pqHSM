//! `tools/pkiops.h` under its C names, for the C callers (`test_pkiops*`, the C tools not yet
//! ported, the GUI): each a thin shim over [`crate::ops`], C's argument conventions in, its
//! `struct p11_err` out.

use std::ffi::{CStr, c_char, c_int, c_long, c_uint};
use std::ptr::null;

use super::{fail, p11_err};
use crate::Error;
use crate::keys::{self, Alg};
use crate::ops::*;

/// A C string argument; C's strlen of NULL crashes, this aborts instead.
unsafe fn arg<'a>(p: *const c_char) -> &'a CStr {
    assert!(!p.is_null(), "a NULL string where tools/pkiops.h takes one");
    // SAFETY: the caller's C string.
    unsafe { CStr::from_ptr(p) }
}

fn put<T>(out: *mut T, v: T) {
    // SAFETY: the caller's output, null or writable.
    if let Some(o) = unsafe { out.as_mut() } {
        *o = v;
    }
}

fn status<T>(r: Result<T, Error>, e: *mut p11_err, ok: impl FnOnce(T)) -> c_int {
    match r {
        Ok(v) => {
            ok(v);
            0
        }
        Err(x) => fail(e, x),
    }
}

/// `pkiops_parse_slot`.
///
/// # Safety
/// `text` is a C string; `out` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_parse_slot(
    text: *const c_char,
    out: *mut c_long,
    e: *mut p11_err,
) -> c_int {
    status(crate::parse_slot(unsafe { arg(text) }.to_bytes()), e, |v| {
        put(out, v)
    })
}

/// `pkiops_token_info`.
///
/// # Safety
/// `out` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_token_info(
    slot: Handle,
    out: *mut TokenInfo,
    e: *mut p11_err,
) -> c_int {
    status(token_info(slot), e, |v| put(out, v))
}

/// A PIN from C: `n` bytes at `p`, which may be NULL when `n` is 0.
///
/// # Safety
/// `p` points at `n` readable bytes when `n` > 0.
unsafe fn pin_arg<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 {
        &[]
    } else {
        assert!(!p.is_null(), "a NULL PIN with a length");
        // SAFETY: the caller's n bytes.
        unsafe { std::slice::from_raw_parts(p, n) }
    }
}

/// `pkiops_token_init`.
///
/// # Safety
/// The PINs are `so_len` and `user_len` readable bytes; `label` a C string; `e` null or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_token_init(
    slot: Handle,
    so_pin: *const u8,
    so_len: usize,
    user_pin: *const u8,
    user_len: usize,
    label: *const c_char,
    e: *mut p11_err,
) -> c_int {
    let (so, user) = unsafe { (pin_arg(so_pin, so_len), pin_arg(user_pin, user_len)) };
    let label = unsafe { arg(label) }.to_bytes();
    status(token_init(slot, so, user, label), e, |()| ())
}

/// `pkiops_alg_name`: NULL out of range.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_alg_name(a: c_uint) -> *const c_char {
    Alg::from_index(a).map_or(null(), |a| a.info().name.as_ptr())
}

/// `pkiops_alg_digest`: NULL out of range.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_alg_digest(a: c_uint) -> *const c_char {
    Alg::from_index(a).map_or(null(), |a| a.info().digest.as_ptr())
}

/// `pkiops_alg_list`.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_alg_list() -> *const c_char {
    keys::ALG_LIST.as_ptr()
}

/// `pkiops_alg_parse`.
///
/// # Safety
/// `name` is null or a C string; `out` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_alg_parse(
    name: *const c_char,
    out: *mut c_uint,
    e: *mut p11_err,
) -> c_int {
    let name = (!name.is_null()).then(|| unsafe { arg(name) }.to_bytes());
    status(Alg::parse(name), e, |a| put(out, a as c_uint))
}

/// `pkiops_key_alg`.
///
/// # Safety
/// `label` is a C string; `out` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_key_alg(
    session: Handle,
    label: *const c_char,
    out: *mut c_uint,
    e: *mut p11_err,
) -> c_int {
    status(key_alg(session, unsafe { arg(label) }.to_bytes()), e, |a| {
        put(out, a as c_uint)
    })
}

/// `pkiops_session_user`.
///
/// # Safety
/// `pin` has `pin_len` readable bytes; `session` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_session_user(
    slot: Handle,
    pin: *const u8,
    pin_len: usize,
    session: *mut Handle,
    e: *mut p11_err,
) -> c_int {
    let pin = unsafe { pin_arg(pin, pin_len) };
    status(session_user(slot, pin), e, |s| put(session, s))
}

/// `pkiops_session_close`.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_session_close(session: Handle) {
    session_close(session)
}

/// `pkiops_keygen`: the composite.
///
/// # Safety
/// As [`pkiops_keygen_alg`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_keygen(
    session: Handle,
    label: *const c_char,
    pub_: *mut Handle,
    priv_: *mut Handle,
    e: *mut p11_err,
) -> c_int {
    unsafe { pkiops_keygen_alg(session, label, Alg::Composite as c_uint, pub_, priv_, e) }
}

/// `pkiops_keygen_alg`.
///
/// # Safety
/// `label` is a C string; `pub_`, `priv_` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_keygen_alg(
    session: Handle,
    label: *const c_char,
    a: c_uint,
    pub_: *mut Handle,
    priv_: *mut Handle,
    e: *mut p11_err,
) -> c_int {
    let Some(a) = Alg::from_index(a) else {
        return fail(e, Error::new(1, "no such algorithm\n"));
    };
    status(
        keygen_alg(session, unsafe { arg(label) }.to_bytes(), a),
        e,
        |(p, k)| {
            put(pub_, p);
            put(priv_, k);
        },
    )
}

/// The length of `pkiops_csr`'s and `pkiops_root`'s DER buffer. The buffer itself goes to the
/// encoder as the raw pointer it is: it may be uninitialised, so no slice is made over it.
unsafe fn der_room<'a>(der: *mut u8, len: *mut usize) -> &'a mut usize {
    assert!(
        !der.is_null() && !len.is_null(),
        "pkiops_csr and pkiops_root write a DER buffer"
    );
    // SAFETY: the caller's contract.
    unsafe { &mut *len }
}

/// `pkiops_csr`.
///
/// # Safety
/// `label` and `subject` are C strings; `der` has `*der_len` writable bytes; `e` null or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_csr(
    session: Handle,
    label: *const c_char,
    subject: *const c_char,
    der: *mut u8,
    der_len: *mut usize,
    e: *mut p11_err,
) -> c_int {
    let (label, subject) = unsafe { (arg(label).to_bytes(), arg(subject)) };
    let len = unsafe { der_room(der, der_len) };
    status(
        unsafe { csr_into(session, label, subject, der, len) },
        e,
        |()| (),
    )
}

/// `pkiops_root`.
///
/// # Safety
/// As [`pkiops_csr`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_root(
    session: Handle,
    label: *const c_char,
    subject: *const c_char,
    serial: c_long,
    days: c_int,
    der: *mut u8,
    der_len: *mut usize,
    e: *mut p11_err,
) -> c_int {
    let (label, subject) = unsafe { (arg(label).to_bytes(), arg(subject)) };
    let len = unsafe { der_room(der, der_len) };
    status(
        unsafe { root_into(session, label, subject, serial, days, der, len) },
        e,
        |()| (),
    )
}
