//! `tools/pkiops.h` under its C names, for the C callers (`test_pkiops*`, the C tools not yet
//! ported, the GUI): each a thin shim over [`crate::ops`], C's argument conventions in, its
//! `struct p11_err` out.

use std::ffi::{CStr, OsStr, c_char, c_int, c_long, c_uint};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null;
use std::sync::atomic::{AtomicU32, Ordering};

use super::{fail, p11_err};
use crate::Error;
use crate::keys::{self, Alg};
use crate::ops::*;
use crate::sign::{self, Hash, Signing, Verdict, Verifying};
use crate::{envelope, objects};

/// A C string argument; C's strlen of NULL crashes, this aborts instead.
unsafe fn arg<'a>(p: *const c_char) -> &'a CStr {
    assert!(!p.is_null(), "a NULL string where tools/pkiops.h takes one");
    // SAFETY: the caller's C string.
    unsafe { CStr::from_ptr(p) }
}

/// # Safety
/// `out` null or writable.
unsafe fn put<T>(out: *mut T, v: T) {
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
        Err(x) => unsafe { fail(e, x) },
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
    status(
        crate::parse_slot(unsafe { arg(text) }.to_bytes()),
        e,
        |v| unsafe { put(out, v) },
    )
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
    status(token_info(Slot(slot)), e, |v| unsafe { put(out, v) })
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
    status(token_init(Slot(slot), so, user, label), e, |()| ())
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
    status(Alg::parse(name), e, |a| unsafe { put(out, a as c_uint) })
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
    status(
        key_alg(Session(session), unsafe { arg(label) }.to_bytes()),
        e,
        |a| unsafe { put(out, a as c_uint) },
    )
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
    status(session_user(Slot(slot), pin), e, |s| unsafe {
        put(session, s.0)
    })
}

/// `pkiops_session_close`.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_session_close(session: Handle) {
    session_close(Session(session))
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
        return unsafe { fail(e, Error::new(1, "no such algorithm\n")) };
    };
    status(
        keygen_alg(Session(session), unsafe { arg(label) }.to_bytes(), a),
        e,
        |(p, k)| {
            unsafe { put(pub_, p.0) };
            unsafe { put(priv_, k.0) };
        },
    )
}

/// The length of `pkiops_csr`'s and `pkiops_root`'s DER buffer. The buffer itself goes to the
/// encoder as the raw pointer it is: it may be uninitialised, so no slice is made over it.
unsafe fn der_room<'a>(der: *mut u8, len: *mut usize) -> &'a mut usize {
    assert!(
        !der.is_null() && !len.is_null(),
        "pkiops_csr, pkiops_root and pkiops_cms_sign write a DER buffer"
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

// --- slice 3: fhsm-crypt's ---------------------------------------------------------------------

/// A Vec copied into a malloc'd array the C caller frees: NULL when `null_if_empty` and there
/// is nothing, as C's `realloc`-grown lists leave it.
fn malloc_copy<T: Copy>(v: &[T], min: usize, null_if_empty: bool) -> Option<*mut T> {
    if v.is_empty() && null_if_empty {
        return Some(std::ptr::null_mut());
    }
    let n = v.len().max(min).max(1);
    // SAFETY: calloc of n elements of T, each zeroed; v.len() <= n of them written.
    unsafe {
        let p = libc::calloc(n, size_of::<T>()).cast::<T>();
        if p.is_null() {
            return None;
        }
        std::ptr::copy_nonoverlapping(v.as_ptr(), p, v.len());
        Some(p)
    }
}

/// `*out` and `*n` from a list, or C's "out of memory".
fn list_out<T: Copy>(
    r: Result<Vec<T>, Error>,
    min: usize,
    null_if_empty: bool,
    out: *mut *mut T,
    n: *mut usize,
    e: *mut p11_err,
) -> c_int {
    let r = r.and_then(|v| {
        malloc_copy(&v, min, null_if_empty)
            .map(|p| (p, v.len()))
            .ok_or_else(|| Error::new(2, "out of memory\n"))
    });
    status(r, e, |(p, len)| {
        unsafe { put(out, p) };
        unsafe { put(n, len) };
    })
}

/// `pkiops_keys`: malloc'd, NULL when there are none.
///
/// # Safety
/// `out`, `n` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_keys(
    session: Handle,
    out: *mut *mut objects::Key,
    n: *mut usize,
    e: *mut p11_err,
) -> c_int {
    list_out(objects::keys(Session(session)), 0, true, out, n, e)
}

/// `pkiops_obj_class_name`: NULL out of range.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_obj_class_name(c: c_uint) -> *const c_char {
    objects::ObjClass::from_index(c).map_or(null(), |c| c.name().as_ptr())
}

/// `pkiops_objects`: malloc'd, NULL when there are none.
///
/// # Safety
/// `out`, `n` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_objects(
    session: Handle,
    classes: c_uint,
    out: *mut *mut objects::Object,
    n: *mut usize,
    e: *mut p11_err,
) -> c_int {
    list_out(
        objects::objects(Session(session), classes),
        0,
        true,
        out,
        n,
        e,
    )
}

/// `pkiops_object_attrs`: malloc'd room for C's 40 lines.
///
/// # Safety
/// `out`, `n` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_object_attrs(
    session: Handle,
    object: Handle,
    out: *mut *mut objects::Attr,
    n: *mut usize,
    e: *mut p11_err,
) -> c_int {
    list_out(
        objects::object_attrs(Session(session), ObjHandle(object)),
        40,
        false,
        out,
        n,
        e,
    )
}

/// `pkiops_destroy`.
///
/// # Safety
/// `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_destroy(session: Handle, object: Handle, e: *mut p11_err) -> c_int {
    status(
        objects::destroy(Session(session), ObjHandle(object)),
        e,
        |()| (),
    )
}

/// `pkiops_skey_name`: NULL out of range.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_skey_name(k: c_uint) -> *const c_char {
    keys::Skey::from_index(k).map_or(null(), |k| k.info().name.as_ptr())
}

/// `pkiops_skey_list`.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_skey_list() -> *const c_char {
    keys::SKEY_LIST.as_ptr()
}

/// `pkiops_skey_parse`.
///
/// # Safety
/// `name` is null or a C string; `out` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_skey_parse(
    name: *const c_char,
    out: *mut c_uint,
    e: *mut p11_err,
) -> c_int {
    let name = (!name.is_null()).then(|| unsafe { arg(name) }.to_bytes());
    status(keys::Skey::parse(name), e, |k| unsafe {
        put(out, k as c_uint)
    })
}

/// `pkiops_keygen_secret`.
///
/// # Safety
/// `label` is a C string; `key` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_keygen_secret(
    session: Handle,
    label: *const c_char,
    k: c_uint,
    key: *mut Handle,
    e: *mut p11_err,
) -> c_int {
    let Some(k) = keys::Skey::from_index(k) else {
        return unsafe { fail(e, Error::new(1, "no such key type\n")) };
    };
    let label = unsafe { arg(label) }.to_bytes();
    status(
        objects::keygen_secret(Session(session), label, k),
        e,
        |h| unsafe { put(key, h.0) },
    )
}

/// A C string path argument.
unsafe fn path_arg<'a>(p: *const c_char) -> &'a Path {
    Path::new(OsStr::from_bytes(unsafe { arg(p) }.to_bytes()))
}

/// `pkiops_encrypt_file`.
///
/// # Safety
/// The strings are C strings; `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_encrypt_file(
    session: Handle,
    label: *const c_char,
    in_path: *const c_char,
    out_path: *const c_char,
    e: *mut p11_err,
) -> c_int {
    let r = unsafe {
        envelope::encrypt_file(
            Session(session),
            arg(label).to_bytes(),
            path_arg(in_path),
            path_arg(out_path),
        )
    };
    status(r, e, |()| ())
}

/// `pkiops_encrypt_file_for_cert`.
///
/// # Safety
/// The strings are C strings; `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_encrypt_file_for_cert(
    cert_path: *const c_char,
    in_path: *const c_char,
    out_path: *const c_char,
    e: *mut p11_err,
) -> c_int {
    let r = unsafe {
        envelope::encrypt_file_for_cert(path_arg(cert_path), path_arg(in_path), path_arg(out_path))
    };
    status(r, e, |()| ())
}

/// `pkiops_decrypt_file`: the label used into `used` as `snprintf(used, used_cap, "%s")`.
///
/// # Safety
/// The paths are C strings; `used` null or `used_cap` writable bytes; `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_decrypt_file(
    session: Handle,
    in_path: *const c_char,
    out_path: *const c_char,
    used: *mut c_char,
    used_cap: usize,
    e: *mut p11_err,
) -> c_int {
    let mut label = None;
    let r = unsafe {
        envelope::decrypt_file(
            Session(session),
            path_arg(in_path),
            path_arg(out_path),
            &mut label,
        )
    };
    if let Some(label) = label
        && !used.is_null()
        && used_cap > 0
    {
        let n = label.len().min(used_cap - 1);
        // SAFETY: used_cap writable bytes, n + 1 <= used_cap of them written.
        unsafe {
            std::ptr::copy_nonoverlapping(label.as_ptr(), used.cast::<u8>(), n);
            *used.add(n) = 0;
        }
    }
    status(r, e, |()| ())
}

// --- slice 4: fhsm-sign's -----------------------------------------------------------------------

/// `g_stream_alg`: the algorithm the stream under way began with, for its end. C's zero, the
/// composite, before any.
static STREAM_ALG: AtomicU32 = AtomicU32::new(0);

fn stream_alg() -> Alg {
    Alg::from_index(STREAM_ALG.load(Ordering::Relaxed)).expect("stored from an Alg")
}

/// A byte argument; NULL is taken only with a zero length.
unsafe fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 {
        return &[];
    }
    assert!(!p.is_null(), "a NULL buffer where tools/pkiops.h takes one");
    // SAFETY: the caller's n readable bytes.
    unsafe { std::slice::from_raw_parts(p, n) }
}

/// `*out` and `*n`: a malloc'd copy of `v`, which the C caller frees.
fn malloc_out(
    r: Result<Vec<u8>, Error>,
    out: *mut *mut u8,
    n: *mut usize,
    e: *mut p11_err,
) -> c_int {
    list_out(r, 0, false, out, n, e)
}

/// `pkiops_sign_begin`.
///
/// # Safety
/// `label` is a C string; `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_sign_begin(
    session: Handle,
    label: *const c_char,
    e: *mut p11_err,
) -> c_int {
    let label = unsafe { arg(label) }.to_bytes();
    status(Signing::begin(Session(session), label), e, |op| {
        STREAM_ALG.store(op.alg as u32, Ordering::Relaxed)
    })
}

/// `pkiops_sign_update`.
///
/// # Safety
/// `data` has `len` readable bytes; `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_sign_update(
    session: Handle,
    data: *const u8,
    len: usize,
    e: *mut p11_err,
) -> c_int {
    let op = Signing {
        s: session,
        alg: stream_alg(),
    };
    status(op.update(unsafe { bytes(data, len) }), e, |()| ())
}

/// `pkiops_sign_end`: `*sig` malloc'd.
///
/// # Safety
/// `sig`, `sig_len` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_sign_end(
    session: Handle,
    sig: *mut *mut u8,
    sig_len: *mut usize,
    e: *mut p11_err,
) -> c_int {
    let op = Signing {
        s: session,
        alg: stream_alg(),
    };
    malloc_out(op.end(), sig, sig_len, e)
}

/// `pkiops_verify_begin`.
///
/// # Safety
/// As `pkiops_sign_begin`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_verify_begin(
    session: Handle,
    label: *const c_char,
    e: *mut p11_err,
) -> c_int {
    let label = unsafe { arg(label) }.to_bytes();
    status(Verifying::begin(Session(session), label), e, |op| {
        STREAM_ALG.store(op.alg as u32, Ordering::Relaxed)
    })
}

/// `pkiops_verify_update`.
///
/// # Safety
/// As `pkiops_sign_update`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_verify_update(
    session: Handle,
    data: *const u8,
    len: usize,
    e: *mut p11_err,
) -> c_int {
    let op = Verifying {
        s: session,
        alg: stream_alg(),
    };
    status(op.update(unsafe { bytes(data, len) }), e, |()| ())
}

/// `pkiops_verify_end`: `*valid` 1 or 0; a failure to check is the only error.
///
/// # Safety
/// `sig` has `sig_len` readable bytes; `valid` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_verify_end(
    session: Handle,
    sig: *const u8,
    sig_len: usize,
    valid: *mut c_int,
    e: *mut p11_err,
) -> c_int {
    let op = Verifying {
        s: session,
        alg: stream_alg(),
    };
    status(op.end(unsafe { bytes(sig, sig_len) }), e, |v| unsafe {
        put(valid, c_int::from(v))
    })
}

/// `pkiops_hash_begin`: NULL on failure; `pkiops_hash_end` frees it.
///
/// # Safety
/// `name` null or a C string; `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_hash_begin(name: *const c_char, e: *mut p11_err) -> *mut Hash {
    // SAFETY: the caller's C string, when not NULL.
    let name = (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) });
    match Hash::begin(name) {
        Ok(h) => Box::into_raw(Box::new(h)),
        Err(x) => {
            unsafe { fail(e, x) };
            std::ptr::null_mut()
        }
    }
}

/// `pkiops_hash_update`.
///
/// # Safety
/// `h` from `pkiops_hash_begin`, not yet ended; `data` has `len` readable bytes; `e` null or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_hash_update(
    h: *mut Hash,
    data: *const u8,
    len: usize,
    e: *mut p11_err,
) -> c_int {
    // SAFETY: the caller's live hash.
    let h = unsafe { h.as_mut() }.expect("a hash from pkiops_hash_begin");
    status(h.update(unsafe { bytes(data, len) }), e, |()| ())
}

/// `pkiops_hash_end`: frees `h` whatever happens.
///
/// # Safety
/// As `pkiops_hash_update`; `out` has 64 writable bytes; `out_len` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_hash_end(
    h: *mut Hash,
    out: *mut u8,
    out_len: *mut usize,
    e: *mut p11_err,
) -> c_int {
    assert!(
        !h.is_null() && !out.is_null(),
        "pkiops_hash_end takes a hash and 64 bytes"
    );
    // SAFETY: the caller hands h back, once.
    let h = unsafe { Box::from_raw(h) };
    status(h.end(), e, |d| {
        // SAFETY: d is at most 64 bytes, out's room.
        unsafe { std::ptr::copy_nonoverlapping(d.as_ptr(), out, d.len()) };
        unsafe { put(out_len, d.len()) };
    })
}

/// `pkiops_cms_sign`.
///
/// # Safety
/// `label` is a C string; `cert` and `digest` cover their lengths; `der` has `*der_len`
/// writable bytes; `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_cms_sign(
    session: Handle,
    label: *const c_char,
    cert: *const u8,
    cert_len: usize,
    digest: *const u8,
    digest_len: usize,
    der: *mut u8,
    der_len: *mut usize,
    e: *mut p11_err,
) -> c_int {
    let label = unsafe { arg(label) }.to_bytes();
    let (cert, digest) = unsafe { (bytes(cert, cert_len), bytes(digest, digest_len)) };
    let len = unsafe { der_room(der, der_len) };
    status(
        unsafe { sign::cms_sign_into(session, label, cert, digest, der, len) },
        e,
        |()| (),
    )
}

/// `pkiops_cms_digest`: 0 and `*name`, or -1.
///
/// # Safety
/// As `fhsm_pki_cms_digest`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_cms_digest(
    cms: *const u8,
    cms_len: usize,
    name: *mut *const c_char,
) -> c_int {
    // SAFETY: the caller's contract, fhsm_pki's.
    if unsafe { pqhsm_pki::ffi::fhsm_pki_cms_digest(cms, cms_len, name) } == 0 {
        0
    } else {
        -1
    }
}

/// `pkiops_cms_verify`: `*verdict` 1 verified, 0 not matching, -1 not a CMS it can read.
///
/// # Safety
/// `cms` and `digest` cover their lengths; `verdict` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_cms_verify(
    cms: *const u8,
    cms_len: usize,
    digest: *const u8,
    digest_len: usize,
    verdict: *mut c_int,
    e: *mut p11_err,
) -> c_int {
    let (cms, digest) = unsafe { (bytes(cms, cms_len), bytes(digest, digest_len)) };
    status(sign::cms_verify(cms, digest), e, |v| unsafe {
        put(
            verdict,
            match v {
                Verdict::Verified { .. } => 1,
                Verdict::Mismatch => 0,
                Verdict::Unreadable => -1,
            },
        )
    })
}
