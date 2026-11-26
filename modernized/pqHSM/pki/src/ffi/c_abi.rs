//! The C ABI of `include/fhsm_revocation.h` over [`crate::revocation`], its `#[repr(C)]`
//! structs, and the two C encoder functions it imports from `src/fhsm_composite.c` (Phase 3).
//! The entry array of a `fhsm_rev_db_t` is a libc allocation, as in C: C callers build a
//! zeroed struct, add to it, and release it through `fhsm_rev_db_free`.
#![allow(non_camel_case_types)]
// The signatures are include/fhsm_revocation.h's, argument for argument.
#![allow(clippy::too_many_arguments)]

use std::ffi::{CStr, OsStr, c_char, c_int, c_long, c_ulonglong, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use crate::revocation::{self as rev, RevError};

/// `fhsm_rev_entry_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fhsm_rev_entry_t {
    pub serial: [u8; 64],
    pub serial_len: usize,
    pub date: [c_char; 16],
    pub reason: c_int,
}

/// `fhsm_rev_db_t`. `e` is a libc allocation: C callers build a zeroed struct, add to it and
/// release it through `fhsm_rev_db_free`.
#[repr(C)]
#[derive(Debug)]
pub struct fhsm_rev_db_t {
    pub crl_number: c_ulonglong,
    pub e: *mut fhsm_rev_entry_t,
    pub n: usize,
    pub cap: usize,
}

/// `fhsm_ocsp_stats_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct fhsm_ocsp_stats_t {
    pub asked: usize,
    pub ours: usize,
    pub revoked: usize,
    pub unknown: usize,
    pub nonce_echoed: c_int,
}

/// `fhsm_composite_sign_cb`.
pub type fhsm_composite_sign_cb =
    Option<unsafe extern "C" fn(*mut c_void, *const u8, usize, *mut u8, *mut usize) -> u32>;

/// `fhsm_composite_ocsp_single_t` (`include/fhsm_composite.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fhsm_composite_ocsp_single_t {
    pub cert_id: *const u8,
    pub cert_id_len: usize,
    pub status: c_int,
    pub revoked_at: *const u8,
    pub revoked_at_len: usize,
    pub reason: c_int,
    pub this_upd: *const u8,
    pub this_upd_len: usize,
    pub next_upd: *const u8,
    pub next_upd_len: usize,
}

/// `fhsm_pki_signer_t` (`include/fhsm_pki.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fhsm_pki_signer_t {
    pub algid: *const u8,
    pub algid_len: usize,
    pub spki: *const u8,
    pub spki_len: usize,
    pub sign: fhsm_composite_sign_cb,
    pub sign_ctx: *mut c_void,
}

/// `fhsm_composite_revoked_t` (`include/fhsm_composite.h`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct fhsm_composite_revoked_t {
    pub serial: *const u8,
    pub serial_len: usize,
    pub date: i64,
    pub reason: c_int,
}

/// # Safety
/// `p` is a NUL-terminated string.
unsafe fn cstr<'a>(p: *const c_char) -> &'a [u8] {
    // SAFETY: the caller's contract
    unsafe { CStr::from_ptr(p) }.to_bytes()
}

/// # Safety
/// `p` is NULL or a NUL-terminated string.
unsafe fn opt_str<'a>(p: *const c_char) -> Option<&'a str> {
    // SAFETY: the caller's contract
    (!p.is_null())
        .then(|| unsafe { CStr::from_ptr(p) }.to_str().ok())
        .flatten()
}

/// # Safety
/// `p` points at `n` readable bytes, or `n` is 0.
unsafe fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if p.is_null() || n == 0 {
        &[]
    } else {
        // SAFETY: the caller's contract
        unsafe { std::slice::from_raw_parts(p, n) }
    }
}

/// # Safety
/// `p` is a NUL-terminated path.
unsafe fn path<'a>(p: *const c_char) -> &'a Path {
    // SAFETY: the caller's contract
    Path::new(OsStr::from_bytes(unsafe { cstr(p) }))
}

/// C's `err`: the message cut to `cap - 1` bytes and NUL-terminated; nothing if NULL or 0.
///
/// # Safety
/// `err` is NULL or has `cap` writable bytes.
unsafe fn put_err(err: *mut c_char, cap: usize, msg: &str) {
    if err.is_null() || cap == 0 {
        return;
    }
    let n = msg.len().min(cap - 1);
    // SAFETY: n + 1 <= cap
    unsafe {
        std::ptr::copy_nonoverlapping(msg.as_ptr().cast(), err, n);
        *err.add(n) = 0;
    }
}

/// # Safety
/// As [`put_err`].
unsafe fn rv(r: Result<(), RevError>, err: *mut c_char, cap: usize) -> c_int {
    match r {
        Ok(()) => 0,
        Err(e) => {
            // SAFETY: the caller's contract
            unsafe { put_err(err, cap, &e.msg) };
            e.code
        }
    }
}

const EMPTY_DB: fhsm_rev_db_t = fhsm_rev_db_t {
    crl_number: 0,
    e: null_mut(),
    n: 0,
    cap: 0,
};

/// # Safety
/// `d` is a database built by this ABI (or zeroed).
unsafe fn entries(d: &fhsm_rev_db_t) -> &[fhsm_rev_entry_t] {
    if d.n == 0 {
        &[]
    } else {
        // SAFETY: e holds n initialised entries
        unsafe { std::slice::from_raw_parts(d.e, d.n) }
    }
}

/// A C `fhsm_rev_db_t` as a [`rev::Db`]: serials past 64 bytes cut there, dates up to their NUL.
///
/// # Safety
/// `d` holds `n` initialised entries at `e` (or `n` is 0), as this ABI and C callers build it.
pub unsafe fn to_db(d: &fhsm_rev_db_t) -> rev::Db {
    // SAFETY: the caller's contract
    let entries = unsafe { entries(d) }.iter().map(|e| rev::Entry {
        serial: e.serial[..e.serial_len.min(64)].to_vec(),
        date: e
            .date
            .iter()
            .take_while(|c| **c != 0)
            .map(|c| *c as u8)
            .collect(),
        reason: e.reason,
    });
    rev::Db {
        crl_number: d.crl_number,
        entries: entries.collect(),
    }
}

/// C's `db_grow` then append: 64 entries, doubling, never past the cap.
///
/// # Safety
/// As [`entries`].
unsafe fn push(d: &mut fhsm_rev_db_t, e: &fhsm_rev_entry_t) -> Result<(), RevError> {
    if d.n == d.cap {
        if d.n >= rev::MAX_ENTRIES {
            return Err(RevError {
                code: rev::EPARSE,
                msg: rev::too_many(),
            });
        }
        let want = if d.cap == 0 {
            64
        } else {
            (d.cap * 2).min(rev::MAX_ENTRIES)
        };
        // SAFETY: e is NULL or a realloc result
        let p = unsafe { libc::realloc(d.e.cast(), want * size_of::<fhsm_rev_entry_t>()) };
        if p.is_null() {
            return Err(RevError {
                code: rev::EIO,
                msg: "out of memory\n".into(),
            });
        }
        d.e = p.cast();
        d.cap = want;
    }
    // SAFETY: n < cap
    unsafe { d.e.add(d.n).write(*e) };
    d.n += 1;
    Ok(())
}

static REASON_NAMES: [&CStr; 9] = [
    c"unspecified",
    c"keyCompromise",
    c"cACompromise",
    c"affiliationChanged",
    c"superseded",
    c"cessationOfOperation",
    c"certificateHold",
    c"privilegeWithdrawn",
    c"aACompromise",
];
static REASON_LIST: &CStr = c"unspecified, keyCompromise, cACompromise, affiliationChanged, \
superseded, cessationOfOperation, certificateHold, privilegeWithdrawn, aACompromise";

/// # Safety
/// `name` is a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_reason_code(name: *const c_char) -> c_int {
    // SAFETY: the caller's contract
    rev::reason_code(unsafe { cstr(name) })
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_rev_reason_name(code: c_int) -> *const c_char {
    rev::reason_name(code)
        .and_then(|n| REASON_NAMES.iter().find(|c| c.to_bytes() == n.as_bytes()))
        .map_or(null(), |c| c.as_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_rev_reason_list() -> *const c_char {
    debug_assert_eq!(REASON_LIST.to_bytes(), rev::reason_list().as_bytes());
    REASON_LIST.as_ptr()
}

/// # Safety
/// `h` is a NUL-terminated string, `out` has `cap` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_hex_to_bytes(
    h: *const c_char,
    out: *mut u8,
    cap: usize,
    n: *mut usize,
) -> c_int {
    // SAFETY: the caller's contract
    let h = unsafe { cstr(h) };
    if h.is_empty() || !h.len().is_multiple_of(2) || h.len() / 2 > cap {
        return 0;
    }
    // pair by pair, as C: the bytes before a bad pair are written, n is not
    for (i, pair) in h.chunks(2).enumerate() {
        match rev::hex_to_bytes(pair, 1) {
            // SAFETY: i < h.len() / 2 <= cap
            Some(b) => unsafe { *out.add(i) = b[0] },
            None => return 0,
        }
    }
    // SAFETY: the caller's contract
    unsafe { *n = h.len() / 2 };
    1
}

/// # Safety
/// `s` is a NUL-terminated string, `out` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_date_to_time(s: *const c_char, out: *mut i64) -> c_int {
    // SAFETY: the caller's contract
    match rev::date_to_time(unsafe { cstr(s) }) {
        Some(t) => unsafe {
            *out = t;
            1
        },
        None => 0,
    }
}

/// # Safety
/// `out` has 16 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_time_to_date(when: i64, out: *mut c_char) -> c_int {
    match rev::time_to_date(when) {
        // SAFETY: the caller's contract; the date is 15 bytes
        Some(s) => unsafe {
            std::ptr::copy_nonoverlapping(s.as_ptr().cast(), out, 15);
            *out.add(15) = 0;
            1
        },
        None => 0,
    }
}

/// # Safety
/// `a` and `b` point at `na` and `nb` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_serial_eq(
    a: *const u8,
    na: usize,
    b: *const u8,
    nb: usize,
) -> c_int {
    // SAFETY: the caller's contract
    unsafe { rev::serial_eq(bytes(a, na), bytes(b, nb)) }.into()
}

/// # Safety
/// `path_c` is a NUL-terminated string, `d` is writable, `err` is NULL or has `err_cap` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_db_load(
    path_c: *const c_char,
    d: *mut fhsm_rev_db_t,
    err: *mut c_char,
    err_cap: usize,
) -> c_int {
    // SAFETY: the caller's contract
    let (d, p) = unsafe { (&mut *d, path(path_c)) };
    *d = EMPTY_DB;
    let db = match rev::Db::load(p) {
        Ok(db) => db,
        // SAFETY: the caller's contract
        Err(e) => return unsafe { rv(Err(e), err, err_cap) },
    };
    d.crl_number = db.crl_number;
    for e in &db.entries {
        let mut x = fhsm_rev_entry_t {
            serial: [0; 64],
            serial_len: e.serial.len(),
            date: [0; 16],
            reason: e.reason,
        };
        x.serial[..e.serial.len()].copy_from_slice(&e.serial);
        x.date
            .iter_mut()
            .zip(&e.date)
            .for_each(|(c, b)| *c = *b as c_char);
        // SAFETY: d was built here; err is the caller's
        if let Err(e) = unsafe { push(d, &x) } {
            unsafe { fhsm_rev_db_free(d) };
            return unsafe { rv(Err(e), err, err_cap) };
        }
    }
    0
}

/// # Safety
/// `path_c` is a NUL-terminated string, `d` a database built by this ABI, `err` as for load.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_db_save(
    path_c: *const c_char,
    d: *const fhsm_rev_db_t,
    err: *mut c_char,
    err_cap: usize,
) -> c_int {
    // SAFETY: the caller's contract
    unsafe { rv(to_db(&*d).save(path(path_c)), err, err_cap) }
}

/// DIV-074's lock, for the C GUI (`gui/fhsm_gui.c` under `PQHSM_REV_LOCK`): opaque to C.
pub struct fhsm_rev_lock_t(#[allow(dead_code)] rev::DbLock);

/// `rev::DbLock::take` with `LOCK_WAIT`: 0 and `*lock` set (free it with `fhsm_rev_db_unlock`),
/// or an error code and message with `*lock` NULL.
///
/// # Safety
/// `path_c` is a NUL-terminated string, `lock` is writable, `err` as for load.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_db_lock(
    path_c: *const c_char,
    exclusive: c_int,
    lock: *mut *mut fhsm_rev_lock_t,
    err: *mut c_char,
    err_cap: usize,
) -> c_int {
    // SAFETY: the caller's contract
    unsafe { *lock = null_mut() };
    // SAFETY: the caller's contract
    match rev::DbLock::take(unsafe { path(path_c) }, exclusive != 0, rev::LOCK_WAIT) {
        Ok(l) => {
            // SAFETY: the caller's contract
            unsafe { *lock = Box::into_raw(Box::new(fhsm_rev_lock_t(l))) };
            0
        }
        // SAFETY: the caller's contract
        Err(e) => unsafe { rv(Err(e), err, err_cap) },
    }
}

/// Releases a lock from `fhsm_rev_db_lock`; NULL is ignored.
///
/// # Safety
/// `lock` is NULL or from `fhsm_rev_db_lock`, not yet released.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_db_unlock(lock: *mut fhsm_rev_lock_t) {
    if !lock.is_null() {
        // SAFETY: the caller's contract
        drop(unsafe { Box::from_raw(lock) });
    }
}

/// # Safety
/// `d` is a database built by this ABI (or zeroed), `e` is readable, `err` as for load.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_db_add(
    d: *mut fhsm_rev_db_t,
    e: *const fhsm_rev_entry_t,
    err: *mut c_char,
    err_cap: usize,
) -> c_int {
    // SAFETY: the caller's contract
    unsafe { rv(push(&mut *d, &*e), err, err_cap) }
}

/// # Safety
/// `d` is a database built by this ABI, `serial` points at `n` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_db_find(
    d: *const fhsm_rev_db_t,
    serial: *const u8,
    n: usize,
) -> *const fhsm_rev_entry_t {
    // SAFETY: the caller's contract
    let (es, q) = unsafe { (entries(&*d), bytes(serial, n)) };
    es.iter()
        .find(|e| rev::serial_eq(q, &e.serial[..e.serial_len.min(64)]))
        .map_or(null(), |e| e as *const _)
}

/// # Safety
/// `d` is NULL or a database built by this ABI.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rev_db_free(d: *mut fhsm_rev_db_t) {
    // SAFETY: the caller's contract; e is NULL or a realloc result
    if let Some(d) = unsafe { d.as_mut() } {
        unsafe { libc::free(d.e.cast()) };
        *d = EMPTY_DB;
    }
}

/// # Safety
/// `out` has 5 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_ocsp_status_response(status: c_int, out: *mut u8) -> usize {
    match rev::status_response(status) {
        // SAFETY: the caller's contract
        Some(b) => unsafe {
            std::ptr::copy_nonoverlapping(b.as_ptr(), out, 5);
            5
        },
        None => 0,
    }
}

/// # Safety
/// The DER pointers point at their lengths; the paths are NULL or NUL-terminated; `err` as
/// for load.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_ocsp_check_responder(
    responder_der: *const u8,
    responder_len: usize,
    ca_der: *const u8,
    ca_len: usize,
    responder_path: *const c_char,
    ca_path: *const c_char,
    err: *mut c_char,
    err_cap: usize,
) -> c_int {
    // SAFETY: the caller's contract
    unsafe {
        let r = rev::check_responder(
            bytes(responder_der, responder_len),
            bytes(ca_der, ca_len),
            opt_str(responder_path),
            opt_str(ca_path),
        );
        rv(r, err, err_cap)
    }
}

/// `fhsm_ocsp_answer_ex` with the composite's AlgorithmIdentifier. If that lookup fails it
/// returns before touching the outputs, as C did (candidate 15).
///
/// # Safety
/// As [`fhsm_ocsp_answer_ex`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_ocsp_answer(
    req: *const u8,
    req_len: usize,
    ca_der: *const u8,
    ca_len: usize,
    responder_der: *const u8,
    responder_len: usize,
    db: *const fhsm_rev_db_t,
    days: c_int,
    req_label: *const c_char,
    sign: fhsm_composite_sign_cb,
    sign_ctx: *mut c_void,
    out: *mut *mut u8,
    out_len: *mut usize,
    stats: *mut fhsm_ocsp_stats_t,
    err: *mut c_char,
    err_cap: usize,
) -> c_int {
    // C asks fhsm_pki_algid, which never fails for the composite: its "no composite
    // AlgorithmIdentifier" branch is unreachable and not carried over
    let (algid, algid_len) = (der::ALGID_COMPOSITE.as_ptr(), der::ALGID_COMPOSITE.len());
    // SAFETY: the caller's contract
    unsafe {
        fhsm_ocsp_answer_ex(
            req,
            req_len,
            ca_der,
            ca_len,
            responder_der,
            responder_len,
            db,
            days,
            req_label,
            algid,
            algid_len,
            sign,
            sign_ctx,
            out,
            out_len,
            stats,
            err,
            err_cap,
        )
    }
}

/// # Safety
/// The DER pointers point at their lengths; `db` is a database built by this ABI;
/// `req_label` is NULL or NUL-terminated; `out` and `out_len` are writable; `stats` is NULL
/// or writable; `err` as for load. `*out` is a libc allocation the caller frees.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_ocsp_answer_ex(
    req: *const u8,
    req_len: usize,
    ca_der: *const u8,
    ca_len: usize,
    responder_der: *const u8,
    responder_len: usize,
    db: *const fhsm_rev_db_t,
    days: c_int,
    req_label: *const c_char,
    algid: *const u8,
    algid_len: usize,
    sign: fhsm_composite_sign_cb,
    sign_ctx: *mut c_void,
    out: *mut *mut u8,
    out_len: *mut usize,
    stats: *mut fhsm_ocsp_stats_t,
    err: *mut c_char,
    err_cap: usize,
) -> c_int {
    // SAFETY: the caller's contract
    let (db, q_label, now) = unsafe {
        *out = null_mut();
        *out_len = 0;
        if let Some(s) = stats.as_mut() {
            *s = fhsm_ocsp_stats_t::default();
        }
        (to_db(&*db), opt_str(req_label), libc::time(null_mut()))
    };
    // SAFETY: the caller's contract
    let q = unsafe {
        rev::Query {
            req: bytes(req, req_len),
            ca: bytes(ca_der, ca_len),
            responder: bytes(responder_der, responder_len),
            db: &db,
            days,
            label: q_label,
            now,
        }
    };
    let signer = fhsm_pki_signer_t {
        algid,
        algid_len,
        spki: null(),
        spki_len: 0,
        sign,
        sign_ctx,
    };
    let mut encode = |t: &rev::Tbs<'_>| -> Result<Vec<u8>, u32> {
        // SAFETY: the caller's contract: algid covers algid_len, sign takes sign_ctx
        let Some(s) = (unsafe { signer_ok(&signer) }) else {
            return Err(crv::ARGUMENTS_BAD);
        };
        let mut sign = c_sign(s);
        let mut signer = Signer {
            // SAFETY: as above
            algid: unsafe { bytes(s.algid, s.algid_len) },
            sign: &mut sign,
        };
        x509::ocsp_for(&mut signer, t)
    };
    match rev::answer(&q, &mut encode) {
        // SAFETY: the caller's contract; malloc's result is checked
        Ok((resp, st)) => unsafe {
            let p: *mut u8 = libc::malloc(resp.len().max(1)).cast();
            if p.is_null() {
                put_err(err, err_cap, "out of memory\n");
                return rev::EIO;
            }
            std::ptr::copy_nonoverlapping(resp.as_ptr(), p, resp.len());
            *out = p;
            *out_len = resp.len();
            if let Some(s) = stats.as_mut() {
                *s = fhsm_ocsp_stats_t {
                    asked: st.asked,
                    ours: st.ours,
                    revoked: st.revoked,
                    unknown: st.unknown,
                    nonce_echoed: st.nonce_echoed.into(),
                };
            }
            0
        },
        // SAFETY: the caller's contract
        Err(e) => unsafe { rv(Err(e), err, err_cap) },
    }
}

// --- include/fhsm_composite.h (Phase 3 slice 5) --------------------------------------------

use crate::composite::{self as comp, CTX_MAX, PQ_SIG_LEN, Params, TRAD_SIG_LEN};
use crate::ffi::composite::{self as ossl, cleanse, rv as crv};

/// `fhsm_composite_params_t`.
#[repr(C)]
#[derive(Debug)]
pub struct fhsm_composite_params_t {
    pub alg: c_int,
    pub name: *const c_char,
    pub oid: *const c_char,
    pub label: *const c_char,
    pub label_len: usize,
    pub ph_name: *const c_char,
    pub ph_len: usize,
}

struct CParams([fhsm_composite_params_t; 1]);
// SAFETY: the pointers are to static C strings, never written
unsafe impl Sync for CParams {}

static C_PARAMS: CParams = CParams({
    let p = &comp::PARAMS[0];
    [fhsm_composite_params_t {
        alg: p.alg,
        name: p.name.as_ptr(),
        oid: p.oid.as_ptr(),
        label: p.label.as_ptr(),
        label_len: p.label.count_bytes(),
        ph_name: p.ph_name.as_ptr(),
        ph_len: p.ph_len,
    }]
});

/// `fhsm_composite_params`.
#[unsafe(no_mangle)]
pub extern "C" fn fhsm_composite_params(alg: c_int) -> *const fhsm_composite_params_t {
    C_PARAMS
        .0
        .iter()
        .find(|p| p.alg == alg)
        .map_or(null(), |p| p as *const _)
}

/// `fhsm_composite_mprime_len`.
#[unsafe(no_mangle)]
pub extern "C" fn fhsm_composite_mprime_len(alg: c_int, ctx_len: usize) -> usize {
    comp::mprime_len(alg, ctx_len)
}

/// `fhsm_composite_ph_name`.
#[unsafe(no_mangle)]
pub extern "C" fn fhsm_composite_ph_name(alg: c_int) -> *const c_char {
    comp::params(alg).map_or(null(), |p| p.ph_name.as_ptr())
}

/// `fhsm_composite_ph_len`.
#[unsafe(no_mangle)]
pub extern "C" fn fhsm_composite_ph_len(alg: c_int) -> usize {
    comp::params(alg).map_or(0, |p| p.ph_len)
}

/// `mprime_layout`, with its checks in C's order: the context pointer, PH, the context's length,
/// the room. On OK `*out_len` is the length written.
///
/// # Safety
/// As `fhsm_composite_mprime_prehashed`, `ph` non-null.
unsafe fn mprime_layout(
    p: &Params,
    ph: *const u8,
    ph_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    out: *mut u8,
    out_len: &mut usize,
) -> u32 {
    if ctx.is_null() && ctx_len != 0 {
        return crv::ARGUMENTS_BAD;
    }
    if ph.is_null() || ph_len != p.ph_len {
        return crv::ARGUMENTS_BAD;
    }
    if ctx_len > CTX_MAX {
        return crv::DATA_LEN_RANGE;
    }
    let need = comp::mprime_len(p.alg, ctx_len);
    if *out_len < need {
        *out_len = need;
        return crv::BUFFER_TOO_SMALL;
    }
    // SAFETY: ph has ph_len bytes, ctx ctx_len, out *out_len >= need (the caller's contract)
    unsafe {
        let out = std::slice::from_raw_parts_mut(out, need);
        *out_len = comp::layout(p, bytes(ph, ph_len), bytes(ctx, ctx_len), out);
    }
    crv::OK
}

/// `fhsm_composite_mprime_prehashed`.
///
/// # Safety
/// `ph` has `ph_len` readable bytes, `ctx` `ctx_len`, `out` `*out_len` writable bytes, each
/// pointer when not NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_mprime_prehashed(
    alg: c_int,
    ph: *const u8,
    ph_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    let Some(p) = comp::params(alg) else {
        return crv::ARGUMENTS_BAD;
    };
    if out.is_null() || out_len.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    // SAFETY: the caller's contract
    unsafe { mprime_layout(p, ph, ph_len, ctx, ctx_len, out, &mut *out_len) }
}

/// `fhsm_composite_mprime`: PH(M) computed after the size query and the context bound, and the
/// whole of M' zeroed when the digest or the layout fails.
///
/// # Safety
/// `msg` has `msg_len` readable bytes, `ctx` `ctx_len`, `out` `*out_len` writable bytes, each
/// pointer when not NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_mprime(
    alg: c_int,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    let Some(p) = comp::params(alg) else {
        return crv::ARGUMENTS_BAD;
    };
    if out.is_null() || out_len.is_null() || (msg.is_null() && msg_len != 0) {
        return crv::ARGUMENTS_BAD;
    }
    if ctx_len > CTX_MAX {
        return crv::DATA_LEN_RANGE;
    }
    let need = comp::mprime_len(alg, ctx_len);
    // SAFETY: out_len is writable; msg, ctx and out as the caller's contract says
    unsafe {
        if *out_len < need {
            *out_len = need;
            return crv::BUFFER_TOO_SMALL;
        }
        let mut ph = [0u8; openssl_sys::EVP_MAX_MD_SIZE as usize];
        let r = match ossl::ph(p, bytes(msg, msg_len), &mut ph) {
            Err(r) => return r,
            Ok(Some(n)) if n == p.ph_len => {
                mprime_layout(p, ph.as_ptr(), n, ctx, ctx_len, out, &mut *out_len)
            }
            Ok(_) => crv::FUNCTION_FAILED,
        };
        cleanse(&mut ph);
        if r != crv::OK {
            std::ptr::write_bytes(out, 0, need);
        }
        r
    }
}

/// `fhsm_composite_split`: the boundary is arithmetic, ML-DSA-65's 3309 bytes then Ed25519's 64.
///
/// # Safety
/// `pq_len` and `trad_len` are writable when not NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_split(
    alg: c_int,
    sig: *const u8,
    sig_len: usize,
    pq_len: *mut usize,
    trad_len: *mut usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512
        || sig.is_null()
        || pq_len.is_null()
        || trad_len.is_null()
    {
        return crv::ARGUMENTS_BAD;
    }
    if sig_len != PQ_SIG_LEN + TRAD_SIG_LEN {
        return crv::ARGUMENTS_BAD;
    }
    // SAFETY: both are writable
    unsafe {
        *pq_len = PQ_SIG_LEN;
        *trad_len = TRAD_SIG_LEN;
    }
    crv::OK
}

/// `blob_pack` into the caller's buffer: BUFFER_TOO_SMALL with the length needed.
///
/// # Safety
/// `out` has `*out_len` writable bytes.
unsafe fn pack_into(alg: c_int, pq: &[u8], trad: &[u8], out: *mut u8, out_len: &mut usize) -> u32 {
    let Some(need) = comp::blob_len(pq, trad) else {
        return crv::FUNCTION_FAILED;
    };
    if *out_len < need {
        *out_len = need;
        return crv::BUFFER_TOO_SMALL;
    }
    // SAFETY: *out_len >= need writable bytes
    comp::pack(alg, pq, trad, unsafe {
        std::slice::from_raw_parts_mut(out, need)
    });
    *out_len = need;
    crv::OK
}

/// `fhsm_composite_keygen`: both components fresh; the private blob is written before the
/// public one's room is checked, as in C.
///
/// # Safety
/// `private` has `*private_len` writable bytes, `public` `*public_len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_keygen(
    alg: c_int,
    private: *mut u8,
    private_len: *mut usize,
    public: *mut u8,
    public_len: *mut usize,
) -> u32 {
    let Some(p) = comp::params(alg) else {
        return crv::ARGUMENTS_BAD;
    };
    if private.is_null() || private_len.is_null() || public.is_null() || public_len.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    let Some([dpq, dtr, ppq, ptr]) = ossl::keygen(p) else {
        return crv::FUNCTION_FAILED;
    };
    // SAFETY: the caller's contract
    unsafe {
        let r = pack_into(alg, dpq.bytes(), dtr.bytes(), private, &mut *private_len);
        if r != crv::OK {
            return r;
        }
        pack_into(alg, ppq.bytes(), ptr.bytes(), public, &mut *public_len)
    }
}

/// `sign_mprime` around M', which is wiped after.
///
/// # Safety
/// `private` has `private_len` readable bytes, `sig` `*sig_len` writable.
unsafe fn sign_mprime(
    p: &Params,
    private: *const u8,
    private_len: usize,
    mprime: &mut [u8; 512],
    mplen: usize,
    sig: *mut u8,
    sig_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    let r = unsafe {
        ossl::sign_mprime(
            p,
            bytes(private, private_len),
            &mprime[..mplen],
            sig,
            &mut *sig_len,
        )
    };
    cleanse(mprime);
    r
}

/// `fhsm_composite_sign`.
///
/// # Safety
/// `private` has `private_len` readable bytes, `msg` `msg_len`, `ctx` `ctx_len`, `sig`
/// `*sig_len` writable, each pointer when not NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_sign(
    alg: c_int,
    private: *const u8,
    private_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *mut u8,
    sig_len: *mut usize,
) -> u32 {
    if private.is_null() || sig.is_null() || sig_len.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    let mut mprime = [0u8; 512];
    let mut mplen = mprime.len();
    // SAFETY: the caller's contract; mprime is 512 writable bytes
    unsafe {
        let r = fhsm_composite_mprime(
            alg,
            msg,
            msg_len,
            ctx,
            ctx_len,
            mprime.as_mut_ptr(),
            &mut mplen,
        );
        if r != crv::OK {
            return r;
        }
        // M' was built, so the algorithm is known
        let Some(p) = comp::params(alg) else {
            return crv::ARGUMENTS_BAD;
        };
        sign_mprime(p, private, private_len, &mut mprime, mplen, sig, sig_len)
    }
}

/// `fhsm_composite_sign_prehashed`.
///
/// # Safety
/// As `fhsm_composite_sign`, `ph` with `ph_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_sign_prehashed(
    alg: c_int,
    private: *const u8,
    private_len: usize,
    ph: *const u8,
    ph_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *mut u8,
    sig_len: *mut usize,
) -> u32 {
    if private.is_null() || sig.is_null() || sig_len.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    let mut mprime = [0u8; 512];
    let mut mplen = mprime.len();
    // SAFETY: as fhsm_composite_sign
    unsafe {
        let r = fhsm_composite_mprime_prehashed(
            alg,
            ph,
            ph_len,
            ctx,
            ctx_len,
            mprime.as_mut_ptr(),
            &mut mplen,
        );
        if r != crv::OK {
            return r;
        }
        // M' was built, so the algorithm is known
        let Some(p) = comp::params(alg) else {
            return crv::ARGUMENTS_BAD;
        };
        sign_mprime(p, private, private_len, &mut mprime, mplen, sig, sig_len)
    }
}

/// `verify_mprime`: the split, then the key, then both components; M' wiped after.
///
/// # Safety
/// `public` has `public_len` readable bytes, `sig` `sig_len`.
unsafe fn verify_mprime(
    p: &Params,
    public: *const u8,
    public_len: usize,
    mprime: &mut [u8; 512],
    mplen: usize,
    sig: *const u8,
    sig_len: usize,
) -> u32 {
    let (mut spq, mut str_) = (0, 0);
    // SAFETY: the caller's contract
    let r = unsafe {
        match fhsm_composite_split(p.alg, sig, sig_len, &mut spq, &mut str_) {
            crv::OK => {
                let sig = bytes(sig, sig_len);
                ossl::verify_mprime(
                    p,
                    bytes(public, public_len),
                    &mprime[..mplen],
                    &sig[..spq],
                    &sig[spq..spq + str_],
                )
            }
            r => r,
        }
    };
    cleanse(mprime);
    r
}

/// `fhsm_composite_verify`.
///
/// # Safety
/// `public` has `public_len` readable bytes, `msg` `msg_len`, `ctx` `ctx_len`, `sig`
/// `sig_len`, each pointer when not NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_verify(
    alg: c_int,
    public: *const u8,
    public_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> u32 {
    if public.is_null() || sig.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    let mut mprime = [0u8; 512];
    let mut mplen = mprime.len();
    // SAFETY: the caller's contract
    unsafe {
        let r = fhsm_composite_mprime(
            alg,
            msg,
            msg_len,
            ctx,
            ctx_len,
            mprime.as_mut_ptr(),
            &mut mplen,
        );
        if r != crv::OK {
            return r;
        }
        // M' was built, so the algorithm is known
        let Some(p) = comp::params(alg) else {
            return crv::ARGUMENTS_BAD;
        };
        verify_mprime(p, public, public_len, &mut mprime, mplen, sig, sig_len)
    }
}

/// `fhsm_composite_verify_prehashed`.
///
/// # Safety
/// As `fhsm_composite_verify`, `ph` with `ph_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_verify_prehashed(
    alg: c_int,
    public: *const u8,
    public_len: usize,
    ph: *const u8,
    ph_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> u32 {
    if public.is_null() || sig.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    let mut mprime = [0u8; 512];
    let mut mplen = mprime.len();
    // SAFETY: as fhsm_composite_verify
    unsafe {
        let r = fhsm_composite_mprime_prehashed(
            alg,
            ph,
            ph_len,
            ctx,
            ctx_len,
            mprime.as_mut_ptr(),
            &mut mplen,
        );
        if r != crv::OK {
            return r;
        }
        // M' was built, so the algorithm is known
        let Some(p) = comp::params(alg) else {
            return crv::ARGUMENTS_BAD;
        };
        verify_mprime(p, public, public_len, &mut mprime, mplen, sig, sig_len)
    }
}

// --- X.509 encoders (Phase 3 slice 5b, src/fhsm_composite.c:482-1450) ----------------------

use crate::ffi::x509::{self as x509, Issue, Signer};
use crate::x509 as der;

/// `fhsm_composite_rng_cb`.
pub type fhsm_composite_rng_cb = Option<unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> u32>;
/// The room `composite_signer` gives the composite SubjectPublicKeyInfo.
const SPKI_ROOM: usize = 8192;

/// `signer_ok`.
///
/// # Safety
/// `s` is NULL or points at a signer.
unsafe fn signer_ok<'a>(s: *const fhsm_pki_signer_t) -> Option<&'a fhsm_pki_signer_t> {
    // SAFETY: the caller's contract
    unsafe { s.as_ref() }.filter(|s| !s.algid.is_null() && s.algid_len != 0 && s.sign.is_some())
}

/// The signer's C callback as a builder's: `*sig_len` the room in, the length out. A length
/// past the room is refused rather than read.
fn c_sign(s: &fhsm_pki_signer_t) -> impl FnMut(&[u8], &mut [u8]) -> Result<usize, u32> + '_ {
    move |tbs, sig| {
        let mut n = sig.len();
        let cb = s.sign.expect("checked by signer_ok");
        // SAFETY: the callback's contract: tbs readable, sig n writable
        match unsafe {
            cb(
                s.sign_ctx,
                tbs.as_ptr(),
                tbs.len(),
                sig.as_mut_ptr(),
                &mut n,
            )
        } {
            crv::OK if n <= sig.len() => Ok(n),
            crv::OK => Err(crv::FUNCTION_FAILED),
            r => Err(r),
        }
    }
}

/// `emit_certificate`, and the end of `fhsm_pki_csr`: the length goes back either way.
///
/// # Safety
/// `out` has `*out_len` writable bytes.
unsafe fn emit(der: Result<Vec<u8>, u32>, out: *mut u8, out_len: &mut usize) -> u32 {
    let der = match der {
        Ok(d) => d,
        Err(r) => return r,
    };
    let r = if *out_len < der.len() {
        crv::BUFFER_TOO_SMALL
    } else {
        // SAFETY: *out_len >= der.len() writable bytes
        unsafe { std::ptr::copy_nonoverlapping(der.as_ptr(), out, der.len()) };
        crv::OK
    };
    *out_len = der.len();
    r
}

/// `fhsm_composite_raw_pub`.
///
/// # Safety
/// `public` has `public_len` readable bytes, `out` `*out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_raw_pub(
    alg: c_int,
    public: *const u8,
    public_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512 || public.is_null() || out.is_null() || out_len.is_null()
    {
        return crv::ARGUMENTS_BAD;
    }
    // SAFETY: the caller's contract
    unsafe {
        let (pq, trad) = match comp::unpack(alg, bytes(public, public_len)) {
            Ok(c) => c,
            Err(e) => return ossl::blob_rv(e),
        };
        if *out_len < der::RAW_PUB {
            *out_len = der::RAW_PUB;
            return crv::BUFFER_TOO_SMALL;
        }
        let r = x509::raw_pub(pq, trad, std::slice::from_raw_parts_mut(out, der::RAW_PUB));
        if r == crv::OK {
            *out_len = der::RAW_PUB;
        }
        r
    }
}

/// `fhsm_composite_spki`: hand-encoded, as C does; the OID has no NID in OpenSSL.
///
/// # Safety
/// As `fhsm_composite_raw_pub`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_spki(
    alg: c_int,
    public: *const u8,
    public_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512 || out.is_null() || out_len.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    let mut raw = [0u8; der::RAW_PUB];
    let mut n = raw.len();
    // SAFETY: the caller's contract; raw is RAW_PUB writable bytes
    unsafe {
        let r = fhsm_composite_raw_pub(alg, public, public_len, raw.as_mut_ptr(), &mut n);
        if r != crv::OK {
            return r;
        }
        let d = der::composite_spki(&raw[..n]);
        if *out_len < d.len() {
            *out_len = d.len();
            return crv::BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(d.as_ptr(), out, d.len());
        *out_len = d.len();
    }
    crv::OK
}

/// `fhsm_composite_algid`: the DER in static storage.
///
/// # Safety
/// `der` and `der_len` are writable when not NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_algid(
    alg: c_int,
    der: *mut *const u8,
    der_len: *mut usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512 || der.is_null() || der_len.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    // SAFETY: both are writable
    unsafe {
        *der = der::ALGID_COMPOSITE.as_ptr();
        *der_len = der::ALGID_COMPOSITE.len();
    }
    crv::OK
}

/// `fhsm_composite_pub_from_raw`: the module's public-key blob from mldsaPK || tradPK.
///
/// # Safety
/// `raw` has `raw_len` readable bytes, `public` `*public_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_pub_from_raw(
    alg: c_int,
    raw: *const u8,
    raw_len: usize,
    public: *mut u8,
    public_len: *mut usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512
        || raw.is_null()
        || public.is_null()
        || public_len.is_null()
    {
        return crv::ARGUMENTS_BAD;
    }
    if raw_len != der::RAW_PUB {
        return crv::ARGUMENTS_BAD;
    }
    // SAFETY: the caller's contract
    unsafe {
        match x509::pub_from_raw(bytes(raw, raw_len)) {
            Ok((q, t)) => pack_into(alg, &q, &t, public, &mut *public_len),
            Err(r) => r,
        }
    }
}

/// `composite_signer`: the composite's AlgorithmIdentifier and SubjectPublicKeyInfo, the latter
/// in `spki`, which must outlive the signer.
///
/// # Safety
/// As `fhsm_composite_spki`.
unsafe fn composite_signer(
    alg: c_int,
    public: *const u8,
    public_len: usize,
    sign: fhsm_composite_sign_cb,
    sign_ctx: *mut c_void,
    spki: &mut [u8; SPKI_ROOM],
) -> Result<fhsm_pki_signer_t, u32> {
    let mut n = spki.len();
    // SAFETY: the caller's contract; spki is SPKI_ROOM writable bytes
    let r = unsafe { fhsm_composite_spki(alg, public, public_len, spki.as_mut_ptr(), &mut n) };
    if r != crv::OK {
        return Err(r);
    }
    Ok(fhsm_pki_signer_t {
        algid: der::ALGID_COMPOSITE.as_ptr(),
        algid_len: der::ALGID_COMPOSITE.len(),
        spki: spki.as_ptr(),
        spki_len: n,
        sign,
        sign_ctx,
    })
}

/// `fhsm_pki_csr`: a PKCS#10 request, signed by `s`, for `s`'s own key.
///
/// # Safety
/// `s` is NULL or a signer whose pointers cover their lengths; `subject` is NULL or a C
/// string; `out` has `*out_len` writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_csr(
    s: *const fhsm_pki_signer_t,
    subject: *const c_char,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let Some(s) = signer_ok(s) else {
            return crv::ARGUMENTS_BAD;
        };
        if s.spki.is_null() || subject.is_null() || out.is_null() || out_len.is_null() {
            return crv::ARGUMENTS_BAD;
        }
        let mut sign = c_sign(s);
        let mut signer = Signer {
            algid: bytes(s.algid, s.algid_len),
            sign: &mut sign,
        };
        let d = x509::csr(&mut signer, bytes(s.spki, s.spki_len), cstr(subject));
        emit(d, out, &mut *out_len)
    }
}

/// `fhsm_composite_csr`.
///
/// # Safety
/// `subject` is NULL or a C string, `public` has `public_len` readable bytes, `out`
/// `*out_len` writable; `sign` is called with `sign_ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_csr(
    alg: c_int,
    subject: *const c_char,
    public: *const u8,
    public_len: usize,
    sign: fhsm_composite_sign_cb,
    sign_ctx: *mut c_void,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512
        || subject.is_null()
        || public.is_null()
        || sign.is_none()
        || out.is_null()
        || out_len.is_null()
    {
        return crv::ARGUMENTS_BAD;
    }
    let mut spki = [0u8; SPKI_ROOM];
    // SAFETY: the caller's contract; spki outlives the signer
    unsafe {
        match composite_signer(alg, public, public_len, sign, sign_ctx, &mut spki) {
            Ok(s) => fhsm_pki_csr(&s, subject, out, out_len),
            Err(r) => r,
        }
    }
}

/// `fhsm_pki_selfsigned`: a root, CA:TRUE, keyCertSign and cRLSign.
///
/// # Safety
/// As `fhsm_pki_csr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_selfsigned(
    s: *const fhsm_pki_signer_t,
    subject: *const c_char,
    serial: c_long,
    days: c_int,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let Some(s) = signer_ok(s) else {
            return crv::ARGUMENTS_BAD;
        };
        if s.spki.is_null() || subject.is_null() || out.is_null() || out_len.is_null() {
            return crv::ARGUMENTS_BAD;
        }
        // serial 0 is malformed and a negative one encodes negative (RFC 5280 4.1.2.2)
        if serial <= 0 || days <= 0 {
            return crv::ARGUMENTS_BAD;
        }
        let mut sign = c_sign(s);
        let mut signer = Signer {
            algid: bytes(s.algid, s.algid_len),
            sign: &mut sign,
        };
        let d = x509::selfsigned(
            &mut signer,
            bytes(s.spki, s.spki_len),
            cstr(subject),
            serial,
            days,
        );
        emit(d, out, &mut *out_len)
    }
}

/// `fhsm_composite_selfsigned`.
///
/// # Safety
/// As `fhsm_composite_csr`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_selfsigned(
    alg: c_int,
    subject: *const c_char,
    serial: c_long,
    days: c_int,
    public: *const u8,
    public_len: usize,
    sign: fhsm_composite_sign_cb,
    sign_ctx: *mut c_void,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512
        || subject.is_null()
        || public.is_null()
        || sign.is_none()
        || out.is_null()
        || out_len.is_null()
    {
        return crv::ARGUMENTS_BAD;
    }
    if serial <= 0 || days <= 0 {
        return crv::ARGUMENTS_BAD;
    }
    let mut spki = [0u8; SPKI_ROOM];
    // SAFETY: the caller's contract; spki outlives the signer
    unsafe {
        match composite_signer(alg, public, public_len, sign, sign_ctx, &mut spki) {
            Ok(s) => fhsm_pki_selfsigned(&s, subject, serial, days, out, out_len),
            Err(r) => r,
        }
    }
}

/// `fhsm_pki_issue`: a certificate for the request's key, under the CA's name, after proof of
/// possession; the request's own extensions are never read.
///
/// # Safety
/// As `fhsm_pki_csr`; `ca_cert` and `csr` cover their lengths, `subject_override` and `san`
/// are NULL or C strings, `crl_urls` is NULL or `n_crl_urls` entries each NULL or a C string;
/// `rng` is called with `rng_ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_issue(
    s: *const fhsm_pki_signer_t,
    ca_cert: *const u8,
    ca_cert_len: usize,
    csr: *const u8,
    csr_len: usize,
    subject_override: *const c_char,
    san: *const c_char,
    crl_urls: *const *const c_char,
    n_crl_urls: usize,
    profile: c_int,
    days: c_int,
    rng: fhsm_composite_rng_cb,
    rng_ctx: *mut c_void,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let Some(s) = signer_ok(s) else {
            return crv::ARGUMENTS_BAD;
        };
        let Some(rng) = rng else {
            return crv::ARGUMENTS_BAD;
        };
        if ca_cert.is_null() || csr.is_null() || out.is_null() || out_len.is_null() || days <= 0 {
            return crv::ARGUMENTS_BAD;
        }
        let opt = |p: *const c_char| (!p.is_null()).then(|| cstr(p));
        let urls: Vec<Option<&[u8]>> = if crl_urls.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(crl_urls, n_crl_urls)
                .iter()
                .map(|&u| opt(u))
                .collect()
        };
        let i = Issue {
            ca: bytes(ca_cert, ca_cert_len),
            csr: bytes(csr, csr_len),
            subject: opt(subject_override),
            san: opt(san),
            crl_urls: &urls,
            profile,
            days,
        };
        let mut sign = c_sign(s);
        let mut signer = Signer {
            algid: bytes(s.algid, s.algid_len),
            sign: &mut sign,
        };
        let mut draw = |b: &mut [u8]| rng(rng_ctx, b.as_mut_ptr(), b.len());
        emit(x509::issue(&mut signer, &i, &mut draw), out, &mut *out_len)
    }
}

/// `fhsm_composite_issue`: the signer has no SubjectPublicKeyInfo; the certificate carries
/// the requester's key and the callback holds the CA's.
///
/// # Safety
/// As `fhsm_pki_issue`; `sign` is called with `sign_ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_issue(
    alg: c_int,
    ca_cert: *const u8,
    ca_cert_len: usize,
    csr: *const u8,
    csr_len: usize,
    subject_override: *const c_char,
    san: *const c_char,
    crl_urls: *const *const c_char,
    n_crl_urls: usize,
    profile: c_int,
    days: c_int,
    sign: fhsm_composite_sign_cb,
    sign_ctx: *mut c_void,
    rng: fhsm_composite_rng_cb,
    rng_ctx: *mut c_void,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512
        || ca_cert.is_null()
        || csr.is_null()
        || sign.is_none()
        || rng.is_none()
        || out.is_null()
        || out_len.is_null()
    {
        return crv::ARGUMENTS_BAD;
    }
    if days <= 0 {
        return crv::ARGUMENTS_BAD;
    }
    let s = fhsm_pki_signer_t {
        algid: der::ALGID_COMPOSITE.as_ptr(),
        algid_len: der::ALGID_COMPOSITE.len(),
        spki: null(),
        spki_len: 0,
        sign,
        sign_ctx,
    };
    // SAFETY: the caller's contract
    unsafe {
        fhsm_pki_issue(
            &s,
            ca_cert,
            ca_cert_len,
            csr,
            csr_len,
            subject_override,
            san,
            crl_urls,
            n_crl_urls,
            profile,
            days,
            rng,
            rng_ctx,
            out,
            out_len,
        )
    }
}

// --- CRL and OCSP encoders (Phase 3 slice 5c, src/fhsm_composite.c:1451-2128) --------------

/// A part that must be present: NULL or empty is ARGUMENTS_BAD.
///
/// # Safety
/// `p` has `n` readable bytes when not NULL.
unsafe fn required<'a>(p: *const u8, n: usize) -> Result<&'a [u8], u32> {
    if p.is_null() || n == 0 {
        return Err(crv::ARGUMENTS_BAD);
    }
    // SAFETY: the caller's contract
    Ok(unsafe { bytes(p, n) })
}

/// A part that may be absent: NULL with 0 is absent; a pointer without a length, or a length
/// without a pointer, is a caller bug and ARGUMENTS_BAD.
///
/// # Safety
/// As `required`.
unsafe fn optional<'a>(p: *const u8, n: usize) -> Result<Option<&'a [u8]>, u32> {
    match (p.is_null(), n == 0) {
        (true, true) => Ok(None),
        // SAFETY: the caller's contract
        (false, false) => Ok(Some(unsafe { bytes(p, n) })),
        _ => Err(crv::ARGUMENTS_BAD),
    }
}

fn refused(r: der::Refused) -> u32 {
    match r {
        der::Refused::Arguments => crv::ARGUMENTS_BAD,
        der::Refused::TooLong => crv::FUNCTION_FAILED,
    }
}

/// `fhsm_composite_crl_tbs`.
///
/// # Safety
/// Each part has its length's readable bytes when not NULL; `out` has `*out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_crl_tbs(
    algid: *const u8,
    algid_len: usize,
    issuer: *const u8,
    issuer_len: usize,
    this_upd: *const u8,
    this_upd_len: usize,
    next_upd: *const u8,
    next_upd_len: usize,
    revoked: *const u8,
    revoked_len: usize,
    exts: *const u8,
    exts_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let parts = || -> Result<_, u32> {
            let r = (
                required(algid, algid_len)?,
                required(issuer, issuer_len)?,
                required(this_upd, this_upd_len)?,
            );
            if out.is_null() || out_len.is_null() {
                return Err(crv::ARGUMENTS_BAD);
            }
            let o = (
                optional(next_upd, next_upd_len)?,
                optional(revoked, revoked_len)?,
                optional(exts, exts_len)?,
            );
            Ok((r, o))
        };
        match parts() {
            Ok(((a, i, t), (n, r, e))) => emit(
                der::crl_tbs(a, i, t, n, r, e).map_err(refused),
                out,
                &mut *out_len,
            ),
            Err(r) => r,
        }
    }
}

/// `fhsm_pki_crl`: a complete CRL, signed by `s` as the CA in `ca_cert`.
///
/// # Safety
/// As `fhsm_pki_csr`; `ca_cert` covers its length, `revoked` is NULL or `n_revoked` entries
/// whose serials cover their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_crl(
    s: *const fhsm_pki_signer_t,
    ca_cert: *const u8,
    ca_cert_len: usize,
    revoked: *const fhsm_composite_revoked_t,
    n_revoked: usize,
    crl_number: u64,
    days: c_int,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let Some(s) = signer_ok(s) else {
            return crv::ARGUMENTS_BAD;
        };
        if ca_cert.is_null() || out.is_null() || out_len.is_null() || days <= 0 {
            return crv::ARGUMENTS_BAD;
        }
        if n_revoked != 0 && revoked.is_null() {
            return crv::ARGUMENTS_BAD;
        }
        let list: Vec<x509::Revoked> = if n_revoked == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(revoked, n_revoked)
                .iter()
                .map(|r| x509::Revoked {
                    serial: bytes(r.serial, r.serial_len),
                    date: r.date,
                    reason: r.reason,
                })
                .collect()
        };
        let mut sign = c_sign(s);
        let mut signer = Signer {
            algid: bytes(s.algid, s.algid_len),
            sign: &mut sign,
        };
        let d = x509::crl(
            &mut signer,
            bytes(ca_cert, ca_cert_len),
            &list,
            crl_number,
            days,
        );
        emit(d, out, &mut *out_len)
    }
}

/// `fhsm_composite_crl`.
///
/// # Safety
/// As `fhsm_pki_crl`; `sign` is called with `sign_ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_crl(
    alg: c_int,
    ca_cert: *const u8,
    ca_cert_len: usize,
    revoked: *const fhsm_composite_revoked_t,
    n_revoked: usize,
    crl_number: u64,
    days: c_int,
    sign: fhsm_composite_sign_cb,
    sign_ctx: *mut c_void,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512 || sign.is_none() {
        return crv::ARGUMENTS_BAD;
    }
    let s = composite_ca(sign, sign_ctx);
    // SAFETY: the caller's contract
    unsafe {
        fhsm_pki_crl(
            &s,
            ca_cert,
            ca_cert_len,
            revoked,
            n_revoked,
            crl_number,
            days,
            out,
            out_len,
        )
    }
}

/// The composite signer as a CA: its AlgorithmIdentifier and the callback, no
/// SubjectPublicKeyInfo.
fn composite_ca(sign: fhsm_composite_sign_cb, sign_ctx: *mut c_void) -> fhsm_pki_signer_t {
    fhsm_pki_signer_t {
        algid: der::ALGID_COMPOSITE.as_ptr(),
        algid_len: der::ALGID_COMPOSITE.len(),
        spki: null(),
        spki_len: 0,
        sign,
        sign_ctx,
    }
}

/// One SingleResponse's pointer/length pairs agreed, in C's order.
///
/// # Safety
/// Each pointer has its length's readable bytes when not NULL.
unsafe fn single<'a>(s: &fhsm_composite_ocsp_single_t) -> Result<x509::Single<'a>, u32> {
    // SAFETY: the caller's contract
    unsafe {
        Ok(x509::Single {
            cert_id: required(s.cert_id, s.cert_id_len)?,
            this_upd: required(s.this_upd, s.this_upd_len)?,
            next_upd: optional(s.next_upd, s.next_upd_len)?,
            status: s.status,
            revoked_at: optional(s.revoked_at, s.revoked_at_len)?,
            reason: s.reason,
        })
    }
}

/// `fhsm_composite_ocsp_single`.
///
/// # Safety
/// `s` is NULL or a single whose pointers cover their lengths; `out` has `*out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_ocsp_single(
    s: *const fhsm_composite_ocsp_single_t,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let Some(s) = s.as_ref() else {
            return crv::ARGUMENTS_BAD;
        };
        if out.is_null() || out_len.is_null() {
            return crv::ARGUMENTS_BAD;
        }
        emit(single(s).and_then(|s| s.encode()), out, &mut *out_len)
    }
}

/// `fhsm_composite_ocsp_tbs`.
///
/// # Safety
/// As `fhsm_composite_crl_tbs`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_ocsp_tbs(
    responder_id: *const u8,
    responder_id_len: usize,
    produced_at: *const u8,
    produced_at_len: usize,
    responses: *const u8,
    responses_len: usize,
    exts: *const u8,
    exts_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let parts = || -> Result<_, u32> {
            let r = (
                required(responder_id, responder_id_len)?,
                required(produced_at, produced_at_len)?,
                required(responses, responses_len)?,
            );
            if out.is_null() || out_len.is_null() {
                return Err(crv::ARGUMENTS_BAD);
            }
            Ok((r, optional(exts, exts_len)?))
        };
        match parts() {
            Ok(((r, p, q), e)) => emit(
                der::ocsp_tbs(r, p, q, e).map_err(refused),
                out,
                &mut *out_len,
            ),
            Err(r) => r,
        }
    }
}

/// `fhsm_pki_ocsp`: a BasicOCSPResponse, signed by `s` as the responder in `responder_cert`.
///
/// # Safety
/// As `fhsm_pki_csr`; `responder_cert`, `produced_at` and `exts` cover their lengths when not
/// NULL; `singles` is NULL or `n` singles whose pointers cover their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_ocsp(
    s: *const fhsm_pki_signer_t,
    responder_cert: *const u8,
    responder_cert_len: usize,
    produced_at: *const u8,
    produced_at_len: usize,
    singles: *const fhsm_composite_ocsp_single_t,
    n: usize,
    exts: *const u8,
    exts_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let Some(s) = signer_ok(s) else {
            return crv::ARGUMENTS_BAD;
        };
        let (Ok(rc), Ok(pa)) = (
            required(responder_cert, responder_cert_len),
            required(produced_at, produced_at_len),
        ) else {
            return crv::ARGUMENTS_BAD;
        };
        if singles.is_null() || n == 0 || out.is_null() || out_len.is_null() {
            return crv::ARGUMENTS_BAD;
        }
        let Ok(exts) = optional(exts, exts_len) else {
            return crv::ARGUMENTS_BAD;
        };
        let all = std::slice::from_raw_parts(singles, n)
            .iter()
            .map(|one| single(one));
        let mut sign = c_sign(s);
        let mut signer = Signer {
            algid: bytes(s.algid, s.algid_len),
            sign: &mut sign,
        };
        emit(
            x509::ocsp(&mut signer, rc, pa, all, exts),
            out,
            &mut *out_len,
        )
    }
}

/// `fhsm_composite_ocsp`.
///
/// # Safety
/// As `fhsm_pki_ocsp`; `sign` is called with `sign_ctx`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_ocsp(
    alg: c_int,
    responder_cert: *const u8,
    responder_cert_len: usize,
    produced_at: *const u8,
    produced_at_len: usize,
    singles: *const fhsm_composite_ocsp_single_t,
    n: usize,
    exts: *const u8,
    exts_len: usize,
    sign: fhsm_composite_sign_cb,
    sign_ctx: *mut c_void,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512 || sign.is_none() {
        return crv::ARGUMENTS_BAD;
    }
    let s = composite_ca(sign, sign_ctx);
    // SAFETY: the caller's contract
    unsafe {
        fhsm_pki_ocsp(
            &s,
            responder_cert,
            responder_cert_len,
            produced_at,
            produced_at_len,
            singles,
            n,
            exts,
            exts_len,
            out,
            out_len,
        )
    }
}

/// `fhsm_pki_algid`: the AlgorithmIdentifier of each `fhsm_pki_sigalg_t`, in static storage.
///
/// # Safety
/// `der` and `der_len` are writable when not NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_algid(a: c_int, der: *mut *const u8, der_len: *mut usize) -> u32 {
    if der.is_null() || der_len.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    let Some(d) = der::pki_algid(a) else {
        return crv::ARGUMENTS_BAD;
    };
    // SAFETY: both are writable
    unsafe {
        *der = d.as_ptr();
        *der_len = d.len();
    }
    crv::OK
}

// --- CMS (Phase 3 slice 5d, src/fhsm_composite.c:2129-2917) and the ECDSA signature form ----

/// `fhsm_composite_cms_signerinfo`.
///
/// # Safety
/// Each part has its length's readable bytes when not NULL; `out` has `*out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_cms_signerinfo(
    issuer: *const u8,
    issuer_len: usize,
    serial: *const u8,
    serial_len: usize,
    digalg: *const u8,
    digalg_len: usize,
    sattrs: *const u8,
    sattrs_len: usize,
    sigalg: *const u8,
    sigalg_len: usize,
    sig: *const u8,
    sig_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let parts = || -> Result<_, u32> {
            let p = [
                required(issuer, issuer_len)?,
                required(serial, serial_len)?,
                required(digalg, digalg_len)?,
                required(sattrs, sattrs_len)?,
                required(sigalg, sigalg_len)?,
                required(sig, sig_len)?,
            ];
            if out.is_null() || out_len.is_null() {
                return Err(crv::ARGUMENTS_BAD);
            }
            Ok(p)
        };
        match parts() {
            Ok([i, s, d, a, g, x]) => emit(
                der::cms_signerinfo(i, s, d, a, g, x).map_err(refused),
                out,
                &mut *out_len,
            ),
            Err(r) => r,
        }
    }
}

/// `fhsm_composite_cms_wrap`: `certs` NULL with 0 for none.
///
/// # Safety
/// Each part has its length's readable bytes when not NULL; `out` has `*out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_cms_wrap(
    digalg: *const u8,
    digalg_len: usize,
    certs: *const u8,
    certs_len: usize,
    signerinfo: *const u8,
    si_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let parts = || -> Result<_, u32> {
            let r = (required(digalg, digalg_len)?, required(signerinfo, si_len)?);
            if out.is_null() || out_len.is_null() {
                return Err(crv::ARGUMENTS_BAD);
            }
            Ok((r, optional(certs, certs_len)?))
        };
        match parts() {
            Ok(((d, s), c)) => emit(der::cms_wrap(d, c, s).map_err(refused), out, &mut *out_len),
            Err(r) => r,
        }
    }
}

/// `fhsm_pki_cms`: detached SignedData over `digest`, which must be `digest_name`'s length,
/// signed by `s` as the holder of `cert`.
///
/// # Safety
/// As `fhsm_pki_csr`; `digest_name` is NUL-terminated; `cert` and `digest` cover their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_cms(
    s: *const fhsm_pki_signer_t,
    digest_name: *const c_char,
    cert: *const u8,
    cert_len: usize,
    digest: *const u8,
    digest_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        let Some(s) = signer_ok(s) else {
            return crv::ARGUMENTS_BAD;
        };
        if digest_name.is_null() || cert.is_null() || digest.is_null() || out.is_null() {
            return crv::ARGUMENTS_BAD;
        }
        let Some(out_len) = out_len.as_mut() else {
            return crv::ARGUMENTS_BAD;
        };
        let mut sign = c_sign(s);
        let mut signer = Signer {
            algid: bytes(s.algid, s.algid_len),
            sign: &mut sign,
        };
        let der = x509::cms(
            &mut signer,
            CStr::from_ptr(digest_name),
            bytes(cert, cert_len),
            bytes(digest, digest_len),
        );
        emit(der, out, out_len)
    }
}

/// `fhsm_composite_cms`: `fhsm_pki_cms` with the composite signer and its SHA-512 pre-hash.
///
/// # Safety
/// As `fhsm_pki_cms`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_cms(
    alg: c_int,
    cert: *const u8,
    cert_len: usize,
    digest: *const u8,
    digest_len: usize,
    sign: fhsm_composite_sign_cb,
    sign_ctx: *mut c_void,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512
        || cert.is_null()
        || digest.is_null()
        || sign.is_none()
        || out.is_null()
        || out_len.is_null()
        || digest_len != fhsm_composite_ph_len(alg)
    {
        return crv::ARGUMENTS_BAD;
    }
    let s = composite_ca(sign, sign_ctx);
    // SAFETY: the caller's contract
    unsafe {
        fhsm_pki_cms(
            &s,
            c"SHA512".as_ptr(),
            cert,
            cert_len,
            digest,
            digest_len,
            out,
            out_len,
        )
    }
}

/// `fhsm_composite_cms_verify`: OK, SIGNATURE_INVALID (the data or the signature changed),
/// or ARGUMENTS_BAD (not a structure this can check).
///
/// # Safety
/// `cms` and `digest` cover their lengths when not NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_composite_cms_verify(
    alg: c_int,
    cms: *const u8,
    cms_len: usize,
    digest: *const u8,
    digest_len: usize,
) -> u32 {
    if alg != comp::MLDSA65_ED25519_SHA512 || cms.is_null() || digest.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    // SAFETY: the caller's contract
    unsafe { x509::composite_cms_verify(bytes(cms, cms_len), bytes(digest, digest_len)) }
}

/// `fhsm_pki_cms_digest`: the name of the digest to compute before checking `cms`.
///
/// # Safety
/// `cms` covers its length when not NULL; `name` is writable when not NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_cms_digest(
    cms: *const u8,
    cms_len: usize,
    name: *mut *const c_char,
) -> u32 {
    if cms.is_null() || name.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    // SAFETY: the caller's contract
    unsafe {
        match x509::cms_digest(bytes(cms, cms_len)) {
            Ok(n) => {
                *name = n.map_or(null(), CStr::as_ptr);
                if n.is_some() {
                    crv::OK
                } else {
                    crv::ARGUMENTS_BAD
                }
            }
            Err(r) => r,
        }
    }
}

/// `fhsm_pki_cms_verify`: `fhsm_composite_cms_verify` for the composite, and the same three
/// answers for the other algorithms.
///
/// # Safety
/// `cms` and `digest` cover their lengths when not NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_cms_verify(
    cms: *const u8,
    cms_len: usize,
    digest: *const u8,
    digest_len: usize,
) -> u32 {
    if cms.is_null() || digest.is_null() {
        return crv::ARGUMENTS_BAD;
    }
    // SAFETY: the caller's contract
    unsafe { x509::pki_cms_verify(bytes(cms, cms_len), bytes(digest, digest_len)) }
}

/// `fhsm_pki_ecdsa_raw_to_der`: r || s (each half the curve's length, 264 bytes at most) as a
/// DER Ecdsa-Sig-Value.
///
/// # Safety
/// `rs` covers `rs_len`; `out` has `*out_len` writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_ecdsa_raw_to_der(
    rs: *const u8,
    rs_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    if rs.is_null()
        || out.is_null()
        || out_len.is_null()
        || rs_len == 0
        || !rs_len.is_multiple_of(2)
        || rs_len > 264
    {
        return crv::ARGUMENTS_BAD;
    }
    // SAFETY: the caller's contract
    unsafe { emit(Ok(der::ecdsa_sig(bytes(rs, rs_len))), out, &mut *out_len) }
}
