//! The C ABI of `include/fhsm_revocation.h` over [`crate::revocation`], its `#[repr(C)]`
//! structs, and the two C encoder functions it imports from `src/fhsm_composite.c` (Phase 3).
//! The entry array of a `fhsm_rev_db_t` is a libc allocation, as in C: C callers build a
//! zeroed struct, add to it, and release it through `fhsm_rev_db_free`.
#![allow(non_camel_case_types)]
// The signatures are include/fhsm_revocation.h's, argument for argument.
#![allow(clippy::too_many_arguments)]

use std::ffi::{CStr, OsStr, c_char, c_int, c_ulonglong, c_void};
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

// The C encoder, resolved at the hybrid link (the C test doubles in `tests/common/` stand in
// under `cargo test`).
unsafe extern "C" {
    pub fn fhsm_pki_ocsp(
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
    ) -> u32;
    pub fn fhsm_pki_algid(a: c_int, der: *mut *const u8, der_len: *mut usize) -> u32;
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

/// # Safety
/// As [`entries`].
unsafe fn to_db(d: &fhsm_rev_db_t) -> rev::Db {
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
    let (mut algid, mut algid_len) = (null(), 0usize);
    // SAFETY: two out-pointers to locals; FHSM_PKI_COMPOSITE is 0
    if unsafe { fhsm_pki_algid(0, &mut algid, &mut algid_len) } != 0 {
        // SAFETY: the caller's contract
        unsafe { put_err(err, err_cap, "no composite AlgorithmIdentifier\n") };
        return rev::EIO;
    }
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
        let singles: Vec<fhsm_composite_ocsp_single_t> = t
            .singles
            .iter()
            .map(|s| fhsm_composite_ocsp_single_t {
                cert_id: s.cert_id.as_ptr(),
                cert_id_len: s.cert_id.len(),
                status: s.status,
                revoked_at: s.revoked_at.as_ref().map_or(null(), |r| r.as_ptr()),
                revoked_at_len: s.revoked_at.as_ref().map_or(0, Vec::len),
                reason: s.reason,
                this_upd: t.this_update.as_ptr(),
                this_upd_len: t.this_update.len(),
                next_upd: t.next_update.as_ptr(),
                next_upd_len: t.next_update.len(),
            })
            .collect();
        let exts = if t.exts.is_empty() {
            null()
        } else {
            t.exts.as_ptr()
        };
        let mut buf = vec![0u8; t.cap];
        let mut n = t.cap;
        // SAFETY: every pointer is to a live slice of the stated length; buf has n bytes
        let r = unsafe {
            fhsm_pki_ocsp(
                &signer,
                t.responder.as_ptr(),
                t.responder.len(),
                t.produced_at.as_ptr(),
                t.produced_at.len(),
                singles.as_ptr(),
                singles.len(),
                exts,
                t.exts.len(),
                buf.as_mut_ptr(),
                &mut n,
            )
        };
        if r != 0 {
            return Err(r);
        }
        buf.truncate(n);
        Ok(buf)
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
