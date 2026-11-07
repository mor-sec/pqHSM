//! The C ABI of `include/fhsm_token.h` (feature `ffi`): 43 functions over [`crate::token`],
//! called by `src/fhsm_pkcs11.c`, `src/fhsm_session.c` and `src/fhsm_apilock.c`.
//!
//! Contracts kept from C (PHASE2_PLAN.md §3, review M2):
//! - `fhsm_token_t` is opaque: a boxed [`Tok`]. NULL arguments give `FHSM_RV_ARGUMENTS_BAD` (or
//!   the accessor's zero value) exactly where C checks them, in C's order.
//! - `fhsm_token_label`/`_serial` point at buffers inside the box, which never moves while the
//!   token is open; re-init rewrites them in place, as C did, without a lock (C's readers took
//!   none either).
//! - `object_get`'s value pointer is the store's own [`crate::store::Value`]: it stays put until
//!   the object leaves the store, and is released through `fhsm_api_free_value` (RULE-078).
//! - `get_label`/`get_id`/`get_meta` return a per-thread copy, a `const`-initialised array with no
//!   destructor, like C's `_Thread_local` buffers.
//! - `fhsm_token_close` takes no lock (M3: the fork-child reset calls it).
//!
//! Differences: DIV-027 (`object_add` with a NULL value and a length is `ARGUMENTS_BAD`); DIV-028
//! (a login or `set_pin` role other than SO or user is `ARGUMENTS_BAD`; C went on with it, keyed
//! the user counters and recorded the bad role as the logged-in one); DIV-029
//! (`FHSM_TPM_SEALING` is read when the token is loaded or created; C re-read it at each login).
#![allow(
    non_camel_case_types,
    clippy::too_many_arguments,
    clippy::missing_safety_doc
)]

use std::cell::{Cell, UnsafeCell};
use std::ffi::{CStr, CString, OsStr, c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null;
use std::sync::Arc;

use crate::Rv;
use crate::store::{self, PolicyAttr};
use crate::token::{Audit, AuditEvent, Meta, Platform, Role, Tmpl, Token};
use crate::tpm;

/// `struct fhsm_token_s`, opaque to C.
#[repr(C)]
pub struct fhsm_token_t {
    _opaque: [u8; 0],
}

/// What a `fhsm_token_t *` points at.
struct Tok {
    token: Token,
    label: UnsafeCell<[u8; 65]>,
    serial: UnsafeCell<[u8; 65]>,
}

impl Tok {
    fn new(token: Token) -> Box<Tok> {
        let t = Box::new(Tok {
            token,
            label: UnsafeCell::new([0; 65]),
            serial: UnsafeCell::new([0; 65]),
        });
        t.refresh();
        t
    }

    /// Copy the label and serial into the buffers C points at.
    fn refresh(&self) {
        for (cell, v) in [
            (&self.label, self.token.label()),
            (&self.serial, self.token.serial()),
        ] {
            let mut b = [0u8; 65];
            let n = v.len().min(64);
            b[..n].copy_from_slice(&v[..n]);
            // SAFETY: the buffer is ours; C reads it without a lock, as it read C's.
            unsafe { *cell.get() = b };
        }
    }
}

unsafe extern "C" {
    fn fhsm_audit_event(ev: c_int, slot: c_int, session: c_int, role: c_int, rv: u32, ...) -> u32;
}

/// Audit through the C entry point (the Rust audit crate behind its variadic shim).
struct CAudit;

impl Audit for CAudit {
    fn event(&self, e: &AuditEvent<'_>) -> Result<(), Rv> {
        let pairs: Vec<(CString, CString)> = e.params.iter().map(|(k, v)| (cs(k), cs(v))).collect();
        let (ev, role, rv) = (e.code as c_int, e.role as c_int, e.rv.0);
        let end = null::<c_char>();
        // SAFETY: every key and value is a NUL-terminated string alive for the call, and the
        // list ends with NULL, as fhsm_audit_event reads it. The token passes at most one pair.
        let r = unsafe {
            match pairs.first() {
                None => fhsm_audit_event(ev, -1, -1, role, rv, end),
                Some((k, v)) => fhsm_audit_event(ev, -1, -1, role, rv, k.as_ptr(), v.as_ptr(), end),
            }
        };
        if r == 0 { Ok(()) } else { Err(Rv(r)) }
    }
}

/// A C string of `b` up to its first NUL.
fn cs(b: &[u8]) -> CString {
    let n = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    CString::new(&b[..n]).unwrap_or_default()
}

fn platform() -> Arc<Platform> {
    Arc::new(Platform {
        tpm: super::c_abi::shared_tpm(),
        sealing_required: tpm::sealing_required_value(
            std::env::var_os("FHSM_TPM_SEALING").as_deref(),
        ),
        audit: Box::new(CAudit),
    })
}

const OK: u32 = 0;
const BAD: u32 = Rv::ARGUMENTS_BAD.0;

fn code(r: Result<(), Rv>) -> u32 {
    r.map_or_else(|e| e.0, |()| OK)
}

unsafe fn tok<'a>(t: *const fhsm_token_t) -> Option<&'a Tok> {
    // SAFETY: the caller's contract: NULL or a pointer this module returned and has not freed
    unsafe { t.cast::<Tok>().as_ref() }
}

unsafe fn cstr<'a>(p: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's contract: NULL or NUL-terminated
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_bytes())
}

/// `n` elements at `p`; empty for NULL or 0, as C's `if (p && n)` guards treat them.
unsafe fn bytes<'a, T>(p: *const T, n: usize) -> &'a [T] {
    if p.is_null() || n == 0 {
        &[]
    } else {
        // SAFETY: the caller's contract: n readable elements at p
        unsafe { std::slice::from_raw_parts(p, n) }
    }
}

/// C passes `fhsm_role_t`; only SO and user name a PIN.
fn pin_role(r: c_int) -> Option<Role> {
    match r {
        1 => Some(Role::So),
        2 => Some(Role::User),
        _ => None,
    }
}

/// The accessors' C reading: SO for 1, the user's counters for anything else.
fn counter_role(r: c_int) -> Role {
    if r == 1 { Role::So } else { Role::User }
}

unsafe fn put<T>(out: *mut T, v: T) {
    if !out.is_null() {
        // SAFETY: non-NULL out is the caller's writable T
        unsafe { *out = v };
    }
}

thread_local! {
    static LABEL_COPY: Cell<[u8; 64]> = const { Cell::new([0; 64]) };
    static META_COPY: Cell<[u8; 64]> = const { Cell::new([0; 64]) };
    static ID_COPY: Cell<[u8; 32]> = const { Cell::new([0; 32]) };
}

/// Put `v` in this thread's copy and return a pointer to it (valid until the thread's next call).
fn thread_copy<const N: usize>(
    slot: &'static std::thread::LocalKey<Cell<[u8; N]>>,
    v: &[u8],
) -> *const u8 {
    slot.with(|c| {
        let mut b = [0u8; N];
        b[..v.len()].copy_from_slice(v);
        c.set(b);
        c.as_ptr().cast::<u8>().cast_const()
    })
}

/// Box a new token into `*out` (checked non-NULL by the caller).
unsafe fn give(out: *mut *mut fhsm_token_t, r: Result<Token, Rv>) -> u32 {
    match r {
        Ok(t) => {
            // SAFETY: out is non-NULL and writable
            unsafe { *out = Box::into_raw(Tok::new(t)).cast() };
            OK
        }
        Err(e) => e.0,
    }
}

fn path(p: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(p))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_load(path_: *const c_char, out: *mut *mut fhsm_token_t) -> u32 {
    let Some(p) = (unsafe { cstr(path_) }) else {
        return BAD;
    };
    if out.is_null() {
        return BAD;
    }
    unsafe { give(out, Token::load(path(p), platform())) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_init(
    path_: *const c_char,
    so_pin: *const c_char,
    label: *const c_char,
    out: *mut *mut fhsm_token_t,
) -> u32 {
    let (Some(p), Some(pin), Some(l)) = (unsafe { (cstr(path_), cstr(so_pin), cstr(label)) })
    else {
        return BAD;
    };
    if out.is_null() {
        return BAD;
    }
    unsafe { give(out, Token::init(path(p), pin, l, platform())) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_close(t: *mut fhsm_token_t) {
    if !t.is_null() {
        // SAFETY: a pointer `give` boxed; ownership comes back here once
        drop(unsafe { Box::from_raw(t.cast::<Tok>()) });
    }
}

unsafe fn pin_call(
    t: *mut fhsm_token_t,
    role: c_int,
    pin: *const c_char,
    pin_len: usize,
    f: fn(&Token, Role, &[u8]) -> Result<(), Rv>,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if pin.is_null() {
        return BAD;
    }
    let Some(role) = pin_role(role) else {
        return BAD;
    };
    code(f(&t.token, role, unsafe {
        bytes(pin.cast::<u8>(), pin_len)
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_login(
    t: *mut fhsm_token_t,
    role: c_int,
    pin: *const c_char,
    pin_len: usize,
) -> u32 {
    unsafe { pin_call(t, role, pin, pin_len, Token::login) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_verify_pin(
    t: *mut fhsm_token_t,
    role: c_int,
    pin: *const c_char,
    pin_len: usize,
) -> u32 {
    unsafe { pin_call(t, role, pin, pin_len, Token::verify_pin) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_logout(t: *mut fhsm_token_t) {
    if let Some(t) = unsafe { tok(t) } {
        t.token.logout();
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_current_role(t: *const fhsm_token_t) -> c_int {
    unsafe { tok(t) }.map_or(0, |t| t.token.current_role() as c_int)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_set_pin(
    t: *mut fhsm_token_t,
    role: c_int,
    old_pin: *const c_char,
    new_pin: *const c_char,
) -> u32 {
    let (Some(t), Some(old), Some(new)) = (unsafe { (tok(t), cstr(old_pin), cstr(new_pin)) })
    else {
        return BAD;
    };
    if new.len() < crate::token::PIN_MIN {
        return Rv::PIN_INCORRECT.0;
    }
    let Some(role) = pin_role(role) else {
        return BAD;
    };
    code(t.token.set_pin(role, old, new))
}

/// DIV-054: [`Token::change_pin`], for `C_SetPIN`. Lengths are the caller's (PKCS#11 PINs are
/// not terminated); a NUL inside either is the caller's to refuse first.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_token_change_pin(
    t: *mut fhsm_token_t,
    role: c_int,
    old_pin: *const c_char,
    old_len: usize,
    new_pin: *const c_char,
    new_len: usize,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if old_pin.is_null() || new_pin.is_null() {
        return BAD;
    }
    let Some(role) = pin_role(role) else {
        return BAD;
    };
    // SAFETY: by the caller's contract, old_len and new_len readable bytes
    let (old, new) = unsafe {
        (
            bytes(old_pin.cast(), old_len),
            bytes(new_pin.cast(), new_len),
        )
    };
    code(t.token.change_pin(role, old, new))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_init_user_pin(t: *mut fhsm_token_t, pin: *const c_char) -> u32 {
    let (Some(t), Some(pin)) = (unsafe { (tok(t), cstr(pin)) }) else {
        return BAD;
    };
    code(t.token.init_user_pin(pin))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_reinit(
    t: *mut fhsm_token_t,
    so_pin: *const c_char,
    label: *const c_char,
) -> u32 {
    let (Some(t), Some(pin), Some(l)) = (unsafe { (tok(t), cstr(so_pin), cstr(label)) }) else {
        return BAD;
    };
    let r = t.token.reinit(pin, l);
    t.refresh();
    code(r)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_label(t: *const fhsm_token_t) -> *const c_char {
    unsafe { tok(t) }.map_or(null(), |t| t.label.get().cast_const().cast())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_serial(t: *const fhsm_token_t) -> *const c_char {
    unsafe { tok(t) }.map_or(null(), |t| t.serial.get().cast_const().cast())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_failed_count(t: *const fhsm_token_t, role: c_int) -> u32 {
    unsafe { tok(t) }.map_or(0, |t| t.token.failed_count(counter_role(role)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_user_initialized(t: *const fhsm_token_t) -> c_int {
    unsafe { tok(t) }.map_or(0, |t| t.token.user_initialized().into())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_is_locked(t: *const fhsm_token_t, role: c_int) -> c_int {
    unsafe { tok(t) }.map_or(0, |t| t.token.is_locked(counter_role(role)).into())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_throttle_remaining_ms(
    t: *const fhsm_token_t,
    role: c_int,
) -> u64 {
    unsafe { tok(t) }.map_or(0, |t| t.token.throttle_remaining_ms(counter_role(role)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_add(
    t: *mut fhsm_token_t,
    cko_class: u32,
    ckk_type: u32,
    label: *const c_char,
    value: *const u8,
    value_len: usize,
    id: *const u8,
    id_len: usize,
    flags: u8,
    out_handle: *mut u32,
) -> u32 {
    unsafe {
        add(
            t, cko_class, ckk_type, label, value, value_len, id, id_len, flags, out_handle, false,
        )
    }
}

/// `fhsm_token_object_add`, the object written only by `fhsm_token_object_publish`, with every
/// attribute set in between (the PKCS#11 layer's creates; the C callers keep the plain add).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_add_pending(
    t: *mut fhsm_token_t,
    cko_class: u32,
    ckk_type: u32,
    label: *const c_char,
    value: *const u8,
    value_len: usize,
    id: *const u8,
    id_len: usize,
    flags: u8,
    out_handle: *mut u32,
) -> u32 {
    unsafe {
        add(
            t, cko_class, ckk_type, label, value, value_len, id, id_len, flags, out_handle, true,
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_publish(t: *mut fhsm_token_t, handle: u32) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    t.token.object_publish(handle).err().map_or(OK, |e| e.0)
}

#[allow(clippy::too_many_arguments)]
unsafe fn add(
    t: *mut fhsm_token_t,
    cko_class: u32,
    ckk_type: u32,
    label: *const c_char,
    value: *const u8,
    value_len: usize,
    id: *const u8,
    id_len: usize,
    flags: u8,
    out_handle: *mut u32,
    pending: bool,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if out_handle.is_null() {
        return BAD;
    }
    if value_len > store::VALUE_MAX {
        return Rv::KEY_SIZE_RANGE.0;
    }
    // DIV-027: C stored the length and later copied it from NULL
    if id_len > 32 || (value.is_null() && value_len > 0) {
        return BAD;
    }
    let (label, value, id) = unsafe { (cstr(label), bytes(value, value_len), bytes(id, id_len)) };
    let r = if pending {
        t.token
            .object_add_pending(cko_class, ckk_type, label, value, id, flags)
    } else {
        t.token
            .object_add(cko_class, ckk_type, label, value, id, flags)
    };
    match r {
        Ok(h) => {
            unsafe { *out_handle = h };
            OK
        }
        Err(e) => e.0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_get(
    t: *mut fhsm_token_t,
    handle: u32,
    value: *mut *const u8,
    value_len: *mut usize,
    out_class: *mut u32,
    out_key_type: *mut u32,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    match t.token.object_value(handle) {
        Ok((v, class, kt)) => {
            let p = if v.is_empty() { null() } else { v.as_ptr() };
            unsafe {
                put(value, p);
                put(value_len, v.len());
                put(out_class, class);
                put(out_key_type, kt);
            }
            OK
        }
        Err(e) => e.0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_find(
    t: *mut fhsm_token_t,
    opt_class: *const u32,
    opt_label: *const c_char,
    handles_out: *mut u32,
    cap: usize,
    count_out: *mut usize,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if count_out.is_null() {
        return BAD;
    }
    let class = unsafe { opt_class.as_ref() }.copied();
    let label = unsafe { cstr(opt_label) };
    let cap = if handles_out.is_null() { 0 } else { cap };
    match t.token.object_find(class, label, cap) {
        Ok((hs, n)) => {
            // SAFETY: hs.len() <= cap, and handles_out has cap slots. A NULL handles_out made
            // cap 0, so hs is empty and is not copied (copy_nonoverlapping needs a non-NULL
            // pointer even for 0 elements).
            unsafe {
                if !hs.is_empty() {
                    std::ptr::copy_nonoverlapping(hs.as_ptr(), handles_out, hs.len());
                }
                *count_out = n;
            }
            OK
        }
        Err(e) => {
            unsafe { *count_out = 0 };
            e.0
        }
    }
}

/// A lookup answered through one of the per-thread copies.
unsafe fn give_copy<const N: usize>(
    out: *mut *const u8,
    out_len: *mut usize,
    slot: &'static std::thread::LocalKey<Cell<[u8; N]>>,
    v: Result<Vec<u8>, Rv>,
) -> u32 {
    match v {
        Ok(v) => {
            // SAFETY: both out pointers were checked non-NULL by the caller
            unsafe {
                *out_len = v.len();
                *out = thread_copy(slot, &v);
            }
            OK
        }
        Err(e) => e.0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_get_label(
    t: *mut fhsm_token_t,
    handle: u32,
    out: *mut *const c_char,
    out_len: *mut usize,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if out.is_null() || out_len.is_null() {
        return BAD;
    }
    unsafe {
        give_copy(
            out.cast(),
            out_len,
            &LABEL_COPY,
            t.token.object_get_label(handle),
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_set_meta(
    t: *mut fhsm_token_t,
    handle: u32,
    start: *const u8,
    start_len: usize,
    end: *const u8,
    end_len: usize,
    app: *const u8,
    app_len: usize,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if start_len > 8 || end_len > 8 || app_len > store::LABEL_LEN {
        return Rv::ATTRIBUTE_VALUE_INVALID.0;
    }
    // A NULL pointer leaves its field alone; a non-NULL one sets it, even to zero bytes.
    let field = |p: *const u8, n| (!p.is_null()).then(|| unsafe { bytes(p, n) });
    code(t.token.object_set_meta(
        handle,
        field(start, start_len),
        field(end, end_len),
        field(app, app_len),
    ))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_get_meta(
    t: *mut fhsm_token_t,
    handle: u32,
    which: c_int,
    out: *mut *const u8,
    out_len: *mut usize,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if out.is_null() || out_len.is_null() {
        return BAD;
    }
    let which = match which {
        0 => Meta::StartDate,
        1 => Meta::EndDate,
        2 => Meta::Application,
        // C looks the handle up before it looks at `which`
        _ => {
            return t
                .token
                .object_get_flags(handle)
                .map_or_else(|e| e.0, |_| BAD);
        }
    };
    unsafe {
        give_copy(
            out,
            out_len,
            &META_COPY,
            t.token.object_get_meta(handle, which),
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_get_id(
    t: *mut fhsm_token_t,
    handle: u32,
    out: *mut *const u8,
    out_len: *mut usize,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if out.is_null() || out_len.is_null() {
        return BAD;
    }
    unsafe { give_copy(out, out_len, &ID_COPY, t.token.object_get_id(handle)) }
}

/// A getter with a required out pointer.
unsafe fn get<T>(
    t: *mut fhsm_token_t,
    out: *mut T,
    f: impl FnOnce(&Token) -> Result<T, Rv>,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if out.is_null() {
        return BAD;
    }
    match f(&t.token) {
        Ok(v) => {
            unsafe { *out = v };
            OK
        }
        Err(e) => e.0,
    }
}

/// A call that needs only the token.
unsafe fn with(t: *mut fhsm_token_t, f: impl FnOnce(&Token) -> Result<(), Rv>) -> u32 {
    unsafe { tok(t) }.map_or(BAD, |t| code(f(&t.token)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_get_flags(
    t: *mut fhsm_token_t,
    h: u32,
    out: *mut u8,
) -> u32 {
    unsafe { get(t, out, |k| k.object_get_flags(h)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_set_flags(t: *mut fhsm_token_t, h: u32, v: u8) -> u32 {
    unsafe { with(t, |k| k.object_set_flags(h, v)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_get_flags2(
    t: *mut fhsm_token_t,
    h: u32,
    out: *mut u8,
) -> u32 {
    unsafe { get(t, out, |k| k.object_get_flags2(h)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_set_flags2(t: *mut fhsm_token_t, h: u32, v: u8) -> u32 {
    unsafe { with(t, |k| k.object_set_flags2(h, v)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_get_flags3(
    t: *mut fhsm_token_t,
    h: u32,
    out: *mut u8,
) -> u32 {
    unsafe { get(t, out, |k| k.object_get_flags3(h)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_set_flags3(t: *mut fhsm_token_t, h: u32, v: u8) -> u32 {
    unsafe { with(t, |k| k.object_set_flags3(h, v)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_get_usage(
    t: *mut fhsm_token_t,
    h: u32,
    out: *mut u8,
) -> u32 {
    unsafe { get(t, out, |k| k.object_get_usage(h)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_set_usage(t: *mut fhsm_token_t, h: u32, v: u8) -> u32 {
    unsafe { with(t, |k| k.object_set_usage(h, v)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_is_token(
    t: *mut fhsm_token_t,
    h: u32,
    out: *mut c_int,
) -> u32 {
    unsafe { get(t, out, |k| k.object_is_token(h).map(c_int::from)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_set_label(
    t: *mut fhsm_token_t,
    h: u32,
    label: *const c_char,
) -> u32 {
    let (Some(t), Some(l)) = (unsafe { (tok(t), cstr(label)) }) else {
        return BAD;
    };
    code(t.token.object_set_label(h, l))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_set_id(
    t: *mut fhsm_token_t,
    h: u32,
    id: *const u8,
    id_len: usize,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if id_len > 32 {
        return Rv::ATTRIBUTE_VALUE_INVALID.0;
    }
    if id_len > 0 && id.is_null() {
        return BAD;
    }
    code(t.token.object_set_id(h, unsafe { bytes(id, id_len) }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_destroy(t: *mut fhsm_token_t, h: u32) -> u32 {
    unsafe { with(t, |k| k.object_destroy(h)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_mark_session(
    t: *mut fhsm_token_t,
    h: u32,
    owner: u32,
) -> u32 {
    unsafe { with(t, |k| k.object_mark_session(h, owner)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_destroy_session_objects(
    t: *mut fhsm_token_t,
    owner: u32,
) -> u32 {
    unsafe { with(t, |k| k.destroy_session_objects(owner)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_mech_allowed(
    t: *mut fhsm_token_t,
    h: u32,
    mech: u32,
) -> u32 {
    unsafe { with(t, |k| k.object_mech_allowed(h, mech)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_get_policy_counts(
    t: *mut fhsm_token_t,
    h: u32,
    out_allowed: *mut u8,
    out_wrap: *mut u8,
    out_unwrap: *mut u8,
    out_derive: *mut u8,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    match t.token.object_policy_counts(h) {
        Ok([a, w, u, d]) => {
            unsafe {
                put(out_allowed, a);
                put(out_wrap, w);
                put(out_unwrap, u);
                put(out_derive, d);
            }
            OK
        }
        Err(e) => e.0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_set_allowed_mechs(
    t: *mut fhsm_token_t,
    h: u32,
    mechs: *const u32,
    count: u8,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if count > 0 && mechs.is_null() {
        return BAD;
    }
    if count as usize > store::POLICY_MECH_MAX {
        return Rv::ATTRIBUTE_VALUE_INVALID.0;
    }
    code(
        t.token
            .object_set_allowed_mechs(h, unsafe { bytes(mechs, count as usize) }),
    )
}

/// C's size-query protocol: `*io_count` in is the room at `out`, out is the count; a NULL `out`
/// asks for the count only.
unsafe fn give_list<T: Copy>(v: Result<Vec<T>, Rv>, out: *mut T, io_count: *mut u8) -> u32 {
    let v = match v {
        Ok(v) => v,
        Err(e) => return e.0,
    };
    // SAFETY: io_count was checked non-NULL by the caller; out has *io_count slots
    unsafe {
        let cap = *io_count as usize;
        *io_count = v.len() as u8;
        if out.is_null() {
            return OK;
        }
        if cap < v.len() {
            return Rv::BUFFER_TOO_SMALL.0;
        }
        std::ptr::copy_nonoverlapping(v.as_ptr(), out, v.len());
    }
    OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_get_allowed_mechs(
    t: *mut fhsm_token_t,
    h: u32,
    out: *mut u32,
    io_count: *mut u8,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if io_count.is_null() {
        return BAD;
    }
    unsafe { give_list(t.token.object_get_allowed_mechs(h), out, io_count) }
}

fn tmpl(which: c_int) -> Option<Tmpl> {
    match which {
        0 => Some(Tmpl::Wrap),
        1 => Some(Tmpl::Unwrap),
        2 => Some(Tmpl::Derive),
        _ => None,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_set_tmpl(
    t: *mut fhsm_token_t,
    h: u32,
    which: c_int,
    a: *const PolicyAttr,
    count: u8,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if count > 0 && a.is_null() {
        return BAD;
    }
    if count as usize > store::POLICY_ATTR_MAX {
        return Rv::ATTRIBUTE_VALUE_INVALID.0;
    }
    let Some(which) = tmpl(which) else {
        return BAD;
    };
    code(
        t.token
            .object_set_tmpl(h, which, unsafe { bytes(a, count as usize) }),
    )
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_object_get_tmpl(
    t: *mut fhsm_token_t,
    h: u32,
    which: c_int,
    out: *mut PolicyAttr,
    io_count: *mut u8,
) -> u32 {
    let Some(t) = (unsafe { tok(t) }) else {
        return BAD;
    };
    if io_count.is_null() {
        return BAD;
    }
    let Some(which) = tmpl(which) else {
        return BAD;
    };
    unsafe { give_list(t.token.object_get_tmpl(h, which), out, io_count) }
}
