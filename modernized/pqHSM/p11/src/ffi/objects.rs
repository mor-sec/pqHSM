//! Phase 4 slice 2a: `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal`,
//! `C_GetObjectSize` and `C_DestroyObject` (`src/fhsm_pkcs11.c:4140-4165, 7649-7670,
//! 8295-8406`), in C's check order, over the token's C ABI as the C called it. The find state
//! (C's `g_finds`) is this module's.

use std::ffi::{c_char, c_int, c_ulong};
use std::ptr::null;
use std::sync::Mutex;

use pqhsm_core::p11::ROLE_USER;
use pqhsm_core::session::MAX;

use super::apilock::Held;
use super::lifecycle::initialized;
use super::session::{TABLE, Tok};
use super::state::in_error;
use super::sys::*;

/// `FHSM_MAX_OBJECTS`: a search returns at most what the store holds.
const MAX_OBJECTS: usize = 1024;
/// `FHSM_MAX_TEMPLATE_ATTRS`.
pub(super) const MAX_TEMPLATE_ATTRS: c_ulong = 1024;
pub(super) const CKA_CLASS: c_ulong = 0x0;
pub(super) const CKA_LABEL: c_ulong = 0x3;
pub(super) const CKA_ID: c_ulong = 0x102;
pub(super) const CKO_PRIVATE_KEY: u32 = 3;
pub(super) const CKO_SECRET_KEY: u32 = 4;
pub(super) const CKF_RW_SESSION: c_ulong = 0x2;
/// `FHSM_OBJF_UNDESTROYABLE`: CKA_DESTROYABLE=FALSE.
pub(super) const OBJF_UNDESTROYABLE: u8 = 0x08;

/// `CK_ATTRIBUTE`.
#[repr(C)]
pub struct Attr {
    pub kind: c_ulong,
    pub value: *mut u8,
    pub len: c_ulong,
}

/// `fhsm_find_state_t`.
struct Find {
    handles: Vec<u32>,
    next: usize,
    active: bool,
}

impl Find {
    const IDLE: Find = Find {
        handles: Vec::new(),
        next: 0,
        active: false,
    };
}

/// One find per session handle, as C's table. shortcut: like C's, it is not cleared when a
/// session closes, so a reused handle inherits a search left active (recorded as a candidate);
/// and a fork while another thread holds the mutex leaves the child's stuck (review M3).
static FINDS: Mutex<[Find; MAX]> = Mutex::new([const { Find::IDLE }; MAX]);

fn finds() -> std::sync::MutexGuard<'static, [Find; MAX]> {
    FINDS.lock().unwrap_or_else(|p| p.into_inner())
}

/// C's `fhsm_zeroize(g_finds)`, at finalize and after a fork.
pub(crate) fn reset_finds() {
    finds().iter_mut().for_each(|f| *f = Find::IDLE);
}

/// DIV-051 and DIV-053, as the shim's gate applied them before the C ran.
pub(super) fn gate() -> Result<(), u32> {
    initialized()?;
    if in_error() {
        return Err(FUNCTION_FAILED);
    }
    Ok(())
}

/// `fhsm_check_template`: NULL with a count, an absurd count, or a NULL value with a length.
///
/// # Safety
/// `t` is NULL or points to `n` attributes.
pub(super) unsafe fn check_template<'a>(t: *const Attr, n: c_ulong) -> Result<&'a [Attr], u32> {
    if n == 0 {
        return Ok(&[]);
    }
    if t.is_null() || n > MAX_TEMPLATE_ATTRS {
        return Err(ARGUMENTS_BAD);
    }
    // SAFETY: the caller's n attributes, n bounded above
    let t = unsafe { std::slice::from_raw_parts(t, n as usize) };
    if t.iter().any(|a| a.value.is_null() && a.len != 0) {
        return Err(ATTRIBUTE_VALUE_INVALID);
    }
    Ok(t)
}

/// `fhsm_token_object_get`'s class, or its rv.
fn class_of(t: Tok, h: u32) -> Result<u32, u32> {
    let (mut v, mut vl, mut class, mut kt) = (null(), 0usize, 0u32, 0u32);
    // SAFETY: a token the registry holds; out pointers of our own
    let rv =
        unsafe { fhsm_token_object_get(t.0.as_ptr(), h, &mut v, &mut vl, &mut class, &mut kt) };
    if rv == OK { Ok(class) } else { Err(rv) }
}

fn private_class(class: u32) -> bool {
    class == CKO_SECRET_KEY || class == CKO_PRIVATE_KEY
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_FindObjectsInit(
    h: c_ulong,
    t: *const Attr,
    n: c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    if h as usize >= MAX {
        return SESSION_HANDLE_INVALID.into();
    }
    if finds()[h as usize].active {
        return OPERATION_ACTIVE.into();
    }
    // SAFETY: the caller's template of n attributes
    let t = match unsafe { check_template(t, n) } {
        Ok(t) => t,
        Err(rv) => return rv.into(),
    };
    let (mut class, mut label, mut id) = (None, None, None);
    for a in t {
        if a.kind == CKA_CLASS && a.len as usize == size_of::<c_ulong>() {
            // SAFETY: a non-NULL value (check_template) of a CK_ULONG's length
            class = Some(unsafe { a.value.cast::<c_ulong>().read_unaligned() } as u32);
        } else if a.kind == CKA_LABEL {
            // C copied 63 bytes at most and terminated them; the token compares to the NUL.
            let n = (a.len as usize).min(63);
            let mut l = [0u8; 64];
            if n > 0 {
                // SAFETY: a non-NULL value of at least n bytes
                l[..n].copy_from_slice(unsafe { std::slice::from_raw_parts(a.value, n) });
            }
            label = Some(l);
        } else if a.kind == CKA_ID && a.len <= 32 {
            let n = a.len as usize;
            id = Some(if n > 0 {
                // SAFETY: as above
                unsafe { std::slice::from_raw_parts(a.value, n) }.to_vec()
            } else {
                vec![]
            });
        }
    }
    let mut prelim = vec![0u32; MAX_OBJECTS];
    let mut got = 0usize;
    // SAFETY: a token the registry holds; class and label ours, alive for the call; prelim has
    // MAX_OBJECTS slots
    let rv = unsafe {
        fhsm_token_object_find(
            tok.0.as_ptr(),
            class.as_ref().map_or(null(), |c| c as *const u32),
            label
                .as_ref()
                .map_or(null(), |l| l.as_ptr().cast::<c_char>()),
            prelim.as_mut_ptr(),
            MAX_OBJECTS,
            &mut got,
        )
    };
    // Private objects are hidden unless the token is logged in as the user (#125).
    // SAFETY: as above
    let authed = unsafe { fhsm_token_current_role(tok.0.as_ptr()) } == ROLE_USER;
    let mut out = Vec::new();
    // C clamps to its buffer: `got` counts every match, not only those written.
    for &o in &prelim[..got.min(MAX_OBJECTS)] {
        if out.len() >= MAX_OBJECTS {
            break;
        }
        // An object the lookup cannot answer for stays, as in C.
        if !authed && class_of(tok, o).is_ok_and(private_class) {
            continue;
        }
        if let Some(want) = &id {
            let (mut p, mut pl) = (null(), 0usize);
            // SAFETY: as above; out pointers of our own
            if unsafe { fhsm_token_object_get_id(tok.0.as_ptr(), o, &mut p, &mut pl) } != OK
                || pl != want.len()
                // SAFETY: the token's per-thread copy, pl bytes, valid until its next lookup
                || (pl > 0 && unsafe { std::slice::from_raw_parts(p, pl) } != want.as_slice())
            {
                continue;
            }
        }
        out.push(o);
    }
    // Set active whatever the search answered, and return its rv, as C did.
    finds()[h as usize] = Find {
        handles: out,
        next: 0,
        active: true,
    };
    rv.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_FindObjects(
    h: c_ulong,
    out: *mut c_ulong,
    max: c_ulong,
    count: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if out.is_null() || count.is_null() {
        return ARGUMENTS_BAD.into();
    }
    if h as usize >= MAX {
        return SESSION_HANDLE_INVALID.into();
    }
    let mut f = finds();
    let f = &mut f[h as usize];
    if !f.active {
        return OPERATION_NOT_INITIALIZED.into();
    }
    let mut k = 0;
    while k < max && f.next < f.handles.len() {
        // SAFETY: the caller's array of max handles, k < max
        unsafe { *out.add(k as usize) = f.handles[f.next].into() };
        f.next += 1;
        k += 1;
    }
    // SAFETY: checked non-NULL above
    unsafe { *count = k };
    OK.into()
}

#[unsafe(no_mangle)]
pub extern "C" fn pqhsm_C_FindObjectsFinal(h: c_ulong) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if h as usize >= MAX {
        return SESSION_HANDLE_INVALID.into();
    }
    let mut f = finds();
    if !f[h as usize].active {
        return OPERATION_NOT_INITIALIZED.into();
    }
    f[h as usize] = Find::IDLE;
    OK.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_GetObjectSize(
    h: c_ulong,
    o: c_ulong,
    size: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if size.is_null() {
        return ARGUMENTS_BAD.into();
    }
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    let (mut v, mut vl, mut class, mut kt) = (null(), 0usize, 0u32, 0u32);
    // SAFETY: a token the registry holds; out pointers of our own
    let rv = unsafe {
        fhsm_token_object_get(
            tok.0.as_ptr(),
            o as u32,
            &mut v,
            &mut vl,
            &mut class,
            &mut kt,
        )
    };
    if rv != OK {
        return lookup_rv(rv).into();
    }
    if access_denied(tok, class) {
        return OBJECT_HANDLE_INVALID.into();
    }
    // SAFETY: checked non-NULL above
    unsafe { *size = vl as c_ulong };
    OK.into()
}

/// `fhsm_object_lookup_rv`: the object calls answer 0x82, not the key calls' 0x60.
pub(super) fn lookup_rv(rv: u32) -> u32 {
    if rv == KEY_HANDLE_INVALID {
        OBJECT_HANDLE_INVALID
    } else {
        rv
    }
}

/// `fhsm_object_access_denied`: a private class unless the token is logged in as the user.
pub(super) fn access_denied(t: Tok, class: u32) -> bool {
    // SAFETY: a token the registry holds
    let role = unsafe { fhsm_token_current_role(t.0.as_ptr()) };
    role != ROLE_USER && private_class(class)
}

#[unsafe(no_mangle)]
pub extern "C" fn pqhsm_C_DestroyObject(h: c_ulong, o: c_ulong) -> c_ulong {
    let _g = Held::exclusive();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    let t = tok.0.as_ptr();
    // DIV-050: a private object is not there for anyone but the user (C let the SO destroy the
    // user's keys). First, so a read-only session's 0xB5 does not show that it exists.
    if class_of(tok, o as u32).is_ok_and(|c| access_denied(tok, c)) {
        return OBJECT_HANDLE_INVALID.into();
    }
    // A token object needs a read-write session (#125); a session object does not.
    let mut is_tok: c_int = 0;
    // SAFETY: a token the registry holds; an out pointer of our own
    if unsafe { fhsm_token_object_is_token(t, o as u32, &mut is_tok) } == OK
        && is_tok != 0
        && TABLE
            .info(h)
            .is_ok_and(|(_, flags, _)| flags & CKF_RW_SESSION == 0)
    {
        return SESSION_READ_ONLY.into();
    }
    let mut of = 0u8;
    // SAFETY: as above
    if unsafe { fhsm_token_object_get_flags(t, o as u32, &mut of) } == OK
        && of & OBJF_UNDESTROYABLE != 0
    {
        return ACTION_PROHIBITED.into();
    }
    // SAFETY: as above
    unsafe { fhsm_token_object_destroy(t, o as u32) }.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::null_mut;

    #[test]
    fn template_checks_are_c_s() {
        // SAFETY: NULL with a count is refused before any read
        assert_eq!(
            unsafe { check_template(null(), 1) }.err(),
            Some(ARGUMENTS_BAD)
        );
        // SAFETY: a count of 0 reads nothing
        assert!(unsafe { check_template(null(), 0) }.is_ok());
        let a = [Attr {
            kind: CKA_LABEL,
            value: null_mut(),
            len: 4,
        }];
        // SAFETY: one attribute
        assert_eq!(
            unsafe { check_template(a.as_ptr(), 1) }.err(),
            Some(ATTRIBUTE_VALUE_INVALID)
        );
        // SAFETY: the count is refused before the slice is made
        assert_eq!(
            unsafe { check_template(a.as_ptr(), 1025) }.err(),
            Some(ARGUMENTS_BAD)
        );
    }

    #[test]
    fn object_lookups_answer_0x82() {
        assert_eq!(lookup_rv(KEY_HANDLE_INVALID), OBJECT_HANDLE_INVALID);
        assert_eq!(lookup_rv(0x6), 0x6);
    }
}
