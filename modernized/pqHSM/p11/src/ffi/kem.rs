//! Phase 4 slice 7: `C_EncapsulateKey` and `C_DecapsulateKey` (`src/fhsm_pkcs11.c:5462-5929`)
//! in C's order, each shared secret stored by `C_DeriveKey`'s `Store`.
//!
//! Divergences: DIV-050 (the decapsulating key is the user's alone), RULE-037(a) (no token
//! object from a read-only session), DIV-069 (the key is stored as a derived key: a secret key
//! of a secret key type at its size, RULE-020's, with its usage and metadata). RULE-058 keeps
//! C's default: a KEM secret is not sensitive unless asked.

use std::ffi::c_ulong;
use std::ptr::null_mut;

use pqhsm_core::session::ROLE_NONE;
use pqhsm_crypto::cipher::{Pkey, PkeyCtx};
use pqhsm_crypto::sig::clear_errors;

use super::apilock::Held;
use super::attrs::{
    CKA_VALUE, CKA_VALUE_LEN, CKK_ML_KEM, CKO_PUBLIC_KEY, OBJF2_NO_DECAPSULATE,
    OBJF2_NO_ENCAPSULATE,
};
use super::copy::{BOOL_ATTRS, ULONG_ATTRS, check_ro_token, check_trusted, find};
use super::crypt::{Secret, object};
use super::derive::Store;
use super::digest::Mech;
use super::keygen::{TEMPLATE_INCONSISTENT, check_lengths, ulong};
use super::objects::{
    Attr, CKO_PRIVATE_KEY, CKO_SECRET_KEY, access_denied, check_template, class_of, gate,
};
use super::session::{TABLE, Tok, fhsm_session_role};
use super::sys::*;
use super::wrap::ok;

const KEY_TYPE_INCONSISTENT: u32 = 0x63;
const KEY_FUNCTION_NOT_PERMITTED: u32 = 0x68;
const MECHANISM_INVALID: u32 = 0x70;
const ENCRYPTED_DATA_LEN_RANGE: u32 = 0x41;

const CKM_ML_KEM: c_ulong = 0x17;
/// C's stack buffer for the secret (ML-KEM's is 32).
const SS_MAX: usize = 64;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_EncapsulateKey(
    h: c_ulong,
    m: *const Mech,
    k: c_ulong,
    tmpl: *const Attr,
    n: c_ulong,
    ct: *mut u8,
    ctl: *mut c_ulong,
    out: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if m.is_null() || out.is_null() || ctl.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // SAFETY: non-NULL, and by the caller's contract a CK_MECHANISM, a template of n
    // attributes, a ciphertext buffer of *ctl bytes or NULL, and a writable length and handle
    // (ctl stays a pointer: a caller may pass the handle's address for it too)
    unsafe { encapsulate(h, &*m, k as u32, tmpl, n, ct, ctl, out) }
        .unwrap_or_else(|rv| rv)
        .into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_DecapsulateKey(
    h: c_ulong,
    m: *const Mech,
    k: c_ulong,
    tmpl: *const Attr,
    n: c_ulong,
    ct: *const u8,
    ctl: c_ulong,
    out: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if m.is_null() || out.is_null() || ct.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // SAFETY: as above; the ciphertext readable for ctl bytes
    unsafe { decapsulate(h, &*m, k as u32, tmpl, n, ct, ctl, out) }
        .unwrap_or_else(|rv| rv)
        .into()
}

/// The checks both make, in C's order, up to and including the key's: `class` and ML-KEM, the
/// mechanism allowed, and the key's `no` flag clear. The template, the token and the key's value.
///
/// # Safety
/// `tmpl` as the entry points'.
unsafe fn key<'a>(
    h: c_ulong,
    m: &Mech,
    k: u32,
    tmpl: *const Attr,
    n: c_ulong,
    class: u32,
    no: u8,
) -> Result<(&'a [Attr], Tok, &'a [u8]), u32> {
    // SAFETY: the caller's
    let t = unsafe { check_template(tmpl, n) }?;
    check_trusted(h, t)?;
    check_lengths(t, &BOOL_ATTRS, 1)?;
    check_lengths(t, &ULONG_ATTRS, size_of::<c_ulong>() as c_ulong)?;
    // The value comes from the encapsulation, never the template.
    if find(t, CKA_VALUE).is_some() {
        return Err(TEMPLATE_INCONSISTENT);
    }
    // RULE-037(a): no token object from a read-only session (C made one).
    check_ro_token(h, t)?;
    if m.mechanism != CKM_ML_KEM {
        return Err(MECHANISM_INVALID);
    }
    let tok = TABLE.token(h).ok_or(SESSION_HANDLE_INVALID)?;
    // DIV-050: a private key is the user's alone (C let the SO decapsulate with it, and
    // answered 0x101 logged out).
    if class_of(tok, k).is_ok_and(|c| access_denied(tok, c)) {
        return Err(KEY_HANDLE_INVALID);
    }
    if fhsm_session_role(h) == ROLE_NONE {
        return Err(USER_NOT_LOGGED_IN);
    }
    let (v, cl, kt) = object(tok, k)?;
    if cl != class || kt != CKK_ML_KEM {
        return Err(KEY_TYPE_INCONSISTENT);
    }
    let tp = tok.0.as_ptr();
    // SAFETY: a token the registry holds
    ok(unsafe { fhsm_token_object_mech_allowed(tp, k, m.mechanism as u32) })?;
    let mut f2 = 0u8;
    // SAFETY: as above; an out byte of our own
    if unsafe { fhsm_token_object_get_flags2(tp, k, &mut f2) } == OK && f2 & no != 0 {
        return Err(KEY_FUNCTION_NOT_PERMITTED);
    }
    Ok((t, tok, v))
}

/// # Safety
/// As `pqhsm_C_EncapsulateKey`'s arguments.
#[allow(clippy::too_many_arguments)]
unsafe fn encapsulate(
    h: c_ulong,
    m: &Mech,
    k: u32,
    tmpl: *const Attr,
    n: c_ulong,
    ct: *mut u8,
    ctl: *mut c_ulong,
    out: *mut c_ulong,
) -> Result<u32, u32> {
    // SAFETY: the caller's
    let (t, tok, v) = unsafe { key(h, m, k, tmpl, n, CKO_PUBLIC_KEY, OBJF2_NO_ENCAPSULATE) }?;
    let pk = Pkey::public(v).ok_or(FUNCTION_FAILED)?;
    let mut c = PkeyCtx::new(&pk, true)?;
    let (mut cl, mut sl) = (0usize, 0usize);
    // SAFETY: NULL outputs ask only the lengths
    if !c.kem_init() || !unsafe { c.encapsulate(null_mut(), &mut cl, null_mut(), &mut sl) } {
        return Err(FUNCTION_FAILED);
    }
    if ct.is_null() {
        // SAFETY: ctl writable (the caller's)
        unsafe { *ctl = cl as c_ulong };
        return Ok(OK);
    }
    // SAFETY: ctl readable (the caller's)
    if (unsafe { *ctl } as usize) < cl {
        // SAFETY: as above
        unsafe { *ctl = cl as c_ulong };
        return Err(BUFFER_TOO_SMALL);
    }
    if sl > SS_MAX {
        return Err(FUNCTION_FAILED);
    }
    let mut ss = Secret::zeroed(SS_MAX)?;
    // SAFETY: as above
    let mut n_out = unsafe { *ctl } as usize;
    // SAFETY: ct writable for *ctl bytes (the caller's), ss for SS_MAX >= sl
    if !unsafe { c.encapsulate(ct, &mut n_out, ss.0.as_mut_ptr(), &mut sl) } {
        return Err(FUNCTION_FAILED);
    }
    // SAFETY: as above
    unsafe { *ctl = n_out as c_ulong };
    store(h, tok, m, t, out, &ss.0[..sl])
}

/// # Safety
/// As `pqhsm_C_DecapsulateKey`'s arguments.
#[allow(clippy::too_many_arguments)]
unsafe fn decapsulate(
    h: c_ulong,
    m: &Mech,
    k: u32,
    tmpl: *const Attr,
    n: c_ulong,
    ct: *const u8,
    ctl: c_ulong,
    out: *mut c_ulong,
) -> Result<u32, u32> {
    // SAFETY: the caller's
    let (t, tok, v) = unsafe { key(h, m, k, tmpl, n, CKO_PRIVATE_KEY, OBJF2_NO_DECAPSULATE) }?;
    let pk = Pkey::private(v)
        .or_else(|| expanded(v))
        .ok_or(FUNCTION_FAILED)?;
    // A ciphertext of the wrong size is the caller's error, and says so.
    let want = [
        (c"ML-KEM-512", 768),
        (c"ML-KEM-768", 1088),
        (c"ML-KEM-1024", 1568),
    ]
    .into_iter()
    .find(|(alg, _)| pk.is_a(alg))
    .map_or(0, |(_, n)| n);
    if want != 0 && ctl != want as c_ulong {
        return Err(ENCRYPTED_DATA_LEN_RANGE);
    }
    // shortcut: with no size to check (never for an ML-KEM key) a length past isize::MAX
    // breaks from_raw_parts' contract (C handed it to OpenSSL), upgrade if one can arrive.
    // SAFETY: the caller's ciphertext, readable for ctl bytes
    let ct = unsafe { super::digest::bytes(ct, ctl as usize) };
    let mut c = PkeyCtx::new(&pk, false)?;
    let mut sl = 0usize;
    // SAFETY: a NULL output asks only the length
    if !c.kem_init() || !unsafe { c.decapsulate(null_mut(), &mut sl, ct) } || sl > SS_MAX {
        return Err(FUNCTION_FAILED);
    }
    let mut ss = Secret::zeroed(SS_MAX)?;
    clear_errors();
    // SAFETY: ss writable for SS_MAX >= sl
    if !unsafe { c.decapsulate(ss.0.as_mut_ptr(), &mut sl, ct) } {
        return Err(FUNCTION_FAILED);
    }
    store(h, tok, m, t, out, &ss.0[..sl])
}

/// C's raw import fallback: an expanded private key, its parameter set by its length.
fn expanded(v: &[u8]) -> Option<Pkey> {
    let alg = match v.len() {
        1632 => c"ML-KEM-512",
        2400 => c"ML-KEM-768",
        3168 => c"ML-KEM-1024",
        _ => return None,
    };
    Pkey::expanded_private(alg, v)
}

/// CKA_VALUE_LEN by truncation (1 up to the secret's length, else 0x13, as C), then the store.
fn store(
    h: c_ulong,
    tok: Tok,
    m: &Mech,
    t: &[Attr],
    out: *mut c_ulong,
    ss: &[u8],
) -> Result<u32, u32> {
    let len = match ulong(t, CKA_VALUE_LEN) {
        Some(Some(l)) if l == 0 || l as usize > ss.len() => return Err(ATTRIBUTE_VALUE_INVALID),
        Some(Some(l)) => l as usize,
        _ => ss.len(),
    };
    // DIV-069: as a derived key, with no inputs to inherit from and no audit record (C has none).
    Store {
        tok,
        h,
        mech: m.mechanism,
        t,
        out,
        event: None,
    }
    .store(&ss[..len], CKO_SECRET_KEY as c_ulong, &[])
}
