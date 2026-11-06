//! Phase 4 slice 6c: `C_WrapKey` and `C_UnwrapKey` (`src/fhsm_pkcs11.c:4974-5444`) in C's
//! order, with the RSA transports (`:8631-8829`). The AES key wrap runs on `crypt.rs`'s
//! cipher helpers.
//!
//! Divergences: DIV-050 (a secret or private key is the user's alone), DIV-058 (a key that is
//! not extractable is never wrapped), DIV-067 (an unwrapped key is a secret key of a secret
//! key type), DIV-001 (the record is made before the blob or the key reaches the caller),
//! RULE-059 (an unwrapped key was never always sensitive, nor never extractable).

use std::ffi::{CStr, c_char, c_int, c_ulong};
use std::ptr::{copy_nonoverlapping, null};

use pqhsm_core::session::ROLE_NONE;
use pqhsm_crypto::cipher::{Pkey, PkeyCtx, md_known};

use super::apilock::Held;
use super::attrs::{
    CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_SENSITIVE, CKA_VALUE_LEN, OBJF_EXTRACTABLE, OBJF_SENSITIVE,
    OBJF_TRUSTED, OBJF2_HAS_UNWRAP_TMPL, OBJF2_HAS_WRAP_TMPL, OBJF2_WRAP_WITH_TRUSTED,
    POLICY_ATTR_MAX, PolicyAttr, USAGE_UNWRAP, USAGE_VALID, USAGE_WRAP, fhsm_token_object_get_tmpl,
    imported,
};
use super::copy::{
    BOOL_ATTRS, ULONG_ATTRS, apply_allowed_mechs, apply_nested_all, apply_obj_meta, bbool, bytes,
    check_ro_token, check_trusted, fhsm_token_object_add, fhsm_token_object_set_usage, find,
};
use super::crypt::{Secret, aes_name, keyed, mgf_md, oaep_md, object, run, strict};
use super::digest::{Mech, sized};
use super::keygen::{
    OBJF_UNWRAP_SENS, TEMPLATE_INCONSISTENT, apply_token_scope, check_lengths, compute_usage, ulong,
};
use super::objects::{
    Attr, CKA_CLASS, CKA_ID, CKA_LABEL, CKO_PRIVATE_KEY, CKO_SECRET_KEY, access_denied,
    check_template, class_of, gate,
};
use super::session::{TABLE, Tok, fhsm_session_role};
use super::sys::*;

const ATTRIBUTE_READ_ONLY: u32 = 0x10;
const KEY_SIZE_RANGE: u32 = 0x62;
const KEY_TYPE_INCONSISTENT: u32 = 0x63;
const KEY_FUNCTION_NOT_PERMITTED: u32 = 0x68;
const KEY_NOT_WRAPPABLE: u32 = 0x69;
const KEY_UNEXTRACTABLE: u32 = 0x6A;
const MECHANISM_INVALID: u32 = 0x70;
const MECHANISM_PARAM_INVALID: u32 = 0x71;
const UNWRAPPING_KEY_HANDLE_INVALID: u32 = 0xF0;
const UNWRAPPING_KEY_TYPE_INCONSISTENT: u32 = 0xF2;
const WRAPPED_KEY_INVALID: u32 = 0x110;
const WRAPPED_KEY_LEN_RANGE: u32 = 0x112;
const WRAPPING_KEY_HANDLE_INVALID: u32 = 0x113;
const WRAPPING_KEY_SIZE_RANGE: u32 = 0x114;
const WRAPPING_KEY_TYPE_INCONSISTENT: u32 = 0x115;

const RSA_PKCS: c_ulong = 0x1;
const RSA_X_509: c_ulong = 0x3;
const OAEP: c_ulong = 0x9;
const KW: c_ulong = 0x2109;
const KWP: c_ulong = 0x210B;

const CKO_PUBLIC_KEY: u32 = 2;
const CKK_RSA: u32 = 0;
const CKK_DES3: u32 = 0x15;
const CKK_AES: u32 = 0x1F;
/// DIV-067: the module's secret key types (generic, DES3, AES, SHA256-HMAC, HKDF).
const SECRET_TYPES: [c_ulong; 5] = [0x10, 0x15, 0x1F, 0x2B, 0x42];
/// `fhsm_tmpl_which_t`.
const TMPL_WRAP: c_int = 0;
const TMPL_UNWRAP: c_int = 1;
/// `FHSM_POLICY_VALUE_MAX`: what `fhsm_read_obj_attr` reads into.
const POLICY_VALUE_MAX: usize = 48;
/// The unwrapped plaintext's buffer (C's `pt[4096]`).
const PT_MAX: usize = 4096;
const EV_WRAP: c_int = 44;
const EV_UNWRAP: c_int = 45;
/// RSA_PKCS1_PADDING, RSA_NO_PADDING.
const PKCS1_PADDING: c_int = 1;
const NO_PADDING: c_int = 3;

fn ok(rv: u32) -> Result<(), u32> {
    if rv == OK { Ok(()) } else { Err(rv) }
}

/// `fhsm_check_usage`: refused only when the key's usage is recorded and lacks `bit`.
fn usage(t: *mut fhsm_token_t, k: u32, bit: u8) -> Result<(), u32> {
    let mut u = 0u8;
    // SAFETY: a token the registry holds; an out byte of our own
    if unsafe { fhsm_token_object_get_usage(t, k, &mut u) } == OK
        && u & USAGE_VALID != 0
        && u & bit == 0
    {
        return Err(KEY_FUNCTION_NOT_PERMITTED);
    }
    Ok(())
}

/// A key's wrap (`which` TMPL_WRAP) or unwrap template entries; none without one.
fn policy(t: *mut fhsm_token_t, k: u32, which: c_int, bit: u8) -> Vec<PolicyAttr> {
    let mut f2 = 0u8;
    // SAFETY: a token the registry holds; an out byte of our own
    if unsafe { fhsm_token_object_get_flags2(t, k, &mut f2) } != OK || f2 & bit == 0 {
        return Vec::new();
    }
    let mut ent = [PolicyAttr {
        kind_: 0,
        kind: 0,
        len: 0,
        value: [0; POLICY_VALUE_MAX],
    }; POLICY_ATTR_MAX];
    let mut cnt = POLICY_ATTR_MAX as u8;
    // SAFETY: as above; ent has cnt slots
    if unsafe { fhsm_token_object_get_tmpl(t, k, which, ent.as_mut_ptr(), &mut cnt) } != OK {
        return Vec::new();
    }
    ent.into_iter().take(cnt as usize).collect()
}

/// An entry's value as stored.
fn value(e: &PolicyAttr) -> Option<&[u8]> {
    e.value.get(..e.len as usize)
}

/// `fhsm_read_obj_attr`: one attribute of an existing object as the wrap template compares
/// it, at most POLICY_VALUE_MAX bytes; `None` for one it does not read.
fn obj_attr(tok: Tok, k: u32, kind: c_ulong) -> Option<Vec<u8>> {
    let (v, class, kt) = object(tok, k).ok()?;
    let t = tok.0.as_ptr();
    let (mut p, mut l) = (null(), 0usize);
    match kind {
        CKA_CLASS => Some((class as c_ulong).to_ne_bytes().to_vec()),
        CKA_KEY_TYPE => Some((kt as c_ulong).to_ne_bytes().to_vec()),
        CKA_VALUE_LEN => Some((v.len() as c_ulong).to_ne_bytes().to_vec()),
        CKA_LABEL => {
            let mut lp: *const c_char = null();
            // SAFETY: as above; out pointers of our own
            (unsafe { fhsm_token_object_get_label(t, k, &mut lp, &mut l) } == OK
                && l <= POLICY_VALUE_MAX)
                // SAFETY: the token's label of l bytes
                .then(|| unsafe { super::digest::bytes(lp.cast(), l) }.to_vec())
        }
        CKA_ID => {
            // SAFETY: as above
            (unsafe { fhsm_token_object_get_id(t, k, &mut p, &mut l) } == OK
                && l <= POLICY_VALUE_MAX)
                // SAFETY: the token's id of l bytes
                .then(|| unsafe { super::digest::bytes(p, l) }.to_vec())
        }
        CKA_SENSITIVE | CKA_EXTRACTABLE => {
            let mut f = 0u8;
            // SAFETY: as above
            if unsafe { fhsm_token_object_get_flags(t, k, &mut f) } != OK {
                return None;
            }
            let bit = if kind == CKA_SENSITIVE {
                OBJF_SENSITIVE
            } else {
                OBJF_EXTRACTABLE
            };
            Some(vec![u8::from(f & bit != 0)])
        }
        _ => None,
    }
}

/// `fhsm_check_wrap_tmpl`: the key wrapped matches every entry of the wrapping key's template.
fn check_wrap_tmpl(tok: Tok, wk: u32, k: u32) -> Result<(), u32> {
    for e in policy(tok.0.as_ptr(), wk, TMPL_WRAP, OBJF2_HAS_WRAP_TMPL) {
        let want = value(&e);
        if want.is_none() || obj_attr(tok, k, e.kind_.into()).as_deref() != want {
            return Err(TEMPLATE_INCONSISTENT);
        }
    }
    Ok(())
}

/// `fhsm_check_nested_tmpl` for the unwrap: the caller's template holds every entry of the
/// unwrapping key's, byte for byte.
fn check_unwrap_tmpl(t: *mut fhsm_token_t, uk: u32, tmpl: &[Attr]) -> Result<(), u32> {
    for e in policy(t, uk, TMPL_UNWRAP, OBJF2_HAS_UNWRAP_TMPL) {
        let same = find(tmpl, e.kind_.into())
            .is_some_and(|a| a.len == c_ulong::from(e.len) && Some(bytes(a)) == value(&e));
        if !same {
            return Err(TEMPLATE_INCONSISTENT);
        }
    }
    Ok(())
}

/// `kw_iv_from_mech`: none, or exactly 8 (KW) or 4 (KWP) bytes.
///
/// # Safety
/// `m.param` readable for `m.param_len` bytes, or NULL.
unsafe fn kw_iv(m: &Mech) -> Result<Option<Vec<u8>>, u32> {
    if m.param.is_null() && m.param_len == 0 {
        return Ok(None);
    }
    let want = if m.mechanism == KW { 8 } else { 4 };
    if m.param.is_null() || m.param_len != want {
        return Err(MECHANISM_PARAM_INVALID);
    }
    // SAFETY: the caller's want bytes
    Ok(Some(
        unsafe { super::digest::bytes(m.param.cast(), want as usize) }.to_vec(),
    ))
}

/// `fhsm_oaep_params_from_mech`: the hash, the MGF and the label (CKZ_DATA_SPECIFIED).
///
/// # Safety
/// As `kw_iv`'s.
unsafe fn oaep_params(m: &Mech) -> Result<(c_ulong, c_ulong, Vec<u8>), u32> {
    if m.param.is_null() || (m.param_len as usize) < 5 * size_of::<c_ulong>() {
        return Err(MECHANISM_PARAM_INVALID);
    }
    // SAFETY: at least five CK_ULONGs (checked); C memcpy'd them, so unaligned is fine
    let [hash, mgf, source, src, src_len] =
        unsafe { m.param.cast::<[c_ulong; 5]>().read_unaligned() };
    let labelled = source == 1 && src_len > 0;
    if labelled && src == 0 {
        return Err(MECHANISM_PARAM_INVALID);
    }
    // Fetched, as C checks them: a name the providers cannot fetch is refused here too.
    let known = |n: Option<&CStr>| n.is_some_and(md_known);
    if !known(oaep_md(hash)) || !known(mgf_md(mgf)) {
        return Err(MECHANISM_PARAM_INVALID);
    }
    // shortcut: a label past C's (int) cast is FUNCTION_FAILED here, before the size query
    // (C failed at the context, after it); only a caller lying about its buffer reaches it.
    if labelled && src_len > c_int::MAX as c_ulong {
        return Err(FUNCTION_FAILED);
    }
    let label = if labelled {
        // SAFETY: the caller's label of src_len bytes
        unsafe { super::digest::bytes(src as *const u8, src_len as usize) }.to_vec()
    } else {
        Vec::new()
    };
    Ok((hash, mgf, label))
}

/// An RSA context with PKCS#1 v1.5 or no padding; FUNCTION_FAILED if it will not set up.
fn raw_ctx(k: &Pkey, enc: bool, raw: bool) -> Result<PkeyCtx, u32> {
    let mut x = PkeyCtx::new(k, enc).map_err(|_| FUNCTION_FAILED)?;
    let pad = if raw { NO_PADDING } else { PKCS1_PADDING };
    if x.init() && x.padding(pad) {
        Ok(x)
    } else {
        Err(FUNCTION_FAILED)
    }
}

/// A modulus length in bytes; FUNCTION_FAILED for none.
fn modulus(k: &Pkey) -> Result<usize, u32> {
    usize::try_from(k.size())
        .ok()
        .filter(|&n| n > 0)
        .ok_or(FUNCTION_FAILED)
}

/// One RSA operation into a fresh buffer of `cap` bytes; `fail` if it fails.
fn rsa_run(x: &mut PkeyCtx, inp: &[u8], cap: usize, fail: u32) -> Result<Secret, u32> {
    let mut o = Secret::zeroed(cap)?;
    let mut got = cap;
    // SAFETY: o holds cap bytes
    if !unsafe { x.run(o.0.as_mut_ptr(), &mut got, inp) } || got > cap {
        return Err(fail);
    }
    o.0.truncate(got);
    Ok(o)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_WrapKey(
    h: c_ulong,
    m: *const Mech,
    wk: c_ulong,
    k: c_ulong,
    out: *mut u8,
    out_len: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if m.is_null() || out_len.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // C's narrowing: the token's handles are 32-bit.
    // SAFETY: non-NULL, and by the caller's contract a CK_MECHANISM; out and out_len theirs
    unsafe { wrap(h, &*m, wk as u32, k as u32, out, out_len) }
        .unwrap_or_else(|rv| rv)
        .into()
}

/// # Safety
/// `out` NULL or writable for `*out_len` bytes; `out_len` a CK_ULONG; `m`'s parameter the
/// caller's.
unsafe fn wrap(
    h: c_ulong,
    m: &Mech,
    wk: u32,
    k: u32,
    out: *mut u8,
    out_len: *mut c_ulong,
) -> Result<u32, u32> {
    let tok = TABLE.token(h).ok_or(SESSION_HANDLE_INVALID)?;
    let t = tok.0.as_ptr();
    // DIV-050: neither key is anyone's but the user's (C let the SO wrap the user's keys, and
    // wrap under them). A key whose lookup fails goes on to C's checks.
    if [wk, k]
        .into_iter()
        .any(|o| class_of(tok, o).is_ok_and(|c| access_denied(tok, c)))
    {
        return Err(KEY_HANDLE_INVALID);
    }
    // SAFETY: a token the registry holds
    ok(unsafe { fhsm_token_object_mech_allowed(t, wk, m.mechanism as u32) })?;
    check_wrap_tmpl(tok, wk, k)?;
    // CKA_WRAP_WITH_TRUSTED on the key wrapped: only under a trusted key.
    let (mut f2, mut wf) = (0u8, 0u8);
    // SAFETY: as above; out bytes of our own
    if unsafe { fhsm_token_object_get_flags2(t, k, &mut f2) } == OK
        && f2 & OBJF2_WRAP_WITH_TRUSTED != 0
        && (unsafe { fhsm_token_object_get_flags(t, wk, &mut wf) } != OK || wf & OBJF_TRUSTED == 0)
    {
        return Err(KEY_NOT_WRAPPABLE);
    }
    usage(t, wk, USAGE_WRAP)?;
    if fhsm_session_role(h) == ROLE_NONE {
        return Err(USER_NOT_LOGGED_IN);
    }
    let (kv, _, _) = object(tok, k)?;
    // DIV-058: a key that is not extractable never leaves (C refused only one that was also
    // sensitive).
    let mut f = 0u8;
    // SAFETY: as above (C ignored a failure, as nothing set)
    unsafe { fhsm_token_object_get_flags(t, k, &mut f) };
    if f & OBJF_EXTRACTABLE == 0 {
        return Err(KEY_UNEXTRACTABLE);
    }
    let (wkv, wcl, wkt) = object(tok, wk)?;
    let n = kv.len();
    let blob = match m.mechanism {
        KW | KWP => {
            if wkt != CKK_AES {
                return Err(KEY_TYPE_INCONSISTENT);
            }
            // SAFETY: the caller's parameter
            let iv = unsafe { kw_iv(m) }?;
            if !matches!(wkv.len(), 16 | 24 | 32) {
                return Err(WRAPPING_KEY_SIZE_RANGE);
            }
            let mode = if m.mechanism == KW {
                "WRAP"
            } else {
                "WRAP-PAD"
            };
            let name = aes_name(mode, wkv.len()).ok_or(WRAPPING_KEY_SIZE_RANGE)?;
            let mut x = keyed(true, name, wkv, iv.as_deref(), true)?;
            let need = if m.mechanism == KW {
                if n < 16 || !n.is_multiple_of(8) {
                    return Err(KEY_SIZE_RANGE);
                }
                n + 8
            } else {
                if n == 0 {
                    return Err(KEY_SIZE_RANGE);
                }
                n.div_ceil(8) * 8 + 8
            };
            // SAFETY: out_len a CK_ULONG (caller)
            if let Some(rv) = unsafe { sized(out, out_len, need as c_ulong) } {
                return Ok(rv);
            }
            run(true, &mut x, kv, need, FUNCTION_FAILED)?
        }
        OAEP => {
            if wcl != CKO_PUBLIC_KEY || wkt != CKK_RSA {
                return Err(WRAPPING_KEY_TYPE_INCONSISTENT);
            }
            // SAFETY: the caller's parameter
            let (hash, mgf, label) = unsafe { oaep_params(m) }?;
            let pk = Pkey::public(wkv).ok_or(WRAPPING_KEY_HANDLE_INVALID)?;
            let need = modulus(&pk)?;
            // SAFETY: as above
            if let Some(rv) = unsafe { sized(out, out_len, need as c_ulong) } {
                return Ok(rv);
            }
            let mut x = PkeyCtx::oaep(&pk, true, oaep_md(hash), mgf_md(mgf), &label)?;
            rsa_run(&mut x, kv, need, FUNCTION_FAILED)?
        }
        RSA_PKCS | RSA_X_509 => {
            if strict() {
                return Err(MECHANISM_INVALID);
            }
            if wcl != CKO_PUBLIC_KEY || wkt != CKK_RSA {
                return Err(WRAPPING_KEY_TYPE_INCONSISTENT);
            }
            let raw = m.mechanism == RSA_X_509;
            let pk = Pkey::public(wkv).ok_or(WRAPPING_KEY_HANDLE_INVALID)?;
            let need = modulus(&pk)?;
            // SAFETY: as above
            if let Some(rv) = unsafe { sized(out, out_len, need as c_ulong) } {
                return Ok(rv);
            }
            if if raw { n > need } else { n + 11 > need } {
                return Err(KEY_SIZE_RANGE);
            }
            let mut x = raw_ctx(&pk, true, raw)?;
            if raw {
                // RSA_NO_PADDING takes exactly the modulus: the key right-aligned on zeros.
                if need > 1024 {
                    return Err(WRAPPING_KEY_SIZE_RANGE);
                }
                let mut p = Secret::zeroed(need)?;
                p.0[need - n..].copy_from_slice(kv);
                rsa_run(&mut x, &p.0, need, FUNCTION_FAILED)?
            } else {
                rsa_run(&mut x, kv, need, FUNCTION_FAILED)?
            }
        }
        _ => return Err(MECHANISM_INVALID),
    };
    // DIV-001: recorded before the blob reaches the caller.
    audit(EV_WRAP, -1, h as c_int, fhsm_session_role(h), OK, &[])?;
    // SAFETY: *out_len >= need >= the blob (sized)
    unsafe {
        copy_nonoverlapping(blob.0.as_ptr(), out, blob.0.len());
        *out_len = blob.0.len() as c_ulong;
    }
    Ok(OK)
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn pqhsm_C_UnwrapKey(
    h: c_ulong,
    m: *const Mech,
    uk: c_ulong,
    w: *const u8,
    wn: c_ulong,
    tmpl: *const Attr,
    n: c_ulong,
    out: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if m.is_null() || w.is_null() || out.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // SAFETY: non-NULL, and by the caller's contract a CK_MECHANISM, a blob of wn bytes, a
    // template of n attributes and a writable handle
    unsafe { unwrap(h, &*m, uk as u32, w, wn, tmpl, n, out) }
        .unwrap_or_else(|rv| rv)
        .into()
}

/// # Safety
/// As `pqhsm_C_UnwrapKey`'s arguments.
#[allow(clippy::too_many_arguments)]
unsafe fn unwrap(
    h: c_ulong,
    m: &Mech,
    uk: u32,
    w: *const u8,
    wn: c_ulong,
    tmpl: *const Attr,
    n: c_ulong,
    out: *mut c_ulong,
) -> Result<u32, u32> {
    // SAFETY: the caller's
    let t = unsafe { check_template(tmpl, n) }?;
    check_trusted(h, t)?;
    check_lengths(t, &BOOL_ATTRS, 1)?;
    check_lengths(t, &ULONG_ATTRS, size_of::<c_ulong>() as c_ulong)?;
    check_ro_token(h, t)?;
    // C's three key checks pass without a token; the session is checked after them.
    if let Some(tok) = TABLE.token(h) {
        let tp = tok.0.as_ptr();
        // DIV-050: the unwrapping key is the user's alone (C let the SO unwrap under it).
        if class_of(tok, uk).is_ok_and(|c| access_denied(tok, c)) {
            return Err(KEY_HANDLE_INVALID);
        }
        // SAFETY: a token the registry holds
        ok(unsafe { fhsm_token_object_mech_allowed(tp, uk, m.mechanism as u32) })?;
        check_unwrap_tmpl(tp, uk, t)?;
        usage(tp, uk, USAGE_UNWRAP)?;
    }
    let tok = TABLE.token(h).ok_or(SESSION_HANDLE_INVALID)?;
    let tp = tok.0.as_ptr();
    if fhsm_session_role(h) == ROLE_NONE {
        return Err(USER_NOT_LOGGED_IN);
    }
    let (ukv, ucl, ukt) = object(tok, uk)?;
    let wn = wn as usize;
    let pt = match m.mechanism {
        KW | KWP => {
            if ukt != CKK_AES {
                return Err(KEY_TYPE_INCONSISTENT);
            }
            // SAFETY: the caller's parameter
            let iv = unsafe { kw_iv(m) }?;
            if !matches!(ukv.len(), 16 | 24 | 32) {
                return Err(WRAPPING_KEY_SIZE_RANGE);
            }
            let min = if m.mechanism == KW { 24 } else { 16 };
            if wn < min || !wn.is_multiple_of(8) || wn - 8 > PT_MAX {
                return Err(WRAPPED_KEY_LEN_RANGE);
            }
            let mode = if m.mechanism == KW {
                "WRAP"
            } else {
                "WRAP-PAD"
            };
            let name = aes_name(mode, ukv.len()).ok_or(WRAPPING_KEY_SIZE_RANGE)?;
            let mut x = keyed(false, name, ukv, iv.as_deref(), true)?;
            // SAFETY: the caller's blob of wn bytes, wn bounded above
            let blob = unsafe { super::digest::bytes(w, wn) };
            run(false, &mut x, blob, wn - 8, WRAPPED_KEY_INVALID)?
        }
        OAEP | RSA_PKCS | RSA_X_509 => {
            let oaep = m.mechanism == OAEP;
            if !oaep && strict() {
                return Err(MECHANISM_INVALID);
            }
            if ucl != CKO_PRIVATE_KEY || ukt != CKK_RSA {
                return Err(UNWRAPPING_KEY_TYPE_INCONSISTENT);
            }
            // SAFETY: the caller's parameter
            let params = if oaep {
                Some(unsafe { oaep_params(m) }?)
            } else {
                None
            };
            let pk = Pkey::private(ukv).ok_or(UNWRAPPING_KEY_HANDLE_INVALID)?;
            let mut x = match &params {
                Some((hash, mgf, label)) => {
                    PkeyCtx::oaep(&pk, false, oaep_md(*hash), mgf_md(*mgf), label)?
                }
                None => {
                    // A blob that is not modulus-sized cannot be a wrapping under this key.
                    if wn != modulus(&pk)? {
                        return Err(WRAPPED_KEY_LEN_RANGE);
                    }
                    raw_ctx(&pk, false, m.mechanism == RSA_X_509)?
                }
            };
            // shortcut: a length no buffer can have is refused as C's OpenSSL call would
            // refuse it; only a caller lying about its buffer reaches this.
            if wn > isize::MAX as usize {
                return Err(WRAPPED_KEY_INVALID);
            }
            // SAFETY: the caller's blob of wn bytes
            let blob = unsafe { super::digest::bytes(w, wn) };
            let mut pt = rsa_run(&mut x, blob, PT_MAX, WRAPPED_KEY_INVALID)?;
            if m.mechanism == RSA_X_509 {
                // Strip the zeros the wrap padded with (C's own, data-dependent).
                let z = pt.0.iter().take_while(|&&b| b == 0).count();
                pt.0.drain(..z);
            }
            pt
        }
        _ => return Err(MECHANISM_INVALID),
    };
    // The decrypted bytes become a secret key; pt is wiped when dropped.
    let mut label = [0u8; 64];
    if let Some(a) = find(t, CKA_LABEL) {
        let b = bytes(a);
        let l = b.len().min(63);
        label[..l].copy_from_slice(&b[..l]);
    }
    // DIV-067: only a secret key, of a secret key type (C stored any type, ignoring CKA_CLASS).
    if ulong(t, CKA_CLASS)
        .flatten()
        .is_some_and(|c| c != CKO_SECRET_KEY as c_ulong)
    {
        return Err(TEMPLATE_INCONSISTENT);
    }
    let kt = ulong(t, CKA_KEY_TYPE)
        .flatten()
        .unwrap_or(CKK_AES as c_ulong);
    if !SECRET_TYPES.contains(&kt) {
        return Err(ATTRIBUTE_VALUE_INVALID);
    }
    let kt = kt as u32;
    let mut flags = OBJF_SENSITIVE;
    if bbool(t, CKA_SENSITIVE) == Some(false) {
        // Tookan §3.3: an unwrapping key whose template demands SENSITIVE refuses a clear one.
        let mut uf = 0u8;
        // SAFETY: as above (C ignored a failure)
        unsafe { fhsm_token_object_get_flags(tp, uk, &mut uf) };
        if uf & OBJF_UNWRAP_SENS != 0 {
            return Err(ATTRIBUTE_READ_ONLY);
        }
        flags &= !OBJF_SENSITIVE;
    }
    if bbool(t, CKA_EXTRACTABLE) == Some(true) {
        flags |= OBJF_EXTRACTABLE;
    }
    let len = pt.0.len();
    if (kt == CKK_AES && !matches!(len, 16 | 24 | 32)) || (kt == CKK_DES3 && len != 24) {
        return Err(KEY_TYPE_INCONSISTENT);
    }
    if ulong(t, CKA_VALUE_LEN)
        .flatten()
        .is_some_and(|l| l != len as c_ulong)
    {
        return Err(ATTRIBUTE_VALUE_INVALID);
    }
    let mut o = 0u32;
    // SAFETY: a token the registry holds; label NUL-terminated; pt valid for len; o our own
    ok(unsafe {
        fhsm_token_object_add(
            tp,
            CKO_SECRET_KEY,
            kt,
            label.as_ptr().cast(),
            pt.0.as_ptr(),
            len,
            null(),
            0,
            flags,
            &mut o,
        )
    })?;
    drop(pt);
    // SAFETY: writable (caller); C wrote the handle before applying the rest
    unsafe { *out = o as c_ulong };
    let step = |r: u32| {
        if r == OK {
            return Ok(());
        }
        // SAFETY: a token the registry holds
        unsafe { fhsm_token_object_destroy(tp, o) };
        Err(r)
    };
    step(apply_allowed_mechs(tp, t, o))?;
    step(apply_nested_all(tp, t, o))?;
    apply_token_scope(tp, h, t, o);
    step(apply_obj_meta(tp, t, o))?;
    // RULE-059: an unwrapped key was in the clear outside the token.
    step(imported(tp, o))?;
    // SAFETY: as above (C ignores the result)
    unsafe { fhsm_token_object_set_usage(tp, o, compute_usage(CKO_SECRET_KEY, t)) };
    // DIV-001: a key whose record cannot be made is not kept.
    step(audited(
        OK,
        audit(EV_UNWRAP, -1, h as c_int, fhsm_session_role(h), OK, &[]),
    ))?;
    Ok(OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kw_iv_lengths() {
        let iv = [0xA6u8; 8];
        let m = |mech, p: &[u8]| Mech {
            mechanism: mech,
            param: p.as_ptr() as *mut _,
            param_len: p.len() as c_ulong,
        };
        // SAFETY: each parameter is the slice it names
        unsafe {
            assert_eq!(kw_iv(&m(KW, &iv)).unwrap().unwrap().len(), 8);
            assert_eq!(kw_iv(&m(KWP, &iv[..4])).unwrap().unwrap().len(), 4);
            assert_eq!(kw_iv(&m(KW, &iv[..4])), Err(MECHANISM_PARAM_INVALID));
            assert_eq!(kw_iv(&m(KWP, &iv)), Err(MECHANISM_PARAM_INVALID));
        }
    }

    #[test]
    fn oaep_label_unbounded() {
        let label = [7u8; 100];
        let p: [c_ulong; 5] = [0x250, 2, 1, label.as_ptr() as c_ulong, 100];
        let m = Mech {
            mechanism: OAEP,
            param: p.as_ptr() as *mut _,
            param_len: size_of_val(&p) as c_ulong,
        };
        // SAFETY: p and label outlive the call
        let (_, _, l) = unsafe { oaep_params(&m) }.unwrap();
        // C's wrap copies any label; only the Init path caps it at 64.
        assert_eq!(l.len(), 100);
        let bad: [c_ulong; 5] = [0x250, 2, 1, 0, 5];
        let m = Mech {
            param: bad.as_ptr() as *mut _,
            ..m
        };
        // SAFETY: as above
        assert_eq!(
            unsafe { oaep_params(&m) }.err(),
            Some(MECHANISM_PARAM_INVALID)
        );
    }
}
