//! Phase 4 slice 6a: `C_GenerateKey` (`src/fhsm_pkcs11.c:2745-3050`) and `C_GenerateKeyPair`
//! (`:6440-6933`), in C's order, with the template helpers only they use (`fhsm_compute_usage`,
//! `fhsm_apply_token_scope`, `fhsm_parse_unwrap_template`, `fhsm_apply_ed_curve_name`, the
//! attribute length checks, the PQC parameter sets). The libcrypto calls are
//! `pqhsm_crypto::keygen`'s.
//! shortcut: C's create, unwrap and derive keep their static copies of these helpers until
//! those entry points move (slices 6b-6d).

use std::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use std::ptr::null;

use pqhsm_core::session::ROLE_NONE;
use pqhsm_crypto::cipher::Pkey;
use pqhsm_crypto::keygen::{Curve, ec_curve, ecm_available, report_keygen_failure};

use super::apilock::Held;
use super::attrs::{
    ATTRIBUTE_TYPE_INVALID, CKA_COPYABLE, CKA_DECAPSULATE, CKA_DESTROYABLE, CKA_ENCAPSULATE,
    CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_MODIFIABLE, CKA_SENSITIVE, CKA_TOKEN, CKA_UNWRAP_TEMPLATE,
    CKA_VALUE_LEN, CKK_ML_DSA, CKK_ML_KEM, CKO_PUBLIC_KEY, OBJF_ALWAYS_AUTH, OBJF_EXTRACTABLE,
    OBJF_LOCAL, OBJF_SENSITIVE, OBJF_UNMODIFIABLE, OBJF2_NOT_COPYABLE, USAGE_DECRYPT, USAGE_DERIVE,
    USAGE_ENCRYPT, USAGE_SIGN, USAGE_UNWRAP, USAGE_VALID, USAGE_VERIFY, USAGE_WRAP,
    fhsm_token_object_set_flags3,
};
use super::copy::{
    BOOL_ATTRS, ULONG_ATTRS, apply_allowed_mechs, apply_encap_flags, apply_nested_all,
    apply_obj_meta, bbool, bytes, check_ro_token, check_trusted, fhsm_token_object_add_pending,
    fhsm_token_object_mark_session, fhsm_token_object_publish, fhsm_token_object_publish_pair,
    fhsm_token_object_set_usage, find,
};
use super::crypt::strict;
use super::digest::Mech;
use super::objects::{
    Attr, CKA_ID, CKA_LABEL, CKO_PRIVATE_KEY, CKO_SECRET_KEY, MAX_TEMPLATE_ATTRS,
    OBJF_UNDESTROYABLE, check_template, gate,
};
use super::session::TABLE;
use super::state::{cnum, fhsm_state_latch_error};
use super::sys::*;

unsafe extern "C" {
    fn fhsm_rng_bytes(out: *mut u8, n: usize) -> u32;
    fn fhsm_pbkdf2(
        alg: c_int,
        password: Slice,
        salt: Slice,
        iterations: u32,
        out: *mut u8,
        out_len: usize,
    ) -> u32;
    fn fhsm_pairwise_check(pkey: *mut c_void, family: c_int) -> u32;
    fn fhsm_composite_keygen(
        alg: c_int,
        private: *mut u8,
        private_len: *mut usize,
        public: *mut u8,
        public_len: *mut usize,
    ) -> u32;
}

const KEY_SIZE_RANGE: u32 = 0x62;
const MECHANISM_INVALID: u32 = 0x70;
const MECHANISM_PARAM_INVALID: u32 = 0x71;
pub(super) const TEMPLATE_INCOMPLETE: u32 = 0xD0;
pub(super) const TEMPLATE_INCONSISTENT: u32 = 0xD1;
pub(super) const CURVE_NOT_SUPPORTED: u32 = 0x140;
const HOST_MEMORY: u32 = 0x2;
const FIPS_NOT_APPROVED: u32 = 0x8000_0003;
const EV_KAT_REPORT: c_int = 3;

const CKM_RSA_PKCS_KEY_PAIR_GEN: c_ulong = 0x0;
pub(super) const CKM_ML_KEM_KEY_PAIR_GEN: c_ulong = 0xF;
pub(super) const CKM_ML_DSA_KEY_PAIR_GEN: c_ulong = 0x1C;
pub(super) const CKM_SLH_DSA_KEY_PAIR_GEN: c_ulong = 0x2D;
const CKM_DES3_KEY_GEN: c_ulong = 0x131;
const CKM_GENERIC_SECRET_KEY_GEN: c_ulong = 0x350;
const CKM_PKCS5_PBKD2: c_ulong = 0x3B0;
const CKM_EC_KEY_PAIR_GEN: c_ulong = 0x1040;
const CKM_EC_EDWARDS_KEY_PAIR_GEN: c_ulong = 0x1055;
const CKM_EC_MONTGOMERY_KEY_PAIR_GEN: c_ulong = 0x1056;
const CKM_AES_KEY_GEN: c_ulong = 0x1080;
const CKM_HKDF_KEY_GEN: c_ulong = 0x402C;
const CKM_COMPOSITE: c_ulong = 0x8000_4202;

pub(super) const CKK_RSA: u32 = 0x0;
pub(super) const CKK_EC: u32 = 0x3;
const CKK_GENERIC_SECRET: u32 = 0x10;
const CKK_DES3: u32 = 0x15;
const CKK_AES: u32 = 0x1F;
pub(super) const CKK_EC_EDWARDS: u32 = 0x40;
pub(super) const CKK_EC_MONTGOMERY: u32 = 0x41;
const CKK_HKDF: u32 = 0x42;
pub(super) const CKK_SLH_DSA: u32 = 0x4B;
const CKK_COMPOSITE: u32 = 0x8000_4202;

const CKA_MODULUS_BITS: c_ulong = 0x121;
const CKA_PUBLIC_EXPONENT: c_ulong = 0x122;
pub(super) const CKA_EC_PARAMS: c_ulong = 0x180;
pub(super) const CKA_ALWAYS_AUTHENTICATE: c_ulong = 0x202;
const CKA_WRAP_WITH_TRUSTED: c_ulong = 0x210;
pub(super) const CKA_PARAMETER_SET: c_ulong = 0x61D;
const CKA_USAGE: [(c_ulong, u8); 7] = [
    (0x104, USAGE_ENCRYPT),
    (0x105, USAGE_DECRYPT),
    (0x108, USAGE_SIGN),
    (0x10A, USAGE_VERIFY),
    (0x106, USAGE_WRAP),
    (0x107, USAGE_UNWRAP),
    (0x10C, USAGE_DERIVE),
];

pub(super) const OBJF_UNWRAP_SENS: u8 = 0x80;
const OBJF2_WRAP_WITH_TRUSTED: u8 = 0x80;
pub(super) const OBJF3_ED_CURVE_NAME: u8 = 0x01;

/// `FHSM_PBKDF2_MAX_OUT`.
const PBKDF2_MAX: usize = 256;
/// The composite blobs' ceilings and its one algorithm.
const COMPOSITE_PRIV_MAX: usize = 8192;
const COMPOSITE_PUB_MAX: usize = 4096;
const COMPOSITE_ALG: c_int = 1;
/// `fhsm_pairwise_family_t`.
const PW_RSA: c_int = 1;
const PW_EC: c_int = 2;
const PW_ML_KEM: c_int = 3;
const PW_ML_DSA: c_int = 4;
const PW_SLH_DSA: c_int = 5;
const PW_EDDSA: c_int = 6;
const PW_ECM: c_int = 7;

/// `fhsm_pset_from_selector`'s tables: the CKP_* order of each family.
pub(super) const ML_KEM_SETS: [&CStr; 3] = [c"ML-KEM-512", c"ML-KEM-768", c"ML-KEM-1024"];
pub(super) const ML_DSA_SETS: [&CStr; 3] = [c"ML-DSA-44", c"ML-DSA-65", c"ML-DSA-87"];
pub(super) const SLH_DSA_SETS: [&CStr; 12] = [
    c"SLH-DSA-SHA2-128s",
    c"SLH-DSA-SHAKE-128s",
    c"SLH-DSA-SHA2-128f",
    c"SLH-DSA-SHAKE-128f",
    c"SLH-DSA-SHA2-192s",
    c"SLH-DSA-SHAKE-192s",
    c"SLH-DSA-SHA2-192f",
    c"SLH-DSA-SHAKE-192f",
    c"SLH-DSA-SHA2-256s",
    c"SLH-DSA-SHAKE-256s",
    c"SLH-DSA-SHA2-256f",
    c"SLH-DSA-SHAKE-256f",
];

/// `ed_curves[]` and `ecm_curves[]`: the OID or RFC 8032 curveName, and the algorithm.
pub(super) const ED_CURVES: [(&[u8], &CStr); 4] = [
    (b"\x06\x03\x2B\x65\x70", c"ED25519"),
    (b"\x06\x03\x2B\x65\x71", c"ED448"),
    (b"\x13\x0Cedwards25519", c"ED25519"),
    (b"\x13\x0Aedwards448", c"ED448"),
];
pub(super) const ECM_CURVES: [(&[u8], &CStr); 2] = [
    (b"\x06\x03\x2B\x65\x6E", c"X25519"),
    (b"\x06\x03\x2B\x65\x6F", c"X448"),
];

pub(super) fn match_curve(table: &[(&[u8], &'static CStr)], v: &[u8]) -> Option<&'static CStr> {
    table.iter().find(|(d, _)| *d == v).map(|(_, n)| *n)
}

/// `fhsm_check_bool_attr_lengths` or `fhsm_check_ulong_attr_lengths`, over one template.
pub(super) fn check_lengths(t: &[Attr], kinds: &[c_ulong], len: c_ulong) -> Result<(), u32> {
    let bad = t
        .iter()
        .any(|a| kinds.contains(&a.kind) && !a.value.is_null() && a.len != len);
    if bad {
        Err(ATTRIBUTE_VALUE_INVALID)
    } else {
        Ok(())
    }
}

/// A CK_ULONG row: `None` if absent, `Some(None)` if not read whole (NULL, or a length other
/// than `sizeof(CK_ULONG)`).
pub(super) fn ulong(t: &[Attr], kind: c_ulong) -> Option<Option<c_ulong>> {
    find(t, kind).map(|a| {
        (!a.value.is_null() && a.len as usize == size_of::<c_ulong>())
            .then(|| c_ulong::from_ne_bytes(bytes(a).try_into().unwrap_or_default()))
    })
}

/// `fhsm_compute_usage`: the class's defaults, then each usage attribute the template sets.
pub(super) fn compute_usage(class: u32, t: &[Attr]) -> u8 {
    let mut u = USAGE_VALID
        | match class {
            CKO_SECRET_KEY => {
                USAGE_ENCRYPT
                    | USAGE_DECRYPT
                    | USAGE_SIGN
                    | USAGE_VERIFY
                    | USAGE_WRAP
                    | USAGE_UNWRAP
            }
            CKO_PUBLIC_KEY => USAGE_ENCRYPT | USAGE_VERIFY | USAGE_WRAP,
            CKO_PRIVATE_KEY => USAGE_DECRYPT | USAGE_SIGN | USAGE_UNWRAP | USAGE_DERIVE,
            _ => 0,
        };
    for (kind, bit) in CKA_USAGE {
        match bbool(t, kind) {
            Some(true) => u |= bit,
            Some(false) => u &= !bit,
            None => {}
        }
    }
    u
}

/// `fhsm_apply_token_scope`: a session object unless CKA_TOKEN is TRUE; MODIFIABLE,
/// DESTROYABLE and COPYABLE FALSE and WRAP_WITH_TRUSTED TRUE stored as flags.
pub(super) fn apply_token_scope(tok: *mut fhsm_token_t, h: c_ulong, t: &[Attr], o: u32) {
    // SAFETY (each call here): a token the registry holds; out pointers of our own. C ignores
    // the results.
    if bbool(t, CKA_TOKEN) != Some(true) {
        unsafe { fhsm_token_object_mark_session(tok, o, h as u32) };
    }
    let mut pf = 0u8;
    if unsafe { fhsm_token_object_get_flags(tok, o, &mut pf) } == OK {
        if bbool(t, CKA_MODIFIABLE) == Some(false) {
            pf |= OBJF_UNMODIFIABLE;
        }
        if bbool(t, CKA_DESTROYABLE) == Some(false) {
            pf |= OBJF_UNDESTROYABLE;
        }
        unsafe { fhsm_token_object_set_flags(tok, o, pf) };
    }
    let trusted = bbool(t, CKA_WRAP_WITH_TRUSTED) == Some(true);
    let uncopyable = bbool(t, CKA_COPYABLE) == Some(false);
    if trusted || uncopyable {
        let mut f2 = 0u8;
        unsafe { fhsm_token_object_get_flags2(tok, o, &mut f2) };
        if uncopyable {
            f2 |= OBJF2_NOT_COPYABLE;
        }
        if trusted {
            f2 |= OBJF2_WRAP_WITH_TRUSTED;
        }
        unsafe { fhsm_token_object_set_flags2(tok, o, f2) };
    }
}

/// `fhsm_parse_unwrap_template`: the UNWRAP_SENS flag of a CKA_SENSITIVE TRUE entry; any
/// other shape is nothing to enforce here (`fhsm_apply_nested_tmpl` judges it).
pub(super) fn parse_unwrap_template(t: &[Attr]) -> u8 {
    let Some(a) = find(t, CKA_UNWRAP_TEMPLATE) else {
        return 0;
    };
    let sz = size_of::<Attr>();
    let cnt = a.len as usize / sz;
    if a.value.is_null() || cnt == 0 || !(a.len as usize).is_multiple_of(sz) {
        return 0;
    }
    if cnt as c_ulong > MAX_TEMPLATE_ATTRS {
        return 0;
    }
    // SAFETY: the caller's array of cnt CK_ATTRIBUTEs (its length says so)
    let nest = unsafe { std::slice::from_raw_parts(a.value.cast::<Attr>(), cnt) };
    let sens = nest
        .iter()
        .any(|n| n.kind == CKA_SENSITIVE && !n.value.is_null() && n.len == 1 && bytes(n)[0] != 0);
    if sens { OBJF_UNWRAP_SENS } else { 0 }
}

/// `fhsm_apply_ed_curve_name`: CKA_EC_PARAMS given as an Edwards curveName is remembered.
pub(super) fn apply_ed_curve_name(tok: *mut fhsm_token_t, t: &[Attr], o: u32) -> u32 {
    let Some(v) = find(t, CKA_EC_PARAMS).map(bytes) else {
        return OK;
    };
    if v.len() < 2 || v[0] != 0x13 || match_curve(&ED_CURVES, v).is_none() {
        return OK;
    }
    let mut f3 = 0u8;
    // SAFETY: a token the registry holds; an out pointer of our own (C ignores the result)
    unsafe { fhsm_token_object_get_flags3(tok, o, &mut f3) };
    // SAFETY: as above
    unsafe { fhsm_token_object_set_flags3(tok, o, f3 | OBJF3_ED_CURVE_NAME) }
}

/// `fhsm_pset_read`: CKA_PARAMETER_SET as a CKP_* selector or a name. `Ok(None)` when absent;
/// `Err` for a selector or name it does not know. RULE-017: a name outside the mechanism's
/// family is not known (C took any of the eighteen). Key generation's buffer is 32 bytes.
pub(super) fn pset_read(t: &[Attr], mech: c_ulong) -> Result<Option<&'static CStr>, ()> {
    pset_read_in(t, mech, 32)
}

/// `fhsm_pset_read` into a buffer of `cap` bytes: a name of `cap` or more is unknown.
pub(super) fn pset_read_in(
    t: &[Attr],
    mech: c_ulong,
    cap: usize,
) -> Result<Option<&'static CStr>, ()> {
    let Some(a) = find(t, CKA_PARAMETER_SET).filter(|a| !a.value.is_null()) else {
        return Ok(None);
    };
    let family: &[&'static CStr] = match mech {
        CKM_ML_KEM_KEY_PAIR_GEN => &ML_KEM_SETS,
        CKM_ML_DSA_KEY_PAIR_GEN => &ML_DSA_SETS,
        CKM_SLH_DSA_KEY_PAIR_GEN => &SLH_DSA_SETS,
        _ => &[],
    };
    let v = bytes(a);
    if v.len() == size_of::<c_ulong>() {
        let sel = c_ulong::from_ne_bytes(v.try_into().map_err(|_| ())?) as usize;
        return sel
            .checked_sub(1)
            .and_then(|i| family.get(i))
            .copied()
            .map(Some)
            .ok_or(());
    }
    if v.is_empty() || v.len() >= cap {
        return Err(());
    }
    // C copied the name and compared it as a C string: up to its first NUL.
    let name = v.split(|&b| b == 0).next().unwrap_or_default();
    family
        .iter()
        .find(|n| n.to_bytes() == name)
        .copied()
        .map(Some)
        .ok_or(())
}

/// The label C stored: at most 63 bytes of the template's, NUL-terminated.
fn label(t: &[Attr]) -> [c_char; 64] {
    let mut l = [0 as c_char; 64];
    if let Some(a) = find(t, CKA_LABEL) {
        for (d, s) in l.iter_mut().zip(bytes(a).iter().take(63)) {
            *d = *s as c_char;
        }
    }
    l
}

fn id(t: &[Attr]) -> (*const u8, usize) {
    find(t, CKA_ID).map_or((null(), 0), |a| (a.value.cast_const(), a.len as usize))
}

/// `CK_PKCS5_PBKD2_PARAMS2`.
#[repr(C)]
#[derive(Clone, Copy)]
struct Pbkd2Params {
    salt_source: c_ulong,
    salt: *const u8,
    salt_len: c_ulong,
    iterations: c_ulong,
    prf: c_ulong,
    prf_data: *const u8,
    prf_len: c_ulong,
    password: *const u8,
    password_len: c_ulong,
}

/// `pbkd2_material` (`:2779-2832`): the key from the mechanism's parameters.
fn pbkd2_material(m: &Mech, out: &mut [u8]) -> u32 {
    if m.param.is_null() || (m.param_len as usize) < size_of::<Pbkd2Params>() {
        return MECHANISM_PARAM_INVALID;
    }
    // SAFETY: the caller's parameter, at least as long as the struct (C's memcpy)
    let p = unsafe { m.param.cast::<Pbkd2Params>().read_unaligned() };
    let bad = |ptr: *const u8, len: c_ulong| len > 0x7FFF_FFFF || (ptr.is_null() && len != 0);
    if p.salt_source != 1
        || bad(p.salt, p.salt_len)
        || bad(p.password, p.password_len)
        || bad(p.prf_data, p.prf_len)
    {
        return MECHANISM_PARAM_INVALID;
    }
    let hash = match p.prf {
        1 => 7,
        3 => 9,
        4 => 1,
        5 => 2,
        6 => 3,
        7 => 10,
        8 => 11,
        _ => return MECHANISM_PARAM_INVALID,
    };
    // RULE-006: C narrowed the count to 32 bits first, so 2^32 + 2000 ran 2000.
    let Ok(iterations) = u32::try_from(p.iterations) else {
        return MECHANISM_PARAM_INVALID;
    };
    let slice = |ptr: *const u8, len: c_ulong| Slice {
        data: if ptr.is_null() {
            c"".as_ptr().cast()
        } else {
            ptr
        },
        len: len as usize,
    };
    // SAFETY: each slice readable for its length (checked above); out writable
    let rv = unsafe {
        fhsm_pbkdf2(
            hash,
            slice(p.password, p.password_len),
            slice(p.salt, p.salt_len),
            iterations,
            out.as_mut_ptr(),
            out.len(),
        )
    };
    if rv == FIPS_NOT_APPROVED {
        MECHANISM_PARAM_INVALID
    } else {
        rv
    }
}

/// The session's token, if a user or the SO is logged in.
fn token_of(h: c_ulong) -> Result<*mut fhsm_token_t, u32> {
    let Some(tok) = TABLE.token(h) else {
        return Err(SESSION_HANDLE_INVALID);
    };
    if TABLE.role(h) == ROLE_NONE {
        return Err(USER_NOT_LOGGED_IN);
    }
    Ok(tok.0.as_ptr())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_GenerateKey(
    h: c_ulong,
    mech: *const Mech,
    tmpl: *const Attr,
    n: c_ulong,
    out: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if mech.is_null() || out.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // SAFETY: the caller's template and mechanism, out writable
    unsafe { generate_key(h, &*mech, tmpl, n, out) }
        .unwrap_or_else(|rv| rv)
        .into()
}

/// The secret key's type and length (`:2875-2979`).
fn secret_kind(m: &Mech, t: &[Attr]) -> Result<(u32, usize), u32> {
    let len = || match ulong(t, CKA_VALUE_LEN) {
        None | Some(None) => Err(ATTRIBUTE_VALUE_INVALID),
        Some(Some(l)) => Ok(l as usize),
    };
    match m.mechanism {
        CKM_PKCS5_PBKD2 => {
            let kt = ulong(t, CKA_KEY_TYPE)
                .flatten()
                .map_or(CKK_GENERIC_SECRET, |k| k as u32);
            let Some(Some(l)) = ulong(t, CKA_VALUE_LEN) else {
                return Err(TEMPLATE_INCOMPLETE);
            };
            let l = l as usize;
            if l == 0 || l > PBKDF2_MAX {
                return Err(KEY_SIZE_RANGE);
            }
            // DIV-064: C stored any key type, of any of those lengths.
            match kt {
                CKK_GENERIC_SECRET => {}
                CKK_AES if matches!(l, 16 | 24 | 32) => {}
                CKK_AES => return Err(KEY_SIZE_RANGE),
                _ => return Err(ATTRIBUTE_VALUE_INVALID),
            }
            Ok((kt, l))
        }
        CKM_DES3_KEY_GEN => {
            if strict() {
                return Err(MECHANISM_INVALID);
            }
            match ulong(t, CKA_VALUE_LEN) {
                Some(None) => return Err(ATTRIBUTE_VALUE_INVALID),
                Some(Some(l)) if l != 24 => return Err(TEMPLATE_INCONSISTENT),
                _ => {}
            }
            Ok((CKK_DES3, 24))
        }
        CKM_AES_KEY_GEN => match len()? {
            l @ (16 | 24 | 32) => Ok((CKK_AES, l)),
            _ => Err(KEY_SIZE_RANGE),
        },
        CKM_GENERIC_SECRET_KEY_GEN => {
            // RULE-014: under 112 bits is not approved (SP 800-131A); the strict build refuses it.
            let min = if strict() { 14 } else { 1 };
            match len()? {
                l if (min..=64).contains(&l) => Ok((CKK_GENERIC_SECRET, l)),
                _ => Err(KEY_SIZE_RANGE),
            }
        }
        CKM_HKDF_KEY_GEN => match len()? {
            l if (1..=PBKDF2_MAX).contains(&l) => Ok((CKK_HKDF, l)),
            _ => Err(KEY_SIZE_RANGE),
        },
        _ => Err(MECHANISM_INVALID),
    }
}

/// `C_GenerateKey` after its arguments (`:2840-3049`).
///
/// # Safety
/// `tmpl` as C_GenerateKey's; `out` writable.
unsafe fn generate_key(
    h: c_ulong,
    m: &Mech,
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
    let tok = token_of(h)?;
    if find(t, CKA_ENCAPSULATE).is_some() || find(t, CKA_DECAPSULATE).is_some() {
        return Err(ATTRIBUTE_TYPE_INVALID);
    }
    let (kt, len) = secret_kind(m, t)?;
    let label = label(t);
    let (id, id_len) = id(t);
    let first = |kind| {
        find(t, kind)
            .filter(|a| !a.value.is_null() && a.len >= 1)
            .map(|a| bytes(a)[0])
    };
    let mut flags = OBJF_SENSITIVE | OBJF_LOCAL | parse_unwrap_template(t);
    if first(CKA_SENSITIVE) == Some(0) {
        flags &= !OBJF_SENSITIVE;
    }
    if first(CKA_EXTRACTABLE).is_some_and(|b| b != 0) {
        flags |= OBJF_EXTRACTABLE;
    }
    let mut key = [0u8; PBKDF2_MAX];
    let rv = if m.mechanism == CKM_PKCS5_PBKD2 {
        pbkd2_material(m, &mut key[..len])
    } else {
        // SAFETY: key writable for len bytes
        unsafe { fhsm_rng_bytes(key.as_mut_ptr(), len) }
    };
    if rv != OK {
        zeroize(&mut key);
        return Err(rv);
    }
    let mut o = 0u32;
    // SAFETY: a token the registry holds; each buffer valid for its length; o our own
    let rv = unsafe {
        fhsm_token_object_add_pending(
            tok,
            CKO_SECRET_KEY,
            kt,
            label.as_ptr(),
            key.as_ptr(),
            len,
            id,
            id_len,
            flags,
            &mut o,
        )
    };
    zeroize(&mut key);
    if rv != OK {
        return Err(rv);
    }
    // SAFETY: writable (caller); C wrote the handle before applying the rest
    unsafe { *out = o as c_ulong };
    let undo = |rv: u32| {
        // SAFETY: a token the registry holds
        unsafe { fhsm_token_object_destroy(tok, o) };
        rv
    };
    let r = apply_allowed_mechs(tok, t, o);
    if r != OK {
        return Err(undo(r));
    }
    let r = apply_nested_all(tok, t, o);
    if r != OK {
        return Err(undo(r));
    }
    apply_token_scope(tok, h, t, o);
    let r = apply_obj_meta(tok, t, o);
    if r != OK {
        return Err(undo(r));
    }
    // SAFETY: a token the registry holds (C ignores the result)
    unsafe { fhsm_token_object_set_usage(tok, o, compute_usage(CKO_SECRET_KEY, t)) };
    // SAFETY: as above
    let r = unsafe { fhsm_token_object_publish(tok, o) };
    if r != OK {
        return Err(undo(r));
    }
    Ok(OK)
}

#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn pqhsm_C_GenerateKeyPair(
    h: c_ulong,
    mech: *const Mech,
    pubt: *const Attr,
    npub: c_ulong,
    privt: *const Attr,
    npriv: c_ulong,
    out_pub: *mut c_ulong,
    out_priv: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if mech.is_null() || out_pub.is_null() || out_priv.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // SAFETY: the caller's templates and mechanism, both outs writable
    unsafe { generate_pair(h, &*mech, (pubt, npub), (privt, npriv), (out_pub, out_priv)) }
        .unwrap_or_else(|rv| rv)
        .into()
}

/// The new pair before it is stored: its DER halves and key type.
struct Pair {
    public: Vec<u8>,
    private: Vec<u8>,
    kt: u32,
}

impl Drop for Pair {
    fn drop(&mut self) {
        zeroize(&mut self.private);
    }
}

/// The mechanism chain (`:6605-6737`): the key (`None` if OpenSSL made none), its type and
/// its pairwise family.
fn pair_kind(m: c_ulong, pubt: &[Attr]) -> Result<(Option<Pkey>, u32, c_int), u32> {
    let params = find(pubt, CKA_EC_PARAMS)
        .filter(|a| !a.value.is_null())
        .map(bytes);
    let pq = |default: &'static CStr| -> Result<Option<Pkey>, u32> {
        let set = pset_read(pubt, m).map_err(|()| ATTRIBUTE_VALUE_INVALID)?;
        Ok(Pkey::generate(set.unwrap_or(default)))
    };
    Ok(match m {
        CKM_RSA_PKCS_KEY_PAIR_GEN => {
            let bits = ulong(pubt, CKA_MODULUS_BITS).flatten().unwrap_or(2048);
            if !matches!(bits, 2048 | 3072 | 4096) {
                return Err(KEY_SIZE_RANGE);
            }
            let e = find(pubt, CKA_PUBLIC_EXPONENT)
                .map(bytes)
                .filter(|e| !e.is_empty())
                .map(rsa_exponent)
                .transpose()?;
            (Pkey::generate_rsa(bits as c_int, e), CKK_RSA, PW_RSA)
        }
        CKM_EC_KEY_PAIR_GEN => {
            let curve = match params.map(|v| ec_curve(v, strict())) {
                None => c"P-256",
                Some(Curve::Named(n)) => n,
                Some(Curve::Unsupported) => return Err(CURVE_NOT_SUPPORTED),
                Some(Curve::Invalid) => return Err(ATTRIBUTE_VALUE_INVALID),
            };
            (Pkey::generate_ec(curve), CKK_EC, PW_EC)
        }
        CKM_EC_EDWARDS_KEY_PAIR_GEN => {
            let alg = match params {
                None => c"ED25519",
                Some(v) => match_curve(&ED_CURVES, v).ok_or(ATTRIBUTE_VALUE_INVALID)?,
            };
            (Pkey::generate(alg), CKK_EC_EDWARDS, PW_EDDSA)
        }
        CKM_EC_MONTGOMERY_KEY_PAIR_GEN => {
            if strict() || !ecm_available() {
                return Err(MECHANISM_INVALID);
            }
            let alg = match params {
                None => c"X25519",
                Some(v) => match_curve(&ECM_CURVES, v).ok_or(ATTRIBUTE_VALUE_INVALID)?,
            };
            (Pkey::generate(alg), CKK_EC_MONTGOMERY, PW_ECM)
        }
        CKM_ML_KEM_KEY_PAIR_GEN => (pq(c"ML-KEM-768")?, CKK_ML_KEM, PW_ML_KEM),
        CKM_ML_DSA_KEY_PAIR_GEN => (pq(c"ML-DSA-65")?, CKK_ML_DSA, PW_ML_DSA),
        CKM_SLH_DSA_KEY_PAIR_GEN => (pq(c"SLH-DSA-SHA2-128s")?, CKK_SLH_DSA, PW_SLH_DSA),
        _ => return Err(MECHANISM_INVALID),
    })
}

/// RULE-015: the requested public exponent, which must be odd and 2^16 < e < 2^256
/// (FIPS 186-5). C required only odd and > 1, then generated with 65537 whatever was asked.
fn rsa_exponent(e: &[u8]) -> Result<&[u8], u32> {
    let e = &e[e.iter().take_while(|&&b| b == 0).count()..];
    let odd = e.last().is_some_and(|b| b & 1 == 1);
    let above = e.len() > 3 || (e.len() == 3 && e > [1, 0, 0].as_slice());
    if odd && above && e.len() <= 32 {
        Ok(e)
    } else {
        Err(ATTRIBUTE_VALUE_INVALID)
    }
}

/// `C_GenerateKeyPair` after its arguments (`:6536-6932`).
///
/// # Safety
/// Each template as C_GenerateKeyPair's; both outs writable.
unsafe fn generate_pair(
    h: c_ulong,
    m: &Mech,
    pubt: (*const Attr, c_ulong),
    privt: (*const Attr, c_ulong),
    outs: (*mut c_ulong, *mut c_ulong),
) -> Result<u32, u32> {
    // SAFETY: the caller's
    let pubt = unsafe { check_template(pubt.0, pubt.1) }?;
    check_trusted(h, pubt)?;
    // SAFETY: the caller's
    let privt = unsafe { check_template(privt.0, privt.1) }?;
    check_trusted(h, privt)?;
    let ul = size_of::<c_ulong>() as c_ulong;
    check_lengths(pubt, &BOOL_ATTRS, 1)?;
    check_lengths(privt, &BOOL_ATTRS, 1)?;
    check_lengths(pubt, &ULONG_ATTRS, ul)?;
    check_lengths(privt, &ULONG_ATTRS, ul)?;
    check_ro_token(h, pubt)?;
    check_ro_token(h, privt)?;
    let mech = m.mechanism;
    if matches!(
        mech,
        CKM_ML_KEM_KEY_PAIR_GEN | CKM_ML_DSA_KEY_PAIR_GEN | CKM_SLH_DSA_KEY_PAIR_GEN
    ) && (pset_read(pubt, mech).is_err() || pset_read(privt, mech).is_err())
    {
        return Err(ATTRIBUTE_VALUE_INVALID);
    }
    let tok = token_of(h)?;
    let pair = if mech == CKM_COMPOSITE {
        if strict() {
            return Err(MECHANISM_INVALID);
        }
        composite_pair()?
    } else {
        let (k, kt, family) = pair_kind(mech, pubt)?;
        let Some(k) = k else {
            report_keygen_failure(mech);
            return Err(FUNCTION_FAILED);
        };
        // SAFETY: a live key
        let pw = unsafe { fhsm_pairwise_check(k.as_ptr().cast(), family) };
        let fam = cnum(family);
        let a = audit(
            EV_KAT_REPORT,
            -1,
            h as c_int,
            TABLE.role(h),
            pw,
            &[(c"pairwise_family", &fam)],
        );
        if pw != OK {
            // DIV-052: C's fhsm_state_set(ERROR) was refused by the transition table.
            // SAFETY: a C string
            unsafe { fhsm_state_latch_error(c"pairwise consistency failure".as_ptr()) };
            return Err(FUNCTION_FAILED);
        }
        // DIV-001: no key from a check that could not be recorded
        a?;
        // public first, as C: the private half goes straight into Pair, which zeroizes it
        let public = k.public_der().ok_or(FUNCTION_FAILED)?;
        let pair = Pair {
            public,
            private: k.private_der().ok_or(FUNCTION_FAILED)?,
            kt,
        };
        if pair.public.len() > 5500 || pair.private.len() > 5500 {
            return Err(FUNCTION_FAILED);
        }
        pair
    };
    // SAFETY: the token, the templates and the outs are the caller's, checked above
    unsafe { store_pair(h, tok, &pair, pubt, privt, outs) }
}

/// `fhsm_composite_keygen` into the pair's halves.
fn composite_pair() -> Result<Pair, u32> {
    let mut pair = Pair {
        public: vec![0u8; COMPOSITE_PUB_MAX],
        private: vec![0u8; COMPOSITE_PRIV_MAX],
        kt: CKK_COMPOSITE,
    };
    let (mut pvl, mut pbl) = (pair.private.len(), pair.public.len());
    // SAFETY: each buffer writable for its length
    let rv = unsafe {
        fhsm_composite_keygen(
            COMPOSITE_ALG,
            pair.private.as_mut_ptr(),
            &mut pvl,
            pair.public.as_mut_ptr(),
            &mut pbl,
        )
    };
    if rv != OK {
        return Err(rv);
    }
    if pvl > pair.private.len() || pbl > pair.public.len() {
        return Err(HOST_MEMORY);
    }
    // The tail being cut held no secret: keygen wrote pvl bytes.
    pair.private.truncate(pvl);
    pair.public.truncate(pbl);
    Ok(pair)
}

/// Both halves stored and their templates applied (`:6810-6931`).
///
/// # Safety
/// `tok` a token the registry holds; the outs writable.
unsafe fn store_pair(
    h: c_ulong,
    tok: *mut fhsm_token_t,
    pair: &Pair,
    pubt: &[Attr],
    privt: &[Attr],
    outs: (*mut c_ulong, *mut c_ulong),
) -> Result<u32, u32> {
    let (lp, lk) = (label(pubt), label(privt));
    let mut priv_flags = OBJF_SENSITIVE | OBJF_LOCAL;
    if find(privt, CKA_ALWAYS_AUTHENTICATE)
        .is_some_and(|a| !a.value.is_null() && a.len == 1 && bytes(a)[0] != 0)
    {
        priv_flags |= OBJF_ALWAYS_AUTH;
    }
    priv_flags |= parse_unwrap_template(privt);
    let add = |class, label: &[c_char; 64], v: &[u8], id: (*const u8, usize), flags| {
        let mut o = 0u32;
        // SAFETY: a token the registry holds; each buffer valid for its length
        let rv = unsafe {
            fhsm_token_object_add_pending(
                tok,
                class,
                pair.kt,
                label.as_ptr(),
                v.as_ptr(),
                v.len(),
                id.0,
                id.1,
                flags,
                &mut o,
            )
        };
        if rv == OK { Ok(o) } else { Err(rv) }
    };
    let destroy = |o: u32| {
        // SAFETY: a token the registry holds
        unsafe { fhsm_token_object_destroy(tok, o) };
    };
    let hp = add(CKO_PUBLIC_KEY, &lp, &pair.public, id(pubt), OBJF_LOCAL)?;
    for r in [
        apply_allowed_mechs(tok, pubt, hp),
        apply_nested_all(tok, pubt, hp),
    ] {
        if r != OK {
            destroy(hp);
            return Err(r);
        }
    }
    let hk = add(CKO_PRIVATE_KEY, &lk, &pair.private, id(privt), priv_flags).inspect_err(|_| {
        destroy(hp);
    })?;
    let both = |r: u32| {
        destroy(hk);
        destroy(hp);
        r
    };
    for r in [
        apply_allowed_mechs(tok, privt, hk),
        apply_nested_all(tok, privt, hk),
    ] {
        if r != OK {
            return Err(both(r));
        }
    }
    // SAFETY: writable (caller); C wrote both handles before applying the rest
    unsafe {
        *outs.0 = hp as c_ulong;
        *outs.1 = hk as c_ulong;
    }
    for r in [
        apply_encap_flags(tok, pubt, hp, CKO_PUBLIC_KEY),
        apply_encap_flags(tok, privt, hk, CKO_PRIVATE_KEY),
    ] {
        if r != OK {
            return Err(both(r));
        }
    }
    let mut r = apply_ed_curve_name(tok, pubt, hp);
    if r == OK {
        r = apply_ed_curve_name(tok, pubt, hk);
    }
    if r != OK {
        return Err(both(r));
    }
    apply_token_scope(tok, h, pubt, hp);
    let r = apply_obj_meta(tok, pubt, hp);
    if r != OK {
        return Err(both(r));
    }
    // SAFETY: a token the registry holds (C ignores the result)
    unsafe { fhsm_token_object_set_usage(tok, hp, compute_usage(CKO_PUBLIC_KEY, pubt)) };
    apply_token_scope(tok, h, privt, hk);
    let r = apply_obj_meta(tok, privt, hk);
    if r != OK {
        return Err(both(r));
    }
    let mut pu = compute_usage(CKO_PRIVATE_KEY, privt);
    // PQC keys do not derive (#125)
    if matches!(pair.kt, CKK_ML_KEM | CKK_ML_DSA | CKK_SLH_DSA) {
        pu &= !USAGE_DERIVE;
    }
    // SAFETY: as above
    unsafe { fhsm_token_object_set_usage(tok, hk, pu) };
    // SAFETY: as above
    let r = unsafe { fhsm_token_object_publish_pair(tok, hp, hk) };
    if r != OK {
        return Err(both(r));
    }
    Ok(OK)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(kind: c_ulong, v: &[u8]) -> Attr {
        Attr {
            kind,
            value: v.as_ptr().cast_mut(),
            len: v.len() as c_ulong,
        }
    }

    #[test]
    fn parameter_sets_keep_to_their_family() {
        let sel = |s: c_ulong| s.to_ne_bytes();
        let one = sel(1);
        let t = [attr(CKA_PARAMETER_SET, &one)];
        assert_eq!(
            pset_read(&t, CKM_ML_KEM_KEY_PAIR_GEN),
            Ok(Some(c"ML-KEM-512"))
        );
        assert_eq!(
            pset_read(&t, CKM_SLH_DSA_KEY_PAIR_GEN),
            Ok(Some(c"SLH-DSA-SHA2-128s"))
        );
        let zero = sel(0);
        assert!(pset_read(&[attr(CKA_PARAMETER_SET, &zero)], CKM_ML_DSA_KEY_PAIR_GEN).is_err());
        let thirteen = sel(13);
        let t13 = [attr(CKA_PARAMETER_SET, &thirteen)];
        assert!(pset_read(&t13, CKM_SLH_DSA_KEY_PAIR_GEN).is_err());
        // RULE-017: a name of another family; a NUL ends the name, as C's strcmp did
        let dsa = [attr(CKA_PARAMETER_SET, b"ML-DSA-44")];
        assert!(pset_read(&dsa, CKM_ML_KEM_KEY_PAIR_GEN).is_err());
        assert_eq!(
            pset_read(&dsa, CKM_ML_DSA_KEY_PAIR_GEN),
            Ok(Some(c"ML-DSA-44"))
        );
        let nul = [attr(CKA_PARAMETER_SET, b"ML-KEM-512\0junk")];
        assert_eq!(
            pset_read(&nul, CKM_ML_KEM_KEY_PAIR_GEN),
            Ok(Some(c"ML-KEM-512"))
        );
        assert!(pset_read(&[attr(CKA_PARAMETER_SET, b"")], CKM_ML_KEM_KEY_PAIR_GEN).is_err());
        assert_eq!(pset_read(&[], CKM_ML_KEM_KEY_PAIR_GEN), Ok(None));
        // C_CreateObject's buffer is 64: a char[32] name, NUL-padded, is still a name there
        let mut padded = [0u8; 32];
        padded[..9].copy_from_slice(b"ML-DSA-44");
        let t32 = [attr(CKA_PARAMETER_SET, &padded)];
        assert!(pset_read(&t32, CKM_ML_DSA_KEY_PAIR_GEN).is_err());
        assert_eq!(
            pset_read_in(&t32, CKM_ML_DSA_KEY_PAIR_GEN, 64),
            Ok(Some(c"ML-DSA-44"))
        );
    }

    #[test]
    fn rsa_exponents_follow_fips_186_5() {
        assert_eq!(rsa_exponent(&[1, 0, 1]), Ok(&[1u8, 0, 1][..]));
        assert_eq!(rsa_exponent(&[0, 1, 0, 1]), Ok(&[1u8, 0, 1][..]));
        assert_eq!(rsa_exponent(&[2, 0, 1]), Ok(&[2u8, 0, 1][..]));
        for bad in [
            &[3u8][..],
            &[4],
            &[1],
            &[0],
            &[1, 0, 0],
            &[1, 0, 2],
            &[1; 33],
        ] {
            assert_eq!(rsa_exponent(bad), Err(ATTRIBUTE_VALUE_INVALID), "{bad:?}");
        }
    }

    #[test]
    fn usage_is_the_class_default_then_the_template() {
        let t = [attr(0x104, &[0]), attr(0x10C, &[1])];
        assert_eq!(
            compute_usage(CKO_SECRET_KEY, &t),
            USAGE_VALID | 0x3E | USAGE_DERIVE
        );
        assert_eq!(compute_usage(CKO_PRIVATE_KEY, &[]), USAGE_VALID | 0x66);
        assert_eq!(compute_usage(CKO_PUBLIC_KEY, &[]), USAGE_VALID | 0x19);
    }
}
