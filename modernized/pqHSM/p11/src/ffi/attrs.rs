//! Phase 4 slice 2b: `C_GetAttributeValue` and `C_SetAttributeValue`
//! (`src/fhsm_pkcs11.c:7155-7647, 7700-7972`), in C's order, over the token's C ABI. The
//! OpenSSL readbacks (RSA and EC components, certificate fields, the parameter set, a PQC
//! public key's raw form) are Rust's since slice 8b-ii, over `pqhsm_crypto::readback`.

use std::ffi::{CStr, c_char, c_int, c_ulong};
use std::ptr::null;

use pqhsm_core::session::{ROLE_NONE, ROLE_SO};
use pqhsm_crypto::cipher::Pkey;
use pqhsm_crypto::readback::{CertField, cert_field};

use super::apilock::Held;
use super::keygen::{
    CKK_EC, CKK_EC_EDWARDS, CKK_EC_MONTGOMERY, CKK_RSA, CKK_SLH_DSA, ML_DSA_SETS, ML_KEM_SETS,
    OBJF3_ED_CURVE_NAME, SLH_DSA_SETS,
};
use super::objects::{
    Attr, CKA_CLASS, CKA_ID, CKA_LABEL, CKF_RW_SESSION, CKO_PRIVATE_KEY, CKO_SECRET_KEY,
    MAX_TEMPLATE_ATTRS, OBJF_UNDESTROYABLE, access_denied, check_template, class_of, gate,
    lookup_rv,
};
use super::session::TABLE;
use super::sys::*;

const UNAVAILABLE: c_ulong = c_ulong::MAX;
const BUFFER_TOO_SMALL: u32 = 0x150;
const ATTRIBUTE_SENSITIVE: u32 = 0x11;
pub(super) const ATTRIBUTE_TYPE_INVALID: u32 = 0x12;
pub(super) const ATTRIBUTE_READ_ONLY: u32 = 0x10;

const CKO_DATA: u32 = 0;
const CKO_CERTIFICATE: u32 = 1;
pub(super) const CKO_PUBLIC_KEY: u32 = 2;
pub(super) const CKK_ML_KEM: u32 = 0x49;
pub(super) const CKK_ML_DSA: u32 = 0x4A;

pub(super) const CKA_TOKEN: c_ulong = 0x1;
pub(super) const CKA_PRIVATE: c_ulong = 0x2;
pub(super) const CKA_APPLICATION: c_ulong = 0x10;
pub(super) const CKA_VALUE: c_ulong = 0x11;
const CKA_CERTIFICATE_TYPE: c_ulong = 0x80;
const CKA_ISSUER: c_ulong = 0x81;
const CKA_SERIAL_NUMBER: c_ulong = 0x82;
pub(super) const CKA_TRUSTED: c_ulong = 0x86;
pub(super) const CKA_KEY_TYPE: c_ulong = 0x100;
const CKA_SUBJECT: c_ulong = 0x101;
pub(super) const CKA_SENSITIVE: c_ulong = 0x103;
const CKA_ENCRYPT: c_ulong = 0x104;
const CKA_DECRYPT: c_ulong = 0x105;
const CKA_WRAP: c_ulong = 0x106;
const CKA_UNWRAP: c_ulong = 0x107;
const CKA_SIGN: c_ulong = 0x108;
const CKA_SIGN_RECOVER: c_ulong = 0x109;
const CKA_VERIFY: c_ulong = 0x10A;
const CKA_VERIFY_RECOVER: c_ulong = 0x10B;
const CKA_DERIVE: c_ulong = 0x10C;
pub(super) const CKA_START_DATE: c_ulong = 0x110;
pub(super) const CKA_END_DATE: c_ulong = 0x111;
const CKA_MODULUS: c_ulong = 0x120;
const CKA_MODULUS_BITS: c_ulong = 0x121;
const CKA_PUBLIC_EXPONENT: c_ulong = 0x122;
pub(super) const CKA_VALUE_LEN: c_ulong = 0x161;
pub(super) const CKA_EXTRACTABLE: c_ulong = 0x162;
const CKA_LOCAL: c_ulong = 0x163;
const CKA_NEVER_EXTRACTABLE: c_ulong = 0x164;
const CKA_ALWAYS_SENSITIVE: c_ulong = 0x165;
pub(super) const CKA_MODIFIABLE: c_ulong = 0x170;
pub(super) const CKA_COPYABLE: c_ulong = 0x171;
pub(super) const CKA_DESTROYABLE: c_ulong = 0x172;
const CKA_EC_PARAMS: c_ulong = 0x180;
const CKA_EC_POINT: c_ulong = 0x181;
const CKA_ALWAYS_AUTHENTICATE: c_ulong = 0x202;
const CKA_WRAP_WITH_TRUSTED: c_ulong = 0x210;
const CKA_PARAMETER_SET: c_ulong = 0x61D;
pub(super) const CKA_ENCAPSULATE: c_ulong = 0x633;
pub(super) const CKA_DECAPSULATE: c_ulong = 0x634;
pub(super) const CKA_WRAP_TEMPLATE: c_ulong = 0x4000_0211;
pub(super) const CKA_UNWRAP_TEMPLATE: c_ulong = 0x4000_0212;
pub(super) const CKA_DERIVE_TEMPLATE: c_ulong = 0x4000_0213;
pub(super) const CKA_ALLOWED_MECHANISMS: c_ulong = 0x4000_0600;

pub(super) const OBJF_SENSITIVE: u8 = 0x01;
pub(super) const OBJF_EXTRACTABLE: u8 = 0x02;
// RULE-059: history in the third flags byte (0x01 is FHSM_OBJF3_ED_CURVE_NAME). Clear in every
// record written before them, which reads as before: the history is the current flags.
/// The key was once not sensitive.
pub(super) const OBJF3_WAS_NOT_SENSITIVE: u8 = 0x02;
/// The key was once extractable.
pub(super) const OBJF3_WAS_EXTRACTABLE: u8 = 0x04;

/// The history bits a flags change from `before` to `after` must record: SENSITIVE turned on,
/// EXTRACTABLE turned off. The reverse moves are refused, so these are the only losses.
pub(super) fn history(before: u8, after: u8) -> u8 {
    let mut h = 0;
    if before & OBJF_SENSITIVE == 0 && after & OBJF_SENSITIVE != 0 {
        h |= OBJF3_WAS_NOT_SENSITIVE;
    }
    if before & OBJF_EXTRACTABLE != 0 && after & OBJF_EXTRACTABLE == 0 {
        h |= OBJF3_WAS_EXTRACTABLE;
    }
    h
}

/// RULE-059: a key made outside the token (imported or unwrapped) was never always sensitive,
/// nor never extractable, per PKCS#11.
pub(super) fn imported(t: *mut fhsm_token_t, o: u32) -> u32 {
    mark(t, o, OBJF3_WAS_NOT_SENSITIVE | OBJF3_WAS_EXTRACTABLE)
}

/// RULE-059: add history `bits` (`OBJF3_WAS_*`) to object o.
pub(super) fn mark(t: *mut fhsm_token_t, o: u32, bits: u8) -> u32 {
    let mut f3 = 0u8;
    // SAFETY: a token the registry holds; an out byte of our own
    let rv = unsafe { fhsm_token_object_get_flags3(t, o, &mut f3) };
    if rv != OK {
        return rv;
    }
    // SAFETY: as above
    unsafe { fhsm_token_object_set_flags3(t, o, f3 | bits) }
}
pub(super) const OBJF_UNMODIFIABLE: u8 = 0x04;
pub(super) const OBJF_LOCAL: u8 = 0x10;
pub(super) const OBJF_ALWAYS_AUTH: u8 = 0x20;
pub(super) const OBJF_TRUSTED: u8 = 0x40;
pub(super) const OBJF2_NO_ENCAPSULATE: u8 = 0x01;
pub(super) const OBJF2_NO_DECAPSULATE: u8 = 0x02;
pub(super) const OBJF2_NOT_COPYABLE: u8 = 0x04;
pub(super) const OBJF2_HAS_ALLOWED_MECH: u8 = 0x08;
pub(super) const OBJF2_HAS_WRAP_TMPL: u8 = 0x10;
pub(super) const OBJF2_HAS_UNWRAP_TMPL: u8 = 0x20;
pub(super) const OBJF2_HAS_DERIVE_TMPL: u8 = 0x40;
pub(super) const OBJF2_WRAP_WITH_TRUSTED: u8 = 0x80;
pub(super) const USAGE_ENCRYPT: u8 = 0x01;
pub(super) const USAGE_DECRYPT: u8 = 0x02;
pub(super) const USAGE_SIGN: u8 = 0x04;
pub(super) const USAGE_VERIFY: u8 = 0x08;
pub(super) const USAGE_WRAP: u8 = 0x10;
pub(super) const USAGE_UNWRAP: u8 = 0x20;
pub(super) const USAGE_DERIVE: u8 = 0x40;
pub(super) const USAGE_VALID: u8 = 0x80;
pub(super) const META_START_DATE: c_int = 0;
pub(super) const META_END_DATE: c_int = 1;
pub(super) const META_APPLICATION: c_int = 2;
pub(super) const POLICY_MECH_MAX: usize = 8;
pub(super) const POLICY_ATTR_MAX: usize = 4;
/// ML-DSA-87's raw public key, the largest of the six (C's `pqc_raw`).
const PQC_RAW_MAX: usize = 2592;

/// `fhsm_policy_attr_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PolicyAttr {
    pub(super) kind_: u32,
    pub(super) kind: u8,
    pub(super) len: u8,
    pub(super) value: [u8; 48],
}

type Getter = unsafe extern "C" fn(*mut fhsm_token_t, u32, *mut u8) -> u32;
unsafe extern "C" {
    pub(super) fn fhsm_token_object_get_flags3(t: *mut fhsm_token_t, h: u32, out: *mut u8) -> u32;
    pub(super) fn fhsm_token_object_set_flags3(t: *mut fhsm_token_t, h: u32, v: u8) -> u32;
    pub(super) fn fhsm_token_object_get_tmpl(
        t: *mut fhsm_token_t,
        h: u32,
        which: c_int,
        out: *mut PolicyAttr,
        io_count: *mut u8,
    ) -> u32;
}

/// `n` bytes at `p`, or none.
///
/// # Safety
/// `p` is NULL or valid for `n` bytes for `'a`.
unsafe fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if p.is_null() || n == 0 {
        &[]
    } else {
        // SAFETY: the caller's
        unsafe { std::slice::from_raw_parts(p, n) }
    }
}

/// A flags byte and its rv; the byte is 0 when the lookup fails, as C's ignored rv left it.
fn flags_of(t: *mut fhsm_token_t, o: u32, get: Getter) -> (u32, u8) {
    let mut f = 0u8;
    // SAFETY: a token the registry holds; an out pointer of our own
    let rv = unsafe { get(t, o, &mut f) };
    (rv, f)
}

/// The usage bit behind a usage attribute, and its class default (`fhsm_usage_bool`'s callers).
pub(super) fn usage_of(kind: c_ulong, class: u32) -> Option<(u8, bool)> {
    Some(match kind {
        CKA_ENCRYPT => (USAGE_ENCRYPT, class != CKO_PRIVATE_KEY),
        CKA_VERIFY => (USAGE_VERIFY, class != CKO_PRIVATE_KEY),
        CKA_WRAP => (USAGE_WRAP, class != CKO_PRIVATE_KEY),
        CKA_DECRYPT => (USAGE_DECRYPT, class != CKO_PUBLIC_KEY),
        CKA_SIGN => (USAGE_SIGN, class != CKO_PUBLIC_KEY),
        CKA_UNWRAP => (USAGE_UNWRAP, class != CKO_PUBLIC_KEY),
        CKA_DERIVE => (USAGE_DERIVE, false),
        _ => return None,
    })
}

/// The explicit usage byte an object without one reads as: its class defaults.
pub(super) fn usage_defaults(class: u32) -> u8 {
    [
        CKA_ENCRYPT,
        CKA_DECRYPT,
        CKA_SIGN,
        CKA_VERIFY,
        CKA_WRAP,
        CKA_UNWRAP,
        CKA_DERIVE,
    ]
    .into_iter()
    .filter_map(|k| usage_of(k, class))
    .filter(|&(_, d)| d)
    .fold(USAGE_VALID, |u, (b, _)| u | b)
}

/// `fhsm_usage_bool`: the stored usage bit if the object carries explicit usage, else the
/// class default.
fn usage_bool(t: *mut fhsm_token_t, o: u32, bit: u8, class_default: bool) -> u8 {
    let (rv, u) = flags_of(t, o, fhsm_token_object_get_usage);
    u8::from(if rv == OK && u & USAGE_VALID != 0 {
        u & bit != 0
    } else {
        class_default
    })
}

/// A stored key's DER as OpenSSL reads it: an SPKI, or a private key.
fn key_of(class: u32, der: &[u8]) -> Option<Pkey> {
    match class {
        CKO_PUBLIC_KEY => Pkey::public(der),
        CKO_PRIVATE_KEY => Pkey::private(der),
        _ => None,
    }
}

/// DER OCTET STRING (long form past 127; C wrote the length's low byte).
fn octet_string(p: &[u8]) -> Vec<u8> {
    let n = p.len() as u8;
    let len: &[u8] = if p.len() > 127 { &[0x81, n] } else { &[n] };
    [&[0x04], len, p].concat()
}

/// `extract_pubkey_attr` (`src/fhsm_pkcs11.c:6951-7120`): RSA's and EC's public parts of the
/// stored key `der`, and the Edwards and Montgomery curves' OID or RFC 8032 name and key.
fn pubkey_attr(
    t: *mut fhsm_token_t,
    o: u32,
    (class, kt, der): (u32, u32, &[u8]),
    kind: c_ulong,
) -> Option<Vec<u8>> {
    let k = key_of(class, der)?;
    match (kt, kind) {
        (CKK_RSA, CKA_MODULUS_BITS) => Some((k.bits() as c_ulong).to_ne_bytes().to_vec()),
        (CKK_RSA, CKA_MODULUS) => k.bn(c"n"),
        (CKK_RSA, CKA_PUBLIC_EXPONENT) => k.bn(c"e"),
        (CKK_EC, CKA_EC_POINT) => k
            .octets(c"encoded-pub-key", 256)
            .filter(|p| !p.is_empty())
            .map(|p| octet_string(&p)),
        (CKK_EC, CKA_EC_PARAMS) => k.group_oid(),
        (CKK_EC_EDWARDS | CKK_EC_MONTGOMERY, CKA_EC_PARAMS | CKA_EC_POINT) => {
            // RFC 8410's consecutive OIDs 1.3.101.110-113
            let last = [
                (c"X25519", 0x6E),
                (c"X448", 0x6F),
                (c"ED25519", 0x70),
                (c"ED448", 0x71),
            ]
            .into_iter()
            .find(|(alg, _)| k.is_a(alg))?
            .1;
            if kind == CKA_EC_POINT {
                return k
                    .octets(c"pub", 64)
                    .filter(|r| !r.is_empty())
                    .map(|r| octet_string(&r));
            }
            // An Edwards key created with its RFC 8032 curve name answers it (flags3 read for
            // those only, as C)
            let named = last >= 0x70 && {
                let (frv, f3) = flags_of(t, o, fhsm_token_object_get_flags3);
                frv == OK && f3 & OBJF3_ED_CURVE_NAME != 0
            };
            if named {
                let nm: &[u8] = if last == 0x70 {
                    b"edwards25519"
                } else {
                    b"edwards448"
                };
                return Some([&[0x13, nm.len() as u8], nm].concat());
            }
            Some(vec![0x06, 0x03, 0x2B, 0x65, last])
        }
        _ => None,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_GetAttributeValue(
    h: c_ulong,
    o: c_ulong,
    tmpl: *mut Attr,
    n: c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    // A NULL value with a length is the size query here, so no fhsm_check_template.
    if n > MAX_TEMPLATE_ATTRS || (tmpl.is_null() && n != 0) {
        return ARGUMENTS_BAD.into();
    }
    let t = tok.0.as_ptr();
    let o = o as u32;
    let (mut vp, mut vl, mut class, mut kt) = (null(), 0usize, 0u32, 0u32);
    // SAFETY: a token the registry holds; out pointers of our own
    let rv = unsafe { fhsm_token_object_get(t, o, &mut vp, &mut vl, &mut class, &mut kt) };
    if rv != OK {
        return lookup_rv(rv).into();
    }
    if access_denied(tok, class) {
        return OBJECT_HANDLE_INVALID.into();
    }
    // SAFETY: the store's value, alive while the object is (no destroy under the shared lock)
    let value = unsafe { bytes(vp, vl) };
    let tmpl: &mut [Attr] = if n == 0 {
        &mut []
    } else {
        // SAFETY: the caller's n attributes, n bounded above
        unsafe { std::slice::from_raw_parts_mut(tmpl, n as usize) }
    };
    let (mut too_small, mut type_invalid, mut sensitive) = (false, false, false);
    let ulong = |v: c_ulong| v.to_ne_bytes();
    for a in tmpl.iter_mut() {
        let ul: [u8; size_of::<c_ulong>()];
        let b: [u8; 1];
        let raw: Vec<u8>;
        let mut mechs = [0u8; POLICY_MECH_MAX * size_of::<c_ulong>()];
        let src: &[u8] = match a.kind {
            CKA_CLASS => {
                ul = ulong(class.into());
                &ul
            }
            // A certificate has no CKA_KEY_TYPE; the store's key_type is its certificate type.
            CKA_KEY_TYPE | CKA_CERTIFICATE_TYPE
                if (a.kind == CKA_KEY_TYPE) == (class == CKO_CERTIFICATE) =>
            {
                a.len = UNAVAILABLE;
                continue;
            }
            CKA_KEY_TYPE | CKA_CERTIFICATE_TYPE => {
                ul = ulong(kt.into());
                &ul
            }
            CKA_VALUE => {
                // Withheld when sensitive, or for a key that is not extractable; flags that
                // cannot be read count as the strict answer for a private or secret key.
                let (frv, of) = flags_of(t, o, fhsm_token_object_get_flags);
                let have = frv == OK;
                let secret = class == CKO_PRIVATE_KEY || class == CKO_SECRET_KEY;
                if (have && of & OBJF_SENSITIVE != 0)
                    || (secret && (!have || of & OBJF_EXTRACTABLE == 0))
                {
                    a.len = UNAVAILABLE;
                    sensitive = true;
                    continue;
                }
                if class == CKO_PUBLIC_KEY && (kt == CKK_ML_KEM || kt == CKK_ML_DSA) {
                    // C read it into a buffer of PQC_RAW_MAX bytes
                    let Some(r) = Pkey::public(value)
                        .and_then(|k| k.raw_pub())
                        .filter(|r| r.len() <= PQC_RAW_MAX)
                    else {
                        a.len = UNAVAILABLE;
                        continue;
                    };
                    raw = r;
                    &raw
                } else {
                    value
                }
            }
            CKA_VALUE_LEN => {
                ul = ulong(vl as c_ulong);
                &ul
            }
            CKA_PARAMETER_SET => {
                // fhsm_pset_selector_of (src/fhsm_pkcs11.c:6505): the CKP_* the key is
                let sets: &[&CStr] = match kt {
                    CKK_ML_KEM => &ML_KEM_SETS,
                    CKK_ML_DSA => &ML_DSA_SETS,
                    CKK_SLH_DSA => &SLH_DSA_SETS,
                    _ => &[],
                };
                let found = (!sets.is_empty())
                    .then(|| key_of(class, value))
                    .flatten()
                    .and_then(|k| sets.iter().position(|s| k.is_a(s)));
                let Some(i) = found else {
                    a.len = UNAVAILABLE;
                    continue;
                };
                ul = ulong(i as c_ulong + 1);
                &ul
            }
            CKA_ENCAPSULATE | CKA_DECAPSULATE => {
                let encap = a.kind == CKA_ENCAPSULATE;
                let want = if encap {
                    CKO_PUBLIC_KEY
                } else {
                    CKO_PRIVATE_KEY
                };
                if kt != CKK_ML_KEM || class != want {
                    a.len = UNAVAILABLE;
                    continue;
                }
                let (_, f2) = flags_of(t, o, fhsm_token_object_get_flags2);
                let bit = if encap {
                    OBJF2_NO_ENCAPSULATE
                } else {
                    OBJF2_NO_DECAPSULATE
                };
                b = [u8::from(f2 & bit == 0)];
                &b
            }
            CKA_ALLOWED_MECHANISMS => {
                let (_, f2) = flags_of(t, o, fhsm_token_object_get_flags2);
                if f2 & OBJF2_HAS_ALLOWED_MECH == 0 {
                    a.len = UNAVAILABLE;
                    continue;
                }
                let mut m = [0u32; POLICY_MECH_MAX];
                let mut cnt = POLICY_MECH_MAX as u8;
                // SAFETY: as above; m has cnt slots
                if unsafe { fhsm_token_object_get_allowed_mechs(t, o, m.as_mut_ptr(), &mut cnt) }
                    != OK
                {
                    a.len = UNAVAILABLE;
                    continue;
                }
                // Widened to CK_MECHANISM_TYPE, the caller's element type.
                let w = size_of::<c_ulong>();
                for (k, &mech) in m.iter().take(cnt as usize).enumerate() {
                    mechs[k * w..(k + 1) * w].copy_from_slice(&ulong(mech.into()));
                }
                &mechs[..cnt as usize * w]
            }
            CKA_WRAP_TEMPLATE | CKA_UNWRAP_TEMPLATE | CKA_DERIVE_TEMPLATE => {
                // SAFETY: the caller's nested array, as C filled it
                unsafe { nested(a, t, o, &mut too_small) };
                continue;
            }
            CKA_SENSITIVE | CKA_EXTRACTABLE => {
                let (_, of) = flags_of(t, o, fhsm_token_object_get_flags);
                let bit = if a.kind == CKA_SENSITIVE {
                    OBJF_SENSITIVE
                } else {
                    OBJF_EXTRACTABLE
                };
                b = [u8::from(of & bit != 0)];
                &b
            }
            CKA_MODULUS_BITS | CKA_MODULUS | CKA_PUBLIC_EXPONENT | CKA_EC_POINT | CKA_EC_PARAMS => {
                // DIV-070: through the common copy below, so a buffer too small is 0x150
                let Some(v) = pubkey_attr(t, o, (class, kt, value), a.kind) else {
                    a.len = UNAVAILABLE;
                    continue;
                };
                raw = v;
                &raw
            }
            CKA_LABEL => {
                let (mut p, mut l) = (null::<c_char>(), 0usize);
                // SAFETY: as above; the per-thread copy is read before the next lookup
                if unsafe { fhsm_token_object_get_label(t, o, &mut p, &mut l) } != OK {
                    a.len = UNAVAILABLE;
                    continue;
                }
                // SAFETY: as above
                unsafe { bytes(p.cast(), l) }
            }
            CKA_ID => {
                let (mut p, mut l) = (null::<u8>(), 0usize);
                // SAFETY: as above
                if unsafe { fhsm_token_object_get_id(t, o, &mut p, &mut l) } != OK {
                    a.len = UNAVAILABLE;
                    continue;
                }
                // SAFETY: as above
                unsafe { bytes(p, l) }
            }
            CKA_TOKEN => {
                let mut is_tok: c_int = 1;
                // SAFETY: as above
                unsafe { fhsm_token_object_is_token(t, o, &mut is_tok) };
                b = [u8::from(is_tok != 0)];
                &b
            }
            CKA_PRIVATE => {
                b = [u8::from(
                    class != CKO_PUBLIC_KEY && class != CKO_CERTIFICATE,
                )];
                &b
            }
            CKA_MODIFIABLE
            | CKA_DESTROYABLE
            | CKA_LOCAL
            | CKA_ALWAYS_AUTHENTICATE
            | CKA_TRUSTED
            | CKA_ALWAYS_SENSITIVE
            | CKA_NEVER_EXTRACTABLE => {
                let (_, of) = flags_of(t, o, fhsm_token_object_get_flags);
                let (_, f3) = flags_of(t, o, fhsm_token_object_get_flags3);
                let set = |bit: u8| of & bit != 0;
                b = [u8::from(match a.kind {
                    CKA_MODIFIABLE => !set(OBJF_UNMODIFIABLE),
                    CKA_DESTROYABLE => !set(OBJF_UNDESTROYABLE),
                    CKA_LOCAL => set(OBJF_LOCAL),
                    CKA_ALWAYS_AUTHENTICATE => set(OBJF_ALWAYS_AUTH),
                    CKA_TRUSTED => set(OBJF_TRUSTED),
                    CKA_ALWAYS_SENSITIVE => {
                        set(OBJF_SENSITIVE) && f3 & OBJF3_WAS_NOT_SENSITIVE == 0
                    }
                    // CKA_NEVER_EXTRACTABLE
                    _ => !set(OBJF_EXTRACTABLE) && f3 & OBJF3_WAS_EXTRACTABLE == 0,
                })];
                &b
            }
            CKA_COPYABLE | CKA_WRAP_WITH_TRUSTED => {
                let (_, f2) = flags_of(t, o, fhsm_token_object_get_flags2);
                b = [u8::from(if a.kind == CKA_COPYABLE {
                    f2 & OBJF2_NOT_COPYABLE == 0
                } else {
                    f2 & OBJF2_WRAP_WITH_TRUSTED != 0
                })];
                &b
            }
            CKA_ENCRYPT | CKA_VERIFY | CKA_WRAP | CKA_DECRYPT | CKA_SIGN | CKA_UNWRAP
            | CKA_DERIVE => {
                let (bit, dflt) = usage_of(a.kind, class).expect("a usage attribute");
                b = [usage_bool(t, o, bit, dflt)];
                &b
            }
            CKA_SIGN_RECOVER | CKA_VERIFY_RECOVER => {
                b = [0];
                &b
            }
            CKA_START_DATE | CKA_END_DATE | CKA_APPLICATION => {
                let which = match a.kind {
                    CKA_START_DATE => META_START_DATE,
                    CKA_END_DATE => META_END_DATE,
                    _ => META_APPLICATION,
                };
                let (mut p, mut l) = (null::<u8>(), 0usize);
                // SAFETY: as above; empty when unset
                if unsafe { fhsm_token_object_get_meta(t, o, which, &mut p, &mut l) } == OK {
                    // SAFETY: as above
                    unsafe { bytes(p, l) }
                } else {
                    &[]
                }
            }
            CKA_SUBJECT | CKA_ISSUER | CKA_SERIAL_NUMBER => {
                let f = match a.kind {
                    CKA_SUBJECT => CertField::Subject,
                    CKA_ISSUER => CertField::Issuer,
                    _ => CertField::Serial,
                };
                // DIV-070: as above
                let Some(v) = (class == CKO_CERTIFICATE)
                    .then(|| cert_field(value, f))
                    .flatten()
                else {
                    a.len = UNAVAILABLE;
                    continue;
                };
                raw = v;
                &raw
            }
            _ => {
                a.len = UNAVAILABLE;
                type_invalid = true;
                continue;
            }
        };
        if a.value.is_null() {
            a.len = src.len() as c_ulong;
        } else if (a.len as usize) < src.len() {
            a.len = UNAVAILABLE;
            too_small = true;
        } else {
            // SAFETY: the caller's buffer, at least src.len() bytes
            unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), a.value, src.len()) };
            a.len = src.len() as c_ulong;
        }
    }
    // When several apply PKCS#11 lets any one be returned; C's order.
    if too_small {
        BUFFER_TOO_SMALL.into()
    } else if sensitive {
        ATTRIBUTE_SENSITIVE.into()
    } else if type_invalid {
        ATTRIBUTE_TYPE_INVALID.into()
    } else {
        OK.into()
    }
}

/// A nested template: the caller owns both levels; the module fills the inner buffers and
/// the lengths, and never touches a pointer.
///
/// # Safety
/// `a.value` is NULL or the caller's array of `a.len` bytes of attributes, each pointing to
/// its own buffer of its length.
unsafe fn nested(a: &mut Attr, t: *mut fhsm_token_t, o: u32, too_small: &mut bool) {
    let (which, bit) = match a.kind {
        CKA_WRAP_TEMPLATE => (0, OBJF2_HAS_WRAP_TMPL),
        CKA_UNWRAP_TEMPLATE => (1, OBJF2_HAS_UNWRAP_TMPL),
        _ => (2, OBJF2_HAS_DERIVE_TMPL),
    };
    let (_, f2) = flags_of(t, o, fhsm_token_object_get_flags2);
    if f2 & bit == 0 {
        a.len = UNAVAILABLE;
        return;
    }
    let mut ent = [PolicyAttr {
        kind_: 0,
        kind: 0,
        len: 0,
        value: [0; 48],
    }; POLICY_ATTR_MAX];
    let mut cnt = POLICY_ATTR_MAX as u8;
    // SAFETY: a token the registry holds; ent has cnt slots
    if unsafe { fhsm_token_object_get_tmpl(t, o, which, ent.as_mut_ptr(), &mut cnt) } != OK {
        a.len = UNAVAILABLE;
        return;
    }
    let need = cnt as usize * size_of::<Attr>();
    if a.value.is_null() {
        a.len = need as c_ulong;
        return;
    }
    if (a.len as usize) < need {
        a.len = UNAVAILABLE;
        *too_small = true;
        return;
    }
    // SAFETY: the caller's array, at least cnt attributes (need bytes)
    let nest = unsafe { std::slice::from_raw_parts_mut(a.value.cast::<Attr>(), cnt as usize) };
    for (d, e) in nest.iter_mut().zip(&ent) {
        d.kind = e.kind_.into();
        let l = e.len as usize;
        if d.value.is_null() {
            d.len = l as c_ulong;
        } else if (d.len as usize) < l {
            // Only this entry is short; the others are still answered.
            d.len = UNAVAILABLE;
        } else {
            // SAFETY: the caller's buffer of at least l bytes
            unsafe { std::ptr::copy_nonoverlapping(e.value.as_ptr(), d.value, l) };
            d.len = l as c_ulong;
        }
    }
    a.len = need as c_ulong;
}

/// `fhsm_date_wellformed`: empty, or eight digits with a month and day in range.
pub(super) fn date_ok(d: &[u8]) -> bool {
    if d.is_empty() {
        return true;
    }
    if d.len() != 8 || !d.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let two = |i: usize| (d[i] - b'0') * 10 + (d[i + 1] - b'0');
    (1..=12).contains(&two(4)) && (1..=31).contains(&two(6))
}

/// One CK_BBOOL row of a set template: 0x13 when it is not one byte.
fn want_bool(a: &Attr) -> Result<bool, u32> {
    if a.len != 1 || a.value.is_null() {
        return Err(ATTRIBUTE_VALUE_INVALID);
    }
    // SAFETY: one byte, non-NULL
    Ok(unsafe { *a.value } != 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_SetAttributeValue(
    h: c_ulong,
    o: c_ulong,
    tmpl: *mut Attr,
    n: c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if tmpl.is_null() || n == 0 {
        return ARGUMENTS_BAD.into();
    }
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    if TABLE.role(h) == ROLE_NONE {
        return USER_NOT_LOGGED_IN.into();
    }
    // SAFETY: the caller's n attributes
    let tmpl = match unsafe { check_template(tmpl, n) } {
        Ok(t) => t,
        Err(rv) => return rv.into(),
    };
    // DIV-050: a private object is not there for anyone but the user (C let the SO relabel the
    // user's keys). First, so a read-only session's 0xB5 does not show that it exists.
    if class_of(tok, o as u32).is_ok_and(|c| access_denied(tok, c)) {
        return OBJECT_HANDLE_INVALID.into();
    }
    // SAFETY: as above
    unsafe { set(h, tok.0.as_ptr(), o as u32, tmpl) }.into()
}

/// The body of `C_SetAttributeValue` after its argument checks: validate every row, then
/// apply, so a rejected row leaves nothing half-written.
///
/// # Safety
/// `t` is a token the registry holds; each row's value is NULL or its length in bytes.
unsafe fn set(h: c_ulong, t: *mut fhsm_token_t, o: u32, tmpl: &[Attr]) -> u32 {
    // A read-only session may not modify a token object.
    let mut is_tok: c_int = 0;
    // SAFETY: the caller's token; an out pointer of our own
    if unsafe { fhsm_token_object_is_token(t, o, &mut is_tok) } == OK
        && is_tok != 0
        && TABLE
            .info(h)
            .is_ok_and(|(_, flags, _)| flags & CKF_RW_SESSION == 0)
    {
        return SESSION_READ_ONLY;
    }
    // fhsm_check_trusted_attr: only the SO may set CKA_TRUSTED to TRUE (the first such row).
    if let Some(a) = tmpl.iter().find(|a| a.kind == CKA_TRUSTED)
        && want_bool(a) == Ok(true)
        && TABLE.role(h) != ROLE_SO
    {
        return ATTRIBUTE_READ_ONLY;
    }
    let (rv, flags_now) = flags_of(t, o, fhsm_token_object_get_flags);
    if rv != OK {
        return lookup_rv(rv);
    }
    if flags_now & OBJF_UNMODIFIABLE != 0 {
        return ACTION_PROHIBITED;
    }
    let (_, f2_now) = flags_of(t, o, fhsm_token_object_get_flags2);
    let (mut flags, mut f2) = (flags_now, f2_now);
    let (mut vp, mut vl, mut class, mut kt) = (null(), 0usize, 0u32, 0u32);
    // SAFETY: as above; a failure leaves class 0, as C's
    unsafe { fhsm_token_object_get(t, o, &mut vp, &mut vl, &mut class, &mut kt) };

    // Pass 1 writes nothing; the one-way rules see earlier rows' intent.
    for a in tmpl {
        // SAFETY: a row's value is NULL only with length 0 (check_template)
        let v = unsafe { bytes(a.value, a.len as usize) };
        match a.kind {
            CKA_LABEL => {}
            CKA_ID if a.len > 32 => return ATTRIBUTE_VALUE_INVALID,
            CKA_ID => {}
            // SENSITIVE only on, EXTRACTABLE and COPYABLE only off, WRAP_WITH_TRUSTED only on.
            CKA_SENSITIVE | CKA_EXTRACTABLE | CKA_WRAP_WITH_TRUSTED | CKA_COPYABLE => {
                let want = match want_bool(a) {
                    Ok(w) => w,
                    Err(e) => return e,
                };
                // (byte, bit, whether the set bit means TRUE, the one value it may move to)
                let (byte, bit, set_is_true, may_become) = match a.kind {
                    CKA_SENSITIVE => (&mut flags, OBJF_SENSITIVE, true, true),
                    CKA_EXTRACTABLE => (&mut flags, OBJF_EXTRACTABLE, true, false),
                    CKA_WRAP_WITH_TRUSTED => (&mut f2, OBJF2_WRAP_WITH_TRUSTED, true, true),
                    _ => (&mut f2, OBJF2_NOT_COPYABLE, false, false),
                };
                let is_now = (*byte & bit != 0) == set_is_true;
                if want == is_now {
                    continue;
                }
                if want != may_become {
                    return ATTRIBUTE_READ_ONLY;
                }
                if want == set_is_true {
                    *byte |= bit;
                } else {
                    *byte &= !bit;
                }
            }
            CKA_START_DATE | CKA_END_DATE => {
                if class == CKO_DATA {
                    return ATTRIBUTE_TYPE_INVALID;
                }
                if !date_ok(v) {
                    return ATTRIBUTE_VALUE_INVALID;
                }
            }
            CKA_APPLICATION => {
                if class != CKO_DATA {
                    return ATTRIBUTE_TYPE_INVALID;
                }
                if a.len > 64 {
                    return ATTRIBUTE_VALUE_INVALID;
                }
            }
            CKA_CLASS
            | CKA_KEY_TYPE
            | CKA_VALUE
            | CKA_TOKEN
            | CKA_PRIVATE
            | CKA_LOCAL
            | CKA_ALWAYS_SENSITIVE
            | CKA_NEVER_EXTRACTABLE
            | CKA_MODIFIABLE
            | CKA_DESTROYABLE
            | CKA_ALWAYS_AUTHENTICATE => return ATTRIBUTE_READ_ONLY,
            _ => return ATTRIBUTE_TYPE_INVALID,
        }
    }

    // Pass 2. A storage error here is the one partial write left, as in C. A NULL pointer
    // leaves a meta field as it is, so an empty value is passed as EMPTY.
    static EMPTY: [u8; 1] = [0];
    let mut meta = [(null::<u8>(), 0usize); 3];
    for a in tmpl {
        let row = || {
            let p = if a.len != 0 {
                a.value.cast_const()
            } else {
                EMPTY.as_ptr()
            };
            (p, a.len as usize)
        };
        let r = match a.kind {
            CKA_START_DATE => {
                meta[0] = row();
                OK
            }
            CKA_END_DATE => {
                meta[1] = row();
                OK
            }
            CKA_APPLICATION => {
                meta[2] = row();
                OK
            }
            CKA_LABEL => {
                let mut buf = [0u8; 64];
                let l = (a.len as usize).min(63);
                // SAFETY: a.len bytes, at least l
                buf[..l].copy_from_slice(unsafe { bytes(a.value, l) });
                // SAFETY: as above; buf is NUL-terminated
                unsafe { fhsm_token_object_set_label(t, o, buf.as_ptr().cast()) }
            }
            // SAFETY: as above
            CKA_ID => unsafe { fhsm_token_object_set_id(t, o, a.value, a.len as usize) },
            _ => OK,
        };
        if r != OK {
            return r;
        }
    }
    let was = history(flags_now, flags);
    if was != 0 {
        // Before the flags, so a failed write cannot leave the key looking always sensitive.
        let (_, f3) = flags_of(t, o, fhsm_token_object_get_flags3);
        // SAFETY: as above
        let r = unsafe { fhsm_token_object_set_flags3(t, o, f3 | was) };
        if r != OK {
            return r;
        }
    }
    if flags != flags_now {
        // SAFETY: as above
        let r = unsafe { fhsm_token_object_set_flags(t, o, flags) };
        if r != OK {
            return r;
        }
    }
    if f2 != f2_now {
        // SAFETY: as above
        let r = unsafe { fhsm_token_object_set_flags2(t, o, f2) };
        if r != OK {
            return r;
        }
    }
    if meta.iter().any(|m| !m.0.is_null()) {
        let [(s, sl), (e, el), (p, pl)] = meta;
        // SAFETY: as above
        return unsafe { fhsm_token_object_set_meta(t, o, s, sl, e, el, p, pl) };
    }
    OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octet_strings_take_the_long_form_past_127() {
        let os = |n: usize| octet_string(&vec![0xAB; n]);
        assert_eq!(os(127)[..2], [0x04, 0x7F]);
        assert_eq!(os(128)[..3], [0x04, 0x81, 0x80]);
        assert_eq!(os(255)[..3], [0x04, 0x81, 0xFF]);
        assert_eq!(os(128).len(), 131);
    }

    #[test]
    fn dates_are_shape_checked_as_c_s() {
        assert!(date_ok(b""));
        assert!(date_ok(b"20260231"));
        assert!(!date_ok(b"20261301"));
        assert!(!date_ok(b"20260100"));
        assert!(!date_ok(b"2026010"));
        assert!(!date_ok(b"2026a101"));
    }

    #[test]
    fn history_records_only_the_one_way_moves() {
        let (s, x) = (OBJF_SENSITIVE, OBJF_EXTRACTABLE);
        assert_eq!(history(0, s), OBJF3_WAS_NOT_SENSITIVE);
        assert_eq!(history(x, 0), OBJF3_WAS_EXTRACTABLE);
        assert_eq!(
            history(x, s),
            OBJF3_WAS_NOT_SENSITIVE | OBJF3_WAS_EXTRACTABLE
        );
        assert_eq!(history(s, s), 0);
        assert_eq!(history(0, 0), 0);
        assert_eq!(history(s | x, s | x), 0);
    }

    #[test]
    fn policy_attr_is_c_s_layout() {
        assert_eq!(size_of::<PolicyAttr>(), 56);
        assert_eq!(std::mem::offset_of!(PolicyAttr, value), 6);
    }
}
