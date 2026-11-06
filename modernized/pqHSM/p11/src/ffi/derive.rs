//! Phase 4 slice 6d: `C_DeriveKey` (`src/fhsm_pkcs11.c:4277-4878`) in C's order: HKDF, the
//! concatenation family, ECDH, each secret stored by `store` (`derive_store_secret`).
//!
//! Divergences: DIV-050 (the base key is the user's alone), DIV-057 (a derived key is
//! sensitive if a secret input is, with that input's history; a data object only from
//! CKM_HKDF_DATA), DIV-068 (a derived key is of a secret key type, at its size), DIV-001 (a key
//! whose record cannot be made is not kept).

use std::ffi::{c_int, c_ulong};
use std::ptr::null;

use pqhsm_core::session::ROLE_NONE;
use pqhsm_crypto::cipher::Pkey;
use pqhsm_crypto::import::Param;
use pqhsm_crypto::keygen::ecm_available;
use pqhsm_crypto::prim::{
    HKDF_EXPAND_ONLY, HKDF_EXTRACT_AND_EXPAND, HKDF_EXTRACT_ONLY, hash_name, hash_size, hkdf,
};

use super::apilock::Held;
use super::attrs::{
    CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_SENSITIVE, CKA_VALUE, CKA_VALUE_LEN, OBJF_EXTRACTABLE,
    OBJF_SENSITIVE, OBJF2_HAS_DERIVE_TMPL, OBJF3_WAS_EXTRACTABLE, OBJF3_WAS_NOT_SENSITIVE,
    USAGE_DERIVE, fhsm_token_object_get_flags3, mark,
};
use super::copy::{
    BOOL_ATTRS, ULONG_ATTRS, apply_allowed_mechs, apply_nested_all, apply_obj_meta, bbool, bytes,
    check_ro_token, check_trusted, fhsm_token_object_add, fhsm_token_object_set_usage, find,
};
use super::crypt::{Secret, object, strict};
use super::digest::{Mech, hash_of};
use super::keygen::{
    TEMPLATE_INCOMPLETE, TEMPLATE_INCONSISTENT, apply_token_scope, check_lengths, compute_usage,
    ulong,
};
use super::objects::{
    Attr, CKA_CLASS, CKA_LABEL, CKO_PRIVATE_KEY, CKO_SECRET_KEY, access_denied, check_template,
    class_of, gate,
};
use super::session::{TABLE, Tok, fhsm_session_role};
use super::sys::*;
use super::wrap::{SECRET_TYPES, check_nested, ok, size_ok, usage};

const KEY_SIZE_RANGE: u32 = 0x62;
const KEY_TYPE_INCONSISTENT: u32 = 0x63;
const MECHANISM_INVALID: u32 = 0x70;
const MECHANISM_PARAM_INVALID: u32 = 0x71;

const HKDF_DERIVE: c_ulong = 0x402A;
const HKDF_DATA: c_ulong = 0x402B;
const BASE_AND_KEY: c_ulong = 0x360;
const BASE_AND_DATA: c_ulong = 0x362;
const DATA_AND_BASE: c_ulong = 0x363;
const XOR_BASE_AND_DATA: c_ulong = 0x364;
const ECDH1: c_ulong = 0x1050;
const ECDH1_COFACTOR: c_ulong = 0x1051;
const MD5: c_ulong = 0x210;
const CKD_NULL: c_ulong = 1;
const SALT_NULL: c_ulong = 1;
const SALT_DATA: c_ulong = 2;
const SALT_KEY: c_ulong = 4;

const CKO_DATA: c_ulong = 0;
const CKK_GENERIC_SECRET: u32 = 0x10;
const CKK_EC: u32 = 3;
const CKK_EC_MONTGOMERY: u32 = 0x41;
/// `fhsm_tmpl_which_t`'s derive template.
const TMPL_DERIVE: c_int = 2;
/// `FHSM_DERIVE_MAX`: the concatenation family's largest output.
const DERIVE_MAX: usize = 4096;
/// `FHSM_ECDH_Z_MAX`: the largest field of a supported curve.
const ECDH_Z_MAX: usize = 128;
/// C's 2 GiB guard on a caller's length.
const LEN_MAX: c_ulong = 0x7FFF_FFFF;
const EV_DERIVE: c_int = 46;

/// `CK_HKDF_PARAMS`.
#[repr(C)]
#[derive(Clone, Copy)]
struct HkdfParams {
    extract: u8,
    expand: u8,
    prf: c_ulong,
    salt_type: c_ulong,
    salt: *const u8,
    salt_len: c_ulong,
    salt_key: c_ulong,
    info: *const u8,
    info_len: c_ulong,
}

/// `CK_KEY_DERIVATION_STRING_DATA`.
#[repr(C)]
#[derive(Clone, Copy)]
struct StringData {
    data: *const u8,
    len: c_ulong,
}

/// `CK_ECDH1_DERIVE_PARAMS`.
#[repr(C)]
#[derive(Clone, Copy)]
struct EcdhParams {
    kdf: c_ulong,
    shared_len: c_ulong,
    shared: *const u8,
    public_len: c_ulong,
    public: *const u8,
}

/// The mechanism's parameter block as a `T`, or `bad` if it is NULL or short.
///
/// # Safety
/// `m.param` readable for `m.param_len` bytes, or NULL.
unsafe fn param<T: Copy>(m: &Mech, bad: u32) -> Result<T, u32> {
    if m.param.is_null() || (m.param_len as usize) < size_of::<T>() {
        return Err(bad);
    }
    // SAFETY: at least size_of::<T>() bytes (checked); C memcpy'd or cast them
    Ok(unsafe { m.param.cast::<T>().read_unaligned() })
}

/// A caller's buffer under C's two guards: at most 2 GiB, and NULL only when empty.
///
/// # Safety
/// `p` readable for `n` bytes, or NULL.
unsafe fn guarded<'a>(p: *const u8, n: c_ulong) -> Result<&'a [u8], u32> {
    if n > LEN_MAX || (p.is_null() && n != 0) {
        return Err(MECHANISM_PARAM_INVALID);
    }
    // SAFETY: the caller's
    Ok(unsafe { super::digest::bytes(p, n as usize) })
}

/// A secret key (C's `fhsm_token_object_get` and class check).
fn secret<'a>(tok: Tok, k: u32) -> Result<&'a [u8], u32> {
    let (v, class, _) = object(tok, k)?;
    if class != CKO_SECRET_KEY {
        return Err(KEY_TYPE_INCONSISTENT);
    }
    Ok(v)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_DeriveKey(
    h: c_ulong,
    m: *const Mech,
    base: c_ulong,
    tmpl: *const Attr,
    n: c_ulong,
    out: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if m.is_null() || out.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // C's narrowing: the token's handles are 32-bit.
    // SAFETY: non-NULL, and by the caller's contract a CK_MECHANISM, a template of n
    // attributes and a writable handle
    unsafe { derive(h, &*m, base as u32, tmpl, n, out) }
        .unwrap_or_else(|rv| rv)
        .into()
}

/// # Safety
/// As `pqhsm_C_DeriveKey`'s arguments.
unsafe fn derive(
    h: c_ulong,
    m: &Mech,
    base: u32,
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
        // DIV-050: the base is the user's alone (C let the SO derive from it).
        if class_of(tok, base).is_ok_and(|c| access_denied(tok, c)) {
            return Err(KEY_HANDLE_INVALID);
        }
        // SAFETY: a token the registry holds
        ok(unsafe { fhsm_token_object_mech_allowed(tp, base, m.mechanism as u32) })?;
        check_nested(tp, base, TMPL_DERIVE, OBJF2_HAS_DERIVE_TMPL, t)?;
        usage(tp, base, USAGE_DERIVE)?;
    }
    let tok = TABLE.token(h).ok_or(SESSION_HANDLE_INVALID)?;
    if fhsm_session_role(h) == ROLE_NONE {
        return Err(USER_NOT_LOGGED_IN);
    }
    let s = Store {
        tok,
        h,
        mech: m.mechanism,
        event: Some(EV_DERIVE),
        t,
        out,
    };
    match m.mechanism {
        // SAFETY: the caller's parameter
        HKDF_DERIVE | HKDF_DATA => unsafe { derive_hkdf(&s, m, base) },
        // SAFETY: as above
        BASE_AND_KEY | BASE_AND_DATA | DATA_AND_BASE | XOR_BASE_AND_DATA => unsafe {
            derive_concat(&s, m, base)
        },
        // SAFETY: as above
        _ => unsafe { derive_ecdh(&s, m, base) },
    }
}

/// HKDF (RFC 5869, PKCS#11 §6.32; `:4323-4497`).
///
/// # Safety
/// `m`'s parameter the caller's.
unsafe fn derive_hkdf(s: &Store, m: &Mech, base: u32) -> Result<u32, u32> {
    // SAFETY: the caller's
    let p: HkdfParams = unsafe { param(m, MECHANISM_PARAM_INVALID) }?;
    if p.extract == 0 && p.expand == 0 {
        return Err(MECHANISM_PARAM_INVALID);
    }
    let (alg, _) = hash_of(p.prf).ok_or(MECHANISM_PARAM_INVALID)?;
    // The PRF is HMAC: of the digests C knows, only MD5's HMAC is withdrawn by the strict build.
    if p.prf == MD5 && strict() {
        return Err(MECHANISM_PARAM_INVALID);
    }
    let ikm = secret(s.tok, base)?;
    let salt = match p.salt_type {
        SALT_NULL => &[][..],
        // SAFETY: the caller's salt
        SALT_DATA => unsafe { guarded(p.salt, p.salt_len) }?,
        SALT_KEY => {
            let v = secret(s.tok, p.salt_key as u32)?;
            // The salt key is read, so it must permit derivation.
            usage(s.tok.0.as_ptr(), p.salt_key as u32, USAGE_DERIVE)?;
            v
        }
        _ => return Err(MECHANISM_PARAM_INVALID),
    };
    // SAFETY: the caller's info
    let info = unsafe { guarded(p.info, p.info_len) }?;
    let hs = hash_size(alg);
    let want = if p.extract != 0 && p.expand == 0 {
        hs
    } else {
        match ulong(s.t, CKA_VALUE_LEN) {
            None => hs,
            Some(None) => return Err(TEMPLATE_INCOMPLETE),
            Some(Some(l)) => l as usize,
        }
    };
    let max = if p.expand != 0 { 255 * hs } else { hs };
    if want == 0 || want > max {
        return Err(ATTRIBUTE_VALUE_INVALID);
    }
    let mode = match (p.extract != 0, p.expand != 0) {
        (true, true) => HKDF_EXTRACT_AND_EXPAND,
        (true, false) => HKDF_EXTRACT_ONLY,
        _ => HKDF_EXPAND_ONLY,
    };
    let mut okm = Secret::zeroed(want)?;
    hkdf(
        mode,
        hash_name(alg).ok_or(MECHANISM_PARAM_INVALID)?,
        ikm,
        salt,
        info,
        &mut okm.0,
    )?;
    let class = if m.mechanism == HKDF_DATA {
        CKO_DATA
    } else {
        CKO_SECRET_KEY as c_ulong
    };
    s.store(&okm.0, class, &[base])
}

/// The concatenation family (PKCS#11 §6.20; `:4504-4588`).
///
/// # Safety
/// `m`'s parameter the caller's.
unsafe fn derive_concat(s: &Store, m: &Mech, base: u32) -> Result<u32, u32> {
    let (bv, bcl, bkt) = object(s.tok, base)?;
    if bcl != CKO_SECRET_KEY {
        return Err(KEY_TYPE_INCONSISTENT);
    }
    // `fhsm_check_key_mech_type`: a combiner's base is a generic secret.
    if bkt != CKK_GENERIC_SECRET {
        return Err(KEY_TYPE_INCONSISTENT);
    }
    let (ov, second) = if m.mechanism == BASE_AND_KEY {
        // SAFETY: the caller's
        let k2 = unsafe { param::<c_ulong>(m, MECHANISM_PARAM_INVALID) }? as u32;
        let v = secret(s.tok, k2)?;
        // The second key must itself permit derivation.
        usage(s.tok.0.as_ptr(), k2, USAGE_DERIVE)?;
        (v, Some(k2))
    } else {
        // SAFETY: as above
        let sd: StringData = unsafe { param(m, MECHANISM_PARAM_INVALID) }?;
        // SAFETY: the caller's data
        (unsafe { guarded(sd.data, sd.len) }?, None)
    };
    let need = if m.mechanism == XOR_BASE_AND_DATA {
        ov.len()
    } else {
        bv.len() + ov.len()
    };
    if need == 0 || need > DERIVE_MAX {
        return Err(MECHANISM_PARAM_INVALID);
    }
    let mut buf = Secret::zeroed(need)?;
    match m.mechanism {
        DATA_AND_BASE => {
            buf.0[..ov.len()].copy_from_slice(ov);
            buf.0[ov.len()..].copy_from_slice(bv);
        }
        // §6.20.4: the data sets the length; past the base's end the data passes through.
        XOR_BASE_AND_DATA => {
            for (i, b) in buf.0.iter_mut().enumerate() {
                *b = bv.get(i).copied().unwrap_or(0) ^ ov[i];
            }
        }
        _ => {
            buf.0[..bv.len()].copy_from_slice(bv);
            buf.0[bv.len()..].copy_from_slice(ov);
        }
    }
    // DIV-057: the second key is a secret input too (§6.20.1).
    match second {
        Some(k2) => s.store(&buf.0, CKO_SECRET_KEY as c_ulong, &[base, k2]),
        None => s.store(&buf.0, CKO_SECRET_KEY as c_ulong, &[base]),
    }
}

/// ECDH, and Montgomery agreement under the same mechanism (`:4594-4772`).
///
/// # Safety
/// `m`'s parameter the caller's.
unsafe fn derive_ecdh(s: &Store, m: &Mech, base: u32) -> Result<u32, u32> {
    if m.mechanism != ECDH1 && m.mechanism != ECDH1_COFACTOR {
        return Err(MECHANISM_INVALID);
    }
    // SAFETY: the caller's
    let p: EcdhParams = unsafe { param(m, ARGUMENTS_BAD) }?;
    if p.kdf != CKD_NULL || p.public.is_null() || p.public_len == 0 {
        return Err(ARGUMENTS_BAD);
    }
    let (kv, cl, kt) = object(s.tok, base)?;
    if cl != CKO_PRIVATE_KEY {
        return Err(KEY_TYPE_INCONSISTENT);
    }
    // Which agreement this is comes from the key, not the mechanism.
    let ecm = kt == CKK_EC_MONTGOMERY;
    if ecm && (strict() || !ecm_available()) {
        return Err(MECHANISM_INVALID);
    }
    if !ecm && kt != CKK_EC {
        return Err(KEY_TYPE_INCONSISTENT);
    }
    let pk = Pkey::private(kv).ok_or(FUNCTION_FAILED)?;
    // SAFETY: the caller's point of public_len bytes, non-NULL (checked). shortcut: a length
    // past isize::MAX breaks from_raw_parts' contract (C read what d2i asked for); only a
    // caller lying about its buffer reaches it.
    let pd = unsafe { super::digest::bytes(p.public, p.public_len as usize) };
    let peer = if ecm {
        // RFC 7748: 32 bytes for X25519, 56 for X448.
        let (alg, want) = if pk.is_a(c"X25519") {
            (c"X25519", 32)
        } else if pk.is_a(c"X448") {
            (c"X448", 56)
        } else {
            return Err(KEY_TYPE_INCONSISTENT);
        };
        if pd.len() != want {
            return Err(ATTRIBUTE_VALUE_INVALID);
        }
        Pkey::raw_public(alg, pd).ok_or(ATTRIBUTE_VALUE_INVALID)?
    } else {
        match Pkey::public(pd) {
            Some(k) => k,
            None => peer_point(&pk, pd)?,
        }
    };
    // The peer's point must be on the curve (invalid-curve attacks).
    if !peer.check(false) {
        return Err(ATTRIBUTE_VALUE_INVALID);
    }
    let mut z = Secret::zeroed(ECDH_Z_MAX)?;
    let zl = pk.derive(&peer, &mut z.0).ok_or(FUNCTION_FAILED)?;
    s.store(&z.0[..zl], CKO_SECRET_KEY as c_ulong, &[base])
}

/// A peer point that is not an SPKI (`:4667-4714`): bare, or in a DER OCTET STRING, told
/// apart by the base curve's field size; ATTRIBUTE_VALUE_INVALID if it will not import.
fn peer_point(pk: &Pkey, raw: &[u8]) -> Result<Pkey, u32> {
    let bits = pk.bits();
    let fb = if bits > 0 {
        (bits as usize).div_ceil(8)
    } else {
        0
    };
    let n = raw.len();
    let bare = fb != 0 && (n == 1 + 2 * fb || n == 1 + fb);
    let point = |l: usize| l == 1 + 2 * fb || l == 1 + fb;
    let raw =
        if !bare && n > 2 && raw[0] == 0x04 && raw[1] as usize + 2 == n && point(raw[1] as usize) {
            &raw[2..]
        } else if !bare && n > 3 && raw[0] == 0x04 && raw[1] == 0x81 && raw[2] as usize + 3 == n {
            &raw[3..]
        } else {
            raw
        };
    let group = pk.group();
    Pkey::from_data(
        c"EC",
        false,
        &[Param::Utf8(c"group", &group), Param::Octets(c"pub", raw)],
    )
    .ok_or(ATTRIBUTE_VALUE_INVALID)
}

/// What `derive_store_secret` needs besides the secret; `event` its audit record, if any (the
/// KEM entry points have none, DIV-069).
pub(super) struct Store<'a> {
    pub(super) tok: Tok,
    pub(super) h: c_ulong,
    pub(super) mech: c_ulong,
    pub(super) t: &'a [Attr],
    pub(super) out: *mut c_ulong,
    pub(super) event: Option<c_int>,
}

impl Store<'_> {
    /// `derive_store_secret` (`:4789-4878`): the secret as a new object of `class` (unless the
    /// template names one), its secret inputs `bases`.
    pub(super) fn store(&self, secret: &[u8], class: c_ulong, bases: &[u32]) -> Result<u32, u32> {
        let (t, tp) = (self.t, self.tok.0.as_ptr());
        // The value comes from the derivation, never the template.
        if find(t, CKA_VALUE).is_some() {
            return Err(TEMPLATE_INCONSISTENT);
        }
        let mut class = class;
        if let Some(Some(c)) = ulong(t, CKA_CLASS) {
            if c != CKO_SECRET_KEY as c_ulong && c != CKO_DATA {
                return Err(TEMPLATE_INCONSISTENT);
            }
            // DIV-057: a data object, readable by anyone, only from CKM_HKDF_DATA.
            if c == CKO_DATA && self.mech != HKDF_DATA {
                return Err(TEMPLATE_INCONSISTENT);
            }
            class = c;
        }
        let mut label = [0u8; 64];
        if let Some(a) = find(t, CKA_LABEL) {
            let b = bytes(a);
            let l = b.len().min(63);
            label[..l].copy_from_slice(&b[..l]);
        }
        // DIV-057: the inputs' sensitivity and history (C: the template's alone). An unreadable
        // input fails the derive rather than read as neither sensitive nor ever extractable.
        let (mut sens, mut always, mut never, mut unext) = (false, true, true, false);
        for &b in bases {
            let (mut f, mut f3) = (0u8, 0u8);
            // SAFETY: a token the registry holds; out bytes of our own
            ok(unsafe { fhsm_token_object_get_flags(tp, b, &mut f) })?;
            // SAFETY: as above
            ok(unsafe { fhsm_token_object_get_flags3(tp, b, &mut f3) })?;
            sens |= f & OBJF_SENSITIVE != 0;
            always &= f & OBJF_SENSITIVE != 0 && f3 & OBJF3_WAS_NOT_SENSITIVE == 0;
            never &= f & OBJF_EXTRACTABLE == 0 && f3 & OBJF3_WAS_EXTRACTABLE == 0;
            unext |= f & OBJF_EXTRACTABLE == 0;
        }
        let key = class == CKO_SECRET_KEY as c_ulong;
        let mut flags = 0u8;
        match bbool(t, CKA_SENSITIVE) {
            Some(false) if key && sens => return Err(TEMPLATE_INCONSISTENT),
            Some(true) => flags |= OBJF_SENSITIVE,
            _ if key && sens => flags |= OBJF_SENSITIVE,
            _ => {}
        }
        // DIV-057 (§6.20): a combiner's output holds its inputs' bytes, so it is extractable only
        // if every input is (C: whatever the template said, so a copy of any key could leave).
        let combiner = matches!(
            self.mech,
            BASE_AND_KEY | BASE_AND_DATA | DATA_AND_BASE | XOR_BASE_AND_DATA
        );
        match bbool(t, CKA_EXTRACTABLE) {
            Some(true) if key && combiner && unext => return Err(TEMPLATE_INCONSISTENT),
            Some(true) => flags |= OBJF_EXTRACTABLE,
            _ => {}
        }
        // DIV-068: a key is of a secret key type, compared whole, at its size (C: any type,
        // narrowed). A data object's type is stored as C stored it.
        let kt = match ulong(t, CKA_KEY_TYPE) {
            Some(Some(k)) if key && !SECRET_TYPES.contains(&k) => {
                return Err(ATTRIBUTE_VALUE_INVALID);
            }
            Some(Some(k)) => k as u32,
            _ => CKK_GENERIC_SECRET,
        };
        let len = secret.len();
        if key && !size_ok(kt, len) {
            return Err(KEY_SIZE_RANGE);
        }
        let mut o = 0u32;
        // SAFETY: a token the registry holds; label NUL-terminated; secret valid for len; o
        // our own
        ok(unsafe {
            fhsm_token_object_add(
                tp,
                class as u32,
                kt,
                label.as_ptr().cast(),
                secret.as_ptr(),
                len,
                null(),
                0,
                flags,
                &mut o,
            )
        })?;
        // SAFETY: writable (caller); C wrote the handle before applying the rest
        unsafe { *self.out = o as c_ulong };
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
        apply_token_scope(tp, self.h, t, o);
        step(apply_obj_meta(tp, t, o))?;
        // DIV-057, RULE-059: ALWAYS_SENSITIVE and NEVER_EXTRACTABLE only if every input's was.
        let hist = if !key {
            0
        } else {
            (if always { 0 } else { OBJF3_WAS_NOT_SENSITIVE })
                | (if never { 0 } else { OBJF3_WAS_EXTRACTABLE })
        };
        if hist != 0 {
            step(mark(tp, o, hist))?;
        }
        // SAFETY: as above (C ignores the result)
        unsafe { fhsm_token_object_set_usage(tp, o, compute_usage(class as u32, t)) };
        // DIV-001: a key whose record cannot be made is not kept.
        if let Some(ev) = self.event {
            let h = self.h;
            step(audited(
                OK,
                audit(ev, -1, h as c_int, fhsm_session_role(h), OK, &[]),
            ))?;
        }
        Ok(OK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_blocks_have_c_layout() {
        let ul = size_of::<c_ulong>();
        assert_eq!(size_of::<HkdfParams>(), 8 * ul);
        assert_eq!(std::mem::offset_of!(HkdfParams, prf), ul);
        assert_eq!(size_of::<StringData>(), 2 * ul);
        assert_eq!(size_of::<EcdhParams>(), 5 * ul);
    }

    #[test]
    fn guarded_refuses_null_with_length_and_past_2gib() {
        // SAFETY: NULL with no length, and refusals that read nothing
        unsafe {
            assert_eq!(guarded(null(), 0).map(<[u8]>::len), Ok(0));
            assert_eq!(guarded(null(), 1).err(), Some(MECHANISM_PARAM_INVALID));
            let b = [0u8; 1];
            assert_eq!(
                guarded(b.as_ptr(), LEN_MAX + 1).err(),
                Some(MECHANISM_PARAM_INVALID)
            );
        }
    }
}
