//! Phase 4 slice 6b: `C_CreateObject` (`src/fhsm_pkcs11.c:3559-4138`) in C's order: the
//! template checks, `pqhsm_core::template`'s parse, then one of three builders (stored as
//! given, a certificate, or a key OpenSSL rebuilds and re-encodes), then the template's
//! restrictions. The libcrypto calls are `pqhsm_crypto::import`'s.

use std::ffi::{CStr, c_char, c_ulong};
use std::ptr::null;

use pqhsm_core::session::ROLE_NONE;
use pqhsm_core::template::{In, Parsed, Path, Rv, parse};
use pqhsm_crypto::cipher::Pkey;
use pqhsm_crypto::import::{Param, RSA_PARAMS};
use pqhsm_crypto::keygen::{Curve, ec_curve, ecm_available};

use super::apilock::Held;
use super::attrs::{
    CKA_EXTRACTABLE, CKA_PRIVATE, CKA_SENSITIVE, CKA_TRUSTED, CKK_ML_DSA, CKK_ML_KEM,
    CKO_PUBLIC_KEY, OBJF_ALWAYS_AUTH, OBJF_EXTRACTABLE, OBJF_SENSITIVE, OBJF_TRUSTED, imported,
};
use super::copy::{
    BOOL_ATTRS, ULONG_ATTRS, apply_allowed_mechs, apply_encap_flags, apply_nested_all,
    apply_obj_meta, bbool, bytes, check_ro_token, check_trusted, fhsm_token_object_add_pending,
    fhsm_token_object_publish, fhsm_token_object_set_usage, find,
};
use super::crypt::strict;
use super::keygen::{
    CKA_ALWAYS_AUTHENTICATE, CKA_EC_PARAMS, CKA_PARAMETER_SET, CKK_EC, CKK_EC_EDWARDS,
    CKK_EC_MONTGOMERY, CKK_SLH_DSA, CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_SLH_DSA_KEY_PAIR_GEN, CURVE_NOT_SUPPORTED, ECM_CURVES, ED_CURVES, TEMPLATE_INCOMPLETE,
    TEMPLATE_INCONSISTENT, apply_ed_curve_name, apply_token_scope, check_lengths, compute_usage,
    match_curve, parse_unwrap_template, pset_read_in, ulong,
};
use super::objects::{Attr, CKA_CLASS, CKO_PRIVATE_KEY, CKO_SECRET_KEY, check_template, gate};
use super::session::TABLE;
use super::sys::*;

const CKO_CERTIFICATE: u32 = 1;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_CreateObject(
    h: c_ulong,
    tmpl: *const Attr,
    n: c_ulong,
    out: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if tmpl.is_null() || out.is_null() || n == 0 {
        return ARGUMENTS_BAD.into();
    }
    // SAFETY: the caller's template; out writable
    unsafe { create(h, tmpl, n, out) }
        .unwrap_or_else(|rv| rv)
        .into()
}

/// `fhsm_check_private_login`: a private object (by default a secret or private key) needs
/// a login.
fn check_private_login(h: c_ulong, t: &[Attr]) -> Result<(), u32> {
    let private_class = [CKO_SECRET_KEY, CKO_PRIVATE_KEY].map(c_ulong::from);
    let dflt = ulong(t, CKA_CLASS)
        .flatten()
        .is_some_and(|c| private_class.contains(&c));
    if bbool(t, CKA_PRIVATE).unwrap_or(dflt) && TABLE.role(h) == ROLE_NONE {
        return Err(USER_NOT_LOGGED_IN);
    }
    Ok(())
}

/// `fhsm_ec_curve_refusal`: CURVE_NOT_SUPPORTED for a curve, ATTRIBUTE_VALUE_INVALID for
/// anything else.
fn refusal(der: &[u8]) -> u32 {
    match ec_curve(der, true) {
        Curve::Invalid => ATTRIBUTE_VALUE_INVALID,
        _ => CURVE_NOT_SUPPORTED,
    }
}

/// The key type for comparing, whole as C compared it: one past 32 bits matches none.
/// (C read CKA_SENSITIVE and CKA_EXTRACTABLE by their first byte; `check_lengths` has made
/// them one byte, so `bbool` is the same.)
fn key_type(ckk: c_ulong) -> u32 {
    u32::try_from(ckk).unwrap_or(u32::MAX)
}

fn family(ckk: u32) -> c_ulong {
    match ckk {
        CKK_ML_KEM => CKM_ML_KEM_KEY_PAIR_GEN,
        CKK_SLH_DSA => CKM_SLH_DSA_KEY_PAIR_GEN,
        _ => CKM_ML_DSA_KEY_PAIR_GEN,
    }
}

/// `fhsm_pqc_alg_from_priv_len`: the ML-KEM or ML-DSA set whose raw private key is `len`.
fn alg_from_priv_len(len: usize, ckk: u32) -> Option<&'static CStr> {
    let t: &[(usize, &'static CStr)] = if ckk == CKK_ML_KEM {
        &[
            (1632, c"ML-KEM-512"),
            (2400, c"ML-KEM-768"),
            (3168, c"ML-KEM-1024"),
        ]
    } else {
        &[
            (2560, c"ML-DSA-44"),
            (4032, c"ML-DSA-65"),
            (4896, c"ML-DSA-87"),
        ]
    };
    t.iter().find(|(l, _)| *l == len).map(|(_, a)| *a)
}

/// `C_CreateObject` after its arguments (`:3565-4137`).
///
/// # Safety
/// `tmpl` as C_CreateObject's; `out` writable.
unsafe fn create(h: c_ulong, tmpl: *const Attr, n: c_ulong, out: *mut c_ulong) -> Result<u32, u32> {
    let Some(tok) = TABLE.token(h) else {
        return Err(SESSION_HANDLE_INVALID);
    };
    // SAFETY: the caller's
    let t = unsafe { check_template(tmpl, n) }?;
    check_ro_token(h, t)?;
    check_private_login(h, t)?;
    check_trusted(h, t)?;
    check_lengths(t, &BOOL_ATTRS, 1)?;
    check_lengths(t, &ULONG_ATTRS, size_of::<c_ulong>() as c_ulong)?;
    let mut trusted = parse_unwrap_template(t);
    if bbool(t, CKA_TRUSTED) == Some(true) {
        trusted |= OBJF_TRUSTED;
    }
    let always_auth = if bbool(t, CKA_ALWAYS_AUTHENTICATE) == Some(true) {
        OBJF_ALWAYS_AUTH
    } else {
        0
    };
    let rows: Vec<In> = t
        .iter()
        .map(|a| In {
            kind: a.kind,
            value: (!a.value.is_null()).then(|| bytes(a)),
        })
        .collect();
    let (a, prv) = parse(&rows);
    match prv {
        Rv::Ok => {}
        // An EC public key on a curve outside the parser's table.
        Rv::CurveNotInTable => {
            return Err(find(t, CKA_EC_PARAMS).map_or(TEMPLATE_INCOMPLETE, |p| refusal(bytes(p))));
        }
        Rv::TemplateIncomplete => return Err(TEMPLATE_INCOMPLETE),
        Rv::TemplateInconsistent => return Err(TEMPLATE_INCONSISTENT),
        Rv::AttributeValueInvalid => return Err(ATTRIBUTE_VALUE_INVALID),
    }
    let (cko, ckk) = (a.cko as u32, key_type(a.ckk));
    if (cko == CKO_PUBLIC_KEY || cko == CKO_PRIVATE_KEY)
        && [CKK_ML_KEM, CKK_ML_DSA, CKK_SLH_DSA].contains(&ckk)
        && find(t, CKA_PARAMETER_SET).is_none()
    {
        return Err(TEMPLATE_INCOMPLETE);
    }
    let st = Store {
        h,
        tok: tok.0.as_ptr(),
        t,
        out,
    };
    match a.path {
        Path::Verbatim => verbatim(&st, &a, trusted, always_auth),
        Path::CertX509 => {
            let flags = OBJF_EXTRACTABLE | trusted;
            let o = st.add(CKO_CERTIFICATE, a.cert_type as u32, &a, a.value, flags)?;
            st.finish(o, cko, false)
        }
        _ => {
            let (mut enc, private) = rebuild(t, &a)?;
            let mut flags = trusted;
            if private {
                flags |= OBJF_SENSITIVE | always_auth;
                if bbool(t, CKA_EXTRACTABLE) == Some(true) {
                    flags |= OBJF_EXTRACTABLE;
                }
            }
            let r = st.add(cko, ckk, &a, Some(&enc), flags);
            zeroize(&mut enc);
            st.finish(r?, cko, true)
        }
    }
}

/// What every builder stores into and applies to.
struct Store<'a> {
    h: c_ulong,
    tok: *mut fhsm_token_t,
    t: &'a [Attr],
    out: *mut c_ulong,
}

impl Store<'_> {
    fn add(
        &self,
        class: u32,
        kt: u32,
        a: &Parsed,
        v: Option<&[u8]>,
        flags: u8,
    ) -> Result<u32, u32> {
        let (vp, vl) = v.map_or((null(), 0), |v| (v.as_ptr(), v.len()));
        let (ip, il) = a.id.map_or((null(), 0), |v| (v.as_ptr(), v.len()));
        let mut o = 0u32;
        // SAFETY: a token the registry holds; each buffer valid for its length; o our own
        let rv = unsafe {
            fhsm_token_object_add_pending(
                self.tok,
                class,
                kt,
                a.label.as_ptr().cast::<c_char>(),
                vp,
                vl,
                ip,
                il,
                flags,
                &mut o,
            )
        };
        if rv == OK { Ok(o) } else { Err(rv) }
    }

    /// The handle written, then the template's restrictions and metadata, the object
    /// destroyed if one fails. A certificate takes no curve name (`ed`). DIV-066: a rebuilt key
    /// takes the encapsulation flags too (C dropped CKA_ENCAPSULATE FALSE on one). RULE-059: an
    /// imported key starts with both history bits.
    fn finish(&self, o: u32, class: u32, ed: bool) -> Result<u32, u32> {
        let (tok, t) = (self.tok, self.t);
        // SAFETY: writable (caller); C wrote the handle before applying the rest
        unsafe { *self.out = o as c_ulong };
        let step = |r: u32| {
            if r == OK {
                return Ok(());
            }
            // SAFETY: a token the registry holds
            unsafe { fhsm_token_object_destroy(tok, o) };
            Err(r)
        };
        step(apply_allowed_mechs(tok, t, o))?;
        step(apply_nested_all(tok, t, o))?;
        step(apply_encap_flags(tok, t, o, class))?;
        if ed {
            step(apply_ed_curve_name(tok, t, o))?;
        }
        apply_token_scope(tok, self.h, t, o);
        step(apply_obj_meta(tok, t, o))?;
        if class == CKO_SECRET_KEY || class == CKO_PRIVATE_KEY {
            step(imported(tok, o))?;
        }
        // SAFETY: a token the registry holds (C ignores the result)
        unsafe { fhsm_token_object_set_usage(tok, o, compute_usage(class, t)) };
        // SAFETY: as above
        step(unsafe { fhsm_token_object_publish(tok, o) })?;
        Ok(OK)
    }
}

/// The stored-as-given path (`:3663-3816`): data, secret keys and private keys, the last
/// converted to PKCS#8 where they arrive raw (EC scalar, PQC, Edwards, Montgomery).
fn verbatim(st: &Store, a: &Parsed, trusted: u8, always_auth: u8) -> Result<u32, u32> {
    let (cko, t) = (a.cko as u32, st.t);
    let mut flags = trusted;
    if cko == CKO_PRIVATE_KEY || (cko == CKO_SECRET_KEY && bbool(t, CKA_SENSITIVE) == Some(true)) {
        flags |= OBJF_SENSITIVE;
    }
    if (cko == CKO_SECRET_KEY || cko == CKO_PRIVATE_KEY) && bbool(t, CKA_EXTRACTABLE) == Some(true)
    {
        flags |= OBJF_EXTRACTABLE;
    }
    if cko == CKO_PRIVATE_KEY {
        flags |= always_auth;
    }
    let mut der = match a.value {
        Some(v) if cko == CKO_PRIVATE_KEY && !v.is_empty() => raw_private(t, key_type(a.ckk), v)?,
        _ => None,
    };
    let r = st.add(cko, a.ckk as u32, a, der.as_deref().or(a.value), flags);
    if let Some(d) = der.as_mut() {
        zeroize(d);
    }
    st.finish(r?, cko, true)
}

/// A raw private key's PKCS#8 (`:3696-3781`); `None` for a type stored as given.
fn raw_private(t: &[Attr], ckk: u32, v: &[u8]) -> Result<Option<Vec<u8>>, u32> {
    let params = || {
        find(t, CKA_EC_PARAMS)
            .filter(|p| !p.value.is_null())
            .map(bytes)
            .ok_or(TEMPLATE_INCOMPLETE)
    };
    let k = match ckk {
        CKK_EC => {
            let p = params()?;
            match ec_curve(p, strict()) {
                Curve::Named(c) => Pkey::ec_from_scalar(c, v),
                _ => return Err(refusal(p)),
            }
        }
        CKK_ML_KEM | CKK_ML_DSA | CKK_SLH_DSA => {
            // RULE-017: a set of another family is unknown here too.
            let by_name = pset_read_in(t, family(ckk), 64).map_err(|()| TEMPLATE_INCONSISTENT)?;
            let by_len = (ckk != CKK_SLH_DSA)
                .then(|| alg_from_priv_len(v.len(), ckk))
                .flatten();
            if by_name.zip(by_len).is_some_and(|(n, l)| n != l) {
                return Err(TEMPLATE_INCONSISTENT);
            }
            let alg = by_name.or(by_len).ok_or(ATTRIBUTE_VALUE_INVALID)?;
            Pkey::raw_private(alg, v)
        }
        CKK_EC_EDWARDS | CKK_EC_MONTGOMERY => {
            let p = params()?;
            let table: &[(&[u8], &'static CStr)] = if ckk == CKK_EC_EDWARDS {
                &ED_CURVES
            } else {
                &ECM_CURVES
            };
            let alg = match_curve(table, p).ok_or_else(|| refusal(p))?;
            // The FIPS provider has no X25519 or X448.
            if ckk == CKK_EC_MONTGOMERY && !ecm_available() {
                return Err(CURVE_NOT_SUPPORTED);
            }
            Pkey::raw_private(alg, v)
        }
        _ => return Ok(None),
    };
    let k = k.ok_or(ATTRIBUTE_VALUE_INVALID)?;
    k.private_der().map(Some).ok_or(FUNCTION_FAILED)
}

/// A key OpenSSL rebuilds from its parts (`:3858-4104`): the SubjectPublicKeyInfo of a public
/// key or the PKCS#8 of an RSA private key, and whether it is the latter.
fn rebuild(t: &[Attr], a: &Parsed) -> Result<(Vec<u8>, bool), u32> {
    let k = match a.path {
        Path::PqcPub => {
            let v = a.value.unwrap_or_default();
            let pset = pset_read_in(t, family(a.ckk as u32), 64).ok().flatten();
            let k = match a.pqc_alg {
                Some(alg) => Pkey::raw_public(alg, v),
                None => (a.ckk as u32 == CKK_SLH_DSA)
                    .then(|| pset.and_then(|p| Pkey::raw_public(p, v)))
                    .flatten()
                    .or_else(|| Pkey::public(v)),
            };
            let k = k.ok_or(ATTRIBUTE_VALUE_INVALID)?;
            // The parameter set must name the key supplied.
            if !pset.is_some_and(|p| k.is_a(p)) {
                return Err(TEMPLATE_INCONSISTENT);
            }
            k
        }
        Path::EcPub | Path::Ed25519Pub | Path::Ed448Pub => {
            let point = Param::Octets(c"pub", a.ec_point.unwrap_or_default());
            let k = match (a.path, a.ec_group) {
                (Path::EcPub, Some(g)) => {
                    Pkey::from_data(c"EC", false, &[Param::Utf8(c"group", g), point])
                }
                (Path::Ed25519Pub, _) => Pkey::from_data(c"ED25519", false, &[point]),
                (Path::Ed448Pub, _) => Pkey::from_data(c"ED448", false, &[point]),
                _ => None,
            };
            k.filter(|k| k.check(false))
                .ok_or(ATTRIBUTE_VALUE_INVALID)?
        }
        Path::RsaPub => {
            let p = [0, 1].map(|i| Param::Bn(RSA_PARAMS[i], a.rsa[i].unwrap_or_default()));
            // DIV-065: C stored it unchecked, an empty modulus too.
            Pkey::from_data(c"RSA", false, &p)
                .filter(|k| k.check(false))
                .ok_or(ATTRIBUTE_VALUE_INVALID)?
        }
        Path::RsaPriv => {
            // DIV-065: without the primes OpenSSL cannot encode it (C: 0x6 after the build).
            if a.rsa[3..].iter().any(Option::is_none) {
                return Err(TEMPLATE_INCOMPLETE);
            }
            let p: Vec<Param> = RSA_PARAMS
                .iter()
                .zip(a.rsa)
                .map(|(n, v)| Param::Bn(n, v.unwrap_or_default()))
                .collect();
            // DIV-065: C stored components that do not make one key.
            Pkey::from_data(c"RSA", true, &p)
                .filter(|k| k.check(true))
                .ok_or(ATTRIBUTE_VALUE_INVALID)?
        }
        _ => return Err(TEMPLATE_INCONSISTENT),
    };
    let private = a.path == Path::RsaPriv;
    let enc = if private {
        k.private_der()
    } else {
        k.public_der()
    };
    enc.map(|e| (e, private)).ok_or(FUNCTION_FAILED)
}
