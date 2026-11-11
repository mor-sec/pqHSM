//! The `tools/pkiops.h` operations ported past the loader, as safe functions (`ffi::capi`
//! exports them under their C names). Slice 1: what `fhsm-csr` calls; slice 2: `fhsm-token`'s.
//! Each is `tools/pkiops.c`'s, call for call (the call log shows the order) and message for
//! message.

use std::ffi::{CStr, c_int, c_long, c_ulong};
use std::ptr::null_mut;

use pqhsm_pki::ffi::fhsm_composite_spki;
use pqhsm_pki::ffi::x509::{self, Signer};

use crate::Error;
use crate::ffi::{
    CK_ATTRIBUTE, CK_MECHANISM, CK_ULONG, w_close_session, w_find_objects, w_find_objects_final,
    w_find_objects_init, w_generate_key_pair, w_get_attribute_value, w_get_token_info, w_init_pin,
    w_init_token, w_login, w_open_session, w_sign, w_sign_init,
};
use crate::keys::{self, Alg};

/// `pkiops_handle`: a slot, session or object, as the module and the C ABI pass it. The safe
/// API takes [`Slot`], [`Session`] and [`ObjHandle`], so one cannot stand in for another.
pub type Handle = c_ulong;

macro_rules! handle {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[repr(transparent)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name(pub Handle);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}
handle!(
    /// A slot (`CK_SLOT_ID`), as [`crate::open`] resolves it.
    Slot
);
handle!(
    /// A session (`CK_SESSION_HANDLE`).
    Session
);
handle!(
    /// An object on the token (`CK_OBJECT_HANDLE`).
    ObjHandle
);

pub(crate) const CKF_RW: CK_ULONG = 6;
pub(crate) const CKU_USER: CK_ULONG = 1;
pub(crate) const CKO_PUBLIC_KEY: CK_ULONG = 2;
pub(crate) const CKO_PRIVATE_KEY: CK_ULONG = 3;
pub(crate) const CKO_SECRET_KEY: CK_ULONG = 4;
pub(crate) const CKA_CLASS: CK_ULONG = 0x000;
pub(crate) const CKA_TOKEN: CK_ULONG = 0x001;
pub(crate) const CKA_LABEL: CK_ULONG = 0x003;
pub(crate) const CKA_VALUE: CK_ULONG = 0x011;
pub(crate) const CKA_KEY_TYPE: CK_ULONG = 0x100;
pub(crate) const CKA_SENSITIVE: CK_ULONG = 0x103;
pub(crate) const CKA_SIGN: CK_ULONG = 0x108;
pub(crate) const CKA_VERIFY: CK_ULONG = 0x10A;
pub(crate) const CKA_MODULUS: CK_ULONG = 0x120;
pub(crate) const CKA_MODULUS_BITS: CK_ULONG = 0x121;
pub(crate) const CKA_PUBLIC_EXPONENT: CK_ULONG = 0x122;
pub(crate) const CKA_EC_PARAMS: CK_ULONG = 0x180;
pub(crate) const CKA_EC_POINT: CK_ULONG = 0x181;
pub(crate) const CKA_PARAMETER_SET: CK_ULONG = 0x61D;
pub(crate) const CKA_ALLOWED_MECHANISMS: CK_ULONG = 0x4000_0600;
pub(crate) const CKM_SHA256: CK_ULONG = 0x250;
pub(crate) const CKG_MGF1_SHA256: CK_ULONG = 2;
/// `FHSM_COMPOSITE_PUB_MAX`.
const COMPOSITE_PUB_MAX: usize = 4096;
/// `FHSM_PKI_SIG_MAX`.
pub(crate) const SIG_MAX: usize = 8192;
pub(crate) const RV_FUNCTION_FAILED: u32 = 0x06;
pub(crate) const RV_ARGUMENTS_BAD: u32 = 0x07;
pub(crate) const RV_BUFFER_TOO_SMALL: u32 = 0x150;

pub(crate) fn err(code: c_int, parts: &[&[u8]]) -> Error {
    Error::new(code, parts.concat())
}

pub(crate) fn at(type_: CK_ULONG, v: &[u8]) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_,
        p_value: v.as_ptr().cast_mut().cast(),
        value_len: v.len() as CK_ULONG,
    }
}

pub(crate) fn at_ul(type_: CK_ULONG, v: &CK_ULONG) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_,
        p_value: (v as *const CK_ULONG).cast_mut().cast(),
        value_len: size_of::<CK_ULONG>() as CK_ULONG,
    }
}

// --- token state ------------------------------------------------------------------------------

const CKU_SO: CK_ULONG = 0;
const CKF_USER_PIN_INITIALIZED: CK_ULONG = 0x0000_0008;
const CKF_TOKEN_INITIALIZED: CK_ULONG = 0x0000_0400;
const CKF_USER_PIN_LOCKED: CK_ULONG = 0x0004_0000;
const CKF_SO_PIN_LOCKED: CK_ULONG = 0x0040_0000;

/// CK_TOKEN_INFO, PKCS#11 v3.2 §C.6.3 (`struct tok_info`).
#[repr(C)]
struct CkTokenInfo {
    label: [u8; 32],
    manufacturer: [u8; 32],
    model: [u8; 16],
    serial: [u8; 16],
    flags: CK_ULONG,
    counts: [CK_ULONG; 4],
    max_pin: CK_ULONG,
    min_pin: CK_ULONG,
    memory: [CK_ULONG; 4],
    versions: [u8; 4],
    utc_time: [u8; 16],
}

/// `struct pkiops_token_info`: the text fields trimmed and NUL-terminated, as C's.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TokenInfo {
    pub label: [u8; 33],
    pub manufacturer: [u8; 33],
    pub model: [u8; 17],
    pub serial: [u8; 17],
    pub initialised: c_int,
    pub user_pin_set: c_int,
    pub so_pin_locked: c_int,
    pub user_pin_locked: c_int,
    pub min_pin: c_ulong,
    pub max_pin: c_ulong,
}

/// `struct pkiops_slot`: a slot, whether it holds a token, and the token's label as
/// [`TokenInfo`]'s (empty without one, or when the module will not say).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SlotInfo {
    pub id: Slot,
    pub has_token: c_int,
    pub label: [u8; 33],
}

/// A C text field (`TokenInfo`'s, [`crate::objects`]'s) up to its NUL, as `%s` prints it.
pub fn text(f: &[u8]) -> &[u8] {
    f.split(|&b| b == 0).next().unwrap_or_default()
}

/// `field`: a space-padded PKCS#11 field, trailing spaces and NULs dropped.
fn field<const N: usize>(f: &[u8]) -> [u8; N] {
    let n = f.len() - f.iter().rev().take_while(|&&b| b == b' ' || b == 0).count();
    let mut out = [0u8; N];
    out[..n].copy_from_slice(&f[..n]);
    out
}

/// `pkiops_token_info`.
pub fn token_info(slot: Slot) -> Result<TokenInfo, Error> {
    let slot = slot.0;
    // SAFETY: CkTokenInfo is plain bytes and integers, valid all zero.
    let mut ti: CkTokenInfo = unsafe { std::mem::zeroed() };
    // SAFETY: ti has CK_TOKEN_INFO's layout and is writable.
    let rv = unsafe { w_get_token_info(slot, (&raw mut ti).cast()) };
    if rv != 0 {
        return Err(Error::new(2, format!("C_GetTokenInfo failed (0x{rv:x})\n")));
    }
    let flag = |f| c_int::from(ti.flags & f != 0);
    Ok(TokenInfo {
        label: field(&ti.label),
        manufacturer: field(&ti.manufacturer),
        model: field(&ti.model),
        serial: field(&ti.serial),
        initialised: flag(CKF_TOKEN_INITIALIZED),
        user_pin_set: flag(CKF_USER_PIN_INITIALIZED),
        so_pin_locked: flag(CKF_SO_PIN_LOCKED),
        user_pin_locked: flag(CKF_USER_PIN_LOCKED),
        min_pin: ti.min_pin,
        max_pin: ti.max_pin,
    })
}

/// `pkiops_token_init`: C_InitToken, then C_InitPIN as the Security Officer. Destroys every
/// object on the token; whether to ask first is the caller's decision.
pub fn token_init(slot: Slot, so: &[u8], user: &[u8], label: &[u8]) -> Result<(), Error> {
    let slot = slot.0;
    // Space-padded to exactly 32 bytes: a short C string once made C_InitToken read past it.
    if label.len() > 32 {
        return Err(Error::new(1, "the token label is at most 32 bytes\n"));
    }
    let mut lbl = [b' '; 32];
    lbl[..label.len()].copy_from_slice(label);
    // SAFETY: so.len() readable bytes and 32 of label; the module writes through neither.
    let rv = unsafe {
        w_init_token(
            slot,
            so.as_ptr().cast_mut(),
            so.len() as CK_ULONG,
            lbl.as_mut_ptr(),
        )
    };
    if rv != 0 {
        return Err(Error::new(2, format!("C_InitToken failed (0x{rv:x})\n")));
    }
    let mut s: Handle = 0;
    // SAFETY: s is writable; no application callback.
    let rv = unsafe { w_open_session(slot, CKF_RW, null_mut(), null_mut(), &mut s) };
    if rv != 0 {
        return Err(Error::new(2, format!("C_OpenSession failed (0x{rv:x})\n")));
    }
    // SAFETY: as C_InitToken's PIN.
    let rv = unsafe { w_login(s, CKU_SO, so.as_ptr().cast_mut(), so.len() as CK_ULONG) };
    if rv != 0 {
        session_close(Session(s));
        return Err(Error::new(2, format!("C_Login (SO) failed (0x{rv:x})\n")));
    }
    // SAFETY: user.len() readable bytes, not written.
    let rv = unsafe { w_init_pin(s, user.as_ptr().cast_mut(), user.len() as CK_ULONG) };
    session_close(Session(s));
    if rv != 0 {
        return Err(Error::new(2, format!("C_InitPIN failed (0x{rv:x})\n")));
    }
    Ok(())
}

// --- sessions ---------------------------------------------------------------------------------

/// `pkiops_session_user`: a read-write session, logged in as the user.
pub fn session_user(slot: Slot, pin: &[u8]) -> Result<Session, Error> {
    let s = session_open(slot)
        .map_err(|rv| Error::new(2, format!("C_OpenSession failed (0x{rv:x})\n")))?;
    let rv = login_user(s, pin);
    if rv != 0 {
        session_close(s);
        return Err(Error::new(2, format!("C_Login failed (0x{rv:x})\n")));
    }
    Ok(s)
}

/// C_OpenSession, read-write; `Err` is the module's `CK_RV`.
pub fn session_open(slot: Slot) -> Result<Session, CK_ULONG> {
    let mut s: Handle = 0;
    // SAFETY: s is writable; no application callback.
    let rv = unsafe { w_open_session(slot.0, CKF_RW, null_mut(), null_mut(), &mut s) };
    if rv == 0 { Ok(Session(s)) } else { Err(rv) }
}

/// C_Login as the user; the module's `CK_RV`.
pub fn login_user(s: Session, pin: &[u8]) -> CK_ULONG {
    // SAFETY: pin.len() readable bytes; the module does not write through it.
    unsafe {
        w_login(
            s.0,
            CKU_USER,
            pin.as_ptr().cast_mut(),
            pin.len() as CK_ULONG,
        )
    }
}

/// `pkiops_session_close`.
pub fn session_close(s: Session) {
    // SAFETY: a plain handle.
    unsafe { w_close_session(s.0) };
}

// --- objects ------------------------------------------------------------------------------------

/// `p11_find_one_e`: exactly one object of class `cls` labelled `label`; two is an ambiguity
/// the operator resolves, not one this picks from.
pub(crate) fn find_one(s: Handle, cls: CK_ULONG, label: &[u8]) -> Result<Handle, Error> {
    let c = cls;
    let mut t = [at_ul(CKA_CLASS, &c), at(CKA_LABEL, label)];
    // SAFETY: a template of 2 whose values outlive the search.
    if unsafe { w_find_objects_init(s, t.as_mut_ptr(), 2) } != 0 {
        return Err(Error::new(2, "C_FindObjectsInit\n"));
    }
    let (mut h, mut n): ([Handle; 4], CK_ULONG) = ([0; 4], 0);
    // SAFETY: room for 4 handles, and n writable.
    let rv = unsafe { w_find_objects(s, h.as_mut_ptr(), 4, &mut n) };
    unsafe { w_find_objects_final(s) };
    if rv != 0 {
        return Err(Error::new(2, format!("C_FindObjects failed (0x{rv:x})\n")));
    }
    let kind: &[u8] = match cls {
        CKO_PUBLIC_KEY => b"public",
        CKO_SECRET_KEY => b"secret",
        _ => b"private",
    };
    match n {
        0 => Err(err(3, &[b"no ", kind, b" key labelled \"", label, b"\"\n"])),
        1 => Ok(h[0]),
        _ => Err(err(
            3,
            &[
                n.to_string().as_bytes(),
                b" keys labelled \"",
                label,
                b"\" -- ambiguous, refusing to guess\n",
            ],
        )),
    }
}

fn attr_failed(type_: CK_ULONG, rv: CK_ULONG) -> Error {
    Error::new(
        2,
        format!("C_GetAttributeValue(0x{type_:x}) failed (0x{rv:x})\n"),
    )
}

/// `get_attr`: one attribute, its length then its value.
pub(crate) fn get_attr(s: Handle, h: Handle, type_: CK_ULONG) -> Result<Vec<u8>, Error> {
    let mut a = CK_ATTRIBUTE {
        type_,
        p_value: null_mut(),
        value_len: 0,
    };
    // SAFETY: a length query, nothing written but the length.
    let rv = unsafe { w_get_attribute_value(s, h, &mut a, 1) };
    if rv != 0 || a.value_len == CK_ULONG::MAX {
        return Err(attr_failed(type_, rv));
    }
    let room = (a.value_len as usize).max(1);
    let mut b = Vec::new();
    if b.try_reserve_exact(room).is_err() {
        return Err(Error::new(2, "out of memory\n"));
    }
    b.resize(room, 0);
    a.p_value = b.as_mut_ptr().cast();
    // SAFETY: a buffer of the length the module gave.
    let rv = unsafe { w_get_attribute_value(s, h, &mut a, 1) };
    if rv != 0 {
        return Err(attr_failed(type_, rv));
    }
    b.truncate(a.value_len as usize);
    Ok(b)
}

pub(crate) fn get_ulong(s: Handle, h: Handle, type_: CK_ULONG) -> Result<CK_ULONG, Error> {
    let mut v: CK_ULONG = 0;
    let mut a = CK_ATTRIBUTE {
        type_,
        p_value: (&raw mut v).cast(),
        value_len: size_of::<CK_ULONG>() as CK_ULONG,
    };
    // SAFETY: a CK_ULONG of room.
    let rv = unsafe { w_get_attribute_value(s, h, &mut a, 1) };
    if rv != 0 || a.value_len != size_of::<CK_ULONG>() as CK_ULONG {
        return Err(attr_failed(type_, rv));
    }
    Ok(v)
}

/// `alg_of`: which algorithm the key labelled `label` signs with, from `h` (its private half
/// to sign, its public half otherwise) and, where the type alone does not say, its public
/// half. An RSA key without CKA_ALLOWED_MECHANISMS, made elsewhere, signs with PSS.
pub(crate) fn alg_of(s: Handle, label: &[u8], h: Handle) -> Result<Alg, Error> {
    let kt = get_ulong(s, h, CKA_KEY_TYPE)?;
    if kt == keys::CKK_COMPOSITE {
        return Ok(Alg::Composite);
    }
    if kt == keys::CKK_RSA {
        let (mut pkcs1, mut pss, mut listed) = (false, false, false);
        if let Ok(v) = get_attr(s, h, CKA_ALLOWED_MECHANISMS) {
            listed = !v.is_empty();
            for m in v.as_chunks::<{ size_of::<CK_ULONG>() }>().0 {
                let m = CK_ULONG::from_ne_bytes(*m);
                pkcs1 |= m == Alg::RsaPkcs1.info().mech;
                pss |= m == Alg::RsaPss.info().mech;
            }
        }
        // An RSA-OAEP key from fhsm-crypt names neither, and is not one to sign with.
        if listed && !pkcs1 && !pss {
            return Err(err(
                3,
                &[b"\"", label, b"\" is an encryption key: it does not sign\n"],
            ));
        }
        return Ok(if pkcs1 && !pss {
            Alg::RsaPkcs1
        } else {
            Alg::RsaPss
        });
    }
    let hpub = find_one(s, CKO_PUBLIC_KEY, label)?;
    let found = if kt == keys::CKK_EC || kt == keys::CKK_EC_EDWARDS {
        let v = get_attr(s, hpub, CKA_EC_PARAMS)?;
        match (kt, &v[..]) {
            (keys::CKK_EC, keys::OID_P256) => Some(Alg::EcdsaP256),
            (keys::CKK_EC, keys::OID_P384) => Some(Alg::EcdsaP384),
            (keys::CKK_EC_EDWARDS, keys::OID_ED25519 | keys::PRINTABLE_ED25519) => {
                Some(Alg::Ed25519)
            }
            _ => None,
        }
    } else if kt == keys::CKK_ML_DSA {
        // The parameter set from the raw public key's length, which every module gives as
        // CKA_VALUE, whatever form its CKA_PARAMETER_SET takes.
        match get_attr(s, hpub, CKA_VALUE)?.len() {
            1312 => Some(Alg::MlDsa44),
            1952 => Some(Alg::MlDsa65),
            2592 => Some(Alg::MlDsa87),
            _ => None,
        }
    } else {
        None
    };
    found.ok_or_else(|| {
        err(
            3,
            &[
                b"the key \"",
                label,
                format!(
                    "\" is not one these tools sign with (key type 0x{kt:x}).\n  They sign with: "
                )
                .as_bytes(),
                keys::ALG_LIST.to_bytes(),
                b"\n",
            ],
        )
    })
}

/// `pkiops_key_alg`: from the public half, which a session not logged in can see.
pub fn key_alg(s: Session, label: &[u8]) -> Result<Alg, Error> {
    let s = s.0;
    let h = find_one(s, CKO_PUBLIC_KEY, label)?;
    alg_of(s, label, h)
}

// --- keys and requests --------------------------------------------------------------------------

/// `pkiops_keygen_alg`: both halves on the token, the private one sensitive and for signing
/// only; RSA 3072 bits. The composite's templates are what they always were: label and token.
pub fn keygen_alg(s: Session, label: &[u8], a: Alg) -> Result<(ObjHandle, ObjHandle), Error> {
    let s = s.0;
    let i = a.info();
    let yes = [1u8];
    let f4 = [0x01u8, 0x00, 0x01];
    let (bits, allowed): (CK_ULONG, CK_ULONG) = (3072, i.mech);
    let pset: CK_ULONG = match a {
        Alg::MlDsa44 => 1,
        Alg::MlDsa65 => 2,
        Alg::MlDsa87 => 3,
        _ => 0,
    };
    let mut pub_t = vec![at(CKA_LABEL, label), at(CKA_TOKEN, &yes)];
    let mut priv_t = vec![at(CKA_LABEL, label), at(CKA_TOKEN, &yes)];
    if a != Alg::Composite {
        pub_t.push(at(CKA_VERIFY, &yes));
        priv_t.extend([at(CKA_SIGN, &yes), at(CKA_SENSITIVE, &yes)]);
    }
    match a {
        Alg::EcdsaP256 => pub_t.push(at(CKA_EC_PARAMS, keys::OID_P256)),
        Alg::EcdsaP384 => pub_t.push(at(CKA_EC_PARAMS, keys::OID_P384)),
        Alg::Ed25519 => pub_t.push(at(CKA_EC_PARAMS, keys::OID_ED25519)),
        Alg::RsaPss | Alg::RsaPkcs1 => {
            pub_t.extend([
                at_ul(CKA_MODULUS_BITS, &bits),
                at(CKA_PUBLIC_EXPONENT, &f4),
                at_ul(CKA_ALLOWED_MECHANISMS, &allowed),
            ]);
            priv_t.push(at_ul(CKA_ALLOWED_MECHANISMS, &allowed));
        }
        _ => {}
    }
    if pset != 0 {
        pub_t.push(at_ul(CKA_PARAMETER_SET, &pset));
    }
    let mut m = CK_MECHANISM {
        mechanism: i.keygen,
        p_parameter: null_mut(),
        parameter_len: 0,
    };
    let (mut hp, mut hk): (Handle, Handle) = (0, 0);
    // SAFETY: both templates' values outlive the call; hp and hk writable.
    let rv = unsafe {
        w_generate_key_pair(
            s,
            &mut m,
            pub_t.as_mut_ptr(),
            pub_t.len() as CK_ULONG,
            priv_t.as_mut_ptr(),
            priv_t.len() as CK_ULONG,
            &mut hp,
            &mut hk,
        )
    };
    if rv != 0 {
        return Err(Error::new(
            2,
            format!("C_GenerateKeyPair failed (0x{rv:x})\n"),
        ));
    }
    Ok((ObjHandle(hp), ObjHandle(hk)))
}

/// OpenSSL's own encoding of the key `der` describes, as C's `i2d_PUBKEY` of the key it
/// built: `load` is the refusal when OpenSSL does not take the key.
fn reencode(der: &[u8], load: &str) -> Result<Vec<u8>, Error> {
    // SAFETY: der.len() readable bytes; the key is freed below; i2d's buffer is OpenSSL's.
    unsafe {
        let mut p = der.as_ptr();
        let k = openssl_sys::d2i_PUBKEY(null_mut(), &mut p, der.len() as c_long);
        if k.is_null() {
            return Err(Error::new(2, load));
        }
        let mut out: *mut u8 = null_mut();
        let n = openssl_sys::i2d_PUBKEY(k, &mut out);
        openssl_sys::EVP_PKEY_free(k);
        if n <= 0 || out.is_null() {
            return Err(Error::new(2, "the public key does not encode\n"));
        }
        let v = std::slice::from_raw_parts(out, n as usize).to_vec();
        openssl_sys::CRYPTO_free(out.cast(), c"pkiops".as_ptr(), 0);
        Ok(v)
    }
}

/// `spki_of`: the public key as a SubjectPublicKeyInfo, from the standard attributes rather
/// than a public key's CKA_VALUE, which the specification leaves undefined for EC, RSA and
/// EdDSA keys.
fn spki_of(s: Handle, hpub: Handle, a: Alg) -> Result<Vec<u8>, Error> {
    let not_composite = "not the composite";
    match a {
        Alg::Composite => {
            // The module's own composite blob, as it has always been read: one call.
            let mut blob = vec![0u8; COMPOSITE_PUB_MAX];
            let mut g = CK_ATTRIBUTE {
                type_: CKA_VALUE,
                p_value: blob.as_mut_ptr().cast(),
                value_len: blob.len() as CK_ULONG,
            };
            // SAFETY: COMPOSITE_PUB_MAX writable bytes.
            let rv = unsafe { w_get_attribute_value(s, hpub, &mut g, 1) };
            if rv != 0 {
                return Err(Error::new(
                    2,
                    format!("C_GetAttributeValue(CKA_VALUE) failed (0x{rv:x})\n"),
                ));
            }
            let mut out = vec![0u8; 8192];
            let mut ol = out.len();
            let n = (g.value_len as usize).min(blob.len());
            // SAFETY: n readable bytes of the blob; ol writable bytes at out.
            let r = unsafe { fhsm_composite_spki(1, blob.as_ptr(), n, out.as_mut_ptr(), &mut ol) };
            if r != 0 {
                return Err(Error::new(
                    2,
                    format!("the composite public key does not encode (0x{r:x})\n"),
                ));
            }
            out.truncate(ol);
            Ok(out)
        }
        Alg::EcdsaP256 | Alg::EcdsaP384 => {
            let v = get_attr(s, hpub, CKA_EC_POINT)?;
            let raw = if a == Alg::EcdsaP256 { 65 } else { 97 };
            let pt = keys::point_of(&v, raw)
                .ok_or_else(|| Error::new(2, "CKA_EC_POINT is not an uncompressed point\n"))?;
            reencode(
                &keys::spki(a, pt, &[]).expect(not_composite),
                "the EC public key does not load\n",
            )
        }
        Alg::RsaPss | Alg::RsaPkcs1 => {
            let n = get_attr(s, hpub, CKA_MODULUS)?;
            let e = get_attr(s, hpub, CKA_PUBLIC_EXPONENT)?;
            reencode(
                &keys::spki(a, &n, &e).expect(not_composite),
                "the RSA public key does not load\n",
            )
        }
        Alg::Ed25519 => {
            let v = get_attr(s, hpub, CKA_EC_POINT)?;
            let pt = keys::point_of(&v, 32)
                .ok_or_else(|| Error::new(2, "CKA_EC_POINT is not an Ed25519 key\n"))?;
            reencode(
                &keys::spki(a, pt, &[]).expect(not_composite),
                "the Ed25519 public key does not load\n",
            )
        }
        Alg::MlDsa44 | Alg::MlDsa65 | Alg::MlDsa87 => {
            let v = get_attr(s, hpub, CKA_VALUE)?;
            reencode(
                &keys::spki(a, &v, &[]).expect(not_composite),
                "the ML-DSA public key does not load\n",
            )
        }
    }
}

/// A signer that reaches the module, for any of the algorithms (`struct tsigner`).
struct TokenSigner {
    s: Handle,
    private: Handle,
    alg: Alg,
}

impl TokenSigner {
    /// `tok_sign`: the module's signature over `tbs` into `sig`, and its length; ECDSA's as
    /// DER, which X.509 and CMS carry where PKCS#11 gives r || s.
    fn sign(&self, tbs: &[u8], sig: &mut [u8]) -> Result<usize, u32> {
        let ok = |rv: CK_ULONG| if rv == 0 { Ok(()) } else { Err(rv as u32) };
        let tbs_len = tbs.len() as CK_ULONG;
        if self.alg == Alg::Composite {
            // p11_sign: the composite's path, unchanged, straight into the builder's room.
            let mut m = CK_MECHANISM {
                mechanism: keys::CKM_COMPOSITE,
                p_parameter: null_mut(),
                parameter_len: 0,
            };
            // SAFETY: m lives for the call.
            ok(unsafe { w_sign_init(self.s, &mut m, self.private) })?;
            let mut n = sig.len() as CK_ULONG;
            // SAFETY: tbs readable, n writable bytes at sig.
            ok(unsafe {
                w_sign(
                    self.s,
                    tbs.as_ptr().cast_mut(),
                    tbs_len,
                    sig.as_mut_ptr(),
                    &mut n,
                )
            })?;
            // A length past the room is refused rather than read.
            return Some(n as usize)
                .filter(|&n| n <= sig.len())
                .ok_or(RV_FUNCTION_FAILED);
        }
        // SAFETY: the mechanism lives for the call.
        ok(with_mechanism(self.alg, |m| unsafe {
            w_sign_init(self.s, m, self.private)
        }))?;
        let mut raw = vec![0u8; SIG_MAX];
        let mut n = SIG_MAX as CK_ULONG;
        // SAFETY: tbs readable, n writable bytes at raw.
        ok(unsafe {
            w_sign(
                self.s,
                tbs.as_ptr().cast_mut(),
                tbs_len,
                raw.as_mut_ptr(),
                &mut n,
            )
        })?;
        raw.truncate((n as usize).min(SIG_MAX));
        if self.alg.info().ecdsa_half != 0 {
            raw = ecdsa_der(&raw)?;
        }
        let out = sig.get_mut(..raw.len()).ok_or(RV_BUFFER_TOO_SMALL)?;
        out.copy_from_slice(&raw);
        Ok(raw.len())
    }
}

/// `fhsm_pki_ecdsa_raw_to_der`: r || s, two halves of equal length and 264 bytes at most, as a
/// DER Ecdsa-Sig-Value.
pub(crate) fn ecdsa_der(rs: &[u8]) -> Result<Vec<u8>, u32> {
    if rs.is_empty() || !rs.len().is_multiple_of(2) || rs.len() > 264 {
        return Err(RV_ARGUMENTS_BAD);
    }
    Ok(pqhsm_pki::x509::ecdsa_sig(rs))
}

/// The SPKI, when a builder wants one.
type Spki = Option<Vec<u8>>;

/// `token_signer`: the key labelled `label`, ready to sign, and with `want_spki` its public
/// key, whose half is then looked up first, as the builders always did, so a missing label
/// reads the same.
fn token_signer(
    s: Handle,
    label: &[u8],
    want_spki: bool,
) -> Result<(TokenSigner, &'static [u8], Spki), Error> {
    let hpub = if want_spki {
        Some(find_one(s, CKO_PUBLIC_KEY, label)?)
    } else {
        None
    };
    let private = find_one(s, CKO_PRIVATE_KEY, label)?;
    let alg = alg_of(s, label, private)?;
    let name = alg.info().name.to_bytes();
    let algid = pqhsm_pki::x509::pki_algid(alg as i32)
        .ok_or_else(|| err(2, &[b"no AlgorithmIdentifier for ", name, b"\n"]))?;
    let spki = hpub.map(|h| spki_of(s, h, alg)).transpose()?;
    Ok((TokenSigner { s, private, alg }, algid, spki))
}

/// `alg_mechanism`: the signing mechanism of `a`, with RSA-PSS's parameters as fhsm_pki's
/// AlgorithmIdentifier names them (SHA-256, MGF1 with SHA-256, a 32-byte salt), for `f`.
pub(crate) fn with_mechanism<T>(a: Alg, f: impl FnOnce(&mut CK_MECHANISM) -> T) -> T {
    let mut pss: [CK_ULONG; 3] = [CKM_SHA256, CKG_MGF1_SHA256, 32];
    let mut m = CK_MECHANISM {
        mechanism: a.info().mech,
        p_parameter: null_mut(),
        parameter_len: 0,
    };
    if a == Alg::RsaPss {
        m.p_parameter = pss.as_mut_ptr().cast();
        m.parameter_len = size_of_val(&pss) as CK_ULONG;
    }
    f(&mut m)
}

/// fhsm_pki's builder `build`, signing with the key `label`, given the key's algorithm and,
/// with `want_spki`, its SubjectPublicKeyInfo (else empty).
pub(crate) fn with_signer<T>(
    s: Handle,
    label: &[u8],
    want_spki: bool,
    build: impl FnOnce(&mut Signer, Alg, &[u8]) -> T,
) -> Result<T, Error> {
    let (ts, algid, spki) = token_signer(s, label, want_spki)?;
    let mut sign = |tbs: &[u8], sig: &mut [u8]| ts.sign(tbs, sig);
    let mut signer = Signer {
        algid,
        sign: &mut sign,
    };
    Ok(build(
        &mut signer,
        ts.alg,
        spki.as_deref().unwrap_or_default(),
    ))
}

/// A builder's result into `out` as fhsm_pki's `emit` writes it: `*len` the room on entry, the
/// length on return once built, too little room BUFFER_TOO_SMALL; a failure "`doing` failed".
///
/// # Safety
/// `out` has `*len` writable bytes.
pub(crate) unsafe fn emit_into(
    der: Result<Vec<u8>, u32>,
    out: *mut u8,
    len: &mut usize,
    doing: &str,
) -> Result<(), Error> {
    der.and_then(|der| {
        let room = std::mem::replace(len, der.len());
        if room < der.len() {
            return Err(RV_BUFFER_TOO_SMALL);
        }
        // SAFETY: the caller's room, at least der.len() bytes.
        unsafe { std::ptr::copy_nonoverlapping(der.as_ptr(), out, der.len()) };
        Ok(())
    })
    .map_err(|r| Error::new(2, format!("{doing} failed (0x{r:x})\n")))
}

/// [`with_signer`], then [`emit_into`] as "building the `what`".
///
/// # Safety
/// `out` has `*len` writable bytes.
pub(crate) unsafe fn signed_by(
    s: Handle,
    label: &[u8],
    want_spki: bool,
    out: *mut u8,
    len: &mut usize,
    what: &str,
    build: impl FnOnce(&mut Signer, Alg, &[u8]) -> Result<Vec<u8>, u32>,
) -> Result<(), Error> {
    let der = with_signer(s, label, want_spki, build)?;
    // SAFETY: the caller's room.
    unsafe { emit_into(der, out, len, &format!("building the {what}")) }
}

/// The DER room the tools give a request or certificate (`tools/fhsm_csr.c`'s buffer).
pub(crate) const DER_MAX: usize = 32768;

/// Into a fresh buffer of `room` bytes, trimmed to what was written.
pub(crate) fn to_vec(
    room: usize,
    f: impl FnOnce(*mut u8, &mut usize) -> Result<(), Error>,
) -> Result<Vec<u8>, Error> {
    let mut der = vec![0u8; room];
    let mut n = der.len();
    f(der.as_mut_ptr(), &mut n)?;
    der.truncate(n);
    Ok(der)
}

/// `pkiops_csr` into the caller's buffer.
///
/// # Safety
/// `out` has `*len` writable bytes.
pub(crate) unsafe fn csr_into(
    s: Handle,
    label: &[u8],
    subject: &CStr,
    out: *mut u8,
    len: &mut usize,
) -> Result<(), Error> {
    // SAFETY: ps and its buffers live for the call; *n writable bytes at out.
    unsafe {
        signed_by(s, label, true, out, len, "request", |sg, _, spki| {
            x509::csr(sg, spki, subject.to_bytes())
        })
    }
}

/// `pkiops_root` into the caller's buffer.
///
/// # Safety
/// As [`csr_into`].
pub(crate) unsafe fn root_into(
    s: Handle,
    label: &[u8],
    subject: &CStr,
    serial: c_long,
    days: c_int,
    out: *mut u8,
    len: &mut usize,
) -> Result<(), Error> {
    // SAFETY: as csr_into.
    unsafe {
        signed_by(s, label, true, out, len, "certificate", |sg, _, spki| {
            // fhsm_pki_selfsigned's: serial 0 is malformed, a negative one encodes negative
            // (RFC 5280 4.1.2.2)
            if serial <= 0 || days <= 0 {
                return Err(RV_ARGUMENTS_BAD);
            }
            x509::selfsigned(sg, spki, subject.to_bytes(), serial, days)
        })
    }
}

/// `pkiops_csr`: a PKCS#10 request signed by the key `label` with its own algorithm.
pub fn csr(s: Session, label: &[u8], subject: &CStr) -> Result<Vec<u8>, Error> {
    // SAFETY: to_vec hands n writable bytes.
    to_vec(DER_MAX, |out, n| unsafe {
        csr_into(s.0, label, subject, out, n)
    })
}

/// `pkiops_root`: a self-signed root, CA:TRUE, keyCertSign and cRLSign.
pub fn root(
    s: Session,
    label: &[u8],
    subject: &CStr,
    serial: c_long,
    days: c_int,
) -> Result<Vec<u8>, Error> {
    // SAFETY: as csr.
    to_vec(DER_MAX, |out, n| unsafe {
        root_into(s.0, label, subject, serial, days, out, n)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_info_as_c() {
        // struct tok_info on LP64: 96 bytes of text, 11 CK_ULONGs, 20 bytes, padded to 8.
        assert_eq!(size_of::<CkTokenInfo>(), 208);
        assert_eq!(std::mem::offset_of!(CkTokenInfo, max_pin), 96 + 5 * 8);
        let f: [u8; 33] = field(b"freehsm \0  \0                    ");
        assert_eq!(text(&f), b"freehsm");
        let full: [u8; 17] = field(&[b'x'; 16]);
        assert_eq!(text(&full), &[b'x'; 16]);
        assert_eq!(text(&field::<17>(&[b' '; 16])), b"");
    }
}
