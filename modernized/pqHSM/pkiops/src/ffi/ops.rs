//! The `tools/pkiops.h` operations ported past the loader, as safe functions for `pqhsm-cli`
//! and under their C names for the C callers. Slice 1: what `fhsm-csr` calls. Each is
//! `tools/pkiops.c`'s, call for call (the call log shows the order) and message for message.

use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};
use std::ptr::{null, null_mut};

use pqhsm_pki::ffi::{
    fhsm_composite_spki, fhsm_pki_csr, fhsm_pki_ecdsa_raw_to_der, fhsm_pki_selfsigned,
    fhsm_pki_signer_t,
};

use super::{
    CK_ATTRIBUTE, CK_MECHANISM, CK_ULONG, fail, p11_err, w_close_session, w_find_objects,
    w_find_objects_final, w_find_objects_init, w_generate_key_pair, w_get_attribute_value, w_login,
    w_open_session, w_sign, w_sign_init,
};
use crate::keys::{self, Alg};
use crate::{Error, SlotId};

/// `pkiops_handle`: a slot, session or object.
pub type Handle = c_ulong;

const CKF_RW: CK_ULONG = 6;
const CKU_USER: CK_ULONG = 1;
const CKO_PUBLIC_KEY: CK_ULONG = 2;
const CKO_PRIVATE_KEY: CK_ULONG = 3;
const CKO_SECRET_KEY: CK_ULONG = 4;
const CKA_CLASS: CK_ULONG = 0x000;
const CKA_TOKEN: CK_ULONG = 0x001;
const CKA_LABEL: CK_ULONG = 0x003;
const CKA_VALUE: CK_ULONG = 0x011;
const CKA_KEY_TYPE: CK_ULONG = 0x100;
const CKA_SENSITIVE: CK_ULONG = 0x103;
const CKA_SIGN: CK_ULONG = 0x108;
const CKA_VERIFY: CK_ULONG = 0x10A;
const CKA_MODULUS: CK_ULONG = 0x120;
const CKA_MODULUS_BITS: CK_ULONG = 0x121;
const CKA_PUBLIC_EXPONENT: CK_ULONG = 0x122;
const CKA_EC_PARAMS: CK_ULONG = 0x180;
const CKA_EC_POINT: CK_ULONG = 0x181;
const CKA_PARAMETER_SET: CK_ULONG = 0x61D;
const CKA_ALLOWED_MECHANISMS: CK_ULONG = 0x4000_0600;
const CKM_SHA256: CK_ULONG = 0x250;
const CKG_MGF1_SHA256: CK_ULONG = 2;
/// `FHSM_COMPOSITE_PUB_MAX`.
const COMPOSITE_PUB_MAX: usize = 4096;
/// `FHSM_PKI_SIG_MAX`.
const SIG_MAX: usize = 8192;
const RV_BUFFER_TOO_SMALL: u32 = 0x150;

fn err(code: c_int, parts: &[&[u8]]) -> Error {
    Error::new(code, parts.concat())
}

fn at(type_: CK_ULONG, v: &[u8]) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_,
        p_value: v.as_ptr().cast_mut().cast(),
        value_len: v.len() as CK_ULONG,
    }
}

fn at_ul(type_: CK_ULONG, v: &CK_ULONG) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_,
        p_value: (v as *const CK_ULONG).cast_mut().cast(),
        value_len: size_of::<CK_ULONG>() as CK_ULONG,
    }
}

// --- sessions ---------------------------------------------------------------------------------

/// `pkiops_session_user`: a read-write session, logged in as the user.
pub fn session_user(slot: SlotId, pin: &[u8]) -> Result<Handle, Error> {
    let mut s: Handle = 0;
    // SAFETY: s is writable; no application callback.
    let rv = unsafe { w_open_session(slot, CKF_RW, null_mut(), null_mut(), &mut s) };
    if rv != 0 {
        return Err(Error::new(2, format!("C_OpenSession failed (0x{rv:x})\n")));
    }
    // SAFETY: pin.len() readable bytes; the module does not write through it.
    let rv = unsafe { w_login(s, CKU_USER, pin.as_ptr().cast_mut(), pin.len() as CK_ULONG) };
    if rv != 0 {
        session_close(s);
        return Err(Error::new(2, format!("C_Login failed (0x{rv:x})\n")));
    }
    Ok(s)
}

/// `pkiops_session_close`.
pub fn session_close(s: Handle) {
    // SAFETY: a plain handle.
    unsafe { w_close_session(s) };
}

// --- objects ------------------------------------------------------------------------------------

/// `p11_find_one_e`: exactly one object of class `cls` labelled `label`; two is an ambiguity
/// the operator resolves, not one this picks from.
fn find_one(s: Handle, cls: CK_ULONG, label: &[u8]) -> Result<Handle, Error> {
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
fn get_attr(s: Handle, h: Handle, type_: CK_ULONG) -> Result<Vec<u8>, Error> {
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

fn get_ulong(s: Handle, h: Handle, type_: CK_ULONG) -> Result<CK_ULONG, Error> {
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
fn alg_of(s: Handle, label: &[u8], h: Handle) -> Result<Alg, Error> {
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
pub fn key_alg(s: Handle, label: &[u8]) -> Result<Alg, Error> {
    let h = find_one(s, CKO_PUBLIC_KEY, label)?;
    alg_of(s, label, h)
}

// --- keys and requests --------------------------------------------------------------------------

/// `pkiops_keygen_alg`: both halves on the token, the private one sensitive and for signing
/// only; RSA 3072 bits. The composite's templates are what they always were: label and token.
pub fn keygen_alg(s: Handle, label: &[u8], a: Alg) -> Result<(Handle, Handle), Error> {
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
    Ok((hp, hk))
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

/// `tok_sign`, the fhsm_pki signing callback. `ctx` is a [`TokenSigner`].
unsafe extern "C" fn tok_sign(
    ctx: *mut c_void,
    tbs: *const u8,
    tbs_len: usize,
    sig: *mut u8,
    sig_len: *mut usize,
) -> u32 {
    // SAFETY: fhsm_pki's contract: ctx is the TokenSigner of signed_by, tbs readable,
    // *sig_len writable bytes at sig.
    unsafe {
        let g = &*ctx.cast::<TokenSigner>();
        if g.alg == Alg::Composite {
            // p11_sign: the composite's path, unchanged.
            let mut m = CK_MECHANISM {
                mechanism: keys::CKM_COMPOSITE,
                p_parameter: null_mut(),
                parameter_len: 0,
            };
            let rv = w_sign_init(g.s, &mut m, g.private);
            if rv != 0 {
                return rv as u32;
            }
            let mut n = *sig_len as CK_ULONG;
            let rv = w_sign(g.s, tbs.cast_mut(), tbs_len as CK_ULONG, sig, &mut n);
            if rv != 0 {
                return rv as u32;
            }
            *sig_len = n as usize;
            return 0;
        }
        // RSA-PSS's parameters as fhsm_pki's AlgorithmIdentifier names them: SHA-256, MGF1
        // with SHA-256, a 32-byte salt.
        let mut pss: [CK_ULONG; 3] = [CKM_SHA256, CKG_MGF1_SHA256, 32];
        let mut m = CK_MECHANISM {
            mechanism: g.alg.info().mech,
            p_parameter: null_mut(),
            parameter_len: 0,
        };
        if g.alg == Alg::RsaPss {
            m.p_parameter = pss.as_mut_ptr().cast();
            m.parameter_len = size_of_val(&pss) as CK_ULONG;
        }
        let rv = w_sign_init(g.s, &mut m, g.private);
        if rv != 0 {
            return rv as u32;
        }
        let mut raw = vec![0u8; SIG_MAX];
        let mut n = SIG_MAX as CK_ULONG;
        let rv = w_sign(
            g.s,
            tbs.cast_mut(),
            tbs_len as CK_ULONG,
            raw.as_mut_ptr(),
            &mut n,
        );
        if rv != 0 {
            return rv as u32;
        }
        let n = (n as usize).min(SIG_MAX);
        // PKCS#11 gives ECDSA as r || s; X.509 and CMS carry DER.
        if g.alg.info().ecdsa_half != 0 {
            return fhsm_pki_ecdsa_raw_to_der(raw.as_ptr(), n, sig, sig_len);
        }
        if n > *sig_len {
            return RV_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(raw.as_ptr(), sig, n);
        *sig_len = n;
        0
    }
}

/// `token_signer`: the key labelled `label`, ready to sign, and its public key. The public
/// half is looked up first, as the builders always did, so a missing label reads the same.
fn token_signer(s: Handle, label: &[u8]) -> Result<(TokenSigner, &'static [u8], Vec<u8>), Error> {
    let hpub = find_one(s, CKO_PUBLIC_KEY, label)?;
    let private = find_one(s, CKO_PRIVATE_KEY, label)?;
    let alg = alg_of(s, label, private)?;
    let name = alg.info().name.to_bytes();
    let algid = pqhsm_pki::x509::pki_algid(alg as i32)
        .ok_or_else(|| err(2, &[b"no AlgorithmIdentifier for ", name, b"\n"]))?;
    let spki = spki_of(s, hpub, alg)?;
    Ok((TokenSigner { s, private, alg }, algid, spki))
}

/// The builder `build` over the key `label`, into `der`: `*len` its room on entry, the length
/// on return, whatever the result, as fhsm_pki writes it.
fn signed_by(
    s: Handle,
    label: &[u8],
    der: &mut [u8],
    len: &mut usize,
    what: &str,
    build: impl FnOnce(&fhsm_pki_signer_t, *mut u8, &mut usize) -> u32,
) -> Result<(), Error> {
    let (mut ts, algid, spki) = token_signer(s, label)?;
    let ps = fhsm_pki_signer_t {
        algid: algid.as_ptr(),
        algid_len: algid.len(),
        spki: spki.as_ptr(),
        spki_len: spki.len(),
        sign: Some(tok_sign),
        sign_ctx: (&raw mut ts).cast(),
    };
    *len = (*len).min(der.len());
    match build(&ps, der.as_mut_ptr(), len) {
        0 => Ok(()),
        r => Err(Error::new(
            2,
            format!("building the {what} failed (0x{r:x})\n"),
        )),
    }
}

/// `pkiops_csr`: a PKCS#10 request signed by the key `label` with its own algorithm.
pub fn csr(
    s: Handle,
    label: &[u8],
    subject: &CStr,
    der: &mut [u8],
    len: &mut usize,
) -> Result<(), Error> {
    // SAFETY: ps and its buffers live for the call; *n writable bytes at out.
    signed_by(s, label, der, len, "request", |ps, out, n| unsafe {
        fhsm_pki_csr(ps, subject.as_ptr(), out, n)
    })
}

/// `pkiops_root`: a self-signed root, CA:TRUE, keyCertSign and cRLSign.
pub fn root(
    s: Handle,
    label: &[u8],
    subject: &CStr,
    serial: c_long,
    days: c_int,
    der: &mut [u8],
    len: &mut usize,
) -> Result<(), Error> {
    // SAFETY: as csr.
    signed_by(s, label, der, len, "certificate", |ps, out, n| unsafe {
        fhsm_pki_selfsigned(ps, subject.as_ptr(), serial, days, out, n)
    })
}

// --- tools/pkiops.h ---------------------------------------------------------------------------

/// A C string argument; C's strlen of NULL crashes, this aborts instead.
unsafe fn arg<'a>(p: *const c_char) -> &'a CStr {
    assert!(!p.is_null(), "a NULL string where tools/pkiops.h takes one");
    // SAFETY: the caller's C string.
    unsafe { CStr::from_ptr(p) }
}

fn put<T>(out: *mut T, v: T) {
    // SAFETY: the caller's output, null or writable.
    if let Some(o) = unsafe { out.as_mut() } {
        *o = v;
    }
}

fn status<T>(r: Result<T, Error>, e: *mut p11_err, ok: impl FnOnce(T)) -> c_int {
    match r {
        Ok(v) => {
            ok(v);
            0
        }
        Err(x) => fail(e, x),
    }
}

/// `pkiops_parse_slot`.
///
/// # Safety
/// `text` is a C string; `out` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_parse_slot(
    text: *const c_char,
    out: *mut c_long,
    e: *mut p11_err,
) -> c_int {
    status(crate::parse_slot(unsafe { arg(text) }.to_bytes()), e, |v| {
        put(out, v)
    })
}

/// `pkiops_alg_name`: NULL out of range.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_alg_name(a: c_uint) -> *const c_char {
    Alg::from_index(a).map_or(null(), |a| a.info().name.as_ptr())
}

/// `pkiops_alg_digest`: NULL out of range.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_alg_digest(a: c_uint) -> *const c_char {
    Alg::from_index(a).map_or(null(), |a| a.info().digest.as_ptr())
}

/// `pkiops_alg_list`.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_alg_list() -> *const c_char {
    keys::ALG_LIST.as_ptr()
}

/// `pkiops_alg_parse`.
///
/// # Safety
/// `name` is null or a C string; `out` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_alg_parse(
    name: *const c_char,
    out: *mut c_uint,
    e: *mut p11_err,
) -> c_int {
    let name = (!name.is_null()).then(|| unsafe { arg(name) }.to_bytes());
    status(Alg::parse(name), e, |a| put(out, a as c_uint))
}

/// `pkiops_key_alg`.
///
/// # Safety
/// `label` is a C string; `out` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_key_alg(
    session: Handle,
    label: *const c_char,
    out: *mut c_uint,
    e: *mut p11_err,
) -> c_int {
    status(key_alg(session, unsafe { arg(label) }.to_bytes()), e, |a| {
        put(out, a as c_uint)
    })
}

/// `pkiops_session_user`.
///
/// # Safety
/// `pin` has `pin_len` readable bytes; `session` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_session_user(
    slot: Handle,
    pin: *const u8,
    pin_len: usize,
    session: *mut Handle,
    e: *mut p11_err,
) -> c_int {
    let pin = if pin_len == 0 {
        &[][..]
    } else {
        unsafe { std::slice::from_raw_parts(pin, pin_len) }
    };
    status(session_user(slot, pin), e, |s| put(session, s))
}

/// `pkiops_session_close`.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_session_close(session: Handle) {
    session_close(session)
}

/// `pkiops_keygen`: the composite.
///
/// # Safety
/// As [`pkiops_keygen_alg`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_keygen(
    session: Handle,
    label: *const c_char,
    pub_: *mut Handle,
    priv_: *mut Handle,
    e: *mut p11_err,
) -> c_int {
    unsafe { pkiops_keygen_alg(session, label, Alg::Composite as c_uint, pub_, priv_, e) }
}

/// `pkiops_keygen_alg`.
///
/// # Safety
/// `label` is a C string; `pub_`, `priv_` and `e` null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_keygen_alg(
    session: Handle,
    label: *const c_char,
    a: c_uint,
    pub_: *mut Handle,
    priv_: *mut Handle,
    e: *mut p11_err,
) -> c_int {
    let Some(a) = Alg::from_index(a) else {
        return fail(e, Error::new(1, "no such algorithm\n"));
    };
    status(
        keygen_alg(session, unsafe { arg(label) }.to_bytes(), a),
        e,
        |(p, k)| {
            put(pub_, p);
            put(priv_, k);
        },
    )
}

/// The DER buffer of `pkiops_csr` and `pkiops_root`: `*der_len` bytes at `der`.
unsafe fn der_buf<'a>(der: *mut u8, der_len: *mut usize) -> (&'a mut [u8], &'a mut usize) {
    assert!(
        !der.is_null() && !der_len.is_null(),
        "pkiops_csr and pkiops_root write a DER buffer"
    );
    // SAFETY: the caller's contract.
    unsafe { (std::slice::from_raw_parts_mut(der, *der_len), &mut *der_len) }
}

/// `pkiops_csr`.
///
/// # Safety
/// `label` and `subject` are C strings; `der` has `*der_len` writable bytes; `e` null or
/// writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_csr(
    session: Handle,
    label: *const c_char,
    subject: *const c_char,
    der: *mut u8,
    der_len: *mut usize,
    e: *mut p11_err,
) -> c_int {
    let (label, subject) = unsafe { (arg(label).to_bytes(), arg(subject)) };
    let (buf, len) = unsafe { der_buf(der, der_len) };
    status(csr(session, label, subject, buf, len), e, |()| ())
}

/// `pkiops_root`.
///
/// # Safety
/// As [`pkiops_csr`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_root(
    session: Handle,
    label: *const c_char,
    subject: *const c_char,
    serial: c_long,
    days: c_int,
    der: *mut u8,
    der_len: *mut usize,
    e: *mut p11_err,
) -> c_int {
    let (label, subject) = unsafe { (arg(label).to_bytes(), arg(subject)) };
    let (buf, len) = unsafe { der_buf(der, der_len) };
    status(
        root(session, label, subject, serial, days, buf, len),
        e,
        |()| (),
    )
}
