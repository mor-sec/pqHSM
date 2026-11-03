//! PKCS#10 requests, self-signed roots and issued certificates over OpenSSL
//! (`src/fhsm_composite.c:482-1450`), in C's calls and with its return codes. OpenSSL assembles
//! the structures (names, validity, the SubjectPublicKeyInfo slot, the signatures); every
//! extension value comes from `crate::x509`. The C ABI around these is in `c_abi`.

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_void};
use std::ptr::{null, null_mut};

use super::composite::{cleanse, rv};
use crate::x509 as der;

type P = *mut c_void;

/// `struct asn1_string_st` (`openssl/asn1.h`, public): the BIT STRING flags are set directly,
/// as C does.
#[repr(C)]
struct Asn1String {
    length: c_int,
    kind: c_int,
    data: *mut u8,
    flags: c_long,
}

const ASN1_STRING_FLAG_BITS_LEFT: c_long = 0x08;
const V_ASN1_UNDEF: c_int = -1;
const V_ASN1_EOC: c_int = 0;
const V_ASN1_BOOLEAN: c_int = 1;
const V_ASN1_NULL: c_int = 5;
const V_ASN1_OBJECT: c_int = 6;
const MBSTRING_UTF8: c_int = 0x1000;
const NID_SUBJECT_KEY_IDENTIFIER: c_int = 82;
const NID_KEY_USAGE: c_int = 83;
const NID_SUBJECT_ALT_NAME: c_int = 85;
const NID_BASIC_CONSTRAINTS: c_int = 87;
const NID_AUTHORITY_KEY_IDENTIFIER: c_int = 90;
const NID_CRL_DISTRIBUTION_POINTS: c_int = 103;
const NID_EXT_KEY_USAGE: c_int = 126;
const NID_ID_PKIX_OCSP_NOCHECK: c_int = 369;
const NID_CRL_REASON: c_int = 141;
/// `FHSM_PKI_SIG_MAX`: the room every signer is given.
const SIG_MAX: usize = 8192;
/// `FHSM_PKI_BACKDATE_SECONDS`.
const BACKDATE: c_long = 3600;
/// `FHSM_CERT_OCSP_RESPONDER`.
pub const OCSP_RESPONDER: c_int = 1;

unsafe extern "C" {
    fn ASN1_BIT_STRING_new() -> P;
    fn ASN1_BIT_STRING_free(a: P);
    fn ASN1_BIT_STRING_set(a: P, d: *const u8, len: c_int) -> c_int;
    fn ASN1_INTEGER_free(a: P);
    fn ASN1_INTEGER_set(a: P, v: c_long) -> c_int;
    fn ASN1_OBJECT_free(a: P);
    fn ASN1_OCTET_STRING_free(a: P);
    fn ASN1_OCTET_STRING_new() -> P;
    fn ASN1_OCTET_STRING_set(a: P, d: *const u8, len: c_int) -> c_int;
    fn ASN1_STRING_dup(a: P) -> P;
    fn ASN1_STRING_free(a: P);
    fn ASN1_STRING_get0_data(a: P) -> *const u8;
    fn ASN1_STRING_length(a: P) -> c_int;
    fn BN_bin2bn(s: *const u8, len: c_int, ret: P) -> P;
    fn BN_free(a: P);
    fn BN_to_ASN1_INTEGER(bn: P, ai: P) -> P;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn CRYPTO_memdup(p: *const c_void, n: usize, file: *const c_char, line: c_int) -> *mut c_void;
    fn ERR_pop_to_mark() -> c_int;
    fn ERR_set_mark() -> c_int;
    fn EVP_PKEY_free(k: P);
    fn EVP_PKEY_get_raw_public_key(k: P, out: *mut u8, len: *mut usize) -> c_int;
    fn EVP_PKEY_new_raw_public_key_ex(
        libctx: P,
        kind: *const c_char,
        propq: *const c_char,
        key: *const u8,
        len: usize,
    ) -> P;
    fn OBJ_dup(o: P) -> P;
    fn OBJ_obj2txt(buf: *mut c_char, len: c_int, o: P, no_name: c_int) -> c_int;
    fn SHA1(d: *const u8, n: usize, md: *mut u8) -> *mut u8;
    fn X509_ALGOR_copy(dst: P, src: P) -> c_int;
    fn X509_ALGOR_free(a: P);
    fn X509_ALGOR_get0(o: *mut P, ptype: *mut c_int, pval: *mut P, a: P);
    fn X509_ALGOR_new() -> P;
    fn X509_EXTENSION_create_by_NID(ex: *mut P, nid: c_int, crit: c_int, data: P) -> P;
    fn X509_EXTENSION_free(e: P);
    fn X509_NAME_add_entry_by_txt(
        n: P,
        field: *const c_char,
        kind: c_int,
        bytes: *const u8,
        len: c_int,
        loc: c_int,
        set: c_int,
    ) -> c_int;
    fn X509_NAME_free(n: P);
    fn X509_NAME_new() -> P;
    fn X509_PUBKEY_free(k: P);
    fn X509_PUBKEY_get0_param(
        alg: *mut P,
        pk: *mut *const u8,
        pklen: *mut c_int,
        pa: *mut P,
        k: P,
    ) -> c_int;
    fn X509_PUBKEY_set0_param(k: P, o: P, ptype: c_int, pval: P, penc: *mut u8, n: c_int) -> c_int;
    fn X509_REQ_free(r: P);
    fn X509_REQ_get0_pubkey(r: P) -> P;
    fn X509_REQ_get0_signature(r: P, sig: *mut P, alg: *mut P);
    fn X509_REQ_get_X509_PUBKEY(r: P) -> P;
    fn X509_REQ_get_subject_name(r: P) -> P;
    fn X509_REQ_new() -> P;
    fn X509_REQ_set0_signature(r: P, sig: P);
    fn X509_REQ_set1_signature_algo(r: P, alg: P) -> c_int;
    fn X509_REQ_set_subject_name(r: P, n: P) -> c_int;
    fn X509_REQ_set_version(r: P, v: c_long) -> c_int;
    fn X509_REQ_verify(r: P, k: P) -> c_int;
    fn ASN1_ENUMERATED_free(a: P);
    fn ASN1_ENUMERATED_new() -> P;
    fn ASN1_ENUMERATED_set(a: P, v: c_long) -> c_int;
    fn ASN1_TIME_free(t: P);
    fn ASN1_TIME_set(t: P, when: libc::time_t) -> P;
    fn X509V3_EXT_i2d(nid: c_int, crit: c_int, ext: P) -> P;
    fn X509_REVOKED_add_ext(r: P, e: P, loc: c_int) -> c_int;
    fn X509_REVOKED_free(r: P);
    fn X509_REVOKED_new() -> P;
    fn X509_REVOKED_set_revocationDate(r: P, t: P) -> c_int;
    fn X509_REVOKED_set_serialNumber(r: P, sn: P) -> c_int;
    fn i2d_ASN1_TIME(t: P, out: *mut *mut u8) -> c_int;
    fn i2d_X509_NAME(n: P, out: *mut *mut u8) -> c_int;
    fn i2d_X509_REVOKED(r: P, out: *mut *mut u8) -> c_int;
    fn X509_add_ext(x: P, e: P, loc: c_int) -> c_int;
    fn X509_free(x: P);
    fn X509_get0_signature(sig: *mut P, alg: *mut P, x: P);
    fn X509_get0_subject_key_id(x: P) -> P;
    fn X509_get0_tbs_sigalg(x: P) -> P;
    fn X509_get_X509_PUBKEY(x: P) -> P;
    fn X509_get_serialNumber(x: P) -> P;
    fn X509_get_subject_name(x: P) -> P;
    fn X509_getm_notAfter(x: P) -> P;
    fn X509_getm_notBefore(x: P) -> P;
    fn X509_gmtime_adj(t: P, adj: c_long) -> P;
    fn X509_new() -> P;
    fn X509_set_issuer_name(x: P, n: P) -> c_int;
    fn X509_set_serialNumber(x: P, sn: P) -> c_int;
    fn X509_set_subject_name(x: P, n: P) -> c_int;
    fn X509_set_version(x: P, v: c_long) -> c_int;
    fn a2i_IPADDRESS(ip: *const c_char) -> P;
    fn d2i_PUBKEY(a: *mut P, pp: *mut *const u8, len: c_long) -> P;
    fn d2i_X509(a: *mut P, pp: *mut *const u8, len: c_long) -> P;
    fn d2i_X509_ALGOR(a: *mut P, pp: *mut *const u8, len: c_long) -> P;
    fn d2i_X509_PUBKEY(a: *mut P, pp: *mut *const u8, len: c_long) -> P;
    fn d2i_X509_REQ(a: *mut P, pp: *mut *const u8, len: c_long) -> P;
    fn i2d_PUBKEY(k: P, out: *mut *mut u8) -> c_int;
    fn i2d_X509(x: P, out: *mut *mut u8) -> c_int;
    fn i2d_X509_REQ(r: P, out: *mut *mut u8) -> c_int;
    fn i2d_re_X509_REQ_tbs(r: P, out: *mut *mut u8) -> c_int;
    fn i2d_re_X509_tbs(x: P, out: *mut *mut u8) -> c_int;
    fn CMS_ContentInfo_free(ci: P);
    fn CMS_SignerInfo_cert_cmp(si: P, x: P) -> c_int;
    fn CMS_SignerInfo_get0_algs(si: P, pk: *mut P, signer: *mut P, pdig: *mut P, psig: *mut P);
    fn CMS_SignerInfo_get0_signature(si: P) -> P;
    fn CMS_get0_SignerInfos(ci: P) -> P;
    fn CMS_get1_certs(ci: P) -> P;
    fn CMS_signed_get_attr(si: P, loc: c_int) -> P;
    fn CMS_signed_get_attr_by_NID(si: P, nid: c_int, lastpos: c_int) -> c_int;
    fn EVP_DigestVerify(m: P, sig: *const u8, sl: usize, tbs: *const u8, n: usize) -> c_int;
    fn EVP_MD_CTX_free(m: P);
    fn EVP_MD_CTX_new() -> P;
    fn EVP_MD_fetch(lib: P, name: *const c_char, props: *const c_char) -> P;
    fn EVP_MD_free(md: P);
    fn EVP_MD_get_size(md: P) -> c_int;
    fn EVP_MD_get_type(md: P) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_mgf1_md_name(pc: P, md: *const c_char, props: *const c_char) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_padding(pc: P, pad: c_int) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_pss_saltlen(pc: P, len: c_int) -> c_int;
    fn EVP_PKEY_is_a(k: P, name: *const c_char) -> c_int;
    fn OBJ_nid2obj(nid: c_int) -> P;
    fn OBJ_obj2nid(o: P) -> c_int;
    fn OPENSSL_sk_num(st: P) -> c_int;
    fn OPENSSL_sk_pop_free(st: P, free: unsafe extern "C" fn(P));
    fn OPENSSL_sk_value(st: P, i: c_int) -> P;
    fn X509_ALGOR_set0(a: P, o: P, ptype: c_int, pval: P) -> c_int;
    fn X509_ATTRIBUTE_get0_type(at: P, idx: c_int) -> P;
    fn X509_get0_pubkey(x: P) -> P;
    fn X509_get_issuer_name(x: P) -> P;
    fn d2i_CMS_ContentInfo(a: *mut P, pp: *mut *const u8, len: c_long) -> P;
    fn i2d_ASN1_INTEGER(a: P, out: *mut *mut u8) -> c_int;
    fn i2d_CMS_ContentInfo(ci: P, out: *mut *mut u8) -> c_int;
    fn i2d_X509_ALGOR(a: P, out: *mut *mut u8) -> c_int;
}

/// An OpenSSL object, freed on drop; None if the constructor returned NULL.
struct Own(P, unsafe extern "C" fn(P));

impl Own {
    fn new(p: P, free: unsafe extern "C" fn(P)) -> Option<Self> {
        (!p.is_null()).then_some(Self(p, free))
    }
}

impl Drop for Own {
    fn drop(&mut self) {
        // SAFETY: self.0 came from the allocator self.1 frees, and is freed once
        unsafe { (self.1)(self.0) }
    }
}

/// `OPENSSL_free`.
fn openssl_free(p: *mut c_void) {
    // SAFETY: p came from OpenSSL's allocator, or is NULL
    unsafe { CRYPTO_free(p, c"".as_ptr(), 0) }
}

/// An `i2d_*` result as bytes.
fn i2d(f: unsafe extern "C" fn(P, *mut *mut u8) -> c_int, o: P) -> Option<Vec<u8>> {
    let mut p = null_mut();
    // SAFETY: o is a live object of f's type; OpenSSL allocates the output
    let n = unsafe { f(o, &mut p) };
    // SAFETY: n bytes at p when n > 0
    let v = (n > 0).then(|| unsafe { std::slice::from_raw_parts(p, n as usize) }.to_vec());
    openssl_free(p.cast());
    v
}

/// A `d2i_*` over `b`: the object (NULL if it does not parse) and how many bytes it left.
fn d2i(f: unsafe extern "C" fn(*mut P, *mut *const u8, c_long) -> P, b: &[u8]) -> (P, usize) {
    let mut q = b.as_ptr();
    // SAFETY: b.len() readable bytes; q only advances within them
    let o = unsafe { f(null_mut(), &mut q, b.len() as c_long) };
    (o, b.len() - (q as usize - b.as_ptr() as usize))
}

/// A signing callback: the to-be-signed bytes and SIG_MAX bytes of room; the signature's length.
pub type SignFn<'a> = dyn FnMut(&[u8], &mut [u8]) -> Result<usize, u32> + 'a;

/// The signer a builder signs with: its AlgorithmIdentifier and the callback, given SIG_MAX
/// bytes.
pub struct Signer<'a> {
    pub algid: &'a [u8],
    pub sign: &'a mut SignFn<'a>,
}

impl Signer<'_> {
    /// The signature over `tbs`, through a SIG_MAX buffer wiped afterwards.
    fn sign(&mut self, tbs: &[u8], with: impl FnOnce(&[u8]) -> u32) -> u32 {
        let mut sig = vec![0u8; SIG_MAX];
        let r = match (self.sign)(tbs, &mut sig) {
            Ok(n) => with(&sig[..n]),
            Err(r) => r,
        };
        cleanse(&mut sig);
        r
    }
}

/// `name_from_oneline`.
fn name(s: &[u8]) -> Option<Own> {
    let parts = der::oneline(s)?;
    // SAFETY: a fresh name; every pointer below is live for its call
    unsafe {
        let n = Own::new(X509_NAME_new(), X509_NAME_free)?;
        for (field, val) in parts {
            let field = CString::new(field).ok()?;
            let ok = X509_NAME_add_entry_by_txt(
                n.0,
                field.as_ptr(),
                MBSTRING_UTF8,
                val.as_ptr(),
                val.len() as c_int,
                -1,
                0,
            );
            if ok != 1 {
                return None;
            }
        }
        Some(n)
    }
}

/// `spki_into_slot`: the SubjectPublicKeyInfo in `from` copied into `slot`, its parameters as
/// they came (absent, NULL, or an OID).
fn spki_into_slot(slot: P, from: P) -> u32 {
    let (mut kalg, mut pk, mut pkl, mut a) = (null_mut(), null(), 0, null_mut());
    // SAFETY: from and slot are live X509_PUBKEYs; set0_param takes ownership on success
    unsafe {
        if slot.is_null()
            || from.is_null()
            || X509_PUBKEY_get0_param(&mut kalg, &mut pk, &mut pkl, &mut a, from) != 1
            || pkl <= 0
        {
            return rv::ARGUMENTS_BAD;
        }
        let (mut o, mut ptype, mut pval) = (null_mut(), V_ASN1_UNDEF, null_mut());
        X509_ALGOR_get0(&mut o, &mut ptype, &mut pval, a);
        // DIV-049: a BOOLEAN's pval is its value, not a string; C dup'd it as one and crashed
        if ptype == V_ASN1_BOOLEAN {
            return rv::ARGUMENTS_BAD;
        }
        let pdup = match ptype {
            V_ASN1_OBJECT => OBJ_dup(pval),
            V_ASN1_UNDEF | V_ASN1_NULL => null_mut(),
            _ => ASN1_STRING_dup(pval),
        };
        let odup = OBJ_dup(o);
        let penc = CRYPTO_memdup(pk.cast(), pkl as usize, c"".as_ptr(), 0).cast::<u8>();
        let need_param = ptype != V_ASN1_UNDEF && ptype != V_ASN1_NULL;
        if !odup.is_null()
            && !penc.is_null()
            && (!need_param || !pdup.is_null())
            && X509_PUBKEY_set0_param(slot, odup, ptype, pdup, penc, pkl) == 1
        {
            // X509_ALGOR_set0 neither takes nor frees a type-0 (EOC) parameter; C leaks it the same way
            if ptype == V_ASN1_EOC {
                ASN1_STRING_free(pdup);
            }
            return rv::OK;
        }
        ASN1_OBJECT_free(odup);
        openssl_free(penc.cast());
        if ptype == V_ASN1_OBJECT {
            ASN1_OBJECT_free(pdup);
        } else {
            ASN1_STRING_free(pdup);
        }
        rv::FUNCTION_FAILED
    }
}

/// `spki_der_into_slot`: OpenSSL's errors from a key it cannot load are popped, not left.
fn spki_der_into_slot(slot: P, spki: &[u8]) -> u32 {
    if spki.is_empty() {
        return rv::ARGUMENTS_BAD;
    }
    // SAFETY: marks are balanced
    let (xp, left) = unsafe {
        ERR_set_mark();
        let r = d2i(d2i_X509_PUBKEY, spki);
        ERR_pop_to_mark();
        r
    };
    let Some(xp) = Own::new(xp, X509_PUBKEY_free) else {
        return rv::ARGUMENTS_BAD;
    };
    if left != 0 {
        return rv::ARGUMENTS_BAD;
    }
    spki_into_slot(slot, xp.0)
}

/// `algor_from_der`: all of `der`, and nothing more.
fn algor_from_der(dst: P, der: &[u8]) -> bool {
    if dst.is_null() || der.is_empty() {
        return false;
    }
    let mut q = der.as_ptr();
    // SAFETY: der.len() readable bytes; a is freed below
    unsafe {
        let a = d2i_X509_ALGOR(null_mut(), &mut q, der.len() as c_long);
        let ok = !a.is_null() && q == der.as_ptr_range().end && X509_ALGOR_copy(dst, a) == 1;
        X509_ALGOR_free(a);
        ok
    }
}

/// `set_sig_bits`: an integral number of octets, no unused bits.
fn set_sig_bits(bs: P, sig: &[u8]) -> bool {
    // SAFETY: bs is a live ASN1_BIT_STRING, whose public layout is Asn1String
    unsafe {
        if ASN1_BIT_STRING_set(bs, sig.as_ptr(), sig.len() as c_int) != 1 {
            return false;
        }
        let s = bs.cast::<Asn1String>();
        (*s).flags &= !(ASN1_STRING_FLAG_BITS_LEFT | 0x07);
        (*s).flags |= ASN1_STRING_FLAG_BITS_LEFT;
    }
    true
}

/// One extension, by NID, from its DER value.
fn add_ext(x: P, nid: c_int, critical: bool, value: &[u8]) -> bool {
    // SAFETY: x is a live X509; os and e are freed below (add_ext copies)
    unsafe {
        let Some(os) = Own::new(ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free) else {
            return false;
        };
        if ASN1_OCTET_STRING_set(os.0, value.as_ptr(), value.len() as c_int) != 1 {
            return false;
        }
        let e = X509_EXTENSION_create_by_NID(null_mut(), nid, c_int::from(critical), os.0);
        let ok = !e.is_null() && X509_add_ext(x, e, -1) == 1;
        X509_EXTENSION_free(e);
        ok
    }
}

/// `add_ski`: SHA-1 of the subjectPublicKey BIT STRING's value (RFC 5280 4.2.1.2 (1)).
fn add_ski(x: P, slot: P) -> bool {
    let (mut pk, mut pkl) = (null(), 0);
    let mut md = [0u8; 20];
    // SAFETY: slot is a live X509_PUBKEY; pk has pkl bytes
    unsafe {
        if X509_PUBKEY_get0_param(null_mut(), &mut pk, &mut pkl, null_mut(), slot) != 1 || pkl <= 0
        {
            return false;
        }
        SHA1(pk, pkl as usize, md.as_mut_ptr());
    }
    add_ext(x, NID_SUBJECT_KEY_IDENTIFIER, false, &der::ski(&md))
}

/// `sign_certificate`: both AlgorithmIdentifiers from the same DER, then the signature.
fn sign_certificate(x: P, s: &mut Signer) -> u32 {
    let (mut cs, mut ca) = (null_mut(), null_mut());
    // SAFETY: x is a live X509; the sigalg fields are written in place, as C does
    unsafe {
        if !algor_from_der(X509_get0_tbs_sigalg(x), s.algid) {
            return rv::ARGUMENTS_BAD;
        }
        X509_get0_signature(&mut cs, &mut ca, x);
        if cs.is_null() || ca.is_null() {
            return rv::FUNCTION_FAILED;
        }
        if !algor_from_der(ca, s.algid) {
            return rv::ARGUMENTS_BAD;
        }
    }
    let Some(tbs) = i2d(i2d_re_X509_tbs, x) else {
        return rv::FUNCTION_FAILED;
    };
    s.sign(&tbs, |sig| {
        if set_sig_bits(cs, sig) {
            rv::OK
        } else {
            rv::FUNCTION_FAILED
        }
    })
}

/// `fhsm_pki_csr` after its argument checks.
pub fn csr(s: &mut Signer, spki: &[u8], subject: &[u8]) -> Result<Vec<u8>, u32> {
    // SAFETY: every object is owned below and live for each call
    unsafe {
        let req = Own::new(X509_REQ_new(), X509_REQ_free);
        let name = name(subject);
        let (Some(req), Some(name)) = (req, name) else {
            return Err(rv::ARGUMENTS_BAD);
        };
        if X509_REQ_set_version(req.0, 0) != 1 || X509_REQ_set_subject_name(req.0, name.0) != 1 {
            return Err(rv::FUNCTION_FAILED);
        }
        ok(spki_der_into_slot(X509_REQ_get_X509_PUBKEY(req.0), spki))?;
        let sa = Own::new(X509_ALGOR_new(), X509_ALGOR_free).ok_or(rv::HOST_MEMORY)?;
        if !algor_from_der(sa.0, s.algid) {
            return Err(rv::ARGUMENTS_BAD);
        }
        if X509_REQ_set1_signature_algo(req.0, sa.0) != 1 {
            return Err(rv::FUNCTION_FAILED);
        }
        let tbs = i2d(i2d_re_X509_REQ_tbs, req.0).ok_or(rv::FUNCTION_FAILED)?;
        ok(s.sign(&tbs, |sig| {
            let Some(bs) = Own::new(ASN1_BIT_STRING_new(), ASN1_BIT_STRING_free) else {
                return rv::HOST_MEMORY;
            };
            if !set_sig_bits(bs.0, sig) {
                return rv::FUNCTION_FAILED;
            }
            X509_REQ_set0_signature(req.0, bs.0);
            std::mem::forget(bs); // owned by req now
            rv::OK
        }))?;
        i2d(i2d_X509_REQ, req.0).ok_or(rv::FUNCTION_FAILED)
    }
}

fn ok(r: u32) -> Result<(), u32> {
    if r == rv::OK { Ok(()) } else { Err(r) }
}

/// notBefore an hour back, notAfter `days` on, both from time() inside libcrypto.
fn validity(x: P, days: c_int) -> bool {
    // SAFETY: x is a live X509
    unsafe {
        !X509_gmtime_adj(X509_getm_notBefore(x), -BACKDATE).is_null()
            && !X509_gmtime_adj(X509_getm_notAfter(x), c_long::from(days) * 86400).is_null()
    }
}

/// `fhsm_pki_selfsigned` after its argument checks.
pub fn selfsigned(
    s: &mut Signer,
    spki: &[u8],
    subject: &[u8],
    serial: c_long,
    days: c_int,
) -> Result<Vec<u8>, u32> {
    // SAFETY: every object is owned below and live for each call
    unsafe {
        let x = Own::new(X509_new(), X509_free);
        let name = name(subject);
        let (Some(x), Some(name)) = (x, name) else {
            return Err(rv::ARGUMENTS_BAD);
        };
        if X509_set_version(x.0, 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(x.0), serial) != 1
            || !validity(x.0, days)
            || X509_set_subject_name(x.0, name.0) != 1
            || X509_set_issuer_name(x.0, name.0) != 1
        {
            return Err(rv::FUNCTION_FAILED);
        }
        ok(spki_der_into_slot(X509_get_X509_PUBKEY(x.0), spki))?;
        if !(add_ext(x.0, NID_BASIC_CONSTRAINTS, true, der::BC_CA)
            && add_ext(x.0, NID_KEY_USAGE, true, der::KU_CA)
            && add_ski(x.0, X509_get_X509_PUBKEY(x.0)))
        {
            return Err(rv::FUNCTION_FAILED);
        }
        ok(sign_certificate(x.0, s))?;
        i2d(i2d_X509, x.0).ok_or(rv::FUNCTION_FAILED)
    }
}

/// `fhsm_composite_raw_pub` after the blob is unpacked and the room checked: mldsaPK || tradPK
/// written into `out` (RAW_PUB bytes) in place, as C writes it.
pub fn raw_pub(pq: &[u8], trad: &[u8], out: &mut [u8]) -> u32 {
    let kpq = Own::new(d2i(d2i_PUBKEY, pq).0, EVP_PKEY_free);
    let ktr = Own::new(d2i(d2i_PUBKEY, trad).0, EVP_PKEY_free);
    let (Some(kpq), Some(ktr)) = (kpq, ktr) else {
        return rv::KEY_HANDLE_INVALID;
    };
    let (mut n1, mut n2) = (der::RAW_PQ_PUB, der::RAW_TRAD_PUB);
    // SAFETY: out has RAW_PUB writable bytes; each call writes at most its n
    unsafe {
        if EVP_PKEY_get_raw_public_key(kpq.0, out.as_mut_ptr(), &mut n1) != 1
            || n1 != der::RAW_PQ_PUB
        {
            return rv::FUNCTION_FAILED;
        }
        let t = out[n1..].as_mut_ptr();
        if EVP_PKEY_get_raw_public_key(ktr.0, t, &mut n2) != 1 || n2 != der::RAW_TRAD_PUB {
            return rv::FUNCTION_FAILED;
        }
    }
    rv::OK
}

/// `fhsm_composite_pub_from_raw` after its checks: each component's SubjectPublicKeyInfo DER.
pub fn pub_from_raw(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), u32> {
    let (pq, trad) = raw.split_at(der::RAW_PQ_PUB);
    // SAFETY: each slice is readable for its length
    let (kq, kt) = unsafe {
        (
            EVP_PKEY_new_raw_public_key_ex(
                null_mut(),
                c"ML-DSA-65".as_ptr(),
                null(),
                pq.as_ptr(),
                pq.len(),
            ),
            EVP_PKEY_new_raw_public_key_ex(
                null_mut(),
                c"ED25519".as_ptr(),
                null(),
                trad.as_ptr(),
                trad.len(),
            ),
        )
    };
    let (kq, kt) = (Own::new(kq, EVP_PKEY_free), Own::new(kt, EVP_PKEY_free));
    let (Some(kq), Some(kt)) = (kq, kt) else {
        return Err(rv::KEY_HANDLE_INVALID);
    };
    match (i2d(i2d_PUBKEY, kq.0), i2d(i2d_PUBKEY, kt.0)) {
        (Some(q), Some(t)) => Ok((q, t)),
        _ => Err(rv::FUNCTION_FAILED),
    }
}

/// `pub_from_slot`: the composite public-key blob for the key in `xp`, which must be one.
fn pub_from_slot(xp: P) -> Result<Vec<u8>, u32> {
    let (mut pk, mut pkl, mut a) = (null(), 0, null_mut());
    // SAFETY: xp is a live X509_PUBKEY or NULL; pk has pkl bytes
    let raw = unsafe {
        if xp.is_null() || X509_PUBKEY_get0_param(null_mut(), &mut pk, &mut pkl, &mut a, xp) != 1 {
            return Err(rv::ARGUMENTS_BAD);
        }
        if oid(a) != der::OID_COMPOSITE {
            return Err(rv::KEY_TYPE_INCONSISTENT);
        }
        std::slice::from_raw_parts(pk, pkl.max(0) as usize)
    };
    if raw.len() != der::RAW_PUB {
        return Err(rv::ARGUMENTS_BAD);
    }
    blob_from_raw(raw)
}

/// `fhsm_composite_pub_from_raw` after its checks: the composite public-key blob.
fn blob_from_raw(raw: &[u8]) -> Result<Vec<u8>, u32> {
    let (q, t) = pub_from_raw(raw)?;
    let n = crate::composite::blob_len(&q, &t).ok_or(rv::FUNCTION_FAILED)?;
    let mut blob = vec![0; n];
    crate::composite::pack(crate::composite::MLDSA65_ED25519_SHA512, &q, &t, &mut blob);
    Ok(blob)
}

/// The dotted OID of an AlgorithmIdentifier.
fn oid(a: P) -> String {
    let (mut o, mut pt, mut pv) = (null_mut(), 0, null_mut());
    let mut buf = [0 as c_char; 128];
    // SAFETY: a is a live X509_ALGOR; buf is 128 bytes, NUL-terminated by OBJ_obj2txt
    unsafe {
        X509_ALGOR_get0(&mut o, &mut pt, &mut pv, a);
        OBJ_obj2txt(buf.as_mut_ptr(), buf.len() as c_int, o, 1);
        std::ffi::CStr::from_ptr(buf.as_ptr())
            .to_string_lossy()
            .into_owned()
    }
}

/// `csr_proof_of_possession`: the request's signature, by its own algorithm, over its own key.
fn proof_of_possession(req: P) -> u32 {
    let (mut sig, mut alg) = (null_mut(), null_mut());
    // SAFETY: req is a live X509_REQ; sig has its length's bytes
    unsafe {
        X509_REQ_get0_signature(req, &mut sig, &mut alg);
        if sig.is_null() || alg.is_null() {
            return rv::ARGUMENTS_BAD;
        }
        if oid(alg) == der::OID_COMPOSITE {
            let public = match pub_from_slot(X509_REQ_get_X509_PUBKEY(req)) {
                Ok(p) => p,
                Err(r) => return r,
            };
            let Some(tbs) = i2d(i2d_re_X509_REQ_tbs, req) else {
                return rv::FUNCTION_FAILED;
            };
            let r = super::c_abi::fhsm_composite_verify(
                crate::composite::MLDSA65_ED25519_SHA512,
                public.as_ptr(),
                public.len(),
                tbs.as_ptr(),
                tbs.len(),
                null(),
                0,
                ASN1_STRING_get0_data(sig),
                ASN1_STRING_length(sig) as usize,
            );
            return if r == rv::OK {
                rv::OK
            } else {
                rv::SIGNATURE_INVALID
            };
        }
        ERR_set_mark();
        let k = X509_REQ_get0_pubkey(req);
        let r = if k.is_null() {
            -1
        } else {
            X509_REQ_verify(req, k)
        };
        ERR_pop_to_mark();
        if k.is_null() {
            rv::MECHANISM_INVALID
        } else if r == 1 {
            rv::OK
        } else {
            rv::SIGNATURE_INVALID
        }
    }
}

/// What `fhsm_pki_issue` is asked to certify, besides the request.
pub struct Issue<'a> {
    pub ca: &'a [u8],
    pub csr: &'a [u8],
    pub subject: Option<&'a [u8]>,
    pub san: Option<&'a [u8]>,
    /// NULL entries as None; refused when reached.
    pub crl_urls: &'a [Option<&'a [u8]>],
    pub profile: c_int,
    pub days: c_int,
}

/// `fhsm_pki_issue` after its argument checks.
pub fn issue(
    s: &mut Signer,
    i: &Issue,
    rng: &mut dyn FnMut(&mut [u8]) -> u32,
) -> Result<Vec<u8>, u32> {
    let ca = Own::new(d2i(d2i_X509, i.ca).0, X509_free);
    let req = Own::new(d2i(d2i_X509_REQ, i.csr).0, X509_REQ_free);
    let (Some(ca), Some(req)) = (ca, req) else {
        return Err(rv::ARGUMENTS_BAD);
    };
    ok(proof_of_possession(req.0))?;
    // SAFETY: every object is owned and live for each call
    unsafe {
        let x = Own::new(X509_new(), X509_free).ok_or(rv::HOST_MEMORY)?;
        if X509_set_version(x.0, 2) != 1 {
            return Err(rv::FUNCTION_FAILED);
        }
        let mut sn = [0u8; 20];
        if rng(&mut sn) != rv::OK {
            return Err(rv::FUNCTION_FAILED);
        }
        sn[0] &= 0x7F; // positive (RFC 5280 4.1.2.2)
        if sn[0] == 0 {
            sn[0] = 1; // and no leading zero octet
        }
        let bn = Own::new(
            BN_bin2bn(sn.as_ptr(), sn.len() as c_int, null_mut()),
            BN_free,
        )
        .ok_or(rv::HOST_MEMORY)?;
        let ai = Own::new(BN_to_ASN1_INTEGER(bn.0, null_mut()), ASN1_INTEGER_free)
            .ok_or(rv::HOST_MEMORY)?;
        if X509_set_serialNumber(x.0, ai.0) != 1
            || !validity(x.0, i.days)
            || X509_set_issuer_name(x.0, X509_get_subject_name(ca.0)) != 1
        {
            return Err(rv::FUNCTION_FAILED);
        }
        let subject_set = match i.subject {
            Some(s) => {
                let n = name(s).ok_or(rv::ARGUMENTS_BAD)?;
                X509_set_subject_name(x.0, n.0)
            }
            None => X509_set_subject_name(x.0, X509_REQ_get_subject_name(req.0)),
        };
        if subject_set != 1 {
            return Err(rv::FUNCTION_FAILED);
        }
        ok(spki_into_slot(
            X509_get_X509_PUBKEY(x.0),
            X509_REQ_get_X509_PUBKEY(req.0),
        ))?;
        // the CA's extensions, never the applicant's
        let mut done = add_ext(x.0, NID_BASIC_CONSTRAINTS, true, der::BC_END_ENTITY)
            && add_ext(x.0, NID_KEY_USAGE, true, der::KU_END_ENTITY);
        if done && i.profile == OCSP_RESPONDER {
            done = add_ext(x.0, NID_EXT_KEY_USAGE, false, der::EKU_OCSP_SIGNING)
                && add_ext(x.0, NID_ID_PKIX_OCSP_NOCHECK, false, der::OCSP_NOCHECK);
        }
        done = done && add_ski(x.0, X509_get_X509_PUBKEY(x.0));
        let caskid = X509_get0_subject_key_id(ca.0);
        if done && !caskid.is_null() {
            let id = std::slice::from_raw_parts(
                ASN1_STRING_get0_data(caskid),
                ASN1_STRING_length(caskid) as usize,
            );
            done = add_ext(x.0, NID_AUTHORITY_KEY_IDENTIFIER, false, &der::akid(id));
        }
        if !done {
            return Err(rv::FUNCTION_FAILED);
        }
        if let Some(san) = i.san {
            let v = der::san(san, ip_address).ok_or(rv::ARGUMENTS_BAD)?;
            if !add_ext(x.0, NID_SUBJECT_ALT_NAME, false, &v) {
                return Err(rv::FUNCTION_FAILED);
            }
        }
        if !i.crl_urls.is_empty() {
            let mut urls = Vec::with_capacity(i.crl_urls.len());
            for u in i.crl_urls {
                match u {
                    Some(u) if der::crl_uri_ok(u) => urls.push(*u),
                    _ => return Err(rv::ARGUMENTS_BAD),
                }
            }
            if !add_ext(x.0, NID_CRL_DISTRIBUTION_POINTS, false, &der::crl_dp(&urls)) {
                return Err(rv::FUNCTION_FAILED);
            }
        }
        ok(sign_certificate(x.0, s))?;
        i2d(i2d_X509, x.0).ok_or(rv::FUNCTION_FAILED)
    }
}

/// a2i_IPADDRESS: an IPv4 or IPv6 address's octets, or None.
fn ip_address(v: &[u8]) -> Option<Vec<u8>> {
    let c = CString::new(v).ok()?;
    // SAFETY: a C string; the octet string is freed below
    unsafe {
        let os = Own::new(a2i_IPADDRESS(c.as_ptr()), ASN1_OCTET_STRING_free)?;
        Some(
            std::slice::from_raw_parts(
                ASN1_STRING_get0_data(os.0),
                ASN1_STRING_length(os.0) as usize,
            )
            .to_vec(),
        )
    }
}

fn refused(r: der::Refused) -> u32 {
    match r {
        der::Refused::Arguments => rv::ARGUMENTS_BAD,
        der::Refused::TooLong => rv::FUNCTION_FAILED,
    }
}

/// The signature over `tbs` and the structure around it, which `wrap` builds from it.
fn sign_and_wrap(
    s: &mut Signer,
    tbs: &[u8],
    wrap: impl FnOnce(&[u8]) -> Result<Vec<u8>, der::Refused>,
) -> Result<Vec<u8>, u32> {
    let mut out = None;
    ok(s.sign(tbs, |sig| match wrap(sig) {
        Ok(v) => {
            out = Some(v);
            rv::OK
        }
        Err(e) => refused(e),
    }))?;
    out.ok_or(rv::FUNCTION_FAILED)
}

/// One `fhsm_composite_revoked_t`: the serial an unsigned magnitude (empty if absent), the
/// date in seconds since the epoch, an RFC 5280 5.3.1 reason or -1.
pub struct Revoked<'a> {
    pub serial: &'a [u8],
    pub date: i64,
    pub reason: c_int,
}

/// `revoked_one`: OpenSSL builds the entry. BN_bin2bn gives the INTEGER its leading zero
/// when the top bit is set; ASN1_TIME_set picks UTCTime or GeneralizedTime by the year.
fn revoked_entry(r: &Revoked) -> Result<Vec<u8>, u32> {
    // SAFETY: every object is owned below and live for each call
    unsafe {
        let x = Own::new(X509_REVOKED_new(), X509_REVOKED_free).ok_or(rv::HOST_MEMORY)?;
        if r.serial.is_empty() {
            return Err(rv::ARGUMENTS_BAD);
        }
        let bn = Own::new(
            BN_bin2bn(r.serial.as_ptr(), r.serial.len() as c_int, null_mut()),
            BN_free,
        )
        .ok_or(rv::HOST_MEMORY)?;
        let sn = Own::new(BN_to_ASN1_INTEGER(bn.0, null_mut()), ASN1_INTEGER_free);
        let rd = Own::new(
            ASN1_TIME_set(null_mut(), r.date as libc::time_t),
            ASN1_TIME_free,
        );
        let (Some(sn), Some(rd)) = (sn, rd) else {
            return Err(rv::HOST_MEMORY);
        };
        if X509_REVOKED_set_serialNumber(x.0, sn.0) != 1
            || X509_REVOKED_set_revocationDate(x.0, rd.0) != 1
        {
            return Err(rv::FUNCTION_FAILED);
        }
        if r.reason >= 0 {
            // removeFromCRL (8) belongs to delta CRLs, which this does not produce
            if r.reason == 7 || r.reason == 8 || r.reason > 10 {
                return Err(rv::ARGUMENTS_BAD);
            }
            let e = Own::new(ASN1_ENUMERATED_new(), ASN1_ENUMERATED_free);
            let ext = e
                .as_ref()
                .filter(|e| ASN1_ENUMERATED_set(e.0, c_long::from(r.reason)) == 1)
                .and_then(|e| {
                    Own::new(X509V3_EXT_i2d(NID_CRL_REASON, 0, e.0), X509_EXTENSION_free)
                });
            if !ext.is_some_and(|ext| X509_REVOKED_add_ext(x.0, ext.0, -1) == 1) {
                return Err(rv::FUNCTION_FAILED);
            }
        }
        i2d(i2d_X509_REVOKED, x.0).ok_or(rv::FUNCTION_FAILED)
    }
}

/// An ASN1_TIME for `when`, DER-encoded: None from ASN1_TIME_set (a year it cannot write) is
/// HOST_MEMORY, as C reports it.
fn time_der(when: libc::time_t) -> Result<Own, u32> {
    // SAFETY: a fresh object
    Own::new(unsafe { ASN1_TIME_set(null_mut(), when) }, ASN1_TIME_free).ok_or(rv::HOST_MEMORY)
}

/// `fhsm_pki_crl` after its argument checks: the issuer is the CA's subject, thisUpdate is
/// time() inside libcrypto's caller, nextUpdate `days` on; crlExtensions are the CA's key
/// identifier and `crl_number`.
pub fn crl(
    s: &mut Signer,
    ca: &[u8],
    revoked: &[Revoked],
    crl_number: u64,
    days: c_int,
) -> Result<Vec<u8>, u32> {
    let ca = Own::new(d2i(d2i_X509, ca).0, X509_free).ok_or(rv::ARGUMENTS_BAD)?;
    // SAFETY: ca is a live X509
    let issuer =
        i2d(i2d_X509_NAME, unsafe { X509_get_subject_name(ca.0) }).ok_or(rv::FUNCTION_FAILED)?;
    // SAFETY: time(2) with no output pointer
    let now = unsafe { libc::time(null_mut()) };
    let (t1, t2) = (
        time_der(now),
        time_der(now + libc::time_t::from(days) * 86400),
    );
    let (Ok(t1), Ok(t2)) = (t1, t2) else {
        return Err(rv::HOST_MEMORY);
    };
    let this = i2d(i2d_ASN1_TIME, t1.0);
    let next = i2d(i2d_ASN1_TIME, t2.0);
    let (Some(this), Some(next)) = (this, next) else {
        return Err(rv::FUNCTION_FAILED);
    };
    // absent, not empty, when there is nothing to list (RFC 5280 5.1.2.6)
    let list = if revoked.is_empty() {
        None
    } else {
        let mut all = Vec::new();
        for r in revoked {
            all.extend(revoked_entry(r)?);
        }
        Some(der::sequence(&all).map_err(|_| rv::FUNCTION_FAILED)?)
    };
    // SAFETY: ca is a live X509; the key identifier is read while it lives
    let skid = unsafe {
        let k = X509_get0_subject_key_id(ca.0);
        (!k.is_null()).then(|| {
            std::slice::from_raw_parts(ASN1_STRING_get0_data(k), ASN1_STRING_length(k) as usize)
        })
    };
    let exts = der::crl_extensions(skid, crl_number).ok_or(rv::FUNCTION_FAILED)?;
    let exts = der::sequence(&exts).map_err(refused)?;
    let tbs = der::crl_tbs(
        s.algid,
        &issuer,
        &this,
        Some(&next),
        list.as_deref(),
        Some(&exts),
    )
    .map_err(refused)?;
    let algid = s.algid;
    sign_and_wrap(s, &tbs, |sig| der::signed(&tbs, algid, sig, None))
}

/// One `fhsm_composite_ocsp_single_t`, its pointer/length pairs already agreed.
pub struct Single<'a> {
    pub cert_id: &'a [u8],
    pub status: c_int,
    pub revoked_at: Option<&'a [u8]>,
    pub reason: c_int,
    pub this_upd: &'a [u8],
    pub next_upd: Option<&'a [u8]>,
}

impl Single<'_> {
    pub fn encode(&self) -> Result<Vec<u8>, u32> {
        der::ocsp_single(
            self.cert_id,
            self.status,
            self.revoked_at,
            self.reason,
            self.this_upd,
            self.next_upd,
        )
        .map_err(refused)
    }
}

/// `fhsm_pki_ocsp` after its argument checks: responderID byName from the responder
/// certificate, which travels in certs (RFC 6960 4.2.2.2). Each single is checked as it is
/// reached.
pub fn ocsp<'a>(
    s: &mut Signer,
    responder: &[u8],
    produced_at: &[u8],
    singles: impl Iterator<Item = Result<Single<'a>, u32>>,
    exts: Option<&[u8]>,
) -> Result<Vec<u8>, u32> {
    let rc = Own::new(d2i(d2i_X509, responder).0, X509_free).ok_or(rv::ARGUMENTS_BAD)?;
    // SAFETY: rc is a live X509
    let name =
        i2d(i2d_X509_NAME, unsafe { X509_get_subject_name(rc.0) }).ok_or(rv::FUNCTION_FAILED)?;
    let rid = der::by_name(&name).map_err(|_| rv::FUNCTION_FAILED)?;
    let mut all = Vec::new();
    for one in singles {
        all.extend(one?.encode()?);
    }
    let responses = der::sequence(&all).map_err(|_| rv::FUNCTION_FAILED)?;
    let tbs = der::ocsp_tbs(&rid, produced_at, &responses, exts).map_err(refused)?;
    let algid = s.algid;
    sign_and_wrap(s, &tbs, |sig| {
        der::signed(&tbs, algid, sig, Some(responder))
    })
}

// --- CMS SignedData (Phase 3 slice 5d, src/fhsm_composite.c:2129-2917) ---------------------

const NID_PKCS9_MESSAGE_DIGEST: c_int = 51;
const NID_SHA256: c_int = 672;
const NID_SHA384: c_int = 673;
const NID_SHA512: c_int = 674;
const V_ASN1_OCTET_STRING: c_int = 4;
const RSA_PKCS1_PSS_PADDING: c_int = 6;
/// The room C gives the SignerInfo inside `fhsm_pki_cms`.
const SIGNERINFO_MAX: usize = 16384;

/// `struct asn1_type_st` (`openssl/asn1.h`, public): the type, and the union of pointers.
#[repr(C)]
struct Asn1Type {
    kind: c_int,
    value: P,
}

/// The bytes of an ASN1_STRING.
///
/// # Safety
/// `a` is a live ASN1_STRING.
unsafe fn string<'a>(a: P) -> &'a [u8] {
    // SAFETY: the caller's contract; length bytes at data
    unsafe {
        let n = ASN1_STRING_length(a).max(0) as usize;
        if n == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(ASN1_STRING_get0_data(a), n)
        }
    }
}

/// A digest by name: its size and NID, or None for one OpenSSL does not fetch.
fn md_by_name(name: &CStr) -> Option<(c_int, c_int)> {
    // SAFETY: name is NUL-terminated; md is freed once
    unsafe {
        let md = Own::new(EVP_MD_fetch(null_mut(), name.as_ptr(), null()), EVP_MD_free)?;
        Some((EVP_MD_get_size(md.0), EVP_MD_get_type(md.0)))
    }
}

/// The digestAlgorithm for `nid`, parameters absent (RFC 5754 2), as OpenSSL encodes it.
fn digest_algid(nid: c_int) -> Result<Vec<u8>, u32> {
    // SAFETY: a fresh X509_ALGOR, freed once; set0 takes the static OBJECT
    unsafe {
        let a = Own::new(X509_ALGOR_new(), X509_ALGOR_free).ok_or(rv::HOST_MEMORY)?;
        if X509_ALGOR_set0(a.0, OBJ_nid2obj(nid), V_ASN1_UNDEF, null_mut()) != 1 {
            return Err(rv::FUNCTION_FAILED);
        }
        i2d(i2d_X509_ALGOR, a.0)
            .filter(|d| d.len() <= 16)
            .ok_or(rv::FUNCTION_FAILED)
    }
}

/// `fhsm_pki_cms` after its pointer checks: detached SignedData over `digest` (the named
/// function's), signed attributes contentType and messageDigest, issuerAndSerialNumber of
/// `cert`, which goes in as the one certificate.
pub fn cms(s: &mut Signer, digest_name: &CStr, cert: &[u8], digest: &[u8]) -> Result<Vec<u8>, u32> {
    // a digest of another length is a caller who hashed with something else
    let nid = match md_by_name(digest_name) {
        Some((size, nid)) if size > 0 && size as usize == digest.len() && nid != 0 => nid,
        _ => return Err(rv::ARGUMENTS_BAD),
    };
    let (x, _) = d2i(d2i_X509, cert);
    let x = Own::new(x, X509_free).ok_or(rv::ARGUMENTS_BAD)?;
    let attrs = der::cms_signed_attrs(digest);
    let mut out = Err(rv::FUNCTION_FAILED);
    let algid = s.algid;
    // the signature covers the attributes, not the content
    ok(s.sign(&attrs, |sig| {
        out = (|| {
            // SAFETY: x is a live X509; the name and serial are its own
            let (issuer, serial, cert) = unsafe {
                (
                    i2d(i2d_X509_NAME, X509_get_issuer_name(x.0)),
                    i2d(i2d_ASN1_INTEGER, X509_get_serialNumber(x.0)),
                    i2d(i2d_X509, x.0),
                )
            };
            let (Some(issuer), Some(serial), Some(cert)) = (issuer, serial, cert) else {
                return Err(rv::FUNCTION_FAILED);
            };
            let digalg = digest_algid(nid)?;
            // certificates: the signer's own, as a SET OF of one
            let certs = der::set_of(&cert).map_err(refused)?;
            let si = der::cms_signerinfo(&issuer, &serial, &digalg, &attrs, algid, sig)
                .map_err(refused)?;
            if si.len() > SIGNERINFO_MAX {
                return Err(rv::BUFFER_TOO_SMALL);
            }
            der::cms_wrap(&digalg, Some(&certs), &si).map_err(refused)
        })();
        rv::OK
    }))?;
    out
}

unsafe extern "C" fn cms_free(ci: P) {
    // SAFETY: ci is a CMS_ContentInfo
    unsafe { CMS_ContentInfo_free(ci) }
}

unsafe extern "C" fn certs_free(st: P) {
    // SAFETY: st is a STACK_OF(X509) owning its certificates
    unsafe { OPENSSL_sk_pop_free(st, X509_free) }
}

/// `cms_one_signer`: the ContentInfo, parsed whole and exactly, and its one SignerInfo.
fn one_signer(cms: &[u8]) -> Option<(Own, P)> {
    let (ci, left) = d2i(d2i_CMS_ContentInfo, cms);
    let ci = Own::new(ci, cms_free)?;
    // SAFETY: ci is live; the SignerInfo belongs to it
    let si = unsafe {
        let sis = CMS_get0_SignerInfos(ci.0);
        if left != 0 || OPENSSL_sk_num(sis) != 1 {
            return None;
        }
        OPENSSL_sk_value(sis, 0)
    };
    Some((ci, si))
}

/// The parameter type of an AlgorithmIdentifier: V_ASN1_UNDEF when absent.
fn param_type(a: P) -> c_int {
    let mut pt = 0;
    // SAFETY: a is a live X509_ALGOR; the object and value are not asked for
    unsafe { X509_ALGOR_get0(&mut null_mut(), &mut pt, &mut null_mut(), a) };
    pt
}

/// The SignerInfo's signatureAlgorithm, or NULL.
fn sig_alg(si: P) -> P {
    let mut sa = null_mut();
    // SAFETY: si is a live SignerInfo; the other outputs are not asked for
    unsafe { CMS_SignerInfo_get0_algs(si, null_mut(), null_mut(), null_mut(), &mut sa) };
    sa
}

/// `cms_digest_name`: the digestAlgorithm, if SHA-256, -384 or -512.
fn digest_name(si: P) -> Option<&'static CStr> {
    let (mut da, mut o, mut pt, mut pv) = (null_mut(), null_mut(), 0, null_mut());
    // SAFETY: si is a live SignerInfo, da its own X509_ALGOR
    unsafe {
        CMS_SignerInfo_get0_algs(si, null_mut(), null_mut(), &mut da, null_mut());
        if da.is_null() {
            return None;
        }
        X509_ALGOR_get0(&mut o, &mut pt, &mut pv, da);
        match OBJ_obj2nid(o) {
            NID_SHA256 => Some(c"SHA256"),
            NID_SHA384 => Some(c"SHA384"),
            NID_SHA512 => Some(c"SHA512"),
            _ => None,
        }
    }
}

/// `fhsm_pki_cms_digest` after its pointer checks: ARGUMENTS_BAD unless one SignerInfo; then
/// the digest's name, if it is one of the three.
pub fn cms_digest(cms: &[u8]) -> Result<Option<&'static CStr>, u32> {
    let (_ci, si) = one_signer(cms).ok_or(rv::ARGUMENTS_BAD)?;
    Ok(digest_name(si))
}

/// The messageDigest attribute against the content the caller hashed: what ties the
/// signature, which covers only the attributes, to the data.
fn message_digest(si: P, digest: &[u8]) -> Result<(), u32> {
    // SAFETY: si is a live SignerInfo; the attribute and its value are its own
    unsafe {
        let loc = CMS_signed_get_attr_by_NID(si, NID_PKCS9_MESSAGE_DIGEST, -1);
        if loc < 0 {
            return Err(rv::ARGUMENTS_BAD);
        }
        let at = CMS_signed_get_attr(si, loc);
        let v = if at.is_null() {
            null()
        } else {
            X509_ATTRIBUTE_get0_type(at, 0)
                .cast::<Asn1Type>()
                .cast_const()
        };
        match v.as_ref() {
            Some(v) if v.kind == V_ASN1_OCTET_STRING => {}
            _ => return Err(rv::ARGUMENTS_BAD),
        }
        if string((*v).value) != digest {
            return Err(rv::SIGNATURE_INVALID);
        }
    }
    Ok(())
}

/// The one certificate the structure carries.
fn one_cert(ci: P) -> Option<(Own, P)> {
    // SAFETY: ci is live; the stack owns its certificates
    unsafe {
        let certs = Own::new(CMS_get1_certs(ci), certs_free)?;
        let x = OPENSSL_sk_value(certs.0, 0);
        (OPENSSL_sk_num(certs.0) == 1).then_some((certs, x))
    }
}

/// The signed attributes as they appear when the structure is re-encoded, retagged to the SET
/// OF that was signed: verifying over the bytes given would only prove agreement with ourselves.
fn signed_attrs(ci: P) -> Option<Vec<u8>> {
    der::cms_signed_attrs_of(&i2d(i2d_CMS_ContentInfo, ci)?)
}

/// `fhsm_composite_cms_verify` after its pointer checks.
pub fn composite_cms_verify(cms: &[u8], digest: &[u8]) -> u32 {
    let comp = crate::composite::MLDSA65_ED25519_SHA512;
    if digest.len() != super::c_abi::fhsm_composite_ph_len(comp) {
        return rv::ARGUMENTS_BAD;
    }
    let Some((ci, si)) = one_signer(cms) else {
        return rv::ARGUMENTS_BAD;
    };
    // the algorithm before anything else
    let sa = sig_alg(si);
    if sa.is_null() || oid(sa) != der::OID_COMPOSITE || param_type(sa) != V_ASN1_UNDEF {
        return rv::ARGUMENTS_BAD;
    }
    if let Err(r) = message_digest(si, digest) {
        return r;
    }
    let Some((_certs, x)) = one_cert(ci.0) else {
        return rv::ARGUMENTS_BAD;
    };
    let (mut pk, mut pkl) = (null(), 0);
    // SAFETY: x is live; pk has pkl bytes
    let raw = unsafe {
        X509_PUBKEY_get0_param(
            null_mut(),
            &mut pk,
            &mut pkl,
            null_mut(),
            X509_get_X509_PUBKEY(x),
        );
        if pk.is_null() || pkl as usize != der::RAW_PUB {
            return rv::ARGUMENTS_BAD;
        }
        std::slice::from_raw_parts(pk, der::RAW_PUB)
    };
    let Ok(public) = blob_from_raw(raw) else {
        return rv::ARGUMENTS_BAD;
    };
    let Some(attrs) = signed_attrs(ci.0) else {
        return rv::ARGUMENTS_BAD;
    };
    // SAFETY: si is live; its signature is its own
    let sg = unsafe { CMS_SignerInfo_get0_signature(si) };
    if sg.is_null() {
        return rv::ARGUMENTS_BAD;
    }
    // SAFETY: every buffer covers its length; no context
    unsafe {
        let sig = string(sg);
        super::c_abi::fhsm_composite_verify(
            comp,
            public.as_ptr(),
            public.len(),
            attrs.as_ptr(),
            attrs.len(),
            null(),
            0,
            sig.as_ptr(),
            sig.len(),
        )
    }
}

/// `classic_verify`: the signature over the signed attributes for the algorithms other than
/// the composite, each told apart by its OID with what that implies checked: the key's type,
/// and the parameters (absent for ECDSA, Ed25519 and ML-DSA; NULL or absent for PKCS#1;
/// exactly fhsm_pki's block for RSASSA-PSS). ARGUMENTS_BAD for a combination it does not
/// recognise, SIGNATURE_INVALID for one it does that does not verify.
fn classic_verify(k: P, sa: P, digest_name: Option<&CStr>, msg: &[u8], sig: &[u8]) -> u32 {
    let pt = param_type(sa);
    let (md, keytype, pss, params_absent) = match oid(sa).as_str() {
        "1.2.840.10045.4.3.2" => (Some(c"SHA256"), c"EC", false, true),
        "1.2.840.10045.4.3.3" => (Some(c"SHA384"), c"EC", false, true),
        "1.2.840.113549.1.1.11" => (Some(c"SHA256"), c"RSA", false, false),
        "1.2.840.113549.1.1.1" => (digest_name, c"RSA", false, false),
        "1.2.840.113549.1.1.10" => {
            // fhsm_pki_sigalg_t RSA_PSS_SHA256
            if i2d(i2d_X509_ALGOR, sa).as_deref() != der::pki_algid(3) {
                return rv::ARGUMENTS_BAD;
            }
            (Some(c"SHA256"), c"RSA", true, false)
        }
        "1.3.101.112" => (None, c"ED25519", false, true),
        "2.16.840.1.101.3.4.3.17" => (None, c"ML-DSA-44", false, true),
        "2.16.840.1.101.3.4.3.18" => (None, c"ML-DSA-65", false, true),
        "2.16.840.1.101.3.4.3.19" => (None, c"ML-DSA-87", false, true),
        _ => return rv::ARGUMENTS_BAD,
    };
    if params_absent && pt != V_ASN1_UNDEF
        || !pss && !params_absent && pt != V_ASN1_NULL && pt != V_ASN1_UNDEF
    {
        return rv::ARGUMENTS_BAD;
    }
    // SAFETY: k is a live EVP_PKEY
    if unsafe { EVP_PKEY_is_a(k, keytype.as_ptr()) } != 1 {
        return rv::ARGUMENTS_BAD;
    }
    // a hash other than the digestAlgorithm would be verified two ways
    if md.zip(digest_name).is_some_and(|(m, d)| m != d) {
        return rv::ARGUMENTS_BAD;
    }
    // SAFETY: m is freed once; pc belongs to m; every buffer covers its length
    unsafe {
        ERR_set_mark();
        let m = EVP_MD_CTX_new();
        let mut pc: P = null_mut();
        let md = md.map_or(null(), CStr::as_ptr);
        let mut ok = !m.is_null()
            && super::composite::EVP_DigestVerifyInit_ex(
                m.cast(),
                (&raw mut pc).cast(),
                md,
                null_mut(),
                null(),
                k.cast(),
                null(),
            ) == 1;
        if ok && pss {
            ok = EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) == 1
                && EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, 32) == 1
                && EVP_PKEY_CTX_set_rsa_mgf1_md_name(pc, c"SHA256".as_ptr(), null()) == 1;
        }
        let r = if ok {
            EVP_DigestVerify(m, sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len())
        } else {
            -1
        };
        EVP_MD_CTX_free(m);
        ERR_pop_to_mark();
        match (ok, r) {
            (false, _) => rv::FUNCTION_FAILED,
            (true, 1) => rv::OK,
            _ => rv::SIGNATURE_INVALID,
        }
    }
}

/// `fhsm_pki_cms_verify` after its pointer checks: the composite goes to its own verifier,
/// unchanged; the others are checked here.
pub fn pki_cms_verify(cms: &[u8], digest: &[u8]) -> u32 {
    let Some((ci, si)) = one_signer(cms) else {
        return rv::ARGUMENTS_BAD;
    };
    let sa = sig_alg(si);
    if sa.is_null() {
        return rv::ARGUMENTS_BAD;
    }
    if oid(sa) == der::OID_COMPOSITE {
        drop(ci);
        return composite_cms_verify(cms, digest);
    }
    // the digest the caller computed must be the one the structure names
    let dn = digest_name(si);
    match dn.and_then(md_by_name) {
        Some((size, _)) if size > 0 && size as usize == digest.len() => {}
        _ => return rv::ARGUMENTS_BAD,
    }
    if let Err(r) = message_digest(si, digest) {
        return r;
    }
    // the one certificate, and the one the SignerInfo names
    let Some((_certs, x)) = one_cert(ci.0) else {
        return rv::ARGUMENTS_BAD;
    };
    // SAFETY: si and x are live; the key belongs to x
    let k = unsafe {
        if CMS_SignerInfo_cert_cmp(si, x) != 0 {
            return rv::ARGUMENTS_BAD;
        }
        ERR_set_mark();
        let k = X509_get0_pubkey(x);
        ERR_pop_to_mark();
        k
    };
    if k.is_null() {
        return rv::ARGUMENTS_BAD;
    }
    let Some(attrs) = signed_attrs(ci.0) else {
        return rv::ARGUMENTS_BAD;
    };
    // SAFETY: si is live; its signature is its own
    let sg = unsafe { CMS_SignerInfo_get0_signature(si) };
    if sg.is_null() {
        return rv::ARGUMENTS_BAD;
    }
    // SAFETY: sg is a live OCTET STRING
    classic_verify(k, sa, dn, &attrs, unsafe { string(sg) })
}
