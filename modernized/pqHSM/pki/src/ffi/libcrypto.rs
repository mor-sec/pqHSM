//! The libcrypto calls the revocation code makes, behind owned handles. Always compiled:
//! `cargo test` uses them too. Declared here, as the audit crate does, because openssl-sys
//! binds only some of them; openssl-sys is still linked, for `-lcrypto`.

use std::ffi::{c_char, c_int, c_long, c_void};
use std::ptr::null_mut;

use openssl_sys as _;

type P = *mut c_void;

unsafe extern "C" {
    fn d2i_X509(a: *mut P, pp: *mut *const u8, len: c_long) -> P;
    fn X509_free(x: P);
    fn X509_get_ext_d2i(x: P, nid: c_int, crit: *mut c_int, idx: *mut c_int) -> P;
    fn X509_get_issuer_name(x: P) -> P;
    fn X509_get_subject_name(x: P) -> P;
    fn X509_get0_pubkey_bitstr(x: P) -> P;
    fn X509_NAME_cmp(a: P, b: P) -> c_int;
    fn EXTENDED_KEY_USAGE_free(e: P);
    fn OPENSSL_sk_num(s: P) -> c_int;
    fn OPENSSL_sk_value(s: P, i: c_int) -> P;
    fn OBJ_obj2nid(o: P) -> c_int;
    fn OBJ_nid2sn(n: c_int) -> *const c_char;
    // EVP_get_digestbyobj is a macro in OpenSSL 3; this is what it expands to.
    fn EVP_get_digestbyname(n: *const c_char) -> P;
    fn d2i_OCSP_REQUEST(a: *mut P, pp: *mut *const u8, len: c_long) -> P;
    fn OCSP_REQUEST_free(r: P);
    fn OCSP_request_onereq_count(r: P) -> c_int;
    fn OCSP_request_onereq_get0(r: P, i: c_int) -> P;
    fn OCSP_onereq_get0_id(o: P) -> P;
    fn OCSP_id_get0_info(nh: *mut P, md: *mut P, kh: *mut P, sn: *mut P, cid: P) -> c_int;
    fn OCSP_cert_id_new(md: P, name: P, key: P, sn: P) -> P;
    fn OCSP_id_issuer_cmp(a: P, b: P) -> c_int;
    fn OCSP_CERTID_free(c: P);
    fn i2d_OCSP_CERTID(c: P, out: *mut *mut u8) -> c_int;
    fn OCSP_REQUEST_get_ext_by_NID(r: P, nid: c_int, last: c_int) -> c_int;
    fn OCSP_REQUEST_get_ext(r: P, i: c_int) -> P;
    fn i2d_X509_EXTENSION(e: P, out: *mut *mut u8) -> c_int;
    fn ASN1_STRING_get0_data(s: P) -> *const u8;
    fn ASN1_STRING_length(s: P) -> c_int;
    fn ASN1_GENERALIZEDTIME_set(s: P, t: libc::time_t) -> P;
    fn ASN1_GENERALIZEDTIME_free(s: P);
    fn i2d_ASN1_GENERALIZEDTIME(s: P, out: *mut *mut u8) -> c_int;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
}

const NID_EXT_KEY_USAGE: c_int = 126;
const NID_OCSP_SIGN: c_int = 180;
const NID_ID_PKIX_OCSP_NONCE: c_int = 366;

/// An `i2d_*` result, copied out and the libcrypto buffer freed. `None` when `n <= 0`.
fn take(p: *mut u8, n: c_int) -> Option<Vec<u8>> {
    if n <= 0 {
        return None;
    }
    // SAFETY: a successful i2d_* wrote n bytes at p, allocated with OPENSSL_malloc
    let v = unsafe { std::slice::from_raw_parts(p, n as usize) }.to_vec();
    unsafe { CRYPTO_free(p.cast(), c"pqhsm-pki".as_ptr(), 0) };
    Some(v)
}

/// An `ASN1_STRING`'s bytes.
///
/// # Safety
/// `s` is a live, non-NULL ASN1_STRING.
unsafe fn bytes<'a>(s: P) -> &'a [u8] {
    // SAFETY: the caller's contract
    unsafe {
        let n = ASN1_STRING_length(s);
        if n <= 0 {
            return &[];
        }
        std::slice::from_raw_parts(ASN1_STRING_get0_data(s), n as usize)
    }
}

/// DER GeneralizedTime for `t`, or `None` if libcrypto cannot represent it.
pub(crate) fn generalized_time(t: i64) -> Option<Vec<u8>> {
    // SAFETY: set allocates a fresh time (NULL in), freed after the encode
    unsafe {
        let g = ASN1_GENERALIZEDTIME_set(null_mut(), t as libc::time_t);
        if g.is_null() {
            return None;
        }
        let mut o = null_mut();
        let n = i2d_ASN1_GENERALIZEDTIME(g, &mut o);
        ASN1_GENERALIZEDTIME_free(g);
        take(o, n)
    }
}

pub(crate) struct Cert(P);

impl Cert {
    pub(crate) fn from_der(der: &[u8]) -> Option<Cert> {
        let mut p = der.as_ptr();
        // SAFETY: d2i reads at most len bytes from p
        let x = unsafe { d2i_X509(null_mut(), &mut p, der.len() as c_long) };
        (!x.is_null()).then_some(Cert(x))
    }

    /// extendedKeyUsage present and listing id-kp-OCSPSigning.
    pub(crate) fn has_ocsp_signing(&self) -> bool {
        // SAFETY: self.0 is live; the decoded EKU stack is ours and freed here
        unsafe {
            let eku = X509_get_ext_d2i(self.0, NID_EXT_KEY_USAGE, null_mut(), null_mut());
            if eku.is_null() {
                return false;
            }
            let ok = (0..OPENSSL_sk_num(eku))
                .any(|k| OBJ_obj2nid(OPENSSL_sk_value(eku, k)) == NID_OCSP_SIGN);
            EXTENDED_KEY_USAGE_free(eku);
            ok
        }
    }

    /// This certificate's issuer name equals `ca`'s subject. A name, not a signature.
    pub(crate) fn issuer_is(&self, ca: &Cert) -> bool {
        // SAFETY: both live; get_*_name return borrowed pointers
        unsafe { X509_NAME_cmp(X509_get_issuer_name(self.0), X509_get_subject_name(ca.0)) == 0 }
    }
}

impl Drop for Cert {
    fn drop(&mut self) {
        // SAFETY: owned since d2i
        unsafe { X509_free(self.0) }
    }
}

/// One CertID of a request.
pub(crate) struct Asked {
    /// The CertID, re-encoded.
    pub der: Vec<u8>,
    /// Issued by `ca`: the CertID's hashes equal `ca`'s, recomputed with the client's
    /// algorithm.
    pub ours: bool,
    pub serial: Vec<u8>,
}

pub(crate) enum AskedError {
    Malformed,
    Reencode,
}

pub(crate) struct Request(P);

impl Request {
    pub(crate) fn from_der(der: &[u8]) -> Option<Request> {
        let mut p = der.as_ptr();
        // SAFETY: d2i reads at most len bytes from p
        let r = unsafe { d2i_OCSP_REQUEST(null_mut(), &mut p, der.len() as c_long) };
        (!r.is_null()).then_some(Request(r))
    }

    pub(crate) fn count(&self) -> c_int {
        // SAFETY: self.0 is live
        unsafe { OCSP_request_onereq_count(self.0) }
    }

    /// The `i`th CertID, `0 <= i < count()`.
    pub(crate) fn asked(&self, i: c_int, ca: &Cert) -> Result<Asked, AskedError> {
        // SAFETY: self.0 and ca.0 are live; every pointer get0 returns is borrowed from the
        // request, and the CertID made for the comparison is freed here
        unsafe {
            let cid = OCSP_onereq_get0_id(OCSP_request_onereq_get0(self.0, i));
            let (mut nh, mut md, mut kh, mut sn) = (null_mut(), null_mut(), null_mut(), null_mut());
            if OCSP_id_get0_info(&mut nh, &mut md, &mut kh, &mut sn, cid) == 0 {
                return Err(AskedError::Malformed);
            }
            let mut o = null_mut();
            let n = i2d_OCSP_CERTID(cid, &mut o);
            let der = take(o, n).ok_or(AskedError::Reencode)?;
            let alg = EVP_get_digestbyname(OBJ_nid2sn(OBJ_obj2nid(md)));
            let ours = !alg.is_null() && {
                let mine = OCSP_cert_id_new(
                    alg,
                    X509_get_subject_name(ca.0),
                    X509_get0_pubkey_bitstr(ca.0),
                    sn,
                );
                let same = !mine.is_null() && OCSP_id_issuer_cmp(mine, cid) == 0;
                OCSP_CERTID_free(mine);
                same
            };
            Ok(Asked {
                der,
                ours,
                serial: bytes(sn).to_vec(),
            })
        }
    }

    /// The nonce extension, DER, if the request carries one.
    pub(crate) fn nonce(&self) -> Option<Vec<u8>> {
        // SAFETY: self.0 is live; the extension is borrowed from it
        unsafe {
            let idx = OCSP_REQUEST_get_ext_by_NID(self.0, NID_ID_PKIX_OCSP_NONCE, -1);
            if idx < 0 {
                return None;
            }
            let e = OCSP_REQUEST_get_ext(self.0, idx);
            if e.is_null() {
                return None;
            }
            let mut o = null_mut();
            let n = i2d_X509_EXTENSION(e, &mut o);
            take(o, n)
        }
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        // SAFETY: owned since d2i
        unsafe { OCSP_REQUEST_free(self.0) }
    }
}
