//! What `C_GetAttributeValue` reads back through OpenSSL (`src/fhsm_pkcs11.c:6505-6526,
//! 6951-7151`): a key's parameters and raw public key, and a certificate's names and serial.
//! Each returns the bytes whole, or None where C's extractor answered -1.

use std::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::ptr::null_mut;

use openssl_sys::{
    ASN1_INTEGER, ASN1_OBJECT, BN_bn2bin, BN_free, BN_num_bits, EVP_PKEY_get_bn_param,
    EVP_PKEY_get_octet_string_param, EVP_PKEY_get_raw_public_key, EVP_PKEY_get_utf8_string_param,
    OBJ_nid2obj, OBJ_sn2nid, OPENSSL_free, X509_free, X509_get_issuer_name, X509_get_serialNumber,
    X509_get_subject_name, d2i_X509, i2d_X509_NAME,
};

use super::cipher::Pkey;

unsafe extern "C" {
    // Not bound by openssl-sys
    fn EC_curve_nist2nid(name: *const c_char) -> c_int;
    fn OBJ_txt2nid(name: *const c_char) -> c_int;
    fn i2d_ASN1_OBJECT(o: *const ASN1_OBJECT, out: *mut *mut u8) -> c_int;
    fn i2d_ASN1_INTEGER(i: *const ASN1_INTEGER, out: *mut *mut u8) -> c_int;
}

/// Copies an OpenSSL-allocated DER of `n` bytes out, and frees it.
///
/// # Safety
/// `der` NULL or allocated by OpenSSL with at least `n` bytes.
unsafe fn take(der: *mut u8, n: c_int) -> Option<Vec<u8>> {
    // SAFETY: the caller's
    let v = (n > 0 && !der.is_null())
        .then(|| unsafe { std::slice::from_raw_parts(der, n as usize) }.to_vec());
    // SAFETY: OpenSSL's allocation, or NULL
    unsafe { OPENSSL_free(der.cast::<c_void>()) };
    v
}

impl Pkey {
    /// `EVP_PKEY_get_bn_param`, big-endian with no leading zero (`BN_bn2bin`).
    pub fn bn(&self, name: &CStr) -> Option<Vec<u8>> {
        let mut bn = null_mut();
        // SAFETY: a live key; a C string; bn is ours to free
        unsafe {
            if EVP_PKEY_get_bn_param(self.0.0, name.as_ptr(), &mut bn) != 1 {
                return None;
            }
            let mut v = vec![0u8; (BN_num_bits(bn) as usize).div_ceil(8)];
            BN_bn2bin(bn, v.as_mut_ptr());
            BN_free(bn);
            Some(v)
        }
    }

    /// `EVP_PKEY_get_octet_string_param` of at most `max` bytes (None if longer).
    pub fn octets(&self, name: &CStr, max: usize) -> Option<Vec<u8>> {
        let (mut v, mut n) = (vec![0u8; max], 0usize);
        // SAFETY: a live key; a C string; v writable for max bytes
        let ok = unsafe {
            EVP_PKEY_get_octet_string_param(self.0.0, name.as_ptr(), v.as_mut_ptr(), max, &mut n)
        } == 1;
        ok.then(|| {
            v.truncate(n);
            v
        })
    }

    /// The curve's OID as DER: its `group` name as a NIST name, a short name or an OID text
    /// (`:7022-7040`).
    pub fn group_oid(&self) -> Option<Vec<u8>> {
        let (mut name, mut n) = ([0 as c_char; 64], 0usize);
        // SAFETY: a live key; name writable for 64 bytes and NUL-terminated by OpenSSL
        unsafe {
            let g = c"group".as_ptr();
            if EVP_PKEY_get_utf8_string_param(self.0.0, g, name.as_mut_ptr(), 64, &mut n) != 1 {
                return None;
            }
            let p = name.as_ptr();
            // In C's order, stopping at the first (OBJ_txt2nid may queue an error)
            let nid = Some(EC_curve_nist2nid(p))
                .filter(|&n| n != 0)
                .or_else(|| Some(OBJ_sn2nid(p)).filter(|&n| n != 0))
                .or_else(|| Some(OBJ_txt2nid(p)).filter(|&n| n != 0))?;
            let obj = OBJ_nid2obj(nid);
            if obj.is_null() {
                return None;
            }
            let mut der = null_mut();
            let dl = i2d_ASN1_OBJECT(obj, &mut der);
            take(der, dl)
        }
    }

    /// `EVP_PKEY_get_raw_public_key`.
    pub fn raw_pub(&self) -> Option<Vec<u8>> {
        let mut n = 0usize;
        // SAFETY: a live key; a NULL out asks the length, then v has n bytes
        unsafe {
            if EVP_PKEY_get_raw_public_key(self.0.0, null_mut(), &mut n) != 1 {
                return None;
            }
            let mut v = vec![0u8; n];
            (EVP_PKEY_get_raw_public_key(self.0.0, v.as_mut_ptr(), &mut n) == 1).then(|| {
                v.truncate(n);
                v
            })
        }
    }
}

/// The three certificate fields C_GetAttributeValue derives from CKA_VALUE.
#[derive(Clone, Copy)]
pub enum CertField {
    Subject,
    Issuer,
    Serial,
}

/// `extract_cert_attr` (`:7128-7151`): the field's DER, from the certificate `der`.
pub fn cert_field(der: &[u8], f: CertField) -> Option<Vec<u8>> {
    let mut p = der.as_ptr();
    // SAFETY: der readable for its length; x freed below; each field belongs to x
    unsafe {
        let x = d2i_X509(null_mut(), &mut p, der.len() as c_long);
        if x.is_null() {
            return None;
        }
        let mut out = null_mut();
        let n = match f {
            CertField::Subject => i2d_X509_NAME(X509_get_subject_name(x), &mut out),
            CertField::Issuer => i2d_X509_NAME(X509_get_issuer_name(x), &mut out),
            CertField::Serial => i2d_ASN1_INTEGER(X509_get_serialNumber(x), &mut out),
        };
        let v = take(out, n);
        X509_free(x);
        v
    }
}
