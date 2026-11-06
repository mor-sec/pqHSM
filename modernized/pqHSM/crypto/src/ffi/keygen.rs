//! Key-pair generation over libcrypto for `C_GenerateKeyPair` (`src/fhsm_pkcs11.c:6581-6808`):
//! the key by algorithm name, an EC key on a named group, an RSA key of a size and exponent,
//! the DER of each half, and the CKA_EC_PARAMS curve matcher (`match_curve_ex`,
//! `fhsm_ec_curve_refusal`, `fhsm_ec_group_served`, `:6320-6442`). The checks and their codes
//! stay with the caller.

use std::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::ptr::{null, null_mut};

use openssl_sys::{
    ASN1_OBJECT_free, BN_bin2bn, BN_free, EC_GROUP_free, EC_GROUP_get_degree,
    EC_GROUP_new_by_curve_name, EVP_PKEY_CTX, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name,
    EVP_PKEY_free, EVP_PKEY_keygen, EVP_PKEY_keygen_init, OBJ_nid2sn, OBJ_obj2nid, OPENSSL_free,
    i2d_PUBKEY, i2d_PrivateKey,
};

use super::cipher::{Owned, Pkey, cleanse};

unsafe extern "C" {
    // OpenSSL 3; not bound by openssl-sys, or bound as 1.1 macros
    fn EVP_PKEY_CTX_set_group_name(c: *mut EVP_PKEY_CTX, name: *const c_char) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_keygen_bits(c: *mut EVP_PKEY_CTX, bits: c_int) -> c_int;
    fn EVP_PKEY_CTX_set1_rsa_keygen_pubexp(c: *mut EVP_PKEY_CTX, e: *mut c_void) -> c_int;
    fn EVP_PKEY_paramgen_init(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EVP_PKEY_paramgen(c: *mut EVP_PKEY_CTX, out: *mut *mut openssl_sys::EVP_PKEY) -> c_int;
    fn EVP_KEYMGMT_fetch(ctx: *mut c_void, alg: *const c_char, props: *const c_char)
    -> *mut c_void;
    fn EVP_KEYMGMT_free(k: *mut c_void);
    fn EC_GROUP_get_field_type(g: *const c_void) -> c_int;
    fn ERR_set_mark() -> c_int;
    fn ERR_pop_to_mark() -> c_int;
    fn ERR_print_errors_fp(fp: *mut libc::FILE);
    static stderr: *mut libc::FILE;
    fn d2i_ASN1_OBJECT(
        a: *mut *mut openssl_sys::ASN1_OBJECT,
        pp: *mut *const u8,
        len: c_long,
    ) -> *mut openssl_sys::ASN1_OBJECT;
}

/// `NID_X9_62_prime_field`, `NID_undef`, and the four curves C refuses as CURVE_NOT_SUPPORTED
/// by name: X25519, X448, ED25519, ED448.
const NID_PRIME_FIELD: c_int = 406;
const NID_UNDEF: c_int = 0;
const NID_NOT_EC: [c_int; 4] = [1034, 1035, 1087, 1088];
/// `FHSM_EC_MIN_BITS`, `FHSM_EC_MAX_BITS`.
const EC_MIN_BITS: c_int = 256;
const EC_MAX_BITS: c_int = 521;

/// A context for `alg`, its keygen begun, `set` applied, then the key.
fn generate(alg: &CStr, set: impl FnOnce(*mut EVP_PKEY_CTX) -> bool) -> Option<Pkey> {
    // SAFETY: a C string; the context is held by an Owned; the key is owned by the result
    unsafe {
        let c = Owned::new(
            EVP_PKEY_CTX_new_from_name(null_mut(), alg.as_ptr(), null()),
            EVP_PKEY_CTX_free,
        )?;
        if EVP_PKEY_keygen_init(c.0) <= 0 || !set(c.0) {
            return None;
        }
        let mut k = null_mut();
        if EVP_PKEY_keygen(c.0, &mut k) <= 0 {
            EVP_PKEY_free(k);
            return None;
        }
        Owned::new(k, EVP_PKEY_free).map(Pkey)
    }
}

impl Pkey {
    /// `EVP_PKEY_Q_keygen(NULL, NULL, alg)`: Ed25519, X448, ML-KEM-768, SLH-DSA-SHA2-128s...
    pub fn generate(alg: &CStr) -> Option<Self> {
        generate(alg, |_| true)
    }

    /// `EVP_PKEY_Q_keygen(NULL, NULL, "EC", curve)`.
    pub fn generate_ec(curve: &CStr) -> Option<Self> {
        // SAFETY: a live context; a C string
        generate(c"EC", |c| unsafe {
            EVP_PKEY_CTX_set_group_name(c, curve.as_ptr()) > 0
        })
    }

    /// `EVP_PKEY_Q_keygen(NULL, NULL, "RSA", bits)`, with the public exponent `e` (big-endian)
    /// where one is given; OpenSSL's 65537 otherwise.
    pub fn generate_rsa(bits: c_int, e: Option<&[u8]>) -> Option<Self> {
        generate(c"RSA", |c| {
            // SAFETY: a live context
            if unsafe { EVP_PKEY_CTX_set_rsa_keygen_bits(c, bits) } <= 0 {
                return false;
            }
            let Some(e) = e else { return true };
            // SAFETY: e readable for its length; the BIGNUM is copied by set1 and freed here
            unsafe {
                let bn = BN_bin2bn(e.as_ptr(), e.len() as c_int, null_mut());
                let ok = !bn.is_null() && EVP_PKEY_CTX_set1_rsa_keygen_pubexp(c, bn.cast()) > 0;
                BN_free(bn);
                ok
            }
        })
    }

    /// `i2d_PUBKEY`: the SubjectPublicKeyInfo.
    pub fn public_der(&self) -> Option<Vec<u8>> {
        // SAFETY: a live key
        unsafe { i2d(|p| i2d_PUBKEY(self.0.0, p)) }
    }

    /// `i2d_PrivateKey`: PKCS#8, unencrypted; OpenSSL's copy is cleansed before it is freed.
    pub fn private_der(&self) -> Option<Vec<u8>> {
        // SAFETY: a live key
        unsafe { i2d(|p| i2d_PrivateKey(self.0.0, p)) }
    }

    /// The raw key, for the C ABI calls that take one (`fhsm_pairwise_check`).
    pub fn as_ptr(&self) -> *mut openssl_sys::EVP_PKEY {
        self.0.0
    }
}

/// An i2d call with OpenSSL allocating: the bytes, its buffer cleansed and freed.
///
/// # Safety
/// `f` an i2d over a live object.
unsafe fn i2d(f: impl FnOnce(*mut *mut u8) -> c_int) -> Option<Vec<u8>> {
    let mut p: *mut u8 = null_mut();
    let n = f(&mut p);
    if p.is_null() {
        return None;
    }
    let len = usize::try_from(n).unwrap_or(0);
    // SAFETY: OpenSSL wrote n bytes at p
    let s = unsafe { std::slice::from_raw_parts_mut(p, len) };
    let v = (n > 0).then(|| s.to_vec());
    cleanse(s);
    // SAFETY: OpenSSL's allocation
    unsafe { OPENSSL_free(p.cast()) };
    v
}

/// The answer for a CKA_EC_PARAMS.
#[derive(Debug, PartialEq, Eq)]
pub enum Curve {
    /// A curve to generate on.
    Named(&'static CStr),
    /// `fhsm_ec_curve_refusal`: CURVE_NOT_SUPPORTED, a curve this module will not take.
    Unsupported,
    /// ATTRIBUTE_VALUE_INVALID: not a curve.
    Invalid,
}

/// The three curves C names by their DER (`ec_curves[]`).
const APPROVED: [(&[u8], &CStr); 3] = [
    (b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07", c"P-256"),
    (b"\x06\x05\x2B\x81\x04\x00\x22", c"P-384"),
    (b"\x06\x05\x2B\x81\x04\x00\x23", c"P-521"),
];

/// `match_curve_ex`, then `fhsm_ec_curve_refusal` where it found none or, in the strict build
/// (`strict`), found a curve other than the three. `match_curve_ex` takes an OID with bytes
/// after it; the refusal does not, so those are not a curve there.
pub fn ec_curve(der: &[u8], strict: bool) -> Curve {
    if let Some((_, n)) = APPROVED.iter().find(|(d, _)| *d == der) {
        return Curve::Named(n);
    }
    if der.is_empty() || der.len() > 64 {
        return Curve::Invalid;
    }
    // SAFETY: der readable for its length; every object is freed here; the mark pops what
    // the refusal's probes push
    unsafe {
        ERR_set_mark();
        let (nid, whole) = nid_of(der);
        let named = (nid != NID_UNDEF).then(|| other_curve(nid)).flatten();
        let r = match named {
            Some(n) if !strict => Curve::Named(n),
            _ if NID_NOT_EC.contains(&nid) => Curve::Unsupported,
            _ if nid != NID_UNDEF && whole && is_group(nid) => Curve::Unsupported,
            _ => Curve::Invalid,
        };
        ERR_pop_to_mark();
        r
    }
}

/// The OID's NID, and whether the OID was the whole of `der`.
///
/// # Safety
/// None beyond the types.
unsafe fn nid_of(der: &[u8]) -> (c_int, bool) {
    let mut p = der.as_ptr();
    // SAFETY: der readable for its length; the object is freed here
    unsafe {
        let o = d2i_ASN1_OBJECT(null_mut(), &mut p, der.len() as c_long);
        if o.is_null() {
            return (NID_UNDEF, false);
        }
        let nid = OBJ_obj2nid(o);
        ASN1_OBJECT_free(o);
        (nid, p.offset_from(der.as_ptr()) as usize == der.len())
    }
}

fn is_group(nid: c_int) -> bool {
    // SAFETY: a NID; the group is freed here
    unsafe {
        let g = EC_GROUP_new_by_curve_name(nid);
        EC_GROUP_free(g);
        !g.is_null()
    }
}

/// `match_curve_ex`'s second half: a prime curve of 256 to 521 bits, not SM2, that a loaded
/// provider can build.
fn other_curve(nid: c_int) -> Option<&'static CStr> {
    // SAFETY: a NID; the group is freed here; OBJ_nid2sn returns a static string
    unsafe {
        let g = EC_GROUP_new_by_curve_name(nid);
        if g.is_null() {
            return None;
        }
        let deg = EC_GROUP_get_degree(g);
        let prime = EC_GROUP_get_field_type(g.cast()) == NID_PRIME_FIELD;
        EC_GROUP_free(g);
        if !prime || !(EC_MIN_BITS..=EC_MAX_BITS).contains(&deg) {
            return None;
        }
        let sn = OBJ_nid2sn(nid);
        if sn.is_null() {
            return None;
        }
        let sn = CStr::from_ptr(sn);
        (sn != c"SM2" && group_served(sn)).then_some(sn)
    }
}

/// `fhsm_ec_group_served`: the providers can make parameters on it.
fn group_served(group: &CStr) -> bool {
    // SAFETY: a C string; every object is freed here
    unsafe {
        let Some(c) = Owned::new(
            EVP_PKEY_CTX_new_from_name(null_mut(), c"EC".as_ptr(), null()),
            EVP_PKEY_CTX_free,
        ) else {
            return false;
        };
        let mut p = null_mut();
        let ok = EVP_PKEY_paramgen_init(c.0) == 1
            && EVP_PKEY_CTX_set_group_name(c.0, group.as_ptr()) == 1
            && EVP_PKEY_paramgen(c.0, &mut p) == 1;
        EVP_PKEY_free(p);
        ok
    }
}

/// C_GenerateKeyPair's report of a key OpenSSL did not make (`:6754-6758`, field issue #5):
/// the mechanism, then OpenSSL's reasons, which empties the thread's queue.
pub fn report_keygen_failure(mechanism: std::ffi::c_ulong) {
    super::sys::stderr(&format!(
        "[freehsm-c] C_GenerateKeyPair: key generation failed.\n  Mechanism 0x{mechanism:08x}. OpenSSL says :\n"
    ));
    // SAFETY: glibc's stderr stream
    unsafe { ERR_print_errors_fp(stderr) };
}

/// `fhsm_ecm_available`: both X25519 and X448 have a key manager.
pub fn ecm_available() -> bool {
    // SAFETY: C strings; each fetch is freed here (free takes NULL)
    unsafe {
        ERR_set_mark();
        let a = EVP_KEYMGMT_fetch(null_mut(), c"X25519".as_ptr(), null());
        let b = EVP_KEYMGMT_fetch(null_mut(), c"X448".as_ptr(), null());
        let ok = !a.is_null() && !b.is_null();
        EVP_KEYMGMT_free(a);
        EVP_KEYMGMT_free(b);
        ERR_pop_to_mark();
        ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curves_are_matched_as_c_matches_them() {
        assert_eq!(ec_curve(APPROVED[0].0, true), Curve::Named(c"P-256"));
        // secp256k1 is served by the default provider: named, refused in the strict build
        assert_eq!(
            ec_curve(b"\x06\x05\x2B\x81\x04\x00\x0A", false),
            Curve::Named(c"secp256k1")
        );
        // P-224 is a curve below 256 bits; sect163k1 a binary one; X25519 by name
        assert_eq!(
            ec_curve(b"\x06\x05\x2B\x81\x04\x00\x21", false),
            Curve::Unsupported
        );
        assert_eq!(
            ec_curve(b"\x06\x05\x2B\x81\x04\x00\x01", false),
            Curve::Unsupported
        );
        assert_eq!(ec_curve(b"\x06\x03\x2B\x65\x6E", false), Curve::Unsupported);
        // not an OID, empty, and P-256 cut short
        assert_eq!(ec_curve(b"\x30\x03\x02\x01\x01", false), Curve::Invalid);
        assert_eq!(ec_curve(b"", false), Curve::Invalid);
        assert_eq!(ec_curve(&APPROVED[0].0[..9], false), Curve::Invalid);
        // review M1: an OID with a byte after it is a curve to match_curve_ex, not to the
        // strict build's refusal
        let junk = [APPROVED[0].0, b"\x00"].concat();
        assert_eq!(ec_curve(&junk, false), Curve::Named(c"prime256v1"));
        assert_eq!(ec_curve(&junk, true), Curve::Invalid);
        assert_eq!(
            ec_curve(b"\x06\x05\x2B\x81\x04\x00\x0A", true),
            Curve::Unsupported
        );
    }

    #[test]
    fn generated_keys_encode_both_halves() {
        let k = Pkey::generate_ec(c"P-256").unwrap();
        assert_eq!(k.public_der().unwrap().len(), 91);
        assert!(k.private_der().unwrap().len() > 100);
        assert!(Pkey::generate(c"ML-KEM-512").is_some());
        assert!(Pkey::generate(c"NO-SUCH-KEY").is_none());
        let r = Pkey::generate_rsa(2048, Some(&[2, 0, 1])).unwrap();
        assert_eq!(r.bits(), 2048);
    }
}
