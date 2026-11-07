//! Key import for `C_CreateObject` (`src/fhsm_pkcs11.c:3696-4086`): a key from raw bytes or
//! from named parameters, an EC key from its scalar (`fhsm_ec_priv_from_scalar`,
//! `:6235-6295`), and the checks run on one. The template rules and their codes stay with
//! the caller.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::ptr::{null, null_mut};

use openssl_sys::{
    BN_bin2bn, BN_clear_free, BN_cmp, BN_num_bits, BN_secure_new, EC_GROUP_free,
    EC_GROUP_new_by_curve_name, EC_POINT_free, EC_POINT_mul, EC_POINT_new, EC_POINT_point2oct,
    EVP_PKEY_CTX, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, EVP_PKEY_KEYPAIR,
    EVP_PKEY_PUBLIC_KEY, EVP_PKEY_free, EVP_PKEY_fromdata, EVP_PKEY_fromdata_init,
    EVP_PKEY_new_raw_private_key_ex, EVP_PKEY_public_check, OBJ_sn2nid, OSSL_PARAM_BLD_free,
    OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_BN, OSSL_PARAM_BLD_push_octet_string,
    OSSL_PARAM_BLD_push_utf8_string, OSSL_PARAM_BLD_to_param, OSSL_PARAM_free,
    point_conversion_form_t,
};

use super::cipher::{Owned, Pkey};

unsafe extern "C" {
    // OpenSSL 3; not bound by openssl-sys
    fn EVP_PKEY_CTX_new_from_pkey(
        lib: *mut c_void,
        k: *mut openssl_sys::EVP_PKEY,
        props: *const c_char,
    ) -> *mut EVP_PKEY_CTX;
    fn EVP_PKEY_pairwise_check(c: *mut EVP_PKEY_CTX) -> c_int;
    fn EC_curve_nist2nid(name: *const c_char) -> c_int;
    fn EC_GROUP_get0_order(g: *const openssl_sys::EC_GROUP) -> *const openssl_sys::BIGNUM;
}

/// An RSA key's eight components as `EVP_PKEY_fromdata` names them: n, e, d, then the CRT five.
pub const RSA_PARAMS: [&CStr; 8] = [
    c"n",
    c"e",
    c"d",
    c"rsa-factor1",
    c"rsa-factor2",
    c"rsa-exponent1",
    c"rsa-exponent2",
    c"rsa-coefficient1",
];

/// One named parameter of `EVP_PKEY_fromdata`.
pub enum Param<'a> {
    Utf8(&'static CStr, &'a CStr),
    Octets(&'static CStr, &'a [u8]),
    /// A big-endian unsigned integer; empty is zero.
    Bn(&'static CStr, &'a [u8]),
}

fn owned(k: *mut openssl_sys::EVP_PKEY) -> Option<Pkey> {
    Owned::new(k, EVP_PKEY_free).map(Pkey)
}

/// `EVP_PKEY_fromdata` of `alg` with the built params, `sel` selecting what it imports.
///
/// # Safety
/// `bld` a live builder.
unsafe fn fromdata(alg: &CStr, sel: c_int, bld: *mut openssl_sys::OSSL_PARAM_BLD) -> Option<Pkey> {
    // SAFETY: the params and context are freed here; a C string
    unsafe {
        // A BIGNUM pushed from the secure heap lands in the array's secure block, which
        // OSSL_PARAM_free clears: the private parts (RSA d, p, q; an EC scalar) are copied there.
        let ps = Owned::new(OSSL_PARAM_BLD_to_param(bld), OSSL_PARAM_free)?;
        let c = Owned::new(
            EVP_PKEY_CTX_new_from_name(null_mut(), alg.as_ptr(), null()),
            EVP_PKEY_CTX_free,
        )?;
        let mut k = null_mut();
        if EVP_PKEY_fromdata_init(c.0) != 1 || EVP_PKEY_fromdata(c.0, &mut k, sel, ps.0) != 1 {
            EVP_PKEY_free(k);
            return None;
        }
        owned(k)
    }
}

/// `v` as a BIGNUM from the secure heap (so its param copy is cleared too); NULL on failure.
///
/// # Safety
/// None beyond the call: the result is the caller's to `BN_clear_free`.
unsafe fn secure_bn(v: &[u8]) -> *mut openssl_sys::BIGNUM {
    // SAFETY: a fresh BIGNUM, filled from v's bytes, freed here if that fails
    unsafe {
        let bn = BN_secure_new();
        if !bn.is_null() && BN_bin2bn(v.as_ptr(), v.len() as c_int, bn).is_null() {
            BN_clear_free(bn);
            return null_mut();
        }
        bn
    }
}

impl Pkey {
    /// `EVP_PKEY_new_raw_private_key_ex(NULL, alg, NULL, ...)`.
    pub fn raw_private(alg: &CStr, key: &[u8]) -> Option<Self> {
        // SAFETY: a C string; key readable for its length
        owned(unsafe {
            EVP_PKEY_new_raw_private_key_ex(
                null_mut(),
                alg.as_ptr(),
                null(),
                key.as_ptr(),
                key.len(),
            )
        })
    }

    /// `EVP_PKEY_fromdata` of `alg`: the public half, or with `pair` the whole key.
    /// shortcut: a BIGNUM or builder allocation failure is `None` too (C: HOST_MEMORY or
    /// FUNCTION_FAILED), reachable only out of memory.
    pub fn from_data(alg: &CStr, pair: bool, params: &[Param]) -> Option<Self> {
        // SAFETY: the builder and its BIGNUMs are freed here, the BIGNUMs after to_param
        // (push_BN keeps the pointer); every C string and slice outlives the build
        unsafe {
            let bld = Owned::new(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free)?;
            let mut bns = Vec::new();
            let mut ok = true;
            for p in params {
                ok = ok
                    && match p {
                        Param::Utf8(k, v) => {
                            OSSL_PARAM_BLD_push_utf8_string(bld.0, k.as_ptr(), v.as_ptr(), 0) == 1
                        }
                        Param::Octets(k, v) => {
                            OSSL_PARAM_BLD_push_octet_string(
                                bld.0,
                                k.as_ptr(),
                                v.as_ptr().cast(),
                                v.len(),
                            ) == 1
                        }
                        Param::Bn(k, v) => {
                            let bn = secure_bn(v);
                            !bn.is_null() && {
                                bns.push(bn);
                                OSSL_PARAM_BLD_push_BN(bld.0, k.as_ptr(), bn) == 1
                            }
                        }
                    };
            }
            let sel = if pair {
                EVP_PKEY_KEYPAIR
            } else {
                EVP_PKEY_PUBLIC_KEY
            };
            let k = if ok { fromdata(alg, sel, bld.0) } else { None };
            for bn in bns {
                BN_clear_free(bn);
            }
            k
        }
    }

    /// `fhsm_ec_priv_from_scalar`: the key on `curve` whose private scalar is `d`, 1 to 132
    /// bytes, non-zero and under the order; its public point computed here.
    pub fn ec_from_scalar(curve: &CStr, d: &[u8]) -> Option<Self> {
        if d.is_empty() || d.len() > 132 {
            return None;
        }
        // SAFETY: a C string; each object is freed here; d readable for its length
        unsafe {
            let mut nid = EC_curve_nist2nid(curve.as_ptr());
            if nid == 0 {
                nid = OBJ_sn2nid(curve.as_ptr());
            }
            let g = Owned::new(EC_GROUP_new_by_curve_name(nid), EC_GROUP_free)?;
            let s = Owned::new(secure_bn(d), BN_clear_free)?;
            let order = EC_GROUP_get0_order(g.0);
            if BN_num_bits(s.0) == 0 || order.is_null() || BN_cmp(s.0, order) >= 0 {
                return None;
            }
            let pt = Owned::new(EC_POINT_new(g.0), EC_POINT_free)?;
            if EC_POINT_mul(g.0, pt.0, s.0, null(), null(), null_mut()) != 1 {
                return None;
            }
            let form = point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED;
            let n = EC_POINT_point2oct(g.0, pt.0, form, null_mut(), 0, null_mut());
            let mut oct = vec![0u8; n];
            if n == 0 || EC_POINT_point2oct(g.0, pt.0, form, oct.as_mut_ptr(), n, null_mut()) != n {
                return None;
            }
            let bld = Owned::new(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free)?;
            if OSSL_PARAM_BLD_push_utf8_string(bld.0, c"group".as_ptr(), curve.as_ptr(), 0) != 1
                || OSSL_PARAM_BLD_push_BN(bld.0, c"priv".as_ptr(), s.0) != 1
                || OSSL_PARAM_BLD_push_octet_string(bld.0, c"pub".as_ptr(), oct.as_ptr().cast(), n)
                    != 1
            {
                return None;
            }
            fromdata(c"EC", EVP_PKEY_KEYPAIR, bld.0)
        }
    }

    /// `EVP_PKEY_public_check`, or with `pairwise` `EVP_PKEY_pairwise_check`, on a fresh
    /// context; false without one.
    pub fn check(&self, pairwise: bool) -> bool {
        // SAFETY: a live key; the context is freed here
        unsafe {
            let Some(c) = Owned::new(
                EVP_PKEY_CTX_new_from_pkey(null_mut(), self.0.0, null()),
                EVP_PKEY_CTX_free,
            ) else {
                return false;
            };
            (if pairwise {
                EVP_PKEY_pairwise_check(c.0)
            } else {
                EVP_PKEY_public_check(c.0)
            }) == 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" {
        fn EVP_PKEY_get_bn_param(
            k: *const openssl_sys::EVP_PKEY,
            name: *const c_char,
            bn: *mut *mut openssl_sys::BIGNUM,
        ) -> c_int;
        fn BN_bn2bin(bn: *const openssl_sys::BIGNUM, to: *mut u8) -> c_int;
    }

    fn parts(k: &Pkey) -> Vec<Vec<u8>> {
        RSA_PARAMS
            .iter()
            .map(|n| {
                let mut bn = null_mut();
                // SAFETY: a live key; the BIGNUM is ours and freed here
                unsafe {
                    assert_eq!(EVP_PKEY_get_bn_param(k.0.0, n.as_ptr(), &mut bn), 1);
                    let mut v = vec![0u8; (BN_num_bits(bn) as usize).div_ceil(8)];
                    BN_bn2bin(bn, v.as_mut_ptr());
                    BN_clear_free(bn);
                    v
                }
            })
            .collect()
    }

    fn rsa(v: &[Vec<u8>], pair: bool) -> Option<Pkey> {
        let ps: Vec<Param> = RSA_PARAMS
            .iter()
            .zip(v)
            .map(|(n, v)| Param::Bn(n, v))
            .collect();
        Pkey::from_data(c"RSA", pair, &ps)
    }

    #[test]
    fn imported_bignums_come_from_the_secure_heap() {
        // OSSL_PARAM_BLD puts a secure BIGNUM's copy in the block OSSL_PARAM_free clears.
        // SAFETY: a BIGNUM of our own, read and freed here
        unsafe {
            let bn = secure_bn(&[0, 0x12, 0x34]);
            assert!(!bn.is_null());
            assert_eq!(
                openssl_sys::BN_get_flags(bn, openssl_sys::BN_FLG_SECURE),
                openssl_sys::BN_FLG_SECURE
            );
            let mut out = [0u8; 2];
            assert_eq!(openssl_sys::BN_bn2bin(bn, out.as_mut_ptr()), 2);
            assert_eq!(out, [0x12, 0x34]);
            BN_clear_free(bn);
        }
    }

    #[test]
    fn rsa_checks() {
        let a = parts(&Pkey::generate_rsa(2048, None).unwrap());
        let b = parts(&Pkey::generate_rsa(2048, None).unwrap());
        assert!(rsa(&a, true).unwrap().check(true));
        let mut x = a.clone();
        x[2] = b[2].clone();
        // fromdata takes another key's d; the pairwise check does not (DIV-065)
        assert!(!rsa(&x, true).unwrap().check(true));
        assert!(rsa(&a[..2], false).unwrap().check(false));
        let empty = [Vec::new(), a[1].clone()];
        assert!(!rsa(&empty, false).is_some_and(|k| k.check(false)));
    }

    #[test]
    fn ec_scalar() {
        let mut d = [0u8; 32];
        d[31] = 7;
        let k = Pkey::ec_from_scalar(c"P-256", &d).unwrap();
        assert!(k.check(true) && k.is_a(c"EC"));
        for bad in [&[0u8; 32][..], &[0xFF; 32], &[]] {
            assert!(Pkey::ec_from_scalar(c"P-256", bad).is_none());
        }
    }
}
