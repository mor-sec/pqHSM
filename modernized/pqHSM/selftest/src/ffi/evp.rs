//! The extended KATs of `kat/cavp_extended.c:1610-1996` over OpenSSL directly, independent of the
//! crypto core so a bug there cannot mask itself: the published GCM, HMAC, SHA-2/SHA-3, CBC,
//! CTR, CMAC, ECDSA, HKDF and PBKDF2 vectors, GMAC two ways, and sign/verify, encrypt/decrypt,
//! encapsulate/decapsulate and derive round trips, most through a DER export and reload of the
//! public key. C's calls and C's legacy getters (`EVP_sha256()`, ...) in C's order; each KAT
//! passes only if every call succeeds and every comparison holds.

use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use std::ptr::{null, null_mut};

use openssl_sys::{
    ENGINE, EVP_CIPHER, EVP_CIPHER_CTX, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free,
    EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_padding, EVP_CTRL_GCM_GET_TAG, EVP_DigestFinal_ex,
    EVP_DigestInit_ex, EVP_DigestSign, EVP_DigestSignInit, EVP_DigestUpdate, EVP_DigestVerify,
    EVP_DigestVerifyInit, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate,
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
    EVP_MAC_CTX_free, EVP_MAC_CTX_new, EVP_MAC_fetch, EVP_MAC_final, EVP_MAC_free, EVP_MAC_init,
    EVP_MAC_update, EVP_MD, EVP_MD_CTX, EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_PKEY, EVP_PKEY_CTX,
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_from_name,
    EVP_PKEY_CTX_set_rsa_keygen_bits, EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_padding,
    EVP_PKEY_CTX_set_rsa_pss_saltlen, EVP_PKEY_CTX_set_signature_md, EVP_PKEY_PUBLIC_KEY,
    EVP_PKEY_Q_keygen, EVP_PKEY_decapsulate, EVP_PKEY_decapsulate_init, EVP_PKEY_decrypt,
    EVP_PKEY_decrypt_init, EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer,
    EVP_PKEY_encapsulate, EVP_PKEY_encapsulate_init, EVP_PKEY_encrypt, EVP_PKEY_encrypt_init,
    EVP_PKEY_free, EVP_PKEY_fromdata, EVP_PKEY_fromdata_init, EVP_PKEY_keygen,
    EVP_PKEY_keygen_init, EVP_PKEY_sign, EVP_PKEY_sign_init, EVP_PKEY_verify, EVP_PKEY_verify_init,
    EVP_aes_256_cbc, EVP_aes_256_ctr, EVP_aes_256_gcm, EVP_sha3_256, EVP_sha3_384, EVP_sha3_512,
    EVP_sha256, EVP_sha384, EVP_sha512, OPENSSL_free, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, RSA_PKCS1_OAEP_PADDING,
    RSA_PKCS1_PSS_PADDING, d2i_PUBKEY, i2d_PUBKEY,
};
use pqhsm_crypto::mem::ct_diff;
use pqhsm_crypto::rv;
use zeroize::Zeroizing;

use crate::kat::vectors::*;
use crate::kat::{Sink, Vid};

unsafe extern "C" {
    // OpenSSL 3; not bound by openssl-sys (its set_rsa_oaep_md is the pre-3 ctrl macro)
    fn EVP_EncryptInit_ex2(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        key: *const u8,
        iv: *const u8,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn EVP_Digest(
        data: *const c_void,
        count: usize,
        md: *mut u8,
        size: *mut c_uint,
        kind: *const EVP_MD,
        engine: *mut ENGINE,
    ) -> c_int;
    fn HMAC(
        md: *const EVP_MD,
        key: *const c_void,
        key_len: c_int,
        data: *const u8,
        data_len: usize,
        out: *mut u8,
        out_len: *mut c_uint,
    ) -> *mut u8;
    fn EVP_DigestSignInit_ex(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        mdname: *const c_char,
        libctx: *mut OSSL_LIB_CTX,
        props: *const c_char,
        pkey: *mut EVP_PKEY,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn EVP_DigestVerifyInit_ex(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        mdname: *const c_char,
        libctx: *mut OSSL_LIB_CTX,
        props: *const c_char,
        pkey: *mut EVP_PKEY,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_oaep_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;
    fn OSSL_PARAM_construct_utf8_string(
        key: *const c_char,
        buf: *mut c_char,
        bsize: usize,
    ) -> OSSL_PARAM;
    fn OSSL_PARAM_construct_uint64(key: *const c_char, buf: *mut u64) -> OSSL_PARAM;
    fn OSSL_PARAM_construct_int(key: *const c_char, buf: *mut c_int) -> OSSL_PARAM;
}

/// An OpenSSL object, freed on drop.
pub(super) struct Own<T>(pub(super) *mut T, unsafe extern "C" fn(*mut T));

impl<T> Own<T> {
    pub(super) fn new(p: *mut T, free: unsafe extern "C" fn(*mut T)) -> Option<Self> {
        (!p.is_null()).then_some(Self(p, free))
    }
}

impl<T> Drop for Own<T> {
    fn drop(&mut self) {
        // SAFETY: self.0 came from the allocator self.1 frees, and is freed once
        unsafe { (self.1)(self.0) }
    }
}

type Md = unsafe extern "C" fn() -> *const EVP_MD;

/// A legacy getter's method table.
fn md(get: Md) -> *const EVP_MD {
    // SAFETY: the getters take nothing and return static method tables
    unsafe { get() }
}

fn cipher(get: unsafe extern "C" fn() -> *const EVP_CIPHER) -> *const EVP_CIPHER {
    // SAFETY: as md
    unsafe { get() }
}

/// A KAT step: `None` fails the KAT.
pub(super) type Step = Option<()>;

/// OpenSSL's 1 for success.
pub(super) fn one(r: c_int) -> Step {
    (r == 1).then_some(())
}

/// OpenSSL's positive for success (the EVP_PKEY family).
pub(super) fn pos(r: c_int) -> Step {
    (r > 0).then_some(())
}

pub(super) fn holds(c: bool) -> Step {
    c.then_some(())
}

pub(super) fn eq(a: &[u8], b: &[u8]) -> Step {
    holds(ct_diff(a, b) == 0)
}

fn utf8(key: &CStr, v: &CStr) -> OSSL_PARAM {
    // SAFETY: OpenSSL only reads a utf8 param given to an init or a derive
    unsafe { OSSL_PARAM_construct_utf8_string(key.as_ptr(), v.as_ptr().cast_mut(), 0) }
}

fn octets(key: &CStr, v: &[u8]) -> OSSL_PARAM {
    // SAFETY: as utf8
    unsafe {
        OSSL_PARAM_construct_octet_string(key.as_ptr(), v.as_ptr().cast_mut().cast(), v.len())
    }
}

/// `fhsm_kat_cavp_extended` (`:1610-1996`): the 47 records after those already in `s`, or
/// ARGUMENTS_BAD when `s` fills first (C then leaves its count as it was). The RSA and
/// post-quantum keys are generated before their report-full check, as in C.
pub fn extended(s: &mut Sink) -> u32 {
    match run(s) {
        Ok(()) => rv::OK,
        Err(rv) => rv,
    }
}

/// A digest vector: algorithm, vector id, getter, message, digest.
type Hash = (
    &'static CStr,
    &'static CStr,
    Md,
    &'static [u8],
    &'static [u8],
);
/// An ECDSA vector: algorithm, vector id, curve, getter, public point, DER signature.
type Ecdsa = (
    &'static CStr,
    &'static CStr,
    &'static CStr,
    Md,
    &'static [u8],
    &'static [u8],
);

fn run(s: &mut Sink) -> Result<(), u32> {
    use Vid::Static as V;
    for (vid, aad, ct, tag) in [
        (c"SP800-38D-TC14", &[][..], &TC13_CT[..], &TC13_TAG[..]),
        (c"SP800-38D-TC15", &KA[..], &TC14_CT[..], &TC14_TAG[..]),
    ] {
        s.kat(c"AES-GCM-256", V(vid), || {
            gcm(&TC13_IV, aad, &KP, ct, tag).is_some()
        })?;
    }
    for (vid, key, data, mac) in [
        (c"RFC4231-TC1", &HKAT1_KEY[..], &HKAT1_DATA[..], &HKAT1_MAC),
        (c"RFC4231-TC2", &HKAT2_KEY[..], &HKAT2_DATA[..], &HKAT2_MAC),
        (c"RFC4231-TC3", &HKAT3_KEY[..], &HKAT3_DATA[..], &HKAT3_MAC),
        (c"RFC4231-TC6", &HKAT6_KEY[..], &HKAT6_DATA[..], &HKAT6_MAC),
    ] {
        s.kat(c"HMAC-SHA-256", V(vid), || hmac(key, data, mac).is_some())?;
    }
    let abc = &SHA_INPUT_ABC[..];
    let sha: [Hash; 12] = [
        (
            c"SHA-256",
            c"FIPS180-4-empty",
            EVP_sha256,
            &[],
            &SHA256_EMPTY,
        ),
        (c"SHA-256", c"FIPS180-4-abc", EVP_sha256, abc, &SHA256_ABC),
        (
            c"SHA-384",
            c"FIPS180-4-empty",
            EVP_sha384,
            &[],
            &SHA384_EMPTY,
        ),
        (c"SHA-384", c"FIPS180-4-abc", EVP_sha384, abc, &SHA384_ABC),
        (
            c"SHA-512",
            c"FIPS180-4-empty",
            EVP_sha512,
            &[],
            &SHA512_EMPTY,
        ),
        (c"SHA-512", c"FIPS180-4-abc", EVP_sha512, abc, &SHA512_ABC),
        (
            c"SHA3-256",
            c"FIPS202-A1-empty",
            EVP_sha3_256,
            &[],
            &SHA3_256_EMPTY,
        ),
        (
            c"SHA3-256",
            c"FIPS202-A1-abc",
            EVP_sha3_256,
            abc,
            &SHA3_256_ABC,
        ),
        (
            c"SHA3-384",
            c"FIPS202-A2-empty",
            EVP_sha3_384,
            &[],
            &SHA3_384_EMPTY,
        ),
        (
            c"SHA3-384",
            c"FIPS202-A2-abc",
            EVP_sha3_384,
            abc,
            &SHA3_384_ABC,
        ),
        (
            c"SHA3-512",
            c"FIPS202-A3-empty",
            EVP_sha3_512,
            &[],
            &SHA3_512_EMPTY,
        ),
        (
            c"SHA3-512",
            c"FIPS202-A3-abc",
            EVP_sha3_512,
            abc,
            &SHA3_512_ABC,
        ),
    ];
    for (alg, vid, get, data, exp) in sha {
        s.kat(alg, V(vid), || digest(md(get), data, exp).is_some())?;
    }
    s.kat(c"AES-256-CBC", V(c"SP800-38A-F.2.5"), || {
        block(
            cipher(EVP_aes_256_cbc),
            &AES256_CBC_IV,
            true,
            &AES256_CBC_CT,
        )
        .is_some()
    })?;
    s.kat(c"AES-256-CTR", V(c"SP800-38A-F.5.5"), || {
        block(
            cipher(EVP_aes_256_ctr),
            &AES256_CTR_IC,
            false,
            &AES256_CTR_CT,
        )
        .is_some()
    })?;
    for (vid, n, tag) in [
        (c"SP800-38B-D.3-Ex7", 0, &AES256_CMAC_EMPTY_TAG),
        (c"SP800-38B-D.3-Ex8", 16, &AES256_CMAC_16_TAG),
        (c"SP800-38B-D.3-Ex9", 40, &AES256_CMAC_40_TAG),
    ] {
        s.kat(c"AES-256-CMAC", V(vid), || {
            cmac(&AES_PLAINTEXT_64[..n], tag).is_some()
        })?;
    }
    s.kat(c"AES-256-GMAC", V(c"SP800-38D-self-consistency"), || {
        gmac_two_ways().is_some()
    })?;
    let ecdsa: [Ecdsa; 3] = [
        (
            c"ECDSA-P256-SHA256",
            c"RFC6979-A.2.5",
            c"P-256",
            EVP_sha256,
            &ECDSA_P256_PUB,
            &ECDSA_P256_SIG,
        ),
        (
            c"ECDSA-P384-SHA384",
            c"RFC6979-A.2.6",
            c"P-384",
            EVP_sha384,
            &ECDSA_P384_PUB,
            &ECDSA_P384_SIG,
        ),
        (
            c"ECDSA-P521-SHA512",
            c"RFC6979-A.2.7",
            c"P-521",
            EVP_sha512,
            &ECDSA_P521_PUB,
            &ECDSA_P521_SIG,
        ),
    ];
    for (alg, vid, curve, get, public, sig) in ecdsa {
        s.kat(alg, V(vid), || {
            ecdsa_verify(curve, md(get), public, sig).is_some()
        })?;
    }
    let self_122 = V(c"v1.2.2-self-consistency");
    let ecdsa_rt: [(&CStr, &CStr, Md); 3] = [
        (c"ECDSA-P256-export-roundtrip", c"P-256", EVP_sha256),
        (c"ECDSA-P384-export-roundtrip", c"P-384", EVP_sha384),
        (c"ECDSA-P521-export-roundtrip", c"P-521", EVP_sha512),
    ];
    for (alg, curve, get) in ecdsa_rt {
        s.kat(alg, self_122, || ecdsa_export(curve, md(get)).is_some())?;
    }
    let self_130 = V(c"v1.3.0-self-consistency");
    s.kat(c"RSA-2048-PSS-SHA256-export-roundtrip", self_130, || {
        rsa_pss_export(md(EVP_sha256)).is_some()
    })?;
    s.kat(c"RSA-2048-OAEP-SHA256-export-roundtrip", self_130, || {
        rsa_oaep_export(md(EVP_sha256)).is_some()
    })?;
    s.kat(c"Ed25519-export-roundtrip", self_130, || {
        sign_export(c"ED25519", &ED25519_RT_MSG, 128).is_some()
    })?;
    s.kat(c"ML-DSA-65-export-roundtrip", self_130, || {
        sign_export(c"ML-DSA-65", &MLDSA_RT_MSG, 5000).is_some()
    })?;
    s.kat(c"ML-KEM-768-export-roundtrip", self_130, || {
        kem_export(c"ML-KEM-768").is_some()
    })?;
    for (alg, curve) in [
        (c"ECDH-P256-export-roundtrip", c"P-256"),
        (c"ECDH-P384-export-roundtrip", c"P-384"),
        (c"ECDH-P521-export-roundtrip", c"P-521"),
    ] {
        s.kat(alg, self_130, || ecdh_export(curve).is_some())?;
    }
    for (vid, ikm, salt, info, okm) in [
        (
            c"RFC5869-A.1",
            &HKDF_TC1_IKM[..],
            &HKDF_TC1_SALT[..],
            &HKDF_TC1_INFO[..],
            &HKDF_TC1_OKM[..],
        ),
        (
            c"RFC5869-A.2",
            &HKDF_TC2_IKM[..],
            &HKDF_TC2_SALT[..],
            &HKDF_TC2_INFO[..],
            &HKDF_TC2_OKM[..],
        ),
    ] {
        s.kat(c"HKDF-SHA-256", V(vid), || {
            hkdf(ikm, salt, info, okm).is_some()
        })?;
    }
    for (vid, iter, dk) in [
        (c"RFC6070-TC1", 1, &PBKDF2_TC1_DK),
        (c"RFC6070-TC2", 2, &PBKDF2_TC2_DK),
    ] {
        s.kat(c"PBKDF2-HMAC-SHA-1", V(vid), || {
            pbkdf2_sha1(&PBKDF2_TC1_PWD, &PBKDF2_TC1_SALT, iter, dk).is_some()
        })?;
    }

    let rsa = keygen(c"RSA", true);
    let with = |k: &Option<Own<EVP_PKEY>>, f: fn(*mut EVP_PKEY) -> Step| {
        k.as_ref().is_some_and(|k| f(k.0).is_some())
    };
    s.kat(c"RSA-2048-PSS-SHA256", V(c"selftest-sign+verify"), || {
        with(&rsa, rsa_pss)
    })?;
    s.kat(
        c"RSA-2048-OAEP-SHA256",
        V(c"selftest-encrypt+decrypt"),
        || with(&rsa, rsa_oaep),
    )?;
    drop(rsa);
    let mlkem = keygen(c"ML-KEM-768", false);
    s.kat(c"ML-KEM-768", V(c"selftest-encaps+decaps"), || {
        with(&mlkem, kem)
    })?;
    drop(mlkem);
    let mldsa = keygen(c"ML-DSA-65", false);
    s.kat(c"ML-DSA-65", V(c"selftest-sign+verify"), || {
        with(&mldsa, pq_sign)
    })?;
    drop(mldsa);
    let slhdsa = keygen(c"SLH-DSA-SHA2-128f", false);
    s.kat(c"SLH-DSA-SHA2-128f", V(c"selftest-sign+verify"), || {
        with(&slhdsa, pq_sign)
    })?;
    Ok(())
}

// Every function below: SAFETY of its unsafe block, once: each pointer passed is a live
// OpenSSL object held by an Own, a C string, or a slice with the length passed beside it;
// OpenSSL writes only into buffers whose capacity it is told; DER from i2d_PUBKEY is freed
// with OPENSSL_free.

/// `run_aesgcm_vec` (`:255-286`): encrypt under `kK`, compare the ciphertext and tag.
fn gcm(iv: &[u8], aad: &[u8], pt: &[u8], ct: &[u8], tag: &[u8]) -> Step {
    let mut out = Zeroizing::new([0u8; 128]);
    let mut out_tag = Zeroizing::new([0u8; 16]);
    // SAFETY: see above; pt fits out (64 of 128 bytes)
    unsafe {
        let c = Own::new(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free)?;
        let (mut n, mut tmp) = (0, 0);
        one(EVP_EncryptInit_ex2(
            c.0,
            EVP_aes_256_gcm(),
            KK.as_ptr(),
            iv.as_ptr(),
            null(),
        ))?;
        if !aad.is_empty() {
            one(EVP_EncryptUpdate(
                c.0,
                null_mut(),
                &mut tmp,
                aad.as_ptr(),
                aad.len() as c_int,
            ))?;
        }
        one(EVP_EncryptUpdate(
            c.0,
            out.as_mut_ptr(),
            &mut n,
            pt.as_ptr(),
            pt.len() as c_int,
        ))?;
        one(EVP_EncryptFinal_ex(
            c.0,
            out.as_mut_ptr().add(n as usize),
            &mut tmp,
        ))?;
        one(EVP_CIPHER_CTX_ctrl(
            c.0,
            EVP_CTRL_GCM_GET_TAG,
            16,
            out_tag.as_mut_ptr().cast(),
        ))?;
    }
    eq(&out[..pt.len()], &ct[..pt.len()])?;
    eq(&out_tag[..], tag)
}

/// `run_hmac_vec` (`:360-372`): HMAC-SHA-256.
fn hmac(key: &[u8], data: &[u8], exp: &[u8]) -> Step {
    let mut mac = Zeroizing::new([0u8; 32]);
    let mut n: c_uint = 0;
    // SAFETY: see above; mac holds a SHA-256 output
    let r = unsafe {
        HMAC(
            EVP_sha256(),
            key.as_ptr().cast(),
            key.len() as c_int,
            data.as_ptr(),
            data.len(),
            mac.as_mut_ptr(),
            &mut n,
        )
    };
    holds(!r.is_null() && n == 32)?;
    eq(&mac[..], exp)
}

/// `run_sha_vec` (`:461-470`): a one-shot digest of the expected length.
fn digest(md: *const EVP_MD, data: &[u8], exp: &[u8]) -> Step {
    let mut out = Zeroizing::new([0u8; 64]);
    let mut n: c_uint = 0;
    // SAFETY: see above; out holds any of the six digests
    one(unsafe {
        EVP_Digest(
            data.as_ptr().cast(),
            data.len(),
            out.as_mut_ptr(),
            &mut n,
            md,
            null_mut(),
        )
    })?;
    holds(n as usize == exp.len())?;
    eq(&out[..exp.len()], exp)
}

/// `run_aescbc_vec` and `run_aesctr_vec` (`:540-582`): the four SP 800-38A blocks under
/// `aes256_key`, CBC without padding.
fn block(cipher: *const EVP_CIPHER, iv: &[u8], unpadded: bool, exp: &[u8]) -> Step {
    let pt = &AES_PLAINTEXT_64;
    let mut out = Zeroizing::new([0u8; 64]);
    // SAFETY: see above; 64 blocks-aligned bytes in, 64 out
    unsafe {
        let c = Own::new(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free)?;
        let (mut n, mut fin) = (0, 0);
        one(EVP_EncryptInit_ex(
            c.0,
            cipher,
            null_mut(),
            AES256_KEY.as_ptr(),
            iv.as_ptr(),
        ))?;
        if unpadded {
            EVP_CIPHER_CTX_set_padding(c.0, 0);
        }
        one(EVP_EncryptUpdate(
            c.0,
            out.as_mut_ptr(),
            &mut n,
            pt.as_ptr(),
            pt.len() as c_int,
        ))?;
        one(EVP_EncryptFinal_ex(
            c.0,
            out.as_mut_ptr().add(n as usize),
            &mut fin,
        ))?;
        holds((n + fin) as usize == pt.len())?;
    }
    eq(&out[..], exp)
}

/// `run_aescmac_vec` (`:1213-1237`): AES-256-CMAC.
fn cmac(msg: &[u8], exp: &[u8]) -> Step {
    let mut tag = Zeroizing::new([0u8; 16]);
    let mut n = 0;
    // SAFETY: see above
    unsafe {
        let mac = Own::new(
            EVP_MAC_fetch(null_mut(), c"CMAC".as_ptr(), null()),
            EVP_MAC_free,
        )?;
        let ctx = Own::new(EVP_MAC_CTX_new(mac.0), EVP_MAC_CTX_free)?;
        let params = [utf8(c"cipher", c"AES-256-CBC"), OSSL_PARAM_construct_end()];
        one(EVP_MAC_init(
            ctx.0,
            AES256_KEY.as_ptr(),
            AES256_KEY.len(),
            params.as_ptr(),
        ))?;
        if !msg.is_empty() {
            one(EVP_MAC_update(ctx.0, msg.as_ptr(), msg.len()))?;
        }
        one(EVP_MAC_final(ctx.0, tag.as_mut_ptr(), &mut n, 16))?;
    }
    holds(n == 16)?;
    eq(&tag[..], exp)
}

/// `run_aesgmac_consistency` (`:169-238`): GMAC as EVP_MAC "GMAC" and as the tag of GCM over
/// an empty plaintext must agree (SP 800-38D §6.4), under `kK`, the TC13 IV and `kA`.
fn gmac_two_ways() -> Step {
    let (mut a, mut b) = (Zeroizing::new([0u8; 16]), Zeroizing::new([0u8; 16]));
    // SAFETY: see above
    unsafe {
        let mac = Own::new(
            EVP_MAC_fetch(null_mut(), c"GMAC".as_ptr(), null()),
            EVP_MAC_free,
        )?;
        let ctx = Own::new(EVP_MAC_CTX_new(mac.0), EVP_MAC_CTX_free)?;
        drop(mac);
        let params = [
            utf8(c"cipher", c"AES-256-GCM"),
            octets(c"iv", &TC13_IV),
            OSSL_PARAM_construct_end(),
        ];
        let mut n = 16;
        one(EVP_MAC_init(ctx.0, KK.as_ptr(), KK.len(), params.as_ptr()))?;
        one(EVP_MAC_update(ctx.0, KA.as_ptr(), KA.len()))?;
        one(EVP_MAC_final(ctx.0, a.as_mut_ptr(), &mut n, 16))?;
        holds(n == 16)?;

        let c = Own::new(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free)?;
        let (mut outl, mut tmp) = (0, 0);
        one(EVP_EncryptInit_ex2(
            c.0,
            EVP_aes_256_gcm(),
            KK.as_ptr(),
            TC13_IV.as_ptr(),
            null(),
        ))?;
        one(EVP_EncryptUpdate(
            c.0,
            null_mut(),
            &mut tmp,
            KA.as_ptr(),
            KA.len() as c_int,
        ))?;
        one(EVP_EncryptFinal_ex(c.0, null_mut(), &mut outl))?;
        one(EVP_CIPHER_CTX_ctrl(
            c.0,
            EVP_CTRL_GCM_GET_TAG,
            16,
            b.as_mut_ptr().cast(),
        ))?;
    }
    eq(&a[..], &b[..])
}

/// `ecdsa_pubkey_from_raw` + `run_ecdsa_verify_vec` (`:723-760`): the RFC 6979 signature on
/// "sample" verifies under the published point.
fn ecdsa_verify(curve: &CStr, md: *const EVP_MD, public: &[u8], sig: &[u8]) -> Step {
    // SAFETY: see above
    unsafe {
        let ctx = Own::new(
            EVP_PKEY_CTX_new_from_name(null_mut(), c"EC".as_ptr(), null()),
            EVP_PKEY_CTX_free,
        )?;
        let mut params = [
            utf8(c"group", curve),
            octets(c"pub", public),
            OSSL_PARAM_construct_end(),
        ];
        let mut pkey = null_mut();
        if EVP_PKEY_fromdata_init(ctx.0) > 0 {
            EVP_PKEY_fromdata(ctx.0, &mut pkey, EVP_PKEY_PUBLIC_KEY, params.as_mut_ptr());
        }
        drop(ctx);
        let pkey = Own::new(pkey, EVP_PKEY_free)?;
        let m = Own::new(EVP_MD_CTX_new(), EVP_MD_CTX_free)?;
        one(EVP_DigestVerifyInit(
            m.0,
            null_mut(),
            md,
            null_mut(),
            pkey.0,
        ))?;
        let msg = &ECDSA_MSG_SAMPLE;
        one(EVP_DigestVerify(
            m.0,
            sig.as_ptr(),
            sig.len(),
            msg.as_ptr(),
            msg.len(),
        ))
    }
}

/// The public half of `pkey` through `i2d_PUBKEY` and back through `d2i_PUBKEY`, as an
/// external verifier would load it.
fn reload(pkey: *mut EVP_PKEY) -> Option<Own<EVP_PKEY>> {
    // SAFETY: see above
    unsafe {
        let mut der = null_mut();
        let n = i2d_PUBKEY(pkey, &mut der);
        let reloaded = if n > 0 {
            let mut p = der.cast_const();
            d2i_PUBKEY(null_mut(), &mut p, c_long::from(n))
        } else {
            null_mut()
        };
        OPENSSL_free(der.cast());
        Own::new(reloaded, EVP_PKEY_free)
    }
}

/// `EVP_PKEY_Q_keygen` for an EC curve, an RSA-2048 key or a named algorithm.
fn q_keygen(alg: &CStr, curve: Option<&CStr>) -> Option<Own<EVP_PKEY>> {
    // SAFETY: see above; the variadic argument is the one alg takes: a curve name for "EC", the
    // size_t bits for "RSA", nothing otherwise
    let k = unsafe {
        match (alg.to_bytes(), curve) {
            (b"EC", Some(c)) => EVP_PKEY_Q_keygen(null_mut(), null(), alg.as_ptr(), c.as_ptr()),
            (b"RSA", _) => EVP_PKEY_Q_keygen(null_mut(), null(), alg.as_ptr(), 2048usize),
            _ => EVP_PKEY_Q_keygen(null_mut(), null(), alg.as_ptr()),
        }
    };
    Own::new(k, EVP_PKEY_free)
}

/// The digest of `msg` through EVP_DigestInit_ex / Update / Final_ex.
fn hash(md: *const EVP_MD, msg: &[u8]) -> Option<(Zeroizing<[u8; 64]>, usize)> {
    let mut out = Zeroizing::new([0u8; 64]);
    let mut n: c_uint = 0;
    // SAFETY: see above
    unsafe {
        let m = Own::new(EVP_MD_CTX_new(), EVP_MD_CTX_free)?;
        one(EVP_DigestInit_ex(m.0, md, null_mut()))?;
        one(EVP_DigestUpdate(m.0, msg.as_ptr().cast(), msg.len()))?;
        one(EVP_DigestFinal_ex(m.0, out.as_mut_ptr(), &mut n))?;
    }
    Some((out, n as usize))
}

/// RSA-PSS's parameters on a sign or verify context: the hash for signature and MGF1, and a
/// salt as long as the hash.
fn pss(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> Step {
    // SAFETY: see above
    unsafe {
        pos(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING))?;
        pos(EVP_PKEY_CTX_set_signature_md(ctx, md))?;
        pos(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md))?;
        pos(EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, -1))
    }
}

/// RSA-OAEP with `md` for both the label hash and MGF1.
fn oaep(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> Step {
    // SAFETY: see above
    unsafe {
        pos(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING))?;
        pos(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md))?;
        pos(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md))
    }
}

/// Sign a digest with `EVP_PKEY_sign` and verify it on the reloaded public key: ECDSA
/// (`run_ecdsa_export_roundtrip`, `:787-862`), RSA-PSS (`run_rsa_pss_export_roundtrip`,
/// `:872-938`, with `params`).
fn sign_digest_export(
    pkey: Own<EVP_PKEY>,
    md: *const EVP_MD,
    msg: &[u8],
    params: Option<fn(*mut EVP_PKEY_CTX, *const EVP_MD) -> Step>,
    sig_cap: usize,
) -> Step {
    let (digest, n) = hash(md, msg)?;
    let mut sig = Zeroizing::new(vec![0u8; sig_cap]);
    let mut sig_len = sig_cap;
    // SAFETY: see above
    unsafe {
        let sctx = Own::new(EVP_PKEY_CTX_new(pkey.0, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_sign_init(sctx.0))?;
        if let Some(p) = params {
            p(sctx.0, md)?;
        }
        pos(EVP_PKEY_sign(
            sctx.0,
            sig.as_mut_ptr(),
            &mut sig_len,
            digest.as_ptr(),
            n,
        ))?;
        let reloaded = reload(pkey.0)?;
        let vctx = Own::new(EVP_PKEY_CTX_new(reloaded.0, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_verify_init(vctx.0))?;
        if let Some(p) = params {
            p(vctx.0, md)?;
        }
        one(EVP_PKEY_verify(
            vctx.0,
            sig.as_ptr(),
            sig_len,
            digest.as_ptr(),
            n,
        ))
    }
}

fn ecdsa_export(curve: &CStr, md: *const EVP_MD) -> Step {
    sign_digest_export(q_keygen(c"EC", Some(curve))?, md, &ECDSA_RT_MSG, None, 256)
}

fn rsa_pss_export(md: *const EVP_MD) -> Step {
    sign_digest_export(
        q_keygen(c"RSA", None)?,
        md,
        &RSA_PSS_RT_MSG,
        Some(pss),
        1024,
    )
}

/// `run_rsa_oaep_export_roundtrip` (`:948-1009`): encrypt to the reloaded public key, decrypt
/// with the key pair.
fn rsa_oaep_export(md: *const EVP_MD) -> Step {
    let pkey = q_keygen(c"RSA", None)?;
    let reloaded = reload(pkey.0)?;
    let pt = &RSA_OAEP_RT_PT;
    let (mut ct, mut out) = (Zeroizing::new([0u8; 1024]), Zeroizing::new([0u8; 512]));
    let (mut ct_len, mut out_len) = (ct.len(), out.len());
    // SAFETY: see above
    unsafe {
        let e = Own::new(EVP_PKEY_CTX_new(reloaded.0, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_encrypt_init(e.0))?;
        oaep(e.0, md)?;
        pos(EVP_PKEY_encrypt(
            e.0,
            ct.as_mut_ptr(),
            &mut ct_len,
            pt.as_ptr(),
            pt.len(),
        ))?;
        let d = Own::new(EVP_PKEY_CTX_new(pkey.0, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_decrypt_init(d.0))?;
        oaep(d.0, md)?;
        pos(EVP_PKEY_decrypt(
            d.0,
            out.as_mut_ptr(),
            &mut out_len,
            ct.as_ptr(),
            ct_len,
        ))?;
    }
    holds(out_len == pt.len())?;
    eq(&out[..out_len], pt)
}

/// `run_evp_digestsign_export_roundtrip` (`:1015-1069`): Ed25519 and ML-DSA sign the message
/// themselves (no digest); verify on the reloaded public key.
fn sign_export(alg: &CStr, msg: &[u8], sig_cap: usize) -> Step {
    let mut sig = Zeroizing::new(vec![0u8; sig_cap]);
    let mut sig_len = sig_cap;
    let pkey = q_keygen(alg, None)?;
    // SAFETY: see above
    unsafe {
        let s = Own::new(EVP_MD_CTX_new(), EVP_MD_CTX_free)?;
        one(EVP_DigestSignInit(
            s.0,
            null_mut(),
            null(),
            null_mut(),
            pkey.0,
        ))?;
        one(EVP_DigestSign(
            s.0,
            sig.as_mut_ptr(),
            &mut sig_len,
            msg.as_ptr(),
            msg.len(),
        ))?;
        let reloaded = reload(pkey.0)?;
        let v = Own::new(EVP_MD_CTX_new(), EVP_MD_CTX_free)?;
        one(EVP_DigestVerifyInit(
            v.0,
            null_mut(),
            null(),
            null_mut(),
            reloaded.0,
        ))?;
        one(EVP_DigestVerify(
            v.0,
            sig.as_ptr(),
            sig_len,
            msg.as_ptr(),
            msg.len(),
        ))
    }
}

/// `run_mlkem_export_roundtrip` (`:1077-1124`): encapsulate to the reloaded public key,
/// decapsulate with the key pair, compare the secrets.
fn kem_export(alg: &CStr) -> Step {
    let pkey = q_keygen(alg, None)?;
    let reloaded = reload(pkey.0)?;
    let mut ct = [0u8; 2048];
    let (mut ss1, mut ss2) = (Zeroizing::new([0u8; 64]), Zeroizing::new([0u8; 64]));
    let (mut ct_len, mut n1, mut n2) = (ct.len(), ss1.len(), ss2.len());
    // SAFETY: see above
    unsafe {
        let e = Own::new(EVP_PKEY_CTX_new(reloaded.0, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_encapsulate_init(e.0, null()))?;
        pos(EVP_PKEY_encapsulate(
            e.0,
            ct.as_mut_ptr(),
            &mut ct_len,
            ss1.as_mut_ptr(),
            &mut n1,
        ))?;
        let d = Own::new(EVP_PKEY_CTX_new(pkey.0, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_decapsulate_init(d.0, null()))?;
        pos(EVP_PKEY_decapsulate(
            d.0,
            ss2.as_mut_ptr(),
            &mut n2,
            ct.as_ptr(),
            ct_len,
        ))?;
    }
    holds(n1 != 0 && n1 == n2)?;
    eq(&ss1[..n1], &ss2[..n1])
}

/// One ECDH derive into a 256-byte buffer, asking the length first.
fn derive(own: *mut EVP_PKEY, peer: *mut EVP_PKEY, out: &mut [u8; 256]) -> Option<usize> {
    let mut n = out.len();
    // SAFETY: see above
    unsafe {
        let d = Own::new(EVP_PKEY_CTX_new(own, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_derive_init(d.0))?;
        pos(EVP_PKEY_derive_set_peer(d.0, peer))?;
        pos(EVP_PKEY_derive(d.0, null_mut(), &mut n))?;
        holds(n != 0 && n <= out.len())?;
        pos(EVP_PKEY_derive(d.0, out.as_mut_ptr(), &mut n))?;
    }
    Some(n)
}

/// `run_ecdh_export_roundtrip` (`:1150-1207`): Alice's secret with Bob's key and with Bob's
/// reloaded public key agree.
fn ecdh_export(curve: &CStr) -> Step {
    let alice = q_keygen(c"EC", Some(curve))?;
    let bob = q_keygen(c"EC", Some(curve))?;
    let (mut ss1, mut ss2) = (Zeroizing::new([0u8; 256]), Zeroizing::new([0u8; 256]));
    let n1 = derive(alice.0, bob.0, &mut ss1)?;
    let bob_pub = reload(bob.0)?;
    let n2 = derive(alice.0, bob_pub.0, &mut ss2)?;
    holds(n1 == n2)?;
    eq(&ss1[..n1], &ss2[..n1])
}

/// One EVP_KDF derive of `exp.len()` bytes, compared with `exp`.
fn kdf(name: &CStr, params: &[OSSL_PARAM], exp: &[u8]) -> Step {
    let mut out = Zeroizing::new([0u8; 128]);
    // SAFETY: see above; exp is at most 82 bytes
    unsafe {
        let k = Own::new(
            EVP_KDF_fetch(null_mut(), name.as_ptr(), null()),
            EVP_KDF_free,
        )?;
        let ctx = Own::new(EVP_KDF_CTX_new(k.0), EVP_KDF_CTX_free)?;
        one(EVP_KDF_derive(
            ctx.0,
            out.as_mut_ptr(),
            exp.len(),
            params.as_ptr(),
        ))?;
    }
    eq(&out[..exp.len()], exp)
}

/// `run_hkdf_vec` (`:1311-1340`): HKDF-SHA-256, extract then expand.
fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], okm: &[u8]) -> Step {
    let params = [
        utf8(c"digest", c"SHA256"),
        octets(c"key", ikm),
        octets(c"salt", salt),
        octets(c"info", info),
        // SAFETY: the end marker reads nothing
        unsafe { OSSL_PARAM_construct_end() },
    ];
    kdf(c"HKDF", &params, okm)
}

/// `run_pbkdf2_vec` (`:1343-1374`): PBKDF2-HMAC-SHA-1 with the SP 800-132 checks off.
fn pbkdf2_sha1(pwd: &[u8], salt: &[u8], mut iter: u64, dk: &[u8]) -> Step {
    let mut pkcs5: c_int = 1;
    // SAFETY: iter and pkcs5 outlive the derive, which only reads them
    let params = unsafe {
        [
            utf8(c"digest", c"SHA1"),
            octets(c"pass", pwd),
            octets(c"salt", salt),
            OSSL_PARAM_construct_uint64(c"iter".as_ptr(), &mut iter),
            OSSL_PARAM_construct_int(c"pkcs5".as_ptr(), &mut pkcs5),
            OSSL_PARAM_construct_end(),
        ]
    };
    kdf(c"PBKDF2", &params, dk)
}

/// `rsa_keygen_2048` (`:1408-1420`) and `pq_keygen` (`:1523-1535`): a key pair through a
/// context made by name; `None` when any step fails.
fn keygen(alg: &CStr, rsa_2048: bool) -> Option<Own<EVP_PKEY>> {
    // SAFETY: see above
    unsafe {
        let ctx = Own::new(
            EVP_PKEY_CTX_new_from_name(null_mut(), alg.as_ptr(), null()),
            EVP_PKEY_CTX_free,
        )?;
        pos(EVP_PKEY_keygen_init(ctx.0))?;
        if rsa_2048 {
            pos(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.0, 2048))?;
        }
        let mut pkey = null_mut();
        let r = EVP_PKEY_keygen(ctx.0, &mut pkey);
        let pkey = Own::new(pkey, EVP_PKEY_free);
        pos(r)?;
        pkey
    }
}

/// `run_rsa_pss_roundtrip` (`:1422-1455`): EVP_DigestSign with SHA-256 and PSS, salt as long as
/// the digest, then EVP_DigestVerify on the same key.
fn rsa_pss(pkey: *mut EVP_PKEY) -> Step {
    let mut sig = Zeroizing::new([0u8; 512]);
    let mut sig_len = sig.len();
    let msg = &RSA_SELFTEST_MSG;
    // SAFETY: see above; pkctx belongs to its EVP_MD_CTX and is not freed here
    unsafe {
        let mut pkctx = null_mut();
        let m = Own::new(EVP_MD_CTX_new(), EVP_MD_CTX_free)?;
        one(EVP_DigestSignInit(
            m.0,
            &mut pkctx,
            EVP_sha256(),
            null_mut(),
            pkey,
        ))?;
        pos(EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING))?;
        pos(EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, -1))?;
        one(EVP_DigestSign(
            m.0,
            sig.as_mut_ptr(),
            &mut sig_len,
            msg.as_ptr(),
            msg.len(),
        ))?;
        drop(m);
        let m = Own::new(EVP_MD_CTX_new(), EVP_MD_CTX_free)?;
        one(EVP_DigestVerifyInit(
            m.0,
            &mut pkctx,
            EVP_sha256(),
            null_mut(),
            pkey,
        ))?;
        pos(EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING))?;
        pos(EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, -1))?;
        one(EVP_DigestVerify(
            m.0,
            sig.as_ptr(),
            sig_len,
            msg.as_ptr(),
            msg.len(),
        ))
    }
}

/// `run_rsa_oaep_roundtrip` (`:1457-1490`): OAEP-SHA-256 encrypt and decrypt with one key.
fn rsa_oaep(pkey: *mut EVP_PKEY) -> Step {
    let msg = &RSA_SELFTEST_MSG;
    let (mut ct, mut pt) = (Zeroizing::new([0u8; 512]), Zeroizing::new([0u8; 256]));
    let (mut ct_len, mut pt_len) = (ct.len(), pt.len());
    // SAFETY: see above
    unsafe {
        let e = Own::new(EVP_PKEY_CTX_new(pkey, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_encrypt_init(e.0))?;
        oaep(e.0, EVP_sha256())?;
        pos(EVP_PKEY_encrypt(
            e.0,
            ct.as_mut_ptr(),
            &mut ct_len,
            msg.as_ptr(),
            msg.len(),
        ))?;
        let d = Own::new(EVP_PKEY_CTX_new(pkey, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_decrypt_init(d.0))?;
        oaep(d.0, EVP_sha256())?;
        pos(EVP_PKEY_decrypt(
            d.0,
            pt.as_mut_ptr(),
            &mut pt_len,
            ct.as_ptr(),
            ct_len,
        ))?;
    }
    holds(pt_len == msg.len())?;
    eq(&pt[..pt_len], msg)
}

/// `run_mlkem_roundtrip` (`:1538-1572`): encapsulate and decapsulate with one key, asking the
/// lengths first.
fn kem(pkey: *mut EVP_PKEY) -> Step {
    let mut ct = [0u8; 2048];
    let (mut a, mut b) = (Zeroizing::new([0u8; 64]), Zeroizing::new([0u8; 64]));
    let (mut ct_len, mut a_len, mut b_len) = (0, 0, 0);
    // SAFETY: see above; each length is checked against its buffer before the buffer is passed
    unsafe {
        let e = Own::new(EVP_PKEY_CTX_new(pkey, null_mut()), EVP_PKEY_CTX_free)?;
        let d = Own::new(EVP_PKEY_CTX_new(pkey, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_encapsulate_init(e.0, null()))?;
        pos(EVP_PKEY_decapsulate_init(d.0, null()))?;
        pos(EVP_PKEY_encapsulate(
            e.0,
            null_mut(),
            &mut ct_len,
            null_mut(),
            &mut a_len,
        ))?;
        holds(ct_len <= ct.len() && a_len <= a.len())?;
        pos(EVP_PKEY_encapsulate(
            e.0,
            ct.as_mut_ptr(),
            &mut ct_len,
            a.as_mut_ptr(),
            &mut a_len,
        ))?;
        pos(EVP_PKEY_decapsulate(
            d.0,
            null_mut(),
            &mut b_len,
            ct.as_ptr(),
            ct_len,
        ))?;
        holds(b_len <= b.len())?;
        pos(EVP_PKEY_decapsulate(
            d.0,
            b.as_mut_ptr(),
            &mut b_len,
            ct.as_ptr(),
            ct_len,
        ))?;
    }
    holds(a_len == b_len)?;
    eq(&a[..a_len], &b[..a_len])
}

/// `run_pq_sign_roundtrip` (`:1580-1606`): ML-DSA or SLH-DSA sign and verify with one key.
fn pq_sign(pkey: *mut EVP_PKEY) -> Step {
    let mut sig = Zeroizing::new(vec![0u8; 18432]);
    let mut sig_len = sig.len();
    let msg = &PQ_SIG_MSG;
    // SAFETY: see above
    unsafe {
        let mut pkctx = null_mut();
        let m = Own::new(EVP_MD_CTX_new(), EVP_MD_CTX_free)?;
        one(EVP_DigestSignInit_ex(
            m.0,
            &mut pkctx,
            null(),
            null_mut(),
            null(),
            pkey,
            null(),
        ))?;
        one(EVP_DigestSign(
            m.0,
            sig.as_mut_ptr(),
            &mut sig_len,
            msg.as_ptr(),
            msg.len(),
        ))?;
        drop(m);
        let m = Own::new(EVP_MD_CTX_new(), EVP_MD_CTX_free)?;
        one(EVP_DigestVerifyInit_ex(
            m.0,
            &mut pkctx,
            null(),
            null_mut(),
            null(),
            pkey,
            null(),
        ))?;
        one(EVP_DigestVerify(
            m.0,
            sig.as_ptr(),
            sig_len,
            msg.as_ptr(),
            msg.len(),
        ))
    }
}

/// Review M3: every check above can fail. A flipped byte of the expected value, or a key of the
/// wrong type for a round trip, must be refused; the KAT goldens only ever see them pass.
#[cfg(test)]
mod tests {
    use super::*;

    fn flip(v: &[u8]) -> Vec<u8> {
        let mut v = v.to_vec();
        *v.last_mut().unwrap() ^= 1;
        v
    }

    #[test]
    fn a_wrong_expected_value_fails_each_check() {
        let gcm_ok = |ct: &[u8], tag: &[u8]| gcm(&TC13_IV, &KA, &KP, ct, tag);
        assert!(gcm_ok(&TC14_CT, &TC14_TAG).is_some());
        assert!(gcm_ok(&flip(&TC14_CT), &TC14_TAG).is_none());
        assert!(gcm_ok(&TC14_CT, &flip(&TC14_TAG)).is_none());
        assert!(hmac(&HKAT1_KEY, &HKAT1_DATA, &HKAT1_MAC).is_some());
        assert!(hmac(&HKAT1_KEY, &HKAT1_DATA, &flip(&HKAT1_MAC)).is_none());
        assert!(digest(md(EVP_sha3_512), b"abc", &SHA3_512_ABC).is_some());
        assert!(digest(md(EVP_sha3_512), b"abc", &flip(&SHA3_512_ABC)).is_none());
        let cbc = cipher(EVP_aes_256_cbc);
        assert!(block(cbc, &AES256_CBC_IV, true, &AES256_CBC_CT).is_some());
        assert!(block(cbc, &AES256_CBC_IV, true, &flip(&AES256_CBC_CT)).is_none());
        assert!(cmac(&AES_PLAINTEXT_64[..16], &AES256_CMAC_16_TAG).is_some());
        assert!(cmac(&AES_PLAINTEXT_64[..16], &flip(&AES256_CMAC_16_TAG)).is_none());
        let p521 = |sig: &[u8]| ecdsa_verify(c"P-521", md(EVP_sha512), &ECDSA_P521_PUB, sig);
        assert!(p521(&ECDSA_P521_SIG).is_some());
        assert!(p521(&flip(&ECDSA_P521_SIG)).is_none());
        let (ikm, salt, info) = (&HKDF_TC1_IKM, &HKDF_TC1_SALT, &HKDF_TC1_INFO);
        assert!(hkdf(ikm, salt, info, &HKDF_TC1_OKM).is_some());
        assert!(hkdf(ikm, salt, info, &flip(&HKDF_TC1_OKM)).is_none());
        let (pwd, salt) = (&PBKDF2_TC1_PWD, &PBKDF2_TC1_SALT);
        assert!(pbkdf2_sha1(pwd, salt, 2, &PBKDF2_TC2_DK).is_some());
        assert!(pbkdf2_sha1(pwd, salt, 2, &flip(&PBKDF2_TC2_DK)).is_none());
    }

    #[test]
    fn a_key_of_the_wrong_type_fails_each_round_trip() {
        let (rsa, ec) = (
            keygen(c"RSA", true).unwrap(),
            keygen(c"X25519", false).unwrap(),
        );
        assert!(rsa_pss(rsa.0).is_some() && rsa_oaep(rsa.0).is_some());
        assert!(rsa_pss(ec.0).is_none() && rsa_oaep(ec.0).is_none());
        let mlkem = keygen(c"ML-KEM-768", false).unwrap();
        assert!(kem(mlkem.0).is_some());
        assert!(kem(rsa.0).is_none());
        let mldsa = keygen(c"ML-DSA-65", false).unwrap();
        assert!(pq_sign(mldsa.0).is_some());
        assert!(pq_sign(ec.0).is_none() && pq_sign(mlkem.0).is_none());
    }
}
