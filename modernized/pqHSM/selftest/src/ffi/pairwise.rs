//! The pair-wise consistency check after key generation (`src/fhsm_pairwise.c`,
//! `include/fhsm_pairwise.h`; FIPS 140-3 §7.10.2): one round trip through the new key pair with
//! the primitive the application will use. RSA encrypts and decrypts (PKCS#1 v1.5), EC signs
//! and verifies a fixed digest, ML-KEM encapsulates and decapsulates, ML-DSA, SLH-DSA and EdDSA
//! sign and verify a fixed message, and X25519/X448 recompute the public key from the private
//! one. `tests/golden/pairwise.tsv` is the specification.

use std::ffi::{CStr, c_int};
use std::ptr::{null, null_mut};

use openssl_sys::{
    EVP_DigestSign, EVP_DigestSignInit, EVP_DigestVerify, EVP_DigestVerifyInit, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_PKEY, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_set_rsa_padding,
    EVP_PKEY_decapsulate, EVP_PKEY_decapsulate_init, EVP_PKEY_decrypt, EVP_PKEY_decrypt_init,
    EVP_PKEY_encapsulate, EVP_PKEY_encapsulate_init, EVP_PKEY_encrypt, EVP_PKEY_encrypt_init,
    EVP_PKEY_free, EVP_PKEY_get_raw_private_key, EVP_PKEY_get_raw_public_key, EVP_PKEY_is_a,
    EVP_PKEY_new_raw_private_key_ex, EVP_PKEY_sign, EVP_PKEY_sign_init, EVP_PKEY_verify,
    EVP_PKEY_verify_init, RSA_PKCS1_PADDING,
};
use pqhsm_crypto::rv;
use zeroize::Zeroizing;

use super::evp::{Own, Step, eq, holds, one, pos};

/// `fhsm_pairwise_family_t`.
pub const RSA: c_int = 1;
pub const EC: c_int = 2;
pub const ML_KEM: c_int = 3;
pub const ML_DSA: c_int = 4;
pub const SLH_DSA: c_int = 5;
pub const EDDSA: c_int = 6;
pub const ECM: c_int = 7;

/// `s_msg`: any 32 bytes would do; fixed so a failure can be reproduced.
const MSG: &[u8; 32] = b"FHSM pair-wise consistency check";
/// `s_digest_sha256`, signed as a digest by the EC check (as in C, not recomputed).
const DIGEST: [u8; 32] = [
    0x5B, 0x7C, 0x10, 0xBA, 0xCC, 0x68, 0xA0, 0xF7, 0xDF, 0xBE, 0x4E, 0x53, 0x4C, 0x88, 0xD8, 0xD2,
    0x97, 0x62, 0x9F, 0x35, 0xD6, 0xE9, 0x82, 0xC2, 0xB6, 0xF5, 0xC4, 0xF6, 0xEB, 0xCC, 0x14, 0x66,
];

/// `fhsm_pairwise_check`: ARGUMENTS_BAD for no key or an unknown family, OK when the round trip
/// holds, FUNCTION_FAILED otherwise (including a key of another type than the family's).
///
/// # Safety
/// `pkey` is null or a live key pair.
pub unsafe fn check(pkey: *mut EVP_PKEY, family: c_int) -> u32 {
    if pkey.is_null() {
        return rv::ARGUMENTS_BAD;
    }
    let pass = match family {
        RSA => rsa(pkey),
        EC => ec(pkey),
        ML_KEM => kem(pkey),
        ML_DSA | SLH_DSA | EDDSA => sign(pkey),
        ECM => ecm(pkey),
        _ => return rv::ARGUMENTS_BAD,
    };
    if pass.is_some() {
        rv::OK
    } else {
        rv::FUNCTION_FAILED
    }
}

// Every function below: SAFETY of its unsafe block: pkey is live (check's contract); each other
// pointer is an OpenSSL object held by an Own, a C string, or a buffer whose capacity OpenSSL is
// told.

/// `pairwise_rsa` (`:115-143`).
fn rsa(pkey: *mut EVP_PKEY) -> Step {
    let (mut ct, mut pt) = (Zeroizing::new([0u8; 1024]), Zeroizing::new([0u8; 1024]));
    let (mut ct_len, mut pt_len) = (ct.len(), pt.len());
    // SAFETY: see above
    unsafe {
        let e = Own::new(EVP_PKEY_CTX_new(pkey, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_encrypt_init(e.0))?;
        pos(EVP_PKEY_CTX_set_rsa_padding(e.0, RSA_PKCS1_PADDING))?;
        pos(EVP_PKEY_encrypt(
            e.0,
            ct.as_mut_ptr(),
            &mut ct_len,
            MSG.as_ptr(),
            MSG.len(),
        ))?;
        let d = Own::new(EVP_PKEY_CTX_new(pkey, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_decrypt_init(d.0))?;
        pos(EVP_PKEY_CTX_set_rsa_padding(d.0, RSA_PKCS1_PADDING))?;
        pos(EVP_PKEY_decrypt(
            d.0,
            pt.as_mut_ptr(),
            &mut pt_len,
            ct.as_ptr(),
            ct_len,
        ))?;
    }
    holds(pt_len == MSG.len())?;
    eq(&pt[..pt_len], MSG)
}

/// `pairwise_ec` (`:148-170`).
fn ec(pkey: *mut EVP_PKEY) -> Step {
    let mut sig = [0u8; 256];
    let mut sig_len = sig.len();
    // SAFETY: see above
    unsafe {
        let s = Own::new(EVP_PKEY_CTX_new(pkey, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_sign_init(s.0))?;
        pos(EVP_PKEY_sign(
            s.0,
            sig.as_mut_ptr(),
            &mut sig_len,
            DIGEST.as_ptr(),
            DIGEST.len(),
        ))?;
        let v = Own::new(EVP_PKEY_CTX_new(pkey, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_verify_init(v.0))?;
        one(EVP_PKEY_verify(
            v.0,
            sig.as_ptr(),
            sig_len,
            DIGEST.as_ptr(),
            DIGEST.len(),
        ))
    }
}

/// `pairwise_pq_sign` (`:177-213`): EVP_DigestSign without a digest, the signature's size asked
/// first (an SLH-DSA signature is up to 49 856 bytes).
fn sign(pkey: *mut EVP_PKEY) -> Step {
    // SAFETY: see above
    unsafe {
        let s = Own::new(EVP_MD_CTX_new(), EVP_MD_CTX_free)?;
        pos(EVP_DigestSignInit(
            s.0,
            null_mut(),
            null(),
            null_mut(),
            pkey,
        ))?;
        let mut sig_len = 0;
        pos(EVP_DigestSign(
            s.0,
            null_mut(),
            &mut sig_len,
            MSG.as_ptr(),
            MSG.len(),
        ))?;
        holds(sig_len != 0)?;
        let mut sig = vec![0u8; sig_len];
        pos(EVP_DigestSign(
            s.0,
            sig.as_mut_ptr(),
            &mut sig_len,
            MSG.as_ptr(),
            MSG.len(),
        ))?;
        let v = Own::new(EVP_MD_CTX_new(), EVP_MD_CTX_free)?;
        pos(EVP_DigestVerifyInit(
            v.0,
            null_mut(),
            null(),
            null_mut(),
            pkey,
        ))?;
        one(EVP_DigestVerify(
            v.0,
            sig.as_ptr(),
            sig_len,
            MSG.as_ptr(),
            MSG.len(),
        ))
    }
}

/// `pairwise_mlkem` (`:218-243`).
fn kem(pkey: *mut EVP_PKEY) -> Step {
    let mut ct = [0u8; 2048];
    let (mut ss1, mut ss2) = (Zeroizing::new([0u8; 64]), Zeroizing::new([0u8; 64]));
    let (mut ct_len, mut n1, mut n2) = (ct.len(), ss1.len(), ss2.len());
    // SAFETY: see above
    unsafe {
        let e = Own::new(EVP_PKEY_CTX_new(pkey, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_encapsulate_init(e.0, null()))?;
        pos(EVP_PKEY_encapsulate(
            e.0,
            ct.as_mut_ptr(),
            &mut ct_len,
            ss1.as_mut_ptr(),
            &mut n1,
        ))?;
        let d = Own::new(EVP_PKEY_CTX_new(pkey, null_mut()), EVP_PKEY_CTX_free)?;
        pos(EVP_PKEY_decapsulate_init(d.0, null()))?;
        pos(EVP_PKEY_decapsulate(
            d.0,
            ss2.as_mut_ptr(),
            &mut n2,
            ct.as_ptr(),
            ct_len,
        ))?;
    }
    holds(n1 == n2 && n1 != 0)?;
    eq(&ss1[..n1], &ss2[..n1])
}

/// `pairwise_ecm` (`:65-108`): the public key recomputed from the private half alone.
fn ecm(pkey: *mut EVP_PKEY) -> Step {
    let mut private = Zeroizing::new([0u8; 64]);
    let (mut generated, mut recomputed) = (Zeroizing::new([0u8; 64]), Zeroizing::new([0u8; 64]));
    // SAFETY: see above
    unsafe {
        let alg: &CStr = if EVP_PKEY_is_a(pkey, c"X25519".as_ptr()) == 1 {
            c"X25519"
        } else if EVP_PKEY_is_a(pkey, c"X448".as_ptr()) == 1 {
            c"X448"
        } else {
            return None;
        };
        let mut n = 0;
        one(EVP_PKEY_get_raw_private_key(pkey, null_mut(), &mut n))?;
        holds(n != 0 && n <= private.len())?;
        one(EVP_PKEY_get_raw_private_key(
            pkey,
            private.as_mut_ptr(),
            &mut n,
        ))?;
        let mut gen_len = generated.len();
        one(EVP_PKEY_get_raw_public_key(
            pkey,
            generated.as_mut_ptr(),
            &mut gen_len,
        ))?;
        let from_private = Own::new(
            EVP_PKEY_new_raw_private_key_ex(null_mut(), alg.as_ptr(), null(), private.as_ptr(), n),
            EVP_PKEY_free,
        )?;
        let mut re_len = recomputed.len();
        one(EVP_PKEY_get_raw_public_key(
            from_private.0,
            recomputed.as_mut_ptr(),
            &mut re_len,
        ))?;
        holds(re_len == gen_len)?;
        eq(&recomputed[..re_len], &generated[..gen_len])
    }
}
