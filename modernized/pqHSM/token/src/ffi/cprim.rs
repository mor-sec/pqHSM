//! The crypto seam with `ffi`: the legacy C primitives (`include/fhsm_crypto.h`), so the
//! self-test gate and the DRBG health tests stay in C until Phase 3. Their codes pass through.

use std::ffi::c_int;
use zeroize::Zeroizing;

use crate::Rv;
use crate::crypto::{HASH_SHA256, KEY_LEN, NONCE_LEN, TAG_LEN};

/// `fhsm_slice_t`.
#[repr(C)]
struct Slice {
    data: *const u8,
    len: usize,
}

fn s(b: &[u8]) -> Slice {
    Slice {
        data: b.as_ptr(),
        len: b.len(),
    }
}

unsafe extern "C" {
    fn fhsm_pbkdf2(
        alg: c_int,
        pw: Slice,
        salt: Slice,
        iter: u32,
        out: *mut u8,
        out_len: usize,
    ) -> u32;
    fn fhsm_aes_gcm_encrypt(
        key: Slice,
        iv: Slice,
        aad: Slice,
        pt: Slice,
        ct: *mut u8,
        ct_len: *mut usize,
        tag: *mut u8,
    ) -> u32;
    fn fhsm_aes_gcm_decrypt(
        key: Slice,
        iv: Slice,
        aad: Slice,
        ct: Slice,
        tag: *const u8,
        pt: *mut u8,
        pt_len: *mut usize,
    ) -> u32;
    fn fhsm_rng_bytes(out: *mut u8, n: usize) -> u32;
}

fn rv(r: u32) -> Result<(), Rv> {
    if r == 0 { Ok(()) } else { Err(Rv(r)) }
}

pub(crate) fn pbkdf2_sha256(pw: &[u8], salt: &[u8], iter: u32, out: &mut [u8]) -> Result<(), Rv> {
    // SAFETY: the slices live for the call; out has out.len() writable bytes
    rv(unsafe {
        fhsm_pbkdf2(
            HASH_SHA256 as c_int,
            s(pw),
            s(salt),
            iter,
            out.as_mut_ptr(),
            out.len(),
        )
    })
}

pub(crate) fn gcm_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), Rv> {
    let mut ct = vec![0u8; pt.len()];
    let mut n = ct.len();
    let mut tag = [0u8; TAG_LEN];
    // SAFETY: ct has n bytes (GCM output equals input), tag 16; n is in/out capacity
    rv(unsafe {
        fhsm_aes_gcm_encrypt(
            s(key),
            s(nonce),
            s(aad),
            s(pt),
            ct.as_mut_ptr(),
            &mut n,
            tag.as_mut_ptr(),
        )
    })?;
    ct.truncate(n);
    Ok((ct, tag))
}

pub(crate) fn gcm_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Zeroizing<Vec<u8>>, Rv> {
    let mut pt = Zeroizing::new(vec![0u8; ct.len()]);
    let mut n = pt.len();
    // SAFETY: pt has n bytes, the tag 16; n is in/out capacity
    rv(unsafe {
        fhsm_aes_gcm_decrypt(
            s(key),
            s(nonce),
            s(aad),
            s(ct),
            tag.as_ptr(),
            pt.as_mut_ptr(),
            &mut n,
        )
    })?;
    pt.truncate(n);
    Ok(pt)
}

pub(crate) fn random(out: &mut [u8]) -> Result<(), Rv> {
    // SAFETY: out has out.len() writable bytes
    rv(unsafe { fhsm_rng_bytes(out.as_mut_ptr(), out.len()) })
}
