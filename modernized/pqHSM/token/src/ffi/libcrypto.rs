//! The crypto seam without `ffi`: libcrypto through openssl-sys, returning C's codes.

use std::ffi::c_int;
use std::ptr::null_mut;

use openssl_sys as sys;
use zeroize::Zeroizing;

use crate::Rv;
use crate::crypto::{KEY_LEN, NONCE_LEN, TAG_LEN};

pub(crate) fn pbkdf2_sha256(pw: &[u8], salt: &[u8], iter: u32, out: &mut [u8]) -> Result<(), Rv> {
    if iter < 1000 {
        return Err(Rv::FIPS_NOT_APPROVED);
    }
    // SAFETY: every pointer/length pair describes a live slice for the call
    let r = unsafe {
        sys::PKCS5_PBKDF2_HMAC(
            pw.as_ptr().cast(),
            pw.len() as c_int,
            salt.as_ptr(),
            salt.len() as c_int,
            iter as c_int,
            sys::EVP_sha256(),
            out.len() as c_int,
            out.as_mut_ptr(),
        )
    };
    if r == 1 {
        Ok(())
    } else {
        Err(Rv::FUNCTION_FAILED)
    }
}

/// One AES-256-GCM pass; `tag` is read when decrypting and written when encrypting.
fn gcm(
    enc: bool,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    input: &[u8],
    tag: &mut [u8; TAG_LEN],
) -> Option<Zeroizing<Vec<u8>>> {
    // Zeroizing: on decrypt this is plaintext key material (review M2)
    let mut out = Zeroizing::new(vec![0u8; input.len() + 16]);
    // SAFETY: ctx is ours from new to free; out has room for input + one block; the tag is 16
    // bytes as both ctrl calls are told
    unsafe {
        let ctx = sys::EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return None;
        }
        let mut n: c_int = 0;
        let mut total = 0usize;
        let mut ok = sys::EVP_CipherInit_ex(
            ctx,
            sys::EVP_aes_256_gcm(),
            null_mut(),
            key.as_ptr(),
            nonce.as_ptr(),
            enc as c_int,
        ) == 1;
        if ok && !aad.is_empty() {
            ok = sys::EVP_CipherUpdate(ctx, null_mut(), &mut n, aad.as_ptr(), aad.len() as c_int)
                == 1;
        }
        if ok && !input.is_empty() {
            ok = sys::EVP_CipherUpdate(
                ctx,
                out.as_mut_ptr(),
                &mut n,
                input.as_ptr(),
                input.len() as c_int,
            ) == 1;
            total = n as usize;
        }
        if ok && !enc {
            ok = sys::EVP_CIPHER_CTX_ctrl(
                ctx,
                sys::EVP_CTRL_GCM_SET_TAG,
                16,
                tag.as_mut_ptr().cast(),
            ) == 1;
        }
        if ok {
            ok = sys::EVP_CipherFinal(ctx, out.as_mut_ptr().add(total), &mut n) == 1;
            total += n as usize;
        }
        if ok && enc {
            ok = sys::EVP_CIPHER_CTX_ctrl(
                ctx,
                sys::EVP_CTRL_GCM_GET_TAG,
                16,
                tag.as_mut_ptr().cast(),
            ) == 1;
        }
        sys::EVP_CIPHER_CTX_free(ctx);
        out.truncate(total);
        ok.then_some(out)
    }
}

pub(crate) fn gcm_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), Rv> {
    let mut tag = [0u8; TAG_LEN];
    let ct = gcm(true, key, nonce, aad, pt, &mut tag).ok_or(Rv::FUNCTION_FAILED)?;
    Ok((ct.to_vec(), tag))
}

pub(crate) fn gcm_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Zeroizing<Vec<u8>>, Rv> {
    let mut t = *tag;
    gcm(false, key, nonce, aad, ct, &mut t).ok_or(Rv::ENCRYPTED_DATA_INVALID)
}

pub(crate) fn random(out: &mut [u8]) -> Result<(), Rv> {
    // SAFETY: out is a live, writable slice of out.len() bytes
    if unsafe { sys::RAND_bytes(out.as_mut_ptr(), out.len() as c_int) } == 1 {
        Ok(())
    } else {
        Err(Rv::FUNCTION_FAILED)
    }
}
