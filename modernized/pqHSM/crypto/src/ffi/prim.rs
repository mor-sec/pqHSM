//! The primitives of `src/fhsm_crypto.c:346-608` (`include/fhsm_crypto.h`; RULE-001, RULE-002):
//! digests, HMAC, AES-GCM and PBKDF2 over OpenSSL, with C's fetches and C's argument checks in
//! C's order. `tests/golden/core.tsv` is the specification. The module ERROR state is checked
//! by the C ABI (`ffi`), which also maps C's pointers and in/out lengths onto these slices.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::ptr::{null, null_mut};

use openssl_sys::{
    EVP_CIPHER, EVP_CIPHER_CTX, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new,
    EVP_CTRL_GCM_GET_TAG, EVP_CTRL_GCM_SET_TAG, EVP_DecryptFinal_ex, EVP_DecryptUpdate,
    EVP_DigestFinal_ex, EVP_DigestUpdate, EVP_EncryptFinal_ex, EVP_EncryptUpdate, EVP_KDF_CTX_free,
    EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free, EVP_MAC_CTX_free,
    EVP_MAC_CTX_new, EVP_MAC_fetch, EVP_MAC_final, EVP_MAC_free, EVP_MAC_init, EVP_MAC_update,
    EVP_MD, EVP_MD_CTX, EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free,
    EVP_aes_128_gcm, EVP_aes_192_gcm, EVP_aes_256_gcm, OSSL_PARAM, OSSL_PARAM_construct_end,
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_uint,
};
use zeroize::Zeroize;

use crate::rv;

unsafe extern "C" {
    // OpenSSL 3; not bound by openssl-sys
    fn EVP_DigestInit_ex2(
        ctx: *mut EVP_MD_CTX,
        md: *const EVP_MD,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn EVP_EncryptInit_ex2(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        key: *const u8,
        iv: *const u8,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn EVP_DecryptInit_ex2(
        ctx: *mut EVP_CIPHER_CTX,
        cipher: *const EVP_CIPHER,
        key: *const u8,
        iv: *const u8,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn OSSL_PARAM_construct_utf8_string(
        key: *const c_char,
        buf: *mut c_char,
        bsize: usize,
    ) -> OSSL_PARAM;
    fn OSSL_PARAM_construct_int(key: *const c_char, buf: *mut c_int) -> OSSL_PARAM;
    fn ERR_set_mark() -> c_int;
    fn ERR_pop_to_mark() -> c_int;
}

/// `FHSM_PBKDF2_MAX_OUT`.
pub const PBKDF2_MAX_OUT: usize = 256;
/// The GCM tag, always 16 bytes.
pub const TAG_LEN: usize = 16;

/// `fhsm_hash_t`: the id, the output size and the OpenSSL name (`:348-376`).
const HASHES: [(u32, usize, &CStr); 12] = [
    (1, 32, c"SHA2-256"),
    (2, 48, c"SHA2-384"),
    (3, 64, c"SHA2-512"),
    (4, 32, c"SHA3-256"),
    (5, 48, c"SHA3-384"),
    (6, 64, c"SHA3-512"),
    (7, 20, c"SHA1"),
    (8, 16, c"MD5"),
    (9, 28, c"SHA2-224"),
    (10, 28, c"SHA512-224"),
    (11, 32, c"SHA512-256"),
    (12, 28, c"SHA3-224"),
];

fn hash(alg: u32) -> Result<(usize, &'static CStr), u32> {
    HASHES
        .iter()
        .find(|h| h.0 == alg)
        .map(|h| (h.1, h.2))
        .ok_or(rv::ARGUMENTS_BAD)
}

/// `fhsm_hash_size`: 0 for an unknown id.
pub fn hash_size(alg: u32) -> usize {
    hash(alg).map_or(0, |h| h.0)
}

/// `fhsm_hash_openssl_name`.
pub fn hash_name(alg: u32) -> Option<&'static CStr> {
    hash(alg).ok().map(|h| h.1)
}

/// An OpenSSL object, freed on drop.
struct Owned<T>(*mut T, unsafe extern "C" fn(*mut T));

impl<T> Owned<T> {
    fn new(p: *mut T, free: unsafe extern "C" fn(*mut T), err: u32) -> Result<Self, u32> {
        if p.is_null() {
            Err(err)
        } else {
            Ok(Self(p, free))
        }
    }
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        // SAFETY: self.0 came from the allocator self.1 frees, and is freed once
        unsafe { (self.1)(self.0) }
    }
}

/// OpenSSL's 1 for success, anything else FUNCTION_FAILED.
fn ok(r: c_int) -> Result<(), u32> {
    if r == 1 {
        Ok(())
    } else {
        Err(rv::FUNCTION_FAILED)
    }
}

/// `fhsm_hash_oneshot` (`:483-511`): the digest of `data` in front of `out`, and its length.
pub fn digest(alg: u32, data: &[u8], out: &mut [u8]) -> Result<usize, u32> {
    let (size, name) = hash(alg)?;
    if out.len() < size {
        return Err(rv::ARGUMENTS_BAD);
    }
    // SAFETY: name is a C string; every object is checked and freed by Owned; out has room for
    // the digest (size bytes)
    unsafe {
        let md = Owned::new(
            EVP_MD_fetch(null_mut(), name.as_ptr(), null()),
            EVP_MD_free,
            rv::MECHANISM_INVALID,
        )?;
        let ctx = Owned::new(EVP_MD_CTX_new(), EVP_MD_CTX_free, rv::HOST_MEMORY)?;
        let mut n = 0;
        ok(EVP_DigestInit_ex2(ctx.0, md.0, null()))?;
        ok(EVP_DigestUpdate(ctx.0, data.as_ptr().cast(), data.len()))?;
        ok(EVP_DigestFinal_ex(ctx.0, out.as_mut_ptr(), &mut n))?;
        Ok(n as usize)
    }
}

/// `fhsm_md_available` (`src/fhsm_pkcs11.c:1526-1534`): can the loaded providers compute this
/// digest? The fetch is bracketed so a failure leaves nothing on the error queue.
pub fn md_available(alg: u32) -> bool {
    let Ok((_, name)) = hash(alg) else {
        return false;
    };
    // SAFETY: name is a C string; the fetched object is freed at once
    unsafe {
        ERR_set_mark();
        let md = EVP_MD_fetch(null_mut(), name.as_ptr(), null());
        let ok = !md.is_null();
        EVP_MD_free(md);
        ERR_pop_to_mark();
        ok
    }
}

/// A multipart digest: the EVP context `C_DigestUpdate` and `C_DigestKey` feed
/// (`src/fhsm_pkcs11.c:11932-12067`), freed on drop.
pub struct Hasher(Owned<EVP_MD_CTX>);

// SAFETY: the context is owned by this value alone, and OpenSSL contexts may move between threads
unsafe impl Send for Hasher {}

impl Hasher {
    /// C's lazy init, in its order: HOST_MEMORY if no context, FUNCTION_FAILED if the fetch or
    /// the init fails.
    pub fn new(alg: u32) -> Result<Self, u32> {
        // SAFETY: as in digest
        unsafe {
            let ctx = Owned::new(EVP_MD_CTX_new(), EVP_MD_CTX_free, rv::HOST_MEMORY)?;
            let name = hash(alg).map_err(|_| rv::FUNCTION_FAILED)?.1;
            let md = Owned::new(
                EVP_MD_fetch(null_mut(), name.as_ptr(), null()),
                EVP_MD_free,
                rv::FUNCTION_FAILED,
            )?;
            ok(EVP_DigestInit_ex2(ctx.0, md.0, null()))?;
            Ok(Self(ctx))
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), u32> {
        // SAFETY: a live context; data readable for its length
        ok(unsafe { EVP_DigestUpdate(self.0.0, data.as_ptr().cast(), data.len()) })
    }

    /// The digest in front of `out`, which the caller has sized for it, and its length.
    pub fn finish(self, out: &mut [u8]) -> Result<usize, u32> {
        let mut n = 0;
        // SAFETY: a live context; out has room for the digest (caller)
        ok(unsafe { EVP_DigestFinal_ex(self.0.0, out.as_mut_ptr(), &mut n) })?;
        Ok(n as usize)
    }

    /// Drop the context without freeing it: after a fork it is the parent's.
    pub fn forget(self) {
        std::mem::forget(self);
    }
}

/// `fhsm_hmac` (`:513-548`): the MAC in front of `out`, and its length. `None` asks only for
/// the length, as C's NULL `mac` does; the caller has checked C's capacity for it.
pub fn hmac(alg: u32, key: &[u8], data: &[u8], out: Option<&mut [u8]>) -> Result<usize, u32> {
    let (size, name) = hash(alg)?;
    let (ptr, cap) = match out {
        Some(o) if o.len() < size => return Err(rv::ARGUMENTS_BAD),
        Some(o) => (o.as_mut_ptr(), o.len()),
        None => (null_mut(), 0),
    };
    // SAFETY: as in digest; ptr has cap writable bytes or is null, which EVP_MAC_final reads as
    // a request for the length
    unsafe {
        let mac = Owned::new(
            EVP_MAC_fetch(null_mut(), c"HMAC".as_ptr(), null()),
            EVP_MAC_free,
            rv::MECHANISM_INVALID,
        )?;
        let ctx = Owned::new(EVP_MAC_CTX_new(mac.0), EVP_MAC_CTX_free, rv::HOST_MEMORY)?;
        let params = [
            OSSL_PARAM_construct_utf8_string(c"digest".as_ptr(), name.as_ptr().cast_mut(), 0),
            OSSL_PARAM_construct_end(),
        ];
        let mut n = 0;
        ok(EVP_MAC_init(
            ctx.0,
            key.as_ptr(),
            key.len(),
            params.as_ptr(),
        ))?;
        ok(EVP_MAC_update(ctx.0, data.as_ptr(), data.len()))?;
        ok(EVP_MAC_final(ctx.0, ptr, &mut n, cap))?;
        Ok(n)
    }
}

/// C's first two AES-GCM checks (`:387-388`, `:432-433`).
pub fn check_gcm(key_len: usize, iv_len: usize) -> Result<(), u32> {
    if !matches!(key_len, 16 | 24 | 32) {
        return Err(rv::KEY_SIZE_RANGE);
    }
    if iv_len != 12 {
        return Err(rv::ARGUMENTS_BAD);
    }
    Ok(())
}

fn gcm_cipher(key_len: usize) -> *const EVP_CIPHER {
    // SAFETY: no arguments; static objects
    unsafe {
        match key_len {
            16 => EVP_aes_128_gcm(),
            24 => EVP_aes_192_gcm(),
            _ => EVP_aes_256_gcm(),
        }
    }
}

/// `fhsm_aes_gcm_encrypt` (`:378-421`): the ciphertext in front of `ct`, its length, and the tag.
pub fn gcm_encrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    pt: &[u8],
    ct: &mut [u8],
    tag: &mut [u8; TAG_LEN],
) -> Result<usize, u32> {
    check_gcm(key.len(), iv.len())?;
    if ct.len() < pt.len() {
        return Err(rv::ARGUMENTS_BAD);
    }
    // SAFETY: the key and IV have the lengths the cipher reads; ct has room for pt (GCM output
    // equals its input and Final writes nothing); the tag is 16 bytes, as the ctrl is told
    unsafe {
        let ctx = Owned::new(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free, rv::HOST_MEMORY)?;
        ok(EVP_EncryptInit_ex2(
            ctx.0,
            gcm_cipher(key.len()),
            key.as_ptr(),
            iv.as_ptr(),
            null(),
        ))?;
        let mut n: c_int = 0;
        if !aad.is_empty() {
            ok(EVP_EncryptUpdate(
                ctx.0,
                null_mut(),
                &mut n,
                aad.as_ptr(),
                aad.len() as c_int,
            ))?;
        }
        ok(EVP_EncryptUpdate(
            ctx.0,
            ct.as_mut_ptr(),
            &mut n,
            pt.as_ptr(),
            pt.len() as c_int,
        ))?;
        let mut produced = n as usize;
        ok(EVP_EncryptFinal_ex(
            ctx.0,
            ct.as_mut_ptr().add(produced),
            &mut n,
        ))?;
        produced += n as usize;
        ok(EVP_CIPHER_CTX_ctrl(
            ctx.0,
            EVP_CTRL_GCM_GET_TAG,
            TAG_LEN as c_int,
            tag.as_mut_ptr().cast::<c_void>(),
        ))?;
        Ok(produced)
    }
}

/// `fhsm_aes_gcm_decrypt` (`:423-475`): the plaintext in front of `pt` and its length. A tag
/// that does not verify cleanses `pt` and is ENCRYPTED_DATA_INVALID.
pub fn gcm_decrypt(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    ct: &[u8],
    tag: &[u8; TAG_LEN],
    pt: &mut [u8],
) -> Result<usize, u32> {
    check_gcm(key.len(), iv.len())?;
    if pt.len() < ct.len() {
        return Err(rv::ARGUMENTS_BAD);
    }
    // SAFETY: as in gcm_encrypt, with pt in place of ct; OpenSSL only reads the tag it is given
    unsafe {
        let ctx = Owned::new(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free, rv::HOST_MEMORY)?;
        ok(EVP_DecryptInit_ex2(
            ctx.0,
            gcm_cipher(key.len()),
            key.as_ptr(),
            iv.as_ptr(),
            null(),
        ))?;
        let mut n: c_int = 0;
        if !aad.is_empty() {
            ok(EVP_DecryptUpdate(
                ctx.0,
                null_mut(),
                &mut n,
                aad.as_ptr(),
                aad.len() as c_int,
            ))?;
        }
        ok(EVP_DecryptUpdate(
            ctx.0,
            pt.as_mut_ptr(),
            &mut n,
            ct.as_ptr(),
            ct.len() as c_int,
        ))?;
        let produced = n as usize;
        ok(EVP_CIPHER_CTX_ctrl(
            ctx.0,
            EVP_CTRL_GCM_SET_TAG,
            TAG_LEN as c_int,
            tag.as_ptr().cast_mut().cast::<c_void>(),
        ))?;
        if EVP_DecryptFinal_ex(ctx.0, pt.as_mut_ptr().add(produced), &mut n) != 1 {
            pt.zeroize();
            return Err(rv::ENCRYPTED_DATA_INVALID);
        }
        Ok(produced + n as usize)
    }
}

/// C's PBKDF2 checks (`:555-573`): fewer than 1000 iterations is FIPS_NOT_APPROVED; the count
/// above that is the caller's policy.
pub fn check_pbkdf2(alg: u32, iterations: u32, out_len: usize) -> Result<&'static CStr, u32> {
    if iterations < 1000 {
        return Err(rv::FIPS_NOT_APPROVED);
    }
    if out_len == 0 || out_len > PBKDF2_MAX_OUT {
        return Err(rv::ARGUMENTS_BAD);
    }
    hash(alg).map(|h| h.1)
}

/// `fhsm_pbkdf2` (`:553-608`), with OpenSSL's SP 800-132 limits off (`pkcs5` = 1) so a PKCS#12
/// salt of 8 bytes is accepted, as in C.
pub fn pbkdf2(
    alg: u32,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), u32> {
    let name = check_pbkdf2(alg, iterations, out.len())?;
    let mut iter = iterations;
    let mut pkcs5: c_int = 1;
    // SAFETY: the params point at locals and slices that outlive the derive, which only reads
    // them; out has out.len() writable bytes
    unsafe {
        let kdf = Owned::new(
            EVP_KDF_fetch(null_mut(), c"PBKDF2".as_ptr(), null()),
            EVP_KDF_free,
            rv::MECHANISM_INVALID,
        )?;
        let ctx = Owned::new(EVP_KDF_CTX_new(kdf.0), EVP_KDF_CTX_free, rv::HOST_MEMORY)?;
        let params = [
            OSSL_PARAM_construct_utf8_string(c"digest".as_ptr(), name.as_ptr().cast_mut(), 0),
            OSSL_PARAM_construct_octet_string(
                c"pass".as_ptr(),
                password.as_ptr().cast_mut().cast(),
                password.len(),
            ),
            OSSL_PARAM_construct_octet_string(
                c"salt".as_ptr(),
                salt.as_ptr().cast_mut().cast(),
                salt.len(),
            ),
            OSSL_PARAM_construct_uint(c"iter".as_ptr(), &mut iter),
            OSSL_PARAM_construct_int(c"pkcs5".as_ptr(), &mut pkcs5),
            OSSL_PARAM_construct_end(),
        ];
        ok(EVP_KDF_derive(
            ctx.0,
            out.as_mut_ptr(),
            out.len(),
            params.as_ptr(),
        ))
    }
}

/// HKDF's modes (`EVP_KDF_HKDF_MODE_*`).
pub const HKDF_EXTRACT_AND_EXPAND: c_int = 0;
pub const HKDF_EXTRACT_ONLY: c_int = 1;
pub const HKDF_EXPAND_ONLY: c_int = 2;

/// `C_DeriveKey`'s HKDF (`src/fhsm_pkcs11.c:4458-4488`): MECHANISM_INVALID if HKDF will not
/// fetch, HOST_MEMORY without a context, FUNCTION_FAILED if the derive fails. An empty salt or
/// info is not passed, as C.
pub fn hkdf(
    mode: c_int,
    digest: &CStr,
    key: &[u8],
    salt: &[u8],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), u32> {
    let mut mode = mode;
    let oct = |k: &CStr, b: &[u8]| {
        // SAFETY: a constructor; b outlives the derive below, which only reads it
        unsafe {
            OSSL_PARAM_construct_octet_string(k.as_ptr(), b.as_ptr().cast_mut().cast(), b.len())
        }
    };
    // SAFETY: as pbkdf2's: the params point at locals and slices that outlive the derive; out
    // has out.len() writable bytes
    unsafe {
        let kdf = Owned::new(
            EVP_KDF_fetch(null_mut(), c"HKDF".as_ptr(), null()),
            EVP_KDF_free,
            rv::MECHANISM_INVALID,
        )?;
        let ctx = Owned::new(EVP_KDF_CTX_new(kdf.0), EVP_KDF_CTX_free, rv::HOST_MEMORY)?;
        let mut params = vec![
            OSSL_PARAM_construct_int(c"mode".as_ptr(), &mut mode),
            OSSL_PARAM_construct_utf8_string(c"digest".as_ptr(), digest.as_ptr().cast_mut(), 0),
            oct(c"key", key),
        ];
        if !salt.is_empty() {
            params.push(oct(c"salt", salt));
        }
        if !info.is_empty() {
            params.push(oct(c"info", info));
        }
        params.push(OSSL_PARAM_construct_end());
        ok(EVP_KDF_derive(
            ctx.0,
            out.as_mut_ptr(),
            out.len(),
            params.as_ptr(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_case_1() {
        let (ikm, salt, info) = (
            [0x0Bu8; 22],
            [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            [0xF0u8, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9],
        );
        let mut okm = [0u8; 42];
        hkdf(
            HKDF_EXTRACT_AND_EXPAND,
            c"SHA256",
            &ikm,
            &salt,
            &info,
            &mut okm,
        )
        .unwrap();
        let hex: String = okm.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}
