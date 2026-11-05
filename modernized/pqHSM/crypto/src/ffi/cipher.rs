//! The EVP calls of `C_Encrypt*` and `C_Decrypt*` (`src/fhsm_pkcs11.c:8506-8630, 9777-10700,
//! 12683-13030`): a cipher context, an RSA key and its encryption context, each freed on drop.
//! Thin on purpose: `pqhsm-p11` makes C's call sequences out of them, so the order of the calls
//! and the code each failure returns stay where C put them. Results are OpenSSL's: `true` for
//! success, the output length for an update or a final.

use std::ffi::{CStr, c_int, c_long, c_void};
use std::ptr::{null, null_mut};

use openssl_sys::{
    CRYPTO_free, CRYPTO_malloc, EVP_CIPHER, EVP_CIPHER_CTX, EVP_CIPHER_CTX_copy,
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CIPHER_CTX_set_flags,
    EVP_CIPHER_CTX_set_padding, EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_DecryptFinal_ex,
    EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex,
    EVP_EncryptUpdate, EVP_MD, EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EVP_PKEY,
    EVP_PKEY_CTX, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_decrypt, EVP_PKEY_decrypt_init,
    EVP_PKEY_encrypt, EVP_PKEY_encrypt_init, EVP_PKEY_free, EVP_PKEY_get_size,
    EVP_aes_128_ccm, EVP_aes_128_gcm, EVP_aes_192_ccm, EVP_aes_192_gcm, EVP_aes_256_ccm,
    EVP_aes_256_gcm, OSSL_PARAM, d2i_AutoPrivateKey, d2i_PUBKEY,
};

use crate::rv;

unsafe extern "C" {
    // OpenSSL 3; not bound by openssl-sys, or bound as 1.1 macros
    fn OPENSSL_cleanse(p: *mut c_void, n: usize);
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
    fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut EVP_PKEY_CTX, pad: c_int) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_oaep_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;
    fn EVP_PKEY_CTX_get_rsa_oaep_md(ctx: *mut EVP_PKEY_CTX, md: *mut *const EVP_MD) -> c_int;
    fn EVP_PKEY_CTX_set0_rsa_oaep_label(ctx: *mut EVP_PKEY_CTX, l: *mut c_void, n: c_int) -> c_int;
}

/// `EVP_CTRL_AEAD_SET_IVLEN`, `_GET_TAG`, `_SET_TAG`: GCM's and CCM's alike.
const SET_IVLEN: c_int = 0x9;
const GET_TAG: c_int = 0x10;
const SET_TAG: c_int = 0x11;
/// `RSA_PKCS1_OAEP_PADDING`.
const OAEP_PADDING: c_int = 4;

/// An OpenSSL object, freed on drop.
struct Owned<T>(*mut T, unsafe extern "C" fn(*mut T));

impl<T> Owned<T> {
    fn new(p: *mut T, free: unsafe extern "C" fn(*mut T)) -> Option<Self> {
        (!p.is_null()).then_some(Self(p, free))
    }
}

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        // SAFETY: self.0 came from the allocator self.1 frees, and is freed once
        unsafe { (self.1)(self.0) }
    }
}

fn ptr(b: Option<&[u8]>) -> *const u8 {
    b.map_or(null(), <[u8]>::as_ptr)
}

/// A cipher fetched by name (`EVP_CIPHER_fetch`), for the `_ex2` inits.
pub struct Fetched(Owned<EVP_CIPHER>);

impl Fetched {
    pub fn new(name: &CStr) -> Option<Self> {
        // SAFETY: a C string; the result is checked and owned
        Owned::new(
            unsafe { EVP_CIPHER_fetch(null_mut(), name.as_ptr(), null()) },
            EVP_CIPHER_free,
        )
        .map(Self)
    }
}

/// An AEAD mode of the built-in table (`EVP_aes_*_gcm`, `_ccm`), for the `_ex` inits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Aead {
    Gcm,
    Ccm,
}

/// `OPENSSL_cleanse`, as `fhsm_zeroize` does.
pub fn cleanse(b: &mut [u8]) {
    // SAFETY: a live, writable buffer of that length
    unsafe { OPENSSL_cleanse(b.as_mut_ptr().cast(), b.len()) }
}

/// An AEAD cipher table, as `aead` returns it.
pub type AeadCipher = *const EVP_CIPHER;

/// The built-in AEAD cipher for a key of `key_len` bytes; `None` for other lengths, as C's
/// switches.
pub fn aead(mode: Aead, key_len: usize) -> Option<*const EVP_CIPHER> {
    // SAFETY: OpenSSL's static tables
    unsafe {
        Some(match (mode, key_len) {
            (Aead::Gcm, 16) => EVP_aes_128_gcm(),
            (Aead::Gcm, 24) => EVP_aes_192_gcm(),
            (Aead::Gcm, 32) => EVP_aes_256_gcm(),
            (Aead::Ccm, 16) => EVP_aes_128_ccm(),
            (Aead::Ccm, 24) => EVP_aes_192_ccm(),
            (Aead::Ccm, 32) => EVP_aes_256_ccm(),
            _ => return None,
        })
    }
}

/// `EVP_CIPHER_CTX`.
pub struct Cipher(Owned<EVP_CIPHER_CTX>);

// SAFETY: the context is owned by this value alone, and OpenSSL contexts may move between threads
unsafe impl Send for Cipher {}

impl Cipher {
    /// `EVP_CIPHER_CTX_new`; HOST_MEMORY without one, as C.
    pub fn new() -> Result<Self, u32> {
        // SAFETY: checked and owned
        Owned::new(unsafe { EVP_CIPHER_CTX_new() }, EVP_CIPHER_CTX_free)
            .map(Self)
            .ok_or(rv::HOST_MEMORY)
    }

    /// `EVP_EncryptInit_ex2` or `EVP_DecryptInit_ex2`. The key and IV must be as long as the
    /// cipher (set now or before) wants.
    pub fn init2(&mut self, enc: bool, c: Option<&Fetched>, key: Option<&[u8]>, iv: Option<&[u8]>) -> bool {
        let c = c.map_or(null(), |c| c.0.0.cast_const());
        let f = if enc { EVP_EncryptInit_ex2 } else { EVP_DecryptInit_ex2 };
        // SAFETY: a live context; key and IV readable for what the cipher reads (caller)
        unsafe { f(self.0.0, c, ptr(key), ptr(iv), null()) == 1 }
    }

    /// `EVP_EncryptInit_ex` or `EVP_DecryptInit_ex`, with a cipher from [`aead`].
    pub fn init(&mut self, enc: bool, c: Option<*const EVP_CIPHER>, key: Option<&[u8]>, iv: Option<&[u8]>) -> bool {
        let c = c.unwrap_or(null());
        let f = if enc { EVP_EncryptInit_ex } else { EVP_DecryptInit_ex };
        // SAFETY: as init2; c is null or one of OpenSSL's static tables
        unsafe { f(self.0.0, c, null_mut(), ptr(key), ptr(iv)) == 1 }
    }

    fn ctrl(&mut self, op: c_int, arg: usize, p: *mut c_void) -> bool {
        // SAFETY: a live context; p is null or holds arg bytes (callers)
        unsafe { EVP_CIPHER_CTX_ctrl(self.0.0, op, arg as c_int, p) == 1 }
    }

    pub fn set_iv_len(&mut self, n: usize) -> bool {
        self.ctrl(SET_IVLEN, n, null_mut())
    }

    /// The expected tag (decrypt), or only its length (CCM's encrypt).
    pub fn set_tag(&mut self, len: usize, tag: Option<&[u8]>) -> bool {
        debug_assert!(tag.is_none_or(|t| t.len() >= len));
        self.ctrl(SET_TAG, len, ptr(tag).cast_mut().cast())
    }

    /// The tag, `out.len()` bytes of it.
    pub fn get_tag(&mut self, out: &mut [u8]) -> bool {
        self.ctrl(GET_TAG, out.len(), out.as_mut_ptr().cast())
    }

    pub fn set_padding(&mut self, on: bool) {
        // SAFETY: a live context
        unsafe { EVP_CIPHER_CTX_set_padding(self.0.0, on as c_int) };
    }

    /// `EVP_CIPHER_CTX_FLAG_WRAP_ALLOW`, which the key-wrap ciphers need.
    pub fn allow_wrap(&mut self) {
        // SAFETY: a live context
        unsafe { EVP_CIPHER_CTX_set_flags(self.0.0, 0x1) };
    }

    /// `EVP_EncryptUpdate` or `EVP_DecryptUpdate` of `n` bytes at `inp`; the bytes written.
    /// A NULL `out` feeds AAD (or, with a NULL `inp`, gives CCM its message length).
    ///
    /// # Safety
    /// `inp` readable for `n` bytes unless NULL; `out` NULL or writable for what the update
    /// produces (`n` plus one block); `n` at most `i32::MAX`.
    pub unsafe fn update(&mut self, enc: bool, out: *mut u8, inp: *const u8, n: usize) -> Option<usize> {
        let f = if enc { EVP_EncryptUpdate } else { EVP_DecryptUpdate };
        let mut l = 0;
        // SAFETY: the caller's
        (unsafe { f(self.0.0, out, &mut l, inp, n as c_int) } == 1).then_some(l as usize)
    }

    /// `EVP_EncryptFinal_ex` or `EVP_DecryptFinal_ex`; the bytes written.
    ///
    /// # Safety
    /// `out` writable for one block.
    pub unsafe fn finish(&mut self, enc: bool, out: *mut u8) -> Option<usize> {
        let f = if enc { EVP_EncryptFinal_ex } else { EVP_DecryptFinal_ex };
        let mut l = 0;
        // SAFETY: the caller's
        (unsafe { f(self.0.0, out, &mut l) } == 1).then_some(l as usize)
    }

    /// `EVP_CIPHER_CTX_copy` into a new context: HOST_MEMORY without one, FUNCTION_FAILED if
    /// the copy fails, as C's probes.
    pub fn try_clone(&self) -> Result<Self, u32> {
        let c = Self::new()?;
        // SAFETY: two live contexts
        if unsafe { EVP_CIPHER_CTX_copy(c.0.0, self.0.0) } != 1 {
            return Err(rv::FUNCTION_FAILED);
        }
        Ok(c)
    }

    /// Drop the context without freeing it: after a fork it is the parent's.
    pub fn forget(self) {
        std::mem::forget(self);
    }
}

/// Can the loaded providers compute this digest (`oaep_md`, `mgf_md` returning non-NULL)?
pub fn md_known(name: &CStr) -> bool {
    // SAFETY: a C string; the fetched object is freed at once
    unsafe {
        let md = EVP_MD_fetch(null_mut(), name.as_ptr(), null());
        EVP_MD_free(md);
        !md.is_null()
    }
}

/// An RSA key from its DER (`EVP_PKEY`).
pub struct Pkey(Owned<EVP_PKEY>);

impl Pkey {
    /// `d2i_PUBKEY`.
    pub fn public(der: &[u8]) -> Option<Self> {
        let mut p = der.as_ptr();
        // SAFETY: der readable for its length
        Owned::new(unsafe { d2i_PUBKEY(null_mut(), &mut p, der.len() as c_long) }, EVP_PKEY_free).map(Self)
    }

    /// `d2i_AutoPrivateKey`.
    pub fn private(der: &[u8]) -> Option<Self> {
        let mut p = der.as_ptr();
        // SAFETY: as above
        Owned::new(unsafe { d2i_AutoPrivateKey(null_mut(), &mut p, der.len() as c_long) }, EVP_PKEY_free)
            .map(Self)
    }

    /// `EVP_PKEY_get_size`: the modulus length in bytes.
    pub fn size(&self) -> c_int {
        // SAFETY: a live key
        unsafe { EVP_PKEY_get_size(self.0.0) }
    }
}

/// `EVP_PKEY_CTX` for one RSA encryption or decryption.
pub struct PkeyCtx {
    ctx: Owned<EVP_PKEY_CTX>,
    enc: bool,
}

impl PkeyCtx {
    /// `oaep_ctx_init` (`:8566-8604`), in its order: HOST_MEMORY without a context,
    /// FUNCTION_FAILED if the init or the padding fails, MECHANISM_PARAM_INVALID if either
    /// digest is unknown (`None`) or will not fetch, FUNCTION_FAILED if setting them or the
    /// label fails. An empty label sets none.
    pub fn oaep(k: &Pkey, enc: bool, md: Option<&CStr>, mgf: Option<&CStr>, label: &[u8]) -> Result<Self, u32> {
        let mut c = Self::new(k, enc)?;
        if !c.init() || !c.padding(OAEP_PADDING) {
            return Err(rv::FUNCTION_FAILED);
        }
        // SAFETY: C strings; each fetched digest is freed below, set_rsa_*_md keep their own
        unsafe {
            let fetch = |n: Option<&CStr>| n.map_or(null_mut(), |n| EVP_MD_fetch(null_mut(), n.as_ptr(), null()));
            let (h, g) = (fetch(md), fetch(mgf));
            let r = if h.is_null() || g.is_null() {
                Err(rv::MECHANISM_PARAM_INVALID)
            } else if EVP_PKEY_CTX_set_rsa_oaep_md(c.ctx.0, h) <= 0
                || EVP_PKEY_CTX_set_rsa_mgf1_md(c.ctx.0, g) <= 0
            {
                Err(rv::FUNCTION_FAILED)
            } else {
                Ok(())
            };
            EVP_MD_free(h);
            EVP_MD_free(g);
            r?;
            if !label.is_empty() {
                // set0 takes an OPENSSL_malloc'd copy
                let l = CRYPTO_malloc(label.len(), c"cipher.rs".as_ptr(), 0);
                if l.is_null() {
                    return Err(rv::FUNCTION_FAILED);
                }
                std::ptr::copy_nonoverlapping(label.as_ptr(), l.cast(), label.len());
                if EVP_PKEY_CTX_set0_rsa_oaep_label(c.ctx.0, l, label.len() as c_int) <= 0 {
                    CRYPTO_free(l, c"cipher.rs".as_ptr(), 0);
                    return Err(rv::FUNCTION_FAILED);
                }
            }
        }
        Ok(c)
    }

    /// `EVP_PKEY_CTX_new`; HOST_MEMORY without one.
    pub fn new(k: &Pkey, enc: bool) -> Result<Self, u32> {
        // SAFETY: a live key
        let ctx = Owned::new(unsafe { EVP_PKEY_CTX_new(k.0.0, null_mut()) }, EVP_PKEY_CTX_free);
        ctx.map(|ctx| Self { ctx, enc }).ok_or(rv::HOST_MEMORY)
    }

    /// `EVP_PKEY_encrypt_init` or `_decrypt_init`.
    pub fn init(&mut self) -> bool {
        // SAFETY: a live context
        unsafe {
            (if self.enc { EVP_PKEY_encrypt_init(self.ctx.0) } else { EVP_PKEY_decrypt_init(self.ctx.0) }) > 0
        }
    }

    /// `EVP_PKEY_CTX_set_rsa_padding`.
    pub fn padding(&mut self, pad: c_int) -> bool {
        // SAFETY: a live context
        unsafe { EVP_PKEY_CTX_set_rsa_padding(self.ctx.0, pad) > 0 }
    }

    /// The OAEP digest's size (`EVP_PKEY_CTX_get_rsa_oaep_md`); -1 when there is none.
    pub fn oaep_md_size(&mut self) -> c_int {
        let mut md = null();
        // SAFETY: a live context; an out pointer of our own
        unsafe {
            if EVP_PKEY_CTX_get_rsa_oaep_md(self.ctx.0, &mut md) > 0 && !md.is_null() {
                EVP_MD_get_size(md)
            } else {
                -1
            }
        }
    }

    /// `EVP_PKEY_encrypt` or `_decrypt` of `inp`: a NULL `out` asks only for the length. On
    /// entry `*len` is `out`'s capacity; on success it is the length.
    ///
    /// # Safety
    /// `out` NULL or writable for `*len` bytes.
    pub unsafe fn run(&mut self, out: *mut u8, len: &mut usize, inp: &[u8]) -> bool {
        let f = if self.enc { EVP_PKEY_encrypt } else { EVP_PKEY_decrypt };
        // SAFETY: the caller's; inp readable for its length
        unsafe { f(self.ctx.0, out, len, inp.as_ptr(), inp.len()) > 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u8; 16] = *b"0123456789abcdef";

    #[test]
    fn ecb_in_parts_equals_one_call_and_decrypts_back() {
        let ecb = Fetched::new(c"AES-128-ECB").unwrap();
        let msg = [7u8; 32];
        let mut one = [0u8; 48];
        let mut c = Cipher::new().unwrap();
        assert!(c.init2(true, Some(&ecb), Some(&K), None));
        c.set_padding(false);
        // SAFETY: buffers sized for the input plus a block
        let n = unsafe { c.update(true, one.as_mut_ptr(), msg.as_ptr(), 32) }.unwrap();
        assert_eq!(n, 32);
        let mut c2 = Cipher::new().unwrap();
        assert!(c2.init2(true, Some(&ecb), Some(&K), None));
        c2.set_padding(false);
        let mut parts = [0u8; 48];
        // SAFETY: as above
        unsafe {
            let a = c2.update(true, parts.as_mut_ptr(), msg.as_ptr(), 5).unwrap();
            let b = c2.try_clone().unwrap().update(true, parts.as_mut_ptr().add(a), msg[5..].as_ptr(), 27);
            assert_eq!(a + b.unwrap(), 32);
        }
        assert_eq!(one[..32], parts[..32]);
        let mut d = Cipher::new().unwrap();
        assert!(d.init2(false, Some(&ecb), Some(&K), None));
        d.set_padding(false);
        let mut back = [0u8; 48];
        // SAFETY: as above
        assert_eq!(unsafe { d.update(false, back.as_mut_ptr(), one.as_ptr(), 32) }, Some(32));
        assert_eq!(back[..32], msg);
    }

    #[test]
    fn gcm_tag_round_trips_and_a_wrong_tag_fails() {
        let iv = [1u8; 12];
        let msg = *b"hello";
        let mut ct = [0u8; 32];
        let mut tag = [0u8; 16];
        let mut e = Cipher::new().unwrap();
        assert!(e.init(true, aead(Aead::Gcm, 16), None, None));
        assert!(e.init(true, None, Some(&K), Some(&iv)));
        // SAFETY: buffers sized for the input plus a block
        unsafe {
            assert_eq!(e.update(true, ct.as_mut_ptr(), msg.as_ptr(), 5), Some(5));
            assert_eq!(e.finish(true, ct.as_mut_ptr().add(5)), Some(0));
        }
        assert!(e.get_tag(&mut tag));
        for flip in [false, true] {
            let mut t = tag;
            t[0] ^= flip as u8;
            let mut d = Cipher::new().unwrap();
            assert!(d.init(false, aead(Aead::Gcm, 16), None, None));
            assert!(d.init(false, None, Some(&K), Some(&iv)));
            let mut pt = [0u8; 32];
            // SAFETY: as above
            unsafe { d.update(false, pt.as_mut_ptr(), ct.as_ptr(), 5) }.unwrap();
            assert!(d.set_tag(16, Some(&t)));
            // SAFETY: as above
            assert_eq!(unsafe { d.finish(false, pt.as_mut_ptr().add(5)) }.is_some(), !flip);
        }
        assert!(aead(Aead::Ccm, 20).is_none() && md_known(c"SHA256") && !md_known(c"NOPE"));
    }
}
