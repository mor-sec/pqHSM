//! The EVP calls of `C_Sign*` and `C_Verify*` (`src/fhsm_pkcs11.c:10765-12662`): MAC and
//! digest streams, the signing and verifying contexts, and their OSSL_PARAMs, each freed on
//! drop. Thin as `cipher.rs` is: `pqhsm-p11` makes C's call sequences out of them, so the
//! order of the calls and the code each failure returns stay where C put them.

use std::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use std::ptr::{null, null_mut};

use openssl_sys::{
    ERR_clear_error, EVP_DigestFinal_ex, EVP_DigestFinalXOF, EVP_DigestInit_ex, EVP_DigestSign,
    EVP_DigestUpdate, EVP_DigestVerify, EVP_MAC_CTX, EVP_MAC_CTX_free, EVP_MAC_CTX_new,
    EVP_MAC_fetch, EVP_MAC_final, EVP_MAC_free, EVP_MAC_init, EVP_MAC_update, EVP_MD, EVP_MD_CTX,
    EVP_MD_CTX_free, EVP_MD_CTX_get0_md, EVP_MD_CTX_new, EVP_MD_fetch, EVP_MD_free, EVP_PKEY,
    EVP_PKEY_CTX, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_CTX_new_from_name,
    EVP_PKEY_CTX_set_params, EVP_PKEY_PUBLIC_KEY, EVP_PKEY_free, EVP_PKEY_fromdata,
    EVP_PKEY_fromdata_init, EVP_PKEY_get_bits, EVP_PKEY_is_a, EVP_PKEY_sign, EVP_PKEY_sign_init,
    EVP_PKEY_verify, EVP_PKEY_verify_init, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_construct_end,
    OSSL_PARAM_construct_octet_string,
};

use super::cipher::{Owned, Pkey};
use crate::rv;

unsafe extern "C" {
    // OpenSSL 3; not bound by openssl-sys, or bound as 1.1 macros
    fn OSSL_PARAM_construct_utf8_string(
        key: *const c_char,
        buf: *mut c_char,
        bsize: usize,
    ) -> OSSL_PARAM;
    fn OSSL_PARAM_construct_int(key: *const c_char, buf: *mut c_int) -> OSSL_PARAM;
    fn EVP_PKEY_get_base_id(k: *const EVP_PKEY) -> c_int;
    fn EVP_MD_get_flags(md: *const EVP_MD) -> c_ulong;
    fn EVP_DigestSignInit_ex(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        md: *const c_char,
        libctx: *mut OSSL_LIB_CTX,
        props: *const c_char,
        k: *mut EVP_PKEY,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn EVP_DigestVerifyInit_ex(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        md: *const c_char,
        libctx: *mut OSSL_LIB_CTX,
        props: *const c_char,
        k: *mut EVP_PKEY,
        params: *const OSSL_PARAM,
    ) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut EVP_PKEY_CTX, pad: c_int) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: *mut EVP_PKEY_CTX, len: c_int) -> c_int;
    fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int;
    fn CRYPTO_memcmp(a: *const c_void, b: *const c_void, len: usize) -> c_int;
}

/// `fhsm_ct_memcmp(a, b, len) == 0` over equal lengths, in constant time.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    assert_eq!(a.len(), b.len());
    // SAFETY: both readable for the length
    unsafe { CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
}

/// `EVP_MD_FLAG_XOF`.
const MD_FLAG_XOF: c_ulong = 0x2;
/// `RSA_PKCS1_PSS_PADDING`.
const PSS_PADDING: c_int = 6;
/// `RSA_NO_PADDING`.
pub const NO_PADDING: c_int = 3;
/// `EVP_PKEY_RSA`, `EVP_PKEY_EC`.
pub const PKEY_RSA: c_int = openssl_sys::EVP_PKEY_RSA;
pub const PKEY_EC: c_int = openssl_sys::EVP_PKEY_EC;

/// One OSSL_PARAM, by what C constructed.
#[derive(Clone, Copy)]
pub enum Param<'a> {
    Int(&'static CStr, c_int),
    Octets(&'static CStr, &'a [u8]),
    Utf8(&'static CStr, &'static CStr),
}

/// The params, ended, over storage for the ints they point to; `'a` is the octets'.
struct Params<'a> {
    list: Vec<OSSL_PARAM>,
    _ints: Vec<c_int>,
    _octets: std::marker::PhantomData<&'a [u8]>,
}

impl<'a> Params<'a> {
    fn new(p: &[Param<'a>]) -> Self {
        let mut ints: Vec<c_int> = p
            .iter()
            .map(|q| if let Param::Int(_, v) = q { *v } else { 0 })
            .collect();
        // One raw pointer to the ints' heap, which moving the Vec into the struct keeps
        let at = ints.as_mut_ptr();
        let mut list: Vec<OSSL_PARAM> = Vec::with_capacity(p.len() + 1);
        for (i, q) in p.iter().enumerate() {
            // SAFETY: keys and buffers outlive the list: static names, the octets for 'a,
            // ints in the Vec this struct owns
            list.push(unsafe {
                match *q {
                    Param::Int(k, _) => OSSL_PARAM_construct_int(k.as_ptr(), at.add(i)),
                    Param::Octets(k, b) => OSSL_PARAM_construct_octet_string(
                        k.as_ptr(),
                        b.as_ptr().cast_mut().cast(),
                        b.len(),
                    ),
                    Param::Utf8(k, v) => {
                        OSSL_PARAM_construct_utf8_string(k.as_ptr(), v.as_ptr().cast_mut(), 0)
                    }
                }
            });
        }
        // SAFETY: a constructor
        list.push(unsafe { OSSL_PARAM_construct_end() });
        Self {
            list,
            _ints: ints,
            _octets: std::marker::PhantomData,
        }
    }

    /// NULL for none, as C passed for an empty list.
    fn ptr(&self) -> *const OSSL_PARAM {
        if self.list.len() == 1 {
            null()
        } else {
            self.list.as_ptr()
        }
    }
}

impl Pkey {
    /// `EVP_PKEY_get_base_id`.
    pub fn base_id(&self) -> c_int {
        // SAFETY: a live key
        unsafe { EVP_PKEY_get_base_id(self.0.0) }
    }

    /// `EVP_PKEY_get_bits`.
    pub fn bits(&self) -> c_int {
        // SAFETY: a live key
        unsafe { EVP_PKEY_get_bits(self.0.0) }
    }

    /// `EVP_PKEY_is_a`.
    pub fn is_a(&self, name: &CStr) -> bool {
        // SAFETY: a live key; a C string
        unsafe { EVP_PKEY_is_a(self.0.0, name.as_ptr()) == 1 }
    }

    /// A raw public key of algorithm `alg` (`EVP_PKEY_fromdata`, `:11687-11700`).
    pub fn raw_public(alg: &CStr, raw: &[u8]) -> Option<Self> {
        // SAFETY: a C string; raw readable for its length, which fromdata copies
        unsafe {
            let c = Owned::new(
                EVP_PKEY_CTX_new_from_name(null_mut(), alg.as_ptr(), null()),
                EVP_PKEY_CTX_free,
            )?;
            if EVP_PKEY_fromdata_init(c.0) <= 0 {
                return None;
            }
            let mut p = [
                OSSL_PARAM_construct_octet_string(
                    c"pub".as_ptr(),
                    raw.as_ptr().cast_mut().cast(),
                    raw.len(),
                ),
                OSSL_PARAM_construct_end(),
            ];
            let mut k = null_mut();
            EVP_PKEY_fromdata(c.0, &mut k, EVP_PKEY_PUBLIC_KEY, p.as_mut_ptr());
            Owned::new(k, EVP_PKEY_free).map(Self)
        }
    }
}

/// `ERR_clear_error`.
pub fn clear_errors() {
    // SAFETY: no arguments
    unsafe { ERR_clear_error() }
}

/// The MGF1 digest of `pss_apply_params`: OpenSSL's default, a named one, or one C's
/// `mgf_md` does not know.
#[derive(Clone, Copy)]
pub enum Mgf {
    Default,
    Named(&'static CStr),
    Unknown,
}

/// `pss_apply_params` (`:11040-11060`): FUNCTION_FAILED if the padding or the salt length
/// will not set, MECHANISM_PARAM_INVALID for an MGF it cannot fetch.
///
/// # Safety
/// `c` a live context.
unsafe fn pss(c: *mut EVP_PKEY_CTX, salt: c_int, mgf: Mgf) -> Result<(), u32> {
    // SAFETY: the caller's; the fetched digest is freed, set_rsa_mgf1_md keeps its own
    unsafe {
        if EVP_PKEY_CTX_set_rsa_padding(c, PSS_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_pss_saltlen(c, salt) <= 0
        {
            return Err(rv::FUNCTION_FAILED);
        }
        let name = match mgf {
            Mgf::Default => return Ok(()),
            Mgf::Unknown => return Err(rv::MECHANISM_PARAM_INVALID),
            Mgf::Named(n) => n,
        };
        let md = EVP_MD_fetch(null_mut(), name.as_ptr(), null());
        if md.is_null() {
            return Err(rv::MECHANISM_PARAM_INVALID);
        }
        let r = EVP_PKEY_CTX_set_rsa_mgf1_md(c, md);
        EVP_MD_free(md);
        if r > 0 {
            Ok(())
        } else {
            Err(rv::FUNCTION_FAILED)
        }
    }
}

/// An `EVP_MD_CTX` signing or verifying with a key (`EVP_DigestSignInit_ex`), and the key
/// context the init gave it.
pub struct DigestCtx {
    ctx: Owned<EVP_MD_CTX>,
    pk: *mut EVP_PKEY_CTX,
}

impl DigestCtx {
    /// `EVP_MD_CTX_new`; HOST_MEMORY without one.
    pub fn new() -> Result<Self, u32> {
        // SAFETY: a constructor
        let ctx =
            Owned::new(unsafe { EVP_MD_CTX_new() }, EVP_MD_CTX_free).ok_or(rv::HOST_MEMORY)?;
        Ok(Self {
            ctx,
            pk: null_mut(),
        })
    }

    /// `EVP_DigestSignInit_ex` (`sign`) or `EVP_DigestVerifyInit_ex` with digest `md` (none for
    /// the schemes that hash their own message) and init params.
    pub fn init(&mut self, sign: bool, k: &Pkey, md: Option<&CStr>, p: &[Param]) -> bool {
        let p = Params::new(p);
        let f = if sign {
            EVP_DigestSignInit_ex
        } else {
            EVP_DigestVerifyInit_ex
        };
        // SAFETY: live contexts; a C string or NULL; params alive for the call
        unsafe {
            f(
                self.ctx.0,
                &mut self.pk,
                md.map_or(null(), CStr::as_ptr),
                null_mut(),
                null(),
                k.0.0,
                p.ptr(),
            ) == 1
        }
    }

    /// `EVP_PKEY_CTX_set_params` on the key context.
    pub fn set_params(&mut self, p: &[Param]) -> bool {
        let p = Params::new(p);
        // SAFETY: the init's key context; params alive for the call
        unsafe { EVP_PKEY_CTX_set_params(self.pk, p.ptr()) > 0 }
    }

    /// `pss_apply_params` on the key context.
    pub fn pss(&mut self, salt: c_int, mgf: Mgf) -> Result<(), u32> {
        // SAFETY: the init's key context
        unsafe { pss(self.pk, salt, mgf) }
    }

    /// `EVP_DigestSign` into `out`: the length, or `None`.
    pub fn sign(&mut self, data: &[u8], out: &mut [u8]) -> Option<usize> {
        let mut n = out.len();
        // SAFETY: live context; out writable for n bytes, data readable for its length
        (unsafe {
            EVP_DigestSign(
                self.ctx.0,
                out.as_mut_ptr(),
                &mut n,
                data.as_ptr(),
                data.len(),
            )
        } == 1)
            .then_some(n)
    }

    /// `EVP_DigestVerify`: OpenSSL's answer.
    pub fn verify(&mut self, sig: &[u8], data: &[u8]) -> c_int {
        // SAFETY: live context; both readable for their lengths
        unsafe {
            EVP_DigestVerify(
                self.ctx.0,
                sig.as_ptr(),
                sig.len(),
                data.as_ptr(),
                data.len(),
            )
        }
    }
}

/// An `EVP_PKEY_CTX` signing or verifying the caller's bytes as they are (`EVP_PKEY_sign`).
pub struct RawCtx(Owned<EVP_PKEY_CTX>);

impl RawCtx {
    /// `EVP_PKEY_CTX_new` then the sign or verify init; `None` if either fails.
    pub fn new(sign: bool, k: &Pkey) -> Option<Self> {
        // SAFETY: a live key
        let c = Owned::new(
            unsafe { EVP_PKEY_CTX_new(k.0.0, null_mut()) },
            EVP_PKEY_CTX_free,
        )?;
        // SAFETY: a live context
        let ok = unsafe {
            if sign {
                EVP_PKEY_sign_init(c.0)
            } else {
                EVP_PKEY_verify_init(c.0)
            }
        } > 0;
        ok.then_some(Self(c))
    }

    /// `EVP_PKEY_CTX_set_rsa_padding`.
    pub fn padding(&mut self, pad: c_int) -> bool {
        // SAFETY: a live context
        unsafe { EVP_PKEY_CTX_set_rsa_padding(self.0.0, pad) > 0 }
    }

    /// `pss_apply_params`.
    pub fn pss(&mut self, salt: c_int, mgf: Mgf) -> Result<(), u32> {
        // SAFETY: a live context
        unsafe { pss(self.0.0, salt, mgf) }
    }

    /// `EVP_PKEY_sign` into `out`: the length, or `None`.
    pub fn sign(&mut self, data: &[u8], out: &mut [u8]) -> Option<usize> {
        let mut n = out.len();
        // SAFETY: live context; out writable for n bytes, data readable for its length
        (unsafe {
            EVP_PKEY_sign(
                self.0.0,
                out.as_mut_ptr(),
                &mut n,
                data.as_ptr(),
                data.len(),
            )
        } > 0)
            .then_some(n)
    }

    /// `EVP_PKEY_verify`: OpenSSL's answer.
    pub fn verify(&mut self, sig: &[u8], data: &[u8]) -> c_int {
        // SAFETY: live context; both readable for their lengths
        unsafe { EVP_PKEY_verify(self.0.0, sig.as_ptr(), sig.len(), data.as_ptr(), data.len()) }
    }
}

/// An `EVP_MAC_CTX`, keyed: HMAC, CMAC or GMAC as `mac_stream_open` and `aes_cmac` make it.
pub struct Mac(Owned<EVP_MAC_CTX>);

// SAFETY: an EVP_MAC_CTX is used by one thread at a time (p11 holds it under a mutex), and
// OpenSSL ties it to no thread.
unsafe impl Send for Mac {}

impl Mac {
    /// MECHANISM_INVALID if `name` will not fetch, HOST_MEMORY without a context,
    /// FUNCTION_FAILED if the init fails.
    pub fn new(name: &CStr, key: &[u8], p: &[Param]) -> Result<Self, u32> {
        let p = Params::new(p);
        // SAFETY: a C string; the fetched MAC is freed once the context holds it; key and params
        // alive for the call
        unsafe {
            let mac = EVP_MAC_fetch(null_mut(), name.as_ptr(), null());
            if mac.is_null() {
                return Err(rv::MECHANISM_INVALID);
            }
            let c = Owned::new(EVP_MAC_CTX_new(mac), EVP_MAC_CTX_free);
            EVP_MAC_free(mac);
            let c = c.ok_or(rv::HOST_MEMORY)?;
            if EVP_MAC_init(c.0, key.as_ptr(), key.len(), p.ptr()) != 1 {
                return Err(rv::FUNCTION_FAILED);
            }
            Ok(Self(c))
        }
    }

    /// `EVP_MAC_update`.
    pub fn update(&mut self, d: &[u8]) -> bool {
        // SAFETY: a live context; d readable for its length
        unsafe { EVP_MAC_update(self.0.0, d.as_ptr(), d.len()) == 1 }
    }

    /// `EVP_MAC_final` into `out`: the length, or `None`.
    pub fn finish(&mut self, out: &mut [u8]) -> Option<usize> {
        let mut n = 0;
        // SAFETY: a live context; out writable for its length
        (unsafe { EVP_MAC_final(self.0.0, out.as_mut_ptr(), &mut n, out.len()) } == 1).then_some(n)
    }

    /// Drop the context without freeing it: after a fork it is the parent's.
    pub fn forget(self) {
        std::mem::forget(self);
    }
}

/// An `EVP_MD_CTX` hashing a stream, by OpenSSL name (HashML-DSA's PH(M), the composite's).
pub struct Md(Owned<EVP_MD_CTX>);

// SAFETY: as Mac's
unsafe impl Send for Md {}

impl Md {
    /// MECHANISM_INVALID if `name` will not fetch, FUNCTION_FAILED without a context or if
    /// its init fails.
    pub fn new(name: &CStr) -> Result<Self, u32> {
        // SAFETY: a C string; the fetched digest is freed once the context holds it
        unsafe {
            let md = EVP_MD_fetch(null_mut(), name.as_ptr(), null());
            if md.is_null() {
                return Err(rv::MECHANISM_INVALID);
            }
            let c = Owned::new(EVP_MD_CTX_new(), EVP_MD_CTX_free);
            let ok = c
                .as_ref()
                .is_some_and(|c| EVP_DigestInit_ex(c.0, md, null_mut()) == 1);
            EVP_MD_free(md);
            match c {
                Some(c) if ok => Ok(Self(c)),
                _ => Err(rv::FUNCTION_FAILED),
            }
        }
    }

    /// `EVP_DigestUpdate`.
    pub fn update(&mut self, d: &[u8]) -> bool {
        // SAFETY: a live context; d readable for its length
        unsafe { EVP_DigestUpdate(self.0.0, d.as_ptr().cast::<c_void>(), d.len()) == 1 }
    }

    /// The digest into `out`: an XOF gives exactly `out.len()` bytes, another digest its own
    /// length, which is returned and must fit (`EVP_MAX_MD_SIZE`, 64, holds every one).
    pub fn finish(&mut self, out: &mut [u8]) -> Option<usize> {
        // SAFETY: a live context; out writable for its length
        unsafe {
            if EVP_MD_get_flags(EVP_MD_CTX_get0_md(self.0.0)) & MD_FLAG_XOF != 0 {
                (EVP_DigestFinalXOF(self.0.0, out.as_mut_ptr(), out.len()) == 1)
                    .then_some(out.len())
            } else if out.len() < 64 {
                let mut full = [0u8; 64];
                let mut n = 0u32;
                let ok = EVP_DigestFinal_ex(self.0.0, full.as_mut_ptr(), &mut n) == 1
                    && n as usize <= out.len();
                if ok {
                    out[..n as usize].copy_from_slice(&full[..n as usize]);
                }
                super::cipher::cleanse(&mut full);
                ok.then_some(n as usize)
            } else {
                let mut n = 0u32;
                (EVP_DigestFinal_ex(self.0.0, out.as_mut_ptr(), &mut n) == 1).then_some(n as usize)
            }
        }
    }

    /// Drop the context without freeing it: after a fork it is the parent's.
    pub fn forget(self) {
        std::mem::forget(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_and_xof_digests_give_their_lengths() {
        let key = [0x0bu8; 20];
        let mut m = Mac::new(c"HMAC", &key, &[Param::Utf8(c"digest", c"SHA256")]).unwrap();
        assert!(m.update(b"Hi There"));
        let mut out = [0u8; 64];
        assert_eq!(m.finish(&mut out), Some(32));
        // RFC 4231 test case 1
        assert_eq!(out[..4], [0xb0, 0x34, 0x4c, 0x61]);
        let mut c = Mac::new(
            c"CMAC",
            &[0u8; 16],
            &[Param::Utf8(c"cipher", c"AES-128-CBC")],
        )
        .unwrap();
        assert_eq!(c.finish(&mut out), Some(16));
        assert_eq!(
            Mac::new(c"NOPE", &key, &[]).err(),
            Some(rv::MECHANISM_INVALID)
        );
        let mut x = Md::new(c"SHAKE128").unwrap();
        assert!(x.update(b""));
        assert_eq!(x.finish(&mut out[..32]), Some(32));
        // FIPS 202: SHAKE128("") begins 7f9c2ba4
        assert_eq!(out[..4], [0x7f, 0x9c, 0x2b, 0xa4]);
        let mut s = Md::new(c"SHA2-256").unwrap();
        assert_eq!(s.finish(&mut out[..32]), Some(32));
        assert_eq!(Md::new(c"NOPE").err(), Some(rv::MECHANISM_INVALID));
        assert!(ct_eq(b"ab", b"ab") && !ct_eq(b"ab", b"ac"));
    }
}
