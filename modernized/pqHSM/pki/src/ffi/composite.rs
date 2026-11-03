//! Composite ML-DSA over OpenSSL (`src/fhsm_composite.c:228-481`): the component keys, PH(M),
//! and each component's sign and verify, in C's calls. The C ABI around them is in `c_abi`.

use std::ffi::{CStr, c_char, c_int, c_long, c_uint, c_void};
use std::ptr::{null, null_mut};

use openssl_sys::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestSign, EVP_DigestUpdate, EVP_DigestVerify,
    EVP_MAX_MD_SIZE, EVP_MD, EVP_MD_CTX, EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_fetch,
    EVP_MD_free, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name,
    EVP_PKEY_free, EVP_PKEY_keygen, EVP_PKEY_keygen_init, OPENSSL_free, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, d2i_PUBKEY, i2d_PUBKEY,
    i2d_PrivateKey,
};

use crate::composite::{BlobError, Params, unpack};

/// The `fhsm_rv_t` codes these calls return (`include/fhsm_common.h`).
pub mod rv {
    pub const OK: u32 = 0;
    pub const HOST_MEMORY: u32 = 0x02;
    pub const FUNCTION_FAILED: u32 = 0x06;
    pub const ARGUMENTS_BAD: u32 = 0x07;
    pub const DATA_LEN_RANGE: u32 = 0x21;
    pub const MECHANISM_INVALID: u32 = 0x70;
    pub const KEY_HANDLE_INVALID: u32 = 0x60;
    pub const KEY_TYPE_INCONSISTENT: u32 = 0x63;
    pub const SIGNATURE_INVALID: u32 = 0xC0;
    pub const BUFFER_TOO_SMALL: u32 = 0x150;
}

unsafe extern "C" {
    // OpenSSL 3; not bound by openssl-sys
    fn d2i_PrivateKey_ex(
        kind: c_int,
        a: *mut *mut EVP_PKEY,
        pp: *mut *const u8,
        len: c_long,
        libctx: *mut OSSL_LIB_CTX,
        propq: *const c_char,
    ) -> *mut EVP_PKEY;
    fn EVP_DigestSignInit_ex(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        mdname: *const c_char,
        libctx: *mut OSSL_LIB_CTX,
        props: *const c_char,
        pkey: *mut EVP_PKEY,
        params: *const OSSL_PARAM,
    ) -> c_int;
    pub(crate) fn EVP_DigestVerifyInit_ex(
        ctx: *mut EVP_MD_CTX,
        pctx: *mut *mut EVP_PKEY_CTX,
        mdname: *const c_char,
        libctx: *mut OSSL_LIB_CTX,
        props: *const c_char,
        pkey: *mut EVP_PKEY,
        params: *const OSSL_PARAM,
    ) -> c_int;
    pub(crate) fn OPENSSL_cleanse(p: *mut c_void, n: usize);
}

/// Wipes `b` as C's OPENSSL_cleanse does.
pub(crate) fn cleanse(b: &mut [u8]) {
    // SAFETY: b.len() writable bytes
    unsafe { OPENSSL_cleanse(b.as_mut_ptr().cast(), b.len()) }
}

/// An OpenSSL object, freed on drop.
struct Own<T>(*mut T, unsafe extern "C" fn(*mut T));

impl<T> Own<T> {
    fn new(p: *mut T, free: unsafe extern "C" fn(*mut T)) -> Option<Self> {
        (!p.is_null()).then_some(Self(p, free))
    }
}

impl<T> Drop for Own<T> {
    fn drop(&mut self) {
        // SAFETY: self.0 came from the allocator self.1 frees, and is freed once
        unsafe { (self.1)(self.0) }
    }
}

/// DER that OpenSSL allocated; a private key's is wiped before it is freed, as C's.
pub struct Der {
    p: *mut u8,
    n: usize,
    secret: bool,
}

impl Der {
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: n bytes at p, from i2d_*
        unsafe { std::slice::from_raw_parts(self.p, self.n) }
    }
}

impl Drop for Der {
    fn drop(&mut self) {
        // SAFETY: p is OpenSSL's, n bytes long, freed once
        unsafe {
            if self.secret {
                OPENSSL_cleanse(self.p.cast(), self.n);
            }
            OPENSSL_free(self.p.cast());
        }
    }
}

type I2d = unsafe extern "C" fn(*const EVP_PKEY, *mut *mut u8) -> c_int;

fn der(i2d: I2d, k: &Own<EVP_PKEY>, secret: bool) -> Option<Der> {
    let mut p = null_mut();
    // SAFETY: k is live; OpenSSL allocates the output
    let n = unsafe { i2d(k.0, &mut p) };
    let d = (!p.is_null()).then_some(Der {
        p,
        n: usize::try_from(n).unwrap_or(0),
        secret,
    });
    if n > 0 { d } else { None }
}

/// `gen_one`.
fn gen_one(name: &CStr) -> Option<Own<EVP_PKEY>> {
    // SAFETY: a C string; every object is held by an Own
    unsafe {
        let c = Own::new(
            EVP_PKEY_CTX_new_from_name(null_mut(), name.as_ptr(), null()),
            EVP_PKEY_CTX_free,
        )?;
        let mut k = null_mut();
        if EVP_PKEY_keygen_init(c.0) <= 0 || EVP_PKEY_keygen(c.0, &mut k) <= 0 {
            EVP_PKEY_free(k);
            return None;
        }
        Own::new(k, EVP_PKEY_free)
    }
}

/// Both component key pairs, fresh (draft §3.1): pq private, trad private, pq SPKI and trad
/// SPKI DER, or None if either generation or any encoding fails.
pub fn keygen(p: &Params) -> Option<[Der; 4]> {
    let (kpq, ktr) = (gen_one(p.pq), gen_one(p.trad));
    let (kpq, ktr) = (kpq?, ktr?);
    let (dpq, dtr) = (
        der(i2d_PrivateKey, &kpq, true),
        der(i2d_PrivateKey, &ktr, true),
    );
    let (ppq, ptr) = (der(i2d_PUBKEY, &kpq, false), der(i2d_PUBKEY, &ktr, false));
    Some([dpq?, dtr?, ppq?, ptr?])
}

/// PH(M) for `fhsm_composite_mprime`: `Err` (FUNCTION_FAILED without the digest, HOST_MEMORY
/// without a context) returns at once, as C's; `Ok(None)` is a digest that failed to run, after
/// which C wipes the output; else the digest's length.
pub fn ph(
    p: &Params,
    msg: &[u8],
    out: &mut [u8; EVP_MAX_MD_SIZE as usize],
) -> Result<Option<usize>, u32> {
    // SAFETY: a C string; md and the context are freed below; msg.len() readable bytes
    unsafe {
        let md: *mut EVP_MD = EVP_MD_fetch(null_mut(), p.ph_name.as_ptr(), null());
        if md.is_null() {
            return Err(rv::FUNCTION_FAILED);
        }
        let ctx = EVP_MD_CTX_new();
        if ctx.is_null() {
            EVP_MD_free(md);
            return Err(rv::HOST_MEMORY);
        }
        let mut n: c_uint = 0;
        let ok = EVP_DigestInit_ex(ctx, md, null_mut()) == 1
            && (msg.is_empty() || EVP_DigestUpdate(ctx, msg.as_ptr().cast(), msg.len()) == 1)
            && EVP_DigestFinal_ex(ctx, out.as_mut_ptr(), &mut n) == 1;
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
        Ok(ok.then_some(n as usize))
    }
}

/// The ML-DSA context string (`OSSL_SIGNATURE_PARAM_CONTEXT_STRING`), or none: the
/// traditional component takes none (draft §3.2).
fn context(label: Option<&CStr>) -> Option<[OSSL_PARAM; 2]> {
    // SAFETY: the label is static; OpenSSL only reads it
    label.map(|l| unsafe {
        [
            OSSL_PARAM_construct_octet_string(
                c"context-string".as_ptr(),
                l.as_ptr() as *mut c_void,
                l.to_bytes().len(),
            ),
            OSSL_PARAM_construct_end(),
        ]
    })
}

/// `sign_component`: EVP_DigestSign without a digest; `*n` the capacity in, the length out.
///
/// # Safety
/// `sig` has `*n` writable bytes.
unsafe fn sign_component(
    k: &Own<EVP_PKEY>,
    label: Option<&CStr>,
    m: &[u8],
    sig: *mut u8,
    n: &mut usize,
) -> bool {
    let params = context(label);
    let pp = params.as_ref().map_or(null(), |p| p.as_ptr());
    // SAFETY: k is live; sig has *n writable bytes (the caller's contract); params outlives
    // the calls; the context is freed below
    unsafe {
        let c = EVP_MD_CTX_new();
        if c.is_null() {
            return false;
        }
        let mut sc = null_mut();
        let r = EVP_DigestSignInit_ex(c, &mut sc, null(), null_mut(), null(), k.0, pp) > 0
            && EVP_DigestSign(c, sig, n, m.as_ptr(), m.len()) > 0;
        EVP_MD_CTX_free(c);
        r
    }
}

/// `verify_component`.
fn verify_component(k: &Own<EVP_PKEY>, label: Option<&CStr>, m: &[u8], sig: &[u8]) -> bool {
    let params = context(label);
    let pp = params.as_ref().map_or(null(), |p| p.as_ptr());
    // SAFETY: as sign_component
    unsafe {
        let c = EVP_MD_CTX_new();
        if c.is_null() {
            return false;
        }
        let mut vc = null_mut();
        let r = EVP_DigestVerifyInit_ex(c, &mut vc, null(), null_mut(), null(), k.0, pp) > 0
            && EVP_DigestVerify(c, sig.as_ptr(), sig.len(), m.as_ptr(), m.len()) == 1;
        EVP_MD_CTX_free(c);
        r
    }
}

pub(crate) fn blob_rv(e: BlobError) -> u32 {
    match e {
        BlobError::Malformed => rv::ARGUMENTS_BAD,
        BlobError::OtherAlgorithm => rv::KEY_TYPE_INCONSISTENT,
    }
}

fn d2i_private(der: &[u8]) -> Option<Own<EVP_PKEY>> {
    let mut q = der.as_ptr();
    // SAFETY: der.len() readable bytes; type 0 (EVP_PKEY_NONE) lets OpenSSL find it
    let k = unsafe {
        d2i_PrivateKey_ex(
            0,
            null_mut(),
            &mut q,
            der.len() as c_long,
            null_mut(),
            null(),
        )
    };
    Own::new(k, EVP_PKEY_free)
}

fn d2i_public(der: &[u8]) -> Option<Own<EVP_PKEY>> {
    let mut q = der.as_ptr();
    // SAFETY: der.len() readable bytes
    let k = unsafe { d2i_PUBKEY(null_mut(), &mut q, der.len() as c_long) };
    Own::new(k, EVP_PKEY_free)
}

/// `sign_mprime`: mldsaSig || tradSig into `sig`; `*n` the capacity in, the signature's
/// length out on OK, unchanged otherwise.
///
/// # Safety
/// `sig` has `*n` writable bytes.
pub unsafe fn sign_mprime(
    p: &Params,
    private: &[u8],
    m: &[u8],
    sig: *mut u8,
    n: &mut usize,
) -> u32 {
    let (dpq, dtr) = match unpack(p.alg, private) {
        Ok(c) => c,
        Err(e) => return blob_rv(e),
    };
    let (kpq, ktr) = (d2i_private(dpq), d2i_private(dtr));
    let (Some(kpq), Some(ktr)) = (kpq, ktr) else {
        return rv::KEY_HANDLE_INVALID;
    };
    let mut spq = *n;
    // SAFETY: sig has *n writable bytes
    if !unsafe { sign_component(&kpq, Some(p.label), m, sig, &mut spq) } {
        return rv::FUNCTION_FAILED;
    }
    let mut str_ = n.saturating_sub(spq);
    // SAFETY: spq <= *n, so sig + spq has *n - spq writable bytes
    if !unsafe { sign_component(&ktr, None, m, sig.add(spq), &mut str_) } {
        return rv::FUNCTION_FAILED;
    }
    *n = spq + str_;
    rv::OK
}

/// `verify_mprime` after the split: OK only if both components verify (draft §3.3).
pub fn verify_mprime(p: &Params, public: &[u8], m: &[u8], pq_sig: &[u8], trad_sig: &[u8]) -> u32 {
    let (ppq, ptr) = match unpack(p.alg, public) {
        Ok(c) => c,
        Err(e) => return blob_rv(e),
    };
    let (kpq, ktr) = (d2i_public(ppq), d2i_public(ptr));
    let (Some(kpq), Some(ktr)) = (kpq, ktr) else {
        return rv::KEY_HANDLE_INVALID;
    };
    if verify_component(&kpq, Some(p.label), m, pq_sig) && verify_component(&ktr, None, m, trad_sig)
    {
        rv::OK
    } else {
        rv::SIGNATURE_INVALID
    }
}
