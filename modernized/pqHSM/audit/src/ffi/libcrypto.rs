//! The two libcrypto calls the audit trail makes. Always compiled: `cargo test` uses them too.

use std::ffi::{c_char, c_uchar, c_void};

unsafe extern "C" {
    // OpenSSL >= 3.0, <openssl/evp.h>; not bound by openssl-sys.
    fn EVP_Q_mac(
        libctx: *mut c_void,
        name: *const c_char,
        propq: *const c_char,
        subalg: *const c_char,
        params: *const c_void,
        key: *const c_void,
        keylen: usize,
        data: *const c_uchar,
        datalen: usize,
        out: *mut c_uchar,
        outsize: usize,
        outlen: *mut usize,
    ) -> *mut c_uchar;
}

/// HMAC-SHA-256 through `EVP_MAC_fetch(NULL, "HMAC", NULL)`, as `fhsm_hmac` does.
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut len = 0usize;
    // SAFETY: every pointer is valid for the length passed with it, the names are NUL-terminated
    // literals, and `out` has room for the 32 bytes asked for.
    let r = unsafe {
        EVP_Q_mac(
            std::ptr::null_mut(),
            c"HMAC".as_ptr(),
            std::ptr::null(),
            c"SHA256".as_ptr(),
            std::ptr::null(),
            key.as_ptr().cast(),
            key.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut len,
        )
    };
    (!r.is_null() && len == out.len()).then_some(out)
}

/// `CRYPTO_memcmp(a, b, 32) == 0`.
pub(crate) fn memcmp_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    // SAFETY: both pointers are valid for 32 bytes.
    unsafe { openssl_sys::CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
}
