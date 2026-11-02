//! Test doubles for the C functions the token's `ffi` crypto backend imports (PHASE2_PLAN.md
//! §6.1: with `ffi` the token calls `src/fhsm_crypto.c`, the secure heap and the apilock).
//! Under `cargo test --features ffi`, and in the workspace `cargo test` where pqhsm-module
//! turns `ffi` on, nothing else defines them; in the hybrid build the real C does and these
//! are never linked.
//!
//! They reproduce what `golden/store/kat.tsv` records of the real functions: PBKDF2-HMAC-SHA256
//! refusing fewer than 1000 iterations with FIPS_NOT_APPROVED (0x80000003), AES-256-GCM with a
//! 16-byte tag, ENCRYPTED_DATA_INVALID (0x40) and a zeroised output on a bad tag. So an `ffi`
//! test run checks the marshalling across the seam; `tests/crypto.rs` checks the values.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_int, c_void};

use openssl::symm::{Cipher, Crypter, Mode};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Slice {
    data: *const u8,
    len: usize,
}

fn bytes<'a>(s: Slice) -> &'a [u8] {
    if s.data.is_null() || s.len == 0 {
        &[]
    } else {
        // SAFETY: the token passes slices over memory it owns for the call.
        unsafe { std::slice::from_raw_parts(s.data, s.len) }
    }
}

const OK: u32 = 0;
const FUNCTION_FAILED: u32 = 0x6;
const ARGUMENTS_BAD: u32 = 0x7;
const ENCRYPTED_DATA_INVALID: u32 = 0x40;
const FIPS_NOT_APPROVED: u32 = 0x8000_0003;
/// `FHSM_RV_RNG_FAILURE` (`include/fhsm_common.h:208`): what a latched DRBG returns.
pub const RNG_FAILURE: u32 = 0x8000_0008;

thread_local! {
    /// `fhsm_rng_bytes` calls made on this thread (the token draws on the caller's thread).
    pub static RNG_DRAWS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Fail the draw with this 0-based index (DIV-025).
    pub static RNG_FAIL_AT: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pbkdf2(
    alg: c_int,
    pw: Slice,
    salt: Slice,
    iter: u32,
    out: *mut u8,
    out_len: usize,
) -> u32 {
    if alg != 1 || out.is_null() || out_len == 0 || out_len > 256 {
        return ARGUMENTS_BAD;
    }
    if iter < 1000 {
        return FIPS_NOT_APPROVED;
    }
    // SAFETY: the caller owns `out_len` bytes at `out`.
    let o = unsafe { std::slice::from_raw_parts_mut(out, out_len) };
    match openssl::pkcs5::pbkdf2_hmac(
        bytes(pw),
        bytes(salt),
        iter as usize,
        openssl::hash::MessageDigest::sha256(),
        o,
    ) {
        Ok(()) => OK,
        Err(_) => FUNCTION_FAILED,
    }
}

fn gcm(
    mode: Mode,
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    input: &[u8],
    tag: &mut [u8; 16],
) -> Option<Vec<u8>> {
    let mut c = Crypter::new(Cipher::aes_256_gcm(), mode, key, Some(iv)).ok()?;
    if matches!(mode, Mode::Decrypt) {
        c.set_tag(tag).ok()?;
    }
    c.aad_update(aad).ok()?;
    let mut out = vec![0u8; input.len() + 32];
    let mut n = c.update(input, &mut out).ok()?;
    n += c.finalize(&mut out[n..]).ok()?;
    out.truncate(n);
    if matches!(mode, Mode::Encrypt) {
        c.get_tag(tag).ok()?;
    }
    Some(out)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_aes_gcm_encrypt(
    key: Slice,
    iv: Slice,
    aad: Slice,
    pt: Slice,
    ct: *mut u8,
    ct_len: *mut usize,
    tag: *mut u8,
) -> u32 {
    if key.len != 32 || iv.len != 12 || ct_len.is_null() || tag.is_null() {
        return ARGUMENTS_BAD;
    }
    let mut t = [0u8; 16];
    let Some(c) = gcm(
        Mode::Encrypt,
        bytes(key),
        bytes(iv),
        bytes(aad),
        bytes(pt),
        &mut t,
    ) else {
        return FUNCTION_FAILED;
    };
    // SAFETY: the caller sized `ct` for the plaintext and passes a 16-byte tag buffer.
    unsafe {
        if !c.is_empty() {
            std::ptr::copy_nonoverlapping(c.as_ptr(), ct, c.len());
        }
        *ct_len = c.len();
        std::ptr::copy_nonoverlapping(t.as_ptr(), tag, 16);
    }
    OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_aes_gcm_decrypt(
    key: Slice,
    iv: Slice,
    aad: Slice,
    ct: Slice,
    tag: *const u8,
    pt: *mut u8,
    pt_len: *mut usize,
) -> u32 {
    if key.len != 32 || iv.len != 12 || pt_len.is_null() || tag.is_null() {
        return ARGUMENTS_BAD;
    }
    // SAFETY: a 16-byte tag, and `pt` sized for the ciphertext.
    let mut t: [u8; 16] = unsafe { std::slice::from_raw_parts(tag, 16) }
        .try_into()
        .unwrap();
    match gcm(
        Mode::Decrypt,
        bytes(key),
        bytes(iv),
        bytes(aad),
        bytes(ct),
        &mut t,
    ) {
        Some(p) => unsafe {
            if !p.is_empty() {
                std::ptr::copy_nonoverlapping(p.as_ptr(), pt, p.len());
            }
            *pt_len = p.len();
            OK
        },
        None => unsafe {
            if ct.len > 0 && !pt.is_null() {
                std::ptr::write_bytes(pt, 0, ct.len);
            }
            ENCRYPTED_DATA_INVALID
        },
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rng_bytes(out: *mut u8, n: usize) -> u32 {
    let k = RNG_DRAWS.get();
    RNG_DRAWS.set(k + 1);
    if RNG_FAIL_AT.get() == Some(k) {
        return RNG_FAILURE; // and leave the buffer as it was, as the latched DRBG does
    }
    if n == 0 {
        return OK;
    }
    // SAFETY: the caller owns `n` bytes at `out`.
    let o = unsafe { std::slice::from_raw_parts_mut(out, n) };
    match openssl::rand::rand_bytes(o) {
        Ok(()) => OK,
        Err(_) => FUNCTION_FAILED,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_secure_malloc(n: usize) -> *mut c_void {
    // SAFETY: plain allocation; freed by fhsm_secure_free.
    unsafe { libc::calloc(1, n.max(1)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_secure_zalloc(n: usize) -> *mut c_void {
    // SAFETY: as above.
    unsafe { libc::calloc(1, n.max(1)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_secure_free(p: *mut c_void) {
    // SAFETY: `p` came from the two allocators above (or is NULL).
    unsafe { libc::free(p) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_zeroize(p: *mut c_void, n: usize) {
    for i in 0..n {
        // SAFETY: the caller owns `n` bytes at `p`.
        unsafe { std::ptr::write_volatile((p as *mut u8).add(i), 0) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_api_free_value(p: *mut c_void, len: usize, secure: c_int) {
    if p.is_null() {
        return;
    }
    // SAFETY: a value the C ABI handed out, with its length.
    unsafe {
        if secure != 0 {
            fhsm_zeroize(p, len);
        }
        libc::free(p);
    }
}

/// Every `(event, role, rv)` the token's C ABI reported through `fhsm_audit_event`.
pub static AUDIT: std::sync::Mutex<Vec<(c_int, c_int, u32)>> = std::sync::Mutex::new(Vec::new());

/// `fhsm_audit_event` is variadic in C (`audit/shim/audit_event.c` in the hybrid build). A
/// non-variadic definition reads the five fixed arguments the same way on the SysV ABI and
/// ignores the key/value list, which the scenario tests check through the safe API instead.
#[unsafe(no_mangle)]
pub extern "C" fn fhsm_audit_event(
    ev: c_int,
    _slot: c_int,
    _session: c_int,
    role: c_int,
    rv: u32,
) -> u32 {
    AUDIT.lock().unwrap().push((ev, role, rv));
    OK
}
