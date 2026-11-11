//! The C ABI of `include/fhsm_tpm.h` and `include/fhsm_token_tpm.h`, over [`crate::tpm`].
//!
//! One process-wide `Tpm`, built on first use (review L4: C's `g_tpm_available` was a plain
//! int raced by every thread). With `tpm-test-hooks` it reads `FHSM_TPM_DEVICE` and
//! `FHSM_TPM_CMD` then, an empty value meaning the default, as C's seam did.

use std::ffi::{CStr, OsStr, c_char, c_int};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use crate::Rv;
use crate::tpm::{self, Tpm};

const OK: u32 = 0;

fn the_tpm() -> &'static Tpm {
    shared_tpm_ref()
}

/// The same `Tpm`, for the token ABI's `Platform` (C's availability cache is process-wide).
pub(super) fn shared_tpm() -> Arc<Tpm> {
    Arc::clone(shared_tpm_ref())
}

fn shared_tpm_ref() -> &'static Arc<Tpm> {
    static TPM: OnceLock<Arc<Tpm>> = OnceLock::new();
    TPM.get_or_init(|| {
        #[cfg(feature = "tpm-test-hooks")]
        {
            let var = |k: &str, default: &str| {
                pqhsm_core::env(k)
                    .and_then(|v| v.into_string().ok())
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| default.into())
            };
            Arc::new(Tpm::new(
                var("FHSM_TPM_DEVICE", "/dev/tpmrm0"),
                tpm::Cli::Shell(var("FHSM_TPM_CMD", "tpm2")),
            ))
        }
        #[cfg(not(feature = "tpm-test-hooks"))]
        Arc::new(Tpm::new("/dev/tpmrm0", tpm::Cli::Exec("tpm2".into())))
    })
}

fn code(r: Result<(), Rv>) -> u32 {
    r.map_or_else(|e| e.0, |()| OK)
}

/// # Safety
/// `p` is NULL or a NUL-terminated string that outlives the returned path.
unsafe fn path<'a>(p: *const c_char) -> Option<&'a Path> {
    // SAFETY: the caller's contract.
    (!p.is_null()).then(|| Path::new(OsStr::from_bytes(unsafe { CStr::from_ptr(p) }.to_bytes())))
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_tpm_available() -> c_int {
    the_tpm().available().into()
}

/// # Safety
/// C contract of `fhsm_tpm_seal`: `secret` is 32 bytes, `out_blob` has `out_cap` writable
/// bytes. Any pointer may be NULL (`ARGUMENTS_BAD`, after the availability check, as in C).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_tpm_seal(
    secret: *const u8,
    out_blob: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> u32 {
    let t = the_tpm();
    if !t.available() {
        return Rv::TPM_UNAVAILABLE.0;
    }
    if secret.is_null() || out_blob.is_null() || out_len.is_null() {
        return Rv::ARGUMENTS_BAD.0;
    }
    // SAFETY: non-NULL, and sized as the caller's contract says.
    let (secret, out) = unsafe {
        (
            &*secret.cast::<[u8; 32]>(),
            std::slice::from_raw_parts_mut(out_blob, out_cap),
        )
    };
    code(t.seal(secret, out).map(|n| {
        // SAFETY: non-NULL, checked above.
        unsafe { *out_len = n }
    }))
}

/// # Safety
/// C contract of `fhsm_tpm_unseal`: `blob` has `blob_len` bytes, `out_secret` 32 writable
/// bytes. Any pointer may be NULL (`ARGUMENTS_BAD`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_tpm_unseal(
    blob: *const u8,
    blob_len: usize,
    out_secret: *mut u8,
) -> u32 {
    let t = the_tpm();
    if !t.available() {
        return Rv::TPM_UNAVAILABLE.0;
    }
    if blob.is_null() || blob_len < 12 || out_secret.is_null() {
        return Rv::ARGUMENTS_BAD.0;
    }
    // SAFETY: non-NULL, and sized as the caller's contract says.
    let (blob, out) = unsafe {
        (
            std::slice::from_raw_parts(blob, blob_len),
            &mut *out_secret.cast::<[u8; 32]>(),
        )
    };
    code(t.unseal(blob, out))
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_token_tpm_required() -> c_int {
    tpm::sealing_required_value(pqhsm_core::env("FHSM_TPM_SEALING").as_deref()).into()
}

/// # Safety
/// `tok_path` is NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_tpm_blob_exists(tok_path: *const c_char) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { path(tok_path) }
        .is_some_and(tpm::companion_exists)
        .into()
}

/// # Safety
/// `tok_path` is NULL or a NUL-terminated string; `dek` points at 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_tpm_seal(tok_path: *const c_char, dek: *const u8) -> u32 {
    let t = the_tpm();
    if !t.available() {
        return Rv::TPM_UNAVAILABLE.0;
    }
    // SAFETY: the caller's contract.
    match (unsafe { path(tok_path) }, unsafe {
        dek.cast::<[u8; 32]>().as_ref()
    }) {
        (Some(p), Some(dek)) => code(t.seal_companion(p, dek)),
        _ => Rv::ARGUMENTS_BAD.0,
    }
}

/// # Safety
/// `tok_path` is NULL or a NUL-terminated string; `dek_out` points at 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_tpm_unseal(tok_path: *const c_char, dek_out: *mut u8) -> u32 {
    let t = the_tpm();
    if !t.available() {
        return Rv::TPM_UNAVAILABLE.0;
    }
    // SAFETY: the caller's contract.
    match (unsafe { path(tok_path) }, unsafe {
        dek_out.cast::<[u8; 32]>().as_mut()
    }) {
        (Some(p), Some(out)) => code(t.unseal_companion(p, out)),
        _ => Rv::ARGUMENTS_BAD.0,
    }
}

/// # Safety
/// `a` and `b` point at 32 bytes each (NULL compares unequal).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_tpm_dek_match(a: *const u8, b: *const u8) -> c_int {
    // SAFETY: the caller's contract.
    match unsafe { (a.cast::<[u8; 32]>().as_ref(), b.cast::<[u8; 32]>().as_ref()) } {
        (Some(a), Some(b)) => tpm::dek_match(a, b).into(),
        _ => 0,
    }
}

/// # Safety
/// `tok_path` is NULL or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_token_tpm_unlink(tok_path: *const c_char) {
    // SAFETY: the caller's contract.
    if let Some(p) = unsafe { path(tok_path) } {
        tpm::unlink_companion(p);
    }
}
