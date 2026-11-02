//! The C ABI with no TPM device (feature `ffi`): availability is checked before the
//! arguments, so a NULL is reported as TPM_UNAVAILABLE here. Separate binary, because the
//! C ABI caches availability for the whole process.
//!
//!   cargo test -p pqhsm-token --features ffi --test tpm_ffi_no_tpm
#![cfg(feature = "ffi")]

mod common;

use std::ffi::c_int;
use std::ptr::{null, null_mut};
use std::sync::Once;

use common::*;
use pqhsm_token as _;

unsafe extern "C" {
    fn fhsm_tpm_available() -> c_int;
    fn fhsm_tpm_seal(secret: *const u8, out: *mut u8, cap: usize, out_len: *mut usize) -> u32;
    fn fhsm_tpm_unseal(blob: *const u8, len: usize, out: *mut u8) -> u32;
}

static SETUP: Once = Once::new();

fn setup() {
    SETUP.call_once(|| {
        let cmd = format!("sh '{}'", golden("tpm2-stub.sh").display());
        // SAFETY: runs once, before any test in this binary reads the environment.
        unsafe {
            std::env::set_var("FHSM_TPM_DEVICE", "/nonexistent/fhsm-tpmrm0");
            std::env::set_var("FHSM_TPM_CMD", cmd);
        }
    });
}

#[test]
fn no_device_means_unavailable() {
    setup();
    assert_eq!(
        unsafe { fhsm_tpm_available() }.to_string(),
        case("avail_no_device").rv
    );
}

#[test]
fn null_secret_without_a_tpm_is_tpm_unavailable() {
    setup();
    let (mut b, mut n) = ([0u8; 2048], 0usize);
    let r = unsafe { fhsm_tpm_seal(null(), b.as_mut_ptr(), b.len(), &mut n) };
    assert_eq!(format!("{r:#x}"), case("ffi_seal_null_secret_no_tpm").rv);
}

#[test]
fn null_out_secret_without_a_tpm_is_tpm_unavailable() {
    setup();
    let b = unhex(case("seal_ok").get("blob"));
    let r = unsafe { fhsm_tpm_unseal(b.as_ptr(), b.len(), null_mut()) };
    assert_eq!(format!("{r:#x}"), case("ffi_unseal_null_out_no_tpm").rv);
}
