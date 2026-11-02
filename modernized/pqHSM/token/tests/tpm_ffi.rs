//! The C ABI of `include/fhsm_tpm.h` and `include/fhsm_token_tpm.h` (feature `ffi`), with a
//! stub TPM present. NULL arguments cannot be written in the safe API, so their goldens
//! (`ffi_*` rows) are checked here. The other tests are marshalling checks against rows that
//! `tpm.rs` also covers.
//!
//! One process, one cache: the C ABI keeps a single process-wide `Tpm` built from
//! FHSM_TPM_DEVICE / FHSM_TPM_CMD on first use, so every test calls `setup()` first.
//! `tpm_ffi_no_tpm.rs` is the same in a process with no device.
//!
//!   cargo test -p pqhsm-token --features ffi --test tpm_ffi
#![cfg(feature = "ffi")]

mod common;

use std::ffi::{CString, c_char, c_int};
use std::ptr::{null, null_mut};
use std::sync::OnceLock;

use common::*;
use pqhsm_token as _;

unsafe extern "C" {
    fn fhsm_tpm_available() -> c_int;
    fn fhsm_tpm_seal(secret: *const u8, out: *mut u8, cap: usize, out_len: *mut usize) -> u32;
    fn fhsm_tpm_unseal(blob: *const u8, len: usize, out: *mut u8) -> u32;
    fn fhsm_token_tpm_required() -> c_int;
    fn fhsm_token_tpm_blob_exists(tok: *const c_char) -> c_int;
    fn fhsm_token_tpm_seal(tok: *const c_char, dek: *const u8) -> u32;
    fn fhsm_token_tpm_unseal(tok: *const c_char, dek_out: *mut u8) -> u32;
    fn fhsm_token_tpm_dek_match(a: *const u8, b: *const u8) -> c_int;
    fn fhsm_token_tpm_unlink(tok: *const c_char);
}

static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();

/// Point the process-wide TPM at the stub, as tests/test_tpm.c's main() does.
fn setup() -> std::path::PathBuf {
    DIR.get_or_init(|| {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("tpmrm0"), b"").unwrap();
        let cmd = format!(
            "FHSM_TPM_FAKE_PCR={PCR} sh '{}'",
            golden("tpm2-stub.sh").display()
        );
        // SAFETY: runs once, inside get_or_init, before any test in this binary reads the
        // environment (every test calls setup() first).
        unsafe {
            std::env::set_var("FHSM_TPM_DEVICE", d.path().join("tpmrm0"));
            std::env::set_var("FHSM_TPM_CMD", cmd);
            std::env::set_var("FHSM_TPM_SEALING", "Y");
        }
        d
    })
    .path()
    .to_owned()
}

fn rv(v: u32) -> String {
    format!("{v:#x}")
}

fn blob() -> Vec<u8> {
    unhex(case("seal_ok").get("blob"))
}

#[test]
fn null_secret_is_arguments_bad() {
    setup();
    let (mut b, mut n) = ([0u8; 2048], 0usize);
    let r = unsafe { fhsm_tpm_seal(null(), b.as_mut_ptr(), b.len(), &mut n) };
    assert_eq!(rv(r), case("ffi_seal_null_secret").rv);
}

#[test]
fn null_out_blob_is_arguments_bad() {
    setup();
    let mut n = 0usize;
    let r = unsafe { fhsm_tpm_seal(S.as_ptr(), null_mut(), 2048, &mut n) };
    assert_eq!(rv(r), case("ffi_seal_null_out").rv);
}

#[test]
fn null_out_len_is_arguments_bad() {
    setup();
    let mut b = [0u8; 2048];
    let r = unsafe { fhsm_tpm_seal(S.as_ptr(), b.as_mut_ptr(), b.len(), null_mut()) };
    assert_eq!(rv(r), case("ffi_seal_null_out_len").rv);
}

#[test]
fn null_blob_is_arguments_bad() {
    setup();
    let mut out = [0u8; 32];
    let r = unsafe { fhsm_tpm_unseal(null(), blob().len(), out.as_mut_ptr()) };
    assert_eq!(rv(r), case("ffi_unseal_null_blob").rv);
}

#[test]
fn null_out_secret_is_arguments_bad() {
    setup();
    let b = blob();
    let r = unsafe { fhsm_tpm_unseal(b.as_ptr(), b.len(), null_mut()) };
    assert_eq!(rv(r), case("ffi_unseal_null_out").rv);
}

#[test]
fn c_abi_seal_and_unseal_match_c() {
    setup();
    assert_eq!(
        unsafe { fhsm_tpm_available() }.to_string(),
        case("avail_ok").rv
    );
    let (mut b, mut n) = ([0xEEu8; 2048], 0usize);
    let r = unsafe { fhsm_tpm_seal(S.as_ptr(), b.as_mut_ptr(), b.len(), &mut n) };
    assert_eq!(rv(r), case("seal_ok").rv);
    assert_eq!(hex(&b[..n]), case("seal_ok").get("blob"));
    let mut out = [0xCCu8; 32];
    let r = unsafe { fhsm_tpm_unseal(b.as_ptr(), n, out.as_mut_ptr()) };
    assert_eq!(rv(r), case("unseal_ok").rv);
    assert_eq!(hex(&out), case("unseal_ok").get("out"));
}

#[test]
fn c_abi_companion_round_trip_matches_c() {
    let dir = setup();
    let tok = dir.join("ffi.tok");
    let ctok = CString::new(tok.to_str().unwrap()).unwrap();
    let r = unsafe { fhsm_token_tpm_seal(ctok.as_ptr(), S.as_ptr()) };
    assert_eq!(rv(r), case("tok_seal_ok").rv);
    assert_eq!(
        state(&with(&tok, ".tpm")),
        case("tok_seal_ok").get("after_tpm")
    );
    assert_eq!(
        unsafe { fhsm_token_tpm_blob_exists(ctok.as_ptr()) }.to_string(),
        case("exists_file").rv
    );
    let mut out = [0xCCu8; 32];
    let r = unsafe { fhsm_token_tpm_unseal(ctok.as_ptr(), out.as_mut_ptr()) };
    assert_eq!(rv(r), case("tok_unseal_ok").rv);
    assert_eq!(hex(&out), case("tok_unseal_ok").get("out"));
    unsafe { fhsm_token_tpm_unlink(ctok.as_ptr()) };
    assert_eq!(
        state(&with(&tok, ".tpm")),
        case("unlink_present").get("after_tpm")
    );
}

#[test]
fn c_abi_dek_match_and_required_match_c() {
    setup();
    let c = case("dek_differ_last");
    let (a, b) = (unhex(c.get("a")), unhex(c.get("b")));
    assert_eq!(
        unsafe { fhsm_token_tpm_dek_match(a.as_ptr(), b.as_ptr()) }.to_string(),
        c.rv
    );
    let c = case("dek_equal");
    assert_eq!(
        unsafe { fhsm_token_tpm_dek_match(S.as_ptr(), S.as_ptr()) }.to_string(),
        c.rv
    );
    // setup() exported FHSM_TPM_SEALING=Y; C reads it on every call
    assert_eq!(
        unsafe { fhsm_token_tpm_required() }.to_string(),
        case("required_upper_Y").rv
    );
}
