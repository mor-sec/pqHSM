//! DIV-029: `FHSM_TPM_SEALING` is read when a token is created or loaded, not at every login
//! (feature `ffi`). Separate binary, because the test changes the process environment.
//!
//!   cargo test -p pqhsm-token --features ffi --test sealing_env_ffi
#![cfg(feature = "ffi")]

mod store_common;

use std::ffi::{CString, c_char, c_int};
use std::ptr::null_mut;

use store_common::*;

#[repr(C)]
struct Tok {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    fn fhsm_token_load(path: *const c_char, out: *mut *mut Tok) -> u32;
    fn fhsm_token_init(
        path: *const c_char,
        so_pin: *const c_char,
        label: *const c_char,
        out: *mut *mut Tok,
    ) -> u32;
    fn fhsm_token_close(t: *mut Tok);
    fn fhsm_token_login(t: *mut Tok, role: c_int, pin: *const c_char, len: usize) -> u32;
    fn fhsm_token_logout(t: *mut Tok);
}

/// C re-reads the variable at every login (`src/fhsm_token.c:1510`), so turning it on under an
/// open, unsealed token fails that token's next login with DEVICE_ERROR. Rust keeps the value
/// the token was opened with; a token loaded after the change requires the seal.
#[test]
fn sealing_is_read_at_load_not_at_login_div029() {
    let dir = tempfile::tempdir().unwrap();
    let path = CString::new(dir.path().join("slot0.tok").to_str().unwrap()).unwrap();
    let so = CString::new(SO_PIN).unwrap();
    let mut t: *mut Tok = null_mut();
    let mut u: *mut Tok = null_mut();
    // SAFETY: the only test in this binary, so nothing else reads the environment meanwhile;
    // both tokens stay live until closed.
    unsafe {
        std::env::remove_var("FHSM_TPM_SEALING");
        let label = CString::new("d29").unwrap();
        assert_eq!(
            fhsm_token_init(path.as_ptr(), so.as_ptr(), label.as_ptr(), &mut t),
            0
        );
        std::env::set_var("FHSM_TPM_SEALING", "Y");
        assert_eq!(fhsm_token_login(t, 1, so.as_ptr(), SO_PIN.len()), 0);
        fhsm_token_logout(t);
        assert_eq!(fhsm_token_load(path.as_ptr(), &mut u), 0);
        assert_eq!(fhsm_token_login(u, 1, so.as_ptr(), SO_PIN.len()), 0x30);
        fhsm_token_close(u);
        fhsm_token_close(t);
    }
}
