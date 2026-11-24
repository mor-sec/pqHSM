//! The C ABI run on this test binary, which carries the crate's all-zero `.fhsm_digest`: the
//! self-locate falls back to `/proc/self/exe`, as for C's statically linked test harnesses.

use std::ffi::{CStr, c_char, c_int};
use std::sync::atomic::{AtomicU32, Ordering};

use pqhsm_crypto::rv;
// links the crate whose C ABI is called below
extern crate pqhsm_selftest;

static LATCHES: AtomicU32 = AtomicU32::new(0);

#[unsafe(no_mangle)]
extern "C" fn fhsm_state_latch_error(reason: *const c_char) {
    // SAFETY: the check passes a C string literal
    assert_eq!(unsafe { CStr::from_ptr(reason) }, c"integrity check failed");
    LATCHES.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" {
    fn fhsm_integrity_verify() -> u32;
    fn pqhsm_integrity_run() -> u32;
    fn fhsm_integrity_is_signed() -> c_int;
    fn fhsm_integrity_last_computed() -> *const u8;
    fn fhsm_integrity_so_path() -> *const c_char;
}

/// DIV-034: without `dev-bypass` the variable is ignored, so the unsigned binary latches ERROR.
/// The check runs once (C's pthread_once); the crypto core's re-run runs it again (DIV-035).
#[test]
fn an_unsigned_module_latches_unless_the_bypass_is_built_in_div034() {
    // SAFETY: the only test in this binary
    unsafe { std::env::set_var("FHSM_INTEGRITY_ALLOW_UNSIGNED", "1") };
    let (want, latches) = if cfg!(feature = "dev-bypass") {
        (rv::OK, 0)
    } else {
        (rv::INTEGRITY_FAILED, 1)
    };
    // SAFETY: no arguments; the pointers returned are static storage
    unsafe {
        assert_eq!(fhsm_integrity_verify(), want);
        assert_eq!(fhsm_integrity_verify(), want);
        assert_eq!(LATCHES.load(Ordering::SeqCst), latches);
        assert_eq!(fhsm_integrity_is_signed(), 0);
        let path = CStr::from_ptr(fhsm_integrity_so_path()).to_str().unwrap();
        assert_eq!(std::path::Path::new(path), std::env::current_exe().unwrap());
        let last = std::slice::from_raw_parts(fhsm_integrity_last_computed(), 48);
        assert!(last.iter().any(|&b| b != 0), "the digest was computed");
        assert_eq!(pqhsm_integrity_run(), want);
        assert_eq!(LATCHES.load(Ordering::SeqCst), 2 * latches);
    }
}
