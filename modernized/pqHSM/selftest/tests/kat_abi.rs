//! `fhsm_kat_run_all` through its C ABI: gen_kat's null_out and null_count scenarios
//! (`tests/golden/kat.tsv`), refused before anything runs, the count untouched.

use std::ffi::{c_char, c_int};

use pqhsm_crypto::KatRecord;

extern crate pqhsm_selftest;

// src/fhsm_state.c, which the crypto core's C ABI links against; neither runs here
#[unsafe(no_mangle)]
extern "C" fn fhsm_state_get() -> c_int {
    unreachable!()
}

#[unsafe(no_mangle)]
extern "C" fn fhsm_state_latch_error(_reason: *const c_char) {
    unreachable!()
}

unsafe extern "C" {
    fn fhsm_kat_run_all(out: *mut KatRecord, cap: usize, count: *mut usize) -> u32;
}

#[test]
fn no_array_or_no_count_is_arguments_bad() {
    let golden = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/kat.tsv");
    let want: Vec<String> = std::fs::read_to_string(golden)
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("null_"))
        .map(str::to_owned)
        .collect();
    let mut out = [const {
        KatRecord {
            algorithm: std::ptr::null(),
            vector_id: std::ptr::null(),
            passed: 0,
            duration_us: 0,
        }
    }; 64];
    let mut count = 77;
    // SAFETY: a null array is refused before any write; count is a live local
    let r = unsafe { fhsm_kat_run_all(std::ptr::null_mut(), 64, &mut count) };
    assert_eq!(
        format!("null_out\tcap=64\trv=0x{r:x};count={count};written=0"),
        want[0]
    );
    // SAFETY: a null count is refused before any write
    let r = unsafe { fhsm_kat_run_all(out.as_mut_ptr(), 64, std::ptr::null_mut()) };
    assert_eq!(
        format!("null_count\tcap=64\trv=0x{r:x};count=0;written=0"),
        want[1]
    );
    assert!(out.iter().all(|r| r.algorithm.is_null()));
}
