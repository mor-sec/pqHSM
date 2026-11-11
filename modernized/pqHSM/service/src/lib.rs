//! pqHSM's HTTP service (Phase 6 of `analysis/pqHSM/MODERNIZATION_BRIEF.md`,
//! `analysis/pqHSM/PHASE6_PLAN.md`), replacing `service/fhsm_service.c`.
//!
//! Slice 0, the scaffold: the module linked in, reached through `pqhsm-pkiops` loaded from
//! the program itself (`dlopen(NULL)`), which needs the binary to export `C_GetFunctionList`
//! (hybrid.mk). `--profile` answers as C's; anything else proves the load and serves nothing.

use std::ffi::{CStr, c_char, c_int};
use std::io::Write;

// The module's C ABI: named so its #[no_mangle] symbols are linked (one copy of std).
extern crate pqhsm_module;

unsafe extern "C" {
    /// `p11/shim/build_config.c`: the profile this binary was linked with.
    static fhsm_build_fips_strict: c_int;
}

/// The binary's `main` (`service/shim/main.c`).
///
/// # Safety
/// `argv` holds `argc` C strings, as `main` receives them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_service_main(argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: main's argv, argc entries.
    let args: Vec<&CStr> = (1..argc.max(1) as usize)
        .map(|i| unsafe { CStr::from_ptr(*argv.add(i)) })
        .collect();
    if args.first().is_some_and(|a| a.to_bytes() == b"--profile") {
        // SAFETY: a constant the link provides.
        let strict = unsafe { fhsm_build_fips_strict } != 0;
        println!(
            "{}",
            if strict {
                "nist-approved-only"
            } else {
                "all-mechanisms"
            }
        );
        return 0;
    }
    match pqhsm_pkiops::load(None) {
        Ok(()) => {
            pqhsm_pkiops::close();
            eprintln!(
                "pqhsm-service: the module answered through the program's C_GetFunctionList; slice 0 serves nothing"
            );
            2
        }
        Err(e) => {
            let mut w = std::io::stderr().lock();
            let _ = w.write_all(b"pqhsm-service: ");
            let _ = w.write_all(e.c_msg());
            1
        }
    }
}
