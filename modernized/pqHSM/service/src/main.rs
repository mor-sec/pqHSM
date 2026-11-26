//! pqhsm-service (Phase 6 slice 5b; was service/shim/main.c, linked by hybrid.mk). The C `main`
//! itself, so the process starts exactly as it did: no Rust runtime set-up before
//! `pqhsm_service_main`, which installs its own signal dispositions (SIGPIPE ignored, lib.rs).
#![no_main]

use std::ffi::{c_char, c_int};

#[unsafe(no_mangle)]
extern "C" fn main(argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: the C runtime's argc and argv
    unsafe { pqhsm_service::pqhsm_service_main(argc, argv) }
}
