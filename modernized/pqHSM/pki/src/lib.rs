//! pqHSM PKI (Phase 2 of `analysis/pqHSM/MODERNIZATION_BRIEF.md`, slice 2).
//!
//! Replaces `src/fhsm_revocation.c`: the safe API is [`revocation`], and the C ABI of
//! `include/fhsm_revocation.h` is in [`ffi`] (feature `ffi`). All `unsafe` is in `ffi`.
//! libcrypto is called through `openssl-sys` directly, never the `openssl` crate.
//!
//! Rules: RULE-023 (OCSP status, preserved incl. "good" for unknown serials), RULE-024
//! (parsing), RULE-099/RULE-100 (no locking, preserved). Divergences: DIV-016, DIV-019 to
//! DIV-022.

pub mod revocation;

pub mod ffi;
