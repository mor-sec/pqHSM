//! pqHSM audit trail: an append-only, HMAC-SHA-256-chained JSON-lines log.
//!
//! Rust replacement for `src/fhsm_audit.c` (Phase 1 of `analysis/pqHSM/MODERNIZATION_BRIEF.md`).
//! The safe API lives in these modules; the C ABI of `include/fhsm_audit.h` is in `ffi`
//! (feature `ffi`). All `unsafe` is in `ffi`, which also holds the two libcrypto calls.
//!
//! Rules implemented: RULE-007, RULE-008 (in-module verifier), RULE-027, RULE-093,
//! RULE-094, RULE-096 (library side). Divergences: DIV-002, DIV-003, DIV-006, DIV-007 in
//! `analysis/pqHSM/DIVERGENCES.md`.

pub mod chain;
pub mod key;
pub mod log;
pub mod record;
pub mod verify;

mod ffi;

/// Length of the chaining key. The only accepted length (DIV-003).
pub const KEY_LEN: usize = 32;
