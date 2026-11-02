//! pqHSM token store and TPM sealing (Phase 2 of `analysis/pqHSM/MODERNIZATION_BRIEF.md`).
//!
//! Slice 1 replaces `src/fhsm_tpm.c` and `src/fhsm_token_tpm.c`: the safe API is [`tpm`], and
//! the C ABI of `include/fhsm_tpm.h` and `include/fhsm_token_tpm.h` is in `ffi` (feature
//! `ffi`). All `unsafe` is in `ffi`: the syscalls, both crypto backends and the C ABI.
//!
//! Rules: RULE-089 (companion file), RULE-093 (via the audit key's TPM path).
//! Divergences: DIV-015(d), DIV-017, DIV-018 in `analysis/pqHSM/DIVERGENCES.md`.
//!
//! Slice 3 replaces `src/fhsm_token.c`: [`header`] (the 317-byte header), [`store`] (the v4
//! object blob and the public section), [`token`] (load, init, login, counters, flock) and
//! [`crypto`] (the one seam to the PBKDF2/GCM/DRBG primitives: C over FFI with `ffi`, openssl-sys
//! without). The C ABI of `include/fhsm_token.h` is `ffi::token_abi` (feature `ffi`).

pub mod crypto;
pub mod header;
pub mod store;
pub mod token;
pub mod tpm;

mod ffi;

/// `fhsm_rv_t` (`include/fhsm_common.h`). Only the values this crate returns are named.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rv(pub u32);

impl Rv {
    pub const OK: Rv = Rv(0x0000_0000);
    pub const HOST_MEMORY: Rv = Rv(0x0000_0002);
    pub const FUNCTION_FAILED: Rv = Rv(0x0000_0006);
    pub const ARGUMENTS_BAD: Rv = Rv(0x0000_0007);
    pub const ATTRIBUTE_VALUE_INVALID: Rv = Rv(0x0000_0013);
    pub const DEVICE_ERROR: Rv = Rv(0x0000_0030);
    pub const ENCRYPTED_DATA_INVALID: Rv = Rv(0x0000_0040);
    pub const KEY_HANDLE_INVALID: Rv = Rv(0x0000_0060);
    pub const KEY_SIZE_RANGE: Rv = Rv(0x0000_0062);
    pub const MECHANISM_INVALID: Rv = Rv(0x0000_0070);
    pub const PIN_INCORRECT: Rv = Rv(0x0000_00A0);
    pub const PIN_LOCKED: Rv = Rv(0x0000_00A4);
    pub const TOKEN_NOT_PRESENT: Rv = Rv(0x0000_00E0);
    pub const USER_ALREADY_LOGGED_IN: Rv = Rv(0x0000_0100);
    pub const USER_NOT_LOGGED_IN: Rv = Rv(0x0000_0101);
    pub const USER_ANOTHER_ALREADY_LOGGED_IN: Rv = Rv(0x0000_0104);
    pub const DEVICE_MEMORY: Rv = Rv(0x0000_0131);
    pub const BUFFER_TOO_SMALL: Rv = Rv(0x0000_0150);
    pub const FIPS_NOT_APPROVED: Rv = Rv(0x8000_0003);
    pub const TPM_UNAVAILABLE: Rv = Rv(0x8000_0005);
}
