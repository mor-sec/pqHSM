//! pqHSM crypto core, Phase 3 (`analysis/pqHSM/PHASE3_PLAN.md`). Slice 1: the operator config
//! reader ([`conf`]) and the secure heap with zeroisation and constant-time comparison ([`mem`]).
//! Slice 2: the hardened DRBG ([`drbg`]). Slice 3: the primitives ([`prim`]) and the self-test
//! lifecycle ([`lifecycle`]).

pub mod conf;
pub mod drbg;
mod ffi;
pub mod lifecycle;
pub mod mem;
#[cfg(feature = "ffi")]
pub use ffi::KatRecord;
pub use ffi::cipher;
pub use ffi::prim;
/// The module locks that a fork child takes afresh; the self-test crate uses it too.
#[cfg(feature = "ffi")]
pub use ffi::sys::ForkMutex;

/// `fhsm_rv_t` codes (`include/fhsm_common.h:150-214`).
pub mod rv {
    pub const OK: u32 = 0;
    pub const HOST_MEMORY: u32 = 0x02;
    pub const FUNCTION_FAILED: u32 = 0x06;
    pub const ARGUMENTS_BAD: u32 = 0x07;
    pub const ENCRYPTED_DATA_INVALID: u32 = 0x40;
    pub const KEY_SIZE_RANGE: u32 = 0x62;
    pub const MECHANISM_INVALID: u32 = 0x70;
    pub const MECHANISM_PARAM_INVALID: u32 = 0x71;
    pub const KAT_FAILED: u32 = 0x8000_0001;
    pub const INTEGRITY_FAILED: u32 = 0x8000_0002;
    pub const FIPS_NOT_APPROVED: u32 = 0x8000_0003;
    pub const RNG_FAILURE: u32 = 0x8000_0008;
    pub const PROVIDER_UNAVAILABLE: u32 = 0x8000_0009;
}
