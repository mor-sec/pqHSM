//! pqHSM crypto core, Phase 3 (`analysis/pqHSM/PHASE3_PLAN.md`). Slice 1: the operator config
//! reader ([`conf`]) and the secure heap with zeroisation and constant-time comparison ([`mem`]).
//! Slice 2: the hardened DRBG ([`drbg`]).

pub mod conf;
pub mod drbg;
mod ffi;
pub mod mem;
