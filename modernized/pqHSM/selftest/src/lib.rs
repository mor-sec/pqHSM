//! pqHSM power-on self-tests, Phase 3 slice 4 (`analysis/pqHSM/PHASE3_PLAN.md`): the module
//! integrity check ([`integrity`]), the known-answer tests ([`kat`]) and the pair-wise check
//! after key generation ([`pairwise`]).

mod ffi;
pub use ffi::pairwise;
pub mod integrity;
pub mod kat;
