//! The safe half of the PKCS#11 layer (PHASE4_PLAN.md §3): module state, sessions and, in
//! later slices, objects, templates and operations. No `unsafe`: the C ABI is `pqhsm-p11`'s.
#![forbid(unsafe_code)]

pub mod p11;
pub mod session;
pub mod state;
