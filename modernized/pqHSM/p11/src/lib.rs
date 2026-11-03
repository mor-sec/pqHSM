//! The PKCS#11 API layer (PHASE4_PLAN.md). Slice 0: the function tables and the three calls
//! that hand them out (`src/fhsm_pkcs11.c:13050-13386`). Every slot still names the C entry
//! point of the same name; later slices move them to Rust.

#[cfg(feature = "ffi")]
mod ffi;
