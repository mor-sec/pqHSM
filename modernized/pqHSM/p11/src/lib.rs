//! The PKCS#11 API layer (PHASE4_PLAN.md). Slice 0: the function tables and the three calls
//! that hand them out (`src/fhsm_pkcs11.c:13050-13386`); every other slot still names the C
//! entry point of the same name. Slice 1a: the session table's C ABI (`src/fhsm_session.c`)
//! over `pqhsm-core`. Slice 1b: the module state (`src/fhsm_state.c`). Slice 1c: the API lock
//! (`src/fhsm_apilock.c`), all in `ffi`: it is pthread throughout.

#[cfg(feature = "ffi")]
mod ffi;
