//! The PKCS#11 API layer (PHASE4_PLAN.md). Slice 0: the function tables and the three calls
//! that hand them out (`src/fhsm_pkcs11.c:13050-13386`); every slot names its entry point by
//! symbol, Rust's or C's. Slice 1a: the session table's C ABI (`src/fhsm_session.c`)
//! over `pqhsm-core`. Slice 1b: the module state (`src/fhsm_state.c`). Slice 1c: the API lock
//! (`src/fhsm_apilock.c`), all in `ffi`: it is pthread throughout. Slice 1d: `C_Initialize` to
//! `C_SetPIN` and the slot registry (`src/fhsm_pkcs11.c:393-1789`); the operation, find and
//! OAEP tables stay C's, reached through `p11/shim/pkcs11_tu.c`.

#[cfg(feature = "ffi")]
mod ffi;
