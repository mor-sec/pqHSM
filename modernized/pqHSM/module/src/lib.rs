//! No code of its own: it bundles the C ABI of every ported crate into one staticlib, so the
//! module carries one copy of std. Naming each crate keeps its `#[no_mangle]` symbols linked
//! (review L1).

extern crate pqhsm_audit;
extern crate pqhsm_crypto;
extern crate pqhsm_p11;
extern crate pqhsm_pki;
extern crate pqhsm_selftest;
extern crate pqhsm_token;
