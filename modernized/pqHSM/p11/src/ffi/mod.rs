//! The C ABI: every `unsafe` and `extern "C"` of the PKCS#11 layer (PHASE4_PLAN.md §3).

mod apilock;
mod session;
mod state;
mod tables;
