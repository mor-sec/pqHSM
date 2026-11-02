//! Every `unsafe` in the crate: the libcrypto bindings the chain uses, and (feature `ffi`) the
//! C ABI of `include/fhsm_audit.h` with its calls back into legacy C.

pub(crate) mod libcrypto;

#[cfg(feature = "ffi")]
mod c_abi;
