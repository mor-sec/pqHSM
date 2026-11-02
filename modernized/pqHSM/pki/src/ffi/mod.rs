//! Every `unsafe` in the crate: the libcrypto calls (always compiled) and, with feature `ffi`,
//! the C ABI of `include/fhsm_revocation.h`.

pub(crate) mod libcrypto;

#[cfg(feature = "ffi")]
mod c_abi;
#[cfg(feature = "ffi")]
pub use c_abi::*;
