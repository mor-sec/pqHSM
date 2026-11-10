//! Every `unsafe` in the crate: the libcrypto calls (always compiled) and, with feature `ffi`,
//! the C ABI of `include/fhsm_revocation.h` and `include/fhsm_composite.h` with the OpenSSL
//! calls behind the latter.

pub(crate) mod libcrypto;

#[cfg(feature = "ffi")]
pub(crate) mod composite;
#[cfg(feature = "ffi")]
pub mod x509;

#[cfg(feature = "ffi")]
mod c_abi;
#[cfg(feature = "ffi")]
pub use c_abi::*;
