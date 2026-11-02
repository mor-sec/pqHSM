//! Every `unsafe` in the crate: the syscalls the TPM path needs, and (feature `ffi`) the C ABI
//! of `include/fhsm_tpm.h` and `include/fhsm_token_tpm.h`.

pub(crate) mod lock;
pub(crate) mod mem;
pub(crate) mod sys;

#[cfg(feature = "ffi")]
pub(crate) mod cprim;
#[cfg(not(feature = "ffi"))]
pub(crate) mod libcrypto;

#[cfg(feature = "ffi")]
mod c_abi;
#[cfg(feature = "ffi")]
mod token_abi;
