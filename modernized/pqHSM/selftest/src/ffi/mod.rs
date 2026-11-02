//! Every `unsafe` in the crate: the extended KATs and the pair-wise check over OpenSSL, and
//! (feature `ffi`) the C ABI of `include/fhsm_integrity.h`, `include/fhsm_pairwise.h` and of the
//! KATs in `include/fhsm_crypto.h`, the module's own file
//! found through `dl_iterate_phdr`, and the digest section the C shim defines.

pub(crate) mod evp;
pub mod pairwise;

#[cfg(feature = "ffi")]
mod c_abi;
