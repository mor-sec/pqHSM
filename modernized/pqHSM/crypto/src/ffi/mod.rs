//! Every `unsafe` in the crate: libcrypto's secure heap and the libc calls the arena needs
//! (`pthread_once`, `getrlimit`), the DRBG's generator and entropy sources, and (feature `ffi`)
//! the C ABI of `include/fhsm_conf.h`, the memory section of `include/fhsm_common.h` and
//! `include/fhsm_drbg.h`, and the primitives over libcrypto with (feature `ffi`) the C ABI of
//! `include/fhsm_crypto.h`.

pub mod cipher;
pub mod import;
pub mod keygen;
pub mod prim;
pub mod readback;
pub mod sig;
pub(crate) mod sys;

// Used by the C ABI only, and by its own tests.
#[cfg_attr(not(feature = "ffi"), allow(dead_code))]
pub(crate) mod entropy;

#[cfg(feature = "ffi")]
mod c_abi;
/// The KAT report entry the self-test crate writes.
#[cfg(feature = "ffi")]
pub use c_abi::KatRecord;
