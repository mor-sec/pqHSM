//! Every `unsafe` in the crate: libcrypto's secure heap and the libc calls the arena needs
//! (`pthread_once`, `getrlimit`), the DRBG's generator and entropy sources, and (feature `ffi`)
//! the C ABI of `include/fhsm_conf.h`, the memory section of `include/fhsm_common.h` and
//! `include/fhsm_drbg.h`.

pub(crate) mod sys;

// Used by the C ABI only, and by its own tests.
#[cfg_attr(not(feature = "ffi"), allow(dead_code))]
pub(crate) mod entropy;

#[cfg(feature = "ffi")]
mod c_abi;
