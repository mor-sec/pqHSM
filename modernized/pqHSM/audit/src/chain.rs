//! HMAC chain (RULE-007).
//!
//! HMAC goes through `EVP_Q_mac` with the default library context and no property query,
//! the same `EVP_MAC_fetch(NULL, "HMAC", NULL)` path `fhsm_hmac` takes, so the provider that
//! answers (default or FIPS) is the one the C module would use. Not the `openssl` crate: its
//! HMAC is the legacy `EVP_PKEY` route, and its initialisation would link `libssl` into the
//! module.

use crate::ffi::libcrypto;

/// Input to the chain head: the first line's `prev_hmac` is `HMAC(key, INIT_LABEL)`.
pub const INIT_LABEL: &[u8] = b"FHSM-AUDIT-INIT|seq=0";

/// libcrypto refused to compute the MAC.
#[derive(Debug, PartialEq, Eq)]
pub struct MacError;

/// HMAC-SHA-256 of `data` under `key`.
pub fn mac(key: &[u8], data: &[u8]) -> Result<[u8; 32], MacError> {
    libcrypto::hmac_sha256(key, data).ok_or(MacError)
}

/// `HMAC-SHA-256(key, "FHSM-AUDIT-INIT|seq=0")`.
pub fn chain_head(key: &[u8]) -> Result<[u8; 32], MacError> {
    mac(key, INIT_LABEL)
}

/// Constant-time equality of two MACs (`CRYPTO_memcmp`).
pub fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    libcrypto::memcmp_eq(a, b)
}
