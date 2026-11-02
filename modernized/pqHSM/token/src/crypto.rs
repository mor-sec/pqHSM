//! The one seam between the token store and the cryptographic primitives (PHASE2_PLAN.md §6.1).
//!
//! - Feature `ffi` (the hybrid build): the legacy C primitives in `src/fhsm_crypto.c`
//!   (`fhsm_pbkdf2`, `fhsm_aes_gcm_*`, `fhsm_rng_bytes`), so the self-test gate, the ERROR state
//!   and the DRBG health tests stay in one place until Phase 3.
//! - Without `ffi` (`cargo test`, the offline `migrate-zero-dek`): libcrypto directly.
//!
//! Both return C's codes: a PBKDF2 count under 1000 is `FIPS_NOT_APPROVED`
//! (`src/fhsm_crypto.c:561`), a GCM tag that does not verify is `ENCRYPTED_DATA_INVALID`
//! (`:463`). `tests/crypto.rs` holds both to the same vectors, recorded from the C primitives.
//! The calls themselves are in `ffi`, like every other `unsafe`.
//!
//! Rules: RULE-001 (PBKDF2, DRBG), RULE-002 (AES-256-GCM). DIV-025: every DRBG failure is an
//! error here, where C ignored it at 12 call sites.

use crate::Rv;
use zeroize::Zeroizing;

#[cfg(feature = "ffi")]
use crate::ffi::cprim as backend;
#[cfg(not(feature = "ffi"))]
use crate::ffi::libcrypto as backend;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// `FHSM_HASH_SHA256`, the only digest the token store uses.
pub const HASH_SHA256: u32 = 1;

pub fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<(), Rv> {
    backend::pbkdf2_sha256(password, salt, iterations, out)
}

pub fn gcm_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, [u8; TAG_LEN]), Rv> {
    backend::gcm_encrypt(key, nonce, aad, plaintext)
}

pub fn gcm_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; TAG_LEN],
) -> Result<Zeroizing<Vec<u8>>, Rv> {
    backend::gcm_decrypt(key, nonce, aad, ciphertext, tag)
}

pub fn random(out: &mut [u8]) -> Result<(), Rv> {
    backend::random(out)
}
