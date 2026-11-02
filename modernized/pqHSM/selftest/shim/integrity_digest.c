/* Phase 3 slice 4 hybrid build: replaces src/fhsm_integrity.c together with the Rust staticlib
 * (modernized/pqHSM/selftest, feature `ffi`).
 *
 * The expected digest stays C: scripts/sign_module.sh finds it in its own ELF section and
 * patches it after the link, and the Rust check reads it as an extern. Definition as at
 * src/fhsm_integrity.c:50-51. */
#include "fhsm_integrity.h"

__attribute__((used, section(FHSM_INTEGRITY_SECTION), aligned(16)))
const volatile uint8_t fhsm_module_integrity_digest[FHSM_INTEGRITY_DIGEST_LEN] = { 0 };
