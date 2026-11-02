/* Phase 3 slice 3 hybrid build: replaces src/fhsm_crypto.c together with the Rust staticlib
 * (modernized/pqHSM/crypto, feature `ffi`).
 *
 * fhsm_kat_results is the module's one export besides the PKCS#11 functions
 * (src/fhsm_crypto.c:302). hybrid.mk links the staticlib with --exclude-libs,ALL, which hides
 * every symbol that comes from it, so the export is defined here and the code stays Rust's. */
#include "fhsm_crypto.h"

const fhsm_kat_result_t *pqhsm_kat_results(size_t *count);

__attribute__((visibility("default")))
const fhsm_kat_result_t *fhsm_kat_results(size_t *count) {
    return pqhsm_kat_results(count);
}
