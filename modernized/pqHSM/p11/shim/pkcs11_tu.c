/* Phase 4 slice 1d hybrid build: src/fhsm_pkcs11.c, unchanged, as one translation unit with
 * the one accessor the Rust entry points still read: the audit switch (slice 8b-i removed the
 * operation-table hooks, 8b-ii the OpenSSL attribute readbacks).
 *
 * hybrid.mk compiles this file in place of src/fhsm_pkcs11.c and makes C's own C_Initialize ...
 * C_SetPIN local (p11/shim/interface.c exports Rust's). Including the .c keeps the legacy file
 * as it is and its statics static; -fvisibility=hidden keeps these out of the module's dynamic
 * table. */
#include "../../../../src/fhsm_pkcs11.c"

extern const int pqhsm_c_audit_mandatory;

/* -DFHSM_AUDIT_MANDATORY=0 (make audit-switch) reaches the Rust C_Initialize through this. */
const int pqhsm_c_audit_mandatory = FHSM_AUDIT_MANDATORY;
