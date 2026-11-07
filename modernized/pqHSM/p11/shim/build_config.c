/* Phase 4 slice 8c: the two build-time settings the Rust entry points read, now that
 * src/fhsm_pkcs11.c (the audit switch, through pkcs11_tu.c) and src/gen/fhsm_dispatch.c (the
 * profile) are unlinked.
 *
 * FHSM_AUDIT_MANDATORY: include/fhsm_common.h's default, -DFHSM_AUDIT_MANDATORY=0 for
 * `make audit-switch`. PQHSM_FIPS_STRICT: hybrid.mk's, from PROFILE_CANON by the formula the
 * Makefile's check-profile asserts the generated fhsm_build_fips_strict equals. */
#include "fhsm_common.h"

#ifndef PQHSM_FIPS_STRICT
#error "hybrid.mk passes -DPQHSM_FIPS_STRICT"
#endif

extern const int pqhsm_c_audit_mandatory;
extern const int fhsm_build_fips_strict;

const int pqhsm_c_audit_mandatory = FHSM_AUDIT_MANDATORY;
const int fhsm_build_fips_strict = PQHSM_FIPS_STRICT;
