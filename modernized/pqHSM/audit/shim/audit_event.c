/* Phase 1 hybrid build: replaces src/fhsm_audit.c together with the Rust staticlib
 * (modernized/pqHSM/audit, feature `ffi`).
 *
 * fhsm_audit_event is C-variadic, which stable Rust cannot define. This collects the
 * key/value list and hands it to pqhsm_audit_event_v. fhsm_audit_mandatory stays here because
 * it is a compile-time constant of the C build (FHSM_AUDIT_MANDATORY). */
#include <stdarg.h>
#include <stddef.h>
#include "fhsm_audit.h"

/* Every rendered pair takes at least 6 bytes of the 1024-byte params buffer, so no more than
 * 170 can fit: a longer list renders as "{}" in C (DIV-004), which is what no pairs renders. */
#define PQHSM_MAX_PAIRS 256

fhsm_rv_t pqhsm_audit_event_v(fhsm_audit_event_t ev, int slot, int session,
                              fhsm_role_t role, fhsm_rv_t rv,
                              const char *const *kv, size_t npairs);

fhsm_rv_t fhsm_audit_event(fhsm_audit_event_t ev, int slot, int session,
                            fhsm_role_t role, fhsm_rv_t rv, ...) {
    const char *kv[2 * PQHSM_MAX_PAIRS];
    size_t n = 0;
    int overflow = 0;
    va_list ap;
    va_start(ap, rv);
    for (const char *k; (k = va_arg(ap, const char *)) != NULL; ) {
        const char *v = va_arg(ap, const char *);
        if (n == PQHSM_MAX_PAIRS) { overflow = 1; continue; }
        kv[2 * n] = k;
        kv[2 * n + 1] = v;
        n++;
    }
    va_end(ap);
    return pqhsm_audit_event_v(ev, slot, session, role, rv, kv, overflow ? 0 : n);
}

int fhsm_audit_mandatory(void) { return FHSM_AUDIT_MANDATORY ? 1 : 0; }
