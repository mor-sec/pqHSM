/* Phase 4 hybrid build. Slice 0: C_GetFunctionList, C_GetInterfaceList and C_GetInterface are
 * Rust's (modernized/pqHSM/p11, feature `ffi`).
 *
 * hybrid.mk links the staticlib with --exclude-libs,ALL, which hides every symbol that comes
 * from it, so the three exports are defined here. hybrid.mk makes C's own three local in
 * fhsm_pkcs11.o and links this file into that object. */
typedef unsigned long CK_RV;

CK_RV pqhsm_p11_get_function_list(void *out);
CK_RV pqhsm_p11_get_interface_list(void *list, unsigned long *count);
CK_RV pqhsm_p11_get_interface(const char *name, const void *version, void *out, unsigned long flags);

/* The legacy CFLAGS make -Wmissing-prototypes an error. */
CK_RV C_GetFunctionList(void *out);
CK_RV C_GetInterfaceList(void *list, unsigned long *count);
CK_RV C_GetInterface(const char *name, const void *version, void *out, unsigned long flags);

__attribute__((visibility("default")))
CK_RV C_GetFunctionList(void *out) {
    return pqhsm_p11_get_function_list(out);
}

__attribute__((visibility("default")))
CK_RV C_GetInterfaceList(void *list, unsigned long *count) {
    return pqhsm_p11_get_interface_list(list, count);
}

__attribute__((visibility("default")))
CK_RV C_GetInterface(const char *name, const void *version, void *out, unsigned long flags) {
    return pqhsm_p11_get_interface(name, version, out, flags);
}

/* Phase 4 slice 1d: the lifecycle, slot, session and login entry points (p11/src/ffi/
 * lifecycle.rs, slots.rs, login.rs). hybrid.mk makes C's own fifteen local. */
typedef unsigned long UL;
#define FWD(name, params, args) \
    CK_RV pqhsm_##name params; CK_RV name params; \
    __attribute__((visibility("default"))) CK_RV name params { return pqhsm_##name args; }

FWD(C_Initialize, (void *a), (a))
FWD(C_Finalize, (void *a), (a))
FWD(C_GetInfo, (void *a), (a))
FWD(C_GetSlotList, (unsigned char p, UL *l, UL *n), (p, l, n))
FWD(C_GetSlotInfo, (UL s, void *i), (s, i))
FWD(C_GetTokenInfo, (UL s, void *i), (s, i))
FWD(C_InitToken, (UL s, const char *p, UL n, const char *l), (s, p, n, l))
FWD(C_OpenSession, (UL s, UL f, void *a, void *c, UL *h), (s, f, a, c, h))
FWD(C_CloseSession, (UL h), (h))
FWD(C_CloseAllSessions, (UL s), (s))
FWD(C_GetSessionInfo, (UL h, void *i), (h, i))
FWD(C_Login, (UL h, UL u, const char *p, UL n), (h, u, p, n))
FWD(C_Logout, (UL h), (h))
FWD(C_InitPIN, (UL h, const char *p, UL n), (h, p, n))
FWD(C_SetPIN, (UL h, const char *o, UL on, const char *p, UL pn), (h, o, on, p, pn))
