/* Phase 4 hybrid build. Slice 0: C_GetFunctionList, C_GetInterfaceList and C_GetInterface are
 * Rust's (modernized/pqHSM/p11, feature `ffi`).
 *
 * hybrid.mk links the staticlib with --exclude-libs,ALL, which hides every symbol that comes
 * from it, so the exports are defined here. hybrid.mk links this file, with build_config.c,
 * as fhsm_pkcs11.o (slice 8c: no C of src/fhsm_pkcs11.c is linked). */
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
 * lifecycle.rs, slots.rs, login.rs). (Until slice 8c hybrid.mk made C's own local.) */
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

/* Phase 4 slice 2a: find, size and destroy (p11/src/ffi/objects.rs). */
FWD(C_FindObjectsInit, (UL h, void *t, UL n), (h, t, n))
FWD(C_FindObjects, (UL h, void *o, UL m, void *n), (h, o, m, n))
FWD(C_FindObjectsFinal, (UL h), (h))
FWD(C_GetObjectSize, (UL h, UL o, void *s), (h, o, s))
FWD(C_DestroyObject, (UL h, UL o), (h, o))

/* Phase 4 slice 2b: get and set attribute (p11/src/ffi/attrs.rs). */
FWD(C_GetAttributeValue, (UL h, UL o, void *t, UL n), (h, o, t, n))
FWD(C_SetAttributeValue, (UL h, UL o, void *t, UL n), (h, o, t, n))

/* Phase 4 slice 2d: copy (p11/src/ffi/copy.rs). */
FWD(C_CopyObject, (UL h, UL o, void *t, UL n, void *no), (h, o, t, n, no))

/* Phase 4 slice 3: digest (p11/src/ffi/digest.rs). */
FWD(C_DigestInit, (UL h, void *m), (h, m))
FWD(C_Digest, (UL h, void *d, UL dn, void *o, void *on), (h, d, dn, o, on))
FWD(C_DigestUpdate, (UL h, void *d, UL dn), (h, d, dn))
FWD(C_DigestKey, (UL h, UL k), (h, k))
FWD(C_DigestFinal, (UL h, void *o, void *on), (h, o, on))
FWD(C_EncryptInit, (UL h, void *m, UL k), (h, m, k))
FWD(C_Encrypt, (UL h, void *d, UL dn, void *e, void *en), (h, d, dn, e, en))
FWD(C_EncryptUpdate, (UL h, void *d, UL dn, void *e, void *en), (h, d, dn, e, en))
FWD(C_EncryptFinal, (UL h, void *e, void *en), (h, e, en))
FWD(C_DecryptInit, (UL h, void *m, UL k), (h, m, k))
FWD(C_Decrypt, (UL h, void *e, UL en, void *d, void *dn), (h, e, en, d, dn))
FWD(C_DecryptUpdate, (UL h, void *e, UL en, void *d, void *dn), (h, e, en, d, dn))
FWD(C_DecryptFinal, (UL h, void *d, void *dn), (h, d, dn))

/* Phase 4 slice 5: sign and verify (p11/src/ffi/sign.rs). */
FWD(C_SignInit, (UL h, void *m, UL k), (h, m, k))
FWD(C_Sign, (UL h, void *d, UL dn, void *s, void *sn), (h, d, dn, s, sn))
FWD(C_SignUpdate, (UL h, void *d, UL dn), (h, d, dn))
FWD(C_SignFinal, (UL h, void *s, void *sn), (h, s, sn))
FWD(C_VerifyInit, (UL h, void *m, UL k), (h, m, k))
FWD(C_Verify, (UL h, void *d, UL dn, void *s, UL sn), (h, d, dn, s, sn))
FWD(C_VerifyUpdate, (UL h, void *d, UL dn), (h, d, dn))
FWD(C_VerifyFinal, (UL h, void *s, UL sn), (h, s, sn))

/* Phase 4 slice 8a: the mechanism, random and stub entry points (p11/src/ffi/misc.rs), which
 * apply DIV-051, DIV-053 and RULE-014 themselves; the C gate and its wrappers are gone. */
typedef void *P;
FWD(C_GetMechanismList, (UL s, P l, P n), (s, l, n))
FWD(C_GetMechanismInfo, (UL s, UL t, P i), (s, t, i))
FWD(C_WaitForSlotEvent, (UL f, P s, P r), (f, s, r))
FWD(C_GetFunctionStatus, (UL h), (h))
FWD(C_CancelFunction, (UL h), (h))
FWD(C_SeedRandom, (UL h, P p, UL n), (h, p, n))
FWD(C_GenerateRandom, (UL h, P p, UL n), (h, p, n))
FWD(C_CreateObject, (UL h, P t, UL n, P o), (h, t, n, o))
FWD(C_GenerateKey, (UL h, P m, P t, UL n, P k), (h, m, t, n, k))
FWD(C_GenerateKeyPair, (UL h, P m, P pu, UL npu, P pr, UL npr, P hpu, P hpr), (h, m, pu, npu, pr, npr, hpu, hpr))
FWD(C_WrapKey, (UL h, P m, UL wk, UL k, P o, P on), (h, m, wk, k, o, on))
FWD(C_UnwrapKey, (UL h, P m, UL uk, P w, UL wn, P t, UL n, P k), (h, m, uk, w, wn, t, n, k))
FWD(C_DeriveKey, (UL h, P m, UL b, P t, UL n, P k), (h, m, b, t, n, k))
FWD(C_EncapsulateKey, (UL h, P m, UL k, P t, UL n, P c, P cn, P nk), (h, m, k, t, n, c, cn, nk))
FWD(C_DecapsulateKey, (UL h, P m, UL k, P t, UL n, P c, UL cn, P nk), (h, m, k, t, n, c, cn, nk))
