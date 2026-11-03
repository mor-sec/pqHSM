/* Phase 4 slice 0 hybrid build: C_GetFunctionList, C_GetInterfaceList and C_GetInterface are
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
