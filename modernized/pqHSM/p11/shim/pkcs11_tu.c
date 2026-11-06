/* Phase 4 slice 1d hybrid build: src/fhsm_pkcs11.c, unchanged, as one translation unit with
 * the accessors the Rust entry points still call: the audit switch and the OpenSSL attribute
 * readbacks (slice 8b-i removed the operation-table hooks: no C entry point fills them).
 *
 * hybrid.mk compiles this file in place of src/fhsm_pkcs11.c and makes C's own C_Initialize ...
 * C_SetPIN local (p11/shim/interface.c exports Rust's). Including the .c keeps the legacy file
 * as it is and its statics static; -fvisibility=hidden keeps these out of the module's dynamic
 * table. */
#include "../../../../src/fhsm_pkcs11.c"

extern const int pqhsm_c_audit_mandatory;

/* -DFHSM_AUDIT_MANDATORY=0 (make audit-switch) reaches the Rust C_Initialize through this. */
const int pqhsm_c_audit_mandatory = FHSM_AUDIT_MANDATORY;


/* Phase 4 slice 2b: C_GetAttributeValue is Rust's; its OpenSSL readbacks are still these.
 * pqhsm_c_pqc_raw_pub is the block C_GetAttributeValue's CKA_VALUE arm ran inline: an ML-KEM
 * or ML-DSA public key's raw form from its stored SPKI; 1 on success. */
int pqhsm_c_extract_pubkey_attr(fhsm_token_t *t, uint32_t h, CK_ATTRIBUTE_TYPE type,
                                uint8_t *out, size_t *out_len);
int pqhsm_c_extract_cert_attr(fhsm_token_t *t, uint32_t h, CK_ATTRIBUTE_TYPE type,
                              uint8_t *out, size_t *out_len);
int pqhsm_c_pset_selector_of(uint32_t cls, uint32_t kt, const uint8_t *v, size_t n,
                             CK_ULONG *sel);
int pqhsm_c_pqc_raw_pub(const uint8_t *v, size_t n, uint8_t *out, size_t *out_len);
int pqhsm_c_extract_pubkey_attr(fhsm_token_t *t, uint32_t h, CK_ATTRIBUTE_TYPE type,
                                uint8_t *out, size_t *out_len) {
    return extract_pubkey_attr(t, h, type, out, out_len);
}
int pqhsm_c_extract_cert_attr(fhsm_token_t *t, uint32_t h, CK_ATTRIBUTE_TYPE type,
                              uint8_t *out, size_t *out_len) {
    return extract_cert_attr(t, h, type, out, out_len);
}
int pqhsm_c_pset_selector_of(uint32_t cls, uint32_t kt, const uint8_t *v, size_t n,
                             CK_ULONG *sel) {
    return fhsm_pset_selector_of(cls, kt, v, n, sel);
}
int pqhsm_c_pqc_raw_pub(const uint8_t *v, size_t n, uint8_t *out, size_t *out_len) {
    const unsigned char *pp = v;
    EVP_PKEY *pk = d2i_PUBKEY(NULL, &pp, (long)n);
    int ok = pk != NULL && EVP_PKEY_get_raw_public_key(pk, out, out_len) == 1;
    if (pk) EVP_PKEY_free(pk);
    return ok;
}
