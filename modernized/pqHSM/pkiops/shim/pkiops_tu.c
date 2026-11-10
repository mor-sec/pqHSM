/* The C of tools/pkiops.c not ported yet, compiled by hybrid.mk in its place (PHASE5_PLAN.md
 * slice 0). The file is included unchanged. The functions pqhsm-pkiops now exports are
 * renamed here, so C's copies link under other names and nothing calls them; and the table
 * the rest calls the module through, p11_util.h's static `p11`, is filled by the Rust loader
 * below, with its call-log wrappers. Each slice adds its functions to the renames. */
#define pkiops_load         pqhsm_c_pkiops_load
#define pkiops_open         pqhsm_c_pkiops_open
#define pkiops_close        pqhsm_c_pkiops_close
#define pkiops_unload       pqhsm_c_pkiops_unload
#define pkiops_set_call_log pqhsm_c_pkiops_set_call_log
/* Slice 1, fhsm-csr's. The C not ported yet that calls one of these (alg_of's message calls
 * pkiops_alg_list, pkiops_keygen calls pkiops_keygen_alg) calls its C copy, which is still
 * here; nothing outside this file reaches them. */
#define pkiops_parse_slot    pqhsm_c_pkiops_parse_slot
#define pkiops_alg_name      pqhsm_c_pkiops_alg_name
#define pkiops_alg_list      pqhsm_c_pkiops_alg_list
#define pkiops_alg_parse     pqhsm_c_pkiops_alg_parse
#define pkiops_alg_digest    pqhsm_c_pkiops_alg_digest
#define pkiops_key_alg       pqhsm_c_pkiops_key_alg
#define pkiops_session_user  pqhsm_c_pkiops_session_user
#define pkiops_session_close pqhsm_c_pkiops_session_close
#define pkiops_keygen        pqhsm_c_pkiops_keygen
#define pkiops_keygen_alg    pqhsm_c_pkiops_keygen_alg
#define pkiops_csr           pqhsm_c_pkiops_csr
#define pkiops_root          pqhsm_c_pkiops_root
/* Slice 2, fhsm-token's (no C here calls them). */
#define pkiops_token_info    pqhsm_c_pkiops_token_info
#define pkiops_token_init    pqhsm_c_pkiops_token_init
/* Slice 3, fhsm-crypt's (only each other's C calls them). */
#define pkiops_keys                  pqhsm_c_pkiops_keys
#define pkiops_obj_class_name        pqhsm_c_pkiops_obj_class_name
#define pkiops_objects               pqhsm_c_pkiops_objects
#define pkiops_object_attrs          pqhsm_c_pkiops_object_attrs
#define pkiops_destroy               pqhsm_c_pkiops_destroy
#define pkiops_skey_name             pqhsm_c_pkiops_skey_name
#define pkiops_skey_list             pqhsm_c_pkiops_skey_list
#define pkiops_skey_parse            pqhsm_c_pkiops_skey_parse
#define pkiops_keygen_secret         pqhsm_c_pkiops_keygen_secret
#define pkiops_encrypt_file          pqhsm_c_pkiops_encrypt_file
#define pkiops_encrypt_file_for_cert pqhsm_c_pkiops_encrypt_file_for_cert
#define pkiops_decrypt_file          pqhsm_c_pkiops_decrypt_file

#include "../../../../tools/pkiops.c"

/* `fns`: p11's 31 functions in its field order (pkiops/src/lib.rs FUNCTIONS, which a test
 * compares with p11_util.h), or NULL to clear the table. */
void pqhsm_c_pkiops_install(void *const *fns);
void pqhsm_c_pkiops_install(void *const *fns) {
    _Static_assert(sizeof p11 == 32 * sizeof(void *),
                   "tools/p11_util.h's table changed: update pkiops/src/lib.rs FUNCTIONS");
    memset(&p11, 0, sizeof p11);
    if (fns) memcpy((char *)&p11 + sizeof p11.h, fns, 31 * sizeof(void *));
}
