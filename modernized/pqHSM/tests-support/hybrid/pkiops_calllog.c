/* Phase 5 slice 0 probe: the PKI tools' module loader and call log, C (tools/pkiops.c) against
 * Rust (pqhsm-pkiops), both over the SAME module, so a difference is the loader's. Prints every
 * call record (function, summary, CK_RV; not the time) and every p11_err, for: the load
 * refusals, pkiops_open with each intent and --slot, two tokens (the refusal that lists them),
 * a reload, and the operations that reach each wrapper pkiops.c calls (all but
 * C_GetMechanismList, C_GetMechanismInfo and C_DigestInit, which nothing in it calls).
 *
 *   pkiops_calllog MODULE        (FHSM_TOKENS_DIR: an empty directory)
 */
#include "pkiops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int records;
static void rec(const struct pkiops_call *c, void *ctx) {
    (void)ctx;
    records++;
    printf("  %s | %s | 0x%lx\n", c->fn, c->args, c->rv);
}

static struct p11_err e;
static int show(const char *what, int rc) {
    printf("%s -> %d", what, rc);
    if (rc) printf(" [%d] %s", e.code, e.msg);
    else printf("\n");
    memset(&e, 0, sizeof e);
    return rc;
}

static const uint8_t PIN[] = "userpin1234", SO[] = "sopin1234";

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: pkiops_calllog MODULE\n"); return 2; }
    const char *mod = argv[1];
    pkiops_handle slot = 99, s = 0, pub = 0, priv = 0, key = 0;
    char path[512];

    /* Before a callback is set nothing is reported; every refusal names its reason. */
    show("load /nonexistent.so", pkiops_load("/nonexistent/libnone.so", &e));
    show("load libc (neither C_GetFunctionList nor C_Initialize)", pkiops_load("libc.so.6", &e));
    show("load module, no log", pkiops_load(mod, &e));
    printf("records so far: %d\n", records);
    pkiops_set_call_log(rec, NULL);

    show("open ANY, no token", pkiops_open(mod, -1, PKIOPS_SLOT_ANY, &slot, &e));
    printf("  slot %lu\n", slot);
    show("open WITH_TOKEN, no token", pkiops_open(mod, -1, PKIOPS_SLOT_WITH_TOKEN, &slot, &e));
    show("open FOR_INIT", pkiops_open(mod, -1, PKIOPS_SLOT_FOR_INIT, &slot, &e));
    printf("  slot %lu\n", slot);
    show("token init 0", pkiops_token_init(0, SO, sizeof SO - 1, PIN, sizeof PIN - 1, "first", &e));
    show("open --slot 9", pkiops_open(mod, 9, PKIOPS_SLOT_ANY, &slot, &e));
    show("open --slot 1 WITH_TOKEN", pkiops_open(mod, 1, PKIOPS_SLOT_WITH_TOKEN, &slot, &e));
    show("open --slot 1 FOR_INIT", pkiops_open(mod, 1, PKIOPS_SLOT_FOR_INIT, &slot, &e));
    show("token init 1", pkiops_token_init(1, SO, sizeof SO - 1, PIN, sizeof PIN - 1, "second", &e));
    show("open WITH_TOKEN, two tokens", pkiops_open(mod, -1, PKIOPS_SLOT_WITH_TOKEN, &slot, &e));
    show("open ANY, two tokens", pkiops_open(mod, -1, PKIOPS_SLOT_ANY, &slot, &e));
    show("open --slot 0 WITH_TOKEN", pkiops_open(mod, 0, PKIOPS_SLOT_WITH_TOKEN, &slot, &e));
    printf("  slot %lu\n", slot);

    struct pkiops_token_info ti;
    show("token info", pkiops_token_info(slot, &ti, &e));
    show("session, wrong PIN", pkiops_session_user(slot, SO, sizeof SO - 1, &s, &e));
    show("session", pkiops_session_user(slot, PIN, sizeof PIN - 1, &s, &e));
    show("keygen ca (composite)", pkiops_keygen(s, "ca", &pub, &priv, &e));
    show("keygen ee (ecdsa-p256)", pkiops_keygen_alg(s, "ee", PKIOPS_ALG_ECDSA_P256, &pub, &priv, &e));
    enum pkiops_alg alg;
    show("key alg ee", pkiops_key_alg(s, "ee", &alg, &e));
    show("key alg nope", pkiops_key_alg(s, "nope", &alg, &e));

    static uint8_t ca[65536], csr[65536], cert[65536];
    size_t ca_len = sizeof ca, csr_len = sizeof csr, cert_len = sizeof cert;
    show("root ca", pkiops_root(s, "ca", "/CN=Probe CA", 1, 30, ca, &ca_len, &e));
    show("csr ee", pkiops_csr(s, "ee", "/CN=ee", csr, &csr_len, &e));
    int pop = -1;
    show("issue ee", pkiops_issue(s, "ca", ca, ca_len, csr, csr_len, NULL, NULL, NULL, 0,
                                  FHSM_CERT_END_ENTITY, 30, cert, &cert_len, &pop, &e));

    uint8_t *sig = NULL; size_t sig_len = 0; int valid = -1;
    static const uint8_t data[] = "the data";
    show("sign begin", pkiops_sign_begin(s, "ee", &e));
    show("sign update", pkiops_sign_update(s, data, sizeof data, &e));
    show("sign end", pkiops_sign_end(s, &sig, &sig_len, &e));
    show("verify begin", pkiops_verify_begin(s, "ee", &e));
    show("verify update", pkiops_verify_update(s, data, sizeof data, &e));
    show("verify end", pkiops_verify_end(s, sig, sig_len, &valid, &e));
    printf("  valid %d\n", valid);
    free(sig);

    show("keygen aes256", pkiops_keygen_secret(s, "box", PKIOPS_SKEY_AES256, &key, &e));
    const char *tmp = getenv("FHSM_TOKENS_DIR");
    snprintf(path, sizeof path, "%s/plain", tmp);
    FILE *f = fopen(path, "wb"); fputs("plain text\n", f); fclose(f);
    char enc[512], dec[512], used[65] = "";
    snprintf(enc, sizeof enc, "%s/plain.cms", tmp);
    snprintf(dec, sizeof dec, "%s/plain.out", tmp);
    show("encrypt", pkiops_encrypt_file(s, "box", path, enc, &e));
    show("decrypt", pkiops_decrypt_file(s, enc, dec, used, sizeof used, &e));

    struct pkiops_object *objs = NULL; size_t n = 0;
    show("objects", pkiops_objects(s, PKIOPS_OBJS_ALL, &objs, &n, &e));
    printf("  %zu objects\n", n);
    struct pkiops_attr *attrs = NULL; size_t na = 0;
    if (n) show("object attrs", pkiops_object_attrs(s, objs[0].handle, &attrs, &na, &e));
    free(attrs);
    show("destroy box", pkiops_destroy(s, key, &e));
    free(objs);
    struct pkiops_slot *sl = NULL; size_t ns = 0;
    show("slots", pkiops_slots(&sl, &ns, &e));
    for (size_t i = 0; i < ns; i++) printf("  slot %lu token %d \"%s\"\n", sl[i].id, sl[i].has_token, sl[i].label);
    free(sl);
    pkiops_session_close(s);

    pkiops_close();
    printf("close again (nothing to finalise)\n");
    pkiops_close();
    show("reload", pkiops_load(mod, &e));
    pkiops_unload();
    pkiops_set_call_log(NULL, NULL);
    int before = records;
    show("load, log off", pkiops_load(mod, &e));
    pkiops_unload();
    printf("records after the log was turned off: %d\n", records - before);
    printf("records: %d\n", records);
    return 0;
}
