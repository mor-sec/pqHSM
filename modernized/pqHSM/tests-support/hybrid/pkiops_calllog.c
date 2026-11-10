/* Phase 5 slice 0 probe: the PKI tools' module loader and call log, C (tools/pkiops.c) against
 * Rust (pqhsm-pkiops), both over the SAME module, so a difference is the loader's. Prints every
 * call record (function, summary, CK_RV; not the time) and every p11_err, for: the load
 * refusals, pkiops_open with each intent and --slot, two tokens (the refusal that lists them),
 * a reload, and the operations that reach each wrapper pkiops.c calls (all but
 * C_GetMechanismList, C_GetMechanismInfo and C_DigestInit, which nothing in it calls); from
 * slice 3, every key fhsm-crypt makes, both kinds of recipient, and every object's attributes;
 * from slice 4, streamed signatures, the digests and CMS SignedData.
 *
 *   pkiops_calllog MODULE        (FHSM_TOKENS_DIR: an empty directory)
 */
#include "pkiops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

    /* Slice 4: a wrong and a non-DER ECDSA signature, the composite and RSA-PSS (its
     * mechanism parameters), the digests and their refusals, and a CMS signed, named and
     * checked against the right data, the wrong data, and something not a CMS. */
    static const uint8_t other[] = "other data";
    show("sign begin ee", pkiops_sign_begin(s, "ee", &e));
    show("sign update ee", pkiops_sign_update(s, data, sizeof data, &e));
    show("sign end ee", pkiops_sign_end(s, &sig, &sig_len, &e));
    show("verify begin", pkiops_verify_begin(s, "ee", &e));
    show("verify update, other data", pkiops_verify_update(s, other, sizeof other, &e));
    show("verify end", pkiops_verify_end(s, sig, sig_len, &valid, &e));
    printf("  valid %d\n", valid);
    show("verify begin", pkiops_verify_begin(s, "ee", &e));
    show("verify end, not DER", pkiops_verify_end(s, data, sizeof data, &valid, &e));
    printf("  valid %d\n", valid);
    free(sig);
    show("keygen pss", pkiops_keygen_alg(s, "pss", PKIOPS_ALG_RSA_PSS, &pub, &priv, &e));
    const char *const signers[] = { "ca", "pss" };
    for (int i = 0; i < 2; i++) {
        show(signers[i], pkiops_sign_begin(s, signers[i], &e));
        show("  sign update", pkiops_sign_update(s, data, sizeof data, &e));
        show("  sign end", pkiops_sign_end(s, &sig, &sig_len, &e));
        printf("  %zu bytes\n", sig_len);
        show("  verify begin", pkiops_verify_begin(s, signers[i], &e));
        show("  verify update", pkiops_verify_update(s, data, sizeof data, &e));
        show("  verify end", pkiops_verify_end(s, sig, sig_len, &valid, &e));
        printf("  valid %d\n", valid);
        free(sig);
    }
    show("sign begin nope", pkiops_sign_begin(s, "nope", &e));
    show("verify begin nope", pkiops_verify_begin(s, "nope", &e));

    uint8_t dg[64], dg2[64]; size_t dl = 0, dl2 = 0;
    struct pkiops_hash *h = pkiops_hash_begin("SHA256", &e);
    show("hash SHA256", h ? 0 : 1);
    show("  update", pkiops_hash_update(h, data, sizeof data, &e));
    show("  end", pkiops_hash_end(h, dg, &dl, &e));
    printf("  %zu bytes\n", dl);
    h = pkiops_hash_begin("SHA256", &e);
    pkiops_hash_update(h, other, sizeof other, &e);
    pkiops_hash_end(h, dg2, &dl2, &e);
    show("hash nope", pkiops_hash_begin("nope", &e) ? 0 : 1);
    show("hash NULL", pkiops_hash_begin(NULL, &e) ? 0 : 1);
    static uint8_t cms[262144];
    size_t cms_len = sizeof cms;
    show("cms sign ee", pkiops_cms_sign(s, "ee", cert, cert_len, dg, dl, cms, &cms_len, &e));
    const char *dname = NULL;
    printf("cms digest -> %d %s\n", pkiops_cms_digest(cms, cms_len, &dname), dname ? dname : "(none)");
    int verdict = 9;
    show("cms verify", pkiops_cms_verify(cms, cms_len, dg, dl, &verdict, &e));
    printf("  verdict %d\n", verdict);
    show("cms verify, other data", pkiops_cms_verify(cms, cms_len, dg2, dl2, &verdict, &e));
    printf("  verdict %d\n", verdict);
    show("cms verify, a certificate", pkiops_cms_verify(cert, cert_len, dg, dl, &verdict, &e));
    printf("  verdict %d\n", verdict);
    printf("cms digest of a certificate -> %d\n", pkiops_cms_digest(cert, cert_len, &dname));
    cms_len = sizeof cms;
    show("cms sign nope", pkiops_cms_sign(s, "nope", cert, cert_len, dg, dl, cms, &cms_len, &e));
    cms_len = sizeof cms;
    show("cms sign ee, digest too short", pkiops_cms_sign(s, "ee", cert, cert_len, dg, 20, cms, &cms_len, &e));

    show("keygen aes256", pkiops_keygen_secret(s, "box", PKIOPS_SKEY_AES256, &key, &e));
    /* Paths relative to the token directory, so the messages naming them do not carry the
     * run's mktemp name. */
    const char *tmp = ".";
    if (chdir(getenv("FHSM_TOKENS_DIR")) != 0) { perror("chdir"); return 2; }
    snprintf(path, sizeof path, "%s/plain", tmp);
    FILE *f = fopen(path, "wb"); fputs("plain text\n", f); fclose(f);
    char enc[512], dec[512], used[65] = "";
    snprintf(enc, sizeof enc, "%s/plain.cms", tmp);
    snprintf(dec, sizeof dec, "%s/plain.out", tmp);
    show("encrypt", pkiops_encrypt_file(s, "box", path, enc, &e));
    show("decrypt", pkiops_decrypt_file(s, enc, dec, used, sizeof used, &e));
    printf("  used \"%s\"\n", used);

    /* Slice 3: every kind of key fhsm-crypt makes, both kinds of recipient, a certificate's
     * holder, the refusals; then every object's fields and every attribute line. */
    show("keygen aes128", pkiops_keygen_secret(s, "box128", PKIOPS_SKEY_AES128, &key, &e));
    show("keygen hmac", pkiops_keygen_secret(s, "mac", PKIOPS_SKEY_HMAC, &key, &e));
    show("keygen rsa-oaep", pkiops_keygen_secret(s, "oaep", PKIOPS_SKEY_RSA_OAEP, &key, &e));
    show("keygen rsa-pkcs1", pkiops_keygen_alg(s, "rsa", PKIOPS_ALG_RSA_PKCS1, &pub, &priv, &e));
    enum pkiops_skey sk;
    show("skey parse rsa-oaep", pkiops_skey_parse("rsa-oaep", &sk, &e));
    show("skey parse ecdsa-p256", pkiops_skey_parse("ecdsa-p256", &sk, &e));
    show("skey parse des", pkiops_skey_parse("des", &sk, &e));
    printf("  skey %s; list %s; class 4 %s\n", pkiops_skey_name(sk), pkiops_skey_list(),
           pkiops_obj_class_name(PKIOPS_OBJ_COUNT) ? "named" : "NULL");
    snprintf(enc, sizeof enc, "%s/oaep.cms", tmp);
    snprintf(dec, sizeof dec, "%s/oaep.out", tmp);
    show("encrypt oaep", pkiops_encrypt_file(s, "oaep", path, enc, &e));
    used[0] = '\0';
    show("decrypt oaep", pkiops_decrypt_file(s, enc, dec, used, sizeof used, &e));
    printf("  used \"%s\"\n", used);
    show("decrypt oaep again (out exists)", pkiops_decrypt_file(s, enc, dec, used, sizeof used, &e));
    snprintf(enc, sizeof enc, "%s/x.cms", tmp);
    show("encrypt mac", pkiops_encrypt_file(s, "mac", path, enc, &e));
    show("encrypt ee (not for encryption)", pkiops_encrypt_file(s, "ee", path, enc, &e));
    show("encrypt nope", pkiops_encrypt_file(s, "nope", path, enc, &e));
    snprintf(dec, sizeof dec, "%s/plain.dec", tmp);
    show("decrypt plain (not CMS)", pkiops_decrypt_file(s, path, dec, used, sizeof used, &e));
    ca_len = sizeof ca;
    show("root rsa", pkiops_root(s, "rsa", "/CN=RSA", 2, 30, ca, &ca_len, &e));
    char crt[512];
    snprintf(crt, sizeof crt, "%s/rsa.der", tmp);
    f = fopen(crt, "wb"); fwrite(ca, 1, ca_len, f); fclose(f);
    snprintf(enc, sizeof enc, "%s/rsa.cms", tmp);
    snprintf(dec, sizeof dec, "%s/rsa.out", tmp);
    show("encrypt for cert", pkiops_encrypt_file_for_cert(crt, path, enc, &e));
    show("encrypt for cert, not a cert", pkiops_encrypt_file_for_cert(path, path, dec, &e));
    show("decrypt for cert (the key may not)", pkiops_decrypt_file(s, enc, dec, used, sizeof used, &e));

    struct pkiops_key *keys = NULL; size_t nk = 0;
    show("keys", pkiops_keys(s, &keys, &nk, &e));
    for (size_t i = 0; i < nk; i++)
        printf("  key %lu private %d type 0x%lx \"%s\" %s\n", keys[i].handle, keys[i].is_private,
               keys[i].key_type, keys[i].label, keys[i].alg);
    free(keys);
    struct pkiops_object *objs = NULL; size_t n = 0;
    show("objects", pkiops_objects(s, PKIOPS_OBJS_ALL, &objs, &n, &e));
    printf("  %zu objects\n", n);
    for (size_t i = 0; i < n; i++) {
        printf("  object %lu %s type 0x%lx \"%s\" id %s alg %s\n", objs[i].handle,
               pkiops_obj_class_name(objs[i].cls), objs[i].key_type, objs[i].label, objs[i].id,
               objs[i].alg);
        struct pkiops_attr *attrs = NULL; size_t na = 0;
        show("  object attrs", pkiops_object_attrs(s, objs[i].handle, &attrs, &na, &e));
        for (size_t q = 0; q < na; q++) printf("    %s = %s\n", attrs[q].name, attrs[q].value);
        free(attrs);
    }
    show("destroy oaep (private half)", pkiops_destroy(s, key, &e));
    struct pkiops_attr *attrs = NULL; size_t na = 0;
    show("object attrs, destroyed", pkiops_object_attrs(s, key, &attrs, &na, &e));
    free(attrs);
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
