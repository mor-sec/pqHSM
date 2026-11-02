/* Phase 3 slice 4 goldens: RUN the legacy power-on KATs and record what they do.
 *
 *   gen_kat vectors <out dir>          every vector array of kat/fhsm_kat_vectors.c and
 *                                      kat/cavp_extended.c, byte for byte (kat_vectors.tsv),
 *                                      and the messages the extended KATs hand to OpenSSL
 *   gen_kat runs <out dir> <rsp dir>   the scenarios (kat.tsv, kat_trace.tsv)
 *
 * Both sources are #included, so every static array is in scope; they compile with the
 * legacy CFLAGS. Seams, on this link line only (gen_token.mk):
 *   the six crypto-core primitives fhsm_kat_run_all calls are defined here: each computes the
 *     real result with OpenSSL, writes one trace line with its arguments, and can be faulted
 *     (fail: FUNCTION_FAILED without output; flip: first output byte inverted; accept: OK
 *     whatever the result; fixed: 0x42 bytes from the RNG);
 *   --wrap=fopen                       the two CAVP file paths open the scenario's fixtures;
 *   --wrap=EVP_DigestUpdate, EVP_DigestSign, EVP_PKEY_encrypt
 *                                      record the messages in `vectors` mode.
 * The extended KATs call OpenSSL directly and run for real. Nothing here computes an expected
 * value: every pass bit and return code is what the C concluded. */
#include "kat/fhsm_kat_vectors.c"
#include "kat/cavp_extended.c"

#include <errno.h>
#include <stdlib.h>
#include <openssl/rand.h>

static FILE *g_tsv, *g_trace;
static const char *g_name;
static int g_call;                       /* primitive calls so far in this scenario */
static int g_fault_call[2];
static const char *g_fault_mode[2];
static const char *g_opt, *g_cwd;        /* the CAVP files; NULL: absent */
static int g_capture;                    /* `vectors` mode */
static char g_prims[64][16];             /* each call's primitive, from the base run */

static void hexf(FILE *f, const uint8_t *p, size_t n) {
    if (!n) { fputc('-', f); return; }
    for (size_t i = 0; i < n; ++i) fprintf(f, "%02x", p[i]);
}

/* Starts the call's trace line; returns its fault, or "". */
static const char *call(const char *prim) {
    int k = ++g_call;
    if (k <= 64) snprintf(g_prims[k - 1], sizeof g_prims[0], "%s", prim);
    fprintf(g_trace, "%s\t%d\t%s\t", g_name, k, prim);
    for (int i = 0; i < 2; ++i)
        if (g_fault_call[i] == k) return g_fault_mode[i];
    return "";
}
static void arg(const char *name, const uint8_t *p, size_t n) {
    fprintf(g_trace, "%s=", name);
    hexf(g_trace, p, n);
    fputc(';', g_trace);
}
static fhsm_rv_t done(const char *fault, fhsm_rv_t rv, uint8_t *out, size_t n) {
    if (!strcmp(fault, "flip") && rv == FHSM_RV_OK && n) out[0] ^= 1;
    if (!strcmp(fault, "accept")) rv = FHSM_RV_OK;
    fprintf(g_trace, "\trv=0x%x\n", (unsigned)rv);
    return rv;
}

fhsm_rv_t fhsm_aes_gcm_encrypt(fhsm_slice_t key, fhsm_slice_t iv, fhsm_slice_t aad,
                               fhsm_slice_t pt, uint8_t *ct, size_t *ct_len, uint8_t tag[16]) {
    const char *f = call("gcm_encrypt");
    arg("key", key.data, key.len); arg("iv", iv.data, iv.len); arg("aad", aad.data, aad.len);
    arg("pt", pt.data, pt.len); fprintf(g_trace, "cap=%zu", *ct_len);
    if (!strcmp(f, "fail")) return done(f, FHSM_RV_FUNCTION_FAILED, NULL, 0);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n = 0, m = 0;
    int ok = c && EVP_EncryptInit_ex2(c, EVP_aes_256_gcm(), key.data, iv.data, NULL) == 1
        && EVP_EncryptUpdate(c, NULL, &n, aad.data, (int)aad.len) == 1
        && EVP_EncryptUpdate(c, ct, &n, pt.data, (int)pt.len) == 1
        && EVP_EncryptFinal_ex(c, ct + n, &m) == 1
        && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(c);
    *ct_len = pt.len;
    return done(f, ok ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED, ct, pt.len);
}

fhsm_rv_t fhsm_aes_gcm_decrypt(fhsm_slice_t key, fhsm_slice_t iv, fhsm_slice_t aad,
                               fhsm_slice_t ct, const uint8_t tag[16], uint8_t *pt,
                               size_t *pt_len) {
    const char *f = call("gcm_decrypt");
    arg("key", key.data, key.len); arg("iv", iv.data, iv.len); arg("aad", aad.data, aad.len);
    arg("ct", ct.data, ct.len); arg("tag", tag, 16); fprintf(g_trace, "cap=%zu", *pt_len);
    if (!strcmp(f, "fail")) return done(f, FHSM_RV_FUNCTION_FAILED, NULL, 0);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int n = 0, m = 0;
    int ok = c && EVP_DecryptInit_ex2(c, EVP_aes_256_gcm(), key.data, iv.data, NULL) == 1
        && EVP_DecryptUpdate(c, NULL, &n, aad.data, (int)aad.len) == 1
        && EVP_DecryptUpdate(c, pt, &n, ct.data, (int)ct.len) == 1
        && EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, (void *)(uintptr_t)tag) == 1;
    ok = ok && EVP_DecryptFinal_ex(c, pt + n, &m) == 1;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return done(f, FHSM_RV_ENCRYPTED_DATA_INVALID, NULL, 0);
    *pt_len = ct.len;
    return done(f, FHSM_RV_OK, pt, ct.len);
}

/* fhsm_kat_run_all asks for SHA-256 only. */
fhsm_rv_t fhsm_hash_oneshot(fhsm_hash_t alg, fhsm_slice_t data, uint8_t *out, size_t *out_len) {
    const char *f = call("hash");
    fprintf(g_trace, "alg=%d;", (int)alg); arg("data", data.data, data.len);
    fprintf(g_trace, "cap=%zu", *out_len);
    if (!strcmp(f, "fail")) return done(f, FHSM_RV_FUNCTION_FAILED, NULL, 0);
    unsigned int n = 0;
    if (alg != FHSM_HASH_SHA256 || !EVP_Digest(data.data, data.len, out, &n, EVP_sha256(), NULL))
        abort();
    *out_len = n;
    return done(f, FHSM_RV_OK, out, n);
}

fhsm_rv_t fhsm_hmac(fhsm_hash_t alg, fhsm_slice_t key, fhsm_slice_t data, uint8_t *mac,
                    size_t *mac_len) {
    const char *f = call("hmac");
    fprintf(g_trace, "alg=%d;", (int)alg); arg("key", key.data, key.len);
    arg("data", data.data, data.len); fprintf(g_trace, "cap=%zu", *mac_len);
    if (!strcmp(f, "fail")) return done(f, FHSM_RV_FUNCTION_FAILED, NULL, 0);
    unsigned int n = 0;
    if (alg != FHSM_HASH_SHA256
        || !HMAC(EVP_sha256(), key.data, (int)key.len, data.data, data.len, mac, &n))
        abort();
    *mac_len = n;
    return done(f, FHSM_RV_OK, mac, n);
}

fhsm_rv_t fhsm_pbkdf2(fhsm_hash_t alg, fhsm_slice_t password, fhsm_slice_t salt,
                      uint32_t iterations, uint8_t *out, size_t out_len) {
    const char *f = call("pbkdf2");
    fprintf(g_trace, "alg=%d;", (int)alg); arg("password", password.data, password.len);
    arg("salt", salt.data, salt.len); fprintf(g_trace, "iter=%u;len=%zu", iterations, out_len);
    if (!strcmp(f, "fail")) return done(f, FHSM_RV_FUNCTION_FAILED, NULL, 0);
    if (alg != FHSM_HASH_SHA256
        || !PKCS5_PBKDF2_HMAC((const char *)password.data, (int)password.len, salt.data,
                              (int)salt.len, (int)iterations, EVP_sha256(), (int)out_len, out))
        abort();
    return done(f, FHSM_RV_OK, out, out_len);
}

fhsm_rv_t fhsm_rng_bytes(uint8_t *out, size_t n) {
    const char *f = call("rng");
    fprintf(g_trace, "n=%zu", n);
    if (!strcmp(f, "fail")) return done(f, FHSM_RV_FUNCTION_FAILED, NULL, 0);
    if (!strcmp(f, "fixed")) { memset(out, 0x42, n); return done("", FHSM_RV_OK, out, n); }
    if (RAND_bytes(out, (int)n) != 1) abort();
    return done(f, FHSM_RV_OK, out, n);
}

FILE *__real_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode) {
    const char *to = path;
    if (!strcmp(path, "/opt/freehsm/share/kat/sha2_256_short.rsp")) to = g_opt;
    else if (!strcmp(path, "kat/cavp/sha2_256_short.rsp")) to = g_cwd;
    if (!to) { errno = ENOENT; return NULL; }
    return __real_fopen(to, mode);
}

/* `vectors` mode: the messages the extended KATs sign, digest or encrypt. */
static void captured(const char *fn, const void *p, size_t n) {
    static int k;
    if (!g_capture) return;
    fprintf(g_tsv, "evp:%s#%d\t", fn, ++k);
    hexf(g_tsv, p, n);
    fputc('\n', g_tsv);
}
int __real_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t n);
int __wrap_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t n);
int __wrap_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t n) {
    captured("EVP_DigestUpdate", d, n);
    return __real_EVP_DigestUpdate(ctx, d, n);
}
int __real_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *s, size_t *sl, const unsigned char *t, size_t tl);
int __wrap_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *s, size_t *sl, const unsigned char *t, size_t tl);
int __wrap_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *s, size_t *sl, const unsigned char *t, size_t tl) {
    captured("EVP_DigestSign", t, tl);
    return __real_EVP_DigestSign(ctx, s, sl, t, tl);
}
int __real_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *o, size_t *ol, const unsigned char *i, size_t il);
int __wrap_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *o, size_t *ol, const unsigned char *i, size_t il);
int __wrap_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *o, size_t *ol, const unsigned char *i, size_t il) {
    captured("EVP_PKEY_encrypt", i, il);
    return __real_EVP_PKEY_encrypt(ctx, o, ol, i, il);
}

static void vectors(void) {
#define D(a) do { fprintf(g_tsv, "%s\t", #a); hexf(g_tsv, (const uint8_t *)(a), sizeof(a)); fputc('\n', g_tsv); } while (0)
#define S(a) do { fprintf(g_tsv, "%s\t", #a); hexf(g_tsv, (const uint8_t *)(a), strlen(a)); fputc('\n', g_tsv); } while (0)
    D(kat_aesgcm_key); D(kat_aesgcm_iv); D(kat_aesgcm_aad); D(kat_aesgcm_pt);
    D(kat_aesgcm_ct_expected); D(kat_aesgcm_tag_expected); S(kat_sha256_msg);
    D(kat_sha256_expected); D(kat_hmac_key); S(kat_hmac_msg); D(kat_hmac_expected);
    D(kK); D(kP); D(kA); D(TC13_IV); D(TC13_CT); D(TC13_TAG); D(TC14_CT); D(TC14_TAG);
    D(hkat1_key); D(hkat1_data); D(hkat1_mac); D(hkat2_key); D(hkat2_data); D(hkat2_mac);
    D(hkat3_key); D(hkat3_data); D(hkat3_mac); D(hkat6_key); D(hkat6_data); D(hkat6_mac);
    D(sha_input_abc); D(sha256_empty); D(sha256_abc); D(sha384_empty); D(sha384_abc);
    D(sha512_empty); D(sha512_abc); D(sha3_256_empty); D(sha3_256_abc); D(sha3_384_empty);
    D(sha3_384_abc); D(sha3_512_empty); D(sha3_512_abc);
    D(aes256_key); D(aes_plaintext_64); D(aes256_cbc_iv); D(aes256_cbc_ct); D(aes256_ctr_ic);
    D(aes256_ctr_ct); D(aes256_cmac_empty_tag); D(aes256_cmac_16_tag); D(aes256_cmac_40_tag);
    D(ecdsa_msg_sample); D(ecdsa_p256_pub); D(ecdsa_p256_sig); D(ecdsa_p384_pub);
    D(ecdsa_p384_sig); D(ecdsa_p521_pub); D(ecdsa_p521_sig);
    D(hkdf_tc1_ikm); D(hkdf_tc1_salt); D(hkdf_tc1_info); D(hkdf_tc1_okm);
    D(hkdf_tc2_ikm); D(hkdf_tc2_salt); D(hkdf_tc2_info); D(hkdf_tc2_okm);
    D(pbkdf2_tc1_pwd); D(pbkdf2_tc1_salt); D(pbkdf2_tc1_dk); D(pbkdf2_tc2_dk);
    D(rsa_selftest_msg); D(pq_sig_msg);
    /* the function-local messages, as the extended KATs pass them to OpenSSL */
    fhsm_kat_result_t out[FHSM_KAT_MAX];
    size_t n = 0;
    g_capture = 1;
    if (fhsm_kat_cavp_extended(out, FHSM_KAT_MAX, &n) != FHSM_RV_OK) abort();
    g_capture = 0;
}

/* One run of fhsm_kat_run_all. records: write one line per record; else only how many. */
static void run(const char *name, size_t cap, const char *opt, const char *cwd,
                int null_out, int null_count, int records) {
    g_name = name; g_call = 0; g_opt = opt; g_cwd = cwd;
    fhsm_kat_result_t *out = calloc(cap ? cap : 1, sizeof *out);
    size_t count = 77;   /* any value: the runner sets it */
    fhsm_rv_t rv = fhsm_kat_run_all(null_out ? NULL : out, cap, null_count ? NULL : &count);
    size_t written = 0;
    for (size_t i = 0; i < cap; ++i) written += out[i].algorithm != NULL;
    fprintf(g_tsv, "%s\tcap=%zu\trv=0x%x;count=%zu;written=%zu\n", name, cap, (unsigned)rv,
            null_count ? (size_t)0 : count, written);
    for (size_t i = 0; records && i < cap && out[i].algorithm; ++i)
        fprintf(g_tsv, "%s\t#%zu\t%s\t%s\t%d\n", name, i, out[i].algorithm,
                out[i].vector_id ? out[i].vector_id : "(null)", out[i].passed);
    free(out);
    g_fault_call[0] = g_fault_call[1] = 0;
}

static const char *FIXTURES[] = {
    "fail_md", "stale_msg", "bad_hex", "short_md", "space_hex", "sign_hex", "prefix_hex",
    "odd_bits", "neg_len", "md_first", "twice", "incomplete", "no_newline", "crlf", "skipped",
    "long_msg", "split_md", "max_len", "many", "empty",
};

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: gen_kat vectors|runs <out dir> [rsp dir]\n"); return 2; }
    char p[512];
    if (!strcmp(argv[1], "vectors")) {
        snprintf(p, sizeof p, "%s/kat_vectors.tsv", argv[2]);
        if (!(g_tsv = __real_fopen(p, "w")) || !(g_trace = __real_fopen("/dev/null", "w"))) return 1;
        fprintf(g_tsv, "# Generated by tests-support/golden/gen_kat.c from the legacy C code. Do not edit.\n"
                       "# array\tbytes  (selftest/tests/kat_golden.rs)\n");
        vectors();
        return fclose(g_tsv) != 0;
    }
    if (strcmp(argv[1], "runs") || argc != 4) return 2;
    const char *real = "kat/cavp/sha2_256_short.rsp", *dir = argv[3];
    snprintf(p, sizeof p, "%s/kat.tsv", argv[2]);
    if (!(g_tsv = __real_fopen(p, "w"))) return 1;
    snprintf(p, sizeof p, "%s/kat_trace.tsv", argv[2]);
    if (!(g_trace = __real_fopen(p, "w"))) return 1;
    fprintf(g_tsv, "# Generated by tests-support/golden/gen_kat.c from the legacy C code. Do not edit.\n"
                   "# scenario\tcap\tresult, then #index\talgorithm\tvector id\tpassed  (selftest/tests/kat_golden.rs)\n");
    fprintf(g_trace, "# Generated by tests-support/golden/gen_kat.c. Do not edit.\n"
                     "# scenario\tcall\tprimitive\targuments\tresult\n");
    run("base", FHSM_KAT_MAX, NULL, real, 0, 0, 1);
    /* every primitive call of the base run, failed and corrupted in turn */
    int calls = g_call;
    char prims[64][16];
    memcpy(prims, g_prims, sizeof prims);
    for (int k = 1; k <= calls; ++k) {
        const char *modes[] = { "fail", "flip", "accept" };
        for (int m = 0; m < 3; ++m) {
            if (m == 2 && strcmp(prims[k - 1], "gcm_decrypt")) continue;
            char name[64];
            snprintf(name, sizeof name, "%s_%d", modes[m], k);
            g_fault_call[0] = k; g_fault_mode[0] = modes[m];
            run(name, FHSM_KAT_MAX, NULL, real, 0, 0, 1);
        }
    }
    g_fault_call[0] = calls - 1; g_fault_mode[0] = "fixed";
    g_fault_call[1] = calls;     g_fault_mode[1] = "fixed";
    run("stuck_rng", FHSM_KAT_MAX, NULL, real, 0, 0, 1);
    for (size_t cap = 0; cap <= FHSM_KAT_MAX; ++cap) {
        char name[32];
        snprintf(name, sizeof name, "cap_%zu", cap);
        run(name, cap, NULL, real, 0, 0, 0);
    }
    run("null_out", FHSM_KAT_MAX, NULL, real, 1, 0, 0);
    run("null_count", FHSM_KAT_MAX, NULL, real, 0, 1, 0);
    char opt[512], fx[512];
    snprintf(opt, sizeof opt, "%s/opt.rsp", dir);
    run("rsp_opt_preferred", FHSM_KAT_MAX, opt, real, 0, 0, 1);
    run("rsp_opt_only", FHSM_KAT_MAX, opt, NULL, 0, 0, 1);
    run("rsp_none", FHSM_KAT_MAX, NULL, NULL, 0, 0, 1);
    for (size_t i = 0; i < sizeof FIXTURES / sizeof FIXTURES[0]; ++i) {
        char name[64];
        snprintf(fx, sizeof fx, "%s/%s.rsp", dir, FIXTURES[i]);
        snprintf(name, sizeof name, "rsp_%s", FIXTURES[i]);
        run(name, FHSM_KAT_MAX, NULL, fx, 0, 0, 1);
    }
    snprintf(fx, sizeof fx, "%s/many.rsp", dir);
    run("rsp_many_cap200", 200, NULL, fx, 0, 0, 1);
    return (fclose(g_tsv) | fclose(g_trace)) != 0;
}
