/* Phase 3 slice 3 goldens: RUN the legacy src/fhsm_crypto.c and record what it returns.
 *
 *   gen_core make OUTDIR
 *
 * Lifecycle: fhsm_integrity_verify, fhsm_kat_run_all, fhsm_drbg_*, fhsm_state_* are scripted
 * stubs here (their objects are not linked), and --wrap=OSSL_PROVIDER_load,
 * OSSL_PROVIDER_unload, EVP_default_properties_enable_fips, RAND_status and RAND_add record
 * each call and fail on demand, so every branch of crypto_init_once runs. Primitives (hash,
 * HMAC, AES-GCM, PBKDF2) run on OpenSSL's real default provider. Each scenario is its own
 * forked child (pthread_once and the providers are process state); its stderr goes to
 * OUTDIR/core/<scenario>.stderr. Writes OUTDIR/core.tsv; crypto/tests/core_golden.rs replays
 * it. Keys, IVs and passwords are generated patterns, not credentials. Used only by
 * regen_crypto.sh. */
#include "fhsm_common.h"
#include "fhsm_crypto.h"
#include "fhsm_drbg.h"
#include "fhsm_integrity.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

/* ---- seams -------------------------------------------------------------------------------- */

OSSL_PROVIDER *__wrap_OSSL_PROVIDER_load(OSSL_LIB_CTX *ctx, const char *name);
int __wrap_OSSL_PROVIDER_unload(OSSL_PROVIDER *prov);
int __wrap_EVP_default_properties_enable_fips(OSSL_LIB_CTX *ctx, int enable);
int __wrap_RAND_status(void);
int __wrap_RAND_add(const void *buf, int num, double randomness);

static char g_trace[1024];
static char g_latch[128];
static int g_state = FHSM_STATE_INITIALIZED;
static int g_fail_integrity, g_fail_fips, g_fail_base, g_fail_default, g_fail_props, g_fail_drbg,
           g_fail_kat, g_fail_rand_status;
static const char *g_names[] = { "fips", "base", "default" };
static char g_fake[3];   /* provider handles: never dereferenced */

static void trace(const char *what) {
    if (g_trace[0]) strncat(g_trace, ",", sizeof g_trace - strlen(g_trace) - 1);
    strncat(g_trace, what, sizeof g_trace - strlen(g_trace) - 1);
}

static void traces(const char *fmt, const char *s) {
    char one[64];
    snprintf(one, sizeof one, fmt, s);
    trace(one);
}

static void tracen(const char *fmt, int n) {
    char one[64];
    snprintf(one, sizeof one, fmt, n);
    trace(one);
}

OSSL_PROVIDER *__wrap_OSSL_PROVIDER_load(OSSL_LIB_CTX *ctx, const char *name) {
    (void)ctx;
    traces("load:%s", name);
    for (int i = 0; i < 3; i++) {
        if (strcmp(name, g_names[i])) continue;
        int fail = i == 0 ? g_fail_fips : i == 1 ? g_fail_base : g_fail_default;
        return fail ? NULL : (OSSL_PROVIDER *)&g_fake[i];
    }
    return NULL;
}

int __wrap_OSSL_PROVIDER_unload(OSSL_PROVIDER *prov) {
    for (int i = 0; i < 3; i++)
        if (prov == (OSSL_PROVIDER *)&g_fake[i]) traces("unload:%s", g_names[i]);
    if (!prov) trace("unload:NULL");
    return 1;
}

int __wrap_EVP_default_properties_enable_fips(OSSL_LIB_CTX *ctx, int enable) {
    (void)ctx;
    tracen("fips_props:%d", enable);
    return enable && g_fail_props ? 0 : 1;
}

int __wrap_RAND_status(void) {
    trace("rand_status");
    return !g_fail_rand_status;
}

int __wrap_RAND_add(const void *buf, int num, double randomness) {
    (void)buf; (void)randomness;
    tracen("rand_add:%d", num);
    return 1;
}

fhsm_module_state_t fhsm_state_get(void) { return (fhsm_module_state_t)g_state; }

void fhsm_state_latch_error(const char *reason) {
    snprintf(g_latch, sizeof g_latch, "%s", reason ? reason : "");
    g_state = FHSM_STATE_ERROR;
}

fhsm_rv_t fhsm_integrity_verify(void) {
    trace("integrity");
    return g_fail_integrity ? FHSM_RV_INTEGRITY_FAILED : FHSM_RV_OK;
}

fhsm_rv_t fhsm_drbg_init(void) {
    trace("drbg_init");
    return g_fail_drbg ? FHSM_RV_RNG_FAILURE : FHSM_RV_OK;
}

fhsm_rv_t fhsm_drbg_bytes(uint8_t *out, size_t n) {
    tracen("drbg_bytes:%d", (int)n);
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(0x5A ^ i);
    return FHSM_RV_OK;
}

fhsm_rv_t fhsm_kat_run_all(fhsm_kat_result_t *out, size_t cap, size_t *count) {
    tracen("kat:%d", (int)cap);
    static const char *alg[] = { "AES-GCM-256", "HMAC-SHA-256", "SHA2-256" };
    static const char *vid[] = { "gcm-tc1", "rfc4231-tc1", "abc" };
    for (size_t i = 0; i < 3; i++)
        out[i] = (fhsm_kat_result_t){ alg[i], vid[i], !(g_fail_kat && i == 1), 0 };
    *count = 3;
    return g_fail_kat ? FHSM_RV_KAT_FAILED : FHSM_RV_OK;
}

/* ---- scenarios ---------------------------------------------------------------------------- */

struct scenario { const char *name; const char *ops; };

#define DEV "env:FHSM_INTEGRITY_ALLOW_UNSIGNED=1 "
static const struct scenario SCEN[] = {
    { "fips_ok", "init kat_results init fips_mode finalize kat_results init" },
    { "integrity_fail", "fail:integrity init init" },
    { "fips_fail", "env:OPENSSL_CONF=/etc/x.cnf fail:fips init" },
    { "fips_fail_noconf", "fail:fips init" },
    { "base_fail", "fail:base init" },
    { "props_fail", "fail:props init" },
    { "drbg_fail", "fail:drbg init" },
    { "kat_fail", "fail:kat init kat_results" },
    { "kat_fail_kat_var_only", "env:FHSM_KAT_ALLOW_FAIL=1 fail:kat init" },
    { "dev_ok", DEV "init kat_results finalize init" },
    { "dev_integrity_fail", DEV "fail:integrity init" },
    { "dev_default_fail", DEV "fail:default init" },
    { "dev_drbg_fail", DEV "fail:drbg init" },
    { "dev_kat_fail", DEV "fail:kat init" },
    { "dev_kat_fail_bypass", DEV "env:FHSM_KAT_ALLOW_FAIL=1 fail:kat init kat_results finalize" },
    { "finalize_first", "finalize kat_results init" },
    { "rng", "rng:5 rng:0 reseed:0 reseed:7 fail:rand_status reseed:7 reseed:0" },
    { "prims_error", "state_error hash:1:616263:64 hmac:1:6b:616263:64 gcm_enc:32:12::00:16:ok "
                     "gcm_dec:32:12::00:ok:16 pbkdf2:1:7077:73616c74:1000:32" },
};

/* The primitive rows, run in the "prims" scenario. */
static const char *PRIMS[] = {
    "size:0", "size:1", "size:2", "size:3", "size:4", "size:5", "size:6", "size:7", "size:8",
    "size:9", "size:10", "size:11", "size:12", "size:13",
    "name:0", "name:1", "name:2", "name:3", "name:4", "name:5", "name:6", "name:7", "name:8",
    "name:9", "name:10", "name:11", "name:12", "name:13",
    /* hash:ALG:DATA:CAP (CAP null = out NULL, lnull = out_len NULL) */
    "hash:1:616263:64", "hash:2:616263:64", "hash:3:616263:64", "hash:4:616263:64",
    "hash:5:616263:64", "hash:6:616263:64", "hash:7:616263:64", "hash:8:616263:64",
    "hash:9:616263:64", "hash:10:616263:64", "hash:11:616263:64", "hash:12:616263:64",
    "hash:1::64", "hash:1:616263:32", "hash:1:616263:31", "hash:0:616263:64", "hash:13:616263:64",
    "hash:1:616263:null", "hash:1:616263:lnull",
    /* hmac:ALG:KEY:DATA:CAP (CAP null = mac NULL with mac_len 64) */
    "hmac:1:6b6579:616263:64", "hmac:2:6b6579:616263:64", "hmac:3:6b6579:616263:64",
    "hmac:4:6b6579:616263:64", "hmac:7:6b6579:616263:64", "hmac:8:6b6579:616263:64",
    "hmac:9:6b6579:616263:64", "hmac:12:6b6579:616263:64",
    "hmac:1::616263:64", "hmac:1:6b6579::64", "hmac:1:6b6579:616263:32",
    "hmac:1:6b6579:616263:31", "hmac:0:6b6579:616263:64", "hmac:1:6b6579:616263:null",
    /* gcm_enc:KEYLEN:IVLEN:AAD:PT:CTCAP:TAG (TAG null = tag NULL; CTCAP lnull = len NULL) */
    "gcm_enc:16:12::00112233:16:ok", "gcm_enc:24:12::00112233:16:ok",
    "gcm_enc:32:12:aabb:00112233445566778899aabbccddeeff00:17:ok",
    "gcm_enc:32:12:aabb::0:ok", "gcm_enc:32:12::00112233:3:ok", "gcm_enc:15:12::00:16:ok",
    "gcm_enc:32:16::00:16:ok", "gcm_enc:32:12::00:16:null", "gcm_enc:32:12::00:lnull:ok",
    "gcm_enc:33:11::00:0:null",
    /* gcm_dec:KEYLEN:IVLEN:AAD:PT:MOD:PTCAP (encrypts PT, then decrypts with MOD applied) */
    "gcm_dec:32:12:aabb:00112233445566778899aabbccddeeff00:ok:17",
    "gcm_dec:16:12::00112233:ok:4", "gcm_dec:32:12:aabb::ok:0",
    "gcm_dec:32:12:aabb:0011223344:tag:8", "gcm_dec:32:12:aabb:0011223344:aad:8",
    "gcm_dec:32:12:aabb:0011223344:ct:8", "gcm_dec:32:12::0011223344:ok:4",
    "gcm_dec:15:12::00:ok:16", "gcm_dec:32:16::00:ok:16", "gcm_dec:32:12::00:tagnull:16",
    "gcm_dec:32:12::00:lnull:16",
    /* pbkdf2:ALG:PW:SALT:ITER:OUTLEN */
    "pbkdf2:1:70617373:73616c74:1000:32", "pbkdf2:2:70617373:73616c74:1000:48",
    "pbkdf2:3:70617373:73616c74:1000:64", "pbkdf2:1:70617373:73616c74:1000:256",
    "pbkdf2:1:70617373:73616c74:1000:257", "pbkdf2:1:70617373:73616c74:1000:0",
    "pbkdf2:1:70617373:73616c74:999:32", "pbkdf2:1::73616c74:1000:16",
    "pbkdf2:1:70617373::1000:16", "pbkdf2:1:70617373:7361:1000:16",
    "pbkdf2:0:70617373:73616c74:1000:16", "pbkdf2:13:70617373:73616c74:1000:16",
    "pbkdf2:4:70617373:73616c74:2048:20", "pbkdf2:7:70617373:73616c74:1000:20",
    NULL,
};

static FILE *tsv;
static char res[4096];

static void hexout(const char *label, const unsigned char *p, size_t n) {
    size_t len = strlen(res);
    len += (size_t)snprintf(res + len, sizeof res - len, "%s", label);
    for (size_t i = 0; i < n && len + 3 < sizeof res; i++)
        len += (size_t)snprintf(res + len, sizeof res - len, "%02x", p[i]);
}

static size_t unhex(const char *s, unsigned char *out) {
    size_t n = 0;
    for (; s[0] && s[1]; s += 2) sscanf(s, "%2hhx", &out[n++]);
    return n;
}

/* The next ':'-separated field of *s, NUL-terminated in place. */
static char *field(char **s) {
    char *f = *s, *c = strchr(f, ':');
    if (c) { *c = 0; *s = c + 1; } else *s = f + strlen(f);
    return f;
}

static void pattern(unsigned char *p, size_t n, unsigned char base) {
    for (size_t i = 0; i < n; i++) p[i] = (unsigned char)(base + 7 * i);
}

static void prim(char *op) {
    char *a = strchr(op, ':');
    char *name = op;
    if (a) *a++ = 0; else a = op + strlen(op);
    fhsm_rv_t rv;
    unsigned char out[512], key[64], iv[32], in[256], aad[64], tag[16], ct[300], pt[300];
    if (!strcmp(name, "size")) {
        snprintf(res, sizeof res, "%zu", fhsm_hash_size((fhsm_hash_t)atoi(a)));
    } else if (!strcmp(name, "name")) {
        const char *n = fhsm_hash_openssl_name((fhsm_hash_t)atoi(a));
        snprintf(res, sizeof res, "%s", n ? n : "NULL");
    } else if (!strcmp(name, "hash")) {
        int alg = atoi(field(&a));
        size_t n = unhex(field(&a), in);
        char *cap = field(&a);
        size_t len = (size_t)atoi(cap);
        memset(out, 0xEE, sizeof out);
        rv = fhsm_hash_oneshot((fhsm_hash_t)alg, FHSM_SLICE(in, n), strcmp(cap, "null") ? out : NULL,
                               strcmp(cap, "lnull") ? &len : NULL);
        snprintf(res, sizeof res, "rv=0x%x;len=%zu;", rv, len);
        hexout("out=", out, rv == FHSM_RV_OK ? len : 0);
    } else if (!strcmp(name, "hmac")) {
        int alg = atoi(field(&a));
        size_t kn = unhex(field(&a), key);
        size_t dn = unhex(field(&a), in);
        char *cap = field(&a);
        int null_mac = !strcmp(cap, "null");
        size_t len = null_mac ? 64 : (size_t)atoi(cap);
        memset(out, 0xEE, sizeof out);
        rv = fhsm_hmac((fhsm_hash_t)alg, FHSM_SLICE(key, kn), FHSM_SLICE(in, dn), null_mac ? NULL : out, &len);
        snprintf(res, sizeof res, "rv=0x%x;len=%zu;", rv, len);
        hexout("mac=", out, rv == FHSM_RV_OK && !null_mac ? len : 0);
    } else if (!strcmp(name, "gcm_enc") || !strcmp(name, "gcm_dec")) {
        int dec = name[4] == 'd';
        size_t kl = (size_t)atoi(field(&a)), il = (size_t)atoi(field(&a));
        size_t an = unhex(field(&a), aad);
        size_t pn = unhex(field(&a), in);
        pattern(key, sizeof key, 0x11);
        pattern(iv, sizeof iv, 0xA0);
        memset(ct, 0xEE, sizeof ct);
        memset(tag, 0xEE, sizeof tag);
        if (!dec) {
            char *cap = field(&a), *tg = field(&a);
            size_t len = (size_t)atoi(cap);
            rv = fhsm_aes_gcm_encrypt(FHSM_SLICE(key, kl), FHSM_SLICE(iv, il), FHSM_SLICE(aad, an),
                                      FHSM_SLICE(in, pn), ct, strcmp(cap, "lnull") ? &len : NULL,
                                      strcmp(tg, "null") ? tag : NULL);
            snprintf(res, sizeof res, "rv=0x%x;len=%zu;", rv, len);
            hexout("ct=", ct, rv == FHSM_RV_OK ? len : 0);
            hexout(";tag=", tag, rv == FHSM_RV_OK ? 16 : 0);
        } else {
            char *mod = field(&a);
            size_t cap = (size_t)atoi(field(&a));
            /* encrypt with valid parameters, whatever the decrypt is then given */
            size_t cl = sizeof ct;
            size_t ekl = (kl == 16 || kl == 24 || kl == 32) ? kl : 32;
            fhsm_rv_t erv = fhsm_aes_gcm_encrypt(FHSM_SLICE(key, ekl), FHSM_SLICE(iv, 12),
                                                 FHSM_SLICE(aad, an), FHSM_SLICE(in, pn), ct, &cl, tag);
            if (!strcmp(mod, "tag")) tag[0] ^= 1;
            if (!strcmp(mod, "aad") && an) aad[0] ^= 1;
            if (!strcmp(mod, "ct") && cl) ct[0] ^= 1;
            memset(pt, 0xEE, sizeof pt);
            size_t len = cap;
            rv = fhsm_aes_gcm_decrypt(FHSM_SLICE(key, kl), FHSM_SLICE(iv, il), FHSM_SLICE(aad, an),
                                      FHSM_SLICE(ct, cl), strcmp(mod, "tagnull") ? tag : NULL, pt,
                                      strcmp(mod, "lnull") ? &len : NULL);
            snprintf(res, sizeof res, "erv=0x%x;rv=0x%x;len=%zu;", erv, rv, len);
            /* the caller's buffer up to its stated capacity: what decrypt wrote or wiped */
            hexout("pt=", pt, cap);
        }
    } else if (!strcmp(name, "pbkdf2")) {
        int alg = atoi(field(&a));
        size_t pn = unhex(field(&a), in);
        size_t sn = unhex(field(&a), aad);
        uint32_t iter = (uint32_t)strtoul(field(&a), NULL, 10);
        size_t ol = (size_t)atoi(field(&a));
        memset(out, 0xEE, sizeof out);
        rv = fhsm_pbkdf2((fhsm_hash_t)alg, FHSM_SLICE(in, pn), FHSM_SLICE(aad, sn), iter, out, ol);
        snprintf(res, sizeof res, "rv=0x%x;", rv);
        hexout("out=", out, rv == FHSM_RV_OK ? ol : 0);
    } else if (!strcmp(name, "rng")) {
        size_t n = (size_t)atoi(a);
        memset(out, 0xEE, sizeof out);
        rv = fhsm_rng_bytes(n ? out : NULL, n);
        snprintf(res, sizeof res, "rv=0x%x;", rv);
        hexout("out=", out, n);
    } else if (!strcmp(name, "reseed")) {
        size_t n = (size_t)atoi(a);
        pattern(in, n, 0x30);
        rv = fhsm_rng_reseed(FHSM_SLICE(n ? in : NULL, n));
        snprintf(res, sizeof res, "rv=0x%x", rv);
    } else {
        fprintf(stderr, "unknown op %s\n", name);
        _exit(3);
    }
}

static void run_op(const char *sc, const char *op_in) {
    char op[512];
    snprintf(op, sizeof op, "%s", op_in);
    g_trace[0] = 0; g_latch[0] = 0; res[0] = 0;
    if (!strncmp(op, "env:", 4)) {
        char *eq = strchr(op + 4, '=');
        *eq = 0;
        setenv(op + 4, eq + 1, 1);
        snprintf(res, sizeof res, "ok");
    } else if (!strncmp(op, "fail:", 5)) {
        const char *w = op + 5;
        int *f = !strcmp(w, "integrity") ? &g_fail_integrity : !strcmp(w, "fips") ? &g_fail_fips
               : !strcmp(w, "base") ? &g_fail_base : !strcmp(w, "default") ? &g_fail_default
               : !strcmp(w, "props") ? &g_fail_props : !strcmp(w, "drbg") ? &g_fail_drbg
               : !strcmp(w, "kat") ? &g_fail_kat : !strcmp(w, "rand_status") ? &g_fail_rand_status : NULL;
        if (!f) { fprintf(stderr, "unknown fail %s\n", w); _exit(3); }
        *f = 1;
        snprintf(res, sizeof res, "ok");
    } else if (!strcmp(op, "state_error")) {
        g_state = FHSM_STATE_ERROR;
        snprintf(res, sizeof res, "ok");
    } else if (!strcmp(op, "init")) {
        snprintf(res, sizeof res, "rv=0x%x", fhsm_crypto_init());
    } else if (!strcmp(op, "finalize")) {
        fhsm_crypto_finalize();
        snprintf(res, sizeof res, "ok");
    } else if (!strcmp(op, "fips_mode")) {
        snprintf(res, sizeof res, "%d", fhsm_fips_mode());
    } else if (!strcmp(op, "kat_results")) {
        size_t n = 99;
        const fhsm_kat_result_t *k = fhsm_kat_results(&n);
        int len = snprintf(res, sizeof res, "count=%zu", n);
        for (size_t i = 0; i < n; i++)
            len += snprintf(res + len, sizeof res - (size_t)len, ";%s/%s/%d", k[i].algorithm,
                            k[i].vector_id, k[i].passed);
    } else {
        prim(op);
    }
    size_t len = strlen(res);
    if (g_trace[0]) snprintf(res + len, sizeof res - len, "%strace=%s", len ? ";" : "", g_trace);
    len = strlen(res);
    if (g_latch[0]) snprintf(res + len, sizeof res - len, ";latch=%s", g_latch);
    fprintf(tsv, "%s\t%s\t%s\n", sc, op_in, res);
}

static void scenario(const char *out, const char *name, const char *ops, const char **list) {
    fflush(tsv);
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid == 0) {
        char p[1024];
        snprintf(p, sizeof p, "%s/core/%s.stderr", out, name);
        /* dup2, not freopen: stderr stays unbuffered, as the module sees it. */
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0 || dup2(fd, 2) < 0) { perror(p); _exit(1); }
        unsetenv("FHSM_INTEGRITY_ALLOW_UNSIGNED");
        unsetenv("FHSM_KAT_ALLOW_FAIL");
        unsetenv("OPENSSL_CONF");
        if (ops) {
            char buf[1024];
            snprintf(buf, sizeof buf, "%s", ops);
            char *save = NULL;
            for (char *t = strtok_r(buf, " ", &save); t; t = strtok_r(NULL, " ", &save)) run_op(name, t);
        }
        for (; list && *list; list++) run_op(name, *list);
        fflush(tsv);
        _exit(0);
    }
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        fprintf(stderr, "scenario %s failed\n", name);
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "make")) {
        fprintf(stderr, "usage: gen_core make OUTDIR\n");
        return 2;
    }
    char p[1024];
    snprintf(p, sizeof p, "%s/core", argv[2]);
    mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/core.tsv", argv[2]);
    tsv = fopen(p, "w");
    if (!tsv) { perror(p); return 1; }
    fprintf(tsv, "# Generated by tests-support/golden/gen_core.c from the legacy C code. Do not edit.\n"
                 "# scenario\top\tresult  (crypto/tests/core_golden.rs)\n");
    for (size_t i = 0; i < sizeof SCEN / sizeof *SCEN; i++) scenario(argv[2], SCEN[i].name, SCEN[i].ops, NULL);
    scenario(argv[2], "prims", NULL, PRIMS);
    return fclose(tsv) == 0 ? 0 : 1;
}
