/* Phase 3 slice 5b: what the legacy X.509 encoders (src/fhsm_composite.c:482-1450) return and
 * write: the raw and SPKI forms of a composite key, PKCS#10 requests, self-signed roots and
 * issued certificates, composite and classic; (slice 5c, :1451-2128 and fhsm_pki_algid) CRLs,
 * OCSP SingleResponses, ResponseData and BasicOCSPResponses, and the AlgorithmIdentifier table;
 * and (slice 5d, :2129-2917) CMS SignedData, its verification, and fhsm_pki_ecdsa_raw_to_der.
 *
 *   gen_x509 <out dir>      writes x509.tsv and x509_fixture.tsv
 *
 * x509.tsv: one row per call, `name<TAB>rv=0x..;len=..;head=<first 8 bytes>;sha256=..;calls=..;
 * cap=..`. Output buffers are prefilled with 0xAA, so `head` shows whether a failed call wrote;
 * sha256 is over the output when the call succeeded. calls/cap are what the signing callback saw.
 *
 * Every signature in an output comes from FAKE: SHA-256 of the to-be-signed bytes, stretched to
 * the signer's length. The encoder treats a signature as opaque, so this pins every byte the
 * encoder produces and what it handed the signer. time() is defined below, so the validity
 * dates (X509_gmtime_adj inside libcrypto) are those of NOW. Requests that must pass proof of
 * possession are signed for real, and kept as inputs in x509_fixture.tsv with the keys' SPKIs,
 * the AlgorithmIdentifiers and the CA certificates; all are fresh test keys, not credentials.
 * CMS verification rows (`cmsv:`) give each structure to both verifiers and to
 * fhsm_pki_cms_digest; the structures are real (really signed, through the encoders) or
 * assembled from parts to reach one refusal each, and are kept in x509_fixture.tsv.
 * The Rust replay is pki/tests/x509_golden.rs. */
#include "fhsm_common.h"
#include "fhsm_composite.h"
#include "fhsm_pki.h"

#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ALG FHSM_COMPOSITE_MLDSA65_ED25519_SHA512
#define NOW ((time_t)1798761600) /* 2027-01-01T00:00:00Z, as gen_rev.c */

/* Interposes libc's time() for libcrypto too: the executable defines it and libcrypto refers
 * to it, so the dynamic linker binds libcrypto's call here. Default visibility, because the
 * legacy CFLAGS hide everything and a hidden symbol is not exported. */
__attribute__((visibility("default"))) time_t time(time_t *t) {
    if (t) *t = NOW;
    return NOW;
}

static FILE *f, *fx;

static void hex(FILE *o, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) fprintf(o, "%02x", p[i]);
}

static void fixture(const char *name, const uint8_t *p, size_t n) {
    fprintf(fx, "%s\t", name);
    hex(fx, p, n);
    fputc('\n', fx);
}

/* ---- the signing and RNG callbacks ------------------------------------- */

typedef struct { size_t len; fhsm_rv_t fail; unsigned calls; size_t cap; } fake_t;

static fhsm_rv_t fake_sign(void *ctx, const uint8_t *tbs, size_t n, uint8_t *sig, size_t *sl) {
    fake_t *c = ctx;
    c->calls++;
    c->cap = *sl;
    if (c->fail) return c->fail;
    uint8_t md[32];
    SHA256(tbs, n, md);
    for (size_t i = 0; i < c->len; ++i) sig[i] = md[i % 32] ^ (uint8_t)(i / 32);
    *sl = c->len;
    return FHSM_RV_OK;
}

typedef struct { int mode; } rng_t;    /* 0 pattern, 1 zeros, 2 ones, 3 fails */

static fhsm_rv_t rng(void *ctx, uint8_t *out, size_t n) {
    rng_t *r = ctx;
    if (r->mode == 3) return FHSM_RV_FUNCTION_FAILED;
    for (size_t i = 0; i < n; ++i)
        out[i] = r->mode == 1 ? 0 : r->mode == 2 ? 0xFF : (uint8_t)(i * 13 + 5);
    return FHSM_RV_OK;
}

static uint8_t PRIV[FHSM_COMPOSITE_PRIV_MAX], PUB[FHSM_COMPOSITE_PUB_MAX];
static size_t PRIV_LEN = sizeof PRIV, PUB_LEN = sizeof PUB;

static fhsm_rv_t comp_sign(void *ctx, const uint8_t *tbs, size_t n, uint8_t *sig, size_t *sl) {
    (void)ctx;
    return fhsm_composite_sign(ALG, PRIV, PRIV_LEN, tbs, n, NULL, 0, sig, sl);
}

typedef struct { EVP_PKEY *k; const char *md; } real_t;

static fhsm_rv_t real_sign(void *ctx, const uint8_t *tbs, size_t n, uint8_t *sig, size_t *sl) {
    real_t *r = ctx;
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    int ok = c && EVP_DigestSignInit_ex(c, NULL, r->md, NULL, NULL, r->k, NULL) == 1
          && EVP_DigestSign(c, sig, sl, tbs, n) == 1;
    EVP_MD_CTX_free(c);
    return ok ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

/* ---- rows ------------------------------------------------------------- */

static uint8_t OUT[32768];

static void row(const char *name, fhsm_rv_t rv, size_t len, const fake_t *s) {
    fprintf(f, "%s\trv=0x%x;len=%zu;head=", name, (unsigned)rv, len);
    hex(f, OUT, 8);
    fputs(";sha256=", f);
    if (rv == FHSM_RV_OK) {
        uint8_t md[32];
        SHA256(OUT, len, md);
        hex(f, md, 32);
    }
    fprintf(f, ";calls=%u;cap=%zu\n", s ? s->calls : 0, s ? s->cap : (size_t)0);
}

static uint8_t *dup_flip(const uint8_t *p, size_t n, size_t at, uint8_t x, size_t extra) {
    uint8_t *b = calloc(1, n + extra + 1);
    memcpy(b, p, n);
    if (at < n) b[at] ^= x;
    return b;
}

static uint8_t *der_of(EVP_PKEY *k, size_t *n) {
    uint8_t *d = NULL;
    int l = i2d_PUBKEY(k, &d);
    if (l <= 0) abort();
    *n = (size_t)l;
    return d;
}

static const uint8_t *algid(fhsm_pki_sigalg_t a, size_t *n) {
    const uint8_t *d = NULL;
    if (fhsm_pki_algid(a, &d, n) != FHSM_RV_OK) abort();
    return d;
}

/* ---- raw, SPKI, AlgorithmIdentifier, blob from raw ---------------------- */

static void key_cases(void) {
    size_t n;
#define RP(name, alg, p, pn, cap)                                                     \
    do {                                                                              \
        memset(OUT, 0xAA, sizeof OUT); n = (cap);                                     \
        { fhsm_rv_t r_ = fhsm_composite_raw_pub((alg), (p), (pn), OUT, &n); row("raw_pub:" name, r_, n, NULL); } \
    } while (0)
    uint8_t *b;
    RP("alg0", 0, PUB, PUB_LEN, 4096);
    RP("null_pub", ALG, NULL, PUB_LEN, 4096);
    RP("short_blob", ALG, PUB, 9, 4096);
    RP("short_blob_cap_short", ALG, PUB, 9, 10);
    b = dup_flip(PUB, PUB_LEN, 5, 3, 0); RP("other_alg", ALG, b, PUB_LEN, 4096); free(b);
    b = dup_flip(PUB, PUB_LEN, 8, 0xFF, 0); RP("bad_pq_der", ALG, b, PUB_LEN, 4096); free(b);
    b = dup_flip(PUB, PUB_LEN, PUB_LEN - 40, 0xFF, 0); RP("bad_trad_der", ALG, b, PUB_LEN, 4096); free(b);
    RP("priv_as_pub", ALG, PRIV, PRIV_LEN, 4096);
    RP("cap_0", ALG, PUB, PUB_LEN, 0);
    RP("cap_short", ALG, PUB, PUB_LEN, FHSM_COMPOSITE_RAW_PUB - 1);
    RP("cap_exact", ALG, PUB, PUB_LEN, FHSM_COMPOSITE_RAW_PUB);
    RP("cap_more", ALG, PUB, PUB_LEN, 4096);
    n = 4096;
    { fhsm_rv_t r_ = fhsm_composite_raw_pub(ALG, PUB, PUB_LEN, NULL, &n); row("raw_pub:null_out", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_composite_raw_pub(ALG, PUB, PUB_LEN, OUT, NULL); row("raw_pub:null_out_len", r_, 0, NULL); }

#define SP(name, alg, p, pn, cap)                                                     \
    do {                                                                              \
        memset(OUT, 0xAA, sizeof OUT); n = (cap);                                     \
        { fhsm_rv_t r_ = fhsm_composite_spki((alg), (p), (pn), OUT, &n); row("spki:" name, r_, n, NULL); }   \
    } while (0)
    SP("alg0", 0, PUB, PUB_LEN, 4096);
    SP("null_pub", ALG, NULL, PUB_LEN, 4096);
    SP("short_blob", ALG, PUB, 9, 4096);
    SP("cap_0", ALG, PUB, PUB_LEN, 0);
    SP("cap_short", ALG, PUB, PUB_LEN, 2000);
    SP("cap_exact", ALG, PUB, PUB_LEN, 2001);
    SP("cap_more", ALG, PUB, PUB_LEN, 4096);
    n = 4096;
    { fhsm_rv_t r_ = fhsm_composite_spki(ALG, PUB, PUB_LEN, NULL, &n); row("spki:null_out", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_composite_spki(ALG, PUB, PUB_LEN, OUT, NULL); row("spki:null_out_len", r_, 0, NULL); }

    const uint8_t *d = NULL;
    fhsm_rv_t r = fhsm_composite_algid(ALG, &d, &n);
    fprintf(f, "algid:ok\trv=0x%x;der=", (unsigned)r);
    hex(f, d, n);
    fputc('\n', f);
    fprintf(f, "algid:alg0\trv=0x%x\n", (unsigned)fhsm_composite_algid(0, &d, &n));
    fprintf(f, "algid:null_der\trv=0x%x\n", (unsigned)fhsm_composite_algid(ALG, NULL, &n));
    fprintf(f, "algid:null_len\trv=0x%x\n", (unsigned)fhsm_composite_algid(ALG, &d, NULL));

    uint8_t raw[FHSM_COMPOSITE_RAW_PUB], zeros[FHSM_COMPOSITE_RAW_PUB] = {0};
    n = sizeof raw;
    if (fhsm_composite_raw_pub(ALG, PUB, PUB_LEN, raw, &n) != FHSM_RV_OK) abort();
#define PR(name, alg, p, pn, cap)                                                     \
    do {                                                                              \
        memset(OUT, 0xAA, sizeof OUT); n = (cap);                                     \
        { fhsm_rv_t r_ = fhsm_composite_pub_from_raw((alg), (p), (pn), OUT, &n); row("pub_from_raw:" name, r_, n, NULL); } \
    } while (0)
    PR("alg0", 0, raw, sizeof raw, 4096);
    PR("null_raw", ALG, NULL, sizeof raw, 4096);
    PR("len_short", ALG, raw, sizeof raw - 1, 4096);
    PR("len_long", ALG, raw, sizeof raw + 1, 4096);
    PR("zeros", ALG, zeros, sizeof zeros, 4096);
    PR("cap_short", ALG, raw, sizeof raw, 100);
    PR("cap_exact", ALG, raw, sizeof raw, PUB_LEN);
    PR("ok", ALG, raw, sizeof raw, 4096);
    n = 4096;
    { fhsm_rv_t r_ = fhsm_composite_pub_from_raw(ALG, raw, sizeof raw, NULL, &n); row("pub_from_raw:null_pub", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_composite_pub_from_raw(ALG, raw, sizeof raw, OUT, NULL); row("pub_from_raw:null_pub_len", r_, 0, NULL); }
}

/* ---- PKCS#10 ---------------------------------------------------------- */

static const char *const SUBJECTS[][2] = {
    { "no_slash", "CN=x" },          { "slash", "/" },              { "no_eq", "/CN" },
    { "empty_field", "/=x" },        { "empty_value", "/CN=" },     { "trailing_slash", "/CN=a/" },
    { "eq_in_value", "/CN=a=b" },    { "three", "/C=FR/O=Simorgh Labs/CN=example" },
    { "unknown_field", "/XX=y" },    { "country_3", "/C=FRA" },     { "oid", "/2.5.4.3=by oid" },
    { "long_name", "/commonName=long" }, { "empty_middle", "/CN=a//O=b" },
    { "bad_utf8", "/CN=\xff\xfe" },  { "utf8", "/CN=\xc3\xa9t\xc3\xa9" },
    { "field_31", "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=x" },
    { "field_32", "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=x" },
    { "cn_64", "/CN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    { "cn_65", "/CN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    /* a dotted OID is a valid type of any length, so these two show where C's bound is */
    { "oid_31", "/1.3.6.1.4.1.55555.1.2.3.4.5.6.7=x" },
    { "oid_32", "/1.3.6.1.4.1.55555.1.2.3.4.5.6.78=x" },
};
#define N_SUBJECTS (sizeof SUBJECTS / sizeof SUBJECTS[0])

static void csr_cases(fhsm_pki_signer_t ed, fhsm_pki_signer_t ec, fhsm_pki_signer_t rsa,
                      fhsm_pki_signer_t ml, fhsm_pki_signer_t comp) {
    size_t n;
    char name[96];
    fake_t s;
#define CC(nm, alg, subj, pub, pn, cb, fk, cap)                                         \
    do {                                                                                \
        memset(OUT, 0xAA, sizeof OUT); n = (cap); s = (fk);                             \
        { fhsm_rv_t r_ = fhsm_composite_csr((alg), (subj), (pub), (pn), (cb), &s, OUT, &n); row(nm, r_, n, &s); } \
    } while (0)
    const fake_t F = { 3373, 0, 0, 0 };
    for (size_t i = 0; i < N_SUBJECTS; ++i) {
        snprintf(name, sizeof name, "csr:subj_%s", SUBJECTS[i][0]);
        CC(name, ALG, SUBJECTS[i][1], PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    }
    CC("csr:alg0", 0, "/CN=x", PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    CC("csr:null_subject", ALG, NULL, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    CC("csr:null_pub", ALG, "/CN=x", NULL, PUB_LEN, fake_sign, F, sizeof OUT);
    CC("csr:null_sign", ALG, "/CN=x", PUB, PUB_LEN, NULL, F, sizeof OUT);
    CC("csr:short_blob", ALG, "/CN=x", PUB, 9, fake_sign, F, sizeof OUT);
    CC("csr:sign_fails", ALG, "/CN=x", PUB, PUB_LEN, fake_sign, ((fake_t){ 3373, FHSM_RV_FUNCTION_FAILED, 0, 0 }), sizeof OUT);
    CC("csr:sign_too_small", ALG, "/CN=x", PUB, PUB_LEN, fake_sign, ((fake_t){ 3373, FHSM_RV_BUFFER_TOO_SMALL, 0, 0 }), sizeof OUT);
    CC("csr:sig_empty", ALG, "/CN=x", PUB, PUB_LEN, fake_sign, ((fake_t){ 0, 0, 0, 0 }), sizeof OUT);
    CC("csr:cap_0", ALG, "/CN=x", PUB, PUB_LEN, fake_sign, F, 0);
    CC("csr:ok", ALG, "/CN=x", PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    size_t ok_len = n;
    CC("csr:cap_short", ALG, "/CN=x", PUB, PUB_LEN, fake_sign, F, ok_len - 1);
    CC("csr:cap_exact", ALG, "/CN=x", PUB, PUB_LEN, fake_sign, F, ok_len);
    n = sizeof OUT; s = F;
    { fhsm_rv_t r_ = fhsm_composite_csr(ALG, "/CN=x", PUB, PUB_LEN, fake_sign, &s, NULL, &n); row("csr:null_out", r_, n, &s); }
    s = F;
    { fhsm_rv_t r_ = fhsm_composite_csr(ALG, "/CN=x", PUB, PUB_LEN, fake_sign, &s, OUT, NULL); row("csr:null_out_len", r_, 0, &s); }

    /* the generic builder, with each kind of key: absent parameters, a curve OID, a NULL */
#define PC(nm, sg, len, subj, cap)                                                      \
    do {                                                                                \
        memset(OUT, 0xAA, sizeof OUT); n = (cap); s = (fake_t){ (len), 0, 0, 0 };       \
        fhsm_pki_signer_t sg_ = (sg); sg_.sign_ctx = &s;                                \
        { fhsm_rv_t r_ = fhsm_pki_csr(&sg_, (subj), OUT, &n); row(nm, r_, n, &s); }                            \
    } while (0)
    PC("pki_csr:ed25519", ed, 64, "/CN=ed", sizeof OUT);
    PC("pki_csr:ec", ec, 72, "/O=ec/CN=ec", sizeof OUT);
    PC("pki_csr:rsa", rsa, 256, "/CN=rsa", sizeof OUT);
    PC("pki_csr:mldsa44", ml, 2420, "/CN=ml", sizeof OUT);
    PC("pki_csr:composite", comp, 3373, "/CN=comp", sizeof OUT);
    PC("pki_csr:bad_subject", ed, 64, "CN=ed", sizeof OUT);
    PC("pki_csr:cap_short", ed, 64, "/CN=ed", 100);
    fhsm_pki_signer_t t;
    t = ed; t.algid = NULL; PC("pki_csr:null_algid", t, 64, "/CN=ed", sizeof OUT);
    t = ed; t.algid_len = 0; PC("pki_csr:algid_len_0", t, 64, "/CN=ed", sizeof OUT);
    t = ed; t.sign = NULL; PC("pki_csr:null_sign", t, 64, "/CN=ed", sizeof OUT);
    t = ed; t.spki = NULL; PC("pki_csr:null_spki", t, 64, "/CN=ed", sizeof OUT);
    t = ed; t.spki_len = 0; PC("pki_csr:spki_len_0", t, 64, "/CN=ed", sizeof OUT);
    uint8_t *b = dup_flip(ed.spki, ed.spki_len, (size_t)-1, 0, 1);
    t = ed; t.spki = b; t.spki_len = ed.spki_len + 1; PC("pki_csr:spki_trailing", t, 64, "/CN=ed", sizeof OUT);
    t = ed; t.spki_len = 3; PC("pki_csr:spki_short", t, 64, "/CN=ed", sizeof OUT);
    free(b);
    b = dup_flip(ed.algid, ed.algid_len, (size_t)-1, 0, 1);
    t = ed; t.algid = b; t.algid_len = ed.algid_len + 1; PC("pki_csr:algid_trailing", t, 64, "/CN=ed", sizeof OUT);
    t = ed; t.algid_len = 2; PC("pki_csr:algid_short", t, 64, "/CN=ed", sizeof OUT);
    free(b);
    t = ed; t.sign_ctx = &s; n = sizeof OUT;
    { fhsm_rv_t r_ = fhsm_pki_csr(NULL, "/CN=ed", OUT, &n); row("pki_csr:null_signer", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_pki_csr(&t, NULL, OUT, &n); row("pki_csr:null_subject", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_pki_csr(&t, "/CN=ed", NULL, &n); row("pki_csr:null_out", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_pki_csr(&t, "/CN=ed", OUT, NULL); row("pki_csr:null_out_len", r_, 0, NULL); }
}

/* ---- self-signed roots ------------------------------------------------ */

static uint8_t CA_COMP[16384], CA_ED[4096];
static size_t CA_COMP_LEN, CA_ED_LEN;
static uint8_t CA_NOSKID[4096];
static size_t CA_NOSKID_LEN;

static void selfsigned_cases(fhsm_pki_signer_t ed, fhsm_pki_signer_t ec, fhsm_pki_signer_t rsa,
                             fhsm_pki_signer_t ml) {
    size_t n;
    fake_t s;
    const fake_t F = { 3373, 0, 0, 0 };
#define SS(nm, alg, subj, ser, days, pub, pn, cb, fk, cap)                              \
    do {                                                                                \
        memset(OUT, 0xAA, sizeof OUT); n = (cap); s = (fk);                             \
        { fhsm_rv_t r_ = fhsm_composite_selfsigned((alg), (subj), (ser), (days), (pub), (pn), (cb), &s, OUT, &n); row(nm, r_, n, &s); } \
    } while (0)
    SS("selfsigned:ok", ALG, "/O=pqHSM goldens/CN=composite root", 1, 3650, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    memcpy(CA_COMP, OUT, n); CA_COMP_LEN = n;
    size_t ok_len = n;
    SS("selfsigned:alg0", 0, "/CN=r", 1, 30, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:null_subject", ALG, NULL, 1, 30, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:null_pub", ALG, "/CN=r", 1, 30, NULL, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:null_sign", ALG, "/CN=r", 1, 30, PUB, PUB_LEN, NULL, F, sizeof OUT);
    SS("selfsigned:serial_0", ALG, "/CN=r", 0, 30, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:serial_neg", ALG, "/CN=r", -1, 30, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:serial_max", ALG, "/CN=r", LONG_MAX, 30, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:days_0", ALG, "/CN=r", 1, 0, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:days_neg", ALG, "/CN=r", 1, -1, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:days_1", ALG, "/CN=r", 1, 1, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:days_50y", ALG, "/CN=r", 1, 18263, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:days_max", ALG, "/CN=r", 1, INT_MAX, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:bad_subject", ALG, "/CN=", 1, 30, PUB, PUB_LEN, fake_sign, F, sizeof OUT);
    SS("selfsigned:short_blob", ALG, "/CN=r", 1, 30, PUB, 9, fake_sign, F, sizeof OUT);
    SS("selfsigned:sign_fails", ALG, "/CN=r", 1, 30, PUB, PUB_LEN, fake_sign, ((fake_t){ 3373, FHSM_RV_FUNCTION_FAILED, 0, 0 }), sizeof OUT);
    SS("selfsigned:cap_0", ALG, "/O=pqHSM goldens/CN=composite root", 1, 3650, PUB, PUB_LEN, fake_sign, F, 0);
    SS("selfsigned:cap_short", ALG, "/O=pqHSM goldens/CN=composite root", 1, 3650, PUB, PUB_LEN, fake_sign, F, ok_len - 1);
    SS("selfsigned:cap_exact", ALG, "/O=pqHSM goldens/CN=composite root", 1, 3650, PUB, PUB_LEN, fake_sign, F, ok_len);
    n = sizeof OUT; s = F;
    { fhsm_rv_t r_ = fhsm_composite_selfsigned(ALG, "/CN=r", 1, 30, PUB, PUB_LEN, fake_sign, &s, NULL, &n); row("selfsigned:null_out", r_, n, &s); }
    s = F;
    { fhsm_rv_t r_ = fhsm_composite_selfsigned(ALG, "/CN=r", 1, 30, PUB, PUB_LEN, fake_sign, &s, OUT, NULL); row("selfsigned:null_out_len", r_, 0, &s); }

#define PS(nm, sg, len, subj, ser, days, cap)                                           \
    do {                                                                                \
        memset(OUT, 0xAA, sizeof OUT); n = (cap); s = (fake_t){ (len), 0, 0, 0 };       \
        fhsm_pki_signer_t sg_ = (sg); sg_.sign_ctx = &s;                                \
        { fhsm_rv_t r_ = fhsm_pki_selfsigned(&sg_, (subj), (ser), (days), OUT, &n); row(nm, r_, n, &s); }      \
    } while (0)
    PS("pki_selfsigned:ed25519", ed, 64, "/CN=ed root", 2, 365, sizeof OUT);
    memcpy(CA_ED, OUT, n); CA_ED_LEN = n;
    PS("pki_selfsigned:ec", ec, 72, "/CN=ec root", 3, 365, sizeof OUT);
    PS("pki_selfsigned:rsa", rsa, 256, "/CN=rsa root", 4, 365, sizeof OUT);
    PS("pki_selfsigned:mldsa44", ml, 2420, "/CN=ml root", 5, 365, sizeof OUT);
    PS("pki_selfsigned:serial_0", ed, 64, "/CN=ed root", 0, 365, sizeof OUT);
    PS("pki_selfsigned:days_0", ed, 64, "/CN=ed root", 2, 0, sizeof OUT);
    PS("pki_selfsigned:bad_subject", ed, 64, "/", 2, 365, sizeof OUT);
    PS("pki_selfsigned:cap_short", ed, 64, "/CN=ed root", 2, 365, 10);
    fhsm_pki_signer_t t;
    t = ed; t.spki = NULL; PS("pki_selfsigned:null_spki", t, 64, "/CN=ed root", 2, 365, sizeof OUT);
    t = ed; t.algid_len = 0; PS("pki_selfsigned:algid_len_0", t, 64, "/CN=ed root", 2, 365, sizeof OUT);
    t = ed; t.algid_len = 2; PS("pki_selfsigned:algid_short", t, 64, "/CN=ed root", 2, 365, sizeof OUT);
    t = ed; t.spki_len = 3; PS("pki_selfsigned:spki_short", t, 64, "/CN=ed root", 2, 365, sizeof OUT);
}

/* ---- issuance --------------------------------------------------------- */

static void issue_cases(fhsm_pki_signer_t ed, fhsm_pki_signer_t comp, EVP_PKEY *ked, EVP_PKEY *kec) {
    size_t n;
    fake_t s;
    rng_t rg;
    const fake_t F = { 3373, 0, 0, 0 };

    /* requests that must pass proof of possession, signed for real */
    static uint8_t CSR_COMP[16384], CSR_ED[4096], CSR_EC[4096], CSR_X1[16384], CSR_X2[16384];
    size_t csr_comp = sizeof CSR_COMP, csr_ed = sizeof CSR_ED, csr_ec = sizeof CSR_EC;
    size_t csr_x1 = sizeof CSR_X1, csr_x2 = sizeof CSR_X2;
    if (fhsm_composite_csr(ALG, "/O=pqHSM goldens/CN=composite applicant", PUB, PUB_LEN, comp_sign, NULL, CSR_COMP, &csr_comp) != FHSM_RV_OK) abort();
    real_t red = { ked, NULL }, rec = { kec, "SHA256" };
    fhsm_pki_signer_t t = ed; t.sign = real_sign; t.sign_ctx = &red;
    if (fhsm_pki_csr(&t, "/CN=ed applicant", CSR_ED, &csr_ed) != FHSM_RV_OK) abort();
    size_t al = 0, sl = 0;
    const uint8_t *ecalg = algid(FHSM_PKI_SIG_ECDSA_SHA256, &al);
    uint8_t *ecspki = der_of(kec, &sl);
    t = (fhsm_pki_signer_t){ ecalg, al, ecspki, sl, real_sign, &rec };
    if (fhsm_pki_csr(&t, "/CN=ec applicant", CSR_EC, &csr_ec) != FHSM_RV_OK) abort();
    /* a composite signature over an Ed25519 key, and an Ed25519 signature over a composite key */
    fake_t s1 = { 3373, 0, 0, 0 }, s2 = { 64, 0, 0, 0 };
    t = (fhsm_pki_signer_t){ comp.algid, comp.algid_len, ed.spki, ed.spki_len, fake_sign, &s1 };
    if (fhsm_pki_csr(&t, "/CN=x1", CSR_X1, &csr_x1) != FHSM_RV_OK) abort();
    t = (fhsm_pki_signer_t){ ed.algid, ed.algid_len, comp.spki, comp.spki_len, fake_sign, &s2 };
    if (fhsm_pki_csr(&t, "/CN=x2", CSR_X2, &csr_x2) != FHSM_RV_OK) abort();
    uint8_t *csr_comp_bad = dup_flip(CSR_COMP, csr_comp, csr_comp - 1, 1, 0);
    uint8_t *csr_ed_bad = dup_flip(CSR_ED, csr_ed, csr_ed - 1, 1, 0);

    /* a CA certificate without a subjectKeyIdentifier */
    X509 *x = X509_new();
    X509_NAME *nm = X509_NAME_new();
    if (!x || !nm || X509_set_version(x, 2) != 1 || ASN1_INTEGER_set(X509_get_serialNumber(x), 7) != 1
        || !X509_gmtime_adj(X509_getm_notBefore(x), 0) || !X509_gmtime_adj(X509_getm_notAfter(x), 86400)
        || X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"no skid CA", -1, -1, 0) != 1
        || X509_set_subject_name(x, nm) != 1 || X509_set_issuer_name(x, nm) != 1
        || X509_set_pubkey(x, ked) != 1 || X509_sign(x, ked, NULL) <= 0) abort();
    uint8_t *ca_noskid = NULL;
    int ca_noskid_len = i2d_X509(x, &ca_noskid);
    if (ca_noskid_len <= 0) abort();
    X509_NAME_free(nm);
    X509_free(x);

    fixture("csr_comp", CSR_COMP, csr_comp);
    fixture("csr_ed", CSR_ED, csr_ed);
    fixture("csr_ec", CSR_EC, csr_ec);
    fixture("csr_comp_sig_ed_key", CSR_X1, csr_x1);
    fixture("csr_ed_sig_comp_key", CSR_X2, csr_x2);
    fixture("ca_noskid", ca_noskid, (size_t)ca_noskid_len);
    if ((size_t)ca_noskid_len > sizeof CA_NOSKID) abort();
    memcpy(CA_NOSKID, ca_noskid, (size_t)ca_noskid_len);
    CA_NOSKID_LEN = (size_t)ca_noskid_len;
    fixture("ca_comp", CA_COMP, CA_COMP_LEN);
    fixture("ca_ed", CA_ED, CA_ED_LEN);

    const char *const crl2[] = { "http://c.example/ca.crl", "ldap://l.example/cn=CA?certificateRevocationList" };
#define CI(nm, alg, ca, can, csr, csn, subj, san, urls, nu, prof, days, sg, fk, rm, cap)  \
    do {                                                                                 \
        memset(OUT, 0xAA, sizeof OUT); n = (cap); s = (fk); rg = (rng_t){ (rm) };        \
        { fhsm_rv_t r_ = fhsm_composite_issue((alg), (ca), (can), (csr), (csn), (subj), (san), (urls), (nu), \
                                     (prof), (days), (sg), &s, rng, &rg, OUT, &n); row(nm, r_, n, &s); } \
    } while (0)
#define OK(nm, csr, csn, subj, san, urls, nu, prof, rm)                                  \
    CI(nm, ALG, CA_COMP, CA_COMP_LEN, (csr), (csn), (subj), (san), (urls), (nu), (prof), 365, fake_sign, F, (rm), sizeof OUT)
    OK("issue:ok", CSR_COMP, csr_comp, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 0);
    size_t ok_len = n;
    OK("issue:ed_applicant", CSR_ED, csr_ed, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 0);
    OK("issue:ec_applicant", CSR_EC, csr_ec, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 0);
    OK("issue:csr_trailing_byte", CSR_COMP, csr_comp + 1, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 0);
    OK("issue:pop_comp_bad_sig", csr_comp_bad, csr_comp, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 0);
    OK("issue:pop_ed_bad_sig", csr_ed_bad, csr_ed, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 0);
    OK("issue:pop_comp_sig_ed_key", CSR_X1, csr_x1, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 0);
    OK("issue:pop_ed_sig_comp_key", CSR_X2, csr_x2, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 0);
    OK("issue:rng_zeros", CSR_COMP, csr_comp, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 1);
    OK("issue:rng_ones", CSR_COMP, csr_comp, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 2);
    OK("issue:rng_fails", CSR_COMP, csr_comp, NULL, NULL, NULL, 0, FHSM_CERT_END_ENTITY, 3);
    OK("issue:subject_override", CSR_COMP, csr_comp, "/O=override/CN=renamed", NULL, NULL, 0, FHSM_CERT_END_ENTITY, 0);
    OK("issue:subject_override_bad", CSR_COMP, csr_comp, "/CN=", NULL, NULL, 0, FHSM_CERT_END_ENTITY, 0);
    OK("issue:ocsp_responder", CSR_COMP, csr_comp, NULL, NULL, NULL, 0, FHSM_CERT_OCSP_RESPONDER, 0);
    OK("issue:profile_7", CSR_COMP, csr_comp, NULL, NULL, NULL, 0, (fhsm_cert_profile_t)7, 0);
    OK("issue:crl_2", CSR_COMP, csr_comp, NULL, NULL, crl2, 2, FHSM_CERT_END_ENTITY, 0);
    OK("issue:crl_n_0", CSR_COMP, csr_comp, NULL, NULL, crl2, 0, FHSM_CERT_END_ENTITY, 0);
    OK("issue:everything", CSR_COMP, csr_comp, "/CN=all", "DNS:all.example,IP:192.0.2.7", crl2, 2, FHSM_CERT_OCSP_RESPONDER, 0);

    static const char *const SANS[][2] = {
        { "one", "DNS:a.example" },
        { "mixed", "DNS:a.example, IP:192.0.2.1,\temail:x@y.example ,URI:http://u.example/p, IP:2001:db8::1" },
        { "trailing_comma", "DNS:a," },       { "empty", "" },            { "empty_item", "DNS:a,,DNS:b" },
        { "blank_item", "DNS:a, ,DNS:b" },    { "unknown_type", "FOO:x" }, { "lower_type", "dns:a" },
        { "no_type", ":x" },                  { "no_value", "DNS:" },     { "no_colon", "DNS" },
        { "bad_ipv4", "IP:999.1.1.1" },       { "short_ipv4", "IP:1.2.3" }, { "bad_ipv6", "IP:2001:db8::g" },
        { "space_in_value", "DNS:a b" },      { "colon_in_value", "URI:urn:x:y" },
        { "non_ascii", "email:\xc3\xa9@x" },
    };
    char name[96];
    for (size_t i = 0; i < sizeof SANS / sizeof SANS[0]; ++i) {
        snprintf(name, sizeof name, "issue:san_%s", SANS[i][0]);
        OK(name, CSR_COMP, csr_comp, NULL, SANS[i][1], NULL, 0, FHSM_CERT_END_ENTITY, 0);
    }
    char long_san[600] = "DNS:";
    memset(long_san + 4, 'a', 507);             /* an item of 511 bytes */
    OK("issue:san_item_511", CSR_COMP, csr_comp, NULL, long_san, NULL, 0, FHSM_CERT_END_ENTITY, 0);
    long_san[4 + 507] = 'a';                    /* 512 */
    OK("issue:san_item_512", CSR_COMP, csr_comp, NULL, long_san, NULL, 0, FHSM_CERT_END_ENTITY, 0);

    static const char *const URLS[][2] = {
        { "http_short", "http://x" },  { "https", "https://c.example/ca.crl" }, { "http_empty", "http://" },
        { "ldap_no_attr", "ldap://x" }, { "ldap_empty_attr", "ldap://x?" },   { "ldap_attr", "ldap://x?a" },
        { "tab", "http://a\tb" },      { "del", "http://\x7f" },            { "non_ascii", "http://\xc3\xa9" },
        { "upper_scheme", "HTTP://x" }, { "ftp", "ftp://x" },
    };
    for (size_t i = 0; i < sizeof URLS / sizeof URLS[0]; ++i) {
        snprintf(name, sizeof name, "issue:crl_%s", URLS[i][0]);
        OK(name, CSR_COMP, csr_comp, NULL, NULL, &URLS[i][1], 1, FHSM_CERT_END_ENTITY, 0);
    }
    const char *const crl_null[] = { "http://ok.example", NULL };
    OK("issue:crl_null_entry", CSR_COMP, csr_comp, NULL, NULL, crl_null, 2, FHSM_CERT_END_ENTITY, 0);
    const char *const crl_bad2[] = { "http://ok.example", "ftp://x" };
    OK("issue:crl_second_bad", CSR_COMP, csr_comp, NULL, NULL, crl_bad2, 2, FHSM_CERT_END_ENTITY, 0);

    CI("issue:ca_noskid", ALG, ca_noskid, (size_t)ca_noskid_len, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, F, 0, sizeof OUT);
    CI("issue:ca_ed", ALG, CA_ED, CA_ED_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, F, 0, sizeof OUT);
    CI("issue:ca_garbage", ALG, CSR_ED, 20, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, F, 0, sizeof OUT);
    CI("issue:csr_garbage", ALG, CA_COMP, CA_COMP_LEN, CA_COMP, 20, NULL, NULL, NULL, 0, 0, 365, fake_sign, F, 0, sizeof OUT);
    CI("issue:csr_is_cert", ALG, CA_COMP, CA_COMP_LEN, CA_COMP, CA_COMP_LEN, NULL, NULL, NULL, 0, 0, 365, fake_sign, F, 0, sizeof OUT);
    CI("issue:alg0", 0, CA_COMP, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, F, 0, sizeof OUT);
    CI("issue:days_0", ALG, CA_COMP, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 0, fake_sign, F, 0, sizeof OUT);
    CI("issue:days_max", ALG, CA_COMP, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, INT_MAX, fake_sign, F, 0, sizeof OUT);
    CI("issue:null_ca", ALG, NULL, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, F, 0, sizeof OUT);
    CI("issue:null_csr", ALG, CA_COMP, CA_COMP_LEN, NULL, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, F, 0, sizeof OUT);
    CI("issue:null_sign", ALG, CA_COMP, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, NULL, F, 0, sizeof OUT);
    CI("issue:sign_fails", ALG, CA_COMP, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, ((fake_t){ 3373, FHSM_RV_FUNCTION_FAILED, 0, 0 }), 0, sizeof OUT);
    CI("issue:cap_0", ALG, CA_COMP, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, F, 0, 0);
    CI("issue:cap_short", ALG, CA_COMP, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, F, 0, ok_len - 1);
    CI("issue:cap_exact", ALG, CA_COMP, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, F, 0, ok_len);
    n = sizeof OUT; s = F; rg.mode = 0;
    { fhsm_rv_t r_ = fhsm_composite_issue(ALG, CA_COMP, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, &s, NULL, &rg, OUT, &n); row("issue:null_rng", r_, n, &s); }
    { fhsm_rv_t r_ = fhsm_composite_issue(ALG, CA_COMP, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, &s, rng, &rg, NULL, &n); row("issue:null_out", r_, n, &s); }
    { fhsm_rv_t r_ = fhsm_composite_issue(ALG, CA_COMP, CA_COMP_LEN, CSR_COMP, csr_comp, NULL, NULL, NULL, 0, 0, 365, fake_sign, &s, rng, &rg, OUT, NULL); row("issue:null_out_len", r_, 0, &s); }

    /* the generic issuer: an Ed25519 CA */
#define PI(nm, sg, len, csr, csn, days)                                                  \
    do {                                                                                 \
        memset(OUT, 0xAA, sizeof OUT); n = sizeof OUT; s = (fake_t){ (len), 0, 0, 0 }; rg.mode = 0; \
        fhsm_pki_signer_t u = (sg); u.sign_ctx = &s;                                     \
        { fhsm_rv_t r_ = fhsm_pki_issue(&u, CA_ED, CA_ED_LEN, (csr), (csn), NULL, NULL, NULL, 0,  \
                               FHSM_CERT_END_ENTITY, (days), rng, &rg, OUT, &n); row(nm, r_, n, &s); } \
    } while (0)
    PI("pki_issue:ed_ca_comp_applicant", ed, 64, CSR_COMP, csr_comp, 90);
    PI("pki_issue:ed_ca_ed_applicant", ed, 64, CSR_ED, csr_ed, 90);
    PI("pki_issue:days_neg", ed, 64, CSR_ED, csr_ed, -1);
    t = ed; t.spki = NULL;
    PI("pki_issue:no_spki", t, 64, CSR_ED, csr_ed, 90);
    t = ed; t.algid = NULL;
    PI("pki_issue:null_algid", t, 64, CSR_ED, csr_ed, 90);
    t = ed; t.algid_len = 2;
    PI("pki_issue:algid_short", t, 64, CSR_ED, csr_ed, 90);

    free(csr_comp_bad);
    free(csr_ed_bad);
    OPENSSL_free(ecspki);
    OPENSSL_free(ca_noskid);
}

/* ---- CRL and OCSP (slice 5c, src/fhsm_composite.c:1451-2128) ------------------------- */

static const uint8_t GT[] = { 0x18, 0x0F, '2', '0', '2', '7', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z' };
static const uint8_t GT2[] = { 0x18, 0x0F, '2', '0', '2', '7', '0', '1', '0', '8', '0', '0', '0', '0', '0', '0', 'Z' };
static const uint8_t UT[] = { 0x17, 0x0D, '2', '7', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z' };
/* 24 bytes: the longest revocationTime C takes */
static const uint8_t GT24[] = { 0x18, 0x16, '2', '0', '2', '7', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0',
                                '.', '1', '2', '3', '4', '5', '6', 'Z' };
static const uint8_t GT25[] = { 0x18, 0x17, '2', '0', '2', '7', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0',
                                '.', '1', '2', '3', '4', '5', '6', '7', 'Z' };
static const uint8_t CERT_ID[] = { 0x30, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03 };
static const uint8_t NAME0[] = { 0x30, 0x00 };
static const uint8_t SEQ5[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
static const uint8_t BYKEY[] = { 0xA2, 0x16, 0x04, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

static uint8_t *big(size_t n, uint8_t tag) {
    uint8_t *b = calloc(1, n);
    if (!b) abort();
    b[0] = tag;
    return b;
}

static void algid_cases(void) {
    for (int a = -1; a <= 9; ++a) {
        const uint8_t *d = NULL; size_t n = 0;
        fhsm_rv_t r = fhsm_pki_algid((fhsm_pki_sigalg_t)a, &d, &n);
        fprintf(f, "pki_algid:%d\trv=0x%x;der=", a, (unsigned)r);
        if (r == FHSM_RV_OK) hex(f, d, n);
        fputc('\n', f);
    }
    const uint8_t *d = NULL; size_t n = 0;
    fprintf(f, "pki_algid:null_der\trv=0x%x\n", (unsigned)fhsm_pki_algid(FHSM_PKI_SIG_ED25519, NULL, &n));
    fprintf(f, "pki_algid:null_len\trv=0x%x\n", (unsigned)fhsm_pki_algid(FHSM_PKI_SIG_ED25519, &d, NULL));
}

static void crl_tbs_cases(const uint8_t *al, size_t aln) {
    size_t n;
#define CT(nm, a, an, i, in, t, tn, x, xn, r, rn, e, en, cap)                                     \
    do {                                                                                          \
        memset(OUT, 0xAA, sizeof OUT); n = (cap);                                                 \
        { fhsm_rv_t r_ = fhsm_composite_crl_tbs((a), (an), (i), (in), (t), (tn), (x), (xn), (r), (rn), \
                                                (e), (en), OUT, &n); row(nm, r_, n, NULL); }      \
    } while (0)
#define CTA(nm, ...) CT(nm, __VA_ARGS__, sizeof OUT)
    CTA("crl_tbs:minimal", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0);
    CTA("crl_tbs:all", al, aln, NAME0, 2, UT, sizeof UT, GT2, sizeof GT2, SEQ5, 5, SEQ5, 5);
    CTA("crl_tbs:generalized_this", al, aln, NAME0, 2, GT, sizeof GT, UT, sizeof UT, NULL, 0, NULL, 0);
    CTA("crl_tbs:null_algid", NULL, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0);
    CTA("crl_tbs:algid_len_0", al, 0, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0);
    CTA("crl_tbs:null_issuer", al, aln, NULL, 2, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0);
    CTA("crl_tbs:issuer_len_0", al, aln, NAME0, 0, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0);
    CTA("crl_tbs:null_this", al, aln, NAME0, 2, NULL, sizeof UT, NULL, 0, NULL, 0, NULL, 0);
    CTA("crl_tbs:this_len_0", al, aln, NAME0, 2, UT, 0, NULL, 0, NULL, 0, NULL, 0);
    CTA("crl_tbs:next_ptr_no_len", al, aln, NAME0, 2, UT, sizeof UT, GT2, 0, NULL, 0, NULL, 0);
    CTA("crl_tbs:next_len_no_ptr", al, aln, NAME0, 2, UT, sizeof UT, NULL, 3, NULL, 0, NULL, 0);
    CTA("crl_tbs:revoked_ptr_no_len", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, SEQ5, 0, NULL, 0);
    CTA("crl_tbs:revoked_len_no_ptr", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 5, NULL, 0);
    CTA("crl_tbs:exts_ptr_no_len", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, SEQ5, 0);
    CTA("crl_tbs:exts_len_no_ptr", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 5);
    CTA("crl_tbs:algid_tag", UT, sizeof UT, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0);
    CTA("crl_tbs:issuer_tag", al, aln, UT, sizeof UT, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0);
    CTA("crl_tbs:this_tag", al, aln, NAME0, 2, NAME0, 2, NULL, 0, NULL, 0, NULL, 0);
    CTA("crl_tbs:next_tag", al, aln, NAME0, 2, UT, sizeof UT, NAME0, 2, NULL, 0, NULL, 0);
    CTA("crl_tbs:revoked_tag", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, UT, sizeof UT, NULL, 0);
    CTA("crl_tbs:exts_tag", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, UT, sizeof UT);
    CT("crl_tbs:cap_0", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0, 0);
    CT("crl_tbs:cap_short", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0, 28);
    CT("crl_tbs:cap_exact", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0, 29);
    /* der_len's three octets: content 0xFFFFFF fits, one more does not (cap 1 reports the size) */
    size_t fixed = 3 + aln + 2 + sizeof UT + 1 + 4;
    uint8_t *e = big(0xFFFFFF - fixed + 1, 0x30);
    CT("crl_tbs:content_max", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, e, 0xFFFFFF - fixed, 1);
    CT("crl_tbs:content_max_plus_1", al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, e, 0xFFFFFF - fixed + 1, 1);
    free(e);
    n = 64;
    { fhsm_rv_t r_ = fhsm_composite_crl_tbs(al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0, NULL, &n);
      row("crl_tbs:null_out", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_composite_crl_tbs(al, aln, NAME0, 2, UT, sizeof UT, NULL, 0, NULL, 0, NULL, 0, OUT, NULL);
      row("crl_tbs:null_out_len", r_, 0, NULL); }
}

static void crl_cases(fhsm_pki_signer_t ed, EVP_PKEY *ked) {
    size_t n;
    fake_t s;
    const fake_t F = { 3373, 0, 0, 0 };
    static const uint8_t S1[] = { 0x01 }, S80[] = { 0x80 }, S005[] = { 0x00, 0x00, 0x05 }, S0[] = { 0x00 };
    static const uint8_t SFF[20] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                     0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
#define RC(nm, alg, ca, can, rv_, nr, num, days, sg, fk, cap)                                    \
    do {                                                                                         \
        memset(OUT, 0xAA, sizeof OUT); n = (cap); s = (fk);                                      \
        { fhsm_rv_t r_ = fhsm_composite_crl((alg), (ca), (can), (rv_), (nr), (num), (days), (sg), &s, OUT, &n); \
          row(nm, r_, n, &s); }                                                                  \
    } while (0)
#define CO(nm, rv_, nr, num, days) RC(nm, ALG, CA_COMP, CA_COMP_LEN, (rv_), (nr), (num), (days), fake_sign, F, sizeof OUT)
    const fhsm_composite_revoked_t one[] = { { S1, 1, 1798675200, -1 } };
    CO("crl:empty", NULL, 0, 1, 7);
    CO("crl:one", one, 1, 2, 7);
    const fhsm_composite_revoked_t serials[] = {
        { S1, 1, 0, -1 }, { S80, 1, 0, -1 }, { S005, 3, 0, -1 }, { S0, 1, 0, -1 }, { SFF, 20, 0, -1 },
    };
    CO("crl:serials", serials, 5, 3, 7);
    fhsm_composite_revoked_t reasons[16];
    int rs[] = { -1, 0, 1, 2, 3, 4, 5, 6, 9, 10, -5 };
    for (size_t i = 0; i < 11; ++i) reasons[i] = (fhsm_composite_revoked_t){ S1, 1, 1798675200, rs[i] };
    CO("crl:reasons", reasons, 11, 4, 7);
    int bad[] = { 7, 8, 11, 0x7fffffff };
    for (size_t i = 0; i < 4; ++i) {
        char nm[64];
        snprintf(nm, sizeof nm, "crl:reason_%d", bad[i]);
        const fhsm_composite_revoked_t b[] = { { S1, 1, 0, -1 }, { S80, 1, 0, bad[i] } };
        CO(nm, b, 2, 5, 7);
    }
    const struct { const char *nm; int64_t t; } dates[] = {
        { "crl:date_0", 0 }, { "crl:date_neg_1", -1 }, { "crl:date_1949", -631152001 },
        { "crl:date_1950", -631152000 }, { "crl:date_2049", 2524607999 }, { "crl:date_2050", 2524608000 },
        { "crl:date_9999", 253402300799 }, { "crl:date_10000", 253402300800 }, { "crl:date_min", INT64_MIN },
    };
    for (size_t i = 0; i < sizeof dates / sizeof *dates; ++i) {
        const fhsm_composite_revoked_t d[] = { { S1, 1, dates[i].t, -1 } };
        CO(dates[i].nm, d, 1, 6, 7);
    }
    const fhsm_composite_revoked_t nul[] = { { S1, 1, 0, -1 }, { NULL, 3, 0, -1 } };
    CO("crl:null_serial", nul, 2, 7, 7);
    const fhsm_composite_revoked_t zero[] = { { S1, 0, 0, -1 } };
    CO("crl:serial_len_0", zero, 1, 7, 7);
    const uint64_t nums[] = { 0, 127, 128, 255, 256, 0x8000000000000000ull, UINT64_MAX };
    for (size_t i = 0; i < sizeof nums / sizeof *nums; ++i) {
        char nm[64];
        snprintf(nm, sizeof nm, "crl:number_%zu", i);
        CO(nm, NULL, 0, nums[i], 7);
    }
    CO("crl:days_1", NULL, 0, 1, 1);
    CO("crl:days_36500", NULL, 0, 1, 36500);
    CO("crl:days_max", NULL, 0, 1, INT_MAX);
    CO("crl:days_0", NULL, 0, 1, 0);
    CO("crl:days_neg", NULL, 0, 1, -1);
    CO("crl:n_without_list", NULL, 2, 1, 7);
    RC("crl:ca_noskid", ALG, CA_NOSKID, CA_NOSKID_LEN, one, 1, 1, 7, fake_sign, F, sizeof OUT);
    RC("crl:ca_ed", ALG, CA_ED, CA_ED_LEN, one, 1, 1, 7, fake_sign, F, sizeof OUT);
    /* a 490-byte subjectKeyIdentifier: authorityKeyIdentifier and crlNumber past C's 512 */
    {
        static uint8_t id[490];
        memset(id, 0x5A, sizeof id);
        X509 *x = X509_new();
        X509_NAME *nm = X509_NAME_new();
        ASN1_OCTET_STRING *o = ASN1_OCTET_STRING_new();
        if (!x || !nm || !o || ASN1_OCTET_STRING_set(o, id, (int)sizeof id) != 1 || X509_set_version(x, 2) != 1
            || ASN1_INTEGER_set(X509_get_serialNumber(x), 8) != 1
            || !X509_gmtime_adj(X509_getm_notBefore(x), 0) || !X509_gmtime_adj(X509_getm_notAfter(x), 86400)
            || X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char *)"long skid CA", -1, -1, 0) != 1
            || X509_set_subject_name(x, nm) != 1 || X509_set_issuer_name(x, nm) != 1
            || X509_add1_ext_i2d(x, NID_subject_key_identifier, o, 0, 0) != 1
            || X509_set_pubkey(x, ked) != 1 || X509_sign(x, ked, NULL) <= 0) abort();
        uint8_t *d = NULL;
        int dn = i2d_X509(x, &d);
        if (dn <= 0) abort();
        fixture("ca_long_skid", d, (size_t)dn);
        RC("crl:ca_long_skid", ALG, d, (size_t)dn, one, 1, 1, 7, fake_sign, F, sizeof OUT);
        OPENSSL_free(d);
        ASN1_OCTET_STRING_free(o);
        X509_NAME_free(nm);
        X509_free(x);
    }
    RC("crl:ca_garbage", ALG, CA_ED, 20, one, 1, 1, 7, fake_sign, F, sizeof OUT);
    RC("crl:ca_len_0", ALG, CA_ED, 0, one, 1, 1, 7, fake_sign, F, sizeof OUT);
    RC("crl:null_ca", ALG, NULL, 10, one, 1, 1, 7, fake_sign, F, sizeof OUT);
    RC("crl:alg0", 0, CA_COMP, CA_COMP_LEN, one, 1, 1, 7, fake_sign, F, sizeof OUT);
    RC("crl:null_sign", ALG, CA_COMP, CA_COMP_LEN, one, 1, 1, 7, NULL, F, sizeof OUT);
    RC("crl:sign_fails", ALG, CA_COMP, CA_COMP_LEN, one, 1, 1, 7, fake_sign, ((fake_t){ 3373, FHSM_RV_FUNCTION_FAILED, 0, 0 }), sizeof OUT);
    RC("crl:sign_too_small", ALG, CA_COMP, CA_COMP_LEN, one, 1, 1, 7, fake_sign, ((fake_t){ 3373, FHSM_RV_BUFFER_TOO_SMALL, 0, 0 }), sizeof OUT);
    RC("crl:sig_empty", ALG, CA_COMP, CA_COMP_LEN, one, 1, 1, 7, fake_sign, ((fake_t){ 0, 0, 0, 0 }), sizeof OUT);
    CO("crl:ok", one, 1, 9, 30);
    size_t ok_len = n;
    RC("crl:cap_0", ALG, CA_COMP, CA_COMP_LEN, one, 1, 9, 30, fake_sign, F, 0);
    RC("crl:cap_short", ALG, CA_COMP, CA_COMP_LEN, one, 1, 9, 30, fake_sign, F, ok_len - 1);
    RC("crl:cap_exact", ALG, CA_COMP, CA_COMP_LEN, one, 1, 9, 30, fake_sign, F, ok_len);
    /* past 64 KiB: three length octets (cap 1 reports the size) */
    static fhsm_composite_revoked_t many[3000];
    for (size_t i = 0; i < 3000; ++i) many[i] = (fhsm_composite_revoked_t){ SFF, 20, (int64_t)i, (int)(i % 7) };
    RC("crl:many_3000", ALG, CA_COMP, CA_COMP_LEN, many, 3000, 10, 7, fake_sign, F, 1);
    CO("crl:many_500", many, 500, 11, 7);
    n = sizeof OUT; s = F;
    { fhsm_rv_t r_ = fhsm_composite_crl(ALG, CA_COMP, CA_COMP_LEN, one, 1, 1, 7, fake_sign, &s, NULL, &n);
      row("crl:null_out", r_, n, &s); }
    s = F;
    { fhsm_rv_t r_ = fhsm_composite_crl(ALG, CA_COMP, CA_COMP_LEN, one, 1, 1, 7, fake_sign, &s, OUT, NULL);
      row("crl:null_out_len", r_, 0, &s); }

#define RP_(nm, sg, len, ca, can)                                                                 \
    do {                                                                                         \
        memset(OUT, 0xAA, sizeof OUT); n = sizeof OUT; s = (fake_t){ (len), 0, 0, 0 };           \
        fhsm_pki_signer_t u = (sg); u.sign_ctx = &s;                                             \
        { fhsm_rv_t r_ = fhsm_pki_crl(&u, (ca), (can), one, 1, 1, 7, OUT, &n); row(nm, r_, n, &s); } \
    } while (0)
    RP_("pki_crl:ed", ed, 64, CA_ED, CA_ED_LEN);
    fhsm_pki_signer_t t = ed; t.algid = NULL;
    RP_("pki_crl:null_algid", t, 64, CA_ED, CA_ED_LEN);
    t = ed; t.algid_len = 0;
    RP_("pki_crl:algid_len_0", t, 64, CA_ED, CA_ED_LEN);
    t = ed; t.algid = UT; t.algid_len = sizeof UT;
    RP_("pki_crl:algid_tag", t, 64, CA_ED, CA_ED_LEN);
    t = ed; t.sign = NULL;
    RP_("pki_crl:null_sign", t, 64, CA_ED, CA_ED_LEN);
    n = sizeof OUT;
    { fhsm_rv_t r_ = fhsm_pki_crl(NULL, CA_ED, CA_ED_LEN, one, 1, 1, 7, OUT, &n); row("pki_crl:null_signer", r_, n, NULL); }
}

static void ocsp_single_cases(void) {
    size_t n;
#define OS(nm, ci, cin, st, ra, ran, rsn, tu, tun, nu, nun, cap)                                  \
    do {                                                                                          \
        memset(OUT, 0xAA, sizeof OUT); n = (cap);                                                 \
        fhsm_composite_ocsp_single_t x_ = { (ci), (cin), (st), (ra), (ran), (rsn), (tu), (tun), (nu), (nun) }; \
        { fhsm_rv_t r_ = fhsm_composite_ocsp_single(&x_, OUT, &n); row(nm, r_, n, NULL); }        \
    } while (0)
#define OSA(nm, ...) OS(nm, __VA_ARGS__, sizeof OUT)
    OSA("ocsp_single:good", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:good_next", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, GT2, sizeof GT2);
    OSA("ocsp_single:unknown", CERT_ID, sizeof CERT_ID, FHSM_OCSP_UNKNOWN, NULL, 0, -1, GT, sizeof GT, NULL, 0);
    int rs[] = { -1, -5, 0, 7, 8, 10, 11 };
    for (size_t i = 0; i < 7; ++i) {
        char nm[64];
        snprintf(nm, sizeof nm, "ocsp_single:revoked_reason_%d", rs[i]);
        OSA(nm, CERT_ID, sizeof CERT_ID, FHSM_OCSP_REVOKED, GT, sizeof GT, rs[i], GT, sizeof GT, GT2, sizeof GT2);
    }
    OSA("ocsp_single:revoked_at_24", CERT_ID, sizeof CERT_ID, FHSM_OCSP_REVOKED, GT24, sizeof GT24, 1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:revoked_at_25", CERT_ID, sizeof CERT_ID, FHSM_OCSP_REVOKED, GT25, sizeof GT25, 1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:revoked_no_time", CERT_ID, sizeof CERT_ID, FHSM_OCSP_REVOKED, NULL, 0, 1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:revoked_time_no_len", CERT_ID, sizeof CERT_ID, FHSM_OCSP_REVOKED, GT, 0, 1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:revoked_time_utc", CERT_ID, sizeof CERT_ID, FHSM_OCSP_REVOKED, UT, sizeof UT, 1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:good_with_time", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, GT, sizeof GT, -1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:good_with_time_len", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 5, -1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:good_with_reason", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, 0, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:unknown_with_time", CERT_ID, sizeof CERT_ID, FHSM_OCSP_UNKNOWN, GT, sizeof GT, -1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:status_3", CERT_ID, sizeof CERT_ID, 3, NULL, 0, -1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:status_neg", CERT_ID, sizeof CERT_ID, -1, NULL, 0, -1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:null_cert_id", NULL, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:cert_id_len_0", CERT_ID, 0, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:cert_id_tag", GT, sizeof GT, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, NULL, 0);
    OSA("ocsp_single:null_this", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, NULL, sizeof GT, NULL, 0);
    OSA("ocsp_single:this_utc", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, UT, sizeof UT, NULL, 0);
    OSA("ocsp_single:next_ptr_no_len", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, GT2, 0);
    OSA("ocsp_single:next_len_no_ptr", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, NULL, 3);
    OSA("ocsp_single:next_utc", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, UT, sizeof UT);
    OS("ocsp_single:cap_0", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, NULL, 0, 0);
    OS("ocsp_single:cap_short", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, NULL, 0, 27);
    OS("ocsp_single:cap_exact", CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, NULL, 0, 28);
    size_t fixed = 2 + sizeof GT;
    uint8_t *c = big(0xFFFFFF - fixed + 1, 0x30);
    OS("ocsp_single:content_max", c, 0xFFFFFF - fixed, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, NULL, 0, 1);
    OS("ocsp_single:content_max_plus_1", c, 0xFFFFFF - fixed + 1, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, NULL, 0, 1);
    free(c);
    fhsm_composite_ocsp_single_t g = { CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, NULL, 0 };
    n = 64;
    { fhsm_rv_t r_ = fhsm_composite_ocsp_single(NULL, OUT, &n); row("ocsp_single:null_single", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_composite_ocsp_single(&g, NULL, &n); row("ocsp_single:null_out", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_composite_ocsp_single(&g, OUT, NULL); row("ocsp_single:null_out_len", r_, 0, NULL); }
}

static void ocsp_tbs_cases(void) {
    size_t n;
    static const uint8_t RID[] = { 0xA1, 0x02, 0x30, 0x00 };
#define OT(nm, r, rn, p, pn, q, qn, e, en, cap)                                                   \
    do {                                                                                          \
        memset(OUT, 0xAA, sizeof OUT); n = (cap);                                                 \
        { fhsm_rv_t r_ = fhsm_composite_ocsp_tbs((r), (rn), (p), (pn), (q), (qn), (e), (en), OUT, &n); \
          row(nm, r_, n, NULL); }                                                                 \
    } while (0)
#define OTA(nm, ...) OT(nm, __VA_ARGS__, sizeof OUT)
    OTA("ocsp_tbs:by_name", RID, sizeof RID, GT, sizeof GT, SEQ5, 5, NULL, 0);
    OTA("ocsp_tbs:by_key", BYKEY, sizeof BYKEY, GT, sizeof GT, SEQ5, 5, NULL, 0);
    OTA("ocsp_tbs:exts", RID, sizeof RID, GT, sizeof GT, SEQ5, 5, SEQ5, 5);
    OTA("ocsp_tbs:rid_tag", NAME0, 2, GT, sizeof GT, SEQ5, 5, NULL, 0);
    OTA("ocsp_tbs:produced_utc", RID, sizeof RID, UT, sizeof UT, SEQ5, 5, NULL, 0);
    OTA("ocsp_tbs:responses_tag", RID, sizeof RID, GT, sizeof GT, GT, sizeof GT, NULL, 0);
    OTA("ocsp_tbs:exts_tag", RID, sizeof RID, GT, sizeof GT, SEQ5, 5, GT, sizeof GT);
    OTA("ocsp_tbs:exts_ptr_no_len", RID, sizeof RID, GT, sizeof GT, SEQ5, 5, SEQ5, 0);
    OTA("ocsp_tbs:exts_len_no_ptr", RID, sizeof RID, GT, sizeof GT, SEQ5, 5, NULL, 5);
    OTA("ocsp_tbs:null_rid", NULL, 4, GT, sizeof GT, SEQ5, 5, NULL, 0);
    OTA("ocsp_tbs:rid_len_0", RID, 0, GT, sizeof GT, SEQ5, 5, NULL, 0);
    OTA("ocsp_tbs:null_produced", RID, sizeof RID, NULL, 17, SEQ5, 5, NULL, 0);
    OTA("ocsp_tbs:null_responses", RID, sizeof RID, GT, sizeof GT, NULL, 5, NULL, 0);
    OTA("ocsp_tbs:responses_len_0", RID, sizeof RID, GT, sizeof GT, SEQ5, 0, NULL, 0);
    OT("ocsp_tbs:cap_short", RID, sizeof RID, GT, sizeof GT, SEQ5, 5, NULL, 0, 27);
    OT("ocsp_tbs:cap_exact", RID, sizeof RID, GT, sizeof GT, SEQ5, 5, NULL, 0, 28);
    size_t fixed = sizeof RID + sizeof GT;
    uint8_t *q = big(0xFFFFFF - fixed + 1, 0x30);
    OT("ocsp_tbs:content_max", RID, sizeof RID, GT, sizeof GT, q, 0xFFFFFF - fixed, NULL, 0, 1);
    OT("ocsp_tbs:content_max_plus_1", RID, sizeof RID, GT, sizeof GT, q, 0xFFFFFF - fixed + 1, NULL, 0, 1);
    free(q);
    n = 64;
    { fhsm_rv_t r_ = fhsm_composite_ocsp_tbs(RID, sizeof RID, GT, sizeof GT, SEQ5, 5, NULL, 0, NULL, &n);
      row("ocsp_tbs:null_out", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_composite_ocsp_tbs(RID, sizeof RID, GT, sizeof GT, SEQ5, 5, NULL, 0, OUT, NULL);
      row("ocsp_tbs:null_out_len", r_, 0, NULL); }
}

static void ocsp_cases(fhsm_pki_signer_t ed) {
    size_t n;
    fake_t s;
    const fake_t F = { 3373, 0, 0, 0 };
    const fhsm_composite_ocsp_single_t good = { CERT_ID, sizeof CERT_ID, FHSM_OCSP_GOOD, NULL, 0, -1, GT, sizeof GT, GT2, sizeof GT2 };
    const fhsm_composite_ocsp_single_t revoked = { CERT_ID, sizeof CERT_ID, FHSM_OCSP_REVOKED, GT, sizeof GT, 1, GT, sizeof GT, GT2, sizeof GT2 };
    const fhsm_composite_ocsp_single_t unknown = { CERT_ID, sizeof CERT_ID, FHSM_OCSP_UNKNOWN, NULL, 0, -1, GT, sizeof GT, NULL, 0 };
    const fhsm_composite_ocsp_single_t badst = { CERT_ID, sizeof CERT_ID, 3, NULL, 0, -1, GT, sizeof GT, NULL, 0 };
    const fhsm_composite_ocsp_single_t three[] = { good, revoked, unknown };
    const fhsm_composite_ocsp_single_t second_bad[] = { good, badst };
#define OC(nm, alg, rc, rcn, p, pn, sg_, ns, e, en, sg, fk, cap)                                 \
    do {                                                                                         \
        memset(OUT, 0xAA, sizeof OUT); n = (cap); s = (fk);                                      \
        { fhsm_rv_t r_ = fhsm_composite_ocsp((alg), (rc), (rcn), (p), (pn), (sg_), (ns), (e), (en), (sg), &s, OUT, &n); \
          row(nm, r_, n, &s); }                                                                  \
    } while (0)
#define OO(nm, sg_, ns, e, en) OC(nm, ALG, CA_COMP, CA_COMP_LEN, GT, sizeof GT, (sg_), (ns), (e), (en), fake_sign, F, sizeof OUT)
    OO("ocsp:good", &good, 1, NULL, 0);
    OO("ocsp:revoked", &revoked, 1, NULL, 0);
    OO("ocsp:three", three, 3, NULL, 0);
    OO("ocsp:exts", &good, 1, SEQ5, 5);
    OO("ocsp:exts_ptr_no_len", &good, 1, SEQ5, 0);
    OO("ocsp:exts_len_no_ptr", &good, 1, NULL, 5);
    OO("ocsp:exts_tag", &good, 1, GT, sizeof GT);
    OO("ocsp:second_bad", second_bad, 2, NULL, 0);
    OO("ocsp:n_0", &good, 0, NULL, 0);
    OO("ocsp:null_singles", NULL, 1, NULL, 0);
    OC("ocsp:produced_utc", ALG, CA_COMP, CA_COMP_LEN, UT, sizeof UT, &good, 1, NULL, 0, fake_sign, F, sizeof OUT);
    OC("ocsp:null_produced", ALG, CA_COMP, CA_COMP_LEN, NULL, 17, &good, 1, NULL, 0, fake_sign, F, sizeof OUT);
    OC("ocsp:produced_len_0", ALG, CA_COMP, CA_COMP_LEN, GT, 0, &good, 1, NULL, 0, fake_sign, F, sizeof OUT);
    OC("ocsp:responder_ed", ALG, CA_ED, CA_ED_LEN, GT, sizeof GT, &good, 1, NULL, 0, fake_sign, F, sizeof OUT);
    OC("ocsp:responder_noskid", ALG, CA_NOSKID, CA_NOSKID_LEN, GT, sizeof GT, &good, 1, NULL, 0, fake_sign, F, sizeof OUT);
    uint8_t *trail = dup_flip(CA_ED, CA_ED_LEN, (size_t)-1, 0, 3);
    OC("ocsp:responder_trailing", ALG, trail, CA_ED_LEN + 3, GT, sizeof GT, &good, 1, NULL, 0, fake_sign, F, sizeof OUT);
    free(trail);
    OC("ocsp:responder_garbage", ALG, CA_ED, 20, GT, sizeof GT, &good, 1, NULL, 0, fake_sign, F, sizeof OUT);
    OC("ocsp:null_responder", ALG, NULL, 10, GT, sizeof GT, &good, 1, NULL, 0, fake_sign, F, sizeof OUT);
    OC("ocsp:responder_len_0", ALG, CA_ED, 0, GT, sizeof GT, &good, 1, NULL, 0, fake_sign, F, sizeof OUT);
    OC("ocsp:alg0", 0, CA_COMP, CA_COMP_LEN, GT, sizeof GT, &good, 1, NULL, 0, fake_sign, F, sizeof OUT);
    OC("ocsp:null_sign", ALG, CA_COMP, CA_COMP_LEN, GT, sizeof GT, &good, 1, NULL, 0, NULL, F, sizeof OUT);
    OC("ocsp:sign_fails", ALG, CA_COMP, CA_COMP_LEN, GT, sizeof GT, &good, 1, NULL, 0, fake_sign, ((fake_t){ 3373, FHSM_RV_FUNCTION_FAILED, 0, 0 }), sizeof OUT);
    OC("ocsp:sig_empty", ALG, CA_COMP, CA_COMP_LEN, GT, sizeof GT, &good, 1, NULL, 0, fake_sign, ((fake_t){ 0, 0, 0, 0 }), sizeof OUT);
    OO("ocsp:ok", three, 3, SEQ5, 5);
    size_t ok_len = n;
    OC("ocsp:cap_0", ALG, CA_COMP, CA_COMP_LEN, GT, sizeof GT, three, 3, SEQ5, 5, fake_sign, F, 0);
    OC("ocsp:cap_short", ALG, CA_COMP, CA_COMP_LEN, GT, sizeof GT, three, 3, SEQ5, 5, fake_sign, F, ok_len - 1);
    OC("ocsp:cap_exact", ALG, CA_COMP, CA_COMP_LEN, GT, sizeof GT, three, 3, SEQ5, 5, fake_sign, F, ok_len);
    n = sizeof OUT; s = F;
    { fhsm_rv_t r_ = fhsm_composite_ocsp(ALG, CA_COMP, CA_COMP_LEN, GT, sizeof GT, &good, 1, NULL, 0, fake_sign, &s, NULL, &n);
      row("ocsp:null_out", r_, n, &s); }
    s = F;
    { fhsm_rv_t r_ = fhsm_composite_ocsp(ALG, CA_COMP, CA_COMP_LEN, GT, sizeof GT, &good, 1, NULL, 0, fake_sign, &s, OUT, NULL);
      row("ocsp:null_out_len", r_, 0, &s); }

#define PO(nm, sg, len)                                                                          \
    do {                                                                                         \
        memset(OUT, 0xAA, sizeof OUT); n = sizeof OUT; s = (fake_t){ (len), 0, 0, 0 };           \
        fhsm_pki_signer_t u = (sg); u.sign_ctx = &s;                                             \
        { fhsm_rv_t r_ = fhsm_pki_ocsp(&u, CA_ED, CA_ED_LEN, GT, sizeof GT, &good, 1, NULL, 0, OUT, &n); \
          row(nm, r_, n, &s); }                                                                  \
    } while (0)
    PO("pki_ocsp:ed", ed, 64);
    fhsm_pki_signer_t t = ed; t.algid = UT; t.algid_len = sizeof UT;
    PO("pki_ocsp:algid_not_checked", t, 64);
    t = ed; t.algid_len = 0;
    PO("pki_ocsp:algid_len_0", t, 64);
    t = ed; t.sign = NULL;
    PO("pki_ocsp:null_sign", t, 64);
    n = sizeof OUT;
    { fhsm_rv_t r_ = fhsm_pki_ocsp(NULL, CA_ED, CA_ED_LEN, GT, sizeof GT, &good, 1, NULL, 0, OUT, &n);
      row("pki_ocsp:null_signer", r_, n, NULL); }
}

/* ---- fhsm_pki_ecdsa_raw_to_der (slice 5d) ----------------------------- */

static void ecdsa_cases(void) {
    size_t n;
    static uint8_t rs[266], z[64], lz[64], ones[64];
#define ER(nm, p, pn, cap)                                                              \
    do {                                                                                \
        memset(OUT, 0xAA, sizeof OUT); n = (cap);                                       \
        { fhsm_rv_t r_ = fhsm_pki_ecdsa_raw_to_der((p), (pn), OUT, &n); row(nm, r_, n, NULL); } \
    } while (0)
    for (size_t i = 0; i < sizeof rs; ++i) rs[i] = (uint8_t)(i * 7 + 1);
    memset(ones, 0xFF, sizeof ones);
    lz[2] = 0x7F; lz[3] = 1; lz[33] = 0x80; lz[34] = 1;
    ER("ecdsa_der:p256", rs, 64, sizeof OUT);
    size_t ok = n;
    ER("ecdsa_der:p384", rs, 96, sizeof OUT);
    ER("ecdsa_der:p521", rs, 132, sizeof OUT);
    ER("ecdsa_der:264", rs, 264, sizeof OUT);
    ER("ecdsa_der:266", rs, 266, sizeof OUT);
    ER("ecdsa_der:2", rs, 2, sizeof OUT);
    ER("ecdsa_der:odd", rs, 63, sizeof OUT);
    ER("ecdsa_der:len_0", rs, 0, sizeof OUT);
    ER("ecdsa_der:zeros", z, 64, sizeof OUT);
    ER("ecdsa_der:leading_zeros", lz, 64, sizeof OUT);
    ER("ecdsa_der:ones", ones, 64, sizeof OUT);
    ER("ecdsa_der:null_rs", NULL, 64, sizeof OUT);
    ER("ecdsa_der:cap_0", rs, 64, 0);
    ER("ecdsa_der:cap_short", rs, 64, ok - 1);
    ER("ecdsa_der:cap_exact", rs, 64, ok);
    n = sizeof OUT;
    { fhsm_rv_t r_ = fhsm_pki_ecdsa_raw_to_der(rs, 64, NULL, &n); row("ecdsa_der:null_out", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_pki_ecdsa_raw_to_der(rs, 64, OUT, NULL); row("ecdsa_der:null_out_len", r_, 0, NULL); }
}

/* ---- CMS SignedData (slice 5d, :2129-2917) ----------------------------- */

static const uint8_t DIGALG256[] = { 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
static const uint8_t SER2[] = { 0x02, 0x01, 0x02 };
static const uint8_t SET3[] = { 0x31, 0x03, 0x04, 0x01, 0x00 };
static const uint8_t SEQ3[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
static const uint8_t SATTRS_A0[] = { 0xA0, 0x03, 0x04, 0x01, 0x00 };

static size_t der_len_octets(size_t n) {
    return n < 0x80 ? 1 : n < 0x100 ? 2 : n < 0x10000 ? 3 : 4;
}

/* tag, minimal length, content */
static uint8_t *tlv_of(uint8_t tag, const uint8_t *a, size_t an, const uint8_t *b, size_t bn, size_t *out) {
    size_t c = an + bn, ln = der_len_octets(c), i = 0;
    uint8_t *t = malloc(1 + ln + c);
    if (!t) abort();
    t[i++] = tag;
    if (ln == 1) t[i++] = (uint8_t)c;
    else {
        t[i++] = (uint8_t)(0x80 | (ln - 1));
        for (size_t k = ln - 1; k-- > 0;) t[i++] = (uint8_t)(c >> (8 * k));
    }
    if (an) memcpy(t + i, a, an);
    if (bn) memcpy(t + i + an, b, bn);
    *out = 1 + ln + c;
    return t;
}

static void cms_si_cases(const uint8_t *iss, size_t il, const uint8_t *sga, size_t sgl) {
    size_t n;
    uint8_t sig[64];
    for (size_t i = 0; i < sizeof sig; ++i) sig[i] = (uint8_t)i;
#define SI(nm, i, in, s, sn, d, dn, a, an, g, gn, x, xn, cap)                                  \
    do {                                                                                       \
        memset(OUT, 0xAA, sizeof OUT); n = (cap);                                              \
        { fhsm_rv_t r_ = fhsm_composite_cms_signerinfo((i), (in), (s), (sn), (d), (dn), (a), (an), (g), (gn), \
                                                       (x), (xn), OUT, &n); row(nm, r_, n, NULL); } \
    } while (0)
#define SIA(nm, ...) SI(nm, __VA_ARGS__, sizeof OUT)
    SIA("cms_si:ok", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64);
    size_t ok = n;
    SIA("cms_si:null_issuer", NULL, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64);
    SIA("cms_si:issuer_len_0", iss, 0, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64);
    SIA("cms_si:null_serial", iss, il, NULL, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64);
    SIA("cms_si:serial_len_0", iss, il, SER2, 0, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64);
    SIA("cms_si:null_digalg", iss, il, SER2, 3, NULL, 13, SET3, 5, sga, sgl, sig, 64);
    SIA("cms_si:digalg_len_0", iss, il, SER2, 3, DIGALG256, 0, SET3, 5, sga, sgl, sig, 64);
    SIA("cms_si:null_sattrs", iss, il, SER2, 3, DIGALG256, 13, NULL, 5, sga, sgl, sig, 64);
    SIA("cms_si:sattrs_len_0", iss, il, SER2, 3, DIGALG256, 13, SET3, 0, sga, sgl, sig, 64);
    SIA("cms_si:null_sigalg", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, NULL, sgl, sig, 64);
    SIA("cms_si:sigalg_len_0", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, 0, sig, 64);
    SIA("cms_si:null_sig", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, NULL, 64);
    SIA("cms_si:sig_len_0", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 0);
    SIA("cms_si:issuer_tag", SET3, 5, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64);
    SIA("cms_si:serial_tag", iss, il, SET3, 5, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64);
    SIA("cms_si:digalg_tag", iss, il, SER2, 3, SET3, 5, SET3, 5, sga, sgl, sig, 64);
    SIA("cms_si:sattrs_tag_a0", iss, il, SER2, 3, DIGALG256, 13, SATTRS_A0, 5, sga, sgl, sig, 64);
    SIA("cms_si:sattrs_tag_seq", iss, il, SER2, 3, DIGALG256, 13, SEQ3, 5, sga, sgl, sig, 64);
    SIA("cms_si:sigalg_tag", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, SET3, 5, sig, 64);
    SI("cms_si:cap_0", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64, 0);
    SI("cms_si:cap_short", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64, ok - 1);
    SI("cms_si:cap_exact", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64, ok);
    n = sizeof OUT;
    { fhsm_rv_t r_ = fhsm_composite_cms_signerinfo(iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64, NULL, &n); row("cms_si:null_out", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_composite_cms_signerinfo(iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64, OUT, NULL); row("cms_si:null_out_len", r_, 0, NULL); }
    /* der_len's three octets: content 0xFFFFFF fits, one more does not; and each part alone */
    size_t ic = il + 3, fixed = 3 + (1 + der_len_octets(ic) + ic) + 13 + 5 + sgl + 5;
    uint8_t *g = big(0x1000000, 0);
    SI("cms_si:content_max", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, g, 0xFFFFFF - fixed, 1);
    SI("cms_si:content_max_plus_1", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, g, 0xFFFFFF - fixed + 1, 1);
    SI("cms_si:sig_over", iss, il, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, g, 0x1000000, 1);
    g[0] = 0x30;
    SI("cms_si:issuer_over", g, 0xFFFFFD, SER2, 3, DIGALG256, 13, SET3, 5, sga, sgl, sig, 64, 1);
    free(g);
}

static void cms_wrap_cases(const uint8_t *cert, size_t cl) {
    size_t n, csn;
    uint8_t *certs = tlv_of(0x31, cert, cl, NULL, 0, &csn);
#define WR(nm, d, dn, c, cn, s, sn, cap)                                                   \
    do {                                                                                   \
        memset(OUT, 0xAA, sizeof OUT); n = (cap);                                          \
        { fhsm_rv_t r_ = fhsm_composite_cms_wrap((d), (dn), (c), (cn), (s), (sn), OUT, &n); row(nm, r_, n, NULL); } \
    } while (0)
    WR("cms_wrap:ok", DIGALG256, 13, certs, csn, SEQ3, 5, sizeof OUT);
    size_t ok = n;
    WR("cms_wrap:no_certs", DIGALG256, 13, NULL, 0, SEQ3, 5, sizeof OUT);
    WR("cms_wrap:null_digalg", NULL, 13, certs, csn, SEQ3, 5, sizeof OUT);
    WR("cms_wrap:digalg_len_0", DIGALG256, 0, certs, csn, SEQ3, 5, sizeof OUT);
    WR("cms_wrap:null_si", DIGALG256, 13, certs, csn, NULL, 5, sizeof OUT);
    WR("cms_wrap:si_len_0", DIGALG256, 13, certs, csn, SEQ3, 0, sizeof OUT);
    WR("cms_wrap:digalg_tag", SET3, 5, certs, csn, SEQ3, 5, sizeof OUT);
    WR("cms_wrap:si_tag", DIGALG256, 13, certs, csn, SET3, 5, sizeof OUT);
    WR("cms_wrap:certs_ptr_no_len", DIGALG256, 13, certs, 0, SEQ3, 5, sizeof OUT);
    WR("cms_wrap:certs_len_no_ptr", DIGALG256, 13, NULL, 5, SEQ3, 5, sizeof OUT);
    WR("cms_wrap:certs_tag", DIGALG256, 13, cert, cl, SEQ3, 5, sizeof OUT);
    WR("cms_wrap:cap_0", DIGALG256, 13, certs, csn, SEQ3, 5, 0);
    WR("cms_wrap:cap_short", DIGALG256, 13, certs, csn, SEQ3, 5, ok - 1);
    WR("cms_wrap:cap_exact", DIGALG256, 13, certs, csn, SEQ3, 5, ok);
    n = sizeof OUT;
    { fhsm_rv_t r_ = fhsm_composite_cms_wrap(DIGALG256, 13, certs, csn, SEQ3, 5, NULL, &n); row("cms_wrap:null_out", r_, n, NULL); }
    { fhsm_rv_t r_ = fhsm_composite_cms_wrap(DIGALG256, 13, certs, csn, SEQ3, 5, OUT, NULL); row("cms_wrap:null_out_len", r_, 0, NULL); }
    /* the longest SignerInfo set that still fits der_len, found by asking (cap 1 never writes) */
    uint8_t *g = big(0x1000000, 0x30);
    size_t lo = 0xFFFFFF;
    for (;; --lo) {
        n = 1;
        if (fhsm_composite_cms_wrap(DIGALG256, 13, certs, csn, g, lo, OUT, &n) != FHSM_RV_FUNCTION_FAILED) break;
    }
    uint8_t be[4] = { (uint8_t)(lo >> 24), (uint8_t)(lo >> 16), (uint8_t)(lo >> 8), (uint8_t)lo };
    fixture("cms_wrap_si_max", be, 4);
    WR("cms_wrap:content_max", DIGALG256, 13, certs, csn, g, lo, 1);
    WR("cms_wrap:content_max_plus_1", DIGALG256, 13, certs, csn, g, lo + 1, 1);
    WR("cms_wrap:si_over", DIGALG256, 13, certs, csn, g, 0x1000000, 1);
    free(g);
    free(certs);
}

/* a CA certificate whose issuer name alone is 130 RDNs: SignerInfo past C's 16384 */
static uint8_t *big_issuer_cert(EVP_PKEY *ked, size_t *len) {
    X509 *x = X509_new();
    X509_NAME *nm = X509_NAME_new();
    if (!x || !nm || X509_set_version(x, 2) != 1 || ASN1_INTEGER_set(X509_get_serialNumber(x), 9) != 1
        || !X509_gmtime_adj(X509_getm_notBefore(x), 0) || !X509_gmtime_adj(X509_getm_notAfter(x), 86400)) abort();
    for (int i = 0; i < 130; ++i)
        if (X509_NAME_add_entry_by_txt(nm, "OU", MBSTRING_ASC,
                (const unsigned char *)"pqHSM golden organisational unit, sixty characters long..", -1, -1, 0) != 1) abort();
    if (X509_set_subject_name(x, nm) != 1 || X509_set_issuer_name(x, nm) != 1
        || X509_set_pubkey(x, ked) != 1 || X509_sign(x, ked, NULL) <= 0) abort();
    uint8_t *d = NULL;
    int dn = i2d_X509(x, &d);
    if (dn <= 0) abort();
    X509_NAME_free(nm);
    X509_free(x);
    *len = (size_t)dn;
    return d;
}

static uint8_t D64[64];

static void pki_cms_cases(fhsm_pki_signer_t ed, fhsm_pki_signer_t ec, fhsm_pki_signer_t rsa,
                          fhsm_pki_signer_t ml, fhsm_pki_signer_t comp, EVP_PKEY *ked) {
    size_t n;
    fake_t s;
    size_t bl;
    uint8_t *bigc = big_issuer_cert(ked, &bl);
    fixture("ca_big_issuer", bigc, bl);
    uint8_t *trail = dup_flip(CA_ED, CA_ED_LEN, CA_ED_LEN, 0, 1);
    static const uint8_t ALG_SET[] = { 0x31, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70 };
#define PKC(nm, sg, dn, c, cn, d, dl, fk, cap)                                              \
    do {                                                                                   \
        memset(OUT, 0xAA, sizeof OUT); n = (cap); s = (fk);                                \
        fhsm_pki_signer_t sg_ = (sg); sg_.sign_ctx = &s;                                   \
        { fhsm_rv_t r_ = fhsm_pki_cms(&sg_, (dn), (c), (cn), (d), (dl), OUT, &n); row(nm, r_, n, &s); } \
    } while (0)
#define PKA(nm, sg, dn, d, dl, fk) PKC(nm, sg, dn, CA_ED, CA_ED_LEN, d, dl, fk, sizeof OUT)
    const fake_t F = { 64, 0, 0, 0 };
    PKA("pki_cms:ed25519", ed, "SHA256", D64, 32, F);
    size_t ok = n;
    PKA("pki_cms:ec", ec, "SHA256", D64, 32, ((fake_t){ 72, 0, 0, 0 }));
    PKA("pki_cms:ec_sha384", ec, "SHA384", D64, 48, ((fake_t){ 72, 0, 0, 0 }));
    PKA("pki_cms:rsa", rsa, "SHA256", D64, 32, ((fake_t){ 256, 0, 0, 0 }));
    PKA("pki_cms:mldsa44", ml, "SHA512", D64, 64, ((fake_t){ 2420, 0, 0, 0 }));
    PKC("pki_cms:composite", comp, "SHA512", CA_COMP, CA_COMP_LEN, D64, 64, ((fake_t){ 3373, 0, 0, 0 }), sizeof OUT);
    PKA("pki_cms:sha256_lower", ed, "sha256", D64, 32, F);
    PKA("pki_cms:sha2_256", ed, "SHA2-256", D64, 32, F);
    PKA("pki_cms:sha3_256", ed, "SHA3-256", D64, 32, F);
    PKA("pki_cms:sha1", ed, "SHA1", D64, 20, F);
    PKA("pki_cms:md5", ed, "MD5", D64, 16, F);
    PKA("pki_cms:shake128_16", ed, "SHAKE128", D64, 16, F);
    PKA("pki_cms:shake128_32", ed, "SHAKE128", D64, 32, F);
    PKA("pki_cms:unknown_digest", ed, "NOPE", D64, 32, F);
    PKA("pki_cms:empty_digest_name", ed, "", D64, 32, F);
    PKA("pki_cms:digest_short", ed, "SHA256", D64, 31, F);
    PKA("pki_cms:digest_long", ed, "SHA256", D64, 33, F);
    PKA("pki_cms:digest_len_0", ed, "SHA256", D64, 0, F);
    PKC("pki_cms:cert_garbage", ed, "SHA256", CA_ED, 20, D64, 32, F, sizeof OUT);
    PKC("pki_cms:cert_len_0", ed, "SHA256", CA_ED, 0, D64, 32, F, sizeof OUT);
    PKC("pki_cms:cert_trailing", ed, "SHA256", trail, CA_ED_LEN + 1, D64, 32, F, sizeof OUT);
    PKC("pki_cms:cert_noskid", ed, "SHA256", CA_NOSKID, CA_NOSKID_LEN, D64, 32, F, sizeof OUT);
    PKA("pki_cms:sign_fails", ed, "SHA256", D64, 32, ((fake_t){ 64, FHSM_RV_DEVICE_ERROR, 0, 0 }));
    PKA("pki_cms:sig_len_0", ed, "SHA256", D64, 32, ((fake_t){ 0, 0, 0, 0 }));
    PKA("pki_cms:sig_8192", ed, "SHA256", D64, 32, ((fake_t){ 8192, 0, 0, 0 }));
    PKC("pki_cms:big_issuer", ed, "SHA256", bigc, bl, D64, 32, ((fake_t){ 8192, 0, 0, 0 }), sizeof OUT);
    PKC("pki_cms:big_issuer_small_sig", ed, "SHA256", bigc, bl, D64, 32, F, sizeof OUT);
    fhsm_pki_signer_t t;
    t = ed; t.algid = ALG_SET; t.algid_len = sizeof ALG_SET; PKA("pki_cms:algid_tag", t, "SHA256", D64, 32, F);
    t = ed; t.algid = NULL; PKA("pki_cms:null_algid", t, "SHA256", D64, 32, F);
    t = ed; t.algid_len = 0; PKA("pki_cms:algid_len_0", t, "SHA256", D64, 32, F);
    t = ed; t.sign = NULL; PKA("pki_cms:null_sign", t, "SHA256", D64, 32, F);
    t = ed; t.spki = NULL; t.spki_len = 0; PKA("pki_cms:no_spki", t, "SHA256", D64, 32, F);
    PKA("pki_cms:null_digest_name", ed, NULL, D64, 32, F);
    PKC("pki_cms:null_cert", ed, "SHA256", NULL, CA_ED_LEN, D64, 32, F, sizeof OUT);
    PKA("pki_cms:null_digest", ed, "SHA256", NULL, 32, F);
    PKC("pki_cms:cap_0", ed, "SHA256", CA_ED, CA_ED_LEN, D64, 32, F, 0);
    PKC("pki_cms:cap_short", ed, "SHA256", CA_ED, CA_ED_LEN, D64, 32, F, ok - 1);
    PKC("pki_cms:cap_exact", ed, "SHA256", CA_ED, CA_ED_LEN, D64, 32, F, ok);
    n = sizeof OUT; s = F;
    { fhsm_rv_t r_ = fhsm_pki_cms(NULL, "SHA256", CA_ED, CA_ED_LEN, D64, 32, OUT, &n); row("pki_cms:null_signer", r_, n, NULL); }
    t = ed; t.sign_ctx = &s;
    { fhsm_rv_t r_ = fhsm_pki_cms(&t, "SHA256", CA_ED, CA_ED_LEN, D64, 32, NULL, &n); row("pki_cms:null_out", r_, n, &s); }
    { fhsm_rv_t r_ = fhsm_pki_cms(&t, "SHA256", CA_ED, CA_ED_LEN, D64, 32, OUT, NULL); row("pki_cms:null_out_len", r_, 0, &s); }
    free(trail);
    OPENSSL_free(bigc);

#define CM(nm, alg, c, cn, d, dl, cb, fk, cap)                                             \
    do {                                                                                   \
        memset(OUT, 0xAA, sizeof OUT); n = (cap); s = (fk);                                \
        { fhsm_rv_t r_ = fhsm_composite_cms((alg), (c), (cn), (d), (dl), (cb), &s, OUT, &n); row(nm, r_, n, &s); } \
    } while (0)
    const fake_t FC = { 3373, 0, 0, 0 };
    CM("cms:ok", ALG, CA_COMP, CA_COMP_LEN, D64, 64, fake_sign, FC, sizeof OUT);
    ok = n;
    CM("cms:alg0", 0, CA_COMP, CA_COMP_LEN, D64, 64, fake_sign, FC, sizeof OUT);
    CM("cms:null_cert", ALG, NULL, CA_COMP_LEN, D64, 64, fake_sign, FC, sizeof OUT);
    CM("cms:cert_garbage", ALG, CA_COMP, 20, D64, 64, fake_sign, FC, sizeof OUT);
    CM("cms:null_digest", ALG, CA_COMP, CA_COMP_LEN, NULL, 64, fake_sign, FC, sizeof OUT);
    CM("cms:digest_32", ALG, CA_COMP, CA_COMP_LEN, D64, 32, fake_sign, FC, sizeof OUT);
    CM("cms:null_sign", ALG, CA_COMP, CA_COMP_LEN, D64, 64, NULL, FC, sizeof OUT);
    CM("cms:sign_fails", ALG, CA_COMP, CA_COMP_LEN, D64, 64, fake_sign, ((fake_t){ 3373, FHSM_RV_FUNCTION_FAILED, 0, 0 }), sizeof OUT);
    CM("cms:cap_short", ALG, CA_COMP, CA_COMP_LEN, D64, 64, fake_sign, FC, ok - 1);
    n = sizeof OUT; s = FC;
    { fhsm_rv_t r_ = fhsm_composite_cms(ALG, CA_COMP, CA_COMP_LEN, D64, 64, fake_sign, &s, NULL, &n); row("cms:null_out", r_, n, &s); }
    { fhsm_rv_t r_ = fhsm_composite_cms(ALG, CA_COMP, CA_COMP_LEN, D64, 64, fake_sign, &s, OUT, NULL); row("cms:null_out_len", r_, 0, &s); }
}

/* ---- verification: real structures, and ones assembled to reach each refusal ---- */

static fhsm_rv_t sign_raw(EVP_PKEY *k, const char *md, int pss_salt, const uint8_t *tbs, size_t n,
                          uint8_t *sig, size_t *sl) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pc = NULL;
    int ok = c && EVP_DigestSignInit_ex(c, &pc, md, NULL, NULL, k, NULL) == 1;
    if (ok && pss_salt)
        ok = EVP_PKEY_CTX_set_rsa_padding(pc, RSA_PKCS1_PSS_PADDING) == 1
          && EVP_PKEY_CTX_set_rsa_pss_saltlen(pc, pss_salt) == 1
          && EVP_PKEY_CTX_set_rsa_mgf1_md_name(pc, "SHA256", NULL) == 1;
    ok = ok && EVP_DigestSign(c, sig, sl, tbs, n) == 1;
    EVP_MD_CTX_free(c);
    return ok ? FHSM_RV_OK : FHSM_RV_FUNCTION_FAILED;
}

typedef struct { EVP_PKEY *k; const char *md; int pss; } skey_t;

static fhsm_rv_t key_sign(void *ctx, const uint8_t *tbs, size_t n, uint8_t *sig, size_t *sl) {
    skey_t *r = ctx;
    return sign_raw(r->k, r->md, r->pss, tbs, n, sig, sl);
}

static void verify_row(const char *name, const uint8_t *cms, size_t cl, const uint8_t *d, size_t dl) {
    char k[96];
    snprintf(k, sizeof k, "cmsv:%s", name);
    fixture(k, cms, cl);
    snprintf(k, sizeof k, "cmsd:%s", name);
    fixture(k, d, dl);
    const char *dn = NULL;
    fhsm_rv_t rc = fhsm_composite_cms_verify(ALG, cms, cl, d, dl);
    fhsm_rv_t rp = fhsm_pki_cms_verify(cms, cl, d, dl);
    fhsm_rv_t rd = fhsm_pki_cms_digest(cms, cl, &dn);
    fprintf(f, "cmsv:%s\tcomposite=0x%x;pki=0x%x;digest=0x%x;name=%s\n", name, (unsigned)rc,
            (unsigned)rp, (unsigned)rd, dn ? dn : "-");
}

/* the structure, and the usual damage to it */
static void verify_rows(const char *name, const uint8_t *cms, size_t cl, const uint8_t *d, size_t dl, int all) {
    char k[96];
    uint8_t *b = dup_flip(cms, cl, cl - 1, 1, 1), *e = dup_flip(d, dl, 0, 0x80, 0);
    verify_row(name, cms, cl, d, dl);
    snprintf(k, sizeof k, "%s/digest_flipped", name); verify_row(k, cms, cl, e, dl);
    snprintf(k, sizeof k, "%s/sig_flipped", name); verify_row(k, b, cl, d, dl);
    if (all) {
        b[cl - 1] ^= 1;
        snprintf(k, sizeof k, "%s/digest_short", name); verify_row(k, cms, cl, d, dl - 1);
        snprintf(k, sizeof k, "%s/trailing", name); verify_row(k, b, cl + 1, d, dl);
        snprintf(k, sizeof k, "%s/truncated", name); verify_row(k, cms, cl - 1, d, dl);
        snprintf(k, sizeof k, "%s/empty", name); verify_row(k, cms, 0, d, dl);
    }
    free(b);
    free(e);
}

static uint8_t SIB[32768], CMSB[65536];

/* SignerInfo naming `named`, over `attrs` signed as given, in a SignedData carrying `certs` */
static size_t assemble(const uint8_t *named, size_t nl, const uint8_t *digalg, size_t dgl,
                       const uint8_t *attrs, size_t al, const uint8_t *sigalg, size_t sgl,
                       const uint8_t *sig, size_t sl, const uint8_t *certs, size_t csl, int twice) {
    const uint8_t *p = named;
    X509 *x = d2i_X509(NULL, &p, (long)nl);
    uint8_t *iss = NULL, *ser = NULL;
    int il = x ? i2d_X509_NAME(X509_get_issuer_name(x), &iss) : -1;
    int sn = x ? i2d_ASN1_INTEGER(X509_get_serialNumber(x), &ser) : -1;
    if (il <= 0 || sn <= 0) abort();
    size_t n = sizeof SIB / 2;
    if (fhsm_composite_cms_signerinfo(iss, (size_t)il, ser, (size_t)sn, digalg, dgl, attrs, al, sigalg, sgl,
                                      sig, sl, SIB, &n) != FHSM_RV_OK) abort();
    if (twice) { memcpy(SIB + n, SIB, n); n *= 2; }
    size_t out = sizeof CMSB;
    if (fhsm_composite_cms_wrap(digalg, dgl, certs, csl, SIB, n, CMSB, &out) != FHSM_RV_OK) abort();
    OPENSSL_free(iss);
    OPENSSL_free(ser);
    X509_free(x);
    return out;
}

/* signed attributes by hand: contentType, messageDigest as `md_tag` (0: absent), either order */
static size_t attrs_of(uint8_t *out, const uint8_t *d, size_t dl, uint8_t md_tag, int reversed) {
    static const uint8_t CT[] = { 0x30, 0x18, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03,
                                  0x31, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
    uint8_t md[128];
    size_t ml = 0;
    if (md_tag) {
        const uint8_t h[] = { 0x30, (uint8_t)(15 + dl), 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04,
                              0x31, (uint8_t)(2 + dl), md_tag, (uint8_t)dl };
        memcpy(md, h, sizeof h);
        memcpy(md + sizeof h, d, dl);
        ml = sizeof h + dl;
    }
    size_t i = 0;
    out[i++] = 0x31;
    out[i++] = (uint8_t)(sizeof CT + ml);
    if (reversed) { memcpy(out + i, md, ml); i += ml; }
    memcpy(out + i, CT, sizeof CT); i += sizeof CT;
    if (!reversed) { memcpy(out + i, md, ml); i += ml; }
    return i;
}

static uint8_t *cert_for(fhsm_pki_signer_t sg, const char *subj, size_t *n) {
    fake_t s = { 64, 0, 0, 0 };
    sg.sign = fake_sign; sg.sign_ctx = &s;
    uint8_t *c = malloc(16384);
    *n = 16384;
    if (!c || fhsm_pki_selfsigned(&sg, subj, 11, 365, c, n) != FHSM_RV_OK) abort();
    return c;
}

static void cms_verify_cases(fhsm_pki_signer_t ed, fhsm_pki_signer_t ec, fhsm_pki_signer_t rsa,
                             fhsm_pki_signer_t ml, EVP_PKEY *ked, EVP_PKEY *kec, EVP_PKEY *krsa,
                             EVP_PKEY *kml) {
    uint8_t d256[32], d384[48], d512[64], sig[8192], attrs[256];
    for (size_t i = 0; i < 64; ++i) {
        d512[i] = (uint8_t)(i * 5 + 3);
        if (i < 48) d384[i] = (uint8_t)(i * 11 + 2);
        if (i < 32) d256[i] = (uint8_t)(i * 3 + 1);
    }
    size_t ecl, rsl, mll, n;
    uint8_t *cec = cert_for(ec, "/CN=ec signer", &ecl);
    uint8_t *crsa = cert_for(rsa, "/CN=rsa signer", &rsl);
    uint8_t *cml = cert_for(ml, "/CN=ml signer", &mll);
    fixture("cert_ec", cec, ecl);

    /* through the encoders */
    skey_t ked_ = { ked, NULL, 0 }, kec256 = { kec, "SHA256", 0 }, kec384 = { kec, "SHA384", 0 };
    skey_t kpss = { krsa, "SHA256", 32 }, kpkcs1 = { krsa, "SHA256", 0 }, kml_ = { kml, NULL, 0 };
    size_t al;
    const struct {
        const char *name; fhsm_pki_sigalg_t alg; const uint8_t *spki; size_t spl; skey_t *k;
        const char *dn; const uint8_t *d; size_t dl; const uint8_t *c; size_t cl;
    } real[] = {
        { "ed25519", FHSM_PKI_SIG_ED25519, ed.spki, ed.spki_len, &ked_, "SHA256", d256, 32, CA_ED, CA_ED_LEN },
        { "ec_sha256", FHSM_PKI_SIG_ECDSA_SHA256, ec.spki, ec.spki_len, &kec256, "SHA256", d256, 32, cec, ecl },
        { "ec_sha384", FHSM_PKI_SIG_ECDSA_SHA384, ec.spki, ec.spki_len, &kec384, "SHA384", d384, 48, cec, ecl },
        { "rsa_pss", FHSM_PKI_SIG_RSA_PSS_SHA256, rsa.spki, rsa.spki_len, &kpss, "SHA256", d256, 32, crsa, rsl },
        { "rsa_pkcs1", FHSM_PKI_SIG_RSA_PKCS1_SHA256, rsa.spki, rsa.spki_len, &kpkcs1, "SHA256", d256, 32, crsa, rsl },
        { "mldsa44", FHSM_PKI_SIG_MLDSA44, ml.spki, ml.spki_len, &kml_, "SHA512", d512, 64, cml, mll },
    };
    for (size_t i = 0; i < sizeof real / sizeof real[0]; ++i) {
        fhsm_pki_signer_t t = { algid(real[i].alg, &al), al, real[i].spki, real[i].spl, key_sign, real[i].k };
        n = sizeof CMSB;
        if (fhsm_pki_cms(&t, real[i].dn, real[i].c, real[i].cl, real[i].d, real[i].dl, CMSB, &n) != FHSM_RV_OK) abort();
        uint8_t *c = malloc(n);
        memcpy(c, CMSB, n);
        verify_rows(real[i].name, c, n, real[i].d, real[i].dl, i == 0);
        free(c);
    }
    n = sizeof CMSB;
    if (fhsm_composite_cms(ALG, CA_COMP, CA_COMP_LEN, d512, 64, comp_sign, NULL, CMSB, &n) != FHSM_RV_OK) abort();
    uint8_t *cc = malloc(n);
    memcpy(cc, CMSB, n);
    verify_rows("composite", cc, n, d512, 64, 1);
    free(cc);

    /* assembled */
    size_t ced_n, cec_n, ccomp_n, two_n;
    uint8_t *certs_ed = tlv_of(0x31, CA_ED, CA_ED_LEN, NULL, 0, &ced_n);
    uint8_t *certs_ec = tlv_of(0x31, cec, ecl, NULL, 0, &cec_n);
    uint8_t *certs_comp = tlv_of(0x31, CA_COMP, CA_COMP_LEN, NULL, 0, &ccomp_n);
    uint8_t *certs_two = tlv_of(0x31, CA_ED, CA_ED_LEN, cec, ecl, &two_n);
    static const uint8_t DIGALG384[] = { 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
    static const uint8_t DIGALG256_NULL[] = { 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00 };
    static const uint8_t DIGALG_SHA1[] = { 0x30, 0x07, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A };
    static const uint8_t ECDSA256_NULL[] = { 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x05, 0x00 };
    static const uint8_t UNKNOWN[] = { 0x30, 0x05, 0x06, 0x03, 0x2A, 0x03, 0x04 };
    static const uint8_t RSA_ENC[] = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
    static const uint8_t PKCS1_ABSENT[] = { 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B };
    static const uint8_t PKCS1_INT[] = { 0x30, 0x0E, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x02, 0x01, 0x00 };
    static const uint8_t ED_NULL[] = { 0x30, 0x07, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x05, 0x00 };
    static const uint8_t COMP_NULL[] = { 0x30, 0x0C, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x30, 0x05, 0x00 };
    const uint8_t *a_ed = algid(FHSM_PKI_SIG_ED25519, &al); size_t a_edl = al;
    const uint8_t *a_ec384 = algid(FHSM_PKI_SIG_ECDSA_SHA384, &al); size_t a_ec384l = al;
    const uint8_t *a_pss = algid(FHSM_PKI_SIG_RSA_PSS_SHA256, &al); size_t a_pssl = al;
    const uint8_t *a_comp = algid(FHSM_PKI_SIG_COMPOSITE_MLDSA65_ED25519, &al); size_t a_compl = al;
    uint8_t pss20[80];
    memcpy(pss20, a_pss, a_pssl);
    pss20[a_pssl - 1] = 20;
    size_t sl, an, cl;
#define SIGN_(k, md, salt) do { sl = sizeof sig; if (sign_raw((k), (md), (salt), attrs, an, sig, &sl) != FHSM_RV_OK) abort(); } while (0)
#define CR(nm, named, nl, dg, dgl, sa, sal, certs, csl, twice, d, dl)                              \
    do { cl = assemble((named), (nl), (dg), (dgl), attrs, an, (sa), (sal), sig, sl, (certs), (csl), (twice)); \
         verify_row(nm, CMSB, cl, (d), (dl)); } while (0)

    an = attrs_of(attrs, d256, 32, 0x04, 0); SIGN_(ked, NULL, 0);
    CR("assembled/ed25519", CA_ED, CA_ED_LEN, DIGALG256, 13, a_ed, a_edl, certs_ed, ced_n, 0, d256, 32);
    CR("assembled/ed25519_digalg_null_params", CA_ED, CA_ED_LEN, DIGALG256_NULL, 15, a_ed, a_edl, certs_ed, ced_n, 0, d256, 32);
    CR("assembled/ed25519_params_null", CA_ED, CA_ED_LEN, DIGALG256, 13, ED_NULL, sizeof ED_NULL, certs_ed, ced_n, 0, d256, 32);
    CR("assembled/unknown_sigalg", CA_ED, CA_ED_LEN, DIGALG256, 13, UNKNOWN, sizeof UNKNOWN, certs_ed, ced_n, 0, d256, 32);
    CR("assembled/two_signers", CA_ED, CA_ED_LEN, DIGALG256, 13, a_ed, a_edl, certs_ed, ced_n, 1, d256, 32);
    CR("assembled/no_certs", CA_ED, CA_ED_LEN, DIGALG256, 13, a_ed, a_edl, NULL, 0, 0, d256, 32);
    CR("assembled/two_certs", CA_ED, CA_ED_LEN, DIGALG256, 13, a_ed, a_edl, certs_two, two_n, 0, d256, 32);
    CR("assembled/names_other_cert", cec, ecl, DIGALG256, 13, a_ed, a_edl, certs_ed, ced_n, 0, d256, 32);
    CR("assembled/ed25519_alg_ec_key", cec, ecl, DIGALG256, 13, a_ed, a_edl, certs_ec, cec_n, 0, d256, 32);
    an = attrs_of(attrs, d256, 20, 0x04, 0); SIGN_(ked, NULL, 0);
    CR("assembled/digalg_sha1", CA_ED, CA_ED_LEN, DIGALG_SHA1, sizeof DIGALG_SHA1, a_ed, a_edl, certs_ed, ced_n, 0, d256, 20);
    an = attrs_of(attrs, d256, 32, 0, 0); SIGN_(ked, NULL, 0);
    CR("assembled/no_message_digest", CA_ED, CA_ED_LEN, DIGALG256, 13, a_ed, a_edl, certs_ed, ced_n, 0, d256, 32);
    an = attrs_of(attrs, d256, 32, 0x02, 0); SIGN_(ked, NULL, 0);
    CR("assembled/message_digest_integer", CA_ED, CA_ED_LEN, DIGALG256, 13, a_ed, a_edl, certs_ed, ced_n, 0, d256, 32);
    an = attrs_of(attrs, d256, 32, 0x04, 1); SIGN_(ked, NULL, 0);
    CR("assembled/attrs_unsorted", CA_ED, CA_ED_LEN, DIGALG256, 13, a_ed, a_edl, certs_ed, ced_n, 0, d256, 32);

    an = attrs_of(attrs, d256, 32, 0x04, 0); SIGN_(kec, "SHA256", 0);
    CR("assembled/ecdsa_params_null", cec, ecl, DIGALG256, 13, ECDSA256_NULL, sizeof ECDSA256_NULL, certs_ec, cec_n, 0, d256, 32);
    SIGN_(kec, "SHA384", 0);
    CR("assembled/ecdsa384_digest256", cec, ecl, DIGALG256, 13, a_ec384, a_ec384l, certs_ec, cec_n, 0, d256, 32);

    size_t certs_rsa_n;
    uint8_t *certs_rsa = tlv_of(0x31, crsa, rsl, NULL, 0, &certs_rsa_n);
    SIGN_(krsa, "SHA256", 20);
    CR("assembled/pss_salt20", crsa, rsl, DIGALG256, 13, pss20, a_pssl, certs_rsa, certs_rsa_n, 0, d256, 32);
    SIGN_(krsa, "SHA256", 32);
    CR("assembled/pss_with_ec_key", cec, ecl, DIGALG256, 13, a_pss, a_pssl, certs_ec, cec_n, 0, d256, 32);
    SIGN_(krsa, "SHA256", 0);
    CR("assembled/rsa_encryption_sha256", crsa, rsl, DIGALG256, 13, RSA_ENC, sizeof RSA_ENC, certs_rsa, certs_rsa_n, 0, d256, 32);
    CR("assembled/pkcs1_params_absent", crsa, rsl, DIGALG256, 13, PKCS1_ABSENT, sizeof PKCS1_ABSENT, certs_rsa, certs_rsa_n, 0, d256, 32);
    CR("assembled/pkcs1_params_integer", crsa, rsl, DIGALG256, 13, PKCS1_INT, sizeof PKCS1_INT, certs_rsa, certs_rsa_n, 0, d256, 32);
    an = attrs_of(attrs, d384, 48, 0x04, 0); SIGN_(krsa, "SHA384", 0);
    CR("assembled/rsa_encryption_sha384", crsa, rsl, DIGALG384, 13, RSA_ENC, sizeof RSA_ENC, certs_rsa, certs_rsa_n, 0, d384, 48);
    free(certs_rsa);

    an = attrs_of(attrs, d512, 64, 0x04, 0);
    sl = sizeof sig;
    if (comp_sign(NULL, attrs, an, sig, &sl) != FHSM_RV_OK) abort();
    CR("assembled/composite", CA_COMP, CA_COMP_LEN, DIGALG256, 13, a_comp, a_compl, certs_comp, ccomp_n, 0, d512, 64);
    CR("assembled/composite_params_null", CA_COMP, CA_COMP_LEN, DIGALG256, 13, COMP_NULL, sizeof COMP_NULL, certs_comp, ccomp_n, 0, d512, 64);
    CR("assembled/composite_ed25519_cert", CA_ED, CA_ED_LEN, DIGALG256, 13, a_comp, a_compl, certs_ed, ced_n, 0, d512, 64);
    CR("assembled/composite_two_certs", CA_COMP, CA_COMP_LEN, DIGALG256, 13, a_comp, a_compl, certs_two, two_n, 0, d512, 64);
    CR("assembled/composite_two_signers", CA_COMP, CA_COMP_LEN, DIGALG256, 13, a_comp, a_compl, certs_comp, ccomp_n, 1, d512, 64);
    /* pinned as C answers them (review H1, M4): the SignerIdentifier is not checked against the
     * certificate, nor the digestAlgorithm against the composite's SHA-512 */
    CR("assembled/composite_names_other_cert", cec, ecl, DIGALG256, 13, a_comp, a_compl, certs_comp, ccomp_n, 0, d512, 64);
    CR("assembled/composite_digalg_sha1", CA_COMP, CA_COMP_LEN, DIGALG_SHA1, sizeof DIGALG_SHA1, a_comp, a_compl, certs_comp, ccomp_n, 0, d512, 64);
    sl -= 10;
    CR("assembled/composite_sig_short", CA_COMP, CA_COMP_LEN, DIGALG256, 13, a_comp, a_compl, certs_comp, ccomp_n, 0, d512, 64);
    an = attrs_of(attrs, d512, 64, 0, 0);
    sl = sizeof sig;
    if (comp_sign(NULL, attrs, an, sig, &sl) != FHSM_RV_OK) abort();
    CR("assembled/composite_no_message_digest", CA_COMP, CA_COMP_LEN, DIGALG256, 13, a_comp, a_compl, certs_comp, ccomp_n, 0, d512, 64);
    an = attrs_of(attrs, d512, 64, 0x02, 0);
    sl = sizeof sig;
    if (comp_sign(NULL, attrs, an, sig, &sl) != FHSM_RV_OK) abort();
    CR("assembled/composite_message_digest_integer", CA_COMP, CA_COMP_LEN, DIGALG256, 13, a_comp, a_compl, certs_comp, ccomp_n, 0, d512, 64);
    an = attrs_of(attrs, d512, 64, 0x04, 1);
    sl = sizeof sig;
    if (comp_sign(NULL, attrs, an, sig, &sl) != FHSM_RV_OK) abort();
    CR("assembled/composite_attrs_unsorted", CA_COMP, CA_COMP_LEN, DIGALG256, 13, a_comp, a_compl, certs_comp, ccomp_n, 0, d512, 64);

    /* the pointer checks */
    const char *dn = "x";
    fprintf(f, "cms_verify:null_cms\tcomposite=0x%x;pki=0x%x\n",
            (unsigned)fhsm_composite_cms_verify(ALG, NULL, 10, d512, 64), (unsigned)fhsm_pki_cms_verify(NULL, 10, d512, 64));
    fprintf(f, "cms_verify:null_digest\tcomposite=0x%x;pki=0x%x\n",
            (unsigned)fhsm_composite_cms_verify(ALG, CMSB, cl, NULL, 64), (unsigned)fhsm_pki_cms_verify(CMSB, cl, NULL, 64));
    fprintf(f, "cms_verify:alg0\tcomposite=0x%x\n", (unsigned)fhsm_composite_cms_verify(0, CMSB, cl, d512, 64));
    fhsm_rv_t r = fhsm_pki_cms_digest(NULL, 10, &dn);
    fprintf(f, "cms_digest:null_cms\trv=0x%x;name=%s\n", (unsigned)r, dn ? dn : "-");
    fprintf(f, "cms_digest:null_name\trv=0x%x\n", (unsigned)fhsm_pki_cms_digest(CMSB, cl, NULL));
    dn = "x";
    r = fhsm_pki_cms_digest(CMSB, 3, &dn);
    fprintf(f, "cms_digest:garbage\trv=0x%x;name=%s\n", (unsigned)r, dn ? dn : "-");
    free(certs_ed); free(certs_ec); free(certs_comp); free(certs_two);
    free(cec); free(crsa); free(cml);
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: gen_x509 <out dir>\n"); return 2; }
    char path[512];
    snprintf(path, sizeof path, "%s/x509.tsv", argv[1]);
    if (!(f = fopen(path, "w"))) return 1;
    snprintf(path, sizeof path, "%s/x509_fixture.tsv", argv[1]);
    if (!(fx = fopen(path, "w"))) return 1;
    fprintf(f, "# Generated by tests-support/golden/gen_x509.c from the legacy C code. Do not edit.\n"
               "# name\tresult  (pki/tests/x509_golden.rs)\n");
    fprintf(fx, "# Inputs for x509.tsv: fresh test keys' public halves, AlgorithmIdentifiers, requests and\n"
                "# CA certificates (tests-support/golden/gen_x509.c). Not credentials: made for the goldens.\n");

    if (fhsm_composite_keygen(ALG, PRIV, &PRIV_LEN, PUB, &PUB_LEN) != FHSM_RV_OK) abort();
    EVP_PKEY *ked = EVP_PKEY_Q_keygen(NULL, NULL, "ED25519");
    EVP_PKEY *kec = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
    EVP_PKEY *krsa = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    EVP_PKEY *kml = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-44");
    if (!ked || !kec || !krsa || !kml) abort();

    size_t n;
    fhsm_pki_signer_t ed, ec, rsa, ml, comp;
    ed.algid = algid(FHSM_PKI_SIG_ED25519, &ed.algid_len);
    ec.algid = algid(FHSM_PKI_SIG_ECDSA_SHA256, &ec.algid_len);
    rsa.algid = algid(FHSM_PKI_SIG_RSA_PSS_SHA256, &rsa.algid_len);
    ml.algid = algid(FHSM_PKI_SIG_MLDSA44, &ml.algid_len);
    comp.algid = algid(FHSM_PKI_SIG_COMPOSITE_MLDSA65_ED25519, &comp.algid_len);
    ed.spki = der_of(ked, &ed.spki_len);
    ec.spki = der_of(kec, &ec.spki_len);
    rsa.spki = der_of(krsa, &rsa.spki_len);
    ml.spki = der_of(kml, &ml.spki_len);
    static uint8_t comp_spki[4096];
    n = sizeof comp_spki;
    if (fhsm_composite_spki(ALG, PUB, PUB_LEN, comp_spki, &n) != FHSM_RV_OK) abort();
    comp.spki = comp_spki;
    comp.spki_len = n;
    fhsm_pki_signer_t *all[] = { &ed, &ec, &rsa, &ml, &comp };
    for (size_t i = 0; i < 5; ++i) { all[i]->sign = fake_sign; all[i]->sign_ctx = NULL; }

    fixture("pub", PUB, PUB_LEN);
    fixture("priv", PRIV, PRIV_LEN);
    const struct { const char *name; fhsm_pki_signer_t *s; } sg[] = {
        { "ed25519", &ed }, { "ec", &ec }, { "rsa", &rsa }, { "mldsa44", &ml }, { "composite", &comp },
    };
    for (size_t i = 0; i < 5; ++i) {
        char nm[64];
        snprintf(nm, sizeof nm, "algid_%s", sg[i].name);
        fixture(nm, sg[i].s->algid, sg[i].s->algid_len);
        snprintf(nm, sizeof nm, "spki_%s", sg[i].name);
        fixture(nm, sg[i].s->spki, sg[i].s->spki_len);
    }

    key_cases();
    csr_cases(ed, ec, rsa, ml, comp);
    selfsigned_cases(ed, ec, rsa, ml);
    issue_cases(ed, comp, ked, kec);
    algid_cases();
    crl_tbs_cases(ed.algid, ed.algid_len);
    crl_cases(ed, ked);
    ocsp_single_cases();
    ocsp_tbs_cases();
    ocsp_cases(ed);
    for (size_t i = 0; i < sizeof D64; ++i) D64[i] = (uint8_t)(i * 3 + 1);
    ecdsa_cases();
    {
        uint8_t *iss = NULL;
        const uint8_t *p = CA_ED;
        X509 *x = d2i_X509(NULL, &p, (long)CA_ED_LEN);
        int il = x ? i2d_X509_NAME(X509_get_issuer_name(x), &iss) : -1;
        if (il <= 0) abort();
        fixture("ca_ed_issuer", iss, (size_t)il);
        cms_si_cases(iss, (size_t)il, ed.algid, ed.algid_len);
        OPENSSL_free(iss);
        X509_free(x);
    }
    cms_wrap_cases(CA_ED, CA_ED_LEN);
    pki_cms_cases(ed, ec, rsa, ml, comp, ked);
    cms_verify_cases(ed, ec, rsa, ml, ked, kec, krsa, kml);
    return (fclose(f) != 0) | (fclose(fx) != 0);
}
