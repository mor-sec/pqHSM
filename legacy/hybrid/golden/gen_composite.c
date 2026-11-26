/* Phase 3 slice 5a: what the legacy composite combiner, key generation, signing and verification
 * (src/fhsm_composite.c:1-481) return and write.
 *
 *   gen_composite <out dir>      writes composite.tsv and composite_fixture.tsv
 *
 * composite.tsv: one row per call, `name<TAB>rv=0x..;len=..;out=<hex>`, every output buffer
 * prefilled with 0xAA so what a call writes, and what it leaves, is visible. Keys are random, so
 * key generation records only lengths and the blob framing. composite_fixture.tsv holds one
 * fresh test key pair from fhsm_composite_keygen and the C's signatures with it; signing is
 * replayed against them (the Ed25519 half is deterministic, the ML-DSA half is checked by
 * verifying it). The Rust replay is pki/tests/composite_golden.rs. */
#include "fhsm_common.h"
#include "fhsm_composite.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALG FHSM_COMPOSITE_MLDSA65_ED25519_SHA512
#define SIG_LEN (3309 + 64)

static FILE *f;

static void hex(FILE *o, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; ++i) fprintf(o, "%02x", p[i]);
}

/* rv, the length left in *len, and the first `shown` bytes of the buffer */
static void row(const char *name, fhsm_rv_t rv, size_t len, const uint8_t *buf, size_t shown) {
    fprintf(f, "%s\trv=0x%x;len=%zu;out=", name, (unsigned)rv, len);
    if (buf) hex(f, buf, shown);
    fputc('\n', f);
}

static const uint8_t MSG[] = "the message signed by the composite goldens";
static uint8_t CTX[256];

static void mprime_cases(void) {
    uint8_t out[512], ph[64];
    size_t n;
    memset(ph, 0x5c, sizeof ph);
#define MP(name, alg, msg, mlen, ctx, clen, cap)                                       \
    do {                                                                               \
        memset(out, 0xAA, sizeof out); n = (cap);                                      \
        fhsm_rv_t r = fhsm_composite_mprime((alg), (msg), (mlen), (ctx), (clen), out, &n); \
        row("mprime:" name, r, n, out, (cap) < sizeof out ? (cap) : sizeof out);       \
    } while (0)
    MP("alg0", 0, MSG, sizeof MSG, NULL, 0, 200);
    MP("alg2", 2, MSG, sizeof MSG, NULL, 0, 200);
    MP("null_msg_len", ALG, NULL, 3, NULL, 0, 200);
    MP("null_msg_empty", ALG, NULL, 0, NULL, 0, 200);
    MP("empty_msg", ALG, MSG, 0, NULL, 0, 200);
    MP("null_ctx_len", ALG, MSG, sizeof MSG, NULL, 2, 200);
    MP("ctx_255", ALG, MSG, sizeof MSG, CTX, 255, 400);
    MP("ctx_256", ALG, MSG, sizeof MSG, CTX, 256, 400);
    MP("ctx_1", ALG, MSG, sizeof MSG, CTX, 1, 200);
    MP("cap_0", ALG, MSG, sizeof MSG, NULL, 0, 0);
    MP("cap_short", ALG, MSG, sizeof MSG, NULL, 0, 126);
    MP("cap_exact", ALG, MSG, sizeof MSG, NULL, 0, 127);
    MP("cap_more", ALG, MSG, sizeof MSG, NULL, 0, 140);
    MP("ctx_3_cap_short", ALG, MSG, sizeof MSG, CTX, 3, 129);
    n = 200;
    row("mprime:null_out", fhsm_composite_mprime(ALG, MSG, sizeof MSG, NULL, 0, NULL, &n), n, NULL, 0);
    row("mprime:null_out_len", fhsm_composite_mprime(ALG, MSG, sizeof MSG, NULL, 0, out, NULL), 0, NULL, 0);
#define PH(name, alg, p, plen, ctx, clen, cap)                                         \
    do {                                                                               \
        memset(out, 0xAA, sizeof out); n = (cap);                                      \
        fhsm_rv_t r = fhsm_composite_mprime_prehashed((alg), (p), (plen), (ctx), (clen), out, &n); \
        row("mprime_ph:" name, r, n, out, (cap) < sizeof out ? (cap) : sizeof out);    \
    } while (0)
    PH("alg0", 0, ph, 64, NULL, 0, 200);
    PH("null_ph", ALG, NULL, 64, NULL, 0, 200);
    PH("ph_63", ALG, ph, 63, NULL, 0, 200);
    PH("ph_65", ALG, ph, 65, NULL, 0, 200);
    PH("null_ctx_len", ALG, ph, 64, NULL, 2, 200);
    PH("ctx_256", ALG, ph, 64, CTX, 256, 400);
    PH("ctx_255", ALG, ph, 64, CTX, 255, 400);
    PH("cap_short", ALG, ph, 64, CTX, 7, 133);
    PH("cap_exact", ALG, ph, 64, CTX, 7, 134);
    PH("ok", ALG, ph, 64, NULL, 0, 200);
    n = 200;
    row("mprime_ph:null_out", fhsm_composite_mprime_prehashed(ALG, ph, 64, NULL, 0, NULL, &n), n, NULL, 0);
    row("mprime_ph:null_out_len", fhsm_composite_mprime_prehashed(ALG, ph, 64, NULL, 0, out, NULL), 0, NULL, 0);
}

static void table_cases(void) {
    for (int alg = 0; alg <= 2; ++alg) {
        const fhsm_composite_params_t *p = fhsm_composite_params((fhsm_composite_alg_t)alg);
        if (!p) { fprintf(f, "params:%d\tNULL\n", alg); continue; }
        fprintf(f, "params:%d\talg=%d;name=%s;oid=%s;label=%s;label_len=%zu;ph_name=%s;ph_len=%zu\n",
                alg, (int)p->alg, p->name, p->oid, p->label, p->label_len, p->ph_name, p->ph_len);
    }
    for (int alg = 0; alg <= 2; ++alg) {
        const char *ph = fhsm_composite_ph_name((fhsm_composite_alg_t)alg);
        fprintf(f, "ph:%d\tname=%s;len=%zu\n", alg, ph ? ph : "NULL",
                fhsm_composite_ph_len((fhsm_composite_alg_t)alg));
        const size_t ctx[] = { 0, 1, 255, 256, (size_t)-1 };
        for (size_t i = 0; i < sizeof ctx / sizeof ctx[0]; ++i)
            fprintf(f, "mprime_len:%d:%zu\t%zu\n", alg, ctx[i],
                    fhsm_composite_mprime_len((fhsm_composite_alg_t)alg, ctx[i]));
    }
    uint8_t sig[1];
    size_t pq = 77, tr = 77;
    const size_t lens[] = { 0, SIG_LEN - 1, SIG_LEN, SIG_LEN + 1 };
    for (size_t i = 0; i < sizeof lens / sizeof lens[0]; ++i) {
        pq = tr = 77;
        fhsm_rv_t r = fhsm_composite_split(ALG, sig, lens[i], &pq, &tr);
        fprintf(f, "split:%zu\trv=0x%x;pq=%zu;trad=%zu\n", lens[i], (unsigned)r, pq, tr);
    }
    pq = tr = 77;
    fprintf(f, "split:alg0\trv=0x%x\n", (unsigned)fhsm_composite_split(0, sig, SIG_LEN, &pq, &tr));
    fprintf(f, "split:null_sig\trv=0x%x\n", (unsigned)fhsm_composite_split(ALG, NULL, SIG_LEN, &pq, &tr));
    fprintf(f, "split:null_pq\trv=0x%x\n", (unsigned)fhsm_composite_split(ALG, sig, SIG_LEN, NULL, &tr));
    fprintf(f, "split:null_trad\trv=0x%x\n", (unsigned)fhsm_composite_split(ALG, sig, SIG_LEN, &pq, NULL));
}

/* A blob's framing, which does not depend on the key: magic, version, alg, both lengths. */
static void framing(const char *name, fhsm_rv_t rv, const uint8_t *b, size_t n) {
    fprintf(f, "%s\trv=0x%x;len=%zu", name, (unsigned)rv, n);
    if (rv == FHSM_RV_OK && n >= 8) {
        size_t n1 = (size_t)b[6] | (size_t)b[7] << 8;
        size_t n2 = (size_t)b[8 + n1] | (size_t)b[9 + n1] << 8;
        fprintf(f, ";head=");
        hex(f, b, 6);
        fprintf(f, ";pq=%zu;trad=%zu", n1, n2);
    }
    fputc('\n', f);
}

static uint8_t PRIV[8192], PUB[4096];
static size_t PRIV_LEN, PUB_LEN;

static void keygen_cases(void) {
    uint8_t a[8192], b[4096];
    size_t na, nb;
#define KG(name, alg, pa, pna, pb, pnb, ca, cb)                                        \
    do {                                                                               \
        na = (ca); nb = (cb); memset(a, 0xAA, sizeof a); memset(b, 0xAA, sizeof b);     \
        fhsm_rv_t r = fhsm_composite_keygen((alg), (pa), (pna), (pb), (pnb));          \
        framing("keygen:" name ":priv", r, a, na);                                     \
        framing("keygen:" name ":pub", r, b, nb);                                      \
        fprintf(f, "keygen:" name ":untouched\tpriv=%d;pub=%d\n", a[0] == 0xAA, b[0] == 0xAA); \
    } while (0)
    KG("alg0", 0, a, &na, b, &nb, sizeof a, sizeof b);
    KG("null_priv", ALG, NULL, &na, b, &nb, sizeof a, sizeof b);
    KG("null_priv_len", ALG, a, NULL, b, &nb, sizeof a, sizeof b);
    KG("null_pub", ALG, a, &na, NULL, &nb, sizeof a, sizeof b);
    KG("null_pub_len", ALG, a, &na, b, NULL, sizeof a, sizeof b);
    KG("priv_short", ALG, a, &na, b, &nb, 100, sizeof b);
    KG("pub_short", ALG, a, &na, b, &nb, sizeof a, 100);
    KG("ok", ALG, a, &na, b, &nb, sizeof a, sizeof b);
    PRIV_LEN = sizeof PRIV; PUB_LEN = sizeof PUB;
    if (fhsm_composite_keygen(ALG, PRIV, &PRIV_LEN, PUB, &PUB_LEN) != FHSM_RV_OK) abort();
}

/* A copy of `src` with one change, for the framing and DER refusals. */
static uint8_t BAD[8192];
static size_t bad(const uint8_t *src, size_t n, size_t at, int xor, long trim) {
    memcpy(BAD, src, n);
    if (at < n) BAD[at] ^= (uint8_t)xor;
    return (size_t)((long)n + trim);
}

static uint8_t SIG[SIG_LEN], SIG_CTX[SIG_LEN], SIG_PH[SIG_LEN];
static const uint8_t PH64[64] = { 1, 2, 3, 4, 5, 6, 7, 8 };

static void sign_cases(void) {
    uint8_t s[SIG_LEN + 100];
    size_t n;
#define SG(name, alg, k, kn, msg, mlen, ctx, clen, cap)                                \
    do {                                                                               \
        memset(s, 0xAA, sizeof s); n = (cap);                                          \
        fhsm_rv_t r = fhsm_composite_sign((alg), (k), (kn), (msg), (mlen), (ctx), (clen), s, &n); \
        fprintf(f, "sign:" name "\trv=0x%x;len=%zu", (unsigned)r, n);                  \
        if (r == FHSM_RV_OK) {                                                         \
            fprintf(f, ";ed25519="); hex(f, s + 3309, 64);                             \
            fprintf(f, ";verifies=0x%x", (unsigned)fhsm_composite_verify(ALG, PUB, PUB_LEN, \
                    (msg), (mlen), (ctx), (clen), s, n));                              \
        }                                                                              \
        fputc('\n', f);                                                                \
    } while (0)
    SG("alg0", 0, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("ctx_256", ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, CTX, 256, sizeof s);
    SG("null_ctx_len", ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 1, sizeof s);
    SG("null_msg_len", ALG, PRIV, PRIV_LEN, NULL, 1, NULL, 0, sizeof s);
    SG("short_blob", ALG, PRIV, 9, MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("bad_magic", ALG, BAD, bad(PRIV, PRIV_LEN, 0, 1, 0), MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("bad_version", ALG, BAD, bad(PRIV, PRIV_LEN, 4, 2, 0), MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("other_alg", ALG, BAD, bad(PRIV, PRIV_LEN, 5, 3, 0), MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("pq_len_past_end", ALG, BAD, bad(PRIV, PRIV_LEN, 7, 0x40, 0), MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("trailing_byte", ALG, BAD, bad(PRIV, PRIV_LEN, PRIV_LEN, 0, 1), MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("missing_byte", ALG, BAD, bad(PRIV, PRIV_LEN, PRIV_LEN, 0, -1), MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("bad_pq_der", ALG, BAD, bad(PRIV, PRIV_LEN, 8, 0xFF, 0), MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("bad_trad_der", ALG, BAD, bad(PRIV, PRIV_LEN, PRIV_LEN - 30, 0xFF, 0), MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("pub_as_priv", ALG, PUB, PUB_LEN, MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("cap_0", ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 0, 0);
    SG("cap_pq_short", ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 0, 3308);
    SG("cap_pq_only", ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 0, 3309);
    SG("cap_ed_short", ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 0, SIG_LEN - 1);
    SG("cap_exact", ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 0, SIG_LEN);
    SG("cap_more", ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 0, sizeof s);
    SG("ctx_5", ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, CTX, 5, sizeof s);
    SG("empty_msg", ALG, PRIV, PRIV_LEN, MSG, 0, NULL, 0, sizeof s);
    n = sizeof s;
    fprintf(f, "sign:null_priv\trv=0x%x\n", (unsigned)fhsm_composite_sign(ALG, NULL, PRIV_LEN, MSG, sizeof MSG, NULL, 0, s, &n));
    fprintf(f, "sign:null_sig\trv=0x%x\n", (unsigned)fhsm_composite_sign(ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 0, NULL, &n));
    fprintf(f, "sign:null_sig_len\trv=0x%x\n", (unsigned)fhsm_composite_sign(ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 0, s, NULL));
    n = sizeof s;
    fhsm_rv_t r = fhsm_composite_sign_prehashed(ALG, PRIV, PRIV_LEN, PH64, 63, NULL, 0, s, &n);
    fprintf(f, "sign_ph:ph_63\trv=0x%x;len=%zu\n", (unsigned)r, n);
    n = sizeof s;
    fprintf(f, "sign_ph:null_priv\trv=0x%x\n", (unsigned)fhsm_composite_sign_prehashed(ALG, NULL, PRIV_LEN, PH64, 64, NULL, 0, s, &n));
    fprintf(f, "sign_ph:null_sig\trv=0x%x\n", (unsigned)fhsm_composite_sign_prehashed(ALG, PRIV, PRIV_LEN, PH64, 64, NULL, 0, NULL, &n));
    fprintf(f, "sign_ph:null_sig_len\trv=0x%x\n", (unsigned)fhsm_composite_sign_prehashed(ALG, PRIV, PRIV_LEN, PH64, 64, NULL, 0, s, NULL));
    n = sizeof s;
    fprintf(f, "sign_ph:ctx_256\trv=0x%x;len=%zu\n", (unsigned)fhsm_composite_sign_prehashed(ALG, PRIV, PRIV_LEN, PH64, 64, CTX, 256, s, &n), n);
    n = sizeof s;
    fprintf(f, "sign_ph:other_alg\trv=0x%x\n", (unsigned)fhsm_composite_sign_prehashed(ALG, BAD, bad(PRIV, PRIV_LEN, 5, 3, 0), PH64, 64, NULL, 0, s, &n));

    /* the fixture signatures */
    n = SIG_LEN;
    if (fhsm_composite_sign(ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 0, SIG, &n) != FHSM_RV_OK) abort();
    n = SIG_LEN;
    if (fhsm_composite_sign(ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, CTX, 9, SIG_CTX, &n) != FHSM_RV_OK) abort();
    n = SIG_LEN;
    if (fhsm_composite_sign_prehashed(ALG, PRIV, PRIV_LEN, PH64, 64, CTX, 9, SIG_PH, &n) != FHSM_RV_OK) abort();
}

static void verify_cases(void) {
    uint8_t s[SIG_LEN];
#define VF(name, alg, k, kn, msg, mlen, ctx, clen, sg, sn)                             \
    fprintf(f, "verify:" name "\trv=0x%x\n", (unsigned)fhsm_composite_verify((alg), (k), (kn), \
            (msg), (mlen), (ctx), (clen), (sg), (sn)))
    VF("ok", ALG, PUB, PUB_LEN, MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN);
    VF("ok_ctx", ALG, PUB, PUB_LEN, MSG, sizeof MSG, CTX, 9, SIG_CTX, SIG_LEN);
    VF("ctx_missing", ALG, PUB, PUB_LEN, MSG, sizeof MSG, NULL, 0, SIG_CTX, SIG_LEN);
    VF("ctx_added", ALG, PUB, PUB_LEN, MSG, sizeof MSG, CTX, 9, SIG, SIG_LEN);
    VF("ctx_other", ALG, PUB, PUB_LEN, MSG, sizeof MSG, CTX + 1, 9, SIG_CTX, SIG_LEN);
    VF("msg_other", ALG, PUB, PUB_LEN, MSG, sizeof MSG - 1, NULL, 0, SIG, SIG_LEN);
    VF("ctx_256", ALG, PUB, PUB_LEN, MSG, sizeof MSG, CTX, 256, SIG, SIG_LEN);
    VF("alg0", 0, PUB, PUB_LEN, MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN);
    VF("null_pub", ALG, NULL, PUB_LEN, MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN);
    VF("null_sig", ALG, PUB, PUB_LEN, MSG, sizeof MSG, NULL, 0, NULL, SIG_LEN);
    VF("sig_short", ALG, PUB, PUB_LEN, MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN - 1);
    memcpy(s, SIG, SIG_LEN); s[100] ^= 1;
    VF("pq_flipped", ALG, PUB, PUB_LEN, MSG, sizeof MSG, NULL, 0, s, SIG_LEN);
    memcpy(s, SIG, SIG_LEN); s[3309 + 10] ^= 1;
    VF("ed_flipped", ALG, PUB, PUB_LEN, MSG, sizeof MSG, NULL, 0, s, SIG_LEN);
    VF("short_blob", ALG, PUB, 9, MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN);
    VF("bad_magic", ALG, BAD, bad(PUB, PUB_LEN, 1, 1, 0), MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN);
    VF("bad_version", ALG, BAD, bad(PUB, PUB_LEN, 4, 1, 0), MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN);
    VF("other_alg", ALG, BAD, bad(PUB, PUB_LEN, 5, 2, 0), MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN);
    VF("trailing_byte", ALG, BAD, bad(PUB, PUB_LEN, PUB_LEN, 0, 1), MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN);
    VF("bad_pq_der", ALG, BAD, bad(PUB, PUB_LEN, 8, 0xFF, 0), MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN);
    VF("bad_trad_der", ALG, BAD, bad(PUB, PUB_LEN, PUB_LEN - 40, 0xFF, 0), MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN);
    VF("priv_as_pub", ALG, PRIV, PRIV_LEN, MSG, sizeof MSG, NULL, 0, SIG, SIG_LEN);
#define VP(name, alg, p, plen, ctx, clen, sg, sn)                                      \
    fprintf(f, "verify_ph:" name "\trv=0x%x\n", (unsigned)fhsm_composite_verify_prehashed((alg), \
            PUB, PUB_LEN, (p), (plen), (ctx), (clen), (sg), (sn)))
    VP("ok", ALG, PH64, 64, CTX, 9, SIG_PH, SIG_LEN);
    VP("ph_other", ALG, PH64 + 1, 63, CTX, 9, SIG_PH, SIG_LEN);
    VP("ctx_other", ALG, PH64, 64, CTX, 8, SIG_PH, SIG_LEN);
    VP("one_shot_sig", ALG, PH64, 64, CTX, 9, SIG_CTX, SIG_LEN);
    VP("null_ph", ALG, NULL, 64, CTX, 9, SIG_PH, SIG_LEN);
    fprintf(f, "verify_ph:null_pub\trv=0x%x\n", (unsigned)fhsm_composite_verify_prehashed(ALG, NULL, PUB_LEN, PH64, 64, CTX, 9, SIG_PH, SIG_LEN));
    fprintf(f, "verify_ph:null_sig\trv=0x%x\n", (unsigned)fhsm_composite_verify_prehashed(ALG, PUB, PUB_LEN, PH64, 64, CTX, 9, NULL, SIG_LEN));
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: gen_composite <out dir>\n"); return 2; }
    for (size_t i = 0; i < sizeof CTX; ++i) CTX[i] = (uint8_t)(i * 7 + 1);
    char path[512];
    snprintf(path, sizeof path, "%s/composite.tsv", argv[1]);
    if (!(f = fopen(path, "w"))) return 1;
    fprintf(f, "# Generated by tests-support/golden/gen_composite.c from the legacy C code. Do not edit.\n"
               "# name\tresult  (pki/tests/composite_golden.rs)\n");
    table_cases();
    mprime_cases();
    keygen_cases();
    sign_cases();
    verify_cases();
    if (fclose(f) != 0) return 1;

    snprintf(path, sizeof path, "%s/composite_fixture.tsv", argv[1]);
    if (!(f = fopen(path, "w"))) return 1;
    fprintf(f, "# A fresh test key pair from the legacy fhsm_composite_keygen, and the C's signatures with\n"
               "# it (tests-support/golden/gen_composite.c). Not a credential: generated for the goldens.\n");
    const struct { const char *name; const uint8_t *p; size_t n; } fx[] = {
        { "priv", PRIV, PRIV_LEN }, { "pub", PUB, PUB_LEN },
        { "sig", SIG, SIG_LEN }, { "sig_ctx9", SIG_CTX, SIG_LEN }, { "sig_ph_ctx9", SIG_PH, SIG_LEN },
    };
    for (size_t i = 0; i < sizeof fx / sizeof fx[0]; ++i) {
        fprintf(f, "%s\t", fx[i].name);
        hex(f, fx[i].p, fx[i].n);
        fputc('\n', f);
    }
    return fclose(f) != 0;
}
