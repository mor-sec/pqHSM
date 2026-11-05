/* p11_sign.c LIB BASE --- slice 5 of PHASE4_PLAN.md §2: call sequences through the eight sign
 * and verify entry points (C_SignInit, C_Sign, C_SignUpdate, C_SignFinal and the four
 * C_Verify*), one row per call: "label TAB rv TAB n TAB hex", n the length it wrote
 * (pre-filled 0xAAAA), hex the output buffer (pre-filled 0xAA). MACs are deterministic and
 * print whole. Asymmetric keys are generated, so their signatures print as "rnd:<len>" and are
 * checked by verifying them; "twice" rows sign twice and say whether the bytes matched. C and
 * hybrid must print the same apart from recorded DIVs (harness step 4m).
 *
 * Each scenario runs in a forked child with its own tokens directory BASE/<n>.
 *
 * Written from the C (src/fhsm_pkcs11.c:5990-6190, 8943-8975, 9037-9579, 9642-9700,
 * 10728-12662, src/fhsm_pq_params.c, src/fhsm_ecdsa_raw.c) before the Rust, as its
 * characterisation. The composite refusal of the strict build (Q17) is not here: this runs
 * on the default build. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

typedef unsigned long UL;
typedef struct { UL mech; void *p; UL len; } Mech;
typedef struct { UL type; void *p; UL len; } Attr;
typedef UL (*F)();

static void *lib;
static char dir[600];
static unsigned char buf[70000], sig[70000];
static UL sign;

static F sym(const char *name) {
    F f = (F)dlsym(lib, name);
    if (!f) { fprintf(stderr, "no %s\n", name); exit(2); }
    return f;
}
#define P11(name, ...) sym(#name)(__VA_ARGS__)

static void hex(const unsigned char *p, UL n) {
    if (!p || !n) { printf("-"); return; }
    for (UL i = 0; i < n; ++i) printf("%02x", p[i]);
}
static void row(const char *label, UL rv, UL n, const unsigned char *p, UL plen) {
    printf("%s\t%#lx\t%#lx\t", label, rv, n);
    hex(p, plen);
    printf("\n");
}
static void rv_row(const char *label, UL rv) { row(label, rv, 0, NULL, 0); }
/* A row labelled "<n> <l>" for a call's rv; needs char s[200] and const char *n in scope. */
#define R(l, call) do { snprintf(s, sizeof s, "%s %s", n, l); rv_row(s, call); } while (0)

#define SO_PIN   "so-pin-1234"
#define USER_PIN "user-pin-1234"
#define LABEL32  "sign                            "
static unsigned char T = 1, Fb = 0;
static UL c_secret = 4, c_pub = 2, c_priv = 3, k_aes = 0x1f, k_gen = 0x10;
static unsigned char K[64];
static unsigned char IV[16] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
static const unsigned char MSG[64] = "The quick brown fox jumps over the lazy dog, 0123456789ABCDEFGH";
static unsigned char AAD[20] = "header-of-twenty-by!";
static unsigned char P256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static unsigned char ED25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };
static unsigned char ED448[] = { 0x06, 0x03, 0x2B, 0x65, 0x71 };
static unsigned char BIG[300];
#define AT(t, v) { t, &(v), sizeof(v) }
#define AB(t, p, n) { t, (void *)(p), n }

/* CK_GCM_PARAMS, CK_RSA_PKCS_PSS_PARAMS, CK_ML_DSA_PARAMS (and SLH), CK_HASH_ML_DSA_PARAMS,
 * CK_EDDSA_PARAMS. */
typedef struct { void *iv; UL iv_len, iv_bits; void *aad; UL aad_len, tag_bits; } Gcm;
typedef struct { UL hash, mgf, slen; } Pss;
typedef struct { UL hedge; void *ctx; UL ctx_len; } Pq;
typedef struct { UL hedge; void *ctx; UL ctx_len; UL hash; } Hpq;
typedef struct { unsigned char ph; UL ctx_len; void *ctx; } Ed;

/* A token initialised, the user PIN set, a RW session logged in as USER. */
static UL setup(void) {
    UL h = 0, so = 0;
    if (P11(C_Initialize, NULL) || P11(C_InitToken, 0UL, SO_PIN, (UL)strlen(SO_PIN), LABEL32)
        || P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &so)
        || P11(C_Login, so, 0UL, SO_PIN, (UL)strlen(SO_PIN))
        || P11(C_InitPIN, so, USER_PIN, (UL)strlen(USER_PIN)) || P11(C_Logout, so)
        || P11(C_CloseSession, so) || P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h)
        || P11(C_Login, h, 1UL, USER_PIN, (UL)strlen(USER_PIN))) {
        fprintf(stderr, "setup failed\n");
        exit(2);
    }
    return h;
}

/* A secret token key of type kt and n bytes of K, SIGN and VERIFY; extra attributes replace
 * or add. */
static UL secret(UL h, const char *label, UL kt, UL n, Attr *extra, UL ne) {
    Attr t[16] = { AT(0x0, c_secret), AT(0x100, kt), AT(0x1, T), AB(0x3, label, strlen(label)),
                   AB(0x11, K, n), AT(0x108, T), AT(0x10A, T), AT(0x103, Fb) };
    UL nt = 8;
    for (UL i = 0; i < ne; ++i) {
        UL j = 0;
        while (j < nt && t[j].type != extra[i].type) ++j;
        t[j] = extra[i];
        if (j == nt) ++nt;
    }
    UL o = 0xAAAAAAAAUL;
    UL rv = P11(C_CreateObject, h, t, nt, &o);
    char l[160];
    snprintf(l, sizeof l, "create %s", label);
    row(l, rv, rv ? 0 : 1, NULL, 0);
    return rv ? 0 : o;
}

/* A generated key pair, the public key VERIFY, the private one SIGN and sensitive. */
static int pair(UL h, const char *l, UL mech, Attr *pe, UL npe, UL *po, UL *vo) {
    Attr pub[8] = { AT(0x0, c_pub), AT(0x1, T), AT(0x10A, T), AB(0x3, l, strlen(l)) };
    Attr prv[8] = { AT(0x0, c_priv), AT(0x1, T), AT(0x108, T), AT(0x103, T),
                    AB(0x3, l, strlen(l)) };
    UL np = 4;
    for (UL i = 0; i < npe; ++i) pub[np++] = pe[i];
    Mech gen = { mech, NULL, 0 };
    *po = *vo = 0;
    UL rv = P11(C_GenerateKeyPair, h, &gen, pub, np, prv, 5UL, po, vo);
    printf("generate %s\t%#lx\t-\t-\n", l, rv);
    return rv == 0;
}

/* An Init row; on success the operation is ended by a one-shot call over dlen bytes, its rv a
 * row of its own (a signature is not printed). v: 0 sign, 1 verify. */
static UL ini(const char *n, const char *l, int v, UL h, Mech *m, UL k, UL dlen, UL slen) {
    char s[200];
    UL rv;
    snprintf(s, sizeof s, "%s %s", n, l);
    rv_row(s, rv = (v ? sym("C_VerifyInit") : sym("C_SignInit"))(h, m, k));
    if (rv) return rv;
    UL len = sizeof buf;
    memset(buf, 0x5A, slen);
    snprintf(s, sizeof s, "%s %s end", n, l);
    rv_row(s, v ? P11(C_Verify, h, BIG, dlen, buf, slen) : P11(C_Sign, h, BIG, dlen, buf, &len));
    return 0;
}

/* Sign in one call, three ways (size query, 1-byte buffer, a fitting one), then once more
 * after the end. The signature is kept in sig/sign. rnd: print its length only. */
static void one_sign(const char *n, UL h, Mech *m, UL k, const unsigned char *in, UL len,
                     int rnd) {
    char s[200];
    UL l, rv;
    sign = 0;
    R("signinit", rv = P11(C_SignInit, h, m, k));
    if (rv) return;
    l = 0xAAAA;
    snprintf(s, sizeof s, "%s sign size", n);
    rv = P11(C_Sign, h, in, len, NULL, &l);
    row(s, rv, l, NULL, 0);
    memset(buf, 0xAA, 64);
    l = 1;
    snprintf(s, sizeof s, "%s sign 1", n);
    rv = P11(C_Sign, h, in, len, buf, &l);
    row(s, rv, l, rnd ? NULL : buf, 1);
    if (rv != 0x150) R("signinit again", P11(C_SignInit, h, m, k));
    memset(buf, 0xAA, sizeof buf);
    l = sizeof buf;
    snprintf(s, sizeof s, "%s sign", n);
    rv = P11(C_Sign, h, in, len, buf, &l);
    if (rnd && !rv) printf("%s\t0\t%#lx\trnd:%lu\n", s, l, l);
    else row(s, rv, l, buf, rv || l > 256 ? 0 : l);
    if (!rv && l <= sizeof sig) { sign = l; memcpy(sig, buf, l); }
    l = sizeof buf;
    R("sign after", P11(C_Sign, h, in, len, buf, &l));
}

/* Verify the signature in sig/sign over in: as is, tampered, a byte short, other data. */
static void one_verify(const char *n, UL h, Mech *m, UL k, const unsigned char *in, UL len) {
    char s[200];
    UL rv;
    R("verifyinit", rv = P11(C_VerifyInit, h, m, k));
    if (rv) return;
    R("verify", P11(C_Verify, h, in, len, sig, sign));
    R("verify after", P11(C_Verify, h, in, len, sig, sign));
    if (!sign) return;
    sig[sign / 2] ^= 0x10;
    R("verifyinit tampered", P11(C_VerifyInit, h, m, k));
    R("verify tampered", P11(C_Verify, h, in, len, sig, sign));
    sig[sign / 2] ^= 0x10;
    R("verifyinit short", P11(C_VerifyInit, h, m, k));
    R("verify short", P11(C_Verify, h, in, len, sig, sign - 1));
    if (len) {
        R("verifyinit other data", P11(C_VerifyInit, h, m, k));
        R("verify other data", P11(C_Verify, h, in, len - 1, sig, sign));
    }
}

/* Multipart: Updates of a and b bytes, Final three ways; the signature must verify one-shot
 * and in parts, and equals the one-shot one when the scheme is deterministic. */
static void parts(const char *n, UL h, Mech *m, UL k, UL vk, const unsigned char *in, UL a,
                  UL b, int rnd) {
    static unsigned char ps[70000];
    char s[200];
    UL l, rv;
    R("parts signinit", rv = P11(C_SignInit, h, m, k));
    if (rv) return;
    R("parts signupdate 0", rv = P11(C_SignUpdate, h, in, a));
    if (rv) return;
    R("parts signupdate 1", rv = P11(C_SignUpdate, h, in + a, b));
    if (rv) return;
    l = 0xAAAA;
    snprintf(s, sizeof s, "%s parts signfinal size", n);
    rv = P11(C_SignFinal, h, NULL, &l);
    row(s, rv, l, NULL, 0);
    memset(buf, 0xAA, 64);
    l = 1;
    snprintf(s, sizeof s, "%s parts signfinal 1", n);
    rv = P11(C_SignFinal, h, buf, &l);
    row(s, rv, l, rnd ? NULL : buf, 1);
    if (rv != 0x150) return;
    memset(buf, 0xAA, sizeof buf);
    l = sizeof buf;
    snprintf(s, sizeof s, "%s parts signfinal", n);
    rv = P11(C_SignFinal, h, buf, &l);
    if (rnd && !rv) printf("%s\t0\t%#lx\trnd:%lu\n", s, l, l);
    else row(s, rv, l, buf, rv || l > 256 ? 0 : l);
    if (rv || l > sizeof ps) return;
    printf("%s parts equals one-shot\t%d\n", n, l == sign && !memcmp(buf, sig, l));
    UL pl = l;
    memcpy(ps, buf, pl);
    R("parts signfinal after", P11(C_SignFinal, h, buf, &l));
    R("parts verifyinit", P11(C_VerifyInit, h, m, vk));
    R("parts verify one-shot", P11(C_Verify, h, in, a + b, ps, pl));
    R("parts verifyinit 2", P11(C_VerifyInit, h, m, vk));
    R("parts verifyupdate 0", P11(C_VerifyUpdate, h, in, a));
    R("parts verifyupdate 1", P11(C_VerifyUpdate, h, in + a, b));
    R("parts verifyfinal", P11(C_VerifyFinal, h, ps, pl));
    R("parts verifyfinal after", P11(C_VerifyFinal, h, ps, pl));
    ps[0] ^= 1;
    R("parts verifyinit tampered", P11(C_VerifyInit, h, m, vk));
    R("parts verifyupdate tampered", P11(C_VerifyUpdate, h, in, a + b));
    R("parts verifyfinal tampered", P11(C_VerifyFinal, h, ps, pl));
    R("parts verifyinit no update", P11(C_VerifyInit, h, m, vk));
    R("parts verifyfinal no update", P11(C_VerifyFinal, h, ps, pl));
}

/* Everything one mechanism does: one-shot sign and verify, and in parts. vk: the verify key. */
static void mech(const char *n, UL h, Mech *m, UL k, UL vk, const unsigned char *in, UL len,
                 int rnd) {
    one_sign(n, h, m, k, in, len, rnd);
    one_verify(n, h, m, vk, in, len);
    if (len >= 2) parts(n, h, m, k, vk, in, len / 2, len - len / 2, rnd);
}

/* Signed twice, compared. */
static void twice(const char *n, UL h, Mech *m, UL k, const unsigned char *in, UL len) {
    static unsigned char a[70000];
    UL la = sizeof a, lb = sizeof buf, r1, r2;
    P11(C_SignInit, h, m, k);
    r1 = P11(C_Sign, h, in, len, a, &la);
    P11(C_SignInit, h, m, k);
    r2 = P11(C_Sign, h, in, len, buf, &lb);
    printf("%s twice\t%#lx\t%#lx\t%d\n", n, r1, r2, !r1 && !r2 && la == lb && !memcmp(a, buf, la));
}

/* 0: C_SignInit's and C_VerifyInit's checks, and every parameter shape. */
static void s_init(void) {
    UL h = setup(), s2 = 0;
    char s[200];
    const char *n;
    for (int i = 0; i < 64; ++i) K[i] = (unsigned char)i;
    UL hm = secret(h, "hmac32", k_gen, 32, NULL, 0);
    UL a16 = secret(h, "aes16", k_aes, 16, NULL, 0);
    Attr nos[] = { AT(0x108, Fb), AT(0x10A, Fb) };
    UL hm_nosign = secret(h, "hmac nosign", k_gen, 32, nos, 2);
    UL allowed = 0x251;
    Attr am[] = { AB(0x40000600, &allowed, sizeof allowed) };
    UL hm_only256 = secret(h, "hmac only256", k_gen, 32, am, 1);
    UL ep = 0, ev = 0, rp = 0, rk = 0, mp = 0, mv = 0, dp = 0, dv = 0, ep4 = 0, ev4 = 0;
    UL bits = 2048, ps44 = 1;
    unsigned char e3[] = { 1, 0, 1 };
    Attr ecp[] = { AB(0x180, P256, sizeof P256) }, edp[] = { AB(0x180, ED25519, sizeof ED25519) };
    Attr ed4p[] = { AB(0x180, ED448, sizeof ED448) };
    Attr rsap[] = { AT(0x121, bits), AT(0x122, e3) };
    Attr mlp[] = { AT(0x61D, ps44) };
    pair(h, "ec", 0x1040, ecp, 1, &ep, &ev);
    pair(h, "rsa", 0x0, rsap, 2, &rp, &rk);
    pair(h, "mldsa44", 0x1C, mlp, 1, &mp, &mv);
    pair(h, "ed25519", 0x1055, edp, 1, &dp, &dv);
    pair(h, "ed448", 0x1055, ed4p, 1, &ep4, &ev4);
    Mech m256 = { 0x251, NULL, 0 }, m512 = { 0x271, NULL, 0 }, bad = { 0x99999, NULL, 0 };
    Mech sha1rsa = { 0x6, NULL, 0 }, x509 = { 0x3, NULL, 0 }, comp = { 0x80004202UL, NULL, 0 };
    Mech ecdsa = { 0x1044, NULL, 0 }, cmac = { 0x108A, NULL, 0 };
    for (int v = 0; v < 2; ++v) {
        n = v ? "vinit" : "sinit";
        ini(n, "bad session", v, 0x77UL, &m256, hm, 3, 32);
        ini(n, "null mech", v, h, NULL, hm, 3, 32);
        ini(n, "unknown mech", v, h, &bad, hm, 3, 32);
        ini(n, "sha1 rsa", v, h, &sha1rsa, v ? rp : rk, 32, 256);
        ini(n, "x509", v, h, &x509, v ? rp : rk, 256, 256);
        ini(n, "composite", v, h, &comp, v ? rp : rk, 32, 256);
        ini(n, "no key", v, h, &m256, 0x7777UL, 3, 32);
        ini(n, "key 0", v, h, &m256, 0UL, 3, 32);
        ini(n, "hmac with an ec key", v, h, &m256, v ? ep : ev, 3, 32);
        ini(n, "ecdsa with an rsa key", v, h, &ecdsa, v ? rp : rk, 3, 64);
        ini(n, "cmac with a generic key", v, h, &cmac, hm, 3, 16);
        ini(n, "hmac with an aes key", v, h, &m256, a16, 3, 32);
        ini(n, "not allowed", v, h, &m512, hm_only256, 3, 64);
        ini(n, "usage", v, h, &m256, hm_nosign, 3, 32);
        ini(n, "with the other half of the pair", v, h, &ecdsa, v ? ev : ep, 3, 64);
        F init = v ? sym("C_VerifyInit") : sym("C_SignInit");
        R("allowed", init(h, &m256, hm_only256));
        R("active", init(h, &m256, hm));
        R("active, bad mech", init(h, &bad, hm));
        R("active, no key", init(h, &m256, 0x7777UL));
        R("active, null mech", init(h, NULL, hm));
        UL l = sizeof buf;
        R("end", v ? P11(C_Verify, h, MSG, 3UL, buf, 32UL) : P11(C_Sign, h, MSG, 3UL, buf, &l));
        /* GMAC parameters. */
        Gcm g = { IV, 12, 96, NULL, 0, 128 }, g16 = { IV, 16, 128, AAD, 20, 96 };
        Gcm gbad = { IV, 12, 96, NULL, 0, 100 }, gnoiv = { NULL, 12, 96, NULL, 0, 128 };
        Gcm g8 = { IV, 8, 64, NULL, 0, 128 };
        struct { const char *l; void *p; UL len; } G[] = {
            { "gmac none", NULL, 0 }, { "gmac iv 11", IV, 11 }, { "gmac iv 12", IV, 12 },
            { "gmac iv 16", IV, 16 }, { "gmac iv 513", buf, 513 }, { "gmac struct", &g, sizeof g },
            { "gmac struct aad", &g16, sizeof g16 }, { "gmac struct tag 100", &gbad, sizeof gbad },
            { "gmac struct no iv", &gnoiv, sizeof gnoiv }, { "gmac struct iv 8", &g8, sizeof g8 },
            { "gmac null len 12", NULL, 12 },
        };
        for (size_t i = 0; i < sizeof G / sizeof *G; ++i) {
            Mech gm = { 0x108E, G[i].p, G[i].len };
            ini(n, G[i].l, v, h, &gm, a16, 3, 16);
        }
        /* RSA-PSS parameters. */
        Pss p = { 0x250, 2, 32 }, pbig = { 0x250, 2, 2000 }, pneg = { 0x250, 2, (UL)-1 };
        Pss pmgf = { 0x250, 0x77, 32 }, p1024 = { 0x250, 2, 1024 };
        struct { const char *l; UL m; void *p; UL len; } P[] = {
            { "pss none", 0x43, NULL, 0 }, { "pss short", 0x43, &p, 16 },
            { "pss ok", 0x43, &p, sizeof p }, { "pss salt 2000", 0x43, &pbig, sizeof pbig },
            { "pss salt 1024", 0x43, &p1024, sizeof p1024 },
            { "pss salt -1", 0x43, &pneg, sizeof pneg }, { "pss mgf unknown", 0x43, &pmgf, sizeof pmgf },
            { "bare pss none", 0xD, NULL, 0 }, { "bare pss ok", 0xD, &p, sizeof p },
        };
        for (size_t i = 0; i < sizeof P / sizeof *P; ++i) {
            Mech pm = { P[i].m, P[i].p, P[i].len };
            ini(n, P[i].l, v, h, &pm, v ? rp : rk, 32, 256);
        }
        /* ML-DSA parameters. */
        Pq q0 = { 0, NULL, 0 }, q2 = { 2, AAD, 20 }, q3 = { 3, NULL, 0 }, q255 = { 0, BIG, 255 };
        Pq q256 = { 0, BIG, 256 }, q300 = { 0, BIG, 300 }, qnull = { 0, NULL, 5 };
        struct { const char *l; void *p; UL len; } Q[] = {
            { "mldsa none", NULL, 0 }, { "mldsa empty", &q0, sizeof q0 },
            { "mldsa det ctx", &q2, sizeof q2 }, { "mldsa hedge 3", &q3, sizeof q3 },
            { "mldsa ctx 255", &q255, sizeof q255 }, { "mldsa ctx 256", &q256, sizeof q256 },
            { "mldsa ctx 300", &q300, sizeof q300 }, { "mldsa null ctx", &qnull, sizeof qnull },
            { "mldsa short block", &q2, 16 }, { "mldsa null len 24", NULL, 24 },
        };
        for (size_t i = 0; i < sizeof Q / sizeof *Q; ++i) {
            Mech qm = { 0x1D, Q[i].p, Q[i].len };
            ini(n, Q[i].l, v, h, &qm, v ? mp : mv, 3, 2420);
        }
        /* HashML-DSA parameters. */
        Hpq hq = { 0, NULL, 0, 0x250 }, hqbad = { 0, NULL, 0, 0x99 }, hqshake = { 0, NULL, 0, 0 };
        Hpq hq300 = { 0, BIG, 300, 0x250 }, hqnull = { 0, NULL, 4, 0x250 };
        Hpq hq3 = { 3, NULL, 0, 0x250 };
        struct { const char *l; UL m; void *p; UL len; } H[] = {
            { "hashmldsa generic none", 0x1F, NULL, 0 },
            { "hashmldsa generic sha256", 0x1F, &hq, sizeof hq },
            { "hashmldsa generic 3 words", 0x1F, &hq, 24 },
            { "hashmldsa generic bad hash", 0x1F, &hqbad, sizeof hqbad },
            { "hashmldsa generic hash 0", 0x1F, &hqshake, sizeof hqshake },
            { "hashmldsa generic ctx 300", 0x1F, &hq300, sizeof hq300 },
            { "hashmldsa generic null ctx", 0x1F, &hqnull, sizeof hqnull },
            { "hashmldsa generic hedge 3", 0x1F, &hq3, sizeof hq3 },
            { "hashmldsa sha256 none", 0x24, NULL, 0 },
            { "hashmldsa sha256 3 words", 0x24, &hq, 24 },
            { "hashmldsa sha256 4 words", 0x24, &hq, sizeof hq },
            { "hashmldsa sha256 null len", 0x24, NULL, 24 },
            { "hashmldsa sha256 ctx 300", 0x24, &hq300, 24 },
            { "hashslhdsa sha256 with an ml-dsa key", 0x37, NULL, 0 },
        };
        for (size_t i = 0; i < sizeof H / sizeof *H; ++i) {
            Mech hmm = { H[i].m, H[i].p, H[i].len };
            ini(n, H[i].l, v, h, &hmm, v ? mp : mv, 32, 2420);
        }
        /* EdDSA parameters. */
        Ed e0 = { 0, 0, NULL }, e1 = { 1, 0, NULL }, ec = { 0, 3, AAD }, en = { 0, 3, NULL };
        Ed ebig = { 0, 0x80000000UL, AAD };
        struct { const char *l; int k; void *p; UL len; } E[] = {
            { "ed25519 none", 0, NULL, 0 }, { "ed25519 empty block", 0, &e0, sizeof e0 },
            { "ed448 none", 1, NULL, 0 }, { "ed448 empty block", 1, &e0, sizeof e0 },
            { "ed448 ph", 1, &e1, sizeof e1 }, { "ed448 ctx", 1, &ec, sizeof ec },
            { "ed448 null ctx", 1, &en, sizeof en }, { "ed448 ctx 2^31", 1, &ebig, sizeof ebig },
            { "ed448 short block", 1, &e0, 16 },
        };
        for (size_t i = 0; i < sizeof E / sizeof *E; ++i) {
            Mech em = { 0x1057, E[i].p, E[i].len };
            UL key = E[i].k ? (v ? ep4 : ev4) : (v ? dp : dv);
            ini(n, E[i].l, v, h, &em, key, 3, E[i].k ? 114 : 64);
        }
    }
    /* A second session's operation is its own. */
    P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &s2);
    n = "two";
    R("signinit 1", P11(C_SignInit, h, &m256, hm));
    R("signinit 2", P11(C_SignInit, s2, &m256, hm));
    R("verifyinit 1", P11(C_VerifyInit, h, &m256, hm));
    UL l = sizeof buf;
    R("sign 2", P11(C_Sign, s2, MSG, 3UL, buf, &l));
    R("sign 2 again", P11(C_Sign, s2, MSG, 3UL, buf, &l));
    R("signinit 1 again", P11(C_SignInit, h, &m256, hm));
}

/* 1: the MACs, one-shot and in parts, at every hash and key size; the argument checks. */
static void s_mac(void) {
    UL h = setup();
    for (int i = 0; i < 64; ++i) K[i] = (unsigned char)(0x40 + i);
    UL g32 = secret(h, "generic32", k_gen, 32, NULL, 0);
    UL g64 = secret(h, "generic64", k_gen, 64, NULL, 0);
    UL g1 = secret(h, "generic1", k_gen, 1, NULL, 0);
    UL a16 = secret(h, "aes16", k_aes, 16, NULL, 0), a24 = secret(h, "aes24", k_aes, 24, NULL, 0);
    UL a32 = secret(h, "aes32", k_aes, 32, NULL, 0), a20 = secret(h, "aes20", k_aes, 20, NULL, 0);
    struct { const char *n; UL m; } M[] = {
        { "hmac sha1", 0x221 }, { "hmac sha224", 0x256 }, { "hmac sha512/224", 0x49 },
        { "hmac sha512/256", 0x4D }, { "hmac sha256", 0x251 }, { "hmac sha384", 0x261 },
        { "hmac sha512", 0x271 }, { "hmac sha3-224", 0x2B6 }, { "hmac sha3-256", 0x2B1 },
        { "hmac sha3-384", 0x2C1 }, { "hmac sha3-512", 0x2D1 },
    };
    char l[160];
    for (size_t i = 0; i < sizeof M / sizeof *M; ++i) {
        Mech m = { M[i].m, NULL, 0 };
        snprintf(l, sizeof l, "%s key32", M[i].n);
        mech(l, h, &m, g32, g32, MSG, 64, 0);
        snprintf(l, sizeof l, "%s key64 empty", M[i].n);
        mech(l, h, &m, g64, g64, MSG, 0, 0);
        snprintf(l, sizeof l, "%s key1", M[i].n);
        one_sign(l, h, &m, g1, MSG, 5, 0);
        snprintf(l, sizeof l, "%s aes key", M[i].n);
        one_sign(l, h, &m, a16, MSG, 5, 0);
    }
    Mech cmac = { 0x108A, NULL, 0 };
    mech("cmac aes16", h, &cmac, a16, a16, MSG, 64, 0);
    mech("cmac aes24", h, &cmac, a24, a24, MSG, 17, 0);
    mech("cmac aes32", h, &cmac, a32, a32, MSG, 0, 0);
    mech("cmac aes20", h, &cmac, a20, a20, MSG, 16, 0);
    Gcm g96 = { IV, 12, 96, NULL, 0, 96 }, g128 = { IV, 16, 128, NULL, 0, 128 };
    Gcm g32t = { IV, 12, 96, NULL, 0, 32 }, gaad = { IV, 12, 96, AAD, 20, 128 };
    struct { const char *n; void *p; UL len; UL k; } G[] = {
        { "gmac raw iv 12", IV, 12, a16 }, { "gmac raw iv 16", IV, 16, a32 },
        { "gmac tag 96", &g96, sizeof g96, a16 }, { "gmac tag 128 iv 16", &g128, sizeof g128, a24 },
        { "gmac tag 32", &g32t, sizeof g32t, a16 }, { "gmac aad", &gaad, sizeof gaad, a16 },
        { "gmac aes20", IV, 12, a20 },
    };
    for (size_t i = 0; i < sizeof G / sizeof *G; ++i) {
        Mech m = { 0x108E, G[i].p, G[i].len };
        mech(G[i].n, h, &m, G[i].k, G[i].k, MSG, 40, 0);
    }
    /* The env alias: GMAC's code point computes CMAC. */
    setenv("FHSM_OPENSC_GMAC_ALIAS", "1", 1);
    Mech gm = { 0x108E, NULL, 0 };
    one_sign("gmac alias", h, &gm, a16, MSG, 64, 0);
    unsetenv("FHSM_OPENSC_GMAC_ALIAS");
    /* Argument checks and which of them end the operation. */
    Mech m = { 0x251, NULL, 0 };
    char s[200];
    const char *n = "args";
    UL ln = sizeof buf, rv;
    R("signinit", P11(C_SignInit, h, &m, g32));
    R("sign null len", P11(C_Sign, h, MSG, 3UL, buf, NULL));
    R("sign null data", P11(C_Sign, h, NULL, 3UL, buf, &ln));
    R("sign after null data", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    R("signinit 2", P11(C_SignInit, h, &m, g32));
    R("sign 2^31", P11(C_Sign, h, MSG, 0x80000000UL, buf, &ln));
    R("sign after 2^31", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    R("signinit 3", P11(C_SignInit, h, &m, g32));
    ln = sizeof buf;
    R("sign null data 0", P11(C_Sign, h, NULL, 0UL, buf, &ln));
    R("verifyinit", P11(C_VerifyInit, h, &m, g32));
    R("verify null data", P11(C_Verify, h, NULL, 3UL, buf, 32UL));
    R("verify after null data", P11(C_Verify, h, MSG, 3UL, buf, 32UL));
    R("verifyinit 2", P11(C_VerifyInit, h, &m, g32));
    R("verify 2^31", P11(C_Verify, h, MSG, 0x80000000UL, buf, 32UL));
    R("verify after 2^31", P11(C_Verify, h, MSG, 3UL, buf, 32UL));
    R("verifyinit 3", P11(C_VerifyInit, h, &m, g32));
    R("verify null sig", P11(C_Verify, h, MSG, 3UL, NULL, 0UL));
    R("verify after null sig", P11(C_Verify, h, MSG, 3UL, buf, 32UL));
    R("signinit 4", P11(C_SignInit, h, &m, g32));
    R("signupdate null", P11(C_SignUpdate, h, NULL, 3UL));
    R("signupdate after null", P11(C_SignUpdate, h, MSG, 3UL));
    R("signinit 5", P11(C_SignInit, h, &m, g32));
    R("signupdate 2^31", P11(C_SignUpdate, h, MSG, 0x80000000UL));
    R("signupdate after 2^31", P11(C_SignUpdate, h, MSG, 3UL));
    R("signinit 6", P11(C_SignInit, h, &m, g32));
    R("signupdate", P11(C_SignUpdate, h, MSG, 3UL));
    R("signfinal null len", P11(C_SignFinal, h, buf, NULL));
    ln = 0xAAAA;
    snprintf(s, sizeof s, "args signfinal size");
    rv = P11(C_SignFinal, h, NULL, &ln);
    row(s, rv, ln, NULL, 0);
    memset(buf, 0xAA, 64);
    ln = sizeof buf;
    snprintf(s, sizeof s, "args signfinal");
    rv = P11(C_SignFinal, h, buf, &ln);
    row(s, rv, ln, buf, rv || ln > 64 ? 0 : ln);
    R("signinit 7", P11(C_SignInit, h, &m, g32));
    ln = sizeof buf;
    snprintf(s, sizeof s, "args signfinal no update");
    rv = P11(C_SignFinal, h, buf, &ln);
    row(s, rv, ln, buf, rv || ln > 64 ? 0 : ln);
    UL macn = rv || ln > 64 ? 0 : ln;
    R("verifyinit 4", P11(C_VerifyInit, h, &m, g32));
    R("verifyupdate null", P11(C_VerifyUpdate, h, NULL, 3UL));
    R("verifyupdate after null", P11(C_VerifyUpdate, h, MSG, 3UL));
    R("verifyinit 5", P11(C_VerifyInit, h, &m, g32));
    R("verifyfinal null", P11(C_VerifyFinal, h, NULL, 32UL));
    R("verifyfinal after null", P11(C_VerifyFinal, h, buf, macn));
    R("verifyinit 6", P11(C_VerifyInit, h, &m, g32));
    R("verifyfinal no update", P11(C_VerifyFinal, h, buf, macn));
    R("verifyinit 7", P11(C_VerifyInit, h, &m, g32));
    R("verifyupdate 2^31", P11(C_VerifyUpdate, h, MSG, 0x80000000UL));
    R("verifyupdate after 2^31", P11(C_VerifyUpdate, h, MSG, 3UL));
    R("signupdate not initialised", P11(C_SignUpdate, h, MSG, 3UL));
    R("verifyfinal not initialised", P11(C_VerifyFinal, h, buf, 32UL));
    ln = sizeof buf;
    R("sign not initialised", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    R("verify not initialised", P11(C_Verify, h, MSG, 3UL, buf, 32UL));
    /* A one-shot call after an update, and a Final after a one-shot BUFFER_TOO_SMALL. */
    R("signinit 8", P11(C_SignInit, h, &m, g32));
    R("signupdate 8", P11(C_SignUpdate, h, MSG, 3UL));
    ln = sizeof buf;
    R("sign after update", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    R("signfinal after sign", P11(C_SignFinal, h, buf, &ln));
    R("signinit 9", P11(C_SignInit, h, &m, g32));
    ln = 1;
    R("sign short", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    ln = sizeof buf;
    R("signupdate after a short sign", P11(C_SignUpdate, h, MSG, 3UL));
    R("verifyinit 9", P11(C_VerifyInit, h, &m, g32));
    R("verifyupdate 9", P11(C_VerifyUpdate, h, MSG, 3UL));
    R("verify after verifyupdate", P11(C_Verify, h, MSG, 3UL, buf, 32UL));
    R("verifyfinal after verify", P11(C_VerifyFinal, h, buf, 32UL));
}

/* 2: the asymmetric schemes, one-shot and in parts. */
static void s_asym(void) {
    UL h = setup(), p, v;
    unsigned char dig[64];
    for (int i = 0; i < 64; ++i) dig[i] = (unsigned char)(0x80 + i);
    unsigned char p384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
    unsigned char p521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };
    struct { const char *n; unsigned char *c; UL len; } EC[] = {
        { "p256", P256, sizeof P256 }, { "p384", p384, sizeof p384 }, { "p521", p521, sizeof p521 },
    };
    char l[160];
    for (size_t i = 0; i < 3; ++i) {
        Attr ecp[] = { AB(0x180, EC[i].c, EC[i].len) };
        if (!pair(h, EC[i].n, 0x1040, ecp, 1, &p, &v)) continue;
        UL ms[] = { 0x1041, 0x1044, 0x1045, 0x1046 };
        for (int j = 0; j < 4; ++j) {
            Mech m = { ms[j], NULL, 0 };
            snprintf(l, sizeof l, "%s ecdsa %#lx", EC[i].n, ms[j]);
            mech(l, h, &m, v, p, j ? MSG : dig, j ? 64 : 32, 1);
        }
        Mech raw = { 0x1041, NULL, 0 };
        snprintf(l, sizeof l, "%s ecdsa raw 64", EC[i].n);
        one_sign(l, h, &raw, v, dig, 64, 1);
        one_verify(l, h, &raw, p, dig, 64);
        snprintf(l, sizeof l, "%s ecdsa raw 20", EC[i].n);
        one_sign(l, h, &raw, v, dig, 20, 1);
        one_verify(l, h, &raw, p, dig, 20);
    }
    Attr edp[] = { AB(0x180, ED25519, sizeof ED25519) }, ed4p[] = { AB(0x180, ED448, sizeof ED448) };
    Mech eddsa = { 0x1057, NULL, 0 };
    if (pair(h, "ed25519", 0x1055, edp, 1, &p, &v)) {
        mech("ed25519", h, &eddsa, v, p, MSG, 64, 1);
        twice("ed25519", h, &eddsa, v, MSG, 64);
        one_sign("ed25519 empty", h, &eddsa, v, MSG, 0, 1);
        one_verify("ed25519 empty", h, &eddsa, p, MSG, 0);
    }
    if (pair(h, "ed448", 0x1055, ed4p, 1, &p, &v)) {
        Ed e0 = { 0, 0, NULL };
        Mech ed448m = { 0x1057, &e0, sizeof e0 };
        mech("ed448", h, &ed448m, v, p, MSG, 64, 1);
        twice("ed448", h, &ed448m, v, MSG, 64);
        mech("ed448 no block", h, &eddsa, v, p, MSG, 64, 1);
    }
    UL bits = 2048;
    unsigned char e3[] = { 1, 0, 1 };
    Attr rsap[] = { AT(0x121, bits), AT(0x122, e3) };
    if (pair(h, "rsa2048", 0x0, rsap, 2, &p, &v)) {
        Pss ps = { 0x250, 2, 32 }, ps0 = { 0x250, 2, 0 }, ps1 = { 0x250, 1, 20 };
        Pss pm = { 0x250, 0x77, 32 }, pmax = { 0x250, 2, 222 }, pover = { 0x250, 2, 223 };
        struct { const char *n; UL m; void *p; UL len; const unsigned char *in; UL inl; } RS[] = {
            { "rsa pkcs raw", 0x1, NULL, 0, dig, 32 }, { "rsa sha256", 0x40, NULL, 0, MSG, 64 },
            { "rsa sha384", 0x41, NULL, 0, MSG, 64 }, { "rsa sha512", 0x42, NULL, 0, MSG, 64 },
            { "rsa sha224", 0x46, NULL, 0, MSG, 64 }, { "rsa sha3-224", 0x66, NULL, 0, MSG, 64 },
            { "rsa sha3-256", 0x60, NULL, 0, MSG, 64 }, { "rsa sha3-384", 0x61, NULL, 0, MSG, 64 },
            { "rsa sha3-512", 0x62, NULL, 0, MSG, 64 }, { "rsa sha1", 0x6, NULL, 0, MSG, 64 },
            { "rsa pss sha256", 0x43, &ps, sizeof ps, MSG, 64 },
            { "rsa pss sha384", 0x44, &ps, sizeof ps, MSG, 64 },
            { "rsa pss sha512 salt 0", 0x45, &ps0, sizeof ps0, MSG, 64 },
            { "rsa pss mgf1 sha1", 0x43, &ps1, sizeof ps1, MSG, 64 },
            { "rsa pss salt 222", 0x43, &pmax, sizeof pmax, MSG, 64 },
            { "rsa pss salt 223", 0x43, &pover, sizeof pover, MSG, 64 },
            { "rsa pss bare", 0xD, &ps, sizeof ps, dig, 32 },
            { "rsa pss bare 20", 0xD, &ps, sizeof ps, dig, 20 },
            { "rsa pss mgf unknown", 0x43, &pm, sizeof pm, MSG, 64 },
            { "rsa pss bare mgf unknown", 0xD, &pm, sizeof pm, dig, 32 },
        };
        for (size_t i = 0; i < sizeof RS / sizeof *RS; ++i) {
            Mech m = { RS[i].m, RS[i].p, RS[i].len };
            mech(RS[i].n, h, &m, v, p, RS[i].in, RS[i].inl, 1);
        }
        Mech pk = { 0x40, NULL, 0 };
        twice("rsa sha256", h, &pk, v, MSG, 64);
        Mech raw = { 0x1, NULL, 0 };
        one_sign("rsa pkcs raw 245", h, &raw, v, BIG, 245, 1);
        one_sign("rsa pkcs raw 246", h, &raw, v, BIG, 246, 1);
        Mech x509 = { 0x3, NULL, 0 };
        one_sign("rsa x509 256", h, &x509, v, BIG, 256, 1);
        one_verify("rsa x509 256", h, &x509, p, BIG, 256);
        one_sign("rsa x509 32", h, &x509, v, dig, 32, 1);
    }
    UL sets[] = { 1, 2, 3 };
    UL siglen[] = { 2420, 3309, 4627 };
    const char *mn[] = { "mldsa44", "mldsa65", "mldsa87" };
    for (int i = 0; i < 3; ++i) {
        Attr mlp[] = { AT(0x61D, sets[i]) };
        if (!pair(h, mn[i], 0x1C, mlp, 1, &p, &v)) continue;
        Mech m = { 0x1D, NULL, 0 };
        mech(mn[i], h, &m, v, p, MSG, 64, 1);
        Pq det = { 2, AAD, 20 }, ctx = { 0, AAD, 20 }, q300 = { 0, BIG, 300 };
        Mech md = { 0x1D, &det, sizeof det }, mc = { 0x1D, &ctx, sizeof ctx };
        Mech mt = { 0x1D, &q300, sizeof q300 };
        snprintf(l, sizeof l, "%s det ctx", mn[i]);
        mech(l, h, &md, v, p, MSG, 64, 1);
        twice(l, h, &md, v, MSG, 64);
        snprintf(l, sizeof l, "%s ctx", mn[i]);
        one_sign(l, h, &mc, v, MSG, 64, 1);
        snprintf(l, sizeof l, "%s ctx verified with det ctx", mn[i]);
        one_verify(l, h, &md, p, MSG, 64);
        snprintf(l, sizeof l, "%s ctx verified with none", mn[i]);
        one_verify(l, h, &m, p, MSG, 64);
        snprintf(l, sizeof l, "%s ctx 300", mn[i]);
        one_verify(l, h, &mt, p, MSG, 64);
        snprintf(l, sizeof l, "%s ctx 300 sign", mn[i]);
        one_sign(l, h, &mt, v, MSG, 64, 1);
        if (i) continue;
        /* HashML-DSA, each hash, and the generic mechanism over a precomputed PH. */
        UL hm[] = { 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C };
        for (int j = 0; j < 10; ++j) {
            Mech hmm = { hm[j], NULL, 0 };
            snprintf(l, sizeof l, "hashmldsa %#lx", hm[j]);
            mech(l, h, &hmm, v, p, MSG, 64, 1);
            Hpq hd = { 2, AAD, 20, 0 };
            Mech hmd = { hm[j], &hd, 3 * sizeof(UL) };
            snprintf(l, sizeof l, "hashmldsa %#lx det ctx", hm[j]);
            mech(l, h, &hmd, v, p, MSG, 64, 1);
            twice(l, h, &hmd, v, MSG, 64);
        }
        UL dg[] = { 0x250, 0x260, 0x270, 0x255, 0x48, 0x4C, 0x2B0, 0x2C0, 0x2D0, 0x2B5 };
        UL dl[] = { 32, 48, 64, 28, 28, 32, 32, 48, 64, 28 };
        for (int j = 0; j < 10; ++j) {
            Hpq hq = { 0, NULL, 0, dg[j] };
            Mech g = { 0x1F, &hq, sizeof hq };
            snprintf(l, sizeof l, "hashmldsa generic %#lx", dg[j]);
            one_sign(l, h, &g, v, dig, dl[j], 1);
            one_verify(l, h, &g, p, dig, dl[j]);
            snprintf(l, sizeof l, "hashmldsa generic %#lx long", dg[j]);
            one_sign(l, h, &g, v, dig, dl[j] + 1, 1);
            char s[200];
            const char *n = l;
            snprintf(l, sizeof l, "hashmldsa generic %#lx update", dg[j]);
            R("signinit", P11(C_SignInit, h, &g, v));
            R("signupdate", P11(C_SignUpdate, h, dig, dl[j]));
            UL ln = sizeof buf;
            R("signfinal", P11(C_SignFinal, h, buf, &ln));
            R("verifyinit", P11(C_VerifyInit, h, &g, p));
            R("verifyupdate", P11(C_VerifyUpdate, h, dig, dl[j]));
            R("verifyfinal", P11(C_VerifyFinal, h, sig, siglen[0]));
        }
        /* The prehash of the named mechanism in parts equals hashing it one-shot: a signature
         * made in parts verifies one-shot (parts() above), and an empty Update is a no-op. */
        Mech h256 = { 0x24, NULL, 0 };
        char s[200];
        const char *n = "hashmldsa sha256 empty updates";
        R("signinit", P11(C_SignInit, h, &h256, v));
        R("signupdate empty", P11(C_SignUpdate, h, MSG, 0UL));
        UL ln = sizeof buf;
        R("signfinal", P11(C_SignFinal, h, buf, &ln));
        memcpy(sig, buf, ln < sizeof sig ? ln : 0);
        R("verifyinit", P11(C_VerifyInit, h, &h256, p));
        R("verify empty", P11(C_Verify, h, MSG, 0UL, sig, ln));
    }
    UL slh[] = { 3, 4 };
    const char *sn[] = { "slh sha2-128f", "slh shake-128f" };
    for (int i = 0; i < 2; ++i) {
        Attr sp[] = { AT(0x61D, slh[i]) };
        if (!pair(h, sn[i], 0x2D, sp, 1, &p, &v)) continue;
        Mech m = { 0x2E, NULL, 0 };
        mech(sn[i], h, &m, v, p, MSG, 64, 1);
        Pq det = { 2, NULL, 0 }, ctx = { 0, AAD, 20 };
        Mech md = { 0x2E, &det, sizeof det }, mc = { 0x2E, &ctx, sizeof ctx };
        snprintf(l, sizeof l, "%s det", sn[i]);
        twice(l, h, &md, v, MSG, 64);
        snprintf(l, sizeof l, "%s ctx", sn[i]);
        one_sign(l, h, &mc, v, MSG, 64, 1);
        one_verify(l, h, &mc, p, MSG, 64);
        snprintf(l, sizeof l, "%s ctx verified with none", sn[i]);
        one_verify(l, h, &m, p, MSG, 64);
        Mech hs = { 0x37, NULL, 0 };
        snprintf(l, sizeof l, "%s hash sha256", sn[i]);
        mech(l, h, &hs, v, p, MSG, 64, 1);
        Mech hk = { 0x3F, NULL, 0 };
        snprintf(l, sizeof l, "%s hash shake256", sn[i]);
        one_sign(l, h, &hk, v, MSG, 64, 1);
        one_verify(l, h, &hk, p, MSG, 64);
        Hpq hq = { 0, NULL, 0, 0x250 };
        Mech g = { 0x34, &hq, sizeof hq };
        snprintf(l, sizeof l, "%s hash generic", sn[i]);
        one_sign(l, h, &g, v, dig, 32, 1);
        one_verify(l, h, &g, p, dig, 32);
    }
    /* The wrong half of a pair. */
    char s[200];
    const char *n = "cross";
    UL ep = 0, ev = 0, ln;
    Attr ecp[] = { AB(0x180, P256, sizeof P256) };
    pair(h, "cross ec", 0x1040, ecp, 1, &ep, &ev);
    Mech m = { 0x1044, NULL, 0 };
    R("verifyinit with the private key", P11(C_VerifyInit, h, &m, ev));
    R("verify with the private key", P11(C_Verify, h, MSG, 64UL, buf, 64UL));
    R("signinit with the public key", P11(C_SignInit, h, &m, ep));
    ln = sizeof buf;
    R("sign with the public key", P11(C_Sign, h, MSG, 64UL, buf, &ln));
}

/* 3: ALWAYS_AUTHENTICATE, the multipart ceiling, sessions, logout, a fork, C_Finalize. */
static void s_life(void) {
    UL h = setup(), h2 = 0, h3 = 0, rv, ln;
    char s[200];
    const char *n = "life";
    for (int i = 0; i < 64; ++i) K[i] = (unsigned char)(0xC0 + i);
    Attr aa[] = { { 0x202, &T, 1 } };
    UL g = secret(h, "generic", k_gen, 32, NULL, 0);
    UL ga = secret(h, "generic always auth", k_gen, 32, aa, 1);
    Mech m = { 0x251, NULL, 0 };
    ln = sizeof buf;
    R("signinit always auth", P11(C_SignInit, h, &m, ga));
    R("sign without context login", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    R("sign after the refusal", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    R("signinit always auth 2", P11(C_SignInit, h, &m, ga));
    R("signupdate without context login", P11(C_SignUpdate, h, MSG, 3UL));
    R("signupdate after the refusal", P11(C_SignUpdate, h, MSG, 3UL));
    R("signinit always auth 3", P11(C_SignInit, h, &m, ga));
    R("context login", P11(C_Login, h, 2UL, USER_PIN, (UL)strlen(USER_PIN)));
    ln = 0xAAAA;
    snprintf(s, sizeof s, "life sign size with context login");
    rv = P11(C_Sign, h, MSG, 3UL, NULL, &ln);
    row(s, rv, ln, NULL, 0);
    ln = sizeof buf;
    R("sign with context login", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    R("signinit always auth 4", P11(C_SignInit, h, &m, ga));
    ln = sizeof buf;
    R("sign: the grant was used", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    R("signinit always auth 5", P11(C_SignInit, h, &m, ga));
    R("context login 5", P11(C_Login, h, 2UL, USER_PIN, (UL)strlen(USER_PIN)));
    R("signupdate with context login", P11(C_SignUpdate, h, MSG, 3UL));
    ln = sizeof buf;
    R("signfinal with context login", P11(C_SignFinal, h, buf, &ln));
    R("verifyinit always auth", P11(C_VerifyInit, h, &m, ga));
    R("verify needs no context login", P11(C_Verify, h, MSG, 3UL, buf, 32UL));
    R("context login without an operation", P11(C_Login, h, 2UL, USER_PIN, (UL)strlen(USER_PIN)));
    /* The 16 MiB ceiling of a buffered multipart signature. */
    Attr edp[] = { AB(0x180, ED25519, sizeof ED25519) };
    UL ep = 0, ev = 0;
    pair(h, "life ed25519", 0x1055, edp, 1, &ep, &ev);
    Mech ed = { 0x1057, NULL, 0 };
    size_t big = 16u * 1024u * 1024u;
    unsigned char *mb = mmap(NULL, big + 1, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    R("signinit ceiling", P11(C_SignInit, h, &ed, ev));
    R("signupdate 16 MiB", P11(C_SignUpdate, h, mb, (UL)big));
    R("signupdate one more byte", P11(C_SignUpdate, h, mb, 1UL));
    R("signupdate after", P11(C_SignUpdate, h, mb, 1UL));
    R("signinit ceiling 2", P11(C_SignInit, h, &ed, ev));
    R("signupdate 16 MiB + 1", P11(C_SignUpdate, h, mb, (UL)big + 1));
    R("signupdate after 2", P11(C_SignUpdate, h, mb, 1UL));
    R("verifyinit ceiling", P11(C_VerifyInit, h, &ed, ep));
    R("verifyupdate 16 MiB + 1", P11(C_VerifyUpdate, h, mb, (UL)big + 1));
    R("verifyupdate after", P11(C_VerifyUpdate, h, mb, 1UL));
    munmap(mb, big + 1);
    /* BUFFER_TOO_SMALL at Final keeps the message. */
    R("signinit keep", P11(C_SignInit, h, &ed, ev));
    R("signupdate keep", P11(C_SignUpdate, h, MSG, 64UL));
    ln = 1;
    snprintf(s, sizeof s, "life signfinal 1");
    rv = P11(C_SignFinal, h, buf, &ln);
    row(s, rv, ln, NULL, 0);
    ln = sizeof buf;
    R("signfinal retry", P11(C_SignFinal, h, buf, &ln));
    R("verifyinit keep", P11(C_VerifyInit, h, &ed, ep));
    R("verify keep", P11(C_Verify, h, MSG, 64UL, buf, ln));
    /* Two sessions, and a closed one's handle reused. */
    P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h2);
    R("signinit 2", P11(C_SignInit, h2, &m, g));
    R("signupdate 2", P11(C_SignUpdate, h2, MSG, 3UL));
    R("verifyinit 2", P11(C_VerifyInit, h2, &m, g));
    R("close 2", P11(C_CloseSession, h2));
    P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h3);
    printf("third reuses second\t%d\n", h3 == h2);
    ln = sizeof buf;
    R("signfinal reused", P11(C_SignFinal, h3, buf, &ln));
    R("verifyfinal reused", P11(C_VerifyFinal, h3, buf, 32UL));
    /* Logout: operations under way, and new ones, on token, session and public keys. */
    Attr st[] = { AT(0x1, Fb) };
    UL gs = secret(h, "generic session", k_gen, 32, st, 1);
    R("signinit before logout", P11(C_SignInit, h, &m, g));
    R("signupdate before logout", P11(C_SignUpdate, h, MSG, 3UL));
    R("verifyinit before logout", P11(C_VerifyInit, h, &m, gs));
    R("signinit ed before logout", P11(C_SignInit, h3, &ed, ev));
    R("signupdate ed before logout", P11(C_SignUpdate, h3, MSG, 64UL));
    R("verifyinit public before logout", P11(C_VerifyInit, h3, &ed, ep));
    R("logout", P11(C_Logout, h));
    R("signupdate after logout", P11(C_SignUpdate, h, MSG, 3UL));
    ln = sizeof buf;
    snprintf(s, sizeof s, "life signfinal after logout");
    rv = P11(C_SignFinal, h, buf, &ln);
    row(s, rv, ln, NULL, 0);
    R("verify session key after logout", P11(C_Verify, h, MSG, 3UL, buf, 32UL));
    ln = sizeof buf;
    snprintf(s, sizeof s, "life signfinal ed after logout");
    rv = P11(C_SignFinal, h3, buf, &ln);
    row(s, rv, ln, NULL, 0);
    R("verify public after logout", P11(C_Verify, h3, MSG, 64UL, buf, 64UL));
    R("signinit logged out", P11(C_SignInit, h, &m, g));
    R("signinit session key logged out", P11(C_SignInit, h, &m, gs));
    ln = sizeof buf;
    R("sign session key logged out", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    R("verifyinit session key logged out", P11(C_VerifyInit, h, &m, gs));
    R("verify session key logged out", P11(C_Verify, h, MSG, 3UL, buf, 32UL));
    R("signinit ed logged out", P11(C_SignInit, h, &ed, ev));
    R("verifyinit public key logged out", P11(C_VerifyInit, h, &ed, ep));
    R("verify public key logged out", P11(C_Verify, h, MSG, 64UL, buf, 64UL));
    R("login so", P11(C_Login, h, 0UL, SO_PIN, (UL)strlen(SO_PIN)));
    R("so signinit session key", P11(C_SignInit, h, &m, gs));
    ln = sizeof buf;
    R("so sign session key", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    R("so verifyinit session key", P11(C_VerifyInit, h, &m, gs));
    R("so verify session key", P11(C_Verify, h, MSG, 3UL, buf, 32UL));
    R("so signinit token key", P11(C_SignInit, h, &m, g));
    R("logout so", P11(C_Logout, h));
    /* A fork; then C_Finalize. */
    R("login user", P11(C_Login, h, 1UL, USER_PIN, (UL)strlen(USER_PIN)));
    R("signinit before fork", P11(C_SignInit, h, &m, g));
    R("signupdate before fork", P11(C_SignUpdate, h, MSG, 3UL));
    pid_t c = fork();
    if (c == 0) {
        ln = sizeof buf;
        printf("child signfinal\t%#lx\n", P11(C_SignFinal, h, buf, &ln));
        printf("child initialize\t%#lx\n", P11(C_Initialize, NULL));
        _exit(0);
    }
    waitpid(c, NULL, 0);
    R("signupdate after fork", P11(C_SignUpdate, h, MSG, 3UL));
    ln = sizeof buf;
    snprintf(s, sizeof s, "life signfinal after fork");
    rv = P11(C_SignFinal, h, buf, &ln);
    row(s, rv, ln, buf, rv || ln > 64 ? 0 : ln);
    R("signinit before finalize", P11(C_SignInit, h, &m, g));
    R("finalize", P11(C_Finalize, NULL));
    ln = sizeof buf;
    R("sign finalized", P11(C_Sign, h, MSG, 3UL, buf, &ln));
    R("signinit finalized", P11(C_SignInit, h, &m, g));
    R("verifyfinal finalized", P11(C_VerifyFinal, h, buf, 32UL));
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: p11_sign LIB BASE\n"); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    void (*S[])(void) = { s_init, s_mac, s_asym, s_life };
    int rc = 0;
    for (size_t i = 0; i < sizeof S / sizeof *S; ++i) {
        snprintf(dir, sizeof dir, "%s/%zu", argv[2], i);
        mkdir(dir, 0700);
        printf("== scenario %zu\n", i);
        pid_t p = fork();
        if (p == 0) {
            setenv("FHSM_TOKENS_DIR", dir, 1);
            S[i]();
            _exit(0);
        }
        int st;
        waitpid(p, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st)) {
            printf("scenario %zu: status %d\n", i, st);
            rc = 1;
        }
    }
    return rc;
}
