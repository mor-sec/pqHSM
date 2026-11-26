/* p11_crypt.c LIB BASE --- slice 4 of PHASE4_PLAN.md §2: call sequences through the eight
 * encrypt and decrypt entry points (C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinal
 * and the four C_Decrypt*), one row per call: "label TAB rv TAB n TAB hex", n the length it
 * wrote (pre-filled 0xAAAA), hex the output buffer (pre-filled 0xAA). RSA-OAEP ciphertexts are
 * random, so they print as "rnd:<len>" and are checked by decrypting them; every other byte is
 * deterministic, so C and hybrid must print the same apart from recorded DIVs (harness step 4l).
 *
 * Each scenario runs in a forked child with its own tokens directory BASE/<n>.
 *
 * Written from the C (src/fhsm_pkcs11.c:2200, 8506-8630, 9005-9600, 9761-10700, 12662-13050)
 * before the Rust, as its characterisation. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

typedef unsigned long UL;
typedef struct { UL mech; void *p; UL len; } Mech;
typedef struct { UL type; void *p; UL len; } Attr;
typedef UL (*F)();

static void *lib;
static char dir[600];
static unsigned char buf[1024];

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

#define SO_PIN   "so-pin-1234"
#define USER_PIN "user-pin-1234"
#define LABEL32  "crypt                           "
static unsigned char T = 1, Fb = 0;
static UL c_secret = 4, c_pub = 2, c_priv = 3, k_aes = 0x1f, k_gen = 0x10;
static unsigned char K[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                               0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
                               0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
static unsigned char IV[16] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
                                0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
static const unsigned char MSG[64] = "The quick brown fox jumps over the lazy dog, 0123456789ABCDEFGH";
static unsigned char AAD[20] = "header-of-twenty-by!";
#define AT(t, v) { t, &(v), sizeof(v) }
#define AB(t, p, n) { t, (void *)(p), n }

/* CK_GCM_PARAMS, CK_CCM_PARAMS, CK_AES_CTR_PARAMS, CK_RSA_PKCS_OAEP_PARAMS. */
typedef struct { void *iv; UL iv_len, iv_bits; void *aad; UL aad_len, tag_bits; } Gcm;
typedef struct { UL data_len; void *nonce; UL nonce_len; void *aad; UL aad_len, mac_len; } Ccm;
typedef struct { UL bits; unsigned char cb[16]; } Ctr;
typedef struct { UL hash, mgf, source; void *src; UL src_len; } Oaep;

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

static UL create(UL h, const char *label, Attr *t, UL n) {
    UL o = 0xAAAAAAAAUL;
    UL rv = P11(C_CreateObject, h, t, n, &o);
    row(label, rv, o, NULL, 0);
    return rv ? 0 : o;
}

/* An AES token key of n bytes, ENCRYPT and DECRYPT; extra attributes replace or add. */
static UL aes(UL h, const char *label, UL n, Attr *extra, UL ne) {
    Attr t[16] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AB(0x3, label, strlen(label)),
                   AB(0x11, K, n), AT(0x104, T), AT(0x105, T), AT(0x103, Fb) };
    UL nt = 8;
    for (UL i = 0; i < ne; ++i) {
        UL j = 0;
        while (j < nt && t[j].type != extra[i].type) ++j;
        t[j] = extra[i];  /* replaces a default rather than repeat the attribute */
        if (j == nt) ++nt;
    }
    char l[160];
    snprintf(l, sizeof l, "create %s", label);
    return create(h, l, t, nt);
}

/* One single-part call, three ways: the size query, a 1-byte buffer, a fitting one. The
 * output is kept in out/outn for the caller. fn 0 encrypt, 1 decrypt. Reinitialised with the
 * same mechanism and key after an answer that may have ended the operation. */
static unsigned char out[1024];
static UL outn;
static void one(int fn, const char *l, UL h, Mech *m, UL k, const unsigned char *in, UL n,
                int rnd) {
    char s[200];
    UL len, rv;
    F init = fn ? sym("C_DecryptInit") : sym("C_EncryptInit");
    F call = fn ? sym("C_Decrypt") : sym("C_Encrypt");
    outn = 0;
    snprintf(s, sizeof s, "%s init", l);
    rv = init(h, m, k);
    rv_row(s, rv);
    if (rv) return;
    len = 0xAAAA;
    snprintf(s, sizeof s, "%s size", l);
    rv = call(h, in, n, NULL, &len);
    row(s, rv, len, NULL, 0);
    memset(buf, 0xAA, sizeof buf);
    len = 1;
    snprintf(s, sizeof s, "%s 1", l);
    rv = call(h, in, n, buf, &len);
    row(s, rv, len, rnd ? NULL : buf, 1);
    if (rv != 0x150) {
        snprintf(s, sizeof s, "%s reinit", l);
        rv_row(s, init(h, m, k));
    }
    memset(buf, 0xAA, sizeof buf);
    len = sizeof buf;
    snprintf(s, sizeof s, "%s get", l);
    rv = call(h, in, n, buf, &len);
    if (rnd && !rv) printf("%s\t0\t%#lx\trnd:%lu\n", s, len, len);
    else row(s, rv, len, buf, rv || len > sizeof buf ? 0 : len);
    outn = rv || len > sizeof out ? 0 : len;
    memcpy(out, buf, outn);
    snprintf(s, sizeof s, "%s after", l);
    len = sizeof buf;
    rv_row(s, call(h, in, n, buf, &len));
}

/* Encrypt, then decrypt what came out; the round trip must give the message back. */
static void trip(const char *l, UL h, Mech *m, UL k, UL n) {
    char s[200];
    snprintf(s, sizeof s, "%s enc", l);
    one(0, s, h, m, k, MSG, n, 0);
    unsigned char ct[1024];
    UL ctn = outn;
    memcpy(ct, out, ctn);
    snprintf(s, sizeof s, "%s dec", l);
    one(1, s, h, m, k, ct, ctn, 0);
    printf("%s round trip\t%d\n", l, outn == n && !memcmp(out, MSG, n));
    if (ctn) {
        ct[ctn - 1] ^= 1;
        snprintf(s, sizeof s, "%s dec tampered", l);
        one(1, s, h, m, k, ct, ctn, 0);
    }
}

/* Multipart: Update with parts of a and b bytes (each: size query, 1-byte buffer, fitting
 * one), then Final the same three ways. The fitting buffer is printed whole (part + 16 bytes)
 * because C does not always say how much it wrote. */
static void parts(int fn, const char *l, UL h, Mech *m, UL k, const unsigned char *in, UL a,
                  UL b) {
    char s[200];
    UL len, rv;
    F init = fn ? sym("C_DecryptInit") : sym("C_EncryptInit");
    F upd = fn ? sym("C_DecryptUpdate") : sym("C_EncryptUpdate");
    F fin = fn ? sym("C_DecryptFinal") : sym("C_EncryptFinal");
    snprintf(s, sizeof s, "%s init", l);
    rv = init(h, m, k);
    rv_row(s, rv);
    if (rv) return;
    UL off = 0, ps[2] = { a, b };
    for (int i = 0; i < 2; ++i) {
        len = 0xAAAA;
        snprintf(s, sizeof s, "%s update %d size", l, i);
        row(s, upd(h, in + off, ps[i], NULL, &len), len, NULL, 0);
        memset(buf, 0xAA, sizeof buf);
        len = 1;
        snprintf(s, sizeof s, "%s update %d 1", l, i);
        rv = upd(h, in + off, ps[i], buf, &len);
        row(s, rv, len, buf, 1);
        if (rv && rv != 0x150) return;
        memset(buf, 0xAA, sizeof buf);
        len = 0xAAAA;
        snprintf(s, sizeof s, "%s update %d get", l, i);
        rv = upd(h, in + off, ps[i], buf, &len);
        row(s, rv, len, buf, ps[i] + 16);
        if (rv) return;
        off += ps[i];
    }
    len = 0xAAAA;
    snprintf(s, sizeof s, "%s final size", l);
    row(s, fin(h, NULL, &len), len, NULL, 0);
    memset(buf, 0xAA, sizeof buf);
    len = 0;
    snprintf(s, sizeof s, "%s final 0", l);
    rv = fin(h, buf, &len);
    row(s, rv, len, buf, 1);
    if (rv && rv != 0x150) return;
    memset(buf, 0xAA, sizeof buf);
    len = 0xAAAA;
    snprintf(s, sizeof s, "%s final get", l);
    rv = fin(h, buf, &len);
    row(s, rv, len, buf, 32);
    snprintf(s, sizeof s, "%s final after", l);
    len = sizeof buf;
    rv_row(s, fin(h, buf, &len));
}

/* 0: C_EncryptInit's and C_DecryptInit's checks in order, and every parameter shape. */
static void s_init(void) {
    UL h = setup();
    Attr noenc[] = { AT(0x104, Fb), AT(0x105, Fb) };
    UL cbc = 0x1082;
    Attr al[] = { AT(0x40000600, cbc) };
    UL k16 = aes(h, "aes16", 16, NULL, 0), k20 = aes(h, "aes20", 20, NULL, 0);
    UL kno = aes(h, "aes no use", 16, noenc, 2), kal = aes(h, "aes cbc only", 16, al, 1);
    Attr gs[] = { AT(0x0, c_secret), AT(0x100, k_gen), AT(0x1, T), AB(0x3, "gen", 3),
                  AB(0x11, K, 32), AT(0x104, T), AT(0x105, T) };
    UL kg = create(h, "create generic", gs, 7);
    Mech ecb = { 0x1081, NULL, 0 };
    for (int fn = 0; fn < 2; ++fn) {
        F init = fn ? sym("C_DecryptInit") : sym("C_EncryptInit");
        F call = fn ? sym("C_Decrypt") : sym("C_Encrypt");
        const char *n = fn ? "dec" : "enc";
        char l[160];
        /* Each Init, then one 16-byte call to end whatever it started. */
#define I(what, ...) do { snprintf(l, sizeof l, "%s %s", n, what); \
        UL r__ = init(__VA_ARGS__); rv_row(l, r__); \
        if (!r__) { UL z = sizeof buf; snprintf(l, sizeof l, "%s %s, use", n, what); \
                    rv_row(l, call(h, MSG, 16UL, buf, &z)); } } while (0)
        I("session 0", 0UL, &ecb, k16);
        I("session 999", 999UL, &ecb, k16);
        I("session 50", 50UL, &ecb, k16);
        I("NULL mech", h, NULL, k16);
        static const UL bad[] = { 0x133, 0x1, 0x3, 0x250, 0x1089, 0x108A, 0x2107, 0x7FFFFFFF };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
            Mech m = { bad[i], NULL, 0 };
            char w[40];
            snprintf(w, sizeof w, "mech %#lx", bad[i]);
            I(w, h, &m, k16);
        }
        I("key 0", h, &ecb, 0UL);
        I("key unknown", h, &ecb, 0x7777UL);
        I("key generic", h, &ecb, kg);
        I("key 20 bytes", h, &ecb, k20);
        I("key without the usage", h, &ecb, kno);
        I("key cbc only, ecb", h, &ecb, kal);
        Mech oaep0 = { 0x9, NULL, 0 };
        I("oaep, aes key", h, &oaep0, k16);
        /* OPERATION_ACTIVE: Init twice without using the first. */
        snprintf(l, sizeof l, "%s active first", n);
        rv_row(l, init(h, &ecb, k16));
        snprintf(l, sizeof l, "%s active second", n);
        rv_row(l, init(h, &ecb, k16));
        { UL z = sizeof buf; call(h, MSG, 16UL, buf, &z); }
        /* CBC: the IV must be 16 bytes. */
        Mech c0 = { 0x1082, NULL, 0 }, c8 = { 0x1082, IV, 8 }, c16 = { 0x1082, IV, 16 },
             c17 = { 0x1082, IV, 17 }, p16 = { 0x1085, IV, 16 }, p0 = { 0x1085, NULL, 16 };
        I("cbc no iv", h, &c0, k16);
        I("cbc iv 8", h, &c8, k16);
        I("cbc iv 16", h, &c16, k16);
        I("cbc iv 17", h, &c17, k16);
        I("cbc pad iv 16", h, &p16, k16);
        I("cbc pad NULL iv len 16", h, &p0, k16);
        I("cbc, cbc-only key", h, &c16, kal);
        /* CTR: 16 bytes, or the struct with 1-128 counter bits. */
        Ctr cr = { 64, { 0 } };
        memcpy(cr.cb, IV, 16);
        Ctr cr0 = cr, cr129 = cr, cr128 = cr;
        cr0.bits = 0; cr129.bits = 129; cr128.bits = 128;
        Mech t0 = { 0x1086, NULL, 0 }, t16 = { 0x1086, IV, 16 }, t10 = { 0x1086, IV, 10 },
             ts = { 0x1086, &cr, sizeof cr }, ts0 = { 0x1086, &cr0, sizeof cr0 },
             ts129 = { 0x1086, &cr129, sizeof cr129 }, ts128 = { 0x1086, &cr128, sizeof cr128 },
             tshort = { 0x1086, &cr, sizeof cr - 1 };
        I("ctr no param", h, &t0, k16);
        I("ctr iv 16", h, &t16, k16);
        I("ctr iv 10", h, &t10, k16);
        I("ctr struct 64", h, &ts, k16);
        I("ctr struct 0", h, &ts0, k16);
        I("ctr struct 128", h, &ts128, k16);
        I("ctr struct 129", h, &ts129, k16);
        I("ctr struct short", h, &tshort, k16);
        /* GCM: the struct (IV >= 12, tag bits a multiple of 8 up to 128), or a bare 12-byte IV. */
        Gcm g = { IV, 12, 96, AAD, 20, 128 };
        Gcm g8 = g, gtag0 = g, gtag96 = g, gtag100 = g, gtag136 = g, gnull = g, gaadnull = g,
            g16 = g, g513 = g;
        g8.iv_len = 8; gtag0.tag_bits = 0; gtag96.tag_bits = 96; gtag100.tag_bits = 100;
        gtag136.tag_bits = 136; gnull.iv = NULL; gaadnull.aad = NULL; g16.iv_len = 16;
        g513.iv_len = 513;
        Mech gm[] = { { 0x1087, NULL, 0 }, { 0x1087, IV, 12 }, { 0x1087, IV, 8 },
                      { 0x1087, &g, sizeof g }, { 0x1087, &g8, sizeof g },
                      { 0x1087, &gtag0, sizeof g }, { 0x1087, &gtag96, sizeof g },
                      { 0x1087, &gtag100, sizeof g }, { 0x1087, &gtag136, sizeof g },
                      { 0x1087, &gnull, sizeof g }, { 0x1087, &gaadnull, sizeof g },
                      { 0x1087, &g16, sizeof g }, { 0x1087, &g513, sizeof g },
                      { 0x1087, &g, sizeof g - 1 } };
        static const char *gn[] = { "gcm no param", "gcm iv 12", "gcm iv 8", "gcm struct",
                                    "gcm struct iv 8", "gcm tag 0", "gcm tag 96", "gcm tag 100",
                                    "gcm tag 136", "gcm NULL iv", "gcm NULL aad", "gcm iv 16",
                                    "gcm iv 513", "gcm struct short" };
        for (size_t i = 0; i < sizeof gm / sizeof gm[0]; ++i) I(gn[i], h, &gm[i], k16);
        /* CCM: nonce 7-13, MAC 4-16 even. */
        Ccm cc = { 16, IV, 12, AAD, 20, 16 };
        Ccm n6 = cc, n7 = cc, n13 = cc, n14 = cc, m5 = cc, m4 = cc, m18 = cc, cnull = cc,
            caad = cc;
        n6.nonce_len = 6; n7.nonce_len = 7; n13.nonce_len = 13; n14.nonce_len = 14;
        m5.mac_len = 5; m4.mac_len = 4; m18.mac_len = 18; cnull.nonce = NULL; caad.aad = NULL;
        Mech cm[] = { { 0x1088, NULL, 0 }, { 0x1088, &cc, sizeof cc }, { 0x1088, &n6, sizeof cc },
                      { 0x1088, &n7, sizeof cc }, { 0x1088, &n13, sizeof cc },
                      { 0x1088, &n14, sizeof cc }, { 0x1088, &m5, sizeof cc },
                      { 0x1088, &m4, sizeof cc }, { 0x1088, &m18, sizeof cc },
                      { 0x1088, &cnull, sizeof cc }, { 0x1088, &caad, sizeof cc },
                      { 0x1088, &cc, sizeof cc - 1 } };
        static const char *cn[] = { "ccm no param", "ccm struct", "ccm nonce 6", "ccm nonce 7",
                                    "ccm nonce 13", "ccm nonce 14", "ccm mac 5", "ccm mac 4",
                                    "ccm mac 18", "ccm NULL nonce", "ccm NULL aad",
                                    "ccm struct short" };
        for (size_t i = 0; i < sizeof cm / sizeof cm[0]; ++i) I(cn[i], h, &cm[i], k16);
        /* AES key wrap: no IV, or exactly 8 (KW) / 4 (KWP) bytes. */
        Mech kw[] = { { 0x2109, NULL, 0 }, { 0x2109, IV, 8 }, { 0x2109, IV, 4 },
                      { 0x2109, NULL, 8 }, { 0x210B, NULL, 0 }, { 0x210B, IV, 4 },
                      { 0x210B, IV, 8 } };
        static const char *kn[] = { "kw no iv", "kw iv 8", "kw iv 4", "kw NULL iv len 8",
                                    "kwp no iv", "kwp iv 4", "kwp iv 8" };
        for (size_t i = 0; i < sizeof kw / sizeof kw[0]; ++i) I(kn[i], h, &kw[i], k16);
#undef I
    }
}

/* 1: single-part round trips for every AES mode at three key sizes, and the tampered input. */
static void s_single(void) {
    UL h = setup();
    UL ks[3] = { aes(h, "aes128", 16, NULL, 0), aes(h, "aes192", 24, NULL, 0),
                 aes(h, "aes256", 32, NULL, 0) };
    Ctr cr = { 32, { 0 } };
    memcpy(cr.cb, IV, 16);
    Gcm g = { IV, 12, 96, AAD, 20, 128 }, g96 = { IV, 16, 128, NULL, 0, 96 };
    Ccm cc = { 0, IV, 12, AAD, 20, 16 }, c8 = { 0, IV, 7, NULL, 0, 8 };
    struct { const char *n; Mech m; UL len; } M[] = {
        { "ecb", { 0x1081, NULL, 0 }, 32 },        { "ecb 13", { 0x1081, NULL, 0 }, 13 },
        { "ecb 0", { 0x1081, NULL, 0 }, 0 },       { "cbc", { 0x1082, IV, 16 }, 48 },
        { "cbc 13", { 0x1082, IV, 16 }, 13 },      { "cbc pad 13", { 0x1085, IV, 16 }, 13 },
        { "cbc pad 32", { 0x1085, IV, 16 }, 32 },  { "cbc pad 0", { 0x1085, IV, 16 }, 0 },
        { "ctr", { 0x1086, IV, 16 }, 37 },         { "ctr struct", { 0x1086, &cr, sizeof cr }, 37 },
        { "gcm", { 0x1087, &g, sizeof g }, 37 },   { "gcm iv only", { 0x1087, IV, 12 }, 13 },
        { "gcm tag 96 iv 16", { 0x1087, &g96, sizeof g96 }, 37 },
        { "gcm 0", { 0x1087, &g, sizeof g }, 0 },  { "ccm", { 0x1088, &cc, sizeof cc }, 37 },
        { "ccm mac 8", { 0x1088, &c8, sizeof c8 }, 13 },
        { "kw", { 0x2109, NULL, 0 }, 32 },         { "kw 8", { 0x2109, NULL, 0 }, 8 },
        { "kw 20", { 0x2109, NULL, 0 }, 20 },      { "kw iv", { 0x2109, IV, 8 }, 24 },
        { "kwp", { 0x210B, NULL, 0 }, 13 },        { "kwp 0", { 0x210B, NULL, 0 }, 0 },
        { "kwp iv", { 0x210B, IV, 4 }, 9 },
    };
    char l[160];
    for (int k = 0; k < 3; ++k)
        for (size_t i = 0; i < sizeof M / sizeof M[0]; ++i) {
            snprintf(l, sizeof l, "aes%d %s", 128 + 64 * k, M[i].n);
            trip(l, h, &M[i].m, ks[k], M[i].len);
        }
    /* Argument checks on the single-part calls, and which of them end the operation. */
    Mech ecb = { 0x1081, NULL, 0 };
    for (int fn = 0; fn < 2; ++fn) {
        F init = fn ? sym("C_DecryptInit") : sym("C_EncryptInit");
        F call = fn ? sym("C_Decrypt") : sym("C_Encrypt");
        const char *n = fn ? "dec" : "enc";
        UL len = sizeof buf;
#define C(what, ...) do { snprintf(l, sizeof l, "%s %s", n, what); rv_row(l, call(__VA_ARGS__)); \
        snprintf(l, sizeof l, "%s %s, then", n, what); len = sizeof buf; \
        rv_row(l, call(h, MSG, 16UL, buf, &len)); } while (0)
        snprintf(l, sizeof l, "%s not init", n);
        rv_row(l, call(h, MSG, 16UL, buf, &len));
        snprintf(l, sizeof l, "%s session 0", n);
        rv_row(l, call(0UL, MSG, 16UL, buf, &len));
        snprintf(l, sizeof l, "%s session 999", n);
        rv_row(l, call(999UL, MSG, 16UL, buf, &len));
        init(h, &ecb, ks[0]);
        C("NULL len", h, MSG, 16UL, buf, NULL);
        init(h, &ecb, ks[0]);
        C("NULL data", h, NULL, 16UL, buf, &len);
        init(h, &ecb, ks[0]);
        C("2^31", h, buf, 0x80000000UL, buf, &len);
        init(h, &ecb, ks[0]);
        len = sizeof buf;
        C("NULL empty", h, NULL, 0UL, buf, &len);
#undef C
    }
}

/* 2: multipart encrypt and decrypt for the modes that have it, and those that do not. */
static void s_parts(void) {
    UL h = setup();
    UL k = aes(h, "aes128", 16, NULL, 0), k32 = aes(h, "aes256", 32, NULL, 0);
    Ctr cr = { 32, { 0 } };
    memcpy(cr.cb, IV, 16);
    Gcm g = { IV, 12, 96, AAD, 20, 128 };
    Ccm cc = { 0, IV, 12, AAD, 20, 16 };
    struct { const char *n; Mech m; UL a, b; } M[] = {
        { "ecb", { 0x1081, NULL, 0 }, 16, 32 },  { "ecb 5+27", { 0x1081, NULL, 0 }, 5, 27 },
        { "cbc", { 0x1082, IV, 16 }, 16, 32 },   { "cbc 5+27", { 0x1082, IV, 16 }, 5, 27 },
        { "cbc pad", { 0x1085, IV, 16 }, 5, 27 }, { "cbc pad 16+16", { 0x1085, IV, 16 }, 16, 16 },
        { "ctr", { 0x1086, IV, 16 }, 5, 27 },     { "ctr struct", { 0x1086, &cr, sizeof cr }, 5, 27 },
        { "gcm", { 0x1087, &g, sizeof g }, 5, 27 }, { "ccm", { 0x1088, &cc, sizeof cc }, 5, 27 },
        { "kw", { 0x2109, NULL, 0 }, 16, 16 },
    };
    char l[160];
    for (int kk = 0; kk < 2; ++kk)
        for (size_t i = 0; i < sizeof M / sizeof M[0]; ++i) {
            UL key = kk ? k32 : k;
            const char *kn = kk ? "aes256" : "aes128";
            snprintf(l, sizeof l, "%s %s enc", kn, M[i].n);
            parts(0, l, h, &M[i].m, key, MSG, M[i].a, M[i].b);
            /* Decrypt the single-part ciphertext of the same length in parts. */
            UL len = sizeof out;
            snprintf(l, sizeof l, "%s %s single for parts init", kn, M[i].n);
            rv_row(l, P11(C_EncryptInit, h, &M[i].m, key));
            memset(out, 0xAA, sizeof out);
            UL rv = P11(C_Encrypt, h, MSG, M[i].a + M[i].b, out, &len);
            snprintf(l, sizeof l, "%s %s single for parts", kn, M[i].n);
            row(l, rv, len, out, rv || len > 64 ? 0 : len);
            if (rv || len > 64) continue;
            UL a = len < M[i].a ? len : M[i].a;
            snprintf(l, sizeof l, "%s %s dec", kn, M[i].n);
            unsigned char ct[128];
            memcpy(ct, out, len);
            parts(1, l, h, &M[i].m, key, ct, a, len - a);
        }
    /* Update's and Final's argument checks. */
    Mech ecb = { 0x1081, NULL, 0 };
    for (int fn = 0; fn < 2; ++fn) {
        F init = fn ? sym("C_DecryptInit") : sym("C_EncryptInit");
        F call = fn ? sym("C_Decrypt") : sym("C_Encrypt");
        F upd = fn ? sym("C_DecryptUpdate") : sym("C_EncryptUpdate");
        F fin = fn ? sym("C_DecryptFinal") : sym("C_EncryptFinal");
        const char *n = fn ? "dec" : "enc";
        UL len = sizeof buf;
#define R(what, x) do { snprintf(l, sizeof l, "%s %s", n, what); rv_row(l, x); } while (0)
        R("update not init", upd(h, MSG, 16UL, buf, &len));
        R("final not init", fin(h, buf, &len));
        R("update session 999", upd(999UL, MSG, 16UL, buf, &len));
        R("init for NULL len", init(h, &ecb, k));
        R("update NULL len", upd(h, MSG, 16UL, buf, NULL));
        len = sizeof buf;
        R("update after NULL len", upd(h, MSG, 16UL, buf, &len));
        R("init for NULL data", init(h, &ecb, k));
        R("update NULL data", upd(h, NULL, 16UL, buf, &len));
        R("init for 2^31", init(h, &ecb, k));
        R("update 2^31", upd(h, buf, 0x80000000UL, buf, &len));
        R("init for final NULL len", init(h, &ecb, k));
        R("final NULL len", fin(h, buf, NULL));
        len = sizeof buf;
        R("final after NULL len", fin(h, buf, &len));
        /* Final with no update; single-part after an update. */
        R("init for final alone", init(h, &ecb, k));
        len = sizeof buf;
        R("final, no update", fin(h, buf, &len));
        R("init for mixing", init(h, &ecb, k));
        len = sizeof buf;
        R("update before single", upd(h, MSG, 16UL, buf, &len));
        len = sizeof buf;
        memset(buf, 0xAA, sizeof buf);
        { UL rv = call(h, MSG, 16UL, buf, &len); snprintf(l, sizeof l, "%s single after update", n); row(l, rv, len, buf, 16); }
        len = sizeof buf;
        R("final after single", fin(h, buf, &len));
        /* A multipart context an error left behind, then a new operation on another key. */
        Mech cbc = { 0x1082, IV, 16 };
        R("init stale ecb", init(h, &ecb, k));
        len = sizeof buf;
        R("update stale ecb", upd(h, MSG, 16UL, buf, &len));
        R("update 2^31 ends it", upd(h, buf, 0x80000000UL, buf, &len));
        R("init cbc, the other key", init(h, &cbc, k32));
        len = sizeof buf;
        memset(buf, 0xAA, sizeof buf);
        { UL rv = upd(h, MSG, 16UL, buf, &len); snprintf(l, sizeof l, "%s update cbc, the other key", n); row(l, rv, len, buf, 16); }
        len = sizeof buf;
        R("final cbc, the other key", fin(h, buf, &len));
#undef R
    }
}

/* 3: RSA-OAEP with a generated 2048-bit key: every parameter, round trips, bad input. */
static void s_oaep(void) {
    UL h = setup();
    UL bits = 2048;
    unsigned char e3[] = { 1, 0, 1 };
    Attr pub[] = { AT(0x0, c_pub), AT(0x1, T), AT(0x121, bits), AT(0x122, e3), AT(0x104, T),
                   AB(0x3, "rsap", 4) };
    Attr prv[] = { AT(0x0, c_priv), AT(0x1, T), AT(0x105, T), AT(0x103, T), AB(0x3, "rsav", 4) };
    Mech gen = { 0x0, NULL, 0 };
    UL po = 0, vo = 0;
    UL rv = P11(C_GenerateKeyPair, h, &gen, pub, 6UL, prv, 5UL, &po, &vo);
    printf("generate rsa\t%#lx\t%#lx,%#lx\t-\n", rv, po, vo);
    if (rv) return;
    UL k16 = aes(h, "aes16", 16, NULL, 0);
    char l[160];
    struct { const char *n; Oaep p; UL plen; } P[] = {
        { "sha256", { 0x250, 2, 1, NULL, 0 }, sizeof(Oaep) },
        { "sha1", { 0x220, 1, 1, NULL, 0 }, sizeof(Oaep) },
        { "sha384 mgf sha256", { 0x260, 2, 1, NULL, 0 }, sizeof(Oaep) },
        { "sha512", { 0x270, 4, 1, NULL, 0 }, sizeof(Oaep) },
        { "sha224", { 0x255, 5, 1, NULL, 0 }, sizeof(Oaep) },
        { "sha3-256", { 0x2B0, 7, 1, NULL, 0 }, sizeof(Oaep) },
        { "label", { 0x250, 2, 1, AAD, 20 }, sizeof(Oaep) },
        { "label NULL", { 0x250, 2, 1, NULL, 20 }, sizeof(Oaep) },
        { "source 0 label", { 0x250, 2, 0, AAD, 20 }, sizeof(Oaep) },
        { "hash md5", { 0x210, 2, 1, NULL, 0 }, sizeof(Oaep) },
        { "hash unknown", { 0x1234, 2, 1, NULL, 0 }, sizeof(Oaep) },
        { "mgf unknown", { 0x250, 0x77, 1, NULL, 0 }, sizeof(Oaep) },
        { "short", { 0x250, 2, 1, NULL, 0 }, sizeof(Oaep) - 1 },
    };
    for (size_t i = 0; i < sizeof P / sizeof P[0]; ++i) {
        Mech m = { 0x9, &P[i].p, P[i].plen };
        snprintf(l, sizeof l, "oaep %s enc", P[i].n);
        one(0, l, h, &m, po, MSG, 32, 1);
        unsigned char ct[512];
        UL ctn = outn;
        memcpy(ct, out, ctn);
        if (!ctn) continue;
        snprintf(l, sizeof l, "oaep %s dec", P[i].n);
        one(1, l, h, &m, vo, ct, ctn, 0);
        printf("oaep %s round trip\t%d\n", P[i].n, outn == 32 && !memcmp(out, MSG, 32));
        ct[10] ^= 1;
        snprintf(l, sizeof l, "oaep %s dec tampered", P[i].n);
        one(1, l, h, &m, vo, ct, ctn, 0);
        snprintf(l, sizeof l, "oaep %s dec short", P[i].n);
        one(1, l, h, &m, vo, ct, ctn - 1, 0);
    }
    Oaep p = { 0x250, 2, 1, NULL, 0 }, lb = { 0x250, 2, 1, AAD, 20 };
    Mech m = { 0x9, &p, sizeof p }, ml = { 0x9, &lb, sizeof lb };
    unsigned char big[256];
    memset(big, 0x41, sizeof big);
    one(0, "oaep 190 bytes", h, &m, po, big, 190, 1);
    one(0, "oaep 191 bytes", h, &m, po, big, 191, 1);
    one(0, "oaep 0 bytes", h, &m, po, big, 0, 1);
    /* Wrong key class or type, and a label the decrypt does not have. */
    UL z;
    rv_row("oaep enc with the private key", P11(C_EncryptInit, h, &m, vo));
    z = sizeof buf;
    rv_row("oaep enc with the private key, encrypt", P11(C_Encrypt, h, MSG, 16UL, buf, &z));
    rv_row("oaep dec with the public key", P11(C_DecryptInit, h, &m, po));
    z = sizeof buf;
    rv_row("oaep dec with the public key, decrypt", P11(C_Decrypt, h, big, 256UL, buf, &z));
    rv_row("oaep with an aes key", P11(C_EncryptInit, h, &m, k16));
    one(0, "oaep labelled", h, &ml, po, MSG, 16, 1);
    unsigned char ct[512];
    UL ctn = outn;
    memcpy(ct, out, ctn);
    one(1, "oaep label dropped", h, &m, vo, ct, ctn, 0);
    one(1, "oaep label kept", h, &ml, vo, ct, ctn, 0);
    /* No multipart for OAEP. */
    parts(0, "oaep parts", h, &m, po, MSG, 5, 5);
}

/* 4: whose keys these are: logged out, as SO, a session key after logout, an
 * ALWAYS_AUTHENTICATE key, and a logout in the middle of an operation. */
static void s_keys(void) {
    UL h = setup();
    Attr sess[] = { AT(0x1, Fb) };
    Attr pub[] = { AT(0x2, Fb) };
    Attr aa[] = { { 0x202, &T, 1 } };
    UL k = aes(h, "token", 16, NULL, 0), ks = aes(h, "session", 16, sess, 1);
    UL kp = aes(h, "not private", 16, pub, 1), ka = aes(h, "always auth", 16, aa, 1);
    Mech ecb = { 0x1081, NULL, 0 };
    char l[160];
    UL len, rv;
    /* ALWAYS_AUTHENTICATE: decrypt needs a context login; encrypt does not. */
    one(0, "always auth enc", h, &ecb, ka, MSG, 16, 0);
    one(1, "always auth dec, no context login", h, &ecb, ka, MSG, 16, 0);
    rv_row("always auth decinit", P11(C_DecryptInit, h, &ecb, ka));
    rv_row("context login", P11(C_Login, h, 2UL, USER_PIN, (UL)strlen(USER_PIN)));
    len = sizeof buf;
    memset(buf, 0xAA, sizeof buf);
    rv = P11(C_Decrypt, h, MSG, 16UL, buf, &len);
    row("always auth dec after context login", rv, len, buf, rv ? 0 : len);
    rv_row("always auth decinit for parts", P11(C_DecryptInit, h, &ecb, ka));
    len = sizeof buf;
    rv_row("always auth decupdate, no context login", P11(C_DecryptUpdate, h, MSG, 16UL, buf, &len));
    rv_row("always auth decinit for final", P11(C_DecryptInit, h, &ecb, ka));
    len = sizeof buf;
    rv_row("always auth decfinal, no context login", P11(C_DecryptFinal, h, buf, &len));
    /* An operation started before logout, continued after it. */
    rv_row("encinit token key", P11(C_EncryptInit, h, &ecb, k));
    rv_row("decinit session key", P11(C_DecryptInit, h, &ecb, ks));
    rv_row("logout", P11(C_Logout, h));
    len = sizeof buf;
    memset(buf, 0xAA, sizeof buf);
    rv = P11(C_Encrypt, h, MSG, 16UL, buf, &len);
    row("encrypt after logout", rv, len, buf, rv ? 0 : len);
    len = sizeof buf;
    memset(buf, 0xAA, sizeof buf);
    rv = P11(C_Decrypt, h, MSG, 16UL, buf, &len);
    row("decrypt after logout", rv, len, buf, rv ? 0 : len);
    /* Logged out: each key, from scratch. */
    struct { const char *n; UL o; } Ks[] = { { "token", k }, { "session", ks },
                                             { "not private", kp } };
    for (size_t i = 0; i < 3; ++i) {
        snprintf(l, sizeof l, "logged out %s", Ks[i].n);
        trip(l, h, &ecb, Ks[i].o, 16);
    }
    /* As SO. */
    rv_row("login so", P11(C_Login, h, 0UL, SO_PIN, (UL)strlen(SO_PIN)));
    for (size_t i = 0; i < 3; ++i) {
        snprintf(l, sizeof l, "so %s", Ks[i].n);
        trip(l, h, &ecb, Ks[i].o, 16);
    }
    rv_row("logout so", P11(C_Logout, h));
    /* Multipart under way across a logout. */
    rv_row("login", P11(C_Login, h, 1UL, USER_PIN, (UL)strlen(USER_PIN)));
    rv_row("encinit parts", P11(C_EncryptInit, h, &ecb, k));
    len = sizeof buf;
    rv_row("encupdate before logout", P11(C_EncryptUpdate, h, MSG, 16UL, buf, &len));
    rv_row("logout", P11(C_Logout, h));
    len = sizeof buf;
    memset(buf, 0xAA, sizeof buf);
    rv = P11(C_EncryptUpdate, h, MSG + 16, 16UL, buf, &len);
    row("encupdate after logout", rv, len, buf, rv ? 0 : 16);
    len = sizeof buf;
    rv_row("encfinal after logout", P11(C_EncryptFinal, h, buf, &len));
}

/* 5: operations across session and module lifetimes. */
static void s_life(void) {
    UL h = setup(), h2 = 0, len, rv;
    UL k = aes(h, "aes", 16, NULL, 0);
    Mech ecb = { 0x1081, NULL, 0 }, cbc = { 0x1082, IV, 16 };
    rv_row("open second", P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h2));
    rv_row("encinit 1 ecb", P11(C_EncryptInit, h, &ecb, k));
    rv_row("encinit 2 cbc", P11(C_EncryptInit, h2, &cbc, k));
    rv_row("decinit 1 cbc", P11(C_DecryptInit, h, &cbc, k));
    len = sizeof buf;
    memset(buf, 0xAA, sizeof buf);
    rv = P11(C_Encrypt, h2, MSG, 16UL, buf, &len);
    row("encrypt 2", rv, len, buf, 16);
    len = sizeof buf;
    memset(buf, 0xAA, sizeof buf);
    rv = P11(C_Encrypt, h, MSG, 16UL, buf, &len);
    row("encrypt 1", rv, len, buf, 16);
    len = sizeof buf;
    memset(buf, 0xAA, sizeof buf);
    rv = P11(C_Decrypt, h, MSG, 16UL, buf, &len);
    row("decrypt 1", rv, len, buf, 16);
    /* Closed with an operation under way; the next session on the handle has none. */
    rv_row("encinit 2", P11(C_EncryptInit, h2, &ecb, k));
    len = sizeof buf;
    rv_row("encupdate 2", P11(C_EncryptUpdate, h2, MSG, 16UL, buf, &len));
    rv_row("decinit 2", P11(C_DecryptInit, h2, &ecb, k));
    rv_row("close 2", P11(C_CloseSession, h2));
    len = sizeof buf;
    rv_row("encfinal closed", P11(C_EncryptFinal, h2, buf, &len));
    UL h3 = 0;
    rv_row("open third", P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h3));
    printf("third reuses second\t%d\n", h3 == h2);
    len = sizeof buf;
    rv_row("encfinal reused", P11(C_EncryptFinal, h3, buf, &len));
    len = sizeof buf;
    rv_row("decrypt reused", P11(C_Decrypt, h3, MSG, 16UL, buf, &len));
    /* Finalize with operations under way. */
    rv_row("encinit 3", P11(C_EncryptInit, h3, &ecb, k));
    rv_row("decinit 3", P11(C_DecryptInit, h3, &ecb, k));
    rv_row("finalize", P11(C_Finalize, NULL));
    len = sizeof buf;
    rv_row("encrypt finalized", P11(C_Encrypt, h3, MSG, 16UL, buf, &len));
    rv_row("initialize", P11(C_Initialize, NULL));
    UL h4 = 0;
    rv_row("open fourth", P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h4));
    printf("fourth reuses third\t%d\n", h4 == h3);
    len = sizeof buf;
    rv_row("encrypt restarted", P11(C_Encrypt, h4, MSG, 16UL, buf, &len));
    rv_row("login", P11(C_Login, h4, 1UL, USER_PIN, (UL)strlen(USER_PIN)));
    /* A fork with a multipart encrypt under way: the child starts again; the parent goes on. */
    rv_row("encinit parts", P11(C_EncryptInit, h4, &cbc, k));
    len = sizeof buf;
    memset(buf, 0xAA, sizeof buf);
    rv = P11(C_EncryptUpdate, h4, MSG, 16UL, buf, &len);
    row("encupdate before fork", rv, len, buf, 16);
    pid_t p = fork();
    if (p == 0) {
        printf("child initialize\t%#lx\n", P11(C_Initialize, NULL));
        len = sizeof buf;
        printf("child encfinal\t%#lx\n", P11(C_EncryptFinal, h4, buf, &len));
        fflush(stdout);
        _exit(0);
    }
    int st;
    waitpid(p, &st, 0);
    printf("child exit\t%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    len = sizeof buf;
    memset(buf, 0xAA, sizeof buf);
    rv = P11(C_EncryptUpdate, h4, MSG + 16, 16UL, buf, &len);
    row("encupdate after fork", rv, len, buf, 16);
    len = sizeof buf;
    rv_row("encfinal after fork", P11(C_EncryptFinal, h4, buf, &len));
}

static void (*const S[])(void) = { s_init, s_single, s_parts, s_oaep, s_keys, s_life };
static const char *const SN[] = { "init", "single-part", "multipart", "oaep", "keys", "lifetimes" };

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: p11_crypt LIB BASE\n"); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    int rc = 0;
    for (size_t i = 0; i < sizeof S / sizeof S[0]; ++i) {
        snprintf(dir, sizeof dir, "%s/%zu", argv[2], i);
        mkdir(dir, 0700);
        printf("=== %zu %s\n", i, SN[i]);
        pid_t p = fork();
        if (p == 0) {
            setenv("FHSM_TOKENS_DIR", dir, 1);
            S[i]();
            _exit(0);
        }
        int st;
        waitpid(p, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st)) {
            printf("scenario %zu: %s %d\n", i, WIFEXITED(st) ? "exit" : "signal",
                   WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st));
            rc = 1;
        }
    }
    return rc;
}
