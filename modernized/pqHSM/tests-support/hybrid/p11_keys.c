/* p11_keys.c LIB BASE --- slice 6 of PHASE4_PLAN.md §2: call sequences through the key
 * generation entry points (6a: C_GenerateKey, C_GenerateKeyPair), one row per call:
 * "label TAB rv TAB n TAB hex", n the handle(s) written (pre-filled 0xAAAAAAAA). Each new
 * object's attributes follow, one row each ("label NAME rv len value"); generated key material
 * prints as "rnd:<len>", PBKDF2's output whole. After a refusal, "objects" counts what the
 * session sees, so a half-made object shows. C and hybrid must print the same apart from
 * recorded DIVs (harness step 4n).
 *
 * Each scenario runs in a forked child with its own tokens directory BASE/<n>.
 *
 * Written from the C (src/fhsm_pkcs11.c:2357-2422, 2551-2584, 2745-3050, 3150-3189,
 * 3505-3534, 6160-6223, 6370-6933) before the Rust, as its characterisation. */
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
typedef struct { UL src; void *salt; UL salt_len; UL iter; UL prf; void *prf_data; UL prf_len;
                 void *pw; UL pw_len; } Pbkd2;
typedef UL (*F)();

static void *lib;
static char dir[600];
static unsigned char buf[8192];

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

/* What a new key shows: slice 2's attribute list less the certificate ones. */
static const struct { const char *n; UL t; } A[] = {
    { "CLASS", 0x0 }, { "TOKEN", 0x1 }, { "PRIVATE", 0x2 }, { "LABEL", 0x3 },
    { "VALUE", 0x11 }, { "TRUSTED", 0x86 }, { "KEY_TYPE", 0x100 }, { "ID", 0x102 },
    { "SENSITIVE", 0x103 }, { "ENCRYPT", 0x104 }, { "DECRYPT", 0x105 }, { "WRAP", 0x106 },
    { "UNWRAP", 0x107 }, { "SIGN", 0x108 }, { "VERIFY", 0x10A }, { "DERIVE", 0x10C },
    { "START_DATE", 0x110 }, { "END_DATE", 0x111 }, { "MODULUS", 0x120 },
    { "MODULUS_BITS", 0x121 }, { "PUBLIC_EXPONENT", 0x122 }, { "VALUE_LEN", 0x161 },
    { "EXTRACTABLE", 0x162 }, { "LOCAL", 0x163 }, { "NEVER_EXTRACTABLE", 0x164 },
    { "ALWAYS_SENSITIVE", 0x165 }, { "KEY_GEN_MECHANISM", 0x166 }, { "MODIFIABLE", 0x170 },
    { "COPYABLE", 0x171 }, { "DESTROYABLE", 0x172 }, { "EC_PARAMS", 0x180 },
    { "EC_POINT", 0x181 }, { "ALWAYS_AUTH", 0x202 }, { "WRAP_WITH_TRUSTED", 0x210 },
    { "WRAP_TEMPLATE", 0x40000211 }, { "UNWRAP_TEMPLATE", 0x40000212 },
    { "DERIVE_TEMPLATE", 0x40000213 }, { "PARAMETER_SET", 0x61D }, { "ENCAPSULATE", 0x633 },
    { "DECAPSULATE", 0x634 }, { "ALLOWED_MECHANISMS", 0x40000600 },
};
#define NA (sizeof A / sizeof A[0])

#define SO_PIN   "so-pin-1234"
#define USER_PIN "user-pin-1234"
#define LABEL32  "keys                            "
static unsigned char T = 1, Fb = 0;
static UL c_pub = 2, k_aes = 0x1f, k_gen = 0x10;
static unsigned char P256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static unsigned char P384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
static unsigned char P521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };
static unsigned char P224[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21 };
static unsigned char K256[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A };
static unsigned char BP256[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
static unsigned char SECT163[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x01 };
static unsigned char ED25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x70 };
static unsigned char ED448[] = { 0x06, 0x03, 0x2B, 0x65, 0x71 };
static unsigned char X25519[] = { 0x06, 0x03, 0x2B, 0x65, 0x6E };
static unsigned char ED25519_NAME[] = "\x13\x0c" "edwards25519";
static unsigned char ED448_NAME[] = "\x13\x0a" "edwards448";
static unsigned char GARBAGE[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
#define AT(t, v) { t, &(v), sizeof(v) }
#define AB(t, p, n) { t, (void *)(p), n }

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

/* A template attribute, as PKCS#11 reads one: the count, then each length, then the values;
 * printed "type:len:value" per entry. */
static void nested(UL h, const char *name, UL o, size_t i) {
    Attr a = { A[i].t, NULL, 0 };
    UL rv = P11(C_GetAttributeValue, h, o, &a, 1UL);
    printf("%s %s\t%#lx\t%#lx\t", name, A[i].n, rv, a.len);
    Attr arr[16];
    UL n = a.len / sizeof(Attr);
    if (rv || a.len == (UL)-1 || n > 16) { printf("-\n"); return; }
    memset(arr, 0, sizeof arr);
    a = (Attr){ A[i].t, arr, n * sizeof(Attr) };
    rv = P11(C_GetAttributeValue, h, o, &a, 1UL);
    UL off = 0;
    for (UL k = 0; k < n && !rv; ++k) {
        if (arr[k].len > 256) { rv = 0xFFFF; break; }
        arr[k].p = buf + off;
        off += arr[k].len;
    }
    if (!rv) rv = P11(C_GetAttributeValue, h, o, &a, 1UL);
    if (rv) { printf("rv %#lx\n", rv); return; }
    for (UL k = 0; k < n; ++k) {
        printf("%s%lx:%lu:", k ? "," : "", arr[k].type, arr[k].len);
        hex(arr[k].p, arr[k].len);
    }
    printf("\n");
}

/* Every attribute of o, read with room to spare. rnd: key material prints as its length, and
 * an RSA private key's VALUE_LEN too (its DER length varies). */
static void dump(UL h, const char *name, UL o, int rnd) {
    UL cls = 0, kt = 0;
    for (size_t i = 0; i < NA; ++i) {
        if ((A[i].t & 0xFFFFFFF0UL) == 0x40000210UL) { nested(h, name, o, i); continue; }
        memset(buf, 0xAA, sizeof buf);
        Attr a = { A[i].t, buf, sizeof buf };
        UL rv = P11(C_GetAttributeValue, h, o, &a, 1UL);
        printf("%s %s\t%#lx\t%#lx\t", name, A[i].n, rv, a.len);
        if (!rv && A[i].t == 0x0) memcpy(&cls, buf, sizeof cls);
        if (!rv && A[i].t == 0x100) memcpy(&kt, buf, sizeof kt);
        int material = A[i].t == 0x11 || A[i].t == 0x120 || A[i].t == 0x181
                       || (A[i].t == 0x161 && cls == 3 && kt == 0);
        if (rv || a.len > sizeof buf) printf("-");
        else if (rnd && material) printf("rnd:%lu", a.len);
        else hex(buf, a.len);
        printf("\n");
    }
}

/* How many objects the session sees. */
static void count(UL h, const char *name) {
    UL found[512], n = 0;
    UL rv = P11(C_FindObjectsInit, h, NULL, 0UL);
    if (!rv) rv = P11(C_FindObjects, h, found, 512UL, &n);
    P11(C_FindObjectsFinal, h);
    printf("%s objects\t%#lx\t%#lx\t-\n", name, rv, n);
}

/* C_GenerateKey; the new key's attributes, or after a refusal the object count. */
static UL gen(UL h, const char *name, Mech *m, Attr *t, UL n, int rnd) {
    UL o = 0xAAAAAAAAUL, rv = P11(C_GenerateKey, h, m, t, n, &o);
    printf("%s\t%#lx\t%#lx\t-\n", name, rv, o);
    if (rv) { count(h, name); return 0; }
    dump(h, name, o, rnd);
    return o;
}

/* C_GenerateKeyPair; both halves' attributes, or after a refusal the object count. */
static int pair(UL h, const char *name, Mech *m, Attr *pu, UL npu, Attr *pr, UL npr) {
    UL po = 0xAAAAAAAAUL, vo = 0xAAAAAAAAUL;
    UL rv = P11(C_GenerateKeyPair, h, m, pu, npu, pr, npr, &po, &vo);
    printf("%s\t%#lx\t%#lx,%#lx\t-\n", name, rv, po, vo);
    if (rv) { count(h, name); return 0; }
    char l[200];
    snprintf(l, sizeof l, "%s pub", name);
    dump(h, l, po, 1);
    snprintf(l, sizeof l, "%s priv", name);
    dump(h, l, vo, 1);
    return 1;
}
#define GEN(name, mech, rnd, ...) do { Mech m_ = { mech, NULL, 0 }; Attr t_[] = { __VA_ARGS__ }; \
    gen(h, name, &m_, t_, sizeof t_ / sizeof t_[0], rnd); } while (0)
#define PAIR(name, mech, pu, npu, pr, npr) do { Mech m_ = { mech, NULL, 0 }; \
    pair(h, name, &m_, pu, npu, pr, npr); } while (0)

static unsigned char salt[16] = "NaCl-and-pepper!", pw[8] = "password";

static void pbkd2(UL h, const char *name, Pbkd2 *p, UL plen, UL len, UL kt) {
    Mech m = { 0x3B0, p, plen };
    Attr t[] = { AT(0x161, len), AT(0x103, Fb), AT(0x162, T), AT(0x100, kt) };
    gen(h, name, &m, t, kt == (UL)-1 ? 3 : 4, 0);
}

/* 0: C_GenerateKey, its checks in order, every mechanism and length, the flags and the
 * templates it applies. */
static void s_gen(void) {
    UL h = setup(), len16 = 16, len = 0;
    Mech aes = { 0x1080, NULL, 0 };
    UL o = 0xAAAAAAAAUL;
    Attr ok[] = { AT(0x161, len16) };
    printf("null mech\t%#lx\t-\t-\n", P11(C_GenerateKey, h, NULL, ok, 1UL, &o));
    printf("null handle\t%#lx\t-\t-\n", P11(C_GenerateKey, h, &aes, ok, 1UL, NULL));
    printf("null template with count\t%#lx\t-\t-\n", P11(C_GenerateKey, h, &aes, NULL, 1UL, &o));
    Attr nullval[] = { AT(0x161, len16), AB(0x3, NULL, 4) };
    printf("null value with length\t%#lx\t-\t-\n", P11(C_GenerateKey, h, &aes, nullval, 2UL, &o));
    GEN("trusted by the user", 0x1080, 1, AT(0x161, len16), AT(0x86, T));
    GEN("trusted false", 0x1080, 1, AT(0x161, len16), AT(0x86, Fb));
    unsigned short two = 1;
    GEN("bool of two bytes", 0x1080, 1, AT(0x161, len16), AT(0x103, two));
    unsigned int four = 16;
    GEN("ulong of four bytes", 0x1080, 1, AT(0x161, four));
    GEN("class of four bytes", 0x1080, 1, AT(0x161, len16), AT(0x0, four));
    printf("bad session\t%#lx\t-\t-\n", P11(C_GenerateKey, 0x7777UL, &aes, ok, 1UL, &o));
    GEN("encapsulate", 0x1080, 1, AT(0x161, len16), AT(0x633, T));
    GEN("decapsulate false", 0x1080, 1, AT(0x161, len16), AT(0x634, Fb));
    GEN("unknown mechanism", 0x99999, 1, AT(0x161, len16));
    GEN("aes key pair mechanism", 0x1040, 1, AT(0x161, len16));
    /* AES, generic, HKDF and 3DES lengths */
    GEN("aes no length", 0x1080, 1, AT(0x103, T));
    Attr nolen[] = { AB(0x161, NULL, 8) };
    gen(h, "aes null length", &aes, nolen, 1, 1);
    UL aes_l[] = { 0, 15, 16, 24, 32, 33, 64 };
    for (size_t i = 0; i < sizeof aes_l / sizeof *aes_l; ++i) {
        char l[64];
        snprintf(l, sizeof l, "aes %lu", aes_l[i]);
        len = aes_l[i];
        GEN(l, 0x1080, 1, AT(0x161, len));
    }
    UL gen_l[] = { 0, 1, 13, 14, 32, 64, 65 };
    for (size_t i = 0; i < sizeof gen_l / sizeof *gen_l; ++i) {
        char l[64];
        snprintf(l, sizeof l, "generic %lu", gen_l[i]);
        len = gen_l[i];
        GEN(l, 0x350, 1, AT(0x161, len));
    }
    UL hkdf_l[] = { 0, 1, 32, 256, 257 };
    for (size_t i = 0; i < sizeof hkdf_l / sizeof *hkdf_l; ++i) {
        char l[64];
        snprintf(l, sizeof l, "hkdf keygen %lu", hkdf_l[i]);
        len = hkdf_l[i];
        GEN(l, 0x402C, 1, AT(0x161, len));
    }
    UL l24 = 24;
    GEN("des3", 0x131, 1, AT(0x161, l24));
    GEN("des3 no length", 0x131, 1, AT(0x103, T));
    GEN("aes key type ignored", 0x1080, 1, AT(0x161, len16), AT(0x100, k_gen));
    GEN("aes class ignored", 0x1080, 1, AT(0x161, len16), AT(0x0, c_pub));
    /* the flags and the attributes they come from */
    GEN("defaults", 0x1080, 1, AT(0x161, len16));
    GEN("not sensitive", 0x1080, 1, AT(0x161, len16), AT(0x103, Fb));
    GEN("extractable", 0x1080, 1, AT(0x161, len16), AT(0x162, T));
    GEN("extractable false", 0x1080, 1, AT(0x161, len16), AT(0x162, Fb));
    GEN("sensitive null", 0x1080, 1, AT(0x161, len16), AB(0x103, NULL, 0));
    GEN("usage", 0x1080, 1, AT(0x161, len16), AT(0x104, Fb), AT(0x108, Fb), AT(0x10C, T),
        AT(0x106, Fb));
    char lab[100];
    memset(lab, 'L', sizeof lab);
    GEN("label of 100", 0x1080, 1, AT(0x161, len16), AB(0x3, lab, 100));
    GEN("label and id", 0x1080, 1, AT(0x161, len16), AB(0x3, "the label", 9),
        AB(0x102, "\x01\x02\x03", 3));
    GEN("empty label", 0x1080, 1, AT(0x161, len16), AB(0x3, "", 0));
    GEN("token", 0x1080, 1, AT(0x161, len16), AT(0x1, T));
    GEN("private false", 0x1080, 1, AT(0x161, len16), AT(0x2, Fb));
    GEN("unmodifiable undestroyable uncopyable", 0x1080, 1, AT(0x161, len16), AT(0x170, Fb),
        AT(0x172, Fb), AT(0x171, Fb));
    GEN("wrap with trusted", 0x1080, 1, AT(0x161, len16), AT(0x210, T));
    GEN("always authenticate", 0x1080, 1, AT(0x161, len16), AT(0x202, T));
    UL am[] = { 0x1081, 0x1087 }, am9[9] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    GEN("allowed mechanisms", 0x1080, 1, AT(0x161, len16), AB(0x40000600, am, sizeof am));
    GEN("allowed mechanisms nine", 0x1080, 1, AT(0x161, len16), AB(0x40000600, am9, sizeof am9));
    GEN("allowed mechanisms odd length", 0x1080, 1, AT(0x161, len16), AB(0x40000600, am, 12));
    Attr nest[] = { AT(0x103, T), AT(0x162, Fb) };
    Attr nest5[] = { AT(0x103, T), AT(0x162, Fb), AT(0x104, T), AT(0x105, T), AT(0x108, T) };
    Attr nestbig[] = { AB(0x3, lab, 49) };
    GEN("unwrap template", 0x1080, 1, AT(0x161, len16), AB(0x40000212, nest, sizeof nest));
    GEN("unwrap template sensitive false", 0x1080, 1, AT(0x161, len16),
        AB(0x40000212, nest + 1, sizeof nest[0]));
    GEN("wrap template", 0x1080, 1, AT(0x161, len16), AB(0x40000211, nest, sizeof nest));
    GEN("derive template", 0x1080, 1, AT(0x161, len16), AB(0x40000213, nest, sizeof nest));
    GEN("wrap template of five", 0x1080, 1, AT(0x161, len16), AB(0x40000211, nest5, sizeof nest5));
    GEN("derive template value of 49", 0x1080, 1, AT(0x161, len16),
        AB(0x40000213, nestbig, sizeof nestbig));
    GEN("unwrap template odd length", 0x1080, 1, AT(0x161, len16), AB(0x40000212, nest, 7));
    unsigned char d1[8] = "20260101", d2[8] = "20271231", dbad[4] = "2026";
    GEN("dates", 0x1080, 1, AT(0x161, len16), AB(0x110, d1, 8), AB(0x111, d2, 8));
    GEN("date of four", 0x1080, 1, AT(0x161, len16), AB(0x110, dbad, 4));
    GEN("application", 0x1080, 1, AT(0x161, len16), AB(0x10, "app", 3));
    /* PBKDF2: its parameters, then the key */
    Pbkd2 p = { 1, salt, 16, 1000, 4, NULL, 0, pw, 8 }, q;
    pbkd2(h, "pbkdf2 sha256", &p, sizeof p, 32, (UL)-1);
    pbkd2(h, "pbkdf2 aes type", &p, sizeof p, 16, k_aes);
    pbkd2(h, "pbkdf2 aes type of 5", &p, sizeof p, 5, k_aes);
    pbkd2(h, "pbkdf2 short param", &p, sizeof p - 1, 32, (UL)-1);
    pbkd2(h, "pbkdf2 null param", NULL, sizeof p, 32, (UL)-1);
    UL prfs[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    for (size_t i = 0; i < sizeof prfs / sizeof *prfs; ++i) {
        char l[64];
        snprintf(l, sizeof l, "pbkdf2 prf %lu", prfs[i]);
        q = p; q.prf = prfs[i];
        pbkd2(h, l, &q, sizeof q, 20, (UL)-1);
    }
    q = p; q.src = 2; pbkd2(h, "pbkdf2 salt source 2", &q, sizeof q, 16, (UL)-1);
    q = p; q.salt = NULL; pbkd2(h, "pbkdf2 null salt", &q, sizeof q, 16, (UL)-1);
    q = p; q.salt = NULL; q.salt_len = 0; pbkd2(h, "pbkdf2 no salt", &q, sizeof q, 16, (UL)-1);
    q = p; q.salt_len = 0x80000000UL; pbkd2(h, "pbkdf2 salt of 2^31", &q, sizeof q, 16, (UL)-1);
    q = p; q.pw = NULL; pbkd2(h, "pbkdf2 null password", &q, sizeof q, 16, (UL)-1);
    q = p; q.pw = NULL; q.pw_len = 0; pbkd2(h, "pbkdf2 no password", &q, sizeof q, 16, (UL)-1);
    q = p; q.prf_len = 4; pbkd2(h, "pbkdf2 null prf data", &q, sizeof q, 16, (UL)-1);
    q = p; q.prf_data = salt; q.prf_len = 4;
    pbkd2(h, "pbkdf2 prf data", &q, sizeof q, 16, (UL)-1);
    q = p; q.iter = 999; pbkd2(h, "pbkdf2 999 iterations", &q, sizeof q, 16, (UL)-1);
    q = p; q.iter = 0x100000000UL + 1000;
    pbkd2(h, "pbkdf2 2^32+1000 iterations", &q, sizeof q, 16, (UL)-1);
    q = p; q.iter = 0x100000000UL + 2;
    pbkd2(h, "pbkdf2 2^32+2 iterations", &q, sizeof q, 16, (UL)-1);
    pbkd2(h, "pbkdf2 length 0", &p, sizeof p, 0, (UL)-1);
    pbkd2(h, "pbkdf2 length 256", &p, sizeof p, 256, (UL)-1);
    pbkd2(h, "pbkdf2 length 257", &p, sizeof p, 257, (UL)-1);
    Mech mp = { 0x3B0, &p, sizeof p };
    Attr nl[] = { AT(0x103, Fb) };
    gen(h, "pbkdf2 no length", &mp, nl, 1, 0);
    Attr nl4[] = { AT(0x161, four) };
    gen(h, "pbkdf2 length of four bytes", &mp, nl4, 1, 0);
    P11(C_Finalize, NULL);
}

/* 1: C_GenerateKeyPair, its checks in order, every family and parameter, the flags and the
 * templates it applies to each half. */
static void s_pair(void) {
    UL h = setup(), po, vo;
    Mech ec = { 0x1040, NULL, 0 };
    Attr pu[] = { AB(0x180, P256, sizeof P256) }, pr[] = { AT(0x108, T) };
    printf("null mech\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, h, NULL, pu, 1UL, pr, 1UL, &po, &vo));
    printf("null pub handle\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, h, &ec, pu, 1UL, pr, 1UL, NULL, &vo));
    printf("null priv handle\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, h, &ec, pu, 1UL, pr, 1UL, &po, NULL));
    printf("null pub template\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, h, &ec, NULL, 1UL, pr, 1UL, &po, &vo));
    printf("null priv template\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, h, &ec, pu, 1UL, NULL, 1UL, &po, &vo));
    printf("bad session\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, 0x7777UL, &ec, pu, 1UL, pr, 1UL, &po, &vo));
    Attr tr[] = { AT(0x86, T) }, b2[] = { AB(0x108, "\x01\x01", 2) };
    unsigned int four = 2048;
    Attr u4[] = { AT(0x121, four) };
    PAIR("pub trusted", 0x1040, tr, 1, pr, 1);
    PAIR("priv trusted", 0x1040, pu, 1, tr, 1);
    PAIR("pub bool of two", 0x1040, b2, 1, pr, 1);
    PAIR("priv bool of two", 0x1040, pu, 1, b2, 1);
    PAIR("pub ulong of four", 0x1040, u4, 1, pr, 1);
    PAIR("priv ulong of four", 0x1040, pu, 1, u4, 1);
    PAIR("unknown mechanism", 0x99999, pu, 1, pr, 1);
    PAIR("composite", 0x80004202UL, NULL, 0, NULL, 0);
    /* EC */
    PAIR("ec default", 0x1040, NULL, 0, NULL, 0);
    struct { const char *n; unsigned char *c; UL l; } curves[] = {
        { "ec p256", P256, sizeof P256 }, { "ec p384", P384, sizeof P384 },
        { "ec p521", P521, sizeof P521 }, { "ec p224", P224, sizeof P224 },
        { "ec secp256k1", K256, sizeof K256 }, { "ec brainpool256", BP256, sizeof BP256 },
        { "ec sect163k1", SECT163, sizeof SECT163 }, { "ec x25519", X25519, sizeof X25519 },
        { "ec ed25519", ED25519, sizeof ED25519 }, { "ec garbage", GARBAGE, sizeof GARBAGE },
        { "ec empty", GARBAGE, 0 }, { "ec p256 truncated", P256, 9 },
    };
    for (size_t i = 0; i < sizeof curves / sizeof *curves; ++i) {
        Attr c[] = { AB(0x180, curves[i].c, curves[i].l) };
        PAIR(curves[i].n, 0x1040, c, 1, NULL, 0);
    }
    Attr cnull[] = { AB(0x180, NULL, 0) };
    PAIR("ec null params", 0x1040, cnull, 1, NULL, 0);
    /* Edwards and Montgomery */
    PAIR("ed default", 0x1055, NULL, 0, NULL, 0);
    struct { const char *n; unsigned char *c; UL l; } eds[] = {
        { "ed ed25519", ED25519, sizeof ED25519 }, { "ed ed448", ED448, sizeof ED448 },
        { "ed edwards25519", ED25519_NAME, 14 }, { "ed edwards448", ED448_NAME, 12 },
        { "ed p256", P256, sizeof P256 }, { "ed x25519", X25519, sizeof X25519 },
    };
    for (size_t i = 0; i < sizeof eds / sizeof *eds; ++i) {
        Attr c[] = { AB(0x180, eds[i].c, eds[i].l) };
        PAIR(eds[i].n, 0x1055, c, 1, NULL, 0);
    }
    PAIR("x25519 default", 0x1056, NULL, 0, NULL, 0);
    Attr cx[] = { AB(0x180, X25519, sizeof X25519) };
    PAIR("x25519", 0x1056, cx, 1, NULL, 0);
    /* RSA */
    PAIR("rsa default", 0x0, NULL, 0, NULL, 0);
    UL bits[] = { 1024, 2047, 3072, 4096, 8192 };
    for (size_t i = 0; i < sizeof bits / sizeof *bits; ++i) {
        char l[64];
        snprintf(l, sizeof l, "rsa %lu", bits[i]);
        Attr b[] = { AT(0x121, bits[i]) };
        PAIR(l, 0x0, b, 1, NULL, 0);
    }
    struct { const char *n; const char *e; UL l; } exps[] = {
        { "rsa e 65537", "\x01\x00\x01", 3 }, { "rsa e 65537 leading zero", "\x00\x01\x00\x01", 4 },
        { "rsa e 3", "\x03", 1 }, { "rsa e 4", "\x04", 1 }, { "rsa e 1", "\x01", 1 },
        { "rsa e 0", "\x00", 1 }, { "rsa e 2^17+1", "\x02\x00\x01", 3 },
        { "rsa e empty", "", 0 },
    };
    for (size_t i = 0; i < sizeof exps / sizeof *exps; ++i) {
        Attr e[] = { AB(0x122, exps[i].e, exps[i].l) };
        PAIR(exps[i].n, 0x0, e, 1, NULL, 0);
    }
    /* ML-KEM, ML-DSA, SLH-DSA parameter sets */
    struct { const char *n; UL m; } pq[] = { { "mlkem", 0xF }, { "mldsa", 0x1C }, { "slhdsa", 0x2D } };
    for (size_t f = 0; f < 3; ++f) {
        char l[96];
        snprintf(l, sizeof l, "%s default", pq[f].n);
        PAIR(l, pq[f].m, NULL, 0, NULL, 0);
        for (UL s = 0; s <= (f == 2 ? 13UL : 4UL); ++s) {
            snprintf(l, sizeof l, "%s selector %lu", pq[f].n, s);
            Attr ps[] = { AT(0x61D, s) };
            PAIR(l, pq[f].m, ps, 1, NULL, 0);
        }
    }
    const char *names[] = { "ML-KEM-512", "ML-DSA-44", "SLH-DSA-SHAKE-128f", "ML-KEM-1024",
                            "ml-kem-512", "" };
    for (size_t f = 0; f < 3; ++f)
        for (size_t i = 0; i < sizeof names / sizeof *names; ++i) {
            char l[96];
            snprintf(l, sizeof l, "%s name '%s'", pq[f].n, names[i]);
            Attr ps[] = { AB(0x61D, names[i], strlen(names[i])) };
            PAIR(l, pq[f].m, ps, 1, NULL, 0);
        }
    char longname[40];
    memset(longname, 'M', sizeof longname);
    Attr pl[] = { AB(0x61D, longname, sizeof longname) };
    PAIR("mlkem name of 40", 0xF, pl, 1, NULL, 0);
    UL s1 = 1, s9 = 9;
    Attr ps1[] = { AT(0x61D, s1) }, ps9[] = { AT(0x61D, s9) };
    PAIR("mldsa priv selector 1", 0x1C, NULL, 0, ps1, 1);
    PAIR("mldsa priv selector 9", 0x1C, NULL, 0, ps9, 1);
    PAIR("ec parameter set ignored", 0x1040, ps9, 1, NULL, 0);
    /* the flags and templates of each half */
    Attr pub_all[] = { AT(0x1, T), AT(0x104, Fb), AT(0x10A, Fb), AB(0x3, "pub label", 9),
                       AB(0x102, "\x0a\x0b", 2), AT(0x2, Fb), AT(0x170, Fb) };
    Attr priv_all[] = { AT(0x1, T), AT(0x103, Fb), AT(0x162, T), AT(0x202, T), AT(0x10C, Fb),
                        AB(0x3, "priv label", 10), AB(0x102, "\x0c", 1), AT(0x171, Fb),
                        AT(0x172, Fb), AT(0x210, T) };
    PAIR("ec flags", 0x1040, pub_all, 7, priv_all, 10);
    Attr aa_f[] = { AT(0x202, Fb) }, aa_2[] = { AB(0x202, "\x01\x00", 2) };
    PAIR("always auth false", 0x1040, NULL, 0, aa_f, 1);
    PAIR("always auth of two", 0x1040, NULL, 0, aa_2, 1);
    UL am[] = { 0x1041 }, am9[9] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    Attr pam[] = { AB(0x40000600, am, sizeof am) }, pam9[] = { AB(0x40000600, am9, sizeof am9) };
    PAIR("pub allowed mechanisms", 0x1040, pam, 1, pam, 1);
    PAIR("pub allowed mechanisms nine", 0x1040, pam9, 1, NULL, 0);
    PAIR("priv allowed mechanisms nine", 0x1040, NULL, 0, pam9, 1);
    Attr nest[] = { AT(0x103, T) }, nest5[] = { AT(0x103, T), AT(0x162, Fb), AT(0x104, T),
                                                AT(0x105, T), AT(0x108, T) };
    Attr pun[] = { AB(0x40000212, nest, sizeof nest) }, pwn[] = { AB(0x40000211, nest, sizeof nest) };
    Attr pdn5[] = { AB(0x40000213, nest5, sizeof nest5) };
    PAIR("unwrap templates", 0x1040, pun, 1, pun, 1);
    PAIR("wrap templates", 0x1040, pwn, 1, pwn, 1);
    PAIR("pub derive template of five", 0x1040, pdn5, 1, NULL, 0);
    PAIR("priv derive template of five", 0x1040, NULL, 0, pdn5, 1);
    unsigned char d1[8] = "20260101", dbad[4] = "2026";
    Attr dt[] = { AB(0x110, d1, 8) }, dtb[] = { AB(0x111, dbad, 4) };
    PAIR("dates", 0x1040, dt, 1, dt, 1);
    PAIR("pub date of four", 0x1040, dtb, 1, NULL, 0);
    PAIR("priv date of four", 0x1040, NULL, 0, dtb, 1);
    Attr enc_t[] = { AT(0x633, T) }, enc_f[] = { AT(0x633, Fb) }, dec_f[] = { AT(0x634, Fb) };
    PAIR("mlkem encapsulate false", 0xF, enc_f, 1, dec_f, 1);
    PAIR("mlkem encapsulate true", 0xF, enc_t, 1, NULL, 0);
    PAIR("ec encapsulate false", 0x1040, enc_f, 1, NULL, 0);
    PAIR("ec decapsulate false", 0x1040, NULL, 0, dec_f, 1);
    PAIR("mldsa derive", 0x1C, NULL, 0, (Attr[]){ AT(0x10C, T) }, 1);
    PAIR("ec derive false", 0x1040, NULL, 0, (Attr[]){ AT(0x10C, Fb) }, 1);
    P11(C_Finalize, NULL);
}

/* 2: the session and module around a generation: read-only sessions, logged out, SO, a second
 * session, close, finalize, a fork. */
static void s_life(void) {
    UL h = setup(), h2 = 0, ro = 0, len16 = 16, po, vo;
    Mech aes = { 0x1080, NULL, 0 }, ec = { 0x1040, NULL, 0 };
    Attr sk[] = { AT(0x161, len16) }, tk[] = { AT(0x161, len16), AT(0x1, T) };
    Attr ptok[] = { AT(0x1, T) };
    UL o = 0xAAAAAAAAUL;
    printf("open ro\t%#lx\t-\t-\n", P11(C_OpenSession, 0UL, 4UL, NULL, NULL, &ro));
    UL rv = P11(C_GenerateKey, ro, &aes, sk, 1UL, &o);
    printf("ro session key\t%#lx\t%#lx\t-\n", rv, o);
    printf("ro token key\t%#lx\t-\t-\n", P11(C_GenerateKey, ro, &aes, tk, 2UL, &o));
    printf("ro session pair\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, ro, &ec, NULL, 0UL, NULL, 0UL, &po, &vo));
    printf("ro token pub\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, ro, &ec, ptok, 1UL, NULL, 0UL, &po, &vo));
    printf("ro token priv\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, ro, &ec, NULL, 0UL, ptok, 1UL, &po, &vo));
    count(ro, "ro");
    printf("close ro\t%#lx\t-\t-\n", P11(C_CloseSession, ro));
    UL ks = gen(h, "session key", &aes, sk, 1, 1);
    printf("open second\t%#lx\t-\t-\n", P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h2));
    count(h2, "second sees");
    printf("close first\t%#lx\t-\t-\n", P11(C_CloseSession, h));
    count(h2, "after close");
    UL a = 0xAAAAUL;
    Attr g = { 0x0, &a, sizeof a };
    printf("closed session's key\t%#lx\t-\t-\n", P11(C_GetAttributeValue, h2, ks, &g, 1UL));
    printf("logout\t%#lx\t-\t-\n", P11(C_Logout, h2));
    o = 0xAAAAAAAAUL;
    rv = P11(C_GenerateKey, h2, &aes, sk, 1UL, &o);
    printf("logged out key\t%#lx\t%#lx\t-\n", rv, o);
    printf("logged out pair\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, h2, &ec, NULL, 0UL, NULL, 0UL, &po, &vo));
    printf("login so\t%#lx\t-\t-\n", P11(C_Login, h2, 0UL, SO_PIN, (UL)strlen(SO_PIN)));
    o = 0xAAAAAAAAUL;
    rv = P11(C_GenerateKey, h2, &aes, sk, 1UL, &o);
    printf("so key\t%#lx\t%#lx\t-\n", rv, o);
    po = vo = 0xAAAAAAAAUL;
    rv = P11(C_GenerateKeyPair, h2, &ec, NULL, 0UL, NULL, 0UL, &po, &vo);
    printf("so pair\t%#lx\t%#lx,%#lx\t-\n", rv, po, vo);
    count(h2, "so");
    printf("logout so\t%#lx\t-\t-\n", P11(C_Logout, h2));
    count(h2, "nobody");
    printf("login user\t%#lx\t-\t-\n", P11(C_Login, h2, 1UL, USER_PIN, (UL)strlen(USER_PIN)));
    count(h2, "user");
    UL tkh = gen(h2, "token key", &aes, tk, 2, 1);
    pid_t p = fork();
    if (p == 0) {
        printf("child key\t%#lx\t-\t-\n", P11(C_GenerateKey, h2, &aes, sk, 1UL, &o));
        printf("child pair\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, h2, &ec, NULL, 0UL, NULL, 0UL, &po, &vo));
        _exit(0);
    }
    int st;
    waitpid(p, &st, 0);
    printf("finalize\t%#lx\t-\t-\n", P11(C_Finalize, NULL));
    printf("key finalized\t%#lx\t-\t-\n", P11(C_GenerateKey, h2, &aes, sk, 1UL, &o));
    printf("pair finalized\t%#lx\t-\t-\n", P11(C_GenerateKeyPair, h2, &ec, NULL, 0UL, NULL, 0UL, &po, &vo));
    /* The token key is still there after a restart. */
    UL h3 = 0;
    P11(C_Initialize, NULL);
    P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h3);
    P11(C_Login, h3, 1UL, USER_PIN, (UL)strlen(USER_PIN));
    count(h3, "restarted");
    dump(h3, "restarted token key", tkh, 1);
    P11(C_Finalize, NULL);
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: p11_keys LIB BASE\n"); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    void (*S[])(void) = { s_gen, s_pair, s_life };
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
