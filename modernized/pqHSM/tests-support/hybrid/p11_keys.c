/* p11_keys.c LIB BASE --- slice 6 of PHASE4_PLAN.md §2: call sequences through the key
 * generation and creation entry points (6a: C_GenerateKey, C_GenerateKeyPair; 6b:
 * C_CreateObject's builders, over keys libcrypto makes here; 6c: C_WrapKey, C_UnwrapKey; 6d: C_DeriveKey; 7: C_EncapsulateKey, C_DecapsulateKey; 8b-ii: the attributes read back through OpenSSL), one row per call:
 * "label TAB rv TAB n TAB hex", n each handle out-parameter: "-" untouched, else its distance
 * from the last handle written (the raw value where a call prints it directly). Each new object's attributes follow, one row each
 * ("label NAME rv len value"); generated key material prints as "rnd:<len>", PBKDF2's output
 * whole. After a refusal, "objects" is the change in what the session sees, so a half-made
 * object shows as +1. C and hybrid must print the same apart from
 * recorded DIVs (harness step 4n).
 *
 * Each scenario runs in a forked child with its own tokens directory BASE/<n>.
 *
 * Written from the C (src/fhsm_pkcs11.c:2357-2422, 2551-2584, 2745-3050, 3150-3189,
 * 3497-3534, 3559-4138, 4277-4878, 4974-5929, 6160-6223, 6370-6933, 8631-8829) before the Rust, as its characterisation. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/x509.h>

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

/* How many objects the session sees; the find's rv in *rv. */
static UL nobj(UL h, UL *rv) {
    UL found[512], n = 0;
    *rv = P11(C_FindObjectsInit, h, NULL, 0UL);
    if (!*rv) *rv = P11(C_FindObjects, h, found, 512UL, &n);
    P11(C_FindObjectsFinal, h);
    return n;
}
static void count(UL h, const char *name) {
    UL rv, n = nobj(h, &rv);
    printf("%s objects\t%#lx\t%#lx\t-\n", name, rv, n);
}

/* After a refusal, what it stored: the change in the count. Absolute counts and handles would
 * renumber every later row behind a key that a DIV now refuses. */
static void stored(UL h, const char *name, UL before) {
    UL rv, n = nobj(h, &rv);
    printf("%s objects\t%#lx\t%+ld\t-\n", name, rv, (long)(n - before));
}

/* A handle out-parameter: "-" if untouched, else its distance from the last handle written
 * here ("+1" the next). Handles only go up, so a key added and destroyed on the way shows as
 * a gap, yet a key a DIV now refuses renumbers nothing after it. */
static UL last_h;
static const char *hv(UL o, char *buf) {
    if (o == 0xAAAAAAAAUL) return "-";
    snprintf(buf, 24, "%+ld", (long)(o - last_h));
    last_h = o;
    return buf;
}

/* C_GenerateKey; the new key's attributes, or after a refusal the objects it stored. */
static UL gen(UL h, const char *name, Mech *m, Attr *t, UL n, int rnd) {
    UL frv, before = nobj(h, &frv), o = 0xAAAAAAAAUL, rv = P11(C_GenerateKey, h, m, t, n, &o);
    char b[24];
    printf("%s\t%#lx\t%s\t-\n", name, rv, hv(o, b));
    if (rv) { stored(h, name, before); return 0; }
    dump(h, name, o, rnd);
    return o;
}

/* C_GenerateKeyPair; both halves' attributes, or after a refusal the objects it stored. */
static int pair(UL h, const char *name, Mech *m, Attr *pu, UL npu, Attr *pr, UL npr) {
    UL frv, before = nobj(h, &frv), po = 0xAAAAAAAAUL, vo = 0xAAAAAAAAUL;
    UL rv = P11(C_GenerateKeyPair, h, m, pu, npu, pr, npr, &po, &vo);
    char b1[24], b2[24];
    const char *p1 = hv(po, b1);
    printf("%s\t%#lx\t%s,%s\t-\n", name, rv, p1, hv(vo, b2));
    if (rv) { stored(h, name, before); return 0; }
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

/* 3 (slice 6b): C_CreateObject's builders, over keys libcrypto makes here. Their material is
 * random; every row that shows it prints its length. */
typedef struct { unsigned char p[4096]; size_t n; } Blob;
static EVP_PKEY *kg(const char *alg, const char *group) {
    EVP_PKEY *k = group ? EVP_PKEY_Q_keygen(NULL, NULL, "EC", group)
                        : !strcmp(alg, "RSA") ? EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048)
                        : EVP_PKEY_Q_keygen(NULL, NULL, alg);
    if (!k) { fprintf(stderr, "keygen %s failed\n", alg); exit(2); }
    return k;
}
static void raw(EVP_PKEY *k, int priv, Blob *b) {
    b->n = sizeof b->p;
    int ok = priv ? EVP_PKEY_get_raw_private_key(k, b->p, &b->n)
                  : EVP_PKEY_get_raw_public_key(k, b->p, &b->n);
    if (ok != 1) b->n = 0;
}
static void spki(EVP_PKEY *k, Blob *b) {
    unsigned char *q = b->p;
    int n = i2d_PUBKEY(k, &q);
    b->n = n > 0 ? (size_t)n : 0;
}
static void bn(EVP_PKEY *k, const char *name, int pad, Blob *b) {
    BIGNUM *x = NULL;
    EVP_PKEY_get_bn_param(k, name, &x);
    int n = !x ? 0 : pad ? BN_bn2binpad(x, b->p, pad) : BN_bn2bin(x, b->p);
    b->n = n > 0 ? (size_t)n : 0;
    BN_clear_free(x);
}
static void oct(EVP_PKEY *k, const char *name, Blob *b) {
    if (EVP_PKEY_get_octet_string_param(k, name, b->p, sizeof b->p, &b->n) != 1) b->n = 0;
}
/* The DER OCTET STRING CKA_EC_POINT holds (each point here is under 128 bytes). */
static void wrap(const Blob *in, Blob *out) {
    out->p[0] = 0x04, out->p[1] = (unsigned char)in->n;
    memcpy(out->p + 2, in->p, in->n);
    out->n = in->n + 2;
}

static UL mk(UL h, const char *name, Attr *t, UL n) {
    UL frv, before = nobj(h, &frv), o = 0xAAAAAAAAUL, rv = P11(C_CreateObject, h, t, n, &o);
    char b[24];
    printf("%s\t%#lx\t%s\t-\n", name, rv, hv(o, b));
    if (rv) { stored(h, name, before); return 0; }
    dump(h, name, o, 1);
    return o;
}
#define MK(name, ...) do { Attr t_[] = { __VA_ARGS__ }; mk(h, name, t_, sizeof t_ / sizeof t_[0]); } while (0)
#define BL(t, b) { t, (b).p, (UL)(b).n }

static void s_create(void) {
    UL h = setup();
    static UL c_priv = 3, k_rsa = 0, k_ec = 3, k_ed = 0x40, k_x = 0x41, k_kem = 0x49,
              k_dsa = 0x4A, k_slh = 0x4B, s1 = 1, s2 = 2, s3 = 3, s4 = 4;
    static Blob p256pt, p256w, p256bad, p256s, p384pt, p384w, k1w, edp, edw, edv, ed4p, ed4w,
        ed4v, xv, rn, re, rd, rp, rq, rdp, rdq, rqi, rd2, kem5p, kem5v, kem7s, dsap, dsav, slhp,
        slhv, zero;
    EVP_PKEY *k = kg("EC", "P-256");
    oct(k, "pub", &p256pt); wrap(&p256pt, &p256w); bn(k, "priv", 32, &p256s);
    p256bad = p256w; p256bad.p[p256bad.n - 1] ^= 1;
    EVP_PKEY_free(k);
    k = kg("EC", "P-384"); oct(k, "pub", &p384pt); wrap(&p384pt, &p384w); EVP_PKEY_free(k);
    k = kg("EC", "secp256k1"); { Blob t; oct(k, "pub", &t); wrap(&t, &k1w); } EVP_PKEY_free(k);
    k = kg("ED25519", NULL); raw(k, 0, &edp); wrap(&edp, &edw); raw(k, 1, &edv); EVP_PKEY_free(k);
    k = kg("ED448", NULL); raw(k, 0, &ed4p); wrap(&ed4p, &ed4w); raw(k, 1, &ed4v); EVP_PKEY_free(k);
    k = kg("X25519", NULL); raw(k, 1, &xv); EVP_PKEY_free(k);
    k = kg("RSA", NULL);
    bn(k, "n", 0, &rn); bn(k, "e", 0, &re); bn(k, "d", 0, &rd); bn(k, "rsa-factor1", 0, &rp);
    bn(k, "rsa-factor2", 0, &rq); bn(k, "rsa-exponent1", 0, &rdp);
    bn(k, "rsa-exponent2", 0, &rdq); bn(k, "rsa-coefficient1", 0, &rqi);
    EVP_PKEY_free(k);
    k = kg("RSA", NULL); bn(k, "d", 0, &rd2); EVP_PKEY_free(k);
    k = kg("ML-KEM-512", NULL); raw(k, 0, &kem5p); raw(k, 1, &kem5v); EVP_PKEY_free(k);
    k = kg("ML-KEM-768", NULL); spki(k, &kem7s); EVP_PKEY_free(k);
    k = kg("ML-DSA-44", NULL); raw(k, 0, &dsap); raw(k, 1, &dsav); EVP_PKEY_free(k);
    k = kg("SLH-DSA-SHA2-128f", NULL); raw(k, 0, &slhp); raw(k, 1, &slhv); EVP_PKEY_free(k);
    zero.n = kem5v.n; memset(zero.p, 0, zero.n);
    UL mechs[] = { 0x1041, 0x1044 };
    UL cls_s = 4;
    Attr wt[] = { AT(0x0, cls_s) };
    unsigned char five[5] = { 0 };

    /* EC public keys: the point wrapped, bare, off the curve, on another curve */
    MK("ec pub p256", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x181, p256w), AT(0x10A, T));
    MK("ec pub p256 bare point", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x181, p256pt));
    MK("ec pub p256 off the curve", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x181, p256bad));
    MK("ec pub p384", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P384, sizeof P384), BL(0x181, p384w));
    MK("ec pub p384 point as p256", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x181, p384w));
    MK("ec pub secp256k1", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, K256, sizeof K256), BL(0x181, k1w));
    MK("ec pub p224", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P224, sizeof P224), BL(0x181, p256w));
    MK("ec pub garbage params", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, GARBAGE, sizeof GARBAGE), BL(0x181, p256w));
    MK("ec pub flags", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x181, p256w),
       AT(0x1, T), AT(0x170, Fb), AT(0x171, Fb), AT(0x104, Fb), AB(0x3, "ecp", 3), AB(0x102, "id", 2),
       AB(0x40000600, mechs, sizeof mechs), AB(0x40000211, wt, sizeof wt));
    MK("ec pub bad wrap template", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x181, p256w),
       AB(0x40000211, five, sizeof five));
    MK("ec pub after a destroyed one", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x181, p256w));
    /* EC private keys: the scalar, a zero one, curves, no curve */
    MK("ec priv p256", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x11, p256s), AT(0x108, T));
    MK("ec priv flags", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x11, p256s),
       AT(0x103, Fb), AT(0x162, T), AT(0x202, T), AT(0x10C, T), AB(0x40000213, wt, sizeof wt));
    MK("ec priv zero scalar", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x11, zero));
    MK("ec priv p256 scalar on p384", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, P384, sizeof P384), BL(0x11, p256s));
    MK("ec priv secp256k1", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, K256, sizeof K256), BL(0x11, p256s));
    MK("ec priv brainpool", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, BP256, sizeof BP256), BL(0x11, p256s));
    MK("ec priv sect163k1", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, SECT163, sizeof SECT163), BL(0x11, p256s));
    MK("ec priv no params", AT(0x0, c_priv), AT(0x100, k_ec), BL(0x11, p256s));
    MK("ec priv null params", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, NULL, 0), BL(0x11, p256s));
    /* Edwards and Montgomery */
    MK("ed25519 pub wrapped", AT(0x0, c_pub), AT(0x100, k_ed), AB(0x180, ED25519, sizeof ED25519), BL(0x181, edw));
    MK("ed25519 pub bare", AT(0x0, c_pub), AT(0x100, k_ed), AB(0x180, ED25519, sizeof ED25519), BL(0x181, edp));
    MK("ed25519 pub by name", AT(0x0, c_pub), AT(0x100, k_ed), AB(0x180, ED25519_NAME, 14), BL(0x181, edw));
    MK("ed25519 pub ed448 point", AT(0x0, c_pub), AT(0x100, k_ed), AB(0x180, ED25519, sizeof ED25519), BL(0x181, ed4w));
    MK("ed448 pub", AT(0x0, c_pub), AT(0x100, k_ed), AB(0x180, ED448, sizeof ED448), BL(0x181, ed4w));
    MK("ed25519 priv", AT(0x0, c_priv), AT(0x100, k_ed), AB(0x180, ED25519, sizeof ED25519), BL(0x11, edv), AT(0x108, T));
    MK("ed25519 priv by name", AT(0x0, c_priv), AT(0x100, k_ed), AB(0x180, ED25519_NAME, 14), BL(0x11, edv));
    MK("ed448 priv by name", AT(0x0, c_priv), AT(0x100, k_ed), AB(0x180, ED448_NAME, 12), BL(0x11, ed4v));
    MK("ed25519 priv ed448 params", AT(0x0, c_priv), AT(0x100, k_ed), AB(0x180, ED448, sizeof ED448), BL(0x11, edv));
    MK("ed25519 priv no params", AT(0x0, c_priv), AT(0x100, k_ed), BL(0x11, edv));
    MK("ed25519 priv p256 params", AT(0x0, c_priv), AT(0x100, k_ed), AB(0x180, P256, sizeof P256), BL(0x11, edv));
    MK("x25519 priv", AT(0x0, c_priv), AT(0x100, k_x), AB(0x180, X25519, sizeof X25519), BL(0x11, xv), AT(0x10C, T));
    MK("x25519 pub", AT(0x0, c_pub), AT(0x100, k_x), AB(0x180, X25519, sizeof X25519), BL(0x181, edw));
    /* RSA */
    MK("rsa pub", AT(0x0, c_pub), AT(0x100, k_rsa), BL(0x120, rn), BL(0x122, re), AT(0x10A, T));
    MK("rsa pub e 3", AT(0x0, c_pub), AT(0x100, k_rsa), BL(0x120, rn), AB(0x122, "\x03", 1));
    MK("rsa pub no exponent", AT(0x0, c_pub), AT(0x100, k_rsa), BL(0x120, rn));
    MK("rsa pub empty modulus", AT(0x0, c_pub), AT(0x100, k_rsa), AB(0x120, rn.p, 0), BL(0x122, re));
    MK("rsa priv full", AT(0x0, c_priv), AT(0x100, k_rsa), BL(0x120, rn), BL(0x122, re), BL(0x123, rd),
       BL(0x124, rp), BL(0x125, rq), BL(0x126, rdp), BL(0x127, rdq), BL(0x128, rqi), AT(0x108, T));
    MK("rsa priv n e d", AT(0x0, c_priv), AT(0x100, k_rsa), BL(0x120, rn), BL(0x122, re), BL(0x123, rd));
    MK("rsa priv another key's d", AT(0x0, c_priv), AT(0x100, k_rsa), BL(0x120, rn), BL(0x122, re), BL(0x123, rd2),
       BL(0x124, rp), BL(0x125, rq), BL(0x126, rdp), BL(0x127, rdq), BL(0x128, rqi));
    MK("rsa priv no d", AT(0x0, c_priv), AT(0x100, k_rsa), BL(0x120, rn), BL(0x122, re), BL(0x124, rp));
    MK("rsa priv extractable", AT(0x0, c_priv), AT(0x100, k_rsa), BL(0x120, rn), BL(0x122, re), BL(0x123, rd),
       BL(0x124, rp), BL(0x125, rq), BL(0x126, rdp), BL(0x127, rdq), BL(0x128, rqi),
       AT(0x162, T), AT(0x202, T), AT(0x103, Fb));
    /* PQC public keys: raw and SPKI, the parameter set agreeing or not */
    MK("mlkem512 pub raw", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, kem5p), AT(0x61D, s1));
    MK("mlkem512 pub raw as 768", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, kem5p), AT(0x61D, s2));
    MK("mlkem512 pub raw by name", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, kem5p), AB(0x61D, "ML-KEM-512", 10));
    MK("mlkem512 pub no set", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, kem5p));
    MK("mlkem512 pub encapsulate false", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, kem5p), AT(0x61D, s1), AT(0x633, Fb));
    MK("mlkem768 pub spki", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, kem7s), AT(0x61D, s2));
    MK("mlkem768 pub spki as 512", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, kem7s), AT(0x61D, s1));
    MK("mlkem pub truncated", AT(0x0, c_pub), AT(0x100, k_kem), AB(0x11, kem5p.p, 100), AT(0x61D, s1));
    MK("mldsa44 pub raw", AT(0x0, c_pub), AT(0x100, k_dsa), BL(0x11, dsap), AT(0x61D, s1), AT(0x10A, T));
    MK("mldsa44 pub raw as 65", AT(0x0, c_pub), AT(0x100, k_dsa), BL(0x11, dsap), AT(0x61D, s2));
    MK("mldsa pub kem key", AT(0x0, c_pub), AT(0x100, k_dsa), BL(0x11, kem5p), AT(0x61D, s1));
    MK("slhdsa sha2-128f pub", AT(0x0, c_pub), AT(0x100, k_slh), BL(0x11, slhp), AT(0x61D, s3));
    MK("slhdsa sha2-128f pub as shake", AT(0x0, c_pub), AT(0x100, k_slh), BL(0x11, slhp), AT(0x61D, s4));
    MK("slhdsa pub no set", AT(0x0, c_pub), AT(0x100, k_slh), BL(0x11, slhp));
    /* PQC private keys */
    MK("mlkem512 priv", AT(0x0, c_priv), AT(0x100, k_kem), BL(0x11, kem5v), AT(0x61D, s1), AT(0x634, Fb));
    MK("mlkem512 priv as 768", AT(0x0, c_priv), AT(0x100, k_kem), BL(0x11, kem5v), AT(0x61D, s2));
    MK("mlkem512 priv no set", AT(0x0, c_priv), AT(0x100, k_kem), BL(0x11, kem5v));
    MK("mlkem512 priv zeros", AT(0x0, c_priv), AT(0x100, k_kem), BL(0x11, zero), AT(0x61D, s1));
    MK("mlkem priv bad set", AT(0x0, c_priv), AT(0x100, k_kem), BL(0x11, kem5v), AT(0x61D, s4));
    MK("mldsa44 priv", AT(0x0, c_priv), AT(0x100, k_dsa), BL(0x11, dsav), AT(0x61D, s1), AT(0x108, T));
    MK("mldsa44 priv as 65", AT(0x0, c_priv), AT(0x100, k_dsa), BL(0x11, dsav), AT(0x61D, s2));
    MK("slhdsa sha2-128f priv", AT(0x0, c_priv), AT(0x100, k_slh), BL(0x11, slhv), AT(0x61D, s3));
    MK("slhdsa priv short", AT(0x0, c_priv), AT(0x100, k_slh), AB(0x11, slhv.p, 10), AT(0x61D, s3));
    /* the SO: trusted, and what it may create */
    P11(C_Logout, h);
    P11(C_Login, h, 0UL, SO_PIN, (UL)strlen(SO_PIN));
    MK("so ec pub trusted", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x181, p256w), AT(0x86, T));
    MK("so rsa pub trusted", AT(0x0, c_pub), AT(0x100, k_rsa), BL(0x120, rn), BL(0x122, re), AT(0x86, T), AT(0x1, T));
    MK("so ec priv", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x11, p256s));
    P11(C_Finalize, NULL);
}

/* 4 (slice 6c): C_WrapKey and C_UnwrapKey, over keys created here from fixed bytes, so every
 * AES-wrapped blob prints whole; an RSA or wrapped-private-key blob prints as its length. */
typedef struct { UL hash, mgf, src; void *data; UL len; } Oaep;
static unsigned char blob[8192];
static UL blob_n;

/* A key the scenario uses: its create row, no dump. */
static UL key(UL h, const char *name, Attr *t, UL n) {
    UL o = 0xAAAAAAAAUL, rv = P11(C_CreateObject, h, t, n, &o);
    char b[24];
    printf("%s\t%#lx\t%s\t-\n", name, rv, hv(o, b));
    return rv ? 0 : o;
}
#define KEY(var, name, ...) do { Attr t_[] = { __VA_ARGS__ }; var = key(h, name, t_, sizeof t_ / sizeof t_[0]); } while (0)

/* One wrap: cap 0 asks the size (NULL buffer), else a buffer of cap bytes. A success with a
 * buffer is kept in blob for the unwraps; rnd prints its length only. */
static void wr(UL h, const char *name, UL mech, void *p, UL pl, UL wk, UL k, UL cap, int rnd) {
    Mech m = { mech, p, pl };
    UL len = cap ? cap : 0xAAAAUL;
    memset(buf, 0xAA, sizeof buf);
    UL rv = P11(C_WrapKey, h, &m, wk, k, cap ? buf : NULL, &len);
    printf("%s\t%#lx\t%#lx\t", name, rv, len);
    if (!rv && cap && len <= sizeof blob) {
        memcpy(blob, buf, len);
        blob_n = len;
        if (rnd) printf("rnd:%lu", len); else hex(buf, len);
    } else printf("-");
    printf("\n");
}

/* One unwrap of b (bn bytes): the call, then the new key's attributes or the object count. */
static void uw(UL h, const char *name, UL mech, void *p, UL pl, UL uk, const unsigned char *b,
               UL bn, Attr *t, UL n) {
    Mech m = { mech, p, pl };
    UL frv, before = nobj(h, &frv), o = 0xAAAAAAAAUL;
    UL rv = P11(C_UnwrapKey, h, &m, uk, b, bn, t, n, &o);
    char hb[24];
    printf("%s\t%#lx\t%s\t-\n", name, rv, hv(o, hb));
    if (rv) stored(h, name, before);
    else dump(h, name, o, 0);
}
#define UW(name, mech, p, pl, uk, b, bn, ...) do { Attr t_[] = { __VA_ARGS__ }; uw(h, name, mech, p, pl, uk, b, bn, t_, sizeof t_ / sizeof t_[0]); } while (0)

static void s_wrap(void) {
    UL h = setup(), h_ro = 0;
    static UL c_sec = 4, c_priv = 3, c_data = 0, k_des3 = 0x15, k_ec = 3, len16 = 16, len32 = 32;
    static unsigned char v16[16], v24[24], v32[32], w16[16], w24[24], w32[32], v5[5] = "abcde";
    for (int i = 0; i < 32; ++i) {
        if (i < 16) v16[i] = (unsigned char)i, w16[i] = (unsigned char)(0xF0 + i);
        if (i < 24) v24[i] = (unsigned char)(0x20 + i), w24[i] = (unsigned char)(0xC0 + i);
        v32[i] = (unsigned char)(0x40 + i), w32[i] = (unsigned char)(0x80 + i);
    }
    UL kek16, kek24, kek32, nowrap, kwp_only, tmpl, gen, rsa_pub = 0, rsa_priv = 0, ec_pub = 0,
       ec_priv = 0, t16, t24, t32, t5, noext, locked, wwt, data, wtmpl, wtmpl_label;
    static UL kwp_mech[] = { 0x210B };
    static unsigned char sens_t = 1;
    static Attr unwrap_t[] = { { 0x103, &sens_t, 1 } };
    static Attr wrap_t[] = { { 0x100, &k_aes, sizeof k_aes } };
    static Attr wrap_lt[] = { { 0x3, "tgt", 3 } };
    KEY(kek16, "kek16", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, w16));
    KEY(kek24, "kek24", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, w24));
    KEY(kek32, "kek32", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, w32));
    KEY(nowrap, "kek no wrap", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, w16), AT(0x106, Fb), AT(0x107, Fb));
    KEY(kwp_only, "kek kwp only", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, w16),
        AB(0x40000600, kwp_mech, sizeof kwp_mech));
    KEY(tmpl, "kek unwrap template", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, w16),
        AB(0x40000212, unwrap_t, sizeof unwrap_t));
    KEY(gen, "generic kek", AT(0x0, c_sec), AT(0x100, k_gen), AT(0x11, w16));
    KEY(wtmpl, "kek wrap template aes", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, w16),
        AB(0x40000211, wrap_t, sizeof wrap_t));
    KEY(wtmpl_label, "kek wrap template label", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, w16),
        AB(0x40000211, wrap_lt, sizeof wrap_lt));
    KEY(t16, "target aes16", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, v16), AT(0x103, Fb), AT(0x162, T));
    KEY(t24, "target generic24", AT(0x0, c_sec), AT(0x100, k_gen), AT(0x11, v24), AT(0x103, Fb), AT(0x162, T));
    KEY(t32, "target aes32 sensitive", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, v32), AT(0x103, T), AT(0x162, T));
    KEY(t5, "target generic5", AT(0x0, c_sec), AT(0x100, k_gen), AT(0x11, v5), AT(0x103, Fb), AT(0x162, T));
    KEY(noext, "target not extractable", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, v16), AT(0x103, Fb), AT(0x162, Fb));
    KEY(locked, "target sensitive not extractable", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, v16), AT(0x103, T), AT(0x162, Fb));
    KEY(wwt, "target wrap with trusted", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, v16), AT(0x162, T), AT(0x210, T));
    KEY(data, "target data", AT(0x0, c_data), AB(0x11, v16, 16));
    {
        Mech ec = { 0x1040, NULL, 0 }, rsa = { 0x0, NULL, 0 };
        static UL bits = 2048;
        Attr pu[] = { AB(0x180, P256, sizeof P256) }, pr[] = { AT(0x162, T), AT(0x103, Fb) };
        Attr rp[] = { AT(0x121, bits) };
        printf("pair ec\t%#lx\n", P11(C_GenerateKeyPair, h, &ec, pu, 1UL, pr, 2UL, &ec_pub, &ec_priv));
        printf("pair rsa\t%#lx\n", P11(C_GenerateKeyPair, h, &rsa, rp, 1UL, NULL, 0UL, &rsa_pub, &rsa_priv));
    }
    static unsigned char iv8[8] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 }, iv0[8],
                         iv4[4] = { 0xA6, 0x59, 0x59, 0xA6 };
    static Oaep oaep = { 0x250, 2, 1, NULL, 0 };
    static unsigned char kw16[64], kw24[64], kwp5[64], oaep16[512], oaepl[512], bad[64];
    UL kw16_n = 0, kw24_n = 0, kwp5_n = 0, oaep16_n = 0, oaepl_n = 0;
    static Oaep oaep_l = { 0x250, 2, 1, "label", 5 }, oaep_l2 = { 0x250, 2, 1, "lab3l", 5 };

    /* wrap: sizes, buffers, IVs */
    wr(h, "kw aes16 size", 0x2109, NULL, 0, kek16, t16, 0, 0);
    wr(h, "kw aes16 small", 0x2109, NULL, 0, kek16, t16, 8, 0);
    wr(h, "kw aes16", 0x2109, NULL, 0, kek16, t16, 64, 0);
    memcpy(kw16, blob, kw16_n = blob_n);
    wr(h, "kw aes16 iv a6", 0x2109, iv8, 8, kek16, t16, 64, 0);
    wr(h, "kw aes16 iv 0", 0x2109, iv0, 8, kek16, t16, 64, 0);
    wr(h, "kw aes16 iv 4", 0x2109, iv4, 4, kek16, t16, 64, 0);
    wr(h, "kw aes16 iv null 8", 0x2109, NULL, 8, kek16, t16, 64, 0);
    wr(h, "kw by kek24", 0x2109, NULL, 0, kek24, t16, 64, 0);
    wr(h, "kw by kek32", 0x2109, NULL, 0, kek32, t16, 64, 0);
    wr(h, "kw aes32 sensitive", 0x2109, NULL, 0, kek16, t32, 64, 0);
    wr(h, "kw generic24", 0x2109, NULL, 0, kek16, t24, 64, 0);
    memcpy(kw24, blob, kw24_n = blob_n);
    wr(h, "kw by wrap template aes, aes target", 0x2109, NULL, 0, wtmpl, t16, 64, 0);
    wr(h, "kw by wrap template aes, generic target", 0x2109, NULL, 0, wtmpl, t24, 64, 0);
    wr(h, "kw by wrap template label, unlabelled", 0x2109, NULL, 0, wtmpl_label, t16, 64, 0);
    wr(h, "kw generic5", 0x2109, NULL, 0, kek16, t5, 64, 0);
    wr(h, "kwp generic5 size", 0x210B, NULL, 0, kek16, t5, 0, 0);
    wr(h, "kwp generic5", 0x210B, NULL, 0, kek16, t5, 64, 0);
    memcpy(kwp5, blob, kwp5_n = blob_n);
    wr(h, "kwp aes16", 0x210B, NULL, 0, kek16, t16, 64, 0);
    wr(h, "kwp iv 4", 0x210B, iv4, 4, kek16, t16, 64, 0);
    wr(h, "kwp iv 8", 0x210B, iv8, 8, kek16, t16, 64, 0);
    /* wrap: which keys, which wrapping keys */
    wr(h, "kw not extractable", 0x2109, NULL, 0, kek16, noext, 64, 0);
    wr(h, "kw sensitive not extractable", 0x2109, NULL, 0, kek16, locked, 64, 0);
    wr(h, "kw wrap with trusted, untrusted kek", 0x2109, NULL, 0, kek16, wwt, 64, 0);
    wr(h, "kw by kek no wrap", 0x2109, NULL, 0, nowrap, t16, 64, 0);
    wr(h, "kw by kek kwp only", 0x2109, NULL, 0, kwp_only, t16, 64, 0);
    wr(h, "kwp by kek kwp only", 0x210B, NULL, 0, kwp_only, t16, 64, 0);
    wr(h, "kw by generic kek", 0x2109, NULL, 0, gen, t16, 64, 0);
    wr(h, "kw by rsa pub", 0x2109, NULL, 0, rsa_pub, t16, 64, 0);
    wr(h, "kwp data object", 0x210B, NULL, 0, kek16, data, 64, 0);
    wr(h, "kwp ec pub", 0x210B, NULL, 0, kek16, ec_pub, 512, 1);
    wr(h, "kwp ec priv extractable", 0x210B, NULL, 0, kek16, ec_priv, 512, 1);
    wr(h, "kwp rsa priv", 0x210B, NULL, 0, kek16, rsa_priv, 4096, 1);
    wr(h, "kw unknown key", 0x2109, NULL, 0, kek16, 999UL, 64, 0);
    wr(h, "kw unknown kek", 0x2109, NULL, 0, 999UL, t16, 64, 0);
    wr(h, "aes ecb", 0x1081, NULL, 0, kek16, t16, 64, 0);
    /* wrap: RSA */
    wr(h, "oaep size", 0x9, &oaep, sizeof oaep, rsa_pub, t16, 0, 1);
    wr(h, "oaep small", 0x9, &oaep, sizeof oaep, rsa_pub, t16, 16, 1);
    wr(h, "oaep", 0x9, &oaep, sizeof oaep, rsa_pub, t16, 512, 1);
    memcpy(oaep16, blob, oaep16_n = blob_n);
    wr(h, "oaep label", 0x9, &oaep_l, sizeof oaep_l, rsa_pub, t16, 512, 1);
    memcpy(oaepl, blob, oaepl_n = blob_n);
    wr(h, "oaep no params", 0x9, NULL, 0, rsa_pub, t16, 512, 1);
    wr(h, "oaep by aes", 0x9, &oaep, sizeof oaep, kek16, t16, 512, 1);
    wr(h, "oaep by rsa priv", 0x9, &oaep, sizeof oaep, rsa_priv, t16, 512, 1);
    wr(h, "rsa pkcs", 0x1, NULL, 0, rsa_pub, t16, 512, 1);
    wr(h, "rsa x509", 0x3, NULL, 0, rsa_pub, t16, 512, 1);
    /* wrap: arguments */
    {
        Mech m = { 0x2109, NULL, 0 };
        UL len = 64;
        printf("wrap null mech\t%#lx\n", P11(C_WrapKey, h, NULL, kek16, t16, buf, &len));
        printf("wrap null len\t%#lx\n", P11(C_WrapKey, h, &m, kek16, t16, buf, NULL));
        printf("wrap bad session\t%#lx\n", P11(C_WrapKey, 99UL, &m, kek16, t16, buf, &len));
    }

    /* unwrap: the template */
    UW("uw aes16", 0x2109, NULL, 0, kek16, kw16, kw16_n, AT(0x0, c_sec), AT(0x100, k_aes),
       AT(0x103, Fb), AT(0x162, T), AB(0x3, "unwrapped", 9));
    uw(h, "uw no template", 0x2109, NULL, 0, kek16, kw16, kw16_n, NULL, 0);
    UW("uw generic", 0x2109, NULL, 0, kek16, kw16, kw16_n, AT(0x100, k_gen), AT(0x103, Fb));
    UW("uw ec type", 0x2109, NULL, 0, kek16, kw16, kw16_n, AT(0x100, k_ec), AT(0x103, Fb));
    UW("uw class private", 0x2109, NULL, 0, kek16, kw16, kw16_n, AT(0x0, c_priv), AT(0x100, k_aes));
    UW("uw value_len 16", 0x2109, NULL, 0, kek16, kw16, kw16_n, AT(0x161, len16));
    UW("uw value_len 32", 0x2109, NULL, 0, kek16, kw16, kw16_n, AT(0x161, len32));
    UW("uw des3 of 16", 0x2109, NULL, 0, kek16, kw16, kw16_n, AT(0x100, k_des3));
    UW("uw des3 of 24", 0x2109, NULL, 0, kek16, kw24, kw24_n, AT(0x100, k_des3), AT(0x103, Fb));
    UW("uw kwp generic5 as aes", 0x210B, NULL, 0, kek16, kwp5, kwp5_n, AT(0x100, k_aes));
    UW("uw kwp generic5", 0x210B, NULL, 0, kek16, kwp5, kwp5_n, AT(0x100, k_gen), AT(0x103, Fb));
    UW("uw token", 0x2109, NULL, 0, kek16, kw16, kw16_n, AT(0x1, T), AT(0x103, Fb));
    UW("uw label 70", 0x2109, NULL, 0, kek16, kw16, kw16_n,
       AB(0x3, "0123456789012345678901234567890123456789012345678901234567890123456789", 70));
    UW("uw allowed mechs", 0x2109, NULL, 0, kek16, kw16, kw16_n, AB(0x40000600, kwp_mech, sizeof kwp_mech));
    UW("uw usage", 0x2109, NULL, 0, kek16, kw16, kw16_n, AT(0x104, Fb), AT(0x10C, T));
    UW("uw trusted", 0x2109, NULL, 0, kek16, kw16, kw16_n, AT(0x86, T));
    UW("uw bool len 2", 0x2109, NULL, 0, kek16, kw16, kw16_n, AB(0x103, "\x01\x01", 2));
    /* unwrap: the blob and the unwrapping key */
    memcpy(bad, kw16, kw16_n);
    bad[3] ^= 1;
    UW("uw corrupted", 0x2109, NULL, 0, kek16, bad, kw16_n, AT(0x103, Fb));
    UW("uw by kek24", 0x2109, NULL, 0, kek24, kw16, kw16_n, AT(0x103, Fb));
    UW("uw iv 0", 0x2109, iv0, 8, kek16, kw16, kw16_n, AT(0x103, Fb));
    UW("uw len 16", 0x2109, NULL, 0, kek16, kw16, 16, AT(0x103, Fb));
    UW("uw len 23", 0x2109, NULL, 0, kek16, kw16, 23, AT(0x103, Fb));
    UW("uw len 4112", 0x2109, NULL, 0, kek16, buf, 4112, AT(0x103, Fb));
    UW("uw kwp len 8", 0x210B, NULL, 0, kek16, kwp5, 8, AT(0x103, Fb));
    UW("uw by kek no wrap", 0x2109, NULL, 0, nowrap, kw16, kw16_n, AT(0x103, Fb));
    UW("uw by kek kwp only", 0x2109, NULL, 0, kwp_only, kw16, kw16_n, AT(0x103, Fb));
    UW("uw template sensitive", 0x2109, NULL, 0, tmpl, kw16, kw16_n, AT(0x103, T));
    UW("uw template not sensitive", 0x2109, NULL, 0, tmpl, kw16, kw16_n, AT(0x103, Fb));
    UW("uw template none", 0x2109, NULL, 0, tmpl, kw16, kw16_n, AT(0x100, k_aes));
    UW("uw by generic kek", 0x2109, NULL, 0, gen, kw16, kw16_n, AT(0x103, Fb));
    UW("uw unknown kek", 0x2109, NULL, 0, 999UL, kw16, kw16_n, AT(0x103, Fb));
    UW("uw aes ecb", 0x1081, NULL, 0, kek16, kw16, kw16_n, AT(0x103, Fb));
    UW("uw oaep", 0x9, &oaep, sizeof oaep, rsa_priv, oaep16, oaep16_n, AT(0x103, Fb), AT(0x100, k_aes));
    UW("uw oaep by rsa pub", 0x9, &oaep, sizeof oaep, rsa_pub, oaep16, oaep16_n, AT(0x103, Fb));
    UW("uw oaep corrupted", 0x9, &oaep, sizeof oaep, rsa_priv, kw16, kw16_n, AT(0x103, Fb));
    UW("uw rsa pkcs", 0x1, NULL, 0, rsa_priv, oaep16, oaep16_n, AT(0x103, Fb));
    UW("uw oaep label", 0x9, &oaep_l, sizeof oaep_l, rsa_priv, oaepl, oaepl_n, AT(0x103, Fb));
    UW("uw oaep other label", 0x9, &oaep_l2, sizeof oaep_l2, rsa_priv, oaepl, oaepl_n, AT(0x103, Fb));
    /* unwrap: arguments and sessions */
    {
        Mech m = { 0x2109, NULL, 0 };
        UL o = 0xAAAAAAAAUL, len = 64;
        Attr t[] = { AT(0x103, Fb) }, tt[] = { AT(0x1, T) };
        printf("unwrap null mech\t%#lx\n", P11(C_UnwrapKey, h, NULL, kek16, kw16, kw16_n, t, 1UL, &o));
        printf("unwrap null blob\t%#lx\n", P11(C_UnwrapKey, h, &m, kek16, NULL, kw16_n, t, 1UL, &o));
        printf("unwrap null out\t%#lx\n", P11(C_UnwrapKey, h, &m, kek16, kw16, kw16_n, t, 1UL, NULL));
        printf("unwrap bad session\t%#lx\n", P11(C_UnwrapKey, 99UL, &m, kek16, kw16, kw16_n, t, 1UL, &o));
        printf("ro session\t%#lx\n", P11(C_OpenSession, 0UL, 4UL, NULL, NULL, &h_ro));
        printf("unwrap ro token\t%#lx\n", P11(C_UnwrapKey, h_ro, &m, kek16, kw16, kw16_n, tt, 1UL, &o));
        printf("unwrap ro session object\t%#lx\n", P11(C_UnwrapKey, h_ro, &m, kek16, kw16, kw16_n, t, 1UL, &o));
        printf("logout\t%#lx\n", P11(C_Logout, h));
        printf("wrap logged out\t%#lx\n", P11(C_WrapKey, h, &m, kek16, t16, buf, &len));
        printf("unwrap logged out\t%#lx\n", P11(C_UnwrapKey, h, &m, kek16, kw16, kw16_n, t, 1UL, &o));
        /* The SO and the user's session keys; then a key only the SO may mark trusted. */
        UL tk = 0xAAAAAAAAUL, olen = 64;
        printf("ro session closed\t%#lx\n", P11(C_CloseSession, h_ro));
        printf("so login\t%#lx\n", P11(C_Login, h, 0UL, SO_PIN, (UL)strlen(SO_PIN)));
        printf("so wrap user key\t%#lx\n", P11(C_WrapKey, h, &m, kek16, t16, buf, &olen));
        printf("so unwrap with user key\t%#lx\n", P11(C_UnwrapKey, h, &m, kek16, kw16, kw16_n, t, 1UL, &o));
        Attr tr[] = { AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, w24), AT(0x86, T) };
        printf("so trusted kek\t%#lx\n", P11(C_CreateObject, h, tr, 4UL, &tk));
        printf("so logout\t%#lx\n", P11(C_Logout, h));
        printf("user login\t%#lx\n", P11(C_Login, h, 1UL, USER_PIN, (UL)strlen(USER_PIN)));
        wr(h, "kw wrap with trusted, trusted kek", 0x2109, NULL, 0, tk, wwt, 64, 0);
    }
    P11(C_Finalize, NULL);
}
/* 5 (slice 6d): C_DeriveKey, over keys made from fixed bytes and EC points computed here from
 * fixed scalars, so every derived value prints whole. A derived key that must stay secret on
 * one side is also wrapped under a fixed key, so its value shows as the blob. */
typedef struct { unsigned char ex, ep; UL prf, st; void *salt; UL sl; UL sk; void *info; UL il; } Hkdf;
typedef struct { UL kdf, sl; void *sd; UL pl; void *pd; } Ecdh;
typedef struct { void *p; UL len; } Str;
static UL derived;

/* One derive: the call, then the new object's attributes or the object count. */
static void dv(UL h, const char *name, UL mech, void *p, UL pl, UL base, Attr *t, UL n, int rnd) {
    Mech m = { mech, p, pl };
    UL frv, before = nobj(h, &frv), o = 0xAAAAAAAAUL;
    UL rv = P11(C_DeriveKey, h, &m, base, t, n, &o);
    char hb[24];
    printf("%s\t%#lx\t%s\t-\n", name, rv, hv(o, hb));
    derived = rv ? 0 : o;
    if (rv) stored(h, name, before);
    else dump(h, name, o, rnd);
}
#define DV(name, mech, p, pl, base, ...) do { Attr t_[] = { __VA_ARGS__ }; \
    dv(h, name, mech, p, pl, base, t_, sizeof t_ / sizeof t_[0], 0); } while (0)
#define DV0(name, mech, p, pl, base) dv(h, name, mech, p, pl, base, NULL, 0UL, 0)

/* d·G on the curve nid: the point (uncompressed, and compressed), the scalar padded to fb
 * bytes, and the point as an SPKI. */
typedef struct { Blob pt, cpt, d, spki; } Ec;
static void ec(int nid, const char *group, unsigned long d, size_t fb, Ec *e) {
    EC_GROUP *g = EC_GROUP_new_by_curve_name(nid);
    EC_POINT *q = g ? EC_POINT_new(g) : NULL;
    BIGNUM *x = BN_new();
    if (!q || !x || !BN_set_word(x, d) || !EC_POINT_mul(g, q, x, NULL, NULL, NULL)) {
        fprintf(stderr, "ec %s failed\n", group);
        exit(2);
    }
    e->pt.n = EC_POINT_point2oct(g, q, POINT_CONVERSION_UNCOMPRESSED, e->pt.p, sizeof e->pt.p, NULL);
    e->cpt.n = EC_POINT_point2oct(g, q, POINT_CONVERSION_COMPRESSED, e->cpt.p, sizeof e->cpt.p, NULL);
    e->d.n = (size_t)BN_bn2binpad(x, e->d.p, (int)fb);
    OSSL_PARAM pp[] = {
        OSSL_PARAM_construct_utf8_string("group", (char *)group, 0),
        OSSL_PARAM_construct_octet_string("pub", e->pt.p, e->pt.n), OSSL_PARAM_construct_end(),
    };
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *k = NULL;
    if (!c || EVP_PKEY_fromdata_init(c) != 1 || EVP_PKEY_fromdata(c, &k, EVP_PKEY_PUBLIC_KEY, pp) != 1) {
        fprintf(stderr, "ec %s spki failed\n", group);
        exit(2);
    }
    spki(k, &e->spki);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(c);
    BN_free(x);
    EC_POINT_free(q);
    EC_GROUP_free(g);
}

static void s_derive(void) {
    UL h = setup(), h_ro = 0;
    static UL c_sec = 4, c_priv = 3, c_pub = 2, c_data = 0, k_ec = 3, k_ed = 0x40, k_x = 0x41,
              len16 = 16, len42 = 42, len0 = 0, len5 = 5, len8160 = 8160, len8161 = 8161,
              wide = 0x10000001FUL, sha256 = 0x250, hkdf_only[] = { 0x402A };
    static unsigned char v32[32], w16[16], s16[16] = "salt-of-sixteen!", info8[8] = "info-123",
                         abcde[5] = "abcde", d40[40], big[4096], x32[32], lab70[70], idb[3] = "id1";
    static unsigned char date[8] = "20260101";
    for (int i = 0; i < 40; ++i) {
        if (i < 32) v32[i] = (unsigned char)(0x40 + i), x32[i] = (unsigned char)(0x11 * (i % 15) + 1);
        if (i < 16) w16[i] = (unsigned char)(0xF0 + i);
        d40[i] = (unsigned char)(0xA0 + i);
    }
    memset(lab70, 'L', sizeof lab70);
    static Ec a256, b256, b384, a521, b521;
    ec(NID_X9_62_prime256v1, "P-256", 0x1234567UL, 32, &a256);
    ec(NID_X9_62_prime256v1, "P-256", 7UL, 32, &b256);
    ec(NID_secp384r1, "P-384", 7UL, 48, &b384);
    ec(NID_secp521r1, "P-521", 0x7654321UL, 66, &a521);
    ec(NID_secp521r1, "P-521", 7UL, 66, &b521);
    static Blob b256w, b521w, offc;
    wrap(&b256.pt, &b256w);
    b521w.p[0] = 0x04, b521w.p[1] = 0x81, b521w.p[2] = (unsigned char)b521.pt.n;
    memcpy(b521w.p + 3, b521.pt.p, b521.pt.n);
    b521w.n = b521.pt.n + 3;
    offc = b256.pt;
    offc.p[offc.n - 1] ^= 1;

    UL base, sbase, aes, noderive, hkonly, dtm, saltk, saltnd, data, second, kek, ep256, ep521,
       epnd, ecpub, edpriv, xpriv;
    static Attr dt_aes[] = { { 0x100, &k_aes, sizeof k_aes } };
    KEY(base, "base", AT(0x0, c_sec), AT(0x100, k_gen), AT(0x11, v32), AT(0x103, Fb), AT(0x162, T), AT(0x10C, T));
    KEY(sbase, "base sensitive", AT(0x0, c_sec), AT(0x100, k_gen), AT(0x11, v32), AT(0x103, T), AT(0x10C, T));
    KEY(aes, "base aes", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, w16), AT(0x103, Fb), AT(0x10C, T));
    KEY(noderive, "base no derive", AT(0x0, c_sec), AT(0x100, k_gen), AT(0x11, v32), AT(0x10C, Fb));
    KEY(hkonly, "base hkdf only", AT(0x0, c_sec), AT(0x100, k_gen), AT(0x11, v32), AT(0x10C, T),
        AB(0x40000600, hkdf_only, sizeof hkdf_only));
    KEY(dtm, "base derive template aes", AT(0x0, c_sec), AT(0x100, k_gen), AT(0x11, v32), AT(0x10C, T),
        AB(0x40000213, dt_aes, sizeof dt_aes));
    KEY(saltk, "salt key", AT(0x0, c_sec), AT(0x100, k_gen), AT(0x11, w16), AT(0x10C, T));
    KEY(saltnd, "salt key no derive", AT(0x0, c_sec), AT(0x100, k_gen), AT(0x11, w16), AT(0x10C, Fb));
    KEY(data, "data object", AT(0x0, c_data), AT(0x11, abcde));
    KEY(second, "second key", AT(0x0, c_sec), AT(0x100, k_gen), AT(0x11, w16), AT(0x10C, T));
    KEY(kek, "kek", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, w16));
    KEY(ep256, "ec p256 priv", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x11, a256.d), AT(0x10C, T));
    KEY(ep521, "ec p521 priv", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, P521, sizeof P521), BL(0x11, a521.d), AT(0x10C, T));
    KEY(epnd, "ec p256 priv no derive", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x11, a256.d), AT(0x10C, Fb));
    KEY(ecpub, "ec p256 pub", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x181, b256w), AT(0x10C, T));
    KEY(edpriv, "ed25519 priv", AT(0x0, c_priv), AT(0x100, k_ed), AB(0x180, ED25519, sizeof ED25519), AT(0x11, x32), AT(0x10C, T));
    KEY(xpriv, "x25519 priv", AT(0x0, c_priv), AT(0x100, k_x), AB(0x180, X25519, sizeof X25519), AT(0x11, x32), AT(0x10C, T));

    /* The checks before any mechanism's, in C's order. */
    {
        Mech m = { 0x402A, NULL, 0 };
        UL o = 0xAAAAAAAAUL;
        Attr tb[] = { { 0x103, &T, 4 } }, tu[] = { { 0x161, &len16, 1 } }, tt[] = { AT(0x86, T) },
             tk[] = { AT(0x1, T) };
        printf("derive null mech\t%#lx\n", P11(C_DeriveKey, h, NULL, base, NULL, 0UL, &o));
        printf("derive null out\t%#lx\n", P11(C_DeriveKey, h, &m, base, NULL, 0UL, NULL));
        printf("derive null template\t%#lx\n", P11(C_DeriveKey, h, &m, base, NULL, 1UL, &o));
        printf("derive trusted\t%#lx\n", P11(C_DeriveKey, h, &m, base, tt, 1UL, &o));
        printf("derive bool len\t%#lx\n", P11(C_DeriveKey, h, &m, base, tb, 1UL, &o));
        printf("derive ulong len\t%#lx\n", P11(C_DeriveKey, h, &m, base, tu, 1UL, &o));
        printf("derive bad session\t%#lx\n", P11(C_DeriveKey, 99UL, &m, base, NULL, 0UL, &o));
        printf("ro session\t%#lx\n", P11(C_OpenSession, 0UL, 4UL, NULL, NULL, &h_ro));
        printf("derive ro token\t%#lx\n", P11(C_DeriveKey, h_ro, &m, base, tk, 1UL, &o));
        printf("ro session closed\t%#lx\n", P11(C_CloseSession, h_ro));
    }

    /* HKDF: the parameter block, the salt, the info, the length, then the store. */
    Hkdf hk = { 1, 1, sha256, 1, NULL, 0, 0, NULL, 0 }, hp;
#define HK(name, mech, base, ...) do { Attr t_[] = { __VA_ARGS__ }; dv(h, name, mech, &hp, sizeof hp, base, t_, sizeof t_ / sizeof t_[0], 0); } while (0)
#define HK0(name, mech, base) dv(h, name, mech, &hp, sizeof hp, base, NULL, 0UL, 0)
    DV0("hkdf null param", 0x402A, NULL, 0, base);
    hp = hk; DV0("hkdf short param", 0x402A, &hp, sizeof hp - 1, base);
    hp = hk; hp.ex = hp.ep = 0; HK0("hkdf neither", 0x402A, base);
    hp = hk; hp.prf = 0x1234; HK0("hkdf bad prf", 0x402A, base);
    hp = hk; hp.prf = 0x220; HK0("hkdf sha1", 0x402A, base);
    hp = hk; hp.prf = 0x255; HK0("hkdf sha224", 0x402A, base);
    hp = hk; hp.prf = 0x270; HK0("hkdf sha512", 0x402A, base);
    hp = hk; hp.prf = 0x2B0; HK0("hkdf sha3-256", 0x402A, base);
    hp = hk; HK0("hkdf base data object", 0x402A, data);
    hp = hk; HK0("hkdf base aes", 0x402A, aes);
    hp = hk; HK0("hkdf base no derive", 0x402A, noderive);
    hp = hk; HK0("hkdf base bad handle", 0x402A, 0x7777UL);
    hp = hk; HK0("hkdf base hkdf only", 0x402A, hkonly);
    hp = hk; HK0("hkdf base derive template, none given", 0x402A, dtm);
    hp = hk; HK("hkdf base derive template, matched", 0x402A, dtm, AT(0x100, k_aes), AT(0x161, len16));
    hp = hk; HK0("hkdf salt null", 0x402A, base);
    hp = hk; hp.st = 2; hp.salt = s16; hp.sl = 16; hp.info = info8; hp.il = 8;
    HK("hkdf salt data, info, 42 bytes", 0x402A, base, AT(0x161, len42));
    hp = hk; hp.st = 2; hp.sl = 4; HK0("hkdf salt data null", 0x402A, base);
    hp = hk; hp.st = 2; hp.salt = s16; hp.sl = 0x80000000UL; HK0("hkdf salt data huge", 0x402A, base);
    hp = hk; hp.st = 2; HK0("hkdf salt data empty", 0x402A, base);
    hp = hk; hp.st = 4; hp.sk = saltk; HK0("hkdf salt key", 0x402A, base);
    hp = hk; hp.st = 4; hp.sk = data; HK0("hkdf salt key data object", 0x402A, base);
    hp = hk; hp.st = 4; hp.sk = saltnd; HK0("hkdf salt key no derive", 0x402A, base);
    hp = hk; hp.st = 4; hp.sk = 0x7777UL; HK0("hkdf salt key bad handle", 0x402A, base);
    hp = hk; hp.st = 3; HK0("hkdf salt type 3", 0x402A, base);
    hp = hk; hp.st = 0; HK0("hkdf salt type 0", 0x402A, base);
    hp = hk; hp.il = 4; HK0("hkdf info null", 0x402A, base);
    hp = hk; hp.info = info8; hp.il = 0x80000000UL; HK0("hkdf info huge", 0x402A, base);
    hp = hk; hp.ep = 0; HK("hkdf extract only, length ignored", 0x402A, base, AT(0x161, len16));
    hp = hk; hp.ex = 0; hp.info = info8; hp.il = 8; HK("hkdf expand only", 0x402A, base, AT(0x161, len16));
    hp = hk; HK("hkdf value_len short", 0x402A, base, { 0x161, &len16, 4 });
    hp = hk; HK("hkdf value_len 0", 0x402A, base, AT(0x161, len0));
    hp = hk; { Attr t[] = { AT(0x161, len8160) }; dv(h, "hkdf value_len 8160", 0x402A, &hp, sizeof hp, base, t, 1UL, 1); }
    hp = hk; HK("hkdf value_len 8161", 0x402A, base, AT(0x161, len8161));
    hp = hk; hp.ep = 0; HK("hkdf extract only, value_len 0", 0x402A, base, AT(0x161, len0));
    hp = hk; HK0("hkdf data", 0x402B, base);
    hp = hk; HK("hkdf data as secret", 0x402B, base, AT(0x0, c_sec));
    hp = hk; HK("hkdf class data", 0x402A, base, AT(0x0, c_data));
    hp = hk; HK("hkdf class private", 0x402A, base, AT(0x0, c_priv));
    hp = hk; HK("hkdf class short", 0x402A, base, { 0x0, &c_data, 4 });
    hp = hk; HK("hkdf label 70", 0x402A, base, AB(0x3, lab70, sizeof lab70));
    hp = hk; HK("hkdf sensitive", 0x402A, base, AT(0x103, T), AT(0x162, Fb));
    hp = hk; HK("hkdf extractable", 0x402A, base, AT(0x103, Fb), AT(0x162, T));
    hp = hk; HK("hkdf key type aes", 0x402A, base, AT(0x100, k_aes), AT(0x161, len16));
    hp = hk; HK("hkdf key type aes 5", 0x402A, base, AT(0x100, k_aes), AT(0x161, len5));
    hp = hk; HK("hkdf key type ec", 0x402A, base, AT(0x100, k_ec));
    hp = hk; HK("hkdf key type wide", 0x402A, base, AT(0x100, wide));
    hp = hk; HK("hkdf key type short", 0x402A, base, { 0x100, &k_aes, 4 });
    hp = hk; HK("hkdf value given", 0x402A, base, AT(0x11, w16));
    hp = hk; HK("hkdf token", 0x402A, base, AT(0x1, T));
    hp = hk; HK("hkdf policy", 0x402A, base, AB(0x40000600, hkdf_only, sizeof hkdf_only),
                AB(0x40000213, dt_aes, sizeof dt_aes), AB(0x102, idb, sizeof idb), AT(0x110, date),
                AT(0x10C, Fb), AT(0x104, T));
    hp = hk; HK0("hkdf from sensitive base", 0x402A, sbase);
    hp = hk; HK("hkdf from sensitive base, sensitive false", 0x402A, sbase, AT(0x103, Fb));
    hp = hk; HK("hkdf from sensitive base, extractable", 0x402A, sbase, AT(0x162, T));
    if (derived) wr(h, "hkdf from sensitive base, wrapped", 0x2109, NULL, 0, kek, derived, 64, 0);
    hp = hk; HK0("hkdf data from sensitive base", 0x402B, sbase);
    hp = hk; HK("hkdf class data from sensitive base", 0x402A, sbase, AT(0x0, c_data));

    /* The concatenation family. */
    Str sd;
    UL kh;
#define CC(name, mech, base, ...) do { Attr t_[] = { __VA_ARGS__ }; dv(h, name, mech, &sd, sizeof sd, base, t_, sizeof t_ / sizeof t_[0], 0); } while (0)
#define CC0(name, mech, base) dv(h, name, mech, &sd, sizeof sd, base, NULL, 0UL, 0)
    kh = second; DV0("concat key", 0x360, &kh, sizeof kh, base);
    kh = second; DV0("concat key short param", 0x360, &kh, sizeof kh - 1, base);
    DV0("concat key null param", 0x360, NULL, 0, base);
    kh = data; DV0("concat key second data object", 0x360, &kh, sizeof kh, base);
    kh = saltnd; DV0("concat key second no derive", 0x360, &kh, sizeof kh, base);
    kh = 0x7777UL; DV0("concat key second bad handle", 0x360, &kh, sizeof kh, base);
    kh = sbase; DV0("concat key second sensitive", 0x360, &kh, sizeof kh, base);
    sd = (Str){ abcde, 5 }; CC0("concat data", 0x362, base);
    sd = (Str){ NULL, 0 }; CC0("concat data empty", 0x362, base);
    sd = (Str){ NULL, 5 }; CC0("concat data null", 0x362, base);
    sd = (Str){ abcde, 0x80000000UL }; CC0("concat data huge", 0x362, base);
    sd = (Str){ abcde, 5 }; DV0("concat data short param", 0x362, &sd, sizeof sd - 1, base);
    sd = (Str){ big, 4064 }; CC0("concat data to 4096", 0x362, base);
    sd = (Str){ big, 4065 }; CC0("concat data past 4096", 0x362, base);
    sd = (Str){ abcde, 5 }; CC0("data and base", 0x363, base);
    sd = (Str){ abcde, 5 }; CC0("xor short data", 0x364, base);
    sd = (Str){ d40, 40 }; CC0("xor long data", 0x364, base);
    sd = (Str){ NULL, 0 }; CC0("xor empty", 0x364, base);
    sd = (Str){ abcde, 5 }; CC0("concat aes base", 0x362, aes);
    sd = (Str){ abcde, 5 }; CC0("concat data object base", 0x362, data);
    sd = (Str){ abcde, 5 }; CC0("concat base hkdf only", 0x362, hkonly);
    sd = (Str){ abcde, 5 }; CC("concat key type aes", 0x362, base, AT(0x100, k_aes));
    sd = (Str){ abcde, 5 }; CC("concat value_len", 0x362, base, AT(0x161, len16));
    sd = (Str){ abcde, 5 }; CC0("concat from sensitive base", 0x362, sbase);
    sd = (Str){ abcde, 5 }; CC("concat class data", 0x362, base, AT(0x0, c_data));
    sd = (Str){ abcde, 5 }; CC("concat class data from sensitive base", 0x362, sbase, AT(0x0, c_data));

    /* ECDH: the mechanism, the parameter block, the base, each form of the peer's point. */
    Ecdh ep;
#define EP(pd_, pl_) (ep = (Ecdh){ 1, 0, NULL, (UL)(pl_), (void *)(pd_) }, &ep)
#define ED(name, mech, base, pd_, pl_, ...) do { Attr t_[] = { __VA_ARGS__ }; dv(h, name, mech, EP(pd_, pl_), sizeof ep, base, t_, sizeof t_ / sizeof t_[0], 0); } while (0)
#define ED0(name, mech, base, pd_, pl_) dv(h, name, mech, EP(pd_, pl_), sizeof ep, base, NULL, 0UL, 0)
    ED0("derive mech invalid", 0x1234, ep256, b256.pt.p, b256.pt.n);
    DV0("ecdh null param", 0x1050, NULL, 0, ep256);
    DV0("ecdh short param", 0x1050, EP(b256.pt.p, b256.pt.n), sizeof ep - 1, ep256);
    ep = (Ecdh){ 2, 0, NULL, (UL)b256.pt.n, b256.pt.p };
    DV0("ecdh kdf sha1", 0x1050, &ep, sizeof ep, ep256);
    ED0("ecdh no public data", 0x1050, ep256, NULL, 65);
    ED0("ecdh public data empty", 0x1050, ep256, b256.pt.p, 0);
    ED0("ecdh secret base", 0x1050, base, b256.pt.p, b256.pt.n);
    ED0("ecdh public base", 0x1050, ecpub, b256.pt.p, b256.pt.n);
    ED0("ecdh ed25519 base", 0x1050, edpriv, b256.pt.p, b256.pt.n);
    ED0("ecdh x25519 base", 0x1050, xpriv, x32, 32);
    ED0("ecdh base no derive", 0x1050, epnd, b256.pt.p, b256.pt.n);
    ED0("ecdh bare point", 0x1050, ep256, b256.pt.p, b256.pt.n);
    ED0("ecdh compressed point", 0x1050, ep256, b256.cpt.p, b256.cpt.n);
    ED0("ecdh octet string", 0x1050, ep256, b256w.p, b256w.n);
    ED0("ecdh spki", 0x1050, ep256, b256.spki.p, b256.spki.n);
    ED0("ecdh cofactor", 0x1051, ep256, b256.pt.p, b256.pt.n);
    ED0("ecdh off curve", 0x1050, ep256, offc.p, offc.n);
    ED0("ecdh garbage", 0x1050, ep256, GARBAGE, sizeof GARBAGE);
    ED0("ecdh p384 point on p256", 0x1050, ep256, b384.pt.p, b384.pt.n);
    ED0("ecdh p384 spki on p256", 0x1050, ep256, b384.spki.p, b384.spki.n);
    ED0("ecdh p521 bare", 0x1050, ep521, b521.pt.p, b521.pt.n);
    ED0("ecdh p521 octet string", 0x1050, ep521, b521w.p, b521w.n);
    ED("ecdh sensitive false", 0x1050, ep256, b256.pt.p, b256.pt.n, AT(0x103, Fb));
    ED("ecdh key type aes 32", 0x1050, ep256, b256.pt.p, b256.pt.n, AT(0x100, k_aes));
    ED("ecdh class data", 0x1050, ep256, b256.pt.p, b256.pt.n, AT(0x0, c_data));
    ED("ecdh extractable", 0x1050, ep256, b256.pt.p, b256.pt.n, AT(0x162, T));
    if (derived) wr(h, "ecdh extractable, wrapped", 0x2109, NULL, 0, kek, derived, 64, 0);

    /* Logged out, then the SO with the user's keys. */
    {
        UL o = 0xAAAAAAAAUL;
        Mech m = { 0x402A, &hp, sizeof hp }, mc = { 0x362, &sd, sizeof sd };
        Mech me = { 0x1050, EP(b256.pt.p, b256.pt.n), sizeof ep };
        hp = hk;
        sd = (Str){ abcde, 5 };
        printf("logout\t%#lx\n", P11(C_Logout, h));
        printf("hkdf logged out\t%#lx\n", P11(C_DeriveKey, h, &m, base, NULL, 0UL, &o));
        printf("so login\t%#lx\n", P11(C_Login, h, 0UL, SO_PIN, (UL)strlen(SO_PIN)));
        printf("so hkdf from user key\t%#lx\n", P11(C_DeriveKey, h, &m, base, NULL, 0UL, &o));
        printf("so concat from user key\t%#lx\n", P11(C_DeriveKey, h, &mc, base, NULL, 0UL, &o));
        printf("so ecdh from user key\t%#lx\n", P11(C_DeriveKey, h, &me, ep256, NULL, 0UL, &o));
        printf("so logout\t%#lx\n", P11(C_Logout, h));
    }
    P11(C_Finalize, NULL);
}

/* Slice 7: an ML-KEM key from a fixed seed, its raw halves, and the ciphertext and secret of an
 * encapsulation with fixed entropy (OpenSSL's "ikme"), so every decapsulation prints whole. */
typedef struct { Blob pub, priv, ct, ss; } Kem;
static void kem(const char *alg, unsigned char s, Kem *k) {
    unsigned char seed[64], ikme[32];
    for (int i = 0; i < 64; ++i) seed[i] = (unsigned char)(s + i);
    memset(ikme, s, sizeof ikme);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *p = NULL;
    OSSL_PARAM sp[] = { OSSL_PARAM_construct_octet_string("seed", seed, 64), OSSL_PARAM_construct_end() },
               ep[] = { OSSL_PARAM_construct_octet_string("ikme", ikme, 32), OSSL_PARAM_construct_end() };
    if (EVP_PKEY_keygen_init(c) <= 0 || EVP_PKEY_CTX_set_params(c, sp) <= 0 || EVP_PKEY_generate(c, &p) <= 0) {
        fprintf(stderr, "kem keygen %s failed\n", alg);
        exit(2);
    }
    EVP_PKEY_CTX_free(c);
    raw(p, 0, &k->pub);
    raw(p, 1, &k->priv);
    c = EVP_PKEY_CTX_new(p, NULL);
    k->ct.n = sizeof k->ct.p, k->ss.n = sizeof k->ss.p;
    if (EVP_PKEY_encapsulate_init(c, ep) <= 0 || EVP_PKEY_encapsulate(c, k->ct.p, &k->ct.n, k->ss.p, &k->ss.n) <= 0) {
        fprintf(stderr, "kem encapsulate %s failed\n", alg);
        exit(2);
    }
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(p);
}

/* One encapsulation: cap 0 asks the size (NULL buffer), else a buffer of cap bytes. The new
 * key's attributes print with its value as "rnd:<len>"; a success's ciphertext is kept in ct. */
static unsigned char kct[2048];
static UL kct_n, kemmed;
static void en(UL h, const char *name, UL pub, Attr *t, UL n, UL cap) {
    Mech m = { 0x17, NULL, 0 };
    UL frv, before = nobj(h, &frv), o = 0xAAAAAAAAUL, len = cap;
    memset(kct, 0xAA, sizeof kct);
    UL rv = P11(C_EncapsulateKey, h, &m, pub, t, n, cap ? kct : NULL, &len, &o);
    char hb[24];
    printf("%s\t%#lx\t%s\t%#lx\n", name, rv, hv(o, hb), len);
    kemmed = rv || !cap ? 0 : o;
    if (!rv && cap) kct_n = len;
    if (rv || !cap) stored(h, name, before);
    else dump(h, name, o, 1);
}
#define EN(name, pub, cap, ...) do { Attr t_[] = { __VA_ARGS__ }; en(h, name, pub, t_, sizeof t_ / sizeof t_[0], cap); } while (0)
#define EN0(name, pub, cap) en(h, name, pub, NULL, 0UL, cap)

/* One decapsulation of ct (cl bytes); the new key's attributes, its value whole unless rnd. */
static void de(UL h, const char *name, UL priv, const unsigned char *ct, UL cl, Attr *t, UL n, int rnd) {
    Mech m = { 0x17, NULL, 0 };
    UL frv, before = nobj(h, &frv), o = 0xAAAAAAAAUL;
    UL rv = P11(C_DecapsulateKey, h, &m, priv, t, n, (unsigned char *)ct, cl, &o);
    char hb[24];
    printf("%s\t%#lx\t%s\t-\n", name, rv, hv(o, hb));
    kemmed = rv ? 0 : o;
    if (rv) stored(h, name, before);
    else dump(h, name, o, rnd);
}
#define DE(name, priv, k, ...) do { Attr t_[] = { __VA_ARGS__ }; \
    de(h, name, priv, (k).ct.p, (UL)(k).ct.n, t_, sizeof t_ / sizeof t_[0], 0); } while (0)
#define DE0(name, priv, k) de(h, name, priv, (k).ct.p, (UL)(k).ct.n, NULL, 0UL, 0)

/* Two keys' values, compared: an encapsulation and the decapsulation of its ciphertext. */
static void same(UL h, const char *name, UL a, UL b) {
    unsigned char va[64], vb[64];
    Attr x = { 0x11, va, sizeof va }, y = { 0x11, vb, sizeof vb };
    UL ra = P11(C_GetAttributeValue, h, a, &x, 1UL), rb = P11(C_GetAttributeValue, h, b, &y, 1UL);
    printf("%s\t%#lx\t%#lx\t%s\n", name, ra, rb,
           ra || rb ? "-" : x.len == y.len && !memcmp(va, vb, x.len) ? "same" : "differ");
}

static void s_kem(void) {
    UL h = setup(), h_ro = 0;
    static UL c_sec = 4, c_priv = 3, c_data = 0, k_kem = 0x49, k_ec = 3, k_des3 = 0x15,
              s1 = 1, s2 = 2, s3 = 3, len0 = 0, len5 = 5, len16 = 16, len24 = 24, len32 = 32,
              len33 = 33, wide = 0x10000001FUL, kem_only[] = { 0x17 }, ecb_only[] = { 0x1081 },
              m_kem = 0xF;
    static unsigned char lab70[70], idb[3] = "id1", date[8] = "20260101", v16[16] = { 1 };
    memset(lab70, 'L', sizeof lab70);
    static Kem k5, k7, k10;
    kem("ML-KEM-512", 0x10, &k5);
    kem("ML-KEM-768", 0x20, &k7);
    kem("ML-KEM-1024", 0x30, &k10);
    static Kem bad5;
    bad5 = k5;
    bad5.ct.p[0] ^= 1;

    UL p5, v5, p7, v7, p10, v10, pnoenc, vnodec, palw, valw, ecpub, sec, gp = 0, gv = 0;
    static Attr dt_aes[] = { { 0x100, &k_aes, sizeof k_aes } };
    KEY(p5, "mlkem512 pub", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, k5.pub), AT(0x61D, s1));
    KEY(v5, "mlkem512 priv", AT(0x0, c_priv), AT(0x100, k_kem), BL(0x11, k5.priv), AT(0x61D, s1));
    KEY(p7, "mlkem768 pub", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, k7.pub), AT(0x61D, s2));
    KEY(v7, "mlkem768 priv", AT(0x0, c_priv), AT(0x100, k_kem), BL(0x11, k7.priv), AT(0x61D, s2));
    KEY(p10, "mlkem1024 pub", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, k10.pub), AT(0x61D, s3));
    KEY(v10, "mlkem1024 priv", AT(0x0, c_priv), AT(0x100, k_kem), BL(0x11, k10.priv), AT(0x61D, s3));
    KEY(pnoenc, "mlkem512 pub encapsulate false", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, k5.pub), AT(0x61D, s1), AT(0x633, Fb));
    KEY(vnodec, "mlkem512 priv decapsulate false", AT(0x0, c_priv), AT(0x100, k_kem), BL(0x11, k5.priv), AT(0x61D, s1), AT(0x634, Fb));
    KEY(palw, "mlkem512 pub ecb only", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, k5.pub), AT(0x61D, s1),
        AB(0x40000600, ecb_only, sizeof ecb_only));
    KEY(valw, "mlkem512 priv kem only", AT(0x0, c_priv), AT(0x100, k_kem), BL(0x11, k5.priv), AT(0x61D, s1),
        AB(0x40000600, kem_only, sizeof kem_only));
    KEY(ecpub, "ec p256 pub", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P256, sizeof P256),
        AB(0x181, "\x04\x41\x04\x6b\x17\xd1\xf2\xe1\x2c\x42\x47\xf8\xbc\xe6\xe5\x63\xa4\x40\xf2\x77\x03\x7d\x81\x2d\xeb\x33\xa0\xf4\xa1\x39\x45\xd8\x98\xc2\x96\x4f\xe3\x42\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xeb\x4a\x7c\x0f\x9e\x16\x2b\xce\x33\x57\x6b\x31\x5e\xce\xcb\xb6\x40\x68\x37\xbf\x51\xf5", 67));
    KEY(sec, "aes key", AT(0x0, c_sec), AT(0x100, k_aes), AT(0x11, v16));
    {
        Mech m = { m_kem, NULL, 0 };
        Attr pu[] = { AT(0x61D, s1) };
        printf("mlkem512 pair\t%#lx\n", P11(C_GenerateKeyPair, h, &m, pu, 1UL, NULL, 0UL, &gp, &gv));
    }

    /* The checks before the key's, in C's order, for both. */
    {
        Mech m = { 0x17, NULL, 0 }, bad = { 0x1081, NULL, 0 };
        UL o = 0xAAAAAAAAUL, len = sizeof kct;
        Attr tb[] = { { 0x103, &T, 4 } }, tu[] = { { 0x161, &len16, 1 } }, tt[] = { AT(0x86, T) },
             tv[] = { BL(0x11, k5.ss) }, tk[] = { AT(0x1, T) };
        printf("encap null mech\t%#lx\n", P11(C_EncapsulateKey, h, NULL, p5, NULL, 0UL, kct, &len, &o));
        printf("encap null out\t%#lx\n", P11(C_EncapsulateKey, h, &m, p5, NULL, 0UL, kct, &len, NULL));
        printf("encap null len\t%#lx\n", P11(C_EncapsulateKey, h, &m, p5, NULL, 0UL, kct, NULL, &o));
        printf("encap null template\t%#lx\n", P11(C_EncapsulateKey, h, &m, p5, NULL, 1UL, kct, &len, &o));
        printf("encap trusted\t%#lx\n", P11(C_EncapsulateKey, h, &m, p5, tt, 1UL, kct, &len, &o));
        printf("encap bool len\t%#lx\n", P11(C_EncapsulateKey, h, &m, p5, tb, 1UL, kct, &len, &o));
        printf("encap ulong len\t%#lx\n", P11(C_EncapsulateKey, h, &m, p5, tu, 1UL, kct, &len, &o));
        printf("encap value\t%#lx\n", P11(C_EncapsulateKey, h, &m, p5, tv, 1UL, kct, &len, &o));
        printf("encap mechanism\t%#lx\n", P11(C_EncapsulateKey, h, &bad, p5, NULL, 0UL, kct, &len, &o));
        printf("encap bad session\t%#lx\n", P11(C_EncapsulateKey, 99UL, &m, p5, NULL, 0UL, kct, &len, &o));
        printf("encap bad handle\t%#lx\n", P11(C_EncapsulateKey, h, &m, 0x7777UL, NULL, 0UL, kct, &len, &o));
        printf("decap null mech\t%#lx\n", P11(C_DecapsulateKey, h, NULL, v5, NULL, 0UL, k5.ct.p, (UL)k5.ct.n, &o));
        printf("decap null out\t%#lx\n", P11(C_DecapsulateKey, h, &m, v5, NULL, 0UL, k5.ct.p, (UL)k5.ct.n, NULL));
        printf("decap null ciphertext\t%#lx\n", P11(C_DecapsulateKey, h, &m, v5, NULL, 0UL, NULL, (UL)k5.ct.n, &o));
        printf("decap null template\t%#lx\n", P11(C_DecapsulateKey, h, &m, v5, NULL, 1UL, k5.ct.p, (UL)k5.ct.n, &o));
        printf("decap trusted\t%#lx\n", P11(C_DecapsulateKey, h, &m, v5, tt, 1UL, k5.ct.p, (UL)k5.ct.n, &o));
        printf("decap bool len\t%#lx\n", P11(C_DecapsulateKey, h, &m, v5, tb, 1UL, k5.ct.p, (UL)k5.ct.n, &o));
        printf("decap ulong len\t%#lx\n", P11(C_DecapsulateKey, h, &m, v5, tu, 1UL, k5.ct.p, (UL)k5.ct.n, &o));
        printf("decap value\t%#lx\n", P11(C_DecapsulateKey, h, &m, v5, tv, 1UL, k5.ct.p, (UL)k5.ct.n, &o));
        printf("decap mechanism\t%#lx\n", P11(C_DecapsulateKey, h, &bad, v5, NULL, 0UL, k5.ct.p, (UL)k5.ct.n, &o));
        printf("decap bad session\t%#lx\n", P11(C_DecapsulateKey, 99UL, &m, v5, NULL, 0UL, k5.ct.p, (UL)k5.ct.n, &o));
        printf("decap bad handle\t%#lx\n", P11(C_DecapsulateKey, h, &m, 0x7777UL, NULL, 0UL, k5.ct.p, (UL)k5.ct.n, &o));
        printf("ro session\t%#lx\n", P11(C_OpenSession, 0UL, 4UL, NULL, NULL, &h_ro));
        en(h_ro, "encap ro token", p5, tk, 1UL, sizeof kct);
        en(h_ro, "encap ro session object", p5, NULL, 0UL, sizeof kct);
        de(h_ro, "decap ro token", v5, k5.ct.p, (UL)k5.ct.n, tk, 1UL, 0);
        de(h_ro, "decap ro session object", v5, k5.ct.p, (UL)k5.ct.n, NULL, 0UL, 0);
        printf("ro session closed\t%#lx\n", P11(C_CloseSession, h_ro));
    }

    /* The key: its class and type, its policy, then the ciphertext's size. */
    EN0("encap with private key", v5, sizeof kct);
    EN0("encap with ec key", ecpub, sizeof kct);
    EN0("encap with secret key", sec, sizeof kct);
    EN0("encap encapsulate false", pnoenc, sizeof kct);
    EN0("encap mechanism not allowed", palw, sizeof kct);
    EN0("encap size query 512", p5, 0);
    EN0("encap size query 768", p7, 0);
    EN0("encap size query 1024", p10, 0);
    EN0("encap buffer short", p5, 767);
    EN0("encap 512", p5, sizeof kct);
    DE0("decap with public key", p5, k5);
    DE0("decap with secret key", sec, k5);
    DE0("decap decapsulate false", vnodec, k5);
    DE0("decap mechanism allowed", valw, k5);
    printf("libcrypto secret 512\t"), hex(k5.ss.p, k5.ss.n), printf("\n");
    printf("libcrypto secret 768\t"), hex(k7.ss.p, k7.ss.n), printf("\n");
    printf("libcrypto secret 1024\t"), hex(k10.ss.p, k10.ss.n), printf("\n");
    DE("decap 512", v5, k5, AT(0x162, T));
    DE("decap 768", v7, k7, AT(0x162, T));
    DE("decap 1024", v10, k10, AT(0x162, T));
    DE0("decap 768 ciphertext with 512 key", v5, k7);
    DE("decap altered ciphertext", v5, bad5, AT(0x162, T));
    de(h, "decap ciphertext short", v5, k5.ct.p, (UL)k5.ct.n - 1, NULL, 0UL, 0);
    de(h, "decap ciphertext long", v5, k5.ct.p, (UL)k5.ct.n + 1, NULL, 0UL, 0);
    de(h, "decap ciphertext empty", v5, k5.ct.p, 0UL, NULL, 0UL, 0);

    /* Round trips through the module, its ciphertext random. */
    {
        UL e;
        Attr tx[] = { AT(0x162, T) };
        en(h, "encap 768 round trip", p7, tx, 1UL, sizeof kct);
        e = kemmed;
        de(h, "decap 768 round trip", v7, kct, kct_n, tx, 1UL, 1);
        same(h, "round trip 768 secrets", e, kemmed);
        en(h, "encap generated", gp, tx, 1UL, sizeof kct);
        e = kemmed;
        de(h, "decap generated", gv, kct, kct_n, tx, 1UL, 1);
        same(h, "round trip generated secrets", e, kemmed);
    }

    /* The new key's template: as C stores it, then what it allows. */
    DE("decap label", v5, k5, AB(0x3, "kem-secret", 10));
    DE("decap label 70", v5, k5, AB(0x3, lab70, sizeof lab70));
    DE("decap sensitive", v5, k5, AT(0x103, T));
    DE("decap sensitive false", v5, k5, AT(0x103, Fb));
    DE("decap extractable", v5, k5, AT(0x162, T));
    DE("decap class secret", v5, k5, AT(0x0, c_sec));
    DE("decap class data", v5, k5, AT(0x0, c_data));
    DE("decap class private", v5, k5, AT(0x0, c_priv));
    DE("decap key type aes", v5, k5, AT(0x100, k_aes));
    DE("decap key type aes 16", v5, k5, AT(0x100, k_aes), AT(0x161, len16));
    DE("decap key type aes 24", v5, k5, AT(0x100, k_aes), AT(0x161, len24));
    DE("decap key type aes 5", v5, k5, AT(0x100, k_aes), AT(0x161, len5));
    DE("decap key type des3 24", v5, k5, AT(0x100, k_des3), AT(0x161, len24));
    DE("decap key type des3", v5, k5, AT(0x100, k_des3));
    DE("decap key type ec", v5, k5, AT(0x100, k_ec));
    DE("decap key type wide", v5, k5, AT(0x100, wide));
    DE("decap key type kem", v5, k5, AT(0x100, k_kem));
    DE("decap value len 0", v5, k5, AT(0x161, len0));
    DE("decap value len 5", v5, k5, AT(0x161, len5));
    DE("decap value len 32", v5, k5, AT(0x161, len32));
    DE("decap value len 33", v5, k5, AT(0x161, len33));
    DE("decap token", v5, k5, AT(0x1, T));
    DE("decap token false", v5, k5, AT(0x1, Fb));
    DE("decap private false", v5, k5, AT(0x2, Fb));
    DE("decap id", v5, k5, AB(0x102, idb, sizeof idb));
    DE("decap start date", v5, k5, AB(0x110, date, sizeof date));
    DE("decap start date short", v5, k5, AB(0x110, date, 5));
    DE("decap not modifiable", v5, k5, AT(0x170, Fb));
    DE("decap not destroyable", v5, k5, AT(0x172, Fb));
    DE("decap not copyable", v5, k5, AT(0x171, Fb));
    DE("decap allowed mechanisms", v5, k5, AB(0x40000600, ecb_only, sizeof ecb_only));
    DE("decap derive template", v5, k5, AT(0x10C, T), AB(0x40000213, dt_aes, sizeof dt_aes));
    DE("decap encrypt false", v5, k5, AT(0x100, k_aes), AT(0x161, len16), AT(0x104, Fb));
    {
        Mech ecb = { 0x1081, NULL, 0 };
        UL k = kemmed;
        printf("encryptinit with encrypt false\t%#lx\n", P11(C_EncryptInit, h, &ecb, k));
        unsigned char pt[16] = { 0 }, ct[32];
        UL cl = sizeof ct;
        printf("encrypt with encrypt false\t%#lx\n", P11(C_Encrypt, h, pt, 16UL, ct, &cl));
    }
    DE("decap aes 16 encrypt", v5, k5, AT(0x100, k_aes), AT(0x161, len16), AT(0x104, T));
    {
        Mech ecb = { 0x1081, NULL, 0 };
        UL k = kemmed, cl = 16;
        unsigned char pt[16] = { 0 }, ct[16];
        printf("encryptinit with the decapsulated key\t%#lx\n", P11(C_EncryptInit, h, &ecb, k));
        printf("encrypt with the decapsulated key\t%#lx\t", P11(C_Encrypt, h, pt, 16UL, ct, &cl));
        hex(ct, cl);
        printf("\n");
    }
    EN("encap key type aes 16", p5, sizeof kct, AT(0x100, k_aes), AT(0x161, len16));
    EN("encap key type aes 5", p5, sizeof kct, AT(0x100, k_aes), AT(0x161, len5));
    EN("encap key type ec", p5, sizeof kct, AT(0x100, k_ec));
    EN("encap class data", p5, sizeof kct, AT(0x0, c_data));
    EN("encap value len 33", p5, sizeof kct, AT(0x161, len33));
    EN("encap sensitive", p5, sizeof kct, AT(0x103, T), AT(0x162, T));
    EN("encap id and dates", p5, sizeof kct, AB(0x102, idb, sizeof idb), AB(0x111, date, sizeof date));

    /* Logged out, then the SO with the user's keys. */
    {
        Mech m = { 0x17, NULL, 0 };
        UL o = 0xAAAAAAAAUL, len = sizeof kct;
        printf("logout\t%#lx\n", P11(C_Logout, h));
        printf("encap logged out\t%#lx\n", P11(C_EncapsulateKey, h, &m, p5, NULL, 0UL, kct, &len, &o));
        printf("decap logged out\t%#lx\n", P11(C_DecapsulateKey, h, &m, v5, NULL, 0UL, k5.ct.p, (UL)k5.ct.n, &o));
        printf("so login\t%#lx\n", P11(C_Login, h, 0UL, SO_PIN, (UL)strlen(SO_PIN)));
        o = 0xAAAAAAAAUL, len = sizeof kct;
        printf("so encap to user key\t%#lx\t%#lx\n", P11(C_EncapsulateKey, h, &m, p5, NULL, 0UL, kct, &len, &o), len);
        printf("so decap with user key\t%#lx\n", P11(C_DecapsulateKey, h, &m, v5, NULL, 0UL, k5.ct.p, (UL)k5.ct.n, &o));
        printf("so logout\t%#lx\n", P11(C_Logout, h));
    }
    P11(C_Finalize, NULL);
}

/* 7 (slice 8b-ii): the attributes C_GetAttributeValue reads back through OpenSSL (an RSA,
 * EC, Edwards or Montgomery key's public parts, a PQC key's raw public key and parameter set,
 * a certificate's subject, issuer and serial), over keys and a certificate made here from
 * fixed bytes, so every value prints whole. Each read-back attribute is also asked its size
 * and read one byte short. */
static const UL RB[] = { 0x120, 0x121, 0x122, 0x180, 0x181, 0x11, 0x61D, 0x101, 0x81, 0x82 };
static void rb(UL h, const char *name, UL o) {
    dump(h, name, o, 0);
    for (size_t i = 0; i < sizeof RB / sizeof RB[0]; ++i) {
        Attr a = { RB[i], NULL, 0 };
        UL rv = P11(C_GetAttributeValue, h, o, &a, 1UL);
        printf("%s %#lx size\t%#lx\t%#lx\t-\n", name, RB[i], rv, a.len);
        if (rv || a.len == 0 || a.len > sizeof buf) continue;
        UL want = a.len;
        memset(buf, 0xAA, want);
        a.p = buf, a.len = want - 1;
        rv = P11(C_GetAttributeValue, h, o, &a, 1UL);
        printf("%s %#lx short\t%#lx\t%#lx\t", name, RB[i], rv, a.len);
        hex(buf, want);
        printf("\n");
        memset(buf, 0xAA, want);
        a.p = buf, a.len = want;
        rv = P11(C_GetAttributeValue, h, o, &a, 1UL);
        printf("%s %#lx get\t%#lx\t%#lx\t", name, RB[i], rv, a.len);
        hex(buf, want);
        printf("\n");
    }
}
static void mk0(UL h, const char *name, Attr *t, UL n) {
    UL o = 0xAAAAAAAAUL, rv = P11(C_CreateObject, h, t, n, &o);
    char b[24];
    printf("%s\t%#lx\t%s\t-\n", name, rv, hv(o, b));
    if (!rv) rb(h, name, o);
}
#define MK0(name, ...) do { Attr t_[] = { __VA_ARGS__ }; mk0(h, name, t_, sizeof t_ / sizeof t_[0]); } while (0)

static void die(const char *what) { fprintf(stderr, "%s failed\n", what); exit(2); }
static void bnb(const BIGNUM *x, Blob *b) { b->n = (size_t)BN_bn2bin(x, b->p); }
/* The first prime from a fixed 1024-bit start (top two bits set, so n has 2048 bits). */
static void prime_from(unsigned char s, BIGNUM *p, BN_CTX *x) {
    unsigned char b[128];
    for (int i = 0; i < 128; ++i) b[i] = (unsigned char)(s * 31 + i * 7);
    b[0] |= 0xC0, b[127] |= 1;
    if (!BN_bin2bn(b, 128, p)) die("prime");
    while (BN_check_prime(p, x, NULL) != 1) BN_add_word(p, 2);
}
typedef struct { Blob n, e, d, p, q, dp, dq, qi; } Rsa;
static void rsa_fixed(Rsa *r) {
    BN_CTX *x = BN_CTX_new();
    BIGNUM *p = BN_new(), *q = BN_new(), *n = BN_new(), *e = BN_new(), *d = BN_new(),
           *p1 = BN_new(), *q1 = BN_new(), *phi = BN_new(), *dp = BN_new(), *dq = BN_new(),
           *qi = BN_new();
    prime_from(1, p, x), prime_from(2, q, x);
    BN_mul(n, p, q, x), BN_set_word(e, 65537);
    BN_sub(p1, p, BN_value_one()), BN_sub(q1, q, BN_value_one()), BN_mul(phi, p1, q1, x);
    if (!BN_mod_inverse(d, e, phi, x) || !BN_mod_inverse(qi, q, p, x)) die("rsa");
    BN_mod(dp, d, p1, x), BN_mod(dq, d, q1, x);
    bnb(n, &r->n), bnb(e, &r->e), bnb(d, &r->d), bnb(p, &r->p), bnb(q, &r->q);
    bnb(dp, &r->dp), bnb(dq, &r->dq), bnb(qi, &r->qi);
    BN_free(p), BN_free(q), BN_free(n), BN_free(e), BN_clear_free(d), BN_free(p1), BN_free(q1);
    BN_free(phi), BN_clear_free(dp), BN_clear_free(dq), BN_free(qi), BN_CTX_free(x);
}
/* CKA_EC_POINT's DER OCTET STRING, the long form past 127 bytes. */
static void wrapl(const Blob *in, Blob *out) {
    size_t o = 0;
    out->p[o++] = 0x04;
    if (in->n > 127) out->p[o++] = 0x81;
    out->p[o++] = (unsigned char)in->n;
    memcpy(out->p + o, in->p, in->n);
    out->n = in->n + o;
}
static void ecx(int type, size_t len, unsigned char s, Blob *pub, Blob *priv) {
    unsigned char k[64];
    for (size_t i = 0; i < len; ++i) k[i] = (unsigned char)(s + i * 3);
    EVP_PKEY *p = EVP_PKEY_new_raw_private_key(type, NULL, k, len);
    if (!p) die("ecx");
    raw(p, 0, pub), raw(p, 1, priv);
    EVP_PKEY_free(p);
}
static void mldsa(const char *alg, unsigned char s, Blob *pub, Blob *priv) {
    unsigned char seed[32];
    for (int i = 0; i < 32; ++i) seed[i] = (unsigned char)(s + i);
    EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *p = NULL;
    OSSL_PARAM sp[] = { OSSL_PARAM_construct_octet_string("seed", seed, 32), OSSL_PARAM_construct_end() };
    if (!c || EVP_PKEY_keygen_init(c) <= 0 || EVP_PKEY_CTX_set_params(c, sp) <= 0
        || EVP_PKEY_generate(c, &p) <= 0) die(alg);
    raw(p, 0, pub), raw(p, 1, priv);
    EVP_PKEY_free(p), EVP_PKEY_CTX_free(c);
}
/* A certificate whose every byte is fixed: Ed25519 signatures are deterministic. */
static void cert_fixed(Blob *der) {
    unsigned char sk[32];
    for (int i = 0; i < 32; ++i) sk[i] = (unsigned char)(0x40 + i);
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, sk, 32);
    X509 *c = X509_new();
    X509_NAME *sn = X509_NAME_new(), *in = X509_NAME_new();
    if (!k || !c || !sn || !in) die("cert");
    X509_set_version(c, 2);
    ASN1_INTEGER_set_uint64(X509_get_serialNumber(c), 0x0102030405060708ULL);
    X509_NAME_add_entry_by_txt(sn, "CN", MBSTRING_ASC, (const unsigned char *)"pqHSM golden leaf", -1, -1, 0);
    X509_NAME_add_entry_by_txt(sn, "O", MBSTRING_ASC, (const unsigned char *)"Test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(in, "CN", MBSTRING_ASC, (const unsigned char *)"pqHSM golden root", -1, -1, 0);
    X509_set_subject_name(c, sn), X509_set_issuer_name(c, in);
    ASN1_TIME_set_string_X509(X509_getm_notBefore(c), "260101000000Z");
    ASN1_TIME_set_string_X509(X509_getm_notAfter(c), "360101000000Z");
    X509_set_pubkey(c, k);
    if (X509_sign(c, k, NULL) <= 0) die("cert sign");
    unsigned char *q = der->p;
    int n = i2d_X509(c, &q);
    der->n = n > 0 ? (size_t)n : 0;
    X509_NAME_free(sn), X509_NAME_free(in), X509_free(c), EVP_PKEY_free(k);
}

static void s_attrs(void) {
    UL h = setup();
    static UL c_priv = 3, c_cert = 1, x509 = 0, k_rsa = 0, k_ec = 3, k_ed = 0x40, k_x = 0x41,
              k_kem = 0x49, k_dsa = 0x4A, s1 = 1, s2 = 2, s3 = 3;
    static unsigned char X448[] = { 0x06, 0x03, 0x2B, 0x65, 0x6F };
    static Rsa r;
    static Ec e256, e384, e521, ek1;
    static Blob w256, w384, w521, wk1, edp, edv, edw, ed4p, ed4v, ed4w, xp, xv, xw, x4p, x4v, x4w,
        d44p, d44v, d65p, d65v, d87p, d87v, kems, crt;
    static Kem k768;
    rsa_fixed(&r);
    ec(NID_X9_62_prime256v1, "P-256", 0x1234567UL, 32, &e256), wrapl(&e256.pt, &w256);
    ec(NID_secp384r1, "P-384", 0x89ABCDEFUL, 48, &e384), wrapl(&e384.pt, &w384);
    ec(NID_secp521r1, "P-521", 0x31415926UL, 66, &e521), wrapl(&e521.pt, &w521);
    ec(NID_secp256k1, "secp256k1", 0x27182818UL, 32, &ek1), wrapl(&ek1.pt, &wk1);
    ecx(EVP_PKEY_ED25519, 32, 1, &edp, &edv), wrapl(&edp, &edw);
    ecx(EVP_PKEY_ED448, 57, 2, &ed4p, &ed4v), wrapl(&ed4p, &ed4w);
    ecx(EVP_PKEY_X25519, 32, 3, &xp, &xv), wrapl(&xp, &xw);
    ecx(EVP_PKEY_X448, 56, 4, &x4p, &x4v), wrapl(&x4p, &x4w);
    mldsa("ML-DSA-44", 5, &d44p, &d44v), mldsa("ML-DSA-65", 6, &d65p, &d65v);
    mldsa("ML-DSA-87", 7, &d87p, &d87v);
    kem("ML-KEM-768", 8, &k768);
    {
        EVP_PKEY *p = EVP_PKEY_new_raw_public_key_ex(NULL, "ML-KEM-768", NULL, k768.pub.p, k768.pub.n);
        if (!p) die("kem spki");
        spki(p, &kems);
        EVP_PKEY_free(p);
    }
    cert_fixed(&crt);

    MK0("fixed rsa pub", AT(0x0, c_pub), AT(0x100, k_rsa), BL(0x120, r.n), BL(0x122, r.e));
    MK0("fixed rsa priv", AT(0x0, c_priv), AT(0x100, k_rsa), BL(0x120, r.n), BL(0x122, r.e), BL(0x123, r.d),
        BL(0x124, r.p), BL(0x125, r.q), BL(0x126, r.dp), BL(0x127, r.dq), BL(0x128, r.qi));
    MK0("fixed ec p256 pub", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x181, w256));
    MK0("fixed ec p256 priv", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, P256, sizeof P256), BL(0x11, e256.d));
    MK0("fixed ec p384 pub", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P384, sizeof P384), BL(0x181, w384));
    MK0("fixed ec p521 pub", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, P521, sizeof P521), BL(0x181, w521));
    MK0("fixed ec p521 priv", AT(0x0, c_priv), AT(0x100, k_ec), AB(0x180, P521, sizeof P521), BL(0x11, e521.d));
    MK0("fixed ec secp256k1 pub", AT(0x0, c_pub), AT(0x100, k_ec), AB(0x180, K256, sizeof K256), BL(0x181, wk1));
    MK0("fixed ed25519 pub", AT(0x0, c_pub), AT(0x100, k_ed), AB(0x180, ED25519, sizeof ED25519), BL(0x181, edw));
    MK0("fixed ed25519 pub by name", AT(0x0, c_pub), AT(0x100, k_ed), AB(0x180, ED25519_NAME, 14), BL(0x181, edw));
    MK0("fixed ed25519 priv", AT(0x0, c_priv), AT(0x100, k_ed), AB(0x180, ED25519, sizeof ED25519), BL(0x11, edv));
    MK0("fixed ed25519 priv by name", AT(0x0, c_priv), AT(0x100, k_ed), AB(0x180, ED25519_NAME, 14), BL(0x11, edv));
    MK0("fixed ed448 pub", AT(0x0, c_pub), AT(0x100, k_ed), AB(0x180, ED448, sizeof ED448), BL(0x181, ed4w));
    MK0("fixed ed448 pub by name", AT(0x0, c_pub), AT(0x100, k_ed), AB(0x180, ED448_NAME, 12), BL(0x181, ed4w));
    MK0("fixed ed448 priv", AT(0x0, c_priv), AT(0x100, k_ed), AB(0x180, ED448, sizeof ED448), BL(0x11, ed4v));
    MK0("fixed x25519 pub", AT(0x0, c_pub), AT(0x100, k_x), AB(0x180, X25519, sizeof X25519), BL(0x181, xw));
    MK0("fixed x25519 priv", AT(0x0, c_priv), AT(0x100, k_x), AB(0x180, X25519, sizeof X25519), BL(0x11, xv));
    MK0("fixed x448 pub", AT(0x0, c_pub), AT(0x100, k_x), AB(0x180, X448, sizeof X448), BL(0x181, x4w));
    MK0("fixed x448 priv", AT(0x0, c_priv), AT(0x100, k_x), AB(0x180, X448, sizeof X448), BL(0x11, x4v));
    MK0("fixed mldsa44 pub", AT(0x0, c_pub), AT(0x100, k_dsa), BL(0x11, d44p), AT(0x61D, s1));
    MK0("fixed mldsa44 priv", AT(0x0, c_priv), AT(0x100, k_dsa), BL(0x11, d44v), AT(0x61D, s1));
    MK0("fixed mldsa65 pub", AT(0x0, c_pub), AT(0x100, k_dsa), BL(0x11, d65p), AT(0x61D, s2));
    MK0("fixed mldsa87 pub", AT(0x0, c_pub), AT(0x100, k_dsa), BL(0x11, d87p), AT(0x61D, s3));
    MK0("fixed mldsa87 priv", AT(0x0, c_priv), AT(0x100, k_dsa), BL(0x11, d87v), AT(0x61D, s3));
    MK0("fixed mlkem768 pub raw", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, k768.pub), AT(0x61D, s2));
    MK0("fixed mlkem768 pub spki", AT(0x0, c_pub), AT(0x100, k_kem), BL(0x11, kems), AT(0x61D, s2));
    MK0("fixed mlkem768 priv", AT(0x0, c_priv), AT(0x100, k_kem), BL(0x11, k768.priv), AT(0x61D, s2));
    MK0("fixed cert", AT(0x0, c_cert), AT(0x80, x509), BL(0x11, crt));
    MK0("fixed cert subject given", AT(0x0, c_cert), AT(0x80, x509), BL(0x11, crt), AB(0x101, "given", 5));
    MK0("fixed cert truncated", AT(0x0, c_cert), AT(0x80, x509), AB(0x11, crt.p, crt.n / 2));
    P11(C_Finalize, NULL);
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: p11_keys LIB BASE\n"); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    void (*S[])(void) = { s_gen, s_pair, s_life, s_create, s_wrap, s_derive, s_kem, s_attrs };
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
