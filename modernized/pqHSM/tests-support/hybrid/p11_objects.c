/* p11_objects.c LIB BASE --- slice 2 of PHASE4_PLAN.md §2: call sequences through the nine
 * object entry points (C_CreateObject, C_CopyObject, C_DestroyObject, C_GetAttributeValue,
 * C_SetAttributeValue, C_GetObjectSize, C_FindObjectsInit/FindObjects/FindObjectsFinal), one
 * row per call: "label TAB rv TAB n TAB hex", n the handle, count or ulValueLen it wrote.
 *
 * Each scenario runs in a forked child with its own tokens directory BASE/<n>. Outputs are
 * pre-filled with 0xAA. Bytes a key generator drew at random are printed as "rnd:<len>", and
 * only for objects the driver marks generated, and so are their CKA_VALUE_LEN and object size
 * (an RSA key's DER length varies by a byte); everything else is deterministic, so C and
 * hybrid must print the same apart from recorded DIVs (harness step 4i).
 *
 * Written from the C (src/fhsm_pkcs11.c:3559-4165, 7155-8406; src/fhsm_create_attrs.c) before
 * the Rust, as its characterisation. */
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
static unsigned char buf[8192];

static F sym(const char *name) {
    F f = (F)dlsym(lib, name);
    if (!f) { fprintf(stderr, "no %s\n", name); exit(2); }
    return f;
}
#define P11(name, ...) sym(#name)(__VA_ARGS__)

static void hex(const unsigned char *p, UL n) {
    if (!n) { printf("-"); return; }
    for (UL i = 0; i < n; ++i) printf("%02x", p[i]);
}

static void row(const char *label, UL rv, UL n, const unsigned char *p, UL plen, int rnd) {
    printf("%s\t%#lx\t%#lx\t", label, rv, n);
    if (!p) printf("-");
    else if (rnd && plen > 8) printf("rnd:%lu", plen);
    else hex(p, plen);
    printf("\n");
}

/* The attribute types slice 2's C handles, plus CKA_KEY_GEN_MECHANISM and one unknown. */
static const struct { const char *n; UL t; } A[] = {
    { "CLASS", 0x0 }, { "TOKEN", 0x1 }, { "PRIVATE", 0x2 }, { "LABEL", 0x3 },
    { "APPLICATION", 0x10 }, { "VALUE", 0x11 }, { "CERTIFICATE_TYPE", 0x80 },
    { "ISSUER", 0x81 }, { "SERIAL_NUMBER", 0x82 }, { "TRUSTED", 0x86 },
    { "KEY_TYPE", 0x100 }, { "SUBJECT", 0x101 }, { "ID", 0x102 }, { "SENSITIVE", 0x103 },
    { "ENCRYPT", 0x104 }, { "DECRYPT", 0x105 }, { "WRAP", 0x106 }, { "UNWRAP", 0x107 },
    { "SIGN", 0x108 }, { "SIGN_RECOVER", 0x109 }, { "VERIFY", 0x10A },
    { "VERIFY_RECOVER", 0x10B }, { "DERIVE", 0x10C }, { "START_DATE", 0x110 },
    { "END_DATE", 0x111 }, { "MODULUS", 0x120 }, { "MODULUS_BITS", 0x121 },
    { "PUBLIC_EXPONENT", 0x122 }, { "VALUE_LEN", 0x161 }, { "EXTRACTABLE", 0x162 },
    { "LOCAL", 0x163 }, { "NEVER_EXTRACTABLE", 0x164 }, { "ALWAYS_SENSITIVE", 0x165 },
    { "KEY_GEN_MECHANISM", 0x166 }, { "MODIFIABLE", 0x170 }, { "COPYABLE", 0x171 },
    { "DESTROYABLE", 0x172 }, { "EC_PARAMS", 0x180 }, { "EC_POINT", 0x181 },
    { "ALWAYS_AUTH", 0x202 }, { "WRAP_WITH_TRUSTED", 0x210 }, { "WRAP_TEMPLATE", 0x40000211 },
    { "UNWRAP_TEMPLATE", 0x40000212 }, { "DERIVE_TEMPLATE", 0x40000213 },
    { "PARAMETER_SET", 0x61D }, { "ENCAPSULATE", 0x633 }, { "DECAPSULATE", 0x634 },
    { "ALLOWED_MECHANISMS", 0x40000600 }, { "UNKNOWN", 0x7FFFFFF0 },
};
#define NA (sizeof A / sizeof A[0])

#define SO_PIN   "so-pin-1234"
#define USER_PIN "user-pin-1234"
#define LABEL32  "objects                         "
static unsigned char T = 1, Fb = 0;
static UL c_data = 0, c_secret = 4, c_pub = 2, c_priv = 3, c_cert = 1;
static UL k_aes = 0x1f, k_gen = 0x10, k_ec = 3, k_mldsa = 0x4a;
static unsigned char p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static unsigned char key16[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
static unsigned char key32[32] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
                                   0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
                                   0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
                                   0x3e, 0x3f };
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

static UL create(UL h, const char *label, Attr *t, UL n) {
    UL o = 0xAAAAAAAAUL;
    UL rv = P11(C_CreateObject, h, t, n, &o);
    row(label, rv, o, NULL, 0, 0);
    return rv ? 0 : o;
}

/* Every attribute of object o, three ways: the size query, a 1-byte buffer, a fitting one. */
static void attrs(UL h, const char *name, UL o, int rnd) {
    char l[160];
    for (size_t i = 0; i < NA; ++i) {
        Attr a = { A[i].t, NULL, 0xAAAAUL };
        UL rv = P11(C_GetAttributeValue, h, o, &a, 1UL);
        snprintf(l, sizeof l, "%s %s size", name, A[i].n);
        row(l, rv, a.len, NULL, 0, 0);
        UL want = a.len;
        memset(buf, 0xAA, sizeof buf);
        a = (Attr){ A[i].t, buf, 1 };
        rv = P11(C_GetAttributeValue, h, o, &a, 1UL);
        snprintf(l, sizeof l, "%s %s 1", name, A[i].n);
        row(l, rv, a.len, buf, 1, rnd);
        if (want == (UL)-1 || want > sizeof buf) continue;
        memset(buf, 0xAA, sizeof buf);
        a = (Attr){ A[i].t, buf, sizeof buf };
        rv = P11(C_GetAttributeValue, h, o, &a, 1UL);
        snprintf(l, sizeof l, "%s %s get", name, A[i].n);
        if (rnd && A[i].t == 0x161 && !rv) { printf("%s\t0\t%#lx\trnd:len\n", l, a.len); continue; }
        row(l, rv, a.len, buf, a.len <= sizeof buf ? a.len : 0, rnd);
    }
    UL sz = 0xAAAAUL;
    snprintf(l, sizeof l, "%s size", name);
    UL rv = P11(C_GetObjectSize, h, o, &sz);
    row(l, rv, rnd && !rv ? 0 : sz, NULL, 0, 0);
}

/* Several attributes in one call: one fine, one sensitive or unknown, one too small. */
static void multi(UL h, const char *name, UL o) {
    unsigned char b1[64], b2[64], b3[1];
    memset(b1, 0xAA, sizeof b1); memset(b2, 0xAA, sizeof b2); memset(b3, 0xAA, sizeof b3);
    Attr t[] = { AB(0x3, b1, sizeof b1), AB(0x11, b2, sizeof b2), AB(0x7FFFFFF0, NULL, 0),
                 AB(0x0, b3, 1) };
    UL rv = P11(C_GetAttributeValue, h, o, t, 4UL);
    char l[160];
    snprintf(l, sizeof l, "%s multi", name);
    printf("%s\t%#lx\t%#lx,%#lx,%#lx,%#lx\t", l, rv, t[0].len, t[1].len, t[2].len, t[3].len);
    hex(b1, t[0].len <= 64 ? t[0].len : 0);
    printf("\n");
}

static UL gen_key(UL h, const char *label, UL mech, UL len) {
    Mech m = { mech, NULL, 0 };
    Attr t[] = { AT(0x161, len), AT(0x1, T), AT(0x104, T), AT(0x105, T), AT(0x162, T),
                 AT(0x103, Fb), AB(0x3, label, strlen(label)) };
    UL o = 0xAAAAAAAAUL, rv = P11(C_GenerateKey, h, &m, t, 7UL, &o);
    row(label, rv, o, NULL, 0, 0);
    return rv ? 0 : o;
}

static void gen_pair(UL h, const char *label, UL mech, Attr *pub, UL np, Attr *prv, UL nv,
                     UL *po, UL *vo) {
    Mech m = { mech, NULL, 0 };
    *po = *vo = 0xAAAAAAAAUL;
    UL rv = P11(C_GenerateKeyPair, h, &m, pub, np, prv, nv, po, vo);
    printf("%s\t%#lx\t%#lx,%#lx\t-\n", label, rv, *po, *vo);
    if (rv) *po = *vo = 0;
}

/* 0: every attribute of every kind of object, logged in as USER, then as SO and nobody. */
static void s_attrs(void) {
    UL h = setup();
    Attr d[] = { AT(0x0, c_data), AT(0x1, T), AB(0x3, "data", 4), AB(0x10, "app", 3),
                 AB(0x11, "payload", 7), AB(0x102, "\x01\x02", 2) };
    Attr aes[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AB(0x3, "aes", 3),
                   AT(0x11, key16), AT(0x103, Fb), AT(0x162, T), AT(0x104, T), AT(0x105, T) };
    Attr aes_s[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AB(0x3, "aes-s", 5),
                     AT(0x11, key32), AT(0x103, T), AT(0x162, Fb), AT(0x108, T),
                     AT(0x172, T), AT(0x170, Fb) };
    Attr gs[] = { AT(0x0, c_secret), AT(0x100, k_gen), AT(0x1, Fb), AB(0x3, "gen", 3),
                  AT(0x11, key32), AT(0x10C, T) };
    Attr ec_pub[] = { AT(0x0, c_pub), AT(0x100, k_ec), AT(0x1, T), AT(0x10A, T),
                      AT(0x180, p256), AB(0x3, "ecp", 3) };
    Attr ec_prv[] = { AT(0x0, c_priv), AT(0x100, k_ec), AT(0x1, T), AT(0x108, T),
                      AT(0x103, T), AB(0x3, "ecv", 3) };
    UL mldsa_set = 2;   /* CKP_ML_DSA_65 */
    Attr ml_pub[] = { AT(0x0, c_pub), AT(0x100, k_mldsa), AT(0x1, T), AT(0x10A, T),
                      AT(0x61D, mldsa_set), AB(0x3, "mlp", 3) };
    Attr ml_prv[] = { AT(0x0, c_priv), AT(0x100, k_mldsa), AT(0x1, T), AT(0x108, T),
                      AT(0x103, T), AB(0x3, "mlv", 3) };
    UL bits = 2048;
    unsigned char e3[] = { 1, 0, 1 };
    Attr rsa_pub[] = { AT(0x0, c_pub), AT(0x1, T), AT(0x121, bits), AT(0x122, e3),
                       AT(0x10A, T), AB(0x3, "rsap", 4) };
    Attr rsa_prv[] = { AT(0x0, c_priv), AT(0x1, T), AT(0x108, T), AT(0x103, T),
                       AB(0x3, "rsav", 4) };
    struct { const char *n; UL o; int rnd; } objs[12];
    int no = 0;
#define ADD(name, o_, r) do { UL o__ = (o_); if (o__) objs[no++] = (typeof(objs[0])){ name, o__, r }; } while (0)
    ADD("data", create(h, "create data", d, 6), 0);
    ADD("aes", create(h, "create aes", aes, 9), 0);
    ADD("aes-s", create(h, "create aes-s", aes_s, 10), 0);
    ADD("gen", create(h, "create gen", gs, 6), 0);
    ADD("aes-g", gen_key(h, "genkey aes", 0x1080, 32), 1);
    UL po, vo;
    gen_pair(h, "genpair ec", 0x1040, ec_pub, 6, ec_prv, 6, &po, &vo);
    ADD("ec-pub", po, 1);
    ADD("ec-prv", vo, 1);
    gen_pair(h, "genpair mldsa", 0x1C, ml_pub, 6, ml_prv, 6, &po, &vo);
    ADD("mldsa-pub", po, 1);
    ADD("mldsa-prv", vo, 1);
    gen_pair(h, "genpair rsa", 0x0, rsa_pub, 6, rsa_prv, 5, &po, &vo);
    ADD("rsa-pub", po, 1);
    ADD("rsa-prv", vo, 1);
    for (int i = 0; i < no; ++i) attrs(h, objs[i].n, objs[i].o, objs[i].rnd);
    for (int i = 0; i < no; ++i) multi(h, objs[i].n, objs[i].o);
    /* argument checks */
    Attr one = { 0x0, buf, 8 };
    row("get null template", P11(C_GetAttributeValue, h, objs[0].o, NULL, 1UL), 0, NULL, 0, 0);
    row("get count 0", P11(C_GetAttributeValue, h, objs[0].o, &one, 0UL), 0, NULL, 0, 0);
    row("get bad handle", P11(C_GetAttributeValue, h, 999UL, &one, 1UL), 0, NULL, 0, 0);
    row("get bad session", P11(C_GetAttributeValue, 99UL, objs[0].o, &one, 1UL), 0, NULL, 0, 0);
    row("size null out", P11(C_GetObjectSize, h, objs[0].o, NULL), 0, NULL, 0, 0);
    UL sz = 0xAAAA;
    row("size bad handle", P11(C_GetObjectSize, h, 999UL, &sz), sz, NULL, 0, 0);
    /* who sees what: SO, then nobody */
    row("logout user", P11(C_Logout, h), 0, NULL, 0, 0);
    for (int i = 0; i < no; ++i) {
        char l[80];
        snprintf(l, sizeof l, "nobody %s", objs[i].n);
        Attr c = { 0x0, buf, 8 };
        row(l, P11(C_GetAttributeValue, h, objs[i].o, &c, 1UL), c.len, NULL, 0, 0);
    }
    row("login so", P11(C_Login, h, 0UL, SO_PIN, (UL)strlen(SO_PIN)), 0, NULL, 0, 0);
    for (int i = 0; i < no; ++i) {
        char l[80];
        snprintf(l, sizeof l, "so %s", objs[i].n);
        Attr c = { 0x0, buf, 8 };
        row(l, P11(C_GetAttributeValue, h, objs[i].o, &c, 1UL), c.len, NULL, 0, 0);
    }
    P11(C_Finalize, NULL);
}

/* 1: C_CreateObject's template checks, one template per row. */
static void s_create(void) {
    UL h = setup(), ro = 0, bad = 99, zero = 0, ul2 = 0;
    unsigned char k15[15] = { 0 }, k24[24] = { 0 }, k33[33] = { 0 }, id33[33] = { 0 };
    unsigned char mechs[16] = { 0x81, 0x10, 0, 0, 0, 0, 0, 0 };   /* CKM_AES_ECB */
    unsigned short short_class = 4;
    char l65[65];
    memset(l65, 'x', sizeof l65);
    UL c3 = 3;
#define CR(label, ...) do { Attr t_[] = { __VA_ARGS__ }; create(h, label, t_, sizeof t_ / sizeof t_[0]); } while (0)
    CR("no class", AT(0x100, k_aes), AT(0x11, key16));
    CR("class short", AT(0x0, short_class), AT(0x100, k_aes), AT(0x11, key16));
    CR("class unknown", AT(0x0, bad), AT(0x11, key16));
    CR("secret no key type", AT(0x0, c_secret), AT(0x11, key16));
    CR("aes no value", AT(0x0, c_secret), AT(0x100, k_aes));
    CR("aes 15", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, k15));
    CR("aes 24", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, k24));
    CR("aes 33", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, k33));
    CR("aes value_len given", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AT(0x161, ul2));
    CR("key type unknown", AT(0x0, c_secret), AT(0x100, bad), AT(0x11, key16));
    CR("key type ec on secret", AT(0x0, c_secret), AT(0x100, k_ec), AT(0x11, key16));
    CR("class twice", AT(0x0, c_secret), AT(0x0, c_data), AT(0x100, k_aes), AT(0x11, key16));
    CR("null value with len", AT(0x0, c_secret), AT(0x100, k_aes), AB(0x11, NULL, 16));
    CR("bool len 2", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AB(0x1, "\x01\x01", 2));
    CR("bool value 2", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AB(0x1, "\x02", 1));
    CR("unknown attribute", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AB(0x7FFFFFF0, "x", 1));
    CR("label 65", AT(0x0, c_data), AT(0x11, key16), AB(0x3, l65, 65));
    CR("label 64", AT(0x0, c_data), AT(0x11, key16), AB(0x3, l65, 64));
    CR("id 33", AT(0x0, c_data), AT(0x11, key16), AT(0x102, id33));
    CR("id 32", AT(0x0, c_data), AT(0x11, key16), AB(0x102, id33, 32));
    CR("allowed mechs", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AB(0x40000600, mechs, 8));
    CR("allowed mechs len 7", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AB(0x40000600, mechs, 7));
    { Attr inner[] = { AT(0x108, T) };
      CR("wrap template", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AT(0x106, T),
         AB(0x40000211, inner, sizeof inner)); }
    CR("never_extractable given", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AT(0x164, T));
    CR("local given", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AT(0x163, T));
    CR("always_sensitive given", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AT(0x165, T));
    CR("private false on secret", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AT(0x2, Fb));
    CR("trusted", AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AT(0x86, T));
    CR("ec public bad point", AT(0x0, c_pub), AT(0x100, k_ec), AT(0x180, p256), AT(0x181, key16));
    CR("ec public no params", AT(0x0, c_pub), AT(0x100, k_ec), AT(0x181, key16));
    CR("ec private 32", AT(0x0, c_priv), AT(0x100, k_ec), AT(0x180, p256), AT(0x11, key32));
    CR("ec private 16", AT(0x0, c_priv), AT(0x100, k_ec), AT(0x180, p256), AT(0x11, key16));
    CR("mldsa private param 3 short", AT(0x0, c_priv), AT(0x100, k_mldsa), AT(0x61D, c3), AT(0x11, key32));
    CR("mldsa public no param", AT(0x0, c_pub), AT(0x100, k_mldsa), AT(0x11, key32));
    CR("cert", AT(0x0, c_cert), AT(0x80, zero), AT(0x11, key32), AB(0x101, "s", 1));
    CR("cert no type", AT(0x0, c_cert), AT(0x11, key32));
    CR("data empty", AT(0x0, c_data));
    { Attr t[] = { AT(0x0, c_data) };
      UL o = 0xAAAA;
      row("null out", P11(C_CreateObject, h, t, 1UL, NULL), o, NULL, 0, 0);
      row("null template", P11(C_CreateObject, h, NULL, 1UL, &o), o, NULL, 0, 0);
      row("count 0", P11(C_CreateObject, h, t, 0UL, &o), o, NULL, 0, 0);
      row("bad session", P11(C_CreateObject, 99UL, t, 1UL, &o), o, NULL, 0, 0); }
    /* a read-only session; then nobody logged in; then SO */
    P11(C_OpenSession, 0UL, 4UL, NULL, NULL, &ro);
    { Attr t[] = { AT(0x0, c_data), AT(0x1, T) }; create(ro, "ro token data", t, 2); }
    { Attr t[] = { AT(0x0, c_data), AT(0x1, Fb) }; create(ro, "ro session data", t, 2); }
    { Attr t[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16), AT(0x1, Fb) };
      create(ro, "ro session aes", t, 4); }
    P11(C_Logout, h);
    { Attr t[] = { AT(0x0, c_data), AT(0x1, T) }; create(h, "nobody token data", t, 2); }
    { Attr t[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16) };
      create(h, "nobody aes", t, 3); }
    row("close ro", P11(C_CloseSession, ro), 0, NULL, 0, 0);   /* an SO login needs none open */
    row("login so", P11(C_Login, h, 0UL, SO_PIN, (UL)strlen(SO_PIN)), 0, NULL, 0, 0);
    { Attr t[] = { AT(0x0, c_data), AT(0x1, T) }; create(h, "so token data", t, 2); }
    { Attr t[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x11, key16) };
      create(h, "so aes", t, 3); }
    P11(C_Finalize, NULL);
}

static void get1(UL h, const char *label, UL o, UL type) {
    memset(buf, 0xAA, 64);
    Attr a = { type, buf, 64 };
    UL rv = P11(C_GetAttributeValue, h, o, &a, 1UL);
    row(label, rv, a.len, buf, a.len <= 64 ? a.len : 0, 0);
}

/* 2: C_SetAttributeValue on every attribute, TRUE then FALSE (or a value), then read back. */
static void s_set(void) {
    UL h = setup(), ro = 0;
    Attr t[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AB(0x3, "set", 3),
                 AT(0x11, key16), AT(0x103, Fb), AT(0x162, T), AT(0x170, T) };
    UL o = create(h, "create modifiable", t, 8);
    char l[160];
    for (size_t i = 0; i < NA; ++i) {
        for (int v = 1; v >= 0; --v) {
            unsigned char b = (unsigned char)v;
            Attr a = { A[i].t, &b, 1 };
            snprintf(l, sizeof l, "set %s %d", A[i].n, v);
            row(l, P11(C_SetAttributeValue, h, o, &a, 1UL), 0, NULL, 0, 0);
            snprintf(l, sizeof l, "after set %s %d", A[i].n, v);
            get1(h, l, o, A[i].t);
        }
    }
    Attr lab = AB(0x3, "renamed", 7), id = AB(0x102, "\x09", 1), app = AB(0x10, "a", 1);
    row("set label", P11(C_SetAttributeValue, h, o, &lab, 1UL), 0, NULL, 0, 0);
    get1(h, "after set label", o, 0x3);
    row("set id", P11(C_SetAttributeValue, h, o, &id, 1UL), 0, NULL, 0, 0);
    get1(h, "after set id", o, 0x102);
    row("set application", P11(C_SetAttributeValue, h, o, &app, 1UL), 0, NULL, 0, 0);
    Attr two[] = { AB(0x3, "two", 3), AB(0x7FFFFFF0, "x", 1) };
    row("set label and unknown", P11(C_SetAttributeValue, h, o, two, 2UL), 0, NULL, 0, 0);
    get1(h, "after set label and unknown", o, 0x3);
    unsigned char yes = 1;
    Attr ab = { 0x104, &yes, 2 };
    row("set bool len 2", P11(C_SetAttributeValue, h, o, &ab, 1UL), 0, NULL, 0, 0);
    row("set null template", P11(C_SetAttributeValue, h, o, NULL, 1UL), 0, NULL, 0, 0);
    row("set count 0", P11(C_SetAttributeValue, h, o, &lab, 0UL), 0, NULL, 0, 0);
    row("set bad handle", P11(C_SetAttributeValue, h, 999UL, &lab, 1UL), 0, NULL, 0, 0);
    Attr t2[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AT(0x11, key16),
                  AT(0x170, Fb) };
    UL fixed = create(h, "create unmodifiable", t2, 5);
    row("set unmodifiable label", P11(C_SetAttributeValue, h, fixed, &lab, 1UL), 0, NULL, 0, 0);
    P11(C_OpenSession, 0UL, 4UL, NULL, NULL, &ro);
    row("set ro token object", P11(C_SetAttributeValue, ro, o, &lab, 1UL), 0, NULL, 0, 0);
    P11(C_Logout, h);
    row("set nobody", P11(C_SetAttributeValue, h, o, &lab, 1UL), 0, NULL, 0, 0);
    P11(C_Finalize, NULL);
}

/* 3: C_CopyObject: templates, then the copy's attributes. */
static void s_copy(void) {
    UL h = setup(), ro = 0;
    UL mech = 0x1081;
    Attr t[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AB(0x3, "src", 3),
                 AT(0x11, key16), AT(0x103, T), AT(0x162, Fb), AT(0x108, Fb), AT(0x104, T),
                 AT(0x171, T), AT(0x40000600, mech) };
    UL src = create(h, "create source", t, 11);
    Attr nc[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AT(0x11, key16),
                  AT(0x171, Fb) };
    UL nocopy = create(h, "create uncopyable", nc, 5);
    static const UL show[] = { 0x1, 0x3, 0x103, 0x104, 0x108, 0x162, 0x170, 0x171, 0x40000600 };
#define CP(label, from, ...) do { Attr t_[] = { __VA_ARGS__ }; UL o_ = 0xAAAA; \
        UL rv_ = P11(C_CopyObject, h, from, t_, sizeof t_ / sizeof t_[0], &o_); \
        row(label, rv_, o_, NULL, 0, 0); \
        if (!rv_) for (size_t i_ = 0; i_ < sizeof show / sizeof show[0]; ++i_) { \
            char l_[160]; snprintf(l_, sizeof l_, "%s attr %#lx", label, show[i_]); \
            get1(h, l_, o_, show[i_]); } } while (0)
    CP("copy plain", src, AB(0x3, "cp", 2));
    CP("copy session", src, AT(0x1, Fb));
    CP("copy sign true", src, AT(0x108, T));
    CP("copy encrypt false", src, AT(0x104, Fb));
    CP("copy sensitive false", src, AT(0x103, Fb));
    CP("copy extractable true", src, AT(0x162, T));
    CP("copy class", src, AT(0x0, c_data));
    CP("copy value", src, AT(0x11, key32));
    { UL wide[2] = { 0x1081, 0x1082 };
      CP("copy wider mechs", src, AB(0x40000600, wide, sizeof wide)); }
    { Attr inner[] = { AT(0x108, T) };
      CP("copy wrap template", src, AB(0x40000211, inner, sizeof inner)); }
    CP("copy uncopyable", nocopy, AB(0x3, "x", 1));
    CP("copy bad handle", 999UL, AB(0x3, "x", 1));
    { UL o = 0xAAAA;
      row("copy null out", P11(C_CopyObject, h, src, NULL, 0UL, NULL), o, NULL, 0, 0);
      row("copy null template count 1", P11(C_CopyObject, h, src, NULL, 1UL, &o), o, NULL, 0, 0);
      row("copy count 0", P11(C_CopyObject, h, src, NULL, 0UL, &o), o, NULL, 0, 0); }
    P11(C_OpenSession, 0UL, 4UL, NULL, NULL, &ro);
    { Attr t_[] = { AB(0x3, "r", 1) }; UL o = 0xAAAA;
      row("copy ro token inherited", P11(C_CopyObject, ro, src, t_, 1UL, &o), o, NULL, 0, 0); }
    { Attr t_[] = { AT(0x1, Fb) }; UL o = 0xAAAA;
      row("copy ro to session", P11(C_CopyObject, ro, src, t_, 1UL, &o), o, NULL, 0, 0); }
    P11(C_Logout, h);
    { Attr t_[] = { AT(0x1, Fb) }; UL o = 0xAAAA;
      row("copy nobody", P11(C_CopyObject, h, src, t_, 1UL, &o), o, NULL, 0, 0); }
    P11(C_Finalize, NULL);
}

static void find(UL h, const char *label, Attr *t, UL n, UL chunk) {
    UL rv = P11(C_FindObjectsInit, h, t, n);
    row(label, rv, 0, NULL, 0, 0);
    if (rv) return;
    UL hs[300], got = 0, total = 0;
    char l[160];
    do {
        got = 0xAAAA;
        rv = P11(C_FindObjects, h, hs + total, chunk, &got);
        if (rv || got > chunk) break;
        total += got;
    } while (got && total + chunk <= 300);
    snprintf(l, sizeof l, "%s found", label);
    printf("%s\t%#lx\t%#lx\t", l, rv, total);
    for (UL i = 0; i < total; ++i) printf("%s%lu", i ? "," : "", hs[i]);
    printf("%s\n", total ? "" : "-");
    snprintf(l, sizeof l, "%s final", label);
    row(l, P11(C_FindObjectsFinal, h), 0, NULL, 0, 0);
}

/* 4: C_FindObjects* filters and states. */
static void s_find(void) {
    UL h = setup(), ro = 0;
    for (int i = 0; i < 6; ++i) {
        char lab[8];
        snprintf(lab, sizeof lab, "o%d", i % 3);
        unsigned char id = (unsigned char)i;
        Attr d[] = { AT(0x0, c_data), AT(0x1, T), AB(0x3, lab, strlen(lab)), AB(0x102, &id, 1) };
        create(h, "create data", d, 4);
    }
    Attr aes[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AB(0x3, "o0", 2),
                   AT(0x11, key16) };
    create(h, "create aes", aes, 5);
    Attr ses[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, Fb), AB(0x3, "s", 1),
                   AT(0x11, key16) };
    create(h, "create session aes", ses, 5);
    find(h, "find all", NULL, 0, 100);
    find(h, "find all by 1", NULL, 0, 1);
    find(h, "find all by 3", NULL, 0, 3);
    { Attr t[] = { AT(0x0, c_data) }; find(h, "find data", t, 1, 100); }
    { Attr t[] = { AT(0x0, c_secret) }; find(h, "find secret", t, 1, 100); }
    { Attr t[] = { AB(0x3, "o0", 2) }; find(h, "find label o0", t, 1, 100); }
    { Attr t[] = { AB(0x3, "o", 1) }; find(h, "find label o", t, 1, 100); }
    { Attr t[] = { AB(0x3, "", 0) }; find(h, "find label empty", t, 1, 100); }
    { Attr t[] = { AT(0x0, c_data), AB(0x3, "o1", 2) }; find(h, "find data o1", t, 2, 100); }
    { unsigned char id = 4; Attr t[] = { AB(0x102, &id, 1) }; find(h, "find id 4", t, 1, 100); }
    { Attr t[] = { AB(0x102, "", 0) }; find(h, "find id empty", t, 1, 100); }
    { unsigned short c = 0; Attr t[] = { AT(0x0, c) }; find(h, "find class short", t, 1, 100); }
    { Attr t[] = { AT(0x1, Fb) }; find(h, "find token false", t, 1, 100); }
    { Attr t[] = { AT(0x100, k_aes) }; find(h, "find key type", t, 1, 100); }
    { Attr t[] = { AB(0x7FFFFFF0, "x", 1) }; find(h, "find unknown attribute", t, 1, 100); }
    { Attr t[] = { AB(0x3, NULL, 4) }; find(h, "find null value", t, 1, 100); }
    row("find null template count 1", P11(C_FindObjectsInit, h, NULL, 1UL), 0, NULL, 0, 0);
    row("find init", P11(C_FindObjectsInit, h, NULL, 0UL), 0, NULL, 0, 0);
    row("find init again", P11(C_FindObjectsInit, h, NULL, 0UL), 0, NULL, 0, 0);
    { UL hs[4], n = 0xAAAA;
      row("find max 0", P11(C_FindObjects, h, hs, 0UL, &n), n, NULL, 0, 0);
      row("find null out", P11(C_FindObjects, h, NULL, 4UL, &n), n, NULL, 0, 0);
      row("find null count", P11(C_FindObjects, h, hs, 4UL, NULL), 0, NULL, 0, 0); }
    row("find final", P11(C_FindObjectsFinal, h), 0, NULL, 0, 0);
    row("find final again", P11(C_FindObjectsFinal, h), 0, NULL, 0, 0);
    { UL hs[4], n = 0xAAAA;
      row("find without init", P11(C_FindObjects, h, hs, 4UL, &n), n, NULL, 0, 0); }
    row("find init bad session", P11(C_FindObjectsInit, 99UL, NULL, 0UL), 0, NULL, 0, 0);
    row("find final bad session", P11(C_FindObjectsFinal, 99UL), 0, NULL, 0, 0);
    P11(C_OpenSession, 0UL, 4UL, NULL, NULL, &ro);
    find(ro, "ro find all", NULL, 0, 100);
    P11(C_Logout, h);
    find(h, "nobody find all", NULL, 0, 100);
    row("close ro", P11(C_CloseSession, ro), 0, NULL, 0, 0);   /* an SO login needs none open */
    row("login so", P11(C_Login, h, 0UL, SO_PIN, (UL)strlen(SO_PIN)), 0, NULL, 0, 0);
    find(h, "so find all", NULL, 0, 100);
    P11(C_Finalize, NULL);
}

/* 5: C_DestroyObject. */
static void s_destroy(void) {
    UL h = setup(), ro = 0;
    Attr tok[] = { AT(0x0, c_data), AT(0x1, T), AB(0x3, "t", 1) };
    Attr ses[] = { AT(0x0, c_data), AT(0x1, Fb), AB(0x3, "s", 1) };
    Attr und[] = { AT(0x0, c_data), AT(0x1, T), AT(0x172, Fb) };
    Attr key[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AT(0x11, key16) };
    UL t1 = create(h, "create token", tok, 3), s1 = create(h, "create session", ses, 3);
    UL u1 = create(h, "create undestroyable", und, 3), k1 = create(h, "create key", key, 4);
    UL t2 = create(h, "create token 2", tok, 3);
    P11(C_OpenSession, 0UL, 4UL, NULL, NULL, &ro);
    row("ro destroy token", P11(C_DestroyObject, ro, t1), 0, NULL, 0, 0);
    row("ro destroy session", P11(C_DestroyObject, ro, s1), 0, NULL, 0, 0);
    row("destroy undestroyable", P11(C_DestroyObject, h, u1), 0, NULL, 0, 0);
    row("destroy token", P11(C_DestroyObject, h, t1), 0, NULL, 0, 0);
    row("destroy token again", P11(C_DestroyObject, h, t1), 0, NULL, 0, 0);
    row("destroy bad handle", P11(C_DestroyObject, h, 999UL), 0, NULL, 0, 0);
    row("destroy handle 0", P11(C_DestroyObject, h, 0UL), 0, NULL, 0, 0);
    row("destroy bad session", P11(C_DestroyObject, 99UL, t2), 0, NULL, 0, 0);
    P11(C_Logout, h);
    row("nobody destroy key", P11(C_DestroyObject, h, k1), 0, NULL, 0, 0);
    row("nobody destroy token data", P11(C_DestroyObject, h, t2), 0, NULL, 0, 0);
    row("close ro", P11(C_CloseSession, ro), 0, NULL, 0, 0);   /* an SO login needs none open */
    row("login so", P11(C_Login, h, 0UL, SO_PIN, (UL)strlen(SO_PIN)), 0, NULL, 0, 0);
    row("so destroy key", P11(C_DestroyObject, h, k1), 0, NULL, 0, 0);
    P11(C_Logout, h);
    P11(C_Login, h, 1UL, USER_PIN, (UL)strlen(USER_PIN));
    find(h, "find after destroys", NULL, 0, 100);
    P11(C_Finalize, NULL);
}

static void (*const S[])(void) = { s_attrs, s_create, s_set, s_copy, s_find, s_destroy };
static const char *const SN[] = { "attrs", "create", "set", "copy", "find", "destroy" };

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: p11_objects LIB BASE\n"); return 2; }
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
