/* p11_misc.c LIB BASE --- slice 8a of PHASE4_PLAN.md §6 item 10: the seven entry points left
 * in C apart from the accessors: C_GetMechanismList, C_GetMechanismInfo, C_GenerateRandom,
 * C_SeedRandom, C_WaitForSlotEvent, C_GetFunctionStatus and C_CancelFunction. One row per call:
 * "label TAB rv TAB n TAB out", n a count or length it wrote, out its output. Random bytes are
 * not printed, only whether they were written and differ, so C and hybrid must print the same
 * apart from recorded DIVs (harness step 4o).
 *
 * Each scenario runs in a forked child with its own tokens directory BASE/<n>.
 *
 * Written from the C (src/fhsm_pkcs11.c:573-658, 1540-1653, 2589-2596) before the Rust, as its
 * characterisation. */
#include <dlfcn.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

typedef unsigned long UL;
typedef UL (*F)();

static void *lib;
static char dir[600];

static F sym(const char *name) {
    F f = (F)dlsym(lib, name);
    if (!f) { fprintf(stderr, "no %s\n", name); exit(2); }
    return f;
}
#define P11(name, ...) sym(#name)(__VA_ARGS__)

static void row(const char *label, UL rv, UL n, const UL *p, UL plen) {
    printf("%s\t%#lx\t%#lx\t", label, rv, n);
    if (!p || !plen) printf("-");
    else for (UL i = 0; i < plen; ++i) printf("%s%lx", i ? "," : "", p[i]);
    printf("\n");
}
static void rv_row(const char *label, UL rv) { row(label, rv, 0, NULL, 0); }

#define SO_PIN   "so-pin-1234"
#define USER_PIN "user-pin-1234"
#define LABEL32  "misc                            "

/* A token initialised, the user PIN set; returns a RW session logged in as USER and, in *ro,
 * a read-only one. */
static UL setup(UL *ro) {
    UL h = 0, so = 0;
    if (P11(C_Initialize, NULL) || P11(C_InitToken, 0UL, SO_PIN, (UL)strlen(SO_PIN), LABEL32)
        || P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &so)
        || P11(C_Login, so, 0UL, SO_PIN, (UL)strlen(SO_PIN))
        || P11(C_InitPIN, so, USER_PIN, (UL)strlen(USER_PIN)) || P11(C_Logout, so)
        || P11(C_CloseSession, so) || P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h)
        || P11(C_Login, h, 1UL, USER_PIN, (UL)strlen(USER_PIN))
        || P11(C_OpenSession, 0UL, 4UL, NULL, NULL, ro)) {
        fprintf(stderr, "setup failed\n");
        exit(2);
    }
    return h;
}

static UL list[1024];

/* The mechanism list: its argument checks, the size query, a short and a fitting buffer. */
static UL mech_list(const char *l) {
    char s[160];
    UL n = 0xAAAA;
    snprintf(s, sizeof s, "%s list slot 1", l);
    UL rv = P11(C_GetMechanismList, 1UL, NULL, &n);
    row(s, rv, n, NULL, 0);
    snprintf(s, sizeof s, "%s list no count", l);
    rv_row(s, P11(C_GetMechanismList, 0UL, list, NULL));
    n = 0xAAAA;
    snprintf(s, sizeof s, "%s list size", l);
    rv = P11(C_GetMechanismList, 0UL, NULL, &n);
    row(s, rv, n, NULL, 0);
    UL want = n;
    memset(list, 0xAA, sizeof list);
    n = want ? want - 1 : 0;
    snprintf(s, sizeof s, "%s list short", l);
    rv = P11(C_GetMechanismList, 0UL, list, &n);
    row(s, rv, n, list, 1);
    memset(list, 0xAA, sizeof list);
    n = sizeof list / sizeof list[0];
    snprintf(s, sizeof s, "%s list get", l);
    rv = P11(C_GetMechanismList, 0UL, list, &n);
    row(s, rv, n, list, rv == 0 && n <= sizeof list / sizeof list[0] ? n : 0);
    return rv == 0 ? n : 0;
}

static void info(const char *l, UL slot, UL type) {
    UL in[3];
    memset(in, 0xAA, sizeof in);
    UL rv = P11(C_GetMechanismInfo, slot, type, in);
    row(l, rv, type, in, rv == 0 ? 3 : 0);
}

static void s_mechs(void) {
    UL ro = 0;
    (void)setup(&ro);
    UL n = mech_list("init");
    char s[160];
    info("info slot 1", 1UL, 0x250UL);
    rv_row("info no out", P11(C_GetMechanismInfo, 0UL, 0x250UL, NULL));
    for (UL i = 0; i < n; ++i) {
        snprintf(s, sizeof s, "info %#lx", list[i]);
        info(s, 0UL, list[i]);
    }
    /* Every type below 0x4400 the list left out: only its refusal, counted. */
    UL other = 0, inval = 0;
    for (UL t = 0; t < 0x4400; ++t) {
        int listed = 0;
        for (UL i = 0; i < n && !listed; ++i) listed = list[i] == t;
        if (listed) continue;
        UL in[3];
        UL rv = P11(C_GetMechanismInfo, 0UL, t, in);
        if (rv == 0x70) { ++inval; continue; }
        ++other;
        snprintf(s, sizeof s, "unlisted %#lx", t);
        rv_row(s, rv);
    }
    row("unlisted mechanism invalid", 0, inval, NULL, 0);
    row("unlisted other", 0, other, NULL, 0);
    info("info vendor unknown", 0UL, 0x8000FFFFUL);
    /* C narrows the type to 32 bits for the lookup, and RULE-014 compares it whole. */
    info("info narrowed 0x100000250", 0UL, 0x100000250UL);
    info("info narrowed 0x100000350", 0UL, 0x100000350UL);
    P11(C_Finalize, NULL);
    mech_list("finalized");
    info("finalized info", 0UL, 0x250UL);
}

/* Random bytes: written (no 0xAA byte left in 64 is 2^-512 by chance) and not repeated. */
static void s_random(void) {
    UL ro = 0;
    UL h = setup(&ro);
    unsigned char a[64], b[64];
    rv_row("random bad session", P11(C_GenerateRandom, 0x7777UL, a, 16UL));
    rv_row("random null", P11(C_GenerateRandom, h, NULL, 16UL));
    rv_row("random zero", P11(C_GenerateRandom, h, a, 0UL));
    memset(a, 0xAA, sizeof a);
    memset(b, 0xAA, sizeof b);
    UL ra = P11(C_GenerateRandom, h, a, (UL)sizeof a);
    UL rb = P11(C_GenerateRandom, ro, b, (UL)sizeof b);
    int wa = 0, wb = 0;
    for (size_t i = 0; i < sizeof a; ++i) { wa += a[i] != 0xAA; wb += b[i] != 0xAA; }
    row("random rw", ra, wa > 0, NULL, 0);
    row("random ro", rb, wb > 0, NULL, 0);
    row("random differ", 0, memcmp(a, b, sizeof a) != 0, NULL, 0);
    // A random byte is 0xAA one time in 256; four draws make a false failure 2^-32.
    for (int k = 0; k < 4; ++k) {
        memset(a, 0xAA, sizeof a);
        ra = P11(C_GenerateRandom, h, a, 1UL);
        if (ra != 0 || a[0] != 0xAA) break;
    }
    row("random 1", ra, a[0] != 0xAA && a[1] == 0xAA, NULL, 0);
    rv_row("seed bad session", P11(C_SeedRandom, 0x7777UL, a, 16UL));
    rv_row("seed null", P11(C_SeedRandom, h, NULL, 16UL));
    rv_row("seed zero", P11(C_SeedRandom, h, a, 0UL));
    rv_row("seed", P11(C_SeedRandom, h, a, 16UL));
    rv_row("seed ro", P11(C_SeedRandom, ro, a, 16UL));
    P11(C_CloseSession, ro);
    rv_row("random closed", P11(C_GenerateRandom, ro, a, 16UL));
    rv_row("seed closed", P11(C_SeedRandom, ro, a, 16UL));
    P11(C_Finalize, NULL);
    rv_row("random finalized", P11(C_GenerateRandom, h, a, 16UL));
    rv_row("seed finalized", P11(C_SeedRandom, h, a, 16UL));
}

static void s_stubs(void) {
    UL ro = 0;
    UL h = setup(&ro);
    UL slot = 0xAAAA;
    UL rv;
    rv = P11(C_WaitForSlotEvent, 1UL, &slot, (void *)&slot);
    row("wait reserved", rv, slot, NULL, 0);
    rv = P11(C_WaitForSlotEvent, 1UL, &slot, NULL);
    row("wait dont block", rv, slot, NULL, 0);
    rv = P11(C_WaitForSlotEvent, 0UL, &slot, NULL);
    row("wait block", rv, slot, NULL, 0);
    row("wait null slot", P11(C_WaitForSlotEvent, 1UL, NULL, NULL), 0, NULL, 0);
    rv_row("status bad session", P11(C_GetFunctionStatus, 0x7777UL));
    rv_row("status", P11(C_GetFunctionStatus, h));
    rv_row("status ro", P11(C_GetFunctionStatus, ro));
    rv_row("cancel bad session", P11(C_CancelFunction, 0x7777UL));
    rv_row("cancel", P11(C_CancelFunction, h));
    rv_row("cancel ro", P11(C_CancelFunction, ro));
    P11(C_Finalize, NULL);
    rv_row("wait finalized", P11(C_WaitForSlotEvent, 1UL, &slot, NULL));
    rv_row("status finalized", P11(C_GetFunctionStatus, h));
    rv_row("cancel finalized", P11(C_CancelFunction, h));
}

/* FHSM_AUDIT=off latches ERROR at C_Initialize (no session can open, so handle 1). */
static void s_error(void) {
    setenv("FHSM_AUDIT", "off", 1);
    rv_row("initialize audit off", P11(C_Initialize, NULL));
    mech_list("error");
    info("error info", 0UL, 0x250UL);
    unsigned char a[16];
    UL slot = 0xAAAA;
    rv_row("error random", P11(C_GenerateRandom, 1UL, a, 16UL));
    rv_row("error seed", P11(C_SeedRandom, 1UL, a, 16UL));
    rv_row("error wait", P11(C_WaitForSlotEvent, 1UL, &slot, NULL));
    rv_row("error status", P11(C_GetFunctionStatus, 1UL));
    rv_row("error cancel", P11(C_CancelFunction, 1UL));
    P11(C_Finalize, NULL);
}

/* Slice 6c review L6: RSA PKCS#1 v1.5 and X.509 wrap and unwrap, which only an all-mechanisms
 * build serves (step 4p; the strict build refuses each, step 4o). The bounds: a key within 11
 * bytes of the modulus (v1.5) or longer than it (X.509), X.509's 1024-byte modulus cap, its
 * zero strip at unwrap, a blob that is not modulus-sized. A v1.5 blob is random, so only its
 * length prints; an X.509 blob and every unwrapped value print whole. The key is the fixed
 * RSA-2048 key of p11_keys.c (rsa_fixed). */
typedef struct { unsigned char p[1100]; int n; } Blob;
static void bn(const BIGNUM *x, Blob *b) { b->n = BN_bn2bin(x, b->p); }
/* The first prime from a fixed start of `len` bytes, top two bits set. */
static void prime_len(unsigned char s, int len, BIGNUM *p, BN_CTX *x) {
    unsigned char b[128];
    for (int i = 0; i < len; ++i) b[i] = (unsigned char)(s * 31 + i * 7);
    b[0] |= 0xC0, b[len - 1] |= 1;
    BN_bin2bn(b, len, p);
    while (BN_check_prime(p, x, NULL) != 1) BN_add_word(p, 2);
}
static Blob rn, re, rd, rp, rq, rdp, rdq, rqi;
static void rsa_fixed(void) {
    BN_CTX *x = BN_CTX_new();
    BIGNUM *p = BN_new(), *q = BN_new(), *n = BN_new(), *e = BN_new(), *d = BN_new(),
           *p1 = BN_new(), *q1 = BN_new(), *phi = BN_new(), *dp = BN_new(), *dq = BN_new(),
           *qi = BN_new();
    prime_len(1, 128, p, x), prime_len(2, 128, q, x);
    BN_mul(n, p, q, x), BN_set_word(e, 65537);
    BN_sub(p1, p, BN_value_one()), BN_sub(q1, q, BN_value_one()), BN_mul(phi, p1, q1, x);
    if (!BN_mod_inverse(d, e, phi, x) || !BN_mod_inverse(qi, q, p, x)) exit(2);
    BN_mod(dp, d, p1, x), BN_mod(dq, d, q1, x);
    bn(n, &rn), bn(e, &re), bn(d, &rd), bn(p, &rp), bn(q, &rq), bn(dp, &rdp), bn(dq, &rdq);
    bn(qi, &rqi);
}
typedef struct { UL type; const void *p; UL len; } Attr;
static void hex_row(const char *label, UL rv, UL n, const unsigned char *p, UL plen) {
    printf("%s\t%#lx\t%#lx\t", label, rv, n);
    if (!p || !plen) printf("-");
    for (UL i = 0; p && i < plen; ++i) printf("%02x", p[i]);
    printf("\n");
}
static UL mk(UL h, Attr *t, UL n) {
    UL o = 0;
    UL rv = P11(C_CreateObject, h, t, n, &o);
    return rv ? (UL)-1 : o;
}
static const unsigned char T = 1, Fa = 0;
static const UL c_sec = 4, c_pub = 2, c_prv = 3, k_gen = 0x10, k_rsa = 0;
/* A generic secret of `len` bytes, byte i = i + `first` (so `first` 0 starts on a zero). */
static UL secret(UL h, UL len, unsigned first) {
    unsigned char v[300];
    for (UL i = 0; i < len; ++i) v[i] = (unsigned char)(i + first);
    Attr t[] = { { 0x0, &c_sec, sizeof c_sec }, { 0x100, &k_gen, sizeof k_gen },
                 { 0x11, v, len }, { 0x162, &T, 1 } };
    return mk(h, t, 4);
}
/* Unwraps `blob` as an extractable, non-sensitive generic secret; prints the rv and the value. */
static void unwrap(UL h, const char *label, UL mech, UL key, const unsigned char *blob, UL n) {
    struct { UL m; void *p; UL len; } m = { mech, NULL, 0 };
    Attr t[] = { { 0x0, &c_sec, sizeof c_sec }, { 0x100, &k_gen, sizeof k_gen },
                 { 0x103, &Fa, 1 }, { 0x162, &T, 1 } };
    UL o = 0;
    UL rv = P11(C_UnwrapKey, h, &m, key, blob, n, t, 4UL, &o);
    unsigned char v[1100];
    Attr a = { 0x11, v, sizeof v };
    if (rv || P11(C_GetAttributeValue, h, o, &a, 1UL)) a.len = 0;
    hex_row(label, rv, a.len, v, a.len);
}
/* Wraps `key`; prints the rv, the length and (X.509 only) the blob, which `out` keeps. */
static UL wrap(UL h, const char *label, UL mech, UL wk, UL key, UL cap, unsigned char *out) {
    struct { UL m; void *p; UL len; } m = { mech, NULL, 0 };
    UL n = cap;
    UL rv = P11(C_WrapKey, h, &m, wk, key, out, &n);
    hex_row(label, rv, n, mech == 3 && out ? out : NULL, rv == 0 && out ? n : 0);
    return rv ? 0 : n;
}
static void s_rsawrap(void) {
    UL ro;
    UL h = setup(&ro);
    rsa_fixed();
    Attr pub[] = { { 0x0, &c_pub, sizeof c_pub }, { 0x100, &k_rsa, sizeof k_rsa },
                   { 0x120, rn.p, (UL)rn.n }, { 0x122, re.p, (UL)re.n }, { 0x106, &T, 1 } };
    Attr prv[] = { { 0x0, &c_prv, sizeof c_prv }, { 0x100, &k_rsa, sizeof k_rsa },
                   { 0x120, rn.p, (UL)rn.n }, { 0x122, re.p, (UL)re.n }, { 0x123, rd.p, (UL)rd.n },
                   { 0x124, rp.p, (UL)rp.n }, { 0x125, rq.p, (UL)rq.n }, { 0x126, rdp.p, (UL)rdp.n },
                   { 0x127, rdq.p, (UL)rdq.n }, { 0x128, rqi.p, (UL)rqi.n }, { 0x107, &T, 1 } };
    UL wk = mk(h, pub, 5), uk = mk(h, prv, 11);
    row("rsawrap keys", wk == (UL)-1 || uk == (UL)-1, 0, NULL, 0);
    unsigned char b[1100], junk[257];
    for (int i = 0; i < 257; ++i) junk[i] = (unsigned char)(i + 1);
    static const UL mechs[] = { 1, 3 };
    for (int i = 0; i < 2; ++i) {
        UL m = mechs[i];
        char l[64];
        const char *mn = m == 1 ? "v1.5" : "x509";
#define L(s) (snprintf(l, sizeof l, "%s %s", mn, s), l)
        UL k16 = secret(h, 16, 1), n;
        wrap(h, L("size query"), m, wk, k16, 0, NULL);
        wrap(h, L("short buffer"), m, wk, k16, 255, b);
        if ((n = wrap(h, L("wrap 16"), m, wk, k16, sizeof b, b))) unwrap(h, L("unwrap 16"), m, uk, b, n);
        /* v1.5: 245 = 256 - 11 fits, 246 does not; X.509: 256 fits, 257 does not */
        UL fit = m == 1 ? 245 : 256;
        if ((n = wrap(h, L("wrap longest"), m, wk, secret(h, fit, 1), sizeof b, b)))
            unwrap(h, L("unwrap longest"), m, uk, b, n);
        wrap(h, L("wrap one over"), m, wk, secret(h, fit + 1, 1), sizeof b, b);
        /* leading zeros: X.509 cannot tell them from its padding */
        if ((n = wrap(h, L("wrap zero-led"), m, wk, secret(h, 16, 0), sizeof b, b)))
            unwrap(h, L("unwrap zero-led"), m, uk, b, n);
        wrap(h, L("wrap under the private key"), m, uk, k16, sizeof b, b);
        unwrap(h, L("unwrap under the public key"), m, wk, junk, 256);
        unwrap(h, L("unwrap 255 bytes"), m, uk, junk, 255);
        unwrap(h, L("unwrap 257 bytes"), m, uk, junk, 257);
        unwrap(h, L("unwrap junk"), m, uk, junk, 256);
#undef L
    }
    /* X.509's cap: a modulus past 1024 bytes, the product of 33 distinct 256-bit primes (8448
     * bits; it passes the public check DIV-065 added, which a made-up modulus does not) */
    Blob big;
    {
        BN_CTX *x = BN_CTX_new();
        BIGNUM *n = BN_new(), *p = BN_new();
        BN_one(n);
        for (int i = 0; i < 33; ++i) prime_len((unsigned char)(i + 10), 32, p, x), BN_mul(n, n, p, x);
        bn(n, &big);
    }
    Attr bp[] = { { 0x0, &c_pub, sizeof c_pub }, { 0x100, &k_rsa, sizeof k_rsa },
                  { 0x120, big.p, (UL)big.n }, { 0x122, re.p, (UL)re.n }, { 0x106, &T, 1 } };
    UL bk = mk(h, bp, 5);
    row("x509 big modulus key", bk == (UL)-1, 0, NULL, 0);
    if (bk != (UL)-1) {
        UL k16 = secret(h, 16, 1);
        wrap(h, "x509 big size query", 3, bk, k16, 0, NULL);
        wrap(h, "x509 big wrap", 3, bk, k16, sizeof b, b);
        wrap(h, "v1.5 big wrap", 1, bk, k16, sizeof b, b);
    }
    P11(C_Finalize, NULL);
}

static void (*const S[])(void) = { s_mechs, s_random, s_stubs, s_error, s_rsawrap };
static const char *const SN[] = { "mechanisms", "random", "stubs", "error", "rsa wrap" };

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: p11_misc LIB BASE\n"); return 2; }
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
