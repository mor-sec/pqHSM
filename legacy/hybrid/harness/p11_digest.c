/* p11_digest.c LIB BASE --- slice 3 of PHASE4_PLAN.md §2: call sequences through the five
 * digest entry points (C_DigestInit, C_Digest, C_DigestUpdate, C_DigestKey, C_DigestFinal),
 * one row per call: "label TAB rv TAB n TAB hex", n the length it wrote, hex the output
 * (pre-filled with 0xAA). Every byte is deterministic, so C and hybrid must print the same
 * apart from recorded DIVs (harness step 4k).
 *
 * Each scenario runs in a forked child with its own tokens directory BASE/<n>.
 *
 * Written from the C (src/fhsm_pkcs11.c:2644-2735, 11932-12067) before the Rust, as its
 * characterisation. */
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
static unsigned char buf[256];

static F sym(const char *name) {
    F f = (F)dlsym(lib, name);
    if (!f) { fprintf(stderr, "no %s\n", name); exit(2); }
    return f;
}
#define P11(name, ...) sym(#name)(__VA_ARGS__)

static void row(const char *label, UL rv, UL n, const unsigned char *p, UL plen) {
    printf("%s\t%#lx\t%#lx\t", label, rv, n);
    if (!p || !plen) printf("-");
    else for (UL i = 0; i < plen; ++i) printf("%02x", p[i]);
    printf("\n");
}
static void rv_row(const char *label, UL rv) { row(label, rv, 0, NULL, 0); }

/* Every digest C_DigestInit knows, two it does not (an HMAC and RSA), and MD5 and SHA-1. */
static const struct { const char *n; UL m; } M[] = {
    { "SHA256", 0x250 }, { "SHA384", 0x260 }, { "SHA512", 0x270 }, { "SHA224", 0x255 },
    { "SHA512_224", 0x48 }, { "SHA512_256", 0x4C }, { "SHA3_224", 0x2B5 },
    { "SHA3_256", 0x2B0 }, { "SHA3_384", 0x2C0 }, { "SHA3_512", 0x2D0 }, { "SHA_1", 0x220 },
    { "MD5", 0x210 }, { "SHA256_HMAC", 0x251 }, { "RSA_PKCS", 0x1 },
};
#define NM (sizeof M / sizeof M[0])

#define SO_PIN   "so-pin-1234"
#define USER_PIN "user-pin-1234"
#define LABEL32  "digest                          "
static unsigned char T = 1, Fb = 0;
static UL c_data = 0, c_secret = 4, k_aes = 0x1f;
static unsigned char key16[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
static Mech sha256 = { 0x250, NULL, 0 };
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

/* C_Digest, three ways: the size query, a 1-byte buffer, a fitting one. */
static void oneshot(const char *l, UL h, const void *d, UL n) {
    char s[160];
    UL len = 0xAAAA;
    snprintf(s, sizeof s, "%s size", l);
    row(s, P11(C_Digest, h, d, n, NULL, &len), len, NULL, 0);
    memset(buf, 0xAA, sizeof buf);
    len = 1;
    snprintf(s, sizeof s, "%s 1", l);
    row(s, P11(C_Digest, h, d, n, buf, &len), len, buf, 1);
    memset(buf, 0xAA, sizeof buf);
    len = sizeof buf;
    snprintf(s, sizeof s, "%s get", l);
    UL rv = P11(C_Digest, h, d, n, buf, &len);
    row(s, rv, len, buf, len <= sizeof buf ? len : 0);
}

/* C_DigestFinal, the same three ways. */
static void final3(const char *l, UL h) {
    char s[160];
    UL len = 0xAAAA;
    snprintf(s, sizeof s, "%s final size", l);
    row(s, P11(C_DigestFinal, h, NULL, &len), len, NULL, 0);
    memset(buf, 0xAA, sizeof buf);
    len = 1;
    snprintf(s, sizeof s, "%s final 1", l);
    row(s, P11(C_DigestFinal, h, buf, &len), len, buf, 1);
    memset(buf, 0xAA, sizeof buf);
    len = sizeof buf;
    snprintf(s, sizeof s, "%s final get", l);
    UL rv = P11(C_DigestFinal, h, buf, &len);
    row(s, rv, len, buf, len <= sizeof buf ? len : 0);
}

static UL create(UL h, const char *label, Attr *t, UL n) {
    UL o = 0xAAAAAAAAUL;
    UL rv = P11(C_CreateObject, h, t, n, &o);
    row(label, rv, o, NULL, 0);
    return rv ? 0 : o;
}

/* 0: C_DigestInit's checks in order, then every mechanism one-shot and in parts. */
static void s_mechs(void) {
    UL h = setup();
    char l[160];
    rv_row("init session 0", P11(C_DigestInit, 0UL, &sha256));
    rv_row("init session 999", P11(C_DigestInit, 999UL, &sha256));
    rv_row("init session 50", P11(C_DigestInit, 50UL, &sha256));
    rv_row("init NULL mech", P11(C_DigestInit, h, NULL));
    Mech p = { 0x250, buf, 0 }, pl = { 0x250, NULL, 4 };
    rv_row("init param ptr", P11(C_DigestInit, h, &p));
    rv_row("init param len", P11(C_DigestInit, h, &pl));
    for (size_t i = 0; i < NM; ++i) {
        Mech m = { M[i].m, NULL, 0 };
        snprintf(l, sizeof l, "%s init", M[i].n);
        UL rv = P11(C_DigestInit, h, &m);
        rv_row(l, rv);
        if (rv) continue;
        snprintf(l, sizeof l, "%s init again", M[i].n);
        rv_row(l, P11(C_DigestInit, h, &m));
        snprintf(l, sizeof l, "%s abc", M[i].n);
        oneshot(l, h, "abc", 3);
        snprintf(l, sizeof l, "%s after", M[i].n);
        UL len = sizeof buf;
        rv_row(l, P11(C_Digest, h, "abc", 3UL, buf, &len));
        snprintf(l, sizeof l, "%s parts init", M[i].n);
        rv_row(l, P11(C_DigestInit, h, &m));
        snprintf(l, sizeof l, "%s update ab", M[i].n);
        rv_row(l, P11(C_DigestUpdate, h, "ab", 2UL));
        snprintf(l, sizeof l, "%s update c", M[i].n);
        rv_row(l, P11(C_DigestUpdate, h, "c", 1UL));
        snprintf(l, sizeof l, "%s update empty", M[i].n);
        rv_row(l, P11(C_DigestUpdate, h, NULL, 0UL));
        snprintf(l, sizeof l, "%s abc", M[i].n);
        final3(l, h);
        snprintf(l, sizeof l, "%s empty init", M[i].n);
        rv_row(l, P11(C_DigestInit, h, &m));
        snprintf(l, sizeof l, "%s empty", M[i].n);
        final3(l, h);
    }
}

/* 1: C_Digest's and C_DigestUpdate's argument checks, and which of them end the operation. */
static void s_args(void) {
    UL h = setup();
    UL len = sizeof buf;
    rv_row("digest not init", P11(C_Digest, h, "abc", 3UL, buf, &len));
    rv_row("digest session 0", P11(C_Digest, 0UL, "abc", 3UL, buf, &len));
    rv_row("digest session 999", P11(C_Digest, 999UL, "abc", 3UL, buf, &len));
    rv_row("digest NULL len, no op", P11(C_Digest, h, "abc", 3UL, buf, NULL));
    rv_row("update not init", P11(C_DigestUpdate, h, "abc", 3UL));
    rv_row("update session 999", P11(C_DigestUpdate, 999UL, "abc", 3UL));
    len = sizeof buf;
    rv_row("final not init", P11(C_DigestFinal, h, buf, &len));
    rv_row("final NULL len, no op", P11(C_DigestFinal, h, buf, NULL));
    rv_row("key not init", P11(C_DigestKey, h, 1UL));

    rv_row("init", P11(C_DigestInit, h, &sha256));
    rv_row("digest NULL len", P11(C_Digest, h, "abc", 3UL, buf, NULL));
    oneshot("still active", h, "abc", 3);

    rv_row("init", P11(C_DigestInit, h, &sha256));
    len = sizeof buf;
    rv_row("digest NULL data", P11(C_Digest, h, NULL, 3UL, buf, &len));
    rv_row("init after NULL data", P11(C_DigestInit, h, &sha256));
    oneshot("NULL empty", h, NULL, 0);

    rv_row("init", P11(C_DigestInit, h, &sha256));
    len = sizeof buf;
    rv_row("digest 2^31", P11(C_Digest, h, buf, 0x80000000UL, buf, &len));
    rv_row("init after 2^31", P11(C_DigestInit, h, &sha256));
    len = sizeof buf;
    rv_row("digest 2^31-1 NULL", P11(C_Digest, h, NULL, 0x7FFFFFFFUL, buf, &len));

    rv_row("init", P11(C_DigestInit, h, &sha256));
    rv_row("update NULL data", P11(C_DigestUpdate, h, NULL, 3UL));
    rv_row("update after NULL", P11(C_DigestUpdate, h, "abc", 3UL));
    rv_row("init", P11(C_DigestInit, h, &sha256));
    rv_row("update abc", P11(C_DigestUpdate, h, "abc", 3UL));
    rv_row("update 2^31", P11(C_DigestUpdate, h, buf, 0x80000000UL));
    len = sizeof buf;
    rv_row("final after 2^31", P11(C_DigestFinal, h, buf, &len));
    /* The context the failed update released is not the next operation's. */
    rv_row("init", P11(C_DigestInit, h, &sha256));
    rv_row("update x", P11(C_DigestUpdate, h, "x", 1UL));
    final3("fresh x", h);

    rv_row("init", P11(C_DigestInit, h, &sha256));
    rv_row("update ab", P11(C_DigestUpdate, h, "ab", 2UL));
    rv_row("final NULL len", P11(C_DigestFinal, h, buf, NULL));
    rv_row("update c", P11(C_DigestUpdate, h, "c", 1UL));
    final3("abc after NULL len", h);

    /* One-shot after parts: C hashes only C_Digest's data. */
    rv_row("init", P11(C_DigestInit, h, &sha256));
    rv_row("update zz", P11(C_DigestUpdate, h, "zz", 2UL));
    oneshot("abc after update", h, "abc", 3);
    rv_row("init", P11(C_DigestInit, h, &sha256));
    rv_row("update q", P11(C_DigestUpdate, h, "q", 1UL));
    final3("q", h);
    /* Init over a context an abandoned operation left (one-shot ended it, parts ran first). */
    rv_row("init", P11(C_DigestInit, h, &sha256));
    rv_row("update zz", P11(C_DigestUpdate, h, "zz", 2UL));
    len = sizeof buf;
    rv_row("digest ends it", P11(C_Digest, h, "abc", 3UL, buf, &len));
    rv_row("init", P11(C_DigestInit, h, &sha256));
    final3("empty after abandoned", h);
}

/* 2: C_DigestKey: which keys it takes, in what order it refuses, and mixed with data. */
static void s_key(void) {
    UL h = setup();
    UL sha = 0x250, sha512 = 0x270;
    Attr aes[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AB(0x3, "aes", 3),
                   AT(0x11, key16), AT(0x103, Fb), AT(0x162, T), AT(0x104, T) };
    Attr aes_s[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AB(0x3, "aes-s", 5),
                     AT(0x11, key16), AT(0x103, T), AT(0x104, T) };
    Attr aes_pub[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AT(0x2, Fb),
                       AB(0x3, "aes-pub", 7), AT(0x11, key16), AT(0x103, Fb) };
    Attr aes_sess[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, Fb), AB(0x3, "aes-ss", 6),
                        AT(0x11, key16), AT(0x103, Fb) };
    Attr aes_al[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AB(0x3, "aes-al", 6),
                      AT(0x11, key16), AT(0x103, Fb), AT(0x40000600, sha512) };
    Attr aes_ok[] = { AT(0x0, c_secret), AT(0x100, k_aes), AT(0x1, T), AB(0x3, "aes-ok", 6),
                      AT(0x11, key16), AT(0x103, Fb), AT(0x40000600, sha) };
    Attr d[] = { AT(0x0, c_data), AT(0x1, T), AB(0x3, "data", 4), AB(0x11, "payload", 7) };
    UL k = create(h, "create aes", aes, 8), ks = create(h, "create aes sensitive", aes_s, 7);
    UL kp = create(h, "create aes public", aes_pub, 7);
    UL kss = create(h, "create aes session", aes_sess, 6);
    UL kal = create(h, "create aes allowed SHA512", aes_al, 7);
    UL kok = create(h, "create aes allowed SHA256", aes_ok, 7);
    UL dd = create(h, "create data", d, 4);
    struct { const char *n; UL o; } K[] = {
        { "aes", k }, { "sensitive", ks }, { "public", kp }, { "session", kss },
        { "allowed SHA512", kal }, { "allowed SHA256", kok }, { "data", dd },
        { "unknown", 0x7777 }, { "handle 0", 0 },
    };
    char l[160];
    for (size_t i = 0; i < sizeof K / sizeof K[0]; ++i) {
        rv_row("init", P11(C_DigestInit, h, &sha256));
        snprintf(l, sizeof l, "key %s", K[i].n);
        rv_row(l, P11(C_DigestKey, h, K[i].o));
        snprintf(l, sizeof l, "key %s", K[i].n);
        final3(l, h);
    }
    /* Data, key, data: one stream. Then the key alone under SHA-512. */
    rv_row("init", P11(C_DigestInit, h, &sha256));
    rv_row("update ab", P11(C_DigestUpdate, h, "ab", 2UL));
    rv_row("key aes", P11(C_DigestKey, h, k));
    rv_row("update c", P11(C_DigestUpdate, h, "c", 1UL));
    final3("ab key c", h);
    Mech m512 = { 0x270, NULL, 0 };
    rv_row("init SHA512", P11(C_DigestInit, h, &m512));
    rv_row("key allowed SHA512", P11(C_DigestKey, h, kal));
    rv_row("key aes", P11(C_DigestKey, h, k));
    final3("SHA512 two keys", h);
    /* Logged out: the private key is out of sight, the public one is not. */
    rv_row("logout", P11(C_Logout, h));
    for (int i = 0; i < 3; ++i) {
        UL o = i == 0 ? k : i == 1 ? kp : ks;
        const char *n = i == 0 ? "aes" : i == 1 ? "public" : "sensitive";
        rv_row("init", P11(C_DigestInit, h, &sha256));
        snprintf(l, sizeof l, "logged out key %s", n);
        rv_row(l, P11(C_DigestKey, h, o));
        snprintf(l, sizeof l, "logged out key %s", n);
        final3(l, h);
    }
    /* A second session's key, and a key digested from another session. */
    UL h2 = 0;
    rv_row("open second", P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h2));
    rv_row("login", P11(C_Login, h, 1UL, USER_PIN, (UL)strlen(USER_PIN)));
    rv_row("init second", P11(C_DigestInit, h2, &sha256));
    rv_row("second: key session", P11(C_DigestKey, h2, kss));
    final3("second: key session", h2);
}

/* 3: operations across session and module lifetimes: two sessions at once, a closed and
 * reused handle, context login, logout, finalize and a fork. */
static void s_life(void) {
    UL h = setup(), h2 = 0, len;
    Mech m384 = { 0x260, NULL, 0 };
    rv_row("open second", P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h2));
    rv_row("init 1 SHA256", P11(C_DigestInit, h, &sha256));
    rv_row("init 2 SHA384", P11(C_DigestInit, h2, &m384));
    rv_row("update 1 a", P11(C_DigestUpdate, h, "a", 1UL));
    rv_row("update 2 b", P11(C_DigestUpdate, h2, "b", 1UL));
    rv_row("update 1 bc", P11(C_DigestUpdate, h, "bc", 2UL));
    final3("2 b", h2);
    final3("1 abc", h);

    /* CKU_CONTEXT_SPECIFIC needs an active operation; a digest is one. */
    rv_row("context login, none", P11(C_Login, h, 2UL, USER_PIN, (UL)strlen(USER_PIN)));
    rv_row("init", P11(C_DigestInit, h, &sha256));
    rv_row("context login, digest", P11(C_Login, h, 2UL, USER_PIN, (UL)strlen(USER_PIN)));
    rv_row("context login, bad pin", P11(C_Login, h, 2UL, "nope", 4UL));
    rv_row("update after context login", P11(C_DigestUpdate, h, "abc", 3UL));
    rv_row("logout", P11(C_Logout, h));
    rv_row("update after logout", P11(C_DigestUpdate, h, "", 0UL));
    final3("abc over logout", h);

    /* A closed handle, and the next session that gets it. */
    rv_row("init 2", P11(C_DigestInit, h2, &sha256));
    rv_row("update 2", P11(C_DigestUpdate, h2, "abc", 3UL));
    rv_row("close 2", P11(C_CloseSession, h2));
    rv_row("update closed", P11(C_DigestUpdate, h2, "abc", 3UL));
    len = sizeof buf;
    rv_row("final closed", P11(C_DigestFinal, h2, buf, &len));
    UL h3 = 0;
    rv_row("open third", P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h3));
    printf("third reuses second\t%d\n", h3 == h2);
    len = sizeof buf;
    rv_row("final reused", P11(C_DigestFinal, h3, buf, &len));
    rv_row("init closed-all", P11(C_DigestInit, h3, &sha256));
    rv_row("update", P11(C_DigestUpdate, h3, "abc", 3UL));
    rv_row("close all", P11(C_CloseAllSessions, 0UL));
    len = sizeof buf;
    rv_row("final after close all", P11(C_DigestFinal, h3, buf, &len));

    /* Finalize with a digest under way; the next module's session starts with none. */
    UL h4 = 0;
    rv_row("open fourth", P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h4));
    rv_row("init", P11(C_DigestInit, h4, &sha256));
    rv_row("update", P11(C_DigestUpdate, h4, "abc", 3UL));
    rv_row("finalize", P11(C_Finalize, NULL));
    len = sizeof buf;
    rv_row("final finalized", P11(C_DigestFinal, h4, buf, &len));
    rv_row("initialize", P11(C_Initialize, NULL));
    UL h5 = 0;
    rv_row("open fifth", P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &h5));
    printf("fifth reuses fourth\t%d\n", h5 == h4);
    len = sizeof buf;
    rv_row("final restarted", P11(C_DigestFinal, h5, buf, &len));

    /* A fork with a digest under way: the child starts again; the parent carries on. */
    rv_row("init", P11(C_DigestInit, h5, &sha256));
    rv_row("update ab", P11(C_DigestUpdate, h5, "ab", 2UL));
    pid_t p = fork();
    if (p == 0) {
        printf("child initialize\t%#lx\n", P11(C_Initialize, NULL));
        len = sizeof buf;
        printf("child final\t%#lx\n", P11(C_DigestFinal, h5, buf, &len));
        UL hc = 0;
        printf("child open\t%#lx\t%d\n", P11(C_OpenSession, 0UL, 6UL, NULL, NULL, &hc), hc == h5);
        len = sizeof buf;
        printf("child final on its session\t%#lx\n", P11(C_DigestFinal, hc, buf, &len));
        P11(C_DigestInit, hc, &sha256);
        P11(C_DigestUpdate, hc, "c", 1UL);
        final3("child c", hc);
        fflush(stdout);
        _exit(0);
    }
    int st;
    waitpid(p, &st, 0);
    printf("child exit\t%d\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    rv_row("update c", P11(C_DigestUpdate, h5, "c", 1UL));
    final3("parent abc", h5);
}

static void (*const S[])(void) = { s_mechs, s_args, s_key, s_life };
static const char *const SN[] = { "mechanisms", "arguments", "digest key", "lifetimes" };

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: p11_digest LIB BASE\n"); return 2; }
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
