/* Phase 4 slice 1's divergence tests (DIVERGENCES.md § Phase 4), one function each. DIV-051's
 * is p11_notinit.c, which needs every entry point.
 *
 *   p11_divs LIB BASE
 *
 * Each test runs in a forked child with its own tokens directory BASE/<name>, and prints its
 * name, pass or FAIL, and for a FAIL every check that answered otherwise. Exit 0 only if all
 * pass. Each must fail on the C library and pass on Rust. */
#include <dirent.h>
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

typedef unsigned long UL;
typedef UL (*F)();

static void *lib;
static int bad;

static F sym(const char *name) {
    F f = (F)dlsym(lib, name);
    if (!f) { fprintf(stderr, "no %s\n", name); exit(2); }
    return f;
}

#define CALL(name, ...) sym(#name)(__VA_ARGS__)

static void want(const char *what, UL got, UL expect) {
    if (got != expect) { ++bad; printf("  %s: 0x%lx, want 0x%lx\n", what, got, expect); }
}

static const char SO[] = "so-pin-1234", USER[] = "user-pin-1234";
#define LABEL "divs                            "

/* C_Initialize, slot `s` initialised, a RW session on it. */
static UL fresh(UL s) {
    UL h = 0;
    want("initialize", CALL(C_Initialize, NULL), 0);
    want("inittoken", CALL(C_InitToken, s, SO, (UL)strlen(SO), LABEL), 0);
    want("open", CALL(C_OpenSession, s, 6UL, NULL, NULL, &h), 0);
    return h;
}

/* RULE-071: a second C_Initialize is CKR_CRYPTOKI_ALREADY_INITIALIZED, not 0x6. */
static void rule_071(void) {
    want("initialize", CALL(C_Initialize, NULL), 0);
    want("initialize again", CALL(C_Initialize, NULL), 0x191);
    want("finalize", CALL(C_Finalize, NULL), 0);
    want("initialize after finalize", CALL(C_Initialize, NULL), 0);
    CALL(C_Finalize, NULL);
}

/* RULE-083: a USER login on a token whose user PIN was never set is
 * CKR_USER_PIN_NOT_INITIALIZED, not 0x101. */
static void rule_083(void) {
    UL h = fresh(0);
    want("login user, no user PIN", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0x102);
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("initpin", CALL(C_InitPIN, h, USER, (UL)strlen(USER)), 0);
    want("logout", CALL(C_Logout, h), 0);
    want("login user", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    CALL(C_Finalize, NULL);
}

/* DIV-059: a PIN being set is at least 8 bytes on every path, 0xA2 below; ulMinPinLen is 8;
 * a login is not length-checked beyond C's 4. */
static void div_059(void) {
    UL h = 0, ti[40];
    want("initialize", CALL(C_Initialize, NULL), 0);
    want("inittoken fresh 7", CALL(C_InitToken, 0UL, "1234567", 7UL, LABEL), 0xA2);
    want("inittoken fresh 8", CALL(C_InitToken, 0UL, "12345678", 8UL, LABEL), 0);
    want("inittoken reinit 7", CALL(C_InitToken, 0UL, "1234567", 7UL, LABEL), 0xA2);
    want("inittoken reinit 8", CALL(C_InitToken, 0UL, "12345678", 8UL, LABEL), 0);
    memset(ti, 0, sizeof ti);
    want("tokinfo", CALL(C_GetTokenInfo, 0UL, ti), 0);
    want("ulMinPinLen", ti[144 / sizeof(UL)], 8);
    want("ulMaxPinLen", ti[136 / sizeof(UL)], 64);
    want("open", CALL(C_OpenSession, 0UL, 6UL, NULL, NULL, &h), 0);
    want("login so", CALL(C_Login, h, 0UL, "12345678", 8UL), 0);
    want("initpin 7", CALL(C_InitPIN, h, "abcdefg", 7UL), 0xA2);
    want("initpin 8", CALL(C_InitPIN, h, "abcdefgh", 8UL), 0);
    want("setpin new 7", CALL(C_SetPIN, h, "12345678", 8UL, "7654321", 7UL), 0xA2);
    want("logout", CALL(C_Logout, h), 0);
    want("login user wrong, 5 bytes", CALL(C_Login, h, 1UL, "abcde", 5UL), 0xA0);
    CALL(C_Finalize, NULL);
}

/* DIV-055: C_CloseAllSessions takes slots 0-3 and closes only that slot's sessions, logging
 * out only that slot's token; a slot past 3 is 0x3. */
static void div_055(void) {
    UL a = fresh(0), b = 0, si[4];
    want("inittoken 1", CALL(C_InitToken, 1UL, SO, (UL)strlen(SO), LABEL), 0);
    want("open 1", CALL(C_OpenSession, 1UL, 6UL, NULL, NULL, &b), 0);
    want("login so 0", CALL(C_Login, a, 0UL, SO, (UL)strlen(SO)), 0);
    want("login so 1", CALL(C_Login, b, 0UL, SO, (UL)strlen(SO)), 0);
    want("closeall 4", CALL(C_CloseAllSessions, 4UL), 0x3);
    want("closeall 1", CALL(C_CloseAllSessions, 1UL), 0);
    want("slot 1 session closed", CALL(C_GetSessionInfo, b, si), 0xB3);
    want("slot 0 session open", CALL(C_GetSessionInfo, a, si), 0);
    want("slot 0 still SO (CKS_RW_SO_FUNCTIONS)", si[1], 4);
    want("closeall 0", CALL(C_CloseAllSessions, 0UL), 0);
    want("slot 0 session closed", CALL(C_GetSessionInfo, a, si), 0xB3);
    CALL(C_Finalize, NULL);
}

/* RULE-084: CKF_*_PIN_COUNT_LOW while 1 <= failures < 5, CKF_*_PIN_FINAL_TRY at 4, for USER
 * and SO; cleared by a good login. */
static UL tflags(void) {
    UL ti[40];
    memset(ti, 0, sizeof ti);
    want("tokinfo", CALL(C_GetTokenInfo, 0UL, ti), 0);
    return ti[96 / sizeof(UL)] & 0x770000UL;   /* the six PIN state bits */
}

static void rule_084(void) {
    static const UL user[] = { 0, 0x10000, 0x10000, 0x10000, 0x30000, 0x40000 };
    UL h = fresh(0);
    char what[64];
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("initpin", CALL(C_InitPIN, h, USER, (UL)strlen(USER)), 0);
    want("logout", CALL(C_Logout, h), 0);
    for (int i = 0; i <= 5; ++i) {
        if (i) CALL(C_Login, h, 1UL, "wrong-pin-0", 11UL);
        snprintf(what, sizeof what, "user flags after %d wrong", i);
        want(what, tflags(), user[i]);
    }
    want("login so wrong", CALL(C_Login, h, 0UL, "wrong-pin-0", 11UL), 0xA0);
    want("so flags after 1 wrong", tflags(), 0x40000 | 0x100000);
    for (int i = 2; i <= 4; ++i) CALL(C_Login, h, 0UL, "wrong-pin-0", 11UL);
    want("so flags after 4 wrong", tflags(), 0x40000 | 0x300000);
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("so flags after a good login", tflags(), 0x40000);
    CALL(C_Finalize, NULL);
}

/* DIV-054: C_SetPIN changes the logged-in role's PIN (C: always 0x100); the old PIN is
 * counted as a login counts it; afterwards only the new PIN logs in. Read-only session 0xB5,
 * nobody logged in 0x101. */
static void div_054(void) {
    static const char NEW_USER[] = "user-pin-5678", NEW_SO[] = "so-pin-5678";
    UL h = fresh(0), ro = 0;
    want("setpin nobody logged in", CALL(C_SetPIN, h, SO, (UL)strlen(SO), NEW_SO, (UL)strlen(NEW_SO)), 0x101);
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("initpin", CALL(C_InitPIN, h, USER, (UL)strlen(USER)), 0);
    want("setpin so", CALL(C_SetPIN, h, SO, (UL)strlen(SO), NEW_SO, (UL)strlen(NEW_SO)), 0);
    want("logout", CALL(C_Logout, h), 0);
    want("login so old", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0xA0);
    want("login so new", CALL(C_Login, h, 0UL, NEW_SO, (UL)strlen(NEW_SO)), 0);
    want("logout", CALL(C_Logout, h), 0);
    want("login user", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("setpin user wrong old", CALL(C_SetPIN, h, "wrong-pin-0", 11UL, NEW_USER, (UL)strlen(NEW_USER)), 0xA0);
    want("wrong old counted (COUNT_LOW)", tflags() & 0x10000UL, 0x10000);
    want("open ro", CALL(C_OpenSession, 0UL, 4UL, NULL, NULL, &ro), 0);
    want("setpin read-only", CALL(C_SetPIN, ro, USER, (UL)strlen(USER), NEW_USER, (UL)strlen(NEW_USER)), 0xB5);
    want("setpin user", CALL(C_SetPIN, h, USER, (UL)strlen(USER), NEW_USER, (UL)strlen(NEW_USER)), 0);
    UL si[4] = { 0 };
    want("sessinfo", CALL(C_GetSessionInfo, h, si), 0);
    want("still logged in (CKS_RW_USER_FUNCTIONS)", si[1], 3);
    want("logout", CALL(C_Logout, h), 0);
    want("login user old", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0xA0);
    want("login user new", CALL(C_Login, h, 1UL, NEW_USER, (UL)strlen(NEW_USER)), 0);
    CALL(C_Finalize, NULL);
    /* The change is on disk: a fresh initialisation logs in with the new PIN. */
    want("initialize", CALL(C_Initialize, NULL), 0);
    want("open", CALL(C_OpenSession, 0UL, 6UL, NULL, NULL, &h), 0);
    want("login user new after restart", CALL(C_Login, h, 1UL, NEW_USER, (UL)strlen(NEW_USER)), 0);
    CALL(C_Finalize, NULL);
}

/* DIV-050, the logout half (SEC-001's reproduction): after C_Logout the user's AES token key
 * is gone, as in a process that never logged in, and a later login brings it back. C keeps it
 * decrypted and usable. Key use as SO or nobody, and an operation continued past the logout,
 * are slices 4 and 5's. */
static void div_050(void) {
    UL h = fresh(0), k = 0, cls = 4, kt = 0x1f, n = 0, found[16], out = 64;
    unsigned char yes = 1, key[16] = { 1 }, pt[16] = { 2 }, ct[64];
    struct { UL type; void *p; UL len; } t[] = {
        { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x001, &yes, 1 },
        { 0x104, &yes, 1 }, { 0x011, key, sizeof key },
    };
    struct { UL m; void *p; UL len; } ecb = { 0x1081, NULL, 0 };
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("initpin", CALL(C_InitPIN, h, USER, (UL)strlen(USER)), 0);
    want("logout so", CALL(C_Logout, h), 0);
    want("login user", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("create the AES token key", CALL(C_CreateObject, h, t, 5UL, &k), 0);
    want("encryptinit logged in", CALL(C_EncryptInit, h, &ecb, k), 0);
    want("encrypt logged in", CALL(C_Encrypt, h, pt, 16UL, ct, &out), 0);
    want("logout user", CALL(C_Logout, h), 0);
    want("encryptinit after logout", CALL(C_EncryptInit, h, &ecb, k), 0x60);
    want("findinit after logout", CALL(C_FindObjectsInit, h, NULL, 0UL), 0);
    want("find after logout", CALL(C_FindObjects, h, found, 16UL, &n), 0);
    for (UL i = 0; i < n; ++i) want("the key is found after logout", found[i] == k, 0);
    CALL(C_FindObjectsFinal, h);
    want("login user again", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("encryptinit after a new login", CALL(C_EncryptInit, h, &ecb, k), 0);
    out = 64;
    want("encrypt after a new login", CALL(C_Encrypt, h, pt, 16UL, ct, &out), 0);
    /* The SO can neither relabel nor destroy the user's key (0x82, as for no such object). */
    want("logout user again", CALL(C_Logout, h), 0);
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    struct { UL type; void *p; UL len; } relabel = { 0x3 /* CKA_LABEL */, (void *)"so's", 4 };
    /* Nor digest it: the key is not sensitive, so C digests it for the SO. */
    struct { UL m; void *p; UL len; } sha256 = { 0x250, NULL, 0 };
    want("so digestinit", CALL(C_DigestInit, h, &sha256), 0);
    want("so digests the user's key", CALL(C_DigestKey, h, k), 0x60);
    out = sizeof ct; /* a refusal does not end the digest (as C); end it */
    want("so digestfinal", CALL(C_DigestFinal, h, ct, &out), 0);
    /* Before the destroy, so on C the key is still there to relabel. */
    want("so relabels the user's key", CALL(C_SetAttributeValue, h, k, &relabel, 1UL), 0x82);
    want("so destroys the user's key", CALL(C_DestroyObject, h, k), 0x82);
    want("logout so again", CALL(C_Logout, h), 0);
    want("login user a third time", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("the key survived", CALL(C_EncryptInit, h, &ecb, k), 0);
    /* A private session key stays after logout (the Target keeps it); it is not digested. */
    unsigned char no = 0;
    struct { UL type; void *p; UL len; } st[] = {
        { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x001, &no, 1 },
        { 0x011, key, sizeof key },
    };
    UL sk = 0;
    want("create a session key", CALL(C_CreateObject, h, st, 4UL, &sk), 0);
    want("logout before the session key's digest", CALL(C_Logout, h), 0);
    want("digestinit logged out", CALL(C_DigestInit, h, &sha256), 0);
    want("digest the session key logged out", CALL(C_DigestKey, h, sk), 0x60);
    CALL(C_DigestFinal, h, ct, &out);
    /* Slice 4: the session key is the user's too. Logged out or as SO it cannot be used, and
     * the logout ends the encryption under way on it. C let both use it. */
    want("encryptinit the session key logged out", CALL(C_EncryptInit, h, &ecb, sk), 0x60);
    want("login user for the session key", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("encryptinit the session key", CALL(C_EncryptInit, h, &ecb, sk), 0);
    want("logout under the encryption", CALL(C_Logout, h), 0);
    out = sizeof ct;
    want("encrypt after the logout", CALL(C_Encrypt, h, pt, 16UL, ct, &out), 0x91);
    want("login so for the session key", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("so encryptinit the session key", CALL(C_EncryptInit, h, &ecb, sk), 0x60);
    /* The logout ends the operations of every session on the token, decryptions in parts too. */
    UL h2 = 0, n2 = 64;
    want("logout so for the sessions", CALL(C_Logout, h), 0);
    want("login user for the sessions", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("open a second session", CALL(C_OpenSession, 0UL, 6UL, NULL, NULL, &h2), 0);
    want("encryptinit in the second", CALL(C_EncryptInit, h2, &ecb, sk), 0);
    want("decryptinit in the first", CALL(C_DecryptInit, h, &ecb, sk), 0);
    want("decryptupdate before the logout", CALL(C_DecryptUpdate, h, pt, 16UL, ct, &n2), 0);
    want("logout in the first", CALL(C_Logout, h), 0);
    n2 = 64;
    want("the second's encryption ended", CALL(C_EncryptUpdate, h2, pt, 16UL, ct, &n2), 0x91);
    n2 = 64;
    want("the first's decryption ended", CALL(C_DecryptUpdate, h, pt, 16UL, ct, &n2), 0x91);
    CALL(C_Finalize, NULL);
}

/* A user session and an AES session key of `n` bytes (key[i] = i). */
static UL user_key(UL *h, UL n) {
    UL k = 0, cls = 4, kt = 0x1f;
    unsigned char no = 0, key[32];
    for (int i = 0; i < 32; ++i) key[i] = (unsigned char)i;
    struct { UL type; void *p; UL len; } t[] = {
        { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x001, &no, 1 },
        { 0x011, key, n },
    };
    *h = fresh(0);
    want("login so", CALL(C_Login, *h, 0UL, SO, (UL)strlen(SO)), 0);
    want("initpin", CALL(C_InitPIN, *h, USER, (UL)strlen(USER)), 0);
    want("logout so", CALL(C_Logout, *h), 0);
    want("login user", CALL(C_Login, *h, 1UL, USER, (UL)strlen(USER)), 0);
    want("create the key", CALL(C_CreateObject, *h, t, 4UL, &k), 0);
    return k;
}

/* DIV-061: single-part AES-ECB with a 20-byte key is CKR_KEY_SIZE_RANGE and ends the
 * operation. C took it for AES-256 and read 32 bytes of the 20. */
static void div_061(void) {
    UL h, k = user_key(&h, 20), out = 64;
    unsigned char pt[16] = { 2 }, ct[64];
    struct { UL m; void *p; UL len; } ecb = { 0x1081, NULL, 0 };
    want("encryptinit", CALL(C_EncryptInit, h, &ecb, k), 0);
    want("encrypt with a 20-byte key", CALL(C_Encrypt, h, pt, 16UL, ct, &out), 0x62);
    out = 64;
    want("the operation ended", CALL(C_Encrypt, h, pt, 16UL, ct, &out), 0x91);
    want("decryptinit", CALL(C_DecryptInit, h, &ecb, k), 0);
    out = 64;
    want("decrypt with a 20-byte key", CALL(C_Decrypt, h, pt, 16UL, ct, &out), 0x62);
    CALL(C_Finalize, NULL);
}

/* DIV-062: an Init after a multipart error starts afresh. C kept the old context, so the next
 * update went on under the old key and mode. */
static void div_062(void) {
    UL h, k = user_key(&h, 16), out = 64, n;
    unsigned char iv[16] = { 7 }, pt[16] = { 2 }, ct[64], want_ct[64];
    struct { UL m; void *p; UL len; } ecb = { 0x1081, NULL, 0 }, cbc = { 0x1082, iv, 16 };
    want("encryptinit cbc", CALL(C_EncryptInit, h, &cbc, k), 0);
    want("encrypt cbc", CALL(C_Encrypt, h, pt, 16UL, want_ct, &out), 0);
    want("encryptinit ecb", CALL(C_EncryptInit, h, &ecb, k), 0);
    out = 64;
    want("update ecb", CALL(C_EncryptUpdate, h, pt, 16UL, ct, &out), 0);
    out = 64;
    want("update 2^31 ends it", CALL(C_EncryptUpdate, h, ct, 0x80000000UL, ct, &out), 0x21);
    want("encryptinit cbc again", CALL(C_EncryptInit, h, &cbc, k), 0);
    n = 64;
    want("update cbc", CALL(C_EncryptUpdate, h, pt, 16UL, ct, &n), 0);
    want("the update is the cbc encryption", n == 16 && !memcmp(ct, want_ct, 16), 1);
    CALL(C_Finalize, NULL);
}

/* The next audit write fails: RLIMIT_FSIZE at the size of the log the module has open (the
 * newest audit.log* in FHSM_TOKENS_DIR). The write that fails latches ERROR. */
static void fail_audit(void) {
    const char *d = getenv("FHSM_TOKENS_DIR");
    char p[700];
    struct stat st;
    off_t size = -1;
    time_t newest = 0;
    DIR *dd = opendir(d);
    for (struct dirent *e; dd && (e = readdir(dd));) {
        snprintf(p, sizeof p, "%s/%s", d, e->d_name);
        if (!strncmp(e->d_name, "audit.log", 9) && !stat(p, &st) && S_ISREG(st.st_mode)
            && st.st_mtime >= newest) {
            newest = st.st_mtime;
            size = st.st_size;
        }
    }
    if (dd) closedir(dd);
    if (size < 0) { ++bad; printf("  no audit.log* in %s\n", d); return; }
    signal(SIGXFSZ, SIG_IGN);
    struct rlimit rl = { (rlim_t)size, (rlim_t)size };
    setrlimit(RLIMIT_FSIZE, &rl);
}

/* DIV-001 at slice 1's sites: a call that succeeded but could not be audited is
 * CKR_DEVICE_ERROR (0x30). C discarded the audit result, so each returns 0x0. One process per
 * case: the first failed write latches ERROR. */
static void div_001_case(int which) {
    if (which == 5) {
        /* A failing single-part call writes nothing either: CBC-PAD over bad padding (the last
         * plaintext byte is 0). C left the first block's plaintext in the buffer. */
        UL hs, k = user_key(&hs, 16), out = 64;
        unsigned char iv[16] = { 7 }, pt[32] = { 0 }, ct[64], got[64];
        struct { UL m; void *p; UL len; } cbc = { 0x1082, iv, 16 }, pad = { 0x1085, iv, 16 };
        want("encryptinit cbc", CALL(C_EncryptInit, hs, &cbc, k), 0);
        want("encrypt cbc", CALL(C_Encrypt, hs, pt, 32UL, ct, &out), 0);
        memset(got, 0xAA, sizeof got);
        out = 64;
        want("decryptinit cbc-pad", CALL(C_DecryptInit, hs, &pad, k), 0);
        want("decrypt, bad padding", CALL(C_Decrypt, hs, ct, 32UL, got, &out), 0x40);
        want("nothing written on the failure", got[0] == 0xAA && got[15] == 0xAA, 1);
        return;
    }
    if (which == 4) {
        /* Slice 4: a C_Encrypt that cannot be audited writes nothing. */
        UL hs, k = user_key(&hs, 16), out = 64;
        unsigned char pt[16] = { 2 }, ct[64];
        struct { UL m; void *p; UL len; } ecb = { 0x1081, NULL, 0 };
        memset(ct, 0xAA, sizeof ct);
        want("encryptinit", CALL(C_EncryptInit, hs, &ecb, k), 0);
        fail_audit();
        want("encrypt, audit failing", CALL(C_Encrypt, hs, pt, 16UL, ct, &out), 0x30);
        want("nothing written", ct[0] == 0xAA && ct[15] == 0xAA && out == 64, 1);
        return;
    }
    UL h = fresh(0);
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    if (which == 0) {
        fail_audit();
        want("initpin, audit failing", CALL(C_InitPIN, h, USER, (UL)strlen(USER)), 0x30);
        return;
    }
    want("initpin", CALL(C_InitPIN, h, USER, (UL)strlen(USER)), 0);
    if (which == 1) {
        fail_audit();
        want("logout, audit failing", CALL(C_Logout, h), 0x30);
        return;
    }
    want("logout", CALL(C_Logout, h), 0);
    if (which == 2) {
        fail_audit();
        want("login user, audit failing", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0x30);
        return;
    }
    want("close", CALL(C_CloseSession, h), 0);
    fail_audit();
    want("reinit, audit failing", CALL(C_InitToken, 0UL, SO, (UL)strlen(SO), LABEL), 0x30);
}

static void div_001(void) {
    const char *base = getenv("FHSM_TOKENS_DIR");
    for (int i = 0; i < 6; ++i) {
        char d[700];
        snprintf(d, sizeof d, "%s/%d", base, i);
        mkdir(d, 0700);
        fflush(stdout);
        pid_t p = fork();
        if (p == 0) {
            setenv("FHSM_TOKENS_DIR", d, 1);
            div_001_case(i);
            fflush(stdout);
            _exit(bad ? 1 : 0);
        }
        int st;
        waitpid(p, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st)) ++bad;
    }
}

/* DIV-060: a copy made uncopyable stays uncopyable when its source carries a restriction
 * (here, allowed mechanisms). C overwrote the copy's restriction byte with the source's. */
static void div_060(void) {
    UL h = fresh(0), k = 0, c = 0, c2 = 0, cls = 4, kt = 0x1f, mech = 0x1081;
    unsigned char yes = 1, no = 0, key[16] = { 1 }, got = 0xAA;
    struct { UL type; void *p; UL len; } t[] = {
        { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x001, &yes, 1 },
        { 0x011, key, sizeof key }, { 0x40000600, &mech, sizeof mech },
    }, nocopy = { 0x171, &no, 1 }, ask = { 0x171, &got, 1 };
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("initpin", CALL(C_InitPIN, h, USER, (UL)strlen(USER)), 0);
    want("logout so", CALL(C_Logout, h), 0);
    want("login user", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("create a key with allowed mechanisms", CALL(C_CreateObject, h, t, 5UL, &k), 0);
    want("copy it, uncopyable", CALL(C_CopyObject, h, k, &nocopy, 1UL, &c), 0);
    want("the copy reads uncopyable", CALL(C_GetAttributeValue, h, c, &ask, 1UL), 0);
    want("CKA_COPYABLE is FALSE", got, 0);
    want("copying the copy is refused", CALL(C_CopyObject, h, c, NULL, 0UL, &c2), 0x1B);
    CALL(C_Finalize, NULL);
}

/* DIV-056: a copy keeps its source's usage, mechanism list and nested templates, and its
 * template may only narrow them. C dropped the usage byte (an ENCRYPT=FALSE key's copy
 * encrypted) and refused every one of these attributes in a copy template as unknown. */
static void div_056(void) {
    UL h = fresh(0), ro = 0, k = 0, w = 0, c = 0, x = 0xAAAA, cls = 4, kt = 0x1f, mech = 0x1081;
    UL wide[2] = { 0x1081, 0x1082 };
    unsigned char yes = 1, no = 0, key[16] = { 1 }, got = 0xAA;
    struct { UL type; void *p; UL len; } t[] = {
        { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x001, &yes, 1 },
        { 0x011, key, sizeof key }, { 0x104, &no, 1 }, { 0x40000600, &mech, sizeof mech },
    }, label = { 0x3, "c", 1 }, encrypt = { 0x104, &yes, 1 }, decrypt = { 0x105, &no, 1 },
       widen = { 0x40000600, wide, sizeof wide }, nest = { 0x40000211, &decrypt, sizeof decrypt },
       ask = { 0x105, &got, 1 };
    struct { UL m; void *p; UL len; } ecb = { 0x1081, NULL, 0 };
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("initpin", CALL(C_InitPIN, h, USER, (UL)strlen(USER)), 0);
    want("logout so", CALL(C_Logout, h), 0);
    want("login user", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("create an ENCRYPT=FALSE key", CALL(C_CreateObject, h, t, 6UL, &k), 0);
    want("copy it", CALL(C_CopyObject, h, k, &label, 1UL, &c), 0);
    want("the copy may not encrypt", CALL(C_EncryptInit, h, &ecb, c), 0x68);
    want("a copy may not widen ENCRYPT", CALL(C_CopyObject, h, k, &encrypt, 1UL, &x), 0x10);
    want("a copy may not widen the mechanisms", CALL(C_CopyObject, h, k, &widen, 1UL, &x), 0x10);
    want("a copy template has no nested template", CALL(C_CopyObject, h, k, &nest, 1UL, &x), 0xD1);
    want("a copy may narrow DECRYPT", CALL(C_CopyObject, h, k, &decrypt, 1UL, &c), 0);
    want("read DECRYPT", CALL(C_GetAttributeValue, h, c, &ask, 1UL), 0);
    want("DECRYPT is FALSE", got, 0);
    /* The source's wrap template goes with the copy: one row, read back by length. */
    struct { UL type; void *p; UL len; } extr = { 0x162, &yes, 1 }, wt[] = {
        { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x011, key, sizeof key },
        { 0x40000211, &extr, sizeof extr },
    }, rd = { 0x40000211, NULL, 0 };
    want("create a key with a wrap template", CALL(C_CreateObject, h, wt, 4UL, &w), 0);
    want("copy it", CALL(C_CopyObject, h, w, &label, 1UL, &c), 0);
    want("read the copy's wrap template", CALL(C_GetAttributeValue, h, c, &rd, 1UL), 0);
    want("the copy's wrap template has one row", rd.len, sizeof extr);
    want("open read-only", CALL(C_OpenSession, 0UL, 4UL, NULL, NULL, &ro), 0);
    want("an inherited token copy from read-only", CALL(C_CopyObject, ro, k, &label, 1UL, &x), 0xB5);
    CALL(C_Finalize, NULL);
}

/* RULE-092: destroying a handle that names no object is CKR_OBJECT_HANDLE_INVALID (0x82),
 * once more after the object is gone. C answered CKR_KEY_HANDLE_INVALID (0x60). */
static void rule_092(void) {
    UL h = fresh(0), o = 0, cls = 0;
    unsigned char no = 0;
    struct { UL type; void *p; UL len; } t[] = { { 0x0, &cls, sizeof cls }, { 0x1, &no, 1 } };
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("initpin", CALL(C_InitPIN, h, USER, (UL)strlen(USER)), 0);
    want("logout so", CALL(C_Logout, h), 0);
    want("login user", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("create a data object", CALL(C_CreateObject, h, t, 2UL, &o), 0);
    want("destroy it", CALL(C_DestroyObject, h, o), 0);
    want("destroy it again", CALL(C_DestroyObject, h, o), 0x82);
    want("destroy a handle never issued", CALL(C_DestroyObject, h, 999UL), 0x82);
    CALL(C_Finalize, NULL);
}

/* RULE-091: the 128 sessions C_GetTokenInfo advertises can all be open, and the last one
 * can run an operation. C's table held 127. */
static void rule_091(void) {
    UL s = fresh(0), n = 0, out = 64;   /* fresh's session is the first */
    unsigned char md[64];
    struct { UL m; void *p; UL len; } sha = { 0x250, NULL, 0 };   /* CKM_SHA256 */
    for (n = 1; n < 128; ++n)
        if (CALL(C_OpenSession, 0UL, 4UL, NULL, NULL, &s) != 0) break;
    want("128 sessions open", n, 128);
    want("digestinit on the last", CALL(C_DigestInit, s, &sha), 0);
    want("digest on the last", CALL(C_Digest, s, (void *)"abc", 3UL, md, &out), 0);
    want("a 129th is refused", CALL(C_OpenSession, 0UL, 4UL, NULL, NULL, &s), 0x2);
    CALL(C_Finalize, NULL);
}

/* RULE-061: the allowed-mechanism check refuses a key it cannot find. C_UnwrapKey runs it
 * before its login check and its own lookup, so with the public view loaded and no login an
 * unknown unwrapping key is 0x60 where C, letting it through, answered 0x101. */
static void rule_061(void) {
    UL h = fresh(0), k = 0, cls = 4, kt = 0x1f;
    unsigned char yes = 1, key[16] = { 1 }, wrapped[24] = { 0 };
    struct { UL type; void *p; UL len; } t[] = {
        { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x001, &yes, 1 },
        { 0x011, key, sizeof key },
    };
    struct { UL m; void *p; UL len; } kw = { 0x2109, NULL, 0 };   /* CKM_AES_KEY_WRAP */
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("initpin", CALL(C_InitPIN, h, USER, (UL)strlen(USER)), 0);
    want("logout so", CALL(C_Logout, h), 0);
    want("login user", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("create a token key", CALL(C_CreateObject, h, t, 4UL, &k), 0);
    want("logout user", CALL(C_Logout, h), 0);
    want("unwrap with an unknown key", CALL(C_UnwrapKey, h, &kw, 999UL, wrapped,
                                            (UL)sizeof wrapped, t, 2UL, &k), 0x60);
    CALL(C_Finalize, NULL);
}

/* RULE-059: ALWAYS_SENSITIVE and NEVER_EXTRACTABLE are history. A key made readable and then
 * made sensitive and unextractable, by set-attribute or in a copy, was never always sensitive;
 * C computed both from the current flags and answered TRUE. */
static UL hist(UL h, UL o, UL type) {
    unsigned char v = 9;
    struct { UL type; void *p; UL len; } a = { type, &v, 1 };
    UL rv = CALL(C_GetAttributeValue, h, o, &a, 1UL);
    return rv ? 0x100 | rv : v;
}

static void rule_059(void) {
    UL h = fresh(0), k = 0, c = 0, cls = 4, kt = 0x1f;
    unsigned char no = 0, yes = 1, key[16] = { 1 };
    struct { UL type; void *p; UL len; } t[] = {
        { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x011, key, sizeof key },
        { 0x103, &no, 1 }, { 0x162, &yes, 1 },
    }, lock[] = { { 0x103, &yes, 1 }, { 0x162, &no, 1 } };
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("initpin", CALL(C_InitPIN, h, USER, (UL)strlen(USER)), 0);
    want("logout so", CALL(C_Logout, h), 0);
    want("login user", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("create a readable key", CALL(C_CreateObject, h, t, 5UL, &k), 0);
    want("copy it locked", CALL(C_CopyObject, h, k, lock, 2UL, &c), 0);
    want("lock the key", CALL(C_SetAttributeValue, h, k, lock, 2UL), 0);
    want("key ALWAYS_SENSITIVE", hist(h, k, 0x165), 0);
    want("key NEVER_EXTRACTABLE", hist(h, k, 0x164), 0);
    want("copy ALWAYS_SENSITIVE", hist(h, c, 0x165), 0);
    want("copy NEVER_EXTRACTABLE", hist(h, c, 0x164), 0);
    want("copy SENSITIVE", hist(h, c, 0x103), 1);
    want("copy the locked key as it is", CALL(C_CopyObject, h, k, NULL, 0UL, &c), 0);
    want("plain copy ALWAYS_SENSITIVE", hist(h, c, 0x165), 0);
    want("plain copy NEVER_EXTRACTABLE", hist(h, c, 0x164), 0);
    CALL(C_Finalize, NULL);
}

static const struct { const char *name; void (*fn)(void); } tests[] = {
    { "RULE-071", rule_071 }, { "RULE-083", rule_083 }, { "DIV-059", div_059 },
    { "DIV-055", div_055 }, { "RULE-084", rule_084 },
    { "DIV-054", div_054 }, { "DIV-050", div_050 }, { "DIV-001", div_001 },
    { "DIV-060", div_060 }, { "DIV-056", div_056 },
    { "RULE-092", rule_092 }, { "RULE-091", rule_091 }, { "RULE-061", rule_061 },
    { "RULE-059", rule_059 }, { "DIV-061", div_061 }, { "DIV-062", div_062 },
};

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: p11_divs LIB BASE\n"); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    int rc = 0;
    for (size_t i = 0; i < sizeof tests / sizeof *tests; ++i) {
        char dir[512];
        snprintf(dir, sizeof dir, "%s/%s", argv[2], tests[i].name);
        mkdir(dir, 0700);
        printf("%s\n", tests[i].name);
        pid_t p = fork();
        if (p == 0) {
            setenv("FHSM_TOKENS_DIR", dir, 1);
            tests[i].fn();
            _exit(bad ? 1 : 0);
        }
        int st;
        waitpid(p, &st, 0);
        int ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
        if (!WIFEXITED(st)) printf("  killed by signal %d\n", WTERMSIG(st));
        printf("%s: %s\n", tests[i].name, ok ? "pass" : "FAIL");
        rc |= !ok;
    }
    return rc;
}
