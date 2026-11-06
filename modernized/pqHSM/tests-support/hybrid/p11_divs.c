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
static void kem_pair(UL h, UL *pub, UL *priv, unsigned char *ct, UL *cl);
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
        { 0x011, key, sizeof key }, { 0x10C, &yes, 1 },
    };
    UL sk = 0;
    want("create a session key", CALL(C_CreateObject, h, st, 5UL, &sk), 0);
    UL kpub = 0, kpriv = 0, kcl = 1568;
    unsigned char kct[1568];
    kem_pair(h, &kpub, &kpriv, kct, &kcl);
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
    /* Slice 5: signing and verifying the same (HMAC takes the AES session key). */
    struct { UL m; void *p; UL len; } hmac = { 0x251, NULL, 0 };
    want("signinit the session key logged out", CALL(C_SignInit, h, &hmac, sk), 0x60);
    want("verifyinit the session key logged out", CALL(C_VerifyInit, h, &hmac, sk), 0x60);
    want("login user for the signature", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("signinit the session key", CALL(C_SignInit, h, &hmac, sk), 0);
    want("verifyinit the session key", CALL(C_VerifyInit, h, &hmac, sk), 0);
    want("logout under the signature", CALL(C_Logout, h), 0);
    out = sizeof ct;
    want("sign after the logout", CALL(C_Sign, h, pt, 16UL, ct, &out), 0x91);
    want("verify after the logout", CALL(C_Verify, h, pt, 16UL, ct, 32UL), 0x91);
    want("login so for the signature", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("so signinit the session key", CALL(C_SignInit, h, &hmac, sk), 0x60);
    /* Slice 6c: nor wrap the user's key, nor unwrap under it. */
    struct { UL m; void *p; UL len; } kwm = { 0x2109, NULL, 0 };
    unsigned char zeros[24] = { 0 };
    UL wl = sizeof ct, uo = 0;
    want("so wraps the user's key", CALL(C_WrapKey, h, &kwm, sk, k, ct, &wl), 0x60);
    want("so unwraps under the user's key",
         CALL(C_UnwrapKey, h, &kwm, sk, zeros, 24UL, NULL, 0UL, &uo), 0x60);
    /* The key wrapped counts too, under a public key anyone may use. */
    UL bits = 2048, rpub = 0, rprv = 0, oaep_p[5] = { 0x250, 2, 1, 0, 0 };
    unsigned char big[512];
    struct { UL type; void *p; UL len; } rp[] = { { 0x121, &bits, sizeof bits } };
    struct { UL m; void *p; UL len; } rsa = { 0x0, NULL, 0 }, oaep = { 0x9, oaep_p, sizeof oaep_p };
    want("so generates an rsa pair", CALL(C_GenerateKeyPair, h, &rsa, rp, 1UL, NULL, 0UL, &rpub, &rprv), 0);
    wl = sizeof big;
    want("so wraps the user's key under a public key", CALL(C_WrapKey, h, &oaep, rpub, k, big, &wl), 0x60);
    /* Slice 6d: nor derive from it. */
    struct { unsigned char ex, ep; UL prf, st; void *salt; UL sl; UL sk; void *info; UL il; } hp =
        { 1, 1, 0x250, 1, NULL, 0, 0, NULL, 0 };
    struct { UL m; void *p; UL len; } hkdf = { 0x402A, &hp, sizeof hp };
    want("so derives from the user's key", CALL(C_DeriveKey, h, &hkdf, sk, NULL, 0UL, &uo), 0x60);
    /* Slice 7: nor decapsulate with the user's ML-KEM key. */
    struct { UL m; void *p; UL len; } kem = { 0x17, NULL, 0 };
    want("so decapsulates with the user's key",
         CALL(C_DecapsulateKey, h, &kem, kpriv, NULL, 0UL, kct, kcl, &uo), 0x60);
    CALL(C_Finalize, NULL);
}

/* A user session and an AES session key of `n` bytes (key[i] = i) that may derive. */
/* Slice 7: an ML-KEM-512 pair in session h (the user's) and one encapsulation to it: *ct of
 * *cl bytes. */
static void kem_pair(UL h, UL *pub, UL *priv, unsigned char *ct, UL *cl) {
    UL set = 1, o = 0;
    struct { UL type; void *p; UL len; } pu[] = { { 0x61D, &set, sizeof set } };
    struct { UL m; void *p; UL len; } gen = { 0xF, NULL, 0 }, kem = { 0x17, NULL, 0 };
    want("generate an ml-kem pair", CALL(C_GenerateKeyPair, h, &gen, pu, 1UL, NULL, 0UL, pub, priv), 0);
    want("encapsulate to it", CALL(C_EncapsulateKey, h, &kem, *pub, NULL, 0UL, ct, cl, &o), 0);
}

static UL user_key(UL *h, UL n) {
    UL k = 0, cls = 4, kt = 0x1f;
    unsigned char no = 0, yes = 1, key[32];
    for (int i = 0; i < 32; ++i) key[i] = (unsigned char)i;
    struct { UL type; void *p; UL len; } t[] = {
        { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x001, &no, 1 },
        { 0x011, key, n }, { 0x10C, &yes, 1 },
    };
    *h = fresh(0);
    want("login so", CALL(C_Login, *h, 0UL, SO, (UL)strlen(SO)), 0);
    want("initpin", CALL(C_InitPIN, *h, USER, (UL)strlen(USER)), 0);
    want("logout so", CALL(C_Logout, *h), 0);
    want("login user", CALL(C_Login, *h, 1UL, USER, (UL)strlen(USER)), 0);
    want("create the key", CALL(C_CreateObject, *h, t, 5UL, &k), 0);
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
    /* Slice 5: a MAC stream. C_Sign ends an operation whose update opened one; C kept the
     * stream, so the next SignInit's update went on with it, under the old data. */
    struct { UL m; void *p; UL len; } hmac = { 0x251, NULL, 0 };
    unsigned char mac[32], mac2[64];
    UL ml = 32;
    want("signinit hmac", CALL(C_SignInit, h, &hmac, k), 0);
    want("sign hmac", CALL(C_Sign, h, pt, 16UL, mac, &ml), 0);
    want("signinit hmac again", CALL(C_SignInit, h, &hmac, k), 0);
    want("signupdate", CALL(C_SignUpdate, h, iv, 16UL), 0);
    ml = sizeof mac2;
    want("sign ends it, leaving the stream", CALL(C_Sign, h, pt, 16UL, mac2, &ml), 0);
    want("signinit hmac a third time", CALL(C_SignInit, h, &hmac, k), 0);
    want("signupdate the data", CALL(C_SignUpdate, h, pt, 16UL), 0);
    ml = sizeof mac2;
    want("signfinal", CALL(C_SignFinal, h, mac2, &ml), 0);
    want("the parts are the single-part mac", ml == 32 && !memcmp(mac, mac2, 32), 1);
    CALL(C_Finalize, NULL);
}

/* DIV-063: C_Verify with a NULL signature and a length is ARGUMENTS_BAD up front. C read
 * through it (a crash at the right length) or answered 0xC0 at a wrong one, as here. */
static void div_063(void) {
    UL h, k = user_key(&h, 16);
    unsigned char pt[16] = { 2 };
    struct { UL m; void *p; UL len; } hmac = { 0x251, NULL, 0 };
    want("verifyinit", CALL(C_VerifyInit, h, &hmac, k), 0);
    want("verify a NULL signature of 10 bytes", CALL(C_Verify, h, pt, 16UL, NULL, 10UL), 0x7);
    want("the operation ended", CALL(C_Verify, h, pt, 16UL, pt, 16UL), 0x91);
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
    if (which == 7 || which == 8) {
        /* Slice 5: an audited verification, and a signature in parts, the audit failing. */
        UL hs, out = 64, pk = 0, vk = 0, cpub = 2, cprv = 3;
        user_key(&hs, 16);
        unsigned char yes = 1, pt[16] = { 2 }, sig[64];
        unsigned char p256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
        struct { UL type; void *p; UL len; } pub[] = {
            { 0x000, &cpub, sizeof cpub }, { 0x10A, &yes, 1 }, { 0x180, p256, sizeof p256 },
        }, prv[] = { { 0x000, &cprv, sizeof cprv }, { 0x108, &yes, 1 }, { 0x103, &yes, 1 } };
        struct { UL m; void *p; UL len; } gen = { 0x1040, NULL, 0 }, ecdsa = { 0x1044, NULL, 0 };
        want("generate p-256", CALL(C_GenerateKeyPair, hs, &gen, pub, 3UL, prv, 3UL, &pk, &vk), 0);
        want("signinit", CALL(C_SignInit, hs, &ecdsa, vk), 0);
        if (which == 7) {
            want("sign", CALL(C_Sign, hs, pt, 16UL, sig, &out), 0);
            want("verifyinit", CALL(C_VerifyInit, hs, &ecdsa, pk), 0);
            fail_audit();
            want("verify, audit failing", CALL(C_Verify, hs, pt, 16UL, sig, out), 0x30);
            return;
        }
        memset(sig, 0xAA, sizeof sig);
        want("signupdate", CALL(C_SignUpdate, hs, pt, 16UL), 0);
        fail_audit();
        want("signfinal, audit failing", CALL(C_SignFinal, hs, sig, &out), 0x30);
        want("nothing written", sig[0] == 0xAA && sig[63] == 0xAA && out == 64, 1);
        return;
    }
    if (which == 9) {
        /* Slice 6a: a pair whose pairwise check cannot be audited is not stored. */
        UL hs, pk = 0xAAAAAAAAUL, vk = 0xAAAAAAAAUL;
        user_key(&hs, 16);
        struct { UL m; void *p; UL len; } gen = { 0x1040, NULL, 0 };
        fail_audit();
        want("generate p-256, audit failing",
             CALL(C_GenerateKeyPair, hs, &gen, NULL, 0UL, NULL, 0UL, &pk, &vk), 0x30);
        /* The failed write latched ERROR, which refuses a find, and the pair would be session
         * objects a restart drops: the handles are what can be seen. */
        want("no handles written", pk == 0xAAAAAAAAUL && vk == 0xAAAAAAAAUL, 1);
        return;
    }
    if (which == 12) {
        /* Slice 6d: a derived key whose record cannot be made is not kept. */
        UL hs, k = user_key(&hs, 32), o = 0;
        struct { unsigned char ex, ep; UL prf, st; void *salt; UL sl; UL sk; void *info; UL il; } hp =
            { 1, 1, 0x250, 1, NULL, 0, 0, NULL, 0 };
        struct { UL m; void *p; UL len; } hkdf = { 0x402A, &hp, sizeof hp };
        fail_audit();
        want("derive, audit failing", CALL(C_DeriveKey, hs, &hkdf, k, NULL, 0UL, &o), 0x30);
        return;
    }
    if (which == 10 || which == 11) {
        /* Slice 6c: a wrap that cannot be audited writes no blob; an unwrap's key is not kept. */
        UL hs, kek = user_key(&hs, 16), x = 0, o = 0xAAAAAAAAUL, out = 64, cls = 4, kt = 0x1f;
        unsigned char yes = 1, key[16] = { 3 }, blob[64];
        struct { UL type; void *p; UL len; } t[] = {
            { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x011, key, 16 },
            { 0x162, &yes, 1 },
        };
        struct { UL m; void *p; UL len; } kw = { 0x2109, NULL, 0 };
        want("create the key to wrap", CALL(C_CreateObject, hs, t, 4UL, &x), 0);
        memset(blob, 0xAA, sizeof blob);
        if (which == 10) {
            fail_audit();
            want("wrap, audit failing", CALL(C_WrapKey, hs, &kw, kek, x, blob, &out), 0x30);
            want("nothing written", blob[0] == 0xAA && blob[23] == 0xAA && out == 64, 1);
            return;
        }
        want("wrap", CALL(C_WrapKey, hs, &kw, kek, x, blob, &out), 0);
        fail_audit();
        want("unwrap, audit failing", CALL(C_UnwrapKey, hs, &kw, kek, blob, out, NULL, 0UL, &o), 0x30);
        return;
    }
    if (which == 6) {
        /* Slice 5: a C_Sign that cannot be audited writes no signature. */
        UL hs, k = user_key(&hs, 16), out = 64;
        unsigned char pt[16] = { 2 }, sig[64];
        struct { UL m; void *p; UL len; } hmac = { 0x251, NULL, 0 };
        memset(sig, 0xAA, sizeof sig);
        want("signinit", CALL(C_SignInit, hs, &hmac, k), 0);
        fail_audit();
        want("sign, audit failing", CALL(C_Sign, hs, pt, 16UL, sig, &out), 0x30);
        want("nothing written", sig[0] == 0xAA && sig[31] == 0xAA && out == 64, 1);
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
    for (int i = 0; i < 13; ++i) {
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
    /* Slices 6b and 6c: an imported or unwrapped key was in the clear outside the token, so it
     * starts with both history bits (C: TRUE, TRUE for a key created or unwrapped locked). */
    UL s = 0, x = 0, u = 0, wl = 64;
    unsigned char blob[64];
    struct { UL type; void *p; UL len; } sec[] = {
        { 0x000, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x011, key, sizeof key },
        { 0x103, &yes, 1 }, { 0x162, &no, 1 },
    }, keep[] = { { 0x162, &no, 1 } };
    struct { UL m; void *p; UL len; } kw = { 0x2109, NULL, 0 };
    want("create a locked key", CALL(C_CreateObject, h, sec, 5UL, &s), 0);
    want("imported ALWAYS_SENSITIVE", hist(h, s, 0x165), 0);
    want("imported NEVER_EXTRACTABLE", hist(h, s, 0x164), 0);
    want("create a key to wrap", CALL(C_CreateObject, h, t, 5UL, &x), 0);
    want("wrap it", CALL(C_WrapKey, h, &kw, s, x, blob, &wl), 0);
    want("unwrap it locked", CALL(C_UnwrapKey, h, &kw, s, blob, wl, keep, 1UL, &u), 0);
    want("unwrapped ALWAYS_SENSITIVE", hist(h, u, 0x165), 0);
    want("unwrapped NEVER_EXTRACTABLE", hist(h, u, 0x164), 0);
    CALL(C_Finalize, NULL);
}

/* Slice 6a. A mechanism, and a CK_ULONG or bytes template row. */
typedef struct { UL m; void *p; UL len; } Mech;
typedef struct { UL type; void *p; UL len; } Attr;

/* The fault on DIV-052's pairwise check. The module binds its libcrypto calls to this
 * executable's definitions first (-rdynamic), and only ML-KEM's pairwise check decapsulates
 * during key generation. */
static int fail_decap;
int EVP_PKEY_decapsulate(void *ctx, unsigned char *s, size_t *sl, const unsigned char *c,
                         size_t cl) {
    static int (*real)(void *, unsigned char *, size_t *, const unsigned char *, size_t);
    if (fail_decap) return 0;
    if (!real) {
        void *crypto = dlopen("libcrypto.so.3", RTLD_NOW | RTLD_NOLOAD);
        /* dlsym(NULL, ...) would find this function again */
        if (!crypto) { fprintf(stderr, "libcrypto.so.3 not loaded\n"); abort(); }
        real = (int (*)(void *, unsigned char *, size_t *, const unsigned char *, size_t))
            dlsym(crypto, "EVP_PKEY_decapsulate");
        if (!real) abort();
    }
    return real(ctx, s, sl, c, cl);
}

/* DIV-052: a failed pairwise check latches ERROR. C asked for ERROR through a transition its
 * table refuses, and the module stayed usable. */
static void div_052(void) {
    UL h, po, vo, o;
    user_key(&h, 16);
    Mech kem = { 0xF, NULL, 0 }, aes = { 0x1080, NULL, 0 };
    UL len = 16;
    Attr t[] = { { 0x161, &len, sizeof len } };
    fail_decap = 1;
    want("a pair whose check fails", CALL(C_GenerateKeyPair, h, &kem, NULL, 0UL, NULL, 0UL, &po, &vo), 0x6);
    fail_decap = 0;
    want("the next pair", CALL(C_GenerateKeyPair, h, &kem, NULL, 0UL, NULL, 0UL, &po, &vo), 0x6);
    want("an AES key", CALL(C_GenerateKey, h, &aes, t, 1UL, &o), 0x6);
    CALL(C_Finalize, NULL);
}

/* CK_PKCS5_PBKD2_PARAMS2, HMAC-SHA256 over a fixed password and salt. */
static unsigned char pb_salt[16] = "NaCl-and-pepper!", pb_pw[8] = "password";
struct pbkd2 { UL src; void *salt; UL salt_len; UL iter; UL prf; void *prf_data; UL prf_len;
               void *pw; UL pw_len; };
static UL pbkdf2(UL h, UL iter, UL kt, UL len) {
    struct pbkd2 p = { 1, pb_salt, 16, iter, 4, NULL, 0, pb_pw, 8 };
    Mech m = { 0x3B0, &p, sizeof p };
    Attr t[] = { { 0x161, &len, sizeof len }, { 0x100, &kt, sizeof kt } };
    UL o = 0;
    return CALL(C_GenerateKey, h, &m, t, 2UL, &o);
}

/* DIV-064: a PBKDF2 key is a generic secret or an AES key of 16, 24 or 32 bytes. C stored
 * any type at any length up to 256. */
static void div_064(void) {
    UL h;
    user_key(&h, 16);
    want("an AES key of 5 bytes", pbkdf2(h, 1000, 0x1f, 5), 0x62);
    want("an EC key of 32 bytes", pbkdf2(h, 1000, 0x3, 32), 0x13);
    want("an AES key of 32 bytes", pbkdf2(h, 1000, 0x1f, 32), 0);
    want("a generic secret of 5 bytes", pbkdf2(h, 1000, 0x10, 5), 0);
    CALL(C_Finalize, NULL);
}

/* RULE-006: a PBKDF2 iteration count past 32 bits is 0x71. C narrowed it first, so
 * 2^32 + 1000 ran 1000 iterations. */
static void rule_006(void) {
    UL h;
    user_key(&h, 16);
    want("2^32 + 1000 iterations", pbkdf2(h, (1UL << 32) + 1000, 0x10, 16), 0x71);
    want("1000 iterations", pbkdf2(h, 1000, 0x10, 16), 0);
    CALL(C_Finalize, NULL);
}

/* RULE-014: in the strict build a generic secret under 112 bits is 0x62, and
 * C_GetMechanismInfo advertises 14 to 64 bytes; the all-mechanisms build keeps 1 to 64. */
static void rule_014(void) {
    UL h, o, len = 24;
    user_key(&h, 16);
    Mech m = { 0x350, NULL, 0 }, des3 = { 0x131, NULL, 0 };
    Attr t[] = { { 0x161, &len, sizeof len } };
    /* DES3 key generation is the strict build's MECHANISM_INVALID, in C and in Rust */
    int strict = CALL(C_GenerateKey, h, &des3, t, 1UL, &o) == 0x70;
    len = 13;
    want("13 bytes", CALL(C_GenerateKey, h, &m, t, 1UL, &o), strict ? 0x62 : 0);
    len = 14;
    want("14 bytes", CALL(C_GenerateKey, h, &m, t, 1UL, &o), 0);
    UL info[3] = { 0 };
    want("mechanism info", CALL(C_GetMechanismInfo, 0UL, 0x350UL, info), 0);
    want("advertised minimum", info[0], strict ? 14 : 1);
    want("advertised maximum", info[1], 64);
    CALL(C_Finalize, NULL);
}

/* RULE-015: an RSA public exponent must be odd and 2^16 < e < 2^256 (FIPS 186-5), and the
 * key is made with it. C took e = 3, and made every key with 65537. */
static void rule_015(void) {
    UL h, po = 0, vo = 0, bits = 2048;
    user_key(&h, 16);
    unsigned char three[1] = { 3 }, e17[3] = { 2, 0, 1 }, got[3] = { 0 };
    Mech m = { 0x0, NULL, 0 };
    Attr t[] = { { 0x121, &bits, sizeof bits }, { 0x122, three, 1 } };
    want("e = 3", CALL(C_GenerateKeyPair, h, &m, t, 2UL, NULL, 0UL, &po, &vo), 0x13);
    t[1].p = e17, t[1].len = 3;
    want("e = 2^17 + 1", CALL(C_GenerateKeyPair, h, &m, t, 2UL, NULL, 0UL, &po, &vo), 0);
    Attr g[] = { { 0x122, got, 3 } };
    want("read e", CALL(C_GetAttributeValue, h, po, g, 1UL), 0);
    want("the key's e", (UL)got[0] << 16 | (UL)got[1] << 8 | got[2], 0x20001);
    CALL(C_Finalize, NULL);
}

/* RULE-017: a CKA_PARAMETER_SET name of another family is 0x13. C took any of the 18: ML-DSA
 * keygen named SLH-DSA stored an SLH-DSA key as CKK_ML_DSA. */
static void rule_017(void) {
    UL h, po, vo;
    user_key(&h, 16);
    Mech dsa = { 0x1C, NULL, 0 };
    char slh[] = "SLH-DSA-SHAKE-128f", ml[] = "ML-DSA-44";
    Attr t[] = { { 0x61D, slh, sizeof slh - 1 } };
    want("ML-DSA named SLH-DSA", CALL(C_GenerateKeyPair, h, &dsa, t, 1UL, NULL, 0UL, &po, &vo), 0x13);
    t[0].p = ml, t[0].len = sizeof ml - 1;
    want("ML-DSA named ML-DSA", CALL(C_GenerateKeyPair, h, &dsa, t, 1UL, NULL, 0UL, &po, &vo), 0);
    CALL(C_Finalize, NULL);
}

/* libcrypto, for keys to import; declared here because evp.h's EVP_PKEY_decapsulate would
 * clash with the interposer's. */
void *EVP_PKEY_Q_keygen(void *lib, const char *props, const char *type, ...);
int EVP_PKEY_get_bn_param(const void *k, const char *name, void **bn);
int BN_bn2bin(const void *bn, unsigned char *to);
void BN_free(void *bn);
void EVP_PKEY_free(void *k);

/* RSA key k's eight components, n to iqmp, into v; their lengths into l. */
static void rsa_parts(void *k, unsigned char v[8][512], UL l[8]) {
    static const char *nm[8] = { "n", "e", "d", "rsa-factor1", "rsa-factor2", "rsa-exponent1",
                                 "rsa-exponent2", "rsa-coefficient1" };
    for (int i = 0; i < 8; ++i) {
        void *bn = NULL;
        EVP_PKEY_get_bn_param(k, nm[i], &bn);
        l[i] = bn ? (UL)BN_bn2bin(bn, v[i]) : 0;
        BN_free(bn);
    }
}

/* DIV-065: an imported RSA key is checked. C stored an empty modulus and a key whose d is
 * another key's, and failed n, e and d alone with 0x6 after asking OpenSSL for the primes. */
static void div_065(void) {
    UL h, o, pub = 2, priv = 3, rsa = 0, l[8], lb[8];
    static unsigned char v[8][512], w[8][512];
    user_key(&h, 16);
    void *a = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    void *b = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    if (!a || !b) { printf("  RSA keygen failed\n"); exit(1); }
    rsa_parts(a, v, l);
    rsa_parts(b, w, lb);
    Attr pt[] = { { 0x0, &pub, sizeof pub }, { 0x100, &rsa, sizeof rsa }, { 0x120, v[0], 0 },
                  { 0x122, v[1], l[1] } };
    want("an empty modulus", CALL(C_CreateObject, h, pt, 4UL, &o), 0x13);
    Attr k[10] = { { 0x0, &priv, sizeof priv }, { 0x100, &rsa, sizeof rsa } };
    for (int i = 0; i < 8; ++i) k[2 + i] = (Attr){ i ? 0x121 + (UL)i : 0x120, v[i], l[i] };  /* e is 0x122 */
    k[4] = (Attr){ 0x123, w[2], lb[2] };
    want("another key's d", CALL(C_CreateObject, h, k, 10UL, &o), 0x13);
    k[4] = (Attr){ 0x123, v[2], l[2] };
    want("n, e and d alone", CALL(C_CreateObject, h, k, 5UL, &o), 0xD0);
    want("the whole key", CALL(C_CreateObject, h, k, 10UL, &o), 0);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    CALL(C_Finalize, NULL);
}

int EVP_PKEY_get_raw_public_key(const void *k, unsigned char *pub, size_t *len);

/* DIV-066: an imported ML-KEM public key keeps CKA_ENCAPSULATE FALSE. C's rebuilt-key path
 * never applied it, so the key read back (and encapsulated) as TRUE. */
static void div_066(void) {
    UL h, o, pub = 2, kem = 0x49, set = 1;
    unsigned char raw[800], f = 0, got = 0xAA;
    size_t n = sizeof raw;
    user_key(&h, 16);
    void *k = EVP_PKEY_Q_keygen(NULL, NULL, "ML-KEM-512");
    if (!k || EVP_PKEY_get_raw_public_key(k, raw, &n) != 1) { printf("  ML-KEM keygen failed\n"); exit(1); }
    EVP_PKEY_free(k);
    Attr t[] = { { 0x0, &pub, sizeof pub }, { 0x100, &kem, sizeof kem }, { 0x11, raw, n },
                 { 0x61D, &set, sizeof set }, { 0x633, &f, 1 } };
    want("create", CALL(C_CreateObject, h, t, 5UL, &o), 0);
    Attr ask = { 0x633, &got, 1 };
    want("read ENCAPSULATE", CALL(C_GetAttributeValue, h, o, &ask, 1UL), 0);
    want("ENCAPSULATE reads FALSE", got, 0);
    CALL(C_Finalize, NULL);
}

/* A user session key of 16 bytes to wrap, SENSITIVE and EXTRACTABLE as given. */
static UL wrap_target(UL h, unsigned char sens, unsigned char ext) {
    UL k = 0, cls = 4, kt = 0x1f;
    unsigned char key[16] = { 7 };
    Attr t[] = { { 0x0, &cls, sizeof cls }, { 0x100, &kt, sizeof kt }, { 0x11, key, 16 },
                 { 0x103, &sens, 1 }, { 0x162, &ext, 1 } };
    want("create the key to wrap", CALL(C_CreateObject, h, t, 5UL, &k), 0);
    return k;
}

/* DIV-058: a key that is not extractable is never wrapped. C refused only one that was also
 * sensitive, so the derive and KEM default (neither) left the token. */
static void div_058(void) {
    UL h, kek = user_key(&h, 16), out = 64;
    Mech kw = { 0x2109, NULL, 0 };
    unsigned char blob[64];
    want("wrap a key neither sensitive nor extractable",
         CALL(C_WrapKey, h, &kw, kek, wrap_target(h, 0, 0), blob, &out), 0x6a);
    out = 64;
    want("wrap an extractable key", CALL(C_WrapKey, h, &kw, kek, wrap_target(h, 0, 1), blob, &out), 0);
    CALL(C_Finalize, NULL);
}

/* DIV-067: C_UnwrapKey stores only a secret key of a secret key type. C stored a CKK_EC secret
 * key, and a secret key for a template asking CKO_PRIVATE_KEY. */
static void div_067(void) {
    UL h, kek = user_key(&h, 16), out = 64, o = 0, ec = 3, priv = 3, aes = 0x1f;
    Mech kw = { 0x2109, NULL, 0 };
    unsigned char blob[64];
    want("wrap", CALL(C_WrapKey, h, &kw, kek, wrap_target(h, 0, 1), blob, &out), 0);
    Attr te[] = { { 0x100, &ec, sizeof ec } }, tc[] = { { 0x0, &priv, sizeof priv } },
         ta[] = { { 0x100, &aes, sizeof aes } };
    want("unwrap as CKK_EC", CALL(C_UnwrapKey, h, &kw, kek, blob, out, te, 1UL, &o), 0x13);
    want("unwrap as CKO_PRIVATE_KEY", CALL(C_UnwrapKey, h, &kw, kek, blob, out, tc, 1UL, &o), 0xd1);
    /* The whole CK_ULONG: C narrowed it to 32 bits and stored this one as AES. */
    UL wide = 0x10000001FUL;
    Attr tw[] = { { 0x100, &wide, sizeof wide } };
    want("unwrap as 2^32 + CKK_AES", CALL(C_UnwrapKey, h, &kw, kek, blob, out, tw, 1UL, &o), 0x13);
    want("unwrap as AES", CALL(C_UnwrapKey, h, &kw, kek, blob, out, ta, 1UL, &o), 0);
    CALL(C_Finalize, NULL);
}

/* Slice 6d: CK_HKDF_PARAMS, extract and expand under SHA-256 with no salt. */
typedef struct { unsigned char ex, ep; UL prf, st; void *salt; UL sl; UL sk; void *info; UL il; } Hkdf;
static Hkdf hk = { 1, 1, 0x250, 1, NULL, 0, 0, NULL, 0 };

/* DIV-057: a key derived from a sensitive key is sensitive, with that key's history; a data
 * object only from CKM_HKDF_DATA. C defaulted every derived key to SENSITIVE FALSE. */
static void div_057(void) {
    UL h, plain = user_key(&h, 32), sk = 0, o = 0, len = 32, data = 0;
    unsigned char yes = 1, no = 0;
    Mech gen = { 0x350, NULL, 0 }, hkdf = { 0x402A, &hk, sizeof hk };
    Attr g[] = { { 0x161, &len, sizeof len }, { 0x103, &yes, 1 }, { 0x10C, &yes, 1 } };
    want("generate a sensitive base", CALL(C_GenerateKey, h, &gen, g, 3UL, &sk), 0);
    want("hkdf from it", CALL(C_DeriveKey, h, &hkdf, sk, NULL, 0UL, &o), 0);
    want("is sensitive", hist(h, o, 0x103), 1);
    want("and always was", hist(h, o, 0x165), 1);
    want("and never extractable", hist(h, o, 0x164), 1);
    Attr te[] = { { 0x162, &yes, 1 } };
    want("hkdf from it, extractable", CALL(C_DeriveKey, h, &hkdf, sk, te, 1UL, &o), 0);
    want("is not never extractable", hist(h, o, 0x164), 0);
    Attr tf[] = { { 0x103, &no, 1 } }, td[] = { { 0x0, &data, sizeof data } };
    want("hkdf from it, sensitive false", CALL(C_DeriveKey, h, &hkdf, sk, tf, 1UL, &o), 0xd1);
    want("hkdf as a data object", CALL(C_DeriveKey, h, &hkdf, plain, td, 1UL, &o), 0xd1);
    /* §6.20.1: the second key of a concatenation is an input too. user_key's AES key is not
     * a combiner's base, so the base is a generic secret made here. */
    UL cls = 4, gk = 0x10, base = 0, k2 = sk;
    unsigned char v[16] = { 1 };
    Attr b[] = { { 0x0, &cls, sizeof cls }, { 0x100, &gk, sizeof gk }, { 0x11, v, 16 },
                 { 0x103, &no, 1 }, { 0x10C, &yes, 1 } };
    Mech cat = { 0x360, &k2, sizeof k2 };
    want("a plain generic base", CALL(C_CreateObject, h, b, 5UL, &base), 0);
    want("concatenate the sensitive key", CALL(C_DeriveKey, h, &cat, base, NULL, 0UL, &o), 0);
    want("is sensitive", hist(h, o, 0x103), 1);
    want("but was not always (its base was imported)", hist(h, o, 0x165), 0);
    want("nor never extractable", hist(h, o, 0x164), 0);
    /* Two keys generated sensitive: the derived key always was, and never was extractable. */
    UL sk2 = 0;
    want("generate a second sensitive key", CALL(C_GenerateKey, h, &gen, g, 3UL, &sk2), 0);
    k2 = sk2;
    want("concatenate two sensitive keys", CALL(C_DeriveKey, h, &cat, sk, NULL, 0UL, &o), 0);
    want("always sensitive", hist(h, o, 0x165), 1);
    want("never extractable", hist(h, o, 0x164), 1);
    /* §6.20: a combiner's output holds its base, so a non-extractable base stays in. */
    struct { void *p; UL len; } none = { NULL, 0 };
    Mech bd = { 0x362, &none, sizeof none };
    want("copy a non-extractable key out extractable", CALL(C_DeriveKey, h, &bd, sk, te, 1UL, &o), 0xd1);
    CALL(C_Finalize, NULL);
}

/* DIV-068: a derived key is of a secret key type, compared whole, and an AES key is 16, 24
 * or 32 bytes. C stored each of these. */
static void div_068(void) {
    UL h, base = user_key(&h, 32), o = 0, ec = 3, wide = 0x10000001FUL, aes = 0x1f, five = 5,
          sixteen = 16, des3 = 0x15;
    Mech hkdf = { 0x402A, &hk, sizeof hk };
    Attr te[] = { { 0x100, &ec, sizeof ec } }, tw[] = { { 0x100, &wide, sizeof wide } },
         t5[] = { { 0x100, &aes, sizeof aes }, { 0x161, &five, sizeof five } },
         t16[] = { { 0x100, &aes, sizeof aes }, { 0x161, &sixteen, sizeof sixteen } },
         td[] = { { 0x100, &des3, sizeof des3 }, { 0x161, &sixteen, sizeof sixteen } };
    want("derive as CKK_EC", CALL(C_DeriveKey, h, &hkdf, base, te, 1UL, &o), 0x13);
    want("derive as 2^32 + CKK_AES", CALL(C_DeriveKey, h, &hkdf, base, tw, 1UL, &o), 0x13);
    want("derive a 5-byte AES key", CALL(C_DeriveKey, h, &hkdf, base, t5, 2UL, &o), 0x62);
    want("derive a 16-byte DES3 key", CALL(C_DeriveKey, h, &hkdf, base, td, 2UL, &o), 0x62);
    want("derive a 16-byte AES key", CALL(C_DeriveKey, h, &hkdf, base, t16, 2UL, &o), 0);
    CALL(C_Finalize, NULL);
}

/* DIV-069: a KEM key is stored as a derived key: a secret key of a secret key type at its
 * size, with its usage. C stored each of these. RULE-037(a): not as a token object from a
 * read-only session. */
static void div_069(void) {
    UL h, pub = 0, priv = 0, cl = 1568, o = 0, d = 0, data = 0, ec = 3, aes = 0x1f,
       five = 5, sixteen = 16, ro = 0;
    unsigned char ct[1568], no = 0, yes = 1;
    user_key(&h, 32); /* the user's session */
    kem_pair(h, &pub, &priv, ct, &cl);
    Mech kem = { 0x17, NULL, 0 }, ecb = { 0x1081, NULL, 0 };
    Attr td[] = { { 0x0, &data, sizeof data } }, te[] = { { 0x100, &ec, sizeof ec } },
         t5[] = { { 0x100, &aes, sizeof aes }, { 0x161, &five, sizeof five } },
         tn[] = { { 0x100, &aes, sizeof aes }, { 0x161, &sixteen, sizeof sixteen }, { 0x104, &no, 1 } },
         tt[] = { { 0x1, &yes, 1 } };
    want("decapsulate as a data object", CALL(C_DecapsulateKey, h, &kem, priv, td, 1UL, ct, cl, &o), 0xd1);
    want("decapsulate as CKK_EC", CALL(C_DecapsulateKey, h, &kem, priv, te, 1UL, ct, cl, &o), 0x13);
    want("decapsulate a 5-byte AES key", CALL(C_DecapsulateKey, h, &kem, priv, t5, 2UL, ct, cl, &o), 0x62);
    want("decapsulate an AES key that may not encrypt",
         CALL(C_DecapsulateKey, h, &kem, priv, tn, 3UL, ct, cl, &o), 0);
    want("which does not encrypt", CALL(C_EncryptInit, h, &ecb, o), 0x68);
    /* PKCS#11's default: a secret key derives only with CKA_DERIVE TRUE (C recorded no usage). */
    Mech hkdf = { 0x402A, &hk, sizeof hk };
    Attr tdv[] = { { 0x10C, &yes, 1 } };
    want("decapsulate a generic secret", CALL(C_DecapsulateKey, h, &kem, priv, NULL, 0UL, ct, cl, &o), 0);
    want("which does not derive", CALL(C_DeriveKey, h, &hkdf, o, NULL, 0UL, &d), 0x68);
    want("decapsulate one that may derive", CALL(C_DecapsulateKey, h, &kem, priv, tdv, 1UL, ct, cl, &o), 0);
    want("which derives", CALL(C_DeriveKey, h, &hkdf, o, NULL, 0UL, &d), 0);
    want("open a read-only session", CALL(C_OpenSession, 0UL, 4UL, NULL, NULL, &ro), 0);
    want("decapsulate to a token object there",
         CALL(C_DecapsulateKey, ro, &kem, priv, tt, 1UL, ct, cl, &o), 0xb5);
    CALL(C_Finalize, NULL);
}

static const struct { const char *name; void (*fn)(void); } tests[] = {
    { "RULE-071", rule_071 }, { "RULE-083", rule_083 }, { "DIV-059", div_059 },
    { "DIV-055", div_055 }, { "RULE-084", rule_084 },
    { "DIV-054", div_054 }, { "DIV-050", div_050 }, { "DIV-001", div_001 },
    { "DIV-060", div_060 }, { "DIV-056", div_056 },
    { "RULE-092", rule_092 }, { "RULE-091", rule_091 }, { "RULE-061", rule_061 },
    { "RULE-059", rule_059 }, { "DIV-061", div_061 }, { "DIV-062", div_062 },
    { "DIV-063", div_063 }, { "DIV-052", div_052 }, { "DIV-064", div_064 },
    { "RULE-006", rule_006 }, { "RULE-014", rule_014 }, { "RULE-015", rule_015 },
    { "RULE-017", rule_017 }, { "DIV-065", div_065 }, { "DIV-066", div_066 },
    { "DIV-058", div_058 }, { "DIV-067", div_067 }, { "DIV-057", div_057 },
    { "DIV-068", div_068 }, { "DIV-069", div_069 },
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
