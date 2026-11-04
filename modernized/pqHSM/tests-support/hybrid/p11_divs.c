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
    /* The destroy part: the SO cannot destroy the user's key (0x82, as for no such object). */
    want("logout user again", CALL(C_Logout, h), 0);
    want("login so", CALL(C_Login, h, 0UL, SO, (UL)strlen(SO)), 0);
    want("so destroys the user's key", CALL(C_DestroyObject, h, k), 0x82);
    want("logout so again", CALL(C_Logout, h), 0);
    want("login user a third time", CALL(C_Login, h, 1UL, USER, (UL)strlen(USER)), 0);
    want("the key survived", CALL(C_EncryptInit, h, &ecb, k), 0);
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
    for (int i = 0; i < 4; ++i) {
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

static const struct { const char *name; void (*fn)(void); } tests[] = {
    { "RULE-071", rule_071 }, { "RULE-083", rule_083 }, { "DIV-059", div_059 },
    { "DIV-055", div_055 }, { "RULE-084", rule_084 },
    { "DIV-054", div_054 }, { "DIV-050", div_050 }, { "DIV-001", div_001 },
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
