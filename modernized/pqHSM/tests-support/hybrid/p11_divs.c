/* Phase 4 slice 1's divergence tests (DIVERGENCES.md § Phase 4), one function each. DIV-051's
 * is p11_notinit.c, which needs every entry point.
 *
 *   p11_divs LIB BASE
 *
 * Each test runs in a forked child with its own tokens directory BASE/<name>, and prints its
 * name, pass or FAIL, and for a FAIL every check that answered otherwise. Exit 0 only if all
 * pass. Each must fail on the C library and pass on Rust. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

static const struct { const char *name; void (*fn)(void); } tests[] = {
    { "RULE-071", rule_071 }, { "RULE-083", rule_083 }, { "DIV-059", div_059 },
    { "DIV-055", div_055 },
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
