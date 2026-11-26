/* The tests that need every entry point (DIVERGENCES.md § Phase 4).
 *
 * DIV-051: outside an initialised process every C_* except C_Initialize and the three that
 * hand out the function lists returns CKR_CRYPTOKI_NOT_INITIALIZED (0x190), and
 * C_Finalize(pReserved != NULL) returns CKR_ARGUMENTS_BAD (0x7) first. Three states: before
 * C_Initialize, after C_Finalize, and a forked child of an initialised parent that has not
 * called C_Initialize.
 *
 * DIV-053: in ERROR every C_* but C_Finalize, the nine status calls, and (amended after the
 * slice 1 review, M2) C_Logout, C_CloseSession and C_CloseAllSessions returns
 * CKR_FUNCTION_FAILED (0x6), a digest started before the latch included; those do not. ERROR is latched from outside by a failed audit write: RLIMIT_FSIZE at the log's size,
 * then an audited call.
 *
 *   p11_notinit LIB
 *
 * Prints every call that answers otherwise, one summary line per state, and one line per DIV;
 * exit 0 only if both pass. Each state runs in a child, so a crash in the C is reported, not
 * fatal. Both fail on the C library. */
#include <dirent.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

typedef unsigned long UL;
typedef struct { UL mech; void *p; UL len; } Mech;
typedef UL (*F)();   /* each called with its own arguments below */

static void *lib;
static int bad, n;
static unsigned char z[4096];
static Mech sha = { 0x250, NULL, 0 };   /* CKM_SHA256: harmless if a call gets through */

static F sym(const char *name) {
    F f = (F)dlsym(lib, name);
    if (!f) { fprintf(stderr, "no %s\n", name); exit(2); }
    return f;
}

static void want(const char *state, const char *name, UL rv, UL expect) {
    ++n;
    if (rv != expect) { ++bad; printf("%s\t%s\t0x%lx\n", state, name, rv); }
}

static int in_error;   /* DIV-053's state rather than DIV-051's */

/* A refused call: 0x190, or in ERROR 0x6. A status call (or one of the three DIV-053 lets
 * through): 0x190, or in ERROR anything else. */
static void call(const char *state, const char *name, UL rv, int status) {
    if (!in_error) { want(state, name, rv, 0x190); return; }
    ++n;
    if (status ? rv == 0x6 : rv != 0x6) { ++bad; printf("%s\t%s\t0x%lx\n", state, name, rv); }
}

#define C(name, ...) call(state, #name, sym(#name)(__VA_ARGS__), 0)
#define S(name, ...) call(state, #name, sym(#name)(__VA_ARGS__), 1)

/* Every entry point but C_Initialize and the list calls, h a session handle, s a slot. */
static void all(const char *state, UL h, UL s) {
    UL *u = (UL *)z;
    memset(z, 0, sizeof z);
    S(C_GetInfo, z);
    S(C_GetSlotList, 0, NULL, u);
    S(C_GetSlotInfo, s, z);
    S(C_GetTokenInfo, s, z);
    S(C_GetMechanismList, s, NULL, u);
    S(C_GetMechanismInfo, s, 0x250UL, z);
    C(C_InitToken, s, "12345678", 8UL, "                                ");
    C(C_InitPIN, h, "12345678", 8UL);
    C(C_SetPIN, h, "12345678", 8UL, "87654321", 8UL);
    C(C_OpenSession, s, 6UL, NULL, NULL, u);
    S(C_CloseSession, h);
    S(C_CloseAllSessions, s);
    C(C_GetSessionInfo, h, z);
    C(C_Login, h, 1UL, "12345678", 8UL);
    S(C_Logout, h);
    C(C_CreateObject, h, z, 0UL, u);
    C(C_CopyObject, h, 1UL, z, 0UL, u);
    C(C_DestroyObject, h, 1UL);
    C(C_GetObjectSize, h, 1UL, u);
    C(C_GetAttributeValue, h, 1UL, z, 0UL);
    C(C_SetAttributeValue, h, 1UL, z, 0UL);
    C(C_FindObjectsInit, h, z, 0UL);
    C(C_FindObjects, h, u, 0UL, u + 1);
    C(C_FindObjectsFinal, h);
    C(C_EncryptInit, h, &sha, 1UL);
    C(C_Encrypt, h, z, 0UL, z, u);
    C(C_EncryptUpdate, h, z, 0UL, z, u);
    C(C_EncryptFinal, h, z, u);
    C(C_DecryptInit, h, &sha, 1UL);
    C(C_Decrypt, h, z, 0UL, z, u);
    C(C_DecryptUpdate, h, z, 0UL, z, u);
    C(C_DecryptFinal, h, z, u);
    C(C_DigestInit, h, &sha);
    C(C_Digest, h, z, 0UL, z, u);
    C(C_DigestUpdate, h, z, 0UL);
    C(C_DigestKey, h, 1UL);
    C(C_DigestFinal, h, z, u);
    C(C_SignInit, h, &sha, 1UL);
    C(C_Sign, h, z, 0UL, z, u);
    C(C_SignUpdate, h, z, 0UL);
    C(C_SignFinal, h, z, u);
    C(C_VerifyInit, h, &sha, 1UL);
    C(C_Verify, h, z, 0UL, z, 0UL);
    C(C_VerifyUpdate, h, z, 0UL);
    C(C_VerifyFinal, h, z, 0UL);
    C(C_GenerateKey, h, &sha, z, 0UL, u);
    C(C_GenerateKeyPair, h, &sha, z, 0UL, z, 0UL, u, u + 1);
    C(C_WrapKey, h, &sha, 1UL, 2UL, z, u);
    C(C_UnwrapKey, h, &sha, 1UL, z, 0UL, z, 0UL, u);
    C(C_DeriveKey, h, &sha, 1UL, z, 0UL, u);
    C(C_EncapsulateKey, h, &sha, 1UL, z, 0UL, z, u, u + 1);
    C(C_DecapsulateKey, h, &sha, 1UL, z, 0UL, z, 0UL, u);
    C(C_SeedRandom, h, z, 0UL);
    C(C_GenerateRandom, h, z, 0UL);
    C(C_GetFunctionStatus, h);
    C(C_CancelFunction, h);
    C(C_WaitForSlotEvent, 1UL, u, NULL);   /* CKF_DONT_BLOCK */
    if (in_error) {
        want(state, "C_Finalize in ERROR", sym("C_Finalize")(NULL), 0);
        return;
    }
    want(state, "C_Finalize reserved", sym("C_Finalize")((void *)1), 0x7);
    C(C_Finalize, NULL);
}

/* An initialised token and an open, logged-in session, so the later states have a real
 * handle: the C answers it with CKR_OK, which is the defect. */
static UL setup(void) {
    UL h = 0;
    if (sym("C_Initialize")(NULL) || sym("C_InitToken")(0UL, "12345678", 8UL,
            "notinit                         ")
        || sym("C_OpenSession")(0UL, 6UL, NULL, NULL, &h)
        || sym("C_Login")(h, 0UL, "12345678", 8UL)) {
        fprintf(stderr, "setup failed\n");
        exit(2);
    }
    return h;
}

static void summary(const char *state) {
    printf("%s: %d of %d refused as expected\n", state, n - bad, n);
}

/* DIV-053: a digest under way, then ERROR, then every call. The digest's update is the
 * active operation that must refuse; the session still exists. */
static void error_state(void) {
    UL h = setup(), d[64];
    want("error", "C_DigestInit before the latch", sym("C_DigestInit")(h, &sha), 0);
    want("error", "C_DigestUpdate before the latch", sym("C_DigestUpdate")(h, "abc", 3UL), 0);
    /* The log the module has open: the newest audit.log* in the tokens dir. */
    const char *dir = getenv("FHSM_TOKENS_DIR");
    char log[600] = "", p[600];
    struct stat st, best = { 0 };
    DIR *dd = opendir(dir);
    for (struct dirent *e; dd && (e = readdir(dd));) {
        snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
        if (!strncmp(e->d_name, "audit.log", 9) && !stat(p, &st) && S_ISREG(st.st_mode)
            && st.st_mtime >= best.st_mtime) {
            best = st;
            snprintf(log, sizeof log, "%s", p);
        }
    }
    if (dd) closedir(dd);
    if (!*log) { printf("error\tno audit.log* in %s\n", dir); ++bad; return; }
    st = best;
    signal(SIGXFSZ, SIG_IGN);
    struct rlimit rl = { (rlim_t)st.st_size, (rlim_t)st.st_size };
    setrlimit(RLIMIT_FSIZE, &rl);
    sym("C_Logout")(h);   /* audited; its write fails and latches ERROR */
    sym("C_Logout")(h);
    in_error = 1;
    /* The digest first, before anything else could end it. */
    call("error", "C_DigestUpdate on the active digest", sym("C_DigestUpdate")(h, "abc", 3UL), 0);
    call("error", "C_DigestFinal on the active digest", sym("C_DigestFinal")(h, d, d + 8), 0);
    all("error", h, 0);
}

static int run(int which) {
    pid_t p = fork();
    if (p == 0) {
        UL h;
        switch (which) {
        case 0:
            all("before-initialize", 1, 0);
            summary("before-initialize");
            break;
        case 3:
            error_state();
            summary("error");
            break;
        case 1:
            h = setup();
            sym("C_Finalize")(NULL);
            all("after-finalize", h, 0);
            summary("after-finalize");
            break;
        default:
            h = setup();
            fflush(stdout);
            pid_t c = fork();
            if (c == 0) {
                all("forked-child", h, 0);
                summary("forked-child");
                _exit(bad ? 1 : 0);
            }
            int cs;
            waitpid(c, &cs, 0);
            sym("C_Finalize")(NULL);
            _exit(WIFEXITED(cs) ? WEXITSTATUS(cs) : 3);
        }
        _exit(bad ? 1 : 0);
    }
    int st;
    waitpid(p, &st, 0);
    if (!WIFEXITED(st)) printf("state %d: killed by signal %d\n", which, WTERMSIG(st));
    return WIFEXITED(st) ? WEXITSTATUS(st) : 3;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: p11_notinit LIB\n"); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    int rc = 0;
    for (int i = 0; i < 3; ++i) rc |= run(i);
    printf("DIV-051: %s\n", rc ? "FAIL" : "pass");
    int rc53 = run(3);
    printf("DIV-053: %s\n", rc53 ? "FAIL" : "pass");
    return rc || rc53 ? 1 : 0;
}
