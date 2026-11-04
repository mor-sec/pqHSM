/* DIV-051's test (DIVERGENCES.md § Phase 4): outside an initialised process every C_* except
 * C_Initialize and the three that hand out the function lists returns
 * CKR_CRYPTOKI_NOT_INITIALIZED (0x190), and C_Finalize(pReserved != NULL) returns
 * CKR_ARGUMENTS_BAD (0x7) first. Three states: before C_Initialize, after C_Finalize, and a
 * forked child of an initialised parent that has not called C_Initialize.
 *
 *   p11_notinit LIB
 *
 * Prints every call that answers otherwise and one summary line per state; exit 0 only if
 * none did. Fails on the C library, which checks only for ERROR. Each state runs in a child,
 * so a crash in the C after C_Finalize is reported, not fatal. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define C(name, ...) want(state, #name, sym(#name)(__VA_ARGS__), 0x190)

/* Every entry point but C_Initialize and the list calls, h a session handle, s a slot. */
static void all(const char *state, UL h, UL s) {
    UL *u = (UL *)z;
    memset(z, 0, sizeof z);
    C(C_GetInfo, z);
    C(C_GetSlotList, 0, NULL, u);
    C(C_GetSlotInfo, s, z);
    C(C_GetTokenInfo, s, z);
    C(C_GetMechanismList, s, NULL, u);
    C(C_GetMechanismInfo, s, 0x250UL, z);
    C(C_InitToken, s, "12345678", 8UL, "                                ");
    C(C_InitPIN, h, "12345678", 8UL);
    C(C_SetPIN, h, "12345678", 8UL, "87654321", 8UL);
    C(C_OpenSession, s, 6UL, NULL, NULL, u);
    C(C_CloseSession, h);
    C(C_CloseAllSessions, s);
    C(C_GetSessionInfo, h, z);
    C(C_Login, h, 1UL, "12345678", 8UL);
    C(C_Logout, h);
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

static int run(int which) {
    pid_t p = fork();
    if (p == 0) {
        UL h;
        switch (which) {
        case 0:
            all("before-initialize", 1, 0);
            summary("before-initialize");
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
    return rc ? 1 : 0;
}
