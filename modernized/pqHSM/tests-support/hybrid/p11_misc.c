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

static void (*const S[])(void) = { s_mechs, s_random, s_stubs, s_error };
static const char *const SN[] = { "mechanisms", "random", "stubs", "error" };

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
