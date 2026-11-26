/* tests/abi/test_kat_results.c --- the module's one export beyond PKCS#11 (Phase 6 slice 5c).
 *
 * fhsm_kat_results() reports the power-on self-tests C_Initialize ran. legacy/tests/test_smoke.c
 * checked it by linking the C objects; this reaches it as any consumer would, by dlsym on the
 * module: after C_Initialize the report holds between 1 and 64 records, each passed, with
 * non-NULL names that outlive the call (include/fhsm_crypto.h, LIFETIME). */
#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *algorithm;
    const char *vector_id;
    int         passed;
    uint32_t    duration_us;
} kat_result_t;

typedef unsigned long (*init_fn)(void *);
typedef const kat_result_t *(*kat_fn)(size_t *);

static int fails;
static void check(int ok, const char *what)
{
    printf("  %s  %s\n", ok ? "ok  " : "FAIL", what);
    fails += !ok;
}

/* Overwrites the stack a callee's locals would have used. */
static void __attribute__((noinline)) scribble(void)
{
    volatile char junk[8192];
    memset((char *)junk, 0x5A, sizeof junk);
}

int main(void)
{
    printf("test_kat_results\n");
    void *m = dlopen("./libfreehsm.so", RTLD_NOW);
    if (!m) { printf("dlopen: %s\n", dlerror()); return 1; }
    init_fn init, fin;
    kat_fn kat;
    *(void **)&init = dlsym(m, "C_Initialize");
    *(void **)&fin = dlsym(m, "C_Finalize");
    *(void **)&kat = dlsym(m, "fhsm_kat_results");
    check(init && fin && kat, "C_Initialize, C_Finalize and fhsm_kat_results are exported");
    if (!init || !fin || !kat) return 1;
    check(init(NULL) == 0, "C_Initialize");
    size_t n = 0;
    const kat_result_t *r = kat(&n);
    check(r != NULL && n >= 1 && n <= 64, "between 1 and 64 records");
    char snap[64][64];
    int named = 1, passed = 1;
    for (size_t i = 0; r && i < n && i < 64; ++i) {
        named &= r[i].algorithm != NULL && r[i].vector_id != NULL;
        passed &= r[i].passed == 1;
        snprintf(snap[i], sizeof snap[i], "%s", r[i].vector_id ? r[i].vector_id : "");
    }
    check(named, "every record is named");
    check(passed, "every self-test passed");
    scribble();
    int kept = 1;
    for (size_t i = 0; r && i < n && i < 64; ++i)
        kept &= r[i].vector_id && strcmp(snap[i], r[i].vector_id) == 0;
    check(kept, "the names outlive the call");
    check(fin(NULL) == 0, "C_Finalize");
    printf("\ntest_kat_results : %s\n", fails ? "FAIL" : "PASS");
    return fails != 0;
}
