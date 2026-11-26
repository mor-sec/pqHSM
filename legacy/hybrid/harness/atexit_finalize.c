/* Phase 1 regression (architecture review, finding 1): C_Finalize from an atexit handler runs
 * after the main thread's TLS destructors, and must still return instead of aborting. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef unsigned long CK_RV;
static CK_RV (*finalize)(void *);

static void finalize_at_exit(void) {
    fprintf(stderr, "C_Finalize at exit: 0x%lx\n", finalize(NULL));
}

int main(int argc, char **argv) {
    void *h = dlopen(argc > 1 ? argv[1] : "./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*initialize)(void *) = (CK_RV (*)(void *))dlsym(h, "C_Initialize");
    finalize = (CK_RV (*)(void *))dlsym(h, "C_Finalize");
    if (!initialize || !finalize) return 2;
    CK_RV rv = initialize(NULL);
    if (rv != 0) { fprintf(stderr, "C_Initialize: 0x%lx\n", rv); return 3; }
    atexit(finalize_at_exit);
    return 0;
}
