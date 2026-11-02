/* Phase 1 regression (DIV-009): a forked child that re-initialises must not write into its
 * parent's audit log. The parent's log is verified afterwards by run.sh. */
#include <dlfcn.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

typedef unsigned long CK_RV;

int main(int argc, char **argv) {
    void *h = dlopen(argc > 1 ? argv[1] : "./libfreehsm.so", RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    CK_RV (*initialize)(void *) = (CK_RV (*)(void *))dlsym(h, "C_Initialize");
    CK_RV (*finalize)(void *) = (CK_RV (*)(void *))dlsym(h, "C_Finalize");
    if (!initialize || !finalize) return 2;
    if (initialize(NULL) != 0) return 3;
    pid_t k = fork();
    if (k < 0) return 4;
    if (k == 0) _exit(initialize(NULL) == 0 && finalize(NULL) == 0 ? 0 : 1);
    int st = 0;
    waitpid(k, &st, 0);
    CK_RV rv = finalize(NULL);
    printf("child exit %d, parent C_Finalize 0x%lx\n", WIFEXITED(st) ? WEXITSTATUS(st) : -1, rv);
    return 0;
}
