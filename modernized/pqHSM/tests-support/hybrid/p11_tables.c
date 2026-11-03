/* p11_tables.c LIB --- every function table the module hands out, slot by slot, and the
 * argument checks of the three calls that hand them out (PHASE4_PLAN.md slice 0).
 *
 * Slots print as the exported symbol at that address, or "unexported" (the not-supported
 * stub). Nothing prints an address, so the output of the C and the hybrid module must be
 * identical: harness step 4f diffs them. */
#define _GNU_SOURCE   /* dladdr */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

typedef unsigned long UL;
typedef struct { unsigned char major, minor; } Ver;
typedef struct { Ver version; void *pfn[]; } List;
typedef struct { char *name; List *list; UL flags; } Iface;
typedef UL (*GetList)(List **);
typedef UL (*GetIfaceList)(Iface *, UL *);
typedef UL (*GetIface)(const char *, const Ver *, Iface **, UL);

static void *unexported;   /* the one address no exported symbol has */
static int stubs = 0;      /* distinct such addresses: 1 in C */

static const char *slot_name(void *p) {
    Dl_info di;
    if (dladdr(p, &di) && di.dli_sname && di.dli_saddr == p) return di.dli_sname;
    if (unexported != p) { unexported = p; stubs++; }
    return "unexported";
}

static void dump(const char *tag, const List *l, int n) {
    printf("%s version %u.%u\n", tag, l->version.major, l->version.minor);
    for (int i = 0; i < n; i++) printf("%s %d %s\n", tag, i, slot_name(l->pfn[i]));
}

static const char *which(const List *l, const List *v240, const List *v30, const List *v32) {
    return l == v240 ? "v2.40" : l == v30 ? "v3.0" : l == v32 ? "v3.2" : "other";
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s LIB\n", argv[0]); return 2; }
    void *h = dlopen(argv[1], RTLD_NOW);
    if (!h) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 2; }
    GetList gl = (GetList)dlsym(h, "C_GetFunctionList");
    GetIfaceList gil = (GetIfaceList)dlsym(h, "C_GetInterfaceList");
    GetIface gi = (GetIface)dlsym(h, "C_GetInterface");
    if (!gl || !gil || !gi) { fprintf(stderr, "missing symbols\n"); return 2; }

    List *v240 = NULL, *again = NULL;
    printf("C_GetFunctionList(NULL) 0x%lx\n", gl(NULL));
    UL r1 = gl(&v240), r2 = gl(&again);   /* argument order is unspecified: call first */
    printf("C_GetFunctionList 0x%lx 0x%lx same %d\n", r1, r2, v240 == again);

    Iface *i30 = NULL, *i32 = NULL, *p = NULL;
    UL rv;
    static const Ver vs[] = { {3, 2}, {3, 0}, {2, 40}, {3, 1}, {3, 3}, {0, 0} };
    gi("PKCS 11", &vs[0], &i32, 0);
    gi("PKCS 11", &vs[1], &i30, 0);
    if (!v240 || !i30 || !i32) { printf("no tables\n"); return 1; }
    const List *v30 = i30->list, *v32 = i32->list;
    dump("v2.40", v240, 68);
    dump("v3.0", v30, 92);
    dump("v3.2", v32, 104);
    printf("unexported addresses %d; calling one: 0x%lx\n", stubs,
           stubs == 1 ? ((UL (*)(void))unexported)() : 0UL);

    /* C_GetInterface: argument order, names, versions, flags, and that a returned record is not
     * rewritten by a later call (src/fhsm_pkcs11.c:13340-13356). */
    printf("C_GetInterface(NULL out) 0x%lx\n", gi("PKCS 11", NULL, NULL, 0));
    printf("C_GetInterface(bad name, NULL out) 0x%lx\n", gi("PKCS 12", NULL, NULL, 0));
    const char *names[] = { NULL, "PKCS 11", "PKCS 12", "", "PKCS 11 " };
    for (int n = 0; n < 5; n++) {
        p = NULL;
        rv = gi(names[n], NULL, &p, 0);
        printf("C_GetInterface(%s, NULL version) 0x%lx %s\n", names[n] ? names[n] : "NULL", rv,
               p ? which(p->list, v240, v30, v32) : "-");
    }
    for (int n = 0; n < 6; n++) {
        p = NULL;
        rv = gi(NULL, &vs[n], &p, 0);
        printf("C_GetInterface(NULL, %u.%u) 0x%lx %s", vs[n].major, vs[n].minor, rv,
               p ? which(p->list, v240, v30, v32) : "-");
        if (p) printf(" name \"%s\" flags 0x%lx", p->name, p->flags);
        printf("\n");
    }
    p = NULL;
    rv = gi("PKCS 11", &vs[0], &p, 1);
    printf("C_GetInterface(flags 1) 0x%lx %s\n", rv, p ? which(p->list, v240, v30, v32) : "-");
    Iface *a = NULL, *b = NULL;
    gi(NULL, &vs[0], &a, 0); gi(NULL, &vs[1], &b, 0);
    printf("v3.2 record after a v3.0 call: %s; same record each call %d\n",
           which(a->list, v240, v30, v32), a == i32 && b == i30);

    /* C_GetInterfaceList: the size query, a short buffer, and the entries (:13359-13372). */
    UL n = 99;
    printf("C_GetInterfaceList(NULL, NULL) 0x%lx\n", gil(NULL, NULL));
    rv = gil(NULL, &n);
    printf("C_GetInterfaceList(NULL, &n) 0x%lx n=%lu\n", rv, n);
    Iface buf[4];
    memset(buf, 0, sizeof buf);
    n = 1;
    rv = gil(buf, &n);
    printf("C_GetInterfaceList(n=1) 0x%lx n=%lu first %s\n", rv, n, buf[0].list ? "written" : "untouched");
    n = 4;
    rv = gil(buf, &n);
    printf("C_GetInterfaceList(n=4) 0x%lx n=%lu\n", rv, n);
    for (int k = 0; k < 2; k++)
        printf("  [%d] name \"%s\" %s flags 0x%lx name shared %d\n", k, buf[k].name,
               which(buf[k].list, v240, v30, v32), buf[k].flags, buf[k].name == i32->name);

    printf("v2.40 slot 3 is C_GetFunctionList %d; v3.0 slots 68, 69 are the exports %d %d\n",
           v240->pfn[3] == (void *)gl, v30->pfn[68] == (void *)gil, v30->pfn[69] == (void *)gi);
    return 0;
}
