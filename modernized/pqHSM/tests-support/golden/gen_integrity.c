/* Phase 3 slice 4 goldens: RUN the legacy src/fhsm_integrity.c and record what it does.
 *
 *   gen_integrity make <out dir>      (out dir holds the integrity/ files make_integrity_elf.py lays out)
 *
 * Seams, on this link line only (gen_token.mk):
 *   --wrap=dl_iterate_phdr  "our own .so" is the scenario's file: one PT_LOAD around the digest
 *                           symbol, named with the file's path; or none ("not found").
 *   fhsm_state_latch_error  defined here: records the reason.
 *   --wrap=EVP_MD_fetch     fails when the scenario says SHA-384 is unavailable.
 *   the embedded digest     the page holding fhsm_module_integrity_digest is made writable and
 *                           set to zero, to a wrong value, or to what the check computed.
 * Every scenario runs in its own process (the check caches under pthread_once), with its
 * stderr kept in integrity/<scenario>.stderr. Nothing here computes an expected value: "good"
 * is the digest the C itself computed for the file, read back with fhsm_integrity_last_computed. */
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "fhsm_common.h"
#include "fhsm_integrity.h"

#define LEN FHSM_INTEGRITY_DIGEST_LEN

static const char *g_path;      /* NULL: dl_iterate_phdr finds nothing */
static char g_latch[128] = "-";
static const char *g_dir;
static int g_no_sha;            /* EVP_MD_fetch fails */

EVP_MD *__real_EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *alg, const char *props);
EVP_MD *__wrap_EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *alg, const char *props);
EVP_MD *__wrap_EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *alg, const char *props) {
    return g_no_sha ? NULL : __real_EVP_MD_fetch(ctx, alg, props);
}

int __wrap_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data);
int __wrap_dl_iterate_phdr(int (*cb)(struct dl_phdr_info *, size_t, void *), void *data) {
    if (!g_path) return 0;
    ElfW(Phdr) ph;
    memset(&ph, 0, sizeof ph);
    ph.p_type = PT_LOAD;
    ph.p_vaddr = (ElfW(Addr))(uintptr_t)fhsm_module_integrity_digest;
    ph.p_memsz = LEN;
    struct dl_phdr_info info;
    memset(&info, 0, sizeof info);
    info.dlpi_name = g_path;
    info.dlpi_phdr = &ph;
    info.dlpi_phnum = 1;
    return cb(&info, sizeof info, data);
}

void fhsm_state_latch_error(const char *reason) {
    snprintf(g_latch, sizeof g_latch, "%s", reason);
}

static void set_embedded(const uint8_t *d) {
    long pg = sysconf(_SC_PAGESIZE);
    uintptr_t p = (uintptr_t)fhsm_module_integrity_digest;
    uintptr_t start = p & ~(uintptr_t)(pg - 1);
    size_t len = ((p + LEN - start) + (size_t)pg - 1) & ~(size_t)(pg - 1);
    if (mprotect((void *)start, len, PROT_READ | PROT_WRITE) != 0) { perror("mprotect"); exit(3); }
    memcpy((void *)(uintptr_t)fhsm_module_integrity_digest, d, LEN);
}

static void hex(FILE *f, const uint8_t *b, size_t n) {
    int any = 0;
    for (size_t i = 0; i < n; ++i) any |= b[i];
    if (!any) { fputc('-', f); return; }
    for (size_t i = 0; i < n; ++i) fprintf(f, "%02x", b[i]);
}

/* The path the check reports, with the fixture directory cut off. */
static const char *shown(const char *p) {
    size_t n = strlen(g_dir);
    return strncmp(p, g_dir, n) == 0 && p[n] == '/' ? p + n + 1 : p;
}

/* Runs one scenario in a child. file NULL: not found. calls: how many times to verify (the
 * file is removed between calls). Writes the computed digest to *last when it is non-NULL. */
static void scenario(FILE *tsv, const char *name, const char *file, const uint8_t *embedded,
                     const char *kind, int bypass, int calls, uint8_t *last) {
    int fd[2];
    if (pipe(fd) != 0) exit(3);
    char path[512];
    if (file) snprintf(path, sizeof path, "%s/%s", g_dir, file);
    fflush(tsv);
    pid_t pid = fork();
    if (pid == 0) {
        close(fd[0]);
        char err[600];
        snprintf(err, sizeof err, "%s/integrity/%s.stderr", g_dir, name);
        if (!freopen(err, "w", stderr)) exit(3);
        setvbuf(stderr, NULL, _IONBF, 0);   /* as C's stderr; _exit below flushes nothing */
        if (bypass) setenv("FHSM_INTEGRITY_ALLOW_UNSIGNED", "1", 1);
        else unsetenv("FHSM_INTEGRITY_ALLOW_UNSIGNED");
        set_embedded(embedded);
        g_path = file ? path : NULL;
        fprintf(tsv, "%s\t%s:%s:%s:%d", name, file ? file : "(not found)", kind,
                bypass ? "bypass" : "strict", calls);
        for (int c = 0; c < calls; ++c) {
            fhsm_rv_t rv = fhsm_integrity_verify();
            fprintf(tsv, "%srv=0x%x", c ? ";" : "\t", (unsigned)rv);
            if (c == 0 && calls > 1) unlink(path);
        }
        fprintf(tsv, ";latch=%s;signed=%d;last=", g_latch, fhsm_integrity_is_signed());
        hex(tsv, fhsm_integrity_last_computed(), LEN);
        fprintf(tsv, ";path=%s\n", shown(fhsm_integrity_so_path()));
        fflush(tsv);
        if (write(fd[1], fhsm_integrity_last_computed(), LEN) != LEN) _exit(3);
        _exit(0);
    }
    close(fd[1]);
    uint8_t got[LEN];
    ssize_t n = read(fd[0], got, LEN);
    close(fd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0 || n != LEN) {
        fprintf(stderr, "gen_integrity: scenario %s failed\n", name);
        exit(1);
    }
    if (last) memcpy(last, got, LEN);
}

static const char *FILES[] = {
    "good", "wide_section", "short_section", "no_section", "bad_magic", "elf32", "no_table",
    "bad_shentsize", "table_past_end", "shstrndx_out", "strtab_past_end", "name_past_strtab",
    "name_unterminated", "section_past_end", "tiny", "empty",
};

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "make") != 0) {
        fprintf(stderr, "usage: gen_integrity make <out dir>\n");
        return 2;
    }
    g_dir = argv[2];
    char p[512];
    snprintf(p, sizeof p, "%s/integrity.tsv", g_dir);
    FILE *tsv = fopen(p, "w");
    if (!tsv) return 1;
    fprintf(tsv, "# Generated by tests-support/golden/gen_integrity.c from the legacy C code. Do not edit.\n"
                 "# scenario\tfile:embedded:mode:calls\tresult  (selftest/tests/integrity_golden.rs)\n");
    uint8_t zero[LEN] = {0}, wrong[LEN];
    memset(wrong, 0x5a, LEN);

    for (size_t i = 0; i < sizeof FILES / sizeof FILES[0]; ++i) {
        char file[64], name[96];
        snprintf(file, sizeof file, "integrity/%s.elf", FILES[i]);
        uint8_t computed[LEN];
        for (int bypass = 0; bypass <= 1; ++bypass) {
            const char *mode = bypass ? "bypass" : "strict";
            snprintf(name, sizeof name, "%s_zero_%s", FILES[i], mode);
            scenario(tsv, name, file, zero, "zero", bypass, 1, NULL);
            snprintf(name, sizeof name, "%s_wrong_%s", FILES[i], mode);
            scenario(tsv, name, file, wrong, "wrong", bypass, 1, computed);
            int any = 0;
            for (size_t k = 0; k < LEN; ++k) any |= computed[k];
            if (any) {
                snprintf(name, sizeof name, "%s_good_%s", FILES[i], mode);
                scenario(tsv, name, file, computed, "good", bypass, 1, NULL);
            }
        }
    }
    for (int bypass = 0; bypass <= 1; ++bypass) {
        const char *mode = bypass ? "bypass" : "strict";
        char name[96];
        snprintf(name, sizeof name, "not_found_%s", mode);
        scenario(tsv, name, NULL, wrong, "wrong", bypass, 1, NULL);
        snprintf(name, sizeof name, "missing_file_%s", mode);
        scenario(tsv, name, "integrity/missing.elf", wrong, "wrong", bypass, 1, NULL);
        g_no_sha = 1;   /* inherited by the child */
        snprintf(name, sizeof name, "no_sha384_%s", mode);
        scenario(tsv, name, "integrity/good.elf", wrong, "no-sha384", bypass, 1, NULL);
        g_no_sha = 0;
    }
    /* The result is cached: a second call does not read the file again. */
    uint8_t computed[LEN];
    scenario(tsv, "cached_probe", "integrity/good.elf", wrong, "wrong", 0, 1, computed);
    char src[512], dst[512];
    snprintf(src, sizeof src, "%s/integrity/good.elf", g_dir);
    snprintf(dst, sizeof dst, "%s/integrity/cached.elf", g_dir);
    FILE *a = fopen(src, "rb"), *b = fopen(dst, "wb");
    if (!a || !b) return 1;
    int c;
    while ((c = fgetc(a)) != EOF) fputc(c, b);
    fclose(a);
    fclose(b);
    scenario(tsv, "cached", "integrity/cached.elf", computed, "good", 0, 2, NULL);
    fclose(tsv);
    return 0;
}
