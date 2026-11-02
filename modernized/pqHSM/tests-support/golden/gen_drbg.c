/* Phase 3 slice 2 goldens: RUN the legacy src/fhsm_drbg.c against a scripted generator and
 * record what it returns.
 *
 *   gen_drbg make OUTDIR
 *
 * Linked with --wrap=RAND_bytes (a deterministic xorshift stream, with injected runs, repeats and
 * failures), --wrap=RAND_add (counts reseeds), --wrap=time (a scripted clock) and
 * --wrap=EVP_MD_fetch (fails the conditioner on demand). fhsm_state_get/_latch_error are defined
 * here: fhsm_state.c is not linked. Each scenario runs in its own forked child, because the DRBG
 * state is module-static. Writes OUTDIR/drbg.tsv; crypto/tests/drbg_golden.rs replays it. Used
 * only by regen_crypto.sh. */
#include "fhsm_common.h"
#include "fhsm_drbg.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ---- the seams ---------------------------------------------------------------------------- */

int __wrap_RAND_bytes(unsigned char *buf, int num);
void __wrap_RAND_add(const void *buf, int num, double randomness);
time_t __wrap_time(time_t *t);
EVP_MD *__real_EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *alg, const char *props);
EVP_MD *__wrap_EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *alg, const char *props);

static uint64_t g_prng = 0x9E3779B97F4A7C15ull;
static time_t g_clock = 1000000;
static int g_cond_fail = 0;
static int g_state = FHSM_STATE_INITIALIZED;
static char g_latch[128];

/* The injection armed for the next RAND_bytes call. */
static enum { INJ_NONE, INJ_REP, INJ_APT, INJ_DUPFIRST, INJ_DUPNEXT, INJ_DUPLAST, INJ_SAME } g_inj;
static unsigned g_inj_b, g_inj_k;
static int g_fail_rand_in = 0;                 /* fail the Nth call from now; 0 = off */
static unsigned char g_prev[65536];
static size_t g_prev_len = 0;

static char g_chunks[2048];
static unsigned g_adds = 0;
/* FNV-1a of every byte RAND_bytes produced in this op: what the caller would get if no check fired. */
static uint64_t g_gen;

static uint64_t fnv64_add(uint64_t h, const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 0x100000001b3ull; }
    return h;
}

static uint8_t prng_byte(void) {
    g_prng ^= g_prng >> 12; g_prng ^= g_prng << 25; g_prng ^= g_prng >> 27;
    return (uint8_t)((g_prng * 0x2545F4914F6CDD1Dull) >> 56);
}

static uint8_t prng_not(uint8_t b) {
    uint8_t x = prng_byte();
    return x == b ? (uint8_t)(x ^ 1) : x;
}

static void note_chunk(int num) {
    char one[32];
    snprintf(one, sizeof one, "%s%d", g_chunks[0] ? "," : "", num);
    strncat(g_chunks, one, sizeof g_chunks - strlen(g_chunks) - 1);
}

int __wrap_RAND_bytes(unsigned char *buf, int num) {
    note_chunk(num);
    if (g_fail_rand_in && --g_fail_rand_in == 0) return 0;
    size_t n = (size_t)num;
    for (size_t i = 0; i < n; i++) buf[i] = prng_byte();
    switch (g_inj) {
    case INJ_REP:       /* K copies of B, then a byte that is not B */
        for (size_t i = 0; i < g_inj_k && i < n; i++) buf[i] = (uint8_t)g_inj_b;
        if (g_inj_k < n) buf[g_inj_k] = prng_not((uint8_t)g_inj_b);
        break;
    case INJ_APT:       /* B at 0, 2, 4, ... K times, never elsewhere in the first 512 */
        for (size_t i = 0; i < n && i < 512; i++)
            buf[i] = (i % 2 == 0 && i / 2 < g_inj_k) ? (uint8_t)g_inj_b : prng_not((uint8_t)g_inj_b);
        break;
    case INJ_DUPFIRST:  /* first block = the previous call's first block */
        if (n >= 16 && g_prev_len >= 16) memcpy(buf, g_prev, 16);
        break;
    case INJ_DUPNEXT:   /* second block = this call's first block */
        if (n >= 32) memcpy(buf + 16, buf, 16);
        break;
    case INJ_DUPLAST:   /* first block = the previous call's last full block */
        if (n >= 16 && g_prev_len >= 16) memcpy(buf, g_prev + (g_prev_len / 16 - 1) * 16, 16);
        break;
    case INJ_SAME:      /* the previous call's bytes again */
        if (n <= g_prev_len) memcpy(buf, g_prev, n);
        break;
    case INJ_NONE:
        break;
    }
    g_inj = INJ_NONE;
    g_gen = fnv64_add(g_gen, buf, n);
    memcpy(g_prev, buf, n);
    g_prev_len = n;
    return 1;
}

void __wrap_RAND_add(const void *buf, int num, double randomness) {
    (void)buf; (void)randomness;
    if (num == 48) g_adds++;
}

time_t __wrap_time(time_t *t) {
    if (t) *t = g_clock;
    return g_clock;
}

EVP_MD *__wrap_EVP_MD_fetch(OSSL_LIB_CTX *ctx, const char *alg, const char *props) {
    return g_cond_fail ? NULL : __real_EVP_MD_fetch(ctx, alg, props);
}

fhsm_module_state_t fhsm_state_get(void) { return (fhsm_module_state_t)g_state; }

void fhsm_state_latch_error(const char *reason) {
    snprintf(g_latch, sizeof g_latch, "%s", reason ? reason : "");
    g_state = FHSM_STATE_ERROR;
}

/* ---- scenarios ---------------------------------------------------------------------------- */

struct scenario { const char *name; const char *ops; };

static const struct scenario SCEN[] = {
    { "basic", "init stats bytes:32 bytes:1 stats reseed stats bytes_null bytes:0 init stats" },
    { "chunking", "init bytes:200000 stats" },
    { "reseed_bytes", "init bytes:1048576 bytes:1 bytes:1 stats" },
    { "reseed_bytes_mid", "init bytes:1000000 bytes:200000 stats" },
    { "reseed_time", "init clock:3600 bytes:8 clock:1 bytes:8 stats" },
    { "lazy", "bytes:16 stats init stats" },
    { "lazy_fail", "fail_cond bytes:16 stats ok_cond bytes:16 stats" },
    { "rct_5", "init rep:65:5 bytes:64 stats" },
    { "rct_6", "init rep:66:6 bytes:64 stats bytes:8" },
    { "rct_across_calls", "init bytes:64 rep:0:3 bytes:3 rep:0:3 bytes:3 stats" },
    { "apt_18", "init apt:90:18 bytes:512 stats" },
    { "apt_19", "init apt:90:19 bytes:512 stats" },
    { "apt_51", "init apt:90:51 bytes:512 stats" },
    { "apt_52", "init apt:90:52 bytes:512 stats" },
    { "apt_window_reset", "init apt:90:18 bytes:512 apt:90:18 bytes:512 stats" },
    { "crngt_first_block", "init bytes:64 dupfirst bytes:64 stats" },
    { "crngt_within_request", "init dupnext bytes:64 stats" },
    { "crngt_last_block", "init bytes:64 duplast bytes:64 stats" },
    { "crngt_short", "init bytes:8 same bytes:8 stats" },
    { "rand_fail_mid", "init fail_rand:2 bytes:200000 stats bytes:8" },
    { "cond_fail_init", "fail_cond init stats ok_cond init stats" },
    { "cond_fail_reseed", "init fail_cond reseed stats" },
    { "cond_fail_periodic", "init fail_cond clock:3601 bytes:32 bytes:32 stats" },
    { "cond_fail_periodic_mid", "init bytes:1000000 fail_cond bytes:200000 stats" },
    { "error_state", "init state_error bytes:8 reseed stats" },
};

static FILE *tsv;

#define FNV_BASIS 0xcbf29ce484222325ull

static void run_op(const char *sc, const char *op) {
    const char *arg = strchr(op, ':');
    char res[2300];
    g_chunks[0] = 0; g_adds = 0; g_latch[0] = 0; g_gen = FNV_BASIS;

    if (!strcmp(op, "init") || !strcmp(op, "reseed")) {
        /* the call first: argument evaluation order is unspecified */
        fhsm_rv_t rv = op[0] == 'i' ? fhsm_drbg_init() : fhsm_drbg_reseed();
        snprintf(res, sizeof res, "rv=0x%x;adds=%u", rv, g_adds);
    }
    else if (!strcmp(op, "stats")) {
        fhsm_drbg_stats_t s;
        fhsm_drbg_get_stats(&s);
        snprintf(res, sizeof res, "emitted=%llu,reseeds=%u,rct=%u,apt=%u,crngt=%u,src=%u",
                 (unsigned long long)s.bytes_emitted, s.reseeds, s.rct_failures, s.apt_failures,
                 s.crngt_failures, s.entropy_sources_active);
    } else if (!strcmp(op, "bytes_null")) {
        snprintf(res, sizeof res, "rv=0x%x", fhsm_drbg_bytes(NULL, 8));
    } else if (!strncmp(op, "bytes:", 6)) {
        size_t n = strtoul(arg + 1, NULL, 10);
        unsigned char *buf = malloc(n ? n : 1);
        if (!buf) { perror("malloc"); _exit(3); }
        memset(buf, 0xEE, n ? n : 1);
        fhsm_rv_t rv = fhsm_drbg_bytes(buf, n);
        uint64_t sum = fnv64_add(FNV_BASIS, buf, n);
        int len = snprintf(res, sizeof res, "rv=0x%x;chunks=%s;adds=%u;sum=%016llx", rv, g_chunks,
                           g_adds, (unsigned long long)sum);
        if (g_gen != sum && g_chunks[0])
            len += snprintf(res + len, sizeof res - len, ";gen=%016llx", (unsigned long long)g_gen);
        if (g_latch[0]) snprintf(res + len, sizeof res - len, ";latch=%s", g_latch);
        free(buf);
    } else if (!strncmp(op, "clock:", 6)) {
        g_clock += strtol(arg + 1, NULL, 10);
        snprintf(res, sizeof res, "ok");
    } else if (!strncmp(op, "rep:", 4) || !strncmp(op, "apt:", 4)) {
        g_inj = op[0] == 'r' ? INJ_REP : INJ_APT;
        sscanf(arg + 1, "%u:%u", &g_inj_b, &g_inj_k);
        snprintf(res, sizeof res, "ok");
    } else if (!strcmp(op, "dupfirst")) { g_inj = INJ_DUPFIRST; snprintf(res, sizeof res, "ok"); }
    else if (!strcmp(op, "dupnext")) { g_inj = INJ_DUPNEXT; snprintf(res, sizeof res, "ok"); }
    else if (!strcmp(op, "duplast")) { g_inj = INJ_DUPLAST; snprintf(res, sizeof res, "ok"); }
    else if (!strcmp(op, "same")) { g_inj = INJ_SAME; snprintf(res, sizeof res, "ok"); }
    else if (!strncmp(op, "fail_rand:", 10)) { g_fail_rand_in = atoi(arg + 1); snprintf(res, sizeof res, "ok"); }
    else if (!strcmp(op, "fail_cond")) { g_cond_fail = 1; snprintf(res, sizeof res, "ok"); }
    else if (!strcmp(op, "ok_cond")) { g_cond_fail = 0; snprintf(res, sizeof res, "ok"); }
    else if (!strcmp(op, "state_error")) { g_state = FHSM_STATE_ERROR; snprintf(res, sizeof res, "ok"); }
    else { fprintf(stderr, "unknown op %s\n", op); _exit(3); }
    fprintf(tsv, "%s\t%s\t%s\n", sc, op, res);
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "make")) {
        fprintf(stderr, "usage: gen_drbg make OUTDIR\n");
        return 2;
    }
    char p[1024];
    snprintf(p, sizeof p, "%s/drbg.tsv", argv[2]);
    tsv = fopen(p, "w");
    if (!tsv) { perror(p); return 1; }
    fprintf(tsv, "# Generated by tests-support/golden/gen_drbg.c from the legacy C code. Do not edit.\n"
                 "# scenario\top\tresult  (crypto/tests/drbg_golden.rs)\n");
    for (size_t i = 0; i < sizeof SCEN / sizeof *SCEN; i++) {
        fflush(tsv);
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); return 1; }
        if (pid == 0) {
            char ops[512];
            snprintf(ops, sizeof ops, "%s", SCEN[i].ops);
            for (char *t = strtok(ops, " "); t; t = strtok(NULL, " ")) run_op(SCEN[i].name, t);
            fflush(tsv);
            _exit(0);
        }
        int st;
        if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            fprintf(stderr, "scenario %s failed\n", SCEN[i].name);
            return 1;
        }
    }
    return fclose(tsv) == 0 ? 0 : 1;
}
