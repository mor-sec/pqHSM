/* Phase 3 slice 1 goldens: RUN the legacy src/fhsm_conf.c and src/fhsm_memory.c through their
 * C ABI and record what they return.
 *
 *   gen_crypto make OUTDIR
 *
 * Writes OUTDIR/cases.tsv, the conf files each row read (OUTDIR/conf/, OUTDIR/heap/), and the
 * stderr of each heap scenario (OUTDIR/heap/<scenario>.stderr). The arena is created once per
 * process, so each heap scenario runs in its own forked child. crypto/tests/golden.rs replays
 * every row through the Rust C ABI. Used only by regen_crypto.sh. */
#include "fhsm_common.h"
#include "fhsm_conf.h"

#include <openssl/crypto.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *OUT;
static FILE *tsv;

static void die(const char *what) { perror(what); exit(1); }

static void hex(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) fprintf(tsv, "%02x", p[i]);
}

static void write_file(const char *path, const char *s, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f || fwrite(s, 1, n, f) != n || fclose(f) != 0) die(path);
}

/* ---- fhsm_conf_lookup / fhsm_conf_secure_heap_bytes ------------------------------------- */

struct conf_case { const char *name; const char *text; size_t len; const char *key; size_t outlen; };
#define T(s) s, sizeof(s) - 1
#define ABSENT NULL, 0

static const struct conf_case LOOKUP[] = {
    { "exact",            T("mode = fips\n"), "mode", 32 },
    { "no_spaces",        T("mode=fips\n"), "mode", 32 },
    { "prefix_key",       T("modem = x\n"), "mode", 32 },
    { "longer_key_first", T("mode_extra = y\nmode = z\n"), "mode", 32 },
    { "leading_space",    T("   mode = fips\n"), "mode", 32 },
    { "tabs",             T("\tmode\t=\tfips\t\n"), "mode", 32 },
    { "vt_ff_leading",    T("\v\fmode = x\n"), "mode", 32 },
    { "comment_hash",     T("#mode = a\n"), "mode", 32 },
    { "comment_semi",     T(";mode = a\n"), "mode", 32 },
    { "section",          T("[mode]\nmode = b\n"), "mode", 32 },
    { "blank_lines",      T("\n\n  \nmode = c\n"), "mode", 32 },
    { "inline_hash",      T("mode = fips # c\n"), "mode", 32 },
    { "inline_semi",      T("mode = fi;ps\n"), "mode", 32 },
    { "crlf",             T("mode = fips\r\n"), "mode", 32 },
    { "empty_then_set",   T("mode =\nmode = b\n"), "mode", 32 },
    { "empty_only",       T("mode = \n"), "mode", 32 },
    { "comment_only_val", T("mode = #x\n"), "mode", 32 },
    { "first_wins",       T("mode = a\nmode = b\n"), "mode", 32 },
    { "no_equals",        T("mode fips\n"), "mode", 32 },
    { "double_equals",    T("mode==x\n"), "mode", 32 },
    { "no_final_newline", T("mode = last"), "mode", 32 },
    { "vt_in_value",      T("mode = \vx\n"), "mode", 32 },
    { "inner_spaces",     T("mode = a b  c  \n"), "mode", 32 },
    { "non_ascii",        T("mode = \xc3\xa9t\xc3\xa9\n"), "mode", 32 },
    { "nul_in_value",     T("mode = ab\0cd\n"), "mode", 32 },
    { "nul_first",        T("\0mode = x\nmode = y\n"), "mode", 32 },
    { "truncate_3",       T("mode = fips\n"), "mode", 3 },
    { "truncate_1",       T("mode = fips\n"), "mode", 1 },
    { "truncate_rtrim",   T("mode = a   b\n"), "mode", 4 },
    { "exact_fit",        T("mode = fips\n"), "mode", 5 },
    { "other_key",        T("secure_heap_kb = 128\nmode = fips\n"), "secure_heap_kb", 32 },
    { "empty_file",       T(""), "mode", 32 },
    { "absent",           ABSENT, "mode", 32 },
    /* Argument checks: each returns 0 before the file is opened. */
    { "args_null_key",    T("mode = fips\n"), NULL, 32 },
    { "args_empty_key",   T("mode = fips\n"), "", 32 },
    { "args_null_out",    T("mode = fips\n"), "mode", 0 },
    { "args_outlen_0",    T("mode = fips\n"), "mode", 0 },
};

static const struct conf_case HEAP_BYTES[] = {
    { "hb_absent_file",   ABSENT, NULL, 0 },
    { "hb_absent_key",    T("mode = fips\n"), NULL, 0 },
    { "hb_min",           T("secure_heap_kb = 64\n"), NULL, 0 },
    { "hb_below_min",     T("secure_heap_kb = 63\n"), NULL, 0 },
    { "hb_max",           T("secure_heap_kb = 65536\n"), NULL, 0 },
    { "hb_above_max",     T("secure_heap_kb = 65537\n"), NULL, 0 },
    { "hb_round_100",     T("secure_heap_kb = 100\n"), NULL, 0 },
    { "hb_round_1000",    T("secure_heap_kb = 1000\n"), NULL, 0 },
    { "hb_pow2_4096",     T("secure_heap_kb = 4096\n"), NULL, 0 },
    { "hb_plus",          T("secure_heap_kb = +128\n"), NULL, 0 },
    { "hb_minus_zero",    T("secure_heap_kb = -0\n"), NULL, 0 },
    { "hb_minus_wraps",   T("secure_heap_kb = -18446744073709486080\n"), NULL, 0 },
    { "hb_vt_leading",    T("secure_heap_kb = \v128\n"), NULL, 0 },
    { "hb_suffix",        T("secure_heap_kb = 128kb\n"), NULL, 0 },
    { "hb_space_suffix",  T("secure_heap_kb = 128 kb\n"), NULL, 0 },
    { "hb_inline_comment",T("secure_heap_kb = 128 # more\n"), NULL, 0 },
    { "hb_hex",           T("secure_heap_kb = 0x80\n"), NULL, 0 },
    { "hb_leading_zeros", T("secure_heap_kb = 00128\n"), NULL, 0 },
    { "hb_overflow",      T("secure_heap_kb = 18446744073709551616\n"), NULL, 0 },
    { "hb_truncated_big", T("secure_heap_kb = 1280000000000000000000000000000000\n"), NULL, 0 },
    { "hb_truncated_one", T("secure_heap_kb = 000000000000000000000000000000128\n"), NULL, 0 },
    { "hb_empty",         T("secure_heap_kb =\n"), NULL, 0 },
    { "hb_sign_only",     T("secure_heap_kb = -\n"), NULL, 0 },
};

static void conf_path(char *p, size_t n, const char *dir, const char *name) {
    snprintf(p, n, "%s/%s/%s.conf", OUT, dir, name);
}

static void put_conf(const char *dir, const struct conf_case *c) {
    char p[1024];
    conf_path(p, sizeof p, dir, c->name);
    if (c->text) write_file(p, c->text, c->len);
    if (setenv("FHSM_CONF", p, 1) != 0) die("setenv");
}

static void lookup_row(const struct conf_case *c) {
    put_conf("conf", c);
    int null_out = !strcmp(c->name, "args_null_out");
    char out[64];
    memset(out, 0xAA, sizeof out);
    int rv = fhsm_conf_lookup(c->key, null_out ? NULL : out, null_out ? 32 : c->outlen);
    fprintf(tsv, "%s\tlookup\t%d\tkey=", c->name, rv);
    if (c->key) hex((const unsigned char *)c->key, strlen(c->key)); else fputs("NULL", tsv);
    fprintf(tsv, "\toutlen=%zu", null_out ? (size_t)32 : c->outlen);
    if (null_out) fputs("\tout=NULL", tsv);
    else if (rv) { fputs("\tout=", tsv); hex((unsigned char *)out, strlen(out)); }
    fputc('\n', tsv);
}

/* A line longer than fgets' 511 bytes is read as several: a key in the second piece of a long
 * comment line is found (kept in Rust, PHASE3_PLAN.md slice 1). */
static void long_line_rows(void) {
    static char text[1200];
    size_t n = 0;
    text[n++] = '#';
    while (n < 511) text[n++] = 'x';
    n += (size_t)sprintf(text + n, "mode = sneaky\n");
    struct conf_case c = { "long_line_split", text, n, "mode", 32 };
    lookup_row(&c);
    /* 512 bytes with the newline: the newline is a piece of its own. */
    n = (size_t)sprintf(text, "mode = ");
    while (n < 511) text[n++] = 'v';
    text[n++] = '\n';
    struct conf_case d = { "long_value_511", text, n, "mode", 64 };
    lookup_row(&d);
}

/* ---- the secure heap --------------------------------------------------------------------- */

/* env: where FHSM_CONF points. "file": heap/<name>.conf with `conf`; "absent": that path, not
 * written; "empty": FHSM_CONF="" (the default path, absent in the image). */
struct heap_scenario { const char *name; const char *env; const char *conf; const char *ops; };

static const struct heap_scenario HEAP[] = {
    { "default", "absent", NULL,
      "total init vmlck used malloc:100 used zalloc:64 used free used free malloc:0 free free_null "
      "malloc:9000000 ct:: ct:00:00 ct:01:03 ct:0ff0:0000 ct:a5a5a5:a5a5a4 zeroize:32 zeroize_null" },
    { "lazy", "absent", NULL, "malloc:64 used total init" },
    { "env_empty", "empty", NULL, "total init" },
    { "kb100", "file", "secure_heap_kb = 100\n",
      "total init vmlck malloc:100000 malloc:100000 used" },
    { "memlock_short", "file", "secure_heap_kb = 65536\n",
      "memlock:8388608 init malloc:16 zalloc:16 total vmlck" },
    { "alloc_fail", "file", "secure_heap_kb = 65536\n",
      "memlock:8388608 as_headroom:16777216 init malloc:16 total" },
    { "adopt_locked", "absent", NULL, "arena:1048576 init total vmlck malloc:100 used" },
    { "adopt_unlocked", "absent", NULL,
      "memlock:0 arena:1048576 memlock:8388608 init total malloc:16" },
};

static long status_kb(const char *field) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return -1;
    char line[256];
    long kb = -1;
    size_t n = strlen(field);
    while (fgets(line, sizeof line, f))
        if (!strncmp(line, field, n)) { kb = strtol(line + n, NULL, 10); break; }
    fclose(f);
    return kb;
}

static int soft_limit(int res, rlim_t v) {
    struct rlimit rl;
    if (getrlimit(res, &rl) != 0) return -1;
    rl.rlim_cur = v;
    return setrlimit(res, &rl);
}

static size_t unhex(const char *s, size_t n, unsigned char *out) {
    for (size_t i = 0; i + 1 < n; i += 2) sscanf(s + i, "%2hhx", &out[i / 2]);
    return n / 2;
}

static void run_op(const char *sc, const char *op) {
    static void *stack[16];
    static int top = 0;
    const char *arg = strchr(op, ':');
    size_t n = arg ? strtoul(arg + 1, NULL, 10) : 0;
    char res[64];

    if (!strcmp(op, "total")) snprintf(res, sizeof res, "%zu", fhsm_secure_heap_total());
    else if (!strcmp(op, "init")) snprintf(res, sizeof res, "0x%x", fhsm_secure_heap_init());
    else if (!strcmp(op, "used")) snprintf(res, sizeof res, "%zu", fhsm_secure_heap_used());
    else if (!strcmp(op, "vmlck")) snprintf(res, sizeof res, "%ld", status_kb("VmLck:"));
    else if (!strncmp(op, "malloc:", 7) || !strncmp(op, "zalloc:", 7)) {
        int z = op[0] == 'z';
        unsigned char *p = z ? fhsm_secure_zalloc(n) : fhsm_secure_malloc(n);
        if (!p) snprintf(res, sizeof res, "null");
        else {
            int zero = 1;
            for (size_t i = 0; z && i < n; i++) zero &= p[i] == 0;
            snprintf(res, sizeof res, "%s%s", CRYPTO_secure_allocated(p) ? "secure" : "plain",
                     z ? (zero ? ",zeroed" : ",dirty") : "");
            stack[top++] = p;
        }
    } else if (!strcmp(op, "free")) {
        fhsm_secure_free(top ? stack[--top] : NULL);
        snprintf(res, sizeof res, "ok");
    } else if (!strcmp(op, "free_null")) {
        fhsm_secure_free(NULL);
        snprintf(res, sizeof res, "ok");
    } else if (!strncmp(op, "ct:", 3)) {
        const char *b = strchr(op + 3, ':');
        unsigned char x[32], y[32];
        size_t lx = unhex(op + 3, (size_t)(b - op - 3), x);
        unhex(b + 1, strlen(b + 1), y);
        snprintf(res, sizeof res, "%d", fhsm_ct_memcmp(lx ? x : NULL, lx ? y : NULL, lx));
    } else if (!strncmp(op, "zeroize:", 8)) {
        unsigned char *p = malloc(n);
        if (!p) die("malloc");
        memset(p, 0x5a, n);
        fhsm_zeroize(p, n);
        int zero = 1;
        for (size_t i = 0; i < n; i++) zero &= p[i] == 0;
        free(p);
        snprintf(res, sizeof res, zero ? "zeroed" : "dirty");
    } else if (!strcmp(op, "zeroize_null")) {
        unsigned char b[4] = { 1, 2, 3, 4 };
        fhsm_zeroize(NULL, 8);
        fhsm_zeroize(b, 0);
        snprintf(res, sizeof res, b[0] == 1 && b[3] == 4 ? "ok" : "touched");
    } else if (!strncmp(op, "memlock:", 8)) {
        snprintf(res, sizeof res, soft_limit(RLIMIT_MEMLOCK, n) ? "err" : "ok");
    } else if (!strncmp(op, "as_headroom:", 12)) {
        rlim_t lim = (rlim_t)status_kb("VmSize:") * 1024 + n;
        snprintf(res, sizeof res, soft_limit(RLIMIT_AS, lim) ? "err" : "ok");
    } else if (!strncmp(op, "arena:", 6)) {
        snprintf(res, sizeof res, "%d", CRYPTO_secure_malloc_init(n, 32));
    } else {
        fprintf(stderr, "unknown op %s\n", op);
        _exit(3);
    }
    fprintf(tsv, "heap_%s\t%s\t%s\n", sc, op, res);
}

static void heap_scenario(const struct heap_scenario *s) {
    char p[1024];
    conf_path(p, sizeof p, "heap", s->name);
    if (!strcmp(s->env, "file")) write_file(p, s->conf, strlen(s->conf));
    fprintf(tsv, "heap_%s\tenv\t%s\n", s->name, s->env);
    fflush(tsv);

    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        if (setenv("FHSM_CONF", strcmp(s->env, "empty") ? p : "", 1) != 0) die("setenv");
        snprintf(p, sizeof p, "%s/heap/%s.stderr", OUT, s->name);
        /* dup2, not freopen: stderr stays unbuffered, as the module sees it. */
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0 || dup2(fd, 2) < 0) die(p);
        char ops[1024];
        snprintf(ops, sizeof ops, "%s", s->ops);
        for (char *t = strtok(ops, " "); t; t = strtok(NULL, " ")) run_op(s->name, t);
        fflush(tsv);
        _exit(0);
    }
    int st;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        fprintf(stderr, "heap scenario %s failed\n", s->name);
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc != 3 || strcmp(argv[1], "make")) {
        fprintf(stderr, "usage: gen_crypto make OUTDIR\n");
        return 2;
    }
    OUT = argv[2];
    char p[1024];
    const char *dirs[] = { "conf", "heap" };
    for (size_t i = 0; i < 2; i++) {
        snprintf(p, sizeof p, "%s/%s", OUT, dirs[i]);
        mkdir(p, 0755);
    }
    snprintf(p, sizeof p, "%s/cases.tsv", OUT);
    tsv = fopen(p, "w");
    if (!tsv) die(p);
    fprintf(tsv, "# Generated by tests-support/golden/gen_crypto.c from the legacy C code. Do not edit.\n"
                 "# case\top\trv\tkey=value...  (crypto/tests/golden.rs)\n");

    for (size_t i = 0; i < sizeof LOOKUP / sizeof *LOOKUP; i++) lookup_row(&LOOKUP[i]);
    long_line_rows();
    for (size_t i = 0; i < sizeof HEAP_BYTES / sizeof *HEAP_BYTES; i++) {
        put_conf("conf", &HEAP_BYTES[i]);
        fprintf(tsv, "%s\theap_bytes\t%zu\n", HEAP_BYTES[i].name, fhsm_conf_secure_heap_bytes());
    }
    for (size_t i = 0; i < sizeof HEAP / sizeof *HEAP; i++) heap_scenario(&HEAP[i]);
    return fclose(tsv) == 0 ? 0 : 1;
}
