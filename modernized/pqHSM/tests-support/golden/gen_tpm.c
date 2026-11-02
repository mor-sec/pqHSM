/* Golden generator for Phase 2 slice 1: the TPM sealing code (src/fhsm_tpm.c through the
 * FHSM_TPM_TEST_HOOKS seam, src/fhsm_token_tpm.c). Writes token/tests/golden/tpm/.
 *
 * Runs the LEGACY C code against tests/tpm2-stub.sh (and tpm2-probe-stub.sh, which wraps
 * it) and records what it returns and what it leaves behind. Built by gen_token.mk
 * (target gen_tpm, linked exactly like tests/test_tpm), driven by regen_tpm.sh.
 *
 *   gen_tpm make OUTDIR STUB PROBE WORKDIR
 *
 * Every case runs in its own forked child, so fhsm_tpm_available()'s process-wide cache
 * starts empty for each one. Output:
 *   OUTDIR/cases.tsv        case, op, rv, then key=value columns (see README.md)
 *   OUTDIR/log/CASE.txt     FHSM_TPM_FAKE_LOG as the stub wrote it (raw fd numbers)
 *   OUTDIR/probe/CASE.txt   FHSM_TPM_PROBE_LOG, for the cases that use the probe stub
 *   OUTDIR/input/CASE.hex   bytes placed in a companion file before the call
 *
 * The secret is the invented, non-secret pattern 0x00..0x1f. Nothing from the legacy tree
 * that is credential-like is used.
 */
#include "fhsm_common.h"
#include "fhsm_tpm.h"
#include "fhsm_token_tpm.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PCR "golden-pcr"
#define TPM_DIR "/var/lib/freehsm/tpm"

static const char *OUT, *STUB, *PROBE, *WORK;
static FILE *tsv;
static uint8_t S[32];
static const char *CASE;
static char cdir[512], device[600], fake_log[600], probe_log[600];
static char kv[65536], envcol[512];

static void die(const char *m) {
    fprintf(stderr, "gen_tpm: %s: %s: %s\n", CASE ? CASE : "-", m, strerror(errno));
    _exit(2);
}

/* ---- key=value columns ------------------------------------------------- */
static void kvs(const char *k, const char *v) {
    size_t l = strlen(kv);
    snprintf(kv + l, sizeof kv - l, "\t%s=%s", k, v);
}
static void kvhex(const char *k, const uint8_t *b, size_t n) {
    size_t l = strlen(kv);
    l += (size_t)snprintf(kv + l, sizeof kv - l, "\t%s=", k);
    for (size_t i = 0; i < n && l + 3 < sizeof kv; i++) l += (size_t)snprintf(kv + l, 3, "%02x", b[i]);
}
static void kvnum(const char *k, long long v) {
    char b[32];
    snprintf(b, sizeof b, "%lld", v);
    kvs(k, b);
}
static void emit(const char *op, const char *rv) {
    fprintf(tsv, "%s\t%s\t%s", CASE, op, rv);
    if (envcol[0]) fprintf(tsv, "\tenv=%s", envcol);
    fprintf(tsv, "%s\n", kv);
    kv[0] = envcol[0] = '\0';
}
static void emit_rv(const char *op, fhsm_rv_t rv) {
    char b[16];
    snprintf(b, sizeof b, "0x%x", (unsigned)rv);
    emit(op, b);
}
static void emit_int(const char *op, int v) {
    char b[16];
    snprintf(b, sizeof b, "%d", v);
    emit(op, b);
}

/* ---- files -------------------------------------------------------------- */
static long slurp(const char *path, uint8_t *buf, size_t cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    size_t n = 0;
    ssize_t r;
    while (n < cap && (r = read(fd, buf + n, cap - n)) > 0) n += (size_t)r;
    close(fd);
    return (long)n;
}
static void spit(const char *path, const uint8_t *b, size_t n) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || (n && write(fd, b, n) != (ssize_t)n) || close(fd) != 0) die(path);
}
static void copy_if_exists(const char *src, const char *dir) {
    static uint8_t b[1 << 16];
    long n = slurp(src, b, sizeof b);
    if (n < 0) return;
    char dst[1024];
    snprintf(dst, sizeof dst, "%s/%s/%s.txt", OUT, dir, CASE);
    spit(dst, b, (size_t)n);
}
static void dump_input(const uint8_t *b, size_t n) {
    char p[1024];
    snprintf(p, sizeof p, "%s/input/%s.hex", OUT, CASE);
    FILE *f = fopen(p, "w");
    if (!f) die(p);
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
    fputc('\n', f);
    fclose(f);
}
/* What is at `path` now: absent | dir | fifo | file:MODE:HEX | file:MODE:unreadable */
static void kvstate(const char *k, const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) { kvs(k, "absent"); return; }
    if (S_ISDIR(st.st_mode)) { kvs(k, "dir"); return; }
    if (S_ISFIFO(st.st_mode)) { kvs(k, "fifo"); return; }
    static uint8_t b[4096];
    char head[32];
    snprintf(head, sizeof head, "file:%04o:", (unsigned)(st.st_mode & 07777));
    long n = slurp(path, b, sizeof b);
    size_t l = strlen(kv);
    snprintf(kv + l, sizeof kv - l, "\t%s=%s", k, head);
    if (n < 0) { strcat(kv, "unreadable"); return; }
    l = strlen(kv);
    for (long i = 0; i < n && l + 3 < sizeof kv; i++) l += (size_t)snprintf(kv + l, 3, "%02x", b[i]);
}
static int count_prefix(const char *path, const char *prefix) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[4096];
    int c = 0;
    while (fgets(line, sizeof line, f)) c += strncmp(line, prefix, strlen(prefix)) == 0;
    fclose(f);
    return c;
}

/* ---- per-case environment ---------------------------------------------- */
static void knob(const char *assign) {
    if (putenv(strdup(assign)) != 0) die("putenv");
    size_t l = strlen(envcol);
    snprintf(envcol + l, sizeof envcol - l, "%s%s", l ? " " : "", assign);
}
static void use_probe(void) {
    char c[1024];
    snprintf(c, sizeof c, "sh %s", PROBE);
    setenv("FHSM_TPM_CMD", c, 1);
    setenv("FHSM_TPM_PROBE_LOG", probe_log, 1);
    kvs("stub", "probe");
}
static void no_device(void) { unlink(device); kvs("device", "absent"); }
static void ready(void) {
    if (!fhsm_tpm_available()) die("ready: fhsm_tpm_available() said no");
    unlink(fake_log);
    unlink(probe_log);
}

/* A token path exactly `n` bytes long under this case's dir, directories created. The
 * algorithm is mirrored by `path_of_len` in token/tests/common/mod.rs. */
static const char *tok_len(size_t n) {
    static char p[1100];
    size_t len = (size_t)snprintf(p, sizeof p, "%s", cdir);
    while (n - len > 200) {
        p[len++] = '/';
        memset(p + len, 'd', 150);
        len += 150;
        p[len] = '\0';
        if (mkdir(p, 0755) != 0 && errno != EEXIST) die("tok_len mkdir");
    }
    p[len++] = '/';
    memset(p + len, 't', n - len);
    p[n] = '\0';
    if (strlen(p) != n) die("tok_len");
    char b[24];
    snprintf(b, sizeof b, "len:%zu", n);
    kvs("tok", b);
    return p;
}
static const char *tok_plain(void) {
    static char p[700];
    snprintf(p, sizeof p, "%s/t.tok", cdir);
    kvs("tok", "plain");
    return p;
}
static const char *with(const char *tok, const char *suffix) {
    static char b[4][1200];
    static int i;
    i = (i + 1) % 4;
    snprintf(b[i], sizeof b[i], "%s%s", tok, suffix);
    return b[i];
}
static void pre_bytes(const char *tok, const uint8_t *b, size_t n, const char *kind) {
    spit(with(tok, ".tpm"), b, n);
    dump_input(b, n);
    kvs("pre", kind);
}
static void pre_dir(const char *tok, int nonempty) {
    if (mkdir(with(tok, ".tpm"), 0755) != 0) die("pre_dir");
    if (nonempty) spit(with(tok, ".tpm/keep"), (const uint8_t *)"k", 1);
    kvs("pre", nonempty ? "dir_nonempty" : "dir");
}
static void after(const char *tok) {
    kvstate("after_tpm", with(tok, ".tpm"));
    kvstate("after_tmp", with(tok, ".tpm.new"));
    kvstate("after_tok", tok);
}

static size_t golden_blob(uint8_t *b) {
    char p[700];
    snprintf(p, sizeof p, "%s/blob.bin", WORK);
    long n = slurp(p, b, 4096);
    if (n <= 0) die("blob.bin (seal_ok must run first)");
    return (size_t)n;
}
/* TPS1 | pub "POLICY:golden-pcr" | priv = zeros then S, `total` bytes in all. */
static size_t crafted_blob(uint8_t *b, size_t total) {
    static const char pol[] = "POLICY:" PCR;
    size_t pl = sizeof pol - 1, rl = total - 12 - pl;
    memcpy(b, "TPS1", 4);
    for (int i = 0; i < 4; i++) {
        b[4 + i] = (uint8_t)(pl >> (8 * i));
        b[8 + i] = (uint8_t)(rl >> (8 * i));
    }
    memcpy(b + 12, pol, pl);
    memset(b + 12 + pl, 0, rl - 32);
    memcpy(b + total - 32, S, 32);
    return total;
}

static void run(const char *name, void (*fn)(const void *), const void *arg) {
    fflush(tsv);
    pid_t pid = fork();
    if (pid < 0) die("fork");
    if (pid == 0) {
        CASE = name;
        snprintf(cdir, sizeof cdir, "%s/c/%s", WORK, name);
        if (mkdir(cdir, 0755) != 0) die("case dir");
        snprintf(device, sizeof device, "%s/tpmrm0", cdir);
        snprintf(fake_log, sizeof fake_log, "%s/fake.log", cdir);
        snprintf(probe_log, sizeof probe_log, "%s/probe.log", cdir);
        spit(device, NULL, 0);
        char c[1024];
        snprintf(c, sizeof c, "sh %s", STUB);
        setenv("FHSM_TPM_CMD", c, 1);
        setenv("FHSM_TPM_DEVICE", device, 1);
        setenv("FHSM_TPM_FAKE_PCR", PCR, 1);
        setenv("FHSM_TPM_FAKE_LOG", fake_log, 1);
        setenv("FHSM_TPM_REAL_STUB", STUB, 1);
        unsetenv("FHSM_TPM_FAKE_FAIL");
        unsetenv("FHSM_TPM_QUIRK");
        unsetenv("FHSM_TPM_PROBE_LOG");
        unsetenv("FHSM_TPM_PROBE_HOLD");
        unsetenv("FHSM_TPM_SEALING");
        fn(arg);
        copy_if_exists(fake_log, "log");
        copy_if_exists(probe_log, "probe");
        fflush(tsv);
        _exit(0);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        fprintf(stderr, "gen_tpm: case %s failed\n", name);
        exit(2);
    }
}

/* ======================================================================== *
 * fhsm_tpm_available
 * ======================================================================== */
static void c_avail(const void *a) {
    const char *how = a;
    if (!strcmp(how, "no_device")) no_device();
    if (!strcmp(how, "startup_fails")) knob("FHSM_TPM_FAKE_FAIL=startup");
    if (!strcmp(how, "cmd_missing")) {
        setenv("FHSM_TPM_CMD", "/nonexistent/tpm2", 1);
        kvs("cmd", "/nonexistent/tpm2");
    }
    if (!strcmp(how, "device_dir")) {
        unlink(device);
        if (mkdir(device, 0755) != 0) die("device dir");
        kvs("device", "dir");
    }
    if (!strcmp(how, "tpm_dir")) {
        if (rmdir(TPM_DIR) != 0 && errno != ENOENT) die("rmdir " TPM_DIR);
    }
    int r = fhsm_tpm_available();
    if (!strcmp(how, "tpm_dir")) {
        struct stat st;
        char m[16];
        if (stat(TPM_DIR, &st) == 0) snprintf(m, sizeof m, "%04o", (unsigned)(st.st_mode & 07777));
        else snprintf(m, sizeof m, "absent");
        kvs("tpm_dir", m);
    }
    kvnum("startup_calls", count_prefix(fake_log, "startup"));
    emit_int("available", r);
}
static void c_avail_cached(const void *a) {
    int yes = !strcmp(a, "yes");
    if (!yes) no_device();
    int first = fhsm_tpm_available();
    if (yes) unlink(device); else spit(device, NULL, 0);
    kvs("then", yes ? "device_removed" : "device_created");
    int second = fhsm_tpm_available();
    kvnum("first", first);
    kvnum("startup_calls", count_prefix(fake_log, "startup"));
    emit_int("available", second);
}

/* ======================================================================== *
 * fhsm_tpm_seal
 * ======================================================================== */
struct seal_args { const char *knob; size_t cap; int probe, no_device, pre_available; const char *cmd_prefix; };
static void c_seal(const void *a) {
    const struct seal_args *s = a;
    if (s->probe) use_probe();
    if (s->knob) knob(s->knob);
    if (s->cmd_prefix) {
        char c[1024];
        snprintf(c, sizeof c, "%s sh %s", s->cmd_prefix, STUB);
        setenv("FHSM_TPM_CMD", c, 1);
        kvs("cmd_prefix", s->cmd_prefix);
    }
    if (s->no_device) no_device();
    else if (s->pre_available) ready();
    else kvs("pre", "not_available_yet");
    uint8_t buf[2048];
    memset(buf, 0xEE, sizeof buf);
    size_t n = 0;
    size_t cap = s->cap;
    if (cap == 0) { /* exact fit / one short: measure the blob first, in this process */
        uint8_t tmp[2048];
        if (fhsm_tpm_seal(S, tmp, sizeof tmp, &n) != FHSM_RV_OK) die("measure");
        cap = n - (strstr(CASE, "short") ? 1 : 0);
        unlink(fake_log);
    }
    fhsm_rv_t rv = fhsm_tpm_seal(S, buf, cap, &n);
    kvnum("cap", (long long)cap);
    if (rv == FHSM_RV_OK) {
        kvhex("blob", buf, n);
        kvnum("pub_len", (long long)(buf[4] | buf[5] << 8 | buf[6] << 16 | (uint32_t)buf[7] << 24));
        if (!strcmp(CASE, "seal_ok")) {
            char p[700];
            snprintf(p, sizeof p, "%s/blob.bin", WORK);
            spit(p, buf, n);
        }
    } else {
        int untouched = 1;
        for (size_t i = 0; i < sizeof buf; i++) untouched &= buf[i] == 0xEE;
        kvs("out", untouched ? "untouched" : "written");
    }
    emit_rv("seal", rv);
}

/* ======================================================================== *
 * fhsm_tpm_unseal
 * ======================================================================== */
struct unseal_args { const char *mut; const char *knob; int probe, no_device; };
static void c_unseal(const void *a) {
    const struct unseal_args *u = a;
    static uint8_t b[4096];
    size_t n = golden_blob(b);
    const char *m = u->mut;
    if (!strcmp(m, "len0")) n = 0;
    else if (!strcmp(m, "len4")) n = 4;
    else if (!strcmp(m, "len11")) n = 11;
    else if (!strcmp(m, "bad_magic")) b[0] = 'X';
    else if (!strcmp(m, "lower_magic")) memcpy(b, "tps1", 4);
    else if (!strcmp(m, "truncated")) n -= 1;
    else if (!strcmp(m, "oversized")) b[n++] = 0x00;
    else if (!strcmp(m, "pub_len_max")) memset(b + 4, 0xff, 4);
    else if (!strcmp(m, "header_only")) { memcpy(b, "TPS1", 4); memset(b + 4, 0, 8); n = 12; }
    else if (!strcmp(m, "garbage_body")) {
        memcpy(b, "TPS1\x10\0\0\0\x20\0\0\0", 12);
        memset(b + 12, 0x5a, 16);
        memset(b + 28, 0xa5, 32);
        n = 60;
    } else if (!strcmp(m, "crafted_2048")) n = crafted_blob(b, 2048);
    else if (strcmp(m, "none")) die("mutation");
    if (u->probe) use_probe();
    if (u->knob) knob(u->knob);
    if (u->no_device) no_device(); else ready();
    uint8_t out[32];
    memset(out, 0xCC, sizeof out);
    kvhex("blob_in", b, n);
    fhsm_rv_t rv = fhsm_tpm_unseal(b, n, out);
    kvhex("out", out, sizeof out);
    emit_rv("unseal", rv);
}

/* ======================================================================== *
 * fhsm_token_tpm_* (the companion file)
 * ======================================================================== */
static const char *tok_for(const char *spec) {
    if (!strcmp(spec, "plain")) return tok_plain();
    if (!strcmp(spec, "nodir")) {
        static char p[700];
        snprintf(p, sizeof p, "%s/nodir/t.tok", cdir);
        kvs("tok", "nodir");
        return p;
    }
    if (!strncmp(spec, "len:", 4)) return tok_len((size_t)strtoul(spec + 4, NULL, 10));
    die("tok spec");
    return NULL;
}
/* pre: none | old | blob | empty | garbage | unreadable | dir | dir_nonempty |
 *      crafted_2048_junk | crafted_2049 | fifo_tmp */
static int fifo_rd = -1;
static void prepare(const char *tok, const char *pre) {
    static uint8_t b[4096];
    if (!strcmp(pre, "none")) return;
    if (!strcmp(pre, "old")) pre_bytes(tok, (const uint8_t *)"old companion\n", 14, "old");
    else if (!strcmp(pre, "blob")) pre_bytes(tok, b, golden_blob(b), "blob");
    else if (!strcmp(pre, "empty")) pre_bytes(tok, b, 0, "empty");
    else if (!strcmp(pre, "garbage")) pre_bytes(tok, (const uint8_t *)"not a sealed blob\n", 18, "garbage");
    else if (!strcmp(pre, "unreadable")) {
        pre_bytes(tok, b, golden_blob(b), "unreadable");
        if (chmod(with(tok, ".tpm"), 0) != 0) die("chmod");
    } else if (!strcmp(pre, "dir")) pre_dir(tok, 0);
    else if (!strcmp(pre, "dir_nonempty")) pre_dir(tok, 1);
    else if (!strcmp(pre, "crafted_2048_junk")) {
        size_t n = crafted_blob(b, 2048);
        memset(b + n, 'J', 100);
        pre_bytes(tok, b, n + 100, "crafted_2048_junk");
    } else if (!strcmp(pre, "crafted_2049")) pre_bytes(tok, b, crafted_blob(b, 2049), "crafted_2049");
    else if (!strcmp(pre, "fifo_tmp")) {
        /* tests/test_audit_fsync.c's technique: write() to a FIFO works, fsync() on it
         * fails with EINVAL. The reader is opened first, non-blocking, so the writer's open
         * does not block and the blob sits in the pipe buffer until read below. */
        if (mkfifo(with(tok, ".tpm.new"), 0600) != 0) die("mkfifo");
        fifo_rd = open(with(tok, ".tpm.new"), O_RDONLY | O_NONBLOCK);
        if (fifo_rd < 0) die("fifo reader");
        kvs("pre", "fifo_tmp");
    } else die("pre spec");
}
static void drained(void) {
    if (fifo_rd < 0) return;
    uint8_t b[4096];
    ssize_t n = read(fifo_rd, b, sizeof b);
    kvhex("drained", b, n > 0 ? (size_t)n : 0);
}

struct tok_args { const char *tok, *pre, *knob; int no_device; };
static void setup_tok(const struct tok_args *t, const char **tok) {
    if (t->knob) knob(t->knob);
    if (t->no_device) no_device(); else ready();
    *tok = tok_for(t->tok);
    prepare(*tok, t->pre);
}
static void c_tok_seal(const void *a) {
    const char *tok;
    setup_tok(a, &tok);
    fhsm_rv_t rv = fhsm_token_tpm_seal(tok, S);
    drained();
    after(tok);
    emit_rv("token_seal", rv);
}
static void c_tok_unseal(const void *a) {
    const char *tok;
    setup_tok(a, &tok);
    uint8_t out[32];
    memset(out, 0xCC, sizeof out);
    fhsm_rv_t rv = fhsm_token_tpm_unseal(tok, out);
    kvhex("out", out, sizeof out);
    emit_rv("token_unseal", rv);
}
static void c_tok_exists(const void *a) {
    const char *tok;
    setup_tok(a, &tok);
    emit_int("blob_exists", fhsm_token_tpm_blob_exists(tok));
}
static void c_tok_unlink(const void *a) {
    const char *tok;
    setup_tok(a, &tok);
    fhsm_token_tpm_unlink(tok);
    kvstate("after_tpm", with(tok, ".tpm"));
    emit("unlink", "-");
}

/* ======================================================================== *
 * fhsm_token_tpm_required, fhsm_token_tpm_dek_match
 * ======================================================================== */
static void c_required(const void *a) {
    const char *v = a;
    if (v) {
        setenv("FHSM_TPM_SEALING", v, 1);
        kvhex("value_hex", (const uint8_t *)v, strlen(v));
    } else {
        kvs("value", "unset");
    }
    emit_int("required", fhsm_token_tpm_required());
}
static void c_dek(const void *a) {
    const char *how = a;
    uint8_t x[32], y[32];
    memcpy(x, S, 32);
    memcpy(y, S, 32);
    if (!strcmp(how, "first")) y[0] ^= 0x01;
    if (!strcmp(how, "last")) y[31] ^= 0x80;
    if (!strcmp(how, "all")) for (int i = 0; i < 32; i++) y[i] = (uint8_t)~y[i];
    if (!strcmp(how, "zero")) { memset(x, 0, 32); memset(y, 0, 32); }
    kvhex("a", x, 32);
    kvhex("b", y, 32);
    emit_int("dek_match", fhsm_token_tpm_dek_match(x, y));
}

/* ======================================================================== *
 * C ABI argument checks (NULLs cannot be expressed in the safe Rust API)
 * ======================================================================== */
static void c_ffi(const void *a) {
    const char *how = a;
    uint8_t buf[2048], out[32];
    size_t n = 0;
    static uint8_t b[4096];
    size_t bl = 0;
    if (strstr(how, "no_tpm")) no_device();
    else { bl = golden_blob(b); ready(); }
    fhsm_rv_t rv;
    if (!strcmp(how, "seal_null_secret") || !strcmp(how, "seal_null_secret_no_tpm"))
        rv = fhsm_tpm_seal(NULL, buf, sizeof buf, &n);
    else if (!strcmp(how, "seal_null_out")) rv = fhsm_tpm_seal(S, NULL, sizeof buf, &n);
    else if (!strcmp(how, "seal_null_out_len")) rv = fhsm_tpm_seal(S, buf, sizeof buf, NULL);
    else if (!strcmp(how, "unseal_null_blob")) rv = fhsm_tpm_unseal(NULL, bl, out);
    else if (!strcmp(how, "unseal_null_out") || !strcmp(how, "unseal_null_out_no_tpm"))
        rv = fhsm_tpm_unseal(b, bl, NULL);
    else { die("ffi case"); return; }
    emit_rv(strncmp(how, "seal", 4) ? "ffi_unseal" : "ffi_seal", rv);
}

/* ======================================================================== *
 * Probe: argv with memfd names, the child's stdout/stderr, inherited memfds
 * ======================================================================== */
/* DIV-017: an unrelated fork+exec made while a seal is in flight. */
static fhsm_rv_t g_seal_rv;
static void *seal_thread(void *x) {
    (void)x;
    uint8_t buf[2048];
    size_t n = 0;
    g_seal_rv = fhsm_tpm_seal(S, buf, sizeof buf, &n);
    return NULL;
}
static void c_fork_during_seal(const void *a) {
    (void)a;
    char hold[700];
    snprintf(hold, sizeof hold, "%s/hold", cdir);
    use_probe();
    setenv("FHSM_TPM_PROBE_HOLD", hold, 1);
    ready();
    pthread_t th;
    if (pthread_create(&th, NULL, seal_thread, NULL) != 0) die("pthread_create");
    struct stat st;
    for (int i = 0; i < 1000 && stat(with(hold, ".ready"), &st) != 0; i++) {
        struct timespec ts = { 0, 10 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    if (stat(with(hold, ".ready"), &st) != 0) die("hold never became ready");
    FILE *p = popen("ls -l /proc/$$/fd", "r");
    if (!p) die("popen");
    char line[1024], seen[1024] = "", names[16][128];
    int k = 0;
    while (fgets(line, sizeof line, p) && k < 16) {
        char *m = strstr(line, "/memfd:");
        if (!m) continue;
        m += 7;
        char *e = strstr(m, " (deleted)");
        if (e) *e = '\0';
        snprintf(names[k++], sizeof names[0], "%s", m);
    }
    pclose(p);
    spit(with(hold, ".go"), NULL, 0);
    pthread_join(th, NULL);
    for (int i = 0; i < k; i++)        /* sorted, so the column does not depend on fd order */
        for (int j = i + 1; j < k; j++)
            if (strcmp(names[j], names[i]) < 0) {
                char t[128];
                memcpy(t, names[i], 128); memcpy(names[i], names[j], 128); memcpy(names[j], t, 128);
            }
    for (int i = 0; i < k; i++) {
        strcat(seen, i ? "," : "");
        strcat(seen, names[i]);
    }
    kvs("seen", k ? seen : "none");
    emit_rv("seal", g_seal_rv);
}

#define SEAL(name, ...) do { static const struct seal_args x_ = { __VA_ARGS__ }; run(name, c_seal, &x_); } while (0)
#define UNSEAL(name, ...) do { static const struct unseal_args x_ = { __VA_ARGS__ }; run(name, c_unseal, &x_); } while (0)
#define TOK(fn, name, ...) do { static const struct tok_args x_ = { __VA_ARGS__ }; run(name, fn, &x_); } while (0)

int main(int argc, char **argv) {
    if (argc != 6 || strcmp(argv[1], "make")) {
        fprintf(stderr, "usage: gen_tpm make OUTDIR STUB PROBE WORKDIR\n");
        return 2;
    }
    OUT = argv[2]; STUB = argv[3]; PROBE = argv[4]; WORK = argv[5];
    for (int i = 0; i < 32; i++) S[i] = (uint8_t)i;
    char p[1024];
    const char *dirs[] = { "log", "probe", "input" };
    for (size_t i = 0; i < 3; i++) {
        snprintf(p, sizeof p, "%s/%s", OUT, dirs[i]);
        mkdir(p, 0755);
    }
    snprintf(p, sizeof p, "%s/c", WORK);
    if (mkdir(p, 0755) != 0) die(p);
    snprintf(p, sizeof p, "%s/cases.tsv", OUT);
    tsv = fopen(p, "a");
    if (!tsv) die(p);
    fprintf(tsv, "# Generated by tests-support/golden/gen_tpm.c from the legacy C code. Do not edit.\n"
                 "# case\top\trv\tkey=value...  (token/tests/README.md)\n");

    /* seal_ok first: it writes the blob every unseal case starts from. */
    SEAL("seal_ok", .cap = 2048, .pre_available = 1);

    run("avail_no_device", c_avail, "no_device");
    run("avail_ok", c_avail, "ok");
    run("avail_startup_fails", c_avail, "startup_fails");
    run("avail_cmd_missing", c_avail, "cmd_missing");
    run("avail_device_is_dir", c_avail, "device_dir");
    run("avail_creates_tpm_dir", c_avail, "tpm_dir");
    run("avail_cached_yes", c_avail_cached, "yes");
    run("avail_cached_no", c_avail_cached, "no");
    SEAL("avail_first_seal_probes", .cap = 2048);

    SEAL("seal_cap_exact", .cap = 0, .pre_available = 1);
    SEAL("seal_cap_short", .cap = 0, .pre_available = 1);
    SEAL("seal_fail_createpolicy", .knob = "FHSM_TPM_FAKE_FAIL=createpolicy", .cap = 2048, .pre_available = 1);
    SEAL("seal_fail_create", .knob = "FHSM_TPM_FAKE_FAIL=create", .cap = 2048, .pre_available = 1);
    SEAL("seal_no_device", .cap = 2048, .no_device = 1);
    SEAL("seal_quirk_pub_512", .knob = "FHSM_TPM_QUIRK=pub-size=512", .probe = 1, .cap = 2048, .pre_available = 1);
    SEAL("seal_quirk_pub_513", .knob = "FHSM_TPM_QUIRK=pub-size=513", .probe = 1, .cap = 2048, .pre_available = 1);
    SEAL("seal_quirk_empty_pub", .knob = "FHSM_TPM_QUIRK=empty-pub", .probe = 1, .cap = 2048, .pre_available = 1);
    SEAL("seal_quirk_empty_priv", .knob = "FHSM_TPM_QUIRK=empty-priv", .probe = 1, .cap = 2048, .pre_available = 1);
    SEAL("seal_cmd_env_prefix", .cmd_prefix = "FHSM_TPM_FAKE_PCR=from-cmd", .cap = 2048, .pre_available = 1);

    UNSEAL("unseal_ok", .mut = "none");
    UNSEAL("unseal_len0", .mut = "len0");
    UNSEAL("unseal_len4", .mut = "len4");
    UNSEAL("unseal_len11", .mut = "len11");
    UNSEAL("unseal_bad_magic", .mut = "bad_magic");
    UNSEAL("unseal_lower_magic", .mut = "lower_magic");
    UNSEAL("unseal_truncated", .mut = "truncated");
    UNSEAL("unseal_oversized", .mut = "oversized");
    UNSEAL("unseal_pub_len_max", .mut = "pub_len_max");
    UNSEAL("unseal_header_only", .mut = "header_only");
    UNSEAL("unseal_garbage_body", .mut = "garbage_body");
    UNSEAL("unseal_crafted_2048", .mut = "crafted_2048");
    UNSEAL("unseal_pcr_changed", .mut = "none", .knob = "FHSM_TPM_FAKE_PCR=boot-state-2");
    UNSEAL("unseal_fail_createpolicy", .mut = "none", .knob = "FHSM_TPM_FAKE_FAIL=createpolicy");
    UNSEAL("unseal_fail_load", .mut = "none", .knob = "FHSM_TPM_FAKE_FAIL=load");
    UNSEAL("unseal_fail_unseal", .mut = "none", .knob = "FHSM_TPM_FAKE_FAIL=unseal");
    UNSEAL("unseal_quirk_out_31", .mut = "none", .knob = "FHSM_TPM_QUIRK=unseal-out=31", .probe = 1);
    UNSEAL("unseal_quirk_out_0", .mut = "none", .knob = "FHSM_TPM_QUIRK=unseal-out=0", .probe = 1);
    UNSEAL("unseal_quirk_out_40", .mut = "none", .knob = "FHSM_TPM_QUIRK=unseal-out=40", .probe = 1);
    UNSEAL("unseal_no_device", .mut = "none", .no_device = 1);

    TOK(c_tok_seal, "tok_seal_ok", .tok = "plain", .pre = "none");
    TOK(c_tok_seal, "tok_seal_replaces_old", .tok = "plain", .pre = "old");
    TOK(c_tok_seal, "tok_seal_fail_keeps_old", .tok = "plain", .pre = "old", .knob = "FHSM_TPM_FAKE_FAIL=create");
    TOK(c_tok_seal, "tok_seal_no_device", .tok = "plain", .pre = "none", .no_device = 1);
    TOK(c_tok_seal, "tok_seal_missing_dir", .tok = "nodir", .pre = "none");
    TOK(c_tok_seal, "tok_seal_rename_onto_dir", .tok = "plain", .pre = "dir_nonempty");
    TOK(c_tok_seal, "tok_seal_stale_tmp_fifo", .tok = "plain", .pre = "fifo_tmp");
    TOK(c_tok_seal, "tok_seal_len_1015", .tok = "len:1015", .pre = "none");
    TOK(c_tok_seal, "tok_seal_len_1016", .tok = "len:1016", .pre = "none");
    TOK(c_tok_seal, "tok_seal_len_1019", .tok = "len:1019", .pre = "none");
    TOK(c_tok_seal, "tok_seal_len_1020", .tok = "len:1020", .pre = "none");
    TOK(c_tok_seal, "tok_seal_len_1020_no_device", .tok = "len:1020", .pre = "none", .no_device = 1);

    TOK(c_tok_unseal, "tok_unseal_ok", .tok = "plain", .pre = "blob");
    TOK(c_tok_unseal, "tok_unseal_missing", .tok = "plain", .pre = "none");
    TOK(c_tok_unseal, "tok_unseal_empty", .tok = "plain", .pre = "empty");
    TOK(c_tok_unseal, "tok_unseal_directory", .tok = "plain", .pre = "dir");
    TOK(c_tok_unseal, "tok_unseal_unreadable", .tok = "plain", .pre = "unreadable");
    TOK(c_tok_unseal, "tok_unseal_garbage", .tok = "plain", .pre = "garbage");
    TOK(c_tok_unseal, "tok_unseal_2048_plus_junk", .tok = "plain", .pre = "crafted_2048_junk");
    TOK(c_tok_unseal, "tok_unseal_2049", .tok = "plain", .pre = "crafted_2049");
    TOK(c_tok_unseal, "tok_unseal_pcr_changed", .tok = "plain", .pre = "blob", .knob = "FHSM_TPM_FAKE_PCR=boot-state-2");
    TOK(c_tok_unseal, "tok_unseal_no_device", .tok = "plain", .pre = "blob", .no_device = 1);
    TOK(c_tok_unseal, "tok_unseal_len_1019", .tok = "len:1019", .pre = "blob");
    TOK(c_tok_unseal, "tok_unseal_len_1020", .tok = "len:1020", .pre = "blob");

    TOK(c_tok_exists, "exists_missing", .tok = "plain", .pre = "none");
    TOK(c_tok_exists, "exists_file", .tok = "plain", .pre = "blob");
    TOK(c_tok_exists, "exists_empty", .tok = "plain", .pre = "empty");
    TOK(c_tok_exists, "exists_directory", .tok = "plain", .pre = "dir");
    TOK(c_tok_exists, "exists_unreadable", .tok = "plain", .pre = "unreadable");
    TOK(c_tok_exists, "exists_no_device", .tok = "plain", .pre = "blob", .no_device = 1);
    TOK(c_tok_exists, "exists_len_1019", .tok = "len:1019", .pre = "blob");
    TOK(c_tok_exists, "exists_len_1020", .tok = "len:1020", .pre = "blob");

    TOK(c_tok_unlink, "unlink_present", .tok = "plain", .pre = "blob");
    TOK(c_tok_unlink, "unlink_missing", .tok = "plain", .pre = "none");
    TOK(c_tok_unlink, "unlink_directory", .tok = "plain", .pre = "dir");
    TOK(c_tok_unlink, "unlink_len_1019", .tok = "len:1019", .pre = "blob");
    TOK(c_tok_unlink, "unlink_len_1020", .tok = "len:1020", .pre = "blob");

    run("required_unset", c_required, NULL);
    run("required_empty", c_required, "");
    run("required_1", c_required, "1");
    run("required_lower_y", c_required, "y");
    run("required_upper_Y", c_required, "Y");
    run("required_yes", c_required, "yes");
    run("required_capital_Yes", c_required, "Yes");
    run("required_10", c_required, "10");
    run("required_0", c_required, "0");
    run("required_lower_n", c_required, "n");
    run("required_upper_N", c_required, "N");
    run("required_true", c_required, "true");
    run("required_on", c_required, "on");
    run("required_space_1", c_required, " 1");

    run("dek_equal", c_dek, "equal");
    run("dek_differ_first", c_dek, "first");
    run("dek_differ_last", c_dek, "last");
    run("dek_all_differ", c_dek, "all");
    run("dek_zero_equal", c_dek, "zero");

    run("ffi_seal_null_secret", c_ffi, "seal_null_secret");
    run("ffi_seal_null_out", c_ffi, "seal_null_out");
    run("ffi_seal_null_out_len", c_ffi, "seal_null_out_len");
    run("ffi_unseal_null_blob", c_ffi, "unseal_null_blob");
    run("ffi_unseal_null_out", c_ffi, "unseal_null_out");
    run("ffi_seal_null_secret_no_tpm", c_ffi, "seal_null_secret_no_tpm");
    run("ffi_unseal_null_out_no_tpm", c_ffi, "unseal_null_out_no_tpm");

    SEAL("probe_seal", .probe = 1, .cap = 2048, .pre_available = 1);
    UNSEAL("probe_unseal", .mut = "none", .probe = 1);
    run("div017_fork_during_seal", c_fork_during_seal, NULL);

    fclose(tsv);
    return 0;
}
