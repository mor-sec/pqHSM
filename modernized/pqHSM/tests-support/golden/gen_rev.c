/* Golden generator for Phase 2 slice 2: the revocation database and the OCSP responder body
 * (src/fhsm_revocation.c). Writes pki/tests/golden/rev/.
 *
 * Runs the LEGACY C code and records what it returns and what it leaves behind. Built by
 * gen_token.mk (target gen_rev), driven by regen_rev.sh. Two link-time seams, on the
 * generator's own link line only:
 *
 *   -Wl,--wrap=fhsm_pki_ocsp  every argument fhsm_ocsp_answer_ex hands the Phase 3 encoder is
 *                             written to ocsp/CASE.enc, and the encoder's output to
 *                             ocsp/CASE.basic.der. That is the contract the Rust code must
 *                             meet; the encoder itself stays C.
 *   -Wl,--wrap=time           time() inside an answer returns NOW, so producedAt,
 *                             thisUpdate and nextUpdate -- and, with Ed25519, the signature
 *                             -- are the same on every run.
 *
 *   gen_rev make OUTDIR WORKDIR
 *
 * Output (see pki/tests/README.md): cases.tsv, db/, saved/, der/, ocsp/.
 *
 * Keys are Ed25519 from invented seeds (bytes base, base+1, ...). Nothing credential-like
 * from the legacy tree is used.
 */
#include "fhsm_common.h"
#include "fhsm_pki.h"
#include "fhsm_revocation.h"

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#pragma GCC diagnostic ignored "-Woverride-init"   /* ANS(): defaults, then the row's */

#define NOW 1798761600LL            /* 2027-01-01T00:00:00Z */
#define DMAX 2912077                /* the last `days` whose nextUpdate is in year 9999 */

static const char *OUT, *WORK;
static FILE *tsv;
static const char *CASE;
static char kv[1 << 21];

static void die(const char *m) {
    fprintf(stderr, "gen_rev: %s: %s: %s\n", CASE ? CASE : "-", m, strerror(errno));
    exit(2);
}

static char pbuf[4][2200];
static const char *at(int slot, const char *dir, const char *name) {
    snprintf(pbuf[slot], sizeof pbuf[slot], "%s/%s", dir, name);
    return pbuf[slot];
}
static void put_file(const char *p, const uint8_t *b, size_t n) {
    FILE *f = fopen(p, "wb");
    if (!f || (n && fwrite(b, 1, n, f) != n) || fclose(f) != 0) die(p);
}
static size_t get_file(const char *p, uint8_t *b, size_t cap) {
    FILE *f = fopen(p, "rb");
    if (!f) die(p);
    size_t n = fread(b, 1, cap, f);
    fclose(f);
    return n;
}
static void copy_file(const char *src, const char *dst) {
    static uint8_t b[1 << 22];
    put_file(dst, b, get_file(src, b, sizeof b));
}
static uint8_t pattern(size_t i) { return (uint8_t)(i * 7 + 3); }

/* ---- seams ----------------------------------------------------------------- */
time_t __real_time(time_t *t);
time_t __wrap_time(time_t *t);
static int pin_time;
time_t __wrap_time(time_t *t) {
    if (!pin_time) return __real_time(t);
    if (t) *t = (time_t)NOW;
    return (time_t)NOW;
}

fhsm_rv_t __real_fhsm_pki_ocsp(const fhsm_pki_signer_t *, const uint8_t *, size_t,
                               const uint8_t *, size_t, const fhsm_composite_ocsp_single_t *,
                               size_t, const uint8_t *, size_t, uint8_t *, size_t *);
fhsm_rv_t __wrap_fhsm_pki_ocsp(const fhsm_pki_signer_t *, const uint8_t *, size_t,
                               const uint8_t *, size_t, const fhsm_composite_ocsp_single_t *,
                               size_t, const uint8_t *, size_t, uint8_t *, size_t *);
static long synth = -1;     /* >= 0: return this many pattern bytes instead of encoding */
static int enc_called;

static void fhex(FILE *f, const uint8_t *b, size_t n) {
    if (!b) { fputc('-', f); return; }
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]);
}

fhsm_rv_t __wrap_fhsm_pki_ocsp(const fhsm_pki_signer_t *s,
                               const uint8_t *rc, size_t rc_len,
                               const uint8_t *pa, size_t pa_len,
                               const fhsm_composite_ocsp_single_t *sg, size_t n,
                               const uint8_t *exts, size_t exts_len,
                               uint8_t *out, size_t *out_len)
{
    enc_called = 1;
    char name[256];
    if (synth >= 0) snprintf(name, sizeof name, "/dev/null");
    else snprintf(name, sizeof name, "%s/ocsp/%s.enc", OUT, CASE);
    FILE *f = fopen(name, "w");
    if (!f) die("enc");
    fprintf(f, "algid "); fhex(f, s->algid, s->algid_len);
    fprintf(f, "\nspki "); fhex(f, s->spki, s->spki_len);
    fprintf(f, "\nresponder "); fhex(f, rc, rc_len);
    fprintf(f, "\nproduced_at "); fhex(f, pa, pa_len);
    fprintf(f, "\ncap %zu\nexts ", *out_len);
    fhex(f, exts, exts_len);
    fputc('\n', f);
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "single ");
        fhex(f, sg[i].cert_id, sg[i].cert_id_len);
        fprintf(f, " %d ", sg[i].status);
        fhex(f, sg[i].revoked_at, sg[i].revoked_at_len);
        fprintf(f, " %d ", sg[i].reason);
        fhex(f, sg[i].this_upd, sg[i].this_upd_len);
        fputc(' ', f);
        fhex(f, sg[i].next_upd, sg[i].next_upd_len);
        fputc('\n', f);
    }
    fhsm_rv_t rv;
    if (synth >= 0) {
        if ((size_t)synth > *out_len) die("synth larger than the buffer");
        for (long i = 0; i < synth; i++) out[i] = pattern((size_t)i);
        *out_len = (size_t)synth;
        rv = FHSM_RV_OK;
    } else {
        rv = __real_fhsm_pki_ocsp(s, rc, rc_len, pa, pa_len, sg, n, exts, exts_len, out, out_len);
    }
    fprintf(f, "rv 0x%x\n", (unsigned)rv);
    if (fclose(f) != 0) die("enc close");
    if (rv == FHSM_RV_OK && synth < 0) {
        snprintf(name, sizeof name, "ocsp/%s.basic.der", CASE);
        put_file(at(3, OUT, name), out, *out_len);
    }
    return rv;
}

/* ---- key=value columns ----------------------------------------------------- */
static void kvraw(const char *k, const char *v) {
    size_t l = strlen(kv);
    snprintf(kv + l, sizeof kv - l, "\t%s=%s", k, v);
}
/* Escaped: \\ \t \n \r, and \xHH for any other byte outside 0x20..0x7e. WORK becomes {dir}. */
static void kvs(const char *k, const char *v) {
    size_t l = strlen(kv), w = strlen(WORK);
    l += (size_t)snprintf(kv + l, sizeof kv - l, "\t%s=", k);
    for (const char *p = v; *p && l + 8 < sizeof kv; p++) {
        unsigned char c = (unsigned char)*p;
        if (!strncmp(p, WORK, w)) { memcpy(kv + l, "{dir}", 5); l += 5; p += w - 1; }
        else if (c == '\\') { kv[l++] = '\\'; kv[l++] = '\\'; }
        else if (c == '\t') { kv[l++] = '\\'; kv[l++] = 't'; }
        else if (c == '\n') { kv[l++] = '\\'; kv[l++] = 'n'; }
        else if (c == '\r') { kv[l++] = '\\'; kv[l++] = 'r'; }
        else if (c < 0x20 || c > 0x7e) l += (size_t)snprintf(kv + l, 5, "\\x%02x", c);
        else kv[l++] = (char)c;
    }
    kv[l] = '\0';
}
static void kvhex(const char *k, const uint8_t *b, size_t n) {
    size_t l = strlen(kv);
    l += (size_t)snprintf(kv + l, sizeof kv - l, "\t%s=", k);
    for (size_t i = 0; i < n && l + 3 < sizeof kv; i++) l += (size_t)snprintf(kv + l, 3, "%02x", b[i]);
}
static void kvu(const char *k, unsigned long long v) {
    char b[32];
    snprintf(b, sizeof b, "%llu", v);
    kvraw(k, b);
}
static void kvnum(const char *k, long long v) {
    char b[32];
    snprintf(b, sizeof b, "%lld", v);
    kvraw(k, b);
}
static void emit(const char *op, long long rv) {
    fprintf(tsv, "%s\t%s\t%lld%s\n", CASE, op, rv, kv);
    kv[0] = '\0';
}
static void emit_s(const char *op, const char *rv) {
    fprintf(tsv, "%s\t%s\t%s%s\n", CASE, op, rv, kv);
    kv[0] = '\0';
}

/* ---- pure helpers ------------------------------------------------------------ */
static void reason_code(const char *c, const char *in) {
    CASE = c; kvs("in", in); emit("reason_code", fhsm_rev_reason_code(in));
}
static void reason_name(const char *c, int code) {
    CASE = c; kvnum("code", code);
    const char *n = fhsm_rev_reason_name(code);
    emit_s("reason_name", n ? n : "NULL");
}
/* `buf` is the caller's cap-byte buffer afterwards (pre-filled ee); `n` stays 999 if unset. */
static void hex(const char *c, const char *in, size_t cap) {
    CASE = c;
    uint8_t buf[80]; size_t n = 999;
    memset(buf, 0xEE, sizeof buf);
    int r = fhsm_rev_hex_to_bytes(in, buf, cap, &n);
    kvs("in", in); kvnum("cap", (long long)cap);
    if (r) kvhex("out", buf, n);
    kvhex("buf", buf, cap); kvnum("n", (long long)n);
    emit("hex", r);
}
static void date(const char *c, const char *in) {
    CASE = c;
    int64_t t = 0x5A5A5A5A;
    int r = fhsm_rev_date_to_time(in, &t);
    kvs("in", in);
    if (t == 0x5A5A5A5A) kvraw("t", "untouched"); else kvnum("t", (long long)t);
    emit("date", r);
}
static void tdate(const char *c, int64_t when) {
    CASE = c;
    char out[17];
    memset(out, '@', sizeof out); out[16] = '\0';
    int r = fhsm_rev_time_to_date(when, out);
    kvnum("t", (long long)when);
    if (r) { kvs("out", out); kvnum("nul", out[15] == '\0'); }
    else kvraw("out", memcmp(out, "@@@@@@@@@@@@@@@@", 16) ? "touched" : "untouched");
    emit("time", r);
}
/* 00:00:00 UTC on 1 January of `year` (proleptic Gregorian, astronomical numbering). */
static int64_t year_start(int year) {
    struct tm t;
    memset(&t, 0, sizeof t);
    t.tm_year = year - 1900; t.tm_mday = 1;
    return (int64_t)timegm(&t);
}
static size_t unhex(const char *h, uint8_t *b) {
    size_t n = strlen(h) / 2;
    for (size_t i = 0; i < n; i++) sscanf(h + 2 * i, "%2hhx", &b[i]);
    return n;
}
static void seq(const char *c, const char *a, const char *b) {
    CASE = c;
    uint8_t x[64], y[64];
    size_t nx = unhex(a, x), ny = unhex(b, y);
    kvraw("a", a); kvraw("b", b);
    emit("serial_eq", fhsm_rev_serial_eq(x, nx, y, ny));
}

/* ---- databases ------------------------------------------------------------------ */
static void kventries(const fhsm_rev_db_t *d) {
    size_t l = strlen(kv);
    l += (size_t)snprintf(kv + l, sizeof kv - l, "\tentries=");
    for (size_t i = 0; i < d->n && l + 300 < sizeof kv; i++) {
        if (i) kv[l++] = ',';
        for (size_t k = 0; k < d->e[i].serial_len; k++) l += (size_t)snprintf(kv + l, 3, "%02x", d->e[i].serial[k]);
        l += (size_t)snprintf(kv + l, sizeof kv - l, "/%s/%d", d->e[i].date, d->e[i].reason);
    }
    kv[l] = '\0';
}

/* "crl=N;e=SERIAL,DATE,REASON;..." -> a database built with fhsm_rev_db_add. REASON is an
 * int code; DATE is copied verbatim and unvalidated, as a caller of _add can. */
static void build(fhsm_rev_db_t *d, const char *spec) {
    memset(d, 0, sizeof *d);
    char s[4096], err[FHSM_REV_ERR_MAX];
    snprintf(s, sizeof s, "%s", spec);
    for (char *tok = strtok(s, ";"); tok; tok = strtok(NULL, ";")) {
        if (!strncmp(tok, "crl=", 4)) { d->crl_number = strtoull(tok + 4, NULL, 10); continue; }
        if (strncmp(tok, "e=", 2)) die("spec");
        fhsm_rev_entry_t e; memset(&e, 0, sizeof e);
        char *c1 = strchr(tok + 2, ','), *c2 = c1 ? strchr(c1 + 1, ',') : NULL;
        if (!c2) die("spec entry");
        *c1 = *c2 = '\0';
        e.serial_len = unhex(tok + 2, e.serial);
        snprintf(e.date, sizeof e.date, "%s", c1 + 1);
        e.reason = atoi(c2 + 1);
        if (fhsm_rev_db_add(d, &e, err, sizeof err) != FHSM_REV_OK) die(err);
    }
}

static void craft(const char *name, const char *text, size_t n) {
    char rel[300];
    snprintf(rel, sizeof rel, "db/%s.db", name);
    put_file(at(0, OUT, rel), (const uint8_t *)text, n);
}
#define CRAFT(name, lit) craft(name, lit, sizeof lit - 1)

/* `file`: db/NAME.db or saved/CASE.db from OUT, copied into WORK under its base name; or a
 * special: missing, dir, unreadable, notdir, gen:N (N lines "%08X 20260101000000Z -"). */
static void load_at(const char *file, char *p, size_t pn) {
    const char *base = strrchr(file, '/') ? strrchr(file, '/') + 1 : file;
    if (!strcmp(file, "missing")) snprintf(p, pn, "%s/missing.db", WORK);
    else if (!strcmp(file, "dir")) { snprintf(p, pn, "%s/dir.db", WORK); mkdir(p, 0755); }
    else if (!strcmp(file, "unreadable")) {
        snprintf(p, pn, "%s/unreadable.db", WORK);
        put_file(p, (const uint8_t *)"A1 20260101000000Z -\n", 21);
        chmod(p, 0);
    } else if (!strcmp(file, "notdir")) {
        put_file(at(0, WORK, "afile"), (const uint8_t *)"", 0);
        snprintf(p, pn, "%s/afile/x.db", WORK);
    } else if (!strncmp(file, "gen:", 4)) {
        long n = atol(file + 4);
        snprintf(p, pn, "%s/gen.db", WORK);
        FILE *f = fopen(p, "w");
        if (!f) die("gen");
        for (long i = 0; i < n; i++) fprintf(f, "%08lX 20260101000000Z -\n", (unsigned long)i);
        if (fclose(f) != 0) die("gen close");
    } else {
        snprintf(p, pn, "%s/%s", WORK, base);
        copy_file(at(0, OUT, file), p);
    }
}
static void load_cleanup(const char *file, const char *p) {
    if (!strcmp(file, "unreadable")) chmod(p, 0600);
    if (!strcmp(file, "dir")) rmdir(p);
    else unlink(p);
    if (!strcmp(file, "notdir")) unlink(at(0, WORK, "afile"));
}

/* errmode 0: err NULL (cap passed anyway, as a caller might); 1: a 1024-byte buffer of '@'
 * with `cap` passed. */
static void load_row(const char *c, const char *file, int errmode, size_t cap) {
    CASE = c;
    char p[1024];
    load_at(file, p, sizeof p);
    fhsm_rev_db_t d;
    memset(&d, 0xA5, sizeof d);     /* load must not read the caller's struct (review L3) */
    char err[1024];
    memset(err, '@', sizeof err); err[sizeof err - 1] = '\0';
    int rv = fhsm_rev_db_load(p, &d, errmode ? err : NULL, cap);
    kvs("file", file);
    if (!errmode) kvraw("err_mode", "null");
    if (cap != FHSM_REV_ERR_MAX) kvnum("err_cap", (long long)cap);
    kvu("crl_number", d.crl_number);
    kvnum("n", (long long)d.n);
    kvnum("cap", (long long)d.cap);
    kvnum("e_null", d.e == NULL);
    if (errmode) {
        if (err[0] == '@') kvraw("err", "untouched");
        else kvs("err", err);
    }
    if (rv == FHSM_REV_OK && d.n <= 300) kventries(&d);
    emit("load", rv);
    load_cleanup(file, p);
    fhsm_rev_db_free(&d);
}
#define LOAD(c, f) load_row(c, f, 1, FHSM_REV_ERR_MAX)

static void kvstate(const char *k, const char *p) {
    struct stat st;
    char v[300];
    if (lstat(p, &st) != 0) { kvraw(k, "absent"); return; }
    if (S_ISLNK(st.st_mode)) {
        char t[256];
        ssize_t n = readlink(p, t, sizeof t - 1);
        t[n < 0 ? 0 : n] = '\0';
        snprintf(v, sizeof v, "symlink:%s", t);
        kvs(k, v);
        return;
    }
    if (S_ISDIR(st.st_mode)) { kvraw(k, "dir"); return; }
    static uint8_t b[1 << 20];
    FILE *f = fopen(p, "rb");
    size_t n = f ? fread(b, 1, sizeof b, f) : 0;
    if (f) fclose(f);
    size_t l = strlen(kv);
    l += (size_t)snprintf(kv + l, sizeof kv - l, "\t%s=file:%04o:", k, (unsigned)(st.st_mode & 07777));
    for (size_t i = 0; i < n && l + 3 < sizeof kv; i++) l += (size_t)snprintf(kv + l, 3, "%02x", b[i]);
}

/* An absolute path of exactly `len` bytes under WORK: "/" + 200 'd's per directory level
 * (created), then "/" + 'f's. pki/tests/common/mod.rs `long_path` builds the same shape. */
static void mk_long(char *p, size_t len) {
    size_t l = strlen(WORK);
    memcpy(p, WORK, l + 1);
    while (len - l > 1 + 200 + 1 + 1) {
        p[l++] = '/';
        memset(p + l, 'd', 200); l += 200; p[l] = '\0';
        mkdir(p, 0755);
    }
    p[l++] = '/';
    memset(p + l, 'f', len - l); p[len] = '\0';
}
static void rm_long(char *p) {
    unlink(p);
    char *s;
    while ((s = strrchr(p, '/')) && (size_t)(s - p) > strlen(WORK)) { *s = '\0'; rmdir(p); }
}

/* target: plain | replace | tmp_exists | missing_dir | ro_dir | is_dir | tmp_full |
 *         tmp_symlink | len:N */
static void save_row(const char *c, const char *spec, const char *target, int errmode) {
    CASE = c;
    fhsm_rev_db_t d;
    build(&d, spec);
    char p[2200], tmp[2300];
    snprintf(p, sizeof p, "%s/%s.db", WORK, c);
    if (!strcmp(target, "missing_dir")) snprintf(p, sizeof p, "%s/nope/%s.db", WORK, c);
    if (!strcmp(target, "ro_dir")) {
        snprintf(p, sizeof p, "%s/ro", WORK); mkdir(p, 0555); chmod(p, 0555);
        snprintf(p, sizeof p, "%s/ro/%s.db", WORK, c);
    }
    if (!strncmp(target, "len:", 4)) mk_long(p, (size_t)atol(target + 4));
    snprintf(tmp, sizeof tmp, "%s.tmp", p);
    if (!strcmp(target, "replace")) { put_file(p, (const uint8_t *)"old\n", 4); chmod(p, 0600); }
    if (!strcmp(target, "tmp_exists")) put_file(tmp, (const uint8_t *)"stale junk\n", 11);
    if (!strcmp(target, "is_dir")) mkdir(p, 0755);
    if (!strcmp(target, "tmp_full") && symlink("/dev/full", tmp) != 0) die("symlink");
    if (!strcmp(target, "tmp_symlink")) {
        put_file(at(0, WORK, "victim"), (const uint8_t *)"victim\n", 7);
        if (symlink("victim", tmp) != 0) die("symlink");
    }

    char err[1024] = "";
    int rv = fhsm_rev_db_save(p, &d, errmode ? err : NULL, errmode ? sizeof err : 0);
    kvs("db", spec); kvraw("target", target);
    if (!errmode) kvraw("err_mode", "null");
    else kvs("err", err);
    if (strncmp(target, "len:", 4)) {
        kvstate("after", p);
        kvstate("after_tmp", tmp);
    } else {
        struct stat st;
        kvraw("after", stat(p, &st) == 0 ? "file" : "absent");
        kvraw("after_tmp", lstat(tmp, &st) == 0 ? "present" : "absent");
    }
    if (!strcmp(target, "tmp_symlink")) kvstate("victim", at(0, WORK, "victim"));
    emit("save", rv);

    struct stat st;
    if (rv == FHSM_REV_OK && lstat(p, &st) == 0 && S_ISREG(st.st_mode) && strncmp(target, "len:", 4)) {
        char rel[300];
        snprintf(rel, sizeof rel, "saved/%s.db", c);
        copy_file(p, at(1, OUT, rel));
    }
    unlink(tmp);
    if (!strncmp(target, "len:", 4)) rm_long(p);
    else if (!strcmp(target, "is_dir")) rmdir(p);
    else unlink(p);
    unlink(at(0, WORK, "victim"));
    if (!strcmp(target, "ro_dir")) rmdir(at(0, WORK, "ro"));
    fhsm_rev_db_free(&d);
}

static void grow_rows(void) {
    CASE = "add_growth_to_the_cap";
    fhsm_rev_db_t d; memset(&d, 0, sizeof d);
    char err[FHSM_REV_ERR_MAX] = "", caps[512] = "";
    size_t last = 0;
    for (size_t i = 0; i < FHSM_REV_MAX_ENTRIES; i++) {
        fhsm_rev_entry_t e; memset(&e, 0, sizeof e);
        e.serial[0] = (uint8_t)(i >> 24); e.serial[1] = (uint8_t)(i >> 16);
        e.serial[2] = (uint8_t)(i >> 8);  e.serial[3] = (uint8_t)i;
        e.serial_len = 4;
        memcpy(e.date, "20260101000000Z", 16);
        e.reason = -1;
        if (fhsm_rev_db_add(&d, &e, err, sizeof err) != FHSM_REV_OK) die(err);
        if (d.cap != last) {
            size_t l = strlen(caps);
            snprintf(caps + l, sizeof caps - l, "%s%zu:%zu", l ? "," : "", d.n, d.cap);
            last = d.cap;
        }
    }
    kvraw("caps", caps);
    kvnum("n", (long long)d.n);
    emit("add_growth", 0);

    CASE = "add_past_the_cap_is_eparse";
    fhsm_rev_entry_t e; memset(&e, 0, sizeof e);
    e.serial[0] = 0xAB; e.serial_len = 1; memcpy(e.date, "20260101000000Z", 16); e.reason = 1;
    int rv = fhsm_rev_db_add(&d, &e, err, sizeof err);
    kvnum("n", (long long)d.n); kvnum("cap", (long long)d.cap); kvs("err", err);
    emit("add_cap", rv);
    fhsm_rev_db_free(&d);
    kvnum("n", (long long)d.n); kvnum("cap", (long long)d.cap); kvnum("e_null", d.e == NULL);
    kvu("crl_number", d.crl_number);
    CASE = "free_resets_every_field";
    emit("free", 0);
}

static void find_row(const char *c, const char *spec, const char *q) {
    CASE = c;
    fhsm_rev_db_t d;
    build(&d, spec);
    uint8_t s[64];
    size_t n = unhex(q, s);
    const fhsm_rev_entry_t *e = fhsm_rev_db_find(&d, s, n);
    kvs("db", spec); kvraw("q", q);
    emit("find", e ? (long long)(e - d.e) : -1);
    fhsm_rev_db_free(&d);
}

/* ---- certificates and requests ---------------------------------------------------- */
typedef struct { const char *name; uint8_t *b; size_t n; } blob_t;
static blob_t blobs[96];
static size_t nblobs;

static void add_blob(const char *name, const uint8_t *b, size_t n) {
    if (nblobs == sizeof blobs / sizeof *blobs) die("too many blobs");
    blobs[nblobs].name = name;
    blobs[nblobs].b = malloc(n ? n : 1);
    if (!blobs[nblobs].b) die("malloc");
    memcpy(blobs[nblobs].b, b, n);
    blobs[nblobs].n = n;
    nblobs++;
    char rel[200];
    snprintf(rel, sizeof rel, "der/%s.der", name);
    put_file(at(0, OUT, rel), b, n);
}
static const blob_t *blob(const char *name) {
    for (size_t i = 0; i < nblobs; i++) if (!strcmp(blobs[i].name, name)) return &blobs[i];
    die(name);
    return NULL;
}

static EVP_PKEY *seed_key(uint8_t base) {
    uint8_t s[32];
    for (int i = 0; i < 32; i++) s[i] = (uint8_t)(base + i);
    EVP_PKEY *k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, s, sizeof s);
    if (!k) die("key");
    return k;
}
static X509_NAME *mkname(const char *o, const char *cn) {
    X509_NAME *n = X509_NAME_new();
    if (!n || !X509_NAME_add_entry_by_txt(n, "O", MBSTRING_ASC, (const unsigned char *)o, -1, -1, 0)
        || !X509_NAME_add_entry_by_txt(n, "CN", MBSTRING_ASC, (const unsigned char *)cn, -1, -1, 0))
        die("name");
    return n;
}
static X509 *mkcert(const char *name, X509_NAME *subj, X509_NAME *issuer, EVP_PKEY *pub,
                    EVP_PKEY *signer, long serial, const char *eku) {
    X509 *x = X509_new();
    if (!x || !X509_set_version(x, X509_VERSION_3)
        || !ASN1_INTEGER_set(X509_get_serialNumber(x), serial)
        || !X509_set_subject_name(x, subj) || !X509_set_issuer_name(x, issuer)
        || !ASN1_TIME_set_string_X509(X509_getm_notBefore(x), "20260101000000Z")
        || !ASN1_TIME_set_string_X509(X509_getm_notAfter(x), "20360101000000Z")
        || !X509_set_pubkey(x, pub))
        die("cert");
    if (eku) {
        X509_EXTENSION *ex = X509V3_EXT_conf_nid(NULL, NULL, NID_ext_key_usage, eku);
        if (!ex || !X509_add_ext(x, ex, -1)) die("eku");
        X509_EXTENSION_free(ex);
    }
    if (X509_sign(x, signer, NULL) <= 0) die("sign cert");
    uint8_t *der = NULL;
    int n = i2d_X509(x, &der);
    if (n <= 0) die("i2d cert");
    add_blob(name, der, (size_t)n);
    OPENSSL_free(der);
    return x;
}

static ASN1_INTEGER *aint(const char *hexv) {
    BIGNUM *b = NULL;
    if (!BN_hex2bn(&b, hexv)) die("bn");
    ASN1_INTEGER *a = BN_to_ASN1_INTEGER(b, NULL);
    BN_free(b);
    if (!a) die("aint");
    return a;
}
static OCSP_CERTID *cid(const EVP_MD *md, X509 *issuer, const char *serial_hex) {
    ASN1_INTEGER *sn = aint(serial_hex);
    OCSP_CERTID *id = OCSP_cert_id_new(md, X509_get_subject_name(issuer),
                                       X509_get0_pubkey_bitstr(issuer), sn);
    ASN1_INTEGER_free(sn);
    if (!id) die("cid");
    return id;
}
static void req_add(OCSP_REQUEST *r, OCSP_CERTID *id) {
    if (!OCSP_request_add0_id(r, id)) die("add id");
}
static void nonce(OCSP_REQUEST *r, size_t n, uint8_t base) {
    uint8_t *v = malloc(n);
    if (!v) die("malloc");
    for (size_t i = 0; i < n; i++) v[i] = (uint8_t)(base + i);
    if (!OCSP_request_add1_nonce(r, v, (int)n)) die("nonce");
    free(v);
}
static void raw_ext(OCSP_REQUEST *r, int nid, const char *oid, int crit, const uint8_t *val, size_t n) {
    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
    if (!os || !ASN1_OCTET_STRING_set(os, val, (int)n)) die("os");
    X509_EXTENSION *e = nid ? X509_EXTENSION_create_by_NID(NULL, nid, crit, os)
                            : X509_EXTENSION_create_by_OBJ(NULL, OBJ_txt2obj(oid, 1), crit, os);
    if (!e || !OCSP_REQUEST_add_ext(r, e, -1)) die("ext");
    X509_EXTENSION_free(e);
    ASN1_OCTET_STRING_free(os);
}
static void req_done(const char *name, OCSP_REQUEST *r, const uint8_t *junk, size_t jn) {
    uint8_t *der = NULL;
    int n = i2d_OCSP_REQUEST(r, &der);
    if (n <= 0) die("i2d req");
    uint8_t *b = malloc((size_t)n + jn);
    if (!b) die("malloc");
    memcpy(b, der, (size_t)n);
    if (jn) memcpy(b + n, junk, jn);
    add_blob(name, b, (size_t)n + jn);
    free(b);
    OPENSSL_free(der);
    OCSP_REQUEST_free(r);
}
/* Replace the first SHA-256 AlgorithmIdentifier OID with 1.3.6.1.4.1.45503.1, which no
 * digest answers to: the "unknown hash" CertID. */
static void patch_unknown_hash(const char *name, const char *from) {
    static const uint8_t sha256[] = { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
    static const uint8_t other[]  = { 0x06, 0x09, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xE3, 0x3F, 0x01 };
    const blob_t *s = blob(from);
    uint8_t *b = malloc(s->n);
    if (!b) die("malloc");
    memcpy(b, s->b, s->n);
    for (size_t i = 0; i + sizeof sha256 <= s->n; i++)
        if (!memcmp(b + i, sha256, sizeof sha256)) {
            memcpy(b + i, other, sizeof other);
            add_blob(name, b, s->n);
            free(b);
            return;
        }
    die("no sha256 oid");
}

static size_t lsz(size_t v) { return v < 0x80 ? 1 : v <= 0xFF ? 2 : v <= 0xFFFF ? 3 : 4; }
/* DER length of the nonce Extension OCSP_request_add1_nonce makes from an L-byte value. */
static size_t nonce_ext_len(size_t L) {
    size_t inner = 1 + lsz(L) + L, oct = 1 + lsz(inner) + inner, c = 11 + oct;
    return 1 + lsz(c) + c;
}
static size_t nonce_for(size_t target) {
    for (size_t L = 1; L < 70000; L++) if (nonce_ext_len(L) >= target) return L;
    die("nonce_for");
    return 0;
}

static X509 *CA, *TWIN, *OTHER;
static EVP_PKEY *K_CA, *K_TWIN, *K_OTHER, *K_RESP;

static void make_inputs(void) {
    K_CA = seed_key(0x40); K_TWIN = seed_key(0x60); K_OTHER = seed_key(0x80); K_RESP = seed_key(0xA0);
    X509_NAME *n_ca = mkname("pqHSM golden", "pqHSM Golden Root CA");
    X509_NAME *n_other = mkname("pqHSM golden", "pqHSM Golden Other CA");
    X509_NAME *n_resp = mkname("pqHSM golden", "pqHSM Golden OCSP Responder");
    X509_NAME *n_case = mkname("PQHSM GOLDEN", "pqhsm   golden root ca");
    CA = mkcert("ca", n_ca, n_ca, K_CA, K_CA, 1, NULL);
    TWIN = mkcert("ca_twin", n_ca, n_ca, K_TWIN, K_TWIN, 2, NULL);
    OTHER = mkcert("other_ca", n_other, n_other, K_OTHER, K_OTHER, 3, NULL);
    X509_free(mkcert("resp_ocsp", n_resp, n_ca, K_RESP, K_CA, 0x10, "OCSPSigning"));
    X509_free(mkcert("resp_noeku", n_resp, n_ca, K_RESP, K_CA, 0x11, NULL));
    X509_free(mkcert("resp_serverauth", n_resp, n_ca, K_RESP, K_CA, 0x12, "serverAuth"));
    X509_free(mkcert("resp_multi", n_resp, n_ca, K_RESP, K_CA, 0x13, "serverAuth,OCSPSigning"));
    X509_free(mkcert("resp_other_issuer", n_resp, n_other, K_RESP, K_OTHER, 0x14, "OCSPSigning"));
    X509_free(mkcert("resp_other_noeku", n_resp, n_other, K_RESP, K_OTHER, 0x15, NULL));
    X509_free(mkcert("resp_twin_issuer", n_resp, n_ca, K_RESP, K_TWIN, 0x16, "OCSPSigning"));
    X509_free(mkcert("resp_issuer_case", n_resp, n_case, K_RESP, K_CA, 0x17, "OCSPSigning"));
    X509_NAME_free(n_ca); X509_NAME_free(n_other); X509_NAME_free(n_resp); X509_NAME_free(n_case);
    {   /* the responder certificate with junk after it: d2i reads a prefix */
        const blob_t *r = blob("resp_ocsp");
        uint8_t *b = malloc(r->n + 4);
        if (!b) die("malloc");
        memcpy(b, r->b, r->n); memcpy(b + r->n, "JUNK", 4);
        add_blob("resp_ocsp_junk", b, r->n + 4);
        uint8_t *c = malloc(blob("ca")->n + 4);
        if (!c) die("malloc");
        memcpy(c, blob("ca")->b, blob("ca")->n); memcpy(c + blob("ca")->n, "JUNK", 4);
        add_blob("ca_junk", c, blob("ca")->n + 4);
        free(b); free(c);
    }
    add_blob("garbage", (const uint8_t *)"this is not DER at all", 22);
    add_blob("empty", (const uint8_t *)"", 0);

    const EVP_MD *s1 = EVP_sha1(), *s256 = EVP_sha256();
    OCSP_REQUEST *r;
    r = OCSP_REQUEST_new(); req_add(r, cid(s1, CA, "0A")); req_done("req_good_sha1", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "0A")); nonce(r, 16, 0x10); req_done("req_good_sha256_nonce", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "01A2")); req_done("req_revoked_kc", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "FF10")); req_done("req_revoked_noreason", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(s1, CA, "7B")); req_done("req_revoked_sha1", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(EVP_sha512(), CA, "7B")); req_done("req_sha512", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(EVP_sha384(), CA, "7B")); req_done("req_sha384", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(EVP_sha224(), CA, "7B")); req_done("req_sha224", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(EVP_sha3_256(), CA, "7B")); req_done("req_sha3_256", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(EVP_md5(), CA, "7B")); req_done("req_md5", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "7B")); req_done("req_sha256_7b", r, NULL, 0);
    patch_unknown_hash("req_unknown_hash", "req_sha256_7b");
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, OTHER, "01A2")); req_done("req_other_issuer", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, TWIN, "01A2")); req_done("req_twin_key", r, NULL, 0);
    r = OCSP_REQUEST_new();
    req_add(r, cid(s1, CA, "0A")); req_add(r, cid(s1, CA, "01A2")); req_add(r, cid(s1, OTHER, "01A2"));
    req_add(r, cid(s256, CA, "7B")); nonce(r, 8, 0x30);
    req_done("req_mixed_pre", r, NULL, 0);
    patch_unknown_hash("req_mixed", "req_mixed_pre");
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "0")); req_done("req_serial_zero", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "-7B")); req_done("req_serial_negative", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "80")); req_done("req_serial_80", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "D0")); req_add(r, cid(s256, CA, "D1")); req_done("req_year_bounds", r, NULL, 0);
    r = OCSP_REQUEST_new();
    for (const char *const *s = (const char *const[]){ "C0", "C1", "C2", "C3", "C4", "C5", "C6", "C9", "CA", NULL }; *s; s++)
        req_add(r, cid(s256, CA, *s));
    req_done("req_all_reasons", r, NULL, 0);
    r = OCSP_REQUEST_new();
    req_add(r, cid(s256, CA, "E1")); req_add(r, cid(s256, CA, "E2")); req_add(r, cid(s256, CA, "E3"));
    req_done("req_div016", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_done("req_empty_list", r, NULL, 0);
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "0A")); req_done("req_trailing_junk", r, (const uint8_t *)"JUNK", 4);
    r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "01A2")); req_add(r, cid(s256, CA, "01A2")); req_done("req_duplicate", r, NULL, 0);
    static const size_t targets[] = { 127, 128, 255, 256, 65535, 65536 };
    static const char *const tnames[] = { "req_nonce_ext_127", "req_nonce_ext_128", "req_nonce_ext_255",
                                          "req_nonce_ext_256", "req_nonce_ext_65535", "req_nonce_ext_65536" };
    for (size_t i = 0; i < 6; i++) {
        r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "0A"));
        nonce(r, nonce_for(targets[i]), 0x01);
        req_done(tnames[i], r, NULL, 0);
    }
    {
        static const uint8_t inner[18] = { 0x04, 0x10, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
                                           0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f };
        r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "0A"));
        raw_ext(r, NID_id_pkix_OCSP_Nonce, NULL, 1, inner, sizeof inner);
        req_done("req_nonce_critical", r, NULL, 0);
        r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "0A"));
        nonce(r, 16, 0x60); nonce(r, 16, 0x70);
        req_done("req_two_nonces", r, NULL, 0);
        r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "0A"));
        raw_ext(r, 0, "1.3.6.1.4.1.45503.2", 0, (const uint8_t *)"\x05\x00", 2);
        req_done("req_other_ext", r, NULL, 0);
        r = OCSP_REQUEST_new(); req_add(r, cid(s256, CA, "0A"));
        raw_ext(r, 0, "1.3.6.1.4.1.45503.2", 0, (const uint8_t *)"\x05\x00", 2);
        nonce(r, 16, 0x80);
        req_done("req_other_then_nonce", r, NULL, 0);
    }
    {   /* 20 CertIDs with 2000-byte serials: about 41 kB, under the service's 64 kB body cap */
        r = OCSP_REQUEST_new();
        static char big[4002];
        for (int i = 0; i < 4000; i++) big[i] = "123456789ABCDEF"[i % 15];
        big[4000] = '\0';
        for (int i = 0; i < 20; i++) req_add(r, cid(s256, CA, big));
        req_done("req_bigserial_x20", r, NULL, 0);
    }
}

/* ---- OCSP rows ------------------------------------------------------------------- */
static fhsm_rv_t sign_ed(void *ctx, const uint8_t *tbs, size_t n, uint8_t *sig, size_t *sl) {
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    size_t cap = *sl;
    int ok = m && EVP_DigestSignInit(m, NULL, NULL, NULL, (EVP_PKEY *)ctx) == 1
             && EVP_DigestSign(m, sig, &cap, tbs, n) == 1;
    EVP_MD_CTX_free(m);
    if (!ok) return FHSM_RV_FUNCTION_FAILED;
    *sl = cap;
    return FHSM_RV_OK;
}
static fhsm_rv_t sign_fail(void *ctx, const uint8_t *tbs, size_t n, uint8_t *sig, size_t *sl) {
    (void)ctx; (void)tbs; (void)n; (void)sig; (void)sl;
    return FHSM_RV_DEVICE_ERROR;
}

static void status_row(const char *c, int st) {
    CASE = c;
    uint8_t out[5];
    memset(out, 0xEE, sizeof out);
    size_t n = fhsm_ocsp_status_response(st, out);
    kvnum("status", st);
    kvhex("out", out, sizeof out);
    emit("status", (long long)n);
}

static void check_row(const char *c, const char *resp, const char *ca, const char *rp, const char *cp) {
    CASE = c;
    const blob_t *r = blob(resp), *a = blob(ca);
    char err[1024];
    memset(err, '@', sizeof err); err[sizeof err - 1] = '\0';
    int rv = fhsm_ocsp_check_responder(r->b, r->n, a->b, a->n, rp, cp, err, FHSM_REV_ERR_MAX);
    kvraw("responder", resp); kvraw("ca", ca);
    kvraw("rpath", rp ? rp : "NULL"); kvraw("cpath", cp ? cp : "NULL");
    if (err[0] == '@') kvraw("err", "untouched"); else kvs("err", err);
    emit("check", rv);
}

static void time_str(char *o, size_t on, const ASN1_GENERALIZEDTIME *t) {
    if (!t) { snprintf(o, on, "-"); return; }
    snprintf(o, on, "%.*s", ASN1_STRING_length(t), (const char *)ASN1_STRING_get0_data(t));
}

/* Parse C's whole OCSPResponse with OpenSSL: what a client would see. */
static void summarise(const uint8_t *der, size_t n, const blob_t *reqb) {
    const uint8_t *p = der;
    OCSP_RESPONSE *r = d2i_OCSP_RESPONSE(NULL, &p, (long)n);
    if (!r) { kvraw("resp", "unparsed"); return; }
    kvnum("resp_status", OCSP_response_status(r));
    OCSP_BASICRESP *bs = OCSP_response_get1_basic(r);
    if (!bs) { kvraw("resp", "no_basic"); OCSP_RESPONSE_free(r); return; }
    char s[8192] = "", t[64], tu[64] = "-", nu[64] = "-";
    for (int i = 0; i < OCSP_resp_count(bs); i++) {
        OCSP_SINGLERESP *sr = OCSP_resp_get0(bs, i);
        int reason = -1;
        ASN1_GENERALIZEDTIME *rt = NULL, *a = NULL, *b = NULL;
        int st = OCSP_single_get0_status(sr, &reason, &rt, &a, &b);
        time_str(t, sizeof t, rt);
        if (i == 0) { time_str(tu, sizeof tu, a); time_str(nu, sizeof nu, b); }
        size_t l = strlen(s);
        snprintf(s + l, sizeof s - l, "%s%s/%d/%s", i ? "," : "",
                 st == V_OCSP_CERTSTATUS_GOOD ? "good" : st == V_OCSP_CERTSTATUS_REVOKED ? "revoked"
                 : st == V_OCSP_CERTSTATUS_UNKNOWN ? "unknown" : "?", reason, t);
    }
    kvraw("resp_singles", s);
    time_str(t, sizeof t, OCSP_resp_get0_produced_at(bs));
    kvraw("resp_produced", t); kvraw("resp_this", tu); kvraw("resp_next", nu);
    const ASN1_OCTET_STRING *kid = NULL; const X509_NAME *nm = NULL;
    if (OCSP_resp_get0_id(bs, &kid, &nm) && nm) {
        char *o = X509_NAME_oneline(nm, NULL, 0);
        kvs("resp_by_name", o ? o : "?");
        OPENSSL_free(o);
    } else kvraw("resp_by_name", "-");
    const uint8_t *q = reqb->b;
    OCSP_REQUEST *req = d2i_OCSP_REQUEST(NULL, &q, (long)reqb->n);
    kvnum("resp_nonce_check", req ? OCSP_check_nonce(req, bs) : -9);
    OCSP_REQUEST_free(req);
    OCSP_BASICRESP_free(bs);
    OCSP_RESPONSE_free(r);
}

static fhsm_rev_db_t OCSP_DB;
typedef struct {
    const char *fn;      /* answer | answer_ex */
    const char *req, *ca, *resp, *db;
    int days;
    const char *label;
    int sign_fail, err_null, stats_null;
    size_t err_cap;
    long synth;
} ans_t;

static void answer_row(const char *c, ans_t a) {
    CASE = c;
    const blob_t *rq = blob(a.req), *ca = blob(a.ca), *rs = blob(a.resp);
    fhsm_rev_db_t spec_db, *db = &OCSP_DB;
    if (a.db) { build(&spec_db, a.db); db = &spec_db; }
    EVP_PKEY *k = !strcmp(a.resp, "ca") ? K_CA : K_RESP;
    const uint8_t *alg = NULL; size_t algn = 0;
    if (fhsm_pki_algid(FHSM_PKI_SIG_ED25519, &alg, &algn) != FHSM_RV_OK) die("algid");
    uint8_t *out = (uint8_t *)&out; size_t out_len = 12345;
    fhsm_ocsp_stats_t st;
    memset(&st, 0xFF, sizeof st);
    char err[1024];
    memset(err, '@', sizeof err); err[sizeof err - 1] = '\0';
    size_t cap = a.err_cap ? a.err_cap : FHSM_REV_ERR_MAX;
    fhsm_composite_sign_cb sg = a.sign_fail ? sign_fail : sign_ed;
    synth = a.synth; enc_called = 0; pin_time = 1;
    int rv = !strcmp(a.fn, "answer")
        ? fhsm_ocsp_answer(rq->b, rq->n, ca->b, ca->n, rs->b, rs->n, db, a.days, a.label, sg, k,
                           &out, &out_len, a.stats_null ? NULL : &st, a.err_null ? NULL : err, cap)
        : fhsm_ocsp_answer_ex(rq->b, rq->n, ca->b, ca->n, rs->b, rs->n, db, a.days, a.label,
                              alg, algn, sg, k, &out, &out_len, a.stats_null ? NULL : &st,
                              a.err_null ? NULL : err, cap);
    pin_time = 0; synth = -1;
    if (strcmp(a.fn, "answer_ex")) kvraw("fn", a.fn);
    kvraw("req", a.req);
    if (strcmp(a.ca, "ca")) kvraw("ca", a.ca);
    if (strcmp(a.resp, "resp_ocsp")) kvraw("responder", a.resp);
    if (a.db) kvs("db", a.db);
    if (a.days != 7) kvnum("days", a.days);
    if (a.label) kvs("label", a.label);
    if (a.sign_fail) kvraw("sign", "fail");
    if (a.err_null) kvraw("err_mode", "null");
    if (a.err_cap) kvnum("err_cap", (long long)a.err_cap);
    if (a.stats_null) kvraw("stats", "null");
    if (a.synth >= 0) kvnum("synth", a.synth);
    kvnum("encoder_called", enc_called);
    if (!a.err_null) { if (err[0] == '@') kvraw("err", "untouched"); else kvs("err", err); }
    if (!a.stats_null) {
        char b[160];
        snprintf(b, sizeof b, "%zu,%zu,%zu,%zu,%d", st.asked, st.ours, st.revoked, st.unknown, st.nonce_echoed);
        kvraw("stats", b);
    }
    kvnum("out_null", out == NULL);
    kvnum("out_len", (long long)out_len);
    if (rv == FHSM_REV_OK && a.synth >= 0) {
        size_t head = out_len - (size_t)a.synth;
        int tail_ok = 1;
        for (long i = 0; i < a.synth; i++) tail_ok &= out[head + (size_t)i] == pattern((size_t)i);
        kvhex("prefix", out, head);
        kvnum("tail_ok", tail_ok);
    } else if (rv == FHSM_REV_OK) {
        char rel[200];
        snprintf(rel, sizeof rel, "ocsp/%s.resp.der", c);
        put_file(at(0, OUT, rel), out, out_len);
        summarise(out, out_len, rq);
    }
    emit("answer", rv);
    if (rv == FHSM_REV_OK) free(out);
    if (a.db) fhsm_rev_db_free(&spec_db);
}
#define ANS(c, ...) answer_row(c, (ans_t){ .fn = "answer_ex", .ca = "ca", .resp = "resp_ocsp", \
                                           .days = 7, .synth = -1, __VA_ARGS__ })

static void layout_row(void) {
    CASE = "c_struct_layout";
    kvnum("entry_size", sizeof(fhsm_rev_entry_t));
    kvnum("entry_serial", offsetof(fhsm_rev_entry_t, serial));
    kvnum("entry_serial_len", offsetof(fhsm_rev_entry_t, serial_len));
    kvnum("entry_date", offsetof(fhsm_rev_entry_t, date));
    kvnum("entry_reason", offsetof(fhsm_rev_entry_t, reason));
    kvnum("db_size", sizeof(fhsm_rev_db_t));
    kvnum("db_crl_number", offsetof(fhsm_rev_db_t, crl_number));
    kvnum("db_e", offsetof(fhsm_rev_db_t, e));
    kvnum("db_n", offsetof(fhsm_rev_db_t, n));
    kvnum("db_cap", offsetof(fhsm_rev_db_t, cap));
    kvnum("stats_size", sizeof(fhsm_ocsp_stats_t));
    kvnum("stats_nonce_echoed", offsetof(fhsm_ocsp_stats_t, nonce_echoed));
    kvnum("single_size", sizeof(fhsm_composite_ocsp_single_t));
    kvnum("signer_size", sizeof(fhsm_pki_signer_t));
    kvnum("err_max", FHSM_REV_ERR_MAX);
    kvnum("max_entries", FHSM_REV_MAX_ENTRIES);
    const uint8_t *alg = NULL; size_t n = 0;
    if (fhsm_pki_algid(FHSM_PKI_SIG_COMPOSITE_MLDSA65_ED25519, &alg, &n) != FHSM_RV_OK) die("algid");
    kvhex("composite_algid", alg, n);
    if (fhsm_pki_algid(FHSM_PKI_SIG_ED25519, &alg, &n) != FHSM_RV_OK) die("algid");
    kvhex("ed25519_algid", alg, n);
    kvnum("now", NOW);
    emit("layout", 0);
}

int main(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[1], "make")) { fprintf(stderr, "usage: gen_rev make OUTDIR WORKDIR\n"); return 2; }
    OUT = argv[2]; WORK = argv[3];
    umask(022);
    if (mkdir(at(0, OUT, "db"), 0755) || mkdir(at(0, OUT, "saved"), 0755)
        || mkdir(at(0, OUT, "der"), 0755) || mkdir(at(0, OUT, "ocsp"), 0755))
        die("mkdir");
    tsv = fopen(at(0, OUT, "cases.tsv"), "w");
    if (!tsv) die("cases.tsv");
    fprintf(tsv, "# generated by tests-support/golden/gen_rev.c from the legacy C; do not edit\n");

    layout_row();

    /* --- reasons --- */
    static const char *const names[] = { "unspecified", "keyCompromise", "cACompromise",
        "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold",
        "privilegeWithdrawn", "aACompromise" };
    char cn[96];
    for (size_t i = 0; i < 9; i++) {
        snprintf(cn, sizeof cn, "reason_code_%s", names[i]);
        reason_code(strdup(cn), names[i]);
    }
    reason_code("reason_code_empty", "");
    reason_code("reason_code_dash", "-");
    reason_code("reason_code_wrong_case", "KeyCompromise");
    reason_code("reason_code_remove_from_crl", "removeFromCRL");
    reason_code("reason_code_numeric", "1");
    reason_code("reason_code_trailing_space", "superseded ");
    for (int code = -3; code <= 11; code++) {
        snprintf(cn, sizeof cn, "reason_name_%s%d", code < 0 ? "minus_" : "", code < 0 ? -code : code);
        reason_name(strdup(cn), code);
    }
    reason_name("reason_name_int_max", INT_MAX);
    CASE = "reason_list"; emit_s("reason_list", fhsm_rev_reason_list());

    /* --- hex --- */
    hex("hex_empty", "", 64);
    hex("hex_one_digit", "0", 64);
    hex("hex_two_digits", "0a", 64);
    hex("hex_upper", "0A1B", 64);
    hex("hex_mixed_case", "aBcD", 64);
    hex("hex_all_digits", "0123456789abcdefABCDEF", 64);
    hex("hex_odd", "A1B", 64);
    hex("hex_bad_first_pair", "g0", 64);
    hex("hex_bad_low_nibble", "0g", 64);
    hex("hex_bad_later_pair_writes_earlier_bytes", "A1B2ZZ", 64);
    hex("hex_0x_prefix", "0x10", 64);
    hex("hex_space", " 1", 64);
    hex("hex_utf8", "\xc3\xa9", 64);
    hex("hex_cap_exact", "0102030405060708", 8);
    hex("hex_cap_over_by_one", "010203040506070809", 8);
    hex("hex_cap_zero", "01", 0);
    {
        char h[200];
        for (int i = 0; i < 128; i++) h[i] = "0123456789abcdef"[i % 16];
        h[128] = '\0';
        hex("hex_64_bytes", h, 64);
        h[128] = 'a'; h[129] = 'b'; h[130] = '\0';
        hex("hex_65_bytes", h, 64);
    }

    /* --- dates --- */
    date("date_valid", "20260101000000Z");
    date("date_epoch", "19700101000000Z");
    date("date_one_second_before_epoch", "19691231235959Z");
    date("date_two_seconds_before_epoch", "19691231235958Z");
    date("date_year_0000", "00000101000000Z");
    date("date_year_9999", "99991231235959Z");
    date("date_leap_day", "20240229000000Z");
    date("date_y2038", "20380119031408Z");
    date("date_14_digits_no_z", "20260101000000");
    date("date_lower_z", "20260101000000z");
    date("date_16_chars", "202601010000000Z");
    date("date_13_digits", "2026010100000Z");
    date("date_letter", "2026O101000000Z");
    date("date_space", "2026 101000000Z");
    date("date_plus", "+026010100000Z0");
    date("date_empty", "");
    date("date_div016_month_13", "20261340990000Z");
    date("date_div016_month_00", "20260001000000Z");
    date("date_div016_day_00", "20260100000000Z");
    date("date_div016_feb_30", "20260230000000Z");
    date("date_div016_feb_29_non_leap", "20230229000000Z");
    date("date_div016_feb_29_1900", "19000229000000Z");
    date("date_div016_apr_31", "20260431000000Z");
    date("date_div016_hour_24", "20260101240000Z");
    date("date_div016_hour_99", "20260101990000Z");
    date("date_div016_minute_60", "20260101006000Z");
    date("date_div016_second_60", "20261231235960Z");
    date("date_div016_all_nines", "20269999999999Z");

    /* --- time_to_date --- */
    tdate("time_epoch", 0);
    tdate("time_minus_one", -1);
    tdate("time_2026", 1767225600);
    tdate("time_last_of_9999", 253402300799LL);
    tdate("time_first_of_10000", 253402300800LL);
    tdate("time_first_of_0000", -62167219200LL);
    tdate("time_last_of_year_minus_1", -62167219201LL);
    tdate("time_first_of_year_minus_999", year_start(-999));
    tdate("time_last_of_year_minus_1000", year_start(-999) - 1);
    tdate("time_int64_max", INT64_MAX);
    tdate("time_int64_min", INT64_MIN);

    /* --- serial_eq --- */
    seq("serial_eq_same", "a1", "a1");
    seq("serial_eq_leading_zero_left", "00a1", "a1");
    seq("serial_eq_leading_zero_right", "a1", "0000a1");
    seq("serial_eq_trailing_zero_differs", "a100", "a1");
    seq("serial_eq_different", "a1", "a2");
    seq("serial_eq_zero_and_zeros", "00", "000000");
    seq("serial_eq_both_empty", "", "");
    seq("serial_eq_zero_and_empty", "00", "");
    seq("serial_eq_prefix", "a1b2", "a1");

    /* --- load: crafted files --- */
    CRAFT("empty", "");
    CRAFT("comments_only", "# a\n#b\n\n   \n\t\n");
    CRAFT("crlf", "crlNumber 3\r\nA1 20260101000000Z keyCompromise\r\nB2 20260102000000Z -\r\n");
    CRAFT("cr_only", "crlNumber 3\rA1 20260101000000Z keyCompromise\rB2 20260102000000Z -\r");
    CRAFT("cr_only_entries", "A1 20260101000000Z -\rB2 20260102000000Z -\r");
    CRAFT("embedded_cr", "A1 20260101000000Z\rjunk\n");
    CRAFT("leading_ws", "  \tA1 20260101000000Z -\n\t# indented comment\n");
    CRAFT("trailing_comment", "A1 20260101000000Z - # note\n");
    CRAFT("trailing_comment_no_reason", "A1 20260101000000Z # note\n");
    CRAFT("extra_token", "A1 20260101000000Z keyCompromise extra\n");
    CRAFT("no_final_newline", "A1 20260101000000Z -");
    CRAFT("many_spaces", "A1    20260101000000Z\t\tsuperseded\n");
    CRAFT("all_reasons", "C0 20260301000000Z unspecified\nC1 20260301000001Z keyCompromise\n"
          "C2 20260301000002Z cACompromise\nC3 20260301000003Z affiliationChanged\n"
          "C4 20260301000004Z superseded\nC5 20260301000005Z cessationOfOperation\n"
          "C6 20260301000006Z certificateHold\nC9 20260301000009Z privilegeWithdrawn\n"
          "CA 20260301000010Z aACompromise\nCB 20260301000011Z -\nCC 20260301000012Z\n");
    CRAFT("reason_wrong_case", "A1 20260101000000Z KeyCompromise\n");
    CRAFT("reason_remove_from_crl", "A1 20260101000000Z removeFromCRL\n");
    CRAFT("reason_numeric", "A1 20260101000000Z 1\n");
    CRAFT("one_token", "A1\n");
    CRAFT("serial_not_hex", "ZZ 20260101000000Z -\n");
    CRAFT("serial_0x", "0xA1 20260101000000Z -\n");
    CRAFT("serial_lower", "a1b2 20260101000000Z -\n");
    CRAFT("serial_zero", "00 20260101000000Z -\n0000 20260102000000Z -\n");
    CRAFT("serial_64_bytes", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
          "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f 20260101000000Z -\n");
    CRAFT("serial_65_bytes", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
          "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40 20260101000000Z -\n");
    CRAFT("date_14_no_z", "A1 20260101000000 -\n");
    CRAFT("date_lower_z", "A1 20260101000000z -\n");
    CRAFT("date_one_second_before_epoch", "A1 19691231235959Z -\n");
    CRAFT("date_epoch", "A1 19700101000000Z -\n");
    CRAFT("date_year_bounds", "A1 00000101000000Z -\nA2 99991231235959Z -\n");
    CRAFT("div016_month_00", "A1 20260001000000Z -\n");
    CRAFT("div016_feb_30", "A1 20260230000000Z -\n");
    CRAFT("div016_hour_24", "A1 20260101240000Z -\n");
    CRAFT("div016_second_60", "A1 20261231235960Z -\n");
    CRAFT("div016_second_line", "A1 20260101000000Z -\nA2 20261340990000Z -\n");
    CRAFT("crl_tab", "crlNumber\t7\n");
    CRAFT("crl_two_spaces", "crlNumber  7\n");
    CRAFT("crl_trailing_space", "crlNumber 7 \n");
    CRAFT("crl_trailing_tab", "crlNumber 7\t\n");
    CRAFT("crl_negative", "crlNumber -1\n");
    CRAFT("crl_overflow", "crlNumber 99999999999999999999\n");
    CRAFT("crl_max", "crlNumber 18446744073709551615\n");
    CRAFT("crl_empty_value", "crlNumber \n");
    CRAFT("crl_hex", "crlNumber 0x10\n");
    CRAFT("crl_plus", "crlNumber +5\n");
    CRAFT("crl_bare", "crlNumber\n");
    CRAFT("crl_lowercase", "crlnumber 7\n");
    CRAFT("crl_twice", "crlNumber 1\ncrlNumber 2\n");
    CRAFT("crl_after_entries", "A1 20260101000000Z -\ncrlNumber 9\n");
    CRAFT("crl_indented", "  crlNumber 4\n");
    CRAFT("crl_then_bad_line", "crlNumber 9\nA1 bad -\n");
    CRAFT("line_number_counts_comments", "# c\n\nA1 20260101000000Z -\nBAD\n");
    CRAFT("nul_byte", "A1 20260101000000Z -\0junk\nB2 20260101000000Z -\n");
    CRAFT("vertical_tab_line", "\v\n");
    CRAFT("formfeed_prefix", "\fA1 20260101000000Z -\n");
    CRAFT("duplicate_serials", "A1 20260101000000Z -\n00A1 20260102000000Z keyCompromise\n");
    CRAFT("utf8_bom", "\xEF\xBB\xBF" "A1 20260101000000Z -\n");
    {
        char b[2048];
        /* a 600-character comment: fgets returns it in two pieces, and the second is parsed */
        memset(b, 'x', sizeof b);
        b[0] = '#'; b[1] = ' '; b[600] = '\n';
        craft("long_comment", b, 601);
        /* a comment whose second 511-byte piece is a valid entry: it comes back to life */
        memset(b, 'x', sizeof b);
        b[0] = '#';
        const char *live = "A1 20260101000000Z keyCompromise\n";
        memcpy(b + 511, live, strlen(live));
        craft("long_comment_revives_an_entry", b, 511 + strlen(live));
        /* an entry followed by 600 spaces: the second piece is blank */
        memset(b, ' ', sizeof b);
        memcpy(b, "A1 20260101000000Z keyCompromise", 32);
        b[700] = '\n';
        craft("long_entry_line", b, 701);
        /* a serial token longer than the %159s field */
        memset(b, 'A', sizeof b);
        memcpy(b + 170, " 20260101000000Z -\n", 19);
        craft("serial_170_digits", b, 189);
    }
    CRAFT("ocsp", "# the database the answer rows use\ncrlNumber 12\n"
          "01A2 20260101000000Z keyCompromise\n00FF10 20260215123000Z -\n"
          "7B 20251231235959Z superseded\n80 20260301000000Z cACompromise\n"
          "00 20260302000000Z unspecified\n"
          "C0 20260301000000Z unspecified\nC1 20260301000001Z keyCompromise\n"
          "C2 20260301000002Z cACompromise\nC3 20260301000003Z affiliationChanged\n"
          "C4 20260301000004Z superseded\nC5 20260301000005Z cessationOfOperation\n"
          "C6 20260301000006Z certificateHold\nC9 20260301000009Z privilegeWithdrawn\n"
          "CA 20260301000010Z aACompromise\n"
          "D0 00000101000000Z affiliationChanged\nD1 99991231235959Z -\n");

    static const char *const crafted[] = { "empty", "comments_only", "crlf", "cr_only",
        "cr_only_entries", "embedded_cr", "leading_ws", "trailing_comment",
        "trailing_comment_no_reason", "extra_token", "no_final_newline", "many_spaces",
        "all_reasons", "reason_wrong_case", "reason_remove_from_crl", "reason_numeric",
        "one_token", "serial_not_hex", "serial_0x", "serial_lower", "serial_zero",
        "serial_64_bytes", "serial_65_bytes", "date_14_no_z", "date_lower_z",
        "date_one_second_before_epoch", "date_epoch", "date_year_bounds", "div016_month_00",
        "div016_feb_30", "div016_hour_24", "div016_second_60", "div016_second_line", "crl_tab",
        "crl_two_spaces", "crl_trailing_space", "crl_trailing_tab", "crl_negative",
        "crl_overflow", "crl_max", "crl_empty_value", "crl_hex", "crl_plus", "crl_bare",
        "crl_lowercase", "crl_twice", "crl_after_entries", "crl_indented", "crl_then_bad_line",
        "line_number_counts_comments", "nul_byte", "vertical_tab_line", "formfeed_prefix",
        "duplicate_serials", "utf8_bom", "long_comment", "long_comment_revives_an_entry",
        "long_entry_line", "serial_170_digits", "ocsp" };
    for (size_t i = 0; i < sizeof crafted / sizeof *crafted; i++) {
        char c[128], f[160];
        snprintf(c, sizeof c, "load_%s", crafted[i]);
        snprintf(f, sizeof f, "db/%s.db", crafted[i]);
        LOAD(strdup(c), strdup(f));
    }
    LOAD("load_missing_file_is_a_first_run", "missing");
    LOAD("load_directory_reads_as_empty", "dir");
    LOAD("load_unreadable_file_is_eio", "unreadable");
    LOAD("load_not_a_directory_is_eio", "notdir");
    LOAD("load_100000_entries", "gen:100000");
    LOAD("load_100001_entries_is_too_many", "gen:100001");
    load_row("load_err_null", "db/date_lower_z.db", 0, FHSM_REV_ERR_MAX);
    load_row("load_err_cap_0", "db/date_lower_z.db", 1, 0);
    load_row("load_err_cap_1", "db/date_lower_z.db", 1, 1);
    load_row("load_err_cap_10", "db/date_lower_z.db", 1, 10);
    load_row("load_err_null_eio", "unreadable", 0, FHSM_REV_ERR_MAX);

    /* --- save --- */
    static const char three[] = "crl=7;e=01A2,20260101000000Z,1;e=00FF10,20260215123000Z,-1;e=7B,20251231235959Z,4";
    save_row("save_three", three, "plain", 1);
    save_row("save_empty", "crl=0", "plain", 1);
    save_row("save_crl_max", "crl=18446744073709551615", "plain", 1);
    save_row("save_every_reason_code", "e=C0,20260301000000Z,0;e=C1,20260301000000Z,1;e=C2,20260301000000Z,2;"
             "e=C3,20260301000000Z,3;e=C4,20260301000000Z,4;e=C5,20260301000000Z,5;e=C6,20260301000000Z,6;"
             "e=C7,20260301000000Z,7;e=C8,20260301000000Z,8;e=C9,20260301000000Z,9;e=CA,20260301000000Z,10;"
             "e=CB,20260301000000Z,11;e=CC,20260301000000Z,-1;e=CD,20260301000000Z,-2;e=CE,20260301000000Z,100", "plain", 1);
    save_row("save_leading_zeros_kept", "e=0000A1,20260101000000Z,-1", "plain", 1);
    save_row("save_empty_serial", "e=,20260101000000Z,-1", "plain", 1);
    save_row("save_64_byte_serial", "e=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
             "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f,20260101000000Z,-1", "plain", 1);
    save_row("save_unvalidated_date", "e=A1,garbage,-1;e=A2,,1", "plain", 1);
    save_row("save_replaces_and_resets_mode", three, "replace", 1);
    save_row("save_overwrites_a_stale_tmp", three, "tmp_exists", 1);
    save_row("save_into_a_missing_dir", three, "missing_dir", 1);
    save_row("save_into_a_read_only_dir", three, "ro_dir", 1);
    save_row("save_onto_a_directory", three, "is_dir", 1);
    save_row("save_tmp_on_a_full_device", three, "tmp_full", 1);
    save_row("save_follows_a_tmp_symlink", three, "tmp_symlink", 1);
    save_row("save_path_1019_bytes", three, "len:1019", 1);
    save_row("save_path_1020_bytes_is_too_long", three, "len:1020", 1);
    save_row("save_err_null", three, "missing_dir", 0);

    /* --- C save, C load --- */
    static const char *const rt[] = { "save_three", "save_empty", "save_crl_max", "save_every_reason_code",
        "save_leading_zeros_kept", "save_empty_serial", "save_64_byte_serial", "save_unvalidated_date" };
    for (size_t i = 0; i < sizeof rt / sizeof *rt; i++) {
        char c[128], f[160];
        snprintf(c, sizeof c, "roundtrip_%s", rt[i] + 5);
        snprintf(f, sizeof f, "saved/%s.db", rt[i]);
        LOAD(strdup(c), strdup(f));
    }

    /* --- add, find, free --- */
    grow_rows();
    static const char fdb[] = "e=A1,20260101000000Z,-1;e=00A1,20260102000000Z,1;e=0000FF,20260103000000Z,-1;e=00,20260104000000Z,-1";
    find_row("find_exact", fdb, "a1");
    find_row("find_first_of_two_equal_serials", fdb, "00a1");
    find_row("find_more_leading_zeros", fdb, "0000a1");
    find_row("find_query_without_the_stored_zeros", fdb, "ff");
    find_row("find_zero", fdb, "00");
    find_row("find_zeros", fdb, "0000");
    find_row("find_empty_query", fdb, "");
    find_row("find_absent", fdb, "b2");
    find_row("find_in_an_empty_db", "crl=0", "a1");

    /* --- OCSP --- */
    for (int s = -1; s <= 6; s++) {
        snprintf(cn, sizeof cn, "status_%s%d", s < 0 ? "minus_" : "", s < 0 ? -s : s);
        status_row(strdup(cn), s);
    }
    status_row("status_256", 256);
    status_row("status_257", 257);
    status_row("status_int_min", INT_MIN);

    make_inputs();
    check_row("check_ok", "resp_ocsp", "ca", "resp.pem", "ca.pem");
    check_row("check_ok_default_names", "resp_ocsp", "ca", NULL, NULL);
    check_row("check_ok_eku_among_others", "resp_multi", "ca", NULL, NULL);
    check_row("check_no_eku", "resp_noeku", "ca", "resp.pem", "ca.pem");
    check_row("check_no_eku_default_names", "resp_noeku", "ca", NULL, NULL);
    check_row("check_server_auth_only", "resp_serverauth", "ca", "resp.pem", NULL);
    check_row("check_other_issuer", "resp_other_issuer", "ca", "resp.pem", "ca.pem");
    check_row("check_other_issuer_default_names", "resp_other_issuer", "ca", NULL, NULL);
    check_row("check_eku_is_checked_before_the_issuer", "resp_other_noeku", "ca", NULL, NULL);
    check_row("check_same_name_other_key_passes", "resp_twin_issuer", "ca", NULL, NULL);
    check_row("check_issuer_name_case_and_spaces_fold", "resp_issuer_case", "ca", NULL, NULL);
    check_row("check_ca_as_its_own_responder", "ca", "ca", "ca.pem", "ca.pem");
    check_row("check_responder_garbage", "garbage", "ca", "resp.pem", "ca.pem");
    check_row("check_responder_garbage_default_name", "garbage", "ca", NULL, NULL);
    check_row("check_responder_empty", "empty", "ca", NULL, NULL);
    check_row("check_ca_garbage", "resp_ocsp", "garbage", "resp.pem", "ca.pem");
    check_row("check_ca_garbage_default_name", "resp_ocsp", "garbage", NULL, NULL);
    check_row("check_both_garbage_names_the_responder", "garbage", "garbage", "resp.pem", "ca.pem");
    check_row("check_trailing_junk_is_ignored", "resp_ocsp_junk", "ca_junk", NULL, NULL);

    {
        char p[1024];
        load_at("db/ocsp.db", p, sizeof p);
        char err[FHSM_REV_ERR_MAX];
        if (fhsm_rev_db_load(p, &OCSP_DB, err, sizeof err) != FHSM_REV_OK) die(err);
        unlink(p);
    }
    ANS("answer_good_sha1", .req = "req_good_sha1");
    ANS("answer_good_sha256_echoes_the_nonce", .req = "req_good_sha256_nonce");
    ANS("answer_revoked_with_reason", .req = "req_revoked_kc");
    ANS("answer_revoked_without_reason_leading_zero_db", .req = "req_revoked_noreason");
    ANS("answer_revoked_sha1", .req = "req_revoked_sha1");
    ANS("answer_sha512", .req = "req_sha512");
    ANS("answer_sha384", .req = "req_sha384");
    ANS("answer_sha224", .req = "req_sha224");
    ANS("answer_sha3_256", .req = "req_sha3_256");
    ANS("answer_md5", .req = "req_md5");
    ANS("answer_unknown_hash_is_unknown", .req = "req_unknown_hash");
    ANS("answer_other_issuer_is_unknown", .req = "req_other_issuer");
    ANS("answer_same_name_other_key_is_unknown", .req = "req_twin_key");
    ANS("answer_mixed", .req = "req_mixed");
    ANS("answer_serial_zero", .req = "req_serial_zero");
    ANS("answer_negative_serial", .req = "req_serial_negative");
    ANS("answer_serial_80", .req = "req_serial_80");
    ANS("answer_year_bounds", .req = "req_year_bounds");
    ANS("answer_every_reason", .req = "req_all_reasons");
    ANS("answer_duplicate_certids", .req = "req_duplicate");
    ANS("answer_trailing_junk_in_request", .req = "req_trailing_junk");
    ANS("answer_nonce_ext_127", .req = "req_nonce_ext_127");
    ANS("answer_nonce_ext_128", .req = "req_nonce_ext_128");
    ANS("answer_nonce_ext_255", .req = "req_nonce_ext_255");
    ANS("answer_nonce_ext_256", .req = "req_nonce_ext_256");
    ANS("answer_nonce_ext_65535", .req = "req_nonce_ext_65535");
    ANS("answer_nonce_ext_65536_header_truncated", .req = "req_nonce_ext_65536");
    ANS("answer_nonce_critical_echoed_as_is", .req = "req_nonce_critical");
    ANS("answer_two_nonces_echoes_the_first", .req = "req_two_nonces");
    ANS("answer_other_extension_not_echoed", .req = "req_other_ext");
    ANS("answer_nonce_after_another_extension", .req = "req_other_then_nonce");
    ANS("answer_big_request_overflows_the_encoder_buffer", .req = "req_bigserial_x20");
    ANS("answer_div016_unvalidated_dates", .req = "req_div016",
        .db = "e=E1,20261340990000Z,-1;e=E2,garbage,-1;e=E3,19691231235959Z,1");
    ANS("answer_composite_algid", .fn = "answer", .req = "req_good_sha256_nonce");
    ANS("answer_ca_answers_for_itself", .req = "req_revoked_kc", .resp = "ca");
    ANS("answer_days_1", .req = "req_good_sha1", .days = 1);
    ANS("answer_days_365", .req = "req_good_sha1", .days = 365);
    ANS("answer_days_last_in_9999", .req = "req_good_sha1", .days = DMAX);
    ANS("answer_days_into_year_10000_emits_a_16_char_time", .req = "req_good_sha1", .days = DMAX + 1);
    ANS("answer_days_int_max_emits_an_18_char_time", .req = "req_good_sha1", .days = INT_MAX);
    ANS("answer_days_0", .req = "req_good_sha1", .days = 0);
    ANS("answer_days_negative_checked_first", .req = "garbage", .ca = "garbage", .days = -1);
    ANS("answer_ca_garbage", .req = "req_good_sha1", .ca = "garbage");
    ANS("answer_ca_checked_before_request", .req = "garbage", .ca = "garbage");
    ANS("answer_ca_trailing_junk", .req = "req_good_sha1", .ca = "ca_junk");
    ANS("answer_request_garbage", .req = "garbage");
    ANS("answer_request_garbage_labelled", .req = "garbage", .label = "requests/bad.der");
    ANS("answer_request_empty", .req = "empty", .label = "");
    ANS("answer_empty_request_list", .req = "req_empty_list");
    ANS("answer_empty_request_list_labelled", .req = "req_empty_list", .label = "q.der");
    ANS("answer_responder_garbage_fails_in_the_encoder", .req = "req_good_sha1", .resp = "garbage");
    ANS("answer_sign_failure", .req = "req_good_sha1", .sign_fail = 1);
    ANS("answer_err_null", .req = "garbage", .err_null = 1);
    ANS("answer_err_cap_8", .req = "garbage", .label = "requests/bad.der", .err_cap = 8);
    ANS("answer_stats_null", .req = "req_mixed", .stats_null = 1);
    ANS("answer_stats_null_on_error", .req = "garbage", .stats_null = 1);

    /* wrap_response: the boundaries of its four length fields. The basic response is
     * replaced by N pattern bytes; the big-nonce request makes the buffer large enough. */
    {
        long prev = -1;
        for (long N = 0; N <= 66000; N++) {
            size_t oct = 1 + lsz((size_t)N) + (size_t)N, sq = 11 + oct;
            size_t rb = 1 + lsz(sq) + sq, a0 = 1 + lsz(rb) + rb, ct = 3 + a0;
            long sig = (long)(lsz((size_t)N) * 1000 + lsz(sq) * 100 + lsz(rb) * 10 + lsz(ct));
            if (N == 0 || sig != prev) {
                long pts[2] = { N - 1, N };
                for (int k = 0; k < 2; k++) {
                    if (pts[k] < 0 || (k == 0 && N == 0)) continue;
                    snprintf(cn, sizeof cn, "wrap_basic_%ld", pts[k]);
                    ANS(strdup(cn), .req = "req_nonce_ext_65536", .synth = pts[k]);
                }
            }
            prev = sig;
        }
    }
    fclose(tsv);
    return 0;
}
