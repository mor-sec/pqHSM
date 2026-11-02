/* Golden generator for Phase 2 slice 3: the LEGACY C token store (src/fhsm_token.c).
 *
 *   gen_store make OUTDIR SCRIPT STUB
 *
 * Runs every scenario of SCRIPT (store_scenarios.txt) against the legacy C code and writes:
 *   OUTDIR/steps.tsv          scenario, step, op line, output (format: common/scenario.rs)
 *   OUTDIR/in/NAME.bin        crafted blob plaintexts the scenarios and store.rs read
 *   OUTDIR/pt/SCEN.STEP.bin   decrypted blob plaintext at each `snap role=...`
 *   OUTDIR/pub/SCEN.STEP.bin  the bytes after the encrypted blob at each `snap`
 *   OUTDIR/tok/SCEN.tok(.tpm) each scenario's final token file (starts for from=tok:...)
 *   OUTDIR/kat.tsv            fhsm_pbkdf2 / fhsm_aes_gcm_* on fixed vectors (tests/crypto.rs)
 *   OUTDIR/ffi.tsv            the C ABI with NULL and out-of-range arguments (tests/token_ffi.rs)
 *
 * Linked with -Wl,--wrap=fhsm_rng_bytes: the DRBG is replaced by a counter stream seeded from
 * the scenario name, so every file is byte-identical from run to run. Each scenario runs in a
 * forked child, so C's process state (the ERROR latch after a failed audit, the cached TPM
 * probe) never leaks into the next one. The inspection helpers (snap, reblob) use libcrypto
 * directly, never fhsm_crypto, so they work after C has latched ERROR.
 *
 * Every PIN is invented (gen_token.c's, plus NEW); none comes from the legacy tree.
 */
#include "fhsm_audit.h"
#include "fhsm_common.h"
#include "fhsm_crypto.h"
#include "fhsm_token.h"
#include "fhsm_token_tpm.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SO_PIN   "golden-so-pin-01"
#define USER_PIN "golden-user-pin-01"
#define WRONG    "golden-wrong-pin"
#define NEW_PIN  "golden-new-pin-02"
#define HDR 317u
#define BLOB_MAX 2148421644ull
#define PUB_MAGIC 0xF5B5B001u
#define V2M 0xF5B20002u
#define V3M 0xF5B30003u
#define V4M 0xF5B40004u

fhsm_rv_t __wrap_fhsm_rng_bytes(uint8_t *out, size_t n);

static const char *g_out, *g_stub;
static char g_scen[128];
static int g_step;
static FILE *g_steps;

static void die(const char *m) { fprintf(stderr, "gen_store: %s (%s)\n", m, strerror(errno)); exit(2); }

/* ------------------------------------------------------------------ deterministic DRBG */
static uint64_t g_rng;
static void rng_seed(const char *s) {
    uint64_t h = 1469598103934665603ull;
    for (; *s; s++) { h ^= (uint8_t)*s; h *= 1099511628211ull; }
    g_rng = h;
}
fhsm_rv_t __wrap_fhsm_rng_bytes(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint64_t z = (g_rng += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        out[i] = (uint8_t)(z ^ (z >> 31));
    }
    return FHSM_RV_OK;
}

/* ------------------------------------------------------------------ audit seam
 * fhsm_token.c's TPM sites (:1279, :1284, :1497, :1505, :1509, :1516) pass a key whose value is
 * FHSM_AUDIT_END, so fhsm_audit.c:620 reads one va_arg past the end: undefined, and it crashes
 * this generator. The wrap stops at the first NULL value and hands the real function an explicit
 * terminator after it -- the one defined outcome, where the stray slot is NULL:
 * {"tpm-seal-init":"INVALID"}. Well-formed calls pass through unchanged. */
fhsm_rv_t __real_fhsm_audit_event(fhsm_audit_event_t ev, int slot, int session, fhsm_role_t role, fhsm_rv_t rv, ...);
fhsm_rv_t __wrap_fhsm_audit_event(fhsm_audit_event_t ev, int slot, int session, fhsm_role_t role, fhsm_rv_t rv, ...);
fhsm_rv_t __wrap_fhsm_audit_event(fhsm_audit_event_t ev, int slot, int session, fhsm_role_t role, fhsm_rv_t rv, ...) {
    const char *kv[8] = { 0 };
    int n = 0;
    va_list ap;
    va_start(ap, rv);
    while (n < 8) {
        const char *k = va_arg(ap, const char *);
        if (!k) break;
        const char *v = va_arg(ap, const char *);
        kv[n++] = k; kv[n++] = v;
        if (!v) break;
    }
    va_end(ap);
    return __real_fhsm_audit_event(ev, slot, session, role, rv, kv[0], kv[1], kv[2], kv[3], kv[4], kv[5], kv[6], kv[7], FHSM_AUDIT_END);
}

/* ------------------------------------------------------------------ small helpers */
static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

typedef struct { char *s; size_t n, cap; } sbuf;
static void sb_add(sbuf *b, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    char tmp[512];
    int n = vsnprintf(tmp, sizeof tmp, fmt, ap);
    va_end(ap);
    if (n < 0) die("vsnprintf");
    if ((size_t)n >= sizeof tmp) { /* long: format again into the buffer */
        if (b->n + (size_t)n + 1 > b->cap) { b->cap = (b->n + (size_t)n + 1) * 2; b->s = realloc(b->s, b->cap); }
        va_start(ap, fmt); vsnprintf(b->s + b->n, (size_t)n + 1, fmt, ap); va_end(ap);
        b->n += (size_t)n; return;
    }
    if (b->n + (size_t)n + 1 > b->cap) { b->cap = (b->n + (size_t)n + 1) * 2 + 256; b->s = realloc(b->s, b->cap); if (!b->s) die("oom"); }
    memcpy(b->s + b->n, tmp, (size_t)n + 1);
    b->n += (size_t)n;
}
static void sb_hex(sbuf *b, const uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) sb_add(b, "%02x", p[i]); }

static uint8_t *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 4096, len = 0;
    uint8_t *b = malloc(cap);
    size_t r;
    while ((r = fread(b + len, 1, cap - len, f)) > 0) { len += r; if (len == cap) { cap *= 2; b = realloc(b, cap); } }
    fclose(f);
    *n = len;
    return b;
}
static void write_file(const char *path, const uint8_t *b, size_t n) {
    FILE *f = fopen(path, "wb");
    if (!f || (n && fwrite(b, 1, n, f) != n) || fclose(f) != 0) die(path);
}
static void copy_file(const char *from, const char *to) {
    size_t n; uint8_t *b = read_file(from, &n);
    if (!b) return;
    write_file(to, b, n);
    chmod(to, 0600);
    free(b);
}

/* ------------------------------------------------------------------ argument parsing */
#define MAXARG 16
static char *g_key[MAXARG], *g_val[MAXARG];
static int g_nargs;
static const char *arg(const char *k) {
    for (int i = 0; i < g_nargs; i++) if (!strcmp(g_key[i], k)) return g_val[i];
    return NULL;
}
static const char *need(const char *k) { const char *v = arg(k); if (!v) { fprintf(stderr, "%s step %d: no %s\n", g_scen, g_step, k); exit(2); } return v; }
static unsigned long long num(const char *s) { return strtoull(s, NULL, 0); }

typedef struct { uint8_t *p; size_t n; int null; } bytes_t;
static bytes_t bytes_of(const char *s) {
    bytes_t b = { NULL, 0, 0 };
    if (!strcmp(s, "-")) { b.null = 1; return b; }
    if (!strncmp(s, "hex:", 4)) {
        s += 4; b.n = strlen(s) / 2; b.p = calloc(b.n + 1, 1);
        for (size_t i = 0; i < b.n; i++) { unsigned v; sscanf(s + 2 * i, "%2x", &v); b.p[i] = (uint8_t)v; }
    } else if (!strncmp(s, "pat:", 4)) {
        char *e; unsigned long base = strtoul(s + 4, &e, 0); b.n = strtoul(e + 1, NULL, 0);
        b.p = calloc(b.n + 1, 1); for (size_t i = 0; i < b.n; i++) b.p[i] = (uint8_t)(base + i);
    } else if (!strncmp(s, "zero:", 5)) {
        b.n = strtoul(s + 5, NULL, 0); b.p = calloc(b.n + 1, 1);
    } else if (!strncmp(s, "rep:", 4)) {
        char c = s[4]; b.n = strtoul(s + 6, NULL, 0); b.p = calloc(b.n + 1, 1); memset(b.p, c, b.n);
    } else if (!strncmp(s, "txt:", 4)) {
        b.n = strlen(s + 4); b.p = (uint8_t *)strdup(s + 4);
    } else {
        b.n = strlen(s); b.p = (uint8_t *)strdup(s);
    }
    return b;
}
static bytes_t pin_of(const char *s) {
    const char *v = !strcmp(s, "SO") ? SO_PIN : !strcmp(s, "USER") ? USER_PIN
                  : !strcmp(s, "WRONG") ? WRONG : !strcmp(s, "NEW") ? NEW_PIN : NULL;
    if (v) { bytes_t b = { (uint8_t *)strdup(v), strlen(v), 0 }; return b; }
    if (!strncmp(s, "lit:", 4)) { bytes_t b = { (uint8_t *)strdup(s + 4), strlen(s + 4), 0 }; return b; }
    return bytes_of(s);
}
static int role_of(const char *s) { return !strcmp(s, "so") ? FHSM_ROLE_SO : !strcmp(s, "user") ? FHSM_ROLE_USER : FHSM_ROLE_NONE; }

/* ------------------------------------------------------------------ libcrypto (inspection only) */
static int x_pbkdf2(const uint8_t *pw, size_t pwn, const uint8_t *salt, uint32_t iter, uint8_t out[32]) {
    if (iter == 0) return 0;
    return PKCS5_PBKDF2_HMAC((const char *)pw, (int)pwn, salt, 16, (int)iter, EVP_sha256(), 32, out) == 1;
}
static int x_gcm(int enc, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aadn,
                 const uint8_t *in, size_t n, uint8_t *out, uint8_t tag[16]) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    int ok = 0, l = 0;
    if (enc ? EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, nonce) != 1
            : EVP_DecryptInit_ex(c, EVP_aes_256_gcm(), NULL, key, nonce) != 1) goto out;
    if (aadn && (enc ? EVP_EncryptUpdate(c, NULL, &l, aad, (int)aadn) : EVP_DecryptUpdate(c, NULL, &l, aad, (int)aadn)) != 1) goto out;
    if (n && (enc ? EVP_EncryptUpdate(c, out, &l, in, (int)n) : EVP_DecryptUpdate(c, out, &l, in, (int)n)) != 1) goto out;
    if (enc) {
        if (EVP_EncryptFinal_ex(c, out + n, &l) != 1) goto out;
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) goto out;
    } else {
        if (EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) goto out;
        if (EVP_DecryptFinal_ex(c, out + n, &l) != 1) goto out;
    }
    ok = 1;
out:
    EVP_CIPHER_CTX_free(c);
    return ok;
}
/* The DEK as `role`'s PIN unwraps it from a token file header. */
static int unwrap_dek(const uint8_t *h, int role, bytes_t pin, uint8_t dek[32]) {
    uint8_t kek[32];
    const uint8_t *salt = h + (role == FHSM_ROLE_SO ? 140 : 216);
    const uint8_t *nonce = h + (role == FHSM_ROLE_SO ? 156 : 232);
    const uint8_t *ct = h + (role == FHSM_ROLE_SO ? 168 : 244);
    if (!x_pbkdf2(pin.p, pin.n, salt, get32(h + 136), kek)) return 0;
    uint8_t tag[16]; memcpy(tag, ct + 32, 16);
    return x_gcm(0, kek, nonce, h + 72, strnlen((const char *)h + 72, 64), ct, 32, dek, tag);
}

/* ------------------------------------------------------------------ crafted plaintexts (in/) */
typedef struct {
    uint32_t handle, cls, kt; const char *label; const uint8_t *value; uint32_t vlen;
    uint8_t id[32]; uint32_t idlen; uint8_t flags, usage, flags2, flags3;
    uint8_t start[8], start_len, end[8], end_len; const char *app; uint8_t app_len;
    uint8_t allowed_count; uint32_t allowed[8];
    uint8_t tcount[3]; uint8_t tent[3][4][56];
} obj_t;

static size_t rec_v1(uint8_t *p, const obj_t *o) {
    memset(p, 0, 5620);
    put32(p, o->handle); put32(p + 4, o->cls); put32(p + 8, o->kt); put32(p + 12, o->vlen);
    if (o->label) memcpy(p + 16, o->label, strlen(o->label));
    memcpy(p + 80, o->value, o->vlen < 5500 ? o->vlen : 5500);
    memcpy(p + 5580, o->id, 32); put32(p + 5612, o->idlen); p[5616] = o->flags;
    return 5620;
}
/* v2/v3/v4 record: rec_len, the fixed part of `fixed` bytes, then the value. */
static size_t rec_v(uint8_t *p, const obj_t *o, uint32_t fixed) {
    memset(p, 0, 4 + fixed);
    put32(p, fixed + o->vlen);
    uint8_t *r = p + 4;
    put32(r, o->handle); put32(r + 4, o->cls); put32(r + 8, o->kt); put32(r + 12, o->vlen);
    if (o->label) memcpy(r + 16, o->label, strlen(o->label));
    memcpy(r + 80, o->id, 32); put32(r + 112, o->idlen);
    r[116] = o->flags; r[117] = o->usage; r[118] = o->flags3;
    if (fixed >= 204) {
        memcpy(r + 120, o->start, 8); r[128] = o->start_len;
        memcpy(r + 129, o->end, 8); r[137] = o->end_len;
        if (o->app) memcpy(r + 138, o->app, strlen(o->app));
        r[202] = o->app_len; r[203] = o->flags2;
    }
    if (fixed >= 912) {
        uint8_t *q = r + 204;
        q[0] = o->allowed_count;
        for (int k = 0; k < 8; k++) put32(q + 1 + 4 * k, o->allowed[k]);
        for (int t = 0; t < 3; t++) {
            uint8_t *e = q + 33 + t * 225;
            e[0] = o->tcount[t];
            memcpy(e + 1, o->tent[t], 4 * 56);
        }
    }
    memcpy(r + fixed, o->value, o->vlen);
    return 4 + fixed + o->vlen;
}
static uint8_t g_pat[256];
static void ent(obj_t *o, int t, int k, uint32_t type, uint8_t kind, uint8_t len, const char *val48) {
    uint8_t *e = o->tent[t][k];
    put32(e, type); e[4] = kind; e[5] = len;
    memcpy(e + 8, val48, strlen(val48) < 48 ? strlen(val48) : 48);
}
static obj_t o_secret(void) {
    obj_t o; memset(&o, 0, sizeof o);
    o.handle = 1; o.cls = 4; o.kt = 0x1f; o.label = "blob-secret"; o.value = g_pat + 16; o.vlen = 32;
    o.id[0] = 0x1d; o.id[1] = 0x10; o.idlen = 2; o.flags = 0x01; o.usage = 0x85; o.flags3 = 0x01;
    return o;
}
static obj_t o_public(void) {
    obj_t o; memset(&o, 0, sizeof o);
    o.handle = 2; o.cls = 2; o.kt = 3; o.label = "blob-public"; o.value = g_pat + 4; o.vlen = 65;
    o.id[0] = 0x1d; o.id[1] = 0x04; o.idlen = 2;
    return o;
}
static obj_t o_meta(void) {
    obj_t o = o_secret();
    memcpy(o.start, "20260101", 8); o.start_len = 8;
    memcpy(o.end, "20271231", 8); o.end_len = 0;            /* bytes present, length 0 */
    o.app = "golden-app"; o.app_len = 10; o.flags2 = 0x87;
    return o;
}
static obj_t o_policy(void) {
    obj_t o = o_meta();
    o.allowed_count = 2; o.allowed[0] = 0x1081; o.allowed[1] = 0x1082;
    for (int k = 2; k < 8; k++) o.allowed[k] = 0xEE00u + (uint32_t)k;  /* junk past the count */
    o.flags2 = 0x08 | 0x10 | 0x40 | 0x03;
    o.tcount[0] = 1; ent(&o, 0, 0, 3, 3, 5, "labelJUNK-past-len");
    ent(&o, 0, 1, 0x999, 1, 1, "x");                                 /* slot past the count */
    o.tcount[1] = 0;
    o.tcount[2] = 2; ent(&o, 2, 0, 0x162, 1, 1, "\x01"); ent(&o, 2, 1, 0x100, 2, 8, "\x1f");
    return o;
}

static uint8_t *g_buf;
static size_t blob_hdr(uint8_t *p, uint32_t magic, uint32_t count, uint32_t next) {
    if (magic) { put32(p, magic); put32(p + 4, count); put32(p + 8, next); return 12; }
    put32(p, count); put32(p + 4, next); return 8;
}
static void save_in(const char *name, const uint8_t *b, size_t n) {
    char p[1024]; snprintf(p, sizeof p, "%s/in/%s.bin", g_out, name);
    write_file(p, b, n);
}
/* A v2/v3/v4 blob of `n` objects. Returns the length; *rec_off gets the first record's offset. */
static size_t blob_v(uint32_t magic, uint32_t fixed, const obj_t *os, int n, uint32_t next) {
    size_t off = blob_hdr(g_buf, magic, (uint32_t)n, next);
    for (int i = 0; i < n; i++) off += rec_v(g_buf + off, &os[i], fixed);
    return off;
}

static void make_inputs(void) {
    char p[1024];
    snprintf(p, sizeof p, "%s/in", g_out); mkdir(p, 0755);
    for (int i = 0; i < 256; i++) g_pat[i] = (uint8_t)i;
    g_buf = calloc(1, 1 << 21);
    size_t n;
    obj_t two[2] = { o_secret(), o_public() };

    /* v1 */
    n = blob_hdr(g_buf, 0, 2, 3); n += rec_v1(g_buf + n, &two[0]); n += rec_v1(g_buf + n, &two[1]);
    save_in("v1_ok", g_buf, n);
    put32(g_buf + 8 + 12, 5501); save_in("v1_value_len_5501", g_buf, n); put32(g_buf + 8 + 12, 32);
    put32(g_buf + 8 + 5612, 33); save_in("v1_id_len_33", g_buf, n); put32(g_buf + 8 + 5612, 2);
    blob_hdr(g_buf, 0, 1, 2); save_in("v1_short", g_buf, 8 + 5619);
    blob_hdr(g_buf, 0, 0, 1); save_in("v1_empty", g_buf, 8);
    blob_hdr(g_buf, 0, 1025, 1); save_in("v1_count_1025", g_buf, 8);

    /* v2 */
    n = blob_v(V2M, 120, two, 2, 3); save_in("v2_ok", g_buf, n);
    { size_t r2 = 12 + 4 + 120 + 32;                       /* second record's rec_len */
      save_in("v2_missing_record", g_buf, r2);
      put32(g_buf + 12, 119); save_in("v2_rec_len_119", g_buf, n);
      put32(g_buf + 12, 120 + 2097152 + 1); save_in("v2_rec_len_over_max", g_buf, n);
      put32(g_buf + 12, 120 + 32);
      put32(g_buf + r2, 120 + 65 + 1); save_in("v2_rec_overrun", g_buf, n); put32(g_buf + r2, 120 + 65);
      put32(g_buf + 16 + 12, 33); save_in("v2_value_len_mismatch", g_buf, n); put32(g_buf + 16 + 12, 32);
      put32(g_buf + 16 + 112, 33); save_in("v2_id_len_33", g_buf, n); put32(g_buf + 16 + 112, 2); }
    blob_hdr(g_buf, V2M, 1025, 1); save_in("v2_count_1025", g_buf, 12);

    /* v3 */
    { obj_t m[2] = { o_meta(), o_public() };
      n = blob_v(V3M, 204, m, 2, 3); save_in("v3_ok", g_buf, n);
      g_buf[16 + 128] = 9; save_in("v3_start_len_9", g_buf, n); g_buf[16 + 128] = 8;
      g_buf[16 + 137] = 9; save_in("v3_end_len_9", g_buf, n); g_buf[16 + 137] = 0;
      g_buf[16 + 202] = 65; save_in("v3_app_len_65", g_buf, n); g_buf[16 + 202] = 10; }

    /* v4 */
    { obj_t m[2] = { o_policy(), o_public() };
      n = blob_v(V4M, 912, m, 2, 9); save_in("v4_ok", g_buf, n);
      memcpy(g_buf + n, "\xde\xad\xbe\xef\x00", 5); save_in("v4_trailing_bytes", g_buf, n + 5);
      uint8_t *q = g_buf + 16 + 204;
      q[0] = 9; save_in("v4_allowed_9", g_buf, n); q[0] = 2;
      q[33] = 5; save_in("v4_wrap_count_5", g_buf, n); q[33] = 1;
      q[33 + 225] = 1; q[33 + 225 + 1 + 5] = 49; q[33 + 225 + 1 + 4] = 3;
      save_in("v4_unwrap_entry_len_49", g_buf, n);
      q[33 + 225] = 0; q[33 + 225 + 1 + 5] = 0; q[33 + 225 + 1 + 4] = 0;
      q[33 + 450 + 1 + 4] = 0; save_in("v4_derive_kind_0", g_buf, n); q[33 + 450 + 1 + 4] = 1;
      q[33 + 1 + 4] = 4; save_in("v4_wrap_kind_4", g_buf, n); q[33 + 1 + 4] = 3;
      put32(g_buf + 12, 911); save_in("v4_rec_len_911", g_buf, n); }
    memcpy(g_buf, "\x04\x00\xb4\xf5\x00\x00\x00", 7); save_in("blob_7_bytes", g_buf, 7);
    put32(g_buf, V4M); memset(g_buf + 4, 0, 6); save_in("v4_magic_10_bytes", g_buf, 10);
    put32(g_buf, 0xDEADBEEFu); put32(g_buf + 4, 0); save_in("unknown_magic", g_buf, 8);

    /* handles and capacity */
    { obj_t o; memset(&o, 0, sizeof o); o.handle = 1; o.label = "one";
      n = blob_v(V4M, 912, &o, 1, 0xFFFFFFFFu); save_in("v4_next_handle_max", g_buf, n); }
    { static obj_t many[1023]; static char labels[1023][8];
      for (int i = 0; i < 1023; i++) {
          memset(&many[i], 0, sizeof many[i]); many[i].handle = (uint32_t)i + 1;
          snprintf(labels[i], sizeof labels[i], "o%d", i + 1); many[i].label = labels[i];
      }
      n = blob_v(V4M, 912, many, 1023, 1024); save_in("v4_1023_objects", g_buf, n); }

    /* public sections */
    { obj_t o = o_secret(); o.handle = 77; n = blob_v(V4M, 912, &o, 1, 78); save_in("v4_secret_key", g_buf, n); }
    { obj_t o = o_public(); o.handle = 77; o.flags = 0x01; n = blob_v(V4M, 912, &o, 1, 78); save_in("v4_sensitive_public_key", g_buf, n); }
    { obj_t o = o_public(); o.handle = 77; o.flags = 0x40; o.label = "planted";
      n = blob_v(V4M, 912, &o, 1, 78); save_in("v4_planted_trusted", g_buf, n); }
    n = blob_hdr(g_buf, V4M, 0, 1); save_in("v4_empty", g_buf, n);
}

/* ------------------------------------------------------------------ one scenario (child) */
static fhsm_token_t *g_tok[2];
static char g_dir[1024], g_tokdir[1100], g_ctl[1100], g_path[1200];
static uint8_t g_ref[HDR]; static uint8_t *g_refblob; static size_t g_refblob_n; static int g_nosave;
static int g_fifo_rd = -1; static char g_audit_path[1300]; static long g_audit_off;
static const uint8_t AUDIT_KEY[32] = { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                                       0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42 };

static void set_ctl(const char *name, const char *text) {
    char p[1400]; snprintf(p, sizeof p, "%s/%s", g_ctl, name);
    write_file(p, (const uint8_t *)text, strlen(text));
}

/* One C audit line -> event/ROLE/rv/params. */
static void audit_line(sbuf *o, const char *l) {
    const char *e = strstr(l, "\"event\":\""), *r = strstr(l, "\"role\":\""), *v = strstr(l, "\"rv\":"),
               *pa = strstr(l, "\"params\":"), *pe = strstr(l, ",\"prev_hmac\"");
    if (!e || !r || !v || !pa || !pe) { sb_add(o, "\taudit=?"); return; }
    e += 9; r += 8; v += 5; pa += 9;
    sb_add(o, "\taudit=%.*s/%.*s/%.*s/%.*s", (int)(strchr(e, '"') - e), e, (int)(strchr(r, '"') - r), r,
           (int)(strcspn(v, ",")), v, (int)(pe - pa), pa);
}
static void audit_collect(sbuf *o) {
    char buf[1 << 16]; size_t n = 0;
    if (g_fifo_rd >= 0) {
        ssize_t r;
        while ((r = read(g_fifo_rd, buf + n, sizeof buf - 1 - n)) > 0) n += (size_t)r;
    } else if (g_audit_path[0]) {
        FILE *f = fopen(g_audit_path, "rb");
        if (!f) return;
        fseek(f, g_audit_off, SEEK_SET);
        n = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        g_audit_off += (long)n;
    }
    buf[n] = 0;
    for (char *l = buf, *nl; *l; l = nl + 1) {
        nl = strchr(l, '\n');
        if (!nl) break;
        *nl = 0;
        audit_line(o, l);
    }
}
static void audit_open_file(void) {
    char base[1300]; snprintf(base, sizeof base, "%s/audit", g_ctl);
    if (fhsm_audit_open(base, FHSM_SLICE(AUDIT_KEY, 32)) != FHSM_RV_OK) die("audit open");
    fhsm_audit_current_path(g_audit_path, sizeof g_audit_path);
    g_audit_off = 0;
}
static void audit_open_fifo(void) {
    char fifo[1300]; snprintf(fifo, sizeof fifo, "%s/audit.fifo", g_ctl);
    fhsm_audit_close();
    g_audit_path[0] = 0;
    if (mkfifo(fifo, 0600) != 0) die("mkfifo");
    g_fifo_rd = open(fifo, O_RDONLY | O_NONBLOCK);
    if (g_fifo_rd < 0) die("fifo read end");
    if (fhsm_audit_open(fifo, FHSM_SLICE(AUDIT_KEY, 32)) != FHSM_RV_OK) die("audit open fifo");
}

static const char *prov(const uint8_t *now, const uint8_t *ref, size_t n) {
    size_t z = 0; for (size_t i = 0; i < n; i++) z |= now[i];
    if (!z) return "zero";
    return memcmp(now, ref, n) ? "new" : "same";
}
static int serial_ok(const uint8_t *s) {
    if (memcmp(s, "FHSM-", 5)) return 0;
    for (int i = 5; i < 21; i++) if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f'))) return 0;
    for (int i = 21; i < 64; i++) if (s[i]) return 0;
    return 1;
}
static void set_ref_from_file(void) {
    size_t n; uint8_t *f = read_file(g_path, &n);
    memset(g_ref, 0, HDR); free(g_refblob); g_refblob = NULL; g_refblob_n = 0;
    if (!f) return;
    memcpy(g_ref, f, n < HDR ? n : HDR);
    if (n > HDR + 4) {
        uint32_t ct = get32(f + HDR);
        if ((uint64_t)HDR + 16 + ct + 16 <= n) { g_refblob_n = 12 + (size_t)ct + 16; g_refblob = malloc(g_refblob_n); memcpy(g_refblob, f + HDR + 4, g_refblob_n); }
    }
    free(f);
}

static void snap(sbuf *o) {
    size_t n; uint8_t *f = read_file(g_path, &n);
    if (!f) { sb_add(o, "\tsize=absent"); return; }
    sb_add(o, "\tsize=%zu", n);
    if (n < HDR) { free(f); return; }
    sb_add(o, "\tmagic="); sb_hex(o, f, 4);
    sb_add(o, "\tver=%u\tlabel=", get32(f + 4)); sb_hex(o, f + 8, strnlen((const char *)f + 8, 64));
    sb_add(o, "\tserial=%s\tserial_fmt=%s\titer=%u", prov(f + 72, g_ref + 72, 64), serial_ok(f + 72) ? "ok" : "bad", get32(f + 136));
    sb_add(o, "\tsalt_so=%s\tso_nonce=%s\tso_ct=%s", prov(f + 140, g_ref + 140, 16), prov(f + 156, g_ref + 156, 12), prov(f + 168, g_ref + 168, 48));
    sb_add(o, "\tsalt_user=%s\tuser_nonce=%s\tuser_ct=%s", prov(f + 216, g_ref + 216, 16), prov(f + 232, g_ref + 232, 12), prov(f + 244, g_ref + 244, 48));
    sb_add(o, "\tuinit=%u\tfso=%u\tfuser=%u\tthr=", f[292], get32(f + 293), get32(f + 297)); sb_hex(o, f + 301, 16);
    sb_add(o, "\tsalts_differ=%d", memcmp(f + 140, f + 216, 16) != 0);
    const uint8_t *blob = NULL; uint32_t ct = 0; size_t end = n;
    if (n == HDR) sb_add(o, "\tblob=none");
    else if (n < HDR + 16) sb_add(o, "\tblob=bad");
    else {
        ct = get32(f + HDR);
        if (ct == 0 || ct > BLOB_MAX || (uint64_t)HDR + 16 + ct + 16 > n) { sb_add(o, "\tblob=bad\tctlen=%u", ct); ct = 0; }
        else {
            blob = f + HDR + 4;
            int same = g_refblob && g_refblob_n == 12 + (size_t)ct + 16 && !memcmp(blob, g_refblob, g_refblob_n);
            sb_add(o, "\tblob=%s\tctlen=%u\tnonce=%s", same ? "same" : "new", ct, g_refblob ? prov(blob, g_refblob, 12) : "new");
            end = HDR + 16 + (size_t)ct + 16;
        }
    }
    if (blob && end < n) {
        char p[1400]; snprintf(p, sizeof p, "%s/pub/%s.%d.bin", g_out, g_scen, g_step);
        write_file(p, f + end, n - end);
        sb_add(o, "\tpub=file:%zu", n - end);
    } else if (blob) sb_add(o, "\tpub=none");
    const char *rs = arg("role");
    if (rs) {
        bytes_t pin = pin_of(need("pin"));
        uint8_t dek[32];
        if (!unwrap_dek(f, role_of(rs), pin, dek)) sb_add(o, "\tpt=nodek");
        else if (!blob) sb_add(o, "\tpt=none");
        else {
            uint8_t *pt = malloc((size_t)ct + 16), tag[16];
            memcpy(tag, blob + 12 + ct, 16);
            static const uint8_t zero[32];
            const char *how = x_gcm(0, dek, blob, f + 72, strnlen((const char *)f + 72, 64), blob + 12, ct, pt, tag) ? "ok"
                            : x_gcm(0, zero, blob, f + 72, strnlen((const char *)f + 72, 64), blob + 12, ct, pt, tag) ? "zero" : NULL;
            if (!how) sb_add(o, "\tpt=fail");
            else {
                char p[1400]; snprintf(p, sizeof p, "%s/pt/%s.%d.bin", g_out, g_scen, g_step);
                write_file(p, pt, ct);
                sb_add(o, "\tpt=%s:%u", how, ct);
            }
            free(pt);
        }
        free(pin.p);
    }
    free(f);
    set_ref_from_file();
}

static void files(sbuf *o) {
    DIR *d = opendir(g_tokdir);
    char names[64][256]; int k = 0;
    struct dirent *e;
    while (d && (e = readdir(d)) && k < 64) if (e->d_name[0] != '.') snprintf(names[k++], 256, "%s", e->d_name);
    if (d) closedir(d);
    qsort(names, (size_t)k, sizeof names[0], (int (*)(const void *, const void *))strcmp);
    sb_add(o, "\tfiles=");
    for (int i = 0; i < k; i++) {
        char p[1400]; struct stat st;
        snprintf(p, sizeof p, "%s/%s", g_tokdir, names[i]);
        lstat(p, &st);
        sb_add(o, "%s%s%s:%o", i ? "," : "", names[i], S_ISDIR(st.st_mode) ? "/" : "", (unsigned)(st.st_mode & 0777));
    }
}

static void dump(sbuf *o, fhsm_token_t *t) {
    static uint32_t hs[2048]; size_t cnt = 0;
    fhsm_rv_t rv = fhsm_token_object_find(t, NULL, NULL, hs, 2048, &cnt);
    sb_add(o, "\trv=0x%x\tn=%zu", (unsigned)rv, cnt);
    for (size_t i = 0; rv == FHSM_RV_OK && i < cnt && i < 2048; i++) {
        uint32_t h = hs[i], c = 0, k = 0; const uint8_t *v = NULL; size_t vl = 0;
        uint8_t f1 = 0, f2 = 0, f3 = 0, us = 0, ca = 0, cw = 0, cu = 0, cd = 0; int tk = 0;
        const char *lab = NULL; const uint8_t *id = NULL, *m = NULL; size_t ll = 0, il = 0, ml = 0;
        fhsm_token_object_get(t, h, &v, &vl, &c, &k);
        fhsm_token_object_get_flags(t, h, &f1); fhsm_token_object_get_flags2(t, h, &f2);
        fhsm_token_object_get_flags3(t, h, &f3); fhsm_token_object_get_usage(t, h, &us);
        fhsm_token_object_is_token(t, h, &tk);
        sb_add(o, "\n\tobj h=%u class=%u kt=%u flags=0x%02x flags2=0x%02x flags3=0x%02x usage=0x%02x tok=%d label=", h, c, k, f1, f2, f3, us, tk);
        if (fhsm_token_object_get_label(t, h, &lab, &ll) == FHSM_RV_OK) sb_hex(o, (const uint8_t *)lab, ll);
        sb_add(o, " id="); if (fhsm_token_object_get_id(t, h, &id, &il) == FHSM_RV_OK) sb_hex(o, id, il);
        sb_add(o, " value="); sb_hex(o, v, vl);
        static const char *const mn[3] = { " start=", " end=", " app=" };
        for (int w = 0; w < 3; w++) {
            sb_add(o, "%s", mn[w]);
            if (fhsm_token_object_get_meta(t, h, (fhsm_obj_meta_t)w, &m, &ml) == FHSM_RV_OK) sb_hex(o, m, ml);
        }
        fhsm_token_object_get_policy_counts(t, h, &ca, &cw, &cu, &cd);
        sb_add(o, " counts=%u,%u,%u,%u mechs=", ca, cw, cu, cd);
        uint32_t mech[8]; uint8_t io = 8;
        if (fhsm_token_object_get_allowed_mechs(t, h, mech, &io) == FHSM_RV_OK)
            for (uint8_t j = 0; j < io; j++) sb_add(o, "%s0x%x", j ? "," : "", mech[j]);
        static const char *const tn[3] = { " wrap=", " unwrap=", " derive=" };
        for (int w = 0; w < 3; w++) {
            fhsm_policy_attr_t a[4]; uint8_t ic = 4;
            sb_add(o, "%s", tn[w]);
            if (fhsm_token_object_get_tmpl(t, h, (fhsm_tmpl_which_t)w, a, &ic) == FHSM_RV_OK)
                for (uint8_t j = 0; j < ic; j++) { sb_add(o, "%s0x%x:%u:%u:", j ? "," : "", a[j].type, a[j].kind, a[j].len); sb_hex(o, a[j].value, 48); }
        }
    }
}

static void tmpl_parse(const char *s, fhsm_policy_attr_t *a, uint8_t *count) {
    *count = 0;
    if (!strcmp(s, "empty")) return;
    char *dup = strdup(s), *save = NULL;
    for (char *e = strtok_r(dup, ",", &save); e; e = strtok_r(NULL, ",", &save)) {
        fhsm_policy_attr_t *x = &a[(*count)++];
        memset(x, 0, sizeof *x);
        char *f1 = strtok(e, ":"), *f2 = strtok(NULL, ":"), *f3 = strtok(NULL, ":"), *f4 = strtok(NULL, ":");
        x->type = (uint32_t)num(f1); x->kind = (uint8_t)num(f2); x->len = (uint8_t)num(f3);
        if (f4) { size_t L = strlen(f4) / 2; for (size_t i = 0; i < L && i < 48; i++) { unsigned b; sscanf(f4 + 2 * i, "%2x", &b); x->value[i] = (uint8_t)b; } }
    }
    free(dup);
}

/* Truncate/extend helpers for file surgery. */
static size_t blob_end(const uint8_t *f, size_t n) {
    if (n < HDR + 4) return n;
    return HDR + 16 + get32(f + HDR) + 16;
}

/* Remaining throttle, rounded up to the next rung of C's ladder 500 * 2^(n-1) capped at 60000,
 * so the time a step takes never shows. */
static uint64_t ladder(uint64_t ms) {
    if (!ms) return 0;
    uint64_t d = 500;
    while (d < ms && d < 60000) d = d * 2 > 60000 ? 60000 : d * 2;
    return d;
}

static void run_op(sbuf *o, char *op) {
    int ti = (arg("t") && !strcmp(arg("t"), "B")) ? 1 : 0;
    fhsm_token_t *t = g_tok[ti];
    const char *h_s = arg("h");
    uint32_t h = h_s ? (uint32_t)num(h_s) : 0;
#define TOKEN_OP if (!t) { sb_add(o, "\tnotoken"); return; }
#define RV(x) do { fhsm_rv_t r_ = (x); sb_add(o, "\trv=0x%x", (unsigned)r_); if (r_ != FHSM_RV_OK) return; } while (0)
#define RV_ONLY(x) sb_add(o, "\trv=0x%x", (unsigned)(x))
    if (!strcmp(op, "init")) {
        if (g_tok[ti]) { fhsm_token_close(g_tok[ti]); g_tok[ti] = NULL; }
        bytes_t so = pin_of(need("so")), lb = bytes_of(need("label"));
        RV_ONLY(fhsm_token_init(g_path, (const char *)so.p, lb.null ? NULL : (const char *)lb.p, &g_tok[ti]));
        free(so.p); free(lb.p);
    } else if (!strcmp(op, "load")) {
        if (g_tok[ti]) { fhsm_token_close(g_tok[ti]); g_tok[ti] = NULL; }
        RV_ONLY(fhsm_token_load(g_path, &g_tok[ti]));
    } else if (!strcmp(op, "close")) {
        TOKEN_OP; fhsm_token_close(t); g_tok[ti] = NULL; sb_add(o, "\t-");
    } else if (!strcmp(op, "login") || !strcmp(op, "verify")) {
        TOKEN_OP;
        bytes_t pin = pin_of(need("pin"));
        int role = role_of(need("role"));
        RV_ONLY(op[0] == 'l' ? fhsm_token_login(t, role, (const char *)pin.p, pin.n)
                             : fhsm_token_verify_pin(t, role, (const char *)pin.p, pin.n));
        free(pin.p);
    } else if (!strcmp(op, "logout")) {
        TOKEN_OP; fhsm_token_logout(t); sb_add(o, "\t-");
    } else if (!strcmp(op, "role")) {
        TOKEN_OP; sb_add(o, "\trole=%d", (int)fhsm_token_current_role(t));
    } else if (!strcmp(op, "set_pin")) {
        TOKEN_OP;
        bytes_t a = pin_of(need("old")), b = pin_of(need("new"));
        RV_ONLY(fhsm_token_set_pin(t, role_of(need("role")), (const char *)a.p, (const char *)b.p));
        free(a.p); free(b.p);
    } else if (!strcmp(op, "init_user_pin")) {
        TOKEN_OP; bytes_t a = pin_of(need("pin"));
        RV_ONLY(fhsm_token_init_user_pin(t, (const char *)a.p)); free(a.p);
    } else if (!strcmp(op, "reinit")) {
        TOKEN_OP; bytes_t a = pin_of(need("so")), b = bytes_of(need("label"));
        RV_ONLY(fhsm_token_reinit(t, (const char *)a.p, (const char *)b.p)); free(a.p); free(b.p);
    } else if (!strcmp(op, "info")) {
        TOKEN_OP;
        /* The serial is random: print its shape. A 64-byte label has no NUL and strlen runs
         * on into the serial (candidate defect): print 64 bytes and say what followed. */
        const char *l = fhsm_token_label(t), *sr = fhsm_token_serial(t);
        size_t ll = strlen(l);
        sb_add(o, "\tlabel="); sb_hex(o, (const uint8_t *)l, ll > 64 ? 64 : ll);
        if (ll > 64) {
            if (!strcmp(l + 64, sr)) sb_add(o, "+overrun:serial");
            else { sb_add(o, "+overrun:"); sb_hex(o, (const uint8_t *)l + 64, ll - 64); }
        }
        int sok = strlen(sr) == 21 && !strncmp(sr, "FHSM-", 5) && strspn(sr + 5, "0123456789abcdef") == 16;
        uint64_t a = fhsm_token_throttle_remaining_ms(t, FHSM_ROLE_SO), b = fhsm_token_throttle_remaining_ms(t, FHSM_ROLE_USER);
        sb_add(o, "\tserial=%s\tfso=%u\tfuser=%u\tuinit=%d\tlso=%d\tluser=%d\ttso=%llu\ttuser=%llu\trole=%d",
               sok ? "ok" : "bad", fhsm_token_failed_count(t, FHSM_ROLE_SO), fhsm_token_failed_count(t, FHSM_ROLE_USER),
               fhsm_token_user_initialized(t), fhsm_token_is_locked(t, FHSM_ROLE_SO), fhsm_token_is_locked(t, FHSM_ROLE_USER),
               (unsigned long long)ladder(a), (unsigned long long)ladder(b),
               (int)fhsm_token_current_role(t));
    } else if (!strcmp(op, "add")) {
        TOKEN_OP;
        bytes_t lb = bytes_of(need("label")), v = bytes_of(need("value")), id = bytes_of(need("id"));
        uint32_t out = 0;
        fhsm_rv_t r = fhsm_token_object_add(t, (uint32_t)num(need("class")), (uint32_t)num(need("kt")),
                                            lb.null ? NULL : (const char *)lb.p, v.p, v.n, id.p, id.n,
                                            (uint8_t)num(need("flags")), &out);
        sb_add(o, "\trv=0x%x", (unsigned)r);
        if (r == FHSM_RV_OK) sb_add(o, "\th=%u", out);
        free(lb.p); free(v.p); free(id.p);
    } else if (!strcmp(op, "get")) {
        TOKEN_OP; const uint8_t *v; size_t vl; uint32_t c, k;
        RV(fhsm_token_object_get(t, h, &v, &vl, &c, &k));
        sb_add(o, "\tclass=%u\tkt=%u\tvalue=", c, k); sb_hex(o, v, vl);
    } else if (!strcmp(op, "find")) {
        TOKEN_OP;
        static uint32_t hs[2048]; size_t cnt = 0;
        size_t cap = arg("cap") ? (size_t)num(arg("cap")) : 2048;
        uint32_t cls = arg("class") ? (uint32_t)num(arg("class")) : 0;
        bytes_t lb = arg("label") ? bytes_of(arg("label")) : (bytes_t){ NULL, 0, 1 };
        fhsm_rv_t r = fhsm_token_object_find(t, arg("class") ? &cls : NULL, lb.null ? NULL : (const char *)lb.p, hs, cap, &cnt);
        sb_add(o, "\trv=0x%x\tn=%zu\ths=", (unsigned)r, cnt);
        for (size_t i = 0; r == FHSM_RV_OK && i < cnt && i < cap; i++) sb_add(o, "%s%u", i ? "," : "", hs[i]);
        free(lb.p);
    } else if (!strcmp(op, "get_label")) {
        TOKEN_OP; const char *l; size_t n; RV(fhsm_token_object_get_label(t, h, &l, &n));
        sb_add(o, "\tv="); sb_hex(o, (const uint8_t *)l, n);
    } else if (!strcmp(op, "get_id")) {
        TOKEN_OP; const uint8_t *l; size_t n; RV(fhsm_token_object_get_id(t, h, &l, &n));
        sb_add(o, "\tv="); sb_hex(o, l, n);
    } else if (!strcmp(op, "get_meta")) {
        TOKEN_OP; const uint8_t *l; size_t n;
        RV(fhsm_token_object_get_meta(t, h, (fhsm_obj_meta_t)num(need("which")), &l, &n));
        sb_add(o, "\tv="); sb_hex(o, l, n);
    } else if (!strncmp(op, "get_flags", 9) || !strcmp(op, "get_usage")) {
        TOKEN_OP; uint8_t v = 0;
        RV(!strcmp(op, "get_flags") ? fhsm_token_object_get_flags(t, h, &v)
           : !strcmp(op, "get_flags2") ? fhsm_token_object_get_flags2(t, h, &v)
           : !strcmp(op, "get_flags3") ? fhsm_token_object_get_flags3(t, h, &v)
           : fhsm_token_object_get_usage(t, h, &v));
        sb_add(o, "\tv=0x%02x", v);
    } else if (!strcmp(op, "is_token")) {
        TOKEN_OP; int v = 0; RV(fhsm_token_object_is_token(t, h, &v)); sb_add(o, "\tv=%d", v);
    } else if (!strcmp(op, "policy")) {
        TOKEN_OP; uint8_t a = 0, b = 0, c = 0, d = 0;
        RV(fhsm_token_object_get_policy_counts(t, h, &a, &b, &c, &d)); sb_add(o, "\tcounts=%u,%u,%u,%u", a, b, c, d);
    } else if (!strcmp(op, "get_mechs")) {
        TOKEN_OP; uint32_t m[8]; uint8_t io = 8;
        RV(fhsm_token_object_get_allowed_mechs(t, h, m, &io));
        sb_add(o, "\tn=%u\tv=", io); for (uint8_t i = 0; i < io; i++) sb_add(o, "%s0x%x", i ? "," : "", m[i]);
    } else if (!strcmp(op, "get_tmpl")) {
        TOKEN_OP; fhsm_policy_attr_t a[4]; uint8_t io = 4;
        RV(fhsm_token_object_get_tmpl(t, h, (fhsm_tmpl_which_t)num(need("which")), a, &io));
        sb_add(o, "\tn=%u\tv=", io);
        for (uint8_t i = 0; i < io; i++) { sb_add(o, "%s0x%x:%u:%u:", i ? "," : "", a[i].type, a[i].kind, a[i].len); sb_hex(o, a[i].value, 48); }
    } else if (!strcmp(op, "mech_allowed")) {
        TOKEN_OP; RV_ONLY(fhsm_token_object_mech_allowed(t, h, (uint32_t)num(need("mech"))));
    } else if (!strcmp(op, "set_label")) {
        TOKEN_OP; bytes_t b = bytes_of(need("label")); RV_ONLY(fhsm_token_object_set_label(t, h, (const char *)b.p)); free(b.p);
    } else if (!strcmp(op, "set_id")) {
        TOKEN_OP; bytes_t b = bytes_of(need("id")); RV_ONLY(fhsm_token_object_set_id(t, h, b.p, b.n)); free(b.p);
    } else if (!strncmp(op, "set_flags", 9) || !strcmp(op, "set_usage")) {
        TOKEN_OP; uint8_t v = (uint8_t)num(need("v"));
        RV_ONLY(!strcmp(op, "set_flags") ? fhsm_token_object_set_flags(t, h, v)
                : !strcmp(op, "set_flags2") ? fhsm_token_object_set_flags2(t, h, v)
                : !strcmp(op, "set_flags3") ? fhsm_token_object_set_flags3(t, h, v)
                : fhsm_token_object_set_usage(t, h, v));
    } else if (!strcmp(op, "set_meta")) {
        TOKEN_OP; bytes_t s = bytes_of(need("start")), e = bytes_of(need("end")), a = bytes_of(need("app"));
        RV_ONLY(fhsm_token_object_set_meta(t, h, s.null ? NULL : s.p ? s.p : (const uint8_t *)"", s.n,
                                           e.null ? NULL : e.p ? e.p : (const uint8_t *)"", e.n,
                                           a.null ? NULL : a.p ? a.p : (const uint8_t *)"", a.n));
        free(s.p); free(e.p); free(a.p);
    } else if (!strcmp(op, "set_mechs")) {
        TOKEN_OP; uint32_t m[16]; uint8_t c = 0; const char *l = need("list");
        if (strcmp(l, "empty")) { char *d = strdup(l), *sv = NULL; for (char *x = strtok_r(d, ",", &sv); x; x = strtok_r(NULL, ",", &sv)) m[c++] = (uint32_t)num(x); free(d); }
        RV_ONLY(fhsm_token_object_set_allowed_mechs(t, h, m, c));
    } else if (!strcmp(op, "set_tmpl")) {
        TOKEN_OP; fhsm_policy_attr_t a[8]; uint8_t c;
        tmpl_parse(need("e"), a, &c);
        RV_ONLY(fhsm_token_object_set_tmpl(t, h, (fhsm_tmpl_which_t)num(need("which")), a, c));
    } else if (!strcmp(op, "mark_session")) {
        TOKEN_OP; RV_ONLY(fhsm_token_object_mark_session(t, h, (uint32_t)num(need("owner"))));
    } else if (!strcmp(op, "destroy")) {
        TOKEN_OP; RV_ONLY(fhsm_token_object_destroy(t, h));
    } else if (!strcmp(op, "destroy_session")) {
        TOKEN_OP; RV_ONLY(fhsm_token_destroy_session_objects(t, (uint32_t)num(need("owner"))));
    } else if (!strcmp(op, "dump")) {
        TOKEN_OP; dump(o, t);
    } else if (!strcmp(op, "snap")) {
        snap(o);
    } else if (!strcmp(op, "files")) {
        files(o);
    } else if (!strcmp(op, "poke")) {
        size_t n; uint8_t *f = read_file(g_path, &n); size_t off = (size_t)num(need("off"));
        if (arg("u32")) put32(f + off, (uint32_t)num(arg("u32")));
        else if (arg("u8")) f[off] = (uint8_t)num(arg("u8"));
        else { const char *hx = need("hex"); for (size_t i = 0; i < strlen(hx) / 2; i++) { unsigned v; sscanf(hx + 2 * i, "%2x", &v); f[off + i] = (uint8_t)v; } }
        write_file(g_path, f, n); free(f); sb_add(o, "\t-");
    } else if (!strcmp(op, "truncate")) {
        if (truncate(g_path, (off_t)num(need("len"))) != 0) die("truncate");
        sb_add(o, "\t-");
    } else if (!strcmp(op, "append")) {
        size_t n; uint8_t *f = read_file(g_path, &n); bytes_t b = bytes_of(need("b"));
        f = realloc(f, n + b.n); memcpy(f + n, b.p, b.n); write_file(g_path, f, n + b.n); free(f); free(b.p); sb_add(o, "\t-");
    } else if (!strcmp(op, "pubsec")) {
        size_t n; uint8_t *f = read_file(g_path, &n); size_t end = blob_end(f, n);
        f = realloc(f, end + (1 << 21));
        if (arg("drop")) n = end;
        else if (arg("set")) {
            char p[1400]; size_t m; snprintf(p, sizeof p, "%s/in/%s.bin", g_out, arg("set"));
            uint8_t *b = read_file(p, &m); if (!b) die(p);
            put32(f + end, PUB_MAGIC); put32(f + end + 4, (uint32_t)m); memcpy(f + end + 8, b, m); n = end + 8 + m; free(b);
        } else if (arg("magic")) put32(f + end, (uint32_t)num(arg("magic")));
        else if (arg("byte")) f[n++] = (uint8_t)num(arg("byte"));
        write_file(g_path, f, n); free(f); sb_add(o, "\t-");
    } else if (!strcmp(op, "reblob")) {
        size_t n, m; uint8_t *f = read_file(g_path, &n), dek[32], nonce[12], tag[16];
        char p[1400]; snprintf(p, sizeof p, "%s/in/%s.bin", g_out, need("pt"));
        uint8_t *pt = read_file(p, &m); if (!pt) die(p);
        bytes_t pin = pin_of(need("pin"));
        if (!unwrap_dek(f, role_of(need("role")), pin, dek)) { sb_add(o, "\terr"); free(f); free(pt); free(pin.p); return; }
        __wrap_fhsm_rng_bytes(nonce, 12);
        uint8_t *img = malloc(HDR + 16 + m + 16 + 8 + (1 << 21));
        memcpy(img, f, HDR); put32(img + HDR, (uint32_t)m); memcpy(img + HDR + 4, nonce, 12);
        if (!x_gcm(1, dek, nonce, f + 72, strnlen((const char *)f + 72, 64), pt, m, img + HDR + 16, tag)) die("gcm");
        if (arg("tag") && !strcmp(arg("tag"), "bad")) tag[0] ^= 1;
        memcpy(img + HDR + 16 + m, tag, 16);
        size_t len = HDR + 16 + m + 16;
        const char *pub = need("pub");
        if (strcmp(pub, "none")) {
            size_t q; snprintf(p, sizeof p, "%s/in/%s.bin", g_out, pub);
            uint8_t *b = read_file(p, &q); if (!b) die(p);
            put32(img + len, PUB_MAGIC); put32(img + len + 4, (uint32_t)q); memcpy(img + len + 8, b, q); len += 8 + q; free(b);
        }
        write_file(g_path, img, len);
        free(img); free(f); free(pt); free(pin.p); sb_add(o, "\t-");
    } else if (!strcmp(op, "rodir") || !strcmp(op, "rwdir")) {
        if (chmod(g_tokdir, op[1] == 'o' ? 0555 : 0755) != 0) die("chmod");
        sb_add(o, "\t-");
    } else if (!strcmp(op, "tokdir")) {
        if (mkdir(g_path, 0755) != 0) die("tokdir");
        sb_add(o, "\t-");
    } else if (!strcmp(op, "tpm")) {
        if (num(need("seal"))) setenv("FHSM_TPM_SEALING", "1", 1); else unsetenv("FHSM_TPM_SEALING");
        sb_add(o, "\t-");
    } else if (!strcmp(op, "pcr")) {
        set_ctl("pcr", need("v")); sb_add(o, "\t-");
    } else if (!strcmp(op, "tpmfail")) {
        set_ctl("fail", strcmp(need("v"), "-") ? need("v") : ""); sb_add(o, "\t-");
    } else if (!strcmp(op, "tpmprefix")) {
        char pre[1300]; snprintf(pre, sizeof pre, "chmod 0555 '%s'\n", g_tokdir);
        set_ctl("pre.sh", !strcmp(need("v"), "rodir") ? pre : ""); sb_add(o, "\t-");
    } else if (!strcmp(op, "reseal_tpm")) {
        bytes_t d = bytes_of(need("dek")); RV_ONLY(fhsm_token_tpm_seal(g_path, d.p)); free(d.p);
    } else if (!strcmp(op, "nosave")) {
        g_nosave = 1; sb_add(o, "\t-");
    } else {
        fprintf(stderr, "%s: unknown op %s\n", g_scen, op); exit(2);
    }
}

static void run_scenario(char **lines, int nlines, const char *from) {
    snprintf(g_dir, sizeof g_dir, "%s/s/%s", g_out, g_scen);
    snprintf(g_tokdir, sizeof g_tokdir, "%s/tok", g_dir);
    snprintf(g_ctl, sizeof g_ctl, "%s/ctl", g_dir);
    snprintf(g_path, sizeof g_path, "%s/slot0.tok", g_tokdir);
    char cmd[3000];
    snprintf(cmd, sizeof cmd, "rm -rf '%s' && mkdir -p '%s' '%s'", g_dir, g_tokdir, g_ctl);
    if (system(cmd) != 0) die("mkdir");
    set_ctl("pcr", "golden-pcr"); set_ctl("fail", ""); set_ctl("pre.sh", "");
    snprintf(cmd, sizeof cmd, "sh '%s/pre.sh'; FHSM_TPM_FAKE_PCR=$(cat '%s/pcr') FHSM_TPM_FAKE_FAIL=$(cat '%s/fail') sh '%s'",
             g_ctl, g_ctl, g_ctl, g_stub);
    setenv("FHSM_TPM_CMD", cmd, 1);
    unsetenv("FHSM_TPM_SEALING");
    if (from) {
        char src[1400];
        if (!strncmp(from, "tok:", 4)) snprintf(src, sizeof src, "%s/tok/%s.tok", g_out, from + 4);
        else snprintf(src, sizeof src, "%s/%s", getenv("GEN_CORPUS") ? getenv("GEN_CORPUS") : "/corpus", from + 7);
        if (access(src, R_OK) != 0) { fprintf(stderr, "%s: no start file %s\n", g_scen, src); exit(2); }
        copy_file(src, g_path);
        char tpm[1500]; snprintf(tpm, sizeof tpm, "%s.tpm", src);
        char dst[1300]; snprintf(dst, sizeof dst, "%s.tpm", g_path);
        if (access(tpm, R_OK) == 0) copy_file(tpm, dst);
    }
    set_ref_from_file();
    rng_seed(g_scen);
    audit_open_file();

    char path[1400]; snprintf(path, sizeof path, "%s/run/%s.tsv", g_out, g_scen);
    g_steps = fopen(path, "w");
    if (!g_steps) die(path);
    for (g_step = 1; g_step <= nlines; g_step++) {
        char *l = strdup(lines[g_step - 1]);
        char *save = NULL, *op = strtok_r(l, " ", &save);
        g_nargs = 0;
        for (char *a = strtok_r(NULL, " ", &save); a && g_nargs < MAXARG; a = strtok_r(NULL, " ", &save)) {
            char *eq = strchr(a, '=');
            g_key[g_nargs] = a; g_val[g_nargs] = eq ? (*eq = 0, eq + 1) : (char *)"";
            g_nargs++;
        }
        sbuf o = { 0 };
        if (!strcmp(op, "audit")) {   /* `audit fail`: every later fsync fails (DIV-001) */
            audit_open_fifo();
            sb_add(&o, "\t-");
        } else {
            run_op(&o, op);
        }
        audit_collect(&o);
        fprintf(g_steps, "%s\t%d\t%s%s\n", g_scen, g_step, lines[g_step - 1], o.s ? o.s : "");
        free(o.s); free(l);
    }
    fclose(g_steps);
    if (!g_nosave) {
        char dst[1400]; snprintf(dst, sizeof dst, "%s/tok/%s.tok", g_out, g_scen);
        struct stat st;
        if (stat(g_path, &st) == 0 && S_ISREG(st.st_mode)) {
            chmod(g_tokdir, 0755);
            copy_file(g_path, dst);
            char tpm[1300], tdst[1500]; snprintf(tpm, sizeof tpm, "%s.tpm", g_path); snprintf(tdst, sizeof tdst, "%s.tpm", dst);
            if (access(tpm, R_OK) == 0) copy_file(tpm, tdst);
        }
    }
}

static void run_script(const char *script) {
    size_t n; char *text = (char *)read_file(script, &n);
    if (!text) die(script);
    text = realloc(text, n + 1); text[n] = 0;
    char *lines[512]; int nl = 0; char from[256] = ""; int have = 0;
    char *save = NULL;
    for (char *l = strtok_r(text, "\n", &save);; l = strtok_r(NULL, "\n", &save)) {
        int is_scen = l && !strncmp(l, "scenario ", 9);
        if ((!l || is_scen) && have) {
            fflush(NULL);
            pid_t pid = fork();
            if (pid == 0) { run_scenario(lines, nl, from[0] ? from : NULL); _exit(0); }
            int st = 0; waitpid(pid, &st, 0);
            if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { fprintf(stderr, "scenario %s: child status 0x%x\n", g_scen, st); exit(2); }
            char p[1400]; snprintf(p, sizeof p, "%s/run/%s.tsv", g_out, g_scen);
            size_t m; uint8_t *b = read_file(p, &m);
            fwrite(b, 1, m, g_steps); free(b); unlink(p);
            have = 0;
        }
        if (!l) break;
        if (is_scen) {
            char name[128] = "", fr[256] = "";
            sscanf(l + 9, "%127s from=%255s", name, fr);
            snprintf(g_scen, sizeof g_scen, "%s", name); snprintf(from, sizeof from, "%s", fr);
            nl = 0; have = 1;
            continue;
        }
        if (l[0] == '#' || l[0] == 0) continue;
        if (have) lines[nl++] = l;
    }
}

/* ------------------------------------------------------------------ KAT (tests/crypto.rs) */
static void kat_hex(FILE *f, const uint8_t *p, size_t n) { fputc('\t', f); for (size_t i = 0; i < n; i++) fprintf(f, "%02x", p[i]); if (!n) fputc('-', f); }
static void kat(void) {
    char p[1100]; snprintf(p, sizeof p, "%s/kat.tsv", g_out);
    FILE *f = fopen(p, "w"); if (!f) die(p);
    fprintf(f, "# op\tinputs...\trv\toutputs...  (hex; - for empty). Made by gen_store.c from fhsm_crypto.c.\n");
    struct { const char *pw; const char *salt; uint32_t iter; size_t len; } pk[] = {
        { "password", "salt", 1000, 32 }, { "password", "salt", 4096, 32 }, { "golden-so-pin-01", "0123456789abcdef", 200000, 32 },
        { "", "0123456789abcdef", 1000, 32 }, { "password", "", 1000, 32 }, { "password", "salt", 1000, 64 },
        { "password", "salt", 999, 32 }, { "password", "salt", 0, 32 },
    };
    for (size_t i = 0; i < sizeof pk / sizeof *pk; i++) {
        uint8_t out[64] = { 0 };
        fhsm_rv_t rv = fhsm_pbkdf2(FHSM_HASH_SHA256, FHSM_SLICE(pk[i].pw, strlen(pk[i].pw)), FHSM_SLICE(pk[i].salt, strlen(pk[i].salt)),
                                   pk[i].iter, out, pk[i].len);
        fprintf(f, "pbkdf2"); kat_hex(f, (const uint8_t *)pk[i].pw, strlen(pk[i].pw)); kat_hex(f, (const uint8_t *)pk[i].salt, strlen(pk[i].salt));
        fprintf(f, "\t%u\t%zu\t0x%x", pk[i].iter, pk[i].len, (unsigned)rv); kat_hex(f, out, rv ? 0 : pk[i].len); fputc('\n', f);
    }
    uint8_t key[32], nonce[12], ptb[1000];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(0xA0 + i);
    for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(0x10 + i);
    for (int i = 0; i < 1000; i++) ptb[i] = (uint8_t)(i * 7);
    const char *aads[] = { "FHSM-0123456789abcdef", "" };
    size_t lens[] = { 32, 0, 1000, 1 };
    for (int a = 0; a < 2; a++) for (int L = 0; L < 4; L++) {
        uint8_t ct[1000], tag[16], back[1000]; size_t cl = lens[L], bl = lens[L];
        fhsm_rv_t rv = fhsm_aes_gcm_encrypt(FHSM_SLICE(key, 32), FHSM_SLICE(nonce, 12), FHSM_SLICE(aads[a], strlen(aads[a])),
                                            FHSM_SLICE(ptb, lens[L]), ct, &cl, tag);
        fprintf(f, "gcm_enc"); kat_hex(f, key, 32); kat_hex(f, nonce, 12); kat_hex(f, (const uint8_t *)aads[a], strlen(aads[a]));
        kat_hex(f, ptb, lens[L]); fprintf(f, "\t0x%x", (unsigned)rv); kat_hex(f, ct, cl); kat_hex(f, tag, 16); fputc('\n', f);
        rv = fhsm_aes_gcm_decrypt(FHSM_SLICE(key, 32), FHSM_SLICE(nonce, 12), FHSM_SLICE(aads[a], strlen(aads[a])),
                                  FHSM_SLICE(ct, cl), tag, back, &bl);
        fprintf(f, "gcm_dec"); kat_hex(f, key, 32); kat_hex(f, nonce, 12); kat_hex(f, (const uint8_t *)aads[a], strlen(aads[a]));
        kat_hex(f, ct, cl); kat_hex(f, tag, 16); fprintf(f, "\t0x%x", (unsigned)rv); kat_hex(f, back, rv ? 0 : bl); fputc('\n', f);
        if (L == 0) {
            uint8_t bad[16]; memcpy(bad, tag, 16); bad[15] ^= 0x80; bl = lens[L];
            rv = fhsm_aes_gcm_decrypt(FHSM_SLICE(key, 32), FHSM_SLICE(nonce, 12), FHSM_SLICE(aads[a], strlen(aads[a])),
                                      FHSM_SLICE(ct, cl), bad, back, &bl);
            fprintf(f, "gcm_dec"); kat_hex(f, key, 32); kat_hex(f, nonce, 12); kat_hex(f, (const uint8_t *)aads[a], strlen(aads[a]));
            kat_hex(f, ct, cl); kat_hex(f, bad, 16); fprintf(f, "\t0x%x", (unsigned)rv); kat_hex(f, back, 0); fputc('\n', f);
            bl = lens[L];
            rv = fhsm_aes_gcm_decrypt(FHSM_SLICE(key, 32), FHSM_SLICE(nonce, 12), FHSM_SLICE("FHSM-x", 6),
                                      FHSM_SLICE(ct, cl), tag, back, &bl);
            fprintf(f, "gcm_dec"); kat_hex(f, key, 32); kat_hex(f, nonce, 12); kat_hex(f, (const uint8_t *)"FHSM-x", 6);
            kat_hex(f, ct, cl); kat_hex(f, tag, 16); fprintf(f, "\t0x%x", (unsigned)rv); kat_hex(f, back, 0); fputc('\n', f);
        }
    }
    fclose(f);
}

/* ------------------------------------------------------------------ C ABI rows (tests/token_ffi.rs) */
static FILE *g_ffi;
static void frow(const char *name, fhsm_rv_t rv, const char *extra) { fprintf(g_ffi, "%s\t0x%x%s%s\n", name, (unsigned)rv, extra ? "\t" : "", extra ? extra : ""); }
static void ffi(void) {
    char p[1100], dir[1100], tp[1200];
    snprintf(p, sizeof p, "%s/ffi.tsv", g_out);
    g_ffi = fopen(p, "w"); if (!g_ffi) die(p);
    fprintf(g_ffi, "# case\trv\t[k=v]  C ABI of include/fhsm_token.h with NULL/out-of-range arguments. Made by gen_store.c.\n");
    snprintf(dir, sizeof dir, "%s/s/ffi", g_out);
    snprintf(tp, sizeof tp, "rm -rf '%s' && mkdir -p '%s'", dir, dir); if (system(tp) != 0) die("ffi dir");
    snprintf(tp, sizeof tp, "%s/slot0.tok", dir);
    unsetenv("FHSM_TPM_SEALING");
    rng_seed("ffi");
    fhsm_token_t *t = NULL;
    frow("load_null_path", fhsm_token_load(NULL, &t), NULL);
    frow("load_null_out", fhsm_token_load(tp, NULL), NULL);
    frow("load_missing", fhsm_token_load(tp, &t), NULL);
    frow("init_null_path", fhsm_token_init(NULL, SO_PIN, "l", &t), NULL);
    frow("init_null_pin", fhsm_token_init(tp, NULL, "l", &t), NULL);
    frow("init_null_label", fhsm_token_init(tp, SO_PIN, NULL, &t), NULL);
    frow("init_null_out", fhsm_token_init(tp, SO_PIN, "l", NULL), NULL);
    frow("init_ok", fhsm_token_init(tp, SO_PIN, "golden-ffi", &t), NULL);
    frow("login_null_token", fhsm_token_login(NULL, FHSM_ROLE_SO, SO_PIN, 16), NULL);
    frow("login_null_pin", fhsm_token_login(t, FHSM_ROLE_SO, NULL, 16), NULL);
    frow("verify_null_token", fhsm_token_verify_pin(NULL, FHSM_ROLE_SO, SO_PIN, 16), NULL);
    frow("verify_null_pin", fhsm_token_verify_pin(t, FHSM_ROLE_SO, NULL, 16), NULL);
    frow("verify_role_3", fhsm_token_verify_pin(t, (fhsm_role_t)3, SO_PIN, 16), NULL);
    frow("set_pin_null_token", fhsm_token_set_pin(NULL, FHSM_ROLE_SO, SO_PIN, NEW_PIN), NULL);
    frow("set_pin_null_old", fhsm_token_set_pin(t, FHSM_ROLE_SO, NULL, NEW_PIN), NULL);
    frow("set_pin_null_new", fhsm_token_set_pin(t, FHSM_ROLE_SO, SO_PIN, NULL), NULL);
    frow("init_user_pin_null_token", fhsm_token_init_user_pin(NULL, USER_PIN), NULL);
    frow("init_user_pin_null_pin", fhsm_token_init_user_pin(t, NULL), NULL);
    frow("reinit_null_token", fhsm_token_reinit(NULL, SO_PIN, "l"), NULL);
    frow("reinit_null_pin", fhsm_token_reinit(t, NULL, "l"), NULL);
    frow("reinit_null_label", fhsm_token_reinit(t, SO_PIN, NULL), NULL);
    {
        char ex[256];
        snprintf(ex, sizeof ex, "role=%d label_null=%d serial_null=%d failed=%u uinit=%d locked=%d thr=%llu",
                 (int)fhsm_token_current_role(NULL), fhsm_token_label(NULL) == NULL, fhsm_token_serial(NULL) == NULL,
                 fhsm_token_failed_count(NULL, FHSM_ROLE_SO), fhsm_token_user_initialized(NULL),
                 fhsm_token_is_locked(NULL, FHSM_ROLE_SO), (unsigned long long)fhsm_token_throttle_remaining_ms(NULL, FHSM_ROLE_SO));
        frow("accessors_null_token", 0, ex);
    }
    frow("login_so", fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN, strlen(SO_PIN)), NULL);
    frow("init_user_pin", fhsm_token_init_user_pin(t, USER_PIN), NULL);
    fhsm_token_logout(t);
    frow("login_user", fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)), NULL);
    uint32_t h = 0, h2 = 0;
    const uint8_t v[4] = { 1, 2, 3, 4 };
    frow("add_null_token", fhsm_token_object_add(NULL, 4, 31, "k", v, 4, NULL, 0, 0, &h), NULL);
    frow("add_null_out", fhsm_token_object_add(t, 4, 31, "k", v, 4, NULL, 0, 0, NULL), NULL);
    frow("add_value_over_max", fhsm_token_object_add(t, 4, 31, "k", v, 2097153, NULL, 0, 0, &h), NULL);
    frow("add_id_33", fhsm_token_object_add(t, 4, 31, "k", v, 4, v, 33, 0, &h), NULL);
    frow("add_value_over_max_and_id_33", fhsm_token_object_add(t, 4, 31, "k", v, 2097153, v, 33, 0, &h), NULL);
    frow("add_ok", fhsm_token_object_add(t, 4, 31, "k", v, 4, v, 2, 0, &h), NULL);
    frow("add_null_label_null_value", fhsm_token_object_add(t, 0, 0, NULL, NULL, 0, NULL, 0, 0, &h2), NULL);
    {
        const uint8_t *pv = (const uint8_t *)1; size_t pl = 99; uint32_t c = 99, k = 99;
        frow("get_null_token", fhsm_token_object_get(NULL, h, &pv, &pl, &c, &k), NULL);
        frow("get_null_outputs", fhsm_token_object_get(t, h, NULL, NULL, NULL, NULL), NULL);
        fhsm_rv_t rv = fhsm_token_object_get(t, h2, &pv, &pl, &c, &k);
        char ex[64]; snprintf(ex, sizeof ex, "value_null=%d len=%zu", pv == NULL, pl);
        frow("get_empty_value", rv, ex);
    }
    {
        size_t cnt = 99; uint32_t hs[4];
        frow("find_null_token", fhsm_token_object_find(NULL, NULL, NULL, hs, 4, &cnt), NULL);
        frow("find_null_count", fhsm_token_object_find(t, NULL, NULL, hs, 4, NULL), NULL);
        fhsm_rv_t rv = fhsm_token_object_find(t, NULL, NULL, NULL, 4, &cnt);
        char ex[32]; snprintf(ex, sizeof ex, "n=%zu", cnt);
        frow("find_null_handles", rv, ex);
    }
    {
        const char *l = NULL; size_t n = 0; const uint8_t *b = NULL;
        frow("get_label_null_out", fhsm_token_object_get_label(t, h, NULL, &n), NULL);
        frow("get_label_null_len", fhsm_token_object_get_label(t, h, &l, NULL), NULL);
        frow("get_id_null_out", fhsm_token_object_get_id(t, h, NULL, &n), NULL);
        frow("get_meta_null_out", fhsm_token_object_get_meta(t, h, FHSM_OBJ_META_START_DATE, NULL, &n), NULL);
        frow("get_meta_which_3", fhsm_token_object_get_meta(t, h, (fhsm_obj_meta_t)3, &b, &n), NULL);
        frow("get_meta_which_3_unknown_handle", fhsm_token_object_get_meta(t, 999, (fhsm_obj_meta_t)3, &b, &n), NULL);
        frow("set_meta_null_token", fhsm_token_object_set_meta(NULL, h, NULL, 0, NULL, 0, NULL, 0), NULL);
        frow("set_meta_start_9", fhsm_token_object_set_meta(t, 999, v, 9, NULL, 0, NULL, 0), NULL);
        frow("set_meta_null_start_len_9", fhsm_token_object_set_meta(t, h, NULL, 9, NULL, 0, NULL, 0), NULL);
    }
    {
        uint8_t f = 0; int it = 0;
        frow("get_flags_null_out", fhsm_token_object_get_flags(t, h, NULL), NULL);
        frow("get_flags2_null_out", fhsm_token_object_get_flags2(t, h, NULL), NULL);
        frow("get_flags3_null_out", fhsm_token_object_get_flags3(t, h, NULL), NULL);
        frow("get_usage_null_out", fhsm_token_object_get_usage(t, h, NULL), NULL);
        frow("is_token_null_out", fhsm_token_object_is_token(t, h, NULL), NULL);
        frow("get_flags_null_token", fhsm_token_object_get_flags(NULL, h, &f), NULL);
        frow("is_token_null_token", fhsm_token_object_is_token(NULL, h, &it), NULL);
        frow("set_flags_null_token", fhsm_token_object_set_flags(NULL, h, 0), NULL);
        frow("set_flags2_null_token", fhsm_token_object_set_flags2(NULL, h, 0), NULL);
        frow("set_flags3_null_token", fhsm_token_object_set_flags3(NULL, h, 0), NULL);
        frow("set_usage_null_token", fhsm_token_object_set_usage(NULL, h, 0), NULL);
        frow("set_label_null_label", fhsm_token_object_set_label(t, h, NULL), NULL);
        frow("set_id_33", fhsm_token_object_set_id(t, 999, v, 33), NULL);
        frow("set_id_null_with_len", fhsm_token_object_set_id(t, h, NULL, 2), NULL);
        frow("set_id_null_len_0", fhsm_token_object_set_id(t, h, NULL, 0), NULL);
        frow("destroy_null_token", fhsm_token_object_destroy(NULL, h), NULL);
        frow("mark_session_owner_0", fhsm_token_object_mark_session(t, h, 0), NULL);
        frow("destroy_session_owner_0", fhsm_token_destroy_session_objects(t, 0), NULL);
        frow("mech_allowed_null_token", fhsm_token_object_mech_allowed(NULL, h, 1), NULL);
        frow("policy_counts_null_token", fhsm_token_object_get_policy_counts(NULL, h, NULL, NULL, NULL, NULL), NULL);
        frow("policy_counts_null_outputs", fhsm_token_object_get_policy_counts(t, h, NULL, NULL, NULL, NULL), NULL);
    }
    {
        uint32_t m[8] = { 0x1081, 0x1082, 3 }; uint8_t io;
        frow("set_mechs_null_with_count", fhsm_token_object_set_allowed_mechs(t, h, NULL, 1), NULL);
        frow("set_mechs_count_9", fhsm_token_object_set_allowed_mechs(t, 999, m, 9), NULL);
        frow("set_mechs_null_count_0", fhsm_token_object_set_allowed_mechs(t, h, NULL, 0), NULL);
        frow("set_mechs_3", fhsm_token_object_set_allowed_mechs(t, h, m, 3), NULL);
        frow("get_mechs_null_io", fhsm_token_object_get_allowed_mechs(t, h, m, NULL), NULL);
        io = 0; { fhsm_rv_t rv = fhsm_token_object_get_allowed_mechs(t, h, NULL, &io); char ex[16]; snprintf(ex, sizeof ex, "io=%u", io); frow("get_mechs_size_query", rv, ex); }
        io = 2; { fhsm_rv_t rv = fhsm_token_object_get_allowed_mechs(t, h, m, &io); char ex[16]; snprintf(ex, sizeof ex, "io=%u", io); frow("get_mechs_cap_2", rv, ex); }
        io = 3; { uint32_t o3[3] = { 0 }; fhsm_rv_t rv = fhsm_token_object_get_allowed_mechs(t, h, o3, &io); char ex[64]; snprintf(ex, sizeof ex, "io=%u v=0x%x,0x%x,0x%x", io, o3[0], o3[1], o3[2]); frow("get_mechs_cap_3", rv, ex); }
        io = 5; { fhsm_rv_t rv = fhsm_token_object_get_allowed_mechs(t, 999, m, &io); char ex[16]; snprintf(ex, sizeof ex, "io=%u", io); frow("get_mechs_unknown_handle", rv, ex); }
    }
    {
        fhsm_policy_attr_t a[5]; memset(a, 0, sizeof a); uint8_t io;
        for (int i = 0; i < 5; i++) { a[i].type = (uint32_t)i + 1; a[i].kind = 1; a[i].len = 1; a[i].value[0] = 1; }
        frow("set_tmpl_null_with_count", fhsm_token_object_set_tmpl(t, h, FHSM_TMPL_WRAP, NULL, 1), NULL);
        frow("set_tmpl_count_5", fhsm_token_object_set_tmpl(t, 999, FHSM_TMPL_WRAP, a, 5), NULL);
        frow("set_tmpl_which_3", fhsm_token_object_set_tmpl(t, 999, (fhsm_tmpl_which_t)3, a, 1), NULL);
        frow("set_tmpl_which_3_count_5", fhsm_token_object_set_tmpl(t, 999, (fhsm_tmpl_which_t)3, a, 5), NULL);
        a[0].kind = 0; frow("set_tmpl_kind_0_which_3", fhsm_token_object_set_tmpl(t, 999, (fhsm_tmpl_which_t)3, a, 1), NULL); a[0].kind = 1;
        frow("set_tmpl_2", fhsm_token_object_set_tmpl(t, h, FHSM_TMPL_DERIVE, a, 2), NULL);
        frow("get_tmpl_null_io", fhsm_token_object_get_tmpl(t, h, FHSM_TMPL_DERIVE, a, NULL), NULL);
        io = 0; frow("get_tmpl_which_3", fhsm_token_object_get_tmpl(t, h, (fhsm_tmpl_which_t)3, a, &io), NULL);
        io = 0; { fhsm_rv_t rv = fhsm_token_object_get_tmpl(t, h, FHSM_TMPL_DERIVE, NULL, &io); char ex[16]; snprintf(ex, sizeof ex, "io=%u", io); frow("get_tmpl_size_query", rv, ex); }
        io = 1; { fhsm_rv_t rv = fhsm_token_object_get_tmpl(t, h, FHSM_TMPL_DERIVE, a, &io); char ex[16]; snprintf(ex, sizeof ex, "io=%u", io); frow("get_tmpl_cap_1", rv, ex); }
    }
    {
        char ex[64]; snprintf(ex, sizeof ex, "size=%zu align=%zu kind=%zu len=%zu value=%zu", sizeof(fhsm_policy_attr_t),
                              _Alignof(fhsm_policy_attr_t), offsetof(fhsm_policy_attr_t, kind), offsetof(fhsm_policy_attr_t, len),
                              offsetof(fhsm_policy_attr_t, value));
        frow("policy_attr_layout", 0, ex);
    }
    fhsm_token_close(NULL);
    fhsm_token_logout(NULL);
    frow("close_and_logout_null", 0, NULL);
    fhsm_token_close(t);
    fclose(g_ffi);
}

int main(int argc, char **argv) {
    if (argc != 5 || strcmp(argv[1], "make")) { fprintf(stderr, "usage: gen_store make OUTDIR SCRIPT STUB\n"); return 2; }
    g_out = argv[2];
    g_stub = argv[4];
    char p[1100];
    snprintf(p, sizeof p, "%s/run", g_out); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/s", g_out); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/tok", g_out); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/pt", g_out); mkdir(p, 0755);
    snprintf(p, sizeof p, "%s/pub", g_out); mkdir(p, 0755);
    make_inputs();
    kat();
    ffi();
    snprintf(p, sizeof p, "%s/steps.tsv", g_out);
    g_steps = fopen(p, "w"); if (!g_steps) die(p);
    fprintf(g_steps, "# scenario\tstep\top line\toutput...  Made by gen_store.c from store_scenarios.txt.\n");
    FILE *top = g_steps;
    run_script(argv[3]);
    (void)top;
    fclose(g_steps);
    snprintf(p, sizeof p, "rm -rf '%s/run' '%s/s'", g_out, g_out);
    return system(p) == 0 ? 0 : 2;
}
