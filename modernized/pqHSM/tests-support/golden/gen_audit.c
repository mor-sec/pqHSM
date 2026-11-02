/* Golden generator for the pqhsm-audit characterization tests.
 *
 * Runs the LEGACY C audit module (src/fhsm_audit.c) and records what it
 * actually does. Linked against the legacy objects, never against Rust.
 * Driven by regen.sh; see audit/tests/README.md.
 *
 *   gen_audit lines   OUTDIR          lines.log + lines.tsv, newline_key.log + .tsv
 *   gen_audit chain   BASE KEYLEN N   N standard events under key 00..KEYLEN-1
 *   gen_audit verify  KEYHEX FILE...  fhsm_audit_verify: "<file>\t<rv>\t<broken>"
 *   gen_audit open    BASE            open under the test key, print the leaf opened
 *   gen_audit stream  PATH N          open PATH, N events: rv of each, then stats
 *   gen_audit fifo    PATH N          as stream, on a FIFO with a draining reader
 *   gen_audit craft   OUTDIR          hand-made, correctly MACed lines (fixed ts)
 *
 * The only key used is the non-secret test key bytes 0x00, 0x01, ... (prefix of
 * the requested length).
 */
#include "fhsm_common.h"
#include "fhsm_audit.h"
#include "fhsm_crypto.h"

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static uint8_t g_key[64];

static void test_key(void) { for (int i = 0; i < 64; i++) g_key[i] = (uint8_t)i; }

static void die(const char *m) { fprintf(stderr, "gen_audit: %s\n", m); exit(2); }

/* ---- one event, dynamic number of pairs ------------------------------- */
#define MAXP 10
typedef struct {
    unsigned code; int slot, session; fhsm_role_t role; unsigned rv;
    const char *actor; size_t actor_len;  /* actor == NULL: set_actor(NULL) */
    int np; const char *k[MAXP]; const char *v[MAXP];
} ev_t;

static fhsm_rv_t emit(const ev_t *e) {
    fhsm_audit_set_actor(e->actor);
    const char *const *k = e->k, *const *v = e->v;
    fhsm_audit_event_t c = (fhsm_audit_event_t)e->code;
#define A(i) k[i], v[i]
    switch (e->np) {
    case 0: return fhsm_audit_event(c, e->slot, e->session, e->role, e->rv, FHSM_AUDIT_END);
    case 1: return fhsm_audit_event(c, e->slot, e->session, e->role, e->rv, A(0), FHSM_AUDIT_END);
    case 2: return fhsm_audit_event(c, e->slot, e->session, e->role, e->rv, A(0), A(1), FHSM_AUDIT_END);
    case 3: return fhsm_audit_event(c, e->slot, e->session, e->role, e->rv, A(0), A(1), A(2), FHSM_AUDIT_END);
    case 10: return fhsm_audit_event(c, e->slot, e->session, e->role, e->rv, A(0), A(1), A(2), A(3),
                                     A(4), A(5), A(6), A(7), A(8), A(9), FHSM_AUDIT_END);
    default: die("unsupported pair count");
    }
#undef A
    return 0;
}

static void hexout(FILE *f, const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) fprintf(f, "%02x", (unsigned char)s[i]);
}

/* code slot session role rv actor(hex|-) pairs(khex:vhex,...|-) */
static void manifest(FILE *f, const ev_t *e) {
    static const char *roles[] = { "NONE", "SO", "USER" };
    fprintf(f, "%u\t%d\t%d\t%s\t%u\t", e->code, e->slot, e->session, roles[e->role], e->rv);
    if (!e->actor) fputs("-", f); else hexout(f, e->actor, e->actor_len);
    fputc('\t', f);
    if (e->np == 0) fputs("-", f);
    for (int i = 0; i < e->np; i++) {
        if (i) fputc(',', f);
        hexout(f, e->k[i], strlen(e->k[i])); fputc(':', f); hexout(f, e->v[i], strlen(e->v[i]));
    }
    fputc('\n', f);
}

static char *rep(char c, size_t n) {
    char *s = malloc(n + 1); if (!s) die("oom");
    memset(s, c, n); s[n] = '\0'; return s;
}

static void open_or_die(const char *base, size_t keylen, char *cur, size_t cap) {
    if (fhsm_audit_open(base, FHSM_SLICE(g_key, keylen)) != FHSM_RV_OK) die("open failed");
    fhsm_audit_current_path(cur, cap);
}

static void write_log(const char *outdir, const char *name, ev_t *evs, int n) {
    char base[600], cur[700], dst[700], tsvp[700];
    snprintf(base, sizeof base, "%s/.tmp-%s", outdir, name);
    open_or_die(base, 32, cur, sizeof cur);
    snprintf(tsvp, sizeof tsvp, "%s/%s.tsv", outdir, name);
    FILE *t = fopen(tsvp, "w"); if (!t) die("tsv");
    fputs("# code\tslot\tsession\trole\trv\tactor_hex|-\tkhex:vhex,...|-\n", t);
    for (int i = 0; i < n; i++) {
        manifest(t, &evs[i]);
        if (emit(&evs[i]) != FHSM_RV_OK) die("event failed");
    }
    fclose(t);
    fhsm_audit_set_actor(NULL);
    fhsm_audit_close();
    snprintf(dst, sizeof dst, "%s/%s.log", outdir, name);
    if (rename(cur, dst) != 0) die("rename");
}

#define EV(code_, slot_, sess_, role_, rv_) \
    (ev_t){ .code = (code_), .slot = (slot_), .session = (sess_), .role = (role_), .rv = (rv_) }

static void with_actor(ev_t *e, const char *a, size_t n) { e->actor = a; e->actor_len = n; }
static void with_pair(ev_t *e, const char *k, const char *v) { e->k[e->np] = k; e->v[e->np] = v; e->np++; }

static int mode_lines(const char *outdir) {
    static ev_t evs[256]; int n = 0;
    static const unsigned codes[] = {
        1, 2, 3, 4, 5, 6, 10, 11, 12, 13, 14, 15, 16, 17, 18, 30, 31, 32, 40, 41, 42, 43, 44,
        45, 46, 47, 48, 49, 60, 70, 71, 72, 73, 80, 81, 82, 83, 84, 85,
        0, 7, 9, 86, 999, 0xFFFFFFFFu };          /* the last six are not in the header */
    for (size_t i = 0; i < sizeof codes / sizeof codes[0]; i++)
        evs[n++] = EV(codes[i], -1, -1, FHSM_ROLE_NONE, 0);

    /* roles, rv, slot/session */
    evs[n++] = EV(12, 0, 1, FHSM_ROLE_SO, 0);
    evs[n++] = EV(12, 0, 1, FHSM_ROLE_USER, 0);
    evs[n++] = EV(13, 0, 1, FHSM_ROLE_USER, 0x000000A0u);
    evs[n++] = EV(3, -1, -1, FHSM_ROLE_NONE, 0x80000001u);
    evs[n++] = EV(3, -1, -1, FHSM_ROLE_NONE, 0xFFFFFFFFu);
    evs[n++] = EV(42, INT_MIN, INT_MIN, FHSM_ROLE_USER, 0);
    evs[n++] = EV(42, INT_MAX, INT_MAX, FHSM_ROLE_USER, 0);
    evs[n++] = EV(42, -5, -7, FHSM_ROLE_USER, 6);

    /* actor */
    static const char a_ff5[] = "CN=a\xff" "bc";
    static const char a_ctl[] = "CN=\x1f";
    static const char a_del[] = "CN=\x7f";
    char *a127 = rep('a', 127), *a128 = rep('a', 128), *a200 = rep('a', 200);
    char *a_cut_ff = rep('b', 130); a_cut_ff[128] = '\xff';    /* unsafe byte past the cut */
    char *a_in_ff = rep('c', 130);  a_in_ff[126] = '\xff';     /* unsafe byte inside the cut */
    char *a_q127 = rep('d', 130);   a_q127[127] = '"';          /* first byte cut off */
    struct { const char *s; size_t n; } actors[] = {
        { "CN=alice,O=Example Corp", 23 }, { "", 0 }, { NULL, 0 }, { a127, 127 }, { a128, 128 },
        { a200, 200 }, { a_cut_ff, 130 }, { a_in_ff, 130 }, { a_q127, 130 },
        { a_ff5, 7 }, { "CN=\"x\"", 6 }, { "CN=a\\b", 6 }, { "CN=a\nb", 6 }, { a_ctl, 4 },
        { a_del, 4 }, { " ~", 2 },
    };
    for (size_t i = 0; i < sizeof actors / sizeof actors[0]; i++) {
        evs[n] = EV(82, 0, 3, FHSM_ROLE_USER, 0);
        with_actor(&evs[n], actors[i].s, actors[i].n); n++;
    }

    /* params */
    struct { const char *k, *v; } single[] = {
        { "alg", "mldsa65" }, { "k", "" }, { "", "v" }, { "sp ace", " ~ " },
        { "q", "a\"b" }, { "bs", "a\\b" }, { "nl", "a\nb" }, { "cr", "a\rb" }, { "c1", "\x01" },
        { "del", "\x7f" }, { "hi", "\x80" }, { "ff", "caf\xc3\xa9" },
        { "a\"b", "x" }, { "a\\b", "x" }, { "k\x7f", "x" }, { "k\x01", "x" }, { "k\t", "x" },
        { "hmac", "1" },
    };
    for (size_t i = 0; i < sizeof single / sizeof single[0]; i++) {
        evs[n] = EV(42, 0, 1, FHSM_ROLE_USER, 0); with_pair(&evs[n], single[i].k, single[i].v); n++;
    }
    evs[n] = EV(47, 0, 1, FHSM_ROLE_USER, 0);
    with_pair(&evs[n], "mech", "0x1081"); with_pair(&evs[n], "len", "32"); with_pair(&evs[n], "q", "\""); n++;
    evs[n] = EV(47, 0, 1, FHSM_ROLE_USER, 0);
    static char kk[10][4], vv[10][4];
    for (int i = 0; i < 10; i++) {
        snprintf(kk[i], sizeof kk[i], "k%d", i); snprintf(vv[i], sizeof vv[i], "v%d", i);
        with_pair(&evs[n], kk[i], vv[i]);
    }
    n++;
    /* fill: "{" + "\"k\":\"" + v + "\"" = 7 + |v| bytes before the closing brace */
    size_t fills[] = { 1015, 1016, 1017, 1100 };
    for (size_t i = 0; i < 4; i++) {
        evs[n] = EV(42, 0, 1, FHSM_ROLE_USER, 0); with_pair(&evs[n], "k", rep('v', fills[i])); n++;
    }
    evs[n] = EV(42, 0, 1, FHSM_ROLE_USER, 0);       /* first fits, second overflows */
    with_pair(&evs[n], "a", rep('x', 600)); with_pair(&evs[n], "b", rep('y', 600)); n++;
    evs[n] = EV(42, 0, 1, FHSM_ROLE_USER, 0);       /* unsafe long value: INVALID, fits */
    { char *u = rep('u', 1100); u[3] = '"'; with_pair(&evs[n], "k", u); } n++;
    evs[n] = EV(42, 0, 1, FHSM_ROLE_USER, 0);       /* unsafe long key: kept, overflows */
    { char *u = rep('K', 1100); u[3] = '"'; with_pair(&evs[n], u, "v"); } n++;
    /* the longest line the writer can produce: 127-byte actor + 1023-byte params */
    evs[n] = EV(48, INT_MIN, INT_MIN, FHSM_ROLE_USER, 0xFFFFFFFFu);
    with_actor(&evs[n], a127, 127); with_pair(&evs[n], "k", rep('w', 1016)); n++;
    evs[n] = EV(48, INT_MIN, INT_MIN, FHSM_ROLE_USER, 0xFFFFFFFFu);
    with_actor(&evs[n], a127, 127); with_pair(&evs[n], "k", rep('w', 1015)); n++;

    write_log(outdir, "lines", evs, n);

    /* An unsafe KEY is written raw: a newline in it splits the record. */
    ev_t nl[2] = { EV(42, 0, 1, FHSM_ROLE_USER, 0), EV(43, 0, 1, FHSM_ROLE_USER, 0) };
    with_pair(&nl[0], "a\nb", "x");
    write_log(outdir, "newline_key", nl, 2);
    return 0;
}

static int mode_chain(const char *base, int keylen, int count) {
    char cur[700];
    open_or_die(base, (size_t)keylen, cur, sizeof cur);
    for (int i = 0; i < count; i++) {
        ev_t e;
        switch (i % 6) {
        case 0: e = EV(1, -1, -1, FHSM_ROLE_NONE, 0); break;
        case 1: e = EV(12, 0, 1, FHSM_ROLE_USER, 0); break;
        case 2: e = EV(42, 0, 1, FHSM_ROLE_USER, 0); with_pair(&e, "alg", "mldsa65"); break;
        case 3: e = EV(13, 0, 1, FHSM_ROLE_NONE, 0xA0); break;
        case 4: e = EV(82, 0, 2, FHSM_ROLE_USER, 0); with_actor(&e, "CN=bob", 6); break;
        default: e = EV(16, 0, 1, FHSM_ROLE_USER, 0); break;
        }
        if (emit(&e) != FHSM_RV_OK) die("event failed");
    }
    fhsm_audit_set_actor(NULL);
    fhsm_audit_close();
    puts(cur);
    return 0;
}

static int unhex(const char *h, uint8_t *out, size_t cap) {
    size_t n = strlen(h) / 2;
    if (n > cap) return -1;
    for (size_t i = 0; i < n; i++) { unsigned b; if (sscanf(h + 2*i, "%2x", &b) != 1) return -1; out[i] = (uint8_t)b; }
    return (int)n;
}

static int mode_verify(const char *keyhex, int argc, char **argv) {
    uint8_t k[64]; int kl = unhex(keyhex, k, sizeof k);
    if (kl < 0) die("bad key hex");
    for (int i = 0; i < argc; i++) {
        size_t broken = 999;
        fhsm_rv_t rv = fhsm_audit_verify(argv[i], FHSM_SLICE(k, (size_t)kl), &broken);
        const char *slash = strrchr(argv[i], '/');
        printf("%s\t0x%x\t%zu\n", slash ? slash + 1 : argv[i], (unsigned)rv, broken);
    }
    return 0;
}

static int mode_open(const char *base) {
    fhsm_rv_t rv = fhsm_audit_open(base, FHSM_SLICE(g_key, 32));
    if (rv != FHSM_RV_OK) { printf("rv=0x%x\n", (unsigned)rv); return 0; }
    char cur[700]; fhsm_audit_current_path(cur, sizeof cur);
    const char *slash = strrchr(cur, '/');
    puts(slash ? slash + 1 : cur);
    fhsm_audit_close();
    return 0;
}

static int run_events(const char *path, int count) {
    uint64_t e0, b0, e1, b1;
    fhsm_audit_barrier_stats(&e0, &b0);
    fhsm_rv_t rv = fhsm_audit_open(path, FHSM_SLICE(g_key, 32));
    printf("open\t0x%x\n", (unsigned)rv);
    if (rv != FHSM_RV_OK) return 0;
    char cur[700]; fhsm_audit_current_path(cur, sizeof cur);
    printf("current_path\t%s\n", cur);
    for (int i = 0; i < count; i++) {
        rv = fhsm_audit_event(FHSM_EV_SIGN, 0, 1, FHSM_ROLE_USER, FHSM_RV_OK, "i", "x", FHSM_AUDIT_END);
        printf("event%d\t0x%x\n", i + 1, (unsigned)rv);
    }
    fhsm_audit_barrier_stats(&e1, &b1);
    printf("stats_events\t%llu\nstats_barriers\t%llu\nstate_error\t%d\n",
           (unsigned long long)(e1 - e0), (unsigned long long)(b1 - b0),
           fhsm_state_get() == FHSM_STATE_ERROR);
    fhsm_audit_close();
    return 0;
}

static const char *g_fifo;
static char g_drained[1 << 16]; static size_t g_dn;
static void *drain(void *v) {
    (void)v;
    int fd = open(g_fifo, O_RDONLY);
    if (fd < 0) return NULL;
    ssize_t r;
    while ((r = read(fd, g_drained + g_dn, sizeof g_drained - g_dn)) > 0) g_dn += (size_t)r;
    close(fd);
    return NULL;
}

static int mode_fifo(const char *path, int count) {
    unlink(path);
    if (mkfifo(path, 0600) != 0) die("mkfifo");
    g_fifo = path;
    pthread_t t; pthread_create(&t, NULL, drain, NULL);
    run_events(path, count);
    pthread_join(t, NULL);
    unlink(path);
    /* one line per record written into the stream: the event name */
    int lines = 0;
    for (char *p = g_drained; p < g_drained + g_dn; ) {
        char *nl = memchr(p, '\n', (size_t)(g_drained + g_dn - p));
        if (!nl) break;
        char *e = strstr(p, "\"event\":\"");
        lines++;
        if (e && e < nl) { e += 9; printf("drained%d\t%.*s\n", lines, (int)(strchr(e, '"') - e), e); }
        p = nl + 1;
    }
    printf("drained_lines\t%d\n", lines);
    return 0;
}

/* ---- crafted lines: fixed bodies, MACed with the C module's own HMAC ---- */
static void hex(const uint8_t *b, char *o) { for (int i = 0; i < 32; i++) sprintf(o + 2*i, "%02x", b[i]); }
static void mac(const char *body, uint8_t out[32]) {
    size_t l = 32;
    if (fhsm_hmac(FHSM_HASH_SHA256, FHSM_SLICE(g_key, 32), FHSM_SLICE(body, strlen(body)), out, &l)
        != FHSM_RV_OK) die("hmac");
}

/* Each spec is a body template where "%P" is the previous MAC (hex) and "%S"
 * the seq; the MAC is appended as "hmac":"<hex>"}. upper=1 writes the
 * prev_hmac hex in upper case (inside the MAC'd body). */
static void craft(const char *outdir, const char *name, const char *const *bodies, int n, int upper) {
    char p[700]; snprintf(p, sizeof p, "%s/%s.log", outdir, name);
    FILE *f = fopen(p, "w"); if (!f) die("craft");
    uint8_t prev[32]; mac("FHSM-AUDIT-INIT|seq=0", prev);
    for (int i = 0; i < n; i++) {
        char ph[65], body[2048], mh[65]; hex(prev, ph);
        if (upper) for (char *c = ph; *c; c++) if (*c >= 'a') *c = (char)(*c - 32);
        snprintf(body, sizeof body, bodies[i], ph);
        uint8_t m[32]; mac(body, m); hex(m, mh);
        fprintf(f, "%s\"hmac\":\"%s\"}\n", body, mh);
        memcpy(prev, m, 32);
    }
    fclose(f);
}

static int mode_craft(const char *outdir) {
#define STD(seq) "{\"seq\":" seq ",\"ts\":1700000000000000000,\"event\":\"sign\",\"slot\":0,\"session\":1," \
                 "\"role\":\"USER\",\"actor\":\"\",\"result\":\"OK\",\"rv\":0,\"params\":{},\"prev_hmac\":\"%s\","
    const char *zeros[]  = { STD("01"), STD("002") };
    const char *plus[]   = { STD("+1"), STD(" 2") };
    const char *junk[]   = { STD("1x"), STD("2.5") };
    const char *minimal[]= { "{\"seq\":1,\"prev_hmac\":\"%s\",", "{\"prev_hmac\":\"%s\",\"seq\":2," };
    const char *upper[]  = { STD("1"), STD("2") };
    const char *fixed[]  = { STD("1"), STD("2"), STD("3") };
    craft(outdir, "craft_seq_leading_zeros", zeros, 2, 0);
    craft(outdir, "craft_seq_sign_and_space", plus, 2, 0);
    craft(outdir, "craft_seq_trailing_junk", junk, 2, 0);
    craft(outdir, "craft_minimal_fields", minimal, 2, 0);
    craft(outdir, "craft_prev_hmac_uppercase_in_body", upper, 2, 1);
    craft(outdir, "craft_fixed_ts", fixed, 3, 0);
    return 0;
}

int main(int argc, char **argv) {
    test_key();
    if (argc >= 3 && !strcmp(argv[1], "lines"))  return mode_lines(argv[2]);
    if (argc == 5 && !strcmp(argv[1], "chain"))  return mode_chain(argv[2], atoi(argv[3]), atoi(argv[4]));
    if (argc >= 4 && !strcmp(argv[1], "verify")) return mode_verify(argv[2], argc - 3, argv + 3);
    if (argc == 3 && !strcmp(argv[1], "open"))   return mode_open(argv[2]);
    if (argc == 4 && !strcmp(argv[1], "stream")) return run_events(argv[2], atoi(argv[3]));
    if (argc == 4 && !strcmp(argv[1], "fifo"))   return mode_fifo(argv[2], atoi(argv[3]));
    if (argc == 3 && !strcmp(argv[1], "craft"))  return mode_craft(argv[2]);
    die("usage: see the header comment");
}
