/* Golden generator for the Phase 2 token-store corpus (modernized/pqHSM/testdata/).
 *
 * Runs the LEGACY C token store (src/fhsm_token.c, fhsm_token_tpm.c, fhsm_tpm.c
 * through the FHSM_TPM_TEST_HOOKS seam, fhsm_revocation.c) and records what it
 * writes and what it reads back. Linked against the legacy objects, never Rust.
 * Built by gen_token.mk, driven by regen_token.sh.
 *
 *   gen_token make OUTDIR     every corpus file, then OUTDIR/manifest.tsv and
 *                             OUTDIR/revocation.tsv (C's own load verdicts)
 *   gen_token describe DIR    DIR/manifest.tsv for token files another writer made under the
 *                             corpus names (PHASE2_PLAN.md §5.1: C reads what Rust wrote)
 *   gen_token public FILE...  the PIN-free view of each token on stdout (the harness's
 *                             token side-effect diff, §5.4)
 *
 * Built against hybrid.mk (GEN_BASE), the same program runs the Rust token store instead.
 *
 * The PINs are invented for this corpus; no PIN from the legacy tree is used.
 */
#include "fhsm_common.h"
#include "fhsm_crypto.h"
#include "fhsm_revocation.h"
#include "fhsm_token.h"
#include "fhsm_tpm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SO_PIN   "golden-so-pin-01"
#define USER_PIN "golden-user-pin-01"
#define WRONG    "golden-wrong-pin"
#define CKO_DATA_ 0u
#define CKO_CERTIFICATE_ 1u
#define CKO_PUBLIC_KEY_  2u
#define CKO_SECRET_KEY_  4u
#define CKK_EC_  3u
#define CKK_AES_ 0x1fu
#define HDR 317

static const char *out;
static FILE *man;

static void die(const char *m) { fprintf(stderr, "gen_token: %s\n", m); exit(2); }
static void must(fhsm_rv_t rv, const char *what) {
    if (rv != FHSM_RV_OK) { fprintf(stderr, "gen_token: %s: rv=0x%x\n", what, (unsigned)rv); exit(2); }
}
static const char *at(const char *name) {
    static char p[1024];
    snprintf(p, sizeof p, "%s/%s", out, name);
    return p;
}
static void hex(FILE *f, const uint8_t *b, size_t n) { for (size_t i = 0; i < n; i++) fprintf(f, "%02x", b[i]); }

static fhsm_token_t *fresh(const char *name, const char *label) {
    fhsm_token_t *t = NULL;
    unlink(at(name));
    must(fhsm_token_init(at(name), SO_PIN, label, &t), "init");
    return t;
}
static void init_user(fhsm_token_t *t) {
    must(fhsm_token_login(t, FHSM_ROLE_SO, SO_PIN, strlen(SO_PIN)), "so login");
    must(fhsm_token_init_user_pin(t, USER_PIN), "init_user_pin");
    fhsm_token_logout(t);
}

/* Value bytes are a fixed, non-secret pattern: base, base+1, ... */
static void add(fhsm_token_t *t, uint32_t cls, uint32_t kt, const char *label,
                uint8_t base, size_t n, uint8_t flags) {
    uint8_t v[96], id[2] = { 0x1d, base };
    for (size_t i = 0; i < n; i++) v[i] = (uint8_t)(base + i);
    uint32_t h;
    must(fhsm_token_object_add(t, cls, kt, label, v, n, id, sizeof id, flags, &h), label);
}

static void build_multi(const char *name) {
    fhsm_token_t *t = fresh(name, "golden-multi");
    init_user(t);
    must(fhsm_token_login(t, FHSM_ROLE_USER, USER_PIN, strlen(USER_PIN)), "user login");
    add(t, CKO_SECRET_KEY_, CKK_AES_, "aes-sensitive", 0x10, 32, FHSM_OBJF_SENSITIVE);
    add(t, CKO_SECRET_KEY_, CKK_AES_, "aes-extractable", 0x40, 16, FHSM_OBJF_EXTRACTABLE);
    add(t, CKO_PUBLIC_KEY_, CKK_EC_, "ec-public", 0x04, 65, 0);
    add(t, CKO_CERTIFICATE_, 0, "certificate", 0x30, 90, 0);
    add(t, CKO_DATA_, 0, "data", 0x61, 8, 0);
    fhsm_token_close(t);
}

/* A <=2.5.0 store: re-encrypt the blob of a C-written token under 32 zero bytes,
 * in place and with the same nonce, exactly as the 2.5.0 defect left it. */
static void zero_dek(const char *src, const char *dst) {
    FILE *f = fopen(at(src), "rb");
    if (!f) die("zero_dek: open");
    static uint8_t buf[1 << 16];
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    char serial[65] = { 0 };
    memcpy(serial, buf + 72, 64);
    uint32_t iter = (uint32_t)buf[136] | buf[137] << 8 | buf[138] << 16 | (uint32_t)buf[139] << 24;
    uint8_t kek[32], dek[32], zero[32] = { 0 };
    must(fhsm_pbkdf2(FHSM_HASH_SHA256, FHSM_SLICE(USER_PIN, strlen(USER_PIN)),
                     FHSM_SLICE(buf + 216, 16), iter, kek, sizeof kek), "pbkdf2");
    size_t l = 32;
    must(fhsm_aes_gcm_decrypt(FHSM_SLICE(kek, 32), FHSM_SLICE(buf + 232, 12),
                              FHSM_SLICE(serial, strlen(serial)), FHSM_SLICE(buf + 244, 32),
                              buf + 276, dek, &l), "unwrap dek");
    uint8_t *b = buf + HDR;
    size_t ct_len = (size_t)b[0] | b[1] << 8 | b[2] << 16 | (size_t)b[3] << 24;
    if (HDR + 4 + 12 + ct_len + 16 > n) die("zero_dek: short blob");
    static uint8_t pt[1 << 16];
    l = ct_len;
    must(fhsm_aes_gcm_decrypt(FHSM_SLICE(dek, 32), FHSM_SLICE(b + 4, 12),
                              FHSM_SLICE(serial, strlen(serial)), FHSM_SLICE(b + 16, ct_len),
                              b + 16 + ct_len, pt, &l), "open blob");
    size_t cl = ct_len;
    must(fhsm_aes_gcm_encrypt(FHSM_SLICE(zero, 32), FHSM_SLICE(b + 4, 12),
                              FHSM_SLICE(serial, strlen(serial)), FHSM_SLICE(pt, l),
                              b + 16, &cl, b + 16 + ct_len), "reseal blob");
    fhsm_zeroize(kek, sizeof kek); fhsm_zeroize(dek, sizeof dek); fhsm_zeroize(pt, l);
    f = fopen(at(dst), "wb");
    if (!f || fwrite(buf, 1, n, f) != n || fclose(f) != 0) die("zero_dek: write");
}

/* What C reads back. Runs on a copy, because a login rewrites the file. */
static void describe(const char *name, fhsm_role_t role, const char *pin) {
    char cp[1100];
    snprintf(cp, sizeof cp, "%s.describe", at(name));
    char cmd[2400];
    snprintf(cmd, sizeof cmd, "cp '%s' '%s' && { [ ! -e '%s.tpm' ] || cp '%s.tpm' '%s.tpm'; }",
             at(name), cp, at(name), at(name), cp);
    if (system(cmd) != 0) die("describe: copy");
    fhsm_token_t *t = NULL;
    fhsm_rv_t rv = fhsm_token_load(cp, &t);
    fprintf(man, "token\t%s\tload=0x%x", name, (unsigned)rv);
    if (rv == FHSM_RV_OK) {
        fprintf(man, "\tlabel=%s\tserial=%s\tuser_initialized=%d\tso_locked=%d\tuser_locked=%d",
                fhsm_token_label(t), fhsm_token_serial(t), fhsm_token_user_initialized(t),
                fhsm_token_is_locked(t, FHSM_ROLE_SO), fhsm_token_is_locked(t, FHSM_ROLE_USER));
        if (pin) {
            fhsm_rv_t lr = fhsm_token_login(t, role, pin, strlen(pin));
            fprintf(man, "\tlogin_%s=0x%x", role == FHSM_ROLE_SO ? "so" : "user", (unsigned)lr);
            uint32_t hs[64];
            size_t cnt = 0;
            if (lr == FHSM_RV_OK && fhsm_token_object_find(t, NULL, NULL, hs, 64, &cnt) == FHSM_RV_OK) {
                fprintf(man, "\tobjects=%zu\n", cnt);
                for (size_t i = 0; i < cnt && i < 64; i++) {
                    const uint8_t *v, *id; size_t vl, il, ll; uint32_t c, k; uint8_t fl = 0;
                    const char *lab;
                    must(fhsm_token_object_get(t, hs[i], &v, &vl, &c, &k), "get");
                    must(fhsm_token_object_get_flags(t, hs[i], &fl), "flags");
                    fprintf(man, "object\t%s\thandle=%u\tclass=%u\tkey_type=%u\tflags=0x%02x\tvalue=",
                            name, hs[i], c, k, fl);
                    hex(man, v, vl);
                    if (fhsm_token_object_get_label(t, hs[i], &lab, &ll) == FHSM_RV_OK)
                        fprintf(man, "\tlabel=%.*s", (int)ll, lab);
                    if (fhsm_token_object_get_id(t, hs[i], &id, &il) == FHSM_RV_OK) {
                        fprintf(man, "\tid="); hex(man, id, il);
                    }
                    fputc('\n', man);
                }
                fhsm_token_close(t);
                unlink(cp);
                strcat(cp, ".tpm");
                unlink(cp);
                return;
            }
        }
        fhsm_token_close(t);
    }
    fputc('\n', man);
    unlink(cp);
    strcat(cp, ".tpm");
    unlink(cp);
}

static void describe_all(void) {
    describe("fresh.tok", FHSM_ROLE_SO, SO_PIN);
    describe("user_initialized.tok", FHSM_ROLE_USER, USER_PIN);
    describe("locked.tok", FHSM_ROLE_USER, USER_PIN);
    describe("multi_object.tok", FHSM_ROLE_USER, USER_PIN);
    describe("reinit.tok", FHSM_ROLE_SO, SO_PIN);
    describe("zero_dek_2_5_0.tok", FHSM_ROLE_USER, USER_PIN);
    setenv("FHSM_TPM_SEALING", "1", 1);
    describe("tpm_sealed.tok", FHSM_ROLE_USER, USER_PIN);
    unsetenv("FHSM_TPM_SEALING");
    fclose(man);
}

/* Everything a token shows without a PIN; the serial is random, so it is left out. */
static void public_view(const char *path) {
    FILE *f = fopen(path, "rb");
    long size = -1;
    if (f) { fseek(f, 0, SEEK_END); size = ftell(f); fclose(f); }
    char tpm[1100];
    snprintf(tpm, sizeof tpm, "%s.tpm", path);
    fhsm_token_t *t = NULL;
    fhsm_rv_t rv = fhsm_token_load(path, &t);
    printf("%s	size=%ld	tpm=%d	load=0x%x", path, size, access(tpm, F_OK) == 0, (unsigned)rv);
    if (rv == FHSM_RV_OK) {
        printf("	label=%s	user_initialized=%d	failed_so=%u	failed_user=%u	so_locked=%d	user_locked=%d",
               fhsm_token_label(t), fhsm_token_user_initialized(t),
               (unsigned)fhsm_token_failed_count(t, FHSM_ROLE_SO), (unsigned)fhsm_token_failed_count(t, FHSM_ROLE_USER),
               fhsm_token_is_locked(t, FHSM_ROLE_SO), fhsm_token_is_locked(t, FHSM_ROLE_USER));
        fhsm_token_close(t);
    }
    putchar('\n');
}

static void rev_save(const char *name, unsigned long long crl, const char *const *lines, size_t n) {
    fhsm_rev_db_t d = { 0 };
    char err[FHSM_REV_ERR_MAX];
    d.crl_number = crl;
    for (size_t i = 0; i < n; i++) {
        fhsm_rev_entry_t e = { 0 };
        char ser[130], date[16], reason[32];
        if (sscanf(lines[i], "%129s %15s %31s", ser, date, reason) != 3) die("rev line");
        if (!fhsm_rev_hex_to_bytes(ser, e.serial, sizeof e.serial, &e.serial_len)) die("rev serial");
        snprintf(e.date, sizeof e.date, "%s", date);
        e.reason = strcmp(reason, "-") ? fhsm_rev_reason_code(reason) : -1;
        if (fhsm_rev_db_add(&d, &e, err, sizeof err) != FHSM_REV_OK) die(err);
    }
    unlink(at(name));
    if (fhsm_rev_db_save(at(name), &d, err, sizeof err) != FHSM_REV_OK) die(err);
    fhsm_rev_db_free(&d);
}

static void rev_craft(const char *name, const char *text) {
    FILE *f = fopen(at(name), "w");
    if (!f || fputs(text, f) < 0 || fclose(f) != 0) die("rev craft");
}

static void rev_describe(FILE *tsv, const char *name) {
    fhsm_rev_db_t d = { 0 };
    char err[FHSM_REV_ERR_MAX] = "";
    int rv = fhsm_rev_db_load(at(name), &d, err, sizeof err);
    for (char *p = err; *p; p++) if (*p == '\n' || *p == '\t') *p = ' ';
    fprintf(tsv, "db\t%s\trv=%d\tcrl_number=%llu\tentries=%zu\terr=%s\n", name, rv, d.crl_number, d.n, err);
    for (size_t i = 0; rv == FHSM_REV_OK && i < d.n; i++) {
        int64_t when = 0;
        fprintf(tsv, "entry\t%s\tserial=", name);
        hex(tsv, d.e[i].serial, d.e[i].serial_len);
        fprintf(tsv, "\tdate=%s\tepoch=%lld\treason=%d\n", d.e[i].date,
                fhsm_rev_date_to_time(d.e[i].date, &when) ? (long long)when : -1LL, d.e[i].reason);
    }
    fhsm_rev_db_free(&d);
}

int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "public")) {
        for (int i = 2; i < argc; i++) public_view(argv[i]);
        return 0;
    }
    if (argc != 3 || (strcmp(argv[1], "make") && strcmp(argv[1], "describe")))
        die("usage: gen_token make|describe DIR | gen_token public FILE...");
    out = argv[2];
    man = fopen(at("manifest.tsv"), "w");
    if (!man) die("manifest");
    if (!strcmp(argv[1], "describe")) {
        describe_all();
        return 0;
    }

    /* fresh: C_InitToken only; the user PIN was never set. */
    fhsm_token_close(fresh("fresh.tok", "golden-fresh"));

    /* user_initialized: SO set the user PIN, no objects. */
    fhsm_token_t *t = fresh("user_initialized.tok", "golden-user");
    init_user(t);
    fhsm_token_close(t);

    /* locked: 2 wrong SO PINs, 5 wrong user PINs (user locked). */
    t = fresh("locked.tok", "golden-locked");
    init_user(t);
    for (int i = 0; i < 2; i++) (void)fhsm_token_login(t, FHSM_ROLE_SO, WRONG, strlen(WRONG));
    for (int i = 0; i < 5; i++) (void)fhsm_token_login(t, FHSM_ROLE_USER, WRONG, strlen(WRONG));
    fhsm_token_close(t);

    build_multi("multi_object.tok");

    /* reinit: the multi-object token wiped by C_InitToken on an existing token. */
    build_multi("reinit.tok");
    must(fhsm_token_load(at("reinit.tok"), &t), "load reinit");
    must(fhsm_token_reinit(t, SO_PIN, "golden-reinit"), "reinit");
    fhsm_token_close(t);

    zero_dek("multi_object.tok", "zero_dek_2_5_0.tok");

    /* tpm_sealed: the same contents with FHSM_TPM_SEALING=1, sealed through the
     * tests/tpm2-stub.sh seam. The .tpm is the stub's blob, not a real TPM's. */
    setenv("FHSM_TPM_SEALING", "1", 1);
    t = fresh("tpm_sealed.tok", "golden-tpm");
    init_user(t);
    fhsm_token_close(t);
    unsetenv("FHSM_TPM_SEALING");

    describe_all();

    static const char *const three[] = {
        "01A2 20260101000000Z keyCompromise",
        "00FF10 20260215123000Z -",
        "7B 20251231235959Z superseded",
    };
    rev_save("rev_empty.db", 0, NULL, 0);
    rev_save("rev_three.db", 7, three, 3);
    rev_craft("rev_month13.db", "A1 20261340990000Z -\n");           /* DIV-016: C accepts */
    rev_craft("rev_bad_date.db", "A1 2026010100000Z -\n");
    rev_craft("rev_bad_reason.db", "A1 20260101000000Z notAReason\n");
    rev_craft("rev_odd_serial.db", "A1B 20260101000000Z -\n");

    FILE *tsv = fopen(at("revocation.tsv"), "w");
    if (!tsv) die("revocation.tsv");
    const char *dbs[] = { "rev_empty.db", "rev_three.db", "rev_month13.db",
                          "rev_bad_date.db", "rev_bad_reason.db", "rev_odd_serial.db" };
    for (size_t i = 0; i < sizeof dbs / sizeof *dbs; i++) rev_describe(tsv, dbs[i]);
    fclose(tsv);
    return 0;
}
