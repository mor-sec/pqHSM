/* Golden generator for Phase 4 slice 1a: the session table (src/fhsm_session.c). Writes
 * core/tests/golden/session.tsv.
 *
 * Runs the LEGACY src/fhsm_session.c, linked alone against the scripted token below, and
 * records each call, what it returns, and the token calls it makes. The token is a stub on
 * purpose: the table is what is under test, and the real token is already Rust's (Phase 2).
 * The Rust test (core/tests/session_golden.rs) replays every row against the same stub.
 *
 *   gen_session OUTFILE
 *
 * Row: "<op> <args>" TAB "<result>" TAB "<token calls>" ("-" when none). Token 0 is NULL;
 * tokens 1-3 are stubs. Stub login: role not 1 or 2 is 0x7, PIN "bad" is 0xa0, the role
 * already logged in is 0x100, another role logged in is 0x104, otherwise 0 and the role is
 * set. "tokset T R" sets a stub's role directly, as another application's login would.
 */
#include "fhsm_common.h"
#include "fhsm_session.h"
#include "fhsm_token.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct fhsm_token_s { int role; };
static struct fhsm_token_s toks[4];
static char trace[512];
static char call[96];
static FILE *out;

static fhsm_token_t *tok(int i) { return i ? &toks[i] : NULL; }
static int tid(const fhsm_token_t *t) { return t ? (int)(t - toks) : 0; }

static void note(const char *s) {
    if (trace[0]) strncat(trace, ",", sizeof trace - strlen(trace) - 1);
    strncat(trace, s, sizeof trace - strlen(trace) - 1);
}

fhsm_rv_t fhsm_token_login(fhsm_token_t *t, fhsm_role_t role, const char *pin, size_t pin_len) {
    fhsm_rv_t rv;
    char s[32];
    if (role != FHSM_ROLE_SO && role != FHSM_ROLE_USER) rv = 0x7;
    else if (pin_len == 3 && memcmp(pin, "bad", 3) == 0) rv = 0xA0;
    else if (t->role == (int)role) rv = 0x100;
    else if (t->role) rv = 0x104;
    else { t->role = (int)role; rv = 0; }
    snprintf(s, sizeof s, "login(%d,%d)", tid(t), (int)role);
    note(s);
    return rv;
}

void fhsm_token_logout(fhsm_token_t *t) {
    char s[32];
    t->role = 0;
    snprintf(s, sizeof s, "logout(%d)", tid(t));
    note(s);
}

fhsm_role_t fhsm_token_current_role(const fhsm_token_t *t) { return (fhsm_role_t)t->role; }

void fhsm_zeroize(void *p, size_t n) { memset(p, 0, n); }

static void row(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void row(const char *fmt, ...) {
    char r[96];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r, sizeof r, fmt, ap);
    va_end(ap);
    fprintf(out, "%s\t%s\t%s\n", call, r, trace[0] ? trace : "-");
    trace[0] = 0;
}

static void op_open(unsigned long slot, unsigned long flags) {
    unsigned long h = 0;
    snprintf(call, sizeof call, "open %lu %lu", slot, flags);
    fhsm_rv_t rv = fhsm_session_open(slot, flags, &h);
    row("%#x %lu", rv, rv ? 0UL : h);
}
static void op_close(unsigned long h) {
    snprintf(call, sizeof call, "close %lu", h);
    row("%#x", fhsm_session_close(h));
}
static void op_login(unsigned long h, int role, const char *pin) {
    snprintf(call, sizeof call, "login %lu %d %s", h, role, pin);
    row("%#x", fhsm_session_login(h, (fhsm_role_t)role, pin, strlen(pin)));
}
static void op_logout(unsigned long h) {
    snprintf(call, sizeof call, "logout %lu", h);
    row("%#x", fhsm_session_logout(h));
}
static void op_attach(unsigned long h, int t) {
    snprintf(call, sizeof call, "attach %lu %d", h, t);
    row("%#x", fhsm_session_attach_token(h, tok(t)));
}
static void op_token(unsigned long h) {
    snprintf(call, sizeof call, "token %lu", h);
    row("%d", tid(fhsm_session_token(h)));
}
static void op_role(unsigned long h) {
    snprintf(call, sizeof call, "role %lu", h);
    row("%d", (int)fhsm_session_role(h));
}
static void op_info(unsigned long h) {
    unsigned long slot = 99, flags = 99;
    fhsm_role_t role = (fhsm_role_t)99;
    snprintf(call, sizeof call, "info %lu", h);
    fhsm_rv_t rv = fhsm_session_info(h, &slot, &flags, &role);
    row("%#x %lu %lu %d", rv, slot, flags, (int)role);
}
static void op_ro(int t) {
    snprintf(call, sizeof call, "ro_exists %d", t);
    row("%d", fhsm_session_ro_exists(tok(t)));
}
static void op_onslot(unsigned long slot) {
    snprintf(call, sizeof call, "exists_on_slot %lu", slot);
    row("%d", fhsm_session_exists_on_slot(slot));
}
static void op_reset(void) {
    snprintf(call, sizeof call, "reset_all");
    fhsm_session_reset_all();
    row("-");
}
static void op_tokset(int t, int role) {
    snprintf(call, sizeof call, "tokset %d %d", t, role);
    toks[t].role = role;
    row("-");
}

int main(int argc, char **argv) {
    if (argc != 2 || !(out = fopen(argv[1], "w"))) { fprintf(stderr, "usage: gen_session OUT\n"); return 2; }
    fprintf(out, "# src/fhsm_session.c against a stub token; see tests-support/golden/gen_session.c\n");

    /* Handle range: 0, the cap, past it, the top of unsigned long, and a free in-range one. */
    unsigned long bad[] = { 0, FHSM_MAX_SESSIONS, FHSM_MAX_SESSIONS + 1UL, ULONG_MAX, 5 };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        op_close(bad[i]); op_login(bad[i], 2, "pin"); op_logout(bad[i]); op_attach(bad[i], 1);
        op_token(bad[i]); op_role(bad[i]); op_info(bad[i]);
    }
    op_ro(0); op_ro(1); op_onslot(0);

    /* One session, no token attached yet. */
    op_open(0, 6);
    op_token(1); op_role(1); op_info(1); op_onslot(0); op_onslot(1); op_ro(0);
    op_login(1, 2, "pin"); op_logout(1);
    op_attach(1, 1); op_token(1); op_ro(1); op_info(1);

    /* Login paths: bad roles, bad PIN, OK, again, the other role. */
    op_login(1, 0, "pin"); op_login(1, 3, "pin"); op_login(1, 2, "bad");
    op_login(1, 2, "pin"); op_role(1); op_info(1);
    op_login(1, 2, "pin"); op_login(1, 1, "pin");
    op_logout(1); op_role(1); op_logout(1);

    /* A read-only sibling blocks an SO login, from either session; after it closes, allowed. */
    op_open(0, 4); op_attach(2, 1); op_ro(1); op_ro(0);
    op_login(1, 1, "pin"); op_login(2, 1, "pin"); op_login(2, 2, "pin"); op_logout(1);
    op_close(2); op_ro(1); op_login(1, 1, "pin"); op_role(1); op_logout(1);
    /* A read-only sibling with no token (handle 2, reused): ro_exists(NULL) sees it. */
    op_open(1, 4); op_ro(0); op_ro(1); op_onslot(1);
    /* A sibling's role follows the token, set out of band (handle 3). */
    op_open(0, 6); op_attach(3, 1); op_role(3); op_info(3);
    op_tokset(1, 2); op_role(1); op_role(3); op_info(1);
    op_logout(3); op_role(1); op_logout(1);
    /* An unattached session keeps its own role field. */
    op_attach(3, 0); op_role(3); op_info(3); op_logout(3); op_role(3);
    op_attach(3, 1); op_login(3, 2, "pin"); op_attach(3, 0); op_role(3); op_info(3);
    op_logout(3); op_role(3); op_attach(3, 1); op_role(3);
    /* "Already logged in" sets the entry's role too; a refused login does not. */
    op_login(1, 2, "pin"); op_login(1, 1, "pin"); op_attach(1, 0); op_role(1); op_attach(1, 1);

    /* Close: the last session on a token logs it out, an earlier one does not. */
    op_login(1, 2, "pin"); op_close(1); op_role(3); op_close(3); op_token(3);
    op_close(3); op_close(2);
    op_info(1);

    /* Handles are reused lowest first, with the role reset. */
    op_open(2, 6); op_open(3, 6); op_info(1); op_info(2); op_info(3);
    op_attach(1, 2); op_attach(2, 3); op_login(1, 2, "pin"); op_login(2, 1, "pin");
    op_close(1); op_open(2, 6); op_role(1); op_info(1);

    /* The cap: handles stop at FHSM_MAX_SESSIONS - 1, then HOST_MEMORY. */
    for (int i = 0; i < FHSM_MAX_SESSIONS + 1; ++i) op_open(3, 6);
    op_onslot(3); op_close(FHSM_MAX_SESSIONS - 1); op_open(3, 2);
    op_info(FHSM_MAX_SESSIONS - 1);

    /* reset_all drops every entry and touches no token. */
    op_tokset(2, 2); op_reset(); op_info(1); op_onslot(2); op_onslot(3); op_ro(0);
    op_role(1); op_close(1); op_logout(2);
    op_open(0, 6); op_info(1);

    return fclose(out) ? 1 : 0;
}
