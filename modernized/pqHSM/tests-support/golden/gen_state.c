/* Golden generator for Phase 4 slice 1b: the module state machine (src/fhsm_state.c). Writes
 * core/tests/golden/state.tsv.
 *
 * Runs the LEGACY src/fhsm_state.c, linked alone against the recording fhsm_audit_event
 * below, and records each call, what it returns, and the audit events it emits. The Rust test
 * (core/tests/state_golden.rs) replays every row.
 *
 *   gen_state OUTFILE
 *
 * Row: "<op> <args>" TAB "<result>" TAB "<events>" ("-" when none). An event is
 * ev<N>:rv=<rv>[:key=value...], with slot, session and role, always -1, -1, 0, checked here.
 * Every from/to pair of states 0-3 (and the out-of-range 5 and -1) is tried, reaching each
 * "from" through reset_after_fork and valid steps. The latched ERROR runs last, once with a
 * reason and once, in a forked child, with NULL.
 */
#include "fhsm_common.h"
#include "fhsm_audit.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static FILE *out;
static char call[300], events[1024];

fhsm_rv_t fhsm_audit_event(fhsm_audit_event_t ev, int slot, int session, fhsm_role_t role,
                           fhsm_rv_t rv, ...) {
    if (slot != -1 || session != -1 || role != FHSM_ROLE_NONE) abort();
    char e[512];
    int n = snprintf(e, sizeof e, "ev%d:rv=%#x", (int)ev, rv);
    va_list ap;
    va_start(ap, rv);
    for (const char *k; (k = va_arg(ap, const char *)) != NULL;)
        n += snprintf(e + n, sizeof e - (size_t)n, ":%s=%s", k, va_arg(ap, const char *));
    va_end(ap);
    if (events[0]) strncat(events, ",", sizeof events - strlen(events) - 1);
    strncat(events, e, sizeof events - strlen(events) - 1);
    return FHSM_RV_OK;
}

static void row(const char *result) {
    fprintf(out, "%s\t%s\t%s\n", call, result, events[0] ? events : "-");
    events[0] = 0;
}

static void op_get(void) {
    char r[16];
    snprintf(call, sizeof call, "get");
    snprintf(r, sizeof r, "%d", (int)fhsm_state_get());
    row(r);
}
static void op_set(int s) {
    char r[16];
    snprintf(call, sizeof call, "set %d", s);
    snprintf(r, sizeof r, "%#x", fhsm_state_set((fhsm_module_state_t)s));
    row(r);
}
static void op_fork_reset(void) {
    snprintf(call, sizeof call, "reset_after_fork");
    fhsm_state_reset_after_fork();
    row("-");
}
static void op_latch(const char *reason) {
    snprintf(call, sizeof call, "latch %s", reason ? reason : "NULL");
    fhsm_state_latch_error(reason);
    row("-");
}

/* POWER_OFF, then the valid steps to `s`. */
static void reach(int s) {
    static const int path[] = { 1, 2, 3 };
    op_fork_reset();
    for (int i = 0; i < s; ++i) op_set(path[i]);
}

int main(int argc, char **argv) {
    if (argc != 2 || !(out = fopen(argv[1], "w"))) { fprintf(stderr, "usage: gen_state OUT\n"); return 2; }
    fprintf(out, "# src/fhsm_state.c with a recording audit; see tests-support/golden/gen_state.c\n");

    op_get();
    static const int to[] = { 0, 1, 2, 3, 4, 5, -1 };
    for (int from = 0; from <= 3; ++from)
        for (size_t i = 0; i < sizeof to / sizeof to[0]; ++i) { reach(from); op_set(to[i]); op_get(); }

    /* reset_after_fork from each state, then a full walk and back. */
    for (int from = 0; from <= 3; ++from) { reach(from); op_fork_reset(); op_get(); }
    reach(3); op_set(2); op_set(3); op_set(0); op_get();

    /* The child's rows sit between "fork" and "join"; the parent's state is untouched. */
    snprintf(call, sizeof call, "fork");
    row("-");
    fflush(out);
    pid_t pid = fork();
    if (pid == 0) {
        /* Latch with a NULL reason, from INITIALIZED. */
        reach(2); op_latch(NULL); op_get(); op_latch(NULL); op_latch("later");
        op_set(0); op_fork_reset(); op_get();
        fflush(out);
        _exit(0);
    }
    int st;
    if (pid < 0 || waitpid(pid, &st, 0) != pid || !WIFEXITED(st) || WEXITSTATUS(st)) return 1;
    snprintf(call, sizeof call, "join");
    row("-");
    op_get();

    /* Latch with a reason longer than C's 128-byte buffer, from AUTHENTICATED. */
    char long_reason[201];
    memset(long_reason, 'r', 200);
    long_reason[200] = 0;
    reach(3); op_latch(long_reason); op_get();
    op_latch("again"); op_get();
    for (size_t i = 0; i < sizeof to / sizeof to[0]; ++i) op_set(to[i]);
    op_fork_reset(); op_get(); op_set(1);
    op_latch(""); op_get();

    return fclose(out) ? 1 : 0;
}
