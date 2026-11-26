/* p11_lifecycle.c LIB BASE --- slice 1 of PHASE4_PLAN.md §2: call sequences through the
 * fifteen lifecycle, slot, session and login entry points, with every return code and output
 * byte, one row per call ("call TAB rv TAB output-hex", "-" for none).
 *
 * Each scenario runs in its own forked child with its own tokens directory, BASE/<n>, so a
 * latched ERROR, a lockout or a fork reset stays inside it. Outputs are pre-filled with 0xAA,
 * so a byte the module did not write shows as aa. Token serials are masked (random per token);
 * nothing else varies, so C and hybrid must print the same (harness step 4g), and each
 * scenario's audit log must normalise the same (corpus_norm.py). stdout is unbuffered so the
 * module's stderr lines fall where they were written.
 *
 * Written from the C (src/fhsm_pkcs11.c:393-1789) before the Rust, as its characterisation. */
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

typedef unsigned long UL;
typedef struct { UL mech; void *p; UL len; } Mech;
typedef struct { UL type; void *p; UL len; } Attr;

static UL (*Init)(void *), (*Fin)(void *), (*Info)(void *);
static UL (*SlotList)(unsigned char, UL *, UL *), (*SlotInfo)(UL, void *), (*TokInfo)(UL, void *);
static UL (*Open)(UL, UL, void *, void *, UL *), (*Close)(UL), (*CloseAll)(UL);
static UL (*SessInfo)(UL, void *), (*Login)(UL, UL, const char *, UL), (*Logout)(UL);
static UL (*InitTok)(UL, const char *, UL, const char *), (*InitPIN)(UL, const char *, UL);
static UL (*SetPIN)(UL, const char *, UL, const char *, UL);
static UL (*DigInit)(UL, Mech *), (*DigUpd)(UL, const void *, UL);
static UL (*GenPair)(UL, Mech *, Attr *, UL, Attr *, UL, UL *, UL *), (*SignInit)(UL, Mech *, UL);
static UL (*Sign)(UL, const void *, UL, void *, UL *);

static unsigned char buf[512];
static char dir[600];

enum { INFO = 88, SLOT = 112, TOK = 208, SESS = 32 };
#define RW  6UL   /* CKF_RW_SESSION | CKF_SERIAL_SESSION */
#define RO  4UL
#define SO_PIN   "so-pin-123"
#define USER_PIN "user-pin-1"
#define LABEL    "lifecycle                       "   /* 32, space-padded */
#define PIN65    "0123456789012345678901234567890123456789012345678901234567890123x"

static void row(const char *call, UL rv, size_t n) {
    printf("%s\t%#lx\t", call, rv);
    if (!n) printf("-");
    for (size_t i = 0; i < n; ++i) printf("%02x", buf[i]);
    printf("\n");
}

/* Run `expr` with buf pre-filled, print `n` bytes of it. */
#define CALL(name, n, expr) do { memset(buf, 0xAA, sizeof buf); UL rv_ = (expr); row(name, rv_, n); } while (0)
/* The handle C_OpenSession wrote into buf. */
#define H (*(UL *)buf)

static void tokinfo(const char *name, UL slot) {
    memset(buf, 0xAA, sizeof buf);
    UL rv = TokInfo(slot, buf);
    if (rv == 0) memset(buf + 80, 'S', 16);   /* serialNumber, after label, manufacturer, model */
    row(name, rv, TOK);
}

static UL open_rw(UL slot) {
    CALL("open rw", 8, Open(slot, RW, NULL, NULL, (UL *)buf));
    return H;
}

static void slotlist(const char *name, unsigned char present, UL cap) {
    UL n = cap;
    memset(buf, 0xAA, sizeof buf);
    UL rv = SlotList(present, (UL *)buf, &n);
    row(name, rv, 40);
    printf("count\t%lu\n", n);
}

/* Every entry point before C_Initialize: C runs most of them (DIV-051). */
static void s_preinit(void) {
    unsetenv("FHSM_INTEGRITY_ALLOW_UNSIGNED");
    CALL("info unsigned-unset", INFO, Info(buf));
    tokinfo("tokinfo 0 unsigned-unset", 0);
    setenv("FHSM_INTEGRITY_ALLOW_UNSIGNED", "1", 1);
    CALL("info", INFO, Info(buf));
    CALL("info NULL", 0, Info(NULL));
    CALL("open 0 blank", 8, Open(0, RW, NULL, NULL, (UL *)buf));
    CALL("close 1", 0, Close(1));
    CALL("closeall 0", 0, CloseAll(0));
    CALL("sessinfo 1", SESS, SessInfo(1, buf));
    CALL("login 1 so", 0, Login(1, 0, SO_PIN, 10));
    CALL("logout 1", 0, Logout(1));
    CALL("initpin 1", 0, InitPIN(1, USER_PIN, 10));
    CALL("setpin 1", 0, SetPIN(1, SO_PIN, 10, SO_PIN, 10));
    CALL("inittoken 0", 0, InitTok(0, SO_PIN, 10, LABEL));
    UL h = open_rw(0);
    CALL("login so", 0, Login(h, 0, SO_PIN, 10));
    CALL("sessinfo", SESS, SessInfo(h, buf));
    CALL("finalize", 0, Fin(NULL));
    CALL("finalize again", 0, Fin(NULL));
    CALL("sessinfo after finalize", SESS, SessInfo(h, buf));
    CALL("initialize", 0, Init(NULL));
    CALL("initialize again", 0, Init(NULL));
    CALL("finalize", 0, Fin(NULL));
    CALL("finalize reserved", 0, Fin((void *)1));
}

static void s_slots(void) {
    CALL("initialize", 0, Init(NULL));
    CALL("slotlist count NULL", 0, SlotList(0, NULL, NULL));
    CALL("slotlist all count", 8, SlotList(0, NULL, (UL *)buf));
    CALL("slotlist present count", 8, SlotList(1, NULL, (UL *)buf));
    slotlist("slotlist all cap 2", 0, 2);
    slotlist("slotlist all cap 4", 0, 4);
    slotlist("slotlist present cap 4", 1, 4);
    for (UL s = 0; s <= 4; ++s) {
        char name[32];
        snprintf(name, sizeof name, "slotinfo %lu", s);
        CALL(name, SLOT, SlotInfo(s, buf));
        snprintf(name, sizeof name, "tokinfo %lu", s);
        tokinfo(name, s);
    }
    CALL("slotinfo NULL", 0, SlotInfo(0, NULL));
    CALL("tokinfo NULL", 0, TokInfo(0, NULL));
    CALL("tokinfo 9 NULL", 0, TokInfo(9, NULL));

    CALL("inittoken slot 4", 0, InitTok(4, SO_PIN, 10, LABEL));
    CALL("inittoken NULL pin", 0, InitTok(0, NULL, 10, LABEL));
    CALL("inittoken len 3", 0, InitTok(0, "abc", 3, LABEL));
    CALL("inittoken len 65", 0, InitTok(0, PIN65, 65, LABEL));
    CALL("inittoken embedded nul", 0, InitTok(0, "so-pin\0-123", 11, LABEL));
    CALL("inittoken NULL label", 0, InitTok(0, SO_PIN, 10, NULL));
    CALL("inittoken len 4 fresh", 0, InitTok(1, "abcd", 4, LABEL));
    CALL("inittoken len 7 fresh", 0, InitTok(1, "abcdefg", 7, LABEL));
    CALL("inittoken 0", 0, InitTok(0, SO_PIN, 10, LABEL));
    CALL("inittoken 2 label all spaces", 0, InitTok(2, SO_PIN, 10, "                                "));
    CALL("inittoken 3 label unpadded", 0, InitTok(3, SO_PIN, 10, "abcdefghijklmnopqrstuvwxyz012345"));
    CALL("slotlist present count", 8, SlotList(1, NULL, (UL *)buf));
    slotlist("slotlist present cap 4", 1, 4);
    for (UL s = 0; s < 4; ++s) {
        char name[32];
        snprintf(name, sizeof name, "slotinfo %lu", s);
        CALL(name, SLOT, SlotInfo(s, buf));
        snprintf(name, sizeof name, "tokinfo %lu", s);
        tokinfo(name, s);
    }
    CALL("inittoken 0 wrong so", 0, InitTok(0, "so-pin-999", 10, LABEL));
    tokinfo("tokinfo 0 after a wrong SO pin", 0);
    CALL("inittoken 0 reinit", 0, InitTok(0, SO_PIN, 10, "relabelled                      "));
    tokinfo("tokinfo 0 reinit", 0);
    CALL("inittoken 0 reinit again", 0, InitTok(0, SO_PIN, 10, LABEL));
    UL h = open_rw(0);
    CALL("inittoken 0 session exists", 0, InitTok(0, SO_PIN, 10, LABEL));
    CALL("inittoken 1 other slot", 0, InitTok(1, SO_PIN, 10, LABEL));
    CALL("close", 0, Close(h));
    CALL("finalize", 0, Fin(NULL));
}

static void s_sessions(void) {
    CALL("initialize", 0, Init(NULL));
    CALL("open NULL out", 0, Open(0, RW, NULL, NULL, NULL));
    CALL("open slot 4", 8, Open(4, RW, NULL, NULL, (UL *)buf));
    CALL("open no serial", 8, Open(0, 2, NULL, NULL, (UL *)buf));
    CALL("open blank slot", 8, Open(0, RW, NULL, NULL, (UL *)buf));
    CALL("inittoken 0", 0, InitTok(0, SO_PIN, 10, LABEL));
    CALL("inittoken 1", 0, InitTok(1, SO_PIN, 10, LABEL));
    UL h1 = open_rw(0);
    CALL("open ro", 8, Open(0, RO, NULL, NULL, (UL *)buf));
    UL h2 = H;
    CALL("sessinfo rw public", SESS, SessInfo(h1, buf));
    CALL("sessinfo ro public", SESS, SessInfo(h2, buf));
    CALL("sessinfo NULL", 0, SessInfo(h1, NULL));
    CALL("sessinfo 0", SESS, SessInfo(0, buf));
    CALL("sessinfo 999", SESS, SessInfo(999, buf));
    CALL("login so with ro open", 0, Login(h1, 0, SO_PIN, 10));
    CALL("close ro", 0, Close(h2));
    CALL("close ro again", 0, Close(h2));
    CALL("login type 3", 0, Login(h1, 3, SO_PIN, 10));
    CALL("login so wrong", 0, Login(h1, 0, "so-pin-000", 10));
    CALL("login so", 0, Login(h1, 0, SO_PIN, 10));
    CALL("login so again", 0, Login(h1, 0, SO_PIN, 10));
    CALL("login user while so", 0, Login(h1, 1, USER_PIN, 10));
    CALL("sessinfo rw so", SESS, SessInfo(h1, buf));
    CALL("open ro while so", 8, Open(0, RO, NULL, NULL, (UL *)buf));
    UL h3 = open_rw(0);
    CALL("sessinfo second rw so", SESS, SessInfo(h3, buf));
    UL h4 = open_rw(1);
    CALL("sessinfo slot 1", SESS, SessInfo(h4, buf));
    CALL("login user not initialised", 0, Login(h4, 1, USER_PIN, 10));

    CALL("initpin NULL", 0, InitPIN(h1, NULL, 10));
    CALL("initpin len 3", 0, InitPIN(h1, "abc", 3));
    CALL("initpin len 65", 0, InitPIN(h1, PIN65, 65));
    CALL("initpin embedded nul", 0, InitPIN(h1, "user\0pin-1", 10));
    CALL("initpin bad handle", 0, InitPIN(999, USER_PIN, 10));
    CALL("initpin not so", 0, InitPIN(h4, USER_PIN, 10));
    CALL("initpin len 4", 0, InitPIN(h1, "1234", 4));
    CALL("initpin", 0, InitPIN(h1, USER_PIN, 10));
    tokinfo("tokinfo user pin set", 0);

    CALL("setpin NULL old", 0, SetPIN(h1, NULL, 10, SO_PIN, 10));
    CALL("setpin NULL new", 0, SetPIN(h1, SO_PIN, 10, NULL, 10));
    CALL("setpin old len 3", 0, SetPIN(h1, "abc", 3, SO_PIN, 10));
    CALL("setpin new len 65", 0, SetPIN(h1, SO_PIN, 10, PIN65, 65));
    CALL("setpin new embedded nul", 0, SetPIN(h1, SO_PIN, 10, "so\0pin-123", 10));
    CALL("setpin bad handle", 0, SetPIN(999, SO_PIN, 10, SO_PIN, 10));
    CALL("setpin not logged in", 0, SetPIN(h4, SO_PIN, 10, SO_PIN, 10));
    CALL("setpin so", 0, SetPIN(h1, SO_PIN, 10, "so-pin-456", 10));
    CALL("setpin so wrong old", 0, SetPIN(h1, "so-pin-000", 10, "so-pin-456", 10));

    CALL("logout bad handle", 0, Logout(999));
    CALL("logout so", 0, Logout(h1));
    CALL("logout again", 0, Logout(h3));
    CALL("initpin after logout", 0, InitPIN(h1, USER_PIN, 10));
    CALL("login user wrong", 0, Login(h1, 1, "user-pin-0", 10));
    CALL("login user", 0, Login(h3, 1, USER_PIN, 10));
    CALL("login user again", 0, Login(h1, 1, USER_PIN, 10));
    CALL("login so while user", 0, Login(h1, 0, SO_PIN, 10));
    CALL("sessinfo rw user", SESS, SessInfo(h1, buf));
    CALL("open ro while user", 8, Open(0, RO, NULL, NULL, (UL *)buf));
    UL h5 = H;
    CALL("sessinfo ro user", SESS, SessInfo(h5, buf));
    CALL("setpin user", 0, SetPIN(h5, USER_PIN, 10, "user-pin-2", 10));
    CALL("logout user", 0, Logout(h5));
    CALL("sessinfo after logout", SESS, SessInfo(h1, buf));
    CALL("login user", 0, Login(h1, 1, USER_PIN, 10));

    /* The last session on a token logs it out, with an audited LOGOUT. */
    CALL("close h1", 0, Close(h1));
    CALL("close h3", 0, Close(h3));
    CALL("sessinfo ro still user", SESS, SessInfo(h5, buf));
    CALL("close h5 (last on slot 0)", 0, Close(h5));
    UL h6 = open_rw(0);
    CALL("sessinfo reopened", SESS, SessInfo(h6, buf));
    CALL("closeall 1", 0, CloseAll(1));
    CALL("closeall 4", 0, CloseAll(4));
    CALL("sessinfo slot 1 after closeall 1", SESS, SessInfo(h4, buf));
    CALL("closeall 0", 0, CloseAll(0));
    CALL("sessinfo slot 1 after closeall 0", SESS, SessInfo(h4, buf));
    CALL("sessinfo slot 0 after closeall 0", SESS, SessInfo(h6, buf));
    CALL("close 0", 0, Close(0));
    CALL("close 999", 0, Close(999));
    CALL("finalize", 0, Fin(NULL));
}

/* C_Login(CKU_CONTEXT_SPECIFIC) and the operation tables the entry points reach. */
static void s_context(void) {
    Mech sha256 = { 0x250, NULL, 0 };
    CALL("initialize", 0, Init(NULL));
    CALL("inittoken 0", 0, InitTok(0, SO_PIN, 10, LABEL));
    UL h = open_rw(0);
    CALL("login so", 0, Login(h, 0, SO_PIN, 10));
    CALL("initpin", 0, InitPIN(h, USER_PIN, 10));
    CALL("logout", 0, Logout(h));
    CALL("context bad handle 0", 0, Login(0, 2, USER_PIN, 10));
    CALL("context bad handle 999", 0, Login(999, 2, USER_PIN, 10));
    CALL("context no op", 0, Login(h, 2, USER_PIN, 10));
    CALL("digestinit", 0, DigInit(h, &sha256));
    CALL("context not logged in", 0, Login(h, 2, USER_PIN, 10));
    CALL("login user", 0, Login(h, 1, USER_PIN, 10));
    CALL("context wrong pin", 0, Login(h, 2, "user-pin-0", 10));
    CALL("context", 0, Login(h, 2, USER_PIN, 10));
    CALL("digestupdate", 0, DigUpd(h, "abc", 3));

    /* The grant is what a CKA_ALWAYS_AUTHENTICATE key's C_Sign consumes. C stores the flag on
     * private keys only, so an EC pair; ECDSA is randomised, so only rv and length print. */
    Mech ecgen = { 0x1040, NULL, 0 }, ecdsa = { 0x1044, NULL, 0 };   /* EC_KEY_PAIR_GEN, ECDSA_SHA256 */
    unsigned char p256[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    unsigned char yes = 1, no = 0;
    Attr pub[] = { { 0x180, p256, sizeof p256 }, { 0x10A, &yes, 1 }, { 0x1, &no, 1 } };
    Attr priv[] = { { 0x108, &yes, 1 }, { 0x202, &yes, 1 }, { 0x1, &no, 1 } };
    UL hpub = 0, hpriv = 0, siglen;
    CALL("generate always-authenticate pair", 0, GenPair(h, &ecgen, pub, 3, priv, 3, &hpub, &hpriv));
    CALL("signinit", 0, SignInit(h, &ecdsa, hpriv));
    siglen = 64;
    CALL("sign without context login", 0, Sign(h, "abc", 3, buf, &siglen));
    CALL("signinit", 0, SignInit(h, &ecdsa, hpriv));
    CALL("context for the sign", 0, Login(h, 2, USER_PIN, 10));
    siglen = 64;
    CALL("sign after context login", 0, Sign(h, "abc", 3, buf, &siglen));
    printf("siglen\t%lu\n", siglen);

    /* A closed session's operation does not reach the handle's next owner. */
    CALL("close", 0, Close(h));
    CALL("digestupdate on the closed handle", 0, DigUpd(h, "abc", 3));
    h = open_rw(0);
    CALL("digestupdate on reused handle", 0, DigUpd(h, "abc", 3));
    CALL("digestinit", 0, DigInit(h, &sha256));
    /* Nor across C_Finalize. */
    CALL("finalize with an active op", 0, Fin(NULL));
    CALL("initialize", 0, Init(NULL));
    h = open_rw(0);
    CALL("digestupdate after restart", 0, DigUpd(h, "abc", 3));
    CALL("sessinfo after restart (logged out)", SESS, SessInfo(h, buf));
    CALL("finalize", 0, Fin(NULL));
}

static void s_lockout(void) {
    CALL("initialize", 0, Init(NULL));
    CALL("inittoken 0", 0, InitTok(0, SO_PIN, 10, LABEL));
    UL h = open_rw(0);
    CALL("login so", 0, Login(h, 0, SO_PIN, 10));
    CALL("initpin", 0, InitPIN(h, USER_PIN, 10));
    CALL("logout", 0, Logout(h));
    char name[40];
    for (int i = 1; i <= 5; ++i) {
        snprintf(name, sizeof name, "login user wrong %d", i);
        CALL(name, 0, Login(h, 1, "user-pin-0", 10));
        snprintf(name, sizeof name, "tokinfo after user %d", i);
        tokinfo(name, 0);
    }
    CALL("login user right, locked", 0, Login(h, 1, USER_PIN, 10));
    for (int i = 1; i <= 5; ++i) {
        snprintf(name, sizeof name, "login so wrong %d", i);
        CALL(name, 0, Login(h, 0, "so-pin-000", 10));
    }
    tokinfo("tokinfo both locked", 0);
    CALL("close", 0, Close(h));
    CALL("inittoken 0 so locked", 0, InitTok(0, SO_PIN, 10, LABEL));
    CALL("finalize", 0, Fin(NULL));
}

/* A forked child adopts nothing (#125): its C_Initialize drops the parent's state. */
static void s_fork(void) {
    CALL("initialize", 0, Init(NULL));
    CALL("inittoken 0", 0, InitTok(0, SO_PIN, 10, LABEL));
    UL h = open_rw(0);
    CALL("login so", 0, Login(h, 0, SO_PIN, 10));
    printf("--- child\n");
    pid_t p = fork();
    if (p == 0) {
        CALL("child sessinfo before initialize", SESS, SessInfo(h, buf));
        CALL("child initialize", 0, Init(NULL));
        CALL("child sessinfo", SESS, SessInfo(h, buf));
        UL c = open_rw(0);
        CALL("child sessinfo new", SESS, SessInfo(c, buf));
        CALL("child login so", 0, Login(c, 0, SO_PIN, 10));
        CALL("child finalize", 0, Fin(NULL));
        _exit(0);
    }
    int st;
    waitpid(p, &st, 0);
    printf("--- child exit %d\n", WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st));
    CALL("parent sessinfo", SESS, SessInfo(h, buf));
    CALL("finalize", 0, Fin(NULL));
}

/* The C_Initialize refusals. Each latches ERROR, so each has its own scenario. */
static void s_audit_off(void) {
    setenv("FHSM_AUDIT", "off", 1);
    CALL("initialize audit off", 0, Init(NULL));
    CALL("info in error", INFO, Info(buf));
    CALL("open in error", 8, Open(0, RW, NULL, NULL, (UL *)buf));
    CALL("inittoken in error", 0, InitTok(0, SO_PIN, 10, LABEL));
    CALL("closeall in error", 0, CloseAll(0));
    CALL("slotlist in error", 8, SlotList(0, NULL, (UL *)buf));
    tokinfo("tokinfo in error", 0);
    CALL("finalize in error", 0, Fin(NULL));
    CALL("initialize after error", 0, Init(NULL));
}

static void s_audit_zero(void) {
    setenv("FHSM_AUDIT", "0", 1);
    CALL("initialize audit 0", 0, Init(NULL));
}

static void s_audit_on(void) {
    setenv("FHSM_AUDIT", "on", 1);
    CALL("initialize audit on", 0, Init(NULL));
    CALL("finalize", 0, Fin(NULL));
}

static void s_bad_dir(void) {
    char d[700];
    snprintf(d, sizeof d, "%s/missing/tokens", dir);
    setenv("FHSM_TOKENS_DIR", d, 1);
    CALL("initialize unusable dir", 0, Init(NULL));
}

static void s_new_dir(void) {
    char d[700];
    snprintf(d, sizeof d, "%s/made", dir);
    setenv("FHSM_TOKENS_DIR", d, 1);
    CALL("initialize makes the dir", 0, Init(NULL));
    struct stat st;
    int ok = stat(d, &st) == 0;
    printf("made\t%s\t%o\n", ok ? "yes" : "no", ok ? (unsigned)(st.st_mode & 0777) : 0u);
    CALL("finalize", 0, Fin(NULL));
}

static void s_bad_key(void) {
    char k[700];
    snprintf(k, sizeof k, "%s/audit.key", dir);
    int fd = open(k, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0 || write(fd, "0123456789abcdef0123456789abcdef", 32) != 32) _exit(3);
    close(fd);
    chmod(k, 0644);
    CALL("initialize readable key", 0, Init(NULL));
}

static void s_stream(void) {
    setenv("FHSM_AUDIT_LOG", "/dev/null", 1);
    CALL("initialize to /dev/null", 0, Init(NULL));
    CALL("inittoken 0", 0, InitTok(0, SO_PIN, 10, LABEL));
    CALL("finalize", 0, Fin(NULL));
}

static void s_log_env(void) {
    char d[700], l[720];
    snprintf(d, sizeof d, "%s/named", dir);
    snprintf(l, sizeof l, "%s/audit.log", d);
    if (mkdir(d, 0700) != 0) _exit(3);
    setenv("FHSM_AUDIT_LOG", l, 1);
    CALL("initialize named log", 0, Init(NULL));
    CALL("finalize", 0, Fin(NULL));
    setenv("FHSM_AUDIT_LOG", "", 1);
    CALL("initialize empty FHSM_AUDIT_LOG", 0, Init(NULL));
    CALL("finalize", 0, Fin(NULL));
}

/* A log whose last line does not parse is refused rather than continued. */
static void s_bad_log(void) {
    char d[700], l[720], p[740];
    snprintf(d, sizeof d, "%s/bad", dir);
    snprintf(l, sizeof l, "%s/audit.log", d);
    snprintf(p, sizeof p, "%s.000001", l);
    if (mkdir(d, 0700) != 0) _exit(3);
    int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "not a record\n", 13) != 13) _exit(3);
    close(fd);
    setenv("FHSM_AUDIT_LOG", l, 1);
    CALL("initialize over an unparsable log", 0, Init(NULL));
}

#define SYM(v, name) do { *(void **)&v = dlsym(lib, name); if (!v) { fprintf(stderr, "no %s\n", name); return 2; } } while (0)

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: p11_lifecycle LIB BASE\n"); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0);
    void *lib = dlopen(argv[1], RTLD_NOW);
    if (!lib) { fprintf(stderr, "%s\n", dlerror()); return 2; }
    SYM(Init, "C_Initialize"); SYM(Fin, "C_Finalize"); SYM(Info, "C_GetInfo");
    SYM(SlotList, "C_GetSlotList"); SYM(SlotInfo, "C_GetSlotInfo"); SYM(TokInfo, "C_GetTokenInfo");
    SYM(Open, "C_OpenSession"); SYM(Close, "C_CloseSession"); SYM(CloseAll, "C_CloseAllSessions");
    SYM(SessInfo, "C_GetSessionInfo"); SYM(Login, "C_Login"); SYM(Logout, "C_Logout");
    SYM(InitTok, "C_InitToken"); SYM(InitPIN, "C_InitPIN"); SYM(SetPIN, "C_SetPIN");
    SYM(DigInit, "C_DigestInit"); SYM(DigUpd, "C_DigestUpdate");
    SYM(GenPair, "C_GenerateKeyPair"); SYM(SignInit, "C_SignInit"); SYM(Sign, "C_Sign");

    static const struct { const char *name; void (*f)(void); } sc[] = {
        { "preinit", s_preinit }, { "slots", s_slots }, { "sessions", s_sessions },
        { "context", s_context }, { "lockout", s_lockout }, { "fork", s_fork },
        { "audit-off", s_audit_off }, { "audit-zero", s_audit_zero }, { "audit-on", s_audit_on },
        { "bad-dir", s_bad_dir }, { "new-dir", s_new_dir }, { "bad-key", s_bad_key },
        { "stream", s_stream }, { "log-env", s_log_env }, { "bad-log", s_bad_log },
    };
    int bad = 0;
    for (size_t i = 0; i < sizeof sc / sizeof sc[0]; ++i) {
        snprintf(dir, sizeof dir, "%s/%zu", argv[2], i);
        if (mkdir(dir, 0700) != 0) { perror(dir); return 2; }
        printf("=== %zu %s\n", i, sc[i].name);
        pid_t p = fork();
        if (p == 0) {
            setenv("FHSM_TOKENS_DIR", dir, 1);
            sc[i].f();
            _exit(0);
        }
        int st;
        if (p < 0 || waitpid(p, &st, 0) != p) return 2;
        int code = WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
        printf("=== exit %d\n", code);
        bad |= code != 0;
    }
    return bad;
}
