//! pqHSM's HTTP service (Phase 6 of `analysis/pqHSM/MODERNIZATION_BRIEF.md`,
//! `analysis/pqHSM/PHASE6_PLAN.md`), replacing `service/fhsm_service.c`.
//!
//! The module is linked in and reached through `pqhsm-pkiops` loaded from the program itself
//! (`dlopen(NULL)`), so the binary exports `C_GetFunctionList` (hybrid.mk). Slice 1: the
//! arguments, the start-up order and the one-shot login (RULE-097), both listeners behind
//! SO_PEERCRED (RULE-067), the acceptor and workers, the request reader, `/health`, `/token`
//! and `/certificates`. Signing, verifying and OCSP are slices 2 and 3.

use std::ffi::{CStr, OsStr, c_char, c_int};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::Ordering;

/// stderr and stdout as C's fprintf and puts: a failed write is ignored, never a panic.
macro_rules! errw {
    ($($t:tt)*) => {{ use std::io::Write as _; let _ = write!(std::io::stderr(), $($t)*); }};
}
macro_rules! errln {
    ($($t:tt)*) => {{ use std::io::Write as _; let _ = writeln!(std::io::stderr(), $($t)*); }};
}
macro_rules! outln {
    ($($t:tt)*) => {{ use std::io::Write as _; let _ = writeln!(std::io::stdout(), $($t)*); }};
}

mod audit;
mod http;
mod listen;
mod ocsp;
mod serve;
mod state;

use listen::Listener;
use state::{Budget, Idents, POOL_MAX_LIMIT, Policy, Pool};

// The module's C ABI: named so its #[no_mangle] symbols are linked (one copy of std).
extern crate pqhsm_module;

unsafe extern "C" {
    /// pqhsm-p11's: the profile this binary was linked with (feature `all-mechanisms`).
    static fhsm_build_fips_strict: c_int;
}

const USAGE: &str = include_str!("usage.txt");
/// `CA_CERT_MAX`: a certificate file is shorter.
const CA_CERT_MAX: usize = 65536;

/// What every worker reads, set once before the first thread starts.
pub struct Svc {
    pub proxy_uid: u32,
    pub pool: Pool,
    pub policy: Policy,
    pub idents: Idents,
    pub budget: Budget,
    pub ca_cert: Vec<u8>,
    pub ocsp: Option<ocsp::Ocsp>,
}

static SVC: OnceLock<Svc> = OnceLock::new();

pub fn svc() -> &'static Svc {
    SVC.get().expect("set before the workers start")
}

extern "C" fn on_signal(_: c_int) {
    listen::STOP.store(true, Ordering::Relaxed);
    listen::wake_all();
}

extern "C" fn on_hup(_: c_int) {
    state::RELOAD.store(true, Ordering::Relaxed);
}

fn handle(sig: c_int, h: libc::sighandler_t, flags: c_int) {
    // SAFETY: a zeroed sigaction is valid; the handlers only touch atomics and write(2).
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = h;
        sa.sa_flags = flags;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

fn perror(what: &str) {
    let e = std::io::Error::last_os_error();
    errln!("pqhsm-service: {what}: {}", pqhsm_pkiops::strerror(&e));
}

/// C's `fopen`/`fread(CA_CERT_MAX)`/`feof`: a file that is empty, or fills the buffer, is
/// refused (so one of exactly 65536 bytes is too).
fn read_cert(path: &Path) -> Option<Vec<u8>> {
    let mut b = Vec::new();
    let f = std::fs::File::open(path).ok()?;
    std::io::Read::read_to_end(&mut std::io::Read::take(f, CA_CERT_MAX as u64), &mut b).ok()?;
    (!b.is_empty() && b.len() < CA_CERT_MAX).then_some(b)
}

/// A listening Unix socket at `path`, mode 0660, non-blocking; `Err` is the exit status.
fn bind(path: &[u8], what: &str) -> Result<c_int, c_int> {
    // SAFETY: all-zero is a valid sockaddr_un.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (d, s) in addr.sun_path.iter_mut().zip(path) {
        *d = *s as c_char;
    }
    let cpath = std::ffi::CString::new(path).unwrap_or_default();
    let sfx = if what.is_empty() {
        String::new()
    } else {
        format!(" ({what})")
    };
    // SAFETY: plain socket calls on a filled sockaddr_un.
    unsafe {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            perror("socket");
            return Err(1);
        }
        libc::unlink(cpath.as_ptr());
        let old = libc::umask(0o117);
        let size = size_of::<libc::sockaddr_un>() as libc::socklen_t;
        if libc::bind(fd, (&raw const addr).cast(), size) != 0 {
            perror(&format!("bind{sfx}"));
            libc::umask(old);
            return Err(1);
        }
        libc::umask(old);
        if libc::listen(fd, 64) != 0 {
            perror(&format!("listen{sfx}"));
            return Err(1);
        }
        libc::fcntl(
            fd,
            libc::F_SETFL,
            libc::fcntl(fd, libc::F_GETFL, 0) | libc::O_NONBLOCK,
        );
        Ok(fd)
    }
}

#[derive(Default)]
struct Args<'a> {
    sock: Option<&'a [u8]>,
    pin_file: Option<&'a [u8]>,
    policy: Option<&'a [u8]>,
    pub_path: Option<&'a [u8]>,
    ca_cert: Option<&'a [u8]>,
    rev_db: Option<&'a [u8]>,
    ocsp_label: Option<&'a [u8]>,
    responder: Option<&'a [u8]>,
    proxy_uid: i64,
    workers: i64,
    pool_max: i64,
    pub_workers: i64,
    queue_depth: i64,
    ocsp_days: i64,
}

enum Parsed<'a> {
    Run(Args<'a>),
    Profile,
    Usage,
}

/// C's `strtol(a, &e, 10)` then `!e || *e`: the whole text, or nothing. An empty text is 0.
fn num(a: &[u8], lo: i64, hi: i64) -> Option<i64> {
    let (v, end, _) = pqhsm_pkiops::strtol(a);
    (end == a.len() && (lo..=hi).contains(&v)).then_some(v)
}

fn parse<'a>(args: &[&'a [u8]]) -> Parsed<'a> {
    let mut a = Args {
        proxy_uid: -1,
        workers: 4,
        pool_max: 32,
        pub_workers: 2,
        queue_depth: 256,
        ocsp_days: 7,
        ..Args::default()
    };
    let mut i = 0;
    while i < args.len() {
        let opt = args[i];
        if opt == b"--profile" {
            return Parsed::Profile;
        }
        let Some(&val) = args.get(i + 1) else {
            return Parsed::Usage;
        };
        let text = match opt {
            b"--socket" => Some(&mut a.sock),
            b"--pin-file" => Some(&mut a.pin_file),
            b"--policy" => Some(&mut a.policy),
            b"--public-socket" => Some(&mut a.pub_path),
            b"--ca-cert" => Some(&mut a.ca_cert),
            b"--revocation-db" => Some(&mut a.rev_db),
            b"--ocsp-label" => Some(&mut a.ocsp_label),
            b"--responder-cert" => Some(&mut a.responder),
            _ => None,
        };
        let ok = if let Some(t) = text {
            *t = Some(val);
            true
        } else {
            let (field, lo, hi) = match opt {
                // a real uid: C took any long and truncated it, so 2^32 was root (DIV-080)
                b"--proxy-uid" => (&mut a.proxy_uid, 0, u32::MAX as i64 - 1),
                b"--workers" => (&mut a.workers, 1, 256),
                b"--pool-max" => (&mut a.pool_max, 1, POOL_MAX_LIMIT),
                b"--public-workers" => (&mut a.pub_workers, 1, 256),
                b"--queue-depth" => (&mut a.queue_depth, 1, 65536),
                b"--ocsp-days" => (&mut a.ocsp_days, 1, 365),
                _ => return Parsed::Usage,
            };
            num(val, lo, hi).map(|v| *field = v).is_some()
        };
        if !ok {
            return Parsed::Usage;
        }
        i += 2;
    }
    if a.sock.is_none() || a.proxy_uid < 0 || a.policy.is_none() {
        return Parsed::Usage;
    }
    Parsed::Run(a)
}

fn path(b: &[u8]) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(b))
}

fn shown(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// The checks C makes on the OCSP options before anything starts, and the responder they
/// configure (none without `--revocation-db`); the exit status on refusal.
fn check_ocsp(a: &Args, ca: &[u8]) -> Result<Option<ocsp::Ocsp>, c_int> {
    let refuse = |msg: &str| {
        errw!("{msg}");
        Err(2)
    };
    if (a.rev_db.is_some() || a.ocsp_label.is_some() || a.responder.is_some())
        && a.pub_path.is_none()
    {
        return refuse(
            "pqhsm-service: the OCSP options need --public-socket.\n  A relying party has no client certificate to present,\n  so /ocsp is on the anonymous listener and nowhere\n  else. Refused rather than configured and unreachable.\n",
        );
    }
    if a.rev_db.is_some() != a.ocsp_label.is_some() {
        return refuse(
            "pqhsm-service: --revocation-db and --ocsp-label go\n  together. One without the other is a responder that\n  could answer but has nothing to answer from, or one\n  that has the answers and cannot sign them.\n",
        );
    }
    if a.rev_db.is_some() && a.ca_cert.is_none() {
        return refuse(
            "pqhsm-service: --revocation-db without --ca-cert.\n  A CertID identifies a certificate by hashes of its\n  issuer's name and key, so without the CA certificate\n  every question would be answered `unknown` -- which\n  is a working responder that is useless.\n",
        );
    }
    if a.responder.is_some() && a.rev_db.is_none() {
        return refuse("pqhsm-service: --responder-cert without a responder.\n");
    }
    let (Some(db), Some(label)) = (a.rev_db, a.ocsp_label) else {
        return Ok(None);
    };
    if db.len() >= 4096 || label.len() >= 128 {
        return refuse("pqhsm-service: OCSP path or label too long.\n");
    }
    let mut responder_der = None;
    if let Some(rp) = a.responder {
        let Some(responder) = read_cert(&path(rp)) else {
            return refuse(&format!(
                "pqhsm-service: cannot read a certificate from {}\n",
                shown(rp)
            ));
        };
        let ca_path = a.ca_cert.map(shown);
        let rp = shown(rp);
        if let Err(e) =
            pqhsm_pki::revocation::check_responder(&responder, ca, Some(&rp), ca_path.as_deref())
        {
            return refuse(&format!("pqhsm-service: {}", e.msg));
        }
        responder_der = Some(responder);
    }
    // DIV-083: C starts, and then answers every request malformedRequest.
    if !pqhsm_pkiops::ca::is_certificate(ca) {
        return refuse(&format!(
            "pqhsm-service: {} is not a certificate.\n  The responder could answer no request.\n",
            a.ca_cert.map_or("the CA certificate".into(), shown)
        ));
    }
    // Read now, so an unreadable database stops the start; a missing one is an empty one.
    let o = ocsp::Ocsp::new(label.to_vec(), path(db), a.ocsp_days as i32, responder_der);
    if !o.refresh() {
        return refuse(&format!(
            "pqhsm-service: refusing to start: the revocation\n  database at {} could not be read.\n",
            shown(db)
        ));
    }
    Ok(Some(o))
}

/// The binary's `main` (`src/main.rs`).
///
/// # Safety
/// `argv` holds `argc` C strings, as `main` receives them.
pub unsafe fn pqhsm_service_main(argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: main's argv, argc entries.
    let args: Vec<&[u8]> = (1..argc.max(1) as usize)
        .map(|i| unsafe { CStr::from_ptr(*argv.add(i)) }.to_bytes())
        .collect();
    run(&args)
}

fn run(args: &[&[u8]]) -> c_int {
    let a = match parse(args) {
        Parsed::Profile => {
            // SAFETY: a constant the link provides.
            let strict = unsafe { fhsm_build_fips_strict } != 0;
            outln!(
                "{}",
                if strict {
                    "nist-approved-only"
                } else {
                    "all-mechanisms"
                }
            );
            return 0;
        }
        Parsed::Usage => {
            errw!("{USAGE}");
            return 2;
        }
        Parsed::Run(a) => a,
    };
    let (Some(sock), Some(policy_file)) = (a.sock, a.policy) else {
        return 2;
    };
    if a.ca_cert.is_some() && a.pub_path.is_none() {
        errw!(
            "pqhsm-service: --ca-cert without --public-socket.\n  The certificate is only served on the public\n  listener, so this asks for something nobody could\n  fetch. Refused rather than loaded and ignored.\n"
        );
        return 2;
    }
    let ca_cert = match a.ca_cert {
        None => Vec::new(),
        Some(p) => match read_cert(&path(p)) {
            Some(c) => c,
            None => {
                errw!(
                    "pqhsm-service: cannot read a certificate from {}\n  (missing, empty, or larger than {CA_CERT_MAX} bytes).\n",
                    shown(p)
                );
                return 2;
            }
        },
    };
    let ocsp = match check_ocsp(&a, &ca_cert) {
        Ok(o) => o,
        Err(rc) => return rc,
    };
    // SAFETY: a constant the link provides.
    if unsafe { fhsm_build_fips_strict } != 0 {
        // The composite mechanism is the only one the service signs with, and this build does
        // not approve it: C started and refused every signature (DIV-081).
        errw!(
            "pqhsm-service: this build is nist-approved-only, and the composite\n  ML-DSA-65+Ed25519 signature the service signs and verifies with\n  is not approved in it. Refusing to start a signing service that\n  could never sign.\n"
        );
        return 2;
    }
    let policy = Policy::new(path(policy_file));
    let Some(n) = policy.load() else {
        errw!(
            "pqhsm-service: cannot load the policy from {}.\n  Refusing to start: with no policy nothing is\n  authorised, and a service that answers every\n  request with a refusal is worse than one that\n  says why it will not run.\n",
            policy.path.display()
        );
        return 1;
    };
    errln!("pqhsm-service: policy loaded, {n} rule(s)");
    let pub_workers = if a.pub_path.is_some() {
        a.pub_workers
    } else {
        0
    };
    // C's second check, --pool-max below --workers alone, cannot fire after this one.
    if a.pool_max < a.workers + pub_workers {
        errw!(
            "pqhsm-service: --pool-max ({}) is below the total\n  worker count ({} + {pub_workers} public).\n",
            a.pool_max,
            a.workers
        );
        return 2;
    }
    // The queue is bounded by descriptors first: past the limit accept() fails silently.
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: rl is writable.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0 {
        let listeners = if a.pub_path.is_some() { 2 } else { 1 };
        let total = a.queue_depth * listeners + 64 + a.workers + pub_workers;
        if total as u64 > rl.rlim_cur {
            errw!(
                "pqhsm-service: --queue-depth {} needs {total} descriptors{},\n  and the limit in force is {}. Past it accept() fails with\n  EMFILE and the connection is dropped without a 503 and\n  without a line -- the silent failure the queue exists to\n  replace. Raise LimitNOFILE or lower --queue-depth.\n",
                a.queue_depth,
                if listeners == 2 {
                    " (two listeners)"
                } else {
                    ""
                },
                rl.rlim_cur as i64
            );
            return 2;
        }
    }

    // Before the socket exists, so no request is served against an empty budget.
    let tokens_dir = pqhsm_core::env("FHSM_TOKENS_DIR");
    let budget = Budget::load(tokens_dir.as_deref().map(OsStr::as_bytes));

    let mut pipe = [-1; 2];
    // SAFETY: pipe writes two descriptors.
    if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
        perror("pipe");
        return 1;
    }
    listen::STOP_READ.store(pipe[0], Ordering::Relaxed);
    listen::STOP_WRITE.store(pipe[1], Ordering::Relaxed);
    // Not SA_RESTART, so poll() returns and the stop is noticed; HUP must not interrupt.
    handle(
        libc::SIGINT,
        on_signal as *const () as libc::sighandler_t,
        0,
    );
    handle(
        libc::SIGTERM,
        on_signal as *const () as libc::sighandler_t,
        0,
    );
    handle(
        libc::SIGHUP,
        on_hup as *const () as libc::sighandler_t,
        libc::SA_RESTART,
    );
    handle(libc::SIGPIPE, libc::SIG_IGN, 0);

    // C_Initialize runs the self-tests and opens the audit log.
    if let Err(e) = pqhsm_pkiops::load(None) {
        let msg = e.c_msg().strip_suffix(b"\n").unwrap_or(e.c_msg());
        let mut w = std::io::stderr().lock();
        let _ = w.write_all(b"pqhsm-service: ");
        let _ = w.write_all(msg);
        let _ = w.write_all(
            b". Nothing is\n  served without the module, and nothing is served\n  without the audit log it opens.\n",
        );
        return 1;
    }
    let tokens: Vec<_> = pqhsm_pkiops::ffi::slots()
        .unwrap_or_default()
        .into_iter()
        .filter(|s| s.has_token != 0)
        .collect();
    let slot = match &tokens[..] {
        [] => {
            errln!("pqhsm-service: no slot holds a token. Run `fhsm-token init` first.");
            return 1;
        }
        [one] => one.id,
        many => {
            errln!(
                "pqhsm-service: {} slots hold a token; this service serves one.",
                many.len()
            );
            return 1;
        }
    };
    let Some(logged_in) = state::login_once(slot, a.pin_file.map(path).as_deref()) else {
        return 1;
    };

    if sock.len() >= 108 {
        errln!("pqhsm-service: socket path is longer than 107 bytes.");
        return 2;
    }
    let lfd = match bind(sock, "") {
        Ok(fd) => fd,
        Err(rc) => return rc,
    };
    let mut pfd = -1;
    if let Some(p) = a.pub_path {
        if p.len() >= 108 {
            errln!("pqhsm-service: --public-socket path is too long");
            return 2;
        }
        pfd = match bind(p, "public") {
            Ok(fd) => fd,
            Err(rc) => return rc,
        };
    }

    let unlink = |p: &[u8]| {
        let c = std::ffi::CString::new(p).unwrap_or_default();
        // SAFETY: a C string.
        unsafe { libc::unlink(c.as_ptr()) };
    };
    let started = audit::event(
        audit::EV_SERVICE_START,
        -1,
        -1,
        audit::ROLE_NONE,
        audit::RV_OK,
        &[
            ("socket", sock),
            ("public_socket", a.pub_path.unwrap_or(b"-")),
            (
                "certificate",
                if ca_cert.is_empty() { b"-" } else { b"loaded" },
            ),
            ("ocsp", ocsp.as_ref().map_or(&b"-"[..], |o| &o.label)),
        ],
    );
    if !started {
        // DIV-001: a service whose start the log cannot hold would serve unrecorded.
        errln!("pqhsm-service: cannot write the audit log; not starting.");
        for (fd, p) in [(lfd, Some(sock)), (pfd, a.pub_path)] {
            if let (true, Some(p)) = (fd >= 0, p) {
                // SAFETY: a listening descriptor nobody polls yet.
                unsafe { libc::close(fd) };
                unlink(p);
            }
        }
        pqhsm_pkiops::ops::session_close(logged_in);
        pqhsm_pkiops::close();
        return 1;
    }
    errln!(
        "pqhsm-service: listening on {}, uid {} only, {} workers, pool ceiling {}",
        shown(sock),
        a.proxy_uid,
        a.workers,
        a.pool_max
    );
    let _ = SVC.set(Svc {
        proxy_uid: a.proxy_uid as u32,
        pool: Pool::new(slot, a.pool_max as usize, logged_in),
        policy,
        idents: Idents::new(a.workers as usize),
        budget,
        ca_cert,
        ocsp,
    });

    let depth = a.queue_depth as usize;
    let private: &'static Listener = Box::leak(Box::new(Listener::new(lfd, false, depth)));
    let public: Option<&'static Listener> = a
        .pub_path
        .map(|_| &*Box::leak(Box::new(Listener::new(pfd, true, depth))));
    let mut pub_threads = Vec::new();
    if let (Some(l), Some(p)) = (public, a.pub_path) {
        for _ in 0..a.pub_workers {
            let Ok(t) = std::thread::Builder::new().spawn(|| l.worker()) else {
                errw!("pqhsm-service: cannot start public worker\n");
                return 1;
            };
            pub_threads.push(t);
        }
        let Ok(t) = std::thread::Builder::new().spawn(|| l.acceptor()) else {
            errw!("pqhsm-service: cannot start the public acceptor\n");
            return 1;
        };
        pub_threads.push(t);
        errln!(
            "pqhsm-service: public listener on {}, {} worker(s), no identity required",
            shown(p),
            a.pub_workers
        );
    }
    let mut workers = Vec::new();
    for i in 0..a.workers {
        let Ok(t) = std::thread::Builder::new().spawn(|| private.worker()) else {
            errw!("pqhsm-service: cannot start worker {i}\n");
            return 1;
        };
        workers.push(t);
    }
    private.acceptor(); // this thread accepts

    for t in workers {
        let _ = t.join();
    }
    if let Some(l) = public {
        l.stop();
    }
    for t in pub_threads {
        let _ = t.join();
    }
    // SAFETY: the listening descriptors, no longer polled.
    unsafe { libc::close(lfd) };
    if let (true, Some(p)) = (pfd >= 0, a.pub_path) {
        // SAFETY: as above.
        unsafe { libc::close(pfd) };
        unlink(p);
    }
    let s = svc();
    s.pool.close_all();
    // After the workers have joined, so no burst can still be growing.
    s.idents.flush_bursts();
    audit::event(
        audit::EV_SERVICE_STOP,
        -1,
        -1,
        audit::ROLE_NONE,
        audit::RV_OK,
        &[],
    );
    unlink(sock);
    pqhsm_pkiops::close();
    errln!("pqhsm-service: stopped");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_parse_as_c_strtol_reads_them() {
        let with = |uid: &str, more: &[&str]| {
            let mut v = vec!["--socket", "s", "--policy", "p", "--proxy-uid", uid];
            v.extend_from_slice(more);
            let b: Vec<&[u8]> = v.iter().map(|s| s.as_bytes()).collect();
            match parse(&b) {
                Parsed::Run(a) => Some((a.proxy_uid, a.workers)),
                Parsed::Profile => Some((-2, -2)),
                Parsed::Usage => None,
            }
        };
        assert_eq!(with("1000", &[]), Some((1000, 4)));
        // strtol: leading blanks and a sign are fine, an empty text is 0, a tail is not
        assert_eq!(with("", &["--workers", " +3"]), Some((0, 3)));
        assert_eq!(with("1", &["--workers", ""]), None); // 0 is out of range
        assert_eq!(with("12x", &[]), None);
        assert_eq!(with("-1", &[]), None);
        assert_eq!(with("4294967294", &[]), Some((4294967294, 4)));
        assert_eq!(with("4294967295", &[]), None); // (uid_t)-1
        assert_eq!(with("4294967296", &[]), None); // C: uid 0
        assert_eq!(with("99999999999999999999", &[]), None);
        assert_eq!(with("1", &["--workers", "257"]), None);
        assert_eq!(with("1", &["--ocsp-days", "366"]), None);
        assert_eq!(with("1", &["--bogus", "x"]), None);
        assert_eq!(with("1", &["--workers"]), None);
        assert_eq!(with("1", &["--workers", "2", "--profile"]), Some((-2, -2)));
        let b: Vec<&[u8]> = ["--socket", "s", "--proxy-uid", "1"]
            .map(str::as_bytes)
            .to_vec();
        assert!(matches!(parse(&b), Parsed::Usage));
    }
}
