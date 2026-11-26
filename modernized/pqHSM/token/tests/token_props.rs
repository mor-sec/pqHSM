//! Properties of the Rust token that the step-by-step scenarios cannot express: timing, locks,
//! ordering and fork safety. Each cites the C value it starts from (golden/store/steps.tsv)
//! and the DIV or plan item (PHASE2_PLAN.md §7) that sets the target.
//!
//!   cargo test -p pqhsm-token --test token_props

mod store_common;

use std::fs;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pqhsm_token::Rv;
use pqhsm_token::token::{Audit, AuditEvent, Platform, Role, Token, event, throttle_delay_ms};
use pqhsm_token::tpm::{Cli, Tpm};
use store_common::*;

fn platform_with(dir: &Path, audit: Box<dyn Audit>) -> Arc<Platform> {
    let device = dir.join("no-tpm-here");
    let cmd = format!("sh '{}'", tpm_stub().display());
    Arc::new(Platform {
        tpm: Arc::new(Tpm::new(device, Cli::Shell(cmd))),
        sealing_required: false,
        audit,
    })
}

fn platform(dir: &Path) -> Arc<Platform> {
    platform_with(dir, Box::new(Rec(Arc::default())))
}

fn start(dir: &Path, golden_tok: &str) -> PathBuf {
    let p = dir.join("slot0.tok");
    fs::copy(store_golden(&format!("tok/{golden_tok}.tok")), &p).unwrap();
    p
}

#[test]
fn token_is_send_and_sync() {
    fn both<T: Send + Sync>() {}
    both::<Token>();
}

/// RULE-084/026: 500 ms × 2^(n-1), capped at 60 s. C's values: throttle_derived_on_load_rule026
/// (tso/tuser after loading counters 1, 2, 3, 7, 8 and u32::MAX).
#[test]
fn throttle_delay_is_c_s_ladder() {
    let c = steps_of("throttle_derived_on_load_rule026");
    assert!(c[3].out.contains("\ttso=500\ttuser=1000\t"), "{}", c[3].out);
    assert!(
        c[8].out.contains("\ttso=2000\ttuser=32000\t"),
        "{}",
        c[8].out
    );
    assert!(
        c[13].out.contains("\ttso=60000\ttuser=60000\t"),
        "{}",
        c[13].out
    );
    let want = [
        (0, 0),
        (1, 500),
        (2, 1000),
        (3, 2000),
        (4, 4000),
        (5, 8000),
        (7, 32_000),
        (8, 60_000),
        (9, 60_000),
        (u32::MAX, 60_000),
    ];
    for (n, ms) in want {
        assert_eq!(throttle_delay_ms(n), ms, "{n} failures");
    }
}

/// RULE-084: a login inside the throttle window waits it out, then checks the PIN (C:
/// wrong_pin_counts_and_resets step 5 logs in right after a failure).
#[test]
fn a_login_inside_the_window_waits_then_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let t = Token::load(&path, platform(dir.path())).unwrap();
    assert_eq!(t.login(Role::User, WRONG_PIN), Err(Rv::PIN_INCORRECT));
    let at = Instant::now();
    t.login(Role::User, USER_PIN).unwrap();
    assert!(
        at.elapsed() >= Duration::from_millis(400),
        "waited {:?}",
        at.elapsed()
    );
}

/// DIV-012's own test: two handles (two open file descriptions, as two processes have) make
/// three wrong attempts each; the fifth failure locks, so the sixth attempt is PIN_LOCKED.
/// C gives each handle its own five (two_handles_bypass_lockout_div012).
#[test]
fn six_wrong_attempts_across_two_handles_lock_div012() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let a = Token::load(&path, platform(dir.path())).unwrap();
    let b = Token::load(&path, platform(dir.path())).unwrap();
    let mut got = Vec::new();
    for t in [&a, &a, &a, &b, &b, &b] {
        got.push(t.login(Role::User, WRONG_PIN).err());
    }
    let (inc, lck) = (Some(Rv::PIN_INCORRECT), Some(Rv::PIN_LOCKED));
    assert_eq!(got, [inc, inc, inc, inc, lck, lck]);
    assert_eq!(a.login(Role::User, USER_PIN), Err(Rv::PIN_LOCKED));
    let f = fs::read(&path).unwrap();
    assert_eq!(u32::from_le_bytes(f[297..301].try_into().unwrap()), 5);
}

/// Review M-2: a failure another handle counted restarts this handle's throttle as soon as it
/// takes the lock, as loading the token would. Before, `b` saw the counter but no deadline.
#[test]
fn another_handles_failure_throttles_this_one_m2() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let a = Token::load(&path, platform(dir.path())).unwrap();
    let b = Token::load(&path, platform(dir.path())).unwrap();
    assert_eq!(a.login(Role::User, WRONG_PIN), Err(Rv::PIN_INCORRECT));
    assert_eq!(b.throttle_remaining_ms(Role::User), 0);
    b.login(Role::So, SO_PIN).unwrap();
    assert_eq!(b.failed_count(Role::User), 1);
    assert!(b.throttle_remaining_ms(Role::User) > 0);
}

/// Review M-1: when the reseal fails at re-init, the token follows the re-initialised file
/// (before, its old serial failed every later transaction) and a SEAL_FAILURE record is written.
#[test]
fn a_failed_reseal_at_reinit_is_audited_and_leaves_the_token_usable_m1() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let rec = Arc::new(Recorder::default());
    let device = dir.path().join("no-tpm-here");
    let cmd = format!("sh '{}'", tpm_stub().display());
    let p = Arc::new(Platform {
        tpm: Arc::new(Tpm::new(device, Cli::Shell(cmd))),
        sealing_required: true,
        audit: Box::new(Rec(rec.clone())),
    });
    let t = Token::load(&path, p).unwrap();
    assert!(t.reinit(SO_PIN, b"after").is_err());
    let f = fs::read(&path).unwrap();
    let serial = &f[72..136];
    let serial = &serial[..serial.iter().position(|&c| c == 0).unwrap()];
    assert_eq!(t.serial(), serial);
    let lines = rec.lines.lock().unwrap().clone();
    assert!(
        lines
            .last()
            .is_some_and(|l| l.starts_with("seal_failure/SO/") && l.contains("tpm-seal-reinit")),
        "{lines:?}"
    );
    // The next re-init is not refused for a changed identity.
    assert!(t.reinit(SO_PIN, b"again").is_err());
    assert_ne!(fs::read(&path).unwrap()[72..136], f[72..136]);
}

/// DIV-031 (Rust-only row of `RUST_ONLY`): C opens `<path>.tmp` with O_CREAT|O_TRUNC
/// (`src/fhsm_token.c:1185`), writes the token through a link planted there and renames the
/// link over the token. Rust removes it and creates the tmp O_EXCL|O_NOFOLLOW.
#[test]
fn a_link_planted_at_the_tmp_name_is_not_written_through_div031() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let victim = dir.path().join("victim");
    fs::write(&victim, b"untouched").unwrap();
    std::os::unix::fs::symlink(&victim, dir.path().join("slot0.tok.tmp")).unwrap();
    let t = Token::load(&path, platform(dir.path())).unwrap();
    assert_eq!(t.login(Role::User, WRONG_PIN), Err(Rv::PIN_INCORRECT));
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
    assert_eq!(t.failed_count(Role::User), 1);
    let f = fs::read(&path).unwrap();
    assert_eq!(u32::from_le_bytes(f[297..301].try_into().unwrap()), 1);
}

/// H4: a mutation is audited before it is written, under the flock. The audit callback sees
/// the old file and cannot take the lock.
#[test]
fn object_create_is_audited_under_the_flock_before_the_write_h4() {
    #[derive(Default)]
    struct Probe {
        path: Mutex<PathBuf>,
        before: Mutex<Vec<u8>>,
        seen: Mutex<Vec<String>>,
    }
    struct Fwd(Arc<Probe>);
    impl Audit for Fwd {
        fn event(&self, e: &AuditEvent<'_>) -> Result<(), Rv> {
            if e.code == event::OBJECT_CREATE {
                let path = self.0.path.lock().unwrap().clone();
                let unchanged = fs::read(&path).unwrap() == *self.0.before.lock().unwrap();
                let f = fs::File::open(&path).unwrap();
                // SAFETY: flock on a descriptor this function owns.
                let held =
                    unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0;
                self.0
                    .seen
                    .lock()
                    .unwrap()
                    .push(format!("unchanged={unchanged} held={held}"));
            }
            Ok(())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let probe = Arc::new(Probe::default());
    *probe.path.lock().unwrap() = path.clone();
    let t = Token::load(
        &path,
        platform_with(dir.path(), Box::new(Fwd(probe.clone()))),
    )
    .unwrap();
    t.login(Role::User, USER_PIN).unwrap();
    let before = fs::read(&path).unwrap();
    *probe.before.lock().unwrap() = before.clone();
    t.object_add(0, 0, Some(b"x"), &[1, 2, 3, 4], &[], 0)
        .unwrap();
    assert_eq!(*probe.seen.lock().unwrap(), ["unchanged=true held=true"]);
    assert_ne!(
        fs::read(&path).unwrap(),
        before,
        "and the object was written after"
    );
}

/// M4: every write draws a fresh blob nonce; salt_so differs from salt_user.
#[test]
fn every_write_draws_a_fresh_nonce_and_the_salts_differ_m4() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "multi_base");
    let t = Token::load(&path, platform(dir.path())).unwrap();
    t.login(Role::User, USER_PIN).unwrap();
    let mut nonces = vec![fs::read(&path).unwrap()[321..333].to_vec()];
    for u in [0x81u8, 0x82, 0x83] {
        t.object_set_usage(1, u).unwrap();
        nonces.push(fs::read(&path).unwrap()[321..333].to_vec());
    }
    for i in 1..nonces.len() {
        assert!(!nonces[..i].contains(&nonces[i]), "nonce {i} reused");
    }
    let f = fs::read(&path).unwrap();
    assert_ne!(f[140..156], f[216..232]);
    // C agrees on every token it wrote with a user PIN.
    for s in steps()
        .iter()
        .filter(|s| s.out.contains("\tuinit=1\t") && s.line.starts_with("snap"))
    {
        assert!(
            s.out.contains("\tsalts_differ=1"),
            "{} step {}",
            s.scenario,
            s.step
        );
    }
}

/// M3: `close` never locks, so a child forked while another thread is inside a login (holding
/// the token mutex and the flock) can close its copy and exit.
#[test]
fn a_child_forked_during_a_login_can_close_its_copy_m3() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let t = Arc::new(Token::load(&path, platform(dir.path())).unwrap());
    let started = Arc::new(AtomicU32::new(0));
    let (t2, s2) = (t.clone(), started.clone());
    let th = std::thread::spawn(move || {
        s2.store(1, Ordering::SeqCst);
        t2.login(Role::User, USER_PIN)
    });
    while started.load(Ordering::SeqCst) == 0 {
        std::hint::spin_loop();
    }
    std::thread::sleep(Duration::from_millis(30)); // inside PBKDF2 (200000 iterations)
    // SAFETY: the child only closes its bitwise copy of the token and _exits.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let copy: Token = unsafe { std::ptr::read(Arc::as_ptr(&t)) };
        copy.close();
        unsafe { libc::_exit(0) };
    }
    assert!(pid > 0);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut status = 0;
    loop {
        // SAFETY: waiting for our own child.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r == pid {
            break;
        }
        if Instant::now() > deadline {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            panic!("the forked child hung in close");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child status {status:#x}"
    );
    th.join().unwrap().unwrap();
}

/// DIV-054: `change_pin` is `C_SetPIN`'s: only for the role logged in, the old PIN counted as a
/// login counts it, no second login, and afterwards only the new PIN opens the token. C's
/// `set_pin` logged in first, so from a logged-in session it was always ALREADY_LOGGED_IN
/// (set_pin_while_logged_in_rule082).
#[test]
fn change_pin_rewraps_for_the_logged_in_role() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let t = Token::load(&path, platform(dir.path())).unwrap();
    assert_eq!(
        t.change_pin(Role::User, USER_PIN, NEW_PIN),
        Err(Rv::USER_NOT_LOGGED_IN)
    );
    t.login(Role::User, USER_PIN).unwrap();
    assert_eq!(
        t.change_pin(Role::So, SO_PIN, NEW_PIN),
        Err(Rv::USER_NOT_LOGGED_IN)
    );
    assert_eq!(
        t.change_pin(Role::User, WRONG_PIN, NEW_PIN),
        Err(Rv::PIN_INCORRECT)
    );
    assert_eq!(t.failed_count(Role::User), 1);
    t.change_pin(Role::User, USER_PIN, NEW_PIN).unwrap();
    assert_eq!(t.current_role(), Role::User);
    assert_eq!(t.failed_count(Role::User), 0);
    t.logout();
    drop(t);
    let t = Token::load(&path, platform(dir.path())).unwrap();
    assert_eq!(t.login(Role::User, USER_PIN), Err(Rv::PIN_INCORRECT));
    t.login(Role::User, NEW_PIN).unwrap();
}

/// DIV-050: logout drops the private token objects (the public view is left), keeps the session
/// objects, and the next login reloads the former and rejoins the latter.
#[test]
fn logout_drops_private_objects_and_login_brings_them_back_div050() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let t = Token::load(&path, platform(dir.path())).unwrap();
    t.login(Role::User, USER_PIN).unwrap();
    let all = |t: &Token| t.object_find(None, None, 64).unwrap().0;
    let tok = all(&t);
    let secret = t.object_add(4, 31, Some(b"s"), &[7; 16], b"", 0).unwrap();
    let ses = t.object_add(4, 31, Some(b"e"), &[8; 16], b"", 0).unwrap();
    t.object_mark_session(ses, 9).unwrap();
    t.logout();
    assert_eq!(t.object_get(secret), Err(Rv::KEY_HANDLE_INVALID));
    let after: Vec<_> = all(&t);
    assert!(
        after.contains(&ses) && !after.contains(&secret),
        "{after:?}"
    );
    t.login(Role::User, USER_PIN).unwrap();
    assert_eq!(t.object_get(secret).unwrap().0, vec![7; 16]);
    assert_eq!(t.object_get(ses).unwrap().0, vec![8; 16]);
    let mut back = all(&t);
    back.sort();
    let mut want = tok.clone();
    want.extend([secret, ses]);
    want.sort();
    assert_eq!(back, want);
    let next = t.object_add(2, 3, Some(b"n"), &[1; 8], b"", 0).unwrap();
    assert!(!want.contains(&next), "handle {next} reused");
}

#[test]
fn a_pending_object_reaches_the_file_once_with_its_attributes_rule059() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let t = Token::load(&path, platform(dir.path())).unwrap();
    t.login(Role::User, USER_PIN).unwrap();
    let before = fs::read(&path).unwrap();
    let h = t
        .object_add_pending(4, 31, Some(b"p"), &[7; 16], b"", 0)
        .unwrap();
    t.object_set_flags3(h, 0x06).unwrap();
    t.object_set_allowed_mechs(h, &[0x1082]).unwrap();
    // A crash here leaves the file as it was: no object without its restrictions.
    assert_eq!(fs::read(&path).unwrap(), before);
    t.object_publish(&[h]).unwrap();
    assert_ne!(fs::read(&path).unwrap(), before);
    let again = Token::load(&path, platform(dir.path())).unwrap();
    again.login(Role::User, USER_PIN).unwrap();
    assert_eq!(again.object_get_flags3(h).unwrap(), 0x06);
    assert_eq!(again.object_get_allowed_mechs(h).unwrap(), vec![0x1082]);
    // Publishing twice writes nothing more.
    let after = fs::read(&path).unwrap();
    t.object_publish(&[h]).unwrap();
    assert_eq!(fs::read(&path).unwrap(), after);
}

/// DIV-001's undo: a pending object (never in the file) is dropped even when its destroy cannot
/// be recorded; a published one is kept, its destroy suppressed (6c M2, 6d M1).
#[test]
fn a_pending_object_goes_when_its_destroy_cannot_be_recorded_div001() {
    struct NoDestroy;
    impl Audit for NoDestroy {
        fn event(&self, e: &AuditEvent<'_>) -> Result<(), Rv> {
            if e.code == event::OBJECT_DESTROY {
                Err(Rv::DEVICE_ERROR)
            } else {
                Ok(())
            }
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let t = Token::load(&path, platform_with(dir.path(), Box::new(NoDestroy))).unwrap();
    t.login(Role::User, USER_PIN).unwrap();
    let before = fs::read(&path).unwrap();
    let p = t
        .object_add_pending(4, 31, Some(b"p"), &[7; 16], b"", 0)
        .unwrap();
    assert_eq!(t.object_destroy(p), Err(Rv::DEVICE_ERROR));
    assert_eq!(t.object_get_flags3(p), Err(Rv::KEY_HANDLE_INVALID));
    assert_eq!(fs::read(&path).unwrap(), before);
    let k = t.object_add(4, 31, Some(b"k"), &[7; 16], b"", 0).unwrap();
    assert_eq!(t.object_destroy(k), Err(Rv::DEVICE_ERROR));
    assert!(t.object_get_flags3(k).is_ok());
}

/// DIV-071 review: a pending object is in no file image, encrypted or public, and no find
/// returns it, while another object is written (M2, M4); a logout drops a pending session
/// object, so a later login cannot rejoin it pending (L4).
#[test]
fn a_pending_object_is_in_no_image_and_no_find_div071() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let t = Token::load(&path, platform(dir.path())).unwrap();
    t.login(Role::User, USER_PIN).unwrap();
    let all = |t: &Token| t.object_find(None, None, 64).unwrap().0;
    let reread = |login: bool| {
        let r = Token::load(&path, platform(dir.path())).unwrap();
        if login {
            r.login(Role::User, USER_PIN).unwrap();
        }
        all(&r)
    };
    let p = t
        .object_add_pending(2, 3, Some(b"pub"), &[1; 8], b"", 0)
        .unwrap();
    let k = t
        .object_add_pending(4, 31, Some(b"sec"), &[7; 16], b"", 0)
        .unwrap();
    let o = t.object_add(4, 31, Some(b"o"), &[9; 16], b"", 0).unwrap();
    let mine = all(&t);
    assert!(mine.contains(&o) && !mine.contains(&p) && !mine.contains(&k), "{mine:?}");
    for login in [false, true] {
        let hs = reread(login);
        assert!(!hs.contains(&p) && !hs.contains(&k), "login {login}: {hs:?}");
    }
    t.object_publish(&[p, k]).unwrap();
    assert!(reread(false).contains(&p));
    let hs = reread(true);
    assert!(hs.contains(&p) && hs.contains(&k), "{hs:?}");

    let q = t
        .object_add_pending(2, 3, Some(b"q"), &[2; 8], b"", 0)
        .unwrap();
    t.object_mark_session(q, 9).unwrap();
    t.logout();
    t.login(Role::User, USER_PIN).unwrap();
    assert_eq!(t.object_publish(&[q]), Err(Rv::KEY_HANDLE_INVALID));
}

/// DIV-071 review M1: a publish whose write fails drops the objects and records each as
/// destroyed, so the log does not end on a create for a key that never existed.
#[test]
fn a_failed_publish_drops_and_records_destroy_div071() {
    use std::os::unix::fs::PermissionsExt;
    struct Codes(Arc<Mutex<Vec<u32>>>);
    impl Audit for Codes {
        fn event(&self, e: &AuditEvent<'_>) -> Result<(), Rv> {
            self.0.lock().unwrap().push(e.code);
            Ok(())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let codes = Arc::new(Mutex::new(Vec::new()));
    let t = Token::load(&path, platform_with(dir.path(), Box::new(Codes(codes.clone())))).unwrap();
    t.login(Role::User, USER_PIN).unwrap();
    let a = t
        .object_add_pending(2, 3, Some(b"a"), &[1; 8], b"", 0)
        .unwrap();
    let b = t
        .object_add_pending(3, 3, Some(b"b"), &[2; 8], b"", 0)
        .unwrap();
    let tokdir = path.parent().unwrap();
    let mode = fs::metadata(tokdir).unwrap().permissions();
    // The write's temporary file cannot be made (the tests run without CAP_DAC_OVERRIDE).
    fs::set_permissions(tokdir, fs::Permissions::from_mode(0o500)).unwrap();
    codes.lock().unwrap().clear();
    let r = t.object_publish(&[a, b]);
    fs::set_permissions(tokdir, mode).unwrap();
    assert!(r.is_err());
    assert_eq!(*codes.lock().unwrap(), vec![event::OBJECT_DESTROY; 2]);
    assert_eq!(t.object_get_flags3(a), Err(Rv::KEY_HANDLE_INVALID));
    assert_eq!(t.object_get_flags3(b), Err(Rv::KEY_HANDLE_INVALID));
}

/// legacy/tests/test_wrong_pin_store.c case 1 (Phase 6 slice 5c): a wrong PIN after a logout, on
/// the same handle, never rewrites the objects (RULE-088): a fresh load and the right PIN find
/// every one with its value. The scenarios cover the fresh-process case only.
#[test]
fn a_wrong_pin_after_a_logout_keeps_every_object_rule088() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "multi_base");
    let values = |t: &Token| {
        let (hs, _) = t.object_find(None, None, 64).unwrap();
        let mut v: Vec<_> = hs.iter().map(|&h| t.object_get(h).unwrap()).collect();
        v.sort();
        v
    };
    let t = Token::load(&path, platform(dir.path())).unwrap();
    t.login(Role::User, USER_PIN).unwrap();
    let before = values(&t);
    assert!(before.len() >= 5, "{}", before.len());
    t.logout();
    assert_eq!(t.login(Role::User, WRONG_PIN), Err(Rv::PIN_INCORRECT));
    t.close();
    let t = Token::load(&path, platform(dir.path())).unwrap();
    t.login(Role::User, USER_PIN).unwrap();
    assert_eq!(values(&t), before);
}

/// legacy/tests/test_token_capacity.c (Phase 6 slice 5c): the Rust writer at scale. The token
/// filled to MAX_OBJECTS, eight of them 12000-byte certificates, then reloaded: every object
/// back, with its value; one more is refused.
#[test]
fn a_full_token_is_written_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = start(dir.path(), "user_base");
    let t = Token::load(&path, platform(dir.path())).unwrap();
    t.login(Role::User, USER_PIN).unwrap();
    let have = t.object_find(None, None, 2048).unwrap().0.len();
    let mut added = Vec::new();
    for i in 0..(pqhsm_token::store::MAX_OBJECTS - have) {
        let (class, key_type, value) = if i % 128 == 0 {
            (1, 0, vec![(i % 251) as u8; 12000]) // CKO_CERTIFICATE, CKC_X_509
        } else {
            (4, 31, (i as u32).to_le_bytes().repeat(4)) // CKO_SECRET_KEY, CKK_AES
        };
        let label = format!("cap-{i}");
        t.object_add(class, key_type, Some(label.as_bytes()), &value, b"", 0).unwrap();
        added.push((label, value));
    }
    assert_eq!(added.iter().filter(|(_, v)| v.len() == 12000).count(), 8);
    // test_token_capacity.c (#125 I1): DEVICE_MEMORY, not HOST_MEMORY
    assert_eq!(t.object_add(4, 31, Some(b"one-more"), &[0; 16], b"", 0), Err(Rv::DEVICE_MEMORY));
    t.close();
    let t = Token::load(&path, platform(dir.path())).unwrap();
    t.login(Role::User, USER_PIN).unwrap();
    assert_eq!(t.object_find(None, None, 2048).unwrap().0.len(), pqhsm_token::store::MAX_OBJECTS);
    for (label, value) in &added {
        let (hs, _) = t.object_find(None, Some(label.as_bytes()), 2).unwrap();
        assert_eq!(hs.len(), 1, "{label}");
        assert_eq!(&t.object_get(hs[0]).unwrap().0, value, "{label}");
    }
}
