//! The token: load, init, login and the PIN counters, PIN administration, the object store API,
//! and the single token-file transaction (`src/fhsm_token.c:1092-2687`).
//!
//! Divergences this module carries (`analysis/pqHSM/DIVERGENCES.md`):
//! - DIV-010: a store that fails GCM under the DEK fails the login (no zero-DEK fallback);
//!   [`migrate_zero_dek`] is the only reader of the zero key.
//! - DIV-011: a header with `pbkdf2_iter != 200000` does not load (see [`crate::header`]).
//! - DIV-012 (amended, H1/H2): every write takes `flock` on the token file, checks the inode,
//!   re-reads the header (counters from disk; a changed serial or wraps fails the call), then
//!   tmp + fsync + rename + directory fsync, then `LOCK_UN`. Lock order: apilock, token mutex,
//!   flock, audit. The flock wait gives up after [`FLOCK_WAIT`] (review M-4), and a failure
//!   another process counted restarts this process's throttle (review M-2).
//! - DIV-013 (amended, H3): login makes `failed+1` durable before PBKDF2 and refuses without
//!   looking at the PIN if it cannot; a failed reset write unloads the objects, zeroises the DEK
//!   and fails the call.
//! - DIV-014: init and re-init zeroise the DEK.
//! - DIV-015 (a), (c), (e): reseal (or remove `.tpm`) on re-init, before the DEK is zeroised
//!   (M5); remove a new `.tpm` when the `.tok` write fails; clear `dek_live` on TPM failures.
//! - DIV-031: the tmp file is created `O_EXCL|O_NOFOLLOW` after removing whatever was there.
//! - DIV-001: the 11 audit calls are checked; a failed audit fails the call with
//!   `DEVICE_ERROR` and suppresses its effect (H4: build a copy, audit, write, swap).
//!
//! Preserved as C does it (deferred): RULE-082/005 (`set_pin` logs in first; Phase 4's
//! `C_SetPIN` uses [`Token::change_pin`] instead, DIV-054), RULE-083 (0x101
//! for an uninitialised user PIN), RULE-086/056 (logout keeps objects), RULE-036/079(a) (PIN
//! minimum 8 on init, 4 elsewhere), RULE-003(1) ([`crate::store::BLOB_MAX`]).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::Rv;
use crate::crypto::{gcm_decrypt, gcm_encrypt, pbkdf2_sha256, random};
use crate::ffi::lock::{Guard, Lock};
use crate::ffi::mem::{self, Buf};
use crate::ffi::sys;
use crate::header::{self, Header};
use crate::store::{self, Object, PolicyAttr, PublicView, Store};
use crate::tpm::{self, Tpm};

pub const PIN_MAX_FAILED: u32 = 5;
pub const THROTTLE_BASE_MS: u64 = 500;
pub const THROTTLE_MAX_MS: u64 = 60_000;
/// Minimum SO PIN on a fresh token (`:1217`), and everywhere else (`:1716`, `:1768`, `:1820`).
pub const INIT_SO_PIN_MIN: usize = 8;
pub const PIN_MIN: usize = 4;
/// How long a transaction waits for another process's token-file lock (review M-4). The holder
/// runs at most one PBKDF2, one TPM unseal and two fsyncs.
pub const FLOCK_WAIT: Duration = Duration::from_secs(10);

pub type Handle = u32;

/// `fhsm_role_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    None = 0,
    So = 1,
    User = 2,
}

/// `fhsm_obj_meta_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Meta {
    StartDate = 0,
    EndDate = 1,
    Application = 2,
}

/// `fhsm_tmpl_which_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tmpl {
    Wrap = 0,
    Unwrap = 1,
    Derive = 2,
}

/// The `fhsm_audit_event_t` codes the token raises (`include/fhsm_audit.h`).
pub mod event {
    pub const TOKEN_INIT: u32 = 10;
    pub const TOKEN_REINIT: u32 = 11;
    pub const SET_PIN: u32 = 17;
    pub const OBJECT_CREATE: u32 = 30;
    pub const OBJECT_DESTROY: u32 = 31;
    pub const SEAL_SUCCESS: u32 = 70;
    pub const SEAL_FAILURE: u32 = 71;
    pub const UNSEAL_SUCCESS: u32 = 72;
    pub const UNSEAL_FAILURE: u32 = 73;
}

/// One audit record the token asks for (slot and session are always -1 here, as in C).
#[derive(Clone, Copy, Debug)]
pub struct AuditEvent<'a> {
    pub code: u32,
    pub role: Role,
    pub rv: Rv,
    /// Key/value pairs as C passes them; rendered by the audit crate.
    pub params: &'a [(&'a [u8], &'a [u8])],
}

/// Where audit records go. The C ABI layer forwards to `fhsm_audit_event` (the C shim in front
/// of the Rust audit crate); tests record. `Err` means the record is not durable (DIV-001).
pub trait Audit: Send + Sync {
    fn event(&self, e: &AuditEvent<'_>) -> Result<(), Rv>;
}

/// What C took from globals: the TPM, `FHSM_TPM_SEALING`, and the audit log.
pub struct Platform {
    pub tpm: Arc<Tpm>,
    /// C: `fhsm_token_tpm_required()`, read when the token is created or loaded (DIV-029).
    pub sealing_required: bool,
    pub audit: Box<dyn Audit>,
}

/// Owned audit key/value pairs, for a record built before the lock is taken.
type Params = Vec<(Vec<u8>, Vec<u8>)>;

const FF: Rv = Rv::FUNCTION_FAILED;
const NOLOGIN: Rv = Rv::USER_NOT_LOGGED_IN;

fn now_ms() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

/// DIV-023: a TPM record's value is its rv as C prints one (`0x%x`, `src/fhsm_audit.c:302`).
fn hex(rv: Rv) -> Vec<u8> {
    format!("0x{:x}", rv.0).into_bytes()
}

fn cstr(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

#[derive(Clone)]
struct Inner {
    path: PathBuf,
    hdr: Header,
    until_so: u64,
    until_user: u64,
    /// The DEK in the secure heap (review M2); `None` is C's zeroised buffer.
    dek: Option<Arc<Buf>>,
    dek_live: bool,
    role: Role,
    store: Store,
    loaded: bool,
    public: bool,
}

impl Inner {
    fn key(&self) -> Result<&[u8; 32], Rv> {
        let b = self.dek.as_deref().ok_or(FF)?;
        b.as_slice().try_into().map_err(|_| FF)
    }
    fn fails(&mut self, r: Role) -> (&mut u32, &mut u64) {
        if r == Role::So {
            (&mut self.hdr.failed_so, &mut self.until_so)
        } else {
            (&mut self.hdr.failed_user, &mut self.until_user)
        }
    }
    /// Zeroise the DEK in place and let it go, as C's logout did (review M-3): the free itself
    /// may still wait for `fhsm_api_free_value`'s readers. Every copy of `Inner` is gone by the
    /// time this runs, so the DEK is never shared here.
    fn drop_dek(&mut self) {
        if let Some(mut k) = self.dek.take() {
            let b = Arc::get_mut(&mut k);
            debug_assert!(b.is_some(), "DEK still shared");
            if let Some(b) = b {
                b.wipe();
            }
        }
        self.dek_live = false;
    }
    /// Take the counters and throttle deadlines `Flock::take` just refreshed in `g`.
    fn counters_from(&mut self, g: &Inner) {
        self.hdr.failed_so = g.hdr.failed_so;
        self.hdr.failed_user = g.hdr.failed_user;
        self.until_so = g.until_so;
        self.until_user = g.until_user;
    }
    fn serial_aad(&self) -> Vec<u8> {
        cstr(&self.hdr.serial).to_vec()
    }
    fn find(&self, h: Handle) -> Option<usize> {
        self.store.objects.iter().position(|o| o.handle == h)
    }
    fn obj(&self, h: Handle) -> Result<&Object, Rv> {
        self.find(h)
            .map(|i| &self.store.objects[i])
            .ok_or(Rv::KEY_HANDLE_INVALID)
    }
    fn visible(&self) -> Result<(), Rv> {
        if self.loaded || self.public {
            Ok(())
        } else {
            Err(NOLOGIN)
        }
    }
    fn writable(&self) -> Result<(), Rv> {
        if self.dek_live && self.loaded {
            Ok(())
        } else {
            Err(NOLOGIN)
        }
    }
    /// `write_atomic`, plus directory fsync and no leftover .tmp (M4).
    fn write(&self) -> Result<(), Rv> {
        let mut img = self.hdr.to_bytes().to_vec();
        if !(self.dek_live && self.loaded) {
            if let Ok(f) = fs::read(&self.path)
                && f.len() > header::LEN
            {
                if (f.len() - header::LEN) as u64 > 2 * (store::BLOB_MAX + 32) {
                    return Err(FF);
                }
                img.extend_from_slice(&f[header::LEN..]);
            }
        } else if !self.store.objects.is_empty() {
            let pt = Zeroizing::new(store::serialize(&self.store, false));
            let mut nonce = [0u8; 12];
            random(&mut nonce)?;
            let (ct, tag) = gcm_encrypt(self.key()?, &nonce, &self.serial_aad(), &pt)?;
            img.extend((ct.len() as u32).to_le_bytes());
            img.extend(nonce);
            img.extend(ct);
            img.extend(tag);
            img.extend(store::public_section(&self.store));
        }
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let r = (|| -> std::io::Result<()> {
            // DIV-031: a link planted at the tmp name is never written through
            let _ = fs::remove_file(&tmp);
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&img)?;
            f.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            if let Some(d) = self.path.parent() {
                let d = if d.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    d
                };
                File::open(d)?.sync_all()?;
            }
            Ok(())
        })();
        if r.is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(FF);
        }
        Ok(())
    }
}

/// The token file's flock, held for one transaction (DIV-012).
struct Flock(Option<File>);

impl Flock {
    /// Lock, check the inode, re-read the header: a changed identity fails, counters come from disk.
    fn take(g: &mut Inner) -> Result<Flock, Rv> {
        loop {
            let Ok(f) = File::open(&g.path) else {
                return Ok(Flock(None));
            };
            if sys::lock_ex(&f, FLOCK_WAIT).is_err() {
                return Err(FF);
            }
            let same = match (f.metadata(), fs::metadata(&g.path)) {
                (Ok(a), Ok(b)) => a.ino() == b.ino() && a.dev() == b.dev(),
                _ => false,
            };
            if !same {
                continue;
            }
            let mut buf = vec![0u8; header::LEN];
            let n = (&f).read(&mut buf).unwrap_or(0);
            if n == header::LEN
                && let Ok(d) = Header::parse(&buf)
            {
                if d.serial != g.hdr.serial
                    || d.so_wrap_ct != g.hdr.so_wrap_ct
                    || d.user_wrap_ct != g.hdr.user_wrap_ct
                {
                    return Err(FF);
                }
                // review M-2: another process's failure (or reset) restarts the throttle here
                if d.failed_so != g.hdr.failed_so {
                    g.until_so = deadline(d.failed_so);
                }
                if d.failed_user != g.hdr.failed_user {
                    g.until_user = deadline(d.failed_user);
                }
                g.hdr.failed_so = d.failed_so;
                g.hdr.failed_user = d.failed_user;
            }
            return Ok(Flock(Some(f)));
        }
    }
}

impl Drop for Flock {
    fn drop(&mut self) {
        if let Some(f) = &self.0 {
            let _ = sys::flock(f, libc::LOCK_UN);
        }
    }
}

/// An open token (`fhsm_token_t`). `Send + Sync`: every method takes the token mutex.
pub struct Token {
    inner: Lock<Inner>,
    platform: Arc<Platform>,
}

/// The throttle deadline after `fails` failures, counted from now, as load derives it.
fn deadline(fails: u32) -> u64 {
    if fails > 0 {
        now_ms() + throttle_delay_ms(fails)
    } else {
        0
    }
}

pub fn throttle_delay_ms(fails: u32) -> u64 {
    if fails == 0 {
        return 0;
    }
    let mut d = THROTTLE_BASE_MS;
    let mut i = 1;
    while i < fails && d < THROTTLE_MAX_MS {
        d *= 2;
        i += 1;
    }
    d.min(THROTTLE_MAX_MS)
}

fn unwrap_dek(h: &Header, role: Role, pin: &[u8]) -> Result<Zeroizing<[u8; 32]>, Rv> {
    let (salt, nonce, ct) = if role == Role::So {
        (&h.salt_so, &h.so_wrap_nonce, &h.so_wrap_ct)
    } else {
        (&h.salt_user, &h.user_wrap_nonce, &h.user_wrap_ct)
    };
    let mut kek = Zeroizing::new([0u8; 32]);
    pbkdf2_sha256(pin, salt, h.pbkdf2_iter, &mut *kek)?;
    let pt = gcm_decrypt(
        &kek,
        nonce,
        cstr(&h.serial),
        &ct[..32],
        ct[32..48].try_into().unwrap(),
    )
    .map_err(|_| Rv::PIN_INCORRECT)?;
    let mut dek = Zeroizing::new([0u8; 32]);
    if pt.len() != dek.len() {
        return Err(Rv::PIN_INCORRECT);
    }
    dek.copy_from_slice(&pt);
    Ok(dek)
}

fn wrap(
    dek: &[u8; 32],
    pin: &[u8],
    salt: &[u8; 16],
    nonce: &[u8; 12],
    serial: &[u8],
) -> Result<[u8; 48], Rv> {
    let mut kek = Zeroizing::new([0u8; 32]);
    pbkdf2_sha256(pin, salt, header::PBKDF2_ITER, &mut *kek)?;
    let (ct, tag) = gcm_encrypt(&kek, nonce, cstr(serial), dek)?;
    let mut out = [0u8; 48];
    out[..32].copy_from_slice(&ct);
    out[32..].copy_from_slice(&tag);
    Ok(out)
}

fn new_serial() -> Result<[u8; 64], Rv> {
    let mut s = [0u8; 8];
    random(&mut s)?;
    let txt = format!(
        "FHSM-{}",
        s.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let mut out = [0u8; 64];
    out[..txt.len()].copy_from_slice(txt.as_bytes());
    Ok(out)
}

/// snprintf("%s") into a 64-byte field: at most 63 bytes, NUL, the rest untouched.
fn put_label(field: &mut [u8; 64], label: &[u8]) {
    let l = cstr(label);
    let n = l.len().min(63);
    field[..n].copy_from_slice(&l[..n]);
    field[n] = 0;
}

pub fn migrate_zero_dek(path: &Path, user_pin: &[u8]) -> Result<usize, Rv> {
    // The token-file lock first (DIV-012), so a running module cannot write in between.
    let lock = File::open(path).map_err(|_| Rv::TOKEN_NOT_PRESENT)?;
    sys::lock_ex(&lock, FLOCK_WAIT).map_err(|_| FF)?;
    let f = fs::read(path).map_err(|_| Rv::TOKEN_NOT_PRESENT)?;
    let h = Header::parse(&f)?;
    let dek = unwrap_dek(&h, Role::User, user_pin)?;
    let b = store::split_blob(&f)?.ok_or(FF)?;
    let pt = gcm_decrypt(&[0u8; 32], &b.nonce, cstr(&h.serial), b.ct, &b.tag).map_err(|_| FF)?;
    let s = store::parse(&pt)?;
    let n = s.objects.len();
    let g = Inner {
        path: path.to_owned(),
        hdr: h,
        until_so: 0,
        until_user: 0,
        dek: Some(Arc::new(mem::key(&dek)?)),
        dek_live: true,
        role: Role::None,
        store: s,
        loaded: true,
        public: false,
    };
    g.write()?;
    Ok(n)
}

impl Token {
    fn audit(&self, code: u32, role: Role, rv: Rv, params: &[(&[u8], &[u8])]) -> Result<(), Rv> {
        self.platform
            .audit
            .event(&AuditEvent {
                code,
                role,
                rv,
                params,
            })
            .map_err(|_| Rv::DEVICE_ERROR)
    }

    fn g(&self) -> Guard<'_, Inner> {
        self.inner.lock()
    }

    pub fn load(path: &Path, platform: Arc<Platform>) -> Result<Token, Rv> {
        let mut f = File::open(path).map_err(|_| Rv::TOKEN_NOT_PRESENT)?;
        let mut buf = vec![0u8; header::LEN];
        let n = f.read(&mut buf).unwrap_or(0);
        if n != header::LEN {
            return Err(FF);
        }
        let hdr = Header::parse(&buf)?;
        let mut g = Inner {
            path: path.to_owned(),
            until_so: deadline(hdr.failed_so),
            until_user: deadline(hdr.failed_user),
            hdr,
            dek: None,
            dek_live: false,
            role: Role::None,
            store: Store::default(),
            loaded: false,
            public: false,
        };
        drop(f);
        if let Ok(file) = fs::read(path) {
            match store::read_public_view(&file) {
                PublicView::Empty => g.public = true,
                PublicView::Objects(s) => {
                    g.store = s;
                    g.public = true;
                }
                PublicView::Unknown => {}
            }
        }
        Ok(Token {
            inner: Lock::new(g),
            platform,
        })
    }

    pub fn init(
        path: &Path,
        so_pin: &[u8],
        label: &[u8],
        platform: Arc<Platform>,
    ) -> Result<Token, Rv> {
        if so_pin.len() < INIT_SO_PIN_MIN {
            return Err(Rv::PIN_INCORRECT);
        }
        let mut hdr = Header {
            label: [0; 64],
            serial: new_serial()?,
            pbkdf2_iter: header::PBKDF2_ITER,
            salt_so: [0; 16],
            so_wrap_nonce: [0; 12],
            so_wrap_ct: [0; 48],
            salt_user: [0; 16],
            user_wrap_nonce: [0; 12],
            user_wrap_ct: [0; 48],
            user_initialized: false,
            failed_so: 0,
            failed_user: 0,
        };
        put_label(&mut hdr.label, label);
        random(&mut hdr.salt_so)?;
        random(&mut hdr.salt_user)?;
        let mut dek = Zeroizing::new([0u8; 32]);
        random(&mut *dek)?;
        random(&mut hdr.so_wrap_nonce)?;
        hdr.so_wrap_ct = wrap(&dek, so_pin, &hdr.salt_so, &hdr.so_wrap_nonce, &hdr.serial)?;
        let g = Inner {
            path: path.to_owned(),
            hdr,
            until_so: 0,
            until_user: 0,
            dek: Some(Arc::new(mem::key(&dek)?)),
            dek_live: true,
            role: Role::None,
            store: Store {
                next_handle: 1,
                objects: vec![],
            },
            loaded: true,
            public: false,
        };
        let t = Token {
            inner: Lock::new(g.clone()),
            platform,
        };
        let mut sealed = false;
        if t.platform.sealing_required {
            if let Err(e) = t.platform.tpm.seal_companion(path, g.key()?) {
                let _ = t.audit(
                    event::SEAL_FAILURE,
                    Role::So,
                    e,
                    &[(b"tpm-seal-init", &hex(e))],
                );
                tpm::unlink_companion(path);
                return Err(e);
            }
            sealed = true;
            if let Err(e) = t.audit(
                event::SEAL_SUCCESS,
                Role::So,
                Rv::OK,
                &[(b"tpm-seal-init", &hex(Rv::OK))],
            ) {
                tpm::unlink_companion(path);
                return Err(e);
            }
        }
        if g.write().is_err() {
            if sealed {
                tpm::unlink_companion(path);
            }
            return Err(FF);
        }
        let lab = cstr(&g.hdr.label).to_vec();
        if let Err(e) = t.audit(event::TOKEN_INIT, Role::So, Rv::OK, &[(b"label", &lab)]) {
            let _ = fs::remove_file(path);
            if sealed {
                tpm::unlink_companion(path);
            }
            return Err(e);
        }
        // DIV-014, once t's copy of the DEK is gone
        let mut cur = t.g();
        *cur = g;
        cur.drop_dek();
        drop(cur);
        Ok(t)
    }

    pub fn close(self) {
        drop(self);
    }

    fn check_pin(&self, role: Role, pin: &[u8], login: bool) -> Result<(), Rv> {
        let mut g = self.g();
        loop {
            if login && g.role == role {
                return Err(Rv::USER_ALREADY_LOGGED_IN);
            }
            if login && g.role != Role::None {
                return Err(Rv::USER_ANOTHER_ALREADY_LOGGED_IN);
            }
            let lock = Flock::take(&mut g)?;
            let now = now_ms();
            let (fails, until) = g.fails(role);
            if *fails >= PIN_MAX_FAILED {
                return Err(Rv::PIN_LOCKED);
            }
            if now < *until {
                let ms = *until - now;
                drop(lock);
                drop(g);
                std::thread::sleep(Duration::from_millis(ms));
                g = self.g();
                continue;
            }
            if role == Role::User && !g.hdr.user_initialized {
                return Err(NOLOGIN);
            }
            // DIV-013: failed+1 durable first
            let before = *g.fails(role).0;
            let until_before = *g.fails(role).1;
            let mut next = g.clone();
            let n = before + 1;
            *next.fails(role).0 = n;
            next.dek_live = false;
            next.write()?;
            *g.fails(role).0 = n;
            *g.fails(role).1 = now + throttle_delay_ms(n);
            let dek = match unwrap_dek(&g.hdr, role, pin) {
                Ok(d) => d,
                Err(Rv::PIN_INCORRECT) => {
                    return Err(if n >= PIN_MAX_FAILED {
                        Rv::PIN_LOCKED
                    } else {
                        Rv::PIN_INCORRECT
                    });
                }
                Err(e) => return Err(e),
            };
            let restore = |g: &mut Inner| {
                *g.fails(role).0 = before;
                *g.fails(role).1 = until_before;
                let live = g.dek_live;
                g.dek_live = false;
                let _ = g.write();
                g.dek_live = live;
            };
            if !login {
                *g.fails(role).0 = 0;
                *g.fails(role).1 = 0;
                return g.write();
            }
            if tpm::companion_exists(&g.path) {
                let mut td = Zeroizing::new([0u8; 32]);
                let r = self.platform.tpm.unseal_companion(&g.path, &mut td);
                let matched = r.is_ok() && tpm::dek_match(&dek, &td);
                if !matched {
                    g.dek_live = false;
                    restore(&mut g);
                    let (rv, k): (Rv, &[u8]) = match r {
                        Err(e) => (e, b"tpm-unseal-failed"),
                        Ok(()) => (Rv::DEVICE_ERROR, b"tpm-dek-mismatch"),
                    };
                    let _ = self.audit(event::UNSEAL_FAILURE, role, rv, &[(k, &hex(rv))]);
                    return Err(Rv::DEVICE_ERROR);
                }
                if let Err(e) = self.audit(
                    event::UNSEAL_SUCCESS,
                    role,
                    Rv::OK,
                    &[(b"tpm-check-login", &hex(Rv::OK))],
                ) {
                    restore(&mut g);
                    return Err(e);
                }
            } else if self.platform.sealing_required {
                let _ = self.audit(
                    event::UNSEAL_FAILURE,
                    role,
                    Rv::TPM_UNAVAILABLE,
                    &[(b"tpm-required-but-missing", &hex(Rv::TPM_UNAVAILABLE))],
                );
                restore(&mut g);
                return Err(Rv::DEVICE_ERROR);
            }
            if !g.loaded {
                // DIV-050: the session objects a logout kept go back in, whatever the file holds
                let sess: Vec<Object> = g
                    .store
                    .objects
                    .iter()
                    .filter(|o| o.owner_session != 0)
                    .cloned()
                    .collect();
                let rejoin = |s: &mut Store| {
                    for o in &sess {
                        s.next_handle = s.next_handle.max(o.handle + 1);
                        s.objects.push(o.clone());
                    }
                };
                let file = fs::read(&g.path);
                g.store = Store::default();
                let mut loaded = false;
                match file {
                    Err(_) => {}
                    Ok(f) => match store::split_blob(&f) {
                        Ok(None) => {
                            g.store.next_handle = 1;
                            loaded = true;
                        }
                        Err(_) => {}
                        Ok(Some(b)) => {
                            match gcm_decrypt(&dek, &b.nonce, &g.serial_aad(), b.ct, &b.tag) {
                                Err(_) => {
                                    // DIV-010
                                    restore(&mut g);
                                    // re-read the public view the clear above dropped
                                    if let Ok(f) = fs::read(&g.path)
                                        && let PublicView::Objects(s) = store::read_public_view(&f)
                                    {
                                        g.store = s;
                                    }
                                    rejoin(&mut g.store);
                                    return Err(FF);
                                }
                                Ok(pt) => match store::parse(&pt) {
                                    Ok(s) => {
                                        g.store = s;
                                        loaded = true;
                                    }
                                    // DIV-024: C logged in with no objects
                                    Err(_) => {
                                        restore(&mut g);
                                        if let Ok(f) = fs::read(&g.path)
                                            && let PublicView::Objects(s) =
                                                store::read_public_view(&f)
                                        {
                                            g.store = s;
                                        }
                                        rejoin(&mut g.store);
                                        return Err(FF);
                                    }
                                },
                            }
                        }
                    },
                }
                rejoin(&mut g.store);
                g.public = false;
                g.loaded = loaded;
            }
            let key = match mem::key(&dek) {
                Ok(k) => Arc::new(k),
                Err(e) => {
                    restore(&mut g);
                    return Err(e);
                }
            };
            g.role = role;
            g.dek = Some(key);
            g.dek_live = true;
            *g.fails(role).0 = 0;
            *g.fails(role).1 = 0;
            if g.write().is_err() {
                // DIV-013: a failed reset logs out
                g.role = Role::None;
                g.drop_dek();
                g.store = Store::default();
                g.loaded = false;
                g.public = false;
                *g.fails(role).0 = n;
                *g.fails(role).1 = now + throttle_delay_ms(n);
                return Err(FF);
            }
            return Ok(());
        }
    }

    pub fn login(&self, role: Role, pin: &[u8]) -> Result<(), Rv> {
        self.check_pin(role, pin, true)
    }

    pub fn verify_pin(&self, role: Role, pin: &[u8]) -> Result<(), Rv> {
        if role == Role::None {
            return Err(Rv::ARGUMENTS_BAD);
        }
        self.check_pin(role, pin, false)
    }

    /// DIV-050: logout drops every private token object, the classes RULE-055 hides (secret and
    /// private keys; C derives CKA_PRIVATE from the class), its value zeroised when its last
    /// reader lets go (`Buf`'s drop). Public objects and session objects stay. The next login
    /// reloads the file.
    pub fn logout(&self) {
        let mut g = self.g();
        g.drop_dek();
        g.role = Role::None;
        if g.loaded {
            g.store
                .objects
                .retain(|o| o.owner_session != 0 || !store::is_private_class(o.class));
            g.loaded = false;
            g.public = true;
        }
    }

    pub fn current_role(&self) -> Role {
        self.g().role
    }

    /// H4: lock, audit, write the copy, swap.
    fn commit(
        &self,
        g: &mut Inner,
        mut next: Inner,
        audit: Option<(u32, Params)>,
    ) -> Result<(), Rv> {
        let _lock = Flock::take(g)?;
        next.counters_from(g);
        if let Some((code, p)) = audit {
            let p: Vec<(&[u8], &[u8])> = p.iter().map(|(k, v)| (&k[..], &v[..])).collect();
            self.audit(code, g.role, Rv::OK, &p)?;
        }
        next.write()?;
        *g = next;
        Ok(())
    }

    pub fn set_pin(&self, role: Role, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Rv> {
        if new_pin.len() < PIN_MIN {
            return Err(Rv::PIN_INCORRECT);
        }
        self.login(role, old_pin)?;
        self.rewrap(role, new_pin)
    }

    /// DIV-054, for `C_SetPIN`: `role` is logged in; its old PIN is checked as a login would
    /// count it (failure counter, throttle, lock) without logging in again, then the DEK is
    /// re-wrapped under the new PIN with a fresh salt and nonce. The DEK itself is not rotated.
    /// [`Self::set_pin`] keeps C's log-in-first behaviour for the token's own callers.
    pub fn change_pin(&self, role: Role, old_pin: &[u8], new_pin: &[u8]) -> Result<(), Rv> {
        {
            let g = self.g();
            if role == Role::None || g.role != role || !g.dek_live {
                return Err(NOLOGIN);
            }
        }
        self.verify_pin(role, old_pin)?;
        self.rewrap(role, new_pin)
    }

    /// The new wrap of the live DEK for `role`, audited, then written (H4).
    fn rewrap(&self, role: Role, new_pin: &[u8]) -> Result<(), Rv> {
        let mut g = self.g();
        // review L1: the role may have changed since the caller's check, between the locks
        if g.role != role || !g.dek_live {
            return Err(NOLOGIN);
        }
        let mut next = g.clone();
        let dek = next.dek.clone();
        let key: &[u8; 32] = dek
            .as_deref()
            .ok_or(FF)?
            .as_slice()
            .try_into()
            .map_err(|_| FF)?;
        let h = &mut next.hdr;
        let (salt, nonce) = if role == Role::So {
            (&mut h.salt_so, &mut h.so_wrap_nonce)
        } else {
            (&mut h.salt_user, &mut h.user_wrap_nonce)
        };
        random(salt)?;
        random(nonce)?;
        let ct = wrap(key, new_pin, salt, nonce, &h.serial)?;
        if role == Role::So {
            next.hdr.so_wrap_ct = ct
        } else {
            next.hdr.user_wrap_ct = ct
        }
        let _lock = Flock::take(&mut g)?;
        next.counters_from(&g);
        self.audit(event::SET_PIN, role, Rv::OK, &[])?;
        next.write()?;
        *g = next;
        Ok(())
    }

    pub fn init_user_pin(&self, pin: &[u8]) -> Result<(), Rv> {
        if pin.len() < PIN_MIN {
            return Err(Rv::PIN_INCORRECT);
        }
        let mut g = self.g();
        if g.role != Role::So || !g.dek_live {
            return Err(NOLOGIN);
        }
        let mut next = g.clone();
        random(&mut next.hdr.salt_user)?;
        random(&mut next.hdr.user_wrap_nonce)?;
        next.hdr.user_wrap_ct = wrap(
            next.key()?,
            pin,
            &next.hdr.salt_user,
            &next.hdr.user_wrap_nonce,
            &next.hdr.serial,
        )?;
        next.hdr.user_initialized = true;
        let _lock = Flock::take(&mut g)?;
        next.counters_from(&g);
        next.hdr.failed_user = 0;
        next.until_user = 0;
        next.write()?;
        *g = next;
        Ok(())
    }

    pub fn reinit(&self, so_pin: &[u8], label: &[u8]) -> Result<(), Rv> {
        if so_pin.len() < PIN_MIN {
            return Err(Rv::PIN_INCORRECT);
        }
        let mut g = self.g();
        let mut next = g.clone();
        let h = &mut next.hdr;
        put_label(&mut h.label, label);
        h.serial = new_serial()?;
        h.user_wrap_ct = [0; 48];
        h.user_wrap_nonce = [0; 12];
        h.salt_user = [0; 16];
        random(&mut h.salt_so)?;
        h.pbkdf2_iter = header::PBKDF2_ITER;
        let mut k = Zeroizing::new([0u8; 32]);
        random(&mut *k)?;
        next.dek = Some(Arc::new(mem::key(&k)?));
        next.dek_live = true;
        next.store = Store {
            next_handle: 1,
            objects: vec![],
        };
        next.public = false;
        next.loaded = true;
        random(&mut next.hdr.so_wrap_nonce)?;
        next.hdr.so_wrap_ct = wrap(
            next.key()?,
            so_pin,
            &next.hdr.salt_so,
            &next.hdr.so_wrap_nonce,
            &next.hdr.serial,
        )?;
        next.hdr.user_initialized = false;
        next.role = Role::None;
        next.until_so = 0;
        next.until_user = 0;
        let _lock = Flock::take(&mut g)?;
        next.hdr.failed_so = 0;
        next.hdr.failed_user = 0;
        let lab = cstr(&next.hdr.label).to_vec();
        self.audit(event::TOKEN_REINIT, Role::So, Rv::OK, &[(b"label", &lab)])?;
        next.write()?;
        // DIV-015(a)
        let sealed = if self.platform.sealing_required {
            self.platform.tpm.seal_companion(&next.path, next.key()?)
        } else {
            tpm::unlink_companion(&next.path);
            Ok(())
        };
        // DIV-014
        next.drop_dek();
        // review M-1: the file is re-initialised even if the seal failed, so the token follows it
        *g = next;
        if let Err(e) = sealed {
            tpm::unlink_companion(&g.path);
            let _ = self.audit(
                event::SEAL_FAILURE,
                Role::So,
                e,
                &[(b"tpm-seal-reinit", &hex(e))],
            );
            return Err(e);
        }
        Ok(())
    }

    pub fn label(&self) -> Vec<u8> {
        cstr(&self.g().hdr.label).to_vec()
    }

    pub fn serial(&self) -> Vec<u8> {
        cstr(&self.g().hdr.serial).to_vec()
    }

    pub fn failed_count(&self, role: Role) -> u32 {
        let g = self.g();
        if role == Role::So {
            g.hdr.failed_so
        } else {
            g.hdr.failed_user
        }
    }

    pub fn user_initialized(&self) -> bool {
        self.g().hdr.user_initialized
    }

    pub fn is_locked(&self, role: Role) -> bool {
        self.failed_count(role) >= PIN_MAX_FAILED
    }

    pub fn throttle_remaining_ms(&self, role: Role) -> u64 {
        let until = {
            let g = self.g();
            if role == Role::So {
                g.until_so
            } else {
                g.until_user
            }
        };
        until.saturating_sub(now_ms())
    }

    pub fn object_add(
        &self,
        class: u32,
        key_type: u32,
        label: Option<&[u8]>,
        value: &[u8],
        id: &[u8],
        flags: u8,
    ) -> Result<Handle, Rv> {
        if value.len() > store::VALUE_MAX {
            return Err(Rv::KEY_SIZE_RANGE);
        }
        if id.len() > 32 {
            return Err(Rv::ARGUMENTS_BAD);
        }
        let mut g = self.g();
        g.writable()?;
        if g.store.objects.len() >= store::MAX_OBJECTS {
            return Err(Rv::DEVICE_MEMORY);
        }
        let mut next = g.clone();
        let mut o = Object {
            handle: if g.store.next_handle == 0 {
                1
            } else {
                g.store.next_handle
            },
            class,
            key_type,
            value: store::Value::new(value, flags & store::OBJF_SENSITIVE != 0)?,
            flags,
            ..Default::default()
        };
        if let Some(l) = label {
            put_label(&mut o.label, l);
        }
        if !id.is_empty() {
            o.id[..id.len()].copy_from_slice(id);
            o.id_len = id.len() as u32;
        }
        let h = o.handle;
        next.store.next_handle = h.wrapping_add(1);
        next.store.objects.push(o);
        let lab = label.map(|l| cstr(l).to_vec()).unwrap_or_default();
        self.commit(
            &mut g,
            next,
            Some((event::OBJECT_CREATE, vec![(b"label".to_vec(), lab)])),
        )?;
        Ok(h)
    }

    pub fn object_get(&self, h: Handle) -> Result<(Vec<u8>, u32, u32), Rv> {
        let g = self.g();
        g.visible()?;
        let o = g.obj(h)?;
        Ok((o.value.to_vec(), o.class, o.key_type))
    }

    /// The value itself, shared with the store: its bytes stay where they are until the object
    /// leaves the store (the C ABI hands out a pointer to them, RULE-078).
    pub fn object_value(&self, h: Handle) -> Result<(store::Value, u32, u32), Rv> {
        let g = self.g();
        g.visible()?;
        let o = g.obj(h)?;
        Ok((o.value.clone(), o.class, o.key_type))
    }

    pub fn object_find(
        &self,
        class: Option<u32>,
        label: Option<&[u8]>,
        cap: usize,
    ) -> Result<(Vec<Handle>, usize), Rv> {
        let g = self.g();
        g.visible()?;
        let want = label.map(|l| {
            let l = cstr(l);
            &l[..l.len().min(64)]
        });
        let mut hs = Vec::new();
        let mut n = 0;
        for o in &g.store.objects {
            if class.is_some_and(|c| c != o.class) {
                continue;
            }
            if let Some(w) = want
                && cstr(&o.label) != w
            {
                continue;
            }
            if hs.len() < cap {
                hs.push(o.handle);
            }
            n += 1;
        }
        Ok((hs, n))
    }

    pub fn object_get_label(&self, h: Handle) -> Result<Vec<u8>, Rv> {
        Ok(cstr(&self.g().obj(h)?.label).to_vec())
    }

    pub fn object_get_id(&self, h: Handle) -> Result<Vec<u8>, Rv> {
        let g = self.g();
        let o = g.obj(h)?;
        Ok(o.id[..o.id_len as usize].to_vec())
    }

    fn mutate(&self, h: Handle, f: impl FnOnce(&mut Object) -> Result<(), Rv>) -> Result<(), Rv> {
        let mut g = self.g();
        g.writable()?;
        let i = g.find(h).ok_or(Rv::KEY_HANDLE_INVALID)?;
        let mut next = g.clone();
        f(&mut next.store.objects[i])?;
        self.commit(&mut g, next, None)
    }

    pub fn object_set_meta(
        &self,
        h: Handle,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        app: Option<&[u8]>,
    ) -> Result<(), Rv> {
        if start.map_or(0, <[u8]>::len) > 8
            || end.map_or(0, <[u8]>::len) > 8
            || app.map_or(0, <[u8]>::len) > 64
        {
            return Err(Rv::ATTRIBUTE_VALUE_INVALID);
        }
        self.mutate(h, |o| {
            if let Some(s) = start {
                o.start_date[..s.len()].copy_from_slice(s);
                o.start_date_len = s.len() as u8;
            }
            if let Some(s) = end {
                o.end_date[..s.len()].copy_from_slice(s);
                o.end_date_len = s.len() as u8;
            }
            if let Some(s) = app {
                o.application[..s.len()].copy_from_slice(s);
                o.application_len = s.len() as u8;
            }
            Ok(())
        })
    }

    pub fn object_get_meta(&self, h: Handle, which: Meta) -> Result<Vec<u8>, Rv> {
        let g = self.g();
        let o = g.obj(h)?;
        Ok(match which {
            Meta::StartDate => o.start_date[..o.start_date_len as usize].to_vec(),
            Meta::EndDate => o.end_date[..o.end_date_len as usize].to_vec(),
            Meta::Application => o.application[..o.application_len as usize].to_vec(),
        })
    }

    pub fn object_get_flags(&self, h: Handle) -> Result<u8, Rv> {
        Ok(self.g().obj(h)?.flags)
    }
    pub fn object_set_flags(&self, h: Handle, flags: u8) -> Result<(), Rv> {
        self.mutate(h, |o| {
            // #127: a value turning sensitive moves into the secure heap (`src/fhsm_token.c:2557`)
            if flags & store::OBJF_SENSITIVE != 0 && !o.value.is_empty() && !o.value.is_secure() {
                o.value = store::Value::new(&o.value, true)?;
            }
            o.flags = flags;
            Ok(())
        })
    }
    pub fn object_get_flags2(&self, h: Handle) -> Result<u8, Rv> {
        Ok(self.g().obj(h)?.flags2)
    }
    pub fn object_set_flags2(&self, h: Handle, v: u8) -> Result<(), Rv> {
        self.mutate(h, |o| {
            o.flags2 = v;
            Ok(())
        })
    }
    pub fn object_get_flags3(&self, h: Handle) -> Result<u8, Rv> {
        Ok(self.g().obj(h)?.flags3)
    }
    pub fn object_set_flags3(&self, h: Handle, v: u8) -> Result<(), Rv> {
        self.mutate(h, |o| {
            o.flags3 = v;
            Ok(())
        })
    }
    pub fn object_get_usage(&self, h: Handle) -> Result<u8, Rv> {
        Ok(self.g().obj(h)?.usage)
    }
    pub fn object_set_usage(&self, h: Handle, v: u8) -> Result<(), Rv> {
        self.mutate(h, |o| {
            o.usage = v;
            Ok(())
        })
    }
    pub fn object_is_token(&self, h: Handle) -> Result<bool, Rv> {
        Ok(self.g().obj(h)?.owner_session == 0)
    }

    pub fn object_set_label(&self, h: Handle, label: &[u8]) -> Result<(), Rv> {
        self.mutate(h, |o| {
            o.label = [0; 64];
            put_label(&mut o.label, label);
            Ok(())
        })
    }

    pub fn object_set_id(&self, h: Handle, id: &[u8]) -> Result<(), Rv> {
        if id.len() > 32 {
            return Err(Rv::ATTRIBUTE_VALUE_INVALID);
        }
        self.mutate(h, |o| {
            o.id = [0; 32];
            o.id[..id.len()].copy_from_slice(id);
            o.id_len = id.len() as u32;
            Ok(())
        })
    }

    pub fn object_set_allowed_mechs(&self, h: Handle, mechs: &[u32]) -> Result<(), Rv> {
        if mechs.len() > store::POLICY_MECH_MAX {
            return Err(Rv::ATTRIBUTE_VALUE_INVALID);
        }
        self.mutate(h, |o| {
            o.allowed = [0; store::POLICY_MECH_MAX];
            o.allowed[..mechs.len()].copy_from_slice(mechs);
            o.allowed_count = mechs.len() as u8;
            o.flags2 |= store::OBJF2_HAS_ALLOWED_MECH;
            Ok(())
        })
    }

    pub fn object_get_allowed_mechs(&self, h: Handle) -> Result<Vec<u32>, Rv> {
        let g = self.g();
        g.visible()?;
        let o = g.obj(h)?;
        Ok(o.allowed[..o.allowed_count as usize].to_vec())
    }

    pub fn object_mech_allowed(&self, h: Handle, mech: u32) -> Result<(), Rv> {
        let g = self.g();
        if g.visible().is_err() {
            return Ok(());
        }
        match g.obj(h) {
            Err(_) => Ok(()),
            Ok(o) if o.flags2 & store::OBJF2_HAS_ALLOWED_MECH == 0 => Ok(()),
            Ok(o) => {
                if o.allowed[..o.allowed_count as usize].contains(&mech) {
                    Ok(())
                } else {
                    Err(Rv::MECHANISM_INVALID)
                }
            }
        }
    }

    pub fn object_set_tmpl(&self, h: Handle, which: Tmpl, attrs: &[PolicyAttr]) -> Result<(), Rv> {
        if attrs.len() > store::POLICY_ATTR_MAX {
            return Err(Rv::ATTRIBUTE_VALUE_INVALID);
        }
        if attrs.iter().any(|a| {
            a.len as usize > store::POLICY_VALUE_MAX
                || a.kind == store::KIND_NONE
                || a.kind > store::KIND_BYTES
        }) {
            return Err(Rv::ATTRIBUTE_VALUE_INVALID);
        }
        self.mutate(h, |o| {
            let (c, slot, bit) = match which {
                Tmpl::Wrap => (&mut o.wrap_count, &mut o.wrap, store::OBJF2_HAS_WRAP_TMPL),
                Tmpl::Unwrap => (
                    &mut o.unwrap_count,
                    &mut o.unwrap,
                    store::OBJF2_HAS_UNWRAP_TMPL,
                ),
                Tmpl::Derive => (
                    &mut o.derive_count,
                    &mut o.derive,
                    store::OBJF2_HAS_DERIVE_TMPL,
                ),
            };
            *slot = [PolicyAttr::default(); store::POLICY_ATTR_MAX];
            for (d, a) in slot.iter_mut().zip(attrs) {
                // DIV-026: C kept the caller's bytes past `len`
                d.type_ = a.type_;
                d.kind = a.kind;
                d.len = a.len;
                d.value[..a.len as usize].copy_from_slice(&a.value[..a.len as usize]);
            }
            *c = attrs.len() as u8;
            o.flags2 |= bit;
            Ok(())
        })
    }

    pub fn object_get_tmpl(&self, h: Handle, which: Tmpl) -> Result<Vec<PolicyAttr>, Rv> {
        let g = self.g();
        g.visible()?;
        let o = g.obj(h)?;
        let (c, s) = match which {
            Tmpl::Wrap => (o.wrap_count, &o.wrap),
            Tmpl::Unwrap => (o.unwrap_count, &o.unwrap),
            Tmpl::Derive => (o.derive_count, &o.derive),
        };
        Ok(s[..c as usize].to_vec())
    }

    pub fn object_policy_counts(&self, h: Handle) -> Result<[u8; 4], Rv> {
        let g = self.g();
        g.visible()?;
        let o = g.obj(h)?;
        Ok([
            o.allowed_count,
            o.wrap_count,
            o.unwrap_count,
            o.derive_count,
        ])
    }

    pub fn object_destroy(&self, h: Handle) -> Result<(), Rv> {
        let mut g = self.g();
        g.writable()?;
        let i = g.find(h).ok_or(Rv::KEY_HANDLE_INVALID)?;
        let mut next = g.clone();
        next.store.objects.swap_remove(i);
        let _lock = Flock::take(&mut g)?;
        next.counters_from(&g);
        self.audit(event::OBJECT_DESTROY, g.role, Rv::OK, &[])?;
        next.write()?;
        *g = next;
        Ok(())
    }

    pub fn object_mark_session(&self, h: Handle, owner: u32) -> Result<(), Rv> {
        if owner == 0 {
            return Err(Rv::ARGUMENTS_BAD);
        }
        self.mutate(h, |o| {
            o.owner_session = owner;
            Ok(())
        })
    }

    pub fn destroy_session_objects(&self, owner: u32) -> Result<(), Rv> {
        if owner == 0 {
            return Err(Rv::ARGUMENTS_BAD);
        }
        let mut g = self.g();
        let mut next = g.clone();
        let mut removed = false;
        let mut i = 0;
        while i < next.store.objects.len() {
            if next.store.objects[i].owner_session == owner {
                next.store.objects.swap_remove(i);
                removed = true;
            } else {
                i += 1;
            }
        }
        if !removed {
            return Ok(());
        }
        self.commit(&mut g, next, None)
    }
}
