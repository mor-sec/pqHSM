//! The slot registry, `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo` and `C_InitToken`
//! (`src/fhsm_pkcs11.c:1014-1269`, `:1681-1731`; Phase 4 slice 1d).
//!
//! As C: slots 0-3 are `<tokens dir>/slot<N>.tok`, the table is built once per process at
//! first use and never rebuilt (C reset a flag that its `pthread_once` never read again), and a
//! slot's token is loaded on first use, under the registry's lock, and closed by `C_Finalize`
//! and by a forked child's `C_Initialize`.
#![allow(clippy::missing_safety_doc)]

use std::cell::UnsafeCell;
use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_uchar, c_ulong, c_void};
use std::os::unix::ffi::OsStrExt;
use std::ptr::{NonNull, null_mut};

use pqhsm_core::p11::{self, MAX_SLOTS, VERSION, pack_field};
use pqhsm_core::session::ROLE_SO;

use super::apilock::Held;
use super::session::{TABLE, Tok};
use super::state::in_error;
use super::sys::*;

struct Slot {
    present: bool,
    path: CString,
    token: Option<Tok>,
}

type Table = [Slot; MAX_SLOTS as usize];

/// The registry under a pthread mutex, as the rest of `ffi`: TSan sees pthread, and the Rust is
/// not instrumented, so a std lock here hid the hand-over of the paths from it.
struct Registry {
    mu: UnsafeCell<libc::pthread_mutex_t>,
    table: UnsafeCell<Option<Table>>,
}
// SAFETY: `table` is only reached through `Locked`, which holds `mu`.
unsafe impl Sync for Registry {}

static SLOTS: Registry = Registry {
    mu: UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER),
    table: UnsafeCell::new(None),
};

/// `SLOTS` locked; unlocked on drop.
struct Locked;

impl Locked {
    fn new() -> Self {
        // SAFETY: a statically initialised mutex, never destroyed
        unsafe { libc::pthread_mutex_lock(SLOTS.mu.get()) };
        Locked
    }

    fn table(&mut self) -> &mut Option<Table> {
        // SAFETY: the mutex is held for as long as `self`, and `self` is borrowed mutably
        unsafe { &mut *SLOTS.table.get() }
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        // SAFETY: locked by `new`
        unsafe { libc::pthread_mutex_unlock(SLOTS.mu.get()) };
    }
}

/// `fhsm_tokens_dir`.
pub(crate) fn tokens_dir() -> Vec<u8> {
    env_nonempty("FHSM_TOKENS_DIR").unwrap_or_else(|| b"/var/lib/freehsm/tokens".to_vec())
}

/// The registry, locked, built on first use.
fn slots() -> impl std::ops::DerefMut<Target = Table> {
    struct Built(Locked);
    impl std::ops::Deref for Built {
        type Target = Table;
        fn deref(&self) -> &Table {
            // SAFETY: as `Locked::table`; built before `Built` is returned
            unsafe { (*SLOTS.table.get()).as_ref().expect("built") }
        }
    }
    impl std::ops::DerefMut for Built {
        fn deref_mut(&mut self) -> &mut Table {
            self.0.table().as_mut().expect("built")
        }
    }
    let mut l = Locked::new();
    l.table().get_or_insert_with(|| {
        let dir = tokens_dir();
        std::array::from_fn(|i| {
            let path = bounded([&dir[..], format!("/slot{i}.tok").as_bytes()].concat(), 512);
            let present = std::fs::metadata(OsStr::from_bytes(path.as_bytes())).is_ok();
            Slot {
                present,
                path,
                token: None,
            }
        })
    });
    Built(l)
}

/// `fhsm_slot_token`: the slot's token, loaded on first use; `None` if the slot is out of
/// range, blank, or its file does not load (tried again next time).
pub(crate) fn slot_token(slot: c_ulong) -> Option<Tok> {
    if slot >= MAX_SLOTS {
        return None;
    }
    let mut s = slots();
    let s = &mut s[slot as usize];
    if !s.present {
        return None;
    }
    if s.token.is_none() {
        let mut t = null_mut();
        // SAFETY: a NUL-terminated path and an out pointer of our own
        if unsafe { fhsm_token_load(s.path.as_ptr(), &mut t) } == OK {
            s.token = NonNull::new(t).map(Tok);
        }
    }
    s.token
}

/// Every loaded token closed (its DEK zeroised, its objects freed); the table itself stays.
pub(crate) fn close_all() {
    let mut l = Locked::new();
    let Some(t) = l.table() else { return };
    for s in t.iter_mut() {
        if let Some(t) = s.token.take() {
            // SAFETY: a token fhsm_token_load or fhsm_token_init gave us, closed once
            unsafe { fhsm_token_close(t.0.as_ptr()) };
        }
    }
}

/// `fhsm_slot_table_init_once`, at the points C calls it: the build reads FHSM_TOKENS_DIR and
/// stats the files then.
fn init_once() {
    drop(slots());
}

fn present(slot: c_ulong) -> bool {
    slots()[slot as usize].present
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_GetSlotList(
    token_present: c_uchar,
    list: *mut c_ulong,
    count: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    if count.is_null() {
        return ARGUMENTS_BAD.into();
    }
    init_once();
    let ids: Vec<c_ulong> = (0..MAX_SLOTS)
        .filter(|&i| token_present == 0 || present(i))
        .collect();
    let n = ids.len() as c_ulong;
    // SAFETY: count is non-NULL and, by the caller's contract, writable; list, when non-NULL,
    // holds *count entries, and at most n <= *count are written
    unsafe {
        if !list.is_null() {
            if *count < n {
                *count = n;
                return BUFFER_TOO_SMALL.into();
            }
            std::ptr::copy_nonoverlapping(ids.as_ptr(), list, ids.len());
        }
        *count = n;
    }
    OK.into()
}

/// `CK_SLOT_INFO`.
#[repr(C)]
struct SlotInfo {
    description: [u8; 64],
    manufacturer: [u8; 32],
    flags: c_ulong,
    hardware: [u8; 2],
    firmware: [u8; 2],
}

const MANUFACTURER: &[u8] = b"Simorgh Labs";
/// `CKF_TOKEN_PRESENT`: every configured slot, blank or not (the SoftHSMv2 convention C keeps,
/// so `pkcs11-tool` reaches `C_InitToken`).
const TOKEN_PRESENT: c_ulong = 0x1;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_GetSlotInfo(slot: c_ulong, info: *mut c_void) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    if info.is_null() {
        return ARGUMENTS_BAD.into();
    }
    if slot >= MAX_SLOTS {
        return SLOT_ID_INVALID.into();
    }
    let state = if present(slot) {
        "initialized"
    } else {
        "uninitialized"
    };
    let desc = format!("FreeHSM slot {slot} ({state})");
    let i = info.cast::<SlotInfo>();
    // SAFETY: by the caller's contract, a writable CK_SLOT_INFO; fields only, as C wrote them
    unsafe {
        pack_field(&mut (*i).description, desc.as_bytes());
        pack_field(&mut (*i).manufacturer, MANUFACTURER);
        (*i).flags = TOKEN_PRESENT;
        (*i).hardware = [1, 0];
        (*i).firmware = VERSION;
    }
    OK.into()
}

/// `CK_TOKEN_INFO`.
#[repr(C)]
struct TokenInfo {
    label: [u8; 32],
    manufacturer: [u8; 32],
    model: [u8; 16],
    serial: [u8; 16],
    flags: c_ulong,
    max_sessions: c_ulong,
    sessions: c_ulong,
    max_rw_sessions: c_ulong,
    rw_sessions: c_ulong,
    max_pin: c_ulong,
    min_pin: c_ulong,
    total_public: c_ulong,
    free_public: c_ulong,
    total_private: c_ulong,
    free_private: c_ulong,
    hardware: [u8; 2],
    firmware: [u8; 2],
    utc_time: [u8; 16],
}

const RNG: c_ulong = 0x1;
const LOGIN_REQUIRED: c_ulong = 0x4;
const USER_PIN_INITIALIZED: c_ulong = 0x8;
const TOKEN_INITIALIZED: c_ulong = 0x400;
const USER_PIN_LOCKED: c_ulong = 0x4_0000;
const SO_PIN_LOCKED: c_ulong = 0x40_0000;

/// A token's C string, or "" for none.
fn cstr<'a>(p: *const c_char) -> &'a [u8] {
    // SAFETY: the token's label and serial are NUL-terminated and live as long as the token
    if p.is_null() {
        b""
    } else {
        unsafe { CStr::from_ptr(p) }.to_bytes()
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_GetTokenInfo(slot: c_ulong, info: *mut c_void) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    if info.is_null() {
        return ARGUMENTS_BAD.into();
    }
    if slot >= MAX_SLOTS {
        return SLOT_ID_INVALID.into();
    }
    // A blank slot answers too, without CKF_TOKEN_INITIALIZED: applications ask before
    // C_InitToken.
    let t = slot_token(slot).map(|t| t.0.as_ptr());
    let mut flags = RNG | LOGIN_REQUIRED;
    let (mut label, mut serial): (&[u8], &[u8]) = (b"", b"");
    if let Some(t) = t {
        // SAFETY: a token the registry holds, read under the API lock as C did
        unsafe {
            label = cstr(fhsm_token_label(t));
            serial = cstr(fhsm_token_serial(t));
            flags |= TOKEN_INITIALIZED;
            if fhsm_token_user_initialized(t) != 0 {
                flags |= USER_PIN_INITIALIZED;
            }
            if fhsm_token_is_locked(t, p11::ROLE_USER) != 0 {
                flags |= USER_PIN_LOCKED;
            }
            if fhsm_token_is_locked(t, ROLE_SO) != 0 {
                flags |= SO_PIN_LOCKED;
            }
        }
    }
    let model: &[u8] = if std::env::var_os("FHSM_INTEGRITY_ALLOW_UNSIGNED").is_some() {
        b"FreeHSM-TESTMODE"
    } else {
        b"FreeHSM-C-v1"
    };
    let i = info.cast::<TokenInfo>();
    // SAFETY: by the caller's contract, a writable CK_TOKEN_INFO; fields only, as C wrote them
    unsafe {
        pack_field(&mut (*i).label, label);
        pack_field(&mut (*i).manufacturer, MANUFACTURER);
        pack_field(&mut (*i).model, model);
        pack_field(&mut (*i).serial, serial);
        (*i).flags = flags;
        (*i).max_sessions = 128;
        (*i).sessions = 0;
        (*i).max_rw_sessions = 128;
        (*i).rw_sessions = 0;
        (*i).max_pin = p11::PIN_MAX_LEN;
        (*i).min_pin = p11::NEW_PIN_MIN_LEN;
        (*i).total_public = 0;
        (*i).free_public = 0;
        (*i).total_private = 0;
        (*i).free_private = 0;
        (*i).hardware = [1, 0];
        (*i).firmware = VERSION;
        pack_field(&mut (*i).utc_time, b"");
    }
    OK.into()
}

/// A PIN of `len` bytes, already range-checked; `None` holds a NUL inside (CKR_PIN_INVALID).
/// The copy is NUL-terminated for the token, which reads C strings.
pub(crate) fn pin_copy(pin: *const c_char, len: c_ulong) -> Option<[u8; 128]> {
    // SAFETY: by the caller's contract, `len` readable bytes; len <= 64 after the range check
    let b = unsafe { std::slice::from_raw_parts(pin.cast::<u8>(), len as usize) };
    if b.contains(&0) {
        return None;
    }
    let mut out = [0u8; 128];
    out[..b.len()].copy_from_slice(b);
    Some(out)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_InitToken(
    slot: c_ulong,
    pin: *const c_char,
    pin_len: c_ulong,
    label: *const c_char,
) -> c_ulong {
    let _g = Held::exclusive();
    if let Err(rv) = super::lifecycle::initialized() {
        return rv.into();
    }
    if in_error() {
        return FUNCTION_FAILED.into();
    }
    if slot >= MAX_SLOTS {
        return SLOT_ID_INVALID.into();
    }
    if pin.is_null() {
        return ARGUMENTS_BAD.into();
    }
    if !p11::new_pin_len_ok(pin_len) {
        return PIN_LEN_RANGE.into();
    }
    let Some(mut pin_c) = pin_copy(pin, pin_len) else {
        return PIN_INVALID.into();
    };
    if label.is_null() {
        zeroize(&mut pin_c);
        return ARGUMENTS_BAD.into();
    }
    init_once();
    // Before the SO PIN, so a refusal here costs no attempt.
    if TABLE.exists_on_slot(slot) {
        zeroize(&mut pin_c);
        return SESSION_EXISTS.into();
    }
    // SAFETY: by the caller's contract, the 32-byte CK_UTF8CHAR label field
    let field = unsafe { &*label.cast::<[u8; 32]>() };
    let label_c = p11::label(field);
    let (pin_p, label_p) = (
        pin_c.as_ptr().cast::<c_char>(),
        label_c.as_ptr().cast::<c_char>(),
    );

    let rv = if present(slot) {
        match slot_token(slot) {
            None => FUNCTION_FAILED,
            // SAFETY: a token the registry holds; NUL-terminated PIN and label copies
            Some(t) => unsafe {
                let rv = fhsm_token_verify_pin(t.0.as_ptr(), ROLE_SO, pin_p, pin_len as usize);
                if rv == OK {
                    fhsm_token_reinit(t.0.as_ptr(), pin_p, label_p)
                } else {
                    rv
                }
            },
        }
    } else {
        let mut s = slots();
        let s = &mut s[slot as usize];
        let mut t = null_mut();
        // SAFETY: NUL-terminated path, PIN and label; an out pointer of our own
        let rv = unsafe { fhsm_token_init(s.path.as_ptr(), pin_p, label_p, &mut t) };
        if rv == OK {
            s.present = true;
            s.token = NonNull::new(t).map(Tok);
        }
        rv
    };
    zeroize(&mut pin_c);
    audit(EV_TOKEN_INIT, slot as c_int, -1, ROLE_SO, rv, &[]);
    rv.into()
}
