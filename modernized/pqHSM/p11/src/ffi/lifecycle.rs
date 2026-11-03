//! `C_Initialize`, `C_Finalize` and `C_GetInfo` (`src/fhsm_pkcs11.c:382-547`, `:660-746`,
//! `:2083-2158`; Phase 4 slice 1d).
//!
//! As C: the process that initialised is remembered, and a forked child's `C_Initialize`
//! drops everything it inherited (tokens, sessions, operation and find state, the state
//! machine) before starting; `C_Finalize` releases the same state in its own process. The
//! operation, find and OAEP tables are still C's, so those two teardowns call into
//! `p11/shim/pkcs11_tu.c` for them, in C's order.
#![allow(clippy::missing_safety_doc)]

use std::ffi::{CStr, CString, OsStr, c_char, c_int, c_ulong, c_void};
use std::os::unix::ffi::OsStrExt;
use std::sync::atomic::{AtomicI32, Ordering::Relaxed};

use pqhsm_core::p11::{VERSION, pack_field};
use pqhsm_core::state::{INITIALIZED, INITIALIZING, POWER_OFF};

use super::apilock::Held;
use super::session::TABLE;
use super::slots;
use super::state::{fhsm_state_latch_error, fhsm_state_reset_after_fork, fhsm_state_set};
use super::sys::*;

/// `g_init_pid`: the process that set the state up; 0 once released.
static INIT_PID: AtomicI32 = AtomicI32::new(0);

/// `fhsm_reset_after_fork`. Operation contexts are zeroised, not freed: they belong to the
/// parent, which is still using them.
fn reset_after_fork() {
    slots::close_all();
    TABLE.reset_all();
    // SAFETY: C's tables, under the EXCLUSIVE lock
    unsafe { pqhsm_c_ops_forget_all() };
    fhsm_state_reset_after_fork();
}

/// `fhsm_finalize_release`: the same, in the owning process, so the contexts are freed.
fn finalize_release() {
    // SAFETY: C's tables, under the EXCLUSIVE lock
    unsafe { pqhsm_c_ops_release_all() };
    TABLE.reset_all();
    slots::close_all();
    INIT_PID.store(0, Relaxed);
}

fn latch(reason: &CStr) {
    // SAFETY: a NUL-terminated literal
    unsafe { fhsm_state_latch_error(reason.as_ptr()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_Initialize(_init_args: *mut c_void) -> c_ulong {
    let _g = Held::exclusive();
    // A state built by another process is a forked child's inheritance: drop it.
    let me = std::process::id() as i32;
    let was = INIT_PID.load(Relaxed);
    if was != 0 && was != me {
        reset_after_fork();
    }
    INIT_PID.store(me, Relaxed);

    // SAFETY: plain calls into the crypto crate
    let rv = unsafe { fhsm_secure_heap_init() };
    if rv != OK {
        return rv.into();
    }
    let rv = fhsm_state_set(INITIALIZING);
    if rv != OK {
        return rv.into();
    }
    // SAFETY: as above
    let rv = unsafe { fhsm_crypto_init() };
    if rv != OK {
        latch(c"crypto_init failed in C_Initialize");
        return rv.into();
    }
    if let Err(rv) = open_audit() {
        return rv.into();
    }
    let rv = fhsm_state_set(INITIALIZED);
    audit(EV_MODULE_INIT, -1, -1, 0, rv, &[]);
    rv.into()
}

/// The audit log, after the crypto layer (chaining needs HMAC). Every failure here latches
/// ERROR and is fatal; the messages are C's, word for word.
fn open_audit() -> Result<(), u32> {
    let dir = slots::tokens_dir();
    let logp = bounded(
        env_nonempty("FHSM_AUDIT_LOG").unwrap_or_else(|| [&dir[..], b"/audit.log"].concat()),
        512,
    );
    let sw = std::env::var_os("FHSM_AUDIT");
    let sw = sw.as_deref().map(OsStr::as_bytes);
    let want_off = matches!(sw, Some(b"off" | b"0"));
    // SAFETY: a constant the C translation unit defines from FHSM_AUDIT_MANDATORY
    let mandatory = unsafe { pqhsm_c_audit_mandatory } != 0;
    if want_off && mandatory {
        say(&[concat!(
            "[freehsm-c] FATAL : FHSM_AUDIT=off is refused by this build.\n",
            "  It was compiled with FHSM_AUDIT_MANDATORY=1, which means the\n",
            "  module will not run without a record of what it did. That is\n",
            "  the default and the intended setting where the audit trail is\n",
            "  part of what the deployment has to show.\n",
            "  To allow it, rebuild with -DFHSM_AUDIT_MANDATORY=0.\n",
        )
        .as_bytes()]);
        latch(c"audit switched off in a mandatory build");
        return Err(FUNCTION_FAILED);
    }
    if want_off {
        say(&[
            b"[freehsm-c] NOTE : the audit log is OFF (FHSM_AUDIT=",
            sw.unwrap_or_default(),
            concat!(
                ").\n",
                "  Nothing this module does will be recorded: no signature, no\n",
                "  login, no failure. Weekly review as described in AGD_OPE 4.3\n",
                "  has nothing to review, and an incident afterwards has nothing\n",
                "  to reconstruct from. This build permits it because it was\n",
                "  compiled with FHSM_AUDIT_MANDATORY=0.\n",
            )
            .as_bytes(),
        ]);
        return Ok(());
    }

    // A fresh install has no tokens directory yet; 0700, it holds the tokens and the key.
    let dir_c = CString::new(dir.clone()).expect("an environment string: no NUL");
    if std::fs::metadata(OsStr::from_bytes(&dir)).is_err()
        // SAFETY: a NUL-terminated path
        && unsafe { libc::mkdir(dir_c.as_ptr(), 0o700) } != 0
    {
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if e != libc::EEXIST {
            // SAFETY: strerror's string, read at once, under the EXCLUSIVE lock
            let why = unsafe { CStr::from_ptr(libc::strerror(e)) }.to_bytes();
            say(&[
                b"[freehsm-c] FATAL : cannot create the tokens directory ",
                &dir,
                b" : ",
                why,
                b"\n  The audit log lives there and the module will not run without it.\n  \
Create it, or point FHSM_TOKENS_DIR somewhere writable.\n",
            ]);
            latch(c"tokens directory unusable");
            return Err(FUNCTION_FAILED);
        }
    }

    let mut key = [0u8; 32];
    let mut sealed: c_int = 0;
    // SAFETY: a NUL-terminated directory, a 32-byte key buffer and an int of our own
    let arv = unsafe { fhsm_audit_key_provision(dir_c.as_ptr(), key.as_mut_ptr(), &mut sealed) };
    if arv != OK {
        let rv = format!("{arv:x}");
        say(&[
            b"[freehsm-c] FATAL : cannot provision the audit key in ",
            &dir,
            b" (rv=0x",
            rv.as_bytes(),
            b")\n  Checked ",
            &dir,
            b"/audit.key and ",
            &dir,
            b"/audit.key.tpm.\n  A key readable by group or others is refused on purpose ;\n  \
so is a sealed blob that will not unseal. See AGD_OPE 4.4.\n",
        ]);
        latch(c"audit key could not be provisioned");
        return Err(arv);
    }
    // SAFETY: a NUL-terminated path and the key, which outlives the call
    let arv = unsafe {
        fhsm_audit_open(
            logp.as_ptr(),
            Slice {
                data: key.as_ptr(),
                len: 32,
            },
        )
    };
    zeroize(&mut key);
    if arv == OK {
        // A base that is not a regular file is used as given: a stream, not a log. The
        // opening reports the file it took; if that is the name given, it is a stream.
        let mut actual = [0u8; 600];
        // SAFETY: a buffer of that capacity, NUL-terminated by the callee
        unsafe { fhsm_audit_current_path(actual.as_mut_ptr().cast::<c_char>(), actual.len()) };
        let actual = CStr::from_bytes_until_nul(&actual)
            .map(CStr::to_bytes)
            .unwrap_or(b"");
        if actual == logp.as_bytes() {
            say(&[
                b"[freehsm-c] NOTE : the audit target ",
                logp.as_bytes(),
                b" is not a regular\n  file. Lines are written to it, but nothing is made durable\n  \
and no chain can be verified afterwards. This is a stream,\n  not a log. If that was not \
intended, name a directory on\n  persistent storage instead.\n",
            ]);
        }
        return Ok(());
    }
    let rv = format!("{arv:x}");
    say(&[
        b"[freehsm-c] FATAL : cannot open the audit log ",
        logp.as_bytes(),
        b" (rv=0x",
        rv.as_bytes(),
        b")\n  An existing log whose last line cannot be parsed is refused\n  \
rather than continued, which would start a second chain in\n  the same file. See AGD_OPE 4.3.\n",
    ]);
    latch(c"audit log could not be opened");
    Err(arv)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_Finalize(_reserved: *mut c_void) -> c_ulong {
    let _g = Held::exclusive();
    audit(EV_MODULE_FINALIZE, -1, -1, 0, OK, &[]);
    // Before the crypto layer goes down: the operation contexts freed are OpenSSL objects.
    finalize_release();
    // SAFETY: plain calls into the crypto and audit crates
    unsafe {
        fhsm_crypto_finalize();
        fhsm_audit_close();
    }
    fhsm_state_set(POWER_OFF);
    OK.into()
}

/// `CK_INFO`.
#[repr(C)]
struct Info {
    cryptoki: [u8; 2],
    manufacturer: [u8; 32],
    flags: c_ulong,
    description: [u8; 32],
    library: [u8; 2],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_GetInfo(info: *mut c_void) -> c_ulong {
    let _g = Held::shared();
    if info.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // The integrity bypass says so in the field every consumer prints.
    let desc: &[u8] = if std::env::var_os("FHSM_INTEGRITY_ALLOW_UNSIGNED").is_some() {
        b"FreeHSM C - TEST MODE, NOT PROD"
    } else {
        b"FreeHSM C PKCS#11 module"
    };
    let i = info.cast::<Info>();
    // SAFETY: by the caller's contract, a writable CK_INFO; fields only, as C wrote them
    unsafe {
        (*i).cryptoki = [3, 2];
        pack_field(&mut (*i).manufacturer, b"Simorgh Labs");
        (*i).flags = 0;
        pack_field(&mut (*i).description, desc);
        (*i).library = VERSION;
    }
    OK.into()
}
