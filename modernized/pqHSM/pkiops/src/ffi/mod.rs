//! The module opened with dlopen, its functions behind the call-log wrappers, and
//! `tools/pkiops.h` under its C names (`capi`). `ops` holds the operations past the loader.
//!
//! One module at a time, process-wide, as in C. The table is written by `pkiops_load` and
//! `pkiops_unload` only; the GUI calls those from one thread, as it did C's.
#![allow(non_camel_case_types)]

mod capi;

use std::ffi::{CStr, CString, c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::Instant;

use crate::calllog::{ARGS_CAP, attr_types, mech_name, user_name};
use crate::ops::{self, Slot};
use crate::{Error, FUNCTIONS, Intent, Need, SlotId, Slots};

pub(crate) type CK_ULONG = c_ulong;
type CK_RV = c_ulong;
type CK_BYTE = c_uchar;

/// `CK_ATTRIBUTE` as `tools/p11_util.h` declares it.
#[repr(C)]
pub struct CK_ATTRIBUTE {
    pub type_: CK_ULONG,
    pub p_value: *mut c_void,
    pub value_len: CK_ULONG,
}

/// `CK_MECHANISM` as `tools/p11_util.h` declares it.
#[repr(C)]
pub struct CK_MECHANISM {
    pub mechanism: CK_ULONG,
    pub p_parameter: *mut c_void,
    pub parameter_len: CK_ULONG,
}

/// `struct p11_err` (`tools/p11_err.h`).
#[repr(C)]
pub struct p11_err {
    pub code: c_int,
    pub msg: [c_char; Error::CAP],
}

/// `struct pkiops_call` (`tools/pkiops.h`).
#[repr(C)]
pub struct pkiops_call {
    pub fn_: *const c_char,
    pub args: [c_char; ARGS_CAP],
    pub rv: c_ulong,
    pub ms: f64,
}

/// `pkiops_call_cb`.
pub type pkiops_call_cb = unsafe extern "C" fn(*const pkiops_call, *mut c_void);

/// `struct p11_function_list` (`tools/p11_util.h`): the version, then v2.40's 68 slots.
#[repr(C)]
struct FunctionList {
    major: c_uchar,
    minor: c_uchar,
    pfn: [*mut c_void; 68],
}

const N: usize = FUNCTIONS.len();

/// The module's own functions, indexed as [`FUNCTIONS`]. Null when not loaded or not given.
static REAL: [AtomicPtr<c_void>; N] = [const { AtomicPtr::new(null_mut()) }; N];
static INITIALISED: AtomicBool = AtomicBool::new(false);

struct Log(Option<pkiops_call_cb>, *mut c_void);
// SAFETY: the context pointer is the caller's, handed back to its callback untouched, as C did.
unsafe impl Send for Log {}
static LOG: Mutex<Log> = Mutex::new(Log(None, null_mut()));

fn index(name: &str) -> usize {
    FUNCTIONS
        .iter()
        .position(|f| f.0 == name)
        .expect("a function of FUNCTIONS")
}

/// The module's function `$name`, as type `$t`. A call with none loaded aborts (C called NULL).
/// Used inside the `unsafe` block of the call: a non-null entry is the module's function of
/// that slot, whose C signature `$t` is (`tools/p11_util.h`); data and function pointers have
/// one size here.
macro_rules! real {
    ($name:literal as $t:ty) => {{
        let p = REAL[index($name)].load(Ordering::Acquire);
        assert!(
            !p.is_null(),
            concat!("C_", $name, " called with no module loaded")
        );
        std::mem::transmute::<*mut c_void, $t>(p)
    }};
}

/// Whether the module gave the function `name` (C's `if (!p11.DestroyObject)`): the optional
/// ones of [`FUNCTIONS`] may be missing.
pub(crate) fn has(name: &str) -> bool {
    !REAL[index(name)].load(Ordering::Acquire).is_null()
}

/// `logcall`: report a call that has returned, if a callback is set.
fn logcall(name: &'static CStr, rv: CK_RV, t0: Instant, args: impl FnOnce() -> String) {
    let (cb, ctx) = {
        let g = LOG.lock().unwrap_or_else(|p| p.into_inner());
        (g.0, g.1)
    };
    let Some(cb) = cb else { return };
    let a = args();
    let n = a.len().min(ARGS_CAP - 1);
    let mut c = pkiops_call {
        fn_: name.as_ptr(),
        args: [0; ARGS_CAP],
        rv,
        ms: 0.0,
    };
    for (d, s) in c.args.iter_mut().zip(&a.as_bytes()[..n]) {
        *d = *s as c_char;
    }
    c.ms = t0.elapsed().as_secs_f64() * 1e3;
    // SAFETY: the caller's callback and context, as pkiops_set_call_log received them.
    unsafe { cb(&c, ctx) }
}

/// `*p` after a successful call, else 0, as each C summary prints it.
///
/// # Safety
/// `p` null or readable once `rv` is 0.
unsafe fn out(rv: CK_RV, p: *const CK_ULONG) -> CK_ULONG {
    // SAFETY: an output pointer the module was handed; read only after it returned OK.
    if rv == 0 && !p.is_null() {
        unsafe { *p }
    } else {
        0
    }
}

/// `*p` whatever the result, as w_Sign and w_SignFinal print it.
///
/// # Safety
/// `p` null or readable.
unsafe fn any(p: *const CK_ULONG) -> CK_ULONG {
    // SAFETY: an output pointer the module was handed, null or valid.
    unsafe { p.as_ref() }.copied().unwrap_or(0)
}

/// # Safety
/// `m` null or readable.
unsafe fn mech(m: *const CK_MECHANISM) -> String {
    // SAFETY: the caller's mechanism, null or valid for the call it was passed to.
    match unsafe { m.as_ref() } {
        Some(m) => mech_name(m.mechanism).into_owned(),
        None => "no mechanism".into(),
    }
}

/// # Safety
/// `t` null or `n` readable attributes.
unsafe fn types(t: *const CK_ATTRIBUTE, n: CK_ULONG, cap: usize) -> String {
    if t.is_null() || n == 0 {
        return attr_types([], cap);
    }
    // SAFETY: the caller's template of n attributes, as the module was given it.
    let t = unsafe { std::slice::from_raw_parts(t, n as usize) };
    attr_types(t.iter().map(|a| a.type_), cap)
}

fn none_if(p: *const c_void, suffix: &'static str) -> &'static str {
    if p.is_null() { suffix } else { "" }
}

// --- the wrappers: tools/pkiops.c's w_*, summary for summary --------------------------------

type S = CK_ULONG;
type M = *mut CK_MECHANISM;
type A = *mut CK_ATTRIBUTE;
type B = *mut CK_BYTE;
type P = *mut CK_ULONG;
type V = *mut c_void;

pub(crate) unsafe extern "C" fn w_initialize(a: V) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("Initialize" as unsafe extern "C" fn(V) -> CK_RV)(a) };
    logcall(c"C_Initialize", rv, t, String::new);
    rv
}
pub(crate) unsafe extern "C" fn w_finalize(a: V) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("Finalize" as unsafe extern "C" fn(V) -> CK_RV)(a) };
    logcall(c"C_Finalize", rv, t, String::new);
    rv
}
pub(crate) unsafe extern "C" fn w_open_session(sl: S, f: S, app: V, nfy: V, s: P) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe {
        real!("OpenSession" as unsafe extern "C" fn(S, S, V, V, P) -> CK_RV)(sl, f, app, nfy, s)
    };
    logcall(c"C_OpenSession", rv, t, || {
        format!("slot {sl}, flags 0x{f:x} -> session {}", unsafe {
            out(rv, s)
        })
    });
    rv
}
pub(crate) unsafe extern "C" fn w_close_session(s: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("CloseSession" as unsafe extern "C" fn(S) -> CK_RV)(s) };
    logcall(c"C_CloseSession", rv, t, || format!("session {s}"));
    rv
}
pub(crate) unsafe extern "C" fn w_login(s: S, u: S, pin: B, n: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("Login" as unsafe extern "C" fn(S, S, B, S) -> CK_RV)(s, u, pin, n) };
    logcall(c"C_Login", rv, t, || {
        format!("session {s}, {}, PIN not shown", user_name(u))
    });
    rv
}
#[allow(clippy::too_many_arguments)] // C_GenerateKeyPair's
pub(crate) unsafe extern "C" fn w_generate_key_pair(
    s: S,
    m: M,
    pt: A,
    pn: S,
    kt: A,
    kn: S,
    hp: P,
    hk: P,
) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe {
        real!("GenerateKeyPair" as unsafe extern "C" fn(S, M, A, S, A, S, P, P) -> CK_RV)(
            s, m, pt, pn, kt, kn, hp, hk,
        )
    };
    logcall(c"C_GenerateKeyPair", rv, t, || {
        format!(
            "session {s}, {} -> public {}, private {}",
            unsafe { mech(m) },
            unsafe { out(rv, hp) },
            unsafe { out(rv, hk) }
        )
    });
    rv
}
pub(crate) unsafe extern "C" fn w_find_objects_init(s: S, tp: A, n: S) -> CK_RV {
    let t = Instant::now();
    let rv =
        unsafe { real!("FindObjectsInit" as unsafe extern "C" fn(S, A, S) -> CK_RV)(s, tp, n) };
    logcall(c"C_FindObjectsInit", rv, t, || {
        format!(
            "session {s}, matching {}",
            if n != 0 {
                unsafe { types(tp, n, 120) }
            } else {
                "anything".into()
            }
        )
    });
    rv
}
pub(crate) unsafe extern "C" fn w_find_objects(s: S, h: P, max: S, n: P) -> CK_RV {
    let t = Instant::now();
    let rv =
        unsafe { real!("FindObjects" as unsafe extern "C" fn(S, P, S, P) -> CK_RV)(s, h, max, n) };
    logcall(c"C_FindObjects", rv, t, || {
        format!("session {s}, up to {max} -> {} found", unsafe {
            out(rv, n)
        })
    });
    rv
}
pub(crate) unsafe extern "C" fn w_find_objects_final(s: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("FindObjectsFinal" as unsafe extern "C" fn(S) -> CK_RV)(s) };
    logcall(c"C_FindObjectsFinal", rv, t, || format!("session {s}"));
    rv
}
pub(crate) unsafe extern "C" fn w_get_attribute_value(s: S, o: S, tp: A, n: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe {
        real!("GetAttributeValue" as unsafe extern "C" fn(S, S, A, S) -> CK_RV)(s, o, tp, n)
    };
    logcall(c"C_GetAttributeValue", rv, t, || {
        format!("session {s}, object {o}, {}, values not shown", unsafe {
            types(tp, n, 120)
        })
    });
    rv
}
pub(crate) unsafe extern "C" fn w_sign_init(s: S, m: M, k: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("SignInit" as unsafe extern "C" fn(S, M, S) -> CK_RV)(s, m, k) };
    logcall(c"C_SignInit", rv, t, || {
        format!("session {s}, {}, key {k}", unsafe { mech(m) })
    });
    rv
}
pub(crate) unsafe extern "C" fn w_sign(s: S, d: B, dn: S, sig: B, sn: P) -> CK_RV {
    let t = Instant::now();
    let rv =
        unsafe { real!("Sign" as unsafe extern "C" fn(S, B, S, B, P) -> CK_RV)(s, d, dn, sig, sn) };
    logcall(c"C_Sign", rv, t, || {
        format!(
            "session {s}, {dn} bytes in -> {} bytes{}",
            unsafe { any(sn) },
            none_if(sig.cast(), " (size query)")
        )
    });
    rv
}
pub(crate) unsafe extern "C" fn w_sign_update(s: S, d: B, dn: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("SignUpdate" as unsafe extern "C" fn(S, B, S) -> CK_RV)(s, d, dn) };
    logcall(c"C_SignUpdate", rv, t, || {
        format!("session {s}, {dn} bytes")
    });
    rv
}
pub(crate) unsafe extern "C" fn w_sign_final(s: S, sig: B, sn: P) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("SignFinal" as unsafe extern "C" fn(S, B, P) -> CK_RV)(s, sig, sn) };
    logcall(c"C_SignFinal", rv, t, || {
        format!(
            "session {s} -> {} bytes{}",
            unsafe { any(sn) },
            none_if(sig.cast(), " (size query)")
        )
    });
    rv
}
pub(crate) unsafe extern "C" fn w_verify_init(s: S, m: M, k: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("VerifyInit" as unsafe extern "C" fn(S, M, S) -> CK_RV)(s, m, k) };
    logcall(c"C_VerifyInit", rv, t, || {
        format!("session {s}, {}, key {k}", unsafe { mech(m) })
    });
    rv
}
pub(crate) unsafe extern "C" fn w_verify_update(s: S, d: B, dn: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("VerifyUpdate" as unsafe extern "C" fn(S, B, S) -> CK_RV)(s, d, dn) };
    logcall(c"C_VerifyUpdate", rv, t, || {
        format!("session {s}, {dn} bytes")
    });
    rv
}
pub(crate) unsafe extern "C" fn w_verify_final(s: S, sig: B, sn: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("VerifyFinal" as unsafe extern "C" fn(S, B, S) -> CK_RV)(s, sig, sn) };
    logcall(c"C_VerifyFinal", rv, t, || {
        format!("session {s}, {sn}-byte signature")
    });
    rv
}
pub(crate) unsafe extern "C" fn w_init_token(sl: S, pin: B, n: S, label: B) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe {
        real!("InitToken" as unsafe extern "C" fn(S, B, S, B) -> CK_RV)(sl, pin, n, label)
    };
    logcall(c"C_InitToken", rv, t, || {
        format!("slot {sl}, SO PIN not shown")
    });
    rv
}
pub(crate) unsafe extern "C" fn w_init_pin(s: S, pin: B, n: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("InitPIN" as unsafe extern "C" fn(S, B, S) -> CK_RV)(s, pin, n) };
    logcall(c"C_InitPIN", rv, t, || {
        format!("session {s}, PIN not shown")
    });
    rv
}
pub(crate) unsafe extern "C" fn w_get_token_info(sl: S, ti: V) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("GetTokenInfo" as unsafe extern "C" fn(S, V) -> CK_RV)(sl, ti) };
    logcall(c"C_GetTokenInfo", rv, t, || format!("slot {sl}"));
    rv
}
pub(crate) unsafe extern "C" fn w_generate_random(s: S, o: B, n: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("GenerateRandom" as unsafe extern "C" fn(S, B, S) -> CK_RV)(s, o, n) };
    logcall(c"C_GenerateRandom", rv, t, || {
        format!("session {s}, {n} bytes, not shown")
    });
    rv
}
pub(crate) unsafe extern "C" fn w_get_slot_list(present: c_uchar, ids: P, n: P) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe {
        real!("GetSlotList" as unsafe extern "C" fn(c_uchar, P, P) -> CK_RV)(present, ids, n)
    };
    logcall(c"C_GetSlotList", rv, t, || {
        let which = if present != 0 {
            "with a token"
        } else {
            "all slots"
        };
        format!(
            "{which} -> {}{}",
            unsafe { out(rv, n) },
            none_if(ids.cast(), " (count)")
        )
    });
    rv
}
pub(crate) unsafe extern "C" fn w_destroy_object(s: S, o: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("DestroyObject" as unsafe extern "C" fn(S, S) -> CK_RV)(s, o) };
    logcall(c"C_DestroyObject", rv, t, || {
        format!("session {s}, object {o}")
    });
    rv
}
pub(crate) unsafe extern "C" fn w_generate_key(s: S, m: M, tp: A, n: S, k: P) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe {
        real!("GenerateKey" as unsafe extern "C" fn(S, M, A, S, P) -> CK_RV)(s, m, tp, n, k)
    };
    logcall(c"C_GenerateKey", rv, t, || {
        format!(
            "session {s}, {}, template {} -> key {}",
            unsafe { mech(m) },
            unsafe { types(tp, n, 200) },
            unsafe { out(rv, k) }
        )
    });
    rv
}
// The cipher calls: mechanism and key, byte counts in and out. Never a byte of data.
pub(crate) unsafe extern "C" fn w_encrypt_init(s: S, m: M, k: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("EncryptInit" as unsafe extern "C" fn(S, M, S) -> CK_RV)(s, m, k) };
    logcall(c"C_EncryptInit", rv, t, || {
        format!("session {s}, {}, key {k}", unsafe { mech(m) })
    });
    rv
}
pub(crate) unsafe extern "C" fn w_encrypt(s: S, i: B, n: S, o: B, on: P) -> CK_RV {
    let t = Instant::now();
    let rv =
        unsafe { real!("Encrypt" as unsafe extern "C" fn(S, B, S, B, P) -> CK_RV)(s, i, n, o, on) };
    logcall(c"C_Encrypt", rv, t, || {
        format!(
            "session {s}, {n} bytes in -> {} out{}, not shown",
            unsafe { out(rv, on) },
            none_if(o.cast(), " (size)")
        )
    });
    rv
}
pub(crate) unsafe extern "C" fn w_decrypt_init(s: S, m: M, k: S) -> CK_RV {
    let t = Instant::now();
    let rv = unsafe { real!("DecryptInit" as unsafe extern "C" fn(S, M, S) -> CK_RV)(s, m, k) };
    logcall(c"C_DecryptInit", rv, t, || {
        format!("session {s}, {}, key {k}", unsafe { mech(m) })
    });
    rv
}
pub(crate) unsafe extern "C" fn w_decrypt(s: S, i: B, n: S, o: B, on: P) -> CK_RV {
    let t = Instant::now();
    let rv =
        unsafe { real!("Decrypt" as unsafe extern "C" fn(S, B, S, B, P) -> CK_RV)(s, i, n, o, on) };
    logcall(c"C_Decrypt", rv, t, || {
        format!(
            "session {s}, {n} bytes in -> {} out{}, not shown",
            unsafe { out(rv, on) },
            none_if(o.cast(), " (size)")
        )
    });
    rv
}

// --- the loader: p11_load_module_e ----------------------------------------------------------

fn dlerror() -> Vec<u8> {
    // SAFETY: dlerror's string is valid until the next dl* call on this thread.
    let p = unsafe { libc::dlerror() };
    if p.is_null() {
        Vec::new()
    } else {
        unsafe { CStr::from_ptr(p) }.to_bytes().to_vec()
    }
}

fn load_module(path: *const c_char) -> Result<[*mut c_void; N], Error> {
    // SAFETY: the caller's path, a C string or null (dlopen's own meaning: the program).
    let h = unsafe { libc::dlopen(path, libc::RTLD_NOW) };
    if h.is_null() {
        let mut m = b"cannot load ".to_vec();
        m.extend(if path.is_null() {
            b"(null)"
        } else {
            unsafe { CStr::from_ptr(path) }.to_bytes()
        });
        m.extend(b": ");
        m.extend(dlerror());
        m.push(b'\n');
        return Err(Error::new(2, m));
    }
    let mut fns = [null_mut(); N];
    // SAFETY: a handle dlopen returned; never dlclose'd (tools/pkiops.h says why).
    let getlist = unsafe { libc::dlsym(h, c"C_GetFunctionList".as_ptr()) };
    if !getlist.is_null() {
        type GetList = unsafe extern "C" fn(*mut *const FunctionList) -> CK_RV;
        // SAFETY: C_GetFunctionList's signature, PKCS#11 §5.2.
        let getlist = unsafe { std::mem::transmute::<*mut c_void, GetList>(getlist) };
        let mut fl: *const FunctionList = null();
        let rv = unsafe { getlist(&mut fl) };
        if rv != 0 || fl.is_null() {
            return Err(Error::new(
                2,
                format!("C_GetFunctionList failed (0x{rv:x})\n"),
            ));
        }
        for (i, &(name, slot, need)) in FUNCTIONS.iter().enumerate() {
            // SAFETY: the module's table, v2.40's 68 slots at least.
            fns[i] = unsafe { (*fl).pfn[slot] };
            if fns[i].is_null() && need != Need::Optional {
                return Err(Error::new(
                    2,
                    format!("the module leaves C_{name} unimplemented\n"),
                ));
            }
        }
        return Ok(fns);
    }
    // No C_GetFunctionList: not conforming, but some modules and test doubles export the
    // functions directly. The mechanism queries are not looked for on this path.
    for (i, &(name, _, need)) in FUNCTIONS.iter().enumerate() {
        if need == Need::ListOnly {
            continue;
        }
        let sym = CString::new(format!("C_{name}")).expect("no NUL in a name");
        // SAFETY: as above.
        fns[i] = unsafe { libc::dlsym(h, sym.as_ptr()) };
        if fns[i].is_null() && need == Need::Both {
            return Err(Error::new(
                2,
                format!("the module exports neither C_GetFunctionList nor C_{name}\n"),
            ));
        }
    }
    Ok(fns)
}

/// Install `fns` (or nothing) as the module.
fn install(fns: Option<&[*mut c_void; N]>) {
    for (i, r) in REAL.iter().enumerate() {
        r.store(fns.map_or(null_mut(), |f| f[i]), Ordering::Release);
    }
}

/// # Safety
/// `e` null or writable.
unsafe fn fail(e: *mut p11_err, err: Error) -> c_int {
    // SAFETY: the caller's p11_err, null or valid (C wrote through it unchecked).
    if let Some(e) = unsafe { e.as_mut() } {
        let m = err.c_msg();
        for (d, s) in e.msg.iter_mut().zip(m) {
            *d = *s as c_char;
        }
        e.msg[m.len()] = 0;
        e.code = err.code;
    }
    err.code
}

/// Slot resolution through the wrapped module, so each call is logged as C's were.
struct Module;

impl Slots for Module {
    fn list(&mut self, present: bool) -> Result<Vec<SlotId>, Error> {
        let p = c_uchar::from(present);
        let failed = |rv: CK_RV| Error::new(2, format!("C_GetSlotList failed (0x{rv:x})\n"));
        let mut n: CK_ULONG = 0;
        // SAFETY: the two-call convention, a count then a buffer of that count.
        let rv = unsafe { w_get_slot_list(p, null_mut(), &mut n) };
        if rv != 0 {
            return Err(failed(rv));
        }
        if n == 0 {
            return Ok(Vec::new());
        }
        let mut ids: Vec<SlotId> = Vec::new();
        if ids.try_reserve_exact(n as usize).is_err() {
            return Err(Error::new(2, "out of memory\n"));
        }
        ids.resize(n as usize, 0);
        let rv = unsafe { w_get_slot_list(p, ids.as_mut_ptr(), &mut n) };
        if rv != 0 {
            return Err(failed(rv));
        }
        // Trust the second answer, which describes the buffer; never past its end.
        ids.truncate(n as usize);
        Ok(ids)
    }

    fn label(&mut self, id: SlotId) -> Vec<u8> {
        if !has("GetTokenInfo") {
            return crate::label_of(None);
        }
        // CK_TOKEN_INFO opens with label[32]; 1024 bytes holds the whole struct, as in C.
        let mut ti = [0u8; 1024];
        // SAFETY: a buffer larger than CK_TOKEN_INFO.
        let rv = unsafe { w_get_token_info(id, ti.as_mut_ptr().cast()) };
        crate::label_of((rv == 0).then_some(&ti[..]))
    }
}

// --- tools/pkiops.h -------------------------------------------------------------------------

/// `pkiops_set_call_log`.
///
/// # Safety
/// `cb`, when set, must be callable with `ctx` for as long as it stays installed: every
/// wrapper calls it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_set_call_log(cb: Option<pkiops_call_cb>, ctx: *mut c_void) {
    *LOG.lock().unwrap_or_else(|p| p.into_inner()) = Log(cb, ctx);
}

/// `pkiops_load`: load the module and C_Initialize it. Whatever was loaded before is
/// finalised and forgotten first; a load that fails leaves none loaded. `None` is C's NULL
/// path (dlopen's own meaning: the program).
pub fn load(module: Option<&CStr>) -> Result<(), Error> {
    unload();
    let fns = load_module(module.map_or(null(), CStr::as_ptr))?;
    install(Some(&fns));
    // SAFETY: the module just installed.
    let rv = unsafe { w_initialize(null_mut()) };
    if rv != 0 {
        unload();
        return Err(Error::new(2, format!("C_Initialize failed (0x{rv:x})\n")));
    }
    INITIALISED.store(true, Ordering::Release);
    Ok(())
}

/// `pkiops_slots`: every slot the loaded module reports, in its order.
pub fn slots() -> Result<Vec<ops::SlotInfo>, Error> {
    let all = Module.list(false)?;
    let tok = Module.list(true)?;
    Ok(all
        .into_iter()
        .map(|id| {
            let has = tok.contains(&id);
            let info = has.then(|| ops::token_info(Slot(id)).ok()).flatten();
            ops::SlotInfo {
                id: Slot(id),
                has_token: has.into(),
                label: info.map_or([0; 33], |t| t.label),
            }
        })
        .collect())
}

/// `pkiops_open`: [`load`], then the slot: `want` is the one the caller named, or -1.
pub fn open(module: Option<&CStr>, want: c_long, intent: Intent) -> Result<Slot, Error> {
    load(module)?;
    crate::resolve(&mut Module, want, intent)
        .map(Slot)
        .inspect_err(|_| close())
}

/// `pkiops_close`: C_Finalize, if initialised.
pub fn close() {
    if INITIALISED.swap(false, Ordering::AcqRel) {
        // SAFETY: the module is loaded while INITIALISED is set.
        unsafe { w_finalize(null_mut()) };
    }
}

/// `pkiops_unload`: [`close`], then forget the module. Not dlclose'd (`tools/pkiops.h`).
pub fn unload() {
    close();
    install(None);
}

/// `pkiops_load`.
///
/// # Safety
/// `module` is a C string or null; `e` is null or a writable `struct p11_err`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_load(module: *const c_char, e: *mut p11_err) -> c_int {
    // SAFETY: the caller's C string, or null.
    match load((!module.is_null()).then(|| unsafe { CStr::from_ptr(module) })) {
        Ok(()) => 0,
        Err(err) => unsafe { fail(e, err) },
    }
}

/// `pkiops_open`.
///
/// # Safety
/// As [`pkiops_load`]; `slot` is null or writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pkiops_open(
    module: *const c_char,
    want: c_long,
    intent: c_int,
    slot: *mut c_ulong,
    e: *mut p11_err,
) -> c_int {
    let intent = match intent {
        1 => Intent::ForInit,
        2 => Intent::Any,
        _ => Intent::WithToken,
    };
    // SAFETY: the caller's C string, or null.
    match open(
        (!module.is_null()).then(|| unsafe { CStr::from_ptr(module) }),
        want,
        intent,
    ) {
        Ok(s) => {
            // SAFETY: the caller's output, null or writable.
            if let Some(slot) = unsafe { slot.as_mut() } {
                *slot = s.0;
            }
            0
        }
        Err(err) => unsafe { fail(e, err) },
    }
}

/// `pkiops_close`.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_close() {
    close()
}

/// `pkiops_unload`.
#[unsafe(no_mangle)]
pub extern "C" fn pkiops_unload() {
    unload()
}
