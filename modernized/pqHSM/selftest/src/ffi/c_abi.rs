//! The C ABI of `include/fhsm_integrity.h` (`src/fhsm_integrity.c`) and of the KATs in
//! `include/fhsm_crypto.h` (`kat/fhsm_kat_vectors.c`, `kat/cavp_extended.c`), for the hybrid
//! build. The digest array stays C (`selftest/shim/integrity_digest.c`): `scripts/sign_module.sh`
//! patches it in its own ELF section.

use std::ffi::{CStr, OsStr, c_char, c_int, c_void};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;

use pqhsm_crypto::prim;
use pqhsm_crypto::{ForkMutex, KatRecord, rv};

use crate::integrity::{self, ALLOW_UNSIGNED, DIGEST_LEN};
use crate::kat;

unsafe extern "C" {
    // selftest/shim/integrity_digest.c: const volatile, patched after the build
    static fhsm_module_integrity_digest: [u8; DIGEST_LEN];
    // src/fhsm_state.c
    fn fhsm_state_latch_error(reason: *const c_char);
}

/// C's `g_so_path[1024]`: a longer path is cut, as `snprintf` cut it.
const PATH_MAX: usize = 1024;

/// C's statics. `result` is `None` until the check has run.
struct State {
    result: Option<u32>,
    last: [u8; DIGEST_LEN],
    path: [u8; PATH_MAX],
}

static STATE: ForkMutex<State> = ForkMutex::new(State {
    result: None,
    last: [0; DIGEST_LEN],
    path: [0; PATH_MAX],
});

static mut FORK_ONCE: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;

/// A fork child takes the locks afresh (review M1: its init re-runs the KATs, DIV-035); the
/// cached result goes with it, as `pthread_once`'s did.
extern "C" fn after_fork() {
    // SAFETY: a fork child handler
    unsafe {
        STATE.after_fork(|_| ());
        VIDS.after_fork(|_| ());
    }
}

extern "C" fn register_fork_handler() {
    // SAFETY: a handler for the child only
    unsafe { libc::pthread_atfork(None, None, Some(after_fork)) };
}

fn fork_safe() {
    // SAFETY: a once-control of static storage
    unsafe { libc::pthread_once(&raw mut FORK_ONCE, register_fork_handler) };
}

fn state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    fork_safe();
    STATE.with(f)
}

/// The embedded digest, read byte by byte from memory: it is patched after compilation.
fn embedded() -> [u8; DIGEST_LEN] {
    let p = (&raw const fhsm_module_integrity_digest).cast::<u8>();
    // SAFETY: 48 readable bytes of static storage
    std::array::from_fn(|i| unsafe { p.add(i).read_volatile() })
}

/// The loaded object holding the digest array: its name, or for the main executable (a test
/// binary linking the objects statically) `/proc/self/exe` (`src/fhsm_integrity.c:104-159`).
fn locate() -> Option<Vec<u8>> {
    struct Find {
        needle: usize,
        found: Option<Vec<u8>>,
    }
    unsafe extern "C" fn cb(info: *mut libc::dl_phdr_info, _: usize, data: *mut c_void) -> c_int {
        // SAFETY: dl_iterate_phdr hands a valid info and our data pointer
        let (info, find) = unsafe { (&*info, &mut *data.cast::<Find>()) };
        let phdrs = if info.dlpi_phdr.is_null() {
            &[][..]
        } else {
            // SAFETY: dlpi_phnum headers at dlpi_phdr
            unsafe { std::slice::from_raw_parts(info.dlpi_phdr, usize::from(info.dlpi_phnum)) }
        };
        for p in phdrs.iter().filter(|p| p.p_type == libc::PT_LOAD) {
            let start = (info.dlpi_addr + p.p_vaddr) as usize;
            if find.needle >= start && find.needle < start + p.p_memsz as usize {
                // SAFETY: a C string, or NULL
                let name = (!info.dlpi_name.is_null())
                    .then(|| unsafe { CStr::from_ptr(info.dlpi_name) }.to_bytes())
                    .filter(|n| !n.is_empty());
                find.found = match name {
                    Some(n) => Some(n.to_vec()),
                    None => std::fs::read_link("/proc/self/exe")
                        .ok()
                        .map(|p| p.into_os_string().into_vec()),
                };
                return 1;
            }
        }
        0
    }
    use std::os::unix::ffi::OsStringExt;
    let mut find = Find {
        needle: (&raw const fhsm_module_integrity_digest) as usize,
        found: None,
    };
    // SAFETY: the callback only reads what it is handed and writes `find`
    unsafe { libc::dl_iterate_phdr(Some(cb), (&raw mut find).cast()) };
    find.found
}

fn bypass() -> bool {
    cfg!(feature = "dev-bypass") && std::env::var_os(ALLOW_UNSIGNED).is_some()
}

/// One run of the check, recorded in `s` as C's statics were.
fn run(s: &mut State) -> u32 {
    // not found: no path, as in a process whose first run found none (review L3)
    let p = locate().unwrap_or_default();
    let n = p.len().min(PATH_MAX - 1);
    s.path[..n].copy_from_slice(&p[..n]);
    s.path[n..].fill(0);
    let path = s.path.split(|&b| b == 0).next().unwrap_or_default();
    let mut file = (!path.is_empty())
        .then(|| std::fs::read(OsStr::from_bytes(path)).ok())
        .flatten();
    let r = integrity::verify(file.as_deref_mut(), &embedded(), bypass(), |data| {
        let mut d = [0; DIGEST_LEN];
        (prim::digest(2, data, &mut d) == Ok(DIGEST_LEN)).then_some(d)
    });
    if let Some(last) = r.last {
        s.last = last;
    }
    // std's stderr is unbuffered, as C's; a failed write must not panic inside C_Initialize
    let _ = std::io::stderr().write_all(r.stderr.as_bytes());
    if r.latched {
        // SAFETY: a static C string
        unsafe { fhsm_state_latch_error(c"integrity check failed".as_ptr()) };
    }
    r.rv
}

/// Runs once per process, as C's `pthread_once`.
#[unsafe(no_mangle)]
pub extern "C" fn fhsm_integrity_verify() -> u32 {
    state(|s| match s.result {
        Some(rv) => rv,
        None => {
            let rv = run(s);
            s.result = Some(rv);
            rv
        }
    })
}

/// The crypto core's init: runs the check again each time the init runs (DIV-035).
#[unsafe(no_mangle)]
pub extern "C" fn pqhsm_integrity_run() -> u32 {
    state(|s| {
        let rv = run(s);
        s.result = Some(rv);
        rv
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_integrity_is_signed() -> c_int {
    c_int::from(embedded().iter().any(|&b| b != 0))
}

/// Static storage, read unlocked as in C.
#[unsafe(no_mangle)]
pub extern "C" fn fhsm_integrity_last_computed() -> *const u8 {
    state(|s| s.last.as_ptr())
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_integrity_so_path() -> *const c_char {
    state(|s| {
        if s.path[0] == 0 {
            c"(unknown)".as_ptr()
        } else {
            s.path.as_ptr().cast()
        }
    })
}

// ---- the KATs ------------------------------------------------------------------------------

unsafe extern "C" {
    // crypto/src/ffi/c_abi.rs (include/fhsm_crypto.h)
    fn fhsm_aes_gcm_encrypt(
        key: Slice,
        iv: Slice,
        aad: Slice,
        pt: Slice,
        ct: *mut u8,
        ct_len: *mut usize,
        tag: *mut u8,
    ) -> u32;
    fn fhsm_aes_gcm_decrypt(
        key: Slice,
        iv: Slice,
        aad: Slice,
        ct: Slice,
        tag: *const u8,
        pt: *mut u8,
        pt_len: *mut usize,
    ) -> u32;
    fn fhsm_hash_oneshot(alg: c_int, data: Slice, out: *mut u8, out_len: *mut usize) -> u32;
    fn fhsm_hmac(alg: c_int, key: Slice, data: Slice, mac: *mut u8, mac_len: *mut usize) -> u32;
    fn fhsm_pbkdf2(
        alg: c_int,
        password: Slice,
        salt: Slice,
        iterations: u32,
        out: *mut u8,
        out_len: usize,
    ) -> u32;
    fn fhsm_rng_bytes(out: *mut u8, n: usize) -> u32;
}

/// `fhsm_slice_t`.
#[repr(C)]
struct Slice {
    data: *const u8,
    len: usize,
}

fn sl(s: &[u8]) -> Slice {
    Slice {
        data: s.as_ptr(),
        len: s.len(),
    }
}

/// The crypto core's primitives, through the C ABI the C KATs called.
struct Core;

// SAFETY (every call below): the slices outlive the call, which only reads them; each output
// has the capacity passed beside it, and a tag is 16 bytes
impl kat::Prims for Core {
    fn gcm_encrypt(
        &mut self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
        tag: &mut [u8; 16],
    ) -> (u32, usize) {
        let mut n = ct.len();
        // SAFETY: see above
        let rv = unsafe {
            fhsm_aes_gcm_encrypt(
                sl(key),
                sl(iv),
                sl(aad),
                sl(pt),
                ct.as_mut_ptr(),
                &mut n,
                tag.as_mut_ptr(),
            )
        };
        (rv, n)
    }

    fn gcm_decrypt(
        &mut self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; 16],
        pt: &mut [u8],
    ) -> (u32, usize) {
        let mut n = pt.len();
        // SAFETY: see above
        let rv = unsafe {
            fhsm_aes_gcm_decrypt(
                sl(key),
                sl(iv),
                sl(aad),
                sl(ct),
                tag.as_ptr(),
                pt.as_mut_ptr(),
                &mut n,
            )
        };
        (rv, n)
    }

    fn hash(&mut self, alg: u32, data: &[u8], out: &mut [u8]) -> (u32, usize) {
        let mut n = out.len();
        // SAFETY: see above
        let rv = unsafe { fhsm_hash_oneshot(alg as c_int, sl(data), out.as_mut_ptr(), &mut n) };
        (rv, n)
    }

    fn hmac(&mut self, alg: u32, key: &[u8], data: &[u8], mac: &mut [u8]) -> (u32, usize) {
        let mut n = mac.len();
        // SAFETY: see above
        let rv = unsafe { fhsm_hmac(alg as c_int, sl(key), sl(data), mac.as_mut_ptr(), &mut n) };
        (rv, n)
    }

    fn pbkdf2(&mut self, alg: u32, password: &[u8], salt: &[u8], iter: u32, out: &mut [u8]) -> u32 {
        // SAFETY: see above
        unsafe {
            fhsm_pbkdf2(
                alg as c_int,
                sl(password),
                sl(salt),
                iter,
                out.as_mut_ptr(),
                out.len(),
            )
        }
    }

    fn rng(&mut self, out: &mut [u8]) -> u32 {
        // SAFETY: see above
        unsafe { fhsm_rng_bytes(out.as_mut_ptr(), out.len()) }
    }
}

/// `FHSM_KAT_VID_LEN`.
const VID_LEN: usize = 32;

/// C's `g_kat_vid`: a CAVP identifier lives in the slot of its report entry, until the next run.
static VIDS: ForkMutex<[[u8; VID_LEN]; kat::KAT_MAX]> =
    ForkMutex::new([[0; VID_LEN]; kat::KAT_MAX]);

/// The records into C's array, from the sink's first entry; a CAVP identifier is formatted
/// into its pool slot.
///
/// # Safety
/// `out` has `sink.len()` writable entries.
unsafe fn report(out: *mut KatRecord, sink: &kat::Sink) {
    let base = sink.len() - sink.recs.len();
    fork_safe();
    VIDS.with(|vids| {
        for (i, r) in sink.recs.iter().enumerate() {
            let at = base + i;
            let vector_id = match r.vector_id {
                kat::Vid::Static(v) => v.as_ptr(),
                kat::Vid::Cavp(bits) => {
                    // run_all records a CAVP vector only below KAT_MAX, and the longest
                    // identifier (Len-2147483648) fits with its NUL
                    let slot = &mut vids[at];
                    let text = format!("CAVP-SHA256-Len{bits}");
                    slot.fill(0);
                    slot[..text.len()].copy_from_slice(text.as_bytes());
                    slot.as_ptr().cast()
                }
            };
            let rec = KatRecord {
                algorithm: r.algorithm.as_ptr(),
                vector_id,
                passed: c_int::from(r.passed),
                duration_us: r.duration_us,
            };
            // SAFETY: at < sink.len(), within the caller's array
            unsafe { out.add(at).write(rec) };
        }
    });
}

/// `fhsm_kat_run_all`: ARGUMENTS_BAD without an array or a count; the records written as C
/// wrote them, and `*count` as C left it (DIV-046: a failed KAT is KAT_FAILED).
///
/// # Safety
/// `out` has `cap` writable entries; `count` is writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_kat_run_all(
    out: *mut KatRecord,
    cap: usize,
    count: *mut usize,
) -> u32 {
    if out.is_null() || count.is_null() {
        return rv::ARGUMENTS_BAD;
    }
    let mut sink = kat::Sink::new(cap);
    let (r, n) = kat::run_all(&mut Core, &kat::CAVP_FILES, &mut sink);
    // SAFETY: the sink never holds more than cap entries; count is writable
    unsafe {
        report(out, &sink);
        *count = n;
    }
    r
}

/// `fhsm_pairwise_check` (`include/fhsm_pairwise.h`).
///
/// # Safety
/// `pkey` is null or a live key pair.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pairwise_check(
    pkey: *mut openssl_sys::EVP_PKEY,
    family: c_int,
) -> u32 {
    // SAFETY: the caller's contract is check's
    unsafe { crate::pairwise::check(pkey, family) }
}

/// `fhsm_kat_cavp_extended`: the extended set after the `*count_io` entries already written;
/// the cursor advances only when the whole set has been recorded, as in C.
///
/// # Safety
/// As `fhsm_kat_run_all`, with `count_io` readable too.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_kat_cavp_extended(
    out: *mut KatRecord,
    cap: usize,
    count_io: *mut usize,
) -> u32 {
    if out.is_null() || count_io.is_null() {
        return rv::ARGUMENTS_BAD;
    }
    // SAFETY: count_io is readable and writable; the sink stays within cap
    unsafe {
        let mut sink = kat::Sink::at(cap, *count_io);
        let r = crate::ffi::evp::extended(&mut sink);
        report(out, &sink);
        if r == rv::OK {
            *count_io = sink.len();
        }
        r
    }
}
