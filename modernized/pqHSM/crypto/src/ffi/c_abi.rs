//! The C ABI of `include/fhsm_conf.h`, the memory section of `include/fhsm_common.h` and
//! `include/fhsm_drbg.h` (`src/fhsm_conf.c`, `src/fhsm_memory.c`, `src/fhsm_drbg.c`), for the
//! hybrid build. Argument checks and results
//! are C's.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::mem::MaybeUninit;

use zeroize::Zeroize;

use std::ptr::NonNull;

use super::entropy::OsSource;
use super::prim;
use super::sys::{self, ForkMutex};
use crate::drbg::{Drbg, Error, Stats};
use crate::lifecycle::{Core, Platform};
use crate::rv as code;
use crate::{conf, mem};

const FHSM_RV_OK: u32 = 0x0;
const FHSM_RV_HOST_MEMORY: u32 = 0x2;

/// 1 and the value in `out` (NUL-terminated, cut to `outlen - 1` bytes), or 0. On 0, `out` is
/// left as it was (C wrote a NUL there when the key matched with an empty value).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_conf_lookup(
    key: *const c_char,
    out: *mut c_char,
    outlen: usize,
) -> c_int {
    if key.is_null() || out.is_null() || outlen == 0 {
        return 0;
    }
    // SAFETY: key is a C string (caller)
    let key = unsafe { CStr::from_ptr(key) }.to_bytes();
    let Some(v) = conf::lookup_in(&conf::path(), key, outlen - 1) else {
        return 0;
    };
    // SAFETY: out has outlen bytes (caller) and v.len() < outlen
    unsafe {
        std::ptr::copy_nonoverlapping(v.as_ptr(), out.cast(), v.len());
        *out.add(v.len()) = 0;
    }
    1
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_conf_secure_heap_bytes() -> usize {
    conf::secure_heap_bytes()
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_secure_heap_init() -> u32 {
    if mem::init() {
        FHSM_RV_OK
    } else {
        FHSM_RV_HOST_MEMORY
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_secure_malloc(n: usize) -> *mut c_void {
    mem::alloc(n).cast()
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_secure_zalloc(n: usize) -> *mut c_void {
    mem::alloc_zeroed(n).cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_secure_free(p: *mut c_void) {
    // SAFETY: p is null or from fhsm_secure_malloc/zalloc (caller)
    unsafe { mem::free(p.cast()) }
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_secure_heap_used() -> usize {
    mem::used()
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_secure_heap_total() -> usize {
    mem::total()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_zeroize(p: *mut c_void, n: usize) {
    if p.is_null() || n == 0 {
        return;
    }
    // SAFETY: p has n writable bytes (caller), possibly never initialised (review L2)
    unsafe { std::slice::from_raw_parts_mut(p.cast::<MaybeUninit<u8>>(), n) }.zeroize();
}

/// 0 when equal; otherwise the OR of the differing bits, which callers treat as a boolean.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_ct_memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int {
    if n == 0 {
        return 0;
    }
    // SAFETY: a and b have n readable bytes (caller)
    let (a, b) = unsafe {
        (
            std::slice::from_raw_parts(a.cast::<u8>(), n),
            std::slice::from_raw_parts(b.cast::<u8>(), n),
        )
    };
    c_int::from(mem::ct_diff(a, b))
}

// ---- DRBG ---------------------------------------------------------------------------------

unsafe extern "C" {
    // src/fhsm_state.c
    fn fhsm_state_get() -> c_int;
    fn fhsm_state_latch_error(reason: *const c_char);
}

/// `FHSM_STATE_ERROR` (`include/fhsm_common.h:249`).
const STATE_ERROR: c_int = 4;

/// The module's DRBG, one per process, as C's module statics under `g_mtx`. A fork child takes
/// its lock afresh, as the crypto core's (slice 3 review M1): the child's init draws from it.
static DRBG: ForkMutex<Drbg<OsSource>> = ForkMutex::new(Drbg::new(OsSource));

/// Runs `f` on the DRBG. The result is latched by the caller, after the lock is released:
/// a latch reaches the audit log, which may draw from the DRBG (slice 3 review L3).
fn drbg<R>(f: impl FnOnce(&mut Drbg<OsSource>) -> R) -> R {
    sys::core_once(register_fork_handler);
    DRBG.with(f)
}

/// Latches ERROR when the failure calls for it, and returns its code.
fn rv(result: Result<(), Error>) -> u32 {
    result.map_or_else(
        |e| {
            if let Some(reason) = e.latch_reason() {
                // SAFETY: a static C string
                unsafe { fhsm_state_latch_error(reason.as_ptr()) };
            }
            e.rv()
        },
        |()| FHSM_RV_OK,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_drbg_init() -> u32 {
    rv(drbg(|d| d.init()))
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_drbg_reseed() -> u32 {
    rv(drbg(|d| d.reseed()))
}

/// The buffer is zeroed before it is filled: Rust may not view caller memory that is possibly
/// uninitialised as bytes. Bytes a failed call never produced are therefore 0, not what was there.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_drbg_bytes(out: *mut u8, n: usize) -> u32 {
    // SAFETY: no arguments
    if unsafe { fhsm_state_get() } == STATE_ERROR {
        return Error::Halted.rv();
    }
    if out.is_null() || n == 0 {
        return Error::Arguments.rv();
    }
    rv(drbg(|drbg| {
        // DIV-041: again under the lock, so no output follows another thread's latch
        // SAFETY: no arguments
        if unsafe { fhsm_state_get() } == STATE_ERROR {
            return Err(Error::Halted);
        }
        // SAFETY: out has n writable bytes (caller); zeroed, they are valid u8
        let out = unsafe {
            out.write_bytes(0, n);
            std::slice::from_raw_parts_mut(out, n)
        };
        drbg.bytes(out)
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_drbg_get_stats(out: *mut Stats) {
    if !out.is_null() {
        // SAFETY: out points to an fhsm_drbg_stats_t (caller); Stats has its layout
        unsafe { out.write(drbg(|d| d.stats())) };
    }
}

// ---- Crypto core (include/fhsm_crypto.h) --------------------------------------------------

unsafe extern "C" {
    // src/fhsm_integrity.c and kat/fhsm_kat_vectors.c, C until slice 4
    fn fhsm_integrity_verify() -> u32;
    fn fhsm_kat_run_all(out: *mut KatRecord, cap: usize, count: *mut usize) -> u32;
    // libcrypto and glibc
    fn ERR_print_errors_fp(fp: *mut libc::FILE);
    static stderr: *mut libc::FILE;
}

/// `fhsm_slice_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Slice {
    data: *const u8,
    len: usize,
}

/// `fhsm_kat_result_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KatRecord {
    algorithm: *const c_char,
    vector_id: *const c_char,
    passed: c_int,
    duration_us: u32,
}

const NO_KAT: KatRecord = KatRecord {
    algorithm: std::ptr::null(),
    vector_id: std::ptr::null(),
    passed: 0,
    duration_us: 0,
};

/// `FHSM_KAT_MAX`.
const KAT_MAX: usize = 64;

/// A loaded OpenSSL provider.
pub struct Provider(NonNull<openssl_sys::OSSL_PROVIDER>);

/// The real collaborators, and the KAT records `fhsm_kat_results` hands out.
pub struct OsPlatform {
    kats: [KatRecord; KAT_MAX],
    kat_count: usize,
}

// SAFETY: provider handles are process-wide OpenSSL objects; the KAT strings have static
// duration (the LIFETIME contract at include/fhsm_crypto.h:186) and are only read
unsafe impl Send for Provider {}
unsafe impl Send for OsPlatform {}

impl Platform for OsPlatform {
    type Provider = Provider;

    fn integrity(&mut self) -> u32 {
        // SAFETY: no arguments
        unsafe { fhsm_integrity_verify() }
    }

    fn load(&mut self, name: &CStr) -> Option<Provider> {
        // SAFETY: a C string; the default library context
        NonNull::new(unsafe {
            openssl_sys::OSSL_PROVIDER_load(std::ptr::null_mut(), name.as_ptr())
        })
        .map(Provider)
    }

    fn unload(&mut self, provider: Provider) {
        // SAFETY: a handle from load, unloaded once
        unsafe { openssl_sys::OSSL_PROVIDER_unload(provider.0.as_ptr()) };
    }

    fn enable_fips(&mut self, on: bool) -> bool {
        // SAFETY: the default library context
        unsafe {
            openssl_sys::EVP_default_properties_enable_fips(std::ptr::null_mut(), c_int::from(on))
                == 1
        }
    }

    fn drbg_init(&mut self) -> u32 {
        fhsm_drbg_init()
    }

    fn kats(&mut self) -> (u32, Vec<String>) {
        self.kat_count = 0;
        // SAFETY: room for KAT_MAX records, as the C function is told
        let rv = unsafe { fhsm_kat_run_all(self.kats.as_mut_ptr(), KAT_MAX, &mut self.kat_count) };
        self.kat_count = self.kat_count.min(KAT_MAX);
        let failed = self.kats[..self.kat_count]
            .iter()
            .filter(|k| k.passed == 0)
            // SAFETY: C strings of static duration, as above
            .map(|k| format!("{} / {}", c_str(k.algorithm), c_str(k.vector_id)))
            .collect();
        (rv, failed)
    }

    fn forget_kats(&mut self) {
        self.kats = [NO_KAT; KAT_MAX];
        self.kat_count = 0;
    }

    fn latch(&mut self, reason: &CStr) {
        // SAFETY: a C string
        unsafe { fhsm_state_latch_error(reason.as_ptr()) };
    }

    fn var(&self, name: &str) -> Option<String> {
        std::env::var_os(name).map(|v| v.to_string_lossy().into_owned())
    }

    fn eprint(&mut self, text: &str) {
        // unbuffered, like C's stderr, so it interleaves with ERR_print_errors_fp
        sys::stderr(text);
    }

    fn eprint_openssl_errors(&mut self) {
        // SAFETY: glibc's stderr stream
        unsafe { ERR_print_errors_fp(stderr) };
    }
}

/// A KAT record's string, or "(null)" as glibc's printf showed a NULL one.
fn c_str(p: *const c_char) -> String {
    if p.is_null() {
        return "(null)".into();
    }
    // SAFETY: a C string of static duration, as above
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

/// The module's crypto core, one per process, as C's statics in `src/fhsm_crypto.c`.
static CORE: ForkMutex<Core<OsPlatform>> = ForkMutex::new(Core::new(
    OsPlatform {
        kats: [NO_KAT; KAT_MAX],
        kat_count: 0,
    },
    cfg!(feature = "dev-bypass"),
));

/// A fork child takes the locks afresh and runs the self-tests again at its first init
/// (DIV-035): the child is a new module instance.
extern "C" fn core_after_fork() {
    // SAFETY: a fork child handler
    unsafe {
        CORE.after_fork(Core::forget);
        DRBG.after_fork(|_| ());
    }
}

extern "C" fn register_fork_handler() {
    // SAFETY: a handler for the child only
    unsafe { libc::pthread_atfork(None, None, Some(core_after_fork)) };
}

fn halted() -> bool {
    // SAFETY: no arguments
    unsafe { fhsm_state_get() == STATE_ERROR }
}

fn code(r: Result<(), u32>) -> u32 {
    r.err().unwrap_or(FHSM_RV_OK)
}

/// A C slice as a Rust one. NULL with a length is refused (DIV-045).
///
/// # Safety
/// `s` describes readable memory, or is NULL.
unsafe fn input<'a>(s: Slice) -> Result<&'a [u8], u32> {
    match (s.len, s.data.is_null()) {
        (0, _) => Ok(&[]),
        (_, true) => Err(code::ARGUMENTS_BAD),
        // SAFETY: the caller's contract
        _ => Ok(unsafe { std::slice::from_raw_parts(s.data, s.len) }),
    }
}

/// Runs `f` on an `n`-byte buffer of its own and copies what it wrote to the `n` bytes at `p`
/// on success; the buffer is wiped either way. Callers pass the same memory for input and
/// output (`C_Digest(h, buf, n, buf, &len)`), which OpenSSL reads before it writes; a Rust view
/// of `p` would alias the input and could not be zeroed first (slice 3 review H1). A failed call
/// leaves `p` as it was. NULL with a length is refused (DIV-045).
///
/// # Safety
/// `p` has `n` writable bytes, or is NULL.
unsafe fn output(
    p: *mut u8,
    n: usize,
    f: impl FnOnce(&mut [u8]) -> Result<usize, u32>,
) -> Result<usize, u32> {
    if n > 0 && p.is_null() {
        return Err(code::ARGUMENTS_BAD);
    }
    let mut buf = vec![0; n];
    let r = f(&mut buf);
    if r.is_ok() && n > 0 {
        // SAFETY: the caller's contract; copy, not copy_nonoverlapping: p may be an input too
        unsafe { std::ptr::copy(buf.as_ptr(), p, n) };
    }
    buf.zeroize();
    r
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_crypto_init() -> u32 {
    sys::core_once(register_fork_handler);
    CORE.with(Core::init)
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_crypto_finalize() {
    CORE.with(Core::finalize);
}

/// `FHSM_FIPS_ONLY`, which no build overrides.
#[unsafe(no_mangle)]
pub extern "C" fn fhsm_fips_mode() -> c_int {
    1
}

/// `fhsm_kat_results`, which `crypto/shim/kat_results.c` exports from the module. The array
/// lives in a static, so the pointer outlives the lock, read unlocked as in C.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_kat_results(count: *mut usize) -> *const KatRecord {
    CORE.with(|core| {
        let p = core.platform();
        if !count.is_null() {
            // SAFETY: count points to a size_t (caller)
            unsafe { count.write(p.kat_count) };
        }
        p.kats.as_ptr()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rng_bytes(out: *mut u8, n: usize) -> u32 {
    // SAFETY: the caller's contract, passed on
    unsafe { fhsm_drbg_bytes(out, n) }
}

/// Personalisation goes to OpenSSL's generator with no entropy credited.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_rng_reseed(personalization: Slice) -> u32 {
    // SAFETY: no arguments
    if unsafe { openssl_sys::RAND_status() } == 0 {
        return code::RNG_FAILURE;
    }
    // SAFETY: the caller's slice
    code(unsafe { input(personalization) }.map(|p| {
        if !p.is_empty() {
            // SAFETY: p is readable for its length
            unsafe { openssl_sys::RAND_add(p.as_ptr().cast(), p.len() as c_int, 0.0) };
        }
    }))
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_hash_size(alg: c_int) -> usize {
    prim::hash_size(alg as u32)
}

#[unsafe(no_mangle)]
pub extern "C" fn fhsm_hash_openssl_name(alg: c_int) -> *const c_char {
    prim::hash_name(alg as u32).map_or(std::ptr::null(), CStr::as_ptr)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_hash_oneshot(
    alg: c_int,
    data: Slice,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    if halted() {
        return code::FUNCTION_FAILED;
    }
    let alg = alg as u32;
    if prim::hash_name(alg).is_none() || out.is_null() || out_len.is_null() {
        return code::ARGUMENTS_BAD;
    }
    let size = prim::hash_size(alg);
    // SAFETY: out_len points to a size_t, out to that many bytes (caller)
    code(unsafe {
        (|| {
            if *out_len < size {
                return Err(code::ARGUMENTS_BAD);
            }
            let data = input(data)?;
            *out_len = output(out, size, |o| prim::digest(alg, data, o))?;
            Ok(())
        })()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_hmac(
    alg: c_int,
    key: Slice,
    data: Slice,
    mac: *mut u8,
    mac_len: *mut usize,
) -> u32 {
    if halted() {
        return code::FUNCTION_FAILED;
    }
    let alg = alg as u32;
    // C dereferenced a NULL mac_len (DIV-045)
    if prim::hash_name(alg).is_none() || mac_len.is_null() {
        return code::ARGUMENTS_BAD;
    }
    let size = prim::hash_size(alg);
    // SAFETY: mac_len points to a size_t, mac to that many bytes or NULL (caller)
    code(unsafe {
        (|| {
            if *mac_len < size {
                return Err(code::ARGUMENTS_BAD);
            }
            let (key, data) = (input(key)?, input(data)?);
            *mac_len = if mac.is_null() {
                prim::hmac(alg, key, data, None)?
            } else {
                output(mac, size, |o| prim::hmac(alg, key, data, Some(o)))?
            };
            Ok(())
        })()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_aes_gcm_encrypt(
    key: Slice,
    iv: Slice,
    aad: Slice,
    plaintext: Slice,
    ciphertext: *mut u8,
    ciphertext_len: *mut usize,
    tag: *mut u8,
) -> u32 {
    if halted() {
        return code::FUNCTION_FAILED;
    }
    if let Err(e) = prim::check_gcm(key.len, iv.len) {
        return e;
    }
    if ciphertext_len.is_null() || tag.is_null() {
        return code::ARGUMENTS_BAD;
    }
    // SAFETY: ciphertext_len points to a size_t, ciphertext to that many bytes, tag to 16 (caller)
    code(unsafe {
        (|| {
            if *ciphertext_len < plaintext.len {
                return Err(code::ARGUMENTS_BAD);
            }
            let (key, iv, aad, pt) = (input(key)?, input(iv)?, input(aad)?, input(plaintext)?);
            let mut t = [0; prim::TAG_LEN];
            *ciphertext_len = output(ciphertext, pt.len(), |o| {
                prim::gcm_encrypt(key, iv, aad, pt, o, &mut t)
            })?;
            tag.copy_from(t.as_ptr(), t.len());
            Ok(())
        })()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_aes_gcm_decrypt(
    key: Slice,
    iv: Slice,
    aad: Slice,
    ciphertext: Slice,
    tag: *const u8,
    plaintext: *mut u8,
    plaintext_len: *mut usize,
) -> u32 {
    if halted() {
        return code::FUNCTION_FAILED;
    }
    if let Err(e) = prim::check_gcm(key.len, iv.len) {
        return e;
    }
    if plaintext_len.is_null() || tag.is_null() {
        return code::ARGUMENTS_BAD;
    }
    // SAFETY: plaintext_len points to a size_t, plaintext to that many bytes, tag to 16 (caller)
    code(unsafe {
        (|| {
            let cap = *plaintext_len;
            if cap < ciphertext.len {
                return Err(code::ARGUMENTS_BAD);
            }
            let (key, iv, aad, ct) = (input(key)?, input(iv)?, input(aad)?, input(ciphertext)?);
            let tag = &*tag.cast::<[u8; prim::TAG_LEN]>();
            match output(plaintext, ct.len(), |o| {
                prim::gcm_decrypt(key, iv, aad, ct, tag, o)
            }) {
                Ok(n) => *plaintext_len = n,
                // §7.10.4: the whole buffer the caller gave, as in C
                Err(code::ENCRYPTED_DATA_INVALID) if !plaintext.is_null() => {
                    plaintext.write_bytes(0, cap);
                    return Err(code::ENCRYPTED_DATA_INVALID);
                }
                Err(e) => return Err(e),
            }
            Ok(())
        })()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pbkdf2(
    alg: c_int,
    password: Slice,
    salt: Slice,
    iterations: u32,
    out: *mut u8,
    out_len: usize,
) -> u32 {
    if halted() {
        return code::FUNCTION_FAILED;
    }
    let alg = alg as u32;
    if let Err(e) = prim::check_pbkdf2(alg, iterations, out_len) {
        return e;
    }
    // SAFETY: the caller's slices; out has out_len bytes
    code(unsafe {
        (|| {
            let (password, salt) = (input(password)?, input(salt)?);
            output(out, out_len, |o| {
                prim::pbkdf2(alg, password, salt, iterations, o).map(|()| out_len)
            })
            .map(drop)
        })()
    })
}
