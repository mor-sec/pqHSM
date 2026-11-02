//! libcrypto's secure heap (`CRYPTO_secure_*`), one per process, and `getrlimit`.

use std::ffi::{c_char, c_int, c_void};
use std::io::Write;
use std::ptr::NonNull;

use openssl_sys as _; // links libcrypto

unsafe extern "C" {
    fn CRYPTO_secure_malloc_init(size: usize, minsize: usize) -> c_int;
    fn CRYPTO_secure_malloc_initialized() -> c_int;
    fn CRYPTO_secure_malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void;
    fn CRYPTO_secure_clear_free(ptr: *mut c_void, num: usize, file: *const c_char, line: c_int);
    fn CRYPTO_secure_allocated(ptr: *const c_void) -> c_int;
    fn CRYPTO_secure_used() -> usize;
    // glibc; the libc crate declares it for WASI only
    fn pthread_once(control: *mut libc::pthread_once_t, init: extern "C" fn()) -> c_int;
}

static mut HEAP_ONCE: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;

/// Runs `init` once per process, as `pthread_once` in C (`src/fhsm_memory.c:206`).
pub(crate) fn heap_once(init: extern "C" fn()) {
    // SAFETY: HEAP_ONCE is only ever handed to pthread_once, which synchronises access to it
    unsafe { pthread_once(&raw mut HEAP_ONCE, init) };
}

/// OpenSSL's allocation-site tag, used only by its memory debugging.
const SITE: *const c_char = c"pqhsm-crypto".as_ptr();

pub(crate) fn secure_heap_exists() -> bool {
    // SAFETY: no arguments; reads OpenSSL's own state
    unsafe { CRYPTO_secure_malloc_initialized() != 0 }
}

/// 1: created and locked; 2: created but not locked; 0: not created.
pub(crate) fn secure_heap_create(bytes: usize, min_block: usize) -> c_int {
    // SAFETY: plain values; OpenSSL validates them
    unsafe { CRYPTO_secure_malloc_init(bytes, min_block) }
}

pub(crate) fn secure_heap_used() -> usize {
    // SAFETY: no arguments
    unsafe { CRYPTO_secure_used() }
}

pub(crate) fn secure_alloc(n: usize) -> *mut u8 {
    // SAFETY: a plain allocation; null on failure
    unsafe { CRYPTO_secure_malloc(n, SITE, 0) }.cast()
}

pub(crate) fn secure_alloc_zeroed(n: usize) -> *mut u8 {
    let p = secure_alloc(n);
    if !p.is_null() {
        // SAFETY: p has n bytes
        unsafe { p.write_bytes(0, n) };
    }
    p
}

/// Returns `p` to the arena, zeroised first (OpenSSL tracks the size). Null is ignored.
///
/// # Safety
/// `p` is null, or came from [`crate::mem::alloc`] or [`crate::mem::alloc_zeroed`] and is not
/// used again.
pub unsafe fn secure_free(p: *mut u8) {
    if !p.is_null() {
        // SAFETY: p came from CRYPTO_secure_malloc (caller)
        unsafe { CRYPTO_secure_clear_free(p.cast(), 0, SITE, 0) };
    }
}

/// One arena block, freed (zeroised) on drop.
pub(crate) struct Block {
    ptr: NonNull<u8>,
    len: usize,
}

impl Block {
    pub(crate) fn alloc(len: usize) -> Option<Block> {
        NonNull::new(secure_alloc(len)).map(|ptr| Block { ptr, len })
    }

    pub(crate) fn in_secure_heap(&self) -> bool {
        // SAFETY: only compares the address with the arena's range
        unsafe { CRYPTO_secure_allocated(self.ptr.as_ptr().cast()) != 0 }
    }

    pub(crate) fn addr(&self) -> usize {
        self.ptr.as_ptr() as usize
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        // SAFETY: ptr came from CRYPTO_secure_malloc with len bytes, and is freed once
        unsafe { CRYPTO_secure_clear_free(self.ptr.as_ptr().cast(), self.len, SITE, 0) };
    }
}

/// The soft `RLIMIT_MEMLOCK` in kB; 0 when unlimited or unknown.
pub(crate) fn memlock_soft_kb() -> u64 {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: rl is a valid out-parameter
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) } == 0;
    if ok && rl.rlim_cur != libc::RLIM_INFINITY {
        rl.rlim_cur / 1024
    } else {
        0
    }
}

/// Best effort, as C's `fputs(stderr)`: a closed stderr must not stop the module.
pub(crate) fn stderr(msg: &str) {
    let _ = std::io::stderr().write_all(msg.as_bytes());
}
