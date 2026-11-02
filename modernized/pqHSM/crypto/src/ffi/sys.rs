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

#[cfg(feature = "ffi")]
static mut CORE_ONCE: libc::pthread_once_t = libc::PTHREAD_ONCE_INIT;

/// Runs `init` once per process: the crypto core's fork handler registration.
#[cfg(feature = "ffi")]
pub(crate) fn core_once(init: extern "C" fn()) {
    // SAFETY: as in heap_once
    unsafe { pthread_once(&raw mut CORE_ONCE, init) };
}

/// A mutex that a fork child can take although a parent thread held it at the fork: the child
/// handler re-initialises it, as `src/fhsm_apilock.c:94` does for the API lock. C's init ran
/// under `pthread_once`, which glibc lets a child run again (review M1).
///
/// It knows its holder, so a re-entrant call aborts rather than deadlocking silently, and a
/// child forked by the holder itself (fork+exec inside the locked section) keeps the lock its
/// own stack still holds (slice 3 review L2).
#[cfg(feature = "ffi")]
pub(crate) struct ForkMutex<T> {
    lock: std::cell::UnsafeCell<libc::pthread_mutex_t>,
    owner: std::sync::atomic::AtomicUsize,
    data: std::cell::UnsafeCell<T>,
}

// SAFETY: data is reached only with the lock held, or in a child with one thread
#[cfg(feature = "ffi")]
unsafe impl<T: Send> Sync for ForkMutex<T> {}

#[cfg(feature = "ffi")]
fn this_thread() -> usize {
    // SAFETY: no arguments; glibc's pthread_t is an address, never 0 for a live thread
    unsafe { libc::pthread_self() as usize }
}

#[cfg(feature = "ffi")]
impl<T> ForkMutex<T> {
    pub(crate) const fn new(data: T) -> Self {
        Self {
            lock: std::cell::UnsafeCell::new(libc::PTHREAD_MUTEX_INITIALIZER),
            owner: std::sync::atomic::AtomicUsize::new(0),
            data: std::cell::UnsafeCell::new(data),
        }
    }

    /// Runs `f` with the lock held. Not re-entrant: a nested call aborts.
    pub(crate) fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        use std::sync::atomic::Ordering::Relaxed;
        struct Unlock<'a>(
            *mut libc::pthread_mutex_t,
            &'a std::sync::atomic::AtomicUsize,
        );
        impl Drop for Unlock<'_> {
            fn drop(&mut self) {
                self.1.store(0, Relaxed);
                // SAFETY: locked below by this thread
                unsafe { libc::pthread_mutex_unlock(self.0) };
            }
        }
        let me = this_thread();
        if self.owner.load(Relaxed) == me {
            stderr("[freehsm-c] FATAL : re-entrant call into a module lock\n");
            std::process::abort();
        }
        // SAFETY: an initialised mutex at a fixed address
        unsafe { libc::pthread_mutex_lock(self.lock.get()) };
        self.owner.store(me, Relaxed);
        let _unlock = Unlock(self.lock.get(), &self.owner);
        // SAFETY: the lock is held until _unlock drops, after f
        f(unsafe { &mut *self.data.get() })
    }

    /// Frees the lock again and runs `f` on the data, unless the forking thread holds it: the
    /// child's copy of that thread is still inside `with` and releases it itself.
    ///
    /// # Safety
    /// Only from a fork child handler: one thread, so no other holder and no other reference.
    pub(crate) unsafe fn after_fork(&self, f: impl FnOnce(&mut T)) {
        if self.owner.load(std::sync::atomic::Ordering::Relaxed) == this_thread() {
            return;
        }
        self.owner.store(0, std::sync::atomic::Ordering::Relaxed);
        // SAFETY: the caller's contract
        unsafe {
            libc::pthread_mutex_init(self.lock.get(), std::ptr::null());
            f(&mut *self.data.get());
        }
    }
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
