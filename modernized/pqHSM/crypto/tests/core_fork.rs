//! The crypto core's lock across `fork` (review M1, DIV-035):
//!
//! 1. a child forked while a parent thread is inside `fhsm_crypto_init` runs its own init
//!    instead of waiting for a thread it does not have, as glibc's `pthread_once` let C's child;
//! 2. a child forked after the parent's init runs the self-tests again;
//! 3. a child forked while a parent thread holds the DRBG lock runs that init too, although
//!    the init seeds the DRBG (slice 3 review M1).
//!
//!   cargo test -p pqhsm-crypto --features ffi --test core_fork
//!
//! The integrity check, the KATs and the module state are stubbed here. The integrity stub holds
//! the parent's init open by reading a pipe until it is written to; the state stub holds a
//! `fhsm_drbg_bytes` inside the DRBG lock the same way (DIV-041 reads the state under it).

use std::ffi::{c_char, c_int};
use std::process::exit;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use std::time::Duration;

use pqhsm_crypto as _; // links the C ABI below

unsafe extern "C" {
    fn fhsm_crypto_init() -> u32;
    fn fhsm_drbg_bytes(out: *mut u8, n: usize) -> u32;
    fn fhsm_drbg_init() -> u32;
}

static HOLD: AtomicBool = AtomicBool::new(true);
static PIPE_READ: AtomicI32 = AtomicI32::new(-1);
static INTEGRITY_RUNS: AtomicU32 = AtomicU32::new(0);
/// The state read that blocks: the second after arming, the one under the DRBG lock.
static STATE_CALLS: AtomicU32 = AtomicU32::new(0);
static STATE_BLOCK_AT: AtomicU32 = AtomicU32::new(0);

#[unsafe(no_mangle)]
extern "C" fn pqhsm_integrity_run() -> u32 {
    INTEGRITY_RUNS.fetch_add(1, Ordering::SeqCst);
    if HOLD.load(Ordering::SeqCst) {
        wait_for_pipe();
    }
    0
}

fn wait_for_pipe() {
    let mut b = 0u8;
    // SAFETY: a pipe fd and one byte of buffer
    unsafe { libc::read(PIPE_READ.load(Ordering::SeqCst), (&raw mut b).cast(), 1) };
}

#[unsafe(no_mangle)]
extern "C" fn fhsm_kat_run_all(_out: *mut u8, _cap: usize, count: *mut usize) -> u32 {
    // SAFETY: count points to a size_t (the caller)
    unsafe { count.write(0) };
    0
}

#[unsafe(no_mangle)]
extern "C" fn fhsm_state_get() -> c_int {
    let n = STATE_CALLS.fetch_add(1, Ordering::SeqCst) + 1;
    if HOLD.load(Ordering::SeqCst) && n == STATE_BLOCK_AT.load(Ordering::SeqCst) {
        wait_for_pipe();
    }
    2
}

#[unsafe(no_mangle)]
extern "C" fn fhsm_state_latch_error(_reason: *const c_char) {}

/// Forks a child that calls the init with HOLD off, and returns whether it finished within 10 s
/// having run the integrity check itself. The child seeds the DRBG too, as the init does once
/// the FIPS provider loads; this image has none, so the init stops before.
fn child_inits() -> bool {
    // SAFETY: the child calls the init under test, async-signal-safe calls and _exit
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        HOLD.store(false, Ordering::SeqCst);
        let before = INTEGRITY_RUNS.load(Ordering::SeqCst);
        // SAFETY: the child has one thread
        unsafe {
            libc::alarm(10);
            fhsm_crypto_init();
            fhsm_drbg_init();
            libc::_exit(if INTEGRITY_RUNS.load(Ordering::SeqCst) > before {
                0
            } else {
                1
            });
        }
    }
    let mut status = 0;
    // SAFETY: pid is our child; status is a valid out-parameter
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

fn main() {
    let mut fds = [0; 2];
    // SAFETY: fds has room for two descriptors
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
    PIPE_READ.store(fds[0], Ordering::SeqCst);

    // SAFETY: no arguments
    let held = std::thread::spawn(|| unsafe { fhsm_crypto_init() });
    while INTEGRITY_RUNS.load(Ordering::SeqCst) == 0 {
        std::thread::sleep(Duration::from_millis(10)); // the thread now holds the lock, blocked
    }
    let during = child_inits();

    // SAFETY: one byte to the pipe's write end
    unsafe { libc::write(fds[1], [1u8].as_ptr().cast(), 1) };
    let parent_rv = held.join().unwrap();
    let after = child_inits();

    STATE_BLOCK_AT.store(STATE_CALLS.load(Ordering::SeqCst) + 2, Ordering::SeqCst);
    // SAFETY: a 32-byte buffer
    let drawing = std::thread::spawn(|| unsafe { fhsm_drbg_bytes([0u8; 32].as_mut_ptr(), 32) });
    while STATE_CALLS.load(Ordering::SeqCst) < STATE_BLOCK_AT.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(10)); // the thread now holds the DRBG lock
    }
    let drbg_held = child_inits();
    // SAFETY: one byte to the pipe's write end
    unsafe { libc::write(fds[1], [1u8].as_ptr().cast(), 1) };
    drawing.join().unwrap(); // its result depends on the image's providers, not on the lock

    println!(
        "core_fork: child during init {}, child after init {}, child while the DRBG is held {}, \
         parent init 0x{parent_rv:x}",
        if during {
            "initialised"
        } else {
            "hung or failed"
        },
        if after {
            "ran the self-tests"
        } else {
            "did not run them"
        },
        if drbg_held {
            "initialised"
        } else {
            "hung or failed"
        }
    );
    if !during || !after || !drbg_held {
        exit(1);
    }
}
