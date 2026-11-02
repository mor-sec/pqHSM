//! Review M1: a child forked while another thread is inside the arena's first-use init must run
//! the init itself, as glibc's `pthread_once` does for C, instead of waiting for a thread the
//! child does not have.
//!
//!   cargo test -p pqhsm-crypto --features ffi --test fork_init
//!
//! The init is held open by pointing `FHSM_CONF` at a FIFO with no writer: reading the conf file
//! blocks. The child points `FHSM_CONF` elsewhere and must finish its own init within 10 s.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::process::exit;
use std::time::Duration;

use pqhsm_crypto as _; // links the C ABI below

unsafe extern "C" {
    fn fhsm_secure_heap_init() -> u32;
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pqhsm-fork-init-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("conf.fifo");
    let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: c is a C string; one thread so far, so set_var is sound
    unsafe {
        assert_eq!(libc::mkfifo(c.as_ptr(), 0o600), 0, "mkfifo");
        std::env::set_var("FHSM_CONF", &fifo);
    }

    // SAFETY: no arguments
    let held = std::thread::spawn(|| unsafe { fhsm_secure_heap_init() });
    std::thread::sleep(Duration::from_millis(300)); // the thread is now blocked opening the FIFO

    // SAFETY: the child only calls the init under test, async-signal-safe calls and _exit
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // SAFETY: the child has one thread
        unsafe {
            std::env::set_var("FHSM_CONF", dir.join("absent.conf"));
            libc::alarm(10);
            libc::_exit(if fhsm_secure_heap_init() == 0 { 0 } else { 1 });
        }
    }
    let mut status = 0;
    // SAFETY: pid is our child; status is a valid out-parameter
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);

    drop(std::fs::OpenOptions::new().write(true).open(&fifo).unwrap()); // EOF: the thread finishes
    let parent_rv = held.join().unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let child_ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    println!(
        "fork_init: child {}, parent init 0x{parent_rv:x}",
        if child_ok {
            "initialised"
        } else {
            "hung or failed"
        }
    );
    if !child_ok || parent_rv != 0 {
        exit(1);
    }
}
