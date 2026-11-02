//! The syscalls `tpm` and `token` need that std does not wrap. Always compiled.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

/// An anonymous in-memory file, close-on-exec (DIV-017: C's were inheritable by any fork).
pub(crate) fn memfd(name: &str) -> io::Result<File> {
    let name = CString::new(name).map_err(|_| io::ErrorKind::InvalidInput)?;
    // SAFETY: `name` is NUL-terminated; a non-negative return is a fresh fd we now own.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is open and owned by nothing else.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Let `cmd`'s child, and only it, inherit `files`: clear their close-on-exec flag after the
/// fork, in the child.
pub(crate) fn inherit(cmd: &mut Command, files: &[&File]) {
    let fds: Vec<i32> = files.iter().map(|f| f.as_raw_fd()).collect();
    // SAFETY: the closure only calls fcntl, which is async-signal-safe, and allocates nothing.
    unsafe {
        cmd.pre_exec(move || {
            for &fd in &fds {
                if libc::fcntl(fd, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// `access(path, mode) == 0`, as C checks it (real uid, symlinks followed).
pub(crate) fn access(path: &Path, mode: libc::c_int) -> bool {
    let Ok(p) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `p` is NUL-terminated.
    unsafe { libc::access(p.as_ptr(), mode) == 0 }
}

/// `flock(fd, op)`, retried on EINTR; the token file transaction (DIV-012) releases with
/// `LOCK_UN`.
pub(crate) fn flock(f: &File, op: libc::c_int) -> io::Result<()> {
    loop {
        // SAFETY: `f` is an open file for the duration of the call.
        if unsafe { libc::flock(f.as_raw_fd(), op) } == 0 {
            return Ok(());
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}

/// `LOCK_EX`, giving up with `WouldBlock` after `wait`: the caller holds the token mutex, so an
/// unbounded wait would stall every thread of the process (review M-4).
pub(crate) fn lock_ex(f: &File, wait: Duration) -> io::Result<()> {
    let end = Instant::now() + wait;
    loop {
        match flock(f, libc::LOCK_EX | libc::LOCK_NB) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(10));
            }
            r => return r,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_ex_gives_up_after_the_wait_then_takes_a_free_lock() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t");
        std::fs::write(&p, b"x").unwrap();
        let (a, b) = (File::open(&p).unwrap(), File::open(&p).unwrap());
        lock_ex(&a, Duration::ZERO).unwrap();
        let at = Instant::now();
        let e = lock_ex(&b, Duration::from_millis(50)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
        assert!(at.elapsed() >= Duration::from_millis(50));
        flock(&a, libc::LOCK_UN).unwrap();
        lock_ex(&b, Duration::ZERO).unwrap();
    }
}
