//! pqHSM's PKI tools (Phase 5 of `analysis/pqHSM/MODERNIZATION_BRIEF.md`): one binary per
//! tool under its C name, with C's flags, messages and exit codes, over `pqhsm-pkiops`. What
//! the tools share is here: the PIN (DIV-072), C's number parsing, error exits, PEM.

use std::ffi::{c_int, c_long};
use std::io::{self, IsTerminal, Write};
use std::os::unix::ffi::OsStringExt;
use std::process::exit;

use pqhsm_pkiops::Error;
use zeroize::Zeroizing;

/// What every tool does first: die of SIGPIPE, as C does, where Rust's runtime would ignore
/// it and turn a closed pipe into a write error and a different exit status.
pub fn init() {
    // SAFETY: restoring a signal's default disposition.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
}

/// `fail`: `prog: message` on stderr, exit with the error's code. Nothing is closed first,
/// as in C.
pub fn fail(prog: &str, e: &Error) -> ! {
    let mut w = io::stderr().lock();
    let _ = w.write_all(format!("{prog}: ").as_bytes());
    let _ = w.write_all(e.c_msg());
    exit(e.code)
}

/// `perror(what)` then exit 2: `what: strerror(errno)`.
pub fn perror_exit(what: &str, e: &io::Error) -> ! {
    // shortcut: strerror's text is io::Error's Display less its " (os error N)" suffix, which
    // holds for errors from the OS, the only kind reaching here.
    let text = e.to_string();
    let text = text.rsplit_once(" (os error ").map_or(&text[..], |t| t.0);
    eprintln!("{what}: {text}");
    exit(2)
}

/// glibc's `atoi`: `(int)strtol(t, NULL, 10)`.
pub fn atoi(t: &[u8]) -> c_int {
    pqhsm_pkiops::strtol(t).0 as c_int
}

/// glibc's `atol`: `strtol(t, NULL, 10)`.
pub fn atol(t: &[u8]) -> c_long {
    pqhsm_pkiops::strtol(t).0
}

/// The PIN in `var` (DIV-072): read as C reads it; when unset or empty and stdin is a
/// terminal, asked for there without echo; otherwise `missing` (C's message, whole) on stderr
/// and exit 1. Wiped when dropped, which the caller does once the login has used it.
pub fn pin(prog: &str, var: &str, what: &str, missing: &str) -> Zeroizing<Vec<u8>> {
    if let Some(v) = std::env::var_os(var).filter(|v| !v.is_empty()) {
        return Zeroizing::new(v.into_vec());
    }
    if io::stdin().is_terminal()
        && let Ok(p) = read_hidden(&format!("{prog}: {what}: "))
        && !p.is_empty()
    {
        return p;
    }
    eprint!("{missing}");
    exit(1)
}

/// A line from the terminal on stdin, echo off but for the newline.
// shortcut: a signal while it waits leaves echo off, as getpass(3) does; a handler would
// restore it, if operators ask.
fn read_hidden(prompt: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut old = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: fd 0 is a terminal (checked by the caller); old is written on success.
    if unsafe { libc::tcgetattr(0, old.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: tcgetattr succeeded.
    let old = unsafe { old.assume_init() };
    let mut quiet = old;
    quiet.c_lflag &= !libc::ECHO;
    quiet.c_lflag |= libc::ECHONL;
    // SAFETY: a termios tcgetattr filled.
    if unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &quiet) } != 0 {
        return Err(io::Error::last_os_error());
    }
    eprint!("{prompt}");
    let r = read_line_unbuffered();
    // SAFETY: as above, the settings found.
    unsafe { libc::tcsetattr(0, libc::TCSAFLUSH, &old) };
    r
}

/// The longest line kept; the rest of a longer one is read and dropped.
const LINE_MAX: usize = 1024;

/// A line from fd 0 a byte at a time, so no copy of it stays in std's stdin buffer, into room
/// reserved up front, so no reallocation leaves one behind either.
// shortcut: a line past LINE_MAX is cut there; a PIN that long fails the module's length
// check, so nothing logs in with a truncated one.
fn read_line_unbuffered() -> io::Result<Zeroizing<Vec<u8>>> {
    use std::os::fd::FromRawFd;
    // SAFETY: fd 0 is open; ManuallyDrop leaves it open.
    let mut fd0 = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(0) });
    let mut line = Zeroizing::new(Vec::with_capacity(LINE_MAX));
    let mut b = Zeroizing::new([0u8; 1]);
    loop {
        match io::Read::read(&mut *fd0, &mut b[..]) {
            Ok(0) => break,
            Ok(_) if b[0] == b'\n' => break,
            Ok(_) if line.len() < LINE_MAX => line.push(b[0]),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(line)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `PEM_write_bio(b, label, "", der, n)`: no headers, 64 characters a line.
pub fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    let mut b64 = Vec::with_capacity(der.len().div_ceil(3) * 4);
    for c in der.chunks(3) {
        let n = c
            .iter()
            .enumerate()
            .fold(0u32, |a, (i, &b)| a | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            b64.push(if i <= c.len() {
                B64[(n >> (18 - 6 * i) & 63) as usize]
            } else {
                b'='
            });
        }
    }
    let mut out = format!("-----BEGIN {label}-----\n").into_bytes();
    for line in b64.chunks(64) {
        out.extend(line);
        out.push(b'\n');
    }
    out.extend(format!("-----END {label}-----\n").as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_is_openssls() {
        assert_eq!(pem("X", b""), b"-----BEGIN X-----\n-----END X-----\n");
        assert_eq!(
            pem("X", b"f"),
            b"-----BEGIN X-----\nZg==\n-----END X-----\n"
        );
        assert_eq!(
            pem("X", b"fo"),
            b"-----BEGIN X-----\nZm8=\n-----END X-----\n"
        );
        assert_eq!(
            pem("X", b"foo"),
            b"-----BEGIN X-----\nZm9v\n-----END X-----\n"
        );
        let p = pem("CERTIFICATE", &[0xFF; 48]);
        let lines: Vec<_> = p.split(|&b| b == b'\n').collect();
        assert_eq!(lines[1], &[b'/'; 64][..]);
        assert_eq!(lines[2], b"-----END CERTIFICATE-----");
        assert_eq!(
            pem("X", &[0xFF; 49]).split(|&b| b == b'\n').nth(2),
            Some(&b"/w=="[..])
        );
    }

    #[test]
    fn numbers_as_glibc() {
        assert_eq!(atoi(b"abc"), 0);
        assert_eq!(atoi(b"10x"), 10);
        assert_eq!(atoi(b" -3"), -3);
        // strtol clamps to LONG_MAX, and the int cast keeps its low 32 bits.
        assert_eq!(atoi(b"2147483648"), i32::MIN);
        assert_eq!(atoi(b"99999999999999999999"), -1);
        assert_eq!(atol(b"99999999999999999999"), c_long::MAX);
    }
}
