//! The operator config file, `/etc/freehsm/freehsm.conf` (`src/fhsm_conf.c`,
//! `include/fhsm_conf.h`). No business rule covers it; `tests/golden/cases.tsv` is the
//! specification.
//!
//! A key ships in the file only if code reads it (#128): today `mode` (`src/fhsm_mode.c`) and
//! `secure_heap_kb` (here). Lines are `key = value`; `#`, `;` and `[` start comments and sections,
//! and `#` or `;` ends a value. Matching is exact: `modem` is not `mode`. The file is read as C's
//! `fgets` with a 512-byte buffer read it, so a line longer than 511 bytes counts as several
//! lines, and a line ends at a NUL byte.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub const DEFAULT_PATH: &str = "/etc/freehsm/freehsm.conf";
/// The compiled default arena, `FHSM_SECURE_HEAP_BYTES` (`include/fhsm_common.h:295`).
pub const DEFAULT_HEAP_BYTES: usize = 8 * 1024 * 1024;
/// `secure_heap_kb` bounds (`include/fhsm_conf.h:49-50`): too small bricks the module, too large
/// fails against `RLIMIT_MEMLOCK`.
pub const HEAP_MIN_KB: u64 = 64;
pub const HEAP_MAX_KB: u64 = 64 * 1024;

/// What `fgets(line, 512, f)` returns at most.
const PIECE: usize = 511;
/// `char v[32]` in `fhsm_conf_secure_heap_bytes`: 31 bytes and the NUL.
const HEAP_VALUE_CAP: usize = 31;

/// `FHSM_CONF` when set and not empty (tests), else [`DEFAULT_PATH`].
pub fn path() -> PathBuf {
    match pqhsm_core::env("FHSM_CONF") {
        Some(p) if !p.is_empty() => p.into(),
        _ => OsString::from(DEFAULT_PATH).into(),
    }
}

/// The value of `key` in the file at `path`, cut to `cap` bytes and then right-trimmed. `None`
/// when the file or the key is absent, or every match has an empty value.
pub fn lookup_in(path: &Path, key: &[u8], cap: usize) -> Option<Vec<u8>> {
    if key.is_empty() {
        return None;
    }
    let text = std::fs::read(path).ok()?;
    text.split_inclusive(|&b| b == b'\n')
        .flat_map(|line| line.chunks(PIECE))
        .find_map(|piece| value(piece, key, cap))
}

fn value(piece: &[u8], key: &[u8], cap: usize) -> Option<Vec<u8>> {
    let line = piece.split(|&b| b == 0).next().unwrap_or_default();
    let line = trim_start(line, is_c_space);
    if matches!(line.first(), None | Some(b'#' | b';' | b'[')) {
        return None;
    }
    let rest = trim_start(line.strip_prefix(key)?, is_blank).strip_prefix(b"=")?;
    let v = trim_start(rest, is_blank);
    let end = v
        .iter()
        .position(|b| matches!(b, b'\n' | b'\r' | b'#' | b';'))
        .unwrap_or(v.len());
    let v = &v[..end.min(cap)];
    let v = &v[..v.iter().rposition(|&b| !is_c_space(b)).map_or(0, |i| i + 1)];
    (!v.is_empty()).then(|| v.to_vec())
}

/// The secure-heap arena size in bytes: `secure_heap_kb` from the file at `path`, rounded up to a
/// power of two (OpenSSL's arena asserts on anything else). The compiled default when the key is
/// absent, does not parse, or is outside [`HEAP_MIN_KB`]..=[`HEAP_MAX_KB`]: a clamped value
/// would be a setting the operator believes took effect.
pub fn secure_heap_bytes_in(path: &Path) -> usize {
    lookup_in(path, b"secure_heap_kb", HEAP_VALUE_CAP)
        .and_then(|v| parse_ulong(&v))
        .filter(|kb| (HEAP_MIN_KB..=HEAP_MAX_KB).contains(kb))
        .map_or(DEFAULT_HEAP_BYTES, |kb| {
            (kb as usize * 1024).next_power_of_two()
        })
}

/// [`secure_heap_bytes_in`] the file [`path`] names.
pub fn secure_heap_bytes() -> usize {
    secure_heap_bytes_in(&path())
}

/// `strtoul(s, &end, 10)` as the C caller accepts it: the whole string consumed and no `ERANGE`.
/// A leading `-` negates modulo 2^64, as `strtoul` does.
fn parse_ulong(s: &[u8]) -> Option<u64> {
    let s = trim_start(s, is_c_space);
    let (neg, digits) = match s.split_first() {
        Some((b'-', d)) => (true, d),
        Some((b'+', d)) => (false, d),
        _ => (false, s),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = digits.iter().try_fold(0u64, |n, &d| {
        n.checked_mul(10)?.checked_add(u64::from(d - b'0'))
    })?;
    Some(if neg { n.wrapping_neg() } else { n })
}

/// C's `isspace` in the C locale.
fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn is_blank(b: u8) -> bool {
    matches!(b, b' ' | b'\t')
}

fn trim_start(s: &[u8], f: fn(u8) -> bool) -> &[u8] {
    &s[s.iter().position(|&b| !f(b)).unwrap_or(s.len())..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::ffi::{CString, c_char};

    /// The C caller's acceptance test on libc's own strtoul.
    fn libc_strtoul(s: &[u8]) -> Option<u64> {
        let c = CString::new(s).ok()?;
        let mut end: *mut c_char = std::ptr::null_mut();
        // SAFETY: c is NUL-terminated and outlives the call; errno is thread-local
        unsafe {
            *libc::__errno_location() = 0;
            let v = libc::strtoul(c.as_ptr(), &mut end, 10);
            let ok = *libc::__errno_location() == 0 && end != c.as_ptr().cast_mut() && *end == 0;
            ok.then_some(v as u64)
        }
    }

    proptest! {
        #[test]
        fn parse_ulong_is_strtoul(s in "[ \t\x0b+\\-0-9a]{0,24}") {
            prop_assert_eq!(parse_ulong(s.as_bytes()), libc_strtoul(s.as_bytes()));
        }

        #[test]
        fn parse_ulong_is_strtoul_near_the_limits(n in any::<u64>(), neg in any::<bool>()) {
            let s = format!("{}{n}", if neg { "-" } else { "" });
            prop_assert_eq!(parse_ulong(s.as_bytes()), libc_strtoul(s.as_bytes()));
        }
    }

    #[test]
    fn path_is_the_default_without_fhsm_conf() {
        // The env var is never set in this test binary.
        assert_eq!(path(), Path::new(DEFAULT_PATH));
    }
}
