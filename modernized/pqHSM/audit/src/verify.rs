//! The module's own chain verifier, `fhsm_audit_verify` (RULE-008, module side).
//! The standalone auditor tool is the separate `pqhsm-audit-verify` crate.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

use crate::chain;

/// `fgets` buffer size in the C verifier.
const FGETS_MAX: u64 = 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Empty key.
    ArgumentsBad,
    /// The file could not be opened or read (`FHSM_RV_FUNCTION_FAILED`).
    Open,
    /// HMAC computation failed.
    Hmac,
    /// The first broken line, 1-based (`FHSM_RV_SIGNATURE_INVALID`). The header comment says
    /// 0-based; the code is 1-based, and this follows the code.
    Broken { line: usize },
}

/// Walk the chain and stop at the first broken line, as `fhsm_audit_verify` does.
///
/// Lines are read the way `fgets` with a 4096-byte buffer reads them: a physical line longer
/// than 4095 bytes counts as several lines. The trailing `\n` is removed. A line is broken if:
/// - it lacks any of `"hmac":"`, `"prev_hmac":"`, `"seq":` (first occurrence of each), or the
///   64 hex characters after `"hmac":"` run past the end of the line;
/// - either hex field is not 64 hex digits (upper or lower case accepted);
/// - `HMAC(key, bytes before "hmac":")` differs from the recorded MAC;
/// - `prev_hmac` differs from the previous line's MAC (the chain head for line 1);
/// - `seq` (parsed like `strtoull`: leading digits, 0 if none) is not the line number;
/// - (DIV-008) it holds a NUL, or does not end exactly with the 64 lowercase hex digits of its
///   MAC and `"}`. C ignored bytes after the MAC and after a NUL, and accepted uppercase.
///
/// Any key length of 1 or more is accepted here (DIV-003 restricts only `open`).
/// An empty file verifies. A read error mid-file is `Open`, where C stops and reports OK
/// (DIV-007).
pub fn verify_file(path: &Path, key: &[u8]) -> Result<(), VerifyError> {
    if key.is_empty() {
        return Err(VerifyError::ArgumentsBad);
    }
    let mut reader = BufReader::new(File::open(path).map_err(|_| VerifyError::Open)?);
    let mut expect_prev = chain::chain_head(key).map_err(|_| VerifyError::Hmac)?;
    let mut buf = Vec::new();
    let mut n = 0usize;
    loop {
        buf.clear();
        if (&mut reader)
            .take(FGETS_MAX - 1)
            .read_until(b'\n', &mut buf)
            .map_err(|_| VerifyError::Open)?
            == 0
        {
            return Ok(());
        }
        n += 1;
        let line = buf.strip_suffix(b"\n").unwrap_or(&buf);
        if line.contains(&0) {
            return Err(VerifyError::Broken { line: n });
        }
        match check_line(line, key, &expect_prev, n) {
            Ok(Some(mac)) => expect_prev = mac,
            Ok(None) => return Err(VerifyError::Broken { line: n }),
            Err(e) => return Err(e),
        }
    }
}

/// `Ok(Some(mac))` for a good line, `Ok(None)` for a broken one.
fn check_line(
    line: &[u8],
    key: &[u8],
    expect_prev: &[u8; 32],
    n: usize,
) -> Result<Option<[u8; 32]>, VerifyError> {
    let (Some(h), Some(p), Some(s)) = (
        find(line, b"\"hmac\":\""),
        find(line, b"\"prev_hmac\":\""),
        find(line, b"\"seq\":"),
    ) else {
        return Ok(None);
    };
    let (Some(recorded), Some(prev)) = (unhex32(&line[h + 8..]), unhex32(&line[p + 13..])) else {
        return Ok(None);
    };
    let mac = chain::mac(key, &line[..h]).map_err(|_| VerifyError::Hmac)?;
    let tail = &line[h + 8..];
    let canonical = tail.len() == 66
        && tail.ends_with(b"\"}")
        && tail[..64]
            .iter()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    let good = canonical
        && chain::ct_eq(&mac, &recorded)
        && prev == *expect_prev
        && strtoull(&line[s + 6..]) == n as u64;
    Ok(good.then_some(recorded))
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// 64 hex digits at the start of `s`, either case.
fn unhex32(s: &[u8]) -> Option<[u8; 32]> {
    let s = s.get(..64)?;
    let mut out = [0u8; 32];
    // not from_str_radix: it accepts a leading '+', which C's unhex32 refuses
    let nib = |c: u8| (c as char).to_digit(16);
    for (o, [hi, lo]) in out.iter_mut().zip(s.as_chunks::<2>().0) {
        *o = (nib(*hi)? << 4 | nib(*lo)?) as u8;
    }
    Some(out)
}

/// C `strtoull(s, NULL, 10)`: optional whitespace and sign, then leading digits; 0 if none,
/// `u64::MAX` on overflow, wrapped negation for `-`.
fn strtoull(s: &[u8]) -> u64 {
    let s = &s[s
        .iter()
        .position(|c| !matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r'))
        .unwrap_or(s.len())..];
    let (neg, s) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    match s
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .try_fold(0u64, |v, &c| {
            v.checked_mul(10)?.checked_add(u64::from(c - b'0'))
        }) {
        Some(v) if neg => v.wrapping_neg(),
        Some(v) => v,
        None => u64::MAX,
    }
}
