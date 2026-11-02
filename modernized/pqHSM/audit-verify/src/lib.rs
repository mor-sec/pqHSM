//! Standalone offline audit verifier, the Rust replacement for `tools/freehsm_audit.c`
//! (RULE-008, auditor side).
//!
//! **Deliberately shares no code with `pqhsm-audit`.** An auditor must be able to build the
//! verifier alone, and a check that shares code with what it checks is a mirror
//! (`tools/freehsm_audit.c:49-52`). The small parsers below duplicate the module's on purpose.
//!
//! Output is byte-for-byte that of the C tool, so the two can be swapped under any script.
//! Every function writes to the given streams and returns the process exit code. The C tool
//! parses with `strstr`/`strtoll`/`sscanf`; their quirks are reproduced, not fixed, so the two
//! tools give the same verdict on any file.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

/// `fgets` buffer size in the C tool.
const LINE_MAX_LEN: u64 = 4096;
/// The C tool's directory table.
const MAX_FILES: usize = 4096;
const INIT: &[u8] = b"FHSM-AUDIT-INIT|seq=0";

const USAGE: &str = "Usage:
  {p} dump   <path.audit.log> [path...]
  {p} verify <path.audit.log> <audit_key_hex_64>
  {p} verify <directory>         <audit_key_hex_64>

  A directory verifies every base.NNNNNN log in it and
  reports holes in the numbering, which is how a removed
  log becomes visible.
";

/// The whole CLI: `args[0]` is the program name. Usage errors print the C usage text with
/// `args[0]` substituted, and exit 2.
pub fn run(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let prog = args.first().map_or("freehsm-audit", String::as_str);
    let usage = |err: &mut dyn Write| {
        let _ = err.write_all(USAGE.replace("{p}", prog).as_bytes());
        2
    };
    match args.get(1).map(String::as_str) {
        Some("dump") if args.len() >= 3 => args[2..]
            .iter()
            .fold(0, |rc, p| rc | dump_file(Path::new(p), out, err)),
        Some("verify") if args.len() == 4 => {
            let target = Path::new(&args[2]);
            if fs::metadata(target).is_ok_and(|m| m.is_dir()) {
                verify_dir(target, &args[3], out, err)
            } else {
                verify_file(target, &args[3], out, err)
            }
        }
        _ => usage(err),
    }
}

// ---- dump ----------------------------------------------------------------------------------

/// `dump <path> [path...]`: one formatted row per line, as `dump_file` prints it.
/// Exit code: 0, or 1 if a file could not be opened (`perror` text on `err`).
pub fn dump_file(path: &Path, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let mut lines = match open_lines(path) {
        Ok(l) => l,
        Err(e) => {
            perror(err, path, &e);
            return 1;
        }
    };
    let mut o = Vec::new();
    o.extend_from_slice(b"# ");
    o.extend_from_slice(path.as_os_str().as_bytes());
    o.push(b'\n');
    o.extend_from_slice(
        format!(
            "# {:<26} {:<7} {:<22} {:<4} {:<7} {:<4} {:<30} {}\n",
            "timestamp", "seq", "event", "slot", "session", "role", "result", "params"
        )
        .as_bytes(),
    );
    let mut n_events = 0;
    let mut buf = Vec::new();
    while lines.next_line(&mut buf) {
        let line = c_str(&buf);
        let num = |k: &str, d: i64| find_int(line, k).unwrap_or(d);
        let (seq, ts, slot, session, rv) = (
            num("seq", 0),
            num("ts", 0),
            num("slot", -1),
            num("session", -1),
            num("rv", 0),
        );
        let event = find_str(line, "event", 64);
        let role = find_str(line, "role", 16);
        let params = find_params(line, 1024).unwrap_or(b"{}");
        o.extend_from_slice(b"  ");
        pad_right(&mut o, ts_to_iso(ts).as_bytes(), 26);
        o.extend_from_slice(format!(" {seq:<7} ").as_bytes());
        pad_right(&mut o, event, 22);
        o.extend_from_slice(format!(" {slot:>4} {session:>7} ").as_bytes());
        pad_right(&mut o, role, 4);
        o.push(b' ');
        pad_right(&mut o, rv_to_name(rv as u64).as_bytes(), 30);
        o.push(b' ');
        o.extend_from_slice(params);
        o.push(b'\n');
        n_events += 1;
    }
    o.extend_from_slice(format!("# total : {n_events} events\n").as_bytes());
    let _ = out.write_all(&o);
    0
}

fn pad_right(o: &mut Vec<u8>, s: &[u8], width: usize) {
    o.extend_from_slice(s);
    o.resize(o.len() + width.saturating_sub(s.len()), b' ');
}

/// C `find_str`: the bytes after `"key":"` up to the next `"`, cut to `cap - 1`. Empty if absent.
fn find_str<'a>(line: &'a [u8], key: &str, cap: usize) -> &'a [u8] {
    let Some(at) = find(line, format!("\"{key}\":\"").as_bytes()) else {
        return b"";
    };
    let rest = &line[at + key.len() + 4..];
    let Some(end) = rest.iter().position(|&c| c == b'"') else {
        return b"";
    };
    &rest[..end.min(cap - 1)]
}

/// C `find_int`: `strtoll` after `"key":`; `None` if absent or no digits.
fn find_int(line: &[u8], key: &str) -> Option<i64> {
    let at = find(line, format!("\"{key}\":").as_bytes())?;
    strtoll(&line[at + key.len() + 3..])
}

/// C `find_params`: the brace-balanced object after `"params":`, or to the end of the line if
/// it never closes; cut to `cap - 1`.
fn find_params(line: &[u8], cap: usize) -> Option<&[u8]> {
    let at = find(line, b"\"params\":")? + 9;
    let rest = &line[at..];
    if rest.first() != Some(&b'{') {
        return None;
    }
    let mut depth = 0i32;
    let mut end = rest.len();
    for (i, &c) in rest.iter().enumerate() {
        match c {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end = i + 1;
                    break;
                }
            }
            _ => {}
        }
    }
    Some(&rest[..end.min(cap - 1)])
}

/// C `ts_to_iso`: `gmtime` of the whole seconds, microseconds clamped to 0..=999999.
fn ts_to_iso(ns: i64) -> String {
    let secs = ns / 1_000_000_000;
    let us = ((ns % 1_000_000_000) / 1000).clamp(0, 999_999);
    let (days, sod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Days since 1970-01-01 to a civil date (H. Hinnant, "chrono-compatible date algorithms").
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{us:06}Z",
        year % 10_000,
        month % 100,
        day % 100,
        sod / 3600,
        sod / 60 % 60,
        sod % 60
    )
}

fn rv_to_name(rv: u64) -> String {
    match rv {
        0x0000_0000 => "CKR_OK".into(),
        0x0000_0005 => "CKR_GENERAL_ERROR".into(),
        0x0000_0006 => "CKR_FUNCTION_FAILED".into(),
        0x0000_0007 => "CKR_ARGUMENTS_BAD".into(),
        0x0000_00A0 => "CKR_PIN_INCORRECT".into(),
        0x0000_00A4 => "CKR_PIN_LOCKED".into(),
        0x0000_0101 => "CKR_USER_NOT_LOGGED_IN".into(),
        0x0000_00E0 => "CKR_TOKEN_NOT_PRESENT".into(),
        0x8000_0001 => "FHSM_RV_KAT_FAILED".into(),
        0x8000_0002 => "FHSM_RV_INTEGRITY_FAILED".into(),
        0x8000_0003 => "FHSM_RV_FIPS_NOT_APPROVED".into(),
        0x8000_0004 => "FHSM_RV_PIN_THROTTLED".into(),
        _ => format!("rv=0x{rv:08x}"),
    }
}

// ---- verify --------------------------------------------------------------------------------

/// `verify <file> <keyhex>`: checks **every** line and reports each failure on `err`, then
/// `verify: N/M records FAILED` (exit 1) or `verify: M records OK, chain intact` on `out`
/// (exit 0). A key that is not 64 hex characters prints
/// `verify: key must be 64 hex chars (32 bytes)` and exits 2.
pub fn verify_file(path: &Path, key_hex: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(key) = key_from_hex(key_hex.as_bytes()) else {
        let _ = err.write_all(b"verify: key must be 64 hex chars (32 bytes)\n");
        return 2;
    };
    let mut lines = match open_lines(path) {
        Ok(l) => l,
        Err(e) => {
            perror(err, path, &e);
            return 1;
        }
    };
    let Some(mut expect_prev) = hmac(&key, INIT) else {
        let _ = err.write_all(b"verify: cannot compute the chain head\n");
        return 1;
    };
    let (mut n, mut bad) = (0u64, 0u64);
    let mut e = Vec::new();
    let mut buf = Vec::new();
    while lines.next_line(&mut buf) {
        n += 1;
        let line = c_str(&buf);
        let (Some(h), Some(p), Some(q)) = (
            find(line, b"\"hmac\":\""),
            find(line, b"\"prev_hmac\":\""),
            find(line, b"\"seq\":"),
        ) else {
            e.extend_from_slice(
                format!("line {n} : missing hmac, prev_hmac or seq field\n").as_bytes(),
            );
            bad += 1;
            continue;
        };
        let (Some(recorded), Some(prev)) = (hex2bin(&line[h + 8..]), hex2bin(&line[p + 13..]))
        else {
            e.extend_from_slice(format!("line {n} : malformed hmac hex\n").as_bytes());
            bad += 1;
            continue;
        };
        let Some(mac) = hmac(&key, &line[..h]) else {
            e.extend_from_slice(format!("line {n} : HMAC computation failed\n").as_bytes());
            bad += 1;
            continue;
        };
        if !openssl::memcmp::eq(&mac, &recorded) {
            e.extend_from_slice(format!("line {n} : HMAC mismatch (record altered)\n").as_bytes());
            bad += 1;
        } else if !ends_with_its_mac(&buf, h) {
            // DIV-008: C stopped reading at the MAC (and at a NUL), so these bytes went unchecked
            e.extend_from_slice(
                format!(
                    "line {n} : record does not end with its lowercase hmac (record altered)\n"
                )
                .as_bytes(),
            );
            bad += 1;
        }
        if !openssl::memcmp::eq(&prev, &expect_prev) {
            e.extend_from_slice(
                format!("line {n} : prev_hmac does not follow line {} (record deleted, inserted or reordered)\n", n - 1)
                    .as_bytes(),
            );
            bad += 1;
        }
        if strtoull(&line[q + 6..]) != n {
            e.extend_from_slice(
                format!("line {n} : seq is not {n} (records missing)\n").as_bytes(),
            );
            bad += 1;
        }
        expect_prev = recorded;
    }
    if bad > 0 {
        e.extend_from_slice(format!("verify: {bad}/{n} records FAILED\n").as_bytes());
        let _ = err.write_all(&e);
        return 1;
    }
    let _ = err.write_all(&e);
    let _ = out.write_all(format!("verify: {n} records OK, chain intact\n").as_bytes());
    0
}

/// `verify <dir> <keyhex>`: verifies every `*.NNNNNN` file in numeric order, reports holes in
/// the numbering, and prints the summary and the "does not start at 000001" note exactly as
/// `verify_dir` does.
pub fn verify_dir(dir: &Path, key_hex: &str, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let entries = match fs::read_dir(dir) {
        Ok(d) => d,
        Err(e) => {
            perror(err, dir, &e);
            return 1;
        }
    };
    let mut files: Vec<(u64, Vec<u8>)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name();
            let name = name.as_bytes();
            let dot = name.iter().rposition(|&c| c == b'.')?;
            let digits = &name[dot + 1..];
            let seq = if digits.len() == 6 {
                strtoul_whole(digits)?
            } else {
                return None;
            };
            let mut path = dir.as_os_str().as_bytes().to_vec();
            path.push(b'/');
            path.extend_from_slice(name);
            Some((seq, path))
        })
        .take(MAX_FILES)
        .collect();
    if files.is_empty() {
        let _ = err
            .write_all(format!("verify: no numbered audit file in {}\n", dir.display()).as_bytes());
        return 1;
    }
    files.sort_by_key(|f| f.0);

    let mut rc = 0;
    for (i, (seq, path)) in files.iter().enumerate() {
        let _ = out.write_all(b"== ");
        let _ = out.write_all(path);
        let _ = out.write_all(b"\n");
        let p = Path::new(std::ffi::OsStr::from_bytes(path));
        if verify_file(p, key_hex, out, err) != 0 {
            rc = 1;
        }
        if i > 0 && *seq != files[i - 1].0.wrapping_add(1) {
            let _ = err.write_all(
                format!(
                    "verify: MISSING log(s) between {:06} and {seq:06} -- a file was removed\n",
                    files[i - 1].0
                )
                .as_bytes(),
            );
            rc = 1;
        }
    }
    let (first, last) = (files[0].0, files[files.len() - 1].0);
    let _ = out.write_all(
        format!(
            "\nverify: {} log(s), sequence {first:06}..{last:06}{}\n",
            files.len(),
            if rc != 0 {
                ""
            } else {
                ", contiguous, every chain intact"
            }
        )
        .as_bytes(),
    );
    if first != 1 {
        let _ = out.write_all(
            format!("verify: note -- the sequence starts at {first:06}, not 000001; earlier logs were archived or removed\n")
                .as_bytes(),
        );
    }
    rc
}

// ---- C-compatible primitives ---------------------------------------------------------------

/// Reads lines as `fgets(buf, 4096, f)` does: at most 4095 bytes, keeping the `\n`.
struct Lines(BufReader<File>);

impl Lines {
    /// Read errors end the file, as `fgets` returning NULL does.
    fn next_line(&mut self, buf: &mut Vec<u8>) -> bool {
        buf.clear();
        (&mut self.0)
            .take(LINE_MAX_LEN - 1)
            .read_until(b'\n', buf)
            .is_ok_and(|n| n > 0)
    }
}

fn open_lines(path: &Path) -> io::Result<Lines> {
    File::open(path).map(|f| Lines(BufReader::new(f)))
}

/// DIV-008: the raw line, less its `\n`, has no NUL and ends with 64 lowercase hex digits and
/// `"}` right after `"hmac":"` (at `h`).
fn ends_with_its_mac(raw: &[u8], h: usize) -> bool {
    let line = raw.strip_suffix(b"\n").unwrap_or(raw);
    let tail = &line[h + 8..];
    !line.contains(&0)
        && tail.len() == 66
        && tail.ends_with(b"\"}")
        && tail[..64]
            .iter()
            .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// The line as C string functions see it: up to the first NUL.
fn c_str(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// `perror(path)`: `path: strerror(errno)`.
fn perror(err: &mut dyn Write, path: &Path, e: &io::Error) {
    let msg = e.to_string();
    let msg = msg.find(" (os error ").map_or(msg.as_str(), |i| &msg[..i]);
    let _ = err.write_all(path.as_os_str().as_bytes());
    let _ = err.write_all(format!(": {msg}\n").as_bytes());
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn hmac(key: &[u8], data: &[u8]) -> Option<[u8; 32]> {
    let pkey = PKey::hmac(key).ok()?;
    let mut s = Signer::new(MessageDigest::sha256(), &pkey).ok()?;
    s.update(data).ok()?;
    let mut out = [0u8; 32];
    s.sign(&mut out).ok()?;
    Some(out)
}

fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn skip_space(s: &[u8]) -> &[u8] {
    &s[s.iter().position(|&c| !is_c_space(c)).unwrap_or(s.len())..]
}

/// The key as the C tool reads it: exactly 64 characters, then `hex2bin`.
fn key_from_hex(hex: &[u8]) -> Option<[u8; 32]> {
    if hex.len() != 64 { None } else { hex2bin(hex) }
}

/// C `hex2bin`: byte `i` is `sscanf(hex + 2*i, "%2x")`.
fn hex2bin(hex: &[u8]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = sscanf_2x(hex.get(2 * i..)?)? as u8;
    }
    Some(out)
}

/// glibc `sscanf(s, "%2x")`: whitespace skipped outside the width, then an optional sign and
/// hex digits within 2 characters; `-` wraps.
// shortcut: a "0x" prefix inside the width is not modelled; no audit line or key can start a
// field with it, since 'x' is not hex.
fn sscanf_2x(s: &[u8]) -> Option<u32> {
    let s = skip_space(s);
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, s[1..].get(..1)),
        Some(b'+') => (false, s[1..].get(..1)),
        _ => (false, s.get(..2).or(s.get(..1))),
    };
    let digits: Vec<u32> = digits?
        .iter()
        .map_while(|&c| (c as char).to_digit(16))
        .collect();
    if digits.is_empty() {
        return None;
    }
    let v = digits.iter().fold(0u32, |v, d| v << 4 | d);
    Some(if neg { v.wrapping_neg() } else { v })
}

/// C `strtoll`: `None` when no digits are consumed; clamps on overflow.
fn strtoll(s: &[u8]) -> Option<i64> {
    let s = skip_space(s);
    let (neg, s) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let digits = s.iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let mag = s[..digits].iter().try_fold(0i128, |v, &c| {
        Some((v * 10 + i128::from(c - b'0')).min(i128::from(u64::MAX)))
    })?;
    let v = if neg { -mag } else { mag };
    Some(v.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64)
}

/// C `strtoull(s, NULL, 10)`: 0 when no digits; `u64::MAX` on overflow; `-` wraps.
fn strtoull(s: &[u8]) -> u64 {
    let s = skip_space(s);
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

/// C `strtoul(s, &end, 10)` that must consume all of `s`.
fn strtoul_whole(s: &[u8]) -> Option<u64> {
    let t = skip_space(s);
    let (neg, d) = match t.first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    if d.is_empty() || !d.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let v: u64 = std::str::from_utf8(d).ok()?.parse().ok()?;
    Some(if neg { v.wrapping_neg() } else { v })
}
