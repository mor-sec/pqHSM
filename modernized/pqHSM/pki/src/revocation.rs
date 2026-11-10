//! The revocation database and the OCSP responder body (`src/fhsm_revocation.c`).
//!
//! [`answer`] takes the OCSP encoder as an argument: it decides every SingleResponse, builds
//! the nonce extension and wraps the encoder's BasicOCSPResponse in an OCSPResponse. The `ffi`
//! C ABI passes `fhsm_pki_ocsp` (Phase 3 slice 5c) with the caller's signer.
//!
//! Behaviour that looks wrong but is kept, as decided, is listed in `DIVERGENCES.md`
//! ("Candidates found in slice 2"); the numbers in comments here refer to that table.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::ffi::libcrypto::{AskedError, Cert, Request, generalized_time};

/// `FHSM_REV_MAX_ENTRIES`: a larger database is refused, not truncated.
pub const MAX_ENTRIES: usize = 100_000;
/// `FHSM_REV_ERR_MAX`: the C callers' diagnostic buffer.
pub const ERR_MAX: usize = 640;

/// `FHSM_REV_EIO`: the caller or the machine got something wrong.
pub const EIO: i32 = 2;
/// `FHSM_REV_EPARSE`: the input could not be understood.
pub const EPARSE: i32 = 3;

/// `FHSM_OCSP_GOOD` / `_REVOKED` / `_UNKNOWN` (`include/fhsm_composite.h`).
pub const OCSP_GOOD: i32 = 0;
pub const OCSP_REVOKED: i32 = 1;
pub const OCSP_UNKNOWN: i32 = 2;

/// A failure, as C reports it: the status code and the full diagnostic (C's `err` text,
/// newlines included, never truncated; truncation to the caller's `err_cap` is the C ABI's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevError {
    pub code: i32,
    pub msg: String,
}

fn fail<T>(code: i32, msg: String) -> Result<T, RevError> {
    Err(RevError { code, msg })
}

/// `strerror` text: what C prints after the path.
fn reason(e: &io::Error) -> String {
    let s = e.to_string();
    s.rsplit_once(" (os error ")
        .map_or(s.clone(), |(m, _)| m.to_owned())
}

fn shown(p: &Path) -> String {
    String::from_utf8_lossy(p.as_os_str().as_bytes()).into_owned()
}

// ---------------------------------------------------------------------------------------
// Reasons, serials, dates
// ---------------------------------------------------------------------------------------

/// RFC 5280 CRLReason names. 7 is unassigned and 8 (removeFromCRL) is refused.
const REASONS: &[(&str, i32)] = &[
    ("unspecified", 0),
    ("keyCompromise", 1),
    ("cACompromise", 2),
    ("affiliationChanged", 3),
    ("superseded", 4),
    ("cessationOfOperation", 5),
    ("certificateHold", 6),
    ("privilegeWithdrawn", 9),
    ("aACompromise", 10),
];

/// RULE-024: the RFC 5280 code for `name`, or -2. (-1 means "no reason" and is never returned.)
pub fn reason_code(name: &[u8]) -> i32 {
    REASONS
        .iter()
        .find(|r| r.0.as_bytes() == name)
        .map_or(-2, |r| r.1)
}

/// RULE-024: the name for `code`, or `None` (7, 8 and anything unassigned).
pub fn reason_name(code: i32) -> Option<&'static str> {
    REASONS.iter().find(|r| r.1 == code).map(|r| r.0)
}

/// The accepted names, comma-separated.
pub fn reason_list() -> &'static str {
    "unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, \
     cessationOfOperation, certificateHold, privilegeWithdrawn, aACompromise"
}

/// RULE-024: hex digits (either case) to at most `cap` bytes; `None` for empty, odd, non-hex
/// or over-cap input.
pub fn hex_to_bytes(h: &[u8], cap: usize) -> Option<Vec<u8>> {
    if h.is_empty() || !h.len().is_multiple_of(2) || h.len() / 2 > cap {
        return None;
    }
    let nib = |c: u8| (c as char).to_digit(16).map(|v| v as u8);
    h.chunks(2)
        .map(|p| Some((nib(p[0])? << 4) | nib(p[1])?))
        .collect()
}

/// Days from 1970-01-01 to a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468
}

/// The inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// RULE-024 with DIV-016: `YYYYMMDDHHMMSSZ` to seconds since the epoch, `None` if malformed or
/// if any field is outside its calendar range.
pub fn date_to_time(s: &[u8]) -> Option<i64> {
    if s.len() != 15 || s[14] != b'Z' || !s[..14].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let n = |a: usize, b: usize| {
        s[a..b]
            .iter()
            .fold(0i64, |v, c| v * 10 + i64::from(c - b'0'))
    };
    let (y, mo, d, h, mi, se) = (n(0, 4), n(4, 6), n(6, 8), n(8, 10), n(10, 12), n(12, 14));
    if !(1..=12).contains(&mo)
        || !(1..=days_in_month(y, mo)).contains(&d)
        || h > 23
        || mi > 59
        || se > 59
    {
        return None;
    }
    let t = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se;
    // C took timegm's -1 as its error value, so 19691231235959Z is refused (candidate 5)
    (t != -1).then_some(t)
}

/// The reverse, `None` when the result is not 15 characters. A negative year prints with
/// its sign and is accepted when it fits (candidate 6).
pub fn time_to_date(when: i64) -> Option<String> {
    let (y, m, d) = civil_from_days(when.div_euclid(86_400));
    let s = when.rem_euclid(86_400);
    let out = format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}Z",
        s / 3600,
        s / 60 % 60,
        s % 60
    );
    (out.len() == 15).then_some(out)
}

/// RULE-024: the same number, ignoring leading zero bytes on either side.
pub fn serial_eq(a: &[u8], b: &[u8]) -> bool {
    fn trim(mut s: &[u8]) -> &[u8] {
        while s.len() > 1 && s[0] == 0 {
            s = &s[1..];
        }
        s
    }
    trim(a) == trim(b)
}

// ---------------------------------------------------------------------------------------
// The database
// ---------------------------------------------------------------------------------------

/// One revocation. `serial` is at most 64 bytes. `date` is the 15-byte `YYYYMMDDHHMMSSZ` a
/// load validated, or whatever a caller of [`Db::add`] put there (C does not check).
/// `reason` is an RFC 5280 code or -1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub serial: Vec<u8>,
    pub date: Vec<u8>,
    pub reason: i32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Db {
    pub crl_number: u64,
    pub entries: Vec<Entry>,
}

const PARTLY_READ: &str = "  Nothing was read. A revocation database that is only partly
  understood would produce a list missing revocations, which is a
  signed statement that a revoked certificate is still valid.
  Fix the line, or remove it deliberately.
";

/// The longest line C's 512-byte `fgets` read whole, newline excluded (DIV-020).
const LINE_MAX: usize = 510;

/// C's `isspace` in the "C" locale.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `strtoull(s, &end, 10)`: the value and how many bytes it used (0 if none). A sign is
/// accepted and `-` wraps; an overflow saturates (candidate 4).
fn strtoull(s: &[u8]) -> (u64, usize) {
    let lead = s.iter().take_while(|c| is_space(**c)).count();
    let mut i = lead;
    let neg = s.get(i) == Some(&b'-');
    if matches!(s.get(i), Some(b'-' | b'+')) {
        i += 1;
    }
    let digits = s[i..].iter().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return (0, 0);
    }
    let v = s[i..i + digits].iter().try_fold(0u64, |v, c| {
        v.checked_mul(10)?.checked_add(u64::from(c - b'0'))
    });
    let v = match v {
        None => u64::MAX,
        Some(v) if neg => v.wrapping_neg(),
        Some(v) => v,
    };
    (v, i + digits)
}

/// `sscanf(p, "%159s %63s %63s")`: up to three words, a word longer than its width split.
fn words(p: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0;
    for width in [159, 63, 63] {
        i += p[i..].iter().take_while(|c| is_space(**c)).count();
        if i == p.len() {
            break;
        }
        let n = p[i..]
            .iter()
            .take(width)
            .take_while(|c| !is_space(**c))
            .count();
        out.push(&p[i..i + n]);
        i += n;
    }
    out
}

impl Db {
    /// RULE-024, RULE-100: the whole file or nothing. A missing file is an empty database.
    /// DIV-019: a CR inside a line, DIV-020: a line over 510 bytes, and DIV-021: a read error
    /// each refuse the file.
    pub fn load(path: &Path) -> Result<Db, RevError> {
        let mut all = Vec::new();
        match File::open(path).and_then(|mut f| f.read_to_end(&mut all)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Db::default()),
            Err(e) => {
                return fail(
                    EIO,
                    format!("cannot read {}: {}\n", shown(path), reason(&e)),
                );
            }
            Ok(_) => {}
        }
        let bad = |ln: usize, why: &str| {
            fail(
                EPARSE,
                format!("{} line {ln}: {why}\n{PARTLY_READ}", shown(path)),
            )
        };

        let mut d = Db::default();
        let mut seen_number = false;
        for (k, raw) in all.split(|c| *c == b'\n').enumerate() {
            let ln = k + 1;
            if raw.len() > LINE_MAX {
                return bad(ln, "line is longer than 510 bytes");
            }
            // C's strings end at a NUL
            let mut line = raw.split(|c| *c == 0).next().unwrap_or_default();
            match line.iter().position(|c| *c == b'\r') {
                Some(cr) if cr + 1 < line.len() => return bad(ln, "carriage return inside a line"),
                Some(cr) => line = &line[..cr],
                None => {}
            }
            let p = &line[line
                .iter()
                .take_while(|c| matches!(c, b' ' | b'\t'))
                .count()..];
            if p.is_empty() || p[0] == b'#' {
                continue;
            }

            if let Some(rest) = p
                .strip_prefix(b"crlNumber")
                .filter(|r| matches!(r.first(), Some(b' ' | b'\t')))
            {
                if seen_number {
                    return bad(ln, "crlNumber appears twice");
                }
                let (v, used) = strtoull(&rest[1..]);
                if used != rest.len() - 1 {
                    return bad(ln, "crlNumber is not a number");
                }
                d.crl_number = v;
                seen_number = true;
                continue;
            }

            if d.entries.len() >= MAX_ENTRIES {
                return bad(ln, "too many entries");
            }
            let w = words(p);
            if w.len() < 2 {
                return bad(ln, "expected: SERIAL DATE [REASON]");
            }
            let Some(serial) = hex_to_bytes(w[0], 64) else {
                return bad(ln, "serial is not an even number of hex digits");
            };
            if date_to_time(w[1]).is_none() {
                return bad(ln, "date is not YYYYMMDDHHMMSSZ");
            }
            let reason = match w.get(2) {
                None | Some(&b"-") => -1,
                Some(r) => match reason_code(r) {
                    -2 => return bad(ln, "unknown revocation reason"),
                    c => c,
                },
            };
            d.entries.push(Entry {
                serial,
                date: w[1].to_vec(),
                reason,
            });
        }
        Ok(d)
    }

    /// RULE-100: `<path>.tmp`, flush, fsync, rename. The lock is the caller's ([`DbLock`], DIV-074).
    /// DIV-022: whatever is at `<path>.tmp` is removed and the tmp created O_EXCL|O_NOFOLLOW,
    /// so a planted link is never written through. A failure leaves the tmp (candidate 7b).
    pub fn save(&self, path: &Path) -> Result<(), RevError> {
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        if tmp.len() >= 1024 {
            return fail(EIO, "path too long\n".into());
        }
        let tmp = Path::new(&tmp);

        let mut text = String::from(
            "# fhsm-ca revocation database v1\n\
             # SERIAL(hex)  DATE(YYYYMMDDHHMMSSZ)  REASON  ('-' for none)\n",
        );
        text += &format!("crlNumber {}\n", self.crl_number);
        for e in &self.entries {
            for b in &e.serial {
                text += &format!("{b:02X}");
            }
            // add does not validate, so a date is written as given (candidate 8)
            let rn = if e.reason < 0 {
                "-"
            } else {
                reason_name(e.reason).unwrap_or("-")
            };
            text += &format!(" {} {rn}\n", String::from_utf8_lossy(&e.date));
        }

        let _ = fs::remove_file(tmp);
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(tmp)
            .or_else(|e| {
                fail(
                    EIO,
                    format!("cannot write {}: {}\n", shown(tmp), reason(&e)),
                )
            })?;
        f.write_all(text.as_bytes())
            .and_then(|()| f.sync_all())
            .or_else(|e| {
                fail(
                    EIO,
                    format!("writing {} failed: {}\n", shown(tmp), reason(&e)),
                )
            })?;
        drop(f);
        fs::rename(tmp, path).or_else(|e| {
            fail(
                EIO,
                format!("cannot replace {}: {}\n", shown(path), reason(&e)),
            )
        })
    }

    /// RULE-099: append; refused with [`EPARSE`] at [`MAX_ENTRIES`] (candidate 9).
    pub fn add(&mut self, e: Entry) -> Result<(), RevError> {
        if self.entries.len() >= MAX_ENTRIES {
            return fail(EPARSE, too_many());
        }
        self.entries.push(e);
        Ok(())
    }

    /// The first entry whose serial is [`serial_eq`] to `serial`.
    pub fn find(&self, serial: &[u8]) -> Option<&Entry> {
        self.entries.iter().find(|e| serial_eq(serial, &e.serial))
    }
}

/// `fhsm_rev_db_add`'s diagnostic at the cap.
pub(crate) fn too_many() -> String {
    format!("too many entries (the limit is {MAX_ENTRIES})\n")
}

// ---------------------------------------------------------------------------------------
// OCSP
// ---------------------------------------------------------------------------------------

/// How long [`DbLock::take`] waits for another holder, as the token's flock (DIV-012).
pub const LOCK_WAIT: Duration = Duration::from_secs(10);

/// DIV-074: `flock` on the database, held from load to save (exclusive) or for a read
/// (shared), as the token file's (DIV-012): a lock on a file a save has since renamed over is
/// taken again on the new one. An exclusive lock on a missing database creates it empty
/// (O_EXCL, so a planted link is not followed), which loads as a missing one, so that two
/// first writers exclude each other too; a reader of a missing one locks nothing. Released
/// when dropped.
pub struct DbLock(Option<File>);

impl DbLock {
    /// Waits up to `wait` for another holder; then [`EIO`], nothing read or changed.
    pub fn take(path: &Path, exclusive: bool, wait: Duration) -> Result<DbLock, RevError> {
        let op = if exclusive {
            libc::LOCK_EX
        } else {
            libc::LOCK_SH
        };
        // one deadline for the whole wait, however often a save replaces the file
        let end = Instant::now() + wait;
        loop {
            // Any other failure to open stops the load too, which says why.
            let f = match File::open(path) {
                Ok(f) => f,
                Err(e) if exclusive && e.kind() == io::ErrorKind::NotFound => {
                    // A writer that lost the race to create it opens the winner's. A path that
                    // is neither (a dangling link) would load as empty, unlocked: refused.
                    match OpenOptions::new().write(true).create_new(true).open(path) {
                        Ok(f) => f,
                        Err(_) => match File::open(path) {
                            Ok(f) => f,
                            Err(e) => {
                                return fail(
                                    EIO,
                                    format!("cannot lock {}: {}\n", shown(path), reason(&e)),
                                );
                            }
                        },
                    }
                }
                Err(_) => return Ok(DbLock(None)),
            };
            loop {
                // SAFETY: f's descriptor, open for the call.
                if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&f), op | libc::LOCK_NB) }
                    == 0
                {
                    break;
                }
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::Interrupted => {}
                    io::ErrorKind::WouldBlock if Instant::now() < end => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    io::ErrorKind::WouldBlock => {
                        return fail(
                            EIO,
                            format!(
                                "{} is locked by another process; gave up after {} seconds.\n  Nothing was changed.\n",
                                shown(path),
                                wait.as_secs()
                            ),
                        );
                    }
                    _ => {
                        return fail(
                            EIO,
                            format!("cannot lock {}: {}\n", shown(path), reason(&e)),
                        );
                    }
                }
            }
            let same = match (f.metadata(), fs::metadata(path)) {
                (Ok(a), Ok(b)) => a.ino() == b.ino() && a.dev() == b.dev(),
                _ => false,
            };
            if same {
                return Ok(DbLock(Some(f)));
            }
        }
    }
}

impl Drop for DbLock {
    fn drop(&mut self) {
        if let Some(f) = &self.0 {
            // SAFETY: f's descriptor, still open.
            unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(f), libc::LOCK_UN) };
        }
    }
}

/// The five-byte unsigned OCSPResponse for malformedRequest(1), internalError(2) or
/// tryLater(3); `None` for anything else, successful(0) included.
pub fn status_response(status: i32) -> Option<[u8; 5]> {
    (1..=3)
        .contains(&status)
        .then_some([0x30, 0x03, 0x0A, 0x01, status as u8])
}

/// Would a verifier accept answers signed by `responder`? EKU OCSPSigning, then issuer name.
/// The paths only name the inputs in the diagnostic.
pub fn check_responder(
    responder: &[u8],
    ca: &[u8],
    responder_path: Option<&str>,
    ca_path: Option<&str>,
) -> Result<(), RevError> {
    let rp = responder_path.unwrap_or("the responder certificate");
    let cp = ca_path.unwrap_or("the CA certificate");
    let Some(r) = Cert::from_der(responder) else {
        return fail(EPARSE, format!("{rp} does not parse as DER.\n"));
    };
    let Some(ca) = Cert::from_der(ca) else {
        return fail(EPARSE, format!("{cp} is not a certificate.\n"));
    };
    if !r.has_ocsp_signing() {
        return fail(
            EPARSE,
            format!(
                "{rp} does not carry extendedKeyUsage OCSPSigning.
  A verifier will refuse every response it signs, so signing them
  would only produce answers nobody accepts. Issue the responder
  with `fhsm-ca issue --profile ocsp-responder`.
"
            ),
        );
    }
    if !r.issuer_is(&ca) {
        return fail(
            EPARSE,
            format!(
                "{rp} was not issued by the CA in {cp}.
  Its issuer name does not match that CA's subject, so a verifier
  has no reason to accept it as speaking for this authority.
"
            ),
        );
    }
    Ok(())
}

/// One SingleResponse decision, as C hands it to `fhsm_pki_ocsp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Single {
    /// The request's CertID, re-encoded (DER).
    pub cert_id: Vec<u8>,
    /// [`OCSP_GOOD`], [`OCSP_REVOKED`] or [`OCSP_UNKNOWN`].
    pub status: i32,
    /// DER GeneralizedTime of the revocation, for [`OCSP_REVOKED`] only.
    pub revoked_at: Option<Vec<u8>>,
    /// The entry's reason for a revoked serial, else -1.
    pub reason: i32,
}

/// Everything the encoder is given: `fhsm_pki_ocsp`'s arguments other than the signer.
/// The times are DER GeneralizedTime; `exts` is the responseExtensions SEQUENCE or empty
/// (the C ABI passes NULL for empty); `cap` is the output buffer C offers the encoder.
#[derive(Debug, Clone, Copy)]
pub struct Tbs<'a> {
    pub responder: &'a [u8],
    pub produced_at: &'a [u8],
    pub this_update: &'a [u8],
    pub next_update: &'a [u8],
    pub singles: &'a [Single],
    pub exts: &'a [u8],
    pub cap: usize,
}

/// `fhsm_ocsp_stats_t`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub asked: usize,
    pub ours: usize,
    pub revoked: usize,
    pub unknown: usize,
    pub nonce_echoed: bool,
}

/// The inputs of `fhsm_ocsp_answer_ex`, less the signer (which the encoder carries) and with
/// the clock made explicit: C reads `time(NULL)` once per answer, the C ABI passes that.
#[derive(Debug, Clone, Copy)]
pub struct Query<'a> {
    pub req: &'a [u8],
    pub ca: &'a [u8],
    pub responder: &'a [u8],
    pub db: &'a Db,
    pub days: i32,
    pub label: Option<&'a str>,
    pub now: i64,
}

/// A DER TLV.
pub(crate) fn tlv(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let n: usize = parts.iter().map(|p| p.len()).sum();
    let mut out = vec![tag];
    match n {
        0..0x80 => out.push(n as u8),
        0x80..=0xFF => out.extend([0x81, n as u8]),
        0x100..=0xFFFF => out.extend([0x82, (n >> 8) as u8, n as u8]),
        0x10000..=0xFF_FFFF => out.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
        _ => {
            out.push(0x84);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
    parts.iter().for_each(|p| out.extend_from_slice(p));
    out
}

/// OCSPResponse { successful, [0] { id-pkix-ocsp-basic, OCTET STRING basic } }.
fn wrap(basic: &[u8]) -> Vec<u8> {
    const BASIC_OID: [u8; 11] = [
        0x06, 0x09, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01,
    ];
    let bytes = tlv(0x30, &[&BASIC_OID, &tlv(0x04, &[basic])]);
    tlv(0x30, &[&[0x0A, 0x01, 0x00], &tlv(0xA0, &[&bytes])])
}

/// responseExtensions: SEQUENCE OF Extension holding the request's nonce. The length header
/// stops at two bytes, so a nonce over 65,535 bytes gets a wrong one (candidate 10).
fn nonce_extensions(ext: Vec<u8>) -> Vec<u8> {
    let mut out = vec![0x30];
    match ext.len() {
        n @ 0..0x80 => out.push(n as u8),
        n @ 0x80..=0xFF => out.extend([0x81, n as u8]),
        n => out.extend([0x82, (n >> 8) as u8, n as u8]),
    }
    out.extend(ext);
    out
}

/// RULE-023: parse the request, decide every CertID, echo the nonce, call `encode` once, and
/// wrap its BasicOCSPResponse in a successful OCSPResponse. `encode` returns the encoder's
/// bytes or its `fhsm_rv_t`. A serial of ours that is not in `db` is "good" (RULE-023,
/// deferred to Phase 6).
pub fn answer(
    q: &Query<'_>,
    encode: &mut dyn FnMut(&Tbs<'_>) -> Result<Vec<u8>, u32>,
) -> Result<(Vec<u8>, Stats), RevError> {
    if q.days <= 0 {
        return fail(EIO, "validity must be positive.\n".into());
    }
    let Some(ca) = Cert::from_der(q.ca) else {
        return fail(EPARSE, "the CA certificate does not parse.\n".into());
    };
    let what = q.label.unwrap_or("the request");
    let Some(req) = Request::from_der(q.req) else {
        return fail(EPARSE, format!("{what} is not an OCSP request.\n"));
    };
    let asked = req.count();
    if asked <= 0 {
        return fail(EPARSE, format!("{what} asks about nothing.\n"));
    }
    // past 9999 libcrypto still encodes, so this cannot fail in practice (candidate 12)
    let next = q.now + i64::from(q.days) * 86_400;
    let (Some(now), Some(next)) = (generalized_time(q.now), generalized_time(next)) else {
        return fail(EIO, "cannot encode the time.\n".into());
    };

    let mut st = Stats {
        asked: asked as usize,
        ..Stats::default()
    };
    let mut singles = Vec::with_capacity(asked as usize);
    for i in 0..asked {
        let a = match req.asked(i, &ca) {
            Ok(a) => a,
            Err(AskedError::Malformed) => {
                return fail(EPARSE, "malformed CertID in the request.\n".into());
            }
            Err(AskedError::Reencode) => return fail(EIO, "cannot re-encode a CertID.\n".into()),
        };
        let mut one = Single {
            cert_id: a.der,
            status: OCSP_UNKNOWN,
            revoked_at: None,
            reason: -1,
        };
        if !a.ours {
            st.unknown += 1;
            singles.push(one);
            continue;
        }
        st.ours += 1;
        // the serial's sign is not compared (candidate 14)
        match q.db.find(&a.serial) {
            Some(e) => {
                // C ignored the parser's result: a date add let through answers 1970 (DIV-016)
                let t = date_to_time(&e.date).unwrap_or(0);
                let Some(at) = generalized_time(t) else {
                    return fail(EIO, "cannot encode a revocation date.\n".into());
                };
                one.status = OCSP_REVOKED;
                one.revoked_at = Some(at);
                one.reason = e.reason;
                st.revoked += 1;
            }
            None => one.status = OCSP_GOOD,
        }
        singles.push(one);
    }

    let exts = req.nonce().map_or_else(Vec::new, nonce_extensions);
    // C's guess at the encoder's output size (candidate 11)
    let cap = 16_384 + q.ca.len() + q.responder.len() + asked as usize * 512 + exts.len();
    let tbs = Tbs {
        responder: q.responder,
        produced_at: &now,
        this_update: &now,
        next_update: &next,
        singles: &singles,
        exts: &exts,
        cap,
    };
    let basic = encode(&tbs).or_else(|rv| {
        fail(
            EIO,
            format!("building the OCSP response failed (0x{rv:X}).\n"),
        )
    })?;
    st.nonce_echoed = !exts.is_empty();
    Ok((wrap(&basic), st))
}
