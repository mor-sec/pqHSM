//! The power-on integrity check (`src/fhsm_integrity.c`, RULE-009, FIPS 140-3 §7.10.2): SHA-384
//! of the module's own file with its `.fhsm_digest` section zeroed, compared in constant time
//! with the digest `scripts/sign_module.sh` patched into that section.

use std::ops::Range;

use pqhsm_crypto::rv;
use zeroize::Zeroize;

pub const DIGEST_LEN: usize = 48;
pub const SECTION: &[u8] = b".fhsm_digest";

/// The bypass variable (DIV-034: honoured only by a `dev-bypass` build).
pub const ALLOW_UNSIGNED: &str = "FHSM_INTEGRITY_ALLOW_UNSIGNED";

const EHDR: usize = 64;
const SHDR: usize = 64;

/// What one run of the check found.
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub rv: u32,
    /// ERROR is latched ("integrity check failed").
    pub latched: bool,
    /// What C wrote to stderr, in order.
    pub stderr: String,
    /// The digest computed, when one was.
    pub last: Option<[u8; DIGEST_LEN]>,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}
fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// `lo..lo + len` when it lies inside a file of `n` bytes: C's bounds, written so no sum can
/// wrap (`src/fhsm_integrity.c:189-194`).
fn within(lo: u64, len: u64, n: usize) -> Option<Range<usize>> {
    let n = n as u64;
    (lo <= n && len <= n - lo).then(|| lo as usize..(lo + len) as usize)
}

/// The file range of the section called `name` in a little-endian ELF64 image, refusing every
/// header, table, name and section that does not fit (`src/fhsm_integrity.c:173-221`).
pub fn find_section(file: &[u8], name: &[u8]) -> Option<Range<usize>> {
    if file.len() < EHDR || &file[..4] != b"\x7fELF" || file[4] != 2 {
        return None;
    }
    let (shoff, shentsize, shnum, shstrndx) = (
        u64_at(file, 0x28),
        u16_at(file, 0x3a),
        u16_at(file, 0x3c),
        u16_at(file, 0x3e),
    );
    if shoff == 0 || shnum == 0 || usize::from(shentsize) != SHDR {
        return None;
    }
    let table = within(shoff, u64::from(shnum) * SHDR as u64, file.len())?;
    if shstrndx >= shnum {
        return None;
    }
    let shdr = |i: u16| table.start + usize::from(i) * SHDR;
    let strtab = within(
        u64_at(file, shdr(shstrndx) + 0x18),
        u64_at(file, shdr(shstrndx) + 0x20),
        file.len(),
    )?;
    let strtab = &file[strtab];
    for i in 0..shnum {
        let at = shdr(i);
        let n = u32_at(file, at) as usize;
        // the name must start, and end, inside the string table
        let len = strtab.get(n..)?.iter().position(|&b| b == 0)?;
        if &strtab[n..n + len] == name {
            return within(u64_at(file, at + 0x18), u64_at(file, at + 0x20), file.len());
        }
    }
    None
}

const NO_SECTION: &str = "[freehsm-c] FATAL : this file has no .fhsm_digest section.\n  It was \
    not built with the integrity check compiled in, so it\n  cannot be a FreeHSM module -- most \
    likely the wrong library is\n  on your path or in --module. Check with :\n    readelf -SW \
    <file> | grep fhsm_digest\n";
const UNSIGNED: &str = "[freehsm-c] FATAL : this module is unsigned.\n  Its .fhsm_digest section \
    is the all-zero placeholder a fresh\n  build leaves, so the integrity self-test has nothing \
    to verify\n  against and the module refuses to start (FIPS 140-3 7.10.2).\n  If you built it \
    yourself :   make integrity\n  If you downloaded it, it was published unsigned -- do not \
    use\n  it, and do not set FHSM_INTEGRITY_ALLOW_UNSIGNED to get past\n  this. See \
    SECURITY.md, \"v1.4.0 published unsigned\".\n";
const MISMATCH: &str = "[freehsm-c] FATAL : this module does not match its signature.\n  \
    .fhsm_digest carries a digest, and it is not the digest of this\n  file. The binary has \
    changed since it was signed.\n  This is not a missing build step. Do not run it. Reinstall \
    from\n  a verified download and check the detached GPG signature that\n  ships beside it.\n";

/// The check over the module's own file (`None`: it could not be located or read), as
/// `fhsm_integrity_verify` runs it (`src/fhsm_integrity.c:223-406`). `bypass` is the honoured
/// bypass variable: it turns every failure into OK without a latch, and says so only for the
/// failures with no message of their own (no file, an unreadable one, no SHA-384). The file is
/// wiped before returning.
pub fn verify(
    file: Option<&mut [u8]>,
    embedded: &[u8; DIGEST_LEN],
    bypass: bool,
    sha384: impl FnOnce(&[u8]) -> Option<[u8; DIGEST_LEN]>,
) -> Report {
    let mut report = Report {
        rv: rv::OK,
        latched: false,
        stderr: String::new(),
        last: None,
    };
    report.rv = match file {
        // C's fstat: a file of size 0 is a setup error, before any section lookup
        None | Some([]) => rv::FUNCTION_FAILED,
        Some(f) => {
            let rv = check(f, embedded, bypass, sha384, &mut report);
            f.zeroize();
            rv
        }
    };
    if report.rv != rv::OK {
        if bypass {
            report.stderr += &format!(
                "[freehsm-c] WARNING : {ALLOW_UNSIGNED} active --- integrity verify failed \
                 (rv=0x{:08x}) but the ERROR latch is suppressed. This is INVALID for any FIPS \
                 140-3 / CC EAL4+ deployment.\n",
                report.rv
            );
            report.rv = rv::OK;
        } else {
            report.latched = true;
        }
    }
    report
}

fn check(
    file: &mut [u8],
    embedded: &[u8; DIGEST_LEN],
    bypass: bool,
    sha384: impl FnOnce(&[u8]) -> Option<[u8; DIGEST_LEN]>,
    report: &mut Report,
) -> u32 {
    let Some(section) = find_section(file, SECTION).filter(|s| s.len() >= DIGEST_LEN) else {
        if bypass {
            return rv::OK;
        }
        report.stderr += NO_SECTION;
        return rv::INTEGRITY_FAILED;
    };
    // the whole section, as sh_size says (RULE-009 (2): the signing script zeroes 48 bytes)
    file[section].fill(0);
    let Some(digest) = sha384(file) else {
        return rv::FUNCTION_FAILED;
    };
    report.last = Some(digest);
    let failure = if embedded.iter().all(|&b| b == 0) {
        UNSIGNED
    } else if pqhsm_crypto::mem::ct_diff(&digest, embedded) != 0 {
        MISMATCH
    } else {
        return rv::OK;
    };
    if bypass {
        return rv::OK;
    }
    report.stderr += failure;
    rv::INTEGRITY_FAILED
}
