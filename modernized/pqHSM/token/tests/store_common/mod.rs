//! Shared helpers for the slice 3 (token store) characterization tests. Every expected value
//! is in `golden/store/`, produced by running the legacy C `src/fhsm_token.c`:
//! `legacy/hybrid/golden/regen_store.sh`. Nothing here decides a value; it reads, renders and
//! compares.
#![allow(dead_code)]

pub mod scenario;

#[cfg(feature = "ffi")]
pub mod c_doubles;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use openssl::symm::{Cipher, Crypter, Mode};
use pqhsm_token::Rv;
use pqhsm_token::token::{Audit, AuditEvent, Role};

/// The invented PINs of gen_token.c / gen_store.c. None comes from the legacy tree.
pub const SO_PIN: &[u8] = b"golden-so-pin-01";
pub const USER_PIN: &[u8] = b"golden-user-pin-01";
pub const WRONG_PIN: &[u8] = b"golden-wrong-pin";
pub const NEW_PIN: &[u8] = b"golden-new-pin-02";

pub const HDR: usize = 317;
pub const BLOB_MAX: u64 = 2_148_421_644;

pub fn store_golden(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/store")
        .join(rel)
}

pub fn read_golden(rel: &str) -> Vec<u8> {
    fs::read(store_golden(rel)).unwrap_or_else(|e| {
        panic!("golden/store/{rel}: {e} (regenerate with legacy/hybrid/golden/regen_store.sh, at commit 0f481e9)")
    })
}

/// `testdata/` (the gen_token.c corpus).
pub fn corpus(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata")
        .join(rel)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

pub fn num(s: &str) -> u64 {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).unwrap(),
        None => s.parse().unwrap(),
    }
}

pub fn rv_hex(r: Rv) -> String {
    format!("0x{:x}", r.0)
}

pub fn rv_of<T>(r: &Result<T, Rv>) -> Rv {
    match r {
        Ok(_) => Rv::OK,
        Err(e) => *e,
    }
}

/// A BYTES argument of store_scenarios.txt; None is `-` (C's NULL).
pub fn bytes_of(s: &str) -> Option<Vec<u8>> {
    if s == "-" {
        return None;
    }
    let (kind, rest) = s.split_once(':').unwrap_or(("", s));
    Some(match kind {
        "hex" => unhex(rest),
        "pat" => {
            let (b, n) = rest.split_once(':').unwrap();
            let (b, n) = (num(b), num(n));
            (0..n).map(|i| (b + i) as u8).collect()
        }
        "zero" => vec![0; num(rest) as usize],
        "rep" => {
            let (c, n) = rest.split_once(':').unwrap();
            vec![c.as_bytes()[0]; num(n) as usize]
        }
        "txt" => rest.as_bytes().to_vec(),
        _ => s.as_bytes().to_vec(),
    })
}

/// A PIN argument: SO, USER, WRONG, NEW, lit:TEXT, or any BYTES form.
pub fn pin_of(s: &str) -> Vec<u8> {
    match s {
        "SO" => SO_PIN.to_vec(),
        "USER" => USER_PIN.to_vec(),
        "WRONG" => WRONG_PIN.to_vec(),
        "NEW" => NEW_PIN.to_vec(),
        _ => match s.strip_prefix("lit:") {
            Some(l) => l.as_bytes().to_vec(),
            None => bytes_of(s).unwrap_or_default(),
        },
    }
}

pub fn role_of(s: &str) -> Role {
    match s {
        "so" => Role::So,
        "user" => Role::User,
        _ => Role::None,
    }
}

/// `*` matches any run of characters; everything else is literal.
pub fn glob(pat: &str, s: &str) -> bool {
    let parts: Vec<&str> = pat.split('*').collect();
    if parts.len() == 1 {
        return pat == s;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !s.starts_with(first) || s.len() < first.len() + last.len() || !s.ends_with(last) {
        return false;
    }
    let mut rest = &s[first.len()..s.len() - last.len()];
    for p in &parts[1..parts.len() - 1] {
        match rest.find(p) {
            Some(i) => rest = &rest[i + p.len()..],
            None => return false,
        }
    }
    true
}

/// An expectation: `||`-separated alternatives, each `&&`-separated globs, each optionally
/// negated with a leading `!`.
pub fn matches(expect: &str, s: &str) -> bool {
    expect.split("||").any(|alt| {
        alt.split("&&").all(|e| match e.strip_prefix('!') {
            Some(neg) => !glob(neg, s),
            None => glob(e, s),
        })
    })
}

// ------------------------------------------------------------------ steps.tsv

/// One row of `steps.tsv`: the scenario, the 1-based step, the op line and C's output (every
/// field after the op line, each with its leading tab; `dump` rows span several lines).
#[derive(Clone, Debug)]
pub struct Step {
    pub scenario: String,
    pub step: usize,
    pub line: String,
    pub out: String,
}

pub fn steps() -> Vec<Step> {
    let text = String::from_utf8(read_golden("steps.tsv")).unwrap();
    let mut rows: Vec<String> = Vec::new();
    for l in text.lines() {
        if l.starts_with('#') {
            continue;
        }
        if l.starts_with('\t') {
            let last = rows.last_mut().expect("continuation before any row");
            last.push('\n');
            last.push_str(l);
        } else {
            rows.push(l.to_owned());
        }
    }
    rows.iter()
        .map(|r| {
            let mut f = r.splitn(4, '\t');
            let (scenario, step, rest) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
            let tail = f.next().map(|t| format!("\t{t}")).unwrap_or_default();
            // The op line itself has no tab; its output starts at the first tab after it.
            Step {
                scenario: scenario.to_owned(),
                step: step.parse().unwrap(),
                line: rest.to_owned(),
                out: tail,
            }
        })
        .collect()
}

pub fn steps_of(name: &str) -> Vec<Step> {
    steps().into_iter().filter(|s| s.scenario == name).collect()
}

/// The scenarios of a script, in order: name, `from=` (if any) and op lines.
pub fn script(text: &str) -> Vec<(String, Option<String>, Vec<String>)> {
    let mut out: Vec<(String, Option<String>, Vec<String>)> = Vec::new();
    for l in text.lines() {
        if let Some(rest) = l.strip_prefix("scenario ") {
            let mut f = rest.split(' ');
            let name = f.next().unwrap().to_owned();
            let from = f
                .next()
                .and_then(|x| x.strip_prefix("from="))
                .map(str::to_owned);
            out.push((name, from, Vec::new()));
        } else if !l.starts_with('#') && !l.trim().is_empty() {
            out.last_mut()
                .expect("op before any scenario")
                .2
                .push(l.to_owned());
        }
    }
    out
}

/// key=value arguments of an op line (the op itself excluded).
pub fn args(line: &str) -> (String, BTreeMap<String, String>) {
    let mut f = line.split(' ');
    let op = f.next().unwrap().to_owned();
    let kv = f
        .map(|a| match a.split_once('=') {
            Some((k, v)) => (k.to_owned(), v.to_owned()),
            None => (a.to_owned(), String::new()),
        })
        .collect();
    (op, kv)
}

// ------------------------------------------------------------------ harness crypto

/// What gen_store.c's `x_pbkdf2` does: PBKDF2-HMAC-SHA256, 16-byte salt; iteration 0 fails.
pub fn kek(pin: &[u8], salt: &[u8], iter: u32) -> Option<[u8; 32]> {
    let mut k = [0u8; 32];
    (iter != 0
        && openssl::pkcs5::pbkdf2_hmac(
            pin,
            salt,
            iter as usize,
            openssl::hash::MessageDigest::sha256(),
            &mut k,
        )
        .is_ok())
    .then_some(k)
}

pub fn gcm(
    enc: bool,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    input: &[u8],
    tag: &mut [u8; 16],
) -> Option<Vec<u8>> {
    let mode = if enc { Mode::Encrypt } else { Mode::Decrypt };
    let mut c = Crypter::new(Cipher::aes_256_gcm(), mode, key, Some(nonce)).ok()?;
    if !enc {
        c.set_tag(tag).ok()?;
    }
    c.aad_update(aad).ok()?;
    let mut out = vec![0u8; input.len() + 32];
    let mut n = c.update(input, &mut out).ok()?;
    n += c.finalize(&mut out[n..]).ok()?;
    out.truncate(n);
    if enc {
        c.get_tag(tag).ok()?;
    }
    Some(out)
}

/// The header serial as AAD: up to the first NUL in its 64 bytes.
pub fn serial_aad(h: &[u8]) -> &[u8] {
    let s = &h[72..136];
    &s[..s.iter().position(|&b| b == 0).unwrap_or(64)]
}

/// The DEK `role`'s PIN unwraps from a token file's header.
pub fn unwrap_dek(h: &[u8], role: Role, pin: &[u8]) -> Option<[u8; 32]> {
    let (salt, nonce, ct) = if role == Role::So {
        (140, 156, 168)
    } else {
        (216, 232, 244)
    };
    let iter = u32::from_le_bytes(h[136..140].try_into().unwrap());
    let k = kek(pin, &h[salt..salt + 16], iter)?;
    let mut tag: [u8; 16] = h[ct + 32..ct + 48].try_into().unwrap();
    let d = gcm(
        false,
        &k,
        &h[nonce..nonce + 12],
        serial_aad(h),
        &h[ct..ct + 32],
        &mut tag,
    )?;
    d.try_into().ok()
}

// ------------------------------------------------------------------ audit double

/// Records every audit event as `event/ROLE/rv/params`, rendered by the audit crate exactly as
/// gen_store.c reads C's log lines back. With `fail` set every event is refused, as an audit
/// log whose fsync fails refuses it (DIV-001).
#[derive(Default)]
pub struct Recorder {
    pub lines: Mutex<Vec<String>>,
    pub fail: AtomicBool,
}

impl Recorder {
    pub fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.lines.lock().unwrap())
    }
    pub fn set_fail(&self, on: bool) {
        self.fail.store(on, Ordering::SeqCst);
    }
}

pub fn render(e: &AuditEvent<'_>) -> String {
    let role = match e.role {
        Role::None => pqhsm_audit::record::Role::None,
        Role::So => pqhsm_audit::record::Role::So,
        Role::User => pqhsm_audit::record::Role::User,
    };
    format!(
        "{}/{}/{}/{}",
        pqhsm_audit::record::event_name(e.code),
        role.as_str(),
        e.rv.0,
        pqhsm_audit::record::render_params(e.params)
    )
}

/// The `Box<dyn Audit>` a `Platform` owns, forwarding to a shared [`Recorder`].
pub struct Rec(pub Arc<Recorder>);

impl Audit for Rec {
    fn event(&self, e: &AuditEvent<'_>) -> Result<(), Rv> {
        self.0.lines.lock().unwrap().push(render(e));
        if self.0.fail.load(Ordering::SeqCst) {
            Err(Rv::FUNCTION_FAILED)
        } else {
            Ok(())
        }
    }
}

/// The TPM stub of slice 1 (a copy of the legacy tests/tpm2-stub.sh).
pub fn tpm_stub() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/tpm/tpm2-stub.sh")
}

pub fn file_or_none(p: &Path) -> Option<Vec<u8>> {
    fs::read(p).ok()
}

// ------------------------------------------------------------------ Rust-only rows

/// A divergence no golden can show: C's side is undefined behaviour, or needs a failure the
/// generator's DRBG never produces. `c` says what C does, from the cited lines; `test` (in
/// `file`) checks `rust`. The scenario meta-tests hold this table to DIVERGENCES.md.
pub struct RustOnly {
    pub div: &'static str,
    pub file: &'static str,
    pub test: &'static str,
    /// `src/fhsm_token.c` lines this row covers.
    pub c_sites: &'static [u32],
    pub c: &'static str,
    pub rust: &'static str,
}

const RNG_C: &str = "rv=0x0: the fhsm_rng_bytes result is ignored and the buffer used as it was";
const RNG_RUST: &str =
    "every draw, failed in turn: rv=0x80000008 (the DRBG's), token file and memory unchanged";

pub const RUST_ONLY: &[RustOnly] = &[
    RustOnly {
        div: "DIV-025",
        file: "token_rng_ffi.rs",
        test: "every_draw_of_init_fails_the_call_div025",
        c_sites: &[1226, 1232, 1233, 1239, 1255],
        c: RNG_C,
        rust: "every draw, failed in turn: rv=0x80000008, no token file and no .tmp",
    },
    RustOnly {
        div: "DIV-025",
        file: "token_rng_ffi.rs",
        test: "every_draw_of_init_user_pin_fails_the_call_div025",
        c_sites: &[1724, 1725],
        c: RNG_C,
        rust: RNG_RUST,
    },
    RustOnly {
        div: "DIV-025",
        file: "token_rng_ffi.rs",
        test: "every_draw_of_set_pin_fails_the_call_div025",
        c_sites: &[1784, 1785],
        c: RNG_C,
        rust: RNG_RUST,
    },
    RustOnly {
        div: "DIV-025",
        file: "token_rng_ffi.rs",
        test: "every_draw_of_reinit_fails_the_call_div025",
        c_sites: &[1833, 1839, 1847, 1868],
        c: RNG_C,
        rust: RNG_RUST,
    },
    RustOnly {
        div: "DIV-025",
        file: "token_rng_ffi.rs",
        test: "every_draw_of_an_object_write_fails_the_call_div025",
        c_sites: &[1169],
        c: RNG_C,
        rust: RNG_RUST,
    },
    RustOnly {
        div: "DIV-027",
        file: "token_ffi.rs",
        test: "object_add_null_value_with_a_length_is_arguments_bad_div027",
        c_sites: &[1923, 1925, 659],
        c: "undefined: value_len is kept and the next write memcpys from NULL",
        rust: "rv=0x7, no object added, token file unchanged",
    },
    RustOnly {
        div: "DIV-028",
        file: "token_ffi.rs",
        test: "login_or_set_pin_with_an_unknown_role_is_arguments_bad_div028",
        c_sites: &[1395, 1397, 1413, 1414, 1415, 1525],
        c: "role 3 is checked against the user's wrap and counters, and recorded as logged in",
        rust: "rv=0x7 for login and set_pin, no failure counted, token file unchanged",
    },
    RustOnly {
        div: "DIV-029",
        file: "sealing_env_ffi.rs",
        test: "sealing_is_read_at_load_not_at_login_div029",
        c_sites: &[1275, 1510],
        c: "FHSM_TPM_SEALING re-read at every login: set under an open token, the next login is 0x30",
        rust: "read at init and load: the open token logs in (0x0), a token loaded after is 0x30",
    },
    RustOnly {
        div: "DIV-030",
        file: "store.rs",
        test: "constants_are_c_s",
        c_sites: &[233, 668, 712, 753, 850],
        c: "-DFHSM_MAX_OBJECTS=N sets the store's capacity",
        rust: "1024 always; the make variable no longer reaches the token store",
    },
    RustOnly {
        div: "DIV-031",
        file: "token_props.rs",
        test: "a_link_planted_at_the_tmp_name_is_not_written_through_div031",
        c_sites: &[1185],
        c: "a link at <path>.tmp is written through and renamed over the token",
        rust: "the link is removed, the tmp created O_EXCL|O_NOFOLLOW, the link's target untouched",
    },
];
