//! Shared helpers for the pqhsm-pki characterization tests. Every expected value is in
//! `golden/rev/`, produced by running the legacy C code: `legacy/hybrid/golden/regen_rev.sh`.
#![allow(dead_code)]

#[cfg(feature = "ffi")]
pub mod c_doubles;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use pqhsm_pki::revocation::{Db, Entry, RevError, Single, Tbs};

pub fn golden(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/rev")
        .join(rel)
}

pub fn golden_bytes(rel: &str) -> Vec<u8> {
    fs::read(golden(rel)).unwrap_or_else(|e| panic!("golden/rev/{rel}: {e} (run regen_rev.sh)"))
}

/// `der/NAME.der`: an invented certificate or OCSP request.
pub fn der(name: &str) -> Vec<u8> {
    golden_bytes(&format!("der/{name}.der"))
}

/// One row of `cases.tsv`: case, op, rv, then key=value columns.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub op: String,
    pub rv: String,
    kv: BTreeMap<String, String>,
}

impl Case {
    pub fn get(&self, k: &str) -> &str {
        self.opt(k)
            .unwrap_or_else(|| panic!("{}: no `{k}` column", self.name))
    }
    pub fn opt(&self, k: &str) -> Option<&str> {
        self.kv.get(k).map(String::as_str)
    }
    pub fn is(&self, k: &str, v: &str) -> bool {
        self.opt(k) == Some(v)
    }
    pub fn num<T: std::str::FromStr>(&self, k: &str) -> T {
        self.get(k)
            .parse()
            .unwrap_or_else(|_| panic!("{}: `{k}` is not a number", self.name))
    }
    pub fn rv_i(&self) -> i64 {
        self.rv.parse().unwrap()
    }
    /// An escaped column, unescaped to C's bytes.
    pub fn bytes(&self, k: &str) -> Vec<u8> {
        unesc(self.get(k))
    }
    /// An escaped column as text (the columns that hold C strings are ASCII here).
    pub fn text(&self, k: &str) -> String {
        String::from_utf8(self.bytes(k)).unwrap()
    }
}

pub fn cases() -> Vec<Case> {
    let text = fs::read_to_string(golden("cases.tsv"))
        .unwrap_or_else(|e| panic!("golden/rev/cases.tsv: {e} (run regen_rev.sh)"));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let mut f = l.split('\t');
            let (name, op, rv) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
            let kv = f
                .map(|c| {
                    let (k, v) = c.split_once('=').unwrap();
                    (k.to_owned(), v.to_owned())
                })
                .collect();
            Case {
                name: name.into(),
                op: op.into(),
                rv: rv.into(),
                kv,
            }
        })
        .collect()
}

pub fn case(name: &str) -> Case {
    cases()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no golden row {name}"))
}

pub fn cases_of(op: &str) -> Vec<Case> {
    cases().into_iter().filter(|c| c.op == op).collect()
}

/// gen_rev.c `kvs`: `\\`, `\t`, `\n`, `\r`, `\xHH`.
pub fn unesc(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        match b[i + 1] {
            b'\\' => out.push(b'\\'),
            b't' => out.push(b'\t'),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b'x' => {
                out.push(u8::from_str_radix(&s[i + 2..i + 4], 16).unwrap());
                i += 2;
            }
            c => panic!("bad escape \\{}", c as char),
        }
        i += 2;
    }
    out
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// C's diagnostics name the generator's work dir as `{dir}`; ours name a temp dir.
pub fn norm(msg: &str, dir: &Path) -> String {
    msg.replace(dir.to_str().unwrap(), "{dir}")
}

/// The `now` every answer row was made at (gen_rev.c pins `time()` to it).
pub fn now() -> i64 {
    case("c_struct_layout").num("now")
}

/// `RevError` as a row prints it.
pub fn rv_of<T>(r: &Result<T, RevError>) -> i64 {
    match r {
        Ok(_) => 0,
        Err(e) => e.code.into(),
    }
}

// ---------------------------------------------------------------------------------------
// Databases
// ---------------------------------------------------------------------------------------

/// gen_rev.c `kventries`: `serialhex/date/reason,...`.
pub fn entries_text(d: &Db) -> String {
    d.entries
        .iter()
        .map(|e| {
            format!(
                "{}/{}/{}",
                hex(&e.serial),
                String::from_utf8_lossy(&e.date),
                e.reason
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The reverse of [`entries_text`]: C's view of a database, built without any Rust code.
pub fn db_from_entries(crl_number: u64, text: &str) -> Db {
    let entries = text
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let mut f = s.split('/');
            Entry {
                serial: unhex(f.next().unwrap()),
                date: f.next().unwrap().as_bytes().to_vec(),
                reason: f.next().unwrap().parse().unwrap(),
            }
        })
        .collect();
    Db {
        crl_number,
        entries,
    }
}

/// gen_rev.c `build`: `crl=N;e=SERIAL,DATE,REASON;...`, unvalidated, as a caller of add can.
pub fn db_from_spec(spec: &str) -> Db {
    let mut d = Db::default();
    for tok in spec.split(';').filter(|t| !t.is_empty()) {
        if let Some(n) = tok.strip_prefix("crl=") {
            d.crl_number = n.parse().unwrap();
            continue;
        }
        let mut f = tok.strip_prefix("e=").unwrap().split(',');
        d.entries.push(Entry {
            serial: unhex(f.next().unwrap()),
            date: f.next().unwrap().as_bytes().to_vec(),
            reason: f.next().unwrap().parse().unwrap(),
        });
    }
    d
}

/// The database every answer row without a `db` column used: C's own load of db/ocsp.db.
pub fn ocsp_db() -> Db {
    let c = case("load_ocsp");
    db_from_entries(c.num("crl_number"), c.get("entries"))
}

/// Rebuild a load row's input in `dir` (gen_rev.c `load_at`) and return the path to load.
pub fn load_input(dir: &Path, file: &str) -> PathBuf {
    match file {
        "missing" => dir.join("missing.db"),
        "dir" => {
            let p = dir.join("dir.db");
            fs::create_dir(&p).unwrap();
            p
        }
        "unreadable" => {
            let p = dir.join("unreadable.db");
            fs::write(&p, b"A1 20260101000000Z -\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
            p
        }
        "notdir" => {
            fs::write(dir.join("afile"), b"").unwrap();
            dir.join("afile/x.db")
        }
        f if f.starts_with("gen:") => {
            let n: usize = f[4..].parse().unwrap();
            let p = dir.join("gen.db");
            let mut s = String::with_capacity(n * 30);
            for i in 0..n {
                s.push_str(&format!("{i:08X} 20260101000000Z -\n"));
            }
            fs::write(&p, s).unwrap();
            p
        }
        f => {
            let base = f.rsplit('/').next().unwrap();
            let p = dir.join(base);
            fs::write(&p, golden_bytes(f)).unwrap();
            p
        }
    }
}

/// gen_rev.c `mk_long`: an absolute path of exactly `len` bytes under `dir`, its directories
/// created: "/" + 200 'd's per level, then "/" + 'f's.
pub fn long_path(dir: &Path, len: usize) -> PathBuf {
    let mut p = dir.to_str().unwrap().to_owned();
    while len - p.len() > 1 + 200 + 1 + 1 {
        p.push('/');
        p.push_str(&"d".repeat(200));
        fs::create_dir(&p).unwrap();
    }
    p.push('/');
    let rest = len - p.len();
    p.push_str(&"f".repeat(rest));
    assert_eq!(p.len(), len);
    PathBuf::from(p)
}

/// gen_rev.c `kvstate`: absent | symlink:TARGET | dir | file:MODE:HEX.
pub fn state(path: &Path, dir: &Path) -> String {
    let Ok(m) = fs::symlink_metadata(path) else {
        return "absent".into();
    };
    if m.file_type().is_symlink() {
        let t = fs::read_link(path).unwrap();
        return format!("symlink:{}", norm(t.to_str().unwrap(), dir));
    }
    if m.is_dir() {
        return "dir".into();
    }
    let b = fs::read(path).unwrap_or_default();
    format!("file:{:04o}:{}", m.permissions().mode() & 0o7777, hex(&b))
}

/// The paragraph every "Nothing was read" diagnostic ends with, taken from a C row.
pub fn db_bad(path_in_msg: &str, line: u32, why: &str) -> String {
    let c = case("load_date_14_no_z");
    let err = c.text("err");
    let tail = &err[err.find('\n').unwrap()..];
    format!("{path_in_msg} line {line}: {why}{tail}")
}

/// True when this process can read a mode-000 file (root with CAP_DAC_OVERRIDE). The
/// "unreadable" and "read-only dir" goldens were made without that capability.
pub fn privileged() -> bool {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("probe");
    fs::write(&p, b"x").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
    fs::read(&p).is_ok()
}

pub fn require_unprivileged(case: &str) {
    assert!(
        !privileged(),
        "{case}: this process can read a mode-000 file, so it cannot reproduce the golden. \
         Run the container with --cap-drop=DAC_OVERRIDE,DAC_READ_SEARCH (tests/README.md)."
    );
}

/// The rows whose input needs an unprivileged process.
pub fn needs_unprivileged(c: &Case) -> bool {
    c.is("file", "unreadable") || c.is("target", "ro_dir")
}

/// save rows create files; C ran under umask 022 (gen_rev.c main).
pub fn umask_022() {
    // SAFETY: umask has no memory effects; every test that sets it sets the same value.
    unsafe {
        libc::umask(0o022);
    }
}

// ---------------------------------------------------------------------------------------
// OCSP
// ---------------------------------------------------------------------------------------

/// DER GeneralizedTime of a `YYYYMMDDHHMMSSZ` string.
pub fn gt(s: &str) -> Vec<u8> {
    let mut v = vec![0x18, s.len() as u8];
    v.extend_from_slice(s.as_bytes());
    v
}

fn opt_hex(b: Option<&[u8]>) -> String {
    b.map_or("-".into(), hex)
}

/// What the encoder was given, in the line format of gen_rev.c's `ocsp/CASE.enc`, from the
/// `responder` line to the last `single` (the signer lines are the C ABI's). Empty `exts` is
/// written `-`, as C passes NULL for it.
pub fn enc_text(t: &Tbs<'_>) -> String {
    let mut s = format!(
        "responder {}\nproduced_at {}\ncap {}\nexts {}\n",
        hex(t.responder),
        hex(t.produced_at),
        t.cap,
        opt_hex((!t.exts.is_empty()).then_some(t.exts)),
    );
    for one in t.singles {
        s += &single_line(one, t.this_update, t.next_update);
    }
    s
}

pub fn single_line(one: &Single, this: &[u8], next: &[u8]) -> String {
    format!(
        "single {} {} {} {} {} {}\n",
        hex(&one.cert_id),
        one.status,
        opt_hex(one.revoked_at.as_deref()),
        one.reason,
        hex(this),
        hex(next)
    )
}

/// A row's `ocsp/CASE.enc`, or None when C never reached the encoder.
pub fn golden_enc(name: &str) -> Option<String> {
    fs::read_to_string(golden(&format!("ocsp/{name}.enc"))).ok()
}

/// The `.enc` lines [`enc_text`] produces.
pub fn enc_body(enc: &str) -> String {
    enc.lines()
        .filter(|l| {
            ["responder ", "produced_at ", "cap ", "exts ", "single "]
                .iter()
                .any(|p| l.starts_with(p))
        })
        .map(|l| format!("{l}\n"))
        .collect()
}

/// The encoder's `fhsm_rv_t` as C recorded it.
pub fn enc_rv(enc: &str) -> u32 {
    let v = enc.lines().find_map(|l| l.strip_prefix("rv 0x")).unwrap();
    u32::from_str_radix(v, 16).unwrap()
}

/// gen_rev.c `pattern`: the synthetic BasicOCSPResponse of the wrap rows.
pub fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + 3) as u8).collect()
}

/// A row's `stats` column: asked,ours,revoked,unknown,nonce_echoed.
pub fn stats_text(s: &pqhsm_pki::revocation::Stats) -> String {
    format!(
        "{},{},{},{},{}",
        s.asked, s.ours, s.revoked, s.unknown, s.nonce_echoed as i32
    )
}

/// The certificates and requests an answer row ran with.
pub struct AnswerInputs {
    pub req: Vec<u8>,
    pub ca: Vec<u8>,
    pub responder: Vec<u8>,
    pub db: Db,
    pub days: i32,
    pub label: Option<String>,
}

pub fn answer_inputs(c: &Case) -> AnswerInputs {
    AnswerInputs {
        req: der(c.get("req")),
        ca: der(c.opt("ca").unwrap_or("ca")),
        responder: der(c.opt("responder").unwrap_or("resp_ocsp")),
        db: c.opt("db").map_or_else(ocsp_db, db_from_spec),
        days: c.opt("days").map_or(7, |d| d.parse().unwrap()),
        label: c.opt("label").map(|_| c.text("label")),
    }
}

/// DIV-019 to DIV-021 (DECIDED, Fix 2026-10-31): input C read wrongly but returned OK for, or
/// refused at the wrong line, is now refused whole. (case, C's rv, C's entries, Rust's rv, the
/// line Rust names, Rust's reason; line 0 means the EIO text "cannot read PATH: REASON")
pub const DIV_LOAD_REFUSED: &[(&str, &str, &str, i64, u32, &str)] = &[
    // DIV-019: a CR anywhere but before the LF
    (
        "load_cr_only",
        "0",
        "",
        3,
        1,
        "carriage return inside a line",
    ),
    (
        "load_cr_only_entries",
        "0",
        "a1/20260101000000Z/-1",
        3,
        1,
        "carriage return inside a line",
    ),
    (
        "load_embedded_cr",
        "0",
        "a1/20260101000000Z/-1",
        3,
        1,
        "carriage return inside a line",
    ),
    // DIV-020: fgets split a line over 510 bytes and parsed its tail
    (
        "load_long_comment",
        "3",
        "",
        3,
        1,
        "line is longer than 510 bytes",
    ),
    (
        "load_long_comment_revives_an_entry",
        "0",
        "a1/20260101000000Z/1",
        3,
        1,
        "line is longer than 510 bytes",
    ),
    (
        "load_long_entry_line",
        "0",
        "a1/20260101000000Z/1",
        3,
        1,
        "line is longer than 510 bytes",
    ),
    // DIV-021: a read error was end of file
    (
        "load_directory_reads_as_empty",
        "0",
        "",
        2,
        0,
        "Is a directory",
    ),
];
