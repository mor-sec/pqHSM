//! Shared helpers for the pqhsm-audit characterization tests. Golden files are produced by
//! running the legacy C code: see `tests-support/golden/regen.sh`.
#![allow(dead_code)]

use std::path::PathBuf;

use pqhsm_audit::record::Role;

/// The fixed, non-secret test key: bytes 0x00..=0x1f (`analysis/pqHSM/baseline/TEST_KEY_HEX`).
pub const KEY: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = i as u8;
        i += 1;
    }
    k
};
pub const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// Keys named in `golden/verify/expected.tsv`: prefixes of 0x00.. (or 0x01.. for `wrong32`).
pub fn key_by_label(label: &str) -> Vec<u8> {
    match label {
        "test32" => (0..32).collect(),
        "test16" => (0..16).collect(),
        "test64" => (0..64).collect(),
        "wrong32" => (1..33).collect(),
        "empty" => vec![],
        other => panic!("unknown key label {other}"),
    }
}

pub fn golden(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(rel)
}

pub fn read_golden(rel: &str) -> Vec<u8> {
    std::fs::read(golden(rel)).unwrap_or_else(|e| panic!("golden file {rel}: {e} (run regen.sh)"))
}

/// Rows of a golden TSV, without `#` comment lines.
pub fn tsv(rel: &str) -> Vec<Vec<String>> {
    String::from_utf8(read_golden(rel))
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| l.split('\t').map(str::to_owned).collect())
        .collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The decimal number right after the first `"name":` in `line`.
pub fn field_num(line: &[u8], name: &str) -> i128 {
    let needle = format!("\"{name}\":");
    let at =
        find(line, needle.as_bytes()).unwrap_or_else(|| panic!("no {name} field")) + needle.len();
    let end = line[at..]
        .iter()
        .position(|c| !(c.is_ascii_digit() || *c == b'-'))
        .unwrap()
        + at;
    std::str::from_utf8(&line[at..end])
        .unwrap()
        .parse()
        .unwrap()
}

/// The 64 hex characters after the first `"name":"` in `line`.
pub fn field_hex(line: &[u8], name: &str) -> String {
    let needle = format!("\"{name}\":\"");
    let at = find(line, needle.as_bytes()).unwrap() + needle.len();
    String::from_utf8(line[at..at + 64].to_vec()).unwrap()
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// One input row of `golden/lines/*.tsv`, as the C driver passed it to `fhsm_audit_event`.
pub struct ManifestEvent {
    pub code: u32,
    pub slot: i32,
    pub session: i32,
    pub role: Role,
    pub rv: u32,
    pub actor: Option<Vec<u8>>,
    pub pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

impl ManifestEvent {
    pub fn pair_refs(&self) -> Vec<(&[u8], &[u8])> {
        self.pairs
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect()
    }
}

pub fn manifest(rel: &str) -> Vec<ManifestEvent> {
    tsv(rel)
        .into_iter()
        .map(|r| ManifestEvent {
            code: r[0].parse().unwrap(),
            slot: r[1].parse().unwrap(),
            session: r[2].parse().unwrap(),
            role: match r[3].as_str() {
                "NONE" => Role::None,
                "SO" => Role::So,
                "USER" => Role::User,
                other => panic!("role {other}"),
            },
            rv: r[4].parse().unwrap(),
            actor: (r[5] != "-").then(|| unhex(&r[5])),
            pairs: if r[6] == "-" {
                vec![]
            } else {
                r[6].split(',')
                    .map(|p| {
                        let (k, v) = p.split_once(':').unwrap();
                        (unhex(k), unhex(v))
                    })
                    .collect()
            },
        })
        .collect()
}

/// A log with `ts` set to 0 and every 64-hex `prev_hmac`/`hmac` value zeroed, so two logs
/// written at different times can be compared byte for byte.
pub fn normalise(log: &[u8]) -> Vec<u8> {
    let mut out = log.to_vec();
    let mut i = 0;
    while i < out.len() {
        if out[i..].starts_with(b"\"ts\":") {
            let s = i + 5;
            let e = s + out[s..].iter().position(|c| !c.is_ascii_digit()).unwrap();
            out.splice(s..e, *b"0");
            i = s + 1;
            continue;
        }
        for needle in [&b"\"prev_hmac\":\""[..], &b"\"hmac\":\""[..]] {
            if out[i..].starts_with(needle) {
                let s = i + needle.len();
                if out.len() >= s + 64 && out[s..s + 64].iter().all(u8::is_ascii_hexdigit) {
                    out[s..s + 64].fill(b'0');
                }
            }
        }
        i += 1;
    }
    out
}

pub fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i64
}

/// Physical lines (fgets-style split on `\n`, each without its `\n`).
pub fn lines(b: &[u8]) -> Vec<&[u8]> {
    let mut v: Vec<&[u8]> = b.split(|c| *c == b'\n').collect();
    if v.last().is_some_and(|l| l.is_empty()) {
        v.pop();
    }
    v
}
