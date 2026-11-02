//! Replays `tests/golden/integrity.tsv`: what the legacy `src/fhsm_integrity.c` did with each
//! ELF file in `tests/golden/integrity/` (tests-support/golden/gen_integrity.c), through
//! `integrity::verify`. The C ran each scenario in its own process; its stderr is the
//! `.stderr` file beside the fixture.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use pqhsm_selftest::integrity::{self, DIGEST_LEN};

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden");

fn sha384(data: &[u8]) -> Option<[u8; DIGEST_LEN]> {
    let mut d = [0; DIGEST_LEN];
    (pqhsm_crypto::prim::digest(2, data, &mut d) == Ok(DIGEST_LEN)).then_some(d)
}

fn unhex(s: &str) -> [u8; DIGEST_LEN] {
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

struct Row {
    name: String,
    file: String,
    embedded: String,
    bypass: bool,
    calls: usize,
    result: HashMap<String, String>,
    rvs: Vec<u32>,
}

fn rows() -> Vec<Row> {
    let tsv = fs::read_to_string(format!("{GOLDEN}/integrity.tsv")).unwrap();
    tsv.lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let [name, input, result] = l.split('\t').collect::<Vec<_>>()[..] else {
                panic!("bad row {l}")
            };
            let [file, embedded, mode, calls] = input.split(':').collect::<Vec<_>>()[..] else {
                panic!("bad input {input}")
            };
            let mut rvs = Vec::new();
            let mut fields = HashMap::new();
            for kv in result.split(';') {
                let (k, v) = kv.split_once('=').unwrap();
                if k == "rv" {
                    rvs.push(u32::from_str_radix(v.trim_start_matches("0x"), 16).unwrap());
                } else {
                    fields.insert(k.to_owned(), v.to_owned());
                }
            }
            Row {
                name: name.into(),
                file: file.into(),
                embedded: embedded.into(),
                bypass: mode == "bypass",
                calls: calls.parse().unwrap(),
                result: fields,
                rvs,
            }
        })
        .collect()
}

#[test]
fn every_scenario_gives_what_the_c_gave() {
    let rows = rows();
    assert_eq!(rows.len(), 76);
    // "good": the digest the C computed for the file, from the scenario that ran before it
    let computed: HashMap<(&str, bool), [u8; DIGEST_LEN]> = rows
        .iter()
        .filter(|r| r.embedded == "wrong" && r.result["last"] != "-")
        .map(|r| ((r.file.as_str(), r.bypass), unhex(&r.result["last"])))
        .collect();
    for r in &rows {
        // the cached scenario's file is a copy of good.elf, removed after the first call
        let file = if r.name == "cached" {
            "integrity/good.elf"
        } else {
            &r.file
        };
        let embedded = match r.embedded.as_str() {
            "zero" => [0; DIGEST_LEN],
            "wrong" | "no-sha384" => [0x5a; DIGEST_LEN],
            "good" => computed[&(file, r.bypass)],
            e => panic!("{e}"),
        };
        let mut data = (r.file != "(not found)")
            .then(|| fs::read(Path::new(GOLDEN).join(file)).ok())
            .flatten();
        let report = integrity::verify(data.as_deref_mut(), &embedded, r.bypass, |d| {
            if r.embedded == "no-sha384" {
                None
            } else {
                sha384(d)
            }
        });
        let ctx = &r.name;
        // a second call returns the cached result (the C ABI's cache: tests/integrity_abi.rs)
        assert_eq!(vec![report.rv; r.calls], r.rvs, "{ctx}");
        let latch = if report.latched {
            "integrity check failed"
        } else {
            "-"
        };
        assert_eq!(latch, r.result["latch"], "{ctx}");
        let last: String = report.last.map_or("-".into(), |d| {
            d.iter().map(|b| format!("{b:02x}")).collect()
        });
        assert_eq!(last, r.result["last"], "{ctx}");
        let signed = embedded.iter().any(|&b| b != 0);
        assert_eq!(signed, r.result["signed"] == "1", "{ctx}");
        let stderr = fs::read_to_string(format!("{GOLDEN}/integrity/{ctx}.stderr")).unwrap();
        assert_eq!(report.stderr, stderr, "{ctx}");
        if let Some(d) = data {
            assert!(d.iter().all(|&b| b == 0), "{ctx}: the copy is wiped");
        }
    }
}

/// The section is found by name and bounds alone; each fixture breaks one bound.
#[test]
fn find_section_refuses_every_malformed_file() {
    let read = |f: &str| fs::read(format!("{GOLDEN}/integrity/{f}.elf")).unwrap();
    let find = |f: &str| integrity::find_section(&read(f), integrity::SECTION);
    let good = read("good");
    let r = integrity::find_section(&good, integrity::SECTION).unwrap();
    assert_eq!(
        (r.len(), &good[r.start..r.start + 2]),
        (48, &[0xa0, 0xa1][..])
    );
    assert_eq!(find("wide_section").unwrap().len(), 64);
    assert_eq!(find("short_section").unwrap().len(), 32);
    for f in [
        "no_section",
        "bad_magic",
        "elf32",
        "no_table",
        "bad_shentsize",
        "table_past_end",
        "shstrndx_out",
        "strtab_past_end",
        "name_past_strtab",
        "name_unterminated",
        "section_past_end",
        "tiny",
        "empty",
    ] {
        assert_eq!(find(f), None, "{f}");
    }
}
