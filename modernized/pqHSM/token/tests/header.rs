//! The 317-byte token header (RULE-004, PHASE2_PLAN.md §5.2) against every header the legacy C
//! wrote: the gen_token.c corpus (`testdata/*.tok`) and every scenario's final token
//! (`golden/store/tok/*.tok`). The load verdicts on malformed headers are C's, from the
//! `header_*` and `iter_*` scenarios of `golden/store/steps.tsv`.
//!
//!   cargo test -p pqhsm-token --test header

mod store_common;

use std::fs;

use pqhsm_token::Rv;
use pqhsm_token::header::{Header, LEN, MAGIC, PBKDF2_ITER, VERSION};
use store_common::*;

fn c_headers() -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    for dir in [store_golden("tok"), corpus("")] {
        for e in fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "tok") {
                v.push((p.display().to_string(), fs::read(&p).unwrap()));
            }
        }
    }
    v.sort();
    assert!(
        v.len() > 100,
        "expected the corpus and the scenario tokens, found {}",
        v.len()
    );
    v
}

fn le(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// Not one of the scenarios that deliberately broke the header (they have their own tests).
fn well_formed(f: &[u8]) -> bool {
    f.len() >= LEN && f[..4] == MAGIC && le(f, 4) == 1 && le(f, 136) == 200_000
}

/// The C load verdict a header scenario recorded for its `load` step.
fn c_load_rv(scenario: &str) -> String {
    steps_of(scenario)
        .into_iter()
        .find(|s| s.line == "load")
        .expect("no load step")
        .out
}

#[test]
fn constants_are_c_s() {
    assert_eq!(
        (LEN, MAGIC, VERSION, PBKDF2_ITER),
        (317, *b"FHSM", 1, 200_000)
    );
}

#[test]
fn every_c_written_header_parses_field_by_field_at_c_s_offsets() {
    for (name, f) in c_headers() {
        if !well_formed(&f) {
            continue; // the header_* / iter_* scenarios' own tokens, covered below
        }
        let h = Header::parse(&f).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(&h.label[..], &f[8..72], "{name}: label");
        assert_eq!(&h.serial[..], &f[72..136], "{name}: serial");
        assert_eq!(h.pbkdf2_iter, le(&f, 136), "{name}");
        assert_eq!(&h.salt_so[..], &f[140..156], "{name}");
        assert_eq!(&h.so_wrap_nonce[..], &f[156..168], "{name}");
        assert_eq!(&h.so_wrap_ct[..], &f[168..216], "{name}");
        assert_eq!(&h.salt_user[..], &f[216..232], "{name}");
        assert_eq!(&h.user_wrap_nonce[..], &f[232..244], "{name}");
        assert_eq!(&h.user_wrap_ct[..], &f[244..292], "{name}");
        assert_eq!(h.user_initialized, f[292] != 0, "{name}");
        assert_eq!(
            (h.failed_so, h.failed_user),
            (le(&f, 293), le(&f, 297)),
            "{name}"
        );
    }
}

#[test]
fn to_bytes_rewrites_every_c_header_byte_for_byte() {
    for (name, f) in c_headers() {
        if !well_formed(&f) {
            continue;
        }
        let h = Header::parse(&f).unwrap();
        assert_eq!(&h.to_bytes()[..], &f[..LEN], "{name}");
    }
}

#[test]
fn c_always_writes_the_throttle_fields_as_zero() {
    for (name, f) in c_headers().into_iter().filter(|(_, f)| f.len() >= LEN) {
        assert!(f[301..317].iter().all(|&b| b == 0), "{name}");
    }
}

#[test]
fn bytes_past_317_are_ignored() {
    let f = read_golden("tok/multi_base.tok");
    assert!(f.len() > LEN);
    assert_eq!(
        Header::parse(&f).unwrap(),
        Header::parse(&f[..LEN]).unwrap()
    );
}

#[test]
fn a_short_file_a_bad_magic_or_a_version_other_than_1_is_function_failed() {
    let f = read_golden("tok/init_fresh.tok");
    assert_eq!(c_load_rv("header_316_bytes"), "\trv=0x6");
    assert_eq!(Header::parse(&f[..316]), Err(Rv::FUNCTION_FAILED));
    assert_eq!(Header::parse(&[]), Err(Rv::FUNCTION_FAILED));
    let mut g = f.clone();
    g[3] = b'N';
    assert_eq!(c_load_rv("header_bad_magic"), "\trv=0x6");
    assert_eq!(Header::parse(&g), Err(Rv::FUNCTION_FAILED));
    for (v, scen) in [(2u32, "header_version_2"), (0, "header_version_0")] {
        let mut g = f.clone();
        g[4..8].copy_from_slice(&v.to_le_bytes());
        assert_eq!(c_load_rv(scen), "\trv=0x6");
        assert_eq!(Header::parse(&g), Err(Rv::FUNCTION_FAILED), "version {v}");
    }
}

#[test]
fn any_non_zero_user_initialized_byte_reads_as_true_and_writes_back_as_1() {
    let mut f = read_golden("tok/user_base.tok");
    f[292] = 2;
    assert_eq!(c_load_rv("header_user_initialized_byte_2"), "\trv=0x0");
    let h = Header::parse(&f).unwrap();
    assert!(h.user_initialized);
    assert_eq!(h.to_bytes()[292], 1);
}

#[test]
fn throttle_bytes_on_disk_are_ignored_and_written_back_as_zero() {
    let mut f = read_golden("tok/user_base.tok");
    f[301..317].fill(0xff);
    assert_eq!(c_load_rv("header_throttle_bytes_ignored"), "\trv=0x0");
    let h = Header::parse(&f).unwrap();
    assert!(h.to_bytes()[301..317].iter().all(|&b| b == 0));
}

/// DIV-011: C loads any count (and PBKDF2 then refuses < 1000); Rust refuses all but 200000.
#[test]
fn a_pbkdf2_count_other_than_200000_is_refused_div011() {
    let f = read_golden("tok/user_base.tok");
    for (iter, scen) in [
        (1000u32, "iter_1000_div011"),
        (999, "iter_999_div011"),
        (0, "iter_0_div011"),
        (200_001, "iter_200001_div011"),
    ] {
        assert_eq!(c_load_rv(scen), "\trv=0x0", "C loaded {iter}");
        let mut g = f.clone();
        g[136..140].copy_from_slice(&iter.to_le_bytes());
        assert_eq!(Header::parse(&g), Err(Rv::FUNCTION_FAILED), "iter {iter}");
    }
}

#[test]
fn c_s_serial_is_fhsm_dash_16_hex_then_nul_padding() {
    for (name, f) in c_headers() {
        let s = &f[72..136];
        assert!(s.starts_with(b"FHSM-"), "{name}");
        assert!(
            s[5..21]
                .iter()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "{name}"
        );
        // header_serial_edited pokes one digit and still has the shape
        assert!(s[21..].iter().all(|&b| b == 0), "{name}");
    }
}
