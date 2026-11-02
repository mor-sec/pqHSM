//! `verify::verify_file` against what C `fhsm_audit_verify` returned (RULE-008, module side).
//! Expected values: `golden/verify/expected.tsv` (rv and `broken_at_line` printed by C).
//! The tampered logs are mutations of `chain.log`, a 6-record log written by the C module.

mod common;

use common::{golden, key_by_label, tsv};
use pqhsm_audit::verify::{VerifyError, verify_file};

/// What C returned for `file` under `key`, as the Rust result type.
fn c_result(file: &str, key: &str) -> Result<(), VerifyError> {
    let rows = tsv("verify/expected.tsv");
    let row = rows
        .iter()
        .find(|r| r[0] == file && r[1] == key)
        .unwrap_or_else(|| panic!("no golden row for {file} / {key}"));
    match row[2].as_str() {
        "0x0" => Ok(()),
        "0xc0" => Err(VerifyError::Broken {
            line: row[3].parse().unwrap(),
        }),
        "0x6" => Err(VerifyError::Open),
        "0x7" => Err(VerifyError::ArgumentsBad),
        rv => panic!("unmapped C rv {rv}"),
    }
}

/// DIV-008: logs C accepted that the Rust verifier breaks, and the line it stops at. Each line
/// must end with its MAC in lowercase and `"}`.
const DIV008: &[(&str, usize)] = &[
    ("crlf.log", 1),
    ("hmac_uppercase_all.log", 1),
    ("trailer_altered_line3.log", 3),
];

fn check(file: &str, key: &str) {
    let mut expected = c_result(file, key);
    if let Some(&(_, line)) = DIV008.iter().find(|(f, _)| *f == file) {
        assert_eq!(expected, Ok(()), "{file}: C accepted it");
        expected = Err(VerifyError::Broken { line });
    }
    assert_eq!(
        verify_file(&golden(&format!("verify/{file}")), &key_by_label(key)),
        expected,
        "{file} / {key}"
    );
}

macro_rules! verify_case {
    ($($name:ident: $file:literal, $key:literal, $why:literal;)*) => {$(
        #[test]
        fn $name() {
            // RULE-008
            let _ = $why;
            check($file, $key);
        }
    )*};
}

verify_case! {
    intact_c_log_verifies: "chain.log", "test32", "OK";
    body_byte_flipped_is_broken_at_that_line: "body_flip_line3.log", "test32", "broken 3";
    mac_hex_digit_flipped_is_broken_at_that_line: "mac_flip_line3.log", "test32", "broken 3";
    deleted_line_is_broken_where_the_gap_is: "line3_deleted.log", "test32", "broken 3";
    swapped_lines_are_broken_at_the_first: "lines3_4_swapped.log", "test32", "broken 3";
    renumbered_seq_is_broken_at_that_line: "seq_renumbered_line3.log", "test32", "broken 3";
    uppercase_recorded_hmac_hex_is_broken_div008: "hmac_uppercase_all.log", "test32", "C: OK, unhex32 accepts A-F";
    uppercase_prev_hmac_changes_the_maced_body: "prev_hmac_uppercase_line2.log", "test32", "broken 2";
    missing_seq_field_is_broken: "field_missing_seq_line2.log", "test32", "broken 2";
    missing_hmac_field_is_broken: "field_missing_hmac_line4.log", "test32", "broken 4";
    hmac_with_63_hex_digits_is_broken: "hmac_63_hex_line5.log", "test32", "broken 5";
    line_longer_than_4095_bytes_is_broken_at_its_first_fgets_chunk: "long_line_appended.log", "test32", "broken 7";
    empty_file_verifies: "empty.log", "test32", "OK";
    missing_final_newline_still_verifies: "no_final_newline.log", "test32", "OK";
    crlf_line_endings_are_broken_div008: "crlf.log", "test32", "C: OK, \\r is after the hmac";
    tail_truncation_is_not_detected: "tail_truncated.log", "test32", "OK: documented limit";
    duplicated_line_is_broken_at_the_copy: "line3_duplicated.log", "test32", "broken 4";
    blank_line_is_broken: "blank_line_inserted_before_3.log", "test32", "broken 3";
    nul_byte_in_body_hides_the_rest_of_the_line: "nul_in_body_line3.log", "test32", "broken 3";
    bytes_after_the_hmac_hex_are_broken_div008: "trailer_altered_line3.log", "test32", "C: OK, not checked";
    plus_sign_in_hmac_hex_is_refused_by_the_module: "hmac_plus_sign.log", "test32", "broken; the CLI accepts it";
    c_log_with_param_named_hmac_is_broken_at_that_record: "lines.log", "test32", "broken 87";
    newline_in_param_key_breaks_the_record: "newline_key.log", "test32", "broken 1";
    seq_with_leading_zeros_verifies: "craft_seq_leading_zeros.log", "test32", "OK: strtoull";
    seq_with_plus_sign_or_leading_space_verifies: "craft_seq_sign_and_space.log", "test32", "OK: strtoull";
    seq_with_trailing_junk_verifies: "craft_seq_trailing_junk.log", "test32", "OK: strtoull stops at junk";
    only_seq_prev_hmac_and_hmac_are_required: "craft_minimal_fields.log", "test32", "OK";
    uppercase_prev_hmac_inside_a_correctly_maced_body_verifies: "craft_prev_hmac_uppercase_in_body.log", "test32", "OK";
    crafted_fixed_ts_log_verifies: "craft_fixed_ts.log", "test32", "OK";
    wrong_key_is_broken_at_line_1: "chain.log", "wrong32", "broken 1";
    shorter_key_is_a_different_key: "chain.log", "test16", "broken 1";
    log_written_under_16_byte_key_verifies_under_it: "key16.log", "test16", "OK (DIV-003: verify still takes any length)";
    log_written_under_64_byte_key_verifies_under_it: "key64.log", "test64", "OK (DIV-003)";
    log_written_under_16_byte_key_fails_under_32_byte_key: "key16.log", "test32", "broken 1";
    log_written_under_64_byte_key_fails_under_32_byte_key: "key64.log", "test32", "broken 1";
    empty_key_is_arguments_bad: "chain.log", "empty", "ARGUMENTS_BAD";
    missing_file_is_open_error: "missing.log", "test32", "FUNCTION_FAILED";
}

#[test]
fn baseline_fixture_verifies() {
    // RULE-008: analysis/pqHSM/baseline/audit.log.000001; C returned rv 0x0 (baseline/expected.tsv)
    assert_eq!(tsv("baseline/expected.tsv")[0][2], "0x0");
    assert_eq!(
        verify_file(&golden("baseline/audit.log.000001"), &common::KEY),
        Ok(())
    );
}

#[test]
fn every_golden_row_is_covered_by_a_named_test() {
    // RULE-008: guard against a regen adding a row nobody asserts
    let src = include_str!("verify.rs");
    for row in tsv("verify/expected.tsv") {
        assert!(
            src.contains(&format!("\"{}\", \"{}\"", row[0], row[1])),
            "untested golden row {row:?}"
        );
    }
}

#[test]
fn nul_after_the_closing_brace_is_broken_div008() {
    // DIV-008: C stopped at the NUL, so `"}\0<anything>` verified
    let c = std::fs::read(golden("verify/chain.log")).unwrap();
    let at = c
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .nth(1)
        .unwrap()
        .0;
    let mut t = c[..at].to_vec();
    t.extend_from_slice(b"\0,\"result\":\"OK\"}");
    t.extend_from_slice(&c[at..]);
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("nul.log");
    std::fs::write(&p, t).unwrap();
    assert_eq!(
        verify_file(&p, &common::KEY),
        Err(VerifyError::Broken { line: 2 })
    );
}
