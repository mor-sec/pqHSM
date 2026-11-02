//! `chain`: chain head and record MAC (RULE-007). Expected values come from C-written logs.

mod common;

use common::{KEY, field_hex, hex, lines, read_golden, unhex};
use pqhsm_audit::chain::{INIT_LABEL, chain_head, mac};

#[test]
fn init_label_is_21_bytes_without_nul() {
    // RULE-007: the length was once 20, cutting the final '0'
    assert_eq!(INIT_LABEL, b"FHSM-AUDIT-INIT|seq=0");
    assert_eq!(INIT_LABEL.len(), 21);
}

#[test]
fn chain_head_of_test_key_is_the_baseline_fixture_first_prev_hmac() {
    // RULE-007: analysis/pqHSM/baseline/audit.log.000001, written by the C module
    let fixture = read_golden("baseline/audit.log.000001");
    let key_hex = String::from_utf8(read_golden("baseline/TEST_KEY_HEX")).unwrap();
    assert_eq!(unhex(key_hex.trim()), KEY);
    assert_eq!(
        hex(&chain_head(&KEY).unwrap()),
        field_hex(lines(&fixture)[0], "prev_hmac")
    );
}

#[test]
fn chain_head_literal_for_test_key() {
    // RULE-007: value printed by the C module (every golden log's first prev_hmac)
    assert_eq!(
        hex(&chain_head(&KEY).unwrap()),
        "98baf27df823f03e90c267d0a8c12351e5c00f4a5a2357c9e0398c16beffbee2"
    );
}

#[test]
fn chain_head_is_the_mac_of_the_init_label() {
    // RULE-007
    assert_eq!(chain_head(&KEY).unwrap(), mac(&KEY, INIT_LABEL).unwrap());
}

#[test]
fn chain_head_for_16_and_64_byte_keys_matches_c() {
    // RULE-007: C accepts 1..64-byte keys; the head is the same HMAC under that key
    for (file, len) in [("verify/key16.log", 16u8), ("verify/key64.log", 64)] {
        let log = read_golden(file);
        let key: Vec<u8> = (0..len).collect();
        assert_eq!(
            hex(&chain_head(&key).unwrap()),
            field_hex(lines(&log)[0], "prev_hmac"),
            "{file}"
        );
    }
}

#[test]
fn record_mac_covers_bytes_before_hmac_field_and_links_to_next_line() {
    // RULE-007: hmac(N) = HMAC(key, line N up to "hmac":"), prev_hmac(N+1) = hmac(N)
    let log = read_golden("baseline/audit.log.000001");
    let ls = lines(&log);
    for (i, line) in ls.iter().enumerate() {
        let body = &line[..common::find(line, b"\"hmac\":\"").unwrap()];
        let m = hex(&mac(&KEY, body).unwrap());
        assert_eq!(m, field_hex(line, "hmac"), "line {}", i + 1);
        if let Some(next) = ls.get(i + 1) {
            assert_eq!(m, field_hex(next, "prev_hmac"), "line {}", i + 2);
        }
    }
}
