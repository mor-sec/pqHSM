//! The core format-equivalence proof (RULE-007, RULE-027): lines written by the C module are
//! reproduced byte for byte from the same inputs. `golden/lines/*.log` were written by
//! `fhsm_audit_event` under the test key; `*.tsv` holds the inputs of each record. `seq` and
//! `ts` are taken from the C line; everything else is rendered by Rust.

mod common;

use common::{KEY, field_num, manifest, normalise, read_golden};
use pqhsm_audit::chain;
use pqhsm_audit::log::{AuditLog, Event};
use pqhsm_audit::record::{Fields, finish_line, render_body, render_params, sanitize_actor};
use pqhsm_audit::verify::{self, VerifyError};

/// Render every manifest record against the C log, walking the C bytes with a cursor (a C
/// record may contain a raw newline, so the log cannot be split on `\n` first).
fn assert_reproduces(name: &str) {
    let c_log = read_golden(&format!("lines/{name}.log"));
    let events = manifest(&format!("lines/{name}.tsv"));
    let mut prev = chain::chain_head(&KEY).unwrap();
    let mut at = 0;
    for (i, ev) in events.iter().enumerate() {
        let rest = &c_log[at..];
        let actor = sanitize_actor(ev.actor.as_deref());
        let params = render_params(&ev.pair_refs());
        if has_unsafe_key(ev) {
            // DIV-006: C wrote the key raw; Rust writes INVALID. Resync on C's record so every
            // other record is still compared byte for byte against C.
            assert_eq!(params, DIV006_PARAMS, "{name}: record {} (DIV-006)", i + 1);
            let h = pos(rest, b"\"hmac\":\"").expect("C record has an hmac field") + 8;
            prev = hex32(&rest[h..h + 64]);
            at += h + 64 + 3; // `"}\n`
            continue;
        }
        let f = Fields {
            seq: field_num(rest, "seq") as u64,
            ts_ns: field_num(rest, "ts") as i64,
            event: ev.code,
            slot: ev.slot,
            session: ev.session,
            role: ev.role,
            actor: &actor,
            rv: ev.rv,
            params: &params,
            prev_hmac: &prev,
        };
        let body = render_body(&f).unwrap();
        let mac = chain::mac(&KEY, body.as_bytes()).unwrap();
        let line = finish_line(&body, &mac).unwrap();
        let n = line.len().min(rest.len());
        assert_eq!(
            String::from_utf8_lossy(&rest[..n]),
            line,
            "{name}: record {} differs from the C line",
            i + 1
        );
        at += line.len();
        prev = mac;
    }
    assert_eq!(
        at,
        c_log.len(),
        "{name}: the C log has bytes after the last record"
    );
}

/// What a single pair with an unsafe key renders as under DIV-006.
const DIV006_PARAMS: &str = r#"{"INVALID":"INVALID"}"#;

/// The C safe-ASCII test, local so the test does not depend on the code under test.
fn has_unsafe_key(ev: &common::ManifestEvent) -> bool {
    let unsafe_key = ev.pairs.iter().any(|(k, _)| {
        k.iter()
            .any(|&c| !(0x20..=0x7e).contains(&c) || c == b'"' || c == b'\\')
    });
    if unsafe_key {
        assert_eq!(
            ev.pairs.len(),
            1,
            "DIV-006 golden records carry exactly one pair"
        );
    }
    unsafe_key
}

fn pos(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn hex32(hex: &[u8]) -> [u8; 32] {
    let s = std::str::from_utf8(hex).unwrap();
    std::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

/// The normalised C log with each DIV-006 record's params replaced by the Rust rendering.
/// Only for logs whose records are one physical line each (`lines`).
fn c_log_under_div006(name: &str) -> Vec<u8> {
    let c = normalise(&read_golden(&format!("lines/{name}.log")));
    let events = manifest(&format!("lines/{name}.tsv"));
    let recs = common::lines(&c);
    assert_eq!(recs.len(), events.len());
    let mut out = Vec::new();
    for (rec, ev) in recs.into_iter().zip(&events) {
        if has_unsafe_key(ev) {
            let s = pos(rec, b"\"params\":").unwrap() + 9;
            let e = pos(rec, b",\"prev_hmac\":").unwrap();
            out.extend_from_slice(&rec[..s]);
            out.extend_from_slice(DIV006_PARAMS.as_bytes());
            out.extend_from_slice(&rec[e..]);
        } else {
            out.extend_from_slice(rec);
        }
        out.push(b'\n');
    }
    out
}

#[test]
fn every_c_line_is_reproduced_byte_for_byte() {
    // RULE-007, RULE-027: event codes, roles, rv, slot/session, actor, params edge cases
    // (records 82-86 and 96 have unsafe keys: DIV-006, checked against the Rust rendering)
    assert_reproduces("lines");
}

#[test]
fn c_splits_a_record_on_a_newline_key_and_rust_does_not_div006() {
    // DIV-006: C writes the key raw, newline included; Rust writes INVALID
    assert_reproduces("newline_key");
    let c_log = read_golden("lines/newline_key.log");
    assert_eq!(
        common::lines(&c_log).len(),
        3,
        "C: two records, three physical lines"
    );
}

#[test]
fn crafted_fixed_ts_lines_match_c_hmacs() {
    // RULE-007: bodies with fixed ts, MACed by the C module's fhsm_hmac
    let c_log = read_golden("verify/craft_fixed_ts.log");
    let mut prev = chain::chain_head(&KEY).unwrap();
    let mut out = String::new();
    for seq in 1..=3 {
        let f = Fields {
            seq,
            ts_ns: 1_700_000_000_000_000_000,
            event: 42,
            slot: 0,
            session: 1,
            role: pqhsm_audit::record::Role::User,
            actor: "",
            rv: 0,
            params: "{}",
            prev_hmac: &prev,
        };
        let body = render_body(&f).unwrap();
        prev = chain::mac(&KEY, body.as_bytes()).unwrap();
        out += &finish_line(&body, &prev).unwrap();
    }
    assert_eq!(out, String::from_utf8(c_log).unwrap());
}

/// Append the manifest through `AuditLog` and return the file it wrote.
fn append_manifest(name: &str) -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let log = AuditLog::open(&dir.path().join("audit.log"), &KEY).unwrap();
    let path = log.path().to_path_buf();
    let events = manifest(&format!("lines/{name}.tsv"));
    for ev in &events {
        let pairs = ev.pair_refs();
        log.append(&Event {
            code: ev.code,
            slot: ev.slot,
            session: ev.session,
            role: ev.role,
            rv: ev.rv,
            actor: ev.actor.as_deref(),
            params: &pairs,
        })
        .unwrap();
    }
    drop(log);
    std::fs::read(path).unwrap()
}

#[test]
fn append_writes_the_c_lines_except_ts_and_macs() {
    // RULE-007, RULE-027 (ts differs by construction; MACs depend on it), DIV-006
    let ours = append_manifest("lines");
    assert_eq!(
        String::from_utf8_lossy(&normalise(&ours)),
        String::from_utf8_lossy(&c_log_under_div006("lines"))
    );
}

#[test]
fn append_newline_key_writes_one_line_per_record_and_verifies_div006() {
    // DIV-006: where C splits record 1 over two lines, Rust writes INVALID and the log verifies
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("newline_key.log");
    std::fs::write(&path, append_manifest("newline_key")).unwrap();
    let ours = std::fs::read(&path).unwrap();
    let ours_lines = common::lines(&ours);
    assert_eq!(ours_lines.len(), 2);
    assert!(
        pos(
            ours_lines[0],
            format!("\"params\":{DIV006_PARAMS},").as_bytes()
        )
        .is_some()
    );
    let c = read_golden("lines/newline_key.log");
    assert_eq!(
        normalise(ours_lines[1]),
        normalise(common::lines(&c)[2]),
        "record 2 as C wrote it"
    );
    assert_eq!(verify::verify_file(&path, &KEY), Ok(()));
}

#[test]
fn a_record_with_a_param_named_hmac_breaks_verification_as_in_c() {
    // RULE-008: the first "hmac":" is inside params, so the MAC'd prefix is cut short.
    // C fhsm_audit_verify on lines.log: SIGNATURE_INVALID at line 87 (golden/verify/expected.tsv)
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("ours.log");
    std::fs::write(&p, append_manifest("lines")).unwrap();
    assert_eq!(
        verify::verify_file(&p, &KEY),
        Err(VerifyError::Broken { line: 87 })
    );
}
