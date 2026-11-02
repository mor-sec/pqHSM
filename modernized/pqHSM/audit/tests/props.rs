//! Property tests over both Rust verifiers: the module's `verify::verify_file` (RULE-008,
//! module side) and the auditor tool `pqhsm_audit_verify::verify_file` (RULE-008, tool side).
//!
//! Where C has blind spots the properties are scoped to what C rejects, and the blind spots
//! are pinned by golden tests instead (verify.rs, audit-verify/tests/cli.rs):
//! upper-case hmac hex and bytes after the hmac hex are not checked; truncating the last line
//! is undetectable; `+X` for `0X` in hmac hex is accepted by the tool only.

mod common;

use std::path::Path;

use common::{KEY, KEY_HEX, find, lines, read_golden};
use pqhsm_audit::log::{AuditLog, Event};
use pqhsm_audit::record::Role;
use pqhsm_audit::verify;
use proptest::prelude::*;

/// (module verifier accepted, tool exit code, tool stdout, tool stderr)
fn both(path: &Path) -> (bool, i32, String, String) {
    let module_ok = verify::verify_file(path, &KEY).is_ok();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = pqhsm_audit_verify::verify_file(path, KEY_HEX, &mut out, &mut err);
    (
        module_ok,
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

fn assert_both_reject(path: &Path) -> Result<(), TestCaseError> {
    let (module_ok, code, _, err) = both(path);
    prop_assert!(!module_ok, "module verifier accepted");
    prop_assert_eq!(code, 1, "tool exit code; stderr: {}", err);
    Ok(())
}

#[derive(Debug, Clone)]
struct Ev {
    code: u32,
    slot: i32,
    session: i32,
    role: Role,
    rv: u32,
    actor: Option<Vec<u8>>,
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
}

fn ev() -> impl Strategy<Value = Ev> {
    let code = prop_oneof![
        prop::sample::select(vec![1u32, 6, 12, 13, 42, 47, 83, 85]),
        any::<u32>()
    ];
    let role = prop::sample::select(vec![Role::None, Role::So, Role::User]);
    // Keys are safe and never "hmac"/"prev_hmac": C itself writes unverifiable lines for those
    // (golden: verify/lines.log record 87, newline_key.log).
    let key = "[a-z_]{0,8}".prop_filter("C-unverifiable key", |k| k != "hmac" && k != "prev_hmac");
    let value = prop::collection::vec(any::<u8>(), 0..40);
    let pairs = prop::collection::vec((key.prop_map(String::into_bytes), value), 0..4);
    let actor = prop::option::of(prop::collection::vec(any::<u8>(), 0..160));
    (
        code,
        any::<i32>(),
        any::<i32>(),
        role,
        any::<u32>(),
        actor,
        pairs,
    )
        .prop_map(|(code, slot, session, role, rv, actor, pairs)| Ev {
            code,
            slot,
            session,
            role,
            rv,
            actor,
            pairs,
        })
}

/// Write `evs` through `AuditLog` and return the dir (kept alive) and the file.
fn write_log(evs: &[Ev]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let log = AuditLog::open(&dir.path().join("audit.log"), &KEY).unwrap();
    for e in evs {
        let pairs: Vec<(&[u8], &[u8])> = e
            .pairs
            .iter()
            .map(|(k, v)| (k.as_slice(), v.as_slice()))
            .collect();
        log.append(&Event {
            code: e.code,
            slot: e.slot,
            session: e.session,
            role: e.role,
            rv: e.rv,
            actor: e.actor.as_deref(),
            params: &pairs,
        })
        .unwrap();
    }
    let p = log.path().to_path_buf();
    drop(log);
    (dir, p)
}

fn rewrite(path: &Path, ls: &[&[u8]]) {
    let mut out = Vec::new();
    for l in ls {
        out.extend_from_slice(l);
        out.push(b'\n');
    }
    std::fs::write(path, out).unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn random_event_sequences_verify_in_both_verifiers(evs in prop::collection::vec(ev(), 0..12)) {
        // RULE-007, RULE-008, RULE-027
        let (_d, p) = write_log(&evs);
        let (module_ok, code, out, err) = both(&p);
        prop_assert!(module_ok);
        prop_assert_eq!(code, 0);
        prop_assert_eq!(out, format!("verify: {} records OK, chain intact\n", evs.len()));
        prop_assert_eq!(err, "");
    }

    #[test]
    fn deleting_any_line_but_the_last_is_rejected_by_both(
        evs in prop::collection::vec(ev(), 2..10), pick in any::<prop::sample::Index>()
    ) {
        // RULE-008: deleting the last line is the documented tail-truncation gap
        let (_d, p) = write_log(&evs);
        let data = std::fs::read(&p).unwrap();
        let mut ls = lines(&data);
        let i = pick.index(ls.len() - 1);
        ls.remove(i);
        rewrite(&p, &ls);
        assert_both_reject(&p)?;
    }

    #[test]
    fn deleting_the_last_line_is_accepted_by_both(evs in prop::collection::vec(ev(), 1..8)) {
        // RULE-008: truncation at the end is undetectable from the file (C behaviour)
        let (_d, p) = write_log(&evs);
        let data = std::fs::read(&p).unwrap();
        let mut ls = lines(&data);
        ls.pop();
        rewrite(&p, &ls);
        let (module_ok, code, _, _) = both(&p);
        prop_assert!(module_ok);
        prop_assert_eq!(code, 0);
    }

    #[test]
    fn swapping_any_two_lines_is_rejected_by_both(
        evs in prop::collection::vec(ev(), 2..10), a in any::<prop::sample::Index>(), b in any::<prop::sample::Index>()
    ) {
        // RULE-008
        let (_d, p) = write_log(&evs);
        let data = std::fs::read(&p).unwrap();
        let mut ls = lines(&data);
        let (i, j) = (a.index(ls.len()), b.index(ls.len()));
        prop_assume!(i != j);
        ls.swap(i, j);
        rewrite(&p, &ls);
        assert_both_reject(&p)?;
    }
}

/// Offsets in the C-written `chain.log` that every C verifier checks: the MAC'd body of each
/// line, and the 64 hmac hex digits.
fn c_log_regions() -> (Vec<u8>, Vec<usize>, Vec<usize>) {
    let data = read_golden("verify/chain.log");
    let (mut body, mut mac) = (Vec::new(), Vec::new());
    let mut at = 0;
    for l in lines(&data) {
        let h = find(l, b"\"hmac\":\"").unwrap();
        body.extend(at..at + h);
        mac.extend(at + h + 8..at + h + 8 + 64);
        at += l.len() + 1;
    }
    (data, body, mac)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn any_byte_change_in_a_maced_body_is_rejected_by_both(pick in any::<prop::sample::Index>(), new in any::<u8>()) {
        // RULE-008 (data: golden/verify/chain.log, written by C)
        let (mut data, body, _) = c_log_regions();
        let i = body[pick.index(body.len())];
        prop_assume!(data[i] != new);
        data[i] = new;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("m.log");
        std::fs::write(&p, &data).unwrap();
        assert_both_reject(&p)?;
    }

    #[test]
    fn any_hmac_hex_digit_changed_to_another_value_is_rejected_by_both(
        pick in any::<prop::sample::Index>(), new in prop::sample::select(b"0123456789abcdefABCDEF".to_vec())
    ) {
        // RULE-008: a case-only change of the same digit is accepted by C, so it is excluded
        let (mut data, _, mac) = c_log_regions();
        let i = mac[pick.index(mac.len())];
        prop_assume!(!data[i].eq_ignore_ascii_case(&new));
        data[i] = new;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("m.log");
        std::fs::write(&p, &data).unwrap();
        assert_both_reject(&p)?;
    }
}
