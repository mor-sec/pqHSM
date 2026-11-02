//! Opt-in: the legacy C auditor must accept logs the Rust module writes (RULE-008).
//! Run inside the legacy container with the C tool built:
//!
//! ```sh
//! FHSM_C_AUDIT_TOOL=/path/to/tools/freehsm-audit cargo test -p pqhsm-audit --test cross_impl -- --ignored
//! ```

mod common;

use std::process::Command;

use common::{KEY, KEY_HEX};
use pqhsm_audit::log::{AuditLog, Event};
use pqhsm_audit::record::Role;

fn c_tool() -> String {
    std::env::var("FHSM_C_AUDIT_TOOL").expect("set FHSM_C_AUDIT_TOOL to the C freehsm-audit binary")
}

fn write_rust_log(base: &std::path::Path, n: usize) -> std::path::PathBuf {
    let log = AuditLog::open(base, &KEY).unwrap();
    let pairs: [(&[u8], &[u8]); 3] = [(b"alg", b"mldsa65"), (b"q", b"a\"b"), (b"", b"")];
    for i in 0..n {
        log.append(&Event {
            code: [1, 12, 42, 13, 999][i % 5],
            slot: i as i32 - 1,
            session: -1,
            role: [Role::None, Role::So, Role::User][i % 3],
            rv: [0, 0xA0, 0x8000_0001][i % 3],
            actor: [None, Some(&b"CN=alice"[..]), Some(&b"CN=\xff"[..])][i % 3],
            params: &pairs[..i % 4],
        })
        .unwrap();
    }
    log.path().to_path_buf()
}

#[test]
#[ignore = "needs the C tool: set FHSM_C_AUDIT_TOOL"]
fn c_tool_verifies_a_rust_written_log() {
    // RULE-008
    let dir = tempfile::tempdir().unwrap();
    let p = write_rust_log(&dir.path().join("audit.log"), 7);
    let o = Command::new(c_tool())
        .args(["verify", p.to_str().unwrap(), KEY_HEX])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&o.stderr), "");
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        "verify: 7 records OK, chain intact\n"
    );
    assert_eq!(o.status.code(), Some(0));
}

#[test]
#[ignore = "needs the C tool: set FHSM_C_AUDIT_TOOL"]
fn c_tool_verifies_a_directory_of_rust_written_logs() {
    // RULE-008, RULE-094
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("audit.log");
    write_rust_log(&base, 3);
    write_rust_log(&base, 2);
    let o = Command::new(c_tool())
        .args(["verify", dir.path().to_str().unwrap(), KEY_HEX])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&o.stderr), "");
    assert!(
        String::from_utf8_lossy(&o.stdout).ends_with(
            "verify: 2 log(s), sequence 000001..000002, contiguous, every chain intact\n"
        ),
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert_eq!(o.status.code(), Some(0));
}
