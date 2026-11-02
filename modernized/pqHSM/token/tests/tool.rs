//! The `pqhsm-token migrate-zero-dek` command (DIV-010), end to end on the C-written corpus.
//!
//!   cargo test -p pqhsm-token --features tool --test tool

mod store_common;

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

use store_common::*;

fn run(path: &std::path::Path, pin: &[u8]) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_pqhsm-token"))
        .arg("migrate-zero-dek")
        .arg(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = c.stdin.take().unwrap();
    stdin.write_all(pin).unwrap();
    stdin.write_all(b"\n").unwrap();
    drop(stdin);
    c.wait_with_output().unwrap()
}

fn copy(dir: &std::path::Path) -> std::path::PathBuf {
    let to = dir.join("slot0.tok");
    let from =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/zero_dek_2_5_0.tok");
    fs::copy(from, &to).unwrap();
    to
}

#[test]
fn migrates_a_zero_dek_store_with_the_user_pin() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy(dir.path());
    let out = run(&path, USER_PIN);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("5 objects re-sealed"));
    // A second run finds no zero-key store and leaves the file alone.
    let before = fs::read(&path).unwrap();
    assert_eq!(run(&path, USER_PIN).status.code(), Some(1));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn a_wrong_pin_or_bad_usage_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy(dir.path());
    let before = fs::read(&path).unwrap();
    assert_eq!(run(&path, WRONG_PIN).status.code(), Some(1));
    assert_eq!(fs::read(&path).unwrap(), before);
    let usage = Command::new(env!("CARGO_BIN_EXE_pqhsm-token"))
        .output()
        .unwrap();
    assert_eq!(usage.status.code(), Some(2));
}
