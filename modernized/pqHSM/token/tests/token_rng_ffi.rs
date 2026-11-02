//! DIV-025: a failed `fhsm_rng_bytes` draw fails the call with the DRBG's code before anything
//! is written. C ignores the result at every site (`src/fhsm_token.c:1169`, `:1226`,
//! `:1232-1233`, `:1239`, `:1255`, `:1724-1725`, `:1784-1785`, `:1833`, `:1839`, `:1847`,
//! `:1868`) and the generator's DRBG never fails, so these are the Rust-only rows of
//! `store_common::RUST_ONLY`.
//!
//! With feature `ffi` the crypto seam draws through C's `fhsm_rng_bytes`, which in tests is
//! the double in `store_common/c_doubles.rs`. Each test counts the draws a clean call makes,
//! then fails each of them in turn. That covers every site without assuming the order or the
//! number of draws, only a floor per operation.
//!
//!   cargo test -p pqhsm-token --features ffi --test token_rng_ffi
#![cfg(feature = "ffi")]

mod store_common;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pqhsm_token::Rv;
use pqhsm_token::token::{Platform, Role, Token};
use pqhsm_token::tpm::{Cli, Tpm};
use store_common::c_doubles::{RNG_DRAWS, RNG_FAIL_AT, RNG_FAILURE};
use store_common::*;

fn platform(dir: &Path) -> Arc<Platform> {
    let cmd = format!("sh '{}'", tpm_stub().display());
    Arc::new(Platform {
        tpm: Arc::new(Tpm::new(dir.join("no-tpm-here"), Cli::Shell(cmd))),
        sealing_required: false,
        audit: Box::new(Rec(Arc::default())),
    })
}

/// A fresh directory holding `tok/NAME.tok` as slot0.tok, or nothing for `None`.
fn start(golden_tok: Option<&str>) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("slot0.tok");
    if let Some(n) = golden_tok {
        fs::copy(store_golden(&format!("tok/{n}.tok")), &p).unwrap();
    }
    (dir, p)
}

fn dir_listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Run `op` once clean to count its draws (at least `floor`), then once per draw with that
/// draw failed: each must return the DRBG's code and leave the directory as `prepare` left it.
/// `prepare` builds the token and does any setup draws before the count starts; `after`
/// checks memory on the failed token.
fn every_draw_fails<T>(
    floor: u64,
    prepare: impl Fn() -> (tempfile::TempDir, PathBuf, T),
    op: impl Fn(&T, &Path, &Path) -> Result<(), Rv>,
    after: impl Fn(&T),
) {
    let (d, p, t) = prepare();
    let before = RNG_DRAWS.get();
    op(&t, d.path(), &p).expect("the clean call succeeds");
    let n = RNG_DRAWS.get() - before;
    assert!(n >= floor, "{n} draws, expected at least {floor}");
    for i in 0..n {
        let (d, p, t) = prepare();
        let (files, bytes) = (dir_listing(d.path()), fs::read(&p).ok());
        RNG_FAIL_AT.set(Some(RNG_DRAWS.get() + i));
        let r = op(&t, d.path(), &p);
        RNG_FAIL_AT.set(None);
        assert_eq!(r, Err(Rv(RNG_FAILURE)), "draw {i} of {n} failed");
        assert_eq!(
            dir_listing(d.path()),
            files,
            "draw {i}: the file set changed"
        );
        assert_eq!(fs::read(&p).ok(), bytes, "draw {i}: the token file changed");
        after(&t);
    }
}

/// `:1226` serial, `:1232-1233` salts, `:1239` DEK, `:1255` SO wrap nonce.
#[test]
fn every_draw_of_init_fails_the_call_div025() {
    every_draw_fails(
        5,
        || {
            let (d, p) = start(None);
            (d, p, ())
        },
        |_, d, p| Token::init(p, SO_PIN, b"rng", platform(d)).map(drop),
        |_| {},
    );
}

/// `:1724-1725` user salt and wrap nonce.
#[test]
fn every_draw_of_init_user_pin_fails_the_call_div025() {
    every_draw_fails(
        2,
        || {
            let (d, p) = start(Some("user_base"));
            let t = Token::load(&p, platform(d.path())).unwrap();
            t.login(Role::So, SO_PIN).unwrap();
            (d, p, t)
        },
        |t, _, _| t.init_user_pin(NEW_PIN),
        |t| assert!(t.user_initialized(), "still the old user PIN"),
    );
}

/// `:1784-1785` salt and wrap nonce of the changed PIN. `user_base` has no objects, so the
/// login inside `set_pin` (RULE-082, preserved) writes no blob and draws nothing.
#[test]
fn every_draw_of_set_pin_fails_the_call_div025() {
    every_draw_fails(
        2,
        || {
            let (d, p) = start(Some("user_base"));
            let t = Token::load(&p, platform(d.path())).unwrap();
            (d, p, t)
        },
        |t, _, _| {
            let r = t.set_pin(Role::User, USER_PIN, NEW_PIN);
            t.logout();
            r
        },
        |t| t.login(Role::User, USER_PIN).unwrap(),
    );
}

/// `:1833` serial, `:1839` SO salt, `:1847` DEK, `:1868` SO wrap nonce.
#[test]
fn every_draw_of_reinit_fails_the_call_div025() {
    every_draw_fails(
        4,
        || {
            let (d, p) = start(Some("multi_base"));
            let t = Token::load(&p, platform(d.path())).unwrap();
            (d, p, t)
        },
        |t, _, _| t.reinit(NEW_PIN, b"rng"),
        |t| assert_eq!(t.label(), b"golden-user", "label unchanged"),
    );
}

/// `:1169` the blob nonce of every write that seals the store: a usage change and an add.
#[test]
fn every_draw_of_an_object_write_fails_the_call_div025() {
    let logged_in = || {
        let (d, p) = start(Some("multi_base"));
        let t = Token::load(&p, platform(d.path())).unwrap();
        t.login(Role::User, USER_PIN).unwrap();
        (d, p, t)
    };
    let usage = |t: &Token| t.object_get_usage(1).unwrap();
    let old = usage(&logged_in().2);
    every_draw_fails(
        1,
        logged_in,
        |t, _, _| t.object_set_usage(1, old ^ 0x80),
        |t| assert_eq!(usage(t), old, "H4: memory unchanged"),
    );
    every_draw_fails(
        1,
        logged_in,
        |t, _, _| {
            t.object_add(0, 0, Some(b"rng"), &[1, 2, 3, 4], &[], 0)
                .map(drop)
        },
        |t| {
            assert_eq!(
                t.object_find(None, None, 0).unwrap().1,
                5,
                "no object added"
            )
        },
    );
}
