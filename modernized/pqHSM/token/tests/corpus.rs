//! The gen_token.c corpus (`testdata/`, PHASE2_PLAN.md §5.1): every token C wrote loads in Rust
//! with the verdicts C recorded in `testdata/manifest.tsv`. One stated exception (M4):
//! `zero_dek_2_5_0.tok` no longer logs in (DIV-010); `migrate_zero_dek` is its way back.
//!
//!   cargo test -p pqhsm-token --test corpus

mod store_common;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use pqhsm_token::Rv;
use pqhsm_token::token::{Platform, Role, Token, migrate_zero_dek};
use pqhsm_token::tpm::{Cli, Tpm};
use store_common::*;

struct Row {
    kind: String,
    file: String,
    kv: BTreeMap<String, String>,
}

fn manifest() -> Vec<Row> {
    fs::read_to_string(corpus("manifest.tsv"))
        .unwrap()
        .lines()
        .map(|l| {
            let mut f = l.split('\t');
            let (kind, file) = (f.next().unwrap().to_owned(), f.next().unwrap().to_owned());
            let kv = f
                .map(|c| {
                    c.split_once('=')
                        .map(|(k, v)| (k.to_owned(), v.to_owned()))
                        .unwrap()
                })
                .collect();
            Row { kind, file, kv }
        })
        .collect()
}

fn platform(dir: &Path, sealing: bool) -> Arc<Platform> {
    let device = dir.join("fake_tpmrm0");
    fs::write(&device, b"").unwrap();
    // gen_token.c ran with FHSM_TPM_FAKE_PCR=golden-pcr
    let cmd = format!("FHSM_TPM_FAKE_PCR=golden-pcr sh '{}'", tpm_stub().display());
    Arc::new(Platform {
        tpm: Arc::new(Tpm::new(device, Cli::Shell(cmd))),
        sealing_required: sealing,
        audit: Box::new(Rec(Arc::default())),
    })
}

fn copy(dir: &Path, name: &str) -> PathBuf {
    let to = dir.join(name);
    fs::copy(corpus(name), &to).unwrap();
    let tpm = corpus(&format!("{name}.tpm"));
    if tpm.exists() {
        fs::copy(tpm, dir.join(format!("{name}.tpm"))).unwrap();
    }
    to
}

fn rvx(r: Rv) -> String {
    rv_hex(r)
}

#[test]
fn every_corpus_token_loads_with_c_s_verdicts() {
    let rows = manifest();
    let mut checked = 0;
    for t in rows.iter().filter(|r| r.kind == "token") {
        let dir = tempfile::tempdir().unwrap();
        let path = copy(dir.path(), &t.file);
        let tok = Token::load(&path, platform(dir.path(), t.file == "tpm_sealed.tok"));
        assert_eq!(rvx(rv_of(&tok)), t.kv["load"], "{}: load", t.file);
        let tok = tok.unwrap();
        let label = tok.label();
        assert_eq!(String::from_utf8_lossy(&label), t.kv["label"], "{}", t.file);
        assert_eq!(
            String::from_utf8_lossy(&tok.serial()),
            t.kv["serial"],
            "{}",
            t.file
        );
        assert_eq!(
            tok.user_initialized() as u8,
            num(&t.kv["user_initialized"]) as u8,
            "{}",
            t.file
        );
        assert_eq!(
            tok.is_locked(Role::So) as u8,
            num(&t.kv["so_locked"]) as u8,
            "{}",
            t.file
        );
        assert_eq!(
            tok.is_locked(Role::User) as u8,
            num(&t.kv["user_locked"]) as u8,
            "{}",
            t.file
        );
        let (role, pin, key) = match t.kv.get("login_so") {
            Some(_) => (Role::So, SO_PIN, "login_so"),
            None => (Role::User, USER_PIN, "login_user"),
        };
        let got = tok.login(role, pin);
        if t.file == "zero_dek_2_5_0.tok" {
            // M4's stated exception: DIV-010.
            assert_eq!(t.kv[key], "0x0", "C logged in");
            assert_eq!(
                got,
                Err(Rv::FUNCTION_FAILED),
                "DIV-010: a zero-key store is an error"
            );
            assert_eq!(
                fs::read(&path).unwrap(),
                fs::read(corpus(&t.file)).unwrap(),
                "and the file is untouched"
            );
            checked += 1;
            continue;
        }
        assert_eq!(rvx(rv_of(&got)), t.kv[key], "{}: {key}", t.file);
        if let Some(n) = t.kv.get("objects") {
            let (hs, total) = tok.object_find(None, None, 2048).unwrap();
            assert_eq!(total.to_string(), *n, "{}", t.file);
            for o in rows
                .iter()
                .filter(|r| r.kind == "object" && r.file == t.file)
            {
                let h = num(&o.kv["handle"]) as u32;
                assert!(hs.contains(&h), "{}: handle {h}", t.file);
                let (v, class, kt) = tok.object_get(h).unwrap();
                assert_eq!(
                    (class.to_string(), kt.to_string(), hex(&v)),
                    (
                        o.kv["class"].clone(),
                        o.kv["key_type"].clone(),
                        o.kv["value"].clone()
                    )
                );
                assert_eq!(
                    format!("0x{:02x}", tok.object_get_flags(h).unwrap()),
                    o.kv["flags"]
                );
                assert_eq!(
                    String::from_utf8_lossy(&tok.object_get_label(h).unwrap()),
                    o.kv["label"]
                );
                assert_eq!(hex(&tok.object_get_id(h).unwrap()), o.kv["id"]);
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 7);
}

fn zero_dek_rows() -> Vec<Row> {
    manifest()
        .into_iter()
        .filter(|r| r.kind == "object" && r.file == "zero_dek_2_5_0.tok")
        .collect()
}

#[test]
fn migrate_zero_dek_rewrites_the_store_under_the_real_dek_div010() {
    let dir = tempfile::tempdir().unwrap();
    let path = copy(dir.path(), "zero_dek_2_5_0.tok");
    assert_eq!(migrate_zero_dek(&path, USER_PIN), Ok(5));
    let f = fs::read(&path).unwrap();
    let dek = unwrap_dek(&f, Role::User, USER_PIN).unwrap();
    let ct = u32::from_le_bytes(f[317..321].try_into().unwrap()) as usize;
    let mut tag: [u8; 16] = f[333 + ct..349 + ct].try_into().unwrap();
    assert!(
        gcm(
            false,
            &dek,
            &f[321..333],
            serial_aad(&f),
            &f[333..333 + ct],
            &mut tag
        )
        .is_some(),
        "sealed under the DEK now"
    );
    let tok = Token::load(&path, platform(dir.path(), false)).unwrap();
    tok.login(Role::User, USER_PIN).unwrap();
    for o in zero_dek_rows() {
        let (v, _, _) = tok.object_get(num(&o.kv["handle"]) as u32).unwrap();
        assert_eq!(hex(&v), o.kv["value"]);
    }
}

#[test]
fn migrate_zero_dek_refuses_a_wrong_pin_or_a_store_not_under_the_zero_key() {
    let dir = tempfile::tempdir().unwrap();
    for (name, pin) in [
        ("zero_dek_2_5_0.tok", WRONG_PIN),
        ("multi_object.tok", USER_PIN),
    ] {
        let path = copy(dir.path(), name);
        let before = fs::read(&path).unwrap();
        assert!(migrate_zero_dek(&path, pin).is_err(), "{name}");
        assert_eq!(fs::read(&path).unwrap(), before, "{name}: untouched");
    }
}

/// legacy/tests/test_v3_fixture.c (Phase 6 slice 5c): `token-v3.tok`, written by a pre-v4 C build
/// (legacy/tests/make_v3_fixture.c), not by the generator whose beliefs the reader shares. Its
/// objects read back with their values and flags2, with no policy (absent, not empty), and a
/// write migrates it to v4 without changing them. Its PIN is the C test's.
#[test]
fn the_c_written_v3_fixture_loads_and_migrates() {
    const PIN: &[u8] = b"userpin1234";
    const V16: [u8; 16] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const V32: [u8; 32] = [
        0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
    ];
    const NOT_COPYABLE: u8 = 0x04;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slot0.tok");
    fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/v3/token-v3.tok"), &path).unwrap();
    let find = |t: &Token, label: &[u8]| {
        let (hs, _) = t.object_find(None, Some(label), 4).unwrap();
        assert_eq!(hs.len(), 1, "{}", String::from_utf8_lossy(label));
        hs[0]
    };
    let before = fs::read(&path).unwrap();
    let t = Token::load(&path, platform(dir.path(), false)).unwrap();
    t.login(Role::User, PIN).unwrap();
    assert_eq!(t.object_find(None, None, 16).unwrap().0.len(), 2);
    let (h16, h32) = (find(&t, b"sixteen"), find(&t, b"thirtytwo"));
    assert_eq!(t.object_get(h16).unwrap().0, V16);
    assert_eq!(t.object_get(h32).unwrap().0, V32);
    assert_eq!((t.object_get_flags2(h32), t.object_get_flags2(h16)), (Ok(NOT_COPYABLE), Ok(0)));
    assert_eq!(t.object_policy_counts(h16), Ok([0; 4]));
    t.object_set_label(h16, b"sixteen").unwrap();
    t.close();
    // rewritten as v4 (by the load or login already, before this write): the same two objects with a
    // policy block each take more room (review L4; 825 bytes to 2261 at the time of writing)
    let after = fs::read(&path).unwrap();
    assert!(after != before && after.len() > before.len(), "{} -> {} bytes", before.len(), after.len());
    let t = Token::load(&path, platform(dir.path(), false)).unwrap();
    t.login(Role::User, PIN).unwrap();
    let h32 = find(&t, b"thirtytwo");
    assert_eq!(t.object_get(h32).unwrap().0, V32);
    assert_eq!(t.object_get_flags2(h32), Ok(NOT_COPYABLE));
}
