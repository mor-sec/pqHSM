//! The token's crypto seam against `src/fhsm_crypto.c`. `golden/store/kat.tsv` is what the
//! real `fhsm_pbkdf2` / `fhsm_aes_gcm_*` returned for fixed vectors (gen_store.c `kat`).
//!
//! Run both ways, the two backends are checked against the same C values, and so against each
//! other (PHASE2_PLAN.md §6.1):
//!   cargo test -p pqhsm-token --test crypto                   # openssl-sys backend
//!   cargo test -p pqhsm-token --test crypto --features ffi    # C seam (doubles in tests)

mod store_common;

use pqhsm_token::Rv;
use pqhsm_token::crypto::{gcm_decrypt, gcm_encrypt, pbkdf2_sha256, random};
use store_common::*;

fn rows(op: &str) -> Vec<Vec<String>> {
    String::from_utf8(read_golden("kat.tsv"))
        .unwrap()
        .lines()
        .filter(|l| l.starts_with(op) && l.as_bytes().get(op.len()) == Some(&b'\t'))
        .map(|l| l.split('\t').skip(1).map(str::to_owned).collect())
        .collect()
}

fn b(s: &str) -> Vec<u8> {
    if s == "-" { Vec::new() } else { unhex(s) }
}

fn rv(s: &str) -> Rv {
    Rv(num(s) as u32)
}

#[test]
fn pbkdf2_matches_c_including_the_1000_iteration_floor() {
    let r = rows("pbkdf2");
    assert_eq!(r.len(), 8, "kat.tsv pbkdf2 rows");
    for f in r {
        // pw, salt, iter, out_len, rv, out
        let (iter, len) = (num(&f[2]) as u32, num(&f[3]) as usize);
        let mut out = vec![0u8; len];
        let got = pbkdf2_sha256(&b(&f[0]), &b(&f[1]), iter, &mut out);
        assert_eq!(rv_of(&got), rv(&f[4]), "pbkdf2 iter={iter}");
        if got.is_ok() {
            assert_eq!(hex(&out), f[5], "pbkdf2 iter={iter} len={len}");
        }
    }
}

#[test]
fn the_store_iteration_count_derives_c_s_kek() {
    // RULE-001: 200000 iterations, as every C-written header says.
    let r = rows("pbkdf2");
    let f = r.iter().find(|f| f[2] == "200000").unwrap();
    let mut out = [0u8; 32];
    pbkdf2_sha256(SO_PIN, &b(&f[1]), 200_000, &mut out).unwrap();
    assert_eq!(hex(&out), f[5]);
}

#[test]
fn gcm_encrypt_matches_c() {
    let r = rows("gcm_enc");
    assert_eq!(r.len(), 8);
    for f in r {
        // key, iv, aad, pt, rv, ct, tag
        let key: [u8; 32] = b(&f[0]).try_into().unwrap();
        let iv: [u8; 12] = b(&f[1]).try_into().unwrap();
        let got = gcm_encrypt(&key, &iv, &b(&f[2]), &b(&f[3]));
        assert_eq!(rv_of(&got), rv(&f[4]));
        let (ct, tag) = got.unwrap();
        assert_eq!(
            (hex(&ct), hex(&tag)),
            (
                if f[5] == "-" {
                    String::new()
                } else {
                    f[5].clone()
                },
                f[6].clone()
            ),
            "pt {}",
            f[3]
        );
    }
}

#[test]
fn gcm_decrypt_matches_c_and_rejects_a_bad_tag_or_aad_with_0x40() {
    let r = rows("gcm_dec");
    assert_eq!(r.len(), 12);
    let mut refused = 0;
    for f in r {
        // key, iv, aad, ct, tag, rv, pt
        let key: [u8; 32] = b(&f[0]).try_into().unwrap();
        let iv: [u8; 12] = b(&f[1]).try_into().unwrap();
        let tag: [u8; 16] = b(&f[4]).try_into().unwrap();
        let got = gcm_decrypt(&key, &iv, &b(&f[2]), &b(&f[3]), &tag);
        assert_eq!(rv_of(&got), rv(&f[5]), "ct {} tag {}", f[3], f[4]);
        match got {
            Ok(pt) => assert_eq!(
                hex(&pt),
                if f[6] == "-" {
                    String::new()
                } else {
                    f[6].clone()
                }
            ),
            Err(e) => {
                assert_eq!(e, Rv::ENCRYPTED_DATA_INVALID);
                refused += 1;
            }
        }
    }
    assert_eq!(refused, 4, "two bad tags and two wrong AADs");
}

#[test]
fn random_fills_and_differs() {
    let (mut a, mut c) = ([0u8; 32], [0u8; 32]);
    random(&mut a).unwrap();
    random(&mut c).unwrap();
    assert_ne!(a, [0u8; 32]);
    assert_ne!(a, c);
}
