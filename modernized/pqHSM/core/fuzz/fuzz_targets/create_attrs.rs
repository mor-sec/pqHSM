//! `template::parse` (C's `fhsm_parse_create_attrs`) on a template decoded as
//! `fuzz/fuzz_create_attrs.c` decodes it, with that harness's invariants and its truncation pass.
#![no_main]

use std::ffi::c_ulong;

use libfuzzer_sys::fuzz_target;
use pqhsm_core::template::{In, Parsed, Path, Rv, parse};

const MAX_ATTRS: usize = 12;

/// The C harness's `build_template`: a count byte, then per row an 8-byte type, a length byte and
/// the value; a row the input cannot finish ends the template.
fn build(data: &[u8]) -> Vec<In<'_>> {
    let mut t = Vec::new();
    let Some((&n, mut rest)) = data.split_first() else {
        return t;
    };
    for _ in 0..usize::from(n) % (MAX_ATTRS + 1) {
        let Some((kind, r)) = rest.split_first_chunk::<8>() else {
            break;
        };
        let Some((&len, r)) = r.split_first() else {
            break;
        };
        let Some((value, r)) = r.split_at_checked(usize::from(len)) else {
            break;
        };
        t.push(In {
            kind: c_ulong::from_ne_bytes(*kind),
            value: Some(value),
        });
        rest = r;
    }
    t
}

fn check(a: &Parsed, rv: Rv) {
    if rv != Rv::Ok {
        assert_eq!(a.path, Path::Invalid, "E1");
        return;
    }
    assert_ne!(a.path, Path::Invalid, "P2");
    assert!(a.label.contains(&0), "P3");
    assert!(a.cko <= 4, "P5");
    match a.path {
        Path::Verbatim => assert!(a.cko == 0 || a.value.is_some(), "P6"),
        Path::EcPub => {
            assert_eq!(a.cko, 2, "P7");
            let g = a.ec_group.expect("P7 group").to_bytes();
            assert!(matches!(g, b"P-256" | b"P-384" | b"P-521"), "P7 curve");
            assert!(a.ec_point.is_some(), "P7 point");
        }
        Path::Ed25519Pub | Path::Ed448Pub => {
            assert_eq!(a.cko, 2, "P8");
            assert!(a.ec_group.is_none() && a.ec_point.is_some(), "P9");
        }
        Path::RsaPub => assert!(a.cko == 2 && a.rsa[0].is_some() && a.rsa[1].is_some(), "P10"),
        Path::CertX509 => assert!(a.cko == 1 && a.value.is_some(), "P11"),
        Path::PqcPub | Path::RsaPriv | Path::Invalid => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let mut t = build(data);
    let (a, rv) = parse(&t);
    check(&a, rv);
    // Pass 2: the last value one byte shorter.
    if let Some(last) = t.last_mut()
        && let Some(v) = last.value.filter(|v| !v.is_empty())
    {
        last.value = Some(&v[..v.len() - 1]);
        let (a, rv) = parse(&t);
        check(&a, rv);
    }
});
