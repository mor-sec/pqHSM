//! `tests/golden/pairwise.tsv` (legacy/hybrid/golden/gen_pairwise.c) replayed: every key type
//! and its mismatched pair under every family selector, and the null key; the keys built as the
//! generator builds them.

use std::ffi::CStr;
use std::ptr::{null, null_mut};

use openssl_sys::{
    EVP_PKEY, EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, EVP_PKEY_KEYPAIR, EVP_PKEY_Q_keygen,
    EVP_PKEY_free, EVP_PKEY_fromdata, EVP_PKEY_fromdata_init, EVP_PKEY_todata, OSSL_PARAM,
    OSSL_PARAM_construct_end, OSSL_PARAM_free, OSSL_PARAM_locate, OSSL_PARAM_merge,
};
use pqhsm_selftest::pairwise;

/// gen_pairwise.c's KEYS: name, algorithm, curve, RSA, family.
type Key = (
    &'static str,
    &'static CStr,
    Option<&'static CStr>,
    bool,
    i32,
);
const KEYS: [Key; 15] = [
    ("RSA-2048", c"RSA", None, true, pairwise::RSA),
    ("EC-P-256", c"EC", Some(c"P-256"), false, pairwise::EC),
    ("EC-P-521", c"EC", Some(c"P-521"), false, pairwise::EC),
    ("X25519", c"X25519", None, false, pairwise::ECM),
    ("X448", c"X448", None, false, pairwise::ECM),
    ("ED25519", c"ED25519", None, false, pairwise::EDDSA),
    ("ED448", c"ED448", None, false, pairwise::EDDSA),
    ("ML-KEM-512", c"ML-KEM-512", None, false, pairwise::ML_KEM),
    ("ML-KEM-768", c"ML-KEM-768", None, false, pairwise::ML_KEM),
    ("ML-KEM-1024", c"ML-KEM-1024", None, false, pairwise::ML_KEM),
    ("ML-DSA-44", c"ML-DSA-44", None, false, pairwise::ML_DSA),
    ("ML-DSA-65", c"ML-DSA-65", None, false, pairwise::ML_DSA),
    ("ML-DSA-87", c"ML-DSA-87", None, false, pairwise::ML_DSA),
    (
        "SLH-DSA-SHA2-128f",
        c"SLH-DSA-SHA2-128f",
        None,
        false,
        pairwise::SLH_DSA,
    ),
    (
        "SLH-DSA-SHAKE-256f",
        c"SLH-DSA-SHAKE-256f",
        None,
        false,
        pairwise::SLH_DSA,
    ),
];
const FAMILIES: [i32; 10] = [-1, 0, 1, 2, 3, 4, 5, 6, 7, 8];

fn keygen(alg: &CStr, curve: Option<&CStr>, rsa: bool) -> *mut EVP_PKEY {
    // SAFETY: the variadic argument is the one alg takes: a curve name, the size_t bits, or none
    let k = unsafe {
        match (curve, rsa) {
            (Some(c), _) => EVP_PKEY_Q_keygen(null_mut(), null(), alg.as_ptr(), c.as_ptr()),
            (None, true) => EVP_PKEY_Q_keygen(null_mut(), null(), alg.as_ptr(), 2048usize),
            (None, false) => EVP_PKEY_Q_keygen(null_mut(), null(), alg.as_ptr()),
        }
    };
    assert!(!k.is_null());
    k
}

/// a's parameters with b's public half (for RSA the modulus); null when fromdata refuses them.
fn mismatched(alg: &CStr, rsa: bool, a: *mut EVP_PKEY, b: *mut EVP_PKEY) -> *mut EVP_PKEY {
    let swap = if rsa { c"n" } else { c"pub" };
    // SAFETY: a and b are live keys; every array OpenSSL returns is freed once, after its last use
    unsafe {
        let ctx = EVP_PKEY_CTX_new_from_name(null_mut(), alg.as_ptr(), null());
        let (mut pa, mut pb): (*mut OSSL_PARAM, *mut OSSL_PARAM) = (null_mut(), null_mut());
        assert!(!ctx.is_null());
        assert_eq!(EVP_PKEY_todata(a, EVP_PKEY_KEYPAIR, &mut pa), 1);
        assert_eq!(EVP_PKEY_todata(b, EVP_PKEY_KEYPAIR, &mut pb), 1);
        let p = OSSL_PARAM_locate(pb, swap.as_ptr());
        assert!(!p.is_null());
        // a bitwise copy of the descriptor, as C's `{ *p, end }`; pb outlives merged's use
        let one = [std::ptr::read(p), OSSL_PARAM_construct_end()];
        let merged = OSSL_PARAM_merge(pa, one.as_ptr());
        assert!(!merged.is_null());
        assert_eq!(EVP_PKEY_fromdata_init(ctx), 1);
        let mut out = null_mut();
        if EVP_PKEY_fromdata(ctx, &mut out, EVP_PKEY_KEYPAIR, merged) != 1 {
            out = null_mut();
        }
        OSSL_PARAM_free(merged);
        OSSL_PARAM_free(pa);
        OSSL_PARAM_free(pb);
        EVP_PKEY_CTX_free(ctx);
        out
    }
}

#[test]
fn every_key_and_family_returns_as_the_c_did() {
    let golden = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/pairwise.tsv");
    let want: Vec<String> = std::fs::read_to_string(golden)
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(str::to_owned)
        .collect();
    // SAFETY: a null key is refused before anything runs
    let r = unsafe { pairwise::check(null_mut(), pairwise::RSA) };
    let mut got = vec![format!("null\t1\t0x{r:x}")];
    for (name, alg, curve, rsa, family) in KEYS {
        let (a, b) = (keygen(alg, curve, rsa), keygen(alg, curve, rsa));
        let m = mismatched(alg, rsa, a, b);
        for (key, label) in [(a, name.to_owned()), (m, format!("mismatched-{name}"))] {
            if key.is_null() {
                got.push(format!("{label}\t{family}\trefused"));
                continue;
            }
            for f in FAMILIES {
                // SAFETY: key is a live key pair
                let r = unsafe { pairwise::check(key, f) };
                got.push(format!("{label}\t{f}\t0x{r:x}"));
            }
        }
        // SAFETY: each key is freed once; free ignores null
        unsafe {
            EVP_PKEY_free(m);
            EVP_PKEY_free(a);
            EVP_PKEY_free(b);
        }
    }
    assert_eq!(got, want);
}
