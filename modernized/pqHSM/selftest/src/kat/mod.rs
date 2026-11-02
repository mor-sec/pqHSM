//! The power-on known-answer tests (`kat/fhsm_kat_vectors.c`, `kat/cavp_extended.c`; RULE-074,
//! FIPS 140-3 §7.10.3): the smoke vectors through the crypto core's primitives ([`Prims`]), the
//! CAVP SHA-256 file ([`cavp`]), the DRBG stuck check, then the extended set over OpenSSL
//! directly (`ffi::evp`). Every KAT is recorded in C's order with C's names; the early returns
//! and the report-full checks are C's.

pub mod cavp;
pub mod vectors;

use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use pqhsm_crypto::mem::ct_diff;
use pqhsm_crypto::rv;
use zeroize::Zeroize;

use vectors::*;

/// `FHSM_KAT_MAX`: the module's report, and the pool the CAVP identifiers are formatted into.
pub const KAT_MAX: usize = 64;
/// The CAVP file as installed, then beside the sources, relative to the working directory
/// (`kat/fhsm_kat_vectors.c:286-287`).
pub const CAVP_FILES: [&str; 2] = [
    "/opt/freehsm/share/kat/sha2_256_short.rsp",
    "kat/cavp/sha2_256_short.rsp",
];
/// `FHSM_HASH_SHA256`.
const SHA256: u32 = 1;

/// A vector identifier: a literal, or `CAVP-SHA256-Len<bits>` built at run time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vid {
    Static(&'static CStr),
    Cavp(i32),
}

/// `fhsm_kat_result_t`.
#[derive(Debug, Clone, Copy)]
pub struct Rec {
    pub algorithm: &'static CStr,
    pub vector_id: Vid,
    pub passed: bool,
    pub duration_us: u32,
}

/// The report being written: C's `out` array of `cap` entries, from entry `base` on.
pub struct Sink {
    cap: usize,
    base: usize,
    pub recs: Vec<Rec>,
}

impl Sink {
    pub fn new(cap: usize) -> Self {
        Self::at(cap, 0)
    }

    /// A report whose first `base` entries are already written (`fhsm_kat_cavp_extended`).
    pub fn at(cap: usize, base: usize) -> Self {
        Self {
            cap,
            base,
            recs: Vec::new(),
        }
    }

    /// The entries written so far, counting those before `base`.
    pub fn len(&self) -> usize {
        self.base + self.recs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn full(&self) -> bool {
        self.len() >= self.cap
    }

    /// One KAT, timed and recorded; ARGUMENTS_BAD, before it runs, when the report is full.
    pub fn kat(
        &mut self,
        algorithm: &'static CStr,
        vector_id: Vid,
        run: impl FnOnce() -> bool,
    ) -> Result<bool, u32> {
        if self.full() {
            return Err(rv::ARGUMENTS_BAD);
        }
        let t0 = Instant::now();
        let passed = run();
        // C's (uint32_t)(ns / 1000)
        let duration_us = t0.elapsed().as_micros() as u32;
        self.recs.push(Rec {
            algorithm,
            vector_id,
            passed,
            duration_us,
        });
        Ok(passed)
    }
}

/// The crypto core's primitives as `kat/fhsm_kat_vectors.c` calls them (`include/fhsm_crypto.h`).
/// Each returns C's return code and, where C passes an in/out length, the length after the call;
/// an output slice's length is the capacity C passes.
pub trait Prims {
    fn gcm_encrypt(
        &mut self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
        tag: &mut [u8; 16],
    ) -> (u32, usize);
    fn gcm_decrypt(
        &mut self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; 16],
        pt: &mut [u8],
    ) -> (u32, usize);
    fn hash(&mut self, alg: u32, data: &[u8], out: &mut [u8]) -> (u32, usize);
    fn hmac(&mut self, alg: u32, key: &[u8], data: &[u8], mac: &mut [u8]) -> (u32, usize);
    fn pbkdf2(&mut self, alg: u32, password: &[u8], salt: &[u8], iter: u32, out: &mut [u8]) -> u32;
    fn rng(&mut self, out: &mut [u8]) -> u32;
}

/// `fhsm_kat_run_all` (`kat/fhsm_kat_vectors.c:161-378`): the report in `sink`, the return
/// code, and the count C leaves in `*count` (the extended set's records are counted only when
/// it completes). `files` are tried in order; the first that opens is read.
///
/// DIV-046: if every KAT ran and one failed, KAT_FAILED, where C returned OK.
pub fn run_all(p: &mut impl Prims, files: &[impl AsRef<Path>], sink: &mut Sink) -> (u32, usize) {
    if let Err(rv) = smoke(p, files, sink) {
        return (rv, sink.len());
    }
    let counted = sink.len();
    let rv = crate::ffi::evp::extended(sink);
    if rv != rv::OK {
        return (rv, counted);
    }
    let failed = sink.recs.iter().any(|r| !r.passed);
    (if failed { rv::KAT_FAILED } else { rv::OK }, sink.len())
}

fn smoke(p: &mut impl Prims, files: &[impl AsRef<Path>], sink: &mut Sink) -> Result<(), u32> {
    let (key, iv, aad) = (&KAT_AESGCM_KEY[..], &KAT_AESGCM_IV[..], &KAT_AESGCM_AAD[..]);
    let mut ct = [0u8; KAT_AESGCM_PT.len()];
    let mut tag = [0u8; 16];
    sink.kat(c"AES-GCM-256", Vid::Static(c"SP800-38D-TC14"), || {
        let (rv, n) = p.gcm_encrypt(key, iv, aad, &KAT_AESGCM_PT, &mut ct, &mut tag);
        rv == rv::OK
            && n == KAT_AESGCM_CT_EXPECTED.len()
            && ct_diff(&ct, &KAT_AESGCM_CT_EXPECTED) == 0
            && ct_diff(&tag, &KAT_AESGCM_TAG_EXPECTED) == 0
    })?;
    ct.zeroize();
    tag.zeroize();

    // the round trip on a fresh encryption (its return code unchecked, as in C), and the same
    // tag with one bit flipped, which must be refused (FIPS 140-3 §7.10.4)
    let mut pt = [0u8; KAT_AESGCM_PT.len()];
    let mut bad_tag = [0u8; 16];
    let pass = sink.kat(
        c"AES-GCM-256-decrypt",
        Vid::Static(c"SP800-38D-TC14+tamper"),
        || {
            let (_, n) = p.gcm_encrypt(key, iv, aad, &KAT_AESGCM_PT, &mut ct, &mut tag);
            let ct = &ct[..n.min(ct.len())];
            let (good, m) = p.gcm_decrypt(key, iv, aad, ct, &tag, &mut pt);
            let decrypt_ok =
                good == rv::OK && m == KAT_AESGCM_PT.len() && ct_diff(&pt, &KAT_AESGCM_PT) == 0;
            bad_tag = tag;
            bad_tag[0] ^= 1;
            let (bad, _) = p.gcm_decrypt(key, iv, aad, ct, &bad_tag, &mut pt);
            decrypt_ok && bad == rv::ENCRYPTED_DATA_INVALID
        },
    )?;
    pt.zeroize();
    ct.zeroize();
    tag.zeroize();
    bad_tag.zeroize();
    if !pass {
        return Err(rv::KAT_FAILED);
    }

    let mut d = [0u8; 32];
    sink.kat(c"SHA-256", Vid::Static(c"FIPS180-4-B.1"), || {
        let (rv, n) = p.hash(SHA256, &KAT_SHA256_MSG, &mut d);
        rv == rv::OK && n == 32 && ct_diff(&d, &KAT_SHA256_EXPECTED) == 0
    })?;
    d.zeroize();

    let mut m = [0u8; 32];
    sink.kat(c"HMAC-SHA-256", Vid::Static(c"RFC4231-TC1"), || {
        let (rv, n) = p.hmac(SHA256, &KAT_HMAC_KEY, &KAT_HMAC_MSG, &mut m);
        rv == rv::OK && n == 32 && ct_diff(&m, &KAT_HMAC_EXPECTED) == 0
    })?;
    m.zeroize();

    // smoke only: the output is not compared (SP 800-132's minimum lengths, under FIPS)
    let mut kdf = [0u8; 32];
    let pass = sink.kat(c"PBKDF2-HMAC-SHA-256", Vid::Static(c"smoke-200k"), || {
        p.pbkdf2(
            SHA256,
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsalt",
            200_000,
            &mut kdf,
        ) == rv::OK
    })?;
    kdf.zeroize();
    if !pass {
        return Err(rv::KAT_FAILED);
    }

    // the CAVP file, when one opens; a missing file is no failure
    if let Some(mut f) = files.iter().find_map(|f| File::open(f).ok()) {
        let mut data = Vec::new();
        // a read error ends the file, as fgets returning NULL does
        let _ = f.read_to_end(&mut data);
        let mut file = cavp::Reader::new(&data);
        while let Some(v) = file.next_vector() {
            // the identifier needs one of the KAT_MAX pool slots
            if sink.full() || sink.len() >= KAT_MAX {
                break;
            }
            let ok = sink.kat(c"SHA-256-CAVP", Vid::Cavp(v.bits), || {
                // DIV-047: a length past C's 256-byte buffer is a failed vector
                let Some(msg) = v.msg else { return false };
                let mut got = [0u8; 32];
                let (rv, n) = p.hash(SHA256, msg, &mut got);
                let ok = rv == rv::OK && n == 32 && ct_diff(&got, v.md) == 0;
                got.zeroize();
                ok
            })?;
            if !ok {
                return Err(rv::KAT_FAILED);
            }
        }
    }

    // two draws must differ (FIPS 140-3 §7.10.4)
    let (mut r1, mut r2) = ([0u8; 32], [0u8; 32]);
    sink.kat(c"CTR_DRBG-AES-256", Vid::Static(c"stuck-check"), || {
        let a = p.rng(&mut r1);
        let b = p.rng(&mut r2);
        a == rv::OK && b == rv::OK && ct_diff(&r1, &r2) != 0
    })?;
    r1.zeroize();
    r2.zeroize();
    Ok(())
}
