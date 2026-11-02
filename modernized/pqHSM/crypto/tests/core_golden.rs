//! Replays `tests/golden/core.tsv`, recorded from the legacy `src/fhsm_crypto.c` by
//! `tests-support/golden/gen_core.c`:
//!
//! - the lifecycle scenarios through [`Core`] on a [`Platform`] scripted as gen_core's stubs and
//!   `--wrap` seams are, its stderr against `core/<scenario>.stderr`;
//! - the primitives through the C ABI, on OpenSSL's default provider as in the recording, with
//!   the module state defined here.
//!
//! The recording is the C build with the bypass variables honoured, so the lifecycle runs as a
//! `dev-bypass` build. Rows that differ on purpose are listed in RUST_ONLY with their DIV.

use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, c_char, c_int};
use std::sync::atomic::{AtomicI32, Ordering};

use pqhsm_crypto::lifecycle::{Core, Platform};
use pqhsm_crypto::rv;

const GOLDEN: &str = include_str!("golden/core.tsv");

/// (scenario, op index, the Rust result): DIV-035, init after finalize runs the self-tests again.
const RUST_ONLY: [(&str, usize, &str); 2] = [
    (
        "fips_ok",
        6,
        "rv=0x0;trace=integrity,load:fips,load:base,fips_props:1,drbg_init,kat:64",
    ),
    (
        "dev_ok",
        4,
        "rv=0x0;trace=integrity,fips_props:0,load:default,drbg_init,kat:64",
    ),
];
/// Scenarios whose second run prints the first run's stderr again (DIV-035).
const STDERR_TWICE: [&str; 1] = ["dev_ok"];
/// Ops not replayed: `fhsm_rng_bytes` is `fhsm_drbg_bytes`, whose own goldens are drbg.tsv, and a
/// RAND_status failure cannot be injected into the real libcrypto here.
const NOT_REPLAYED: [(&str, usize); 5] =
    [("rng", 0), ("rng", 1), ("rng", 4), ("rng", 5), ("rng", 6)];

// ---- the lifecycle ------------------------------------------------------------------------

#[derive(Default)]
struct Script {
    trace: Vec<String>,
    latch: Option<String>,
    fail: HashSet<String>,
    env: HashMap<String, String>,
    err: String,
    kats: Vec<(&'static str, &'static str, bool)>,
}

impl Platform for Script {
    type Provider = String;

    fn integrity(&mut self) -> u32 {
        self.trace.push("integrity".into());
        if self.fail.contains("integrity") {
            rv::INTEGRITY_FAILED
        } else {
            rv::OK
        }
    }
    fn load(&mut self, name: &CStr) -> Option<String> {
        let name = name.to_str().unwrap().to_owned();
        self.trace.push(format!("load:{name}"));
        (!self.fail.contains(&name)).then_some(name)
    }
    fn unload(&mut self, provider: String) {
        self.trace.push(format!("unload:{provider}"));
    }
    fn enable_fips(&mut self, on: bool) -> bool {
        self.trace.push(format!("fips_props:{}", i32::from(on)));
        !(on && self.fail.contains("props"))
    }
    fn drbg_init(&mut self) -> u32 {
        self.trace.push("drbg_init".into());
        if self.fail.contains("drbg") {
            rv::RNG_FAILURE
        } else {
            rv::OK
        }
    }
    fn kats(&mut self) -> (u32, Vec<String>) {
        self.trace.push("kat:64".into());
        let fail = self.fail.contains("kat");
        self.kats = vec![
            ("AES-GCM-256", "gcm-tc1", true),
            ("HMAC-SHA-256", "rfc4231-tc1", !fail),
            ("SHA2-256", "abc", true),
        ];
        let failed = self
            .kats
            .iter()
            .filter(|k| !k.2)
            .map(|k| format!("{} / {}", k.0, k.1))
            .collect();
        (if fail { rv::KAT_FAILED } else { rv::OK }, failed)
    }
    fn forget_kats(&mut self) {
        self.kats.clear();
    }
    fn latch(&mut self, reason: &CStr) {
        self.latch = Some(reason.to_str().unwrap().to_owned());
    }
    fn var(&self, name: &str) -> Option<String> {
        self.env.get(name).cloned()
    }
    fn eprint(&mut self, text: &str) {
        self.err.push_str(text);
    }
    fn eprint_openssl_errors(&mut self) {} // the recording's load seam leaves OpenSSL's stack empty
}

unsafe extern "C" {
    fn fhsm_fips_mode() -> c_int;
}

fn lifecycle_op(core: &mut Core<Script>, op: &str) -> String {
    let p = core.platform();
    p.trace.clear();
    p.latch = None;
    let mut res = if let Some(kv) = op.strip_prefix("env:") {
        let (k, v) = kv.split_once('=').unwrap();
        p.env.insert(k.into(), v.into());
        "ok".to_owned()
    } else if let Some(what) = op.strip_prefix("fail:") {
        p.fail.insert(what.into());
        "ok".to_owned()
    } else {
        match op {
            "init" => format!("rv={:#x}", core.init()),
            "finalize" => {
                core.finalize();
                "ok".to_owned()
            }
            // SAFETY: no arguments
            "fips_mode" => unsafe { fhsm_fips_mode() }.to_string(),
            "kat_results" => {
                let k = &core.platform().kats;
                let mut s = format!("count={}", k.len());
                for (a, v, ok) in k {
                    s += &format!(";{a}/{v}/{}", i32::from(*ok));
                }
                s
            }
            _ => panic!("unknown lifecycle op {op}"),
        }
    };
    let p = core.platform();
    if !p.trace.is_empty() {
        res += &format!(";trace={}", p.trace.join(","));
    }
    if let Some(l) = &p.latch {
        res += &format!(";latch={l}");
    }
    res
}

/// C unloads NULL handles after a failure in dev mode; Rust holds none to unload.
fn without_null_unloads(c: &str) -> String {
    let s = c.replace(",unload:NULL", "");
    s.replace(";trace=unload:NULL", "")
}

// ---- the primitives -----------------------------------------------------------------------

static STATE: AtomicI32 = AtomicI32::new(2); // FHSM_STATE_INITIALIZED
/// The tests below share STATE, which the replay sets to ERROR for a while.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[unsafe(no_mangle)]
extern "C" fn fhsm_state_get() -> c_int {
    STATE.load(Ordering::SeqCst)
}

#[unsafe(no_mangle)]
extern "C" fn fhsm_state_latch_error(_reason: *const c_char) {
    STATE.store(4, Ordering::SeqCst);
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Slice {
    data: *const u8,
    len: usize,
}

fn sl(b: &[u8]) -> Slice {
    Slice {
        data: b.as_ptr(),
        len: b.len(),
    }
}

unsafe extern "C" {
    fn fhsm_hash_size(alg: c_int) -> usize;
    fn fhsm_hash_openssl_name(alg: c_int) -> *const c_char;
    fn fhsm_hash_oneshot(alg: c_int, data: Slice, out: *mut u8, out_len: *mut usize) -> u32;
    fn fhsm_hmac(alg: c_int, key: Slice, data: Slice, mac: *mut u8, mac_len: *mut usize) -> u32;
    fn fhsm_aes_gcm_encrypt(
        key: Slice,
        iv: Slice,
        aad: Slice,
        pt: Slice,
        ct: *mut u8,
        ct_len: *mut usize,
        tag: *mut u8,
    ) -> u32;
    fn fhsm_aes_gcm_decrypt(
        key: Slice,
        iv: Slice,
        aad: Slice,
        ct: Slice,
        tag: *const u8,
        pt: *mut u8,
        pt_len: *mut usize,
    ) -> u32;
    fn fhsm_pbkdf2(
        alg: c_int,
        pw: Slice,
        salt: Slice,
        iter: u32,
        out: *mut u8,
        out_len: usize,
    ) -> u32;
    fn fhsm_rng_reseed(personalization: Slice) -> u32;
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// gen_core.c's generated keys and IVs: base + 7i.
fn pattern(n: usize, base: u8) -> Vec<u8> {
    (0..n).map(|i| base.wrapping_add((7 * i) as u8)).collect()
}

/// C's atoi, for capacities written as "null" and "lnull".
fn atoi(s: &str) -> usize {
    s.parse().unwrap_or(0)
}

/// gen_core.c's prim(), through the C ABI.
fn prim_op(op: &str) -> String {
    if op == "state_error" {
        STATE.store(4, Ordering::SeqCst);
        return "ok".into();
    }
    let (name, args) = op.split_once(':').unwrap();
    let f: Vec<&str> = args.split(':').collect();
    let mut out = [0xEEu8; 512];
    // SAFETY: every pointer below is a live local with the length it is passed with, or null
    // where a row asks for NULL
    unsafe {
        match name {
            "size" => fhsm_hash_size(f[0].parse().unwrap()).to_string(),
            "name" => {
                let p = fhsm_hash_openssl_name(f[0].parse().unwrap());
                if p.is_null() {
                    "NULL".into()
                } else {
                    CStr::from_ptr(p).to_str().unwrap().into()
                }
            }
            "hash" => {
                let data = unhex(f[1]);
                let mut len = atoi(f[2]);
                let o = if f[2] == "null" {
                    std::ptr::null_mut()
                } else {
                    out.as_mut_ptr()
                };
                let l: *mut usize = if f[2] == "lnull" {
                    std::ptr::null_mut()
                } else {
                    &mut len
                };
                let r = fhsm_hash_oneshot(f[0].parse().unwrap(), sl(&data), o, l);
                format!(
                    "rv={r:#x};len={len};out={}",
                    if r == 0 {
                        hex(&out[..len])
                    } else {
                        String::new()
                    }
                )
            }
            "hmac" => {
                let (key, data) = (unhex(f[1]), unhex(f[2]));
                let null_mac = f[3] == "null";
                let mut len = if null_mac { 64 } else { atoi(f[3]) };
                let m = if null_mac {
                    std::ptr::null_mut()
                } else {
                    out.as_mut_ptr()
                };
                let r = fhsm_hmac(f[0].parse().unwrap(), sl(&key), sl(&data), m, &mut len);
                let shown = if r == 0 && !null_mac {
                    hex(&out[..len])
                } else {
                    String::new()
                };
                format!("rv={r:#x};len={len};mac={shown}")
            }
            "gcm_enc" => {
                let (kl, il): (usize, usize) = (f[0].parse().unwrap(), f[1].parse().unwrap());
                let (aad, pt) = (unhex(f[2]), unhex(f[3]));
                let (key, iv) = (pattern(64, 0x11), pattern(32, 0xA0));
                let mut ct = [0xEEu8; 300];
                let mut tag = [0xEEu8; 16];
                let mut len = atoi(f[4]);
                let l: *mut usize = if f[4] == "lnull" {
                    std::ptr::null_mut()
                } else {
                    &mut len
                };
                let t = if f[5] == "null" {
                    std::ptr::null_mut()
                } else {
                    tag.as_mut_ptr()
                };
                let r = fhsm_aes_gcm_encrypt(
                    sl(&key[..kl]),
                    sl(&iv[..il]),
                    sl(&aad),
                    sl(&pt),
                    ct.as_mut_ptr(),
                    l,
                    t,
                );
                let (c, tg) = if r == 0 {
                    (hex(&ct[..len]), hex(&tag))
                } else {
                    Default::default()
                };
                format!("rv={r:#x};len={len};ct={c};tag={tg}")
            }
            "gcm_dec" => {
                let (kl, il): (usize, usize) = (f[0].parse().unwrap(), f[1].parse().unwrap());
                let (mut aad, pt) = (unhex(f[2]), unhex(f[3]));
                let (md, cap) = (f[4], atoi(f[5]));
                let (key, iv) = (pattern(64, 0x11), pattern(32, 0xA0));
                let mut ct = [0xEEu8; 300];
                let mut tag = [0xEEu8; 16];
                let mut cl = ct.len();
                let ekl = if matches!(kl, 16 | 24 | 32) { kl } else { 32 };
                let erv = fhsm_aes_gcm_encrypt(
                    sl(&key[..ekl]),
                    sl(&iv[..12]),
                    sl(&aad),
                    sl(&pt),
                    ct.as_mut_ptr(),
                    &mut cl,
                    tag.as_mut_ptr(),
                );
                match md {
                    "tag" => tag[0] ^= 1,
                    "aad" if !aad.is_empty() => aad[0] ^= 1,
                    "ct" if cl > 0 => ct[0] ^= 1,
                    _ => {}
                }
                let mut plain = [0xEEu8; 300];
                let mut len = cap;
                let t = if md == "tagnull" {
                    std::ptr::null()
                } else {
                    tag.as_ptr()
                };
                let l: *mut usize = if md == "lnull" {
                    std::ptr::null_mut()
                } else {
                    &mut len
                };
                let r = fhsm_aes_gcm_decrypt(
                    sl(&key[..kl]),
                    sl(&iv[..il]),
                    sl(&aad),
                    sl(&ct[..cl]),
                    t,
                    plain.as_mut_ptr(),
                    l,
                );
                format!("erv={erv:#x};rv={r:#x};len={len};pt={}", hex(&plain[..cap]))
            }
            "pbkdf2" => {
                let (pw, salt) = (unhex(f[1]), unhex(f[2]));
                let ol = atoi(f[4]);
                let r = fhsm_pbkdf2(
                    f[0].parse().unwrap(),
                    sl(&pw),
                    sl(&salt),
                    f[3].parse().unwrap(),
                    out.as_mut_ptr(),
                    ol,
                );
                format!(
                    "rv={r:#x};out={}",
                    if r == 0 {
                        hex(&out[..ol])
                    } else {
                        String::new()
                    }
                )
            }
            "reseed" => {
                let p = pattern(atoi(f[0]), 0x30);
                format!("rv={:#x}", fhsm_rng_reseed(sl(&p)))
            }
            _ => panic!("unknown primitive op {op}"),
        }
    }
}

/// The trace a C row records for `fhsm_rng_reseed`; the real libcrypto has no trace.
fn without_trace(c: &str) -> &str {
    c.split(";trace=").next().unwrap()
}

#[test]
fn replays_the_c_goldens() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut scenarios: Vec<(&str, Vec<(&str, &str)>)> = Vec::new();
    for line in GOLDEN.lines().filter(|l| !l.starts_with('#')) {
        let mut f = line.splitn(3, '\t');
        let (sc, op, res) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
        match scenarios.last_mut() {
            Some((s, rows)) if *s == sc => rows.push((op, res)),
            _ => scenarios.push((sc, vec![(op, res)])),
        }
    }
    let (mut rows, mut rust_only, mut skipped) = (0, 0, 0);
    for (sc, ops) in &scenarios {
        let primitives = sc.starts_with("prims") || *sc == "rng";
        let mut core = Core::new(Script::default(), true);
        for (i, (op, c)) in ops.iter().enumerate() {
            if NOT_REPLAYED.contains(&(*sc, i)) {
                skipped += 1;
                continue;
            }
            let got = if primitives {
                prim_op(op)
            } else {
                lifecycle_op(&mut core, op)
            };
            let want = match RUST_ONLY.iter().find(|r| r.0 == *sc && r.1 == i) {
                Some(r) => {
                    rust_only += 1;
                    r.2.to_owned()
                }
                None if primitives => without_trace(c).to_owned(),
                None => without_null_unloads(c),
            };
            assert_eq!(got, want, "{sc} #{i} {op}");
            rows += 1;
        }
        if !primitives {
            let c_err = std::fs::read_to_string(format!(
                "{}/tests/golden/core/{sc}.stderr",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            let want = if STDERR_TWICE.contains(sc) {
                c_err.repeat(2)
            } else {
                c_err
            };
            assert_eq!(core.platform().err, want, "{sc} stderr");
        }
        STATE.store(2, Ordering::SeqCst);
    }
    assert_eq!((rows + skipped, rust_only, skipped), (162, 2, 5));
    println!(
        "{rows} rows ok ({} scenarios, {rust_only} Rust-only, {skipped} not replayed)",
        scenarios.len()
    );
}

/// Callers pass one buffer as input and output (`C_Digest(h, buf, n, buf, &len)`); OpenSSL reads
/// before it writes, so C gave the same result as with two buffers (slice 3 review H1).
#[test]
fn in_place_buffers_give_what_separate_ones_do() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (key, iv, aad) = (pattern(32, 0x11), pattern(12, 0xA0), pattern(5, 0x30));
    let data = pattern(64, 0x42);
    // SAFETY: every pointer below covers the length given with it
    unsafe {
        let mut want = [0u8; 32];
        let mut n = want.len();
        assert_eq!(
            fhsm_hash_oneshot(1, sl(&data), want.as_mut_ptr(), &mut n),
            rv::OK
        );
        let mut buf = data.clone();
        let mut n = buf.len();
        assert_eq!(
            fhsm_hash_oneshot(1, sl(&buf), buf.as_mut_ptr(), &mut n),
            rv::OK
        );
        assert_eq!((n, &buf[..32]), (32, &want[..]), "digest in place");

        let mut n = want.len();
        assert_eq!(
            fhsm_hmac(1, sl(&key), sl(&data), want.as_mut_ptr(), &mut n),
            rv::OK
        );
        let mut buf = data.clone();
        let mut n = buf.len();
        assert_eq!(
            fhsm_hmac(1, sl(&key), sl(&buf), buf.as_mut_ptr(), &mut n),
            rv::OK
        );
        assert_eq!((n, &buf[..32]), (32, &want[..]), "hmac in place");

        let (mut ct, mut tag) = (vec![0u8; 64], [0u8; 16]);
        let mut n = ct.len();
        let rv = fhsm_aes_gcm_encrypt(
            sl(&key),
            sl(&iv),
            sl(&aad),
            sl(&data),
            ct.as_mut_ptr(),
            &mut n,
            tag.as_mut_ptr(),
        );
        assert_eq!(rv, rv::OK);
        let (mut buf, mut tag2) = (data.clone(), [0u8; 16]);
        let mut n = buf.len();
        let rv = fhsm_aes_gcm_encrypt(
            sl(&key),
            sl(&iv),
            sl(&aad),
            sl(&buf),
            buf.as_mut_ptr(),
            &mut n,
            tag2.as_mut_ptr(),
        );
        assert_eq!((rv, &buf, tag2), (rv::OK, &ct, tag), "encrypt in place");

        let mut n = buf.len();
        let rv = fhsm_aes_gcm_decrypt(
            sl(&key),
            sl(&iv),
            sl(&aad),
            sl(&buf),
            tag.as_ptr(),
            buf.as_mut_ptr(),
            &mut n,
        );
        assert_eq!((rv, &buf), (rv::OK, &data), "decrypt in place");

        // a refused call leaves the output as it was
        let mut out = [0xEEu8; 32];
        let mut n = out.len();
        assert_eq!(
            fhsm_hash_oneshot(13, sl(&data), out.as_mut_ptr(), &mut n),
            rv::ARGUMENTS_BAD
        );
        assert_eq!(out, [0xEE; 32]);
    }
}
