//! The KATs against the legacy C (`tests-support/golden/gen_kat.c`, which ran
//! `kat/fhsm_kat_vectors.c` and `kat/cavp_extended.c`): every vector table byte for byte, and
//! every scenario's report and primitive-call trace. The primitives are faked as gen_kat faked
//! them: real results, with one call failed, its first output byte flipped, a tag refusal
//! accepted, or the DRBG stuck. The extended set runs for real.
//!
//! DIV-046: where C returned OK with a failed record, KAT_FAILED is expected instead.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};

use pqhsm_crypto::{prim, rv};
use pqhsm_selftest::kat::{self, KAT_MAX, Prims, Sink, Vid, vectors};

fn golden(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name)
}

fn rows(name: &str) -> Vec<String> {
    std::fs::read_to_string(golden(name))
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

fn hex(b: &[u8]) -> String {
    if b.is_empty() {
        return "-".into();
    }
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn every_vector_table_is_the_c_one_byte_for_byte() {
    let ours: BTreeMap<&str, &[u8]> = vectors::ALL.iter().copied().collect();
    // the messages C passes to OpenSSL more than once, or as a named table
    let repeated = [
        ("evp:EVP_DigestUpdate#2", &vectors::ECDSA_RT_MSG[..]),
        ("evp:EVP_DigestUpdate#3", &vectors::ECDSA_RT_MSG),
        ("evp:EVP_DigestSign#8", &vectors::RSA_SELFTEST_MSG),
        ("evp:EVP_PKEY_encrypt#9", &vectors::RSA_SELFTEST_MSG),
        ("evp:EVP_DigestSign#10", &vectors::PQ_SIG_MSG),
        ("evp:EVP_DigestSign#11", &vectors::PQ_SIG_MSG),
    ];
    let rows = rows("kat_vectors.tsv");
    for row in &rows {
        let (name, bytes) = row.split_once('\t').unwrap();
        let mine = ours
            .get(name)
            .copied()
            .or_else(|| repeated.iter().find(|r| r.0 == name).map(|r| r.1))
            .unwrap_or_else(|| panic!("{name}: no Rust table"));
        assert_eq!(hex(mine), bytes, "{name}");
    }
    assert_eq!(
        rows.len(),
        ours.len() + repeated.len(),
        "a Rust table the C does not have"
    );
}

/// gen_kat's stubs: each call writes its trace line; `faults` maps a call number to its fault.
struct Fake {
    name: String,
    k: u32,
    faults: Vec<(u32, &'static str)>,
    trace: String,
}

impl Fake {
    fn call(&mut self, prim: &str) -> &'static str {
        self.k += 1;
        write!(self.trace, "{}\t{}\t{prim}\t", self.name, self.k).unwrap();
        self.faults
            .iter()
            .find(|f| f.0 == self.k)
            .map_or("", |f| f.1)
    }

    fn arg(&mut self, name: &str, b: &[u8]) {
        write!(self.trace, "{name}={};", hex(b)).unwrap();
    }

    fn done(&mut self, fault: &str, mut r: u32, out: &mut [u8]) -> u32 {
        if fault == "flip" && r == rv::OK && !out.is_empty() {
            out[0] ^= 1;
        }
        if fault == "accept" {
            r = rv::OK;
        }
        writeln!(self.trace, "\trv=0x{r:x}").unwrap();
        r
    }
}

impl Prims for Fake {
    fn gcm_encrypt(
        &mut self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct: &mut [u8],
        tag: &mut [u8; 16],
    ) -> (u32, usize) {
        let f = self.call("gcm_encrypt");
        self.arg("key", key);
        self.arg("iv", iv);
        self.arg("aad", aad);
        self.arg("pt", pt);
        write!(self.trace, "cap={}", ct.len()).unwrap();
        if f == "fail" {
            return (self.done(f, rv::FUNCTION_FAILED, &mut []), ct.len());
        }
        let r =
            prim::gcm_encrypt(key, iv, aad, pt, ct, tag).map_or(rv::FUNCTION_FAILED, |_| rv::OK);
        (self.done(f, r, &mut ct[..pt.len()]), pt.len())
    }

    fn gcm_decrypt(
        &mut self,
        key: &[u8],
        iv: &[u8],
        aad: &[u8],
        ct: &[u8],
        tag: &[u8; 16],
        pt: &mut [u8],
    ) -> (u32, usize) {
        let f = self.call("gcm_decrypt");
        self.arg("key", key);
        self.arg("iv", iv);
        self.arg("aad", aad);
        self.arg("ct", ct);
        self.arg("tag", tag);
        write!(self.trace, "cap={}", pt.len()).unwrap();
        if f == "fail" {
            return (self.done(f, rv::FUNCTION_FAILED, &mut []), pt.len());
        }
        if prim::gcm_decrypt(key, iv, aad, ct, tag, pt).is_err() {
            return (self.done(f, rv::ENCRYPTED_DATA_INVALID, &mut []), pt.len());
        }
        (self.done(f, rv::OK, &mut pt[..ct.len()]), ct.len())
    }

    fn hash(&mut self, alg: u32, data: &[u8], out: &mut [u8]) -> (u32, usize) {
        let f = self.call("hash");
        write!(self.trace, "alg={alg};").unwrap();
        self.arg("data", data);
        write!(self.trace, "cap={}", out.len()).unwrap();
        if f == "fail" {
            return (self.done(f, rv::FUNCTION_FAILED, &mut []), out.len());
        }
        let n = prim::digest(alg, data, out).unwrap();
        (self.done(f, rv::OK, &mut out[..n]), n)
    }

    fn hmac(&mut self, alg: u32, key: &[u8], data: &[u8], mac: &mut [u8]) -> (u32, usize) {
        let f = self.call("hmac");
        write!(self.trace, "alg={alg};").unwrap();
        self.arg("key", key);
        self.arg("data", data);
        write!(self.trace, "cap={}", mac.len()).unwrap();
        if f == "fail" {
            return (self.done(f, rv::FUNCTION_FAILED, &mut []), mac.len());
        }
        let n = prim::hmac(alg, key, data, Some(mac)).unwrap();
        (self.done(f, rv::OK, &mut mac[..n]), n)
    }

    fn pbkdf2(&mut self, alg: u32, password: &[u8], salt: &[u8], iter: u32, out: &mut [u8]) -> u32 {
        let f = self.call("pbkdf2");
        write!(self.trace, "alg={alg};").unwrap();
        self.arg("password", password);
        self.arg("salt", salt);
        write!(self.trace, "iter={iter};len={}", out.len()).unwrap();
        if f == "fail" {
            return self.done(f, rv::FUNCTION_FAILED, &mut []);
        }
        // shortcut: the KAT never reads the output (smoke only), so 200 000 iterations are not
        // run per scenario; derive for real if a check of it is ever added
        self.done(f, rv::OK, out)
    }

    fn rng(&mut self, out: &mut [u8]) -> u32 {
        let f = self.call("rng");
        write!(self.trace, "n={}", out.len()).unwrap();
        match f {
            "fail" => self.done(f, rv::FUNCTION_FAILED, &mut []),
            "fixed" => {
                out.fill(0x42);
                self.done("", rv::OK, out)
            }
            // distinct per call, as two DRBG draws are
            _ => {
                out.fill(self.k as u8);
                self.done(f, rv::OK, out)
            }
        }
    }
}

/// One scenario as gen_kat's `run`: the summary line, the records, and the trace.
fn run(
    name: &str,
    cap: usize,
    files: [&Path; 2],
    faults: Vec<(u32, &'static str)>,
) -> (Vec<String>, String, u32) {
    let mut p = Fake {
        name: name.into(),
        k: 0,
        faults,
        trace: String::new(),
    };
    let mut sink = Sink::new(cap);
    let (r, count) = kat::run_all(&mut p, &files, &mut sink);
    let mut lines = vec![format!(
        "{name}\tcap={cap}\trv=0x{r:x};count={count};written={}",
        sink.recs.len()
    )];
    for (i, rec) in sink.recs.iter().enumerate() {
        let vid = match rec.vector_id {
            Vid::Static(v) => v.to_str().unwrap().to_owned(),
            Vid::Cavp(bits) => format!("CAVP-SHA256-Len{bits}"),
        };
        lines.push(format!(
            "{name}\t#{i}\t{}\t{vid}\t{}",
            rec.algorithm.to_str().unwrap(),
            u8::from(rec.passed)
        ));
    }
    (lines, p.trace, p.k)
}

/// name, cap, the two CAVP paths, the faults, whether kat.tsv has its records.
type Scenario = (String, usize, [PathBuf; 2], Vec<(u32, &'static str)>, bool);

const FIXTURES: [&str; 20] = [
    "fail_md",
    "stale_msg",
    "bad_hex",
    "short_md",
    "space_hex",
    "sign_hex",
    "prefix_hex",
    "odd_bits",
    "neg_len",
    "md_first",
    "twice",
    "incomplete",
    "no_newline",
    "crlf",
    "skipped",
    "long_msg",
    "split_md",
    "max_len",
    "many",
    "empty",
];

/// C's report for one scenario, with DIV-046 applied: OK with a failed record is KAT_FAILED.
fn expected(c: &[String], div046: &mut Vec<String>) -> Vec<String> {
    let mut out = c.to_vec();
    let failed = c[1..].iter().any(|l| l.ends_with("\t0"));
    if failed && c[0].contains("rv=0x0;") {
        div046.push(c[0].split('\t').next().unwrap().to_owned());
        out[0] = c[0].replace("rv=0x0;", &format!("rv=0x{:x};", rv::KAT_FAILED));
    }
    out
}

#[test]
fn every_scenario_reports_and_calls_as_the_c_did() {
    let tsv = rows("kat.tsv");
    let mut by_name: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for l in &tsv {
        by_name
            .entry(l.split('\t').next().unwrap())
            .or_default()
            .push(l.clone());
    }
    let none = Path::new("/nonexistent/sha2_256_short.rsp");
    let real = golden("kat/sha2_256_short.rsp");
    let opt = golden("kat/opt.rsp");

    let mut scenarios: Vec<Scenario> = Vec::new();
    let std_files = || [none.to_path_buf(), real.clone()];
    let (_, _, calls) = run("base", KAT_MAX, [none, &real], vec![]);
    let base_trace: Vec<String> = rows("kat_trace.tsv")
        .into_iter()
        .filter(|l| l.starts_with("base\t"))
        .collect();
    scenarios.push(("base".into(), KAT_MAX, std_files(), vec![], true));
    for k in 1..=calls {
        let prim = base_trace[k as usize - 1]
            .split('\t')
            .nth(2)
            .unwrap()
            .to_owned();
        for mode in ["fail", "flip", "accept"] {
            if mode == "accept" && prim != "gcm_decrypt" {
                continue;
            }
            scenarios.push((
                format!("{mode}_{k}"),
                KAT_MAX,
                std_files(),
                vec![(k, mode)],
                true,
            ));
        }
    }
    scenarios.push((
        "stuck_rng".into(),
        KAT_MAX,
        std_files(),
        vec![(calls - 1, "fixed"), (calls, "fixed")],
        true,
    ));
    for cap in 0..=KAT_MAX {
        scenarios.push((format!("cap_{cap}"), cap, std_files(), vec![], false));
    }
    scenarios.push((
        "rsp_opt_preferred".into(),
        KAT_MAX,
        [opt.clone(), real.clone()],
        vec![],
        true,
    ));
    scenarios.push((
        "rsp_opt_only".into(),
        KAT_MAX,
        [opt.clone(), none.to_path_buf()],
        vec![],
        true,
    ));
    scenarios.push((
        "rsp_none".into(),
        KAT_MAX,
        [none.to_path_buf(), none.to_path_buf()],
        vec![],
        true,
    ));
    for fx in FIXTURES {
        let f = golden(&format!("kat/{fx}.rsp"));
        scenarios.push((
            format!("rsp_{fx}"),
            KAT_MAX,
            [none.to_path_buf(), f],
            vec![],
            true,
        ));
    }
    scenarios.push((
        "rsp_many_cap200".into(),
        200,
        [none.to_path_buf(), golden("kat/many.rsp")],
        vec![],
        true,
    ));

    // the scenarios are independent: run them on every core
    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = scenarios
            .iter()
            .map(|(name, cap, files, faults, _)| {
                s.spawn(move || run(name, *cap, [&files[0], &files[1]], faults.clone()))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    let mut trace = String::new();
    let mut div046 = Vec::new();
    for ((name, _, _, _, records), (lines, t, _)) in scenarios.iter().zip(&results) {
        let c = by_name
            .remove(name.as_str())
            .unwrap_or_else(|| panic!("{name}: not in kat.tsv"));
        let want = expected(&c, &mut div046);
        let got = if *records { &lines[..] } else { &lines[..1] };
        assert_eq!(got, &want[..], "{name}");
        trace.push_str(t);
    }
    // null_out and null_count are the C ABI's (tests/kat_abi.rs)
    let left: Vec<&str> = by_name.keys().copied().collect();
    assert_eq!(left, ["null_count", "null_out"], "scenarios not replayed");

    let want_trace: Vec<String> = rows("kat_trace.tsv")
        .into_iter()
        .filter(|l| !l.starts_with("null_"))
        .collect();
    let got_trace: Vec<&str> = trace.lines().collect();
    assert_eq!(got_trace.len(), want_trace.len(), "trace lines");
    for (g, w) in got_trace.iter().zip(&want_trace) {
        assert_eq!(g, w);
    }

    // where C returned OK with a failed record (DIV-046); a flipped DRBG draw still differs
    let div046: Vec<&str> = div046.iter().map(String::as_str).collect();
    assert_eq!(
        div046,
        [
            "fail_1",
            "flip_1",
            "fail_5",
            "flip_5",
            "fail_6",
            "flip_6",
            "fail_17",
            "fail_18",
            "stuck_rng"
        ]
    );
}

/// DIV-047: a `Len` past C's 256-byte message buffer, or one that makes the length negative,
/// is a failed vector (C hashed past the end of its buffer).
#[test]
fn a_length_past_the_message_buffer_is_a_failed_vector_div047() {
    let md = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    for len in ["2056", "-15"] {
        let dir = std::env::temp_dir().join(format!("pqhsm-div047-{}-{len}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("sha2_256_short.rsp");
        std::fs::write(&f, format!("Len = {len}\nMsg = 00\nMD = {md}\n")).unwrap();
        let (lines, _, _) = run("div047", KAT_MAX, [Path::new("/nonexistent"), &f], vec![]);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            lines[0],
            format!(
                "div047\tcap=64\trv=0x{:x};count=6;written=6",
                rv::KAT_FAILED
            )
        );
        assert_eq!(
            lines[6],
            format!("div047\t#5\tSHA-256-CAVP\tCAVP-SHA256-Len{len}\t0")
        );
    }
}
