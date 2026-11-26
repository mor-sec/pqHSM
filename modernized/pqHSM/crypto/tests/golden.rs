//! Phase 3 slice 1: replays `tests/golden/cases.tsv`, made by `legacy/hybrid/golden/gen_crypto.c`
//! from the legacy C, through the C ABI (feature `ffi`).
//!
//!   cargo test -p pqhsm-crypto --features ffi --test golden
//!   legacy/hybrid/golden/regen_crypto.sh          (regenerates the goldens from the C)
//!
//! Its own harness: the arena is created once per process, so each heap scenario runs in a child
//! (this binary again, with `PQHSM_HEAP_SCENARIO` set) and its stderr is compared byte for byte;
//! the conf rows set `FHSM_CONF` while the process has one thread. Run without CAP_IPC_LOCK, as
//! the goldens were made: the scenarios lower `RLIMIT_MEMLOCK`.

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};
use std::process::{Command, exit};
use std::ptr::{null, null_mut};

use pqhsm_crypto as _; // links the C ABI below

unsafe extern "C" {
    fn fhsm_conf_lookup(key: *const c_char, out: *mut c_char, outlen: usize) -> c_int;
    fn fhsm_conf_secure_heap_bytes() -> usize;
    fn fhsm_secure_heap_init() -> u32;
    fn fhsm_secure_malloc(n: usize) -> *mut c_void;
    fn fhsm_secure_zalloc(n: usize) -> *mut c_void;
    fn fhsm_secure_free(p: *mut c_void);
    fn fhsm_secure_heap_used() -> usize;
    fn fhsm_secure_heap_total() -> usize;
    fn fhsm_zeroize(p: *mut c_void, n: usize);
    fn fhsm_ct_memcmp(a: *const c_void, b: *const c_void, n: usize) -> c_int;
    // libcrypto, for the scenarios that create the arena before the module does
    fn CRYPTO_secure_malloc_init(size: usize, minsize: usize) -> c_int;
    fn CRYPTO_secure_allocated(p: *const c_void) -> c_int;
}

/// Rows where Rust deliberately differs: (case, op, Rust's result, why).
const RUST_ONLY: &[(&str, &str, &str, &str)] = &[(
    "heap_adopt_locked",
    "total",
    "1048576",
    "DIV-038: C reports an address-sized number for an adopted arena",
)];

struct Row {
    case: String,
    op: String,
    rv: String,
    kv: HashMap<String, String>,
}

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn rows() -> Vec<Row> {
    std::fs::read_to_string(golden().join("cases.tsv"))
        .expect("cases.tsv")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let mut f = l.split('\t');
            let (case, op, rv) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
            let kv = f
                .filter_map(|p| p.split_once('='))
                .map(|(k, v)| (k.into(), v.into()))
                .collect();
            Row {
                case: case.into(),
                op: op.into(),
                rv: rv.into(),
                kv,
            }
        })
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn main() {
    let rows = rows();
    if let Ok(name) = std::env::var("PQHSM_HEAP_SCENARIO") {
        exit(child(&name, &rows));
    }
    let mut fails = conf_rows(&rows);
    let mut scenarios = 0;
    for r in rows.iter().filter(|r| r.op == "env") {
        fails += parent(&r.case, &r.rv);
        scenarios += 1;
    }
    let n = rows.len();
    if fails > 0 {
        eprintln!("golden: {fails} mismatches in {n} rows");
        exit(1);
    }
    println!(
        "golden: {n} rows ok ({scenarios} heap scenarios, {} Rust-only)",
        RUST_ONLY.len()
    );
}

fn conf_rows(rows: &[Row]) -> usize {
    let mut fails = 0;
    for r in rows
        .iter()
        .filter(|r| r.op == "lookup" || r.op == "heap_bytes")
    {
        let path = golden().join("conf").join(format!("{}.conf", r.case));
        // SAFETY: the process has one thread here (harness = false, no child spawned yet)
        unsafe { std::env::set_var("FHSM_CONF", &path) };
        let (got, want) = if r.op == "heap_bytes" {
            // SAFETY: no arguments
            (
                unsafe { fhsm_conf_secure_heap_bytes() }.to_string(),
                r.rv.clone(),
            )
        } else {
            lookup(r)
        };
        if got != want {
            eprintln!("{} {}: got {got:?}, C {want:?}", r.case, r.op);
            fails += 1;
        }
    }
    fails
}

fn lookup(r: &Row) -> (String, String) {
    let key = (r.kv["key"] != "NULL").then(|| CString::new(unhex(&r.kv["key"])).unwrap());
    let outlen: usize = r.kv["outlen"].parse().unwrap();
    let null_out = r.kv.get("out").is_some_and(|o| o == "NULL");
    let mut buf = [0xAAu8; 64];
    let out = if null_out {
        null_mut()
    } else {
        buf.as_mut_ptr().cast()
    };
    // SAFETY: key is null or a C string; out is null or has 64 >= outlen bytes
    let rv = unsafe { fhsm_conf_lookup(key.as_ref().map_or(null(), |k| k.as_ptr()), out, outlen) };
    let mut got = rv.to_string();
    if rv == 1 {
        got += &format!(
            " out={}",
            hex(CStr::from_bytes_until_nul(&buf).unwrap().to_bytes())
        );
    } else if buf.iter().any(|&b| b != 0xAA) {
        got += " out=written (DIV-039: untouched on 0)";
    }
    let want = match r.kv.get("out") {
        Some(o) if o != "NULL" => format!("{} out={o}", r.rv),
        _ => r.rv.clone(),
    };
    (got, want)
}

fn parent(case: &str, env: &str) -> usize {
    let name = case.strip_prefix("heap_").unwrap();
    let conf = golden().join("heap").join(format!("{name}.conf"));
    let out = Command::new(std::env::current_exe().unwrap())
        .env("PQHSM_HEAP_SCENARIO", name)
        .env(
            "FHSM_CONF",
            if env == "empty" { PathBuf::new() } else { conf },
        )
        .output()
        .expect("spawn child");
    print!("{}", String::from_utf8_lossy(&out.stdout));
    let want = std::fs::read(golden().join("heap").join(format!("{name}.stderr"))).unwrap();
    let mut fails = usize::from(!out.status.success());
    if out.stderr != want {
        eprintln!(
            "{case}: stderr differs\n--- Rust\n{}--- C\n{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&want)
        );
        fails += 1;
    }
    fails
}

/// Runs one scenario's ops in order, as gen_crypto.c's run_op did; mismatches go to stdout.
fn child(name: &str, rows: &[Row]) -> i32 {
    let case = format!("heap_{name}");
    let mut held: Vec<*mut c_void> = Vec::new();
    let mut fails = 0;
    for r in rows.iter().filter(|r| r.case == case && r.op != "env") {
        let got = run_op(&r.op, &mut held);
        let want = match RUST_ONLY.iter().find(|x| x.0 == case && x.1 == r.op) {
            Some(&(_, _, rust, why)) => {
                if r.rv == rust {
                    println!(
                        "{case} {}: C now gives {rust:?} too; drop the RUST_ONLY row ({why})",
                        r.op
                    );
                    fails += 1;
                }
                rust.to_owned()
            }
            None => r.rv.clone(),
        };
        if got != want {
            println!("{case} {}: got {got:?}, want {want:?}", r.op);
            fails += 1;
        }
    }
    i32::from(fails > 0)
}

fn status_kb(field: &str) -> i64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines()
        .find_map(|l| l.strip_prefix(field))
        .and_then(|v| v.split_whitespace().next()?.parse().ok())
        .unwrap_or(-1)
}

fn soft_limit(res: libc::__rlimit_resource_t, v: u64) -> &'static str {
    let mut rl = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: rl is a valid in/out parameter
    let ok = unsafe {
        libc::getrlimit(res, &mut rl) == 0 && {
            rl.rlim_cur = v;
            libc::setrlimit(res, &rl) == 0
        }
    };
    if ok { "ok" } else { "err" }
}

fn run_op(op: &str, held: &mut Vec<*mut c_void>) -> String {
    let (verb, arg) = op.split_once(':').unwrap_or((op, ""));
    let n: usize = arg.parse().unwrap_or(0);
    // SAFETY: each call passes what the C ABI documents: sizes, pointers it returned, or
    // buffers of the stated length
    unsafe {
        match verb {
            "total" => fhsm_secure_heap_total().to_string(),
            "init" => format!("0x{:x}", fhsm_secure_heap_init()),
            "used" => fhsm_secure_heap_used().to_string(),
            "vmlck" => status_kb("VmLck:").to_string(),
            "malloc" | "zalloc" => {
                let z = verb == "zalloc";
                let p = if z {
                    fhsm_secure_zalloc(n)
                } else {
                    fhsm_secure_malloc(n)
                };
                if p.is_null() {
                    return "null".into();
                }
                held.push(p);
                let place = if CRYPTO_secure_allocated(p) != 0 {
                    "secure"
                } else {
                    "plain"
                };
                if !z {
                    return place.into();
                }
                let zero = std::slice::from_raw_parts(p.cast::<u8>(), n)
                    .iter()
                    .all(|&b| b == 0);
                format!("{place},{}", if zero { "zeroed" } else { "dirty" })
            }
            "free" => {
                fhsm_secure_free(held.pop().unwrap_or(null_mut()));
                "ok".into()
            }
            "free_null" => {
                fhsm_secure_free(null_mut());
                "ok".into()
            }
            "ct" => {
                let (a, b) = arg.split_once(':').unwrap();
                let (a, b) = (unhex(a), unhex(b));
                let (pa, pb) = if a.is_empty() {
                    (null(), null())
                } else {
                    (a.as_ptr().cast(), b.as_ptr().cast())
                };
                fhsm_ct_memcmp(pa, pb, a.len()).to_string()
            }
            "zeroize" => {
                let mut v = vec![0x5au8; n];
                fhsm_zeroize(v.as_mut_ptr().cast(), n);
                (if v.iter().all(|&b| b == 0) {
                    "zeroed"
                } else {
                    "dirty"
                })
                .into()
            }
            "zeroize_null" => {
                let mut b = [1u8, 2, 3, 4];
                fhsm_zeroize(null_mut(), 8);
                fhsm_zeroize(b.as_mut_ptr().cast(), 0);
                (if b == [1, 2, 3, 4] { "ok" } else { "touched" }).into()
            }
            "memlock" => soft_limit(libc::RLIMIT_MEMLOCK, n as u64).into(),
            "as_headroom" => {
                let lim = status_kb("VmSize:") as u64 * 1024 + n as u64;
                soft_limit(libc::RLIMIT_AS, lim).into()
            }
            "arena" => CRYPTO_secure_malloc_init(n, 32).to_string(),
            _ => panic!("unknown op {op}"),
        }
    }
}
