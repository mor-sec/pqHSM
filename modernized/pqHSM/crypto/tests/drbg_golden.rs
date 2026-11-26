//! Replays `tests/golden/drbg.tsv`, written by running the legacy `src/fhsm_drbg.c`
//! (`legacy/hybrid/golden/gen_drbg.c`; regenerate with `legacy/hybrid/golden/regen_crypto.sh`).
//! The scripted source here mirrors that generator's seams byte for byte: the same xorshift
//! stream, injections, clock and conditioner failures. The ERROR state is the one thing C keeps
//! outside the DRBG; it is kept here as `fhsm_drbg_bytes` checks it.

use std::cell::RefCell;
use std::rc::Rc;

use pqhsm_crypto::drbg::{Drbg, Error, Source};

const FNV_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

fn fnv(h: u64, bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .fold(h, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

#[derive(Clone, Copy)]
enum Inj {
    None,
    Rep(u8, usize),
    Apt(u8, usize),
    DupFirst,
    DupNext,
    DupLast,
    Same,
}

struct Script {
    prng: u64,
    clock: u64,
    cond_fail: bool,
    inj: Inj,
    fail_rand_in: u32,
    prev: Vec<u8>,
    chunks: Vec<usize>,
    adds: u32,
    gen_sum: u64,
}

impl Script {
    fn byte(&mut self) -> u8 {
        let g = &mut self.prng;
        *g ^= *g >> 12;
        *g ^= *g << 25;
        *g ^= *g >> 27;
        (g.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
    }

    fn byte_not(&mut self, b: u8) -> u8 {
        let x = self.byte();
        if x == b { x ^ 1 } else { x }
    }
}

struct Scripted(Rc<RefCell<Script>>);

impl Source for Scripted {
    fn generate(&mut self, buf: &mut [u8]) -> bool {
        let s = &mut *self.0.borrow_mut();
        s.chunks.push(buf.len());
        if s.fail_rand_in > 0 {
            s.fail_rand_in -= 1;
            if s.fail_rand_in == 0 {
                return false;
            }
        }
        let n = buf.len();
        for b in buf.iter_mut() {
            *b = s.byte();
        }
        match s.inj {
            Inj::Rep(b, k) => {
                buf[..k.min(n)].fill(b);
                if k < n {
                    buf[k] = s.byte_not(b);
                }
            }
            Inj::Apt(b, k) => {
                for (i, x) in buf.iter_mut().enumerate().take(512) {
                    *x = if i % 2 == 0 && i / 2 < k {
                        b
                    } else {
                        s.byte_not(b)
                    };
                }
            }
            Inj::DupFirst if n >= 16 && s.prev.len() >= 16 => {
                buf[..16].copy_from_slice(&s.prev[..16]);
            }
            Inj::DupNext if n >= 32 => buf.copy_within(..16, 16),
            Inj::DupLast if n >= 16 && s.prev.len() >= 16 => {
                let last = (s.prev.len() / 16 - 1) * 16;
                buf[..16].copy_from_slice(&s.prev[last..last + 16]);
            }
            Inj::Same if n <= s.prev.len() => buf.copy_from_slice(&s.prev[..n]),
            _ => {}
        }
        s.inj = Inj::None;
        s.gen_sum = fnv(s.gen_sum, buf);
        s.prev = buf.to_vec();
        true
    }

    fn seed(&mut self) -> (u32, bool) {
        let s = &mut *self.0.borrow_mut();
        if !s.cond_fail {
            s.adds += 1;
        }
        // C's value: getrandom filled the pool. OsSource reports every source (DIV-043, its own test).
        (1, !s.cond_fail)
    }

    fn now(&self) -> u64 {
        self.0.borrow().clock
    }
}

/// Rows the decided divergences change, keyed by scenario and op number within it: the C row is
/// replaced by this one. Every sum here comes from the C rows (`gen=` is what C's generator
/// produced, `sum=` what the caller got), except `gen=*`, which C never produced.
const RUST_ONLY: &[(&str, usize, &str)] = &[
    // DIV-044: a failed first seed inside a request latches ERROR, as a failed reseed does.
    (
        "lazy_fail",
        1,
        "rv=0x6;chunks=;adds=0;sum=dd3fc6b86d146065;latch=DRBG reseed failed",
    ),
    ("lazy_fail", 4, "rv=0x6;chunks=;adds=0;sum=dd3fc6b86d146065"),
    (
        "lazy_fail",
        5,
        "emitted=0,reseeds=0,rct=0,apt=0,crngt=0,src=1",
    ),
    // DIV-042: a generator failure cleanses the request's output, the failed chunk included.
    (
        "rand_fail_mid",
        2,
        "rv=0x80000008;chunks=65536,65536;adds=0;sum=d21499b68e817825;gen=1338e68e5654d996;latch=RAND_bytes failed",
    ),
    // DIV-032: the 19th occurrence of the window's first byte fails (C failed at the 52nd).
    (
        "apt_19",
        2,
        "rv=0x80000008;chunks=512;adds=0;sum=7da144b97d054b25;gen=167becdcbd321d08;latch=DRBG APT alarm",
    ),
    ("apt_19", 3, "emitted=0,reseeds=1,rct=0,apt=1,crngt=0,src=1"),
    (
        "apt_51",
        2,
        "rv=0x80000008;chunks=512;adds=0;sum=7da144b97d054b25;gen=ddca9f14f9e55707;latch=DRBG APT alarm",
    ),
    ("apt_51", 3, "emitted=0,reseeds=1,rct=0,apt=1,crngt=0,src=1"),
    // DIV-037: each block against the one before it, not each request's first block against the
    // previous request's first.
    (
        "crngt_first_block",
        3,
        "rv=0x0;chunks=64;adds=0;sum=7d97b284cdf6757b",
    ),
    (
        "crngt_first_block",
        4,
        "emitted=128,reseeds=1,rct=0,apt=0,crngt=0,src=1",
    ),
    (
        "crngt_within_request",
        2,
        "rv=0x80000008;chunks=64;adds=0;sum=b9b23f3a46fd0825;gen=669d561cc6c75bfe;latch=DRBG CRNGT repeated block",
    ),
    (
        "crngt_within_request",
        3,
        "emitted=0,reseeds=1,rct=0,apt=0,crngt=1,src=1",
    ),
    (
        "crngt_last_block",
        3,
        "rv=0x80000008;chunks=64;adds=0;sum=b9b23f3a46fd0825;gen=3b2f6d66dae03958;latch=DRBG CRNGT repeated block",
    ),
    (
        "crngt_last_block",
        4,
        "emitted=64,reseeds=1,rct=0,apt=0,crngt=1,src=1",
    ),
    // DIV-033: a failed periodic reseed latches ERROR; nothing of the request is returned.
    (
        "cond_fail_periodic",
        3,
        "rv=0x6;chunks=;adds=0;sum=cca597c7f7aad3a5;latch=DRBG reseed failed",
    ),
    (
        "cond_fail_periodic",
        4,
        "rv=0x6;chunks=;adds=0;sum=cca597c7f7aad3a5",
    ),
    (
        "cond_fail_periodic",
        5,
        "emitted=0,reseeds=1,rct=0,apt=0,crngt=0,src=1",
    ),
    (
        "cond_fail_periodic_mid",
        3,
        "rv=0x6;chunks=65536;adds=0;sum=476008841d717825;gen=*;latch=DRBG reseed failed",
    ),
    (
        "cond_fail_periodic_mid",
        4,
        "emitted=1065536,reseeds=1,rct=0,apt=0,crngt=0,src=1",
    ),
];

struct Run {
    script: Rc<RefCell<Script>>,
    drbg: Drbg<Scripted>,
    halted: bool,
}

impl Run {
    fn new() -> Self {
        let script = Rc::new(RefCell::new(Script {
            prng: 0x9E37_79B9_7F4A_7C15,
            clock: 1_000_000,
            cond_fail: false,
            inj: Inj::None,
            fail_rand_in: 0,
            prev: Vec::new(),
            chunks: Vec::new(),
            adds: 0,
            gen_sum: FNV_BASIS,
        }));
        let drbg = Drbg::new(Scripted(script.clone()));
        Self {
            script,
            drbg,
            halted: false,
        }
    }

    /// `rv` and the latch reason, latching as `fhsm_drbg_*` does.
    fn result(&mut self, r: Result<(), Error>) -> (u32, Option<String>) {
        let Err(e) = r else {
            return (0, None);
        };
        let reason = e.latch_reason().map(|r| r.to_str().unwrap().to_owned());
        self.halted |= reason.is_some();
        (e.rv(), reason)
    }

    fn set(&self, f: impl FnOnce(&mut Script)) -> String {
        f(&mut self.script.borrow_mut());
        "ok".to_owned()
    }

    fn op(&mut self, op: &str) -> String {
        {
            let s = &mut *self.script.borrow_mut();
            s.chunks.clear();
            s.adds = 0;
            s.gen_sum = FNV_BASIS;
        }
        let (name, arg) = op.split_once(':').unwrap_or((op, ""));
        match name {
            "clock" => self.set(|s| s.clock += arg.parse::<u64>().unwrap()),
            "rep" | "apt" => {
                let (b, k) = arg.split_once(':').unwrap();
                let (b, k) = (b.parse().unwrap(), k.parse().unwrap());
                let inj = if name == "rep" {
                    Inj::Rep(b, k)
                } else {
                    Inj::Apt(b, k)
                };
                self.set(|s| s.inj = inj)
            }
            "dupfirst" => self.set(|s| s.inj = Inj::DupFirst),
            "dupnext" => self.set(|s| s.inj = Inj::DupNext),
            "duplast" => self.set(|s| s.inj = Inj::DupLast),
            "same" => self.set(|s| s.inj = Inj::Same),
            "fail_rand" => self.set(|s| s.fail_rand_in = arg.parse().unwrap()),
            "fail_cond" => self.set(|s| s.cond_fail = true),
            "ok_cond" => self.set(|s| s.cond_fail = false),
            "state_error" => {
                self.halted = true;
                "ok".to_owned()
            }
            "init" | "reseed" => {
                let r = if name == "init" {
                    self.drbg.init()
                } else {
                    self.drbg.reseed()
                };
                let (rv, _) = self.result(r);
                format!("rv={rv:#x};adds={}", self.script.borrow().adds)
            }
            "stats" => {
                let s = self.drbg.stats();
                format!(
                    "emitted={},reseeds={},rct={},apt={},crngt={},src={}",
                    s.bytes_emitted,
                    s.reseeds,
                    s.rct_failures,
                    s.apt_failures,
                    s.crngt_failures,
                    s.entropy_sources_active
                )
            }
            "bytes_null" => {
                let e = if self.halted {
                    Error::Halted
                } else {
                    Error::Arguments
                };
                format!("rv={:#x}", e.rv())
            }
            "bytes" => {
                let mut buf = vec![0xEE; arg.parse().unwrap()];
                let r = if self.halted {
                    Err(Error::Halted)
                } else {
                    self.drbg.bytes(&mut buf)
                };
                let (rv, reason) = self.result(r);
                let s = self.script.borrow();
                let sum = fnv(FNV_BASIS, &buf);
                let chunks: Vec<_> = s.chunks.iter().map(usize::to_string).collect();
                let mut line = format!(
                    "rv={rv:#x};chunks={};adds={};sum={sum:016x}",
                    chunks.join(","),
                    s.adds
                );
                if s.gen_sum != sum && !s.chunks.is_empty() {
                    line += &format!(";gen={:016x}", s.gen_sum);
                }
                if let Some(r) = reason {
                    line += &format!(";latch={r}");
                }
                line
            }
            _ => panic!("unknown op {op}"),
        }
    }
}

/// The row without its `gen=` field, for the one row whose `gen` C never produced.
fn without_gen(row: &str) -> String {
    row.split(';')
        .filter(|f| !f.starts_with("gen="))
        .collect::<Vec<_>>()
        .join(";")
}

#[test]
fn drbg_goldens() {
    let tsv = include_str!("golden/drbg.tsv");
    let (mut rows, mut runs) = (0, 0);
    let mut current: Option<(&str, Run, usize)> = None;
    for line in tsv.lines().filter(|l| !l.starts_with('#')) {
        let mut f = line.splitn(3, '\t');
        let (sc, op, c_row) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
        if current.as_ref().is_none_or(|(name, _, _)| *name != sc) {
            current = Some((sc, Run::new(), 0));
            runs += 1;
        }
        let (_, run, i) = current.as_mut().unwrap();
        let got = run.op(op);
        let want = RUST_ONLY
            .iter()
            .find(|(s, n, _)| *s == sc && n == i)
            .map_or(c_row, |(_, _, r)| r);
        if want.contains(";gen=*") {
            assert_eq!(without_gen(&got), without_gen(want), "{sc} #{i} {op}");
        } else {
            assert_eq!(got, want, "{sc} #{i} {op}");
        }
        *i += 1;
        rows += 1;
    }
    assert_eq!(
        (runs, rows),
        (25, 127),
        "drbg.tsv changed: update the counts"
    );
    println!(
        "drbg golden: {rows} rows ok ({runs} scenarios, {} Rust-only)",
        RUST_ONLY.len()
    );
}
