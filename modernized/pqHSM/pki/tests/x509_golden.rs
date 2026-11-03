//! `tests/golden/composite/x509.tsv` (tests-support/golden/gen_x509.c) replayed: every call the
//! generator made to the X.509 encoders, made again through the Rust C ABI with the same
//! arguments, the same signing and RNG callbacks and the same clock, each row formatted as the
//! C formatted it. Inputs C made (keys' public halves, AlgorithmIdentifiers, really-signed
//! requests, CA certificates, the CMS structures to verify) come from `x509_fixture.tsv`.
//!
//! As in the generator, `time()` is defined here: libcrypto's X509_gmtime_adj binds to it, so
//! every validity date is that of NOW.
#![cfg(feature = "ffi")]
#![allow(clippy::too_many_arguments)]

use std::collections::HashMap;
use std::ffi::{CString, c_char, c_int, c_long, c_void};
use std::fmt::Write;
use std::ptr::{null, null_mut};

use pqhsm_pki::ffi::*;

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/composite");
const ALG: c_int = 1;
const NOW: libc::time_t = 1_798_761_600; // 2027-01-01T00:00:00Z, as gen_x509.c
const RAW_PUB: usize = 1984;
const FUNCTION_FAILED: u32 = 0x06;
const ARGUMENTS_BAD: u32 = 0x07;
const BUFFER_TOO_SMALL: u32 = 0x150;

/// # Safety
/// `t` is NULL or a writable time_t, as time(2) takes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn time(t: *mut libc::time_t) -> libc::time_t {
    if !t.is_null() {
        // SAFETY: the caller's contract
        unsafe { *t = NOW };
    }
    NOW
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn sha256(b: &[u8]) -> [u8; 32] {
    let mut md = [0u8; 32];
    // SAFETY: b is readable, md is 32 bytes
    unsafe { openssl_sys::SHA256(b.as_ptr(), b.len(), md.as_mut_ptr()) };
    md
}

/// gen_x509.c's `fake_t` and `fake_sign`: SHA-256 of the to-be-signed bytes, stretched.
#[derive(Clone, Copy)]
struct Fake {
    len: usize,
    fail: u32,
    calls: u32,
    cap: usize,
}

const fn fake(len: usize) -> Fake {
    Fake {
        len,
        fail: 0,
        calls: 0,
        cap: 0,
    }
}

const fn failing(len: usize, fail: u32) -> Fake {
    Fake {
        len,
        fail,
        calls: 0,
        cap: 0,
    }
}

unsafe extern "C" fn fake_sign(
    ctx: *mut c_void,
    tbs: *const u8,
    n: usize,
    sig: *mut u8,
    sl: *mut usize,
) -> u32 {
    // SAFETY: ctx is a Fake; tbs has n bytes; sig has *sl writable bytes
    unsafe {
        let c = &mut *ctx.cast::<Fake>();
        c.calls += 1;
        c.cap = *sl;
        if c.fail != 0 {
            return c.fail;
        }
        let md = sha256(std::slice::from_raw_parts(tbs, n));
        for i in 0..c.len {
            *sig.add(i) = md[i % 32] ^ (i / 32) as u8;
        }
        *sl = c.len;
    }
    0
}

/// gen_x509.c's `rng`: 0 a pattern, 1 zeros, 2 ones, 3 fails.
unsafe extern "C" fn rng(ctx: *mut c_void, out: *mut u8, n: usize) -> u32 {
    // SAFETY: ctx is a c_int mode; out has n writable bytes
    unsafe {
        let mode = *ctx.cast::<c_int>();
        if mode == 3 {
            return FUNCTION_FAILED;
        }
        for i in 0..n {
            *out.add(i) = match mode {
                1 => 0,
                2 => 0xFF,
                _ => (i * 13 + 5) as u8,
            };
        }
    }
    0
}

const SIGN: fhsm_composite_sign_cb = Some(fake_sign);
const RNG: fhsm_composite_rng_cb = Some(rng);

struct Run {
    rows: Vec<String>,
    out: Vec<u8>,
    n: usize,
    s: Fake,
    fx: HashMap<String, Vec<u8>>,
}

impl Run {
    fn fx(&self, name: &str) -> Vec<u8> {
        self.fx[name].clone()
    }

    /// gen_x509.c's `row`, over the shared OUT buffer.
    fn row(&mut self, name: &str, rv: u32, len: usize, with_fake: bool) {
        let mut r = format!(
            "{name}\trv=0x{rv:x};len={len};head={};sha256=",
            hex(&self.out[..8])
        );
        if rv == 0 {
            r += &hex(&sha256(&self.out[..len]));
        }
        let (calls, cap) = if with_fake {
            (self.s.calls, self.s.cap)
        } else {
            (0, 0)
        };
        let _ = write!(r, ";calls={calls};cap={cap}");
        self.rows.push(r);
    }

    /// memset(OUT, 0xAA); n = cap; s = fk.
    fn fresh(&mut self, cap: usize, fk: Fake) {
        self.out.fill(0xAA);
        self.n = cap;
        self.s = fk;
    }

    fn ctx(&mut self) -> *mut c_void {
        (&raw mut self.s).cast()
    }

    fn signer(&self, kind: &str) -> fhsm_pki_signer_t {
        let (a, k) = (
            &self.fx[&format!("algid_{kind}")],
            &self.fx[&format!("spki_{kind}")],
        );
        fhsm_pki_signer_t {
            algid: a.as_ptr(),
            algid_len: a.len(),
            spki: k.as_ptr(),
            spki_len: k.len(),
            sign: SIGN,
            sign_ctx: null_mut(),
        }
    }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn cb(s: &[u8]) -> CString {
    CString::new(s).unwrap()
}

fn flip(b: &[u8], at: usize, x: u8, extra: usize) -> Vec<u8> {
    let mut v = b.to_vec();
    v.resize(b.len() + extra, 0);
    if at < b.len() {
        v[at] ^= x;
    }
    v
}

fn key_cases(t: &mut Run) {
    let (public, private) = (t.fx("pub"), t.fx("priv"));
    let rp = |t: &mut Run, name: &str, alg: c_int, p: *const u8, pn: usize, cap: usize| {
        t.fresh(cap, t.s);
        // SAFETY: every pointer is NULL or covers its length
        let r = unsafe { fhsm_composite_raw_pub(alg, p, pn, t.out.as_mut_ptr(), &mut t.n) };
        let n = t.n;
        t.row(&format!("raw_pub:{name}"), r, n, false);
    };
    let pp = public.as_ptr();
    rp(t, "alg0", 0, pp, public.len(), 4096);
    rp(t, "null_pub", ALG, null(), public.len(), 4096);
    rp(t, "short_blob", ALG, pp, 9, 4096);
    rp(t, "short_blob_cap_short", ALG, pp, 9, 10);
    let b = flip(&public, 5, 3, 0);
    rp(t, "other_alg", ALG, b.as_ptr(), public.len(), 4096);
    let b = flip(&public, 8, 0xFF, 0);
    rp(t, "bad_pq_der", ALG, b.as_ptr(), public.len(), 4096);
    let b = flip(&public, public.len() - 40, 0xFF, 0);
    rp(t, "bad_trad_der", ALG, b.as_ptr(), public.len(), 4096);
    rp(t, "priv_as_pub", ALG, private.as_ptr(), private.len(), 4096);
    rp(t, "cap_0", ALG, pp, public.len(), 0);
    rp(t, "cap_short", ALG, pp, public.len(), RAW_PUB - 1);
    rp(t, "cap_exact", ALG, pp, public.len(), RAW_PUB);
    rp(t, "cap_more", ALG, pp, public.len(), 4096);
    t.n = 4096;
    // SAFETY: NULL outputs are refused before anything is written
    unsafe {
        let r = fhsm_composite_raw_pub(ALG, pp, public.len(), null_mut(), &mut t.n);
        let n = t.n;
        t.row("raw_pub:null_out", r, n, false);
        let r = fhsm_composite_raw_pub(ALG, pp, public.len(), t.out.as_mut_ptr(), null_mut());
        t.row("raw_pub:null_out_len", r, 0, false);
    }

    let sp = |t: &mut Run, name: &str, alg: c_int, p: *const u8, pn: usize, cap: usize| {
        t.fresh(cap, t.s);
        // SAFETY: as rp
        let r = unsafe { fhsm_composite_spki(alg, p, pn, t.out.as_mut_ptr(), &mut t.n) };
        let n = t.n;
        t.row(&format!("spki:{name}"), r, n, false);
    };
    sp(t, "alg0", 0, pp, public.len(), 4096);
    sp(t, "null_pub", ALG, null(), public.len(), 4096);
    sp(t, "short_blob", ALG, pp, 9, 4096);
    sp(t, "cap_0", ALG, pp, public.len(), 0);
    sp(t, "cap_short", ALG, pp, public.len(), 2000);
    sp(t, "cap_exact", ALG, pp, public.len(), 2001);
    sp(t, "cap_more", ALG, pp, public.len(), 4096);
    t.n = 4096;
    // SAFETY: as above
    unsafe {
        let r = fhsm_composite_spki(ALG, pp, public.len(), null_mut(), &mut t.n);
        let n = t.n;
        t.row("spki:null_out", r, n, false);
        let r = fhsm_composite_spki(ALG, pp, public.len(), t.out.as_mut_ptr(), null_mut());
        t.row("spki:null_out_len", r, 0, false);

        let (mut d, mut n) = (null(), 0);
        let r = fhsm_composite_algid(ALG, &mut d, &mut n);
        t.rows.push(format!(
            "algid:ok\trv=0x{r:x};der={}",
            hex(std::slice::from_raw_parts(d, n))
        ));
        t.rows.push(format!(
            "algid:alg0\trv=0x{:x}",
            fhsm_composite_algid(0, &mut d, &mut n)
        ));
        t.rows.push(format!(
            "algid:null_der\trv=0x{:x}",
            fhsm_composite_algid(ALG, null_mut(), &mut n)
        ));
        t.rows.push(format!(
            "algid:null_len\trv=0x{:x}",
            fhsm_composite_algid(ALG, &mut d, null_mut())
        ));
    }

    let mut raw = [0u8; RAW_PUB];
    let mut n = raw.len();
    // SAFETY: raw is RAW_PUB bytes
    assert_eq!(
        unsafe { fhsm_composite_raw_pub(ALG, pp, public.len(), raw.as_mut_ptr(), &mut n) },
        0
    );
    let zeros = [0u8; RAW_PUB];
    let pr = |t: &mut Run, name: &str, alg: c_int, p: *const u8, pn: usize, cap: usize| {
        t.fresh(cap, t.s);
        // SAFETY: as rp
        let r = unsafe { fhsm_composite_pub_from_raw(alg, p, pn, t.out.as_mut_ptr(), &mut t.n) };
        let n = t.n;
        t.row(&format!("pub_from_raw:{name}"), r, n, false);
    };
    let rw = raw.as_ptr();
    pr(t, "alg0", 0, rw, RAW_PUB, 4096);
    pr(t, "null_raw", ALG, null(), RAW_PUB, 4096);
    pr(t, "len_short", ALG, rw, RAW_PUB - 1, 4096);
    pr(t, "len_long", ALG, rw, RAW_PUB + 1, 4096);
    pr(t, "zeros", ALG, zeros.as_ptr(), RAW_PUB, 4096);
    pr(t, "cap_short", ALG, rw, RAW_PUB, 100);
    pr(t, "cap_exact", ALG, rw, RAW_PUB, public.len());
    pr(t, "ok", ALG, rw, RAW_PUB, 4096);
    t.n = 4096;
    // SAFETY: as above
    unsafe {
        let r = fhsm_composite_pub_from_raw(ALG, rw, RAW_PUB, null_mut(), &mut t.n);
        let n = t.n;
        t.row("pub_from_raw:null_pub", r, n, false);
        let r = fhsm_composite_pub_from_raw(ALG, rw, RAW_PUB, t.out.as_mut_ptr(), null_mut());
        t.row("pub_from_raw:null_pub_len", r, 0, false);
    }
}

const SUBJECTS: [(&str, &[u8]); 21] = [
    ("no_slash", b"CN=x"),
    ("slash", b"/"),
    ("no_eq", b"/CN"),
    ("empty_field", b"/=x"),
    ("empty_value", b"/CN="),
    ("trailing_slash", b"/CN=a/"),
    ("eq_in_value", b"/CN=a=b"),
    ("three", b"/C=FR/O=Simorgh Labs/CN=example"),
    ("unknown_field", b"/XX=y"),
    ("country_3", b"/C=FRA"),
    ("oid", b"/2.5.4.3=by oid"),
    ("long_name", b"/commonName=long"),
    ("empty_middle", b"/CN=a//O=b"),
    ("bad_utf8", b"/CN=\xff\xfe"),
    ("utf8", b"/CN=\xc3\xa9t\xc3\xa9"),
    ("field_31", b"/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=x"),
    ("field_32", b"/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=x"),
    (
        "cn_64",
        b"/CN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ),
    (
        "cn_65",
        b"/CN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ),
    ("oid_31", b"/1.3.6.1.4.1.55555.1.2.3.4.5.6.7=x"),
    ("oid_32", b"/1.3.6.1.4.1.55555.1.2.3.4.5.6.78=x"),
];

fn csr_cases(t: &mut Run) {
    let public = t.fx("pub");
    let cc = |t: &mut Run,
              nm: &str,
              alg: c_int,
              subj: Option<&[u8]>,
              p: *const u8,
              pn: usize,
              sg: fhsm_composite_sign_cb,
              fk: Fake,
              cap: usize| {
        t.fresh(cap, fk);
        let subj = subj.map(cb);
        let ctx = t.ctx();
        // SAFETY: every pointer is NULL or covers its length
        let r = unsafe {
            fhsm_composite_csr(
                alg,
                subj.as_ref().map_or(null(), |s| s.as_ptr()),
                p,
                pn,
                sg,
                ctx,
                t.out.as_mut_ptr(),
                &mut t.n,
            )
        };
        let n = t.n;
        t.row(nm, r, n, true);
    };
    let (pp, pl) = (public.as_ptr(), public.len());
    let x = Some(&b"/CN=x"[..]);
    for (name, subj) in SUBJECTS {
        cc(
            t,
            &format!("csr:subj_{name}"),
            ALG,
            Some(subj),
            pp,
            pl,
            SIGN,
            fake(3373),
            32768,
        );
    }
    cc(t, "csr:alg0", 0, x, pp, pl, SIGN, fake(3373), 32768);
    cc(
        t,
        "csr:null_subject",
        ALG,
        None,
        pp,
        pl,
        SIGN,
        fake(3373),
        32768,
    );
    cc(
        t,
        "csr:null_pub",
        ALG,
        x,
        null(),
        pl,
        SIGN,
        fake(3373),
        32768,
    );
    cc(t, "csr:null_sign", ALG, x, pp, pl, None, fake(3373), 32768);
    cc(t, "csr:short_blob", ALG, x, pp, 9, SIGN, fake(3373), 32768);
    cc(
        t,
        "csr:sign_fails",
        ALG,
        x,
        pp,
        pl,
        SIGN,
        failing(3373, FUNCTION_FAILED),
        32768,
    );
    cc(
        t,
        "csr:sign_too_small",
        ALG,
        x,
        pp,
        pl,
        SIGN,
        failing(3373, BUFFER_TOO_SMALL),
        32768,
    );
    cc(t, "csr:sig_empty", ALG, x, pp, pl, SIGN, fake(0), 32768);
    cc(t, "csr:cap_0", ALG, x, pp, pl, SIGN, fake(3373), 0);
    cc(t, "csr:ok", ALG, x, pp, pl, SIGN, fake(3373), 32768);
    let ok_len = t.n;
    cc(
        t,
        "csr:cap_short",
        ALG,
        x,
        pp,
        pl,
        SIGN,
        fake(3373),
        ok_len - 1,
    );
    cc(t, "csr:cap_exact", ALG, x, pp, pl, SIGN, fake(3373), ok_len);
    let cx = c("/CN=x");
    t.n = 32768;
    t.s = fake(3373);
    let ctx = t.ctx();
    // SAFETY: NULL outputs are refused before anything is written
    unsafe {
        let r = fhsm_composite_csr(ALG, cx.as_ptr(), pp, pl, SIGN, ctx, null_mut(), &mut t.n);
        let n = t.n;
        t.row("csr:null_out", r, n, true);
        t.s = fake(3373);
        let r = fhsm_composite_csr(
            ALG,
            cx.as_ptr(),
            pp,
            pl,
            SIGN,
            ctx,
            t.out.as_mut_ptr(),
            null_mut(),
        );
        t.row("csr:null_out_len", r, 0, true);
    }

    let pc = |t: &mut Run, nm: &str, sg: fhsm_pki_signer_t, len: usize, subj: &str, cap: usize| {
        t.fresh(cap, fake(len));
        let mut sg = sg;
        sg.sign_ctx = t.ctx();
        let subj = c(subj);
        // SAFETY: the signer's pointers cover their lengths
        let r = unsafe { fhsm_pki_csr(&sg, subj.as_ptr(), t.out.as_mut_ptr(), &mut t.n) };
        let n = t.n;
        t.row(nm, r, n, true);
    };
    let (ed, ec, rsa, ml, comp) = (
        t.signer("ed25519"),
        t.signer("ec"),
        t.signer("rsa"),
        t.signer("mldsa44"),
        t.signer("composite"),
    );
    pc(t, "pki_csr:ed25519", ed, 64, "/CN=ed", 32768);
    pc(t, "pki_csr:ec", ec, 72, "/O=ec/CN=ec", 32768);
    pc(t, "pki_csr:rsa", rsa, 256, "/CN=rsa", 32768);
    pc(t, "pki_csr:mldsa44", ml, 2420, "/CN=ml", 32768);
    pc(t, "pki_csr:composite", comp, 3373, "/CN=comp", 32768);
    pc(t, "pki_csr:bad_subject", ed, 64, "CN=ed", 32768);
    pc(t, "pki_csr:cap_short", ed, 64, "/CN=ed", 100);
    pc(
        t,
        "pki_csr:null_algid",
        fhsm_pki_signer_t {
            algid: null(),
            ..ed
        },
        64,
        "/CN=ed",
        32768,
    );
    pc(
        t,
        "pki_csr:algid_len_0",
        fhsm_pki_signer_t { algid_len: 0, ..ed },
        64,
        "/CN=ed",
        32768,
    );
    pc(
        t,
        "pki_csr:null_sign",
        fhsm_pki_signer_t { sign: None, ..ed },
        64,
        "/CN=ed",
        32768,
    );
    pc(
        t,
        "pki_csr:null_spki",
        fhsm_pki_signer_t { spki: null(), ..ed },
        64,
        "/CN=ed",
        32768,
    );
    pc(
        t,
        "pki_csr:spki_len_0",
        fhsm_pki_signer_t { spki_len: 0, ..ed },
        64,
        "/CN=ed",
        32768,
    );
    let edspki = t.fx("spki_ed25519");
    let b = flip(&edspki, usize::MAX, 0, 1);
    pc(
        t,
        "pki_csr:spki_trailing",
        fhsm_pki_signer_t {
            spki: b.as_ptr(),
            spki_len: b.len(),
            ..ed
        },
        64,
        "/CN=ed",
        32768,
    );
    pc(
        t,
        "pki_csr:spki_short",
        fhsm_pki_signer_t { spki_len: 3, ..ed },
        64,
        "/CN=ed",
        32768,
    );
    let edalg = t.fx("algid_ed25519");
    let b = flip(&edalg, usize::MAX, 0, 1);
    pc(
        t,
        "pki_csr:algid_trailing",
        fhsm_pki_signer_t {
            algid: b.as_ptr(),
            algid_len: b.len(),
            ..ed
        },
        64,
        "/CN=ed",
        32768,
    );
    pc(
        t,
        "pki_csr:algid_short",
        fhsm_pki_signer_t { algid_len: 2, ..ed },
        64,
        "/CN=ed",
        32768,
    );
    let s = fhsm_pki_signer_t {
        sign_ctx: t.ctx(),
        ..ed
    };
    t.n = 32768;
    let cn = c("/CN=ed");
    // SAFETY: NULL arguments are refused before anything is written
    unsafe {
        let r = fhsm_pki_csr(null(), cn.as_ptr(), t.out.as_mut_ptr(), &mut t.n);
        let n = t.n;
        t.row("pki_csr:null_signer", r, n, false);
        let r = fhsm_pki_csr(&s, null(), t.out.as_mut_ptr(), &mut t.n);
        t.row("pki_csr:null_subject", r, n, false);
        let r = fhsm_pki_csr(&s, cn.as_ptr(), null_mut(), &mut t.n);
        t.row("pki_csr:null_out", r, n, false);
        let r = fhsm_pki_csr(&s, cn.as_ptr(), t.out.as_mut_ptr(), null_mut());
        t.row("pki_csr:null_out_len", r, 0, false);
    }
}

fn selfsigned_cases(t: &mut Run) {
    let public = t.fx("pub");
    let (pp, pl) = (public.as_ptr(), public.len());
    let ss = |t: &mut Run,
              nm: &str,
              alg: c_int,
              subj: Option<&str>,
              ser: c_long,
              days: c_int,
              p: *const u8,
              pn: usize,
              sg: fhsm_composite_sign_cb,
              fk: Fake,
              cap: usize| {
        t.fresh(cap, fk);
        let subj = subj.map(c);
        let ctx = t.ctx();
        // SAFETY: every pointer is NULL or covers its length
        let r = unsafe {
            fhsm_composite_selfsigned(
                alg,
                subj.as_ref().map_or(null(), |s| s.as_ptr()),
                ser,
                days,
                p,
                pn,
                sg,
                ctx,
                t.out.as_mut_ptr(),
                &mut t.n,
            )
        };
        let n = t.n;
        t.row(nm, r, n, true);
    };
    let root = Some("/O=pqHSM goldens/CN=composite root");
    let r1 = Some("/CN=r");
    let f = fake(3373);
    ss(
        t,
        "selfsigned:ok",
        ALG,
        root,
        1,
        3650,
        pp,
        pl,
        SIGN,
        f,
        32768,
    );
    let ok_len = t.n;
    ss(t, "selfsigned:alg0", 0, r1, 1, 30, pp, pl, SIGN, f, 32768);
    ss(
        t,
        "selfsigned:null_subject",
        ALG,
        None,
        1,
        30,
        pp,
        pl,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:null_pub",
        ALG,
        r1,
        1,
        30,
        null(),
        pl,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:null_sign",
        ALG,
        r1,
        1,
        30,
        pp,
        pl,
        None,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:serial_0",
        ALG,
        r1,
        0,
        30,
        pp,
        pl,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:serial_neg",
        ALG,
        r1,
        -1,
        30,
        pp,
        pl,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:serial_max",
        ALG,
        r1,
        c_long::MAX,
        30,
        pp,
        pl,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:days_0",
        ALG,
        r1,
        1,
        0,
        pp,
        pl,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:days_neg",
        ALG,
        r1,
        1,
        -1,
        pp,
        pl,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:days_1",
        ALG,
        r1,
        1,
        1,
        pp,
        pl,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:days_50y",
        ALG,
        r1,
        1,
        18263,
        pp,
        pl,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:days_max",
        ALG,
        r1,
        1,
        c_int::MAX,
        pp,
        pl,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:bad_subject",
        ALG,
        Some("/CN="),
        1,
        30,
        pp,
        pl,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:short_blob",
        ALG,
        r1,
        1,
        30,
        pp,
        9,
        SIGN,
        f,
        32768,
    );
    ss(
        t,
        "selfsigned:sign_fails",
        ALG,
        r1,
        1,
        30,
        pp,
        pl,
        SIGN,
        failing(3373, FUNCTION_FAILED),
        32768,
    );
    ss(
        t,
        "selfsigned:cap_0",
        ALG,
        root,
        1,
        3650,
        pp,
        pl,
        SIGN,
        f,
        0,
    );
    ss(
        t,
        "selfsigned:cap_short",
        ALG,
        root,
        1,
        3650,
        pp,
        pl,
        SIGN,
        f,
        ok_len - 1,
    );
    ss(
        t,
        "selfsigned:cap_exact",
        ALG,
        root,
        1,
        3650,
        pp,
        pl,
        SIGN,
        f,
        ok_len,
    );
    let cr = c("/CN=r");
    t.n = 32768;
    t.s = f;
    let ctx = t.ctx();
    // SAFETY: NULL outputs are refused before anything is written
    unsafe {
        let r = fhsm_composite_selfsigned(
            ALG,
            cr.as_ptr(),
            1,
            30,
            pp,
            pl,
            SIGN,
            ctx,
            null_mut(),
            &mut t.n,
        );
        let n = t.n;
        t.row("selfsigned:null_out", r, n, true);
        t.s = f;
        let r = fhsm_composite_selfsigned(
            ALG,
            cr.as_ptr(),
            1,
            30,
            pp,
            pl,
            SIGN,
            ctx,
            t.out.as_mut_ptr(),
            null_mut(),
        );
        t.row("selfsigned:null_out_len", r, 0, true);
    }

    let ps = |t: &mut Run,
              nm: &str,
              sg: fhsm_pki_signer_t,
              len: usize,
              subj: &str,
              ser: c_long,
              days: c_int,
              cap: usize| {
        t.fresh(cap, fake(len));
        let mut sg = sg;
        sg.sign_ctx = t.ctx();
        let subj = c(subj);
        // SAFETY: the signer's pointers cover their lengths
        let r = unsafe {
            fhsm_pki_selfsigned(&sg, subj.as_ptr(), ser, days, t.out.as_mut_ptr(), &mut t.n)
        };
        let n = t.n;
        t.row(nm, r, n, true);
    };
    let (ed, ec, rsa, ml) = (
        t.signer("ed25519"),
        t.signer("ec"),
        t.signer("rsa"),
        t.signer("mldsa44"),
    );
    ps(
        t,
        "pki_selfsigned:ed25519",
        ed,
        64,
        "/CN=ed root",
        2,
        365,
        32768,
    );
    ps(t, "pki_selfsigned:ec", ec, 72, "/CN=ec root", 3, 365, 32768);
    ps(
        t,
        "pki_selfsigned:rsa",
        rsa,
        256,
        "/CN=rsa root",
        4,
        365,
        32768,
    );
    ps(
        t,
        "pki_selfsigned:mldsa44",
        ml,
        2420,
        "/CN=ml root",
        5,
        365,
        32768,
    );
    ps(
        t,
        "pki_selfsigned:serial_0",
        ed,
        64,
        "/CN=ed root",
        0,
        365,
        32768,
    );
    ps(
        t,
        "pki_selfsigned:days_0",
        ed,
        64,
        "/CN=ed root",
        2,
        0,
        32768,
    );
    ps(t, "pki_selfsigned:bad_subject", ed, 64, "/", 2, 365, 32768);
    ps(
        t,
        "pki_selfsigned:cap_short",
        ed,
        64,
        "/CN=ed root",
        2,
        365,
        10,
    );
    ps(
        t,
        "pki_selfsigned:null_spki",
        fhsm_pki_signer_t { spki: null(), ..ed },
        64,
        "/CN=ed root",
        2,
        365,
        32768,
    );
    ps(
        t,
        "pki_selfsigned:algid_len_0",
        fhsm_pki_signer_t { algid_len: 0, ..ed },
        64,
        "/CN=ed root",
        2,
        365,
        32768,
    );
    ps(
        t,
        "pki_selfsigned:algid_short",
        fhsm_pki_signer_t { algid_len: 2, ..ed },
        64,
        "/CN=ed root",
        2,
        365,
        32768,
    );
    ps(
        t,
        "pki_selfsigned:spki_short",
        fhsm_pki_signer_t { spki_len: 3, ..ed },
        64,
        "/CN=ed root",
        2,
        365,
        32768,
    );
}

/// What one fhsm_composite_issue call is given besides OUT and the callbacks' state.
struct Ci<'a> {
    alg: c_int,
    ca: &'a [u8],
    csr: &'a [u8],
    subj: Option<&'a str>,
    san: Option<&'a [u8]>,
    urls: Option<&'a [Option<&'a str>]>,
    nu: usize,
    profile: c_int,
    days: c_int,
    sign: fhsm_composite_sign_cb,
    fake: Fake,
    rng_mode: c_int,
    cap: usize,
    /// NULL for the ca or csr pointer.
    null_ca: bool,
    null_csr: bool,
}

fn issue_cases(t: &mut Run) {
    let (ca_comp, ca_ed, ca_noskid) = (t.fx("ca_comp"), t.fx("ca_ed"), t.fx("ca_noskid"));
    let (csr_comp, csr_ed, csr_ec) = (t.fx("csr_comp"), t.fx("csr_ed"), t.fx("csr_ec"));
    let (csr_x1, csr_x2) = (t.fx("csr_comp_sig_ed_key"), t.fx("csr_ed_sig_comp_key"));
    let ci = |t: &mut Run, nm: &str, a: Ci| {
        t.fresh(a.cap, a.fake);
        let mut mode = a.rng_mode;
        let subj = a.subj.map(c);
        let san = a.san.map(cb);
        let owned: Vec<Option<CString>> = a.urls.unwrap_or(&[]).iter().map(|u| u.map(c)).collect();
        let ptrs: Vec<*const c_char> = owned
            .iter()
            .map(|u| u.as_ref().map_or(null(), |u| u.as_ptr()))
            .collect();
        let ctx = t.ctx();
        // SAFETY: every pointer is NULL or covers its length
        let r = unsafe {
            fhsm_composite_issue(
                a.alg,
                if a.null_ca { null() } else { a.ca.as_ptr() },
                a.ca.len(),
                if a.null_csr { null() } else { a.csr.as_ptr() },
                a.csr.len(),
                subj.as_ref().map_or(null(), |s| s.as_ptr()),
                san.as_ref().map_or(null(), |s| s.as_ptr()),
                if a.urls.is_some() {
                    ptrs.as_ptr()
                } else {
                    null()
                },
                a.nu,
                a.profile,
                a.days,
                a.sign,
                ctx,
                RNG,
                (&raw mut mode).cast(),
                t.out.as_mut_ptr(),
                &mut t.n,
            )
        };
        let n = t.n;
        t.row(nm, r, n, true);
    };
    let base = Ci {
        alg: ALG,
        ca: &ca_comp,
        csr: &csr_comp,
        subj: None,
        san: None,
        urls: None,
        nu: 0,
        profile: 0,
        days: 365,
        sign: SIGN,
        fake: fake(3373),
        rng_mode: 0,
        cap: 32768,
        null_ca: false,
        null_csr: false,
    };
    macro_rules! ok {
        ($nm:expr $(, $f:ident: $v:expr)*) => {
            ci(t, $nm, Ci { $($f: $v,)* ..base })
        };
    }
    let crl2 = [
        Some("http://c.example/ca.crl"),
        Some("ldap://l.example/cn=CA?certificateRevocationList"),
    ];
    let csr_trailing = flip(&csr_comp, usize::MAX, 0, 1);
    let comp_bad = flip(&csr_comp, csr_comp.len() - 1, 1, 0);
    let ed_bad = flip(&csr_ed, csr_ed.len() - 1, 1, 0);
    ok!("issue:ok");
    let ok_len = t.n;
    ok!("issue:ed_applicant", csr: &csr_ed);
    ok!("issue:ec_applicant", csr: &csr_ec);
    ok!("issue:csr_trailing_byte", csr: &csr_trailing);
    ok!("issue:pop_comp_bad_sig", csr: &comp_bad);
    ok!("issue:pop_ed_bad_sig", csr: &ed_bad);
    ok!("issue:pop_comp_sig_ed_key", csr: &csr_x1);
    ok!("issue:pop_ed_sig_comp_key", csr: &csr_x2);
    ok!("issue:rng_zeros", rng_mode: 1);
    ok!("issue:rng_ones", rng_mode: 2);
    ok!("issue:rng_fails", rng_mode: 3);
    ok!("issue:subject_override", subj: Some("/O=override/CN=renamed"));
    ok!("issue:subject_override_bad", subj: Some("/CN="));
    ok!("issue:ocsp_responder", profile: 1);
    ok!("issue:profile_7", profile: 7);
    ok!("issue:crl_2", urls: Some(&crl2), nu: 2);
    ok!("issue:crl_n_0", urls: Some(&crl2), nu: 0);
    ok!("issue:everything", subj: Some("/CN=all"), san: Some(b"DNS:all.example,IP:192.0.2.7"), urls: Some(&crl2), nu: 2, profile: 1);
    let sans: [(&str, &[u8]); 17] = [
        ("one", b"DNS:a.example"),
        ("mixed", b"DNS:a.example, IP:192.0.2.1,\temail:x@y.example ,URI:http://u.example/p, IP:2001:db8::1"),
        ("trailing_comma", b"DNS:a,"),
        ("empty", b""),
        ("empty_item", b"DNS:a,,DNS:b"),
        ("blank_item", b"DNS:a, ,DNS:b"),
        ("unknown_type", b"FOO:x"),
        ("lower_type", b"dns:a"),
        ("no_type", b":x"),
        ("no_value", b"DNS:"),
        ("no_colon", b"DNS"),
        ("bad_ipv4", b"IP:999.1.1.1"),
        ("short_ipv4", b"IP:1.2.3"),
        ("bad_ipv6", b"IP:2001:db8::g"),
        ("space_in_value", b"DNS:a b"),
        ("colon_in_value", b"URI:urn:x:y"),
        ("non_ascii", b"email:\xc3\xa9@x"),
    ];
    for (name, san) in sans {
        ok!(&format!("issue:san_{name}"), san: Some(san));
    }
    let mut long_san = b"DNS:".to_vec();
    long_san.extend([b'a'; 507]);
    ok!("issue:san_item_511", san: Some(&long_san));
    long_san.push(b'a');
    ok!("issue:san_item_512", san: Some(&long_san));
    let urls: [(&str, &str); 11] = [
        ("http_short", "http://x"),
        ("https", "https://c.example/ca.crl"),
        ("http_empty", "http://"),
        ("ldap_no_attr", "ldap://x"),
        ("ldap_empty_attr", "ldap://x?"),
        ("ldap_attr", "ldap://x?a"),
        ("tab", "http://a\tb"),
        ("del", "http://\x7f"),
        ("non_ascii", "http://\u{e9}"),
        ("upper_scheme", "HTTP://x"),
        ("ftp", "ftp://x"),
    ];
    for (name, u) in urls {
        ok!(&format!("issue:crl_{name}"), urls: Some(&[Some(u)]), nu: 1);
    }
    ok!("issue:crl_null_entry", urls: Some(&[Some("http://ok.example"), None]), nu: 2);
    ok!("issue:crl_second_bad", urls: Some(&[Some("http://ok.example"), Some("ftp://x")]), nu: 2);
    ok!("issue:ca_noskid", ca: &ca_noskid);
    ok!("issue:ca_ed", ca: &ca_ed);
    ok!("issue:ca_garbage", ca: &csr_ed[..20]);
    ok!("issue:csr_garbage", csr: &ca_comp[..20]);
    ok!("issue:csr_is_cert", csr: &ca_comp);
    ok!("issue:alg0", alg: 0);
    ok!("issue:days_0", days: 0);
    ok!("issue:days_max", days: c_int::MAX);
    ok!("issue:null_ca", null_ca: true);
    ok!("issue:null_csr", null_csr: true);
    ok!("issue:null_sign", sign: None);
    ok!("issue:sign_fails", fake: failing(3373, FUNCTION_FAILED));
    ok!("issue:cap_0", cap: 0);
    ok!("issue:cap_short", cap: ok_len - 1);
    ok!("issue:cap_exact", cap: ok_len);
    t.n = 32768;
    t.s = fake(3373);
    let mut mode: c_int = 0;
    let (ctx, mp) = (t.ctx(), (&raw mut mode).cast::<c_void>());
    let (ca, cs) = (&ca_comp, &csr_comp);
    // SAFETY: NULL arguments are refused before anything is written
    unsafe {
        let r = fhsm_composite_issue(
            ALG,
            ca.as_ptr(),
            ca.len(),
            cs.as_ptr(),
            cs.len(),
            null(),
            null(),
            null(),
            0,
            0,
            365,
            SIGN,
            ctx,
            None,
            mp,
            t.out.as_mut_ptr(),
            &mut t.n,
        );
        let n = t.n;
        t.row("issue:null_rng", r, n, true);
        let r = fhsm_composite_issue(
            ALG,
            ca.as_ptr(),
            ca.len(),
            cs.as_ptr(),
            cs.len(),
            null(),
            null(),
            null(),
            0,
            0,
            365,
            SIGN,
            ctx,
            RNG,
            mp,
            null_mut(),
            &mut t.n,
        );
        t.row("issue:null_out", r, n, true);
        let r = fhsm_composite_issue(
            ALG,
            ca.as_ptr(),
            ca.len(),
            cs.as_ptr(),
            cs.len(),
            null(),
            null(),
            null(),
            0,
            0,
            365,
            SIGN,
            ctx,
            RNG,
            mp,
            t.out.as_mut_ptr(),
            null_mut(),
        );
        t.row("issue:null_out_len", r, 0, true);
    }

    let ed = t.signer("ed25519");
    let pi = |t: &mut Run, nm: &str, sg: fhsm_pki_signer_t, len: usize, csr: &[u8], days: c_int| {
        t.fresh(32768, fake(len));
        let mut mode: c_int = 0;
        let mut u = sg;
        u.sign_ctx = t.ctx();
        // SAFETY: every pointer is NULL or covers its length
        let r = unsafe {
            fhsm_pki_issue(
                &u,
                ca_ed.as_ptr(),
                ca_ed.len(),
                csr.as_ptr(),
                csr.len(),
                null(),
                null(),
                null(),
                0,
                0,
                days,
                RNG,
                (&raw mut mode).cast(),
                t.out.as_mut_ptr(),
                &mut t.n,
            )
        };
        let n = t.n;
        t.row(nm, r, n, true);
    };
    pi(t, "pki_issue:ed_ca_comp_applicant", ed, 64, &csr_comp, 90);
    pi(t, "pki_issue:ed_ca_ed_applicant", ed, 64, &csr_ed, 90);
    pi(t, "pki_issue:days_neg", ed, 64, &csr_ed, -1);
    pi(
        t,
        "pki_issue:no_spki",
        fhsm_pki_signer_t { spki: null(), ..ed },
        64,
        &csr_ed,
        90,
    );
    pi(
        t,
        "pki_issue:null_algid",
        fhsm_pki_signer_t {
            algid: null(),
            ..ed
        },
        64,
        &csr_ed,
        90,
    );
    pi(
        t,
        "pki_issue:algid_short",
        fhsm_pki_signer_t { algid_len: 2, ..ed },
        64,
        &csr_ed,
        90,
    );
}

// ---- CRL and OCSP (slice 5c) -------------------------------------------------------------

const GT: &[u8] = b"\x18\x0f20270101000000Z";
const GT2: &[u8] = b"\x18\x0f20270108000000Z";
const UT: &[u8] = b"\x17\x0d270101000000Z";
const GT24: &[u8] = b"\x18\x1620270101000000.123456Z";
const GT25: &[u8] = b"\x18\x1720270101000000.1234567Z";
const CERT_ID: &[u8] = &[0x30, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03];
const NAME0: &[u8] = &[0x30, 0x00];
const SEQ5: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x05];
const BYKEY: &[u8] = &[
    0xA2, 0x16, 0x04, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
];
const RID: &[u8] = &[0xA1, 0x02, 0x30, 0x00];

/// A pointer/length pair as C passes it, including the inconsistent ones.
type Part = (*const u8, usize);
const NONE: Part = (null(), 0);

fn p(b: &[u8]) -> Part {
    (b.as_ptr(), b.len())
}

fn big(n: usize, tag: u8) -> Vec<u8> {
    let mut v = vec![0; n];
    v[0] = tag;
    v
}

fn algid_cases(t: &mut Run) {
    for a in -1..=9 {
        let (mut d, mut n) = (null(), 0);
        // SAFETY: two out-pointers
        let r = unsafe { fhsm_pki_algid(a, &mut d, &mut n) };
        // SAFETY: n bytes of static storage on success
        let der = if r == 0 {
            hex(unsafe { std::slice::from_raw_parts(d, n) })
        } else {
            String::new()
        };
        t.rows.push(format!("pki_algid:{a}\trv=0x{r:x};der={der}"));
    }
    let (mut d, mut n) = (null(), 0);
    // SAFETY: NULL outputs are refused
    unsafe {
        t.rows.push(format!(
            "pki_algid:null_der\trv=0x{:x}",
            fhsm_pki_algid(5, null_mut(), &mut n)
        ));
        t.rows.push(format!(
            "pki_algid:null_len\trv=0x{:x}",
            fhsm_pki_algid(5, &mut d, null_mut())
        ));
    }
}

fn crl_tbs_cases(t: &mut Run) {
    let al = t.fx("algid_ed25519");
    let ct = |t: &mut Run, nm: &str, parts: [Part; 6], cap: usize| {
        t.fresh(cap, t.s);
        let [a, i, th, nx, rv, e] = parts;
        // SAFETY: every pointer is NULL or covers its length where the length is checked
        let r = unsafe {
            fhsm_composite_crl_tbs(
                a.0,
                a.1,
                i.0,
                i.1,
                th.0,
                th.1,
                nx.0,
                nx.1,
                rv.0,
                rv.1,
                e.0,
                e.1,
                t.out.as_mut_ptr(),
                &mut t.n,
            )
        };
        let n = t.n;
        t.row(&format!("crl_tbs:{nm}"), r, n, false);
    };
    let (a, nm, u) = (p(&al), p(NAME0), p(UT));
    let m = 32768;
    ct(t, "minimal", [a, nm, u, NONE, NONE, NONE], m);
    ct(t, "all", [a, nm, u, p(GT2), p(SEQ5), p(SEQ5)], m);
    ct(t, "generalized_this", [a, nm, p(GT), u, NONE, NONE], m);
    ct(
        t,
        "null_algid",
        [(null(), al.len()), nm, u, NONE, NONE, NONE],
        m,
    );
    ct(
        t,
        "algid_len_0",
        [(al.as_ptr(), 0), nm, u, NONE, NONE, NONE],
        m,
    );
    ct(t, "null_issuer", [a, (null(), 2), u, NONE, NONE, NONE], m);
    ct(
        t,
        "issuer_len_0",
        [a, (NAME0.as_ptr(), 0), u, NONE, NONE, NONE],
        m,
    );
    ct(
        t,
        "null_this",
        [a, nm, (null(), UT.len()), NONE, NONE, NONE],
        m,
    );
    ct(
        t,
        "this_len_0",
        [a, nm, (UT.as_ptr(), 0), NONE, NONE, NONE],
        m,
    );
    ct(
        t,
        "next_ptr_no_len",
        [a, nm, u, (GT2.as_ptr(), 0), NONE, NONE],
        m,
    );
    ct(t, "next_len_no_ptr", [a, nm, u, (null(), 3), NONE, NONE], m);
    ct(
        t,
        "revoked_ptr_no_len",
        [a, nm, u, NONE, (SEQ5.as_ptr(), 0), NONE],
        m,
    );
    ct(
        t,
        "revoked_len_no_ptr",
        [a, nm, u, NONE, (null(), 5), NONE],
        m,
    );
    ct(
        t,
        "exts_ptr_no_len",
        [a, nm, u, NONE, NONE, (SEQ5.as_ptr(), 0)],
        m,
    );
    ct(t, "exts_len_no_ptr", [a, nm, u, NONE, NONE, (null(), 5)], m);
    ct(t, "algid_tag", [u, nm, u, NONE, NONE, NONE], m);
    ct(t, "issuer_tag", [a, u, u, NONE, NONE, NONE], m);
    ct(t, "this_tag", [a, nm, nm, NONE, NONE, NONE], m);
    ct(t, "next_tag", [a, nm, u, nm, NONE, NONE], m);
    ct(t, "revoked_tag", [a, nm, u, NONE, u, NONE], m);
    ct(t, "exts_tag", [a, nm, u, NONE, NONE, u], m);
    ct(t, "cap_0", [a, nm, u, NONE, NONE, NONE], 0);
    ct(t, "cap_short", [a, nm, u, NONE, NONE, NONE], 28);
    ct(t, "cap_exact", [a, nm, u, NONE, NONE, NONE], 29);
    let fixed = 3 + al.len() + 2 + UT.len() + 1 + 4;
    let e = big(0xFF_FFFF - fixed + 1, 0x30);
    ct(
        t,
        "content_max",
        [a, nm, u, NONE, NONE, (e.as_ptr(), 0xFF_FFFF - fixed)],
        1,
    );
    ct(t, "content_max_plus_1", [a, nm, u, NONE, NONE, p(&e)], 1);
    t.n = 64;
    // SAFETY: NULL outputs are refused before anything is written
    unsafe {
        let r = fhsm_composite_crl_tbs(
            a.0,
            a.1,
            nm.0,
            nm.1,
            u.0,
            u.1,
            null(),
            0,
            null(),
            0,
            null(),
            0,
            null_mut(),
            &mut t.n,
        );
        let n = t.n;
        t.row("crl_tbs:null_out", r, n, false);
        let r = fhsm_composite_crl_tbs(
            a.0,
            a.1,
            nm.0,
            nm.1,
            u.0,
            u.1,
            null(),
            0,
            null(),
            0,
            null(),
            0,
            t.out.as_mut_ptr(),
            null_mut(),
        );
        t.row("crl_tbs:null_out_len", r, 0, false);
    }
}

fn rev(serial: &[u8], date: i64, reason: c_int) -> fhsm_composite_revoked_t {
    fhsm_composite_revoked_t {
        serial: serial.as_ptr(),
        serial_len: serial.len(),
        date,
        reason,
    }
}

fn crl_cases(t: &mut Run) {
    let (ca_comp, ca_ed, ca_noskid) = (t.fx("ca_comp"), t.fx("ca_ed"), t.fx("ca_noskid"));
    let f = fake(3373);
    let rc = |t: &mut Run,
              nm: &str,
              alg: c_int,
              ca: Part,
              list: Option<&[fhsm_composite_revoked_t]>,
              nr: usize,
              num: u64,
              days: c_int,
              sg: fhsm_composite_sign_cb,
              fk: Fake,
              cap: usize| {
        t.fresh(cap, fk);
        let ctx = t.ctx();
        let lp = list.map_or(null(), <[_]>::as_ptr);
        // SAFETY: every pointer is NULL or covers its length
        let r = unsafe {
            fhsm_composite_crl(
                alg,
                ca.0,
                ca.1,
                lp,
                nr,
                num,
                days,
                sg,
                ctx,
                t.out.as_mut_ptr(),
                &mut t.n,
            )
        };
        let n = t.n;
        t.row(nm, r, n, true);
    };
    let cc = p(&ca_comp);
    let co = |t: &mut Run,
              nm: &str,
              list: Option<&[fhsm_composite_revoked_t]>,
              nr: usize,
              num: u64,
              days: c_int| { rc(t, nm, ALG, cc, list, nr, num, days, SIGN, f, 32768) };
    let one = [rev(&[1], 1_798_675_200, -1)];
    co(t, "crl:empty", None, 0, 1, 7);
    co(t, "crl:one", Some(&one), 1, 2, 7);
    let ff = [0xFFu8; 20];
    let serials = [
        rev(&[1], 0, -1),
        rev(&[0x80], 0, -1),
        rev(&[0, 0, 5], 0, -1),
        rev(&[0], 0, -1),
        rev(&ff, 0, -1),
    ];
    co(t, "crl:serials", Some(&serials), 5, 3, 7);
    let reasons: Vec<_> = [-1, 0, 1, 2, 3, 4, 5, 6, 9, 10, -5]
        .iter()
        .map(|&r| rev(&[1], 1_798_675_200, r))
        .collect();
    co(t, "crl:reasons", Some(&reasons), 11, 4, 7);
    for bad in [7, 8, 11, c_int::MAX] {
        let b = [rev(&[1], 0, -1), rev(&[0x80], 0, bad)];
        co(t, &format!("crl:reason_{bad}"), Some(&b), 2, 5, 7);
    }
    let dates: [(&str, i64); 9] = [
        ("crl:date_0", 0),
        ("crl:date_neg_1", -1),
        ("crl:date_1949", -631_152_001),
        ("crl:date_1950", -631_152_000),
        ("crl:date_2049", 2_524_607_999),
        ("crl:date_2050", 2_524_608_000),
        ("crl:date_9999", 253_402_300_799),
        ("crl:date_10000", 253_402_300_800),
        ("crl:date_min", i64::MIN),
    ];
    for (nm, d) in dates {
        co(t, nm, Some(&[rev(&[1], d, -1)]), 1, 6, 7);
    }
    let nul = [
        rev(&[1], 0, -1),
        fhsm_composite_revoked_t {
            serial: null(),
            serial_len: 3,
            date: 0,
            reason: -1,
        },
    ];
    co(t, "crl:null_serial", Some(&nul), 2, 7, 7);
    co(
        t,
        "crl:serial_len_0",
        Some(&[rev(&[1][..0], 0, -1)]),
        1,
        7,
        7,
    );
    for (i, num) in [0, 127, 128, 255, 256, 1 << 63, u64::MAX]
        .into_iter()
        .enumerate()
    {
        co(t, &format!("crl:number_{i}"), None, 0, num, 7);
    }
    co(t, "crl:days_1", None, 0, 1, 1);
    co(t, "crl:days_36500", None, 0, 1, 36500);
    co(t, "crl:days_max", None, 0, 1, c_int::MAX);
    co(t, "crl:days_0", None, 0, 1, 0);
    co(t, "crl:days_neg", None, 0, 1, -1);
    co(t, "crl:n_without_list", None, 2, 1, 7);
    let o = Some(&one[..]);
    rc(
        t,
        "crl:ca_noskid",
        ALG,
        p(&ca_noskid),
        o,
        1,
        1,
        7,
        SIGN,
        f,
        32768,
    );
    rc(t, "crl:ca_ed", ALG, p(&ca_ed), o, 1, 1, 7, SIGN, f, 32768);
    let long = t.fx("ca_long_skid");
    rc(
        t,
        "crl:ca_long_skid",
        ALG,
        p(&long),
        o,
        1,
        1,
        7,
        SIGN,
        f,
        32768,
    );
    rc(
        t,
        "crl:ca_garbage",
        ALG,
        (ca_ed.as_ptr(), 20),
        o,
        1,
        1,
        7,
        SIGN,
        f,
        32768,
    );
    rc(
        t,
        "crl:ca_len_0",
        ALG,
        (ca_ed.as_ptr(), 0),
        o,
        1,
        1,
        7,
        SIGN,
        f,
        32768,
    );
    rc(
        t,
        "crl:null_ca",
        ALG,
        (null(), 10),
        o,
        1,
        1,
        7,
        SIGN,
        f,
        32768,
    );
    rc(t, "crl:alg0", 0, cc, o, 1, 1, 7, SIGN, f, 32768);
    rc(t, "crl:null_sign", ALG, cc, o, 1, 1, 7, None, f, 32768);
    rc(
        t,
        "crl:sign_fails",
        ALG,
        cc,
        o,
        1,
        1,
        7,
        SIGN,
        failing(3373, FUNCTION_FAILED),
        32768,
    );
    rc(
        t,
        "crl:sign_too_small",
        ALG,
        cc,
        o,
        1,
        1,
        7,
        SIGN,
        failing(3373, BUFFER_TOO_SMALL),
        32768,
    );
    rc(
        t,
        "crl:sig_empty",
        ALG,
        cc,
        o,
        1,
        1,
        7,
        SIGN,
        fake(0),
        32768,
    );
    co(t, "crl:ok", o, 1, 9, 30);
    let ok_len = t.n;
    rc(t, "crl:cap_0", ALG, cc, o, 1, 9, 30, SIGN, f, 0);
    rc(
        t,
        "crl:cap_short",
        ALG,
        cc,
        o,
        1,
        9,
        30,
        SIGN,
        f,
        ok_len - 1,
    );
    rc(t, "crl:cap_exact", ALG, cc, o, 1, 9, 30, SIGN, f, ok_len);
    let many: Vec<_> = (0..3000).map(|i| rev(&ff, i, (i % 7) as c_int)).collect();
    rc(
        t,
        "crl:many_3000",
        ALG,
        cc,
        Some(&many),
        3000,
        10,
        7,
        SIGN,
        f,
        1,
    );
    co(t, "crl:many_500", Some(&many), 500, 11, 7);
    t.n = 32768;
    t.s = f;
    let ctx = t.ctx();
    // SAFETY: NULL outputs are refused before anything is written
    unsafe {
        let r = fhsm_composite_crl(
            ALG,
            cc.0,
            cc.1,
            one.as_ptr(),
            1,
            1,
            7,
            SIGN,
            ctx,
            null_mut(),
            &mut t.n,
        );
        let n = t.n;
        t.row("crl:null_out", r, n, true);
        t.s = f;
        let r = fhsm_composite_crl(
            ALG,
            cc.0,
            cc.1,
            one.as_ptr(),
            1,
            1,
            7,
            SIGN,
            ctx,
            t.out.as_mut_ptr(),
            null_mut(),
        );
        t.row("crl:null_out_len", r, 0, true);
    }

    let ed = t.signer("ed25519");
    let rp = |t: &mut Run, nm: &str, sg: fhsm_pki_signer_t| {
        t.fresh(32768, fake(64));
        let u = fhsm_pki_signer_t {
            sign_ctx: t.ctx(),
            ..sg
        };
        // SAFETY: the signer's pointers cover their lengths
        let r = unsafe {
            fhsm_pki_crl(
                &u,
                ca_ed.as_ptr(),
                ca_ed.len(),
                one.as_ptr(),
                1,
                1,
                7,
                t.out.as_mut_ptr(),
                &mut t.n,
            )
        };
        let n = t.n;
        t.row(nm, r, n, true);
    };
    rp(t, "pki_crl:ed", ed);
    rp(
        t,
        "pki_crl:null_algid",
        fhsm_pki_signer_t {
            algid: null(),
            ..ed
        },
    );
    rp(
        t,
        "pki_crl:algid_len_0",
        fhsm_pki_signer_t { algid_len: 0, ..ed },
    );
    rp(
        t,
        "pki_crl:algid_tag",
        fhsm_pki_signer_t {
            algid: UT.as_ptr(),
            algid_len: UT.len(),
            ..ed
        },
    );
    rp(
        t,
        "pki_crl:null_sign",
        fhsm_pki_signer_t { sign: None, ..ed },
    );
    t.n = 32768;
    // SAFETY: a NULL signer is refused
    let r = unsafe {
        fhsm_pki_crl(
            null(),
            ca_ed.as_ptr(),
            ca_ed.len(),
            one.as_ptr(),
            1,
            1,
            7,
            t.out.as_mut_ptr(),
            &mut t.n,
        )
    };
    let n = t.n;
    t.row("pki_crl:null_signer", r, n, false);
}

fn single(
    ci: Part,
    status: c_int,
    ra: Part,
    reason: c_int,
    tu: Part,
    nu: Part,
) -> fhsm_composite_ocsp_single_t {
    fhsm_composite_ocsp_single_t {
        cert_id: ci.0,
        cert_id_len: ci.1,
        status,
        revoked_at: ra.0,
        revoked_at_len: ra.1,
        reason,
        this_upd: tu.0,
        this_upd_len: tu.1,
        next_upd: nu.0,
        next_upd_len: nu.1,
    }
}

fn ocsp_single_cases(t: &mut Run) {
    let os = |t: &mut Run, nm: &str, x: fhsm_composite_ocsp_single_t, cap: usize| {
        t.fresh(cap, t.s);
        // SAFETY: the single's pointers cover their lengths where they are read
        let r = unsafe { fhsm_composite_ocsp_single(&x, t.out.as_mut_ptr(), &mut t.n) };
        let n = t.n;
        t.row(&format!("ocsp_single:{nm}"), r, n, false);
    };
    let (ci, g, g2, m) = (p(CERT_ID), p(GT), p(GT2), 32768);
    let (good, rvk, unk) = (0, 1, 2);
    os(t, "good", single(ci, good, NONE, -1, g, NONE), m);
    os(t, "good_next", single(ci, good, NONE, -1, g, g2), m);
    os(t, "unknown", single(ci, unk, NONE, -1, g, NONE), m);
    for r in [-1, -5, 0, 7, 8, 10, 11] {
        os(
            t,
            &format!("revoked_reason_{r}"),
            single(ci, rvk, g, r, g, g2),
            m,
        );
    }
    os(t, "revoked_at_24", single(ci, rvk, p(GT24), 1, g, NONE), m);
    os(t, "revoked_at_25", single(ci, rvk, p(GT25), 1, g, NONE), m);
    os(t, "revoked_no_time", single(ci, rvk, NONE, 1, g, NONE), m);
    os(
        t,
        "revoked_time_no_len",
        single(ci, rvk, (GT.as_ptr(), 0), 1, g, NONE),
        m,
    );
    os(t, "revoked_time_utc", single(ci, rvk, p(UT), 1, g, NONE), m);
    os(t, "good_with_time", single(ci, good, g, -1, g, NONE), m);
    os(
        t,
        "good_with_time_len",
        single(ci, good, (null(), 5), -1, g, NONE),
        m,
    );
    os(t, "good_with_reason", single(ci, good, NONE, 0, g, NONE), m);
    os(t, "unknown_with_time", single(ci, unk, g, -1, g, NONE), m);
    os(t, "status_3", single(ci, 3, NONE, -1, g, NONE), m);
    os(t, "status_neg", single(ci, -1, NONE, -1, g, NONE), m);
    os(
        t,
        "null_cert_id",
        single((null(), CERT_ID.len()), good, NONE, -1, g, NONE),
        m,
    );
    os(
        t,
        "cert_id_len_0",
        single((CERT_ID.as_ptr(), 0), good, NONE, -1, g, NONE),
        m,
    );
    os(t, "cert_id_tag", single(g, good, NONE, -1, g, NONE), m);
    os(
        t,
        "null_this",
        single(ci, good, NONE, -1, (null(), GT.len()), NONE),
        m,
    );
    os(t, "this_utc", single(ci, good, NONE, -1, p(UT), NONE), m);
    os(
        t,
        "next_ptr_no_len",
        single(ci, good, NONE, -1, g, (GT2.as_ptr(), 0)),
        m,
    );
    os(
        t,
        "next_len_no_ptr",
        single(ci, good, NONE, -1, g, (null(), 3)),
        m,
    );
    os(t, "next_utc", single(ci, good, NONE, -1, g, p(UT)), m);
    os(t, "cap_0", single(ci, good, NONE, -1, g, NONE), 0);
    os(t, "cap_short", single(ci, good, NONE, -1, g, NONE), 27);
    os(t, "cap_exact", single(ci, good, NONE, -1, g, NONE), 28);
    let fixed = 2 + GT.len();
    let c = big(0xFF_FFFF - fixed + 1, 0x30);
    os(
        t,
        "content_max",
        single((c.as_ptr(), 0xFF_FFFF - fixed), good, NONE, -1, g, NONE),
        1,
    );
    os(
        t,
        "content_max_plus_1",
        single(p(&c), good, NONE, -1, g, NONE),
        1,
    );
    let x = single(ci, good, NONE, -1, g, NONE);
    t.n = 64;
    // SAFETY: NULL arguments are refused before anything is written
    unsafe {
        let r = fhsm_composite_ocsp_single(null(), t.out.as_mut_ptr(), &mut t.n);
        let n = t.n;
        t.row("ocsp_single:null_single", r, n, false);
        let r = fhsm_composite_ocsp_single(&x, null_mut(), &mut t.n);
        t.row("ocsp_single:null_out", r, n, false);
        let r = fhsm_composite_ocsp_single(&x, t.out.as_mut_ptr(), null_mut());
        t.row("ocsp_single:null_out_len", r, 0, false);
    }
}

fn ocsp_tbs_cases(t: &mut Run) {
    let ot = |t: &mut Run, nm: &str, parts: [Part; 4], cap: usize| {
        t.fresh(cap, t.s);
        let [r, pa, q, e] = parts;
        // SAFETY: every pointer is NULL or covers its length where the length is checked
        let rv = unsafe {
            fhsm_composite_ocsp_tbs(
                r.0,
                r.1,
                pa.0,
                pa.1,
                q.0,
                q.1,
                e.0,
                e.1,
                t.out.as_mut_ptr(),
                &mut t.n,
            )
        };
        let n = t.n;
        t.row(&format!("ocsp_tbs:{nm}"), rv, n, false);
    };
    let (r, g, q, m) = (p(RID), p(GT), p(SEQ5), 32768);
    ot(t, "by_name", [r, g, q, NONE], m);
    ot(t, "by_key", [p(BYKEY), g, q, NONE], m);
    ot(t, "exts", [r, g, q, q], m);
    ot(t, "rid_tag", [p(NAME0), g, q, NONE], m);
    ot(t, "produced_utc", [r, p(UT), q, NONE], m);
    ot(t, "responses_tag", [r, g, g, NONE], m);
    ot(t, "exts_tag", [r, g, q, g], m);
    ot(t, "exts_ptr_no_len", [r, g, q, (SEQ5.as_ptr(), 0)], m);
    ot(t, "exts_len_no_ptr", [r, g, q, (null(), 5)], m);
    ot(t, "null_rid", [(null(), 4), g, q, NONE], m);
    ot(t, "rid_len_0", [(RID.as_ptr(), 0), g, q, NONE], m);
    ot(t, "null_produced", [r, (null(), 17), q, NONE], m);
    ot(t, "null_responses", [r, g, (null(), 5), NONE], m);
    ot(t, "responses_len_0", [r, g, (SEQ5.as_ptr(), 0), NONE], m);
    ot(t, "cap_short", [r, g, q, NONE], 27);
    ot(t, "cap_exact", [r, g, q, NONE], 28);
    let fixed = RID.len() + GT.len();
    let big_q = big(0xFF_FFFF - fixed + 1, 0x30);
    ot(
        t,
        "content_max",
        [r, g, (big_q.as_ptr(), 0xFF_FFFF - fixed), NONE],
        1,
    );
    ot(t, "content_max_plus_1", [r, g, p(&big_q), NONE], 1);
    t.n = 64;
    // SAFETY: NULL outputs are refused before anything is written
    unsafe {
        let rv = fhsm_composite_ocsp_tbs(
            r.0,
            r.1,
            g.0,
            g.1,
            q.0,
            q.1,
            null(),
            0,
            null_mut(),
            &mut t.n,
        );
        let n = t.n;
        t.row("ocsp_tbs:null_out", rv, n, false);
        let rv = fhsm_composite_ocsp_tbs(
            r.0,
            r.1,
            g.0,
            g.1,
            q.0,
            q.1,
            null(),
            0,
            t.out.as_mut_ptr(),
            null_mut(),
        );
        t.row("ocsp_tbs:null_out_len", rv, 0, false);
    }
}

fn ocsp_cases(t: &mut Run) {
    let (ca_comp, ca_ed, ca_noskid) = (t.fx("ca_comp"), t.fx("ca_ed"), t.fx("ca_noskid"));
    let f = fake(3373);
    let (ci, g, g2) = (p(CERT_ID), p(GT), p(GT2));
    let good = single(ci, 0, NONE, -1, g, g2);
    let revoked = single(ci, 1, g, 1, g, g2);
    let unknown = single(ci, 2, NONE, -1, g, NONE);
    let badst = single(ci, 3, NONE, -1, g, NONE);
    let three = [good, revoked, unknown];
    let second_bad = [good, badst];
    let oc = |t: &mut Run,
              nm: &str,
              alg: c_int,
              rc: Part,
              pa: Part,
              sg_: (*const fhsm_composite_ocsp_single_t, usize),
              e: Part,
              sg: fhsm_composite_sign_cb,
              fk: Fake,
              cap: usize| {
        t.fresh(cap, fk);
        let ctx = t.ctx();
        // SAFETY: every pointer is NULL or covers its length
        let r = unsafe {
            fhsm_composite_ocsp(
                alg,
                rc.0,
                rc.1,
                pa.0,
                pa.1,
                sg_.0,
                sg_.1,
                e.0,
                e.1,
                sg,
                ctx,
                t.out.as_mut_ptr(),
                &mut t.n,
            )
        };
        let n = t.n;
        t.row(nm, r, n, true);
    };
    let cc = p(&ca_comp);
    let oo = |t: &mut Run, nm: &str, sg_: (*const fhsm_composite_ocsp_single_t, usize), e: Part| {
        oc(t, nm, ALG, cc, g, sg_, e, SIGN, f, 32768)
    };
    let s1 = (&raw const good, 1);
    oo(t, "ocsp:good", s1, NONE);
    oo(t, "ocsp:revoked", (&raw const revoked, 1), NONE);
    oo(t, "ocsp:three", (three.as_ptr(), 3), NONE);
    oo(t, "ocsp:exts", s1, p(SEQ5));
    oo(t, "ocsp:exts_ptr_no_len", s1, (SEQ5.as_ptr(), 0));
    oo(t, "ocsp:exts_len_no_ptr", s1, (null(), 5));
    oo(t, "ocsp:exts_tag", s1, g);
    oo(t, "ocsp:second_bad", (second_bad.as_ptr(), 2), NONE);
    oo(t, "ocsp:n_0", (&raw const good, 0), NONE);
    oo(t, "ocsp:null_singles", (null(), 1), NONE);
    oc(
        t,
        "ocsp:produced_utc",
        ALG,
        cc,
        p(UT),
        s1,
        NONE,
        SIGN,
        f,
        32768,
    );
    oc(
        t,
        "ocsp:null_produced",
        ALG,
        cc,
        (null(), 17),
        s1,
        NONE,
        SIGN,
        f,
        32768,
    );
    oc(
        t,
        "ocsp:produced_len_0",
        ALG,
        cc,
        (GT.as_ptr(), 0),
        s1,
        NONE,
        SIGN,
        f,
        32768,
    );
    oc(
        t,
        "ocsp:responder_ed",
        ALG,
        p(&ca_ed),
        g,
        s1,
        NONE,
        SIGN,
        f,
        32768,
    );
    oc(
        t,
        "ocsp:responder_noskid",
        ALG,
        p(&ca_noskid),
        g,
        s1,
        NONE,
        SIGN,
        f,
        32768,
    );
    let trail = flip(&ca_ed, usize::MAX, 0, 3);
    oc(
        t,
        "ocsp:responder_trailing",
        ALG,
        p(&trail),
        g,
        s1,
        NONE,
        SIGN,
        f,
        32768,
    );
    oc(
        t,
        "ocsp:responder_garbage",
        ALG,
        (ca_ed.as_ptr(), 20),
        g,
        s1,
        NONE,
        SIGN,
        f,
        32768,
    );
    oc(
        t,
        "ocsp:null_responder",
        ALG,
        (null(), 10),
        g,
        s1,
        NONE,
        SIGN,
        f,
        32768,
    );
    oc(
        t,
        "ocsp:responder_len_0",
        ALG,
        (ca_ed.as_ptr(), 0),
        g,
        s1,
        NONE,
        SIGN,
        f,
        32768,
    );
    oc(t, "ocsp:alg0", 0, cc, g, s1, NONE, SIGN, f, 32768);
    oc(t, "ocsp:null_sign", ALG, cc, g, s1, NONE, None, f, 32768);
    oc(
        t,
        "ocsp:sign_fails",
        ALG,
        cc,
        g,
        s1,
        NONE,
        SIGN,
        failing(3373, FUNCTION_FAILED),
        32768,
    );
    oc(
        t,
        "ocsp:sig_empty",
        ALG,
        cc,
        g,
        s1,
        NONE,
        SIGN,
        fake(0),
        32768,
    );
    let s3 = (three.as_ptr(), 3);
    oo(t, "ocsp:ok", s3, p(SEQ5));
    let ok_len = t.n;
    oc(t, "ocsp:cap_0", ALG, cc, g, s3, p(SEQ5), SIGN, f, 0);
    oc(
        t,
        "ocsp:cap_short",
        ALG,
        cc,
        g,
        s3,
        p(SEQ5),
        SIGN,
        f,
        ok_len - 1,
    );
    oc(
        t,
        "ocsp:cap_exact",
        ALG,
        cc,
        g,
        s3,
        p(SEQ5),
        SIGN,
        f,
        ok_len,
    );
    t.n = 32768;
    t.s = f;
    let ctx = t.ctx();
    // SAFETY: NULL outputs are refused before anything is written
    unsafe {
        let r = fhsm_composite_ocsp(
            ALG,
            cc.0,
            cc.1,
            g.0,
            g.1,
            &good,
            1,
            null(),
            0,
            SIGN,
            ctx,
            null_mut(),
            &mut t.n,
        );
        let n = t.n;
        t.row("ocsp:null_out", r, n, true);
        t.s = f;
        let r = fhsm_composite_ocsp(
            ALG,
            cc.0,
            cc.1,
            g.0,
            g.1,
            &good,
            1,
            null(),
            0,
            SIGN,
            ctx,
            t.out.as_mut_ptr(),
            null_mut(),
        );
        t.row("ocsp:null_out_len", r, 0, true);
    }

    let ed = t.signer("ed25519");
    let po = |t: &mut Run, nm: &str, sg: fhsm_pki_signer_t| {
        t.fresh(32768, fake(64));
        let u = fhsm_pki_signer_t {
            sign_ctx: t.ctx(),
            ..sg
        };
        // SAFETY: the signer's pointers cover their lengths
        let r = unsafe {
            fhsm_pki_ocsp(
                &u,
                ca_ed.as_ptr(),
                ca_ed.len(),
                g.0,
                g.1,
                &good,
                1,
                null(),
                0,
                t.out.as_mut_ptr(),
                &mut t.n,
            )
        };
        let n = t.n;
        t.row(nm, r, n, true);
    };
    po(t, "pki_ocsp:ed", ed);
    po(
        t,
        "pki_ocsp:algid_not_checked",
        fhsm_pki_signer_t {
            algid: UT.as_ptr(),
            algid_len: UT.len(),
            ..ed
        },
    );
    po(
        t,
        "pki_ocsp:algid_len_0",
        fhsm_pki_signer_t { algid_len: 0, ..ed },
    );
    po(
        t,
        "pki_ocsp:null_sign",
        fhsm_pki_signer_t { sign: None, ..ed },
    );
    t.n = 32768;
    // SAFETY: a NULL signer is refused
    let r = unsafe {
        fhsm_pki_ocsp(
            null(),
            ca_ed.as_ptr(),
            ca_ed.len(),
            g.0,
            g.1,
            &good,
            1,
            null(),
            0,
            t.out.as_mut_ptr(),
            &mut t.n,
        )
    };
    let n = t.n;
    t.row("pki_ocsp:null_signer", r, n, false);
}

// --- slice 5d: fhsm_pki_ecdsa_raw_to_der and CMS ----------------------------------------

/// One out-writing call as the generator's macros make it: memset, n = cap, s = fk.
fn call(
    t: &mut Run,
    name: &str,
    cap: usize,
    fk: Fake,
    with_fake: bool,
    f: impl FnOnce(*mut c_void, *mut u8, *mut usize) -> u32,
) {
    t.fresh(cap, fk);
    let ctx = t.ctx();
    let r = f(ctx, t.out.as_mut_ptr(), &mut t.n);
    let n = t.n;
    t.row(name, r, n, with_fake);
}

/// The same with OUT and s as the previous row left them, and n = sizeof OUT.
fn call_as_is(
    t: &mut Run,
    name: &str,
    with_fake: bool,
    f: impl FnOnce(*mut c_void, *mut u8, *mut usize) -> u32,
) {
    t.n = t.out.len();
    let ctx = t.ctx();
    let r = f(ctx, t.out.as_mut_ptr(), &mut t.n);
    let n = t.n;
    t.row(name, r, n, with_fake);
}

fn tlv_of(tag: u8, content: &[u8]) -> Vec<u8> {
    let n = content.len();
    let mut v = vec![tag];
    match n {
        0..0x80 => v.push(n as u8),
        0x80..=0xFF => v.extend([0x81, n as u8]),
        0x100..=0xFFFF => v.extend([0x82, (n >> 8) as u8, n as u8]),
        _ => v.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
    }
    v.extend_from_slice(content);
    v
}

fn ecdsa_cases(t: &mut Run) {
    let rs: Vec<u8> = (0..266).map(|i| (i * 7 + 1) as u8).collect();
    let (z, ones) = ([0u8; 64], [0xFFu8; 64]);
    let mut lz = [0u8; 64];
    (lz[2], lz[3], lz[33], lz[34]) = (0x7F, 1, 0x80, 1);
    let er = |t: &mut Run, name: &str, p: *const u8, pn: usize, cap: usize| {
        // SAFETY: p covers pn when not NULL; out has n bytes
        call(t, name, cap, fake(0), false, |_, o, n| unsafe {
            fhsm_pki_ecdsa_raw_to_der(p, pn, o, n)
        });
    };
    let full = 32768;
    er(t, "ecdsa_der:p256", rs.as_ptr(), 64, full);
    let ok = t.n;
    for (name, n) in [
        ("p384", 96),
        ("p521", 132),
        ("264", 264),
        ("266", 266),
        ("2", 2),
        ("odd", 63),
        ("len_0", 0),
    ] {
        er(t, &format!("ecdsa_der:{name}"), rs.as_ptr(), n, full);
    }
    er(t, "ecdsa_der:zeros", z.as_ptr(), 64, full);
    er(t, "ecdsa_der:leading_zeros", lz.as_ptr(), 64, full);
    er(t, "ecdsa_der:ones", ones.as_ptr(), 64, full);
    er(t, "ecdsa_der:null_rs", null(), 64, full);
    er(t, "ecdsa_der:cap_0", rs.as_ptr(), 64, 0);
    er(t, "ecdsa_der:cap_short", rs.as_ptr(), 64, ok - 1);
    er(t, "ecdsa_der:cap_exact", rs.as_ptr(), 64, ok);
    // SAFETY: as above
    call_as_is(t, "ecdsa_der:null_out", false, |_, _, n| unsafe {
        fhsm_pki_ecdsa_raw_to_der(rs.as_ptr(), 64, null_mut(), n)
    });
    // SAFETY: as above
    let r = unsafe { fhsm_pki_ecdsa_raw_to_der(rs.as_ptr(), 64, t.out.as_mut_ptr(), null_mut()) };
    t.row("ecdsa_der:null_out_len", r, 0, false);
}

const DIGALG256: &[u8] = &[
    0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];
const SER2: &[u8] = &[0x02, 0x01, 0x02];
const SET3: &[u8] = &[0x31, 0x03, 0x04, 0x01, 0x00];
const SEQ3: &[u8] = &[0x30, 0x03, 0x02, 0x01, 0x01];
const SATTRS_A0: &[u8] = &[0xA0, 0x03, 0x04, 0x01, 0x00];

fn der_len_octets(n: usize) -> usize {
    match n {
        0..0x80 => 1,
        0x80..0x100 => 2,
        0x100..0x10000 => 3,
        _ => 4,
    }
}

/// fhsm_composite_cms_signerinfo over six parts: issuer, serial, digalg, sattrs, sigalg, sig.
///
/// # Safety
/// Each part covers its length when not NULL; `o` has `*n` writable bytes when not NULL.
unsafe fn signerinfo(p: [Part; 6], o: *mut u8, n: *mut usize) -> u32 {
    // SAFETY: the caller's contract
    unsafe {
        fhsm_composite_cms_signerinfo(
            p[0].0, p[0].1, p[1].0, p[1].1, p[2].0, p[2].1, p[3].0, p[3].1, p[4].0, p[4].1, p[5].0,
            p[5].1, o, n,
        )
    }
}

fn cms_si_cases(t: &mut Run) {
    let (iss, sga) = (t.fx("ca_ed_issuer"), t.fx("algid_ed25519"));
    let sig: Vec<u8> = (0..64).collect();
    let si = |t: &mut Run, name: &str, parts: [Part; 6], cap: usize| {
        // SAFETY: each part covers its length when not NULL; out has n bytes
        call(t, name, cap, fake(0), false, |_, o, n| unsafe {
            signerinfo(parts, o, n)
        });
    };
    let good = [p(&iss), p(SER2), p(DIGALG256), p(SET3), p(&sga), p(&sig)];
    let with = |i: usize, part: Part| {
        let mut v = good;
        v[i] = part;
        v
    };
    let full = 32768;
    si(t, "cms_si:ok", good, full);
    let ok = t.n;
    let names = ["issuer", "serial", "digalg", "sattrs", "sigalg", "sig"];
    for (i, name) in names.iter().enumerate() {
        si(
            t,
            &format!("cms_si:null_{name}"),
            with(i, (null(), good[i].1)),
            full,
        );
        si(
            t,
            &format!("cms_si:{name}_len_0"),
            with(i, (good[i].0, 0)),
            full,
        );
    }
    si(t, "cms_si:issuer_tag", with(0, p(SET3)), full);
    si(t, "cms_si:serial_tag", with(1, p(SET3)), full);
    si(t, "cms_si:digalg_tag", with(2, p(SET3)), full);
    si(t, "cms_si:sattrs_tag_a0", with(3, p(SATTRS_A0)), full);
    si(t, "cms_si:sattrs_tag_seq", with(3, p(SEQ3)), full);
    si(t, "cms_si:sigalg_tag", with(4, p(SET3)), full);
    si(t, "cms_si:cap_0", good, 0);
    si(t, "cms_si:cap_short", good, ok - 1);
    si(t, "cms_si:cap_exact", good, ok);
    // SAFETY: as above
    call_as_is(t, "cms_si:null_out", false, |_, _, n| unsafe {
        signerinfo(good, null_mut(), n)
    });
    // SAFETY: as above
    let r = unsafe { signerinfo(good, t.out.as_mut_ptr(), null_mut()) };
    t.row("cms_si:null_out_len", r, 0, false);
    let ic = iss.len() + 3;
    let fixed = 3 + (1 + der_len_octets(ic) + ic) + 13 + 5 + sga.len() + 5;
    let mut b = big(0x100_0000, 0);
    si(
        t,
        "cms_si:content_max",
        with(5, (b.as_ptr(), 0xFF_FFFF - fixed)),
        1,
    );
    si(
        t,
        "cms_si:content_max_plus_1",
        with(5, (b.as_ptr(), 0xFF_FFFF - fixed + 1)),
        1,
    );
    si(t, "cms_si:sig_over", with(5, (b.as_ptr(), 0x100_0000)), 1);
    b[0] = 0x30;
    si(t, "cms_si:issuer_over", with(0, (b.as_ptr(), 0xFF_FFFD)), 1);
}

fn cms_wrap_cases(t: &mut Run) {
    let cert = t.fx("ca_ed");
    let certs = tlv_of(0x31, &cert);
    let wr = |t: &mut Run, name: &str, d: Part, c: Part, s: Part, cap: usize| {
        // SAFETY: each part covers its length when not NULL; out has n bytes
        call(t, name, cap, fake(0), false, |_, o, n| unsafe {
            fhsm_composite_cms_wrap(d.0, d.1, c.0, c.1, s.0, s.1, o, n)
        });
    };
    let (d, c, s, full) = (p(DIGALG256), p(&certs), p(SEQ3), 32768);
    wr(t, "cms_wrap:ok", d, c, s, full);
    let ok = t.n;
    wr(t, "cms_wrap:no_certs", d, NONE, s, full);
    wr(t, "cms_wrap:null_digalg", (null(), 13), c, s, full);
    wr(t, "cms_wrap:digalg_len_0", (d.0, 0), c, s, full);
    wr(t, "cms_wrap:null_si", d, c, (null(), 5), full);
    wr(t, "cms_wrap:si_len_0", d, c, (s.0, 0), full);
    wr(t, "cms_wrap:digalg_tag", p(SET3), c, s, full);
    wr(t, "cms_wrap:si_tag", d, c, p(SET3), full);
    wr(t, "cms_wrap:certs_ptr_no_len", d, (c.0, 0), s, full);
    wr(t, "cms_wrap:certs_len_no_ptr", d, (null(), 5), s, full);
    wr(t, "cms_wrap:certs_tag", d, p(&cert), s, full);
    wr(t, "cms_wrap:cap_0", d, c, s, 0);
    wr(t, "cms_wrap:cap_short", d, c, s, ok - 1);
    wr(t, "cms_wrap:cap_exact", d, c, s, ok);
    // SAFETY: as above
    call_as_is(t, "cms_wrap:null_out", false, |_, _, n| unsafe {
        fhsm_composite_cms_wrap(d.0, d.1, c.0, c.1, s.0, s.1, null_mut(), n)
    });
    // SAFETY: as above
    let r = unsafe {
        fhsm_composite_cms_wrap(d.0, d.1, c.0, c.1, s.0, s.1, t.out.as_mut_ptr(), null_mut())
    };
    t.row("cms_wrap:null_out_len", r, 0, false);
    let lo = t
        .fx("cms_wrap_si_max")
        .iter()
        .fold(0usize, |n, &x| n << 8 | usize::from(x));
    let g = big(0x100_0000, 0x30);
    wr(t, "cms_wrap:content_max", d, c, (g.as_ptr(), lo), 1);
    wr(
        t,
        "cms_wrap:content_max_plus_1",
        d,
        c,
        (g.as_ptr(), lo + 1),
        1,
    );
    wr(t, "cms_wrap:si_over", d, c, (g.as_ptr(), 0x100_0000), 1);
}

fn pki_cms_cases(t: &mut Run) {
    const ALG_SET: &[u8] = &[0x31, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];
    let d64: Vec<u8> = (0..64).map(|i| (i * 3 + 1) as u8).collect();
    let (ca_ed, ca_comp) = (t.fx("ca_ed"), t.fx("ca_comp"));
    let (noskid, bigc) = (t.fx("ca_noskid"), t.fx("ca_big_issuer"));
    let trail = flip(&ca_ed, ca_ed.len(), 0, 1);
    let pc = |t: &mut Run,
              name: &str,
              sg: fhsm_pki_signer_t,
              dn: Option<&str>,
              cert: Part,
              dg: Part,
              fk: Fake,
              cap: usize| {
        let dn = dn.map(c);
        call(t, name, cap, fk, true, |ctx, o, n| {
            let mut sg = sg;
            sg.sign_ctx = ctx;
            let dn = dn.as_ref().map_or(null(), |d| d.as_ptr());
            // SAFETY: the signer's buffers, the name, cert and digest cover their lengths
            unsafe { fhsm_pki_cms(&sg, dn, cert.0, cert.1, dg.0, dg.1, o, n) }
        });
    };
    let (ed, ec, rsa) = (t.signer("ed25519"), t.signer("ec"), t.signer("rsa"));
    let (ml, comp) = (t.signer("mldsa44"), t.signer("composite"));
    let (e, full, f, s256) = (p(&ca_ed), 32768, fake(64), Some("SHA256"));
    let d = |n: usize| (d64.as_ptr(), n);
    pc(t, "pki_cms:ed25519", ed, s256, e, d(32), f, full);
    let ok = t.n;
    pc(t, "pki_cms:ec", ec, s256, e, d(32), fake(72), full);
    pc(
        t,
        "pki_cms:ec_sha384",
        ec,
        Some("SHA384"),
        e,
        d(48),
        fake(72),
        full,
    );
    pc(t, "pki_cms:rsa", rsa, s256, e, d(32), fake(256), full);
    pc(
        t,
        "pki_cms:mldsa44",
        ml,
        Some("SHA512"),
        e,
        d(64),
        fake(2420),
        full,
    );
    let cc = p(&ca_comp);
    pc(
        t,
        "pki_cms:composite",
        comp,
        Some("SHA512"),
        cc,
        d(64),
        fake(3373),
        full,
    );
    for (name, dn, n) in [
        ("sha256_lower", "sha256", 32),
        ("sha2_256", "SHA2-256", 32),
        ("sha3_256", "SHA3-256", 32),
        ("sha1", "SHA1", 20),
        ("md5", "MD5", 16),
        ("shake128_16", "SHAKE128", 16),
        ("shake128_32", "SHAKE128", 32),
        ("unknown_digest", "NOPE", 32),
        ("empty_digest_name", "", 32),
        ("digest_short", "SHA256", 31),
        ("digest_long", "SHA256", 33),
        ("digest_len_0", "SHA256", 0),
    ] {
        pc(
            t,
            &format!("pki_cms:{name}"),
            ed,
            Some(dn),
            e,
            d(n),
            f,
            full,
        );
    }
    pc(
        t,
        "pki_cms:cert_garbage",
        ed,
        s256,
        (e.0, 20),
        d(32),
        f,
        full,
    );
    pc(t, "pki_cms:cert_len_0", ed, s256, (e.0, 0), d(32), f, full);
    pc(
        t,
        "pki_cms:cert_trailing",
        ed,
        s256,
        p(&trail),
        d(32),
        f,
        full,
    );
    pc(
        t,
        "pki_cms:cert_noskid",
        ed,
        s256,
        p(&noskid),
        d(32),
        f,
        full,
    );
    pc(
        t,
        "pki_cms:sign_fails",
        ed,
        s256,
        e,
        d(32),
        failing(64, 0x30),
        full,
    );
    pc(t, "pki_cms:sig_len_0", ed, s256, e, d(32), fake(0), full);
    pc(t, "pki_cms:sig_8192", ed, s256, e, d(32), fake(8192), full);
    pc(
        t,
        "pki_cms:big_issuer",
        ed,
        s256,
        p(&bigc),
        d(32),
        fake(8192),
        full,
    );
    pc(
        t,
        "pki_cms:big_issuer_small_sig",
        ed,
        s256,
        p(&bigc),
        d(32),
        f,
        full,
    );
    let mut x = ed;
    (x.algid, x.algid_len) = (ALG_SET.as_ptr(), ALG_SET.len());
    pc(t, "pki_cms:algid_tag", x, s256, e, d(32), f, full);
    x = ed;
    x.algid = null();
    pc(t, "pki_cms:null_algid", x, s256, e, d(32), f, full);
    x = ed;
    x.algid_len = 0;
    pc(t, "pki_cms:algid_len_0", x, s256, e, d(32), f, full);
    x = ed;
    x.sign = None;
    pc(t, "pki_cms:null_sign", x, s256, e, d(32), f, full);
    x = ed;
    (x.spki, x.spki_len) = (null(), 0);
    pc(t, "pki_cms:no_spki", x, s256, e, d(32), f, full);
    pc(t, "pki_cms:null_digest_name", ed, None, e, d(32), f, full);
    pc(
        t,
        "pki_cms:null_cert",
        ed,
        s256,
        (null(), e.1),
        d(32),
        f,
        full,
    );
    pc(t, "pki_cms:null_digest", ed, s256, e, (null(), 32), f, full);
    pc(t, "pki_cms:cap_0", ed, s256, e, d(32), f, 0);
    pc(t, "pki_cms:cap_short", ed, s256, e, d(32), f, ok - 1);
    pc(t, "pki_cms:cap_exact", ed, s256, e, d(32), f, ok);
    let sha = c("SHA256");
    // SAFETY (this call and the next two): as above
    call_as_is(t, "pki_cms:null_signer", false, |_, o, n| unsafe {
        fhsm_pki_cms(null(), sha.as_ptr(), e.0, e.1, d64.as_ptr(), 32, o, n)
    });
    t.s = f;
    call_as_is(t, "pki_cms:null_out", true, |ctx, _, n| {
        let mut sg = ed;
        sg.sign_ctx = ctx;
        unsafe { fhsm_pki_cms(&sg, sha.as_ptr(), e.0, e.1, d64.as_ptr(), 32, null_mut(), n) }
    });
    let mut sg = ed;
    sg.sign_ctx = t.ctx();
    let out = t.out.as_mut_ptr();
    let r = unsafe {
        fhsm_pki_cms(
            &sg,
            sha.as_ptr(),
            e.0,
            e.1,
            d64.as_ptr(),
            32,
            out,
            null_mut(),
        )
    };
    t.row("pki_cms:null_out_len", r, 0, true);

    let cm = |t: &mut Run,
              name: &str,
              alg: c_int,
              cert: Part,
              dg: Part,
              cb: fhsm_composite_sign_cb,
              fk: Fake,
              cap: usize| {
        // SAFETY: cert and digest cover their lengths when not NULL; out has n bytes
        call(t, name, cap, fk, true, |ctx, o, n| unsafe {
            fhsm_composite_cms(alg, cert.0, cert.1, dg.0, dg.1, cb, ctx, o, n)
        });
    };
    let fc = fake(3373);
    cm(t, "cms:ok", ALG, cc, d(64), SIGN, fc, full);
    let ok = t.n;
    cm(t, "cms:alg0", 0, cc, d(64), SIGN, fc, full);
    cm(
        t,
        "cms:null_cert",
        ALG,
        (null(), cc.1),
        d(64),
        SIGN,
        fc,
        full,
    );
    cm(
        t,
        "cms:cert_garbage",
        ALG,
        (cc.0, 20),
        d(64),
        SIGN,
        fc,
        full,
    );
    cm(t, "cms:null_digest", ALG, cc, (null(), 64), SIGN, fc, full);
    cm(t, "cms:digest_32", ALG, cc, d(32), SIGN, fc, full);
    cm(t, "cms:null_sign", ALG, cc, d(64), None, fc, full);
    let fails = failing(3373, FUNCTION_FAILED);
    cm(t, "cms:sign_fails", ALG, cc, d(64), SIGN, fails, full);
    cm(t, "cms:cap_short", ALG, cc, d(64), SIGN, fc, ok - 1);
    t.s = fc;
    // SAFETY (this call and the next): as above
    call_as_is(t, "cms:null_out", true, |ctx, _, n| unsafe {
        fhsm_composite_cms(ALG, cc.0, cc.1, d64.as_ptr(), 64, SIGN, ctx, null_mut(), n)
    });
    let (ctx, out) = (t.ctx(), t.out.as_mut_ptr());
    let r = unsafe {
        fhsm_composite_cms(
            ALG,
            cc.0,
            cc.1,
            d64.as_ptr(),
            64,
            SIGN,
            ctx,
            out,
            null_mut(),
        )
    };
    t.row("cms:null_out_len", r, 0, true);
}

fn digest_name(p: *const c_char) -> String {
    if p.is_null() {
        "-".into()
    } else {
        // SAFETY: a NUL-terminated name
        unsafe { std::ffi::CStr::from_ptr(p) }
            .to_string_lossy()
            .into_owned()
    }
}

/// Every structure the generator verified (the `cmsv:` rows, inputs in the fixture) through
/// both verifiers and fhsm_pki_cms_digest; then the pointer checks.
fn cms_verify_cases(t: &mut Run, want: &[String]) {
    let names = want
        .iter()
        .filter_map(|w| Some(w.strip_prefix("cmsv:")?.split_once('\t')?.0.to_owned()));
    for name in names {
        let cms = t.fx(&format!("cmsv:{name}"));
        let d = t.fx(&format!("cmsd:{name}"));
        let mut dn = null();
        // SAFETY: each buffer covers its length; dn is writable
        let (rc, rp, rd) = unsafe {
            (
                fhsm_composite_cms_verify(ALG, cms.as_ptr(), cms.len(), d.as_ptr(), d.len()),
                fhsm_pki_cms_verify(cms.as_ptr(), cms.len(), d.as_ptr(), d.len()),
                fhsm_pki_cms_digest(cms.as_ptr(), cms.len(), &mut dn),
            )
        };
        let dn = digest_name(dn);
        t.rows.push(format!(
            "cmsv:{name}\tcomposite=0x{rc:x};pki=0x{rp:x};digest=0x{rd:x};name={dn}"
        ));
    }
    let last = t.fx("cmsv:assembled/composite_attrs_unsorted");
    let d: Vec<u8> = (0..64).map(|i| (i * 5 + 3) as u8).collect();
    let x = c("x");
    // SAFETY: each buffer covers its length when not NULL
    unsafe {
        let (rc, rp) = (
            fhsm_composite_cms_verify(ALG, null(), 10, d.as_ptr(), 64),
            fhsm_pki_cms_verify(null(), 10, d.as_ptr(), 64),
        );
        t.rows.push(format!(
            "cms_verify:null_cms\tcomposite=0x{rc:x};pki=0x{rp:x}"
        ));
        let (rc, rp) = (
            fhsm_composite_cms_verify(ALG, last.as_ptr(), last.len(), null(), 64),
            fhsm_pki_cms_verify(last.as_ptr(), last.len(), null(), 64),
        );
        t.rows.push(format!(
            "cms_verify:null_digest\tcomposite=0x{rc:x};pki=0x{rp:x}"
        ));
        let rc = fhsm_composite_cms_verify(0, last.as_ptr(), last.len(), d.as_ptr(), 64);
        t.rows.push(format!("cms_verify:alg0\tcomposite=0x{rc:x}"));
        let mut dn = x.as_ptr();
        let r = fhsm_pki_cms_digest(null(), 10, &mut dn);
        t.rows.push(format!(
            "cms_digest:null_cms\trv=0x{r:x};name={}",
            digest_name(dn)
        ));
        let r = fhsm_pki_cms_digest(last.as_ptr(), last.len(), null_mut());
        t.rows.push(format!("cms_digest:null_name\trv=0x{r:x}"));
        let mut dn = x.as_ptr();
        let r = fhsm_pki_cms_digest(last.as_ptr(), 3, &mut dn);
        t.rows.push(format!(
            "cms_digest:garbage\trv=0x{r:x};name={}",
            digest_name(dn)
        ));
    }
}

#[test]
fn every_call_returns_and_writes_what_the_c_did() {
    let read = |f: &str| std::fs::read_to_string(format!("{GOLDEN}/{f}")).unwrap();
    let want: Vec<String> = read("x509.tsv")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(str::to_owned)
        .collect();
    let fx = read("x509_fixture.tsv")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once('\t').unwrap();
            let b = (0..v.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&v[i..i + 2], 16).unwrap())
                .collect();
            (k.to_owned(), b)
        })
        .collect();
    let mut t = Run {
        rows: Vec::new(),
        out: vec![0; 32768],
        n: 0,
        s: fake(0),
        fx,
    };
    key_cases(&mut t);
    csr_cases(&mut t);
    selfsigned_cases(&mut t);
    issue_cases(&mut t);
    algid_cases(&mut t);
    crl_tbs_cases(&mut t);
    crl_cases(&mut t);
    ocsp_single_cases(&mut t);
    ocsp_tbs_cases(&mut t);
    ocsp_cases(&mut t);
    ecdsa_cases(&mut t);
    cms_si_cases(&mut t);
    cms_wrap_cases(&mut t);
    pki_cms_cases(&mut t);
    cms_verify_cases(&mut t, &want);
    for (got, want) in t.rows.iter().zip(&want) {
        assert_eq!(got, want);
    }
    assert_eq!(t.rows.len(), want.len());

    // DIV-048: a signer reporting more signature than its room fails the build; C read past it.
    unsafe extern "C" fn over(
        _: *mut c_void,
        _: *const u8,
        _: usize,
        _: *mut u8,
        sl: *mut usize,
    ) -> u32 {
        // SAFETY: sl is writable
        unsafe { *sl += 1 };
        0
    }
    let mut s = t.signer("ed25519");
    s.sign = Some(over);
    let mut n = t.out.len();
    // SAFETY: the signer's buffers and the subject are live; out has n bytes
    let r = unsafe { fhsm_pki_csr(&s, c"/CN=div048".as_ptr(), t.out.as_mut_ptr(), &mut n) };
    assert_eq!(r, FUNCTION_FAILED, "DIV-048");

    // DIV-049: an SPKI whose parameters are a BOOLEAN is refused; C dup'd the value as a string
    // and crashed. The same copy takes an issued request's key.
    let spki = [
        &[
            0x30, 0x32, 0x30, 0x0D, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x30,
        ][..],
        &[0x01, 0x01, 0xFF, 0x03, 0x21, 0x00],
        &[0x11; 32],
    ]
    .concat();
    let mut s = t.signer("ed25519");
    (s.spki, s.spki_len) = (spki.as_ptr(), spki.len());
    let mut n = t.out.len();
    // SAFETY: as above
    let r = unsafe { fhsm_pki_csr(&s, c"/CN=div049".as_ptr(), t.out.as_mut_ptr(), &mut n) };
    assert_eq!(r, ARGUMENTS_BAD, "DIV-049");
}
