//! `tests/golden/composite/composite.tsv` (tests-support/golden/gen_composite.c) replayed: every
//! call the generator made, made again through the Rust C ABI with the same arguments, each row
//! formatted as the C formatted it. Signing uses the C's key pair (`composite_fixture.tsv`):
//! the Ed25519 half is deterministic and compared byte for byte, the ML-DSA half is checked by
//! verifying it; verification runs on the C's own signatures.
#![cfg(feature = "ffi")]
#![allow(clippy::too_many_arguments)]

use std::ffi::{CStr, c_int};
use std::fmt::Write;
use std::ptr::{null, null_mut};

use pqhsm_pki::ffi::*;

const GOLDEN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden/composite");
const ALG: c_int = 1;
const SIG_LEN: usize = 3309 + 64;
/// gen_composite.c's MSG, its NUL included (`sizeof MSG`).
const MSG: &[u8] = b"the message signed by the composite goldens\0";
const PH64: [u8; 64] = {
    let mut p = [0u8; 64];
    let mut i = 0;
    while i < 8 {
        p[i] = i as u8 + 1;
        i += 1;
    }
    p
};

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn fixture(name: &str) -> Vec<u8> {
    let f = std::fs::read_to_string(format!("{GOLDEN}/composite_fixture.tsv")).unwrap();
    let line = f
        .lines()
        .find(|l| l.starts_with(&format!("{name}\t")))
        .unwrap();
    unhex(line.split('\t').nth(1).unwrap())
}

/// gen_composite.c's `bad`: a copy with one byte changed and the length moved.
fn bad(src: &[u8], at: usize, xor: u8, trim: isize) -> Vec<u8> {
    let mut b = src.to_vec();
    b.resize(src.len() + 1, 0);
    if at < src.len() {
        b[at] ^= xor;
    }
    b.truncate((src.len() as isize + trim) as usize);
    b
}

struct Run {
    rows: Vec<String>,
    ctx: [u8; 256],
    private: Vec<u8>,
    public: Vec<u8>,
}

impl Run {
    fn row(&mut self, name: &str, rv: u32, len: usize, out: Option<&[u8]>) {
        self.rows.push(format!(
            "{name}\trv=0x{rv:x};len={len};out={}",
            out.map_or(String::new(), hex)
        ));
    }

    fn mprime(
        &mut self,
        name: &str,
        alg: c_int,
        msg: Option<&[u8]>,
        mlen: usize,
        ctx: Option<usize>,
        clen: usize,
        cap: usize,
    ) {
        let mut out = [0xAAu8; 512];
        let mut n = cap;
        let msg = msg.map_or(null(), <[u8]>::as_ptr);
        let ctx = ctx.map_or(null(), |o| self.ctx[o..].as_ptr());
        // SAFETY: every pointer is NULL or covers its length
        let r =
            unsafe { fhsm_composite_mprime(alg, msg, mlen, ctx, clen, out.as_mut_ptr(), &mut n) };
        self.row(&format!("mprime:{name}"), r, n, Some(&out[..cap.min(512)]));
    }

    fn mprime_ph(
        &mut self,
        name: &str,
        alg: c_int,
        ph: Option<&[u8]>,
        plen: usize,
        ctx: Option<usize>,
        clen: usize,
        cap: usize,
    ) {
        let mut out = [0xAAu8; 512];
        let mut n = cap;
        let ph = ph.map_or(null(), <[u8]>::as_ptr);
        let ctx = ctx.map_or(null(), |o| self.ctx[o..].as_ptr());
        // SAFETY: as mprime
        let r = unsafe {
            fhsm_composite_mprime_prehashed(alg, ph, plen, ctx, clen, out.as_mut_ptr(), &mut n)
        };
        self.row(
            &format!("mprime_ph:{name}"),
            r,
            n,
            Some(&out[..cap.min(512)]),
        );
    }

    fn framing(&mut self, name: &str, rv: u32, b: &[u8], n: usize) {
        let mut s = format!("{name}\trv=0x{rv:x};len={n}");
        if rv == 0 && n >= 8 {
            let n1 = usize::from(b[6]) | usize::from(b[7]) << 8;
            let n2 = usize::from(b[8 + n1]) | usize::from(b[9 + n1]) << 8;
            let _ = write!(s, ";head={};pq={n1};trad={n2}", hex(&b[..6]));
        }
        self.rows.push(s);
    }

    fn keygen(
        &mut self,
        name: &str,
        alg: c_int,
        null_priv: bool,
        null_priv_len: bool,
        null_pub: bool,
        null_pub_len: bool,
        ca: usize,
        cb: usize,
    ) {
        let (mut a, mut b) = (vec![0xAAu8; 8192], vec![0xAAu8; 4096]);
        let (mut na, mut nb) = (ca, cb);
        let pa = if null_priv {
            null_mut()
        } else {
            a.as_mut_ptr()
        };
        let pna = if null_priv_len {
            null_mut()
        } else {
            &raw mut na
        };
        let pb = if null_pub { null_mut() } else { b.as_mut_ptr() };
        let pnb = if null_pub_len {
            null_mut()
        } else {
            &raw mut nb
        };
        // SAFETY: each buffer has at least the length passed
        let r = unsafe { fhsm_composite_keygen(alg, pa, pna, pb, pnb) };
        self.framing(&format!("keygen:{name}:priv"), r, &a, na);
        self.framing(&format!("keygen:{name}:pub"), r, &b, nb);
        self.rows.push(format!(
            "keygen:{name}:untouched\tpriv={};pub={}",
            u8::from(a[0] == 0xAA),
            u8::from(b[0] == 0xAA)
        ));
    }

    fn verify(&self, msg: &[u8], ctx: Option<(usize, usize)>, sig: &[u8]) -> u32 {
        let (c, clen) = ctx.map_or((null(), 0), |(o, n)| (self.ctx[o..].as_ptr(), n));
        // SAFETY: every pointer covers its length
        unsafe {
            fhsm_composite_verify(
                ALG,
                self.public.as_ptr(),
                self.public.len(),
                msg.as_ptr(),
                msg.len(),
                c,
                clen,
                sig.as_ptr(),
                sig.len(),
            )
        }
    }

    fn sign(
        &mut self,
        name: &str,
        alg: c_int,
        key: &[u8],
        msg: Option<&[u8]>,
        mlen: usize,
        ctx: Option<usize>,
        clen: usize,
        cap: usize,
    ) {
        let mut s = vec![0xAAu8; SIG_LEN + 100];
        let mut n = cap;
        let m = msg.map_or(null(), <[u8]>::as_ptr);
        let c = ctx.map_or(null(), |o| self.ctx[o..].as_ptr());
        // SAFETY: every pointer is NULL or covers its length
        let r = unsafe {
            fhsm_composite_sign(
                alg,
                key.as_ptr(),
                key.len(),
                m,
                mlen,
                c,
                clen,
                s.as_mut_ptr(),
                &mut n,
            )
        };
        let mut row = format!("sign:{name}\trv=0x{r:x};len={n}");
        if r == 0 {
            let v = self.verify(&msg.unwrap()[..mlen], ctx.map(|o| (o, clen)), &s[..n]);
            let _ = write!(
                row,
                ";ed25519={};verifies=0x{v:x}",
                hex(&s[3309..3309 + 64])
            );
        }
        self.rows.push(row);
    }
}

#[test]
fn every_call_returns_and_writes_what_the_c_did() {
    let want: Vec<String> = std::fs::read_to_string(format!("{GOLDEN}/composite.tsv"))
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(str::to_owned)
        .collect();
    let mut ctx = [0u8; 256];
    for (i, c) in ctx.iter_mut().enumerate() {
        *c = (i * 7 + 1) as u8;
    }
    let mut t = Run {
        rows: Vec::new(),
        ctx,
        private: fixture("priv"),
        public: fixture("pub"),
    };

    // table_cases
    for alg in 0..=2 {
        let p = fhsm_composite_params(alg);
        if p.is_null() {
            t.rows.push(format!("params:{alg}\tNULL"));
            continue;
        }
        // SAFETY: a pointer to the static table and its static strings
        let p = unsafe { &*p };
        let s = |c| unsafe { CStr::from_ptr(c) }.to_str().unwrap();
        t.rows.push(format!(
            "params:{alg}\talg={};name={};oid={};label={};label_len={};ph_name={};ph_len={}",
            p.alg,
            s(p.name),
            s(p.oid),
            s(p.label),
            p.label_len,
            s(p.ph_name),
            p.ph_len
        ));
    }
    for alg in 0..=2 {
        let ph = fhsm_composite_ph_name(alg);
        // SAFETY: NULL or a static string
        let name = if ph.is_null() {
            "NULL"
        } else {
            unsafe { CStr::from_ptr(ph) }.to_str().unwrap()
        };
        t.rows.push(format!(
            "ph:{alg}\tname={name};len={}",
            fhsm_composite_ph_len(alg)
        ));
        for c in [0, 1, 255, 256, usize::MAX] {
            t.rows.push(format!(
                "mprime_len:{alg}:{c}\t{}",
                fhsm_composite_mprime_len(alg, c)
            ));
        }
    }
    let sig1 = [0u8; 1];
    for len in [0, SIG_LEN - 1, SIG_LEN, SIG_LEN + 1] {
        let (mut pq, mut tr) = (77, 77);
        // SAFETY: the signature is not read; both outputs are locals
        let r = unsafe { fhsm_composite_split(ALG, sig1.as_ptr(), len, &mut pq, &mut tr) };
        t.rows
            .push(format!("split:{len}\trv=0x{r:x};pq={pq};trad={tr}"));
    }
    let (mut pq, mut tr) = (77, 77);
    // SAFETY: as above, or NULL
    unsafe {
        t.rows.push(format!(
            "split:alg0\trv=0x{:x}",
            fhsm_composite_split(0, sig1.as_ptr(), SIG_LEN, &mut pq, &mut tr)
        ));
        t.rows.push(format!(
            "split:null_sig\trv=0x{:x}",
            fhsm_composite_split(ALG, null(), SIG_LEN, &mut pq, &mut tr)
        ));
        t.rows.push(format!(
            "split:null_pq\trv=0x{:x}",
            fhsm_composite_split(ALG, sig1.as_ptr(), SIG_LEN, null_mut(), &mut tr)
        ));
        t.rows.push(format!(
            "split:null_trad\trv=0x{:x}",
            fhsm_composite_split(ALG, sig1.as_ptr(), SIG_LEN, &mut pq, null_mut())
        ));
    }

    // mprime_cases
    let m = Some(MSG);
    let ml = MSG.len();
    t.mprime("alg0", 0, m, ml, None, 0, 200);
    t.mprime("alg2", 2, m, ml, None, 0, 200);
    t.mprime("null_msg_len", ALG, None, 3, None, 0, 200);
    t.mprime("null_msg_empty", ALG, None, 0, None, 0, 200);
    t.mprime("empty_msg", ALG, m, 0, None, 0, 200);
    t.mprime("null_ctx_len", ALG, m, ml, None, 2, 200);
    t.mprime("ctx_255", ALG, m, ml, Some(0), 255, 400);
    t.mprime("ctx_256", ALG, m, ml, Some(0), 256, 400);
    t.mprime("ctx_1", ALG, m, ml, Some(0), 1, 200);
    t.mprime("cap_0", ALG, m, ml, None, 0, 0);
    t.mprime("cap_short", ALG, m, ml, None, 0, 126);
    t.mprime("cap_exact", ALG, m, ml, None, 0, 127);
    t.mprime("cap_more", ALG, m, ml, None, 0, 140);
    t.mprime("ctx_3_cap_short", ALG, m, ml, Some(0), 3, 129);
    let mut out = [0u8; 512];
    let mut n = 200;
    // SAFETY: NULL outputs are refused before anything is written
    unsafe {
        let r = fhsm_composite_mprime(ALG, MSG.as_ptr(), ml, null(), 0, null_mut(), &mut n);
        t.row("mprime:null_out", r, n, None);
        let r = fhsm_composite_mprime(
            ALG,
            MSG.as_ptr(),
            ml,
            null(),
            0,
            out.as_mut_ptr(),
            null_mut(),
        );
        t.row("mprime:null_out_len", r, 0, None);
    }
    let ph = [0x5cu8; 64];
    let p = Some(&ph[..]);
    t.mprime_ph("alg0", 0, p, 64, None, 0, 200);
    t.mprime_ph("null_ph", ALG, None, 64, None, 0, 200);
    t.mprime_ph("ph_63", ALG, p, 63, None, 0, 200);
    t.mprime_ph("ph_65", ALG, p, 65, None, 0, 200);
    t.mprime_ph("null_ctx_len", ALG, p, 64, None, 2, 200);
    t.mprime_ph("ctx_256", ALG, p, 64, Some(0), 256, 400);
    t.mprime_ph("ctx_255", ALG, p, 64, Some(0), 255, 400);
    t.mprime_ph("cap_short", ALG, p, 64, Some(0), 7, 133);
    t.mprime_ph("cap_exact", ALG, p, 64, Some(0), 7, 134);
    t.mprime_ph("ok", ALG, p, 64, None, 0, 200);
    n = 200;
    // SAFETY: as above
    unsafe {
        let r =
            fhsm_composite_mprime_prehashed(ALG, ph.as_ptr(), 64, null(), 0, null_mut(), &mut n);
        t.row("mprime_ph:null_out", r, n, None);
        let r = fhsm_composite_mprime_prehashed(
            ALG,
            ph.as_ptr(),
            64,
            null(),
            0,
            out.as_mut_ptr(),
            null_mut(),
        );
        t.row("mprime_ph:null_out_len", r, 0, None);
    }

    // keygen_cases
    t.keygen("alg0", 0, false, false, false, false, 8192, 4096);
    t.keygen("null_priv", ALG, true, false, false, false, 8192, 4096);
    t.keygen("null_priv_len", ALG, false, true, false, false, 8192, 4096);
    t.keygen("null_pub", ALG, false, false, true, false, 8192, 4096);
    t.keygen("null_pub_len", ALG, false, false, false, true, 8192, 4096);
    t.keygen("priv_short", ALG, false, false, false, false, 100, 4096);
    t.keygen("pub_short", ALG, false, false, false, false, 8192, 100);
    t.keygen("ok", ALG, false, false, false, false, 8192, 4096);

    // sign_cases
    let (k, kn) = (t.private.clone(), t.private.len());
    let cap = SIG_LEN + 100;
    t.sign("alg0", 0, &k, m, ml, None, 0, cap);
    t.sign("ctx_256", ALG, &k, m, ml, Some(0), 256, cap);
    t.sign("null_ctx_len", ALG, &k, m, ml, None, 1, cap);
    t.sign("null_msg_len", ALG, &k, None, 1, None, 0, cap);
    t.sign("short_blob", ALG, &k[..9], m, ml, None, 0, cap);
    t.sign("bad_magic", ALG, &bad(&k, 0, 1, 0), m, ml, None, 0, cap);
    t.sign("bad_version", ALG, &bad(&k, 4, 2, 0), m, ml, None, 0, cap);
    t.sign("other_alg", ALG, &bad(&k, 5, 3, 0), m, ml, None, 0, cap);
    t.sign(
        "pq_len_past_end",
        ALG,
        &bad(&k, 7, 0x40, 0),
        m,
        ml,
        None,
        0,
        cap,
    );
    t.sign(
        "trailing_byte",
        ALG,
        &bad(&k, kn, 0, 1),
        m,
        ml,
        None,
        0,
        cap,
    );
    t.sign(
        "missing_byte",
        ALG,
        &bad(&k, kn, 0, -1),
        m,
        ml,
        None,
        0,
        cap,
    );
    t.sign("bad_pq_der", ALG, &bad(&k, 8, 0xFF, 0), m, ml, None, 0, cap);
    t.sign(
        "bad_trad_der",
        ALG,
        &bad(&k, kn - 30, 0xFF, 0),
        m,
        ml,
        None,
        0,
        cap,
    );
    let public = t.public.clone();
    t.sign("pub_as_priv", ALG, &public, m, ml, None, 0, cap);
    t.sign("cap_0", ALG, &k, m, ml, None, 0, 0);
    t.sign("cap_pq_short", ALG, &k, m, ml, None, 0, 3308);
    t.sign("cap_pq_only", ALG, &k, m, ml, None, 0, 3309);
    t.sign("cap_ed_short", ALG, &k, m, ml, None, 0, SIG_LEN - 1);
    t.sign("cap_exact", ALG, &k, m, ml, None, 0, SIG_LEN);
    t.sign("cap_more", ALG, &k, m, ml, None, 0, cap);
    t.sign("ctx_5", ALG, &k, m, ml, Some(0), 5, cap);
    t.sign("empty_msg", ALG, &k, m, 0, None, 0, cap);
    let mut s = vec![0u8; cap];
    let mut n = cap;
    let ctx = t.ctx;
    // SAFETY: NULL arguments are refused first; the rest cover their lengths
    unsafe {
        let ms = MSG.as_ptr();
        let rows = [
            (
                "sign:null_priv",
                fhsm_composite_sign(ALG, null(), kn, ms, ml, null(), 0, s.as_mut_ptr(), &mut n),
            ),
            (
                "sign:null_sig",
                fhsm_composite_sign(ALG, k.as_ptr(), kn, ms, ml, null(), 0, null_mut(), &mut n),
            ),
            (
                "sign:null_sig_len",
                fhsm_composite_sign(
                    ALG,
                    k.as_ptr(),
                    kn,
                    ms,
                    ml,
                    null(),
                    0,
                    s.as_mut_ptr(),
                    null_mut(),
                ),
            ),
        ];
        for (name, r) in rows {
            t.rows.push(format!("{name}\trv=0x{r:x}"));
        }
        n = cap;
        let r = fhsm_composite_sign_prehashed(
            ALG,
            k.as_ptr(),
            kn,
            PH64.as_ptr(),
            63,
            null(),
            0,
            s.as_mut_ptr(),
            &mut n,
        );
        t.rows.push(format!("sign_ph:ph_63\trv=0x{r:x};len={n}"));
        n = cap;
        let p = PH64.as_ptr();
        let rows = [
            (
                "sign_ph:null_priv",
                fhsm_composite_sign_prehashed(
                    ALG,
                    null(),
                    kn,
                    p,
                    64,
                    null(),
                    0,
                    s.as_mut_ptr(),
                    &mut n,
                ),
            ),
            (
                "sign_ph:null_sig",
                fhsm_composite_sign_prehashed(
                    ALG,
                    k.as_ptr(),
                    kn,
                    p,
                    64,
                    null(),
                    0,
                    null_mut(),
                    &mut n,
                ),
            ),
            (
                "sign_ph:null_sig_len",
                fhsm_composite_sign_prehashed(
                    ALG,
                    k.as_ptr(),
                    kn,
                    p,
                    64,
                    null(),
                    0,
                    s.as_mut_ptr(),
                    null_mut(),
                ),
            ),
        ];
        for (name, r) in rows {
            t.rows.push(format!("{name}\trv=0x{r:x}"));
        }
        n = cap;
        let r = fhsm_composite_sign_prehashed(
            ALG,
            k.as_ptr(),
            kn,
            p,
            64,
            ctx.as_ptr(),
            256,
            s.as_mut_ptr(),
            &mut n,
        );
        t.rows.push(format!("sign_ph:ctx_256\trv=0x{r:x};len={n}"));
        n = cap;
        let b = bad(&k, 5, 3, 0);
        let r = fhsm_composite_sign_prehashed(
            ALG,
            b.as_ptr(),
            b.len(),
            p,
            64,
            null(),
            0,
            s.as_mut_ptr(),
            &mut n,
        );
        t.rows.push(format!("sign_ph:other_alg\trv=0x{r:x}"));
    }

    // verify_cases, on the C's signatures
    let (sig, sig_ctx, sig_ph) = (fixture("sig"), fixture("sig_ctx9"), fixture("sig_ph_ctx9"));
    let (pb, pn) = (t.public.clone(), t.public.len());
    let priv_ = t.private.clone();
    let vf = |alg: c_int,
              key: &[u8],
              msg: &[u8],
              c: Option<(usize, usize)>,
              sg: *const u8,
              sn: usize| {
        let (cp, cl) = c.map_or((null(), 0), |(o, n)| (ctx[o..].as_ptr(), n));
        let kp = if key.is_empty() { null() } else { key.as_ptr() };
        // SAFETY: every pointer is NULL or covers its length
        unsafe {
            fhsm_composite_verify(alg, kp, key.len(), msg.as_ptr(), msg.len(), cp, cl, sg, sn)
        }
    };
    let flip = |at: usize| {
        let mut s = sig.clone();
        s[at] ^= 1;
        s
    };
    let (pq_flipped, ed_flipped) = (flip(100), flip(3309 + 10));
    let cases: Vec<(&str, u32)> = vec![
        ("ok", vf(ALG, &pb, MSG, None, sig.as_ptr(), SIG_LEN)),
        (
            "ok_ctx",
            vf(ALG, &pb, MSG, Some((0, 9)), sig_ctx.as_ptr(), SIG_LEN),
        ),
        (
            "ctx_missing",
            vf(ALG, &pb, MSG, None, sig_ctx.as_ptr(), SIG_LEN),
        ),
        (
            "ctx_added",
            vf(ALG, &pb, MSG, Some((0, 9)), sig.as_ptr(), SIG_LEN),
        ),
        (
            "ctx_other",
            vf(ALG, &pb, MSG, Some((1, 9)), sig_ctx.as_ptr(), SIG_LEN),
        ),
        (
            "msg_other",
            vf(ALG, &pb, &MSG[..ml - 1], None, sig.as_ptr(), SIG_LEN),
        ),
        (
            "ctx_256",
            vf(ALG, &pb, MSG, Some((0, 256)), sig.as_ptr(), SIG_LEN),
        ),
        ("alg0", vf(0, &pb, MSG, None, sig.as_ptr(), SIG_LEN)),
        ("null_pub", vf(ALG, &[], MSG, None, sig.as_ptr(), SIG_LEN)),
        ("null_sig", vf(ALG, &pb, MSG, None, null(), SIG_LEN)),
        (
            "sig_short",
            vf(ALG, &pb, MSG, None, sig.as_ptr(), SIG_LEN - 1),
        ),
        (
            "pq_flipped",
            vf(ALG, &pb, MSG, None, pq_flipped.as_ptr(), SIG_LEN),
        ),
        (
            "ed_flipped",
            vf(ALG, &pb, MSG, None, ed_flipped.as_ptr(), SIG_LEN),
        ),
        (
            "short_blob",
            vf(ALG, &pb[..9], MSG, None, sig.as_ptr(), SIG_LEN),
        ),
        (
            "bad_magic",
            vf(ALG, &bad(&pb, 1, 1, 0), MSG, None, sig.as_ptr(), SIG_LEN),
        ),
        (
            "bad_version",
            vf(ALG, &bad(&pb, 4, 1, 0), MSG, None, sig.as_ptr(), SIG_LEN),
        ),
        (
            "other_alg",
            vf(ALG, &bad(&pb, 5, 2, 0), MSG, None, sig.as_ptr(), SIG_LEN),
        ),
        (
            "trailing_byte",
            vf(ALG, &bad(&pb, pn, 0, 1), MSG, None, sig.as_ptr(), SIG_LEN),
        ),
        (
            "bad_pq_der",
            vf(ALG, &bad(&pb, 8, 0xFF, 0), MSG, None, sig.as_ptr(), SIG_LEN),
        ),
        (
            "bad_trad_der",
            vf(
                ALG,
                &bad(&pb, pn - 40, 0xFF, 0),
                MSG,
                None,
                sig.as_ptr(),
                SIG_LEN,
            ),
        ),
        (
            "priv_as_pub",
            vf(ALG, &priv_, MSG, None, sig.as_ptr(), SIG_LEN),
        ),
    ];
    for (name, r) in cases {
        t.rows.push(format!("verify:{name}\trv=0x{r:x}"));
    }
    let vp = |key: *const u8, ph: *const u8, plen: usize, clen: usize, sg: *const u8| {
        // SAFETY: every pointer is NULL or covers its length
        unsafe {
            fhsm_composite_verify_prehashed(ALG, key, pn, ph, plen, ctx.as_ptr(), clen, sg, SIG_LEN)
        }
    };
    let cases = [
        ("ok", vp(pb.as_ptr(), PH64.as_ptr(), 64, 9, sig_ph.as_ptr())),
        (
            "ph_other",
            vp(pb.as_ptr(), PH64[1..].as_ptr(), 63, 9, sig_ph.as_ptr()),
        ),
        (
            "ctx_other",
            vp(pb.as_ptr(), PH64.as_ptr(), 64, 8, sig_ph.as_ptr()),
        ),
        (
            "one_shot_sig",
            vp(pb.as_ptr(), PH64.as_ptr(), 64, 9, sig_ctx.as_ptr()),
        ),
        ("null_ph", vp(pb.as_ptr(), null(), 64, 9, sig_ph.as_ptr())),
        (
            "null_pub",
            vp(null(), PH64.as_ptr(), 64, 9, sig_ph.as_ptr()),
        ),
        ("null_sig", vp(pb.as_ptr(), PH64.as_ptr(), 64, 9, null())),
    ];
    for (name, r) in cases {
        t.rows.push(format!("verify_ph:{name}\trv=0x{r:x}"));
    }

    assert_eq!(t.rows.len(), want.len());
    for (got, want) in t.rows.iter().zip(&want) {
        assert_eq!(got, want);
    }
}
