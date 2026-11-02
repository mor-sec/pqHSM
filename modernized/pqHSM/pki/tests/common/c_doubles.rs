//! Test doubles for the two C functions the `ffi` C ABI imports from `src/fhsm_composite.c`
//! (`fhsm_pki_ocsp`, `fhsm_pki_algid`). Under `cargo test --features ffi` nothing else
//! defines them; in the hybrid build the real C encoder does, and these are never linked.
//!
//! `fhsm_pki_ocsp` replays a golden row: it checks every argument against the row's
//! `ocsp/CASE.enc` (C's own arguments to the real encoder) and returns the row's
//! `ocsp/CASE.basic.der`. The C ABI reads the real clock, so the three times are checked
//! against the call's time window and `days`, then masked. A mismatch cannot panic (it would
//! abort inside `extern "C"`), so it is recorded and the test reports it after the call.
#![allow(clippy::too_many_arguments)]

use std::cell::{Cell, RefCell};
use std::ffi::c_int;
use std::sync::OnceLock;

use pqhsm_pki::ffi::{fhsm_composite_ocsp_single_t, fhsm_pki_signer_t};

use super::{case, hex, pattern, unhex};

pub struct Replay {
    pub case: String,
    /// The golden `.enc` (every line but `rv`), or None if C never reached the encoder.
    pub enc: Option<String>,
    pub basic: Vec<u8>,
    pub rv: u32,
    pub synth: Option<usize>,
    pub days: i64,
    /// `time()` just before and just after the C ABI call.
    pub window: (i64, i64),
    pub calls: usize,
    pub signer: Option<(usize, usize)>,
    pub failure: Option<String>,
}

thread_local! {
    pub static REPLAY: RefCell<Option<Replay>> = const { RefCell::new(None) };
    pub static ALGID_FAIL: Cell<bool> = const { Cell::new(false) };
}

fn slice<'a>(p: *const u8, n: usize) -> Option<&'a [u8]> {
    // SAFETY: the C ABI under test passes pointer/length pairs it owns for the call.
    (!p.is_null()).then(|| unsafe { std::slice::from_raw_parts(p, n) })
}

fn h(b: Option<&[u8]>) -> String {
    b.map_or("-".into(), hex)
}

/// Seconds since the epoch of a DER GeneralizedTime `..YYYYMMDDHHMMSSZ` (any year width).
pub fn gt_epoch(der: &[u8]) -> Option<i64> {
    if der.len() < 2 || der[0] != 0x18 || der[1] as usize != der.len() - 2 {
        return None;
    }
    let s = std::str::from_utf8(&der[2..]).ok()?.strip_suffix('Z')?;
    let (y, rest) = s.split_at(s.len().checked_sub(10)?);
    let n = |a: usize| rest[a..a + 2].parse::<i64>().ok();
    let (y, m, d) = (y.parse::<i64>().ok()?, n(0)?, n(2)?);
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    Some(days * 86_400 + n(4)? * 3600 + n(6)? * 60 + n(8)?)
}

/// Replace the three times with placeholders after checking them: producedAt in `ok_now`,
/// every thisUpdate equal to it, every nextUpdate `days` later.
pub fn mask(enc: &str, days: i64, ok_now: impl Fn(i64) -> bool) -> Result<String, String> {
    let mut produced = None;
    let mut out = String::new();
    for l in enc.lines() {
        if let Some(v) = l.strip_prefix("produced_at ") {
            let t = gt_epoch(&unhex(v)).ok_or("producedAt is not a GeneralizedTime")?;
            if !ok_now(t) {
                return Err(format!("producedAt {t} is not now"));
            }
            produced = Some((v.to_owned(), t));
            out += "produced_at <now>\n";
        } else if let Some(v) = l.strip_prefix("single ") {
            let (p, t) = produced.clone().ok_or("single before producedAt")?;
            let mut f: Vec<&str> = v.split(' ').collect();
            if f[4] != p {
                return Err("thisUpdate is not producedAt".into());
            }
            if gt_epoch(&unhex(f[5])) != Some(t + days * 86_400) {
                return Err(format!("nextUpdate is not {days} days later"));
            }
            f[4] = "<now>";
            f[5] = "<next>";
            out += &format!("single {}\n", f.join(" "));
        } else if !l.starts_with("rv ") {
            out += &format!("{l}\n");
        }
    }
    Ok(out)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_ocsp(
    s: *const fhsm_pki_signer_t,
    responder_cert: *const u8,
    responder_cert_len: usize,
    produced_at: *const u8,
    produced_at_len: usize,
    singles: *const fhsm_composite_ocsp_single_t,
    n: usize,
    exts: *const u8,
    exts_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> u32 {
    REPLAY.with_borrow_mut(|r| {
        let Some(r) = r.as_mut() else {
            return 0x6;
        };
        r.calls += 1;
        // SAFETY: the C ABI under test passes its own signer, singles and output buffer.
        let (s, sg, cap) = unsafe { (&*s, std::slice::from_raw_parts(singles, n), *out_len) };
        r.signer = Some((s.sign.map_or(0, |f| f as usize), s.sign_ctx as usize));
        let mut text = format!(
            "algid {}\nspki {}\nresponder {}\nproduced_at {}\ncap {cap}\nexts {}\n",
            h(slice(s.algid, s.algid_len)),
            h(slice(s.spki, s.spki_len)),
            h(slice(responder_cert, responder_cert_len)),
            h(slice(produced_at, produced_at_len)),
            h(slice(exts, exts_len)),
        );
        for one in sg {
            text += &format!(
                "single {} {} {} {} {} {}\n",
                h(slice(one.cert_id, one.cert_id_len)),
                one.status,
                h(slice(one.revoked_at, one.revoked_at_len)),
                one.reason,
                h(slice(one.this_upd, one.this_upd_len)),
                h(slice(one.next_upd, one.next_upd_len)),
            );
        }
        let (lo, hi) = r.window;
        let now = case("c_struct_layout").num::<i64>("now");
        let got = mask(&text, r.days, |t| (lo..=hi).contains(&t));
        let want = r.enc.as_deref().map(|e| mask(e, r.days, |t| t == now));
        let bytes = match (got, want, r.synth) {
            (Err(e), _, _) => Err(format!("encoder input: {e}")),
            (Ok(_), _, Some(k)) => Ok(pattern(k)),
            (Ok(g), Some(Ok(w)), None) if g == w => Ok(r.basic.clone()),
            (Ok(g), Some(Ok(w)), None) => Err(format!("encoder input\n got: {g}\nwant: {w}")),
            (Ok(_), _, None) => Err("C never reached the encoder".into()),
        };
        match bytes {
            Err(e) => {
                r.failure.get_or_insert(format!("{}: {e}", r.case));
                0x6
            }
            Ok(_) if r.rv != 0 && r.synth.is_none() => r.rv,
            Ok(b) if b.len() > cap => 0x150,
            Ok(b) => {
                // SAFETY: `out` has `cap` bytes, checked above.
                unsafe {
                    std::ptr::copy_nonoverlapping(b.as_ptr(), out, b.len());
                    *out_len = b.len();
                }
                0
            }
        }
    })
}

fn static_bytes(cell: &'static OnceLock<Vec<u8>>, col: &str) -> &'static [u8] {
    cell.get_or_init(|| unhex(case("c_struct_layout").get(col)))
}

/// FHSM_PKI_SIG_COMPOSITE_MLDSA65_ED25519 (0) and FHSM_PKI_SIG_ED25519 (5), as the C
/// generator read them from the real `fhsm_pki_algid`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_pki_algid(a: c_int, der: *mut *const u8, der_len: *mut usize) -> u32 {
    static COMPOSITE: OnceLock<Vec<u8>> = OnceLock::new();
    static ED25519: OnceLock<Vec<u8>> = OnceLock::new();
    if ALGID_FAIL.get() {
        return 0x6;
    }
    let b = match a {
        0 => static_bytes(&COMPOSITE, "composite_algid"),
        5 => static_bytes(&ED25519, "ed25519_algid"),
        _ => return 0x7,
    };
    // SAFETY: the C ABI under test passes two out-pointers.
    unsafe {
        *der = b.as_ptr();
        *der_len = b.len();
    }
    0
}
