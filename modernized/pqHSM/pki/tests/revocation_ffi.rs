//! The C ABI of `include/fhsm_revocation.h` (feature `ffi`). What the safe API cannot show is
//! checked here, row by row from the same goldens: the struct layout, what each function leaves
//! in the caller's buffers on failure, `err` NULL and truncation at `err_cap`, the growth of
//! `cap`, NULL `stats`, `*out` ownership, and the responses the real encoder writes with C's
//! signatures (the clock and signer doubles are in `common/c_doubles.rs`).
//!
//!   cargo test -p pqhsm-pki --features ffi --test revocation_ffi
//!
//! Every row named here is also named in `revocation.rs`; this file loops over rows by op.
#![cfg(feature = "ffi")]

mod common;

use std::ffi::{CStr, CString, c_char, c_void};
use std::mem::{offset_of, size_of};
use std::path::Path;
use std::ptr::{null, null_mut};

use common::*;
use pqhsm_pki::ffi::*;
use pqhsm_pki::revocation::Db;

fn cs(b: &[u8]) -> CString {
    CString::new(b).unwrap()
}

fn path_c(p: &Path) -> CString {
    CString::new(p.to_str().unwrap()).unwrap()
}

/// A 1024-byte '@' buffer, as gen_rev.c passes.
fn err_buf() -> Vec<u8> {
    let mut v = vec![b'@'; 1024];
    v[1023] = 0;
    v
}

/// gen_rev.c's reading of an err buffer: "untouched" if the first byte is still '@'.
fn err_of(buf: &[u8]) -> Option<String> {
    (buf[0] != b'@').then(|| {
        CStr::from_bytes_until_nul(buf)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    })
}

/// A C-side database holding `d`, built through `fhsm_rev_db_add` as a C caller would.
fn c_db(d: &Db) -> fhsm_rev_db_t {
    let mut c = fhsm_rev_db_t {
        crl_number: d.crl_number,
        e: null_mut(),
        n: 0,
        cap: 0,
    };
    for e in &d.entries {
        let mut x = fhsm_rev_entry_t {
            serial: [0; 64],
            serial_len: e.serial.len(),
            date: [0; 16],
            reason: e.reason,
        };
        x.serial[..e.serial.len()].copy_from_slice(&e.serial);
        for (k, b) in e.date.iter().enumerate() {
            x.date[k] = *b as c_char;
        }
        // SAFETY: both structs are ours and live for the call.
        let rv = unsafe { fhsm_rev_db_add(&mut c, &x, null_mut(), 0) };
        assert_eq!(rv, 0);
    }
    c
}

#[test]
fn c_struct_layout_is_c_s() {
    // the #[repr(C)] structs C callers see (PHASE2_PLAN.md §3)
    let c = case("c_struct_layout");
    let n = |k: &str| c.num::<usize>(k);
    assert_eq!(size_of::<fhsm_rev_entry_t>(), n("entry_size"));
    assert_eq!(offset_of!(fhsm_rev_entry_t, serial), n("entry_serial"));
    assert_eq!(
        offset_of!(fhsm_rev_entry_t, serial_len),
        n("entry_serial_len")
    );
    assert_eq!(offset_of!(fhsm_rev_entry_t, date), n("entry_date"));
    assert_eq!(offset_of!(fhsm_rev_entry_t, reason), n("entry_reason"));
    assert_eq!(size_of::<fhsm_rev_db_t>(), n("db_size"));
    assert_eq!(offset_of!(fhsm_rev_db_t, crl_number), n("db_crl_number"));
    assert_eq!(offset_of!(fhsm_rev_db_t, e), n("db_e"));
    assert_eq!(offset_of!(fhsm_rev_db_t, n), n("db_n"));
    assert_eq!(offset_of!(fhsm_rev_db_t, cap), n("db_cap"));
    assert_eq!(size_of::<fhsm_ocsp_stats_t>(), n("stats_size"));
    assert_eq!(
        offset_of!(fhsm_ocsp_stats_t, nonce_echoed),
        n("stats_nonce_echoed")
    );
    assert_eq!(size_of::<fhsm_composite_ocsp_single_t>(), n("single_size"));
    assert_eq!(size_of::<fhsm_pki_signer_t>(), n("signer_size"));
    assert_eq!(pqhsm_pki::revocation::ERR_MAX, n("err_max"));
    assert_eq!(pqhsm_pki::revocation::MAX_ENTRIES, n("max_entries"));
}

#[test]
fn reasons_through_the_c_abi() {
    // RULE-024: static, NUL-terminated names; NULL for unknown codes
    for c in cases_of("reason_code") {
        // SAFETY: a valid C string
        let got = unsafe { fhsm_rev_reason_code(cs(&c.bytes("in")).as_ptr()) };
        assert_eq!(got.to_string(), c.rv, "{}", c.name);
    }
    for c in cases_of("reason_name") {
        let p = fhsm_rev_reason_name(c.num("code"));
        // SAFETY: a static C string or NULL
        let got = (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) }.to_str().unwrap());
        assert_eq!(got.unwrap_or("NULL"), c.rv, "{}", c.name);
    }
    // SAFETY: a static C string
    let list = unsafe { CStr::from_ptr(fhsm_rev_reason_list()) };
    assert_eq!(list.to_str().unwrap(), case("reason_list").rv);
}

#[test]
fn hex_leaves_the_bytes_before_a_bad_pair_and_n_untouched() {
    // RULE-024: C writes each pair as it goes, and sets *n only on success
    for c in cases_of("hex") {
        let cap: usize = c.num("cap");
        let mut buf = vec![0xEE_u8; cap];
        let mut n = 999usize;
        // SAFETY: buf has cap bytes
        let rv = unsafe {
            fhsm_rev_hex_to_bytes(cs(&c.bytes("in")).as_ptr(), buf.as_mut_ptr(), cap, &mut n)
        };
        assert_eq!(rv.to_string(), c.rv, "{}", c.name);
        assert_eq!(hex(&buf), c.get("buf"), "{}: buffer", c.name);
        assert_eq!(n.to_string(), c.get("n"), "{}: n", c.name);
    }
}

#[test]
fn date_leaves_out_untouched_on_failure_div016() {
    // RULE-024; DIV-016 rows (date_div016_*, tabled in revocation.rs) are refusals in Rust
    for c in cases_of("date") {
        let mut t: i64 = 0x5A5A_5A5A;
        // SAFETY: a valid C string and an i64
        let rv = unsafe { fhsm_rev_date_to_time(cs(&c.bytes("in")).as_ptr(), &mut t) };
        let (want_rv, want_t) = if c.name.starts_with("date_div016_") {
            assert_eq!(c.rv, "1", "{}: C's value", c.name);
            ("0".to_owned(), "untouched".to_owned())
        } else {
            (c.rv.clone(), c.get("t").to_owned())
        };
        let got_t = if t == 0x5A5A_5A5A {
            "untouched".into()
        } else {
            t.to_string()
        };
        assert_eq!((rv.to_string(), got_t), (want_rv, want_t), "{}", c.name);
    }
}

#[test]
fn time_writes_16_bytes_or_nothing() {
    // RULE-024
    for c in cases_of("time") {
        let mut out = [b'@' as c_char; 17];
        // SAFETY: out has 16 bytes and more
        let rv = unsafe { fhsm_rev_time_to_date(c.num("t"), out.as_mut_ptr()) };
        assert_eq!(rv.to_string(), c.rv, "{}", c.name);
        let b: Vec<u8> = out[..16].iter().map(|x| *x as u8).collect();
        if rv == 1 {
            assert_eq!(&b[..15], c.text("out").as_bytes(), "{}", c.name);
            assert_eq!(b[15], 0, "{}: NUL", c.name);
        } else {
            assert_eq!(c.get("out"), "untouched");
            assert!(b.iter().all(|x| *x == b'@'), "{}: out touched", c.name);
        }
    }
}

#[test]
fn serial_eq_through_the_c_abi() {
    // RULE-024
    for c in cases_of("serial_eq") {
        let (a, b) = (unhex(c.get("a")), unhex(c.get("b")));
        // SAFETY: two slices
        let rv = unsafe { fhsm_rev_serial_eq(a.as_ptr(), a.len(), b.as_ptr(), b.len()) };
        assert_eq!(rv.to_string(), c.rv, "{}", c.name);
    }
}

#[test]
fn load_fills_the_struct_and_err_exactly_as_c_did_div016() {
    // RULE-024, RULE-100, review L3 (the caller's struct is never read)
    let privileged = privileged();
    for c in cases_of("load") {
        if needs_unprivileged(&c) && privileged {
            require_unprivileged(&c.name);
        }
        let dir = tempfile::tempdir().unwrap();
        let p = load_input(dir.path(), c.get("file"));
        let mut d: fhsm_rev_db_t = unsafe { std::mem::zeroed() };
        // SAFETY: d is plain data; garbage in it must not matter
        unsafe {
            std::ptr::write_bytes(
                &mut d as *mut fhsm_rev_db_t as *mut u8,
                0xA5,
                size_of::<fhsm_rev_db_t>(),
            )
        };
        let mut err = err_buf();
        let cap: usize = c.opt("err_cap").map_or(640, |v| v.parse().unwrap());
        let errp = if c.is("err_mode", "null") {
            null_mut()
        } else {
            err.as_mut_ptr() as *mut c_char
        };
        // SAFETY: a C string, our struct, a 1024-byte buffer or NULL
        let rv = unsafe { fhsm_rev_db_load(path_c(&p).as_ptr(), &mut d, errp, cap) };
        let base = format!("{{dir}}/{}", p.file_name().unwrap().to_str().unwrap());
        let div = c.name.starts_with("load_div016_");
        let refused = DIV_LOAD_REFUSED.iter().find(|d| d.0 == c.name);
        let want_rv = match refused {
            Some(d) => d.3,
            None if div => 3,
            None => c.rv_i(),
        };
        assert_eq!(rv as i64, want_rv, "{}: rv", c.name);
        let fields = (d.crl_number, d.n, d.cap, d.e.is_null() as u8);
        let want = if div || refused.is_some() {
            (0, 0, 0, 1)
        } else {
            (
                c.num("crl_number"),
                c.num("n"),
                c.num("cap"),
                c.num("e_null"),
            )
        };
        assert_eq!(fields, want, "{}: crl_number, n, cap, e is NULL", c.name);
        if !c.is("err_mode", "null") {
            let got = err_of(&err).map(|e| norm(&e, dir.path()));
            let want = if let Some(&(_, _, _, _, line, why)) = refused {
                Some(match line {
                    0 => format!("cannot read {base}: {why}\n"),
                    _ => db_bad(&base, line, why),
                })
            } else if div {
                let line = if c.name.ends_with("second_line") {
                    2
                } else {
                    1
                };
                Some(db_bad(&base, line, "date is not YYYYMMDDHHMMSSZ"))
            } else if let Some(cap) = c.opt("err_cap").map(|v| v.parse::<usize>().unwrap()) {
                // vsnprintf: the first cap-1 bytes of the whole diagnostic, then NUL
                let full_c = cases_of("load")
                    .into_iter()
                    .find(|o| {
                        o.get("file") == c.get("file")
                            && o.opt("err_cap").is_none()
                            && o.opt("err_mode").is_none()
                    })
                    .unwrap()
                    .text("err")
                    .replace("{dir}", dir.path().to_str().unwrap());
                (cap > 0).then(|| norm(&full_c[..cap - 1], dir.path()))
            } else {
                c.opt("err")
                    .filter(|e| *e != "untouched")
                    .map(|_| c.text("err"))
            };
            assert_eq!(got, want, "{}: err", c.name);
        }
        // SAFETY: d came from fhsm_rev_db_load
        unsafe { fhsm_rev_db_free(&mut d) };
        if c.is("file", "unreadable") {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
}

#[test]
fn add_grows_64_then_doubling_to_the_cap_and_free_resets() {
    // RULE-099: "add_growth_to_the_cap", "add_past_the_cap_is_eparse", "free_resets_every_field"
    let grow = case("add_growth_to_the_cap");
    let mut d = fhsm_rev_db_t {
        crl_number: 5,
        e: null_mut(),
        n: 0,
        cap: 0,
    };
    let mut caps = Vec::new();
    let mut last = 0;
    for i in 0..grow.num::<u32>("n") {
        let mut e = fhsm_rev_entry_t {
            serial: [0; 64],
            serial_len: 4,
            date: [0; 16],
            reason: -1,
        };
        e.serial[..4].copy_from_slice(&i.to_be_bytes());
        for (k, b) in b"20260101000000Z".iter().enumerate() {
            e.date[k] = *b as c_char;
        }
        // SAFETY: our struct and entry
        assert_eq!(unsafe { fhsm_rev_db_add(&mut d, &e, null_mut(), 0) }, 0);
        if d.cap != last {
            caps.push(format!("{}:{}", d.n, d.cap));
            last = d.cap;
        }
    }
    assert_eq!(caps.join(","), grow.get("caps"));

    let past = case("add_past_the_cap_is_eparse");
    let mut e = fhsm_rev_entry_t {
        serial: [0; 64],
        serial_len: 1,
        date: [0; 16],
        reason: 1,
    };
    e.serial[0] = 0xAB;
    let mut err = err_buf();
    // SAFETY: our struct, entry and buffer
    let rv = unsafe { fhsm_rev_db_add(&mut d, &e, err.as_mut_ptr() as *mut c_char, 640) };
    assert_eq!(rv as i64, past.rv_i());
    assert_eq!(err_of(&err).unwrap(), past.text("err"));
    assert_eq!((d.n, d.cap), (past.num("n"), past.num("cap")));

    let free = case("free_resets_every_field");
    // SAFETY: d's allocation is the C ABI's
    unsafe { fhsm_rev_db_free(&mut d) };
    assert_eq!(
        (d.n, d.cap, d.e.is_null() as u8, d.crl_number),
        (
            free.num("n"),
            free.num("cap"),
            free.num("e_null"),
            free.num("crl_number")
        )
    );
    // SAFETY: NULL is accepted (review L3)
    unsafe { fhsm_rev_db_free(null_mut()) };
}

#[test]
fn find_returns_a_pointer_into_the_array() {
    // RULE-099
    for c in cases_of("find") {
        let mut d = c_db(&db_from_spec(c.get("db")));
        let q = unhex(c.get("q"));
        // SAFETY: our db
        let p = unsafe { fhsm_rev_db_find(&d, q.as_ptr(), q.len()) };
        // SAFETY: p points into d.e when not NULL
        let idx = if p.is_null() {
            -1
        } else {
            unsafe { p.offset_from(d.e) as i64 }
        };
        assert_eq!(idx, c.rv_i(), "{}", c.name);
        // SAFETY: built by c_db
        unsafe { fhsm_rev_db_free(&mut d) };
    }
}

#[test]
fn save_through_the_c_abi() {
    // RULE-100: the rows whose input a C caller builds (unnamed codes, err NULL, path length)
    umask_022();
    for name in [
        "save_three",
        "save_every_reason_code",
        "save_unvalidated_date",
        "save_err_null",
        "save_into_a_missing_dir",
        "save_path_1020_bytes_is_too_long",
    ] {
        let c = case(name);
        let dir = tempfile::tempdir().unwrap();
        let p = match c.get("target") {
            "missing_dir" => dir.path().join(format!("nope/{name}.db")),
            t if t.starts_with("len:") => long_path(dir.path(), t[4..].parse().unwrap()),
            _ => dir.path().join(format!("{name}.db")),
        };
        let mut d = c_db(&db_from_spec(c.get("db")));
        let mut err = err_buf();
        let errp = if c.is("err_mode", "null") {
            null_mut()
        } else {
            err.as_mut_ptr() as *mut c_char
        };
        // SAFETY: a C string, our db, a buffer or NULL
        let rv = unsafe { fhsm_rev_db_save(path_c(&p).as_ptr(), &d, errp, 1024) };
        assert_eq!(rv as i64, c.rv_i(), "{name}");
        if !c.is("err_mode", "null") && rv != 0 {
            assert_eq!(
                norm(&err_of(&err).unwrap(), dir.path()),
                c.text("err"),
                "{name}"
            );
        }
        if !c.get("target").starts_with("len:") {
            assert_eq!(state(&p, dir.path()), c.get("after"), "{name}");
        }
        // SAFETY: built by c_db
        unsafe { fhsm_rev_db_free(&mut d) };
    }
}

#[test]
fn status_response_leaves_out_untouched_when_it_refuses() {
    // RULE-023
    for c in cases_of("status") {
        let mut out = [0xEE_u8; 5];
        // SAFETY: five bytes
        let n = unsafe { fhsm_ocsp_status_response(c.num("status"), out.as_mut_ptr()) };
        assert_eq!(n.to_string(), c.rv, "{}", c.name);
        assert_eq!(hex(&out), c.get("out"), "{}", c.name);
    }
}

#[test]
fn check_responder_through_the_c_abi() {
    // RULE-023: NULL paths name "the responder certificate" / "the CA certificate"
    for c in cases_of("check") {
        let (r, a) = (der(c.get("responder")), der(c.get("ca")));
        let rp = (!c.is("rpath", "NULL")).then(|| cs(c.get("rpath").as_bytes()));
        let cp = (!c.is("cpath", "NULL")).then(|| cs(c.get("cpath").as_bytes()));
        let mut err = err_buf();
        // SAFETY: slices, C strings or NULL, a 1024-byte buffer with cap 640
        let rv = unsafe {
            fhsm_ocsp_check_responder(
                r.as_ptr(),
                r.len(),
                a.as_ptr(),
                a.len(),
                rp.as_ref().map_or(null(), |s| s.as_ptr()),
                cp.as_ref().map_or(null(), |s| s.as_ptr()),
                err.as_mut_ptr() as *mut c_char,
                640,
            )
        };
        assert_eq!(rv as i64, c.rv_i(), "{}", c.name);
        let want = c
            .opt("err")
            .filter(|e| *e != "untouched")
            .map(|_| c.text("err"));
        assert_eq!(err_of(&err), want, "{}", c.name);
    }
}

/// The elements of a DER SEQUENCE (definite lengths up to four octets).
fn elements(der: &[u8]) -> Vec<&[u8]> {
    let tlv = |b: &[u8]| -> (usize, usize) {
        let (n, h) = match b[1] {
            l @ 0..0x80 => (l as usize, 2),
            l => {
                let k = (l & 0x7F) as usize;
                (
                    b[2..2 + k].iter().fold(0, |a, &x| a << 8 | x as usize),
                    2 + k,
                )
            }
        };
        (h, h + n)
    };
    let (h, end) = tlv(der);
    let (mut rest, mut out) = (&der[h..end], Vec::new());
    while !rest.is_empty() {
        let (_, n) = tlv(rest);
        out.push(&rest[..n]);
        rest = &rest[n..];
    }
    out
}

#[test]
fn answer_through_the_c_abi_writes_c_s_response() {
    // RULE-023: every answer row through the real encoder, with the clock pinned to gen_rev's
    // NOW and C's own signature handed back by the signer: the response must be C's bytes and
    // the encoder must have asked to sign C's tbsResponseData. The synth rows (an encoder
    // output of a forced size) need gen_rev's encoder seam; revocation.rs replays them
    // through the same closure seam in rev::answer
    let layout = case("c_struct_layout");
    let (now, ed) = (layout.num::<i64>("now"), unhex(layout.get("ed25519_algid")));
    let (mut seen, mut synth) = (0, 0);
    for c in cases_of("answer") {
        if c.opt("synth").is_some() {
            synth += 1;
            continue;
        }
        let inp = answer_inputs(&c);
        let mut db = c_db(&inp.db);
        let enc = golden_enc(&c.name);
        let basic = (enc.as_deref().map_or(1, enc_rv) == 0)
            .then(|| golden_bytes(&format!("ocsp/{}.basic.der", c.name)));
        // DIV-016: the in-memory month-13 entry is revoked at t = 0 in Rust
        let div016 = |b: Vec<u8>| -> Vec<u8> {
            if c.name != "answer_div016_unvalidated_dates" {
                return b;
            }
            let (c_t, r_t) = (gt("20270213030000Z"), gt("19700101000000Z"));
            let at = b
                .windows(c_t.len())
                .position(|w| w == c_t)
                .expect("C's value");
            [&b[..at], &r_t, &b[at + c_t.len()..]].concat()
        };
        let tbs = basic.as_ref().map(|b| div016(elements(b)[0].to_vec()));
        // C's signature, from the BIT STRING (2-byte header, no unused bits); 64 bytes where
        // C's encoder refused after signing, so the sizes it compared are C's
        let sig = basic
            .as_ref()
            .map_or(vec![0; 64], |b| elements(b)[2][3..].to_vec());
        let mut rp = common::c_doubles::Replay {
            sig,
            seen: None,
            calls: 0,
        };
        let sign: fhsm_composite_sign_cb = if c.is("sign", "fail") {
            Some(common::c_doubles::failing_sign)
        } else {
            Some(common::c_doubles::replay_sign)
        };
        let ctx = (&raw mut rp).cast::<c_void>();
        let label = inp.label.as_ref().map(|l| cs(l.as_bytes()));
        let mut out: *mut u8 = std::ptr::dangling_mut::<u8>();
        let mut out_len = 12345usize;
        let mut st = fhsm_ocsp_stats_t {
            asked: !0,
            ours: !0,
            revoked: !0,
            unknown: !0,
            nonce_echoed: -1,
        };
        let mut err = err_buf();
        let cap = c.opt("err_cap").map_or(640, |v| v.parse().unwrap());
        let errp = if c.is("err_mode", "null") {
            null_mut()
        } else {
            err.as_mut_ptr() as *mut c_char
        };
        let stp = if c.is("stats", "null") {
            null_mut()
        } else {
            &mut st as *mut _
        };
        let lp = label.as_ref().map_or(null(), |s| s.as_ptr());
        // SAFETY: every pointer is ours and lives for the call
        let rv = common::c_doubles::pinned(now, || unsafe {
            if c.is("fn", "answer") {
                fhsm_ocsp_answer(
                    inp.req.as_ptr(),
                    inp.req.len(),
                    inp.ca.as_ptr(),
                    inp.ca.len(),
                    inp.responder.as_ptr(),
                    inp.responder.len(),
                    &db,
                    inp.days,
                    lp,
                    sign,
                    ctx,
                    &mut out,
                    &mut out_len,
                    stp,
                    errp,
                    cap,
                )
            } else {
                fhsm_ocsp_answer_ex(
                    inp.req.as_ptr(),
                    inp.req.len(),
                    inp.ca.as_ptr(),
                    inp.ca.len(),
                    inp.responder.as_ptr(),
                    inp.responder.len(),
                    &db,
                    inp.days,
                    lp,
                    ed.as_ptr(),
                    ed.len(),
                    sign,
                    ctx,
                    &mut out,
                    &mut out_len,
                    stp,
                    errp,
                    cap,
                )
            }
        });
        // the encoder signs last: it can be reached and refuse first (encoder_called counts it)
        let reached: usize = c.num("encoder_called");
        assert!(rp.calls <= reached, "{}: signer calls", c.name);
        if let Some(t) = &tbs {
            assert!(rp.seen.as_ref() == Some(t), "{}: tbsResponseData", c.name);
        }
        assert_eq!(rv as i64, c.rv_i(), "{}: rv", c.name);
        assert_eq!(
            ((out.is_null()) as u8).to_string(),
            c.get("out_null"),
            "{}: out",
            c.name
        );
        assert_eq!(out_len.to_string(), c.get("out_len"), "{}: out_len", c.name);
        if let Some(s) = c.opt("stats").filter(|s| *s != "null") {
            let got = format!(
                "{},{},{},{},{}",
                st.asked, st.ours, st.revoked, st.unknown, st.nonce_echoed
            );
            assert_eq!(got, s, "{}: stats", c.name);
        }
        if !c.is("err_mode", "null") {
            let want = c
                .opt("err")
                .filter(|e| *e != "untouched")
                .map(|_| c.text("err"));
            assert_eq!(err_of(&err), want, "{}: err", c.name);
        }
        if rv == 0 {
            // SAFETY: *out is a malloc'd buffer of out_len bytes that belongs to the caller
            let got = unsafe { std::slice::from_raw_parts(out, out_len) }.to_vec();
            unsafe { libc::free(out as *mut c_void) };
            let want = div016(golden_bytes(&format!("ocsp/{}.resp.der", c.name)));
            assert!(got == want, "{}: bytes", c.name);
        }
        // SAFETY: built by c_db
        unsafe { fhsm_rev_db_free(&mut db) };
        seen += 1;
    }
    assert_eq!((seen, synth), (56, 25), "every answer row");
}
