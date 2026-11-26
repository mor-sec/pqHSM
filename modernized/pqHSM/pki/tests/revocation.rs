//! Characterization tests for Phase 2 slice 2: `src/fhsm_revocation.c` (RULE-023, RULE-024,
//! RULE-099, RULE-100), against what the legacy C code did.
//!
//! Every expected value is a row of `golden/rev/cases.tsv` (written by
//! `legacy/hybrid/golden/gen_rev.c`), or `testdata/revocation.tsv` for the Phase 2 corpus. A
//! test names its row, rebuilds the row's inputs, calls the safe API, and compares. Where Rust
//! is meant to differ (DIV-016, DIV-019 to DIV-022), the test first asserts what C did, then
//! what Rust must.
//!
//! OCSP: `answer` takes the encoder (`fhsm_pki_ocsp`) as an argument. The tests pass a replay encoder that (1) requires exactly the arguments C handed
//! the real encoder (`ocsp/CASE.enc`, captured through `--wrap`) and (2) returns exactly what
//! the real encoder returned (`ocsp/CASE.basic.der`). Rust's whole OCSPResponse must then
//! equal C's (`ocsp/CASE.resp.der`) byte for byte: C's clock was pinned, so nothing is masked.

mod common;

use std::cell::Cell;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

use common::*;
use pqhsm_pki::revocation::{self as rev, Db, DbLock, Entry, Query, Tbs};

/// DIV-016 (DECIDED, Fix): `fhsm_rev_date_to_time` rejects any field outside its calendar
/// range. C let `timegm` normalise it. (case, C's epoch seconds); Rust returns None.
/// Seconds = 60 is counted out of range (OpenSSL's GeneralizedTime check allows 0..59).
const DIV016_DATE: &[(&str, &str)] = &[
    ("date_div016_month_13", "1802487600"),
    ("date_div016_month_00", "1764547200"),
    ("date_div016_day_00", "1767139200"),
    ("date_div016_feb_30", "1772409600"),
    ("date_div016_feb_29_non_leap", "1677628800"),
    ("date_div016_feb_29_1900", "-2203891200"),
    ("date_div016_apr_31", "1777593600"),
    ("date_div016_hour_24", "1767312000"),
    ("date_div016_hour_99", "1767582000"),
    ("date_div016_minute_60", "1767229200"),
    ("date_div016_second_60", "1798761600"),
    ("date_div016_all_nines", "2033613639"),
];

/// DIV-016 in the loader: a line C loaded is now a refusal of the whole file, with C's
/// existing "date is not YYYYMMDDHHMMSSZ" reason. (case, C's entries, the line Rust names)
const DIV016_LOAD: &[(&str, &str, u32)] = &[
    ("load_div016_month_00", "a1/20260001000000Z/-1", 1),
    ("load_div016_feb_30", "a1/20260230000000Z/-1", 1),
    ("load_div016_hour_24", "a1/20260101240000Z/-1", 1),
    ("load_div016_second_60", "a1/20261231235960Z/-1", 1),
    (
        "load_div016_second_line",
        "a1/20260101000000Z/-1,a2/20261340990000Z/-1",
        2,
    ),
];

/// DIV-016 in the OCSP answer: an entry added in memory (never loaded) with a normalisable
/// date. C ignores date_to_time's result and answered revoked at the normalised instant; with
/// the date refused, the same code path leaves t = 0. (case, single, C's time, Rust's time)
/// Rust's 1970 value is the mechanical consequence, flagged as a candidate DIV in README.md.
const DIV016_ANSWER: &[(&str, usize, &str, &str)] = &[(
    "answer_div016_unvalidated_dates",
    0,
    "20270213030000Z",
    "19700101000000Z",
)];

/// DIV-016 in the Phase 2 corpus (`testdata/revocation.tsv`). (file, C's entry line)
const DIV016_CORPUS: &[(&str, &str)] = &[(
    "rev_month13.db",
    "entry\trev_month13.db\tserial=a1\tdate=20261340990000Z\tepoch=1802487600\treason=-1",
)];

/// DIV-022 (DECIDED, Fix 2026-10-31): save removes whatever is at `<path>.tmp` and creates it
/// with O_EXCL|O_NOFOLLOW, so a symlink there is never written through. Rust saves normally:
/// rv 0, the database as `save_three` wrote it, no tmp left, the victim untouched.
/// (case, C's rv, C's after, C's after_tmp)
const DIV022_SAVE: &[(&str, &str, &str, &str)] = &[
    (
        "save_follows_a_tmp_symlink",
        "0",
        "symlink:victim",
        "absent",
    ),
    (
        "save_tmp_on_a_full_device",
        "2",
        "absent",
        "symlink:/dev/full",
    ),
];

macro_rules! golden {
    ($($test:ident => $run:ident($case:literal);)*) => {$(
        #[test]
        fn $test() {
            $run($case);
        }
    )*};
}

// ---------------------------------------------------------------------------------------
// Runners
// ---------------------------------------------------------------------------------------

fn run_reason_code(name: &str) {
    // RULE-024
    let c = case(name);
    assert_eq!(c.op, "reason_code");
    assert_eq!(rev::reason_code(&c.bytes("in")).to_string(), c.rv, "{name}");
}

fn run_reason_name(name: &str) {
    // RULE-024
    let c = case(name);
    assert_eq!(c.op, "reason_name");
    let want = (c.rv != "NULL").then_some(c.rv.as_str());
    assert_eq!(rev::reason_name(c.num("code")), want, "{name}");
}

fn run_hex(name: &str) {
    // RULE-024
    let c = case(name);
    assert_eq!(c.op, "hex");
    let want = (c.rv == "1").then(|| unhex(c.get("out")));
    assert_eq!(
        rev::hex_to_bytes(&c.bytes("in"), c.num("cap")),
        want,
        "{name}"
    );
}

fn run_date(name: &str) {
    // RULE-024, DIV-016
    let c = case(name);
    assert_eq!(c.op, "date");
    let want = match DIV016_DATE.iter().find(|d| d.0 == name) {
        Some(&(_, c_t)) => {
            assert_eq!((c.rv.as_str(), c.get("t")), ("1", c_t), "{name}: C's value");
            None
        }
        None => (c.rv == "1").then(|| c.num::<i64>("t")),
    };
    assert_eq!(rev::date_to_time(&c.bytes("in")), want, "{name}");
}

fn run_time(name: &str) {
    // RULE-024
    let c = case(name);
    assert_eq!(c.op, "time");
    let want = (c.rv == "1").then(|| c.text("out"));
    assert_eq!(rev::time_to_date(c.num("t")), want, "{name}");
}

fn run_serial_eq(name: &str) {
    // RULE-024
    let c = case(name);
    assert_eq!(c.op, "serial_eq");
    let got = rev::serial_eq(&unhex(c.get("a")), &unhex(c.get("b")));
    assert_eq!((got as i32).to_string(), c.rv, "{name}");
}

fn run_load(name: &str) {
    // RULE-024, RULE-100, DIV-016
    let c = case(name);
    assert_eq!(c.op, "load");
    if needs_unprivileged(&c) {
        require_unprivileged(name);
    }
    let dir = tempfile::tempdir().unwrap();
    let p = load_input(dir.path(), c.get("file"));
    let r = Db::load(&p);
    let base = format!("{{dir}}/{}", p.file_name().unwrap().to_str().unwrap());

    let div = DIV_LOAD_REFUSED.iter().find(|d| d.0 == name);
    let (rv, entries, err) = match (DIV016_LOAD.iter().find(|d| d.0 == name), div) {
        (Some(&(_, c_entries, line)), _) => {
            assert_eq!(
                (c.rv.as_str(), c.get("entries")),
                ("0", c_entries),
                "{name}: C's value"
            );
            let why = "date is not YYYYMMDDHHMMSSZ";
            (3, String::new(), db_bad(&base, line, why))
        }
        (None, Some(&(_, c_rv, c_entries, rv, line, why))) => {
            assert_eq!(
                (c.rv.as_str(), c.opt("entries").unwrap_or("")),
                (c_rv, c_entries),
                "{name}: C's value"
            );
            let err = match line {
                0 => format!("cannot read {base}: {why}\n"),
                _ => db_bad(&base, line, why),
            };
            (rv, String::new(), err)
        }
        (None, None) => (
            c.rv_i(),
            c.opt("entries").unwrap_or("").to_owned(),
            full_load_err(&c),
        ),
    };
    assert_eq!(rv_of(&r), rv, "{name}: rv");
    match r {
        Ok(d) => {
            assert_eq!(
                d.crl_number,
                c.num::<u64>("crl_number"),
                "{name}: crlNumber"
            );
            assert_eq!(d.entries.len(), c.num::<usize>("n"), "{name}: n");
            if c.opt("entries").is_some() {
                assert_eq!(entries_text(&d), entries, "{name}: entries");
            }
        }
        Err(e) => assert_eq!(norm(&e.msg, dir.path()), err, "{name}: err"),
    }
    if c.is("file", "unreadable") {
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// The whole diagnostic C gave a load row. A row made with err NULL or a small cap (the C
/// ABI's business) takes it from the row that loaded the same input into a full buffer.
fn full_load_err(c: &Case) -> String {
    if c.opt("err_cap").is_none() && c.opt("err_mode").is_none() {
        return c.opt("err").map_or(String::new(), |_| c.text("err"));
    }
    let full = cases_of("load")
        .into_iter()
        .find(|o| {
            o.get("file") == c.get("file")
                && o.opt("err_cap").is_none()
                && o.opt("err_mode").is_none()
        })
        .unwrap_or_else(|| panic!("{}: no full-buffer row for its input", c.name));
    full.text("err")
}

fn run_save(name: &str) {
    // RULE-100
    let c = case(name);
    assert_eq!(c.op, "save");
    if needs_unprivileged(&c) {
        require_unprivileged(name);
    }
    umask_022();
    let dir = tempfile::tempdir().unwrap();
    let d = db_from_spec(c.get("db"));
    let target = c.get("target");
    let mut p = dir.path().join(format!("{name}.db"));
    match target {
        "missing_dir" => p = dir.path().join(format!("nope/{name}.db")),
        "ro_dir" => {
            let ro = dir.path().join("ro");
            fs::create_dir(&ro).unwrap();
            fs::set_permissions(&ro, fs::Permissions::from_mode(0o555)).unwrap();
            p = ro.join(format!("{name}.db"));
        }
        t if t.starts_with("len:") => p = long_path(dir.path(), t[4..].parse().unwrap()),
        _ => {}
    }
    let mut tmp = p.clone().into_os_string();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    match target {
        "replace" => {
            fs::write(&p, b"old\n").unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        }
        "tmp_exists" => fs::write(&tmp, b"stale junk\n").unwrap(),
        "is_dir" => fs::create_dir(&p).unwrap(),
        "tmp_full" => symlink("/dev/full", &tmp).unwrap(),
        "tmp_symlink" => {
            fs::write(dir.path().join("victim"), b"victim\n").unwrap();
            symlink("victim", &tmp).unwrap();
        }
        _ => {}
    }

    let r = d.save(&p);
    if let Some(&(_, c_rv, c_after, c_tmp)) = DIV022_SAVE.iter().find(|d| d.0 == name) {
        assert_eq!(
            (c.rv.as_str(), c.get("after"), c.get("after_tmp")),
            (c_rv, c_after, c_tmp),
            "{name}: C's value"
        );
        assert_eq!(rv_of(&r), 0, "{name}: rv");
        let want = case("save_three");
        assert_eq!(state(&p, dir.path()), want.get("after"), "{name}: after");
        assert_eq!(state(&tmp, dir.path()), "absent", "{name}: tmp");
        if c.opt("victim").is_some() {
            let victim = format!("file:0644:{}", hex(b"victim\n"));
            assert_eq!(state(&dir.path().join("victim"), dir.path()), victim);
        }
        return;
    }
    assert_eq!(rv_of(&r), c.rv_i(), "{name}: rv");
    if let (Err(e), Some(_)) = (&r, c.opt("err")) {
        assert_eq!(norm(&e.msg, dir.path()), c.text("err"), "{name}: err");
    }
    if target.starts_with("len:") {
        let present = |q: &std::path::Path| fs::symlink_metadata(q).is_ok();
        assert_eq!(present(&p), c.is("after", "file"), "{name}: after");
        assert_eq!(present(&tmp), c.is("after_tmp", "present"), "{name}: tmp");
    } else {
        assert_eq!(state(&p, dir.path()), c.get("after"), "{name}: after");
        assert_eq!(state(&tmp, dir.path()), c.get("after_tmp"), "{name}: tmp");
    }
    if let Some(v) = c.opt("victim") {
        assert_eq!(state(&dir.path().join("victim"), dir.path()), v);
    }
    if target == "ro_dir" {
        fs::set_permissions(dir.path().join("ro"), fs::Permissions::from_mode(0o755)).unwrap();
    }
}

fn run_find(name: &str) {
    // RULE-099
    let c = case(name);
    assert_eq!(c.op, "find");
    let d = db_from_spec(c.get("db"));
    let got = d
        .find(&unhex(c.get("q")))
        .map(|e| d.entries.iter().position(|x| std::ptr::eq(x, e)).unwrap() as i64);
    assert_eq!(got.unwrap_or(-1), c.rv_i(), "{name}");
}

fn run_status(name: &str) {
    // RULE-023
    let c = case(name);
    assert_eq!(c.op, "status");
    let want = (c.rv == "5").then(|| unhex(c.get("out")));
    let got = rev::status_response(c.num("status")).map(|b| b.to_vec());
    assert_eq!(got, want, "{name}");
}

fn run_check(name: &str) {
    // RULE-023
    let c = case(name);
    assert_eq!(c.op, "check");
    let path = |k: &str| (!c.is(k, "NULL")).then(|| c.get(k).to_owned());
    let (rp, cp) = (path("rpath"), path("cpath"));
    let r = rev::check_responder(
        &der(c.get("responder")),
        &der(c.get("ca")),
        rp.as_deref(),
        cp.as_deref(),
    );
    assert_eq!(rv_of(&r), c.rv_i(), "{name}: rv");
    if let Err(e) = r {
        assert_eq!(e.msg, c.text("err"), "{name}: err");
    }
}

/// The encoder input Rust must produce for a row: C's, unless DIV-016 changes a revocation
/// time (C's value is checked first).
fn want_enc(name: &str, c_enc: &str) -> String {
    let body = enc_body(c_enc);
    let Some(&(_, idx, c_time, rust_time)) = DIV016_ANSWER.iter().find(|d| d.0 == name) else {
        return body;
    };
    let mut lines: Vec<String> = body.lines().map(str::to_owned).collect();
    let k = lines.iter().position(|l| l.starts_with("single ")).unwrap() + idx;
    let mut f: Vec<String> = lines[k].split(' ').map(str::to_owned).collect();
    assert_eq!(f[3], hex(&gt(c_time)), "{name}: C's revocation time");
    f[3] = hex(&gt(rust_time));
    lines[k] = f.join(" ");
    lines.iter().map(|l| format!("{l}\n")).collect()
}

fn run_answer(name: &str) {
    // RULE-023
    let c = case(name);
    assert_eq!(c.op, "answer");
    let inp = answer_inputs(&c);
    let q = Query {
        req: &inp.req,
        ca: &inp.ca,
        responder: &inp.responder,
        db: &inp.db,
        days: inp.days,
        label: inp.label.as_deref(),
        now: now(),
    };
    let synth: Option<usize> = c.opt("synth").map(|s| s.parse().unwrap());
    let c_enc = golden_enc(name);
    let called = Cell::new(0);
    let mut encode = |t: &Tbs<'_>| -> Result<Vec<u8>, u32> {
        called.set(called.get() + 1);
        if let Some(n) = synth {
            assert!(n <= t.cap, "{name}: synthetic basic larger than the cap");
            return Ok(pattern(n));
        }
        let enc = c_enc
            .as_deref()
            .unwrap_or_else(|| panic!("{name}: C never reached the encoder"));
        assert_eq!(enc_text(t), want_enc(name, enc), "{name}: encoder input");
        match enc_rv(enc) {
            0 => Ok(golden_bytes(&format!("ocsp/{name}.basic.der"))),
            rv => Err(rv),
        }
    };
    let r = rev::answer(&q, &mut encode);
    assert_eq!(
        called.get().to_string(),
        c.get("encoder_called"),
        "{name}: encoder calls"
    );
    assert_eq!(rv_of(&r), c.rv_i(), "{name}: rv");
    match r {
        Ok((out, stats)) => {
            if let Some(s) = c.opt("stats").filter(|s| *s != "null") {
                assert_eq!(stats_text(&stats), s, "{name}: stats");
            }
            assert_eq!(out.len(), c.num::<usize>("out_len"), "{name}: length");
            match synth {
                Some(n) => {
                    let head = out.len() - n;
                    assert_eq!(hex(&out[..head]), c.get("prefix"), "{name}: wrap");
                    assert_eq!(out[head..], pattern(n)[..], "{name}: basic");
                }
                None => assert!(
                    out == golden_bytes(&format!("ocsp/{name}.resp.der")),
                    "{name}: the OCSPResponse differs from C's"
                ),
            }
        }
        Err(e) => match c.opt("err_cap") {
            // the cap is the C ABI's: the safe API returns the whole diagnostic
            Some(cap) => {
                let cap: usize = cap.parse().unwrap();
                assert_eq!(e.msg.as_bytes()[..cap - 1], c.bytes("err")[..], "{name}");
            }
            None if c.opt("err").is_some() => assert_eq!(e.msg, c.text("err"), "{name}: err"),
            None => {}
        },
    }
}

// ---------------------------------------------------------------------------------------
// Reasons, serials, dates
// ---------------------------------------------------------------------------------------
golden! {
    reason_code_unspecified_is_0 => run_reason_code("reason_code_unspecified");
    reason_code_key_compromise_is_1 => run_reason_code("reason_code_keyCompromise");
    reason_code_ca_compromise_is_2 => run_reason_code("reason_code_cACompromise");
    reason_code_affiliation_changed_is_3 => run_reason_code("reason_code_affiliationChanged");
    reason_code_superseded_is_4 => run_reason_code("reason_code_superseded");
    reason_code_cessation_is_5 => run_reason_code("reason_code_cessationOfOperation");
    reason_code_certificate_hold_is_6 => run_reason_code("reason_code_certificateHold");
    reason_code_privilege_withdrawn_is_9 => run_reason_code("reason_code_privilegeWithdrawn");
    reason_code_aa_compromise_is_10 => run_reason_code("reason_code_aACompromise");
    reason_code_of_empty_is_minus_2 => run_reason_code("reason_code_empty");
    reason_code_of_dash_is_minus_2 => run_reason_code("reason_code_dash");
    reason_code_is_case_sensitive => run_reason_code("reason_code_wrong_case");
    reason_code_refuses_remove_from_crl => run_reason_code("reason_code_remove_from_crl");
    reason_code_refuses_a_number => run_reason_code("reason_code_numeric");
    reason_code_refuses_a_trailing_space => run_reason_code("reason_code_trailing_space");
    reason_name_minus_3_is_none => run_reason_name("reason_name_minus_3");
    reason_name_minus_2_is_none => run_reason_name("reason_name_minus_2");
    reason_name_minus_1_is_none => run_reason_name("reason_name_minus_1");
    reason_name_0 => run_reason_name("reason_name_0");
    reason_name_1 => run_reason_name("reason_name_1");
    reason_name_2 => run_reason_name("reason_name_2");
    reason_name_3 => run_reason_name("reason_name_3");
    reason_name_4 => run_reason_name("reason_name_4");
    reason_name_5 => run_reason_name("reason_name_5");
    reason_name_6 => run_reason_name("reason_name_6");
    reason_name_7_unassigned_is_none => run_reason_name("reason_name_7");
    reason_name_8_remove_from_crl_is_none => run_reason_name("reason_name_8");
    reason_name_9 => run_reason_name("reason_name_9");
    reason_name_10 => run_reason_name("reason_name_10");
    reason_name_11_is_none => run_reason_name("reason_name_11");
    reason_name_int_max_is_none => run_reason_name("reason_name_int_max");

    hex_empty_is_refused => run_hex("hex_empty");
    hex_one_digit_is_refused => run_hex("hex_one_digit");
    hex_two_digits => run_hex("hex_two_digits");
    hex_upper_case => run_hex("hex_upper");
    hex_mixed_case => run_hex("hex_mixed_case");
    hex_every_digit => run_hex("hex_all_digits");
    hex_odd_length_is_refused => run_hex("hex_odd");
    hex_bad_high_nibble_is_refused => run_hex("hex_bad_first_pair");
    hex_bad_low_nibble_is_refused => run_hex("hex_bad_low_nibble");
    hex_bad_later_pair_is_refused => run_hex("hex_bad_later_pair_writes_earlier_bytes");
    hex_0x_prefix_is_refused => run_hex("hex_0x_prefix");
    hex_leading_space_is_refused => run_hex("hex_space");
    hex_non_ascii_is_refused => run_hex("hex_utf8");
    hex_exactly_the_cap => run_hex("hex_cap_exact");
    hex_one_byte_over_the_cap_is_refused => run_hex("hex_cap_over_by_one");
    hex_cap_zero_is_refused => run_hex("hex_cap_zero");
    hex_64_bytes_fit_an_entry => run_hex("hex_64_bytes");
    hex_65_bytes_do_not => run_hex("hex_65_bytes");

    date_valid => run_date("date_valid");
    date_epoch_is_0 => run_date("date_epoch");
    date_one_second_before_epoch_is_refused_as_timegm_s_error_value => run_date("date_one_second_before_epoch");
    date_two_seconds_before_epoch_is_minus_2 => run_date("date_two_seconds_before_epoch");
    date_year_0000 => run_date("date_year_0000");
    date_year_9999 => run_date("date_year_9999");
    date_leap_day => run_date("date_leap_day");
    date_after_2038 => run_date("date_y2038");
    date_without_z_is_refused => run_date("date_14_digits_no_z");
    date_lower_case_z_is_refused => run_date("date_lower_z");
    date_16_chars_is_refused => run_date("date_16_chars");
    date_13_digits_is_refused => run_date("date_13_digits");
    date_letter_is_refused => run_date("date_letter");
    date_space_is_refused => run_date("date_space");
    date_sign_is_refused => run_date("date_plus");
    date_empty_is_refused => run_date("date_empty");
    date_month_13_div016 => run_date("date_div016_month_13");
    date_month_00_div016 => run_date("date_div016_month_00");
    date_day_00_div016 => run_date("date_div016_day_00");
    date_feb_30_div016 => run_date("date_div016_feb_30");
    date_feb_29_non_leap_div016 => run_date("date_div016_feb_29_non_leap");
    date_feb_29_1900_div016 => run_date("date_div016_feb_29_1900");
    date_apr_31_div016 => run_date("date_div016_apr_31");
    date_hour_24_div016 => run_date("date_div016_hour_24");
    date_hour_99_div016 => run_date("date_div016_hour_99");
    date_minute_60_div016 => run_date("date_div016_minute_60");
    date_second_60_div016 => run_date("date_div016_second_60");
    date_all_nines_div016 => run_date("date_div016_all_nines");

    time_epoch => run_time("time_epoch");
    time_minus_one => run_time("time_minus_one");
    time_2026 => run_time("time_2026");
    time_last_second_of_9999 => run_time("time_last_of_9999");
    time_year_10000_does_not_fit => run_time("time_first_of_10000");
    time_year_0000 => run_time("time_first_of_0000");
    time_year_minus_1_prints_a_sign => run_time("time_last_of_year_minus_1");
    time_year_minus_999_prints_a_sign => run_time("time_first_of_year_minus_999");
    time_year_minus_1000_does_not_fit => run_time("time_last_of_year_minus_1000");
    time_int64_max_fails => run_time("time_int64_max");
    time_int64_min_fails => run_time("time_int64_min");

    serial_eq_same => run_serial_eq("serial_eq_same");
    serial_eq_ignores_leading_zeros_on_the_left => run_serial_eq("serial_eq_leading_zero_left");
    serial_eq_ignores_leading_zeros_on_the_right => run_serial_eq("serial_eq_leading_zero_right");
    serial_eq_trailing_zeros_matter => run_serial_eq("serial_eq_trailing_zero_differs");
    serial_eq_different => run_serial_eq("serial_eq_different");
    serial_eq_zero_equals_zeros => run_serial_eq("serial_eq_zero_and_zeros");
    serial_eq_two_empty_serials_are_equal => run_serial_eq("serial_eq_both_empty");
    serial_eq_zero_is_not_empty => run_serial_eq("serial_eq_zero_and_empty");
    serial_eq_prefix_is_not_equal => run_serial_eq("serial_eq_prefix");
}

#[test]
fn reason_list_is_c_s_text() {
    // RULE-024
    assert_eq!(rev::reason_list(), case("reason_list").rv);
}

// ---------------------------------------------------------------------------------------
// Load
// ---------------------------------------------------------------------------------------
golden! {
    load_empty_file => run_load("load_empty");
    load_comments_and_blank_lines => run_load("load_comments_only");
    load_crlf => run_load("load_crlf");
    load_refuses_a_cr_only_file_div019 => run_load("load_cr_only");
    load_refuses_cr_only_entries_div019 => run_load("load_cr_only_entries");
    load_a_cr_ends_the_line => run_load("load_embedded_cr");
    load_leading_whitespace => run_load("load_leading_ws");
    load_a_comment_as_the_reason_field_is_ignored_after_three_tokens => run_load("load_trailing_comment");
    load_a_comment_in_the_reason_field_is_an_unknown_reason => run_load("load_trailing_comment_no_reason");
    load_a_fourth_token_is_ignored => run_load("load_extra_token");
    load_no_final_newline => run_load("load_no_final_newline");
    load_runs_of_whitespace => run_load("load_many_spaces");
    load_every_reason_dash_and_none => run_load("load_all_reasons");
    load_reason_is_case_sensitive => run_load("load_reason_wrong_case");
    load_refuses_remove_from_crl => run_load("load_reason_remove_from_crl");
    load_refuses_a_numeric_reason => run_load("load_reason_numeric");
    load_refuses_a_lone_serial => run_load("load_one_token");
    load_refuses_a_non_hex_serial => run_load("load_serial_not_hex");
    load_refuses_0x => run_load("load_serial_0x");
    load_lower_case_serial => run_load("load_serial_lower");
    load_zero_serials_kept_as_written => run_load("load_serial_zero");
    load_64_byte_serial => run_load("load_serial_64_bytes");
    load_refuses_a_65_byte_serial => run_load("load_serial_65_bytes");
    load_refuses_a_date_without_z => run_load("load_date_14_no_z");
    load_refuses_lower_case_z => run_load("load_date_lower_z");
    load_refuses_one_second_before_epoch => run_load("load_date_one_second_before_epoch");
    load_epoch_date => run_load("load_date_epoch");
    load_years_0000_and_9999 => run_load("load_date_year_bounds");
    load_month_00_div016 => run_load("load_div016_month_00");
    load_feb_30_div016 => run_load("load_div016_feb_30");
    load_hour_24_div016 => run_load("load_div016_hour_24");
    load_second_60_div016 => run_load("load_div016_second_60");
    load_names_the_bad_line_div016 => run_load("load_div016_second_line");
    load_crl_number_after_a_tab => run_load("load_crl_tab");
    load_crl_number_after_two_spaces => run_load("load_crl_two_spaces");
    load_crl_number_trailing_space_is_refused => run_load("load_crl_trailing_space");
    load_crl_number_trailing_tab_is_refused => run_load("load_crl_trailing_tab");
    load_crl_number_minus_1_wraps_to_u64_max => run_load("load_crl_negative");
    load_crl_number_overflow_saturates => run_load("load_crl_overflow");
    load_crl_number_u64_max => run_load("load_crl_max");
    load_crl_number_with_no_digits_is_0 => run_load("load_crl_empty_value");
    load_crl_number_hex_is_refused => run_load("load_crl_hex");
    load_crl_number_plus_sign => run_load("load_crl_plus");
    load_bare_crl_number_is_an_entry_line => run_load("load_crl_bare");
    load_crlnumber_lower_case_is_an_entry_line => run_load("load_crl_lowercase");
    load_crl_number_twice_is_refused => run_load("load_crl_twice");
    load_crl_number_after_entries => run_load("load_crl_after_entries");
    load_crl_number_indented => run_load("load_crl_indented");
    load_failure_forgets_the_crl_number => run_load("load_crl_then_bad_line");
    load_line_numbers_count_comments => run_load("load_line_number_counts_comments");
    load_a_nul_ends_the_line => run_load("load_nul_byte");
    load_a_vertical_tab_line_is_not_blank => run_load("load_vertical_tab_line");
    load_a_form_feed_is_whitespace_to_sscanf => run_load("load_formfeed_prefix");
    load_keeps_duplicate_serials => run_load("load_duplicate_serials");
    load_refuses_a_bom => run_load("load_utf8_bom");
    load_refuses_a_long_comment_at_its_own_line_div020 => run_load("load_long_comment");
    load_refuses_an_entry_hidden_in_a_long_comment_div020 => run_load("load_long_comment_revives_an_entry");
    load_refuses_a_long_entry_line_div020 => run_load("load_long_entry_line");
    load_refuses_a_170_digit_serial => run_load("load_serial_170_digits");
    load_the_ocsp_database => run_load("load_ocsp");
    load_missing_file_is_a_first_run => run_load("load_missing_file_is_a_first_run");
    load_of_a_directory_is_eio_div021 => run_load("load_directory_reads_as_empty");
    load_unreadable_file_is_eio => run_load("load_unreadable_file_is_eio");
    load_path_through_a_file_is_eio => run_load("load_not_a_directory_is_eio");
    load_100000_entries => run_load("load_100000_entries");
    load_100001_entries_is_too_many => run_load("load_100001_entries_is_too_many");
    load_err_null => run_load("load_err_null");
    load_err_cap_0 => run_load("load_err_cap_0");
    load_err_cap_1 => run_load("load_err_cap_1");
    load_err_cap_10 => run_load("load_err_cap_10");
    load_err_null_on_eio => run_load("load_err_null_eio");
}

// ---------------------------------------------------------------------------------------
// Save, C-save then load, add, find
// ---------------------------------------------------------------------------------------
golden! {
    save_three_entries => run_save("save_three");
    save_empty => run_save("save_empty");
    save_crl_number_u64_max => run_save("save_crl_max");
    save_writes_dash_for_codes_without_a_name => run_save("save_every_reason_code");
    save_keeps_leading_zeros => run_save("save_leading_zeros_kept");
    save_an_empty_serial => run_save("save_empty_serial");
    save_a_64_byte_serial => run_save("save_64_byte_serial");
    save_writes_dates_unvalidated => run_save("save_unvalidated_date");
    save_replaces_and_the_mode_follows_the_umask => run_save("save_replaces_and_resets_mode");
    save_overwrites_a_stale_tmp => run_save("save_overwrites_a_stale_tmp");
    save_into_a_missing_dir_is_eio => run_save("save_into_a_missing_dir");
    save_into_a_read_only_dir_is_eio => run_save("save_into_a_read_only_dir");
    save_onto_a_directory_leaves_the_tmp => run_save("save_onto_a_directory");
    save_replaces_a_tmp_symlink_to_dev_full_div022 => run_save("save_tmp_on_a_full_device");
    save_never_writes_through_a_tmp_symlink_div022 => run_save("save_follows_a_tmp_symlink");
    save_at_1019_bytes => run_save("save_path_1019_bytes");
    save_at_1020_bytes_is_too_long => run_save("save_path_1020_bytes_is_too_long");
    save_err_null => run_save("save_err_null");

    roundtrip_three => run_load("roundtrip_three");
    roundtrip_empty => run_load("roundtrip_empty");
    roundtrip_crl_number_u64_max => run_load("roundtrip_crl_max");
    roundtrip_unnamed_codes_come_back_as_none => run_load("roundtrip_every_reason_code");
    roundtrip_leading_zeros => run_load("roundtrip_leading_zeros_kept");
    roundtrip_empty_serial_is_refused_on_load => run_load("roundtrip_empty_serial");
    roundtrip_64_byte_serial => run_load("roundtrip_64_byte_serial");
    roundtrip_unvalidated_date_is_refused_on_load => run_load("roundtrip_unvalidated_date");

    find_exact => run_find("find_exact");
    find_returns_the_first_of_two_equal_serials => run_find("find_first_of_two_equal_serials");
    find_ignores_more_leading_zeros => run_find("find_more_leading_zeros");
    find_ignores_the_stored_leading_zeros => run_find("find_query_without_the_stored_zeros");
    find_zero => run_find("find_zero");
    find_zeros => run_find("find_zeros");
    find_empty_query_matches_nothing => run_find("find_empty_query");
    find_absent => run_find("find_absent");
    find_in_an_empty_db => run_find("find_in_an_empty_db");
}

fn entry(i: u32) -> Entry {
    Entry {
        serial: i.to_be_bytes().to_vec(),
        date: b"20260101000000Z".to_vec(),
        reason: -1,
    }
}

#[test]
fn add_reaches_the_cap_and_the_next_is_eparse() {
    // RULE-099: add_growth_to_the_cap, add_past_the_cap_is_eparse (the header says EIO; C
    // returns EPARSE)
    let grow = case("add_growth_to_the_cap");
    let cap = case("add_past_the_cap_is_eparse");
    let mut d = Db::default();
    for i in 0..grow.num::<u32>("n") {
        d.add(entry(i)).unwrap();
    }
    assert_eq!(d.entries.len(), rev::MAX_ENTRIES);
    let r = d.add(Entry {
        serial: vec![0xAB],
        date: b"20260101000000Z".to_vec(),
        reason: 1,
    });
    assert_eq!(rv_of(&r), cap.rv_i());
    assert_eq!(r.unwrap_err().msg, cap.text("err"));
    assert_eq!(
        d.entries.len(),
        cap.num::<usize>("n"),
        "the db is unchanged"
    );
}

#[test]
fn add_keeps_an_entry_exactly_as_given() {
    // RULE-099: add copies the struct; nothing is validated ("save_unvalidated_date" relies
    // on it, "free_resets_every_field" is the C ABI's)
    assert_eq!(case("free_resets_every_field").rv, "0");
    let mut d = Db::default();
    let e = Entry {
        serial: vec![],
        date: b"garbage".to_vec(),
        reason: 77,
    };
    d.add(e.clone()).unwrap();
    assert_eq!(d.entries, vec![e]);
}

// ---------------------------------------------------------------------------------------
// The Phase 2 corpus: testdata/revocation.tsv (made by gen_token.c), reproduced exactly
// ---------------------------------------------------------------------------------------

/// gen_token.c `rev_describe`, run on a copy of the file as `/out/NAME`.
fn describe(name: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata");
    let p = dir.path().join(name);
    fs::copy(corpus.join(name), &p).unwrap();
    let r = Db::load(&p);
    let (rv, d, err) = match r {
        Ok(d) => (0, d, String::new()),
        Err(e) => (e.code, Db::default(), e.msg),
    };
    let err = err
        .replace(dir.path().to_str().unwrap(), "/out")
        .replace(['\n', '\t'], " ");
    let mut s = format!(
        "db\t{name}\trv={rv}\tcrl_number={}\tentries={}\terr={err}\n",
        d.crl_number,
        d.entries.len()
    );
    for e in &d.entries {
        let epoch = rev::date_to_time(&e.date).unwrap_or(-1);
        s += &format!(
            "entry\t{name}\tserial={}\tdate={}\tepoch={epoch}\treason={}\n",
            hex(&e.serial),
            String::from_utf8_lossy(&e.date),
            e.reason
        );
    }
    s
}

#[test]
fn the_phase2_corpus_revocation_tsv_is_reproduced_div016() {
    // RULE-024, DIV-016: every line of testdata/revocation.tsv, except that rev_month13.db,
    // which C loads, is refused with the same text C gives rev_bad_date.db
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata");
    let c_tsv = fs::read_to_string(corpus.join("revocation.tsv")).unwrap();
    let mut want = String::new();
    let mut files = Vec::new();
    for line in c_tsv.lines() {
        let name = line.split('\t').nth(1).unwrap();
        if line.starts_with("db\t") {
            files.push(name.to_owned());
        }
        match DIV016_CORPUS.iter().find(|d| d.0 == name) {
            Some(&(_, c_entry)) if line.starts_with("entry\t") => {
                assert_eq!(line, c_entry, "C's value");
            }
            Some(_) => {
                assert!(line.contains("\trv=0\t"), "C loaded {name}");
                let bad = c_tsv
                    .lines()
                    .find(|l| l.starts_with("db\trev_bad_date.db\t"))
                    .unwrap();
                let rust = bad.replace("rev_bad_date.db", name);
                want += &format!("{rust}\n");
            }
            None => want += &format!("{line}\n"),
        }
    }
    let got: String = files.iter().map(|f| describe(f)).collect();
    assert_eq!(got, want);
}

// ---------------------------------------------------------------------------------------
// OCSP
// ---------------------------------------------------------------------------------------
golden! {
    status_minus_1_is_refused => run_status("status_minus_1");
    status_successful_is_refused => run_status("status_0");
    status_malformed_request => run_status("status_1");
    status_internal_error => run_status("status_2");
    status_try_later => run_status("status_3");
    status_4_unassigned_is_refused => run_status("status_4");
    status_sig_required_is_refused => run_status("status_5");
    status_unauthorized_is_refused => run_status("status_6");
    status_256_is_refused => run_status("status_256");
    status_257_is_refused => run_status("status_257");
    status_int_min_is_refused => run_status("status_int_min");

    check_ok => run_check("check_ok");
    check_ok_default_names => run_check("check_ok_default_names");
    check_ok_with_ocsp_signing_among_others => run_check("check_ok_eku_among_others");
    check_no_eku => run_check("check_no_eku");
    check_no_eku_default_names => run_check("check_no_eku_default_names");
    check_server_auth_only => run_check("check_server_auth_only");
    check_other_issuer => run_check("check_other_issuer");
    check_other_issuer_default_names => run_check("check_other_issuer_default_names");
    check_eku_is_checked_before_the_issuer => run_check("check_eku_is_checked_before_the_issuer");
    check_same_name_other_key_passes => run_check("check_same_name_other_key_passes");
    check_issuer_name_comparison_folds_case_and_spaces => run_check("check_issuer_name_case_and_spaces_fold");
    check_the_ca_itself_has_no_eku => run_check("check_ca_as_its_own_responder");
    check_responder_garbage => run_check("check_responder_garbage");
    check_responder_garbage_default_name => run_check("check_responder_garbage_default_name");
    check_responder_empty => run_check("check_responder_empty");
    check_ca_garbage => run_check("check_ca_garbage");
    check_ca_garbage_default_name => run_check("check_ca_garbage_default_name");
    check_both_garbage_names_the_responder => run_check("check_both_garbage_names_the_responder");
    check_ignores_trailing_junk => run_check("check_trailing_junk_is_ignored");

    answer_good_for_sha1 => run_answer("answer_good_sha1");
    answer_good_for_sha256_and_echoes_the_nonce => run_answer("answer_good_sha256_echoes_the_nonce");
    answer_revoked_with_its_reason => run_answer("answer_revoked_with_reason");
    answer_revoked_without_a_reason_ignoring_leading_zeros => run_answer("answer_revoked_without_reason_leading_zero_db");
    answer_revoked_for_sha1 => run_answer("answer_revoked_sha1");
    answer_sha512 => run_answer("answer_sha512");
    answer_sha384 => run_answer("answer_sha384");
    answer_sha224 => run_answer("answer_sha224");
    answer_sha3_256 => run_answer("answer_sha3_256");
    answer_md5 => run_answer("answer_md5");
    answer_unknown_hash_is_unknown => run_answer("answer_unknown_hash_is_unknown");
    answer_other_issuer_is_unknown => run_answer("answer_other_issuer_is_unknown");
    answer_same_name_other_key_is_unknown => run_answer("answer_same_name_other_key_is_unknown");
    answer_mixed_request_and_stats => run_answer("answer_mixed");
    answer_serial_zero_matches_entry_00 => run_answer("answer_serial_zero");
    answer_negative_serial_matches_its_magnitude => run_answer("answer_negative_serial");
    answer_serial_80_matches_without_the_der_zero => run_answer("answer_serial_80");
    answer_revocation_years_0000_and_9999 => run_answer("answer_year_bounds");
    answer_every_reason => run_answer("answer_every_reason");
    answer_duplicate_certids_each_answered => run_answer("answer_duplicate_certids");
    answer_ignores_trailing_junk_in_the_request => run_answer("answer_trailing_junk_in_request");
    answer_nonce_extension_of_127_bytes => run_answer("answer_nonce_ext_127");
    answer_nonce_extension_of_128_bytes => run_answer("answer_nonce_ext_128");
    answer_nonce_extension_of_255_bytes => run_answer("answer_nonce_ext_255");
    answer_nonce_extension_of_256_bytes => run_answer("answer_nonce_ext_256");
    answer_nonce_extension_of_65535_bytes => run_answer("answer_nonce_ext_65535");
    answer_nonce_extension_of_65536_bytes_gets_a_truncated_header => run_answer("answer_nonce_ext_65536_header_truncated");
    answer_critical_nonce_echoed_as_is => run_answer("answer_nonce_critical_echoed_as_is");
    answer_echoes_the_first_of_two_nonces => run_answer("answer_two_nonces_echoes_the_first");
    answer_does_not_echo_other_extensions => run_answer("answer_other_extension_not_echoed");
    answer_finds_the_nonce_after_another_extension => run_answer("answer_nonce_after_another_extension");
    answer_big_request_overflows_the_encoder_buffer => run_answer("answer_big_request_overflows_the_encoder_buffer");
    answer_unvalidated_dates_div016 => run_answer("answer_div016_unvalidated_dates");
    answer_composite_entry_point_decides_the_same => run_answer("answer_composite_algid");
    answer_the_ca_answering_for_itself => run_answer("answer_ca_answers_for_itself");
    answer_days_1 => run_answer("answer_days_1");
    answer_days_365 => run_answer("answer_days_365");
    answer_days_up_to_year_9999 => run_answer("answer_days_last_in_9999");
    answer_days_into_year_10000_emits_a_16_char_time => run_answer("answer_days_into_year_10000_emits_a_16_char_time");
    answer_days_int_max_emits_an_18_char_time => run_answer("answer_days_int_max_emits_an_18_char_time");
    answer_days_0_is_eio => run_answer("answer_days_0");
    answer_days_are_checked_before_anything_else => run_answer("answer_days_negative_checked_first");
    answer_ca_garbage => run_answer("answer_ca_garbage");
    answer_ca_is_checked_before_the_request => run_answer("answer_ca_checked_before_request");
    answer_ca_trailing_junk_is_ignored => run_answer("answer_ca_trailing_junk");
    answer_request_garbage => run_answer("answer_request_garbage");
    answer_request_garbage_names_the_label => run_answer("answer_request_garbage_labelled");
    answer_empty_request_with_an_empty_label => run_answer("answer_request_empty");
    answer_request_asking_about_nothing => run_answer("answer_empty_request_list");
    answer_request_asking_about_nothing_names_the_label => run_answer("answer_empty_request_list_labelled");
    answer_encoder_failure_on_a_garbage_responder => run_answer("answer_responder_garbage_fails_in_the_encoder");
    answer_sign_failure_reports_the_rv => run_answer("answer_sign_failure");
    answer_err_null => run_answer("answer_err_null");
    answer_err_cap_8 => run_answer("answer_err_cap_8");
    answer_stats_null => run_answer("answer_stats_null");
    answer_stats_null_on_error => run_answer("answer_stats_null_on_error");

    wrap_basic_0 => run_answer("wrap_basic_0");
    wrap_basic_107 => run_answer("wrap_basic_107");
    wrap_basic_108 => run_answer("wrap_basic_108");
    wrap_basic_112 => run_answer("wrap_basic_112");
    wrap_basic_113 => run_answer("wrap_basic_113");
    wrap_basic_114 => run_answer("wrap_basic_114");
    wrap_basic_115 => run_answer("wrap_basic_115");
    wrap_basic_127 => run_answer("wrap_basic_127");
    wrap_basic_128 => run_answer("wrap_basic_128");
    wrap_basic_232 => run_answer("wrap_basic_232");
    wrap_basic_233 => run_answer("wrap_basic_233");
    wrap_basic_238 => run_answer("wrap_basic_238");
    wrap_basic_239 => run_answer("wrap_basic_239");
    wrap_basic_241 => run_answer("wrap_basic_241");
    wrap_basic_242 => run_answer("wrap_basic_242");
    wrap_basic_255 => run_answer("wrap_basic_255");
    wrap_basic_256 => run_answer("wrap_basic_256");
    wrap_basic_65509 => run_answer("wrap_basic_65509");
    wrap_basic_65510 => run_answer("wrap_basic_65510");
    wrap_basic_65516 => run_answer("wrap_basic_65516");
    wrap_basic_65517 => run_answer("wrap_basic_65517");
    wrap_basic_65520 => run_answer("wrap_basic_65520");
    wrap_basic_65521 => run_answer("wrap_basic_65521");
    wrap_basic_65535 => run_answer("wrap_basic_65535");
    wrap_basic_65536 => run_answer("wrap_basic_65536");
}

#[test]
fn the_answers_agree_with_openssl_s_reading_of_c_s_responses() {
    // RULE-023: independent of the bytes, what a client sees in each C response matches the
    // decisions in the encoder input (status, reason, revocation time) and the clock
    let now = case("c_struct_layout").num::<i64>("now");
    assert_eq!(now, 1_798_761_600, "2027-01-01T00:00:00Z");
    let mut seen = 0;
    for c in cases_of("answer") {
        let (Some(singles), Some(enc)) = (c.opt("resp_singles"), golden_enc(&c.name)) else {
            continue;
        };
        assert_eq!(c.get("resp_produced"), "20270101000000Z", "{}", c.name);
        assert_eq!(c.get("resp_this"), "20270101000000Z", "{}", c.name);
        let decided: Vec<String> = enc_body(&enc)
            .lines()
            .filter_map(|l| l.strip_prefix("single "))
            .map(|l| {
                let f: Vec<&str> = l.split(' ').collect();
                let status = ["good", "revoked", "unknown"][f[1].parse::<usize>().unwrap()];
                let t = (f[2] != "-").then(|| String::from_utf8(unhex(&f[2][4..])).unwrap());
                format!("{status}/{}/{}", f[3], t.as_deref().unwrap_or("-"))
            })
            .collect();
        assert_eq!(decided.join(","), singles, "{}", c.name);
        seen += 1;
    }
    assert!(seen >= 40, "expected the answer rows, saw {seen}");
}

// ---------------------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------------------

#[test]
fn every_golden_row_is_covered_by_a_named_test() {
    // guard against a regen adding a row nobody asserts
    let src = [
        include_str!("revocation.rs"),
        include_str!("revocation_ffi.rs"),
    ]
    .concat();
    for c in cases() {
        assert!(
            src.contains(&format!("\"{}\"", c.name)),
            "untested golden row {}",
            c.name
        );
    }
}

#[test]
fn every_div_row_exists_in_the_goldens() {
    // the DIV tables must name real rows, or the override silently never applies
    let names: Vec<String> = cases().into_iter().map(|c| c.name).collect();
    let rows = DIV016_DATE
        .iter()
        .map(|d| d.0)
        .chain(DIV016_LOAD.iter().map(|d| d.0))
        .chain(DIV016_ANSWER.iter().map(|d| d.0))
        .chain(DIV_LOAD_REFUSED.iter().map(|d| d.0))
        .chain(DIV022_SAVE.iter().map(|d| d.0));
    for n in rows {
        assert!(
            names.iter().any(|x| x == n),
            "DIV table names missing row {n}"
        );
    }
    for (f, _) in DIV016_CORPUS {
        let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata");
        assert!(corpus.join(f).exists(), "{f}");
    }
}

#[test]
fn the_div_tables_match_divergences_md() {
    // DIV-016 and DIV-019 to DIV-022 are the decided Fixes for this file; RULE-023 and
    // RULE-099/100 are deferred, so their C behaviour is pinned unchanged here
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../analysis/pqHSM/DIVERGENCES.md");
    let md = fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "{}: {e}. Mount the repository root, not only the workspace (tests/README.md).",
            p.display()
        )
    });
    let sections: Vec<&str> = md.split("\n### ").skip(1).collect();
    let div016 = sections
        .iter()
        .find(|s| s.starts_with("DIV-016 "))
        .expect("DIV-016 section");
    assert!(div016.contains("DECIDED, Fix"), "DIV-016 is decided Fix");
    assert!(div016.contains("fhsm_rev_date_to_time"));
    assert!(
        div016.contains("20261340990000Z"),
        "the md's example is the month-13 row"
    );
    assert!(DIV016_DATE.iter().any(|d| d.0 == "date_div016_month_13"));
    let tabled = ["DIV-016 ", "DIV-019 ", "DIV-020 ", "DIV-021 ", "DIV-022 "];
    for id in &tabled[1..] {
        let sec = sections.iter().find(|s| s.starts_with(id)).expect(id);
        assert!(sec.contains("DECIDED, Fix"), "{id}is decided Fix");
    }
    // no other decided DIV touches this file, so no other table is owed
    for s in &sections {
        if s.starts_with("DIV-") && s.contains("fhsm_revocation.c") {
            assert!(
                tabled.iter().any(|t| s.starts_with(t)),
                "a DIV for fhsm_revocation.c: {}",
                &s[..40]
            );
        }
    }
    let deferred = sections
        .iter()
        .find(|s| s.starts_with("Deferred"))
        .expect("the deferral table");
    assert!(deferred.contains("| RULE-099, RULE-100 |"));
    assert!(deferred.contains("| RULE-023 |"));
}

/// DIV-074: a held lock refuses another writer and a reader after the wait, with nothing
/// changed; a shared lock admits a reader; a missing database is created empty by a writer's
/// lock (and loads as missing), not by a reader's; and a lock taken on a file a save has since
/// replaced is taken again on the new one.
#[test]
fn div074_lock() {
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("rev.db");
    let none = Duration::ZERO;
    drop(DbLock::take(&p, false, none).unwrap());
    assert!(!p.exists(), "a reader creates nothing");
    let held = DbLock::take(&p, true, none).unwrap();
    assert_eq!(fs::metadata(&p).unwrap().len(), 0);
    assert_eq!(Db::load(&p).unwrap(), Db::default());
    for exclusive in [true, false] {
        let e = DbLock::take(&p, exclusive, Duration::from_millis(50))
            .err()
            .unwrap();
        assert_eq!(e.code, rev::EIO);
        assert!(
            e.msg.ends_with(
                "is locked by another process; gave up after 0 seconds.\n  Nothing was changed.\n"
            ),
            "{}",
            e.msg
        );
    }
    drop(held);
    let r1 = DbLock::take(&p, false, none).unwrap();
    let _r2 = DbLock::take(&p, false, none).expect("readers share");
    assert!(DbLock::take(&p, true, none).is_err());
    drop((r1, _r2));
    // A writer's save renames a new file over the one a waiter opened: the waiter's lock is
    // on the old inode until it looks again.
    let w = DbLock::take(&p, true, none).unwrap();
    let t = std::thread::spawn({
        let p = p.clone();
        move || {
            let l = DbLock::take(&p, true, Duration::from_secs(5)).unwrap();
            let d = Db::load(&p).unwrap();
            drop(l);
            d.crl_number
        }
    });
    std::thread::sleep(Duration::from_millis(100));
    let mut d = Db::load(&p).unwrap();
    d.crl_number = 7;
    d.save(&p).unwrap();
    drop(w);
    assert_eq!(
        t.join().unwrap(),
        7,
        "the waiter reads what the holder saved"
    );

    // Two writers on a missing database: one creates it, the other waits for it.
    let q = dir.path().join("new.db");
    let first = DbLock::take(&q, true, none).unwrap();
    let t = std::thread::spawn({
        let q = q.clone();
        move || DbLock::take(&q, true, Duration::from_secs(5)).is_ok()
    });
    std::thread::sleep(Duration::from_millis(100));
    assert!(!t.is_finished(), "the second writer waits");
    drop(first);
    assert!(t.join().unwrap());

    // A dangling link would load as an empty database: refused, and nothing created.
    let link = dir.path().join("link.db");
    symlink(dir.path().join("gone/rev.db"), &link).unwrap();
    let e = DbLock::take(&link, true, none).err().expect("refused");
    assert!(e.msg.starts_with("cannot lock "), "{}", e.msg);
    assert!(!dir.path().join("gone").exists());
}
