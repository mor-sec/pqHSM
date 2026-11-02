//! `record`: line format (RULE-007) and sanitising (RULE-027). Literal expectations below were
//! read from lines the C module wrote (`golden/lines/lines.log`); the golden-driven
//! equivalence over every C line is in `golden_lines.rs`.

mod common;

use common::{lines, manifest, read_golden};
use pqhsm_audit::record::{
    ACTOR_MAX, Fields, LINE_MAX, PARAMS_MAX, Role, TooLong, event_name, finish_line, is_safe_ascii,
    render_body, render_params, sanitize_actor,
};

// ---- constants ----------------------------------------------------------------------------

#[test]
fn buffer_sizes_are_the_c_buffer_sizes() {
    // RULE-007, RULE-027: line[2048], params[1024], FHSM_AUDIT_ACTOR_MAX 128
    assert_eq!((LINE_MAX, PARAMS_MAX, ACTOR_MAX), (2048, 1024, 128));
}

// ---- event names and roles -------------------------------------------------------------------

#[test]
fn event_name_matches_c_for_every_header_code_and_unknown_codes() {
    // RULE-007: lines.tsv rows 1..45 are every header code then 0, 7, 9, 86, 999, 0xFFFFFFFF
    let log = read_golden("lines/lines.log");
    let c_lines = lines(&log);
    for (ev, line) in manifest("lines/lines.tsv").iter().zip(&c_lines) {
        let at = common::find(line, b"\"event\":\"").unwrap() + 9;
        let len = line[at..].iter().position(|c| *c == b'"').unwrap();
        let c_name = std::str::from_utf8(&line[at..at + len]).unwrap();
        assert_eq!(event_name(ev.code), c_name, "code {}", ev.code);
    }
}

#[test]
fn event_name_spot_checks() {
    // RULE-007
    assert_eq!(event_name(1), "module_init");
    assert_eq!(event_name(6), "state_transition");
    assert_eq!(event_name(42), "sign");
    assert_eq!(event_name(48), "generate_keypair");
    assert_eq!(event_name(85), "identity_limited");
}

#[test]
fn event_name_is_unknown_for_codes_not_in_the_header() {
    // RULE-007
    for code in [0, 7, 9, 19, 86, 999, u32::MAX] {
        assert_eq!(event_name(code), "unknown", "code {code}");
    }
}

#[test]
fn role_strings() {
    // RULE-007
    assert_eq!(Role::None.as_str(), "NONE");
    assert_eq!(Role::So.as_str(), "SO");
    assert_eq!(Role::User.as_str(), "USER");
}

// ---- safe ASCII ------------------------------------------------------------------------------

#[test]
fn safe_ascii_accepts_printable_ascii_and_the_empty_string() {
    // RULE-027
    assert!(is_safe_ascii(b""));
    assert!(is_safe_ascii(b" ~"));
    assert!(is_safe_ascii(b"CN=alice,O=Example Corp"));
}

#[test]
fn safe_ascii_rejects_controls_quote_backslash_del_and_high_bytes() {
    // RULE-027
    for bad in [
        &b"\x00"[..],
        b"\x01",
        b"\t",
        b"\n",
        b"\r",
        b"\x1f",
        b"\"",
        b"\\",
        b"\x7f",
        b"\x80",
        b"\xff",
        b"caf\xc3\xa9",
    ] {
        assert!(!is_safe_ascii(bad), "{bad:?}");
    }
}

// ---- actor -----------------------------------------------------------------------------------

#[test]
fn actor_none_is_empty() {
    // RULE-027: fhsm_audit_set_actor(NULL)
    assert_eq!(sanitize_actor(None), "");
}

#[test]
fn actor_empty_stays_empty() {
    // RULE-027
    assert_eq!(sanitize_actor(Some(b"")), "");
}

#[test]
fn actor_safe_is_kept_verbatim() {
    // RULE-027
    assert_eq!(
        sanitize_actor(Some(b"CN=alice,O=Example Corp")),
        "CN=alice,O=Example Corp"
    );
    assert_eq!(sanitize_actor(Some(b" ~")), " ~");
}

#[test]
fn actor_is_cut_to_127_bytes() {
    // RULE-027: snprintf into char[128]
    assert_eq!(sanitize_actor(Some(&[b'a'; 127])), "a".repeat(127));
    assert_eq!(sanitize_actor(Some(&[b'a'; 128])), "a".repeat(127));
    assert_eq!(sanitize_actor(Some(&[b'a'; 200])), "a".repeat(127));
}

#[test]
fn actor_unsafe_byte_past_the_cut_is_dropped_and_the_actor_stays_valid() {
    // RULE-027: cut first, then the safety check
    let mut s = vec![b'b'; 130];
    s[128] = 0xff;
    assert_eq!(sanitize_actor(Some(&s)), "b".repeat(127));
    let mut s = vec![b'd'; 130];
    s[127] = b'"'; // the first byte that is cut off
    assert_eq!(sanitize_actor(Some(&s)), "d".repeat(127));
}

#[test]
fn actor_unsafe_byte_inside_the_cut_gives_invalid() {
    // RULE-027
    let mut s = vec![b'c'; 130];
    s[126] = 0xff;
    assert_eq!(sanitize_actor(Some(&s)), "INVALID");
}

#[test]
fn actor_with_quote_backslash_newline_control_del_or_high_byte_is_invalid() {
    // RULE-027
    for bad in [
        &b"CN=\"x\""[..],
        b"CN=a\\b",
        b"CN=a\nb",
        b"CN=\x1f",
        b"CN=\x7f",
        b"CN=a\xffbc",
    ] {
        assert_eq!(sanitize_actor(Some(bad)), "INVALID", "{bad:?}");
    }
}

// ---- params ----------------------------------------------------------------------------------

fn params(pairs: &[(&[u8], &[u8])]) -> String {
    render_params(pairs)
}

#[test]
fn params_empty_list_is_braces() {
    // RULE-027
    assert_eq!(params(&[]), "{}");
}

#[test]
fn params_pairs_are_comma_separated_without_spaces() {
    // RULE-027
    assert_eq!(params(&[(b"alg", b"mldsa65")]), r#"{"alg":"mldsa65"}"#);
    assert_eq!(
        params(&[(b"mech", b"0x1081"), (b"len", b"32"), (b"q", b"\"")]),
        r#"{"mech":"0x1081","len":"32","q":"INVALID"}"#
    );
}

#[test]
fn params_empty_value_and_empty_key_are_safe() {
    // RULE-027
    assert_eq!(params(&[(b"k", b"")]), r#"{"k":""}"#);
    assert_eq!(params(&[(b"", b"v")]), r#"{"":"v"}"#);
    assert_eq!(params(&[(b"sp ace", b" ~ ")]), r#"{"sp ace":" ~ "}"#);
}

#[test]
fn params_unsafe_value_becomes_invalid() {
    // RULE-027
    for (k, v) in [
        ("q", &b"a\"b"[..]),
        ("bs", b"a\\b"),
        ("nl", b"a\nb"),
        ("cr", b"a\rb"),
        ("c1", b"\x01"),
        ("del", b"\x7f"),
        ("hi", b"\x80"),
        ("ff", b"caf\xc3\xa9"),
    ] {
        assert_eq!(
            params(&[(k.as_bytes(), v)]),
            format!(r#"{{"{k}":"INVALID"}}"#),
            "{v:?}"
        );
    }
}

#[test]
fn params_unsafe_key_becomes_invalid_div006() {
    // DIV-006 (fix): C writes the unsafe key raw (src/fhsm_audit.c:623-627); Rust replaces it too
    for k in [
        &b"a\"b"[..],
        b"a\\b",
        b"k\x7f",
        b"k\x01",
        b"k\t",
        b"a\nb",
        b"k\xc3\xa9",
    ] {
        assert_eq!(
            params(&[(k, b"x")]),
            r#"{"INVALID":"INVALID"}"#,
            "key {k:?}"
        );
    }
    assert_eq!(
        params(&[(b"ok", b"1"), (b"a\nb", b"2")]),
        r#"{"ok":"1","INVALID":"INVALID"}"#
    );
}

#[test]
fn params_filling_1022_bytes_gets_its_closing_brace() {
    // RULE-027: 7 + 1015 = 1022, then "}" makes 1023
    let v = vec![b'v'; 1015];
    let p = params(&[(b"k", &v)]);
    assert_eq!(p.len(), 1023);
    assert_eq!(p, format!(r#"{{"k":"{}"}}"#, "v".repeat(1015)));
}

#[test]
fn params_filling_exactly_1023_bytes_drops_the_closing_brace() {
    // RULE-027 / DIV-004 preserved: src/fhsm_audit.c:639 has no room for "}"
    let v = vec![b'v'; 1016];
    let p = params(&[(b"k", &v)]);
    assert_eq!(p.len(), 1023);
    assert_eq!(p, format!(r#"{{"k":"{}""#, "v".repeat(1016)));
}

#[test]
fn params_overflow_collapses_to_empty_object() {
    // DIV-004 (preserve): one byte too many and everything is lost, no marker
    assert_eq!(params(&[(b"k", &[b'v'; 1017])]), "{}");
    assert_eq!(params(&[(b"k", &[b'v'; 1100])]), "{}");
}

#[test]
fn params_overflow_on_a_later_pair_drops_the_earlier_pairs_too() {
    // DIV-004 (preserve)
    assert_eq!(params(&[(b"a", &[b'x'; 600]), (b"b", &[b'y'; 600])]), "{}");
}

#[test]
fn params_unsafe_long_value_is_replaced_before_the_length_check() {
    // RULE-027
    let mut v = vec![b'u'; 1100];
    v[3] = b'"';
    assert_eq!(params(&[(b"k", &v)]), r#"{"k":"INVALID"}"#);
}

#[test]
fn params_unsafe_long_key_is_replaced_before_the_length_check_div006() {
    // DIV-006 (fix): C kept the key and collapsed to {} (DIV-004); Rust replaces it first
    let mut k = vec![b'K'; 1100];
    k[3] = b'"';
    assert_eq!(params(&[(&k, b"v")]), r#"{"INVALID":"INVALID"}"#);
}

#[test]
fn params_ten_pairs() {
    // RULE-027
    let kv: Vec<(String, String)> = (0..10)
        .map(|i| (format!("k{i}"), format!("v{i}")))
        .collect();
    let pairs: Vec<(&[u8], &[u8])> = kv
        .iter()
        .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
        .collect();
    assert_eq!(
        params(&pairs),
        r#"{"k0":"v0","k1":"v1","k2":"v2","k3":"v3","k4":"v4","k5":"v5","k6":"v6","k7":"v7","k8":"v8","k9":"v9"}"#
    );
}

// ---- body and line ---------------------------------------------------------------------------

const ZERO: [u8; 32] = [0; 32];

fn fields<'a>(params: &'a str, prev: &'a [u8; 32]) -> Fields<'a> {
    Fields {
        seq: 1,
        ts_ns: 0,
        event: 1,
        slot: -1,
        session: -1,
        role: Role::None,
        actor: "",
        rv: 0,
        params,
        prev_hmac: prev,
    }
}

const PREFIX: &str = r#"{"seq":1,"ts":0,"event":"module_init","slot":-1,"session":-1,"role":"NONE","actor":"","result":"OK","rv":0,"params":"#;

fn suffix(prev: &[u8; 32]) -> String {
    format!(r#","prev_hmac":"{}","#, common::hex(prev))
}

#[test]
fn body_layout_is_the_c_format_string() {
    // RULE-007: src/fhsm_audit.c:643-653
    assert_eq!(
        render_body(&fields("{}", &ZERO)).unwrap(),
        format!("{PREFIX}{{}}{}", suffix(&ZERO))
    );
}

#[test]
fn body_writes_rv_as_unsigned_decimal_and_result_fail() {
    // RULE-007
    let f = Fields {
        rv: 0x8000_0001,
        event: 3,
        ..fields("{}", &ZERO)
    };
    let b = render_body(&f).unwrap();
    assert!(b.contains(r#""event":"kat_report""#), "{b}");
    assert!(b.contains(r#""result":"FAIL","rv":2147483649,"#), "{b}");
    let f = Fields {
        rv: u32::MAX,
        ..fields("{}", &ZERO)
    };
    assert!(
        render_body(&f)
            .unwrap()
            .contains(r#""result":"FAIL","rv":4294967295,"#)
    );
}

#[test]
fn body_writes_negative_and_extreme_slot_and_session() {
    // RULE-007
    let f = Fields {
        slot: i32::MIN,
        session: i32::MIN,
        ..fields("{}", &ZERO)
    };
    assert!(
        render_body(&f)
            .unwrap()
            .contains(r#""slot":-2147483648,"session":-2147483648,"#)
    );
    let f = Fields {
        slot: -5,
        session: -7,
        ..fields("{}", &ZERO)
    };
    assert!(
        render_body(&f)
            .unwrap()
            .contains(r#""slot":-5,"session":-7,"#)
    );
}

#[test]
fn body_writes_prev_hmac_as_lowercase_hex() {
    // RULE-007
    let prev = [0xAB; 32];
    let b = render_body(&fields("{}", &prev)).unwrap();
    assert!(
        b.ends_with(&format!(r#""prev_hmac":"{}","#, "ab".repeat(32))),
        "{b}"
    );
}

#[test]
fn body_of_2047_bytes_fits() {
    // RULE-007: line_len >= sizeof(line) is the C limit
    let fill = 2047 - PREFIX.len() - suffix(&ZERO).len();
    let p = "p".repeat(fill);
    let b = render_body(&fields(&p, &ZERO)).unwrap();
    assert_eq!(b.len(), 2047);
    assert_eq!(b, format!("{PREFIX}{p}{}", suffix(&ZERO)));
}

#[test]
fn body_of_2048_bytes_is_too_long() {
    // RULE-007 / RULE-096 "audit line truncated"
    let fill = 2048 - PREFIX.len() - suffix(&ZERO).len();
    assert_eq!(render_body(&fields(&"p".repeat(fill), &ZERO)), Err(TooLong));
}

#[test]
fn finish_line_appends_hmac_brace_and_newline() {
    // RULE-007
    let mac = [0x0f; 32];
    assert_eq!(
        finish_line("BODY,", &mac).unwrap(),
        format!("BODY,\"hmac\":\"{}\"}}\n", "0f".repeat(32))
    );
}

#[test]
fn finish_line_of_2047_bytes_fits() {
    // RULE-007: body + 75 suffix bytes (`"hmac":"` 8, hex 64, `"}` 2, "\n" 1) must stay below
    // 2048 (src/fhsm_audit.c:678)
    let line = finish_line(&"x".repeat(1972), &ZERO).unwrap();
    assert_eq!(line.len(), 2047);
}

#[test]
fn finish_line_of_2048_bytes_is_too_long() {
    // RULE-007 / RULE-096 "audit suffix truncated"
    assert_eq!(finish_line(&"x".repeat(1973), &ZERO), Err(TooLong));
}
