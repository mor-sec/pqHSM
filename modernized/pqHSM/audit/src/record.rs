//! Line format (RULE-007) and input sanitising (RULE-027, DIV-006).
//!
//! A line is
//! `{"seq":S,"ts":T,"event":"E","slot":N,"session":N,"role":"R","actor":"A","result":"OK|FAIL","rv":U,"params":P,"prev_hmac":"H","hmac":"M"}\n`
//! with no spaces. The MAC covers every byte before `"hmac":"`.

use std::fmt::Write as _;

/// C line buffer, including its NUL: a complete line is at most `LINE_MAX - 1` bytes.
pub const LINE_MAX: usize = 2048;
/// C params buffer, including its NUL.
pub const PARAMS_MAX: usize = 1024;
/// C actor buffer, including its NUL: an actor keeps at most `ACTOR_MAX - 1` bytes.
pub const ACTOR_MAX: usize = 128;

const INVALID: &str = "INVALID";

/// Session role as written in the `role` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    None,
    So,
    User,
}

impl Role {
    /// `"NONE"`, `"SO"` or `"USER"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::None => "NONE",
            Role::So => "SO",
            Role::User => "USER",
        }
    }
}

/// Canonical event name for an `fhsm_audit_event_t` code (`include/fhsm_audit.h:71-133`),
/// or `"unknown"` for any code not in that list.
pub fn event_name(code: u32) -> &'static str {
    match code {
        1 => "module_init",
        2 => "module_finalize",
        3 => "kat_report",
        4 => "integrity_ok",
        5 => "integrity_fail",
        6 => "state_transition",
        10 => "token_init",
        11 => "token_reinit",
        12 => "login_ok",
        13 => "login_fail",
        14 => "login_locked",
        15 => "login_throttled",
        16 => "logout",
        17 => "set_pin",
        18 => "dek_rotation",
        30 => "object_create",
        31 => "object_destroy",
        32 => "object_find",
        40 => "encrypt",
        41 => "decrypt",
        42 => "sign",
        43 => "verify",
        44 => "wrap",
        45 => "unwrap",
        46 => "derive",
        47 => "generate_key",
        48 => "generate_keypair",
        49 => "digest",
        60 => "rng_reseed",
        70 => "seal_success",
        71 => "seal_failure",
        72 => "unseal_success",
        73 => "unseal_failure",
        80 => "service_start",
        81 => "service_stop",
        82 => "request_accepted",
        83 => "request_refused",
        84 => "identity_resumed",
        85 => "identity_limited",
        _ => "unknown",
    }
}

/// True when every byte is in 0x20..=0x7E and none is `"` or `\`. The empty string is safe.
pub fn is_safe_ascii(s: &[u8]) -> bool {
    s.iter()
        .all(|&c| (0x20..=0x7e).contains(&c) && c != b'"' && c != b'\\')
}

/// A safe byte string as `&str`. Safe ASCII is valid UTF-8 by construction.
fn safe_str(s: &[u8]) -> Option<&str> {
    if is_safe_ascii(s) {
        std::str::from_utf8(s).ok()
    } else {
        None
    }
}

/// The `actor` field value for a subject (`fhsm_audit_set_actor`).
/// `None` gives `""`. Otherwise the subject is cut to its first `ACTOR_MAX - 1` bytes,
/// and the cut value is `"INVALID"` if it is not safe ASCII.
pub fn sanitize_actor(subject: Option<&[u8]>) -> String {
    let Some(s) = subject else {
        return String::new();
    };
    let cut = &s[..s.len().min(ACTOR_MAX - 1)];
    safe_str(cut).unwrap_or(INVALID).to_owned()
}

/// The `params` object for key/value pairs, as `fhsm_audit_event` builds it:
/// - each pair renders as `"k":"v"`, comma-separated, inside `{` `}`;
/// - if the value is not safe ASCII, it becomes `INVALID`; if the key is not, both key and
///   value become `INVALID` (DIV-006: C kept the unsafe key raw);
/// - if a pair would not fit in the `PARAMS_MAX` buffer (with its NUL), everything collapses
///   to `{}` (no marker, DIV-004 preserves this);
/// - if the pairs fill the buffer to exactly `PARAMS_MAX - 1` bytes, the closing `}` is
///   omitted, as in C (`src/fhsm_audit.c:636-641`).
pub fn render_params(pairs: &[(&[u8], &[u8])]) -> String {
    let mut out = String::from("{");
    for (i, (k, v)) in pairs.iter().enumerate() {
        let (k, v) = match (safe_str(k), safe_str(v)) {
            (Some(k), Some(v)) => (k, v),
            (Some(k), None) => (k, INVALID),
            (None, _) => (INVALID, INVALID),
        };
        let sep = if i == 0 { "" } else { "," };
        let pair_len = sep.len() + k.len() + v.len() + 5; // 4 quotes and a colon
        if out.len() + pair_len >= PARAMS_MAX {
            return "{}".to_owned();
        }
        let _ = write!(out, "{sep}\"{k}\":\"{v}\"");
    }
    if out.len() < PARAMS_MAX - 1 {
        out.push('}');
    }
    out
}

/// Everything of a record except the trailing MAC.
#[derive(Clone, Debug)]
pub struct Fields<'a> {
    pub seq: u64,
    pub ts_ns: i64,
    pub event: u32,
    pub slot: i32,
    pub session: i32,
    pub role: Role,
    /// Already sanitised (see [`sanitize_actor`]).
    pub actor: &'a str,
    /// `result` is `"OK"` when `rv == 0`, else `"FAIL"`; `rv` is written in decimal.
    pub rv: u32,
    /// Already rendered (see [`render_params`]).
    pub params: &'a str,
    pub prev_hmac: &'a [u8; 32],
}

/// The line was too long for the C buffer.
#[derive(Debug, PartialEq, Eq)]
pub struct TooLong;

/// Lowercase hex of a MAC.
pub(crate) fn hex(b: &[u8; 32]) -> String {
    b.iter().fold(String::with_capacity(64), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

/// The MAC'd part of a line: from `{"seq":` up to and including `"prev_hmac":"<64 hex>",`.
/// Lowercase hex. `Err(TooLong)` when its length is `>= LINE_MAX` (C latches
/// "audit line truncated").
pub fn render_body(f: &Fields<'_>) -> Result<String, TooLong> {
    let body = format!(
        r#"{{"seq":{},"ts":{},"event":"{}","slot":{},"session":{},"role":"{}","actor":"{}","result":"{}","rv":{},"params":{},"prev_hmac":"{}","#,
        f.seq,
        f.ts_ns,
        event_name(f.event),
        f.slot,
        f.session,
        f.role.as_str(),
        f.actor,
        if f.rv == 0 { "OK" } else { "FAIL" },
        f.rv,
        f.params,
        hex(f.prev_hmac),
    );
    if body.len() >= LINE_MAX {
        Err(TooLong)
    } else {
        Ok(body)
    }
}

/// `body` + `"hmac":"<64 hex>"}` + `\n`. `Err(TooLong)` when the whole line is
/// `>= LINE_MAX` bytes (C latches "audit suffix truncated").
pub fn finish_line(body: &str, mac: &[u8; 32]) -> Result<String, TooLong> {
    let line = format!("{body}\"hmac\":\"{}\"}}\n", hex(mac));
    if line.len() >= LINE_MAX {
        Err(TooLong)
    } else {
        Ok(line)
    }
}
