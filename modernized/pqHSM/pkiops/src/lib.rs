//! pqHSM PKI operations (Phase 5 of `analysis/pqHSM/MODERNIZATION_BRIEF.md`).
//!
//! Replaces `tools/pkiops.c` and `tools/p11_util.h`, slice by slice (`PHASE5_PLAN.md` §2).
//! Slice 0: the module loader, `pkiops_load`, `pkiops_open`, `pkiops_close`,
//! `pkiops_unload`, the call log and the error a function returns. Slice 1: what `fhsm-csr`
//! calls (sessions, the algorithms, key pairs, requests and roots). Slice 2: `fhsm-token`'s
//! token state and init. Slice 3: `fhsm-crypt`'s objects, secret keys and CMS envelopes
//! (`objects`, `cms_env`, `envelope`). Slice 4: `fhsm-sign`'s digests, streamed signatures
//! and CMS SignedData (`sign`). Slice 5: `fhsm-ca`'s issuing, CRL and OCSP (`ca`) and the slot
//! list, the last of `pkiops.h`: no C of `tools/pkiops.c` or `tools/cms_env.c` is linked.
//! The raw pointers are in `ffi`; `pqhsm-cli` calls the safe functions.
//!
//! Every message is C's, byte for byte: `tests/pki_tools_characterize.sh` is the golden.

use std::ffi::{c_long, c_ulong};
use std::io::Write;

pub mod ca;
pub mod cms_env;
pub mod envelope;
pub mod ffi;
pub mod keys;
pub mod objects;
pub mod ops;
pub mod sign;

pub use ffi::{close, load, open, unload};

/// `strtol(t, &end, 10)`: the value, clamped as strtol clamps it, how many bytes it read (0
/// when no digits), and whether it overflowed (strtol's ERANGE).
pub fn strtol(t: &[u8]) -> (c_long, usize, bool) {
    let mut i = t
        .iter()
        .take_while(|&&c| c == b' ' || (b'\t'..=b'\r').contains(&c))
        .count();
    let neg = t.get(i) == Some(&b'-');
    if matches!(t.get(i), Some(b'-' | b'+')) {
        i += 1;
    }
    let digits = t[i.min(t.len())..]
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .count();
    if digits == 0 {
        return (0, 0, false);
    }
    let mut v: i128 = 0;
    for &c in &t[i..i + digits] {
        // Capped past both ends, so the clamp below still sees an overflow either way.
        v = (v * 10 + i128::from(c - b'0')).min(i128::from(c_long::MAX) + 2);
    }
    let v = if neg { -v } else { v };
    let clamped = v.clamp(c_long::MIN.into(), c_long::MAX.into());
    (clamped as c_long, i + digits, clamped != v)
}

/// `pkiops_parse_slot`: a whole decimal, not negative.
pub fn parse_slot(t: &[u8]) -> Result<c_long, Error> {
    let (v, end, overflow) = strtol(t);
    // C: errno, an empty text, or `*end` not the end (nothing read leaves end at the start).
    if overflow || end == 0 || end != t.len() || v < 0 {
        return Err(Error::new(
            1,
            [b"--slot ", t, b" is not a slot identifier.\n"].concat(),
        ));
    }
    Ok(v)
}

/// `strerror(errno)` for an error from the OS: the text C's messages carry.
pub fn strerror(e: &std::io::Error) -> String {
    let n = e.raw_os_error().unwrap_or(0);
    // SAFETY: strerror returns a NUL-terminated string valid until the next call on this
    // thread; it is copied at once.
    unsafe { std::ffi::CStr::from_ptr(libc::strerror(n)) }
        .to_string_lossy()
        .into_owned()
}

/// `CK_SLOT_ID`.
pub type SlotId = c_ulong;

/// A `struct p11_err` (`tools/p11_err.h`): `code` is the exit status a tool would use (2 for
/// the module or a PKCS#11 call, 3 for a missing or ambiguous slot or key), `msg` the whole
/// message without the tool's name, final newline included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: i32,
    pub msg: Vec<u8>,
}

impl Error {
    /// C's `msg[4096]`: what does not fit, NUL included, is cut (vsnprintf, `p11_append`).
    pub const CAP: usize = 4096;

    pub fn new(code: i32, msg: impl Into<Vec<u8>>) -> Self {
        Error {
            code,
            msg: msg.into(),
        }
    }

    /// The message as C's buffer holds it.
    pub fn c_msg(&self) -> &[u8] {
        &self.msg[..self.msg.len().min(Self::CAP - 1)]
    }
}

/// Whether the loader requires a function: on both load paths, only when the module has
/// `C_GetFunctionList` (the other path does not look for it), or never.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    Both,
    ListOnly,
    Optional,
}

/// The module functions the tools call, in the field order of `tools/p11_util.h`'s `p11`
/// table, with their PKCS#11 v2.40 §C.6
/// slot numbers. A test compares both with the header.
pub const FUNCTIONS: [(&str, usize, Need); 31] = [
    ("Initialize", 0, Need::Both),
    ("Finalize", 1, Need::Both),
    ("OpenSession", 12, Need::Both),
    ("CloseSession", 13, Need::Both),
    ("Login", 18, Need::Both),
    ("GenerateKeyPair", 59, Need::Both),
    ("FindObjectsInit", 26, Need::Both),
    ("FindObjects", 27, Need::Both),
    ("FindObjectsFinal", 28, Need::Both),
    ("GetAttributeValue", 24, Need::Both),
    ("DigestInit", 37, Need::Both),
    ("SignInit", 42, Need::Both),
    ("Sign", 43, Need::Both),
    ("SignUpdate", 44, Need::Both),
    ("SignFinal", 45, Need::Both),
    ("VerifyInit", 48, Need::Both),
    ("VerifyUpdate", 50, Need::Both),
    ("VerifyFinal", 51, Need::Both),
    ("InitToken", 9, Need::Both),
    ("InitPIN", 10, Need::Both),
    ("GetTokenInfo", 6, Need::Both),
    ("GenerateRandom", 64, Need::Both),
    ("GetSlotList", 4, Need::Both),
    ("GetMechanismList", 7, Need::ListOnly),
    ("GetMechanismInfo", 8, Need::ListOnly),
    ("DestroyObject", 22, Need::Optional),
    ("GenerateKey", 58, Need::Optional),
    ("EncryptInit", 29, Need::Optional),
    ("Encrypt", 30, Need::Optional),
    ("DecryptInit", 33, Need::Optional),
    ("Decrypt", 34, Need::Optional),
];

/// Functions the tools' table (`tools/p11_util.h`) does not name, which `pqhsm-service` calls:
/// loaded after [`FUNCTIONS`], each optional.
pub const EXTRA: [(&str, usize, Need); 1] = [("Verify", 49, Need::Optional)];

/// Which slot an operation wants when the caller names none (`enum pkiops_slot_intent`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Intent {
    /// Exactly one initialised token, or refuse.
    WithToken,
    /// The lowest empty slot.
    ForInit,
    /// The one token, or the first slot if none.
    Any,
}

/// What slot resolution asks of the module.
pub trait Slots {
    /// `C_GetSlotList`'s two calls, tokens only or every slot.
    fn list(&mut self, token_present: bool) -> Result<Vec<SlotId>, Error>;
    /// A token's label as a refusal lists it ([`label_of`]).
    fn label(&mut self, id: SlotId) -> Vec<u8>;
}

/// The label `p11_label_of` prints from `CK_TOKEN_INFO`'s first 32 bytes, or `None` if
/// `C_GetTokenInfo` failed.
pub fn label_of(info: Option<&[u8]>) -> Vec<u8> {
    let Some(info) = info else {
        return b"(unreadable)".to_vec();
    };
    let mut l = &info[..32.min(info.len())];
    while let [rest @ .., b' ' | 0] = l {
        l = rest;
    }
    // C prints it with %s, so a NUL inside ends it.
    let l = l.split(|&b| b == 0).next().unwrap_or_default();
    if l.is_empty() {
        b"(no label)".to_vec()
    } else {
        l.to_vec()
    }
}

fn append_slots(e: &mut Error, m: &mut impl Slots, ids: &[SlotId]) {
    for &id in ids {
        let _ = write!(e.msg, "    --slot {id}   ");
        e.msg.extend(m.label(id));
        e.msg.push(b'\n');
    }
}

fn several(m: &mut impl Slots, tok: &[SlotId]) -> Error {
    let mut e = Error::new(
        3,
        format!("{} slots hold a token; name one with --slot:\n", tok.len()),
    );
    append_slots(&mut e, m, tok);
    e
}

/// `p11_resolve_slot_e`: `want` is `--slot`, or negative when the operator gave none.
pub fn resolve(m: &mut impl Slots, want: c_long, intent: Intent) -> Result<SlotId, Error> {
    let all = m.list(false)?;
    let tok = m.list(true)?;
    if all.is_empty() {
        return Err(Error::new(3, "the module reports no slot at all.\n"));
    }
    if want >= 0 {
        let w = want as SlotId;
        if !all.contains(&w) {
            let mut e = Error::new(3, format!("no slot {want} on this module. Available:\n"));
            append_slots(&mut e, m, &all);
            return Err(e);
        }
        if intent == Intent::WithToken && !tok.contains(&w) {
            let mut e = Error::new(
                3,
                format!(
                    "slot {want} holds no initialised token.\n  `fhsm-token init --slot {want}` creates one.\n"
                ),
            );
            if !tok.is_empty() {
                e.msg.extend(b"  Slots that do hold one:\n");
                append_slots(&mut e, m, &tok);
            }
            return Err(e);
        }
        return Ok(w);
    }
    match intent {
        Intent::WithToken => match tok[..] {
            [] => Err(Error::new(
                3,
                "no slot on this module holds an initialised token.\n  `fhsm-token init` creates one.\n",
            )),
            [one] => Ok(one),
            _ => Err(several(m, &tok)),
        },
        Intent::ForInit => match all.iter().find(|s| !tok.contains(s)) {
            Some(&s) => Ok(s),
            None => {
                let mut e = Error::new(
                    3,
                    "every slot already holds a token, so there is no\n  empty one to initialise. Name the slot to re-initialise\n  with --slot, and note that doing so DESTROYS its keys:\n",
                );
                append_slots(&mut e, m, &all);
                Err(e)
            }
        },
        Intent::Any => match tok[..] {
            [one] => Ok(one),
            [] => Ok(all[0]),
            _ => Err(several(m, &tok)),
        },
    }
}

/// The call log's summaries (`tools/pkiops.c`): handles, slots, mechanisms, attribute types
/// and byte counts, never a PIN, its length or a value.
pub mod calllog {
    use std::borrow::Cow;
    use std::ffi::c_ulong;

    /// `struct pkiops_call`'s `args[160]`.
    pub const ARGS_CAP: usize = 160;

    pub fn mech_name(m: c_ulong) -> Cow<'static, str> {
        Cow::Borrowed(match m {
            0x8000_4202 => "CKM_COMPOSITE_MLDSA65_ED25519",
            0x0000 => "CKM_RSA_PKCS_KEY_PAIR_GEN",
            0x001C => "CKM_ML_DSA_KEY_PAIR_GEN",
            0x001D => "CKM_ML_DSA",
            0x0040 => "CKM_SHA256_RSA_PKCS",
            0x0043 => "CKM_SHA256_RSA_PKCS_PSS",
            0x1040 => "CKM_EC_KEY_PAIR_GEN",
            0x1044 => "CKM_ECDSA_SHA256",
            0x1045 => "CKM_ECDSA_SHA384",
            0x1055 => "CKM_EC_EDWARDS_KEY_PAIR_GEN",
            0x1057 => "CKM_EDDSA",
            0x0350 => "CKM_GENERIC_SECRET_KEY_GEN",
            0x1080 => "CKM_AES_KEY_GEN",
            0x2109 => "CKM_AES_KEY_WRAP",
            _ => return Cow::Owned(format!("mechanism 0x{m:x}")),
        })
    }

    pub fn user_name(u: c_ulong) -> &'static str {
        match u {
            0 => "CKU_SO",
            1 => "CKU_USER",
            2 => "CKU_CONTEXT_SPECIFIC",
            _ => "user type ?",
        }
    }

    /// `attr_types`: the types, comma-separated, cut to a `cap`-byte buffer.
    pub fn attr_types(types: impl IntoIterator<Item = c_ulong>, cap: usize) -> String {
        let mut out = String::new();
        for (i, t) in types.into_iter().enumerate() {
            if out.len() >= cap {
                break;
            }
            if i > 0 {
                out.push_str(", ");
            }
            match attr_name(t) {
                Some(n) => out.push_str(n),
                None => out.push_str(&format!("0x{t:x}")),
            }
        }
        out.truncate(out.len().min(cap - 1)); // ASCII only, so no char is split
        out
    }

    fn attr_name(t: c_ulong) -> Option<&'static str> {
        Some(match t {
            0x000 => "CKA_CLASS",
            0x001 => "CKA_TOKEN",
            0x003 => "CKA_LABEL",
            0x011 => "CKA_VALUE",
            0x100 => "CKA_KEY_TYPE",
            0x102 => "CKA_ID",
            0x002 => "CKA_PRIVATE",
            0x104 => "CKA_ENCRYPT",
            0x105 => "CKA_DECRYPT",
            0x106 => "CKA_WRAP",
            0x107 => "CKA_UNWRAP",
            0x161 => "CKA_VALUE_LEN",
            0x162 => "CKA_EXTRACTABLE",
            0x103 => "CKA_SENSITIVE",
            0x108 => "CKA_SIGN",
            0x10A => "CKA_VERIFY",
            0x120 => "CKA_MODULUS",
            0x121 => "CKA_MODULUS_BITS",
            0x122 => "CKA_PUBLIC_EXPONENT",
            0x180 => "CKA_EC_PARAMS",
            0x181 => "CKA_EC_POINT",
            0x61D => "CKA_PARAMETER_SET",
            0x4000_0600 => "CKA_ALLOWED_MECHANISMS",
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, HashMap};

    /// Every function `tools/pkiops.h` declares is exported, and nothing else under its
    /// prefix: the C callers link no C copy.
    #[test]
    fn exports_are_pkiops_h() {
        let dir = env!("CARGO_MANIFEST_DIR");
        let names = |text: &str, key: &str| -> BTreeSet<String> {
            text.lines()
                .filter_map(|l| Some(l.split_once(key)?.1))
                .filter(|r| r.contains('('))
                .map(|r| {
                    r.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                        .next()
                        .unwrap()
                })
                .map(|n| format!("pkiops_{n}"))
                .collect()
        };
        let rust: BTreeSet<String> = ["mod.rs", "capi.rs"]
            .iter()
            .flat_map(|f| {
                let t = std::fs::read_to_string(format!("{dir}/src/ffi/{f}")).expect("ffi source");
                names(&t, "extern \"C\" fn pkiops_")
            })
            .collect();
        let h =
            std::fs::read_to_string(format!("{dir}/../gui/include/pkiops.h")).expect("pkiops.h");
        // a declaration starts in column 0 and names the function just before its '('
        let decl: BTreeSet<String> = h
            .lines()
            .filter(|l| l.starts_with(|c: char| c.is_ascii_alphabetic()))
            .filter_map(|l| {
                let head = &l[..l.find('(')?];
                let name = &head[head.rfind(|c: char| !(c.is_alphanumeric() || c == '_'))? + 1..];
                name.starts_with("pkiops_").then(|| name.to_owned())
            })
            .collect();
        assert_eq!(rust, decl);
    }

    #[test]
    fn strtol_and_slots_as_c() {
        assert_eq!(strtol(b" \t\x0b+42x"), (42, 6, false));
        assert_eq!(strtol(b"-7"), (-7, 2, false));
        assert_eq!(strtol(b"abc"), (0, 0, false));
        assert_eq!(strtol(b"-"), (0, 0, false));
        assert_eq!(strtol(b"9223372036854775807"), (c_long::MAX, 19, false));
        assert_eq!(strtol(b"9223372036854775808"), (c_long::MAX, 19, true));
        assert_eq!(strtol(b"-9223372036854775808"), (c_long::MIN, 20, false));
        assert_eq!(strtol(b"-99999999999999999999999"), (c_long::MIN, 24, true));
        assert_eq!(parse_slot(b"0"), Ok(0));
        assert_eq!(parse_slot(b" +3"), Ok(3));
        assert_eq!(parse_slot(b"-0"), Ok(0));
        for bad in [&b""[..], b" ", b"1x", b"-1", b"x", b"99999999999999999999"] {
            let e = parse_slot(bad).unwrap_err();
            assert_eq!(
                e,
                Error::new(
                    1,
                    [b"--slot ", bad, b" is not a slot identifier.\n"].concat()
                )
            );
        }
    }

    /// EXTRA's slot numbers against the module's v2.40 table (`p11/src/ffi/tables.rs`): a wrong
    /// one would call another function through C_Verify's type.
    #[test]
    fn extra_slots_match_the_modules_table() {
        let t = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../p11/src/ffi/tables.rs"
        ))
        .expect("p11/src/ffi/tables.rs");
        let words: Vec<&str> = t.split_whitespace().collect();
        for (name, slot, _) in EXTRA {
            let at = words
                .iter()
                .position(|w| *w == format!("C_{name}"))
                .expect(name);
            assert_eq!(words[at - 1], slot.to_string(), "{name}");
        }
    }

    /// The copy of `tests/abi/p11_util.h`'s order and slot numbers is safe only while something
    /// compares them; `tests/abi/test_p11_loader.c` compares the header's with the module's.
    #[test]
    fn functions_match_p11_util_h() {
        let h = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/abi/p11_util.h"
        ))
        .expect("tests/abi/p11_util.h");
        let table = &h[h.find("static struct {").unwrap()..h.find("} p11;").unwrap()];
        let fields: Vec<&str> = table
            .split("(*")
            .skip(1)
            .map(|s| &s[..s.find(')').unwrap()])
            .collect();
        let slots: HashMap<&str, usize> = h
            .lines()
            .filter_map(|l| l.trim().strip_prefix("P11_SLOT_"))
            .filter_map(|l| {
                let (n, v) = l.split_once('=')?;
                Some((
                    n.trim(),
                    v.trim()
                        .trim_end_matches(',')
                        .split_whitespace()
                        .next()?
                        .parse()
                        .ok()?,
                ))
            })
            .collect();
        let ours: Vec<&str> = FUNCTIONS.iter().map(|f| f.0).collect();
        assert_eq!(fields, ours);
        for (name, slot, _) in FUNCTIONS {
            assert_eq!(slots.get(name), Some(&slot), "{name}");
        }
    }

    struct Fake {
        all: Vec<SlotId>,
        tok: Vec<SlotId>,
        fail: bool,
    }
    impl Slots for Fake {
        fn list(&mut self, present: bool) -> Result<Vec<SlotId>, Error> {
            if self.fail {
                return Err(Error::new(2, "C_GetSlotList failed (0x5)\n"));
            }
            Ok(if present {
                self.tok.clone()
            } else {
                self.all.clone()
            })
        }
        fn label(&mut self, id: SlotId) -> Vec<u8> {
            format!("tok{id}").into_bytes()
        }
    }
    fn f(all: &[SlotId], tok: &[SlotId]) -> Fake {
        Fake {
            all: all.to_vec(),
            tok: tok.to_vec(),
            fail: false,
        }
    }
    fn msg(r: Result<SlotId, Error>) -> (i32, String) {
        let e = r.unwrap_err();
        (e.code, String::from_utf8(e.msg).unwrap())
    }

    #[test]
    fn resolve_follows_p11_util_h() {
        use Intent::*;
        assert_eq!(resolve(&mut f(&[0, 1, 2], &[1]), -1, WithToken), Ok(1));
        assert_eq!(resolve(&mut f(&[0, 1, 2], &[0, 2]), -1, ForInit), Ok(1));
        assert_eq!(resolve(&mut f(&[3, 4], &[]), -1, Any), Ok(3));
        assert_eq!(resolve(&mut f(&[3, 4], &[4]), -1, Any), Ok(4));
        assert_eq!(resolve(&mut f(&[0, 1], &[]), 1, ForInit), Ok(1));
        assert_eq!(resolve(&mut f(&[0, 1], &[0]), 0, WithToken), Ok(0));
        assert_eq!(
            msg(resolve(&mut f(&[], &[]), 0, Any)),
            (3, "the module reports no slot at all.\n".into())
        );
        assert_eq!(
            msg(resolve(&mut f(&[0, 1], &[0]), 7, Any)),
            (
                3,
                "no slot 7 on this module. Available:\n    --slot 0   tok0\n    --slot 1   tok1\n"
                    .into()
            )
        );
        assert_eq!(
            msg(resolve(&mut f(&[0, 1], &[0]), 1, WithToken)),
            (3, "slot 1 holds no initialised token.\n  `fhsm-token init --slot 1` creates one.\n  Slots that do hold one:\n    --slot 0   tok0\n".into())
        );
        assert_eq!(
            msg(resolve(&mut f(&[0, 1], &[]), 1, WithToken)),
            (
                3,
                "slot 1 holds no initialised token.\n  `fhsm-token init --slot 1` creates one.\n"
                    .into()
            )
        );
        assert_eq!(
            msg(resolve(&mut f(&[0], &[]), -1, WithToken)),
            (3, "no slot on this module holds an initialised token.\n  `fhsm-token init` creates one.\n".into())
        );
        for i in [WithToken, Any] {
            assert_eq!(
                msg(resolve(&mut f(&[0, 1], &[0, 1]), -1, i)),
                (3, "2 slots hold a token; name one with --slot:\n    --slot 0   tok0\n    --slot 1   tok1\n".into())
            );
        }
        assert_eq!(
            msg(resolve(&mut f(&[0], &[0]), -1, ForInit))
                .1
                .lines()
                .count(),
            4
        );
        let mut bad = f(&[0], &[0]);
        bad.fail = true;
        assert_eq!(
            msg(resolve(&mut bad, -1, Any)),
            (2, "C_GetSlotList failed (0x5)\n".into())
        );
    }

    #[test]
    fn labels_and_summaries() {
        let mut ti = [b' '; 64];
        ti[..4].copy_from_slice(b"char");
        assert_eq!(label_of(Some(&ti)), b"char");
        assert_eq!(label_of(Some(&[0u8; 64])), b"(no label)");
        assert_eq!(label_of(Some(b"ab\0cd                           ")), b"ab");
        assert_eq!(label_of(None), b"(unreadable)");
        assert_eq!(calllog::mech_name(0x1057), "CKM_EDDSA");
        assert_eq!(calllog::mech_name(0x1234), "mechanism 0x1234");
        assert_eq!(
            calllog::attr_types([0, 3, 0x999], 120),
            "CKA_CLASS, CKA_LABEL, 0x999"
        );
        assert_eq!(calllog::attr_types([0, 3], 12), "CKA_CLASS, ");
        let e = Error::new(2, vec![b'x'; 5000]);
        assert_eq!(e.c_msg().len(), 4095);
    }
}
