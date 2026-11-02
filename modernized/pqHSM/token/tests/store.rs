//! The object store's pure functions (RULE-003, 044, 088) against the legacy C:
//! - the readers: every crafted plaintext in `golden/store/in/` gets C's verdict, taken from
//!   the scenario that sealed it into a token and logged in (`parse_*`, `handle_wraps_*` ...);
//! - the v4 writer: every blob plaintext C wrote (`golden/store/pt/`) parses and re-serialises
//!   byte for byte, and its public section is C's (`golden/store/pub/`);
//! - the frame and the public view, on C-written token files.
//!
//!   cargo test -p pqhsm-token --test store

mod store_common;

use std::collections::BTreeMap;
use std::fs;

use pqhsm_token::Rv;
use pqhsm_token::store::{
    self, BLOB_MAX, MAX_OBJECTS, PUB_MAGIC, PolicyAttr, PublicView, V1_REC, V2_FIXED, V3_FIXED,
    V4_FIXED, VALUE_MAX, is_public, parse, public_section, read_public_view, serialize, split_blob,
};
use store_common::*;

/// C's verdict on each `in/NAME.bin` it sealed into a token: did the login load it?
fn c_verdicts() -> BTreeMap<String, bool> {
    let all = steps();
    let mut v = BTreeMap::new();
    for (i, s) in all.iter().enumerate() {
        let (op, kv) = args(&s.line);
        if op != "reblob" || kv.contains_key("tag") {
            continue;
        }
        // the first find/dump after the login
        let after = all[i + 1..]
            .iter()
            .take_while(|x| x.scenario == s.scenario)
            .find(|x| x.line.starts_with("find") || x.line.starts_with("dump"))
            .unwrap();
        v.insert(kv["pt"].clone(), after.out.starts_with("\trv=0x0"));
    }
    v
}

#[test]
fn constants_are_c_s() {
    assert_eq!(BLOB_MAX, 2_148_421_644, "FHSM_OBJ_BLOB_MAX");
    assert!(
        BLOB_MAX > i32::MAX as u64,
        "RULE-003(1): above INT_MAX, as in C"
    );
    assert_eq!((MAX_OBJECTS, VALUE_MAX), (1024, 2 * 1024 * 1024));
    assert_eq!(
        (V1_REC, V2_FIXED, V3_FIXED, V4_FIXED),
        (5620, 120, 204, 912)
    );
    assert_eq!(PUB_MAGIC, 0xF5B5_B001);
}

#[test]
fn policy_attr_has_c_s_layout() {
    let row = String::from_utf8(read_golden("ffi.tsv")).unwrap();
    let row = row
        .lines()
        .find(|l| l.starts_with("policy_attr_layout"))
        .unwrap()
        .to_owned();
    let got = format!(
        "size={} align={} kind={} len={} value={}",
        size_of::<PolicyAttr>(),
        align_of::<PolicyAttr>(),
        std::mem::offset_of!(PolicyAttr, kind),
        std::mem::offset_of!(PolicyAttr, len),
        std::mem::offset_of!(PolicyAttr, value)
    );
    assert!(row.ends_with(&got), "C: {row}\nRust: {got}");
}

#[test]
fn every_crafted_plaintext_gets_c_s_verdict() {
    let v = c_verdicts();
    assert!(v.len() >= 30, "{} verdicts", v.len());
    for (name, ok) in &v {
        let pt = read_golden(&format!("in/{name}.bin"));
        let got = parse(&pt);
        assert_eq!(
            got.is_ok(),
            *ok,
            "{name}: C {}",
            if *ok { "loaded it" } else { "refused it" }
        );
        if let Err(e) = got {
            assert_eq!(e, Rv::FUNCTION_FAILED, "{name}");
        }
    }
}

#[test]
fn the_public_section_inputs_are_well_formed_v4_blobs() {
    // Used only as public sections (public_view_* scenarios); C never sealed them as a store.
    for name in [
        "v4_secret_key",
        "v4_sensitive_public_key",
        "v4_planted_trusted",
        "v4_empty",
        "v3_ok",
        "v4_wrap_kind_4",
    ] {
        let r = parse(&read_golden(&format!("in/{name}.bin")));
        assert_eq!(r.is_ok(), name != "v4_wrap_kind_4", "{name}");
    }
}

#[test]
fn v1_to_v3_load_with_c_s_defaults_and_v4_keeps_policy_up_to_len_div026() {
    let s = parse(&read_golden("in/v4_ok.bin")).unwrap();
    assert_eq!(s.next_handle, 9);
    let o = &s.objects[0];
    assert_eq!(
        (o.handle, o.class, o.key_type, o.flags, o.usage, o.flags3),
        (1, 4, 0x1f, 0x01, 0x85, 0x01)
    );
    assert_eq!(o.allowed_count, 2);
    assert_eq!(o.allowed[..2], [0x1081, 0x1082]);
    assert_eq!(
        o.allowed[2], 0xEE02,
        "slots past the count are kept as read"
    );
    assert_eq!((o.wrap_count, o.unwrap_count, o.derive_count), (1, 0, 2));
    // DIV-026: C kept the 13 bytes after `len` that the file carries; Rust keeps only `len`.
    let raw = read_golden("in/v4_ok.bin");
    assert!(
        raw.windows(18).any(|w| w == b"labelJUNK-past-len"),
        "C's input carries bytes past len"
    );
    assert_eq!(o.wrap[0].len, 5);
    assert_eq!(&o.wrap[0].value[..5], b"label");
    assert_eq!(
        o.wrap[0].value[5..],
        [0u8; 43],
        "DIV-026: bytes past len are not stored"
    );
    let v1 = parse(&read_golden("in/v1_ok.bin")).unwrap();
    assert_eq!((v1.next_handle, v1.objects.len()), (3, 2));
    assert_eq!(
        (
            v1.objects[0].usage,
            v1.objects[0].flags2,
            v1.objects[0].allowed_count
        ),
        (0, 0, 0)
    );
    assert_eq!(v1.objects[0].value.len(), 32);
}

/// Every plaintext the C writer produced (the `pt=ok` snaps) re-serialises byte for byte.
#[test]
fn the_v4_writer_reproduces_every_c_blob_byte_for_byte() {
    let mut n = 0;
    for e in fs::read_dir(store_golden("pt")).unwrap() {
        let p = e.unwrap().path();
        let pt = fs::read(&p).unwrap();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let s = parse(&pt).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(serialize(&s, false), pt, "{name}");
        let public = fs::read(store_golden(&format!("pub/{name}")));
        if let Ok(public) = public {
            assert_eq!(public_section(&s), public, "{name}: public section");
        }
        n += 1;
    }
    assert!(n >= 15, "{n} blobs");
}

#[test]
fn public_objects_are_unsensitive_public_keys_and_certificates() {
    let s = parse(&read_golden("pt/multi_base.9.bin")).unwrap();
    let public: Vec<u32> = s
        .objects
        .iter()
        .filter(|o| is_public(o))
        .map(|o| o.handle)
        .collect();
    assert_eq!(public, [3, 4]);
    let crud = parse(&read_golden("pt/objects_crud.50.bin")).unwrap();
    let h5 = crud.objects.iter().find(|o| o.handle == 5).unwrap();
    assert_eq!((h5.class, h5.flags & store::OBJF_SENSITIVE), (2, 1));
    assert!(!is_public(h5), "a sensitive public key is not public");
}

#[test]
fn split_blob_reads_the_frame_as_c_does() {
    let f = read_golden("tok/multi_base.tok");
    let b = split_blob(&f).unwrap().unwrap();
    assert_eq!(b.ct.len(), 4803);
    assert_eq!(&b.nonce[..], &f[321..333]);
    assert_eq!(&b.tag[..], &f[333 + 4803..333 + 4803 + 16]);
    assert_eq!(
        split_blob(&f[..317]).unwrap(),
        None,
        "a bare header has no store"
    );
    // RULE-003: header + < 16 bytes, ct_len 0, ct_len > BLOB_MAX, or a frame past the end
    let mut bad = vec![[&f[..317], &[0u8; 10][..]].concat()];
    for ct in [0u32, 2_148_421_645, 2_148_421_644] {
        let mut g = f.clone();
        g[317..321].copy_from_slice(&ct.to_le_bytes());
        bad.push(g);
    }
    bad.push(f[..343].to_vec());
    for (i, g) in bad.iter().enumerate() {
        assert_eq!(split_blob(g).err(), Some(Rv::FUNCTION_FAILED), "case {i}");
    }
}

fn with_pub(f: &[u8], section: Option<&[u8]>) -> Vec<u8> {
    let ct = u32::from_le_bytes(f[317..321].try_into().unwrap()) as usize;
    let mut g = f[..317 + 16 + ct + 16].to_vec();
    if let Some(s) = section {
        g.extend(s);
    }
    g
}

fn section(name: &str) -> Vec<u8> {
    let b = read_golden(&format!("in/{name}.bin"));
    [
        &PUB_MAGIC.to_le_bytes()[..],
        &(b.len() as u32).to_le_bytes(),
        &b,
    ]
    .concat()
}

fn view_handles(v: &PublicView) -> Option<Vec<u32>> {
    match v {
        PublicView::Objects(s) => Some(s.objects.iter().map(|o| o.handle).collect()),
        PublicView::Empty => Some(Vec::new()),
        PublicView::Unknown => None,
    }
}

/// RULE-044: the C verdicts are the `find` before login in each public_view_* scenario.
#[test]
fn the_public_view_is_c_s_on_every_section_variant() {
    let f = read_golden("tok/multi_base.tok");
    assert_eq!(read_public_view(&f[..317]), PublicView::Empty);
    let mut bad_magic = f.clone();
    let end = with_pub(&f, None).len();
    bad_magic[end..end + 4].copy_from_slice(&0xF5B5_B002u32.to_le_bytes());
    type Case<'a> = (&'a str, Vec<u8>, Option<Vec<u32>>);
    let cases: Vec<Case> = vec![
        ("public_view_before_login", f.clone(), Some(vec![3, 4])),
        ("public_view_absent", with_pub(&f, None), None),
        ("public_view_bad_magic", bad_magic, None),
        (
            "public_view_length_short_of_file",
            [&f[..], &[0u8]].concat(),
            None,
        ),
        (
            "public_view_secret_object",
            with_pub(&f, Some(&section("v4_secret_key"))),
            None,
        ),
        (
            "public_view_sensitive_public_key",
            with_pub(&f, Some(&section("v4_sensitive_public_key"))),
            None,
        ),
        (
            "public_view_v3_section",
            with_pub(&f, Some(&section("v3_ok"))),
            None,
        ),
        (
            "public_view_unparsable",
            with_pub(&f, Some(&section("v4_wrap_kind_4"))),
            None,
        ),
        (
            "public_view_empty_section",
            with_pub(&f, Some(&section("v4_empty"))),
            Some(vec![]),
        ),
        (
            "public_view_planted_trusted_key_rule044",
            with_pub(&f, Some(&section("v4_planted_trusted"))),
            Some(vec![77]),
        ),
    ];
    for (scen, file, want) in cases {
        let c = steps_of(scen)
            .into_iter()
            .find(|s| s.line == "find")
            .unwrap()
            .out;
        let c_handles = c.strip_prefix("\trv=0x0\tn=").map(|r| {
            let hs = r.split_once("\ths=").unwrap().1;
            hs.split(',')
                .filter(|x| !x.is_empty())
                .map(|x| x.parse().unwrap())
                .collect::<Vec<u32>>()
        });
        assert_eq!(c_handles, want, "{scen}: C's find was {c:?}");
        assert_eq!(view_handles(&read_public_view(&file)), want, "{scen}");
    }
}
