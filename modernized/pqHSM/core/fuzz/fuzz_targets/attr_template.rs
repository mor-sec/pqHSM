//! `template::strip_octet_string` (C's `fhsm_strip_octet_string_inline`) with
//! `fuzz/fuzz_attr_template.c`'s property, that what it accepts is a suffix of the input, and the
//! one that property misses: the length the header declares is the payload's. That harness's
//! `fhsm_find_attr` half is private here, and create_attrs reaches it through `parse`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pqhsm_core::template::strip_octet_string;

fn check(v: &[u8]) {
    let Some(out) = strip_octet_string(v) else {
        return;
    };
    assert!(v.ends_with(out) && v[0] == 0x04);
    let declared = match v.len() - out.len() {
        2 => usize::from(v[1]),
        3 => usize::from(v[2]),
        4 => usize::from(u16::from_be_bytes([v[2], v[3]])),
        h => panic!("a {h}-byte header"),
    };
    assert_eq!(declared, out.len());
}

fuzz_target!(|data: &[u8]| {
    let Some((_, v)) = data.split_first() else {
        return;
    };
    check(v);
    if let Some((_, short)) = v.split_last() {
        check(short);
    }
});
