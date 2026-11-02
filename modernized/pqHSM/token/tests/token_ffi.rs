//! The C ABI of `include/fhsm_token.h` (feature `ffi`). NULL and out-of-range arguments
//! cannot be written in the safe API, so their goldens are checked here: `golden/store/ffi.tsv`
//! is gen_store.c's `ffi()` run against the legacy C, and [`replays_c_s_abi_rows_in_order`]
//! makes the same calls in the same order (state carries from row to row). Plus the pointer
//! contracts of PHASE2_PLAN.md §7 M2.
//!
//!   cargo test -p pqhsm-token --features ffi --test token_ffi
#![cfg(feature = "ffi")]
#![allow(clippy::too_many_arguments)]

mod store_common;

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr::{null, null_mut};

use pqhsm_token::store::PolicyAttr;
use store_common::*;

#[repr(C)]
struct Tok {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    fn fhsm_token_load(path: *const c_char, out: *mut *mut Tok) -> u32;
    fn fhsm_token_init(
        path: *const c_char,
        so_pin: *const c_char,
        label: *const c_char,
        out: *mut *mut Tok,
    ) -> u32;
    fn fhsm_token_close(t: *mut Tok);
    fn fhsm_token_login(t: *mut Tok, role: c_int, pin: *const c_char, len: usize) -> u32;
    fn fhsm_token_verify_pin(t: *mut Tok, role: c_int, pin: *const c_char, len: usize) -> u32;
    fn fhsm_token_logout(t: *mut Tok);
    fn fhsm_token_current_role(t: *const Tok) -> c_int;
    fn fhsm_token_set_pin(t: *mut Tok, role: c_int, old: *const c_char, new: *const c_char) -> u32;
    fn fhsm_token_init_user_pin(t: *mut Tok, pin: *const c_char) -> u32;
    fn fhsm_token_reinit(t: *mut Tok, so_pin: *const c_char, label: *const c_char) -> u32;
    fn fhsm_token_label(t: *const Tok) -> *const c_char;
    fn fhsm_token_serial(t: *const Tok) -> *const c_char;
    fn fhsm_token_failed_count(t: *const Tok, role: c_int) -> u32;
    fn fhsm_token_user_initialized(t: *const Tok) -> c_int;
    fn fhsm_token_is_locked(t: *const Tok, role: c_int) -> c_int;
    fn fhsm_token_throttle_remaining_ms(t: *const Tok, role: c_int) -> u64;
    fn fhsm_token_object_add(
        t: *mut Tok,
        class: u32,
        kt: u32,
        label: *const c_char,
        value: *const u8,
        value_len: usize,
        id: *const u8,
        id_len: usize,
        flags: u8,
        out: *mut u32,
    ) -> u32;
    fn fhsm_token_object_get(
        t: *mut Tok,
        h: u32,
        v: *mut *const u8,
        vl: *mut usize,
        c: *mut u32,
        k: *mut u32,
    ) -> u32;
    fn fhsm_token_object_find(
        t: *mut Tok,
        class: *const u32,
        label: *const c_char,
        hs: *mut u32,
        cap: usize,
        n: *mut usize,
    ) -> u32;
    fn fhsm_token_object_get_label(
        t: *mut Tok,
        h: u32,
        out: *mut *const c_char,
        len: *mut usize,
    ) -> u32;
    fn fhsm_token_object_get_id(t: *mut Tok, h: u32, out: *mut *const u8, len: *mut usize) -> u32;
    fn fhsm_token_object_get_meta(
        t: *mut Tok,
        h: u32,
        which: c_int,
        out: *mut *const u8,
        len: *mut usize,
    ) -> u32;
    fn fhsm_token_object_set_meta(
        t: *mut Tok,
        h: u32,
        s: *const u8,
        sl: usize,
        e: *const u8,
        el: usize,
        a: *const u8,
        al: usize,
    ) -> u32;
    fn fhsm_token_object_get_flags(t: *mut Tok, h: u32, out: *mut u8) -> u32;
    fn fhsm_token_object_get_flags2(t: *mut Tok, h: u32, out: *mut u8) -> u32;
    fn fhsm_token_object_get_flags3(t: *mut Tok, h: u32, out: *mut u8) -> u32;
    fn fhsm_token_object_get_usage(t: *mut Tok, h: u32, out: *mut u8) -> u32;
    fn fhsm_token_object_set_flags(t: *mut Tok, h: u32, v: u8) -> u32;
    fn fhsm_token_object_set_flags2(t: *mut Tok, h: u32, v: u8) -> u32;
    fn fhsm_token_object_set_flags3(t: *mut Tok, h: u32, v: u8) -> u32;
    fn fhsm_token_object_set_usage(t: *mut Tok, h: u32, v: u8) -> u32;
    fn fhsm_token_object_is_token(t: *mut Tok, h: u32, out: *mut c_int) -> u32;
    fn fhsm_token_object_set_label(t: *mut Tok, h: u32, label: *const c_char) -> u32;
    fn fhsm_token_object_set_id(t: *mut Tok, h: u32, id: *const u8, len: usize) -> u32;
    fn fhsm_token_object_destroy(t: *mut Tok, h: u32) -> u32;
    fn fhsm_token_object_mark_session(t: *mut Tok, h: u32, owner: u32) -> u32;
    fn fhsm_token_destroy_session_objects(t: *mut Tok, owner: u32) -> u32;
    fn fhsm_token_object_mech_allowed(t: *mut Tok, h: u32, mech: u32) -> u32;
    fn fhsm_token_object_get_policy_counts(
        t: *mut Tok,
        h: u32,
        a: *mut u8,
        w: *mut u8,
        u: *mut u8,
        d: *mut u8,
    ) -> u32;
    fn fhsm_token_object_set_allowed_mechs(t: *mut Tok, h: u32, m: *const u32, n: u8) -> u32;
    fn fhsm_token_object_get_allowed_mechs(t: *mut Tok, h: u32, m: *mut u32, io: *mut u8) -> u32;
    fn fhsm_token_object_set_tmpl(
        t: *mut Tok,
        h: u32,
        which: c_int,
        a: *const PolicyAttr,
        n: u8,
    ) -> u32;
    fn fhsm_token_object_get_tmpl(
        t: *mut Tok,
        h: u32,
        which: c_int,
        a: *mut PolicyAttr,
        io: *mut u8,
    ) -> u32;
}

fn golden_rows() -> BTreeMap<String, String> {
    String::from_utf8(read_golden("ffi.tsv"))
        .unwrap()
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once('\t').unwrap();
            (k.to_owned(), v.to_owned())
        })
        .collect()
}

struct Rows {
    c: BTreeMap<String, String>,
    seen: Vec<String>,
    bad: Vec<String>,
}

impl Rows {
    fn row(&mut self, name: &str, rv: u32, extra: Option<String>) {
        let got = match extra {
            Some(e) => format!("0x{rv:x}\t{e}"),
            None => format!("0x{rv:x}"),
        };
        match self.c.get(name) {
            None => self.bad.push(format!("{name}: no golden row")),
            Some(c) if *c != got => self.bad.push(format!("{name}: C {c:?}, Rust {got:?}")),
            _ => {}
        }
        self.seen.push(name.to_owned());
    }
}

fn cs(s: &[u8]) -> CString {
    CString::new(s).unwrap()
}

/// gen_store.c `ffi()`, call for call.
#[test]
fn replays_c_s_abi_rows_in_order() {
    let dir = tempfile::tempdir().unwrap();
    let tp = cs(dir.path().join("slot0.tok").to_str().unwrap().as_bytes());
    let (so, user, newp, l) = (cs(SO_PIN), cs(USER_PIN), cs(NEW_PIN), cs(b"l"));
    let mut r = Rows {
        c: golden_rows(),
        seen: Vec::new(),
        bad: Vec::new(),
    };
    let mut t: *mut Tok = null_mut();
    // SAFETY: every call passes either NULL where the row says so, or live buffers.
    unsafe {
        r.row("load_null_path", fhsm_token_load(null(), &mut t), None);
        r.row(
            "load_null_out",
            fhsm_token_load(tp.as_ptr(), null_mut()),
            None,
        );
        r.row("load_missing", fhsm_token_load(tp.as_ptr(), &mut t), None);
        r.row(
            "init_null_path",
            fhsm_token_init(null(), so.as_ptr(), l.as_ptr(), &mut t),
            None,
        );
        r.row(
            "init_null_pin",
            fhsm_token_init(tp.as_ptr(), null(), l.as_ptr(), &mut t),
            None,
        );
        r.row(
            "init_null_label",
            fhsm_token_init(tp.as_ptr(), so.as_ptr(), null(), &mut t),
            None,
        );
        r.row(
            "init_null_out",
            fhsm_token_init(tp.as_ptr(), so.as_ptr(), l.as_ptr(), null_mut()),
            None,
        );
        r.row(
            "init_ok",
            fhsm_token_init(tp.as_ptr(), so.as_ptr(), cs(b"golden-ffi").as_ptr(), &mut t),
            None,
        );
        r.row(
            "login_null_token",
            fhsm_token_login(null_mut(), 1, so.as_ptr(), 16),
            None,
        );
        r.row("login_null_pin", fhsm_token_login(t, 1, null(), 16), None);
        r.row(
            "verify_null_token",
            fhsm_token_verify_pin(null_mut(), 1, so.as_ptr(), 16),
            None,
        );
        r.row(
            "verify_null_pin",
            fhsm_token_verify_pin(t, 1, null(), 16),
            None,
        );
        r.row(
            "verify_role_3",
            fhsm_token_verify_pin(t, 3, so.as_ptr(), 16),
            None,
        );
        r.row(
            "set_pin_null_token",
            fhsm_token_set_pin(null_mut(), 1, so.as_ptr(), newp.as_ptr()),
            None,
        );
        r.row(
            "set_pin_null_old",
            fhsm_token_set_pin(t, 1, null(), newp.as_ptr()),
            None,
        );
        r.row(
            "set_pin_null_new",
            fhsm_token_set_pin(t, 1, so.as_ptr(), null()),
            None,
        );
        r.row(
            "init_user_pin_null_token",
            fhsm_token_init_user_pin(null_mut(), user.as_ptr()),
            None,
        );
        r.row(
            "init_user_pin_null_pin",
            fhsm_token_init_user_pin(t, null()),
            None,
        );
        r.row(
            "reinit_null_token",
            fhsm_token_reinit(null_mut(), so.as_ptr(), l.as_ptr()),
            None,
        );
        r.row(
            "reinit_null_pin",
            fhsm_token_reinit(t, null(), l.as_ptr()),
            None,
        );
        r.row(
            "reinit_null_label",
            fhsm_token_reinit(t, so.as_ptr(), null()),
            None,
        );
        let ex = format!(
            "role={} label_null={} serial_null={} failed={} uinit={} locked={} thr={}",
            fhsm_token_current_role(null()),
            fhsm_token_label(null()).is_null() as u8,
            fhsm_token_serial(null()).is_null() as u8,
            fhsm_token_failed_count(null(), 1),
            fhsm_token_user_initialized(null()),
            fhsm_token_is_locked(null(), 1),
            fhsm_token_throttle_remaining_ms(null(), 1)
        );
        r.row("accessors_null_token", 0, Some(ex));
        r.row(
            "login_so",
            fhsm_token_login(t, 1, so.as_ptr(), SO_PIN.len()),
            None,
        );
        r.row(
            "init_user_pin",
            fhsm_token_init_user_pin(t, user.as_ptr()),
            None,
        );
        fhsm_token_logout(t);
        r.row(
            "login_user",
            fhsm_token_login(t, 2, user.as_ptr(), USER_PIN.len()),
            None,
        );
        let (mut h, mut h2) = (0u32, 0u32);
        let v = [1u8, 2, 3, 4];
        let k = cs(b"k");
        let big = vec![0u8; 2_097_153];
        r.row(
            "add_null_token",
            fhsm_token_object_add(
                null_mut(),
                4,
                31,
                k.as_ptr(),
                v.as_ptr(),
                4,
                null(),
                0,
                0,
                &mut h,
            ),
            None,
        );
        r.row(
            "add_null_out",
            fhsm_token_object_add(
                t,
                4,
                31,
                k.as_ptr(),
                v.as_ptr(),
                4,
                null(),
                0,
                0,
                null_mut(),
            ),
            None,
        );
        r.row(
            "add_value_over_max",
            fhsm_token_object_add(
                t,
                4,
                31,
                k.as_ptr(),
                big.as_ptr(),
                big.len(),
                null(),
                0,
                0,
                &mut h,
            ),
            None,
        );
        r.row(
            "add_id_33",
            fhsm_token_object_add(
                t,
                4,
                31,
                k.as_ptr(),
                v.as_ptr(),
                4,
                big.as_ptr(),
                33,
                0,
                &mut h,
            ),
            None,
        );
        r.row(
            "add_value_over_max_and_id_33",
            fhsm_token_object_add(
                t,
                4,
                31,
                k.as_ptr(),
                big.as_ptr(),
                big.len(),
                big.as_ptr(),
                33,
                0,
                &mut h,
            ),
            None,
        );
        r.row(
            "add_ok",
            fhsm_token_object_add(
                t,
                4,
                31,
                k.as_ptr(),
                v.as_ptr(),
                4,
                v.as_ptr(),
                2,
                0,
                &mut h,
            ),
            None,
        );
        r.row(
            "add_null_label_null_value",
            fhsm_token_object_add(t, 0, 0, null(), null(), 0, null(), 0, 0, &mut h2),
            None,
        );
        let (mut pv, mut pl, mut c, mut kt): (*const u8, usize, u32, u32) =
            (v.as_ptr(), 99, 99, 99);
        r.row(
            "get_null_token",
            fhsm_token_object_get(null_mut(), h, &mut pv, &mut pl, &mut c, &mut kt),
            None,
        );
        r.row(
            "get_null_outputs",
            fhsm_token_object_get(t, h, null_mut(), null_mut(), null_mut(), null_mut()),
            None,
        );
        let rv = fhsm_token_object_get(t, h2, &mut pv, &mut pl, &mut c, &mut kt);
        r.row(
            "get_empty_value",
            rv,
            Some(format!("value_null={} len={pl}", pv.is_null() as u8)),
        );
        let (mut cnt, mut hs) = (99usize, [0u32; 4]);
        r.row(
            "find_null_token",
            fhsm_token_object_find(null_mut(), null(), null(), hs.as_mut_ptr(), 4, &mut cnt),
            None,
        );
        r.row(
            "find_null_count",
            fhsm_token_object_find(t, null(), null(), hs.as_mut_ptr(), 4, null_mut()),
            None,
        );
        let rv = fhsm_token_object_find(t, null(), null(), null_mut(), 4, &mut cnt);
        r.row("find_null_handles", rv, Some(format!("n={cnt}")));
        let (mut lp, mut n, mut bp): (*const c_char, usize, *const u8) = (null(), 0, null());
        r.row(
            "get_label_null_out",
            fhsm_token_object_get_label(t, h, null_mut(), &mut n),
            None,
        );
        r.row(
            "get_label_null_len",
            fhsm_token_object_get_label(t, h, &mut lp, null_mut()),
            None,
        );
        r.row(
            "get_id_null_out",
            fhsm_token_object_get_id(t, h, null_mut(), &mut n),
            None,
        );
        r.row(
            "get_meta_null_out",
            fhsm_token_object_get_meta(t, h, 0, null_mut(), &mut n),
            None,
        );
        r.row(
            "get_meta_which_3",
            fhsm_token_object_get_meta(t, h, 3, &mut bp, &mut n),
            None,
        );
        r.row(
            "get_meta_which_3_unknown_handle",
            fhsm_token_object_get_meta(t, 999, 3, &mut bp, &mut n),
            None,
        );
        r.row(
            "set_meta_null_token",
            fhsm_token_object_set_meta(null_mut(), h, null(), 0, null(), 0, null(), 0),
            None,
        );
        r.row(
            "set_meta_start_9",
            fhsm_token_object_set_meta(t, 999, big.as_ptr(), 9, null(), 0, null(), 0),
            None,
        );
        r.row(
            "set_meta_null_start_len_9",
            fhsm_token_object_set_meta(t, h, null(), 9, null(), 0, null(), 0),
            None,
        );
        let (mut f, mut it) = (0u8, 0 as c_int);
        r.row(
            "get_flags_null_out",
            fhsm_token_object_get_flags(t, h, null_mut()),
            None,
        );
        r.row(
            "get_flags2_null_out",
            fhsm_token_object_get_flags2(t, h, null_mut()),
            None,
        );
        r.row(
            "get_flags3_null_out",
            fhsm_token_object_get_flags3(t, h, null_mut()),
            None,
        );
        r.row(
            "get_usage_null_out",
            fhsm_token_object_get_usage(t, h, null_mut()),
            None,
        );
        r.row(
            "is_token_null_out",
            fhsm_token_object_is_token(t, h, null_mut()),
            None,
        );
        r.row(
            "get_flags_null_token",
            fhsm_token_object_get_flags(null_mut(), h, &mut f),
            None,
        );
        r.row(
            "is_token_null_token",
            fhsm_token_object_is_token(null_mut(), h, &mut it),
            None,
        );
        r.row(
            "set_flags_null_token",
            fhsm_token_object_set_flags(null_mut(), h, 0),
            None,
        );
        r.row(
            "set_flags2_null_token",
            fhsm_token_object_set_flags2(null_mut(), h, 0),
            None,
        );
        r.row(
            "set_flags3_null_token",
            fhsm_token_object_set_flags3(null_mut(), h, 0),
            None,
        );
        r.row(
            "set_usage_null_token",
            fhsm_token_object_set_usage(null_mut(), h, 0),
            None,
        );
        r.row(
            "set_label_null_label",
            fhsm_token_object_set_label(t, h, null()),
            None,
        );
        r.row(
            "set_id_33",
            fhsm_token_object_set_id(t, 999, big.as_ptr(), 33),
            None,
        );
        r.row(
            "set_id_null_with_len",
            fhsm_token_object_set_id(t, h, null(), 2),
            None,
        );
        r.row(
            "set_id_null_len_0",
            fhsm_token_object_set_id(t, h, null(), 0),
            None,
        );
        r.row(
            "destroy_null_token",
            fhsm_token_object_destroy(null_mut(), h),
            None,
        );
        r.row(
            "mark_session_owner_0",
            fhsm_token_object_mark_session(t, h, 0),
            None,
        );
        r.row(
            "destroy_session_owner_0",
            fhsm_token_destroy_session_objects(t, 0),
            None,
        );
        r.row(
            "mech_allowed_null_token",
            fhsm_token_object_mech_allowed(null_mut(), h, 1),
            None,
        );
        r.row(
            "policy_counts_null_token",
            fhsm_token_object_get_policy_counts(
                null_mut(),
                h,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            ),
            None,
        );
        r.row(
            "policy_counts_null_outputs",
            fhsm_token_object_get_policy_counts(
                t,
                h,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
            ),
            None,
        );
        let mut m = [0x1081u32, 0x1082, 3, 0, 0, 0, 0, 0];
        r.row(
            "set_mechs_null_with_count",
            fhsm_token_object_set_allowed_mechs(t, h, null(), 1),
            None,
        );
        r.row(
            "set_mechs_count_9",
            fhsm_token_object_set_allowed_mechs(t, 999, m.as_ptr(), 9),
            None,
        );
        r.row(
            "set_mechs_null_count_0",
            fhsm_token_object_set_allowed_mechs(t, h, null(), 0),
            None,
        );
        r.row(
            "set_mechs_3",
            fhsm_token_object_set_allowed_mechs(t, h, m.as_ptr(), 3),
            None,
        );
        r.row(
            "get_mechs_null_io",
            fhsm_token_object_get_allowed_mechs(t, h, m.as_mut_ptr(), null_mut()),
            None,
        );
        let mut io = 0u8;
        let rv = fhsm_token_object_get_allowed_mechs(t, h, null_mut(), &mut io);
        r.row("get_mechs_size_query", rv, Some(format!("io={io}")));
        io = 2;
        let rv = fhsm_token_object_get_allowed_mechs(t, h, m.as_mut_ptr(), &mut io);
        r.row("get_mechs_cap_2", rv, Some(format!("io={io}")));
        io = 3;
        let mut o3 = [0u32; 3];
        let rv = fhsm_token_object_get_allowed_mechs(t, h, o3.as_mut_ptr(), &mut io);
        r.row(
            "get_mechs_cap_3",
            rv,
            Some(format!(
                "io={io} v=0x{:x},0x{:x},0x{:x}",
                o3[0], o3[1], o3[2]
            )),
        );
        io = 5;
        let rv = fhsm_token_object_get_allowed_mechs(t, 999, m.as_mut_ptr(), &mut io);
        r.row("get_mechs_unknown_handle", rv, Some(format!("io={io}")));
        let mut a = [PolicyAttr::default(); 5];
        for (i, x) in a.iter_mut().enumerate() {
            (x.type_, x.kind, x.len, x.value[0]) = (i as u32 + 1, 1, 1, 1);
        }
        r.row(
            "set_tmpl_null_with_count",
            fhsm_token_object_set_tmpl(t, h, 0, null(), 1),
            None,
        );
        r.row(
            "set_tmpl_count_5",
            fhsm_token_object_set_tmpl(t, 999, 0, a.as_ptr(), 5),
            None,
        );
        r.row(
            "set_tmpl_which_3",
            fhsm_token_object_set_tmpl(t, 999, 3, a.as_ptr(), 1),
            None,
        );
        r.row(
            "set_tmpl_which_3_count_5",
            fhsm_token_object_set_tmpl(t, 999, 3, a.as_ptr(), 5),
            None,
        );
        a[0].kind = 0;
        r.row(
            "set_tmpl_kind_0_which_3",
            fhsm_token_object_set_tmpl(t, 999, 3, a.as_ptr(), 1),
            None,
        );
        a[0].kind = 1;
        r.row(
            "set_tmpl_2",
            fhsm_token_object_set_tmpl(t, h, 2, a.as_ptr(), 2),
            None,
        );
        r.row(
            "get_tmpl_null_io",
            fhsm_token_object_get_tmpl(t, h, 2, a.as_mut_ptr(), null_mut()),
            None,
        );
        io = 0;
        r.row(
            "get_tmpl_which_3",
            fhsm_token_object_get_tmpl(t, h, 3, a.as_mut_ptr(), &mut io),
            None,
        );
        io = 0;
        let rv = fhsm_token_object_get_tmpl(t, h, 2, null_mut(), &mut io);
        r.row("get_tmpl_size_query", rv, Some(format!("io={io}")));
        io = 1;
        let rv = fhsm_token_object_get_tmpl(t, h, 2, a.as_mut_ptr(), &mut io);
        r.row("get_tmpl_cap_1", rv, Some(format!("io={io}")));
        let layout = format!(
            "size={} align={} kind={} len={} value={}",
            size_of::<PolicyAttr>(),
            align_of::<PolicyAttr>(),
            std::mem::offset_of!(PolicyAttr, kind),
            std::mem::offset_of!(PolicyAttr, len),
            std::mem::offset_of!(PolicyAttr, value)
        );
        r.row("policy_attr_layout", 0, Some(layout));
        fhsm_token_close(null_mut());
        fhsm_token_logout(null_mut());
        r.row("close_and_logout_null", 0, None);
        fhsm_token_close(t);
    }
    let missing: Vec<&String> = r.c.keys().filter(|k| !r.seen.contains(k)).collect();
    assert!(missing.is_empty(), "golden rows never called: {missing:?}");
    assert!(r.bad.is_empty(), "{}", r.bad.join("\n"));
}

/// M2: `fhsm_token_label` / `fhsm_token_serial` point into the token, NUL-terminated, and the
/// pointer does not move between calls.
#[test]
fn label_and_serial_pointers_are_stable_and_terminated_m2() {
    let dir = tempfile::tempdir().unwrap();
    let tp = cs(dir.path().join("slot0.tok").to_str().unwrap().as_bytes());
    let mut t: *mut Tok = null_mut();
    // SAFETY: a live token for the whole test.
    unsafe {
        assert_eq!(
            fhsm_token_init(
                tp.as_ptr(),
                cs(SO_PIN).as_ptr(),
                cs(&[b'L'; 70]).as_ptr(),
                &mut t
            ),
            0
        );
        let (l1, s1) = (fhsm_token_label(t), fhsm_token_serial(t));
        assert_eq!(
            CStr::from_ptr(l1).to_bytes(),
            &[b'L'; 63],
            "RULE-079: init keeps 63 bytes"
        );
        assert_eq!(CStr::from_ptr(s1).to_bytes().len(), 21);
        assert_eq!((fhsm_token_label(t), fhsm_token_serial(t)), (l1, s1));
        fhsm_token_close(t);
    }
}

/// M2: get_label / get_id / get_meta return per-thread copies, so a pointer stays valid while
/// another thread reads another object.
#[test]
fn get_label_pointers_are_per_thread_m2() {
    struct P(*mut Tok);
    // SAFETY: the C ABI token is Send + Sync (every entry point takes the token mutex).
    unsafe impl Send for P {}
    unsafe impl Sync for P {}
    impl P {
        fn get(&self) -> *mut Tok {
            self.0
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let tp = cs(dir.path().join("slot0.tok").to_str().unwrap().as_bytes());
    let mut t: *mut Tok = null_mut();
    let (mut h1, mut h2) = (0u32, 0u32);
    // SAFETY: a live, logged-in token for the whole test.
    unsafe {
        assert_eq!(
            fhsm_token_init(tp.as_ptr(), cs(SO_PIN).as_ptr(), cs(b"m2").as_ptr(), &mut t),
            0
        );
        assert_eq!(fhsm_token_login(t, 1, cs(SO_PIN).as_ptr(), SO_PIN.len()), 0);
        assert_eq!(fhsm_token_init_user_pin(t, cs(USER_PIN).as_ptr()), 0);
        fhsm_token_logout(t);
        assert_eq!(
            fhsm_token_login(t, 2, cs(USER_PIN).as_ptr(), USER_PIN.len()),
            0
        );
        assert_eq!(
            fhsm_token_object_add(
                t,
                0,
                0,
                cs(b"first").as_ptr(),
                null(),
                0,
                null(),
                0,
                0,
                &mut h1
            ),
            0
        );
        assert_eq!(
            fhsm_token_object_add(
                t,
                0,
                0,
                cs(b"second").as_ptr(),
                null(),
                0,
                null(),
                0,
                0,
                &mut h2
            ),
            0
        );
    }
    let p = P(t);
    let (mut lp, mut n): (*const c_char, usize) = (null(), 0);
    // SAFETY: as above.
    unsafe { assert_eq!(fhsm_token_object_get_label(p.0, h1, &mut lp, &mut n), 0) };
    std::thread::scope(|s| {
        s.spawn(|| {
            let (mut q, mut m): (*const c_char, usize) = (null(), 0);
            // SAFETY: as above.
            unsafe { assert_eq!(fhsm_token_object_get_label(p.get(), h2, &mut q, &mut m), 0) };
            assert_eq!(m, 6);
        });
    });
    // SAFETY: the pointer this thread got is still its own copy.
    unsafe {
        assert_eq!(std::slice::from_raw_parts(lp as *const u8, n), b"first");
        fhsm_token_close(p.0);
    }
}

/// DIV-027 (Rust-only row of `RUST_ONLY`): C keeps `value_len` for a NULL value
/// (`src/fhsm_token.c:1923-1925`) and its next write `memcpy`s from NULL (`:659`), undefined
/// behaviour no golden can record. Rust refuses the call with ARGUMENTS_BAD and adds nothing.
#[test]
fn object_add_null_value_with_a_length_is_arguments_bad_div027() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slot0.tok");
    let tp = cs(path.to_str().unwrap().as_bytes());
    let mut t: *mut Tok = null_mut();
    // SAFETY: a live token for the whole test; every out-pointer is a local.
    unsafe {
        assert_eq!(
            fhsm_token_init(
                tp.as_ptr(),
                cs(SO_PIN).as_ptr(),
                cs(b"d27").as_ptr(),
                &mut t
            ),
            0
        );
        assert_eq!(fhsm_token_login(t, 1, cs(SO_PIN).as_ptr(), SO_PIN.len()), 0);
        let before = std::fs::read(&path).unwrap();
        let mut h = 0u32;
        let rv = fhsm_token_object_add(t, 0, 0, cs(b"x").as_ptr(), null(), 4, null(), 0, 0, &mut h);
        assert_eq!(rv, 0x7, "ARGUMENTS_BAD");
        let mut n = usize::MAX;
        assert_eq!(
            fhsm_token_object_find(t, null(), null(), null_mut(), 0, &mut n),
            0
        );
        assert_eq!(n, 0, "nothing added");
        assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");
        fhsm_token_close(t);
    }
}

/// DIV-028 (Rust-only row of `RUST_ONLY`): C takes any role other than SO as the user's
/// (`src/fhsm_token.c:1395-1415`): role 3 checks the PIN against the user's wrap, counts a
/// user failure, and on success records role 3 as logged in (`:1525`). No golden calls it.
/// Rust refuses login and `set_pin` with ARGUMENTS_BAD and counts nothing.
#[test]
fn login_or_set_pin_with_an_unknown_role_is_arguments_bad_div028() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slot0.tok");
    let tp = cs(path.to_str().unwrap().as_bytes());
    let mut t: *mut Tok = null_mut();
    // SAFETY: a live token for the whole test; every out-pointer is a local.
    unsafe {
        assert_eq!(
            fhsm_token_init(
                tp.as_ptr(),
                cs(SO_PIN).as_ptr(),
                cs(b"d28").as_ptr(),
                &mut t
            ),
            0
        );
        let before = std::fs::read(&path).unwrap();
        let so = cs(SO_PIN);
        assert_eq!(fhsm_token_login(t, 3, so.as_ptr(), SO_PIN.len()), 0x7);
        assert_eq!(
            fhsm_token_set_pin(t, 3, so.as_ptr(), cs(NEW_PIN).as_ptr()),
            0x7
        );
        assert_eq!(fhsm_token_current_role(t), 0);
        assert_eq!(fhsm_token_failed_count(t, 2), 0);
        assert_eq!(std::fs::read(&path).unwrap(), before, "nothing written");
        fhsm_token_close(t);
    }
}
