//! Phase 4 slice 2d: `C_CopyObject` (`src/fhsm_pkcs11.c:7995-8293`), in C's order, and
//! the template helpers it applies once the copy exists (`fhsm_check_trusted_attr`,
//! `fhsm_check_ro_token`, `fhsm_apply_allowed_mechs`, `fhsm_apply_nested_tmpl`,
//! `fhsm_apply_encap_flags`, `fhsm_apply_obj_meta`, `tmpl_bbool`).
//! shortcut: C's create, generate, unwrap and derive keep their static copies of these
//! helpers until those entry points move (slice 6, decided 2026-11-05); then these are the
//! only ones.

use std::ffi::{c_char, c_int, c_ulong};
use std::ptr::null;

use pqhsm_core::session::{ROLE_NONE, ROLE_SO};

use super::apilock::Held;
use super::attrs::{
    ATTRIBUTE_READ_ONLY, ATTRIBUTE_TYPE_INVALID, CKA_ALLOWED_MECHANISMS, CKA_APPLICATION,
    CKA_COPYABLE, CKA_DECAPSULATE, CKA_DERIVE_TEMPLATE, CKA_DESTROYABLE, CKA_ENCAPSULATE,
    CKA_END_DATE, CKA_EXTRACTABLE, CKA_KEY_TYPE, CKA_MODIFIABLE, CKA_PRIVATE, CKA_SENSITIVE,
    CKA_START_DATE, CKA_TOKEN, CKA_TRUSTED, CKA_UNWRAP_TEMPLATE, CKA_VALUE, CKA_VALUE_LEN,
    CKA_WRAP_TEMPLATE, CKO_PUBLIC_KEY, META_APPLICATION, META_END_DATE, META_START_DATE,
    OBJF_EXTRACTABLE, OBJF_SENSITIVE, OBJF_UNMODIFIABLE, OBJF2_NO_DECAPSULATE,
    OBJF2_NO_ENCAPSULATE, OBJF2_NOT_COPYABLE, POLICY_ATTR_MAX, POLICY_MECH_MAX, PolicyAttr,
    date_ok,
};
use super::objects::{
    Attr, CKA_CLASS, CKA_ID, CKA_LABEL, CKF_RW_SESSION, OBJF_UNDESTROYABLE, check_template, gate,
    lookup_rv,
};
use super::session::TABLE;
use super::sys::*;

const TEMPLATE_INCONSISTENT: u32 = 0xD1;
/// `fhsm_tmpl_which_t`.
const TMPL_WRAP: c_int = 0;
const TMPL_UNWRAP: c_int = 1;
const TMPL_DERIVE: c_int = 2;
const POLICY_VALUE_MAX: usize = 48;
const POLICY_KIND_BOOL: u8 = 1;
const POLICY_KIND_ULONG: u8 = 2;
const POLICY_KIND_BYTES: u8 = 3;
/// `fhsm_bool_attr_types` and `fhsm_ulong_attr_types`.
const BOOL_ATTRS: [c_ulong; 22] = [
    0x001, 0x002, 0x086, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108, 0x109, 0x10A, 0x10B, 0x10C,
    0x162, 0x163, 0x164, 0x165, 0x170, 0x171, 0x172, 0x202, 0x210,
];
const ULONG_ATTRS: [c_ulong; 5] = [0x000, 0x100, 0x161, 0x121, 0x080];

unsafe extern "C" {
    fn fhsm_token_object_add(
        t: *mut fhsm_token_t,
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
    fn fhsm_token_object_mark_session(t: *mut fhsm_token_t, h: u32, owner: u32) -> u32;
    fn fhsm_token_object_get_flags3(t: *mut fhsm_token_t, h: u32, out: *mut u8) -> u32;
    fn fhsm_token_object_set_flags3(t: *mut fhsm_token_t, h: u32, v: u8) -> u32;
    fn fhsm_token_object_set_allowed_mechs(
        t: *mut fhsm_token_t,
        h: u32,
        mechs: *const u32,
        count: u8,
    ) -> u32;
    fn fhsm_token_object_set_tmpl(
        t: *mut fhsm_token_t,
        h: u32,
        which: c_int,
        a: *const PolicyAttr,
        count: u8,
    ) -> u32;
}

/// `find_attr`: the first row of `kind`.
fn find(t: &[Attr], kind: c_ulong) -> Option<&Attr> {
    t.iter().find(|a| a.kind == kind)
}

/// A row's bytes; a NULL value has none (`check_template` refused NULL with a length).
fn bytes(a: &Attr) -> &[u8] {
    if a.value.is_null() || a.len == 0 {
        &[]
    } else {
        // SAFETY: a checked template row: its value is valid for its length
        unsafe { std::slice::from_raw_parts(a.value, a.len as usize) }
    }
}

/// The first row of `kind` as a well-formed CK_BBOOL, if there is one.
fn bbool(t: &[Attr], kind: c_ulong) -> Option<bool> {
    find(t, kind)
        .filter(|a| !a.value.is_null() && a.len == 1)
        .map(|a| bytes(a)[0] != 0)
}

/// `fhsm_check_trusted_attr`: only the SO may set CKA_TRUSTED to TRUE.
pub(super) fn check_trusted(h: c_ulong, t: &[Attr]) -> Result<(), u32> {
    if bbool(t, CKA_TRUSTED) == Some(true) && TABLE.role(h) != ROLE_SO {
        return Err(ATTRIBUTE_READ_ONLY);
    }
    Ok(())
}

/// `fhsm_check_ro_token`: a token object needs a read-write session.
pub(super) fn check_ro_token(h: c_ulong, t: &[Attr]) -> Result<(), u32> {
    if bbool(t, CKA_TOKEN) == Some(true)
        && TABLE
            .info(h)
            .is_ok_and(|(_, flags, _)| flags & CKF_RW_SESSION == 0)
    {
        return Err(SESSION_READ_ONLY);
    }
    Ok(())
}

/// `fhsm_apply_allowed_mechs`: absent is no restriction; CK_ULONGs, at most eight.
pub(super) fn apply_allowed_mechs(tok: *mut fhsm_token_t, t: &[Attr], h: u32) -> u32 {
    let Some(a) = find(t, CKA_ALLOWED_MECHANISMS) else {
        return OK;
    };
    let w = size_of::<c_ulong>();
    let v = bytes(a);
    if !(a.len as usize).is_multiple_of(w) || a.len as usize / w > POLICY_MECH_MAX {
        return ATTRIBUTE_VALUE_INVALID;
    }
    let mut m = [0u32; POLICY_MECH_MAX];
    for (k, c) in v.chunks_exact(w).enumerate() {
        // C truncates each CK_MECHANISM_TYPE to the record's u32.
        m[k] = c_ulong::from_ne_bytes(c.try_into().expect("w bytes")) as u32;
    }
    // SAFETY: a token the registry holds; m holds at least the count
    unsafe { fhsm_token_object_set_allowed_mechs(tok, h, m.as_ptr(), (v.len() / w) as u8) }
}

/// `fhsm_policy_kind_of`.
fn policy_kind(kind: c_ulong) -> u8 {
    if BOOL_ATTRS.contains(&kind) {
        POLICY_KIND_BOOL
    } else if ULONG_ATTRS.contains(&kind) {
        POLICY_KIND_ULONG
    } else {
        POLICY_KIND_BYTES
    }
}

/// `fhsm_wrap_tmpl_attr_supported`: the attributes the wrap check reads.
fn wrap_tmpl_supported(kind: c_ulong) -> bool {
    [
        CKA_CLASS,
        CKA_KEY_TYPE,
        CKA_VALUE_LEN,
        CKA_LABEL,
        CKA_ID,
        CKA_SENSITIVE,
        CKA_EXTRACTABLE,
    ]
    .contains(&kind)
}

/// `fhsm_apply_nested_tmpl`: at most four attributes, each value at most 48 bytes.
fn apply_nested_tmpl(
    tok: *mut fhsm_token_t,
    t: &[Attr],
    h: u32,
    attr: c_ulong,
    which: c_int,
) -> u32 {
    let Some(a) = find(t, attr) else {
        return OK;
    };
    let sz = size_of::<Attr>();
    let cnt = a.len as usize / sz;
    if !(a.len as usize).is_multiple_of(sz)
        || cnt > POLICY_ATTR_MAX
        || (cnt > 0 && a.value.is_null())
    {
        return ATTRIBUTE_VALUE_INVALID;
    }
    let nest: &[Attr] = if cnt == 0 {
        &[]
    } else {
        // SAFETY: the caller's array of cnt CK_ATTRIBUTEs (its length says so)
        unsafe { std::slice::from_raw_parts(a.value.cast::<Attr>(), cnt) }
    };
    let mut ent = [PolicyAttr {
        kind_: 0,
        kind: 0,
        len: 0,
        value: [0; POLICY_VALUE_MAX],
    }; POLICY_ATTR_MAX];
    for (e, n) in ent.iter_mut().zip(nest) {
        if (n.value.is_null() && n.len != 0)
            || n.len as usize > POLICY_VALUE_MAX
            || (which == TMPL_WRAP && !wrap_tmpl_supported(n.kind))
        {
            return ATTRIBUTE_VALUE_INVALID;
        }
        e.kind_ = n.kind as u32;
        e.kind = policy_kind(n.kind);
        e.len = n.len as u8;
        let v = bytes(n);
        e.value[..v.len()].copy_from_slice(v);
    }
    // SAFETY: a token the registry holds; ent has at least cnt rows
    unsafe { fhsm_token_object_set_tmpl(tok, h, which, ent.as_ptr(), cnt as u8) }
}

/// The three nested templates, in C's order: unwrap, derive, wrap.
pub(super) fn apply_nested_all(tok: *mut fhsm_token_t, t: &[Attr], h: u32) -> u32 {
    for (attr, which) in [
        (CKA_UNWRAP_TEMPLATE, TMPL_UNWRAP),
        (CKA_DERIVE_TEMPLATE, TMPL_DERIVE),
        (CKA_WRAP_TEMPLATE, TMPL_WRAP),
    ] {
        let r = apply_nested_tmpl(tok, t, h, attr, which);
        if r != OK {
            return r;
        }
    }
    OK
}

/// `fhsm_apply_encap_flags`: CKA_ENCAPSULATE (public) or CKA_DECAPSULATE FALSE records the
/// restriction; TRUE is the default.
pub(super) fn apply_encap_flags(tok: *mut fhsm_token_t, t: &[Attr], h: u32, class: u32) -> u32 {
    let (which, bit) = if class == CKO_PUBLIC_KEY {
        (CKA_ENCAPSULATE, OBJF2_NO_ENCAPSULATE)
    } else {
        (CKA_DECAPSULATE, OBJF2_NO_DECAPSULATE)
    };
    if bbool(t, which) != Some(false) {
        return OK;
    }
    let mut f2 = 0u8;
    // SAFETY: a token the registry holds; an out pointer of our own (C ignores the result)
    unsafe { fhsm_token_object_get_flags2(tok, h, &mut f2) };
    // SAFETY: as above
    unsafe { fhsm_token_object_set_flags2(tok, h, f2 | bit) }
}

/// `fhsm_apply_obj_meta`: the dates and CKA_APPLICATION, shape-checked and stored.
pub(super) fn apply_obj_meta(tok: *mut fhsm_token_t, t: &[Attr], h: u32) -> u32 {
    let rows = [
        find(t, CKA_START_DATE),
        find(t, CKA_END_DATE),
        find(t, CKA_APPLICATION),
    ];
    if rows.iter().all(Option::is_none) {
        return OK;
    }
    if rows[..2].iter().flatten().any(|d| !date_ok(bytes(d))) || rows[2].is_some_and(|a| a.len > 64)
    {
        return ATTRIBUTE_VALUE_INVALID;
    }
    // A NULL pointer leaves a field as it is, so a present empty value passes EMPTY.
    static EMPTY: [u8; 1] = [0];
    let [s, e, a] = rows.map(|r| {
        r.map_or((null(), 0), |r| {
            let p = if r.value.is_null() {
                EMPTY.as_ptr()
            } else {
                r.value.cast_const()
            };
            (p, r.len as usize)
        })
    });
    // SAFETY: a token the registry holds; each pointer valid for its length
    unsafe { fhsm_token_object_set_meta(tok, h, s.0, s.1, e.0, e.1, a.0, a.1) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_CopyObject(
    h: c_ulong,
    o: c_ulong,
    tmpl: *const Attr,
    n: c_ulong,
    out: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if out.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // An empty template is a verbatim copy.
    // SAFETY: the caller's n attributes
    let t = match unsafe { check_template(tmpl, n) } {
        Ok(t) => t,
        Err(rv) => return rv.into(),
    };
    if let Err(rv) = check_trusted(h, t).and_then(|()| check_ro_token(h, t)) {
        return rv.into();
    }
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    // SAFETY: a token the registry holds
    match unsafe { copy(h, tok.0.as_ptr(), o as u32, t) } {
        Ok(new) => {
            // SAFETY: checked non-NULL above
            unsafe { *out = new.into() };
            OK.into()
        }
        Err(rv) => rv.into(),
    }
}

/// The body of `C_CopyObject` after its argument checks.
///
/// # Safety
/// `tok` is a token the registry holds; `t` is a checked template.
unsafe fn copy(h: c_ulong, tok: *mut fhsm_token_t, o: u32, t: &[Attr]) -> Result<u32, u32> {
    // CKA_COPYABLE=FALSE on the source: refused before anything is read.
    let mut sf2 = 0u8;
    // SAFETY: the caller's token; out pointers of our own, here and below
    if unsafe { fhsm_token_object_get_flags2(tok, o, &mut sf2) } == OK
        && sf2 & OBJF2_NOT_COPYABLE != 0
    {
        return Err(ACTION_PROHIBITED);
    }
    if TABLE.role(h) == ROLE_NONE {
        return Err(USER_NOT_LOGGED_IN);
    }
    let (mut vp, mut vl, mut class, mut kt) = (null(), 0usize, 0u32, 0u32);
    // SAFETY: as above
    let r = unsafe { fhsm_token_object_get(tok, o, &mut vp, &mut vl, &mut class, &mut kt) };
    if r != OK {
        return Err(lookup_rv(r));
    }
    let mut label = [0u8; 64];
    let (mut lp, mut ll) = (null::<c_char>(), 0usize);
    // SAFETY: as above
    if unsafe { fhsm_token_object_get_label(tok, o, &mut lp, &mut ll) } == OK
        && !lp.is_null()
        && ll > 0
    {
        let n = ll.min(63);
        // SAFETY: the token's label, at least n bytes
        label[..n].copy_from_slice(unsafe { std::slice::from_raw_parts(lp.cast::<u8>(), n) });
    }
    let (mut id, mut id_len) = ([0u8; 32], 0usize);
    let (mut ip, mut il) = (null::<u8>(), 0usize);
    // SAFETY: as above
    if unsafe { fhsm_token_object_get_id(tok, o, &mut ip, &mut il) } == OK
        && !ip.is_null()
        && il > 0
        && il <= id.len()
    {
        // SAFETY: the token's id, il bytes
        id[..il].copy_from_slice(unsafe { std::slice::from_raw_parts(ip, il) });
        id_len = il;
    }
    let mut flags = 0u8;
    // SAFETY: as above
    unsafe { fhsm_token_object_get_flags(tok, o, &mut flags) };

    // The override template: set-attribute's rules, but the class-changing three are
    // CKR_TEMPLATE_INCONSISTENT here (v3.2 §C.6.7.3).
    for a in t {
        let v = bytes(a);
        match a.kind {
            CKA_LABEL => {
                label = [0; 64];
                let n = v.len().min(63);
                label[..n].copy_from_slice(&v[..n]);
            }
            CKA_ID => {
                if v.len() > id.len() {
                    return Err(ATTRIBUTE_VALUE_INVALID);
                }
                id = [0; 32];
                id[..v.len()].copy_from_slice(v);
                id_len = v.len();
            }
            // A copy may become sensitive or unextractable, never the reverse.
            CKA_SENSITIVE | CKA_EXTRACTABLE => {
                if a.len != 1 {
                    return Err(ATTRIBUTE_VALUE_INVALID);
                }
                let (bit, allowed) = if a.kind == CKA_SENSITIVE {
                    (OBJF_SENSITIVE, true)
                } else {
                    (OBJF_EXTRACTABLE, false)
                };
                let want = v[0] != 0;
                if want == (flags & bit != 0) {
                    continue;
                }
                if want != allowed {
                    return Err(ATTRIBUTE_READ_ONLY);
                }
                flags ^= bit;
            }
            // Applied once the copy exists; only their shape is checked here.
            CKA_TOKEN | CKA_PRIVATE | CKA_MODIFIABLE | CKA_DESTROYABLE | CKA_COPYABLE => {
                if a.len != 1 || a.value.is_null() {
                    return Err(ATTRIBUTE_VALUE_INVALID);
                }
            }
            CKA_CLASS | CKA_KEY_TYPE | CKA_VALUE => return Err(TEMPLATE_INCONSISTENT),
            _ => return Err(ATTRIBUTE_TYPE_INVALID),
        }
    }

    let mut new = 0u32;
    // SAFETY: as above; the store copies what it is handed
    let r = unsafe {
        fhsm_token_object_add(
            tok,
            class,
            kt,
            label.as_ptr().cast(),
            vp,
            vl,
            id.as_ptr(),
            id_len,
            flags,
            &mut new,
        )
    };
    if r != OK {
        return Err(r);
    }
    let undo = |r: u32| {
        // SAFETY: the object just added
        unsafe { fhsm_token_object_destroy(tok, new) };
        r
    };
    let r = apply_allowed_mechs(tok, t, new);
    if r != OK {
        return Err(undo(r));
    }
    let r = apply_nested_all(tok, t, new);
    if r != OK {
        return Err(undo(r));
    }

    // Scope: the template's CKA_TOKEN if stated, else the source's own.
    let want_token = bbool(t, CKA_TOKEN).unwrap_or_else(|| {
        let mut it: c_int = 1;
        // SAFETY: as above
        unsafe { fhsm_token_object_is_token(tok, o, &mut it) };
        it != 0
    });
    if !want_token {
        // SAFETY: as above (C ignores the result)
        unsafe { fhsm_token_object_mark_session(tok, new, h as u32) };
    }
    let mut pf = 0u8;
    // SAFETY: as above
    if unsafe { fhsm_token_object_get_flags(tok, new, &mut pf) } == OK {
        if bbool(t, CKA_MODIFIABLE) == Some(false) {
            pf |= OBJF_UNMODIFIABLE;
        }
        if bbool(t, CKA_DESTROYABLE) == Some(false) {
            pf |= OBJF_UNDESTROYABLE;
        }
        // SAFETY: as above
        unsafe { fhsm_token_object_set_flags(tok, new, pf) };
    }
    if bbool(t, CKA_COPYABLE) == Some(false) {
        let mut cf2 = 0u8;
        // SAFETY: as above
        unsafe { fhsm_token_object_get_flags2(tok, new, &mut cf2) };
        // SAFETY: as above
        unsafe { fhsm_token_object_set_flags2(tok, new, cf2 | OBJF2_NOT_COPYABLE) };
    }
    // The source's second and third flag bytes: as in C, a nonzero source byte replaces
    // the copy's whole byte.
    let mut b = 0u8;
    // SAFETY: as above
    if unsafe { fhsm_token_object_get_flags2(tok, o, &mut b) } == OK && b != 0 {
        // SAFETY: as above
        unsafe { fhsm_token_object_set_flags2(tok, new, b) };
    }
    b = 0;
    // SAFETY: as above
    if unsafe { fhsm_token_object_get_flags3(tok, o, &mut b) } == OK && b != 0 {
        // SAFETY: as above
        unsafe { fhsm_token_object_set_flags3(tok, new, b) };
    }
    let (mut cp, mut cl, mut cc, mut ck) = (null(), 0usize, 0u32, 0u32);
    // SAFETY: as above
    if unsafe { fhsm_token_object_get(tok, new, &mut cp, &mut cl, &mut cc, &mut ck) } == OK {
        let r = apply_encap_flags(tok, t, new, cc);
        if r != OK {
            return Err(undo(r));
        }
    }

    // The source's dates and CKA_APPLICATION, then the template's over them.
    let mut bufs = [[0u8; 64]; 3];
    let mut got = [None::<usize>; 3];
    for (i, (which, cap)) in [
        (META_START_DATE, 8),
        (META_END_DATE, 8),
        (META_APPLICATION, 64),
    ]
    .into_iter()
    .enumerate()
    {
        let (mut m, mut ml) = (null::<u8>(), 0usize);
        // SAFETY: as above
        if unsafe { fhsm_token_object_get_meta(tok, o, which, &mut m, &mut ml) } == OK && ml <= cap
        {
            if ml > 0 {
                // SAFETY: the token's copy, ml bytes
                bufs[i][..ml].copy_from_slice(unsafe { std::slice::from_raw_parts(m, ml) });
            }
            got[i] = Some(ml);
        }
    }
    if got.iter().any(|g| g.is_some_and(|l| l > 0)) {
        let arg = |i: usize| got[i].map_or((null(), 0), |l| (bufs[i].as_ptr(), l));
        let [s, e, a] = [arg(0), arg(1), arg(2)];
        // SAFETY: as above; a NULL pointer leaves that field
        unsafe { fhsm_token_object_set_meta(tok, new, s.0, s.1, e.0, e.1, a.0, a.1) };
    }
    let r = apply_obj_meta(tok, t, new);
    if r != OK {
        return Err(undo(r));
    }
    Ok(new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_kinds_are_c_s() {
        assert_eq!(policy_kind(0x103), POLICY_KIND_BOOL);
        assert_eq!(policy_kind(0x161), POLICY_KIND_ULONG);
        assert_eq!(policy_kind(0x3), POLICY_KIND_BYTES);
        assert!(wrap_tmpl_supported(CKA_LABEL) && !wrap_tmpl_supported(CKA_TOKEN));
    }
}
