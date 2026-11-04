//! `fhsm_parse_create_attrs` (`include/fhsm_create_attrs.h`) over `pqhsm_core::template`, for
//! the C still calling it: `C_CreateObject` and `fuzz/fuzz_create_attrs.c`.

use std::ffi::{CStr, c_char, c_ulong};
use std::ptr::null;

use pqhsm_core::template::{In, parse};

use super::objects::Attr;

/// A pointer and length pair of `fhsm_create_attrs_t`; NULL and 0 for `None`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Span {
    p: *const u8,
    len: usize,
}

impl From<Option<&[u8]>> for Span {
    fn from(s: Option<&[u8]>) -> Span {
        s.map_or(Span { p: null(), len: 0 }, |s| Span {
            p: s.as_ptr(),
            len: s.len(),
        })
    }
}

/// `fhsm_create_attrs_t`.
#[repr(C)]
pub struct CreateAttrs {
    path: u32,
    cko: c_ulong,
    ckk: c_ulong,
    cert_type: c_ulong,
    label: [u8; 64],
    id: Span,
    value: Span,
    pqc_alg: *const c_char,
    ec_group: *const c_char,
    ec_point: Span,
    rsa: [Span; 8],
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fhsm_parse_create_attrs(
    t: *const Attr,
    n: c_ulong,
    out: *mut CreateAttrs,
) -> u32 {
    let rows: Vec<In<'_>> = if t.is_null() || n == 0 {
        Vec::new()
    } else {
        // SAFETY: the caller's n attributes, each value NULL or valid for its length
        unsafe { std::slice::from_raw_parts(t, n as usize) }
            .iter()
            .map(|a| In {
                kind: a.kind,
                value: (!a.value.is_null())
                    // SAFETY: as above
                    .then(|| unsafe { std::slice::from_raw_parts(a.value, a.len as usize) }),
            })
            .collect()
    };
    let (p, rv) = parse(&rows);
    let cstr = |s: Option<&'static CStr>| s.map_or(null(), CStr::as_ptr);
    // SAFETY: the caller's out struct
    unsafe {
        out.write(CreateAttrs {
            path: p.path as u32,
            cko: p.cko,
            ckk: p.ckk,
            cert_type: p.cert_type,
            label: p.label,
            id: p.id.into(),
            value: p.value.into(),
            pqc_alg: cstr(p.pqc_alg),
            ec_group: cstr(p.ec_group),
            ec_point: p.ec_point.into(),
            rsa: p.rsa.map(Span::from),
        })
    };
    rv as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_is_c_s() {
        // fhsm_create_attrs_t on LP64: path padded to 8, three ulongs, label, then pairs.
        assert_eq!(std::mem::offset_of!(CreateAttrs, label), 32);
        assert_eq!(std::mem::offset_of!(CreateAttrs, id), 96);
        assert_eq!(std::mem::offset_of!(CreateAttrs, pqc_alg), 128);
        assert_eq!(std::mem::offset_of!(CreateAttrs, rsa), 160);
        assert_eq!(size_of::<CreateAttrs>(), 288);
    }
}
