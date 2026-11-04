//! `src/fhsm_create_attrs.c`: the pure parser for a `C_CreateObject` template. It reads the
//! class, key type, label and ID, picks the create path from (class, key type) and points at
//! the attributes that path builds from. It checks shape only; the builder checks the key.
//!
//! The same results as C for every template `C_CreateObject` can pass it. One difference is
//! unreachable there: a NULL value with a length (C read through it; here it counts as no
//! bytes), which `fhsm_check_template` refuses first.

use std::ffi::{CStr, c_ulong};

const CKA_CLASS: c_ulong = 0x0;
const CKA_LABEL: c_ulong = 0x3;
const CKA_VALUE: c_ulong = 0x11;
const CKA_CERTIFICATE_TYPE: c_ulong = 0x80;
const CKA_KEY_TYPE: c_ulong = 0x100;
const CKA_ID: c_ulong = 0x102;
const CKA_MODULUS: c_ulong = 0x120;
const CKA_PUBLIC_EXPONENT: c_ulong = 0x122;
const CKA_PRIVATE_EXPONENT: c_ulong = 0x123;
const CKA_PRIME_1: c_ulong = 0x124;
const CKA_PRIME_2: c_ulong = 0x125;
const CKA_EXPONENT_1: c_ulong = 0x126;
const CKA_EXPONENT_2: c_ulong = 0x127;
const CKA_COEFFICIENT: c_ulong = 0x128;
const CKA_EC_PARAMS: c_ulong = 0x180;
const CKA_EC_POINT: c_ulong = 0x181;

const CKO_DATA: c_ulong = 0;
const CKO_CERTIFICATE: c_ulong = 1;
const CKO_PUBLIC_KEY: c_ulong = 2;
const CKO_PRIVATE_KEY: c_ulong = 3;
const CKO_SECRET_KEY: c_ulong = 4;
const CKC_X_509: c_ulong = 0;
const CKK_RSA: c_ulong = 0x0;
const CKK_EC: c_ulong = 0x3;
const CKK_EC_EDWARDS: c_ulong = 0x40;
const CKK_ML_KEM: c_ulong = 0x49;
const CKK_ML_DSA: c_ulong = 0x4A;
const CKK_SLH_DSA: c_ulong = 0x4B;

/// The three NIST curves, by DER OID.
const EC_OIDS: [(&[u8], &CStr); 3] = [
    (
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        c"P-256",
    ),
    (&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22], c"P-384"),
    (&[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23], c"P-521"),
];
const ED25519_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
const ED448_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x71];
/// RFC 8032 key lengths: a wrapped point is at least two bytes longer, so these are bare.
const ED25519_LEN: usize = 32;
const ED448_LEN: usize = 57;

/// Raw PQC public-key lengths, one per set; distinct, so the length names the set.
const PQC_PUB_LENS: [(usize, &CStr); 6] = [
    (800, c"ML-KEM-512"),
    (1184, c"ML-KEM-768"),
    (1568, c"ML-KEM-1024"),
    (1312, c"ML-DSA-44"),
    (1952, c"ML-DSA-65"),
    (2592, c"ML-DSA-87"),
];

/// One template row: `None` for a NULL value.
#[derive(Clone, Copy, Debug)]
pub struct In<'a> {
    pub kind: c_ulong,
    pub value: Option<&'a [u8]>,
}

/// `fhsm_create_path_t`, in C's order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum Path {
    #[default]
    Invalid = 0,
    Verbatim,
    PqcPub,
    EcPub,
    Ed25519Pub,
    Ed448Pub,
    RsaPub,
    RsaPriv,
    CertX509,
}

/// `fhsm_parse_rv_t`, in C's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Rv {
    Ok = 0,
    TemplateIncomplete,
    TemplateInconsistent,
    AttributeValueInvalid,
    CurveNotInTable,
}

/// `fhsm_create_attrs_t`. Each slice points into the template; `None` is C's NULL. RSA's
/// components are n, e, d, p, q, dmp1, dmq1, iqmp.
#[derive(Clone, Copy, Debug)]
pub struct Parsed<'a> {
    pub path: Path,
    pub cko: c_ulong,
    pub ckk: c_ulong,
    pub cert_type: c_ulong,
    /// NUL-terminated, at most 63 bytes.
    pub label: [u8; 64],
    pub id: Option<&'a [u8]>,
    pub value: Option<&'a [u8]>,
    pub pqc_alg: Option<&'static CStr>,
    pub ec_group: Option<&'static CStr>,
    pub ec_point: Option<&'a [u8]>,
    pub rsa: [Option<&'a [u8]>; 8],
}

fn find<'a>(t: &[In<'a>], kind: c_ulong) -> Option<In<'a>> {
    t.iter().find(|a| a.kind == kind).copied()
}

/// `read_attr_ulong`: the first CK_ULONG's worth of the value, which may be longer.
fn read_ulong(t: &[In<'_>], kind: c_ulong) -> Option<c_ulong> {
    let v = find(t, kind)?.value?;
    let b = v.get(..size_of::<c_ulong>())?;
    Some(c_ulong::from_ne_bytes(b.try_into().ok()?))
}

/// `fhsm_strip_octet_string_inline`: the payload of a DER OCTET STRING whose length, in any
/// of the three forms, is the whole rest of the input.
pub fn strip_octet_string(v: &[u8]) -> Option<&[u8]> {
    let n = v.len();
    if n > 2 && v[0] == 0x04 && v[1] != 0x04 && usize::from(v[1]) + 2 == n {
        return Some(&v[2..]);
    }
    if n > 3 && v[0] == 0x04 && v[1] == 0x81 && usize::from(v[2]) + 3 == n {
        return Some(&v[3..]);
    }
    if n > 4 && v[0] == 0x04 && v[1] == 0x82 {
        let l = (usize::from(v[2]) << 8) | usize::from(v[3]);
        if l + 4 == n {
            return Some(&v[4..]);
        }
    }
    None
}

/// `fhsm_parse_create_attrs`. Like C it returns what it filled in before a failure too.
pub fn parse<'a>(t: &[In<'a>]) -> (Parsed<'a>, Rv) {
    let mut a = Parsed {
        path: Path::Invalid,
        cko: 0,
        ckk: 0,
        cert_type: 0,
        label: [0; 64],
        id: None,
        value: None,
        pqc_alg: None,
        ec_group: None,
        ec_point: None,
        rsa: [None; 8],
    };
    let rv = fill(t, &mut a);
    (a, rv)
}

fn fill<'a>(t: &[In<'a>], a: &mut Parsed<'a>) -> Rv {
    if t.is_empty() {
        return Rv::TemplateIncomplete;
    }
    let Some(cko) = read_ulong(t, CKA_CLASS) else {
        return Rv::TemplateIncomplete;
    };
    a.cko = cko;
    if ![
        CKO_DATA,
        CKO_PUBLIC_KEY,
        CKO_PRIVATE_KEY,
        CKO_SECRET_KEY,
        CKO_CERTIFICATE,
    ]
    .contains(&cko)
    {
        return Rv::TemplateInconsistent;
    }
    if let Some(l) = find(t, CKA_LABEL) {
        let v = l.value.unwrap_or(&[]);
        let n = v.len().min(a.label.len() - 1);
        a.label[..n].copy_from_slice(&v[..n]);
    }
    if let Some(i) = find(t, CKA_ID) {
        a.id = i.value;
    }

    // A data object: no key type, CKA_VALUE optional, stored verbatim.
    if cko == CKO_DATA {
        a.value = find(t, CKA_VALUE).and_then(|v| v.value);
        a.path = Path::Verbatim;
        return Rv::Ok;
    }
    // A certificate: CKA_CERTIFICATE_TYPE, X.509 only, the DER in CKA_VALUE.
    if cko == CKO_CERTIFICATE {
        let Some(ct) = read_ulong(t, CKA_CERTIFICATE_TYPE) else {
            return Rv::TemplateIncomplete;
        };
        a.cert_type = ct;
        if ct != CKC_X_509 {
            return Rv::TemplateInconsistent;
        }
        match find(t, CKA_VALUE).and_then(|v| v.value) {
            Some(v) if !v.is_empty() => a.value = Some(v),
            _ => return Rv::TemplateIncomplete,
        }
        a.path = Path::CertX509;
        return Rv::Ok;
    }
    let Some(ckk) = read_ulong(t, CKA_KEY_TYPE) else {
        return Rv::TemplateIncomplete;
    };
    a.ckk = ckk;
    // An EC private key with no curve is refused rather than stored curveless.
    if cko == CKO_PRIVATE_KEY && ckk == CKK_EC && find(t, CKA_EC_PARAMS).is_none() {
        return Rv::TemplateInconsistent;
    }
    // RSA private components, only when CKA_VALUE is absent.
    if cko == CKO_PRIVATE_KEY && ckk == CKK_RSA && find(t, CKA_VALUE).is_none() {
        return rsa_priv(t, a);
    }
    if cko == CKO_SECRET_KEY || cko == CKO_PRIVATE_KEY {
        let Some(v) = find(t, CKA_VALUE) else {
            return Rv::TemplateIncomplete;
        };
        a.value = v.value;
        a.path = Path::Verbatim;
        return Rv::Ok;
    }
    // CKO_PUBLIC_KEY.
    match ckk {
        CKK_ML_KEM | CKK_ML_DSA | CKK_SLH_DSA => pqc_pub(t, a),
        CKK_EC => ec_pub(t, a),
        CKK_EC_EDWARDS => ed_pub(t, a),
        CKK_RSA => {
            let (Some(m), Some(e)) = (find(t, CKA_MODULUS), find(t, CKA_PUBLIC_EXPONENT)) else {
                return Rv::TemplateIncomplete;
            };
            a.rsa[0] = m.value;
            a.rsa[1] = e.value;
            a.path = Path::RsaPub;
            Rv::Ok
        }
        _ => Rv::TemplateInconsistent,
    }
}

/// n, e and d required (absent, NULL or empty is missing); the CRT five optional.
fn rsa_priv<'a>(t: &[In<'a>], a: &mut Parsed<'a>) -> Rv {
    let kinds = [
        CKA_MODULUS,
        CKA_PUBLIC_EXPONENT,
        CKA_PRIVATE_EXPONENT,
        CKA_PRIME_1,
        CKA_PRIME_2,
        CKA_EXPONENT_1,
        CKA_EXPONENT_2,
        CKA_COEFFICIENT,
    ];
    for (i, k) in kinds.into_iter().enumerate() {
        match find(t, k).and_then(|x| x.value).filter(|v| !v.is_empty()) {
            Some(v) => a.rsa[i] = Some(v),
            None if i < 3 => return Rv::TemplateIncomplete,
            None => {}
        }
    }
    a.path = Path::RsaPriv;
    Rv::Ok
}

/// A PQC public key: CKA_VALUE raw or DER; only a raw length names the set here.
fn pqc_pub<'a>(t: &[In<'a>], a: &mut Parsed<'a>) -> Rv {
    let Some(v) = find(t, CKA_VALUE) else {
        return Rv::TemplateIncomplete;
    };
    let Some(v) = v.value.filter(|v| !v.is_empty()) else {
        return Rv::AttributeValueInvalid;
    };
    a.value = Some(v);
    // SLH-DSA has none: each of its lengths is four sets, named by CKA_PARAMETER_SET.
    let family: &[u8] = if a.ckk == CKK_ML_KEM {
        b"ML-KEM"
    } else {
        b"ML-DSA"
    };
    if a.ckk != CKK_SLH_DSA {
        a.pqc_alg = PQC_PUB_LENS
            .iter()
            .find(|(l, alg)| *l == v.len() && alg.to_bytes().starts_with(family))
            .map(|(_, alg)| *alg);
    }
    a.path = Path::PqcPub;
    Rv::Ok
}

fn ec_pub<'a>(t: &[In<'a>], a: &mut Parsed<'a>) -> Rv {
    let (Some(p), Some(pt)) = (find(t, CKA_EC_PARAMS), find(t, CKA_EC_POINT)) else {
        return Rv::TemplateIncomplete;
    };
    let oid = p.value.unwrap_or(&[]);
    let Some((_, group)) = EC_OIDS.iter().find(|(o, _)| *o == oid) else {
        return Rv::CurveNotInTable;
    };
    a.ec_group = Some(group);
    let Some(point) = strip_octet_string(pt.value.unwrap_or(&[])) else {
        return Rv::AttributeValueInvalid;
    };
    a.ec_point = Some(point);
    a.path = Path::EcPub;
    Rv::Ok
}

/// An Edwards public key: the point wrapped or bare, either way the curve's key length.
fn ed_pub<'a>(t: &[In<'a>], a: &mut Parsed<'a>) -> Rv {
    let (Some(p), Some(pt)) = (find(t, CKA_EC_PARAMS), find(t, CKA_EC_POINT)) else {
        return Rv::TemplateIncomplete;
    };
    let (path, bare) = match p.value.unwrap_or(&[]) {
        ED25519_OID => (Path::Ed25519Pub, ED25519_LEN),
        ED448_OID => (Path::Ed448Pub, ED448_LEN),
        _ => return Rv::AttributeValueInvalid,
    };
    let raw = pt.value.unwrap_or(&[]);
    let point = match strip_octet_string(raw) {
        Some(inner) if inner.len() == bare => inner,
        Some(_) => return Rv::AttributeValueInvalid,
        None if raw.len() == bare => raw,
        None => return Rv::AttributeValueInvalid,
    };
    a.ec_point = Some(point);
    a.ec_group = None;
    a.path = path;
    Rv::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ul(v: c_ulong) -> Vec<u8> {
        v.to_ne_bytes().to_vec()
    }

    fn row(kind: c_ulong, v: &[u8]) -> In<'_> {
        In {
            kind,
            value: Some(v),
        }
    }

    #[test]
    fn each_path_as_c_s() {
        let (sec, aes) = (ul(CKO_SECRET_KEY), ul(0x1F));
        let k = [0u8; 16];
        let (p, rv) = parse(&[
            row(CKA_CLASS, &sec),
            row(CKA_KEY_TYPE, &aes),
            row(CKA_VALUE, &k),
        ]);
        assert_eq!(
            (rv, p.path, p.value.map(<[u8]>::len)),
            (Rv::Ok, Path::Verbatim, Some(16))
        );

        let (pubk, ec) = (ul(CKO_PUBLIC_KEY), ul(CKK_EC));
        let mut point = vec![0x04, 65, 0x04];
        point.extend([7u8; 64]);
        let (p, rv) = parse(&[
            row(CKA_CLASS, &pubk),
            row(CKA_KEY_TYPE, &ec),
            row(CKA_EC_PARAMS, EC_OIDS[1].0),
            row(CKA_EC_POINT, &point),
        ]);
        assert_eq!(
            (rv, p.path, p.ec_group),
            (Rv::Ok, Path::EcPub, Some(c"P-384"))
        );
        assert_eq!(p.ec_point.map(<[u8]>::len), Some(65));

        let ed = ul(CKK_EC_EDWARDS);
        let bare = [1u8; 32];
        let (p, rv) = parse(&[
            row(CKA_CLASS, &pubk),
            row(CKA_KEY_TYPE, &ed),
            row(CKA_EC_PARAMS, ED25519_OID),
            row(CKA_EC_POINT, &bare),
        ]);
        assert_eq!((rv, p.path), (Rv::Ok, Path::Ed25519Pub));

        let (mlkem, raw) = (ul(CKK_ML_KEM), vec![0u8; 1312]);
        let (p, rv) = parse(&[
            row(CKA_CLASS, &pubk),
            row(CKA_KEY_TYPE, &mlkem),
            row(CKA_VALUE, &raw),
        ]);
        // 1312 is ML-DSA-44's length: not a set of the family the key type names.
        assert_eq!((rv, p.path, p.pqc_alg), (Rv::Ok, Path::PqcPub, None));

        let (prv, rsa) = (ul(CKO_PRIVATE_KEY), ul(CKK_RSA));
        let (p, rv) = parse(&[
            row(CKA_CLASS, &prv),
            row(CKA_KEY_TYPE, &rsa),
            row(CKA_MODULUS, &k),
        ]);
        assert_eq!((rv, p.path), (Rv::TemplateIncomplete, Path::Invalid));

        let nine = ul(9);
        let (p, rv) = parse(&[row(CKA_CLASS, &nine)]);
        assert_eq!((rv, p.cko), (Rv::TemplateInconsistent, 9));
        assert_eq!(parse(&[]).1, Rv::TemplateIncomplete);
    }

    #[test]
    fn octet_string_forms() {
        assert_eq!(strip_octet_string(&[0x04, 1, 9]), Some(&[9u8][..]));
        assert_eq!(strip_octet_string(&[0x04, 0x04, 9, 9, 9, 9]), None);
        let mut l1 = vec![0x04, 0x81, 200];
        l1.extend([0u8; 200]);
        assert_eq!(strip_octet_string(&l1).map(<[u8]>::len), Some(200));
        let mut l2 = vec![0x04, 0x82, 1, 0];
        l2.extend([0u8; 256]);
        assert_eq!(strip_octet_string(&l2).map(<[u8]>::len), Some(256));
        assert_eq!(strip_octet_string(&[0x04, 2, 9]), None);
    }

    /// Types the parser reads, so random templates reach every path.
    const KINDS: [c_ulong; 16] = [
        CKA_CLASS,
        CKA_LABEL,
        CKA_VALUE,
        CKA_CERTIFICATE_TYPE,
        CKA_KEY_TYPE,
        CKA_ID,
        CKA_MODULUS,
        CKA_PUBLIC_EXPONENT,
        CKA_PRIVATE_EXPONENT,
        CKA_PRIME_1,
        CKA_COEFFICIENT,
        CKA_EC_PARAMS,
        CKA_EC_POINT,
        0x1,
        0x162,
        0xdead,
    ];

    fn value() -> impl Strategy<Value = Option<Vec<u8>>> {
        prop_oneof![
            Just(None),
            (0..5 as c_ulong).prop_map(|c| Some(ul(c))),
            prop_oneof![
                Just(0x3 as c_ulong),
                Just(0x40),
                Just(0x49),
                Just(0x4A),
                Just(0x4B),
                Just(0x0)
            ]
            .prop_map(|k| Some(ul(k))),
            Just(Some(EC_OIDS[0].0.to_vec())),
            Just(Some(ED25519_OID.to_vec())),
            Just(Some([0x04, 32].into_iter().chain([5u8; 32]).collect())),
            proptest::collection::vec(any::<u8>(), 0..80).prop_map(Some),
            Just(Some(vec![0u8; 1184])),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        /// fuzz_create_attrs.c's properties: no panic; a success has a path and a supported
        /// class, a failure none; the label is terminated; every slice points into the template.
        #[test]
        fn parse_holds_c_s_invariants(
            rows in proptest::collection::vec((0..KINDS.len(), value()), 0..10),
        ) {
            let t: Vec<In<'_>> = rows
                .iter()
                .map(|(k, v)| In { kind: KINDS[*k], value: v.as_deref() })
                .collect();
            let (p, rv) = parse(&t);
            prop_assert!(p.label.contains(&0));
            if rv == Rv::Ok {
                prop_assert_ne!(p.path, Path::Invalid);
                prop_assert!(p.cko <= 4);
            } else {
                prop_assert_eq!(p.path, Path::Invalid);
            }
            let inside = |s: &[u8]| {
                t.iter().filter_map(|a| a.value).any(|v| {
                    let r = v.as_ptr_range();
                    r.start <= s.as_ptr() && s.as_ptr_range().end <= r.end
                })
            };
            for s in [p.id, p.value, p.ec_point].into_iter().chain(p.rsa).flatten() {
                prop_assert!(inside(s));
            }
        }
    }
}
