//! The objects on a token: listing them, describing one, destroying one; and the keys that do
//! not sign (`tools/pkiops.c`, docs/fhsm-crypt-plan.md stages 0 and 1; PHASE5_PLAN.md slice 3).
//! Each is C's, call for call and message for message. The records are `pkiops.h`'s structs,
//! so the C exports copy them out whole and `fhsm-crypt` prints what C's printed.

use std::ffi::{CStr, c_char, c_int, c_long, c_ulong};
use std::ptr::null_mut;

use crate::Error;
use crate::calllog::mech_name;
use crate::ffi::{
    CK_ATTRIBUTE, CK_MECHANISM, CK_ULONG, has, w_destroy_object, w_find_objects,
    w_find_objects_final, w_find_objects_init, w_generate_key, w_generate_key_pair,
    w_get_attribute_value,
};
use crate::keys::{self, OID_ED25519, OID_P256, OID_P384, SKEY, Skey};
use crate::ops::{
    CKA_ALLOWED_MECHANISMS, CKA_CLASS, CKA_EC_PARAMS, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS,
    CKA_MODULUS_BITS, CKA_PARAMETER_SET, CKA_PUBLIC_EXPONENT, CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN,
    CKA_VALUE, CKA_VERIFY, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY, Handle, alg_of, at,
    at_ul, get_attr, get_ulong, text,
};

const CKO_CERTIFICATE: CK_ULONG = 1;
const CKA_PRIVATE: CK_ULONG = 0x002;
const CKA_ID: CK_ULONG = 0x102;
const CKA_ENCRYPT: CK_ULONG = 0x104;
const CKA_DECRYPT: CK_ULONG = 0x105;
const CKA_WRAP: CK_ULONG = 0x106;
const CKA_UNWRAP: CK_ULONG = 0x107;
const CKA_DERIVE: CK_ULONG = 0x10C;
pub(crate) const CKA_VALUE_LEN: CK_ULONG = 0x161;
const CKA_EXTRACTABLE: CK_ULONG = 0x162;
pub(crate) const CKM_RSA_PKCS_OAEP: CK_ULONG = 0x9;

/// `enum pkiops_obj_class`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ObjClass {
    Cert = 0,
    Public,
    Private,
    Secret,
}

/// `PKIOPS_OBJS_*`: masks of `1 << ObjClass`.
pub const OBJS_CERTS: u32 = 1 << ObjClass::Cert as u32;
pub const OBJS_KEYS: u32 =
    1 << ObjClass::Public as u32 | 1 << ObjClass::Private as u32 | 1 << ObjClass::Secret as u32;
pub const OBJS_ALL: u32 = OBJS_CERTS | OBJS_KEYS;

impl ObjClass {
    const ALL: [ObjClass; 4] = [
        ObjClass::Cert,
        ObjClass::Public,
        ObjClass::Private,
        ObjClass::Secret,
    ];

    pub fn from_index(i: u32) -> Option<ObjClass> {
        Self::ALL.get(i as usize).copied()
    }

    /// `pkiops_obj_class_name`.
    pub fn name(self) -> &'static CStr {
        match self {
            ObjClass::Cert => c"certificate",
            ObjClass::Public => c"public key",
            ObjClass::Private => c"private key",
            ObjClass::Secret => c"secret key",
        }
    }

    fn cko(self) -> CK_ULONG {
        match self {
            ObjClass::Cert => CKO_CERTIFICATE,
            ObjClass::Public => CKO_PUBLIC_KEY,
            ObjClass::Private => CKO_PRIVATE_KEY,
            ObjClass::Secret => CKO_SECRET_KEY,
        }
    }
}

/// `struct pkiops_key`. Text fields are NUL-terminated; [`text`] reads them.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Key {
    pub handle: Handle,
    pub is_private: c_int,
    /// CKA_KEY_TYPE.
    pub key_type: c_ulong,
    /// Cut at 64 bytes.
    pub label: [u8; 65],
    /// The name of the algorithm it signs with, or "" for a key these tools do not sign with
    /// or whose label is not unique.
    pub alg: [u8; 16],
}

/// `struct pkiops_object`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Object {
    pub handle: Handle,
    pub cls: ObjClass,
    /// CKA_KEY_TYPE; 0 for a certificate.
    pub key_type: c_ulong,
    /// Cut at 64 bytes; "" if none.
    pub label: [u8; 65],
    /// CKA_ID in hex, its first 20 bytes; "" if none.
    pub id: [u8; 41],
    /// A secret key's kind ("aes256", "hmac"), "rsa-oaep" for an OAEP pair; else "".
    pub alg: [u8; 16],
}

/// `struct pkiops_attr`: one line of `show`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Attr {
    pub name: [u8; 28],
    pub value: [u8; 220],
}

/// A fixed C field holding `s`, cut to leave its NUL, as `snprintf("%s")` and C's copies fill
/// them.
fn fill<const N: usize>(s: &[u8]) -> [u8; N] {
    let mut f = [0u8; N];
    let n = s.len().min(N - 1);
    f[..n].copy_from_slice(&s[..n]);
    f
}

/// `snprintf(buf + *used, cap - *used, ...)` of `piece`, as C's comma lists build: the length
/// advances only when the piece fits whole, but a piece that does not still leaves its cut
/// text in the buffer, where a later piece that fits writes over it.
pub(crate) fn append_capped(buf: &mut Vec<u8>, used: &mut usize, cap: usize, piece: &[u8]) {
    buf.truncate(*used);
    let room = cap - *used;
    if piece.len() < room {
        buf.extend(piece);
        *used += piece.len();
    } else {
        buf.extend(&piece[..room - 1]);
    }
}

/// One attribute into a buffer of C's size: its length when the module answered (a length
/// past the buffer is the module's to answer for; callers cut it).
fn read_into(s: Handle, h: Handle, type_: CK_ULONG, buf: &mut [u8]) -> Option<usize> {
    let mut a = CK_ATTRIBUTE {
        type_,
        p_value: buf.as_mut_ptr().cast(),
        value_len: buf.len() as CK_ULONG,
    };
    // SAFETY: buf.len() writable bytes.
    let rv = unsafe { w_get_attribute_value(s, h, &mut a, 1) };
    (rv == 0).then_some(a.value_len as usize)
}

/// A CK_ULONG attribute the way the listing reads it: answered or not, its length unchecked.
fn read_ulong(s: Handle, h: Handle, type_: CK_ULONG) -> Option<CK_ULONG> {
    let mut b = [0u8; size_of::<CK_ULONG>()];
    read_into(s, h, type_, &mut b).map(|_| CK_ULONG::from_ne_bytes(b))
}

/// The objects of class `cls`, 16 handles a search call, each handed to `each` before the
/// next call (as C reads their attributes inside the search); the search is finished
/// whatever happens.
fn search(s: Handle, cls: CK_ULONG, mut each: impl FnMut(Handle)) -> Result<(), Error> {
    let c = cls;
    let mut t = [at_ul(CKA_CLASS, &c)];
    // SAFETY: a template of 1 whose value outlives the search.
    let rv = unsafe { w_find_objects_init(s, t.as_mut_ptr(), 1) };
    if rv != 0 {
        return Err(Error::new(
            2,
            format!("C_FindObjectsInit failed (0x{rv:x})\n"),
        ));
    }
    loop {
        let (mut h, mut got): ([Handle; 16], CK_ULONG) = ([0; 16], 0);
        // SAFETY: room for 16 handles, and got writable.
        let rv = unsafe { w_find_objects(s, h.as_mut_ptr(), 16, &mut got) };
        if rv != 0 {
            // SAFETY: a plain handle.
            unsafe { w_find_objects_final(s) };
            return Err(Error::new(2, format!("C_FindObjects failed (0x{rv:x})\n")));
        }
        // A module that claims more than it was given room for gets the room's worth.
        h[..(got as usize).min(16)].iter().for_each(|&x| each(x));
        if got < 16 {
            break;
        }
    }
    // SAFETY: a plain handle.
    unsafe { w_find_objects_final(s) };
    Ok(())
}

// --- keys -----------------------------------------------------------------------------------

/// `pkiops_keys`: the key pairs' halves a session can see, public then private, each with the
/// algorithm it signs with when that can be read.
pub fn keys(s: Handle) -> Result<Vec<Key>, Error> {
    let mut v = Vec::new();
    for cls in [CKO_PUBLIC_KEY, CKO_PRIVATE_KEY] {
        search(s, cls, |h| {
            let mut k = Key {
                handle: h,
                is_private: c_int::from(cls == CKO_PRIVATE_KEY),
                key_type: 0,
                label: [0; 65],
                alg: [0; 16],
            };
            let (mut lbl, mut kt) = ([0u8; 256], 0 as CK_ULONG);
            let mut a = [
                CK_ATTRIBUTE {
                    type_: CKA_LABEL,
                    p_value: lbl.as_mut_ptr().cast(),
                    value_len: lbl.len() as CK_ULONG,
                },
                CK_ATTRIBUTE {
                    type_: CKA_KEY_TYPE,
                    p_value: (&raw mut kt).cast(),
                    value_len: size_of::<CK_ULONG>() as CK_ULONG,
                },
            ];
            // A key without a label, or one too long for the buffer, still lists: the handle
            // identifies it, the label only names it.
            // SAFETY: both buffers writable for their lengths.
            if unsafe { w_get_attribute_value(s, h, a.as_mut_ptr(), 2) } == 0 {
                k.label = fill(&lbl[..(a[0].value_len as usize).min(lbl.len())]);
                k.key_type = kt;
            }
            v.push(k);
        })?;
    }
    // Each key's algorithm once the searches are over: reading it may need a search of its own
    // (the public half's curve or parameter set), and a session holds one at a time.
    for k in &mut v {
        let label = text(&k.label).to_vec();
        if !label.is_empty()
            && let Ok(a) = alg_of(s, &label, k.handle)
        {
            k.alg = fill(a.info().name.to_bytes());
        }
    }
    Ok(v)
}

// --- objects ----------------------------------------------------------------------------------

/// `objects_of_class`: one attribute a call, so a module that does not keep one (CKA_ID, a
/// certificate's CKA_KEY_TYPE) loses that field and not the label asked beside it.
fn objects_of_class(s: Handle, oc: ObjClass, v: &mut Vec<Object>) -> Result<(), Error> {
    search(s, oc.cko(), |h| {
        let mut o = Object {
            handle: h,
            cls: oc,
            key_type: 0,
            label: [0; 65],
            id: [0; 41],
            alg: [0; 16],
        };
        let mut lbl = [0u8; 256];
        if let Some(n) = read_into(s, h, CKA_LABEL, &mut lbl) {
            o.label = fill(&lbl[..n.min(lbl.len())]);
        }
        let mut id = [0u8; 64];
        if let Some(n) = read_into(s, h, CKA_ID, &mut id) {
            let hex: String = id[..n.min(20)].iter().map(|b| format!("{b:02x}")).collect();
            o.id = fill(hex.as_bytes());
        }
        if oc != ObjClass::Cert
            && let Some(kt) = read_ulong(s, h, CKA_KEY_TYPE)
        {
            o.key_type = kt;
        }
        // An RSA key whose one allowed mechanism is OAEP is an encryption key, which the
        // signing names would leave unnamed.
        if matches!(oc, ObjClass::Public | ObjClass::Private)
            && o.key_type == keys::CKK_RSA
            && let Ok(am) = get_attr(s, h, CKA_ALLOWED_MECHANISMS)
            && am.len() == size_of::<CK_ULONG>()
            && CK_ULONG::from_ne_bytes(am[..].try_into().expect("one CK_ULONG"))
                == CKM_RSA_PKCS_OAEP
        {
            o.alg = fill(b"rsa-oaep");
        }
        // A secret key is named by its type and CKA_VALUE_LEN, which a sensitive key still
        // answers: the length is not the value.
        if oc == ObjClass::Secret
            && let Some(vl) = read_ulong(s, h, CKA_VALUE_LEN)
        {
            let name = SKEY
                .iter()
                .rfind(|k| k.keytype == o.key_type && k.len == vl)
                .map(|k| k.name.to_bytes().to_vec());
            o.alg = fill(&name.unwrap_or_else(|| {
                if o.key_type == keys::CKK_AES {
                    format!("aes{}", vl.wrapping_mul(8)).into_bytes()
                } else {
                    format!("secret-{vl}").into_bytes()
                }
            }));
        }
        v.push(o);
    })
}

/// `pkiops_objects`: the objects of the classes in `classes` (a mask of `OBJS_*`) a session can
/// see, certificates first.
pub fn objects(s: Handle, classes: u32) -> Result<Vec<Object>, Error> {
    let mut v = Vec::new();
    for oc in ObjClass::ALL {
        if classes & (1 << oc as u32) != 0 {
            objects_of_class(s, oc, &mut v)?;
        }
    }
    Ok(v)
}

/// `pkiops_destroy`: cannot be undone, so the caller asks first.
pub fn destroy(s: Handle, object: Handle) -> Result<(), Error> {
    if !has("DestroyObject") {
        return Err(Error::new(
            2,
            "the module does not implement C_DestroyObject\n",
        ));
    }
    // SAFETY: plain handles.
    let rv = unsafe { w_destroy_object(s, object) };
    if rv != 0 {
        return Err(Error::new(
            2,
            format!("C_DestroyObject failed (0x{rv:x})\n"),
        ));
    }
    Ok(())
}

// --- an object's attributes, as a person reads them ------------------------------------------

/// `ATTRS_MAX`: lines past it are dropped, as C's fixed array drops them.
const ATTRS_MAX: usize = 40;

struct Lines(Vec<Attr>);

impl Lines {
    fn add(&mut self, name: &str, value: impl AsRef<[u8]>) {
        if self.0.len() < ATTRS_MAX {
            self.0.push(Attr {
                name: fill(name.as_bytes()),
                value: fill(value.as_ref()),
            });
        }
    }

    fn yes_no(&mut self, s: Handle, h: Handle, name: &str, type_: CK_ULONG) {
        if let Some(b) = attr_bool(s, h, type_) {
            self.add(name, if b { "yes" } else { "no" });
        }
    }
}

/// A CK_BBOOL, or None when the module does not answer it.
fn attr_bool(s: Handle, h: Handle, type_: CK_ULONG) -> Option<bool> {
    let mut b = [0u8; 1];
    match read_into(s, h, type_, &mut b) {
        Some(1) => Some(b[0] != 0),
        _ => None,
    }
}

fn attr_ul(s: Handle, h: Handle, type_: CK_ULONG) -> Option<CK_ULONG> {
    get_ulong(s, h, type_).ok()
}

fn key_type_name(kt: CK_ULONG) -> Option<&'static str> {
    Some(match kt {
        0x00 => "RSA",
        0x03 => "EC",
        0x10 => "generic secret",
        0x1F => "AES",
        0x40 => "EC Edwards",
        0x41 => "EC Montgomery",
        0x49 => "ML-KEM",
        0x4A => "ML-DSA",
        0x8000_4202 => "composite ML-DSA-65 + Ed25519",
        _ => return None,
    })
}

/// CKA_EC_PARAMS, named when it is one of the curves this project meets.
fn curve_name(p: &[u8]) -> Option<&'static str> {
    const P521: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23];
    const ED448: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x71];
    const X25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6E];
    const X448: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6F];
    let named = [
        (OID_P256, "P-256"),
        (OID_P384, "P-384"),
        (P521, "P-521"),
        (OID_ED25519, "Ed25519"),
        (ED448, "Ed448"),
        (X25519, "X25519"),
        (X448, "X448"),
    ];
    if let Some(&(_, n)) = named.iter().find(|(oid, _)| *oid == p) {
        return Some(n);
    }
    // PKCS#11 v3 also allows a PrintableString curve name for Edwards keys.
    match p {
        [0x13, l, name @ ..] if *l as usize == name.len() && name == b"edwards25519" => {
            Some("Ed25519")
        }
        [0x13, l, name @ ..] if *l as usize == name.len() && name == b"edwards448" => Some("Ed448"),
        _ => None,
    }
}

unsafe extern "C" {
    /// Not bound by openssl-sys.
    fn X509_NAME_print_ex(
        out: *mut openssl_sys::BIO,
        nm: *const openssl_sys::X509_NAME,
        indent: c_int,
        flags: c_ulong,
    ) -> c_int;
}

/// `XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB`: RFC 2253 escaping, quotes, ", " and " = "
/// separators, short names; UTF-8 left as UTF-8.
const NAME_FLAGS: c_ulong = 0x0082_031B;

/// `bio_text`: what `print` writes into a memory BIO, cut to `cap - 1` bytes; nothing when no
/// BIO could be had.
///
/// # Safety
/// `print` writes only to the BIO it is given.
unsafe fn bio_text(cap: usize, print: impl FnOnce(*mut openssl_sys::BIO)) -> Option<Vec<u8>> {
    // SAFETY: a fresh memory BIO, freed below; buf has cap - 1 writable bytes.
    unsafe {
        let b = openssl_sys::BIO_new(openssl_sys::BIO_s_mem());
        if b.is_null() {
            return None;
        }
        print(b);
        let mut buf = vec![0u8; cap - 1];
        let r = openssl_sys::BIO_read(b, buf.as_mut_ptr().cast(), (cap - 1) as c_int);
        openssl_sys::BIO_free_all(b);
        buf.truncate(r.max(0) as usize);
        Some(buf)
    }
}

/// A certificate's lines: its type, trust, and from its DER subject, issuer, serial and
/// validity.
fn cert_attrs(o: &mut Lines, s: Handle, h: Handle) {
    if let Some(ct) = attr_ul(s, h, 0x80) {
        o.add("certificate type", if ct == 0 { "X.509" } else { "other" });
    }
    o.yes_no(s, h, "trusted", 0x86);
    let Ok(der) = get_attr(s, h, CKA_VALUE) else {
        return;
    };
    // SAFETY: der is readable for its length; every object made here is freed here, and the
    // names, serial and times borrowed from x are used before x is freed.
    unsafe {
        let mut p = der.as_ptr();
        let x = openssl_sys::d2i_X509(null_mut(), &mut p, der.len() as c_long);
        if x.is_null() {
            o.add(
                "value",
                format!("{} bytes, not a DER certificate", der.len()),
            );
            return;
        }
        for (name, xn) in [
            ("subject", openssl_sys::X509_get_subject_name(x)),
            ("issuer", openssl_sys::X509_get_issuer_name(x)),
        ] {
            if let Some(t) = bio_text(256, |b| {
                X509_NAME_print_ex(b, xn, 0, NAME_FLAGS);
            }) {
                o.add(name, t);
            }
        }
        let bn = openssl_sys::ASN1_INTEGER_to_BN(openssl_sys::X509_get_serialNumber(x), null_mut());
        let hex: *mut c_char = if bn.is_null() {
            null_mut()
        } else {
            openssl_sys::BN_bn2hex(bn)
        };
        if !hex.is_null() {
            o.add("serial", CStr::from_ptr(hex).to_bytes());
            openssl_sys::CRYPTO_free(hex.cast(), c"pkiops".as_ptr(), 0);
        }
        openssl_sys::BN_free(bn);
        for (name, t) in [
            ("valid from", openssl_sys::X509_getm_notBefore(x)),
            ("valid until", openssl_sys::X509_getm_notAfter(x)),
        ] {
            if let Some(v) = bio_text(64, |b| {
                openssl_sys::ASN1_TIME_print(b, t);
            }) {
                o.add(name, v);
            }
        }
        openssl_sys::X509_free(x);
    }
}

/// A key's lines: type, size, usage, allowed mechanisms, protection, origin. A private or
/// secret key's value is never asked for.
fn key_attrs(o: &mut Lines, s: Handle, h: Handle, oc: ObjClass) {
    let kt = attr_ul(s, h, CKA_KEY_TYPE);
    if let Some(kt) = kt {
        match key_type_name(kt) {
            Some(n) => o.add("key type", n),
            None => o.add("key type", format!("0x{kt:x}")),
        }
    }

    // Size, the way each family states it.
    match kt {
        Some(0x00) => {
            if let Some(v) = attr_ul(s, h, CKA_MODULUS_BITS) {
                o.add("size", format!("{v} bits"));
            } else if let Ok(b) = get_attr(s, h, CKA_MODULUS) {
                let z = b.iter().take_while(|&&x| x == 0).count();
                o.add("size", format!("{} bits", (b.len() - z) * 8));
            }
        }
        Some(0x03 | 0x40 | 0x41) => {
            if let Ok(b) = get_attr(s, h, CKA_EC_PARAMS) {
                match curve_name(&b) {
                    Some(c) => o.add("curve", c),
                    None => o.add(
                        "curve",
                        format!("{}-byte parameters, not one named here", b.len()),
                    ),
                }
            }
        }
        Some(t @ (0x49 | 0x4A)) => {
            if let Some(v) = attr_ul(s, h, CKA_PARAMETER_SET) {
                const DSA: [&str; 4] = ["?", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"];
                const KEM: [&str; 4] = ["?", "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"];
                let names = if t == 0x4A { DSA } else { KEM };
                o.add(
                    "parameter set",
                    names.get(v as usize).copied().unwrap_or("?"),
                );
            }
        }
        _ => {
            if oc == ObjClass::Secret
                && let Some(v) = attr_ul(s, h, CKA_VALUE_LEN)
            {
                o.add("size", format!("{} bits", v.wrapping_mul(8)));
            }
        }
    }

    // What it may be used for: the usage attributes that are set.
    const USE: [(CK_ULONG, &str); 11] = [
        (0x104, "encrypt"),
        (0x105, "decrypt"),
        (0x106, "wrap"),
        (0x107, "unwrap"),
        (0x108, "sign"),
        (0x109, "sign-recover"),
        (0x10A, "verify"),
        (0x10B, "verify-recover"),
        (0x10C, "derive"),
        (0x633, "encapsulate"),
        (0x634, "decapsulate"),
    ];
    let (mut use_, mut ul) = (Vec::new(), 0);
    for (t, name) in USE {
        if attr_bool(s, h, t) == Some(true) {
            let piece = [if ul > 0 { ", " } else { "" }, name].concat();
            append_capped(&mut use_, &mut ul, 200, piece.as_bytes());
        }
    }
    o.add("usage", if ul > 0 { &use_[..] } else { b"none" });

    // CKA_ALLOWED_MECHANISMS: absent or empty means any the key type allows.
    if let Ok(b) = get_attr(s, h, CKA_ALLOWED_MECHANISMS) {
        let (mut m, mut ml) = (Vec::new(), 0);
        for c in b.as_chunks::<{ size_of::<CK_ULONG>() }>().0 {
            let piece = [
                if ml > 0 { ", " } else { "" },
                &mech_name(CK_ULONG::from_ne_bytes(*c)),
            ]
            .concat();
            append_capped(&mut m, &mut ml, 200, piece.as_bytes());
        }
        o.add("allowed mechanisms", if ml > 0 { &m[..] } else { b"any" });
    }

    if oc != ObjClass::Public {
        o.yes_no(s, h, "sensitive", CKA_SENSITIVE);
        o.yes_no(s, h, "always sensitive", 0x165);
        o.yes_no(s, h, "extractable", CKA_EXTRACTABLE);
        o.yes_no(s, h, "never extractable", 0x164);
        o.yes_no(s, h, "always authenticate", 0x202);
        o.yes_no(s, h, "wrap with trusted only", 0x210);
    }
    o.yes_no(s, h, "generated on the token", 0x163);
    if let Some(v) = attr_ul(s, h, 0x166)
        && v != CK_ULONG::MAX
    {
        o.add("generated with", &*mech_name(v));
    }
}

/// `pkiops_object_attrs`: one object's attributes as name/value lines, each read on its own;
/// one the module does not keep is left out.
pub fn object_attrs(s: Handle, h: Handle) -> Result<Vec<Attr>, Error> {
    // The class is asked, not taken from the list: a handle gone stale since says so here.
    let Some(c) = attr_ul(s, h, CKA_CLASS) else {
        return Err(Error::new(
            2,
            format!("object {h} does not answer (it may have been deleted)\n"),
        ));
    };
    let oc = match c {
        CKO_CERTIFICATE => ObjClass::Cert,
        CKO_PUBLIC_KEY => ObjClass::Public,
        CKO_PRIVATE_KEY => ObjClass::Private,
        _ => ObjClass::Secret,
    };
    let mut o = Lines(Vec::with_capacity(ATTRS_MAX));
    o.add("class", oc.name().to_bytes());
    let mut lbl = [0u8; 256];
    if let Some(n) = read_into(s, h, CKA_LABEL, &mut lbl[..255]) {
        o.add("label", text(&lbl[..n.min(255)]));
    }
    let mut id = [0u8; 64];
    if let Some(n) = read_into(s, h, CKA_ID, &mut id)
        && (1..=id.len()).contains(&n)
    {
        let hex: String = id[..n].iter().map(|b| format!("{b:02x}")).collect();
        o.add("CKA_ID", hex);
    }
    o.yes_no(s, h, "on the token", CKA_TOKEN);
    o.yes_no(s, h, "private", CKA_PRIVATE);
    o.yes_no(s, h, "modifiable", 0x170);
    o.yes_no(s, h, "destroyable", 0x172);
    if oc == ObjClass::Cert {
        cert_attrs(&mut o, s, h);
    } else {
        key_attrs(&mut o, s, h, oc);
    }
    Ok(o.0)
}

// --- keys that do not sign --------------------------------------------------------------------

/// `keygen_oaep`: RSA 3072 for RSA-OAEP and nothing else. CKA_ALLOWED_MECHANISMS names OAEP
/// alone on both halves, so the pair cannot sign, and every usage is stated. The private half
/// is sensitive and stays on the token; its handle is returned.
fn keygen_oaep(s: Handle, label: &[u8]) -> Result<Handle, Error> {
    let (yes, no) = ([1u8], [0u8]);
    let (bits, allowed): (CK_ULONG, CK_ULONG) = (3072, CKM_RSA_PKCS_OAEP);
    let f4 = [0x01u8, 0x00, 0x01];
    let mut pub_t = [
        at(CKA_LABEL, label),
        at(CKA_TOKEN, &yes),
        at_ul(CKA_MODULUS_BITS, &bits),
        at(CKA_PUBLIC_EXPONENT, &f4),
        at(CKA_ENCRYPT, &yes),
        at(CKA_WRAP, &yes),
        at(CKA_VERIFY, &no),
        at_ul(CKA_ALLOWED_MECHANISMS, &allowed),
    ];
    let mut priv_t = [
        at(CKA_LABEL, label),
        at(CKA_TOKEN, &yes),
        at(CKA_PRIVATE, &yes),
        at(CKA_SENSITIVE, &yes),
        at(CKA_EXTRACTABLE, &no),
        at(CKA_DECRYPT, &yes),
        at(CKA_UNWRAP, &yes),
        at(CKA_SIGN, &no),
        at_ul(CKA_ALLOWED_MECHANISMS, &allowed),
    ];
    let mut m = CK_MECHANISM {
        mechanism: 0x0000, // CKM_RSA_PKCS_KEY_PAIR_GEN
        p_parameter: null_mut(),
        parameter_len: 0,
    };
    let (mut hp, mut hk): (Handle, Handle) = (0, 0);
    // SAFETY: both templates' values outlive the call; hp and hk writable.
    let rv = unsafe {
        w_generate_key_pair(
            s,
            &mut m,
            pub_t.as_mut_ptr(),
            pub_t.len() as CK_ULONG,
            priv_t.as_mut_ptr(),
            priv_t.len() as CK_ULONG,
            &mut hp,
            &mut hk,
        )
    };
    if rv != 0 {
        return Err(Error::new(
            2,
            format!("C_GenerateKeyPair failed (0x{rv:x})\n"),
        ));
    }
    Ok(hk)
}

/// `pkiops_keygen_secret`: a secret key on the token, sensitive, not extractable, private.
/// AES keys encrypt, decrypt, wrap and unwrap; the HMAC key signs and verifies. For rsa-oaep,
/// the private half of an OAEP-only RSA pair.
pub fn keygen_secret(s: Handle, label: &[u8], k: Skey) -> Result<Handle, Error> {
    if k == Skey::RsaOaep {
        return keygen_oaep(s, label);
    }
    if !has("GenerateKey") {
        return Err(Error::new(
            2,
            "the module does not implement C_GenerateKey\n",
        ));
    }
    let ki = k.info();
    let (cls, kt, len) = (CKO_SECRET_KEY, ki.keytype, ki.len);
    let (yes, no) = ([1u8], [0u8]);
    // Every usage is stated, the ones the key does not have as false: what a template leaves
    // out takes the module's default, and the promise above should not depend on the module.
    let (c, mac) = if ki.cipher { (&yes, &no) } else { (&no, &yes) };
    let mut t = [
        at_ul(CKA_CLASS, &cls),
        at_ul(CKA_KEY_TYPE, &kt),
        at_ul(CKA_VALUE_LEN, &len),
        at(CKA_LABEL, label),
        at(CKA_TOKEN, &yes),
        at(CKA_PRIVATE, &yes),
        at(CKA_SENSITIVE, &yes),
        at(CKA_EXTRACTABLE, &no),
        at(CKA_ENCRYPT, c),
        at(CKA_DECRYPT, c),
        at(CKA_WRAP, c),
        at(CKA_UNWRAP, c),
        at(CKA_SIGN, mac),
        at(CKA_VERIFY, mac),
        at(CKA_DERIVE, &no),
    ];
    let mut m = CK_MECHANISM {
        mechanism: ki.keygen,
        p_parameter: null_mut(),
        parameter_len: 0,
    };
    let mut h: Handle = 0;
    // SAFETY: the template's values outlive the call; h writable.
    let rv = unsafe { w_generate_key(s, &mut m, t.as_mut_ptr(), t.len() as CK_ULONG, &mut h) };
    if rv != 0 {
        return Err(Error::new(2, format!("C_GenerateKey failed (0x{rv:x})\n")));
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_as_c() {
        // struct pkiops_key, _object, _attr on LP64, as tools/pkiops.h lays them out.
        assert_eq!(size_of::<Key>(), 8 + 4 + 4 + 8 + 65 + 16 + 7);
        assert_eq!(std::mem::offset_of!(Key, key_type), 16);
        assert_eq!(size_of::<Object>(), 8 + 4 + 4 + 8 + 65 + 41 + 16 + 6);
        assert_eq!(std::mem::offset_of!(Object, id), 24 + 65);
        assert_eq!(size_of::<Attr>(), 248);
        assert_eq!((OBJS_CERTS, OBJS_KEYS, OBJS_ALL), (1, 14, 15));
        let names: Vec<_> = (0..5)
            .map(|i| ObjClass::from_index(i).map(|c| c.name()))
            .collect();
        assert_eq!(
            names,
            [
                Some(c"certificate"),
                Some(c"public key"),
                Some(c"private key"),
                Some(c"secret key"),
                None
            ]
        );
    }

    #[test]
    fn fields_and_lists_as_snprintf() {
        assert_eq!(text(&fill::<4>(b"abcdef")), b"abc");
        assert_eq!(
            text(&fill::<16>(b"secret-18446744073709551615")),
            b"secret-18446744"
        );
        // A piece that does not fit leaves its cut text; one that fits after it writes over.
        let (mut b, mut n) = (Vec::new(), 0);
        append_capped(&mut b, &mut n, 10, b"abcd");
        append_capped(&mut b, &mut n, 10, b", efghij");
        assert_eq!((&b[..], n), (&b"abcd, efg"[..], 4));
        append_capped(&mut b, &mut n, 10, b", g");
        assert_eq!((&b[..], n), (&b"abcd, g"[..], 7));
    }

    #[test]
    fn curves_and_flags() {
        assert_eq!(curve_name(OID_P256), Some("P-256"));
        assert_eq!(curve_name(b"\x13\x0cedwards25519"), Some("Ed25519"));
        assert_eq!(curve_name(b"\x13\x0aedwards448"), Some("Ed448"));
        assert_eq!(curve_name(b"\x13\x0bedwards448"), None);
        assert_eq!(curve_name(&[0x06, 0x01, 0x00]), None);
        // XN_FLAG_ONELINE = ASN1_STRFLGS_RFC2253 (0x317) | ESC_QUOTE (8) | SEP_CPLUS_SPC
        // (2 << 16) | SPC_EQ (1 << 23) | FN_SN (0); less ESC_MSB (4).
        assert_eq!(NAME_FLAGS, (0x317 | 8 | 2 << 16 | 1 << 23) & !4);
    }
}
