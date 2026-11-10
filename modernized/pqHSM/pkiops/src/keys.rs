//! The signature algorithms the tools offer (`tools/pkiops.c`'s `ALG` table) and the public
//! key a request or root carries, built from the standard attributes (`spki_of`'s DER).

use std::ffi::{CStr, c_ulong};

use crate::Error;

/// `enum pkiops_alg`, in its order, which is also `fhsm_pki_sigalg_t`'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Alg {
    Composite = 0,
    EcdsaP256,
    EcdsaP384,
    RsaPss,
    RsaPkcs1,
    Ed25519,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

pub const CKK_RSA: c_ulong = 0x00;
pub const CKK_EC: c_ulong = 0x03;
pub const CKK_EC_EDWARDS: c_ulong = 0x40;
pub const CKK_ML_DSA: c_ulong = 0x4A;
pub const CKK_COMPOSITE: c_ulong = 0x8000_4202;
pub const CKM_COMPOSITE: c_ulong = 0x8000_4202;

/// One row of `ALG`.
pub struct Info {
    pub name: &'static CStr,
    pub keytype: c_ulong,
    /// The key-pair generation mechanism.
    pub keygen: c_ulong,
    /// The signing mechanism.
    pub mech: c_ulong,
    /// The CMS digest.
    pub digest: &'static CStr,
    /// r's and s's length; 0 if not ECDSA.
    pub ecdsa_half: usize,
}

const fn row(
    name: &'static CStr,
    keytype: c_ulong,
    keygen: c_ulong,
    mech: c_ulong,
    digest: &'static CStr,
    ecdsa_half: usize,
) -> Info {
    Info {
        name,
        keytype,
        keygen,
        mech,
        digest,
        ecdsa_half,
    }
}

pub const ALG: [Info; 9] = [
    row(
        c"composite",
        CKK_COMPOSITE,
        CKM_COMPOSITE,
        CKM_COMPOSITE,
        c"SHA512",
        0,
    ),
    row(c"ecdsa-p256", CKK_EC, 0x1040, 0x1044, c"SHA256", 32),
    row(c"ecdsa-p384", CKK_EC, 0x1040, 0x1045, c"SHA384", 48),
    row(c"rsa-pss", CKK_RSA, 0x0000, 0x0043, c"SHA256", 0),
    row(c"rsa-pkcs1", CKK_RSA, 0x0000, 0x0040, c"SHA256", 0),
    row(c"ed25519", CKK_EC_EDWARDS, 0x1055, 0x1057, c"SHA512", 0),
    row(c"ml-dsa-44", CKK_ML_DSA, 0x001C, 0x001D, c"SHA512", 0),
    row(c"ml-dsa-65", CKK_ML_DSA, 0x001C, 0x001D, c"SHA512", 0),
    row(c"ml-dsa-87", CKK_ML_DSA, 0x001C, 0x001D, c"SHA512", 0),
];

const ALL: [Alg; 9] = [
    Alg::Composite,
    Alg::EcdsaP256,
    Alg::EcdsaP384,
    Alg::RsaPss,
    Alg::RsaPkcs1,
    Alg::Ed25519,
    Alg::MlDsa44,
    Alg::MlDsa65,
    Alg::MlDsa87,
];

/// `pkiops_alg_list`.
pub const ALG_LIST: &CStr = c"composite, ecdsa-p256, ecdsa-p384, rsa-pss, rsa-pkcs1, ed25519, ml-dsa-44, ml-dsa-65, ml-dsa-87";

/// `enum pkiops_skey`: the keys that do not sign, in its order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Skey {
    Aes128 = 0,
    Aes256,
    /// A 32-byte generic secret.
    Hmac,
    /// An RSA 3072 pair, OAEP only.
    RsaOaep,
}

pub const CKK_GENERIC_SECRET: c_ulong = 0x10;
pub const CKK_AES: c_ulong = 0x1F;

/// One row of `SKEY`.
pub struct SkeyInfo {
    pub name: &'static CStr,
    pub keytype: c_ulong,
    pub keygen: c_ulong,
    /// CKA_VALUE_LEN.
    pub len: c_ulong,
    /// Encrypts and wraps; a MAC key otherwise.
    pub cipher: bool,
}

/// `SKEY`. The rsa-oaep row is a key pair, generated apart; listing still matches on it.
pub const SKEY: [SkeyInfo; 4] = [
    SkeyInfo {
        name: c"aes128",
        keytype: CKK_AES,
        keygen: 0x1080,
        len: 16,
        cipher: true,
    },
    SkeyInfo {
        name: c"aes256",
        keytype: CKK_AES,
        keygen: 0x1080,
        len: 32,
        cipher: true,
    },
    SkeyInfo {
        name: c"hmac",
        keytype: CKK_GENERIC_SECRET,
        keygen: 0x0350,
        len: 32,
        cipher: false,
    },
    SkeyInfo {
        name: c"rsa-oaep",
        keytype: CKK_RSA,
        keygen: 0,
        len: 0,
        cipher: false,
    },
];

const SKEYS: [Skey; 4] = [Skey::Aes128, Skey::Aes256, Skey::Hmac, Skey::RsaOaep];

/// `pkiops_skey_list`.
pub const SKEY_LIST: &CStr = c"aes128, aes256, hmac, rsa-oaep";

impl Skey {
    pub fn from_index(i: u32) -> Option<Skey> {
        SKEYS.get(i as usize).copied()
    }

    pub fn info(self) -> &'static SkeyInfo {
        &SKEY[self as usize]
    }

    /// `pkiops_skey_parse`; `None` is C's NULL name. A signature algorithm's name is sent to
    /// fhsm-csr, as [`Alg::parse`] sends these to fhsm-crypt.
    pub fn parse(name: Option<&[u8]>) -> Result<Skey, Error> {
        if let Some(n) = name {
            if let Some(&k) = SKEYS.iter().find(|k| k.info().name.to_bytes() == n) {
                return Ok(k);
            }
            if ALL.iter().any(|a| a.info().name.to_bytes() == n) {
                let n = String::from_utf8_lossy(n); // one of ALG's names: ASCII
                return Err(Error::new(
                    1,
                    format!(
                        "\"{n}\" is a signature algorithm: fhsm-csr keygen --alg {n} makes it.\n"
                    ),
                ));
            }
        }
        let mut m = b"\"".to_vec();
        m.extend(name.unwrap_or_default());
        m.extend(b"\" is not a key fhsm-crypt makes.\n  One of: ");
        m.extend(SKEY_LIST.to_bytes());
        m.push(b'\n');
        Err(Error::new(1, m))
    }
}

impl Alg {
    pub fn from_index(i: u32) -> Option<Alg> {
        ALL.get(i as usize).copied()
    }

    pub fn info(self) -> &'static Info {
        &ALG[self as usize]
    }

    /// `pkiops_alg_parse`; `None` is C's NULL name.
    pub fn parse(name: Option<&[u8]>) -> Result<Alg, Error> {
        if let Some(n) = name {
            if let Some(&a) = ALL.iter().find(|a| a.info().name.to_bytes() == n) {
                return Ok(a);
            }
            if SKEYS.iter().any(|k| k.info().name.to_bytes() == n) {
                let n = String::from_utf8_lossy(n);
                return Err(Error::new(
                    1,
                    format!(
                        "\"{n}\" is a key that does not sign: fhsm-crypt keygen --alg {n} makes it.\n"
                    ),
                ));
            }
        }
        let mut m = b"\"".to_vec();
        m.extend(name.unwrap_or_default());
        m.extend(b"\" is not an algorithm these tools offer.\n  One of: ");
        m.extend(ALG_LIST.to_bytes());
        m.push(b'\n');
        Err(Error::new(1, m))
    }
}

/// The curve OIDs, as CKA_EC_PARAMS carries them.
pub const OID_P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
pub const OID_P384: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22];
pub const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
/// The string form of the Ed25519 curve some modules give as CKA_EC_PARAMS.
pub const PRINTABLE_ED25519: &[u8] = b"\x13\x0Cedwards25519";

/// `point_of`: CKA_EC_POINT as a DER OCTET STRING (the specification) or as the bare point
/// (modules in the field), told apart by the bare form's length, not by a leading 0x04.
pub fn point_of(p: &[u8], raw_len: usize) -> Option<&[u8]> {
    if p.len() == raw_len {
        return Some(p);
    }
    if p.len() >= 2 && p[0] == 0x04 {
        let (mut hl, mut l) = (2, p[1] as usize);
        if l & 0x80 != 0 {
            let k = l & 0x7F;
            if k == 0 || k > 2 || p.len() < 2 + k {
                return None;
            }
            l = p[2..2 + k].iter().fold(0, |a, &b| (a << 8) | b as usize);
            hl = 2 + k;
        }
        if hl + l == p.len() && l == raw_len {
            return Some(&p[hl..]);
        }
    }
    None
}

fn tlv(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let n: usize = parts.iter().map(|p| p.len()).sum();
    let mut v = vec![tag];
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let be = n.to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        v.push(0x80 | (be.len() - skip) as u8);
        v.extend(&be[skip..]);
    }
    for p in parts {
        v.extend(*p);
    }
    v
}

/// A DER INTEGER of the unsigned big-endian `b`, as BN_bin2bn then i2d write it.
fn uint(b: &[u8]) -> Vec<u8> {
    let b = &b[b.iter().take_while(|&&x| x == 0).count()..];
    match b.first() {
        None => tlv(0x02, &[&[0]]),
        Some(&f) if f & 0x80 != 0 => tlv(0x02, &[&[0], b]),
        Some(_) => tlv(0x02, &[b]),
    }
}

const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_RSA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];
const NULL: &[u8] = &[0x05, 0x00];

fn oid_mldsa(last: u8) -> [u8; 11] {
    [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, last,
    ]
}

/// A SubjectPublicKeyInfo for a non-composite `a` (None for the composite, whose blob
/// pqhsm-pki encodes): `k1` the point (EC, Ed25519), the raw key (ML-DSA) or the modulus
/// (RSA), `k2` RSA's exponent. The caller has OpenSSL read it back and write it again, as
/// C's `EVP_PKEY_fromdata` then `i2d_PUBKEY` did.
pub fn spki(a: Alg, k1: &[u8], k2: &[u8]) -> Option<Vec<u8>> {
    let (algid, key) = match a {
        Alg::Composite => return None,
        Alg::EcdsaP256 => (tlv(0x30, &[OID_EC_PUBLIC_KEY, OID_P256]), k1.to_vec()),
        Alg::EcdsaP384 => (tlv(0x30, &[OID_EC_PUBLIC_KEY, OID_P384]), k1.to_vec()),
        Alg::RsaPss | Alg::RsaPkcs1 => (
            tlv(0x30, &[OID_RSA, NULL]),
            tlv(0x30, &[&uint(k1), &uint(k2)]),
        ),
        Alg::Ed25519 => (tlv(0x30, &[OID_ED25519]), k1.to_vec()),
        Alg::MlDsa44 => (tlv(0x30, &[&oid_mldsa(0x11)]), k1.to_vec()),
        Alg::MlDsa65 => (tlv(0x30, &[&oid_mldsa(0x12)]), k1.to_vec()),
        Alg::MlDsa87 => (tlv(0x30, &[&oid_mldsa(0x13)]), k1.to_vec()),
    };
    Some(tlv(0x30, &[&algid, &tlv(0x03, &[&[0], &key])]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_names_follow_pkiops_c() {
        for (i, a) in ALL.iter().enumerate() {
            assert_eq!(*a as usize, i);
            assert_eq!(Alg::parse(Some(a.info().name.to_bytes())), Ok(*a));
        }
        assert_eq!(
            ALG_LIST.to_bytes(),
            ALG.map(|r| r.name.to_str().unwrap()).join(", ").as_bytes()
        );
        assert_eq!(Alg::from_index(9), None);
        let e = Alg::parse(Some(b"aes256")).unwrap_err();
        assert_eq!((e.code, &e.msg[..]), (1, &b"\"aes256\" is a key that does not sign: fhsm-crypt keygen --alg aes256 makes it.\n"[..]));
        let e = Alg::parse(None).unwrap_err();
        assert!(
            e.msg
                .starts_with(b"\"\" is not an algorithm these tools offer.\n  One of: composite, ")
        );
        // The names, in order, and the secret keys' are tools/pkiops.c's.
        let c = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tools/pkiops.c"
        ))
        .unwrap();
        let named: Vec<_> = c
            .lines()
            .filter_map(|l| l.trim().strip_prefix("[PKIOPS_ALG_"))
            .map(|l| l.split('"').nth(1).unwrap())
            .collect();
        assert_eq!(named, ALG.map(|r| r.name.to_str().unwrap()));
        // SKEY's rows: `[PKIOPS_SKEY_AES128] = { "aes128", CKK_AES_, 0x1080UL, 16, 1 },`.
        let rows: Vec<Vec<String>> = c
            .lines()
            .filter_map(|l| l.trim().strip_prefix("[PKIOPS_SKEY_"))
            .map(|l| {
                let body = l.split('{').nth(1).unwrap().split('}').next().unwrap();
                body.split(',')
                    .map(|f| f.trim().trim_matches('"').to_string())
                    .collect()
            })
            .collect();
        assert_eq!(rows.len(), SKEY.len());
        for (r, k) in rows.iter().zip(&SKEY) {
            assert_eq!(r[0], k.name.to_str().unwrap());
            assert_eq!(r[2], format!("0x{:04X}UL", k.keygen));
            assert_eq!(r[3], k.len.to_string());
        }
    }

    #[test]
    fn skeys_as_c() {
        for (i, k) in SKEYS.iter().enumerate() {
            assert_eq!(*k as usize, i);
            assert_eq!(Skey::parse(Some(k.info().name.to_bytes())), Ok(*k));
        }
        assert_eq!(Skey::from_index(4), None);
        assert_eq!(
            SKEY_LIST.to_bytes(),
            SKEY.map(|r| r.name.to_str().unwrap()).join(", ").as_bytes()
        );
        let e = Skey::parse(Some(b"ed25519")).unwrap_err();
        assert_eq!(
            (e.code, &e.msg[..]),
            (
                1,
                &b"\"ed25519\" is a signature algorithm: fhsm-csr keygen --alg ed25519 makes it.\n"
                    [..]
            )
        );
        let e = Skey::parse(None).unwrap_err();
        assert_eq!(
            &e.msg[..],
            b"\"\" is not a key fhsm-crypt makes.\n  One of: aes128, aes256, hmac, rsa-oaep\n"
        );
    }

    #[test]
    fn point_of_takes_both_forms() {
        let raw = [0x04u8; 65];
        assert_eq!(point_of(&raw, 65), Some(&raw[..]));
        let wrapped = [&[0x04, 65][..], &raw].concat();
        assert_eq!(point_of(&wrapped, 65), Some(&raw[..]));
        let long = [&[0x04, 0x81, 65][..], &raw].concat();
        assert_eq!(point_of(&long, 65), Some(&raw[..]));
        assert_eq!(point_of(&[0x04, 0x80], 65), None);
        assert_eq!(point_of(&[0x04, 3, 1, 2, 3], 65), None);
        assert_eq!(point_of(&[0x05, 0x01, 0x00], 1), None);
    }

    #[test]
    fn der_lengths_and_integers() {
        assert_eq!(tlv(0x04, &[&[0; 0x7F]])[..2], [0x04, 0x7F]);
        assert_eq!(tlv(0x04, &[&[0; 0x80]])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(tlv(0x04, &[&[0; 0x1234]])[..4], [0x04, 0x82, 0x12, 0x34]);
        assert_eq!(uint(&[]), [0x02, 0x01, 0x00]);
        assert_eq!(uint(&[0, 0, 0x7F]), [0x02, 0x01, 0x7F]);
        assert_eq!(uint(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(uint(&[0x01, 0x00, 0x01]), [0x02, 0x03, 0x01, 0x00, 0x01]);
        assert_eq!(spki(Alg::Composite, &[], &[]), None);
    }
}
