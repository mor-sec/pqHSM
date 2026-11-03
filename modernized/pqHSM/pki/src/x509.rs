//! The X.509 pieces encoded here rather than by OpenSSL (`src/fhsm_composite.c:482-1450`): the
//! composite key's SubjectPublicKeyInfo, every extension value, and the parsing of the
//! operator's subject, subjectAltName and CRL URLs, refused rather than skipped; the CRL and
//! OCSP structures (`:1451-2128`); and CMS SignedData with the DER reader that finds its
//! signed attributes (`:2129-2917`). Pure; what OpenSSL assembles or parses around them is in
//! `ffi::x509`.

use crate::revocation::tlv;

/// id-MLDSA65-Ed25519-SHA512 (1.3.6.1.5.5.7.6.48), parameters absent.
pub static ALGID_COMPOSITE: [u8; 12] = [
    0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x30,
];
/// `fhsm_pki_algid`'s table, by `fhsm_pki_sigalg_t`: the composite, ECDSA with SHA-256 and
/// SHA-384, RSASSA-PSS (SHA-256, MGF1-SHA-256, salt 32), sha256WithRSAEncryption (parameters
/// NULL, RFC 4055 5), Ed25519, ML-DSA-44/65/87 (parameters absent).
pub fn pki_algid(a: i32) -> Option<&'static [u8]> {
    const ECDSA_SHA256: &[u8] = &[
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
    ];
    const ECDSA_SHA384: &[u8] = &[
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03,
    ];
    const RSA_PSS_SHA256: &[u8] = &[
        0x30, 0x41, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, 0x30, 0x34,
        0xA0, 0x0F, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0xA1, 0x1C, 0x30, 0x1A, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x01, 0x08, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
        0x05, 0x00, 0xA2, 0x03, 0x02, 0x01, 0x20,
    ];
    const RSA_PKCS1_SHA256: &[u8] = &[
        0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
    ];
    const ED25519: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];
    const MLDSA44: &[u8] = &[
        0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11,
    ];
    const MLDSA65: &[u8] = &[
        0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
    ];
    const MLDSA87: &[u8] = &[
        0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13,
    ];
    let table: [&'static [u8]; 9] = [
        &ALGID_COMPOSITE,
        ECDSA_SHA256,
        ECDSA_SHA384,
        RSA_PSS_SHA256,
        RSA_PKCS1_SHA256,
        ED25519,
        MLDSA44,
        MLDSA65,
        MLDSA87,
    ];
    usize::try_from(a).ok().and_then(|i| table.get(i).copied())
}
pub const OID_COMPOSITE: &str = "1.3.6.1.5.5.7.6.48";
/// mldsaPK || tradPK (draft §4.1).
pub const RAW_PQ_PUB: usize = 1952;
pub const RAW_TRAD_PUB: usize = 32;
pub const RAW_PUB: usize = RAW_PQ_PUB + RAW_TRAD_PUB;

/// basicConstraints and keyUsage of a root (CA:TRUE; keyCertSign, cRLSign) and of an issued
/// certificate (CA:FALSE; digitalSignature, nonRepudiation); both critical.
pub const BC_CA: &[u8] = &[0x30, 0x03, 0x01, 0x01, 0xFF];
pub const KU_CA: &[u8] = &[0x03, 0x02, 0x01, 0x06];
pub const BC_END_ENTITY: &[u8] = &[0x30, 0x00];
pub const KU_END_ENTITY: &[u8] = &[0x03, 0x02, 0x06, 0xC0];
/// extendedKeyUsage id-kp-OCSPSigning, and id-pkix-ocsp-nocheck's NULL (RFC 6960 4.2.2.2).
pub const EKU_OCSP_SIGNING: &[u8] = &[
    0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09,
];
pub const OCSP_NOCHECK: &[u8] = &[0x05, 0x00];

/// SubjectPublicKeyInfo { composite AlgorithmIdentifier, BIT STRING (no unused bits) raw }.
pub fn composite_spki(raw: &[u8]) -> Vec<u8> {
    tlv(0x30, &[&ALGID_COMPOSITE, &tlv(0x03, &[&[0], raw])])
}

/// subjectKeyIdentifier: the OCTET STRING of the key identifier.
pub fn ski(key_id: &[u8]) -> Vec<u8> {
    tlv(0x04, &[key_id])
}

/// authorityKeyIdentifier with only `[0] keyIdentifier`.
pub fn akid(key_id: &[u8]) -> Vec<u8> {
    tlv(0x30, &[&tlv(0x80, &[key_id])])
}

/// `name_from_oneline`: "/C=FR/O=Simorgh Labs/CN=example" as (attribute type, value) pairs, or
/// None for anything malformed: no leading '/', a type of 0 or more than 31 bytes, an empty
/// value. The type ends at the first '=' anywhere after it, as C's strchr finds it.
pub fn oneline(s: &[u8]) -> Option<Vec<(&[u8], &[u8])>> {
    let mut p = s.strip_prefix(b"/")?;
    let mut out = Vec::new();
    while !p.is_empty() {
        let eq = p.iter().position(|&c| c == b'=')?;
        if eq == 0 || eq >= 32 {
            return None;
        }
        let val = &p[eq + 1..];
        let end = val.iter().position(|&c| c == b'/');
        let v = &val[..end.unwrap_or(val.len())];
        if v.is_empty() {
            return None;
        }
        out.push((&p[..eq], v));
        match end {
            Some(e) => p = &val[e + 1..],
            None => break,
        }
    }
    (!out.is_empty()).then_some(out)
}

/// `san_extension`: the subjectAltName value for "TYPE:value, ..." (DNS, email, URI, IP;
/// spaces and tabs around each item trimmed), or None to refuse. `ip` is OpenSSL's
/// a2i_IPADDRESS, which alone decides what an address is.
pub fn san(list: &[u8], ip: impl Fn(&[u8]) -> Option<Vec<u8>>) -> Option<Vec<u8>> {
    if list.is_empty() {
        return None;
    }
    let mut names = Vec::new();
    let mut p = list;
    loop {
        let comma = p.iter().position(|&c| c == b',');
        let item = trim_blank(&p[..comma.unwrap_or(p.len())]);
        names.push(san_one(item, &ip)?);
        match comma {
            Some(c) if c + 1 < p.len() => p = &p[c + 1..],
            _ => break,
        }
    }
    let parts: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
    Some(tlv(0x30, &parts))
}

/// Spaces and tabs off both ends of an item, as `san_extension` trims.
fn trim_blank(b: &[u8]) -> &[u8] {
    let blank = |c: &u8| *c == b' ' || *c == b'\t';
    let start = b.iter().position(|c| !blank(c)).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !blank(c)).map_or(start, |e| e + 1);
    &b[start..end]
}

/// `san_one`: one GeneralName, from an item of 1 to 511 bytes.
fn san_one(item: &[u8], ip: &impl Fn(&[u8]) -> Option<Vec<u8>>) -> Option<Vec<u8>> {
    if item.is_empty() || item.len() >= 512 {
        return None;
    }
    let colon = item.iter().position(|&c| c == b':')?;
    let (kind, val) = (&item[..colon], &item[colon + 1..]);
    if kind.is_empty() || val.is_empty() {
        return None;
    }
    let tag = match kind {
        b"DNS" => 0x82,
        b"email" => 0x81,
        b"URI" => 0x86,
        b"IP" => return Some(tlv(0x87, &[&ip(val)?])),
        _ => return None,
    };
    Some(tlv(tag, &[val]))
}

/// `crldp_uri_ok`: printable ASCII, and http:// with something after it, or ldap:// with an
/// attribute after a '?'. https:// is refused (RFC 5280 4.2.1.13: no TLS loop for a CRL).
pub fn crl_uri_ok(u: &[u8]) -> bool {
    if !u.iter().all(|c| (0x20..=0x7E).contains(c)) {
        return false;
    }
    if let Some(rest) = u.strip_prefix(b"http://") {
        return !rest.is_empty();
    }
    if let Some(rest) = u.strip_prefix(b"ldap://") {
        return rest
            .iter()
            .position(|&c| c == b'?')
            .is_some_and(|q| q + 1 < rest.len());
    }
    false
}

/// cRLDistributionPoints: one DistributionPoint whose fullName holds every URI.
pub fn crl_dp(urls: &[&[u8]]) -> Vec<u8> {
    let names: Vec<Vec<u8>> = urls.iter().map(|u| tlv(0x86, &[u])).collect();
    let parts: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
    tlv(0x30, &[&tlv(0x30, &[&tlv(0xA0, &[&tlv(0xA0, &parts)])])])
}

/// Why a hand-assembled structure was refused: a part that cannot be what its position needs
/// (FHSM_RV_ARGUMENTS_BAD), or a length past the three-octet form `der_len` stops at
/// (FHSM_RV_FUNCTION_FAILED).
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Arguments,
    TooLong,
}

/// `der_len`'s ceiling: lengths up to 16 MiB - 1.
const DER_LEN_MAX: usize = 0xFF_FFFF;

/// One TLV, or TooLong past DER_LEN_MAX.
fn der(tag: u8, parts: &[&[u8]]) -> Result<Vec<u8>, Refused> {
    if parts.iter().map(|p| p.len()).sum::<usize>() > DER_LEN_MAX {
        return Err(Refused::TooLong);
    }
    Ok(tlv(tag, parts))
}

fn tagged(part: &[u8], tags: &[u8]) -> Result<(), Refused> {
    if part.first().is_some_and(|t| tags.contains(t)) {
        Ok(())
    } else {
        Err(Refused::Arguments)
    }
}

/// v2, written unconditionally: the CRL always carries crlNumber (RFC 5280 5.1.2.1).
const CRL_VERSION_V2: &[u8] = &[0x02, 0x01, 0x01];
const UTC_OR_GENERALIZED: &[u8] = &[0x17, 0x18];
const GENERALIZED: &[u8] = &[0x18];

/// `fhsm_composite_crl_tbs`: TBSCertList from parts already encoded, each non-empty and
/// starting with the tag its position needs (the cheap check against two buffers swapped).
pub fn crl_tbs(
    algid: &[u8],
    issuer: &[u8],
    this_upd: &[u8],
    next_upd: Option<&[u8]>,
    revoked: Option<&[u8]>,
    exts: Option<&[u8]>,
) -> Result<Vec<u8>, Refused> {
    tagged(algid, &[0x30])?;
    tagged(issuer, &[0x30])?;
    tagged(this_upd, UTC_OR_GENERALIZED)?;
    next_upd.map_or(Ok(()), |n| tagged(n, UTC_OR_GENERALIZED))?;
    revoked.map_or(Ok(()), |r| tagged(r, &[0x30]))?;
    exts.map_or(Ok(()), |e| tagged(e, &[0x30]))?;
    // crlExtensions is [0] EXPLICIT
    let exts = exts.map(|e| der(0xA0, &[e])).transpose()?;
    der(
        0x30,
        &[
            CRL_VERSION_V2,
            algid,
            issuer,
            this_upd,
            next_upd.unwrap_or_default(),
            revoked.unwrap_or_default(),
            exts.as_deref().unwrap_or_default(),
        ],
    )
}

/// crlExtensions' content: authorityKeyIdentifier (when the CA has a subjectKeyIdentifier)
/// then crlNumber, both non-critical; at most 512 bytes, as C's buffer holds.
pub fn crl_extensions(ca_skid: Option<&[u8]>, crl_number: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(id) = ca_skid {
        out.extend(tlv(
            0x30,
            &[&[0x06, 0x03, 0x55, 0x1D, 0x23], &tlv(0x04, &[&akid(id)])],
        ));
    }
    let n = crl_number.to_be_bytes();
    let first = n.iter().position(|&b| b != 0).unwrap_or(7);
    let int = [&[0][..usize::from(n[first] & 0x80 != 0)], &n[first..]].concat();
    let number = tlv(0x02, &[&int]);
    out.extend(tlv(
        0x30,
        &[&[0x06, 0x03, 0x55, 0x1D, 0x14], &tlv(0x04, &[&number])],
    ));
    (out.len() <= 512).then_some(out)
}

/// `FHSM_OCSP_*`.
pub const OCSP_GOOD: i32 = 0;
pub const OCSP_REVOKED: i32 = 1;
pub const OCSP_UNKNOWN: i32 = 2;

/// `fhsm_composite_ocsp_single`: one SingleResponse. A revocation time belongs to a revoked
/// certificate and no other; a reason only to a revoked one, 0 to 10.
pub fn ocsp_single(
    cert_id: &[u8],
    status: i32,
    revoked_at: Option<&[u8]>,
    reason: i32,
    this_upd: &[u8],
    next_upd: Option<&[u8]>,
) -> Result<Vec<u8>, Refused> {
    tagged(cert_id, &[0x30])?;
    tagged(this_upd, GENERALIZED)?;
    next_upd.map_or(Ok(()), |n| tagged(n, GENERALIZED))?;
    // IMPLICIT keeps the constructed bit of the type underneath: good and unknown are
    // primitive NULLs (0x80, 0x82), RevokedInfo a SEQUENCE (0xA1)
    let st = match (status, revoked_at) {
        (OCSP_REVOKED, Some(at)) => {
            tagged(at, GENERALIZED)?;
            if at.len() > 24 || reason > 10 {
                return Err(Refused::Arguments);
            }
            // revocationReason is [0] EXPLICIT CRLReason
            let why = (reason >= 0).then_some([0xA0, 0x03, 0x0A, 0x01, reason as u8]);
            tlv(0xA1, &[at, why.as_ref().map_or(&[][..], |w| &w[..])])
        }
        (OCSP_GOOD, None) if reason < 0 => vec![0x80, 0x00],
        (OCSP_UNKNOWN, None) if reason < 0 => vec![0x82, 0x00],
        _ => return Err(Refused::Arguments),
    };
    // nextUpdate is [0] EXPLICIT
    let next = next_upd.map(|n| der(0xA0, &[n])).transpose()?;
    der(
        0x30,
        &[cert_id, &st, this_upd, next.as_deref().unwrap_or_default()],
    )
}

/// `fhsm_composite_ocsp_tbs`: ResponseData, responderID byName [1] or byKey [2].
pub fn ocsp_tbs(
    responder_id: &[u8],
    produced_at: &[u8],
    responses: &[u8],
    exts: Option<&[u8]>,
) -> Result<Vec<u8>, Refused> {
    tagged(responder_id, &[0xA1, 0xA2])?;
    tagged(produced_at, GENERALIZED)?;
    tagged(responses, &[0x30])?;
    exts.map_or(Ok(()), |e| tagged(e, &[0x30]))?;
    // responseExtensions is [1] EXPLICIT
    let exts = exts.map(|e| der(0xA1, &[e])).transpose()?;
    der(
        0x30,
        &[
            responder_id,
            produced_at,
            responses,
            exts.as_deref().unwrap_or_default(),
        ],
    )
}

/// The SEQUENCE around a list of already-encoded entries.
pub fn sequence(entries: &[u8]) -> Result<Vec<u8>, Refused> {
    der(0x30, &[entries])
}

/// The SET OF around a list of already-encoded members.
pub fn set_of(members: &[u8]) -> Result<Vec<u8>, Refused> {
    der(0x31, &[members])
}

/// responderID byName: [1] EXPLICIT Name.
pub fn by_name(name: &[u8]) -> Result<Vec<u8>, Refused> {
    der(0xA1, &[name])
}

/// CertificateList, or BasicOCSPResponse with `certs`: { tbs, algid, BIT STRING signature
/// (no unused bits) [, certs [0] EXPLICIT SEQUENCE OF Certificate] }.
pub fn signed(
    tbs: &[u8],
    algid: &[u8],
    sig: &[u8],
    certs: Option<&[u8]>,
) -> Result<Vec<u8>, Refused> {
    let bits = der(0x03, &[&[0], sig])?;
    let certs = certs
        .map(|c| der(0x30, &[c]).and_then(|l| der(0xA0, &[&l])))
        .transpose()?;
    der(
        0x30,
        &[tbs, algid, &bits, certs.as_deref().unwrap_or_default()],
    )
}

// --- CMS SignedData (RFC 5652; Phase 3 slice 5d, src/fhsm_composite.c:2129-2917) ---------------

/// CMSVersion 1: the version that goes with the issuerAndSerialNumber SignerIdentifier
/// (RFC 5652 5.3).
const CMS_VERSION_1: &[u8] = &[0x02, 0x01, 0x01];
/// id-signedData, id-data, id-contentType and id-messageDigest, as OID TLVs.
const OID_SIGNED_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
];
const OID_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01,
];
const OID_CONTENT_TYPE: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x03,
];
const OID_MESSAGE_DIGEST: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04,
];

/// The same content under another identifier octet: the [0] IMPLICIT retag of a SET OF.
fn retagged(tag: u8, tlv: &[u8]) -> Vec<u8> {
    [&[tag][..], &tlv[1..]].concat()
}

/// `fhsm_composite_cms_signerinfo`: SignerInfo from parts already encoded, each non-empty and
/// tagged for its position. The signed attributes arrive as the SET OF that was signed, never
/// the [0] form that is sent, and leave retagged.
pub fn cms_signerinfo(
    issuer: &[u8],
    serial: &[u8],
    digalg: &[u8],
    sattrs: &[u8],
    sigalg: &[u8],
    sig: &[u8],
) -> Result<Vec<u8>, Refused> {
    if [issuer, serial, digalg, sattrs, sigalg, sig]
        .iter()
        .any(|p| p.is_empty())
    {
        return Err(Refused::Arguments);
    }
    tagged(issuer, &[0x30])?;
    tagged(serial, &[0x02])?;
    tagged(digalg, &[0x30])?;
    tagged(sigalg, &[0x30])?;
    tagged(sattrs, &[0x31])?;
    let ias = der(0x30, &[issuer, serial])?;
    // an OCTET STRING here, where X.509 has a BIT STRING
    let sig = der(0x04, &[sig])?;
    let attrs = retagged(0xA0, sattrs);
    der(0x30, &[CMS_VERSION_1, &ias, digalg, &attrs, sigalg, &sig])
}

/// `fhsm_composite_cms_wrap`: ContentInfo { id-signedData, [0] EXPLICIT SignedData } around one
/// digest algorithm, eContent absent (detached), the certificates' SET OF retagged [0], and
/// the SignerInfo(s).
pub fn cms_wrap(
    digalg: &[u8],
    certs: Option<&[u8]>,
    signerinfo: &[u8],
) -> Result<Vec<u8>, Refused> {
    if digalg.is_empty() || signerinfo.is_empty() || certs.is_some_and(|c| c.is_empty()) {
        return Err(Refused::Arguments);
    }
    tagged(digalg, &[0x30])?;
    tagged(signerinfo, &[0x30])?;
    if let Some(c) = certs {
        tagged(c, &[0x31])?;
    }
    let algs = der(0x31, &[digalg])?;
    let content = der(0x30, &[OID_DATA])?;
    let certs = certs.map(|c| retagged(0xA0, c)).unwrap_or_default();
    let infos = der(0x31, &[signerinfo])?;
    let sd = der(0x30, &[CMS_VERSION_1, &algs, &content, &certs, &infos])?;
    let c0 = der(0xA0, &[&sd])?;
    der(0x30, &[OID_SIGNED_DATA, &c0])
}

/// `cms_signed_attrs`: contentType id-data and messageDigest, as the DER SET OF that gets
/// signed. X.690 11.6 orders the members by their encodings as octet strings, a prefix first:
/// slice order.
pub fn cms_signed_attrs(digest: &[u8]) -> Vec<u8> {
    let ct = tlv(0x30, &[OID_CONTENT_TYPE, &tlv(0x31, &[OID_DATA])]);
    let md = tlv(
        0x30,
        &[OID_MESSAGE_DIGEST, &tlv(0x31, &[&tlv(0x04, &[digest])])],
    );
    let (a, b) = if ct < md { (ct, md) } else { (md, ct) };
    tlv(0x31, &[&a, &b])
}

/// `tlv_at`: the TLV at the start of `b` as (tag, value, whole). Definite lengths of up to
/// four octets, which is all DER produces.
pub fn tlv_at(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, &n0) = (b.first()?, b.get(1)?);
    let (hl, n) = if n0 & 0x80 == 0 {
        (2, usize::from(n0))
    } else {
        let k = usize::from(n0 & 0x7F);
        if k == 0 || k > 4 {
            return None;
        }
        let len = b.get(2..2 + k)?;
        (2 + k, len.iter().fold(0, |n, &x| n << 8 | usize::from(x)))
    };
    let whole = b.get(..hl.checked_add(n)?)?;
    Some((tag, &whole[hl..], whole))
}

/// The TLVs inside a value, in order, up to the first that does not parse (`tlv_child`).
fn children(mut v: &[u8]) -> impl Iterator<Item = (u8, &[u8], &[u8])> {
    std::iter::from_fn(move || {
        let t = tlv_at(v)?;
        v = &v[t.2.len()..];
        Some(t)
    })
}

/// `cms_find_signerinfo` and the walk after it: in a ContentInfo, ContentInfo -> [0] ->
/// SignedData -> its trailing SET OF -> the first SignerInfo -> its [0] signed attributes,
/// retagged to the SET OF that was signed.
pub fn cms_signed_attrs_of(der: &[u8]) -> Option<Vec<u8>> {
    let (_, ci, _) = tlv_at(der)?;
    let (_, c0, _) = children(ci).nth(1)?;
    let (_, sd, _) = tlv_at(c0)?;
    let (mut left, mut last) = (sd, None);
    while !left.is_empty() {
        let t = tlv_at(left)?;
        left = &left[t.2.len()..];
        last = Some(t);
    }
    let (0x31, infos, _) = last? else {
        return None;
    };
    let (_, si, _) = children(infos).next()?;
    let (_, _, attrs) = children(si).find(|t| t.0 == 0xA0)?;
    Some(retagged(0x31, attrs))
}

/// `fhsm_pki_ecdsa_raw_to_der` after its checks: r || s, halves of equal length, as an
/// Ecdsa-Sig-Value of two minimal non-negative INTEGERs.
pub fn ecdsa_sig(rs: &[u8]) -> Vec<u8> {
    let int = |b: &[u8]| {
        let b = &b[b.iter().take_while(|&&x| x == 0).count()..];
        match b.first() {
            None => tlv(0x02, &[&[0]]),
            Some(x) if x & 0x80 != 0 => tlv(0x02, &[&[0], b]),
            Some(_) => tlv(0x02, &[b]),
        }
    };
    let (r, s) = rs.split_at(rs.len() / 2);
    tlv(0x30, &[&int(r), &int(s)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parsers_refuse_rather_than_skip() {
        assert_eq!(oneline(b"/CN=a/"), Some(vec![(&b"CN"[..], &b"a"[..])]));
        assert_eq!(oneline(b"/CN=a=b"), Some(vec![(&b"CN"[..], &b"a=b"[..])]));
        // C's strchr makes the second type "/O", which OpenSSL then refuses as a name
        assert_eq!(
            oneline(b"/CN=a//O=b"),
            Some(vec![(&b"CN"[..], &b"a"[..]), (&b"/O"[..], &b"b"[..])])
        );
        assert_eq!(oneline(b"/CN="), None);
        let ip = |_: &[u8]| Some(vec![1, 2, 3, 4]);
        assert_eq!(san(b"DNS:a,", ip), Some(vec![0x30, 0x03, 0x82, 0x01, b'a']));
        assert_eq!(san(b"DNS:a, ,DNS:b", ip), None);
        assert_eq!(
            san(b" IP:x\t", ip),
            Some(vec![0x30, 0x06, 0x87, 0x04, 1, 2, 3, 4])
        );
        assert!(
            crl_uri_ok(b"ldap://x?a") && !crl_uri_ok(b"ldap://x?") && !crl_uri_ok(b"https://x")
        );
    }

    #[test]
    fn the_der_reader_stops_at_what_does_not_parse() {
        assert_eq!(
            tlv_at(&[0x04, 0x01, 7, 9]),
            Some((4, &[7][..], &[4, 1, 7][..]))
        );
        assert_eq!(
            tlv_at(&[0x04, 0x81, 1, 7]),
            Some((4, &[7][..], &[4, 0x81, 1, 7][..]))
        );
        // indefinite, five length octets, short of the length, short of the value
        for b in [
            &[0x30, 0x80][..],
            &[4, 0x85, 0, 0, 0, 0, 1],
            &[4, 0x82, 0],
            &[4, 2, 0],
            &[4],
        ] {
            assert_eq!(tlv_at(b), None, "{b:02x?}");
        }
        assert_eq!(tlv_at(&[4, 0x84, 0xFF, 0xFF, 0xFF, 0xFF]), None);
        assert_eq!(
            tlv_at(&[4, 0x84, 0, 0, 0, 1, 7]),
            Some((4, &[7][..], &[4, 0x84, 0, 0, 0, 1, 7][..]))
        );
        assert_eq!(cms_signed_attrs_of(&[0x30, 0x02, 0x05, 0x00]), None);
        // ContentInfo { OID, [0] { SignedData { X { SignerInfo { [0] attrs } } } } }: the
        // signed attributes only when X, the last element, is the SET OF SignerInfo
        let ci = |x: u8| {
            [
                0x30, 0x0F, 0x06, 0x01, 0x00, 0xA0, 0x0A, 0x30, 0x08, x, 0x06, 0x30, 0x04, 0xA0,
                0x02, 0x05, 0x00,
            ]
        };
        assert_eq!(
            cms_signed_attrs_of(&ci(0x31)),
            Some(vec![0x31, 0x02, 0x05, 0x00])
        );
        assert_eq!(cms_signed_attrs_of(&ci(0x30)), None);
        assert_eq!(ecdsa_sig(&[0, 0]), [0x30, 6, 2, 1, 0, 2, 1, 0]);
        assert_eq!(ecdsa_sig(&[0, 0x80]), [0x30, 7, 2, 1, 0, 2, 2, 0, 0x80]);
    }
}
