//! CMS AuthEnvelopedData (RFC 5083) with AES-GCM content (RFC 5084), as fhsm-crypt writes and
//! reads it (`tools/cms_env.c`, PHASE5_PLAN.md slice 3; why not OpenSSL's CMS API is in
//! `tools/cms_env.h`: a key held in a token never yields the bytes that API wants).
//!
//! The head (everything before the encrypted bytes) and the tail (the GCM tag) only: the
//! content between them is streamed by the caller, never held. Only what this project and
//! OpenSSL produce are read: definite-length DER, a primitive encryptedContent, no
//! authenticated attributes; anything else is refused by name.
//!
//! ```text
//! 30 ContentInfo
//!    06 id-ct-authEnvelopedData            1.2.840.113549.1.9.16.1.23
//!    A0 [0] EXPLICIT
//!       30 AuthEnvelopedData
//!          02 version 0
//!          31 RecipientInfos { A2 KEKRecipientInfo | 30 KeyTransRecipientInfo ... }
//!          30 EncryptedContentInfo
//!             06 id-data
//!             30 AlgorithmIdentifier { 06 id-aesNNN-GCM, 30 GCMParameters { 04 nonce, 02 ICVlen } }
//!             80 [0] IMPLICIT encryptedContent   <- the content, streamed
//!          04 mac                                <- the tail
//! ```

/// More than any head this writes or OpenSSL writes for a handful of recipients; a head that
/// does not fit is refused, not truncated.
pub const HEAD_MAX: usize = 65536;
/// Recipients of each kind kept; any past these are skipped, as C's fixed arrays skip them.
pub const KEK_MAX: usize = 8;
pub const KTRI_MAX: usize = 8;

const OID_AUTH_ENV: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x17,
];
const OID_DATA: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
/// 2.16.840.1.101.3.4.1.x: aes, the last arc naming mode and size.
const OID_AES_PREFIX: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01];
const OID_RSAES_OAEP: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x07];
const OID_RSA_ENC: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
const OID_MGF1: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x08];
const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];

fn wrap_arc(bits: u32) -> Option<u8> {
    match bits {
        128 => Some(5),
        192 => Some(25),
        256 => Some(45),
        _ => None,
    }
}

fn gcm_arc(bits: u32) -> Option<u8> {
    match bits {
        128 => Some(6),
        192 => Some(26),
        256 => Some(46),
        _ => None,
    }
}

// --- writing ----------------------------------------------------------------------------------

/// The size of a whole TLV whose value is `len` bytes.
fn tlv(len: u64) -> u64 {
    let len_bytes = if len < 0x80 {
        1
    } else {
        1 + u64::from((64 - len.leading_zeros()).div_ceil(8))
    };
    1 + len_bytes + len
}

fn tl(out: &mut Vec<u8>, tag: u8, len: u64) {
    out.push(tag);
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let b = len.to_be_bytes();
        let skip = b.iter().take_while(|&&x| x == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend(&b[skip..]);
    }
}

fn aes_oid(out: &mut Vec<u8>, arc: u8) {
    tl(out, 0x06, OID_AES_PREFIX.len() as u64 + 1);
    out.extend(OID_AES_PREFIX);
    out.push(arc);
}

/// `cmsenv_kekri`: a key-encryption-key recipient, the content key wrapped with AES key wrap;
/// None for a wrap size that is not 128, 192 or 256.
pub fn kekri(id: &[u8], wrap_bits: u32, ekey: &[u8]) -> Option<Vec<u8>> {
    let arc = wrap_arc(wrap_bits)?;
    let oid_aes = tlv(OID_AES_PREFIX.len() as u64 + 1);
    let inner = 3 + tlv(tlv(id.len() as u64)) + tlv(oid_aes) + tlv(ekey.len() as u64);
    let mut d = Vec::new();
    tl(&mut d, 0xA2, inner);
    d.extend([0x02, 0x01, 0x04]);
    tl(&mut d, 0x30, tlv(id.len() as u64));
    tl(&mut d, 0x04, id.len() as u64);
    d.extend(id);
    tl(&mut d, 0x30, oid_aes);
    aes_oid(&mut d, arc);
    tl(&mut d, 0x04, ekey.len() as u64);
    d.extend(ekey);
    Some(d)
}

/// How a key-transport recipient names its key.
pub enum Rid<'a> {
    /// `[0] subjectKeyIdentifier` (version 2).
    Ski(&'a [u8]),
    /// `issuerAndSerialNumber`, its whole DER (version 0).
    Ias(&'a [u8]),
}

fn sha256_alg(d: &mut Vec<u8>) {
    tl(d, 0x30, tlv(OID_SHA256.len() as u64));
    tl(d, 0x06, OID_SHA256.len() as u64);
    d.extend(OID_SHA256);
}

/// `cmsenv_ktri_oaep`: a key-transport recipient, RSAES-OAEP with SHA-256 and MGF1-SHA-256,
/// the empty label (RFC 4055 §4.1). The SHA-256 AlgorithmIdentifiers carry no parameters, as
/// RFC 4055 asks and OpenSSL writes.
pub fn ktri_oaep(rid: Rid, ekey: &[u8]) -> Vec<u8> {
    let sha = tlv(tlv(OID_SHA256.len() as u64));
    let mgf_in = tlv(OID_MGF1.len() as u64) + sha;
    let prm_in = tlv(sha) + tlv(tlv(mgf_in));
    let alg_in = tlv(OID_RSAES_OAEP.len() as u64) + tlv(prm_in);
    let (rid_len, ver) = match rid {
        Rid::Ski(s) => (tlv(s.len() as u64), 2),
        Rid::Ias(i) => (i.len() as u64, 0),
    };
    let inner = 3 + rid_len + tlv(alg_in) + tlv(ekey.len() as u64);
    let mut d = Vec::new();
    tl(&mut d, 0x30, inner);
    d.extend([0x02, 0x01, ver]);
    match rid {
        Rid::Ski(s) => {
            tl(&mut d, 0x80, s.len() as u64);
            d.extend(s);
        }
        Rid::Ias(i) => d.extend(i),
    }
    tl(&mut d, 0x30, alg_in);
    tl(&mut d, 0x06, OID_RSAES_OAEP.len() as u64);
    d.extend(OID_RSAES_OAEP);
    tl(&mut d, 0x30, prm_in);
    tl(&mut d, 0xA0, sha);
    sha256_alg(&mut d);
    tl(&mut d, 0xA1, tlv(mgf_in));
    tl(&mut d, 0x30, mgf_in);
    tl(&mut d, 0x06, OID_MGF1.len() as u64);
    d.extend(OID_MGF1);
    sha256_alg(&mut d);
    tl(&mut d, 0x04, ekey.len() as u64);
    d.extend(ekey);
    d
}

/// `cmsenv_write_head`: everything before the encrypted content, for the recipient `ri`. The
/// content that follows must be exactly `content_len` bytes, and the tail then carries a tag
/// of `tag_len` bytes. None on an argument C refused.
pub fn head(
    ri: &[u8],
    gcm_bits: u32,
    nonce: &[u8],
    content_len: u64,
    tag_len: usize,
) -> Option<Vec<u8>> {
    let arc = gcm_arc(gcm_bits)?;
    if !(12..=16).contains(&tag_len) || !(1..=16).contains(&nonce.len()) {
        return None;
    }
    let oid_aes = tlv(OID_AES_PREFIX.len() as u64 + 1);
    // Sizes, innermost first.
    let set_in = ri.len() as u64;
    let gp_in = tlv(nonce.len() as u64) + 3;
    let alg_in = oid_aes + tlv(gp_in);
    let eci_in = tlv(OID_DATA.len() as u64) + tlv(alg_in) + tlv(content_len);
    let aed_in = 3 + tlv(set_in) + tlv(eci_in) + tlv(tag_len as u64);
    let ci_in = tlv(OID_AUTH_ENV.len() as u64) + tlv(tlv(aed_in));
    let mut d = Vec::new();
    tl(&mut d, 0x30, ci_in);
    tl(&mut d, 0x06, OID_AUTH_ENV.len() as u64);
    d.extend(OID_AUTH_ENV);
    tl(&mut d, 0xA0, tlv(aed_in));
    tl(&mut d, 0x30, aed_in);
    d.extend([0x02, 0x01, 0x00]);
    tl(&mut d, 0x31, set_in);
    d.extend(ri);
    tl(&mut d, 0x30, eci_in);
    tl(&mut d, 0x06, OID_DATA.len() as u64);
    d.extend(OID_DATA);
    tl(&mut d, 0x30, alg_in);
    aes_oid(&mut d, arc);
    tl(&mut d, 0x30, gp_in);
    tl(&mut d, 0x04, nonce.len() as u64);
    d.extend(nonce);
    d.extend([0x02, 0x01, tag_len as u8]);
    tl(&mut d, 0x80, content_len);
    Some(d)
}

/// `cmsenv_write_tail`: what follows the content, the tag.
pub fn tail(tag: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    tl(&mut d, 0x04, tag.len() as u64);
    d.extend(tag);
    d
}

/// One whole DER TLV at the start of `d`: its tag, its value, and what follows it. None for
/// a long tag, an indefinite length or a value past the end.
pub(crate) fn der_tlv(d: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let mut r = Rd { p: d, pos: 0 };
    let (t, l) = r.get_tl()?;
    let l = usize::try_from(l).ok().filter(|&l| l <= r.left())?;
    let v = r.take(l);
    Some((t, v, &d[r.pos + l..]))
}

// --- reading ----------------------------------------------------------------------------------

/// A key-encryption-key recipient (KEKRecipientInfo, RFC 5652 §6.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kek<'a> {
    /// KEKIdentifier.keyIdentifier.
    pub id: &'a [u8],
    /// 128, 192, 256: id-aesNNN-wrap.
    pub wrap_bits: u32,
    /// The wrapped content key.
    pub ekey: &'a [u8],
}

/// A key-transport recipient (KeyTransRecipientInfo, RFC 5652 §6.2.1). Only RSAES-OAEP with
/// SHA-256 and MGF1-SHA-256 opens; any other is listed with the reason in `refused`, so a
/// caller can say why the file did not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ktri<'a> {
    /// `[0] subjectKeyIdentifier`, or
    pub ski: Option<&'a [u8]>,
    /// `issuerAndSerialNumber`, its whole TLV.
    pub ias: Option<&'a [u8]>,
    pub refused: Option<&'static str>,
    pub ekey: &'a [u8],
}

/// `struct cmsenv_head`, its slices pointing into the buffer read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head<'a> {
    pub kek: Vec<Kek<'a>>,
    pub ktri: Vec<Ktri<'a>>,
    /// Recipients of other kinds, not read here.
    pub n_other: usize,
    /// 128, 192 or 256.
    pub gcm_bits: u32,
    pub nonce: &'a [u8],
    /// aes-ICVlen; 12 when the file leaves it out.
    pub tag_len: usize,
    /// Where the encrypted bytes start.
    pub content_off: u64,
    pub content_len: u64,
}

/// `struct rd`.
struct Rd<'a> {
    p: &'a [u8],
    pos: usize,
}

impl<'a> Rd<'a> {
    fn left(&self) -> usize {
        self.p.len() - self.pos
    }

    /// The byte at `pos`, which C reads only once it has checked `pos` is inside.
    fn byte(&self) -> u8 {
        self.p[self.pos]
    }

    fn take(&self, len: usize) -> &'a [u8] {
        &self.p[self.pos..self.pos + len]
    }

    /// `get_tl`: one TL, definite lengths only. The length may exceed what is left (the
    /// encrypted content's does); the caller decides whether that is allowed.
    fn get_tl(&mut self) -> Option<(u8, u64)> {
        if self.pos + 2 > self.p.len() {
            return None;
        }
        let tag = self.byte();
        self.pos += 1;
        if tag & 0x1F == 0x1F {
            return None; // high tag numbers: none here
        }
        let b = self.byte();
        self.pos += 1;
        if b < 0x80 {
            return Some((tag, u64::from(b)));
        }
        let k = usize::from(b & 0x7F);
        if k == 0 || k > 8 || self.pos + k > self.p.len() {
            return None; // 0x80: indefinite
        }
        let v = self
            .take(k)
            .iter()
            .fold(0u64, |v, &x| v << 8 | u64::from(x));
        self.pos += k;
        Some((tag, v))
    }

    /// `expect`: a TL of tag `want` whose value fits in the buffer; the value's length.
    fn expect(&mut self, want: u8) -> Option<usize> {
        match self.get_tl()? {
            (t, l) if t == want && l <= self.left() as u64 => Some(l as usize),
            _ => None,
        }
    }

    /// `expect` of an OBJECT IDENTIFIER whose value is `oid`.
    fn expect_oid(&mut self, oid: &[u8]) -> bool {
        matches!(self.expect(0x06), Some(l) if self.take(l) == oid)
    }
}

/// `aes_oid_arc`: the last arc of an AES OID, its value `v`.
fn aes_oid_arc(v: &[u8]) -> Option<u8> {
    match v {
        [prefix @ .., arc] if prefix == OID_AES_PREFIX => Some(*arc),
        _ => None,
    }
}

fn parse_kek<'a>(r: &mut Rd<'a>, len: usize, h: &mut Head<'a>) -> Result<(), &'static str> {
    let end = r.pos + len;
    match r.expect(0x02) {
        Some(1) if r.byte() == 4 => r.pos += 1,
        _ => return Err("a KEK recipient whose version is not 4"),
    }
    let l = r
        .expect(0x30)
        .ok_or("a KEK recipient without a KEKIdentifier")?;
    let kid_end = r.pos + l;
    let il = r
        .expect(0x04)
        .ok_or("a KEKIdentifier without a keyIdentifier")?;
    let id = r.take(il);
    r.pos = kid_end; // date and other: not used
    let l = r
        .expect(0x30)
        .ok_or("a KEK recipient without its wrap algorithm")?;
    let alg_end = r.pos + l;
    let not_wrap = "a KEK recipient whose key is not wrapped with AES key wrap";
    let ol = r.expect(0x06).ok_or(not_wrap)?;
    let wrap_bits = match aes_oid_arc(r.take(ol)).ok_or(not_wrap)? {
        5 => 128,
        25 => 192,
        45 => 256,
        _ => return Err(not_wrap),
    };
    r.pos = alg_end;
    let l = r
        .expect(0x04)
        .ok_or("a KEK recipient without its encrypted key")?;
    let ekey = r.take(l);
    r.pos = end;
    if h.kek.len() < KEK_MAX {
        h.kek.push(Kek {
            id,
            wrap_bits,
            ekey,
        });
    }
    Ok(())
}

/// `is_alg`: an AlgorithmIdentifier whose OID is `oid`, parameters absent or NULL.
fn is_alg(r: &mut Rd, oid: &[u8]) -> bool {
    let Some(l) = r.expect(0x30) else {
        return false;
    };
    let end = r.pos + l;
    let Some(ol) = r.expect(0x06) else {
        return false;
    };
    if r.take(ol) != oid {
        return false;
    }
    r.pos += ol;
    if r.pos < end && !(end - r.pos == 2 && r.p[r.pos] == 0x05 && r.p[r.pos + 1] == 0) {
        return false;
    }
    r.pos = end;
    true
}

/// `oaep_params`: SHA-256, MGF1 with SHA-256, the empty label. Anything else is named, not
/// guessed at: SHA-1 is the default the structure falls back to when the fields are left out.
fn oaep_params(r: &mut Rd, end: usize) -> Option<&'static str> {
    let (mut hash_ok, mut mgf_ok) = (false, false);
    if r.pos < end && r.byte() == 0xA0 {
        let Some(l) = r.expect(0xA0) else {
            return Some("malformed RSAES-OAEP parameters");
        };
        let e0 = r.pos + l;
        hash_ok = is_alg(r, OID_SHA256) && r.pos == e0;
        r.pos = e0;
    }
    if r.pos < end && r.byte() == 0xA1 {
        let Some(l) = r.expect(0xA1) else {
            return Some("malformed RSAES-OAEP parameters");
        };
        let e1 = r.pos + l;
        if let Some(sl) = r.expect(0x30) {
            let se = r.pos + sl;
            if let Some(ol) = r.expect(0x06)
                && r.take(ol) == OID_MGF1
            {
                r.pos += ol;
                mgf_ok = is_alg(r, OID_SHA256) && r.pos == se;
            }
        }
        r.pos = e1;
    }
    if r.pos < end {
        return Some("RSA-OAEP with a label, which this does not open");
    }
    if !hash_ok || !mgf_ok {
        return Some("RSA-OAEP with a hash other than SHA-256, which this does not open");
    }
    None
}

fn parse_ktri<'a>(r: &mut Rd<'a>, len: usize, h: &mut Head<'a>) -> Result<(), &'static str> {
    let end = r.pos + len;
    match r.expect(0x02) {
        Some(1) if matches!(r.byte(), 0 | 2) => r.pos += 1,
        _ => return Err("a key-transport recipient whose version is neither 0 nor 2"),
    }
    let (mut ski, mut ias) = (None, None);
    if r.pos < end && r.byte() == 0x80 {
        let l = r.expect(0x80).ok_or("a malformed subjectKeyIdentifier")?;
        ski = Some(r.take(l));
        r.pos += l;
    } else {
        let at = r.pos;
        let l = r
            .expect(0x30)
            .ok_or("a key-transport recipient that names no key")?;
        r.pos += l;
        ias = Some(&r.p[at..r.pos]);
    }
    let no_alg = "a key-transport recipient without its algorithm";
    let l = r.expect(0x30).ok_or(no_alg)?;
    let alg_end = r.pos + l;
    let ol = r.expect(0x06).ok_or(no_alg)?;
    let oid = r.take(ol);
    r.pos += ol;
    let refused = if oid == OID_RSAES_OAEP {
        match (r.pos < alg_end).then(|| r.expect(0x30)).flatten() {
            None => Some("RSA-OAEP with SHA-1, which this does not open"),
            Some(pl) => oaep_params(r, r.pos + pl),
        }
    } else if oid == OID_RSA_ENC {
        Some(
            "RSA PKCS#1 v1.5 key transport, which this does not open: it is the padding Bleichenbacher's attack works on",
        )
    } else {
        Some("a key-transport algorithm this does not know")
    };
    r.pos = alg_end;
    let l = r
        .expect(0x04)
        .ok_or("a key-transport recipient without its encrypted key")?;
    let ekey = r.take(l);
    r.pos = end;
    if h.ktri.len() < KTRI_MAX {
        h.ktri.push(Ktri {
            ski,
            ias,
            refused,
            ekey,
        });
    }
    Ok(())
}

/// `cmsenv_parse_head`: the head, from the first bytes of a file (up to [`HEAD_MAX`]). The
/// error is a phrase a person can act on.
pub fn parse_head(buf: &[u8]) -> Result<Head<'_>, &'static str> {
    let mut r = Rd { p: buf, pos: 0 };
    let mut h = Head {
        kek: Vec::new(),
        ktri: Vec::new(),
        n_other: 0,
        gcm_bits: 0,
        nonce: &[],
        tag_len: 12,
        content_off: 0,
        content_len: 0,
    };
    if !matches!(r.get_tl(), Some((0x30, _))) {
        return Err(
            "not a DER CMS structure (an indefinite-length BER file can be converted with openssl cms -cmsout -outform DER)",
        );
    }
    match r.expect(0x06) {
        Some(l) if r.take(l) == OID_AUTH_ENV => r.pos += l,
        _ => return Err("not CMS AuthEnvelopedData"),
    }
    if !matches!(r.get_tl(), Some((0xA0, _))) {
        return Err("AuthEnvelopedData without its content");
    }
    if !matches!(r.get_tl(), Some((0x30, _))) {
        return Err("AuthEnvelopedData is not a SEQUENCE");
    }
    match r.expect(0x02) {
        Some(1) if r.byte() == 0 => r.pos += 1,
        _ => return Err("AuthEnvelopedData version is not 0"),
    }
    if r.pos < buf.len() && r.byte() == 0xA0 {
        // originatorInfo: skipped
        let l = r.expect(0xA0).ok_or("a malformed originatorInfo")?;
        r.pos += l;
    }
    let l = r.expect(0x31).ok_or("no recipients")?;
    let set_end = r.pos + l;
    while r.pos < set_end {
        // A recipient whose TL runs past the set is refused here; C's unsigned subtraction
        // let it through to the next check (recorded in TRANSFORMATION_NOTES.md, slice 3).
        let (t, l) = match r.get_tl() {
            Some((t, l)) if r.pos <= set_end && l <= (set_end - r.pos) as u64 => (t, l as usize),
            _ => return Err("a malformed recipient"),
        };
        match t {
            0xA2 => parse_kek(&mut r, l, &mut h)?,
            0x30 => parse_ktri(&mut r, l, &mut h)?,
            _ => {
                h.n_other += 1; // A1 kari, A3 pwri, A4 ori
                r.pos += l;
            }
        }
    }
    // EncryptedContentInfo holds the content itself, so its length runs past the head: its
    // tag is checked, its length is not held to the buffer.
    if !matches!(r.get_tl(), Some((0x30, _))) {
        return Err("no EncryptedContentInfo");
    }
    if !r.expect_oid(OID_DATA) {
        return Err("the encrypted content is not plain data");
    }
    r.pos += OID_DATA.len();
    let l = r.expect(0x30).ok_or("no content-encryption algorithm")?;
    let alg_end = r.pos + l;
    let not_gcm = "the content is not AES-GCM";
    let l = r.expect(0x06).ok_or(not_gcm)?;
    h.gcm_bits = match aes_oid_arc(r.take(l)).ok_or(not_gcm)? {
        6 => 128,
        26 => 192,
        46 => 256,
        _ => return Err(not_gcm),
    };
    r.pos += l;
    let l = r.expect(0x30).ok_or("AES-GCM without its parameters")?;
    let gp_end = r.pos + l;
    match r.expect(0x04) {
        Some(l) if (1..=16).contains(&l) => {
            h.nonce = r.take(l);
            r.pos += l;
        }
        _ => return Err("an AES-GCM nonce this does not take"),
    }
    if r.pos < gp_end {
        match r.expect(0x02) {
            Some(1) if (12..=16).contains(&r.byte()) => {
                h.tag_len = usize::from(r.byte());
                r.pos += 1;
            }
            _ => return Err("an AES-GCM tag length outside 12..16"),
        }
    }
    r.pos = alg_end;
    match r.get_tl() {
        Some((0xA0, _)) => {
            return Err(
                "the encrypted content is in BER pieces; convert with openssl cms -cmsout -outform DER",
            );
        }
        Some((0x80, l)) => {
            h.content_off = r.pos as u64;
            h.content_len = l;
        }
        _ => return Err("no encrypted content"),
    }
    if h.kek.is_empty() && h.ktri.is_empty() {
        return Err(if h.n_other > 0 {
            "no recipient this tool opens: key agreement, password and other recipients are not read"
        } else {
            "no recipients"
        });
    }
    Ok(h)
}

/// `cmsenv_parse_tail`: the bytes after the content, to the end of the file; the tag.
pub fn parse_tail<'a>(buf: &'a [u8], h: &Head) -> Result<&'a [u8], &'static str> {
    let mut r = Rd { p: buf, pos: 0 };
    let tag = match r.get_tl() {
        None => return Err("the file ends before its authentication tag"),
        Some((0xA1, _)) => return Err("authenticated attributes, which this does not read"),
        Some((0x04, l)) if l == h.tag_len as u64 && l <= r.left() as u64 => r.take(l as usize),
        Some(_) => return Err("an authentication tag of the wrong length"),
    };
    r.pos += tag.len();
    // unauthAttrs [2] may follow; nothing else may.
    if r.pos < buf.len() && r.byte() != 0xA2 {
        return Err("bytes after the authentication tag");
    }
    Ok(tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(ri: &[u8], content: &[u8], tag: &[u8]) -> Vec<u8> {
        let mut f = head(ri, 256, &[7; 12], content.len() as u64, tag.len()).unwrap();
        f.extend(content);
        f.extend(tail(tag));
        f
    }

    #[test]
    fn round_trip_both_recipients() {
        let kek = kekri(b"filekey", 256, &[0xEE; 40]).unwrap();
        let ktri = ktri_oaep(Rid::Ski(&[0x5A; 20]), &[0xCC; 384]);
        let ias = ktri_oaep(Rid::Ias(&[0x30, 0x03, 0x02, 0x01, 0x09]), &[0xCC; 8]);
        for (ri, kind) in [(&kek, 0), (&ktri, 1), (&ias, 2)] {
            let content = vec![0xAB; 300]; // a long-form length in the content's TL
            let f = file(ri, &content, &[0x11; 16]);
            let h = parse_head(&f).unwrap();
            assert_eq!((h.gcm_bits, h.nonce, h.tag_len), (256, &[7u8; 12][..], 16));
            let off = h.content_off as usize;
            assert_eq!(&f[off..off + h.content_len as usize], &content[..]);
            assert_eq!(
                parse_tail(&f[off + content.len()..], &h),
                Ok(&[0x11u8; 16][..])
            );
            match kind {
                0 => assert_eq!(
                    h.kek,
                    [Kek {
                        id: b"filekey",
                        wrap_bits: 256,
                        ekey: &[0xEE; 40]
                    }]
                ),
                1 => assert_eq!(
                    (h.ktri[0].ski, h.ktri[0].refused, h.ktri[0].ekey.len()),
                    (Some(&[0x5A; 20][..]), None, 384)
                ),
                _ => assert_eq!(
                    (h.ktri[0].ias, h.ktri[0].ski),
                    (Some(&[0x30, 0x03, 0x02, 0x01, 0x09][..]), None)
                ),
            }
        }
    }

    #[test]
    fn writes_as_cms_env_c() {
        // tlv and tl agree on every length form.
        for len in [0u64, 0x7F, 0x80, 0xFF, 0x100, 0xFFFF, 0x1_0000, 1 << 40] {
            let mut d = Vec::new();
            tl(&mut d, 0x04, len);
            assert_eq!(d.len() as u64 + len, tlv(len), "{len:#x}");
        }
        // The KEK recipient, byte for byte as cmsenv_kekri builds it.
        assert_eq!(
            kekri(b"k", 128, &[1, 2]).unwrap(),
            [
                0xA2, 0x19, 0x02, 0x01, 0x04, 0x30, 0x03, 0x04, 0x01, b'k', 0x30, 0x0B, 0x06, 0x09,
                0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x05, 0x04, 0x02, 1, 2
            ]
        );
        assert_eq!(kekri(b"k", 64, &[]), None);
        assert_eq!(head(b"", 256, &[0; 12], 0, 11), None);
        assert_eq!(head(b"", 256, &[], 0, 16), None);
        assert_eq!(head(b"", 255, &[0; 12], 0, 16), None);
    }

    #[test]
    fn refusals_by_name() {
        let kek = kekri(b"k", 256, &[0; 40]).unwrap();
        let good = file(&kek, b"x", &[0; 16]);
        assert_eq!(
            parse_head(b"\x31\x00").unwrap_err(),
            "not a DER CMS structure (an indefinite-length BER file can be converted with openssl cms -cmsout -outform DER)"
        );
        let mut bad = good.clone();
        bad[3 + 2 + 9] ^= 1; // a byte of the OID, after the head's long-form 30 81 xx
        assert_eq!(parse_head(&bad).unwrap_err(), "not CMS AuthEnvelopedData");
        // Only key-agreement recipients.
        let other = file(b"\xA1\x00", b"x", &[0; 16]);
        assert_eq!(
            parse_head(&other).unwrap_err(),
            "no recipient this tool opens: key agreement, password and other recipients are not read"
        );
        // PKCS#1 v1.5 and SHA-1 OAEP are read and refused by name, not as malformed.
        let v15 = [
            &[
                0x30, 0x19, 0x02, 0x01, 0x02, 0x80, 0x01, 0xAA, 0x30, 0x0D, 0x06, 0x09,
            ][..],
            OID_RSA_ENC,
            &[0x05, 0x00, 0x04, 0x02, 0xBB, 0xBB],
        ]
        .concat();
        let h = file(&v15, b"x", &[0; 16]);
        let h = parse_head(&h).unwrap();
        assert!(h.ktri[0].refused.unwrap().starts_with("RSA PKCS#1 v1.5"));
        let sha1 = [
            &[
                0x30, 0x17, 0x02, 0x01, 0x02, 0x80, 0x01, 0xAA, 0x30, 0x0B, 0x06, 0x09,
            ][..],
            OID_RSAES_OAEP,
            &[0x04, 0x02, 0xBB, 0xBB],
        ]
        .concat();
        let h = file(&sha1, b"x", &[0; 16]);
        assert_eq!(
            parse_head(&h).unwrap().ktri[0].refused,
            Some("RSA-OAEP with SHA-1, which this does not open")
        );
        // The tail.
        let h = parse_head(&good).unwrap();
        assert_eq!(
            parse_tail(b"\x04\x0C", &h).unwrap_err(),
            "an authentication tag of the wrong length"
        );
        assert_eq!(
            parse_tail(b"\xA1\x00", &h).unwrap_err(),
            "authenticated attributes, which this does not read"
        );
        assert_eq!(
            parse_tail(&[&tail(&[0; 16])[..], b"\x05"].concat(), &h).unwrap_err(),
            "bytes after the authentication tag"
        );
        assert!(parse_tail(&[&tail(&[0; 16])[..], b"\xA2\x00"].concat(), &h).is_ok());
        // Every prefix of a good head, and every single-byte change to one of each recipient
        // kind, is refused or read, never a panic.
        for n in 0..good.len() {
            let _ = parse_head(&good[..n]);
        }
        let ktri = ktri_oaep(Rid::Ski(&[0x5A; 20]), &[0xCC; 384]);
        let ias = ktri_oaep(Rid::Ias(&[0x30, 0x03, 0x02, 0x01, 0x09]), &[0xCC; 8]);
        for f in [
            good.clone(),
            file(&ktri, b"x", &[0; 16]),
            file(&ias, b"x", &[0; 16]),
        ] {
            for i in 0..f.len() {
                for x in [0x01, 0x80, 0xFF] {
                    let mut m = f.clone();
                    m[i] ^= x;
                    if let Ok(h) = parse_head(&m) {
                        let at = (h.content_off + h.content_len).min(m.len() as u64) as usize;
                        let _ = parse_tail(&m[at..], &h);
                    }
                }
            }
        }
    }
}
