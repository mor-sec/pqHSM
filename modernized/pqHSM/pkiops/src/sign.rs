//! What `fhsm-sign` calls (PHASE5_PLAN.md slice 4): digests of a stream (`pkiops_hash_*`),
//! signatures streamed through the module (`pkiops_sign_*`, `pkiops_verify_*`), and detached
//! CMS SignedData (`pkiops_cms_*`), with DIV-075's signer.

use std::ffi::{CStr, c_int, c_long, c_void};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{null, null_mut};

use openssl::md::Md;
use openssl::md_ctx::MdCtx;
use pqhsm_pki::ffi::x509;

use crate::ffi::{
    CK_MECHANISM, CK_ULONG, w_sign_final, w_sign_init, w_sign_update, w_verify_final,
    w_verify_init, w_verify_update,
};
use crate::keys::Alg;
use crate::ops::{
    CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, Handle, RV_ARGUMENTS_BAD, Session, alg_of, ecdsa_der, err,
    find_one, signed_by, to_vec, with_mechanism,
};
use crate::{Error, strerror};

const CKR_SIGNATURE_INVALID: CK_ULONG = 0xC0;
const RV_SIGNATURE_INVALID: u32 = 0xC0;

/// The room `tools/fhsm_sign.c` gives a certificate, a CMS structure, and the CMS it builds.
pub const CMS_MAX: usize = 262_144;

/// `struct pkiops_hash`: one digest over a stream.
/// `EVP_DigestInit_ex` holds its own reference to the fetched digest.
pub struct Hash {
    ctx: MdCtx,
}

impl Hash {
    /// `pkiops_hash_begin`: the digest `name` names, as `EVP_MD_fetch` takes it.
    pub fn begin(name: Option<&CStr>) -> Result<Hash, Error> {
        let fail = || Error::new(2, "digest init failed\n");
        let md = name
            .and_then(|n| n.to_str().ok())
            .and_then(|n| Md::fetch(None, n, None).ok())
            .ok_or_else(fail)?;
        let mut ctx = MdCtx::new().map_err(|_| fail())?;
        ctx.digest_init(&md).map_err(|_| fail())?;
        Ok(Hash { ctx })
    }

    /// `pkiops_hash_update`.
    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        self.ctx
            .digest_update(data)
            .map_err(|_| Error::new(2, "digest failed\n"))
    }

    /// `pkiops_hash_end`: the digest, at most EVP_MAX_MD_SIZE (64) bytes.
    pub fn end(mut self) -> Result<Vec<u8>, Error> {
        let mut out = [0u8; 64];
        let n = self
            .ctx
            .digest_final(&mut out)
            .map_err(|_| Error::new(2, "digest failed\n"))?;
        Ok(out[..n].to_vec())
    }
}

type Init = unsafe extern "C" fn(CK_ULONG, *mut CK_MECHANISM, CK_ULONG) -> CK_ULONG;
type Update = unsafe extern "C" fn(CK_ULONG, *mut u8, CK_ULONG) -> CK_ULONG;

/// The key of `class` labelled `label`, its algorithm, and `init` with its mechanism.
fn begin(s: Handle, label: &[u8], class: CK_ULONG, init: Init, what: &str) -> Result<Alg, Error> {
    let h = find_one(s, class, label)?;
    let a = alg_of(s, label, h)?;
    // SAFETY: the mechanism lives for the call.
    let rv = with_mechanism(a, |m| unsafe { init(s, m, h) });
    if rv != 0 {
        return Err(Error::new(2, format!("{what} failed (0x{rv:x})\n")));
    }
    Ok(a)
}

/// `update` with `data`.
fn feed(s: Handle, data: &[u8], update: Update, what: &str) -> Result<(), Error> {
    // SAFETY: data.len() readable bytes, not written.
    let rv = unsafe { update(s, data.as_ptr().cast_mut(), data.len() as CK_ULONG) };
    if rv != 0 {
        return Err(Error::new(2, format!("{what} failed (0x{rv:x})\n")));
    }
    Ok(())
}

/// A signature under way: the module allows one operation per session, and its algorithm is
/// kept for the ECDSA signature's conversion at the end.
pub struct Signing {
    pub(crate) s: Handle,
    pub(crate) alg: Alg,
}

impl Signing {
    /// `pkiops_sign_begin`: with the private key `label`, in its own algorithm.
    pub fn begin(s: Session, label: &[u8]) -> Result<Signing, Error> {
        let alg = begin(s.0, label, CKO_PRIVATE_KEY, w_sign_init, "C_SignInit")?;
        Ok(Signing { s: s.0, alg })
    }

    /// `pkiops_sign_update`.
    pub fn update(&self, data: &[u8]) -> Result<(), Error> {
        feed(self.s, data, w_sign_update, "C_SignUpdate")
    }

    /// `pkiops_sign_end`: the signature, ECDSA's as DER, which `openssl dgst -verify` reads.
    pub fn end(self) -> Result<Vec<u8>, Error> {
        // The length is the module's to say: it is the mechanism's.
        let mut need: CK_ULONG = 0;
        // SAFETY: a size query; need is writable.
        let rv = unsafe { w_sign_final(self.s, null_mut(), &mut need) };
        if rv != 0 {
            return Err(Error::new(
                2,
                format!("C_SignFinal (size query) failed (0x{rv:x})\n"),
            ));
        }
        let mut buf = vec![0u8; need as usize];
        let mut n = need;
        // SAFETY: n writable bytes at buf.
        let rv = unsafe { w_sign_final(self.s, buf.as_mut_ptr(), &mut n) };
        if rv != 0 {
            return Err(Error::new(2, format!("C_SignFinal failed (0x{rv:x})\n")));
        }
        buf.truncate(n as usize);
        if self.alg.info().ecdsa_half == 0 {
            return Ok(buf);
        }
        ecdsa_der(&buf).map_err(|r| {
            Error::new(
                2,
                format!("encoding the ECDSA signature failed (0x{r:x})\n"),
            )
        })
    }
}

/// A verification under way, as [`Signing`].
pub struct Verifying {
    pub(crate) s: Handle,
    pub(crate) alg: Alg,
}

impl Verifying {
    /// `pkiops_verify_begin`: with the public key `label`.
    pub fn begin(s: Session, label: &[u8]) -> Result<Verifying, Error> {
        let alg = begin(s.0, label, CKO_PUBLIC_KEY, w_verify_init, "C_VerifyInit")?;
        Ok(Verifying { s: s.0, alg })
    }

    /// `pkiops_verify_update`.
    pub fn update(&self, data: &[u8]) -> Result<(), Error> {
        feed(self.s, data, w_verify_update, "C_VerifyUpdate")
    }

    /// `pkiops_verify_end`: whether `sig` matches. A signature that does not, or is not one
    /// at all, is `false`; only a failure to check is an error.
    pub fn end(self, sig: &[u8]) -> Result<bool, Error> {
        let half = self.alg.info().ecdsa_half;
        let raw;
        let sig = if half == 0 {
            sig
        } else if let Some(r) = ecdsa_der_to_raw(sig, half) {
            raw = r;
            &raw[..]
        } else {
            // Not an ECDSA signature. The operation is still ended: the session outlives it.
            let zero = vec![0u8; 2 * half];
            // SAFETY: 2 * half readable bytes.
            unsafe { w_verify_final(self.s, zero.as_ptr().cast_mut(), zero.len() as CK_ULONG) };
            return Ok(false);
        };
        // SAFETY: sig.len() readable bytes, not written.
        match unsafe { w_verify_final(self.s, sig.as_ptr().cast_mut(), sig.len() as CK_ULONG) } {
            0 => Ok(true),
            CKR_SIGNATURE_INVALID => Ok(false),
            rv => Err(Error::new(2, format!("C_VerifyFinal failed (0x{rv:x})\n"))),
        }
    }
}

/// `ecdsa_der_to_raw`: a DER Ecdsa-Sig-Value, parsed whole, as the r || s PKCS#11 takes.
fn ecdsa_der_to_raw(der: &[u8], half: usize) -> Option<Vec<u8>> {
    let mut raw = vec![0u8; 2 * half];
    // SAFETY: der readable for its length; es freed below; raw has 2 * half writable bytes.
    unsafe {
        let mut p = der.as_ptr();
        let es = openssl_sys::d2i_ECDSA_SIG(null_mut(), &mut p, der.len() as c_long);
        if es.is_null() {
            return None;
        }
        let (mut r, mut s) = (null(), null());
        openssl_sys::ECDSA_SIG_get0(es, &mut r, &mut s);
        let h = half as c_int;
        let ok = p == der.as_ptr().add(der.len())
            && openssl_sys::BN_bn2binpad(r, raw.as_mut_ptr(), h) == h
            && openssl_sys::BN_bn2binpad(s, raw.as_mut_ptr().add(half), h) == h;
        openssl_sys::ECDSA_SIG_free(es);
        ok.then_some(raw)
    }
}

/// `pkiops_cms_sign` into the caller's buffer.
///
/// # Safety
/// `out` has `*len` writable bytes.
pub(crate) unsafe fn cms_sign_into(
    s: Handle,
    label: &[u8],
    cert: &[u8],
    digest: &[u8],
    out: *mut u8,
    len: &mut usize,
) -> Result<(), Error> {
    // SAFETY: the caller's room.
    unsafe {
        signed_by(s, label, false, out, len, "CMS", |sg, alg, _| {
            x509::cms(sg, alg.info().digest, cert, digest)
        })
    }
}

/// `pkiops_cms_sign`: detached SignedData over `digest` (computed with the key's algorithm's
/// digest, [`crate::keys::Info::digest`]) with signed attributes, carrying `cert`.
pub fn cms_sign(s: Session, label: &[u8], cert: &[u8], digest: &[u8]) -> Result<Vec<u8>, Error> {
    // SAFETY: to_vec hands n writable bytes.
    to_vec(CMS_MAX, |out, n| unsafe {
        cms_sign_into(s.0, label, cert, digest, out, n)
    })
}

/// `pkiops_cms_digest`: the digest `cms` names, when it has one SignerInfo naming SHA-256,
/// -384 or -512.
pub fn cms_digest(cms: &[u8]) -> Option<&'static CStr> {
    x509::cms_digest(cms).ok().flatten()
}

/// What `pkiops_cms_verify` says of a CMS and the data's digest.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// It verifies, under `signer` (DER).
    Verified { signer: Vec<u8> },
    /// It does not match the data.
    Mismatch,
    /// It is not a CMS this library can read.
    Unreadable,
}

/// `pkiops_cms_verify`. DIV-075: verified only when its SignerInfo names the certificate it
/// carries, which fhsm_pki checks for the other algorithms and not for the composite.
pub fn cms_verify(cms: &[u8], digest: &[u8]) -> Result<Verdict, Error> {
    match x509::pki_cms_verify(cms, digest) {
        0 => {
            Ok(signer_cert(cms).map_or(Verdict::Unreadable, |signer| Verdict::Verified { signer }))
        }
        RV_SIGNATURE_INVALID => Ok(Verdict::Mismatch),
        RV_ARGUMENTS_BAD => Ok(Verdict::Unreadable),
        r => Err(Error::new(
            2,
            format!("verifying the CMS failed (0x{r:x})\n"),
        )),
    }
}

type P = *mut c_void;

unsafe extern "C" {
    fn d2i_CMS_ContentInfo(a: *mut P, pp: *mut *const u8, len: c_long) -> P;
    fn CMS_ContentInfo_free(ci: P);
    fn CMS_get0_SignerInfos(ci: P) -> P;
    fn CMS_get1_certs(ci: P) -> P;
    fn CMS_SignerInfo_cert_cmp(si: P, x: P) -> c_int;
    fn OPENSSL_sk_num(st: P) -> c_int;
    fn OPENSSL_sk_value(st: P, i: c_int) -> P;
    fn OPENSSL_sk_pop_free(st: P, f: unsafe extern "C" fn(P));
    fn X509_free(x: P);
    fn i2d_X509(x: P, out: *mut *mut u8) -> c_int;
}

/// The one certificate `cms` carries, DER, when its one SignerInfo's identifier (issuer and
/// serial, or subject key identifier) names it.
fn signer_cert(cms: &[u8]) -> Option<Vec<u8>> {
    // SAFETY: cms readable for its length; ci and the certificate stack are freed below, and
    // the SignerInfo and certificate borrowed from them used before.
    unsafe {
        let mut p = cms.as_ptr();
        let ci = d2i_CMS_ContentInfo(null_mut(), &mut p, cms.len() as c_long);
        if ci.is_null() {
            return None;
        }
        let sis = CMS_get0_SignerInfos(ci);
        let certs = CMS_get1_certs(ci);
        let mut der = None;
        if !sis.is_null()
            && !certs.is_null()
            && OPENSSL_sk_num(sis) == 1
            && OPENSSL_sk_num(certs) == 1
        {
            let x = OPENSSL_sk_value(certs, 0);
            let n = i2d_X509(x, null_mut());
            if CMS_SignerInfo_cert_cmp(OPENSSL_sk_value(sis, 0), x) == 0 && n > 0 {
                let mut v = vec![0u8; n as usize];
                let mut q = v.as_mut_ptr();
                i2d_X509(x, &mut q);
                der = Some(v);
            }
        }
        if !certs.is_null() {
            OPENSSL_sk_pop_free(certs, X509_free);
        }
        CMS_ContentInfo_free(ci);
        der
    }
}

/// A DER certificate's subject, as `fhsm-crypt show` prints one, and its SHA-256 fingerprint
/// in hex; None when it is not a certificate.
pub fn describe_cert(der: &[u8]) -> Option<(Vec<u8>, String)> {
    let subject = crate::objects::cert_subject(der)?;
    let fp = openssl::sha::sha256(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Some((subject, fp))
}

unsafe extern "C" {
    fn PEM_read_bio(
        bp: *mut openssl_sys::BIO,
        name: *mut *mut libc::c_char,
        header: *mut *mut libc::c_char,
        data: *mut *mut u8,
        len: *mut c_long,
    ) -> c_int;
}

/// `slurp_der`: a whole small file, a certificate or a CMS, at most [`CMS_MAX`] bytes; PEM is
/// decoded (its first block, whatever its label). The data being signed is never read so.
pub fn read_der(path: &Path) -> Result<Vec<u8>, Error> {
    let name = path.as_os_str().as_bytes();
    let mut f = File::open(path).map_err(|e| {
        err(
            2,
            &[b"cannot read ", name, b": ", strerror(&e).as_bytes(), b"\n"],
        )
    })?;
    // fread's: until full, the end, or an error.
    let mut buf = vec![0u8; CMS_MAX];
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(err(2, &[b"reading ", name, b" failed\n"])),
        }
    }
    if n == 0 {
        return Err(err(2, &[name, b" is empty\n"]));
    }
    // A full buffer is too large, whether or not more follows.
    if n == buf.len() {
        return Err(err(2, &[name, b" is too large\n"]));
    }
    buf.truncate(n);
    if n > 11 && buf.starts_with(b"-----BEGIN ") {
        return pem_body(&buf)
            .ok_or_else(|| err(2, &[name, b" looks like PEM but did not parse\n"]));
    }
    Ok(buf)
}

/// `PEM_read_bio`'s first block, when it parses and is not empty.
fn pem_body(text: &[u8]) -> Option<Vec<u8>> {
    // SAFETY: a read-only memory BIO over text, freed below with what PEM_read_bio allocated.
    unsafe {
        let b = openssl_sys::BIO_new_mem_buf(text.as_ptr().cast(), text.len() as c_int);
        if b.is_null() {
            return None;
        }
        let (mut nm, mut hdr, mut d, mut dl) = (null_mut(), null_mut(), null_mut(), 0);
        let ok = PEM_read_bio(b, &mut nm, &mut hdr, &mut d, &mut dl) == 1
            && dl > 0
            && dl as usize <= CMS_MAX;
        let out = ok.then(|| std::slice::from_raw_parts(d, dl as usize).to_vec());
        for p in [nm.cast::<c_void>(), hdr.cast(), d.cast()] {
            openssl_sys::CRYPTO_free(p, c"pkiops".as_ptr(), 0);
        }
        openssl_sys::BIO_free_all(b);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_names_and_lengths() {
        let mut h = Hash::begin(Some(c"SHA256")).unwrap();
        h.update(b"abc").unwrap();
        let d = h.end().unwrap();
        assert_eq!(
            d.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            Hash::begin(Some(c"SHA512")).unwrap().end().unwrap().len(),
            64
        );
        for bad in [None, Some(c"nope"), Some(c"")] {
            assert_eq!(
                Hash::begin(bad).err().unwrap().c_msg(),
                b"digest init failed\n"
            );
        }
    }

    #[test]
    fn ecdsa_der_parsed_whole() {
        // SEQUENCE { INTEGER 1, INTEGER 2 }, for P-256's 32-byte halves.
        let der = [0x30, 6, 2, 1, 1, 2, 1, 2];
        let raw = ecdsa_der_to_raw(&der, 32).unwrap();
        assert_eq!((raw[31], raw[63], raw.len()), (1, 2, 64));
        let mut trailing = der.to_vec();
        trailing.push(0);
        assert_eq!(ecdsa_der_to_raw(&trailing, 32), None);
        assert_eq!(ecdsa_der_to_raw(&der[..7], 32), None);
        assert_eq!(ecdsa_der_to_raw(b"", 32), None);
        // r longer than the half
        let mut long = vec![0x30, 38, 2, 33, 0x7f];
        long.extend([1u8; 32]);
        long.extend([2, 1, 2]);
        assert_eq!(ecdsa_der_to_raw(&long, 32), None);
    }

    #[test]
    fn read_der_as_slurp_der() {
        let dir = tempfile::tempdir().unwrap();
        let p = |n: &str| dir.path().join(n);
        let msg =
            |r: Result<Vec<u8>, Error>| String::from_utf8(r.unwrap_err().c_msg().to_vec()).unwrap();
        std::fs::write(p("der"), [0x30, 0]).unwrap();
        assert_eq!(read_der(&p("der")).unwrap(), [0x30, 0]);
        std::fs::write(p("empty"), b"").unwrap();
        assert!(msg(read_der(&p("empty"))).ends_with("empty is empty\n"));
        std::fs::write(p("big"), vec![0u8; CMS_MAX]).unwrap();
        assert!(msg(read_der(&p("big"))).ends_with("big is too large\n"));
        std::fs::write(p("pem"), b"-----BEGIN X-----\nMAA=\n-----END X-----\n").unwrap();
        assert_eq!(read_der(&p("pem")).unwrap(), [0x30, 0]);
        std::fs::write(p("badpem"), b"-----BEGIN X-----\nMAA=\n").unwrap();
        assert!(msg(read_der(&p("badpem"))).ends_with("badpem looks like PEM but did not parse\n"));
        assert!(msg(read_der(&p("none"))).ends_with("none: No such file or directory\n"));
        assert!(msg(read_der(dir.path())).ends_with(" failed\n"));
    }

    #[test]
    fn cms_verdicts_on_garbage() {
        assert_eq!(
            cms_verify(b"\x30\x00", &[0; 32]).unwrap(),
            Verdict::Unreadable
        );
        assert_eq!(cms_digest(b"\x30\x00"), None);
        assert_eq!(signer_cert(b""), None);
        assert_eq!(describe_cert(b"\x30\x00"), None);
        // a certificate with anything after it is not one certificate
        let key = openssl::pkey::PKey::from_ec_key(
            openssl::ec::EcKey::generate(
                &openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
        let mut b = openssl::x509::X509Builder::new().unwrap();
        b.set_pubkey(&key).unwrap();
        let mut n = openssl::x509::X509NameBuilder::new().unwrap();
        n.append_entry_by_text("CN", "t").unwrap();
        let n = n.build();
        b.set_subject_name(&n).unwrap();
        b.set_issuer_name(&n).unwrap();
        b.set_not_before(&openssl::asn1::Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&openssl::asn1::Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.sign(&key, openssl::hash::MessageDigest::sha256())
            .unwrap();
        let mut der = b.build().to_der().unwrap();
        assert!(describe_cert(&der).is_some());
        der.push(0);
        assert_eq!(describe_cert(&der), None);
    }
}
