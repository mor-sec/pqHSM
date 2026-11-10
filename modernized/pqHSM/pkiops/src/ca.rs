//! `fhsm-ca`'s operations (PHASE5_PLAN.md slice 5): issuing a certificate from a request,
//! signing the revocation list, and answering an OCSP request, each with a key on the token.
//! The database itself, which signs nothing, is `pqhsm_pki::revocation`'s.

use pqhsm_pki::ffi::x509::{self, Revoked};
use pqhsm_pki::revocation::{self as rev, Db, Query, Stats};

pub use pqhsm_pki::ffi::x509::Issue;

use crate::Error;
use crate::ffi::{CK_ULONG, w_generate_random};
use crate::ops::{
    DER_MAX, Handle, RV_ARGUMENTS_BAD, RV_BUFFER_TOO_SMALL, SIG_MAX, Session, emit_into, to_vec,
    with_signer,
};

/// `d2i_X509`'s verdict: whether `der` opens with a certificate (bytes after it allowed).
pub fn is_certificate(der: &[u8]) -> bool {
    openssl::x509::X509::from_der(der).is_ok()
}

/// `FHSM_RV_SIGNATURE_INVALID`: what the issuer says of a request whose proof of possession
/// does not verify.
const RV_SIGNATURE_INVALID: u32 = 0xC0;

/// `pkiops_issue` into the caller's buffer: false, with nothing written, when the request's
/// signature does not match the key it carries.
///
/// # Safety
/// `out` has `*len` writable bytes.
pub(crate) unsafe fn issue_into(
    s: Handle,
    label: &[u8],
    i: &Issue,
    out: *mut u8,
    len: &mut usize,
) -> Result<bool, Error> {
    let der = with_signer(s, label, false, |sg, _, _| {
        // fhsm_pki_issue's
        if i.days <= 0 {
            return Err(RV_ARGUMENTS_BAD);
        }
        // p11_rng: the serial from the token's own DRBG.
        let mut rng = |b: &mut [u8]| {
            // SAFETY: b.len() writable bytes.
            unsafe { w_generate_random(s, b.as_mut_ptr(), b.len() as CK_ULONG) as u32 }
        };
        x509::issue(sg, i, &mut rng)
    })?;
    if der == Err(RV_SIGNATURE_INVALID) {
        return Ok(false);
    }
    // SAFETY: the caller's room.
    unsafe { emit_into(der, out, len, "issuing the certificate") }?;
    Ok(true)
}

/// `pkiops_issue`: the certificate the CA key `label` issues for the request in `i`, or
/// `None` when the request's signature does not match the key it carries (proof of
/// possession), in which case nothing is signed. The request's extensions are ignored.
pub fn issue(s: Session, label: &[u8], i: &Issue) -> Result<Option<Vec<u8>>, Error> {
    let mut valid = true;
    // SAFETY: to_vec hands n writable bytes.
    let der = to_vec(DER_MAX, |out, n| unsafe {
        issue_into(s.0, label, i, out, n).map(|v| valid = v)
    })?;
    Ok(valid.then_some(der))
}

/// `pkiops_crl`: the CRL over `db`, numbered `db.crl_number`, signed with the CA key `label`;
/// `ca` is the CA's certificate. Advancing the number is the caller's.
pub fn crl(s: Session, label: &[u8], ca: &[u8], db: &Db, days: i32) -> Result<Vec<u8>, Error> {
    let list: Vec<Revoked> = db
        .entries
        .iter()
        .map(|e| Revoked {
            serial: &e.serial,
            // validated at load
            date: rev::date_to_time(&e.date).unwrap_or(0),
            reason: e.reason,
        })
        .collect();
    // C's buffer
    let cap = 8192 + db.entries.len() * 80 + SIG_MAX;
    with_signer(s.0, label, false, |sg, _, _| {
        // fhsm_pki_crl's
        if days <= 0 {
            return Err(RV_ARGUMENTS_BAD);
        }
        x509::crl(sg, ca, &list, db.crl_number, days)
    })?
    .and_then(|d| {
        if d.len() > cap {
            Err(RV_BUFFER_TOO_SMALL)
        } else {
            Ok(d)
        }
    })
    .map_err(|r| {
        Error::new(
            2,
            format!("building the revocation list failed (0x{r:x})\n"),
        )
    })
}

/// `pkiops_ocsp`: the answer to `q`'s request, signed with the key `label` (the CA's, or a
/// delegated responder's whose certificate is `q.responder`), and what it said.
pub fn ocsp(s: Session, label: &[u8], q: &Query) -> Result<(Vec<u8>, Stats), Error> {
    with_signer(s.0, label, false, |sg, _, _| {
        rev::answer(q, &mut |t| x509::ocsp_for(sg, t))
    })?
    .map_err(|e| Error::new(e.code, e.msg))
}
