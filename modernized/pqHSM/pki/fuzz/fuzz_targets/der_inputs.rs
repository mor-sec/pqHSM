//! Slice 5 C ABI entry points that parse DER from their caller, given arbitrary bytes. The first
//! byte picks one: 0 the CMS verifiers and fhsm_pki_cms_digest; 1 to 3 the certificate input of
//! fhsm_pki_cms, fhsm_pki_crl and fhsm_pki_ocsp; 4 fhsm_pki_issue, a big-endian 16-bit CA length,
//! the CA, then the request; 5 the signer's SubjectPublicKeyInfo, through fhsm_pki_csr; 6 the
//! signer's AlgorithmIdentifier, the same way; 7 a raw composite public key. The signer writes
//! zeros; nothing needs a key. A mutated request fails its proof of possession, so what issuance
//! does after it sees only the seeds; 5 reaches the same SPKI copy (DIV-049) without one.
#![no_main]

use std::ffi::c_void;
use std::ptr::{null, null_mut};

use libfuzzer_sys::fuzz_target;
use pqhsm_pki::ffi::*;

const ED25519: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];
const ED25519_SPKI: &[u8] = &[
    0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
/// What a verifier may answer: OK, SIGNATURE_INVALID, ARGUMENTS_BAD.
const VERIFY_RV: [u32; 3] = [0, 0xC0, 0x07];
const GENERALIZED: &[u8] = b"\x18\x0f20270101000000Z";

unsafe extern "C" fn sign(_: *mut c_void, _: *const u8, _: usize, sig: *mut u8, sl: *mut usize) -> u32 {
    // SAFETY: sig has *sl writable bytes
    unsafe {
        *sl = (*sl).min(64);
        sig.write_bytes(0, *sl);
    }
    0
}

unsafe extern "C" fn rng(_: *mut c_void, out: *mut u8, n: usize) -> u32 {
    // SAFETY: out has n writable bytes
    unsafe { out.write_bytes(7, n) };
    0
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, der)) = data.split_first() else {
        return;
    };
    let digest = [0x5A; 64];
    let mut out = vec![0u8; 1 << 17];
    let mut n = out.len();
    let s = fhsm_pki_signer_t {
        algid: ED25519.as_ptr(),
        algid_len: ED25519.len(),
        spki: null(),
        spki_len: 0,
        sign: Some(sign),
        sign_ctx: null_mut(),
    };
    let (o, d) = (out.as_mut_ptr(), digest.as_ptr());
    // SAFETY: every buffer covers the length passed with it; out has n writable bytes
    unsafe {
        match which % 8 {
            0 => {
                let mut name = null();
                let r = fhsm_pki_cms_digest(der.as_ptr(), der.len(), &mut name);
                assert!(r == 0 || r == 0x07, "cms_digest 0x{r:x}");
                for r in [
                    fhsm_pki_cms_verify(der.as_ptr(), der.len(), d, 32),
                    fhsm_pki_cms_verify(der.as_ptr(), der.len(), d, 64),
                    fhsm_composite_cms_verify(1, der.as_ptr(), der.len(), d, 64),
                ] {
                    assert!(VERIFY_RV.contains(&r), "verify 0x{r:x}");
                }
            }
            1 => {
                fhsm_pki_cms(&s, c"SHA256".as_ptr(), der.as_ptr(), der.len(), d, 32, o, &mut n);
            }
            2 => {
                fhsm_pki_crl(&s, der.as_ptr(), der.len(), null(), 0, 1, 7, o, &mut n);
            }
            3 => {
                let cert_id = [0x30, 0x03, 0x02, 0x01, 0x01];
                let single = fhsm_composite_ocsp_single_t {
                    cert_id: cert_id.as_ptr(),
                    cert_id_len: cert_id.len(),
                    status: 0,
                    revoked_at: null(),
                    revoked_at_len: 0,
                    reason: -1,
                    this_upd: GENERALIZED.as_ptr(),
                    this_upd_len: GENERALIZED.len(),
                    next_upd: null(),
                    next_upd_len: 0,
                };
                let g = GENERALIZED;
                fhsm_pki_ocsp(&s, der.as_ptr(), der.len(), g.as_ptr(), g.len(), &single, 1, null(), 0, o, &mut n);
            }
            5 => {
                let s = fhsm_pki_signer_t { spki: der.as_ptr(), spki_len: der.len(), ..s };
                fhsm_pki_csr(&s, c"/CN=fuzz".as_ptr(), o, &mut n);
            }
            6 => {
                let s = fhsm_pki_signer_t {
                    algid: der.as_ptr(),
                    algid_len: der.len(),
                    spki: ED25519_SPKI.as_ptr(),
                    spki_len: ED25519_SPKI.len(),
                    ..s
                };
                fhsm_pki_csr(&s, c"/CN=fuzz".as_ptr(), o, &mut n);
            }
            7 => {
                fhsm_composite_raw_pub(1, der.as_ptr(), der.len(), o, &mut n);
            }
            _ => {
                let Some((len, rest)) = der.split_first_chunk::<2>() else {
                    return;
                };
                let (ca, csr) = rest.split_at(usize::from(u16::from_be_bytes(*len)).min(rest.len()));
                fhsm_pki_issue(
                    &s,
                    ca.as_ptr(),
                    ca.len(),
                    csr.as_ptr(),
                    csr.len(),
                    null(),
                    null(),
                    null(),
                    0,
                    0,
                    30,
                    Some(rng),
                    null_mut(),
                    o,
                    &mut n,
                );
            }
        }
    }
});
