//! Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs, `src/fhsm_composite.c:1-481`): the
//! algorithm table, the message representative M' and the module's key blob. Pure; the keys,
//! signing and verification over OpenSSL are in `ffi::composite`.

use std::ffi::CStr;

/// `FHSM_COMPOSITE_MLDSA65_ED25519_SHA512`, the one algorithm.
pub const MLDSA65_ED25519_SHA512: i32 = 1;
/// "CompositeAlgorithmSignatures2025": every M' starts with it.
pub const PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";
/// The context is prefixed by one length byte (draft §2.2).
pub const CTX_MAX: usize = 255;
const BLOB_MAGIC: &[u8; 4] = b"FCMP";
const BLOB_VERSION: u8 = 1;
/// ML-DSA-65 and Ed25519 signature lengths: a composite signature is their concatenation.
pub const PQ_SIG_LEN: usize = 3309;
pub const TRAD_SIG_LEN: usize = 64;

/// `fhsm_composite_params_t` (draft §6).
#[derive(Debug)]
pub struct Params {
    pub alg: i32,
    pub name: &'static CStr,
    pub oid: &'static CStr,
    /// ASCII, used as bytes in M' and as ML-DSA's context string.
    pub label: &'static CStr,
    pub ph_name: &'static CStr,
    pub ph_len: usize,
    /// The components' OpenSSL names.
    pub pq: &'static CStr,
    pub trad: &'static CStr,
}

pub static PARAMS: [Params; 1] = [Params {
    alg: MLDSA65_ED25519_SHA512,
    name: c"id-MLDSA65-Ed25519-SHA512",
    oid: c"1.3.6.1.5.5.7.6.48",
    label: c"COMPSIG-MLDSA65-Ed25519-SHA512",
    ph_name: c"SHA512",
    ph_len: 64,
    pq: c"ML-DSA-65",
    trad: c"ED25519",
}];

/// `fhsm_composite_params`.
pub fn params(alg: i32) -> Option<&'static Params> {
    PARAMS.iter().find(|p| p.alg == alg)
}

/// `fhsm_composite_mprime_len`: 0 for an unknown algorithm or a context over 255 bytes.
pub fn mprime_len(alg: i32, ctx_len: usize) -> usize {
    match params(alg) {
        Some(p) if ctx_len <= CTX_MAX => mprime_need(p, ctx_len),
        _ => 0,
    }
}

fn mprime_need(p: &Params, ctx_len: usize) -> usize {
    PREFIX.len() + p.label.to_bytes().len() + 1 + ctx_len + p.ph_len
}

/// M' = Prefix || Label || len(ctx) || ctx || PH(M) (draft §3.2), into the front of `out`,
/// which holds at least `mprime_len` bytes; returns that length. The caller has checked the
/// context's length and PH's.
pub fn layout(p: &Params, ph: &[u8], ctx: &[u8], out: &mut [u8]) -> usize {
    let label = p.label.to_bytes();
    let parts: [&[u8]; 5] = [PREFIX, label, &[ctx.len() as u8], ctx, ph];
    let mut at = 0;
    for part in parts {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    at
}

/// The blob's length for these components, or None past its 16-bit length fields.
pub fn blob_len(pq: &[u8], trad: &[u8]) -> Option<usize> {
    (pq.len() <= 0xFFFF && trad.len() <= 0xFFFF).then(|| 4 + 1 + 1 + 2 + pq.len() + 2 + trad.len())
}

/// `blob_pack`: "FCMP", version, algorithm, then each component DER behind a little-endian
/// 16-bit length. `out` holds `blob_len` bytes.
pub fn pack(alg: i32, pq: &[u8], trad: &[u8], out: &mut [u8]) {
    let (n1, n2) = (
        (pq.len() as u16).to_le_bytes(),
        (trad.len() as u16).to_le_bytes(),
    );
    let parts: [&[u8]; 6] = [BLOB_MAGIC, &[BLOB_VERSION, alg as u8], &n1, pq, &n2, trad];
    let mut at = 0;
    for part in parts {
        out[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
}

/// Why a blob is refused: C's ARGUMENTS_BAD, or KEY_TYPE_INCONSISTENT for another algorithm's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobError {
    Malformed,
    OtherAlgorithm,
}

/// `blob_unpack`: the two component DERs, checked in C's order.
pub fn unpack(alg: i32, b: &[u8]) -> Result<(&[u8], &[u8]), BlobError> {
    if b.len() < 10 || &b[..4] != BLOB_MAGIC || b[4] != BLOB_VERSION {
        return Err(BlobError::Malformed);
    }
    if b[5] != alg as u8 {
        return Err(BlobError::OtherAlgorithm);
    }
    let n1 = usize::from(u16::from_le_bytes([b[6], b[7]]));
    let rest = &b[8..];
    if n1 + 2 > rest.len() {
        return Err(BlobError::Malformed);
    }
    let (pq, rest) = rest.split_at(n1);
    let n2 = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
    let trad = &rest[2..];
    if n2 != trad.len() {
        return Err(BlobError::Malformed);
    }
    Ok((pq, trad))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packed_blob_unpacks_to_its_components() {
        let (pq, trad) = (&[1u8, 2, 3][..], &[9u8; 300][..]);
        let mut b = vec![0; blob_len(pq, trad).unwrap()];
        pack(MLDSA65_ED25519_SHA512, pq, trad, &mut b);
        assert_eq!(unpack(MLDSA65_ED25519_SHA512, &b), Ok((pq, trad)));
        assert_eq!(unpack(2, &b), Err(BlobError::OtherAlgorithm));
        assert_eq!(unpack(1, &b[..b.len() - 1]), Err(BlobError::Malformed));
        assert_eq!(blob_len(&[0; 0x10000], trad), None);
    }
}
