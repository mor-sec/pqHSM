//! Phase 4 slice 5: `C_SignInit`, `C_Sign`, `C_SignUpdate`, `C_SignFinal` and the four
//! `C_Verify*` (`src/fhsm_pkcs11.c:10728-12662`, with `op_init`'s signature half
//! `:9037-9580`, the HashML-DSA helpers `:6005-6150` and `src/fhsm_ecdsa_raw.c`), in C's check
//! order and with C's EVP call sequences (`pqhsm_crypto::sig`). The sign and verify operation
//! tables (C's `g_op_sig`, `g_op_ver`) are this module's.
//!
//! Divergences: DIV-053's refusal is `gate`. DIV-050: a secret or private key is usable only
//! while the user is logged in, and `C_Logout` ends the operations under way on one. DIV-062:
//! every Init starts afresh, so no MAC stream an ended operation left carries on (C continued
//! it). DIV-001: a success whose audit record fails returns 0x30 and writes no signature.
//! Where C read through a NULL signature pointer with a length (`C_Verify`), this refuses with
//! 0x7.

use std::ffi::{CStr, c_int, c_long, c_ulong};
use std::ptr::{copy_nonoverlapping, null};
use std::sync::{Mutex, MutexGuard};

use pqhsm_core::ecdsa::{der_to_raw, is_ecdsa, raw_to_der};
use pqhsm_core::session::MAX;
use pqhsm_crypto::cipher::{Pkey, cleanse};
use pqhsm_crypto::prim::hmac;
use pqhsm_crypto::sig::{
    DigestCtx, Mac, Md, Mgf, NO_PADDING, PKEY_EC, PKEY_RSA, Param, RawCtx, clear_errors, ct_eq,
};

use super::apilock::Held;
use super::crypt::{Secret, copied, mgf_md, object, strict, ulongs};
use super::digest::{Mech, bytes};
use super::objects::{CKO_PRIVATE_KEY, CKO_SECRET_KEY, access_denied, gate};
use super::session::{TABLE, Tok, fhsm_session_role};
use super::sys::*;

const HOST_MEMORY: u32 = 0x2;
const DATA_LEN_RANGE: u32 = 0x21;
const FUNCTION_NOT_SUPPORTED: u32 = 0x54;
const KEY_SIZE_RANGE: u32 = 0x62;
const KEY_TYPE_INCONSISTENT: u32 = 0x63;
const KEY_FUNCTION_NOT_PERMITTED: u32 = 0x68;
const MECHANISM_INVALID: u32 = 0x70;
const MECHANISM_PARAM_INVALID: u32 = 0x71;
const SIGNATURE_INVALID: u32 = 0xC0;

const RSA_PKCS: c_ulong = 0x1;
const RSA_X_509: c_ulong = 0x3;
const SHA1_RSA: c_ulong = 0x6;
const PSS: c_ulong = 0xD;
const ML_DSA: c_ulong = 0x1D;
const HASH_ML_DSA: c_ulong = 0x1F;
const SLH_DSA: c_ulong = 0x2E;
const HASH_SLH_DSA: c_ulong = 0x34;
const CMAC: c_ulong = 0x108A;
const GMAC: c_ulong = 0x108E;
const EDDSA: c_ulong = 0x1057;
const COMPOSITE: c_ulong = 0x8000_4202;

const CKO_PUBLIC_KEY: u32 = 2;
const CKK_RSA: u32 = 0;
const CKK_EC: u32 = 3;
const CKK_AES: u32 = 0x1F;
const CKK_COMPOSITE: u32 = 0x8000_4202;
const OBJF_ALWAYS_AUTH: u8 = 0x20;
const OBJF3_ED_CURVE_NAME: u8 = 0x01;
const USAGE_SIGN: u8 = 0x04;
const USAGE_VERIFY: u8 = 0x08;
const USAGE_VALID: u8 = 0x80;
const EV_SIGN: c_int = 42;
const EV_VERIFY: c_int = 43;
/// `FHSM_COMPOSITE_MLDSA65_ED25519_SHA512`.
const COMPOSITE_ALG: c_int = 1;
/// ML-DSA-65 || Ed25519.
const COMPOSITE_SIG: usize = 3309 + 64;

/// C's 2 GiB ceiling on one call's input (#125 isize).
const MAX_INPUT: c_ulong = 0x7FFF_FFFF;
/// `FHSM_AAD_MAX`.
const AAD_MAX: usize = 1024 * 1024;
/// `sizeof(op->gcm_iv)`.
const GCM_IV_MAX: usize = 512;
/// `op_append_multipart`'s ceiling on the buffered message.
const MP_MAX: usize = 16 * 1024 * 1024;
const UL: usize = size_of::<c_ulong>();

/// `fhsm_hmac_hash_of` and `hmac_digest_name`: the HMAC mechanisms' `fhsm_hash_t`, OpenSSL
/// digest name and MAC length.
fn hmac_of(m: c_ulong) -> Option<(u32, &'static CStr, usize)> {
    Some(match m {
        0x221 => (7, c"SHA1", 20),
        0x256 => (9, c"SHA224", 28),
        0x49 => (10, c"SHA512-224", 28),
        0x4D => (11, c"SHA512-256", 32),
        0x251 => (1, c"SHA256", 32),
        0x261 => (2, c"SHA384", 48),
        0x271 => (3, c"SHA512", 64),
        0x2B6 => (12, c"SHA3-224", 28),
        0x2B1 => (4, c"SHA3-256", 32),
        0x2C1 => (5, c"SHA3-384", 48),
        0x2D1 => (6, c"SHA3-512", 64),
        _ => return None,
    })
}

/// One `HMLDSA[]` row: HashML-DSA's and HashSLH-DSA's mechanism (0: generic only), the digest
/// mechanism the generic one names (0: not nameable), the OpenSSL name, the OID's last arc and
/// the length of PH(M).
struct HmRow(c_ulong, c_ulong, c_ulong, &'static CStr, u8, usize);

const HMLDSA: [HmRow; 12] = [
    HmRow(0x23, 0x36, 0x255, c"SHA2-224", 4, 28),
    HmRow(0x24, 0x37, 0x250, c"SHA2-256", 1, 32),
    HmRow(0x25, 0x38, 0x260, c"SHA2-384", 2, 48),
    HmRow(0x26, 0x39, 0x270, c"SHA2-512", 3, 64),
    HmRow(0, 0, 0x048, c"SHA2-512/224", 5, 28),
    HmRow(0, 0, 0x04C, c"SHA2-512/256", 6, 32),
    HmRow(0x27, 0x3A, 0x2B5, c"SHA3-224", 7, 28),
    HmRow(0x28, 0x3B, 0x2B0, c"SHA3-256", 8, 32),
    HmRow(0x29, 0x3C, 0x2C0, c"SHA3-384", 9, 48),
    HmRow(0x2A, 0x3D, 0x2D0, c"SHA3-512", 10, 64),
    HmRow(0x2B, 0x3E, 0, c"SHAKE128", 11, 32),
    HmRow(0x2C, 0x3F, 0, c"SHAKE256", 12, 64),
];
/// DER of 2.16.840.1.101.3.4.2, less the last arc.
const HMLDSA_OID_PREFIX: [u8; 10] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];

/// `hmldsa_row_of_mech`: 1-based, 0 for none.
fn hm_row_of(m: c_ulong) -> usize {
    HMLDSA
        .iter()
        .position(|r| (r.0 != 0 && r.0 == m) || (r.1 != 0 && r.1 == m))
        .map_or(0, |i| i + 1)
}

fn hm_generic(m: c_ulong) -> bool {
    m == HASH_ML_DSA || m == HASH_SLH_DSA
}

/// `hm_slh`.
fn hm_slh(m: c_ulong) -> bool {
    m == HASH_SLH_DSA || HMLDSA.iter().any(|r| r.1 != 0 && r.1 == m)
}

/// `hmldsa_is`.
fn hmldsa_is(m: c_ulong) -> bool {
    hm_generic(m) || hm_row_of(m) != 0
}

/// `mech_hash_name`.
fn hash_name(m: c_ulong) -> Option<&'static CStr> {
    Some(match m {
        SHA1_RSA => c"SHA1",
        0x46 => c"SHA224",
        0x1044 | 0x40 | 0x43 => c"SHA256",
        0x1045 | 0x41 | 0x44 => c"SHA384",
        0x1046 | 0x42 | 0x45 => c"SHA512",
        0x66 => c"SHA3-224",
        0x60 => c"SHA3-256",
        0x61 => c"SHA3-384",
        0x62 => c"SHA3-512",
        _ => return None,
    })
}

/// `mech_is_pss`.
fn is_pss(m: c_ulong) -> bool {
    matches!(m, PSS | 0x43 | 0x44 | 0x45)
}

/// `sig_family_bound`: the scratch a signature is made in.
fn family_bound(m: c_ulong) -> usize {
    if m == SLH_DSA || hm_slh(m) {
        65536
    } else if m == ML_DSA || hmldsa_is(m) {
        8192
    } else {
        512
    }
}

/// `mech_sign_is_buffered_multipart`.
fn buffered(m: c_ulong) -> bool {
    !(m == COMPOSITE || m == CMAC || m == GMAC || hmac_of(m).is_some())
}

/// SignInit's and VerifyInit's mechanism switch (`:10798-10837`): `None` for a mechanism
/// they do not take, `Some(true)` for the three the strict build refuses.
fn listed(m: c_ulong) -> Option<bool> {
    if hmac_of(m).is_some() {
        return Some(false);
    }
    match m {
        CMAC
        | GMAC
        | 0x1041
        | 0x1044..=0x1046
        | EDDSA
        | RSA_PKCS
        | 0x40..=0x46
        | PSS
        | 0x60..=0x62
        | 0x66
        | ML_DSA
        | SLH_DSA
        | HASH_ML_DSA
        | 0x23..=0x2C
        | HASH_SLH_DSA
        | 0x36..=0x3F => Some(false),
        SHA1_RSA | RSA_X_509 | COMPOSITE => Some(true),
        _ => None,
    }
}

/// `fhsm_check_key_mech_type`'s signature rows: does key type `kt` suit mechanism `m`? HMAC
/// takes any key but an RSA, EC or Edwards one; the SHA-224, SHA-3 and SHA-512/t rows and the
/// composite are not checked.
fn key_type_ok(m: c_ulong, kt: u32) -> bool {
    match m {
        RSA_PKCS | RSA_X_509 | PSS | SHA1_RSA | 0x40..=0x45 => kt == CKK_RSA,
        0x1041..=0x1046 => kt == CKK_EC,
        EDDSA => kt == 0x40,
        ML_DSA | HASH_ML_DSA | 0x23..=0x2C => kt == 0x4A,
        SLH_DSA | HASH_SLH_DSA | 0x36..=0x3F => kt == 0x4B,
        CMAC | GMAC => kt == CKK_AES,
        0x251 | 0x261 | 0x271 | 0x256 | 0x2B1 | 0x2C1 | 0x2D1 | 0x2B6 | 0x221 => {
            !matches!(kt, 0 | 3 | 0x40)
        }
        _ => true,
    }
}

/// One session's sign or verify operation (C's `fhsm_op_t`, the fields a signature uses).
struct Op {
    active: bool,
    /// After `resolve_mech`.
    mech: c_ulong,
    key: u32,
    /// DIV-050: the token and whether the key is the user's (secret or private), so a logout
    /// ends the operation.
    tok: Option<Tok>,
    private: bool,
    auth_required: bool,
    auth_done: bool,
    /// GMAC's IV and tag length (`gcm_have`, `gcm_iv`, `gcm_tag_len`).
    gcm_have: bool,
    gcm_iv: Vec<u8>,
    tag_len: usize,
    /// CK_RSA_PKCS_PSS_PARAMS' MGF and salt length (`pss_have`).
    pss: Option<(c_ulong, c_long)>,
    /// The ML-DSA or SLH-DSA context string (`pq_ctx_have`), `pq_ctx_toolong`, the hedge.
    ctx: Option<Vec<u8>>,
    toolong: bool,
    hedge: c_ulong,
    /// HashML-DSA's `HMLDSA[]` row (1-based; 0 for another mechanism) and whether the
    /// multipart buffer now holds PH(M).
    hm_row: usize,
    prehashed: bool,
    /// The buffered message (`mp_buf`), HashML-DSA's or the composite's PH(M) stream
    /// (`md_ctx`), and the MAC stream (`mac_ctx`).
    mp: Secret,
    md: Option<Md>,
    mac: Option<Mac>,
}

impl Op {
    const IDLE: Op = Op {
        active: false,
        mech: 0,
        key: 0,
        tok: None,
        private: false,
        auth_required: false,
        auth_done: false,
        gcm_have: false,
        gcm_iv: Vec::new(),
        tag_len: 16,
        pss: None,
        ctx: None,
        toolong: false,
        hedge: 0,
        hm_row: 0,
        prehashed: false,
        mp: Secret::NONE,
        md: None,
        mac: None,
    };

    /// C's `op->active = 0; return rv;`.
    fn end(&mut self, rv: u32) -> u32 {
        self.active = false;
        rv
    }

    /// `op_require_ctx_auth`.
    fn ctx_auth(&mut self) -> Result<(), u32> {
        if self.auth_required && !self.auth_done {
            return Err(self.end(USER_NOT_LOGGED_IN));
        }
        Ok(())
    }

    /// C_Sign's and C_Verify's MAC length: GMAC's tag length, else 16.
    fn aes_mac_len(&self) -> usize {
        if self.mech == GMAC && self.tag_len != 0 {
            self.tag_len
        } else {
            16
        }
    }

    /// `mac_stream_len`: 0 for a mechanism that is no MAC.
    fn stream_len(&self) -> usize {
        match hmac_of(self.mech) {
            Some((_, _, n)) => n,
            None if self.mech == CMAC => 16,
            None if self.mech == GMAC && (1..=16).contains(&self.tag_len) => self.tag_len,
            None if self.mech == GMAC => 16,
            None => 0,
        }
    }

    /// `pss_apply_params`' arguments.
    fn pss_args(&self) -> (c_int, Mgf) {
        match self.pss {
            None => (-1, Mgf::Default),
            Some((0, s)) => (s as c_int, Mgf::Default),
            Some((g, s)) => (s as c_int, mgf_md(g).map_or(Mgf::Unknown, Mgf::Named)),
        }
    }

    /// The context string, empty when there is none.
    fn ctx(&self) -> &[u8] {
        self.ctx.as_deref().unwrap_or(&[])
    }

    /// `hmldsa_fail`.
    fn hm_fail(&mut self, rv: u32) -> u32 {
        self.md = None;
        self.mp = Secret::NONE;
        self.end(rv)
    }
}

/// One slot per session handle, as C's tables; handle 0 and those past the table have none.
/// shortcut: a fork while another thread is inside a sign call deadlocks the child's
/// C_Initialize in `forget_all`, as crypt.rs's slots (review M1); fix with them in the M3
/// atfork work.
static SIG: [Mutex<Op>; MAX] = [const { Mutex::new(Op::IDLE) }; MAX];
static VER: [Mutex<Op>; MAX] = [const { Mutex::new(Op::IDLE) }; MAX];

fn lock(m: &'static Mutex<Op>) -> MutexGuard<'static, Op> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// `op_slot(g_op_sig or g_op_ver, h)`.
fn slot(sign: bool, h: c_ulong) -> Option<MutexGuard<'static, Op>> {
    let t = if sign { &SIG } else { &VER };
    (h != 0 && (h as usize) < MAX).then(|| lock(&t[h as usize]))
}

fn active_slot(sign: bool, h: c_ulong) -> Option<MutexGuard<'static, Op>> {
    let mut o = slot(sign, h).filter(|o| o.active)?;
    // DIV-050's backstop to the logout's sweep, which a concurrent Init can slip past on the
    // DIV-001 login rollback (review L3 of slice 5): a user's key out of sight ends it.
    if o.private && o.tok.is_some_and(|t| access_denied(t, CKO_PRIVATE_KEY)) {
        *o = Op::IDLE;
        return None;
    }
    Some(o)
}

/// This session's operations, freed (`fhsm_session_ops_reset`'s signature part).
pub(super) fn reset(h: c_ulong) {
    for sign in [true, false] {
        if let Some(mut o) = slot(sign, h) {
            *o = Op::IDLE;
        }
    }
}

/// Is a signature or verification active in this session?
pub(super) fn active(h: c_ulong) -> bool {
    active_slot(true, h).is_some() || active_slot(false, h).is_some()
}

/// The context-specific login's grant to this session's active operations.
pub(super) fn grant(h: c_ulong) {
    for sign in [true, false] {
        if let Some(mut o) = active_slot(sign, h) {
            o.auth_done = true;
        }
    }
}

/// DIV-050: the logout of `t` ends every operation under way on one of its user's keys; the
/// next call answers 0x91.
pub(super) fn end_private(t: Tok) {
    for s in SIG[1..].iter().chain(&VER[1..]) {
        let mut o = lock(s);
        // Ended ones too: their contexts may still hold the key (review M3 of slice 5)
        if o.private && o.tok == Some(t) {
            *o = Op::IDLE;
        }
    }
}

/// At finalize: every session's operations freed.
pub(super) fn release_all() {
    (1..MAX as c_ulong).for_each(reset);
}

/// After a fork: every operation forgotten, its contexts not freed (the parent's).
pub(super) fn forget_all() {
    for s in SIG[1..].iter().chain(&VER[1..]) {
        let mut o = lock(s);
        if let Some(m) = o.mac.take() {
            m.forget();
        }
        if let Some(m) = o.md.take() {
            m.forget();
        }
        *o = Op::IDLE;
    }
}

/// The audit record of a sign or verify call (DIV-001: its result counts).
fn record(sign: bool, h: c_ulong, rv: u32, kv: &[(&CStr, &CStr)]) -> Result<(), u32> {
    audit(
        if sign { EV_SIGN } else { EV_VERIFY },
        -1,
        h as c_int,
        fhsm_session_role(h),
        rv,
        kv,
    )
}

/// An audited outcome other than a signature: the operation ends, the record is made, a
/// success that cannot be recorded is 0x30 (DIV-001), a failure keeps its rv.
fn recorded(sign: bool, h: c_ulong, op: &mut Op, rv: u32, kv: &[(&CStr, &CStr)]) -> u32 {
    op.active = false;
    audited(rv, record(sign, h, rv, kv))
}

/// A signature made: the operation ends, the record is made, and only then (DIV-001) do the
/// bytes and their length reach the caller.
///
/// # Safety
/// `out` writable for `b.len()` bytes, which C's checks before established.
unsafe fn emit(
    h: c_ulong,
    op: &mut Op,
    b: &[u8],
    out: *mut u8,
    out_len: *mut c_ulong,
    kv: &[(&CStr, &CStr)],
) -> u32 {
    op.active = false;
    if let Err(e) = record(true, h, OK, kv) {
        return e;
    }
    // SAFETY: the caller's
    unsafe {
        copy_nonoverlapping(b.as_ptr(), out, b.len());
        *out_len = b.len() as c_ulong;
    }
    OK
}

/// `resolve_mech`: GMAC read as CMAC while `FHSM_OPENSC_GMAC_ALIAS` is set.
fn resolve(m: c_ulong) -> c_ulong {
    if m == GMAC && pqhsm_core::env("FHSM_OPENSC_GMAC_ALIAS").is_some() {
        CMAC
    } else {
        m
    }
}

/// Is the key, public or private, of OpenSSL type `name`? (`:9488-9496`, `:9554-9562`)
fn key_is(t: Tok, k: u32, name: &CStr) -> bool {
    let Ok((kv, cl, _)) = object(t, k) else {
        return false;
    };
    let pk = match cl {
        CKO_PUBLIC_KEY => Pkey::public(kv),
        CKO_PRIVATE_KEY => Pkey::private(kv),
        _ => None,
    };
    pk.is_some_and(|p| p.is_a(name))
}

/// `hmldsa_init` (`:6076-6112`).
///
/// # Safety
/// As `params`.
unsafe fn hmldsa_init(op: &mut Op, p: *const u8, n: usize) -> Result<(), u32> {
    let generic = hm_generic(op.mech);
    op.hm_row = if generic { 0 } else { hm_row_of(op.mech) };
    if p.is_null() && n == 0 {
        // No block: empty context, hedged; the generic mechanism needs one to name its hash.
        return if generic {
            Err(MECHANISM_PARAM_INVALID)
        } else {
            Ok(())
        };
    }
    let want = if generic { 4 } else { 3 } * UL;
    if p.is_null() || n != want {
        return Err(MECHANISM_PARAM_INVALID);
    }
    // SAFETY: want bytes (caller)
    let [hedge, ctx, ctx_len, digest] = unsafe {
        if generic {
            ulongs::<4>(p)
        } else {
            let [a, b, c] = ulongs::<3>(p);
            [a, b, c, 0]
        }
    };
    if hedge > 2 || (ctx_len != 0 && ctx == 0 && ctx_len <= 255) {
        return Err(MECHANISM_PARAM_INVALID);
    }
    if generic {
        op.hm_row = HMLDSA
            .iter()
            .position(|r| r.2 != 0 && r.2 == digest)
            .map_or(0, |i| i + 1);
        if op.hm_row == 0 {
            return Err(MECHANISM_PARAM_INVALID);
        }
    }
    op.hedge = hedge;
    if ctx_len > 255 {
        op.toolong = true;
        return Ok(());
    }
    // SAFETY: the caller's context of ctx_len bytes
    op.ctx = Some(unsafe { copied(ctx, ctx_len as usize) });
    Ok(())
}

/// `op_init`'s signature half (`:9037-9580`), into a fresh operation: the parameters each
/// mechanism takes, in C's order.
///
/// # Safety
/// `m.param` readable for `m.param_len` bytes, and every pointer inside it for its length.
unsafe fn params(m: &Mech, op: &mut Op, t: Tok, k: u32) -> Result<(), u32> {
    let (p, n) = (m.param.cast::<u8>().cast_const(), m.param_len as usize);
    if op.mech == GMAC && !p.is_null() && n >= 6 * UL {
        // CK_GCM_PARAMS, as GCM reads it; GMAC uses its IV and tag length, not its AAD.
        // SAFETY: n bytes (caller)
        let [iv, iv_len, _, aad, aad_len, tag_bits] = unsafe { ulongs::<6>(p) };
        let (iv_len, aad_len) = (iv_len as usize, aad_len as usize);
        let tag_bits = if tag_bits == 0 { 128 } else { tag_bits };
        if (iv_len != 0 && iv == 0) || (aad_len != 0 && aad == 0) {
            return Err(MECHANISM_PARAM_INVALID);
        }
        if iv_len > GCM_IV_MAX || aad_len > AAD_MAX || tag_bits > 128 || tag_bits & 7 != 0 {
            return Err(ARGUMENTS_BAD);
        }
        // SAFETY: the caller's IV of iv_len bytes
        op.gcm_iv = unsafe { copied(iv, iv_len) };
        op.tag_len = tag_bits as usize / 8;
        op.gcm_have = true;
    }
    if op.mech == GMAC && !op.gcm_have && !p.is_null() && n > 0 {
        // The raw IV OpenSC passes.
        if n > GCM_IV_MAX {
            return Err(ARGUMENTS_BAD);
        }
        if n < 12 {
            return Err(MECHANISM_PARAM_INVALID);
        }
        // SAFETY: n bytes (caller)
        op.gcm_iv = unsafe { bytes(p, n) }.to_vec();
        op.gcm_have = true;
    }
    if op.mech == GMAC && !op.gcm_have {
        return Err(MECHANISM_PARAM_INVALID);
    }
    if is_pss(op.mech) {
        if p.is_null() || n < 3 * UL {
            return Err(MECHANISM_PARAM_INVALID);
        }
        // SAFETY: n bytes (caller)
        let [_, mgf, salt] = unsafe { ulongs::<3>(p) };
        let salt = salt as c_long;
        if !(0..=1024).contains(&salt) {
            return Err(MECHANISM_PARAM_INVALID);
        }
        op.pss = Some((mgf as u32 as c_ulong, salt));
    }
    if matches!(op.mech, ML_DSA | SLH_DSA) && !p.is_null() && n >= 3 * UL {
        // fhsm_parse_pq_params and op_init's checks after it: CK_SIGN_ADDITIONAL_CONTEXT
        // { hedgeVariant; pContext; ulContextLen }. A shorter block is none.
        // SAFETY: n bytes (caller)
        let [hedge, ctx, ctx_len] = unsafe { ulongs::<3>(p) };
        if hedge > 2 {
            return Err(MECHANISM_PARAM_INVALID);
        }
        op.hedge = hedge;
        if ctx_len > 255 {
            op.toolong = true;
        } else if ctx_len != 0 && ctx == 0 {
            return Err(MECHANISM_PARAM_INVALID);
        } else {
            // SAFETY: the caller's context of ctx_len bytes
            op.ctx = Some(unsafe { copied(ctx, ctx_len as usize) });
        }
    }
    if hmldsa_is(op.mech) {
        // SAFETY: the caller's
        unsafe { hmldsa_init(op, p, n) }?;
    }
    if op.mech == EDDSA && p.is_null() {
        // RFC 8032's edwards448 takes a context, so no block on a key named by curve.
        let mut f3 = 0u8;
        // SAFETY: a token the registry holds; an out byte of our own
        let named = unsafe { fhsm_token_object_get_flags3(t.0.as_ptr(), k, &mut f3) } == OK;
        if named && f3 & OBJF3_ED_CURVE_NAME != 0 && key_is(t, k, c"ED448") {
            return Err(MECHANISM_PARAM_INVALID);
        }
    }
    if op.mech == EDDSA && !p.is_null() {
        // CK_EDDSA_PARAMS { CK_BBOOL phFlag; CK_ULONG ulContextDataLen; pContextData }: only
        // the empty, pure form, and not on an Ed25519 key.
        if n < 3 * UL {
            return Err(MECHANISM_PARAM_INVALID);
        }
        // SAFETY: n bytes (caller)
        let [ph, len, ctx] = unsafe { ulongs::<3>(p) };
        if len > 0x7FFF_FFFF || (ctx == 0 && len != 0) || len != 0 || ph as u8 != 0 {
            return Err(MECHANISM_PARAM_INVALID);
        }
        if key_is(t, k, c"ED25519") {
            return Err(MECHANISM_PARAM_INVALID);
        }
    }
    Ok(())
}

/// `C_SignInit` and `C_VerifyInit` (`:10793`, `:11487`).
unsafe fn init(sign: bool, h: c_ulong, m: *const Mech, key: c_ulong) -> u32 {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv;
    }
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID;
    };
    if m.is_null() {
        return ARGUMENTS_BAD;
    }
    // SAFETY: non-NULL, and by the caller's contract a CK_MECHANISM
    let m = unsafe { &*m };
    match listed(m.mechanism) {
        None => return MECHANISM_INVALID,
        Some(true) if strict() => return MECHANISM_INVALID,
        Some(_) => {}
    }
    // C's narrowing: the token's handles and mechanisms are 32-bit.
    let (t, k) = (tok.0.as_ptr(), key as u32);
    // fhsm_require_key
    let Ok((_, class, kt)) = object(tok, k) else {
        return KEY_HANDLE_INVALID;
    };
    // DIV-050: a secret or private key is the user's alone.
    if access_denied(tok, class) {
        return KEY_HANDLE_INVALID;
    }
    if !key_type_ok(m.mechanism, kt) {
        return KEY_TYPE_INCONSISTENT;
    }
    // SAFETY: a token the registry holds
    let rv = unsafe { fhsm_token_object_mech_allowed(t, k, m.mechanism as u32) };
    if rv != OK {
        return rv;
    }
    let mut u = 0u8;
    let bit = if sign { USAGE_SIGN } else { USAGE_VERIFY };
    // SAFETY: as above; an out byte of our own
    let usage = unsafe { fhsm_token_object_get_usage(t, k, &mut u) } == OK;
    if usage && u & USAGE_VALID != 0 && u & bit == 0 {
        return KEY_FUNCTION_NOT_PERMITTED;
    }
    let Some(mut slot) = slot(sign, h) else {
        return SESSION_HANDLE_INVALID;
    };
    if slot.active {
        return OPERATION_ACTIVE;
    }
    let mut f = 0u8;
    // SAFETY: as above
    let always =
        unsafe { fhsm_token_object_get_flags(t, k, &mut f) } == OK && f & OBJF_ALWAYS_AUTH != 0;
    // DIV-062: a fresh operation, so no MAC stream an earlier one left carries on.
    let mut op = Op {
        mech: resolve(m.mechanism),
        key: k,
        tok: Some(tok),
        private: class == CKO_SECRET_KEY || class == CKO_PRIVATE_KEY,
        auth_required: always,
        ..Op::IDLE
    };
    // SAFETY: the caller's CK_MECHANISM
    if let Err(rv) = unsafe { params(m, &mut op, tok, k) } {
        return rv;
    }
    // A context over 255 bytes cannot be signed (FIPS 204 Algorithms 2 and 7); a verification
    // under it answers false.
    if sign && op.toolong {
        return MECHANISM_PARAM_INVALID;
    }
    op.active = true;
    *slot = op;
    OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_SignInit(h: c_ulong, m: *const Mech, key: c_ulong) -> c_ulong {
    // SAFETY: the caller's
    unsafe { init(true, h, m, key) }.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_VerifyInit(h: c_ulong, m: *const Mech, key: c_ulong) -> c_ulong {
    // SAFETY: the caller's
    unsafe { init(false, h, m, key) }.into()
}

/// `aes_gmac` and `aes_cmac` (`:10910-10965`): the whole 16-byte tag. The key length is
/// checked before the MAC is fetched (C: after), which only reorders failures that cannot
/// happen.
fn aes_mac(gmac: bool, kv: &[u8], iv: &[u8], data: &[u8]) -> Result<[u8; 16], u32> {
    let name = aes_mac_cipher(kv.len(), !gmac).ok_or(KEY_SIZE_RANGE)?;
    let p = [Param::Utf8(c"cipher", name), Param::Octets(c"iv", iv)];
    let mut m = Mac::new(
        if gmac { c"GMAC" } else { c"CMAC" },
        kv,
        if gmac { &p } else { &p[..1] },
    )?;
    if !m.update(data) {
        return Err(FUNCTION_FAILED);
    }
    let mut out = [0u8; 16];
    match m.finish(&mut out) {
        Some(16) => Ok(out),
        _ => {
            cleanse(&mut out);
            Err(FUNCTION_FAILED)
        }
    }
}

/// `aes_mac_cipher_name`.
fn aes_mac_cipher(n: usize, cbc: bool) -> Option<&'static CStr> {
    Some(match (n, cbc) {
        (16, true) => c"AES-128-CBC",
        (24, true) => c"AES-192-CBC",
        (32, true) => c"AES-256-CBC",
        (16, false) => c"AES-128-GCM",
        (24, false) => c"AES-192-GCM",
        (32, false) => c"AES-256-GCM",
        _ => return None,
    })
}

/// `mac_stream_open` (`:12222-12265`).
fn mac_open(t: Tok, op: &Op) -> Result<Mac, u32> {
    let (kv, _, kt) = object(t, op.key)?;
    if let Some((_, name, _)) = hmac_of(op.mech) {
        return Mac::new(c"HMAC", kv, &[Param::Utf8(c"digest", name)]);
    }
    if op.mech != CMAC && op.mech != GMAC {
        return Err(MECHANISM_INVALID);
    }
    let gmac = op.mech == GMAC;
    if kt != CKK_AES {
        return Err(KEY_TYPE_INCONSISTENT);
    }
    if gmac && (!op.gcm_have || op.gcm_iv.is_empty()) {
        return Err(ARGUMENTS_BAD);
    }
    let name = aes_mac_cipher(kv.len(), !gmac).ok_or(KEY_SIZE_RANGE)?;
    let p = [
        Param::Utf8(c"cipher", name),
        Param::Octets(c"iv", &op.gcm_iv),
    ];
    Mac::new(
        if gmac { c"GMAC" } else { c"CMAC" },
        kv,
        if gmac { &p } else { &p[..1] },
    )
}

/// `fhsm_exact_sig_len`: the signature length of the operation's private key, 0 if unknown.
fn exact_len(t: Tok, op: &Op) -> usize {
    let Ok((kv, cl, _)) = object(t, op.key) else {
        return 0;
    };
    if cl != CKO_PRIVATE_KEY {
        return 0;
    }
    let Some(k) = Pkey::private(kv) else {
        return 0;
    };
    let n = if is_ecdsa(op.mech) {
        2 * ((k.bits() + 7) / 8)
    } else {
        k.size()
    };
    n.max(0) as usize
}

/// `hmldsa_message` (`:6118-6150`): M' = 01 || len(ctx) || ctx || OID || PH(M).
fn hm_message(op: &Op, data: &[u8]) -> Result<Vec<u8>, u32> {
    if op.hm_row == 0 || op.hm_row > HMLDSA.len() || op.ctx().len() > 255 {
        return Err(FUNCTION_FAILED);
    }
    let r = &HMLDSA[op.hm_row - 1];
    let mut mp = vec![0x01, op.ctx().len() as u8];
    mp.extend_from_slice(op.ctx());
    mp.extend_from_slice(&HMLDSA_OID_PREFIX);
    mp.push(r.4);
    if hm_generic(op.mech) || op.prehashed {
        if data.len() != r.5 {
            return Err(DATA_LEN_RANGE);
        }
        mp.extend_from_slice(data);
    } else {
        let at = mp.len();
        mp.resize(at + r.5, 0);
        let mut md = Md::new(r.3).map_err(|_| FUNCTION_FAILED)?;
        if !md.update(data) || md.finish(&mut mp[at..]) != Some(r.5) {
            return Err(FUNCTION_FAILED);
        }
    }
    Ok(mp)
}

/// `hmldsa_ph_update` (`:12125-12140`).
fn hm_ph_update(op: &mut Op, part: &[u8]) -> Result<(), u32> {
    if hm_generic(op.mech) {
        return Err(FUNCTION_NOT_SUPPORTED);
    }
    if op.hm_row == 0 || op.hm_row > HMLDSA.len() || op.prehashed {
        return Err(FUNCTION_FAILED);
    }
    if op.md.is_none() {
        op.md = Some(Md::new(HMLDSA[op.hm_row - 1].3).map_err(|_| FUNCTION_FAILED)?);
    }
    if !part.is_empty() && !op.md.as_mut().is_some_and(|m| m.update(part)) {
        return Err(FUNCTION_FAILED);
    }
    Ok(())
}

/// `hmldsa_ph_finish` (`:12149-12166`): PH(M) replaces the buffered message.
fn hm_ph_finish(op: &mut Op) -> Result<(), u32> {
    if hm_generic(op.mech) {
        return Err(FUNCTION_NOT_SUPPORTED);
    }
    let Some(mut md) = op.md.take() else {
        return Ok(());
    };
    let n = HMLDSA[op.hm_row - 1].5;
    let mut ph = [0u8; 64];
    if md.finish(&mut ph[..n]) != Some(n) {
        return Err(FUNCTION_FAILED);
    }
    op.mp = Secret(ph[..n].to_vec());
    op.prehashed = true;
    Ok(())
}

/// `composite_ph_update` (`:12085-12101`).
fn composite_update(op: &mut Op, part: &[u8]) -> u32 {
    if op.md.is_none() {
        // SAFETY: a constant name or NULL
        let name = unsafe { fhsm_composite_ph_name(COMPOSITE_ALG) };
        if name.is_null() {
            return MECHANISM_INVALID;
        }
        // SAFETY: a NUL-terminated static string
        match Md::new(unsafe { CStr::from_ptr(name) }) {
            Ok(m) => op.md = Some(m),
            Err(rv) => return rv,
        }
    }
    if !part.is_empty() && !op.md.as_mut().is_some_and(|m| m.update(part)) {
        return FUNCTION_FAILED;
    }
    OK
}

/// `composite_ph_final` (`:12106-12120`): PH(M) into `ph`, its length.
fn composite_final(op: &mut Op, ph: &mut [u8; 64]) -> Result<usize, u32> {
    // SAFETY: no pointers
    let want = unsafe { fhsm_composite_ph_len(COMPOSITE_ALG) };
    if want == 0 || want > 64 {
        return Err(FUNCTION_FAILED);
    }
    if op.md.is_none() {
        let rv = composite_update(op, b"");
        if rv != OK {
            return Err(rv);
        }
    }
    match op.md.take().and_then(|mut m| m.finish(ph)) {
        Some(l) if l == want => Ok(l),
        _ => Err(FUNCTION_FAILED),
    }
}

/// `op_append_multipart`: the part added to the buffered message, under its 16 MiB ceiling.
fn append(op: &mut Op, part: &[u8]) -> u32 {
    if part.is_empty() {
        return OK;
    }
    let need = op.mp.0.len() + part.len();
    if part.len() > MP_MAX || need > MP_MAX {
        op.mp = Secret::NONE;
        return op.end(DATA_LEN_RANGE);
    }
    // Grown by hand, so the old buffer is cleansed as it is dropped (C cleansed mp_buf)
    if op.mp.0.capacity() < need {
        let mut v = Vec::new();
        if v.try_reserve_exact(need.max((2 * op.mp.0.capacity()).min(MP_MAX)))
            .is_err()
        {
            op.mp = Secret::NONE;
            return op.end(HOST_MEMORY);
        }
        v.extend_from_slice(&op.mp.0);
        op.mp = Secret(v);
    }
    op.mp.0.extend_from_slice(part);
    OK
}

/// `sign_asymmetric` (`:11113-11307`): the signature into `out`, its length.
fn sign_asymmetric(t: Tok, op: &Op, data: &[u8], out: &mut [u8]) -> Result<usize, u32> {
    let (kv, cl, kt) = object(t, op.key)?;
    if cl != CKO_PRIVATE_KEY {
        return Err(KEY_TYPE_INCONSISTENT);
    }
    let k = Pkey::private(kv).ok_or(FUNCTION_FAILED)?;
    if (kt == CKK_RSA && k.base_id() != PKEY_RSA) || (kt == CKK_EC && k.base_id() != PKEY_EC) {
        return Err(KEY_TYPE_INCONSISTENT);
    }
    let det = op.hedge == 2;
    if op.hm_row != 0 {
        // HashML-DSA: Sign_internal over M', built here.
        let mp = hm_message(op, data)?;
        let mut p = vec![Param::Int(c"message-encoding", 0)];
        if det {
            p.push(Param::Int(c"deterministic", 1));
        }
        let mut c = DigestCtx::new()?;
        if !c.init(true, &k, None, &p) {
            return Err(FUNCTION_FAILED);
        }
        return c.sign(&mp, out).ok_or(FUNCTION_FAILED);
    }
    if matches!(op.mech, ML_DSA | SLH_DSA | EDDSA) {
        let mut c = DigestCtx::new()?;
        if !c.init(true, &k, None, &[]) {
            return Err(FUNCTION_FAILED);
        }
        if op.mech != EDDSA {
            let mut p = Vec::new();
            if !op.ctx().is_empty() {
                p.push(Param::Octets(c"context-string", op.ctx()));
            }
            if det {
                p.push(Param::Int(c"deterministic", 1));
            }
            if !p.is_empty() && !c.set_params(&p) {
                return Err(FUNCTION_FAILED);
            }
        }
        return c.sign(data, out).ok_or(FUNCTION_FAILED);
    }
    let (salt, mgf) = op.pss_args();
    let n = match hash_name(op.mech) {
        None => {
            let mut c = RawCtx::new(true, &k).ok_or(FUNCTION_FAILED)?;
            if op.mech == RSA_X_509 && !c.padding(NO_PADDING) {
                return Err(FUNCTION_FAILED);
            }
            if is_pss(op.mech) && c.pss(salt, mgf).is_err() {
                return Err(FUNCTION_FAILED);
            }
            c.sign(data, out)
        }
        Some(hash) => {
            // C's NULL context here was FUNCTION_FAILED, not HOST_MEMORY.
            let mut c = DigestCtx::new().map_err(|_| FUNCTION_FAILED)?;
            if !c.init(true, &k, Some(hash), &[]) || (is_pss(op.mech) && c.pss(salt, mgf).is_err())
            {
                return Err(FUNCTION_FAILED);
            }
            c.sign(data, out)
        }
    }
    .ok_or(FUNCTION_FAILED)?;
    if !is_ecdsa(op.mech) {
        return Ok(n);
    }
    // PKCS#11's ECDSA signature is r || s, each the order's length; OpenSSL's is DER.
    let nlen = ((k.bits() + 7) / 8).max(0) as usize;
    if nlen == 0 || out.len() < 2 * nlen {
        return Err(FUNCTION_FAILED);
    }
    let raw = der_to_raw(&out[..n], nlen).ok_or(FUNCTION_FAILED)?;
    out[..raw.len()].copy_from_slice(&raw);
    Ok(raw.len())
}

/// A caller's signature (`pSignature`, `ulSignatureLen`), read only where C read it.
struct Sig {
    p: *const u8,
    n: usize,
}

impl Sig {
    /// The bytes (`C_Verify` refused NULL with a length up front, DIV-063).
    ///
    /// # Safety
    /// `p` NULL with `n` 0, or readable for `n` bytes.
    unsafe fn get<'a>(&self) -> &'a [u8] {
        // SAFETY: the caller's
        unsafe { bytes(self.p, self.n) }
    }
}

/// `verify_asymmetric` (`:11647-11905`), which ends the operation.
///
/// # Safety
/// As `Sig::get`.
unsafe fn verify_asymmetric(h: c_ulong, t: Tok, op: &mut Op, data: &[u8], sig: &Sig) -> u32 {
    let (kv, cl, _) = match object(t, op.key) {
        Ok(o) => o,
        Err(rv) => return op.end(rv),
    };
    if cl != CKO_PUBLIC_KEY {
        return op.end(KEY_TYPE_INCONSISTENT);
    }
    // A context over 255 bytes: Verify returns false (FIPS 204 Algorithms 3 and 8).
    if op.toolong {
        return recorded(false, h, op, SIGNATURE_INVALID, &[]);
    }
    let raw_alg = match kv.len() {
        1312 => Some(c"ML-DSA-44"),
        1952 => Some(c"ML-DSA-65"),
        2592 => Some(c"ML-DSA-87"),
        _ => None,
    };
    let fallback = || {
        raw_alg
            .filter(|_| op.mech == ML_DSA || op.hm_row != 0)
            .and_then(|a| Pkey::raw_public(a, kv))
    };
    let Some(k) = Pkey::public(kv).or_else(fallback) else {
        return op.end(FUNCTION_FAILED);
    };
    // SAFETY: the caller's
    let sig_bytes = || unsafe { sig.get() };
    if op.hm_row != 0 {
        let mp = match hm_message(op, data) {
            Ok(mp) => mp,
            // Table 283 gives C_Verify any input length: a PH(M) of the wrong one is false.
            Err(DATA_LEN_RANGE) => return recorded(false, h, op, SIGNATURE_INVALID, &[]),
            Err(rv) => return recorded(false, h, op, rv, &[]),
        };
        let s = sig_bytes();
        let enc = [Param::Int(c"message-encoding", 0)];
        let init = DigestCtx::new()
            .ok()
            .and_then(|mut c| c.init(false, &k, None, &enc).then_some(c));
        let rv = match init.map(|mut c| c.verify(s, &mp)) {
            None => FUNCTION_FAILED,
            Some(1) => OK,
            Some(_) => SIGNATURE_INVALID,
        };
        clear_errors();
        return recorded(false, h, op, rv, &[]);
    }
    if matches!(op.mech, ML_DSA | SLH_DSA | EDDSA) {
        let Ok(mut c) = DigestCtx::new() else {
            return op.end(HOST_MEMORY);
        };
        let mut ok = false;
        if c.init(false, &k, None, &[]) {
            let with_ctx = op.mech != EDDSA && !op.ctx().is_empty();
            if with_ctx && !c.set_params(&[Param::Octets(c"context-string", op.ctx())]) {
                return op.end(FUNCTION_FAILED);
            }
            let s = sig_bytes();
            let v = c.verify(s, data);
            if v < 0 {
                return op.end(FUNCTION_FAILED);
            }
            ok = v == 1;
        }
        return recorded(false, h, op, if ok { OK } else { SIGNATURE_INVALID }, &[]);
    }
    let ecdsa = is_ecdsa(op.mech);
    let der;
    let s = if ecdsa {
        let nlen = ((k.bits() + 7) / 8).max(0) as usize;
        if nlen == 0 || sig.n != 2 * nlen {
            return op.end(SIGNATURE_INVALID);
        }
        der = match raw_to_der(sig_bytes(), nlen) {
            Some(d) => d,
            None => return op.end(SIGNATURE_INVALID),
        };
        &der[..]
    } else {
        sig_bytes()
    };
    let (salt, mgf) = op.pss_args();
    // `None`: the checks before the verification failed, which is a signature that does not
    // verify (C's `goto vcleanup`).
    let v = match hash_name(op.mech) {
        None => RawCtx::new(false, &k).and_then(|mut c| {
            let ok = (op.mech != RSA_X_509 || c.padding(NO_PADDING))
                && (!is_pss(op.mech) || c.pss(salt, mgf).is_ok());
            ok.then(|| c.verify(s, data))
        }),
        Some(hash) => match DigestCtx::new()
            .ok()
            .and_then(|mut c| c.init(false, &k, Some(hash), &[]).then_some(c))
        {
            Some(mut c) => {
                if is_pss(op.mech)
                    && let Err(prv) = c.pss(salt, mgf)
                {
                    return op.end(prv);
                }
                Some(c.verify(s, data))
            }
            None => None,
        },
    };
    let ok = match v {
        // ECDSA: OpenSSL answers -1 for some signatures that do not verify.
        Some(v) if v < 0 && ecdsa => {
            clear_errors();
            false
        }
        Some(v) if v < 0 => return op.end(FUNCTION_FAILED),
        Some(v) => v == 1,
        None => false,
    };
    recorded(false, h, op, if ok { OK } else { SIGNATURE_INVALID }, &[])
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_Sign(
    h: c_ulong,
    data: *const u8,
    n: c_ulong,
    out: *mut u8,
    out_len: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(mut op) = active_slot(true, h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    if let Err(rv) = op.ctx_auth() {
        return rv.into();
    }
    if n > MAX_INPUT {
        return op.end(DATA_LEN_RANGE).into();
    }
    if out_len.is_null() {
        return ARGUMENTS_BAD.into();
    }
    if data.is_null() && n != 0 {
        return op.end(ARGUMENTS_BAD).into();
    }
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    // SAFETY: readable for n bytes (caller), n bounded above
    let data = unsafe { bytes(data, n as usize) };
    // SAFETY: out writable for *out_len bytes unless NULL, out_len a CK_ULONG (caller)
    unsafe { sign_one(h, &mut op, tok, data, out, out_len) }.into()
}

/// The length C_Sign or C_SignFinal answers a size query or a short buffer with, or `None`
/// to go on.
///
/// # Safety
/// `out_len` a CK_ULONG.
unsafe fn sized(out: *mut u8, out_len: *mut c_ulong, need: usize) -> Option<u32> {
    // SAFETY: the caller's
    unsafe {
        if !out.is_null() && *out_len as usize >= need {
            return None;
        }
        *out_len = need as c_ulong;
    }
    Some(if out.is_null() { OK } else { BUFFER_TOO_SMALL })
}

/// C_Sign's mechanism paths (`:11337-11480`).
///
/// # Safety
/// As C_Sign's: `out` NULL or writable for `*out_len` bytes, `out_len` a CK_ULONG.
unsafe fn sign_one(
    h: c_ulong,
    op: &mut Op,
    t: Tok,
    data: &[u8],
    out: *mut u8,
    out_len: *mut c_ulong,
) -> u32 {
    // SAFETY: the caller's; every write below is to *out_len or to out within *out_len
    unsafe {
        if op.mech == COMPOSITE {
            let (kv, cl, kt) = match object(t, op.key) {
                Ok(o) => o,
                Err(rv) => return op.end(rv),
            };
            if cl != CKO_PRIVATE_KEY || kt != CKK_COMPOSITE {
                return op.end(KEY_TYPE_INCONSISTENT);
            }
            if let Some(rv) = sized(out, out_len, COMPOSITE_SIG) {
                return rv;
            }
            let mut s = vec![0u8; COMPOSITE_SIG];
            let mut sl = s.len();
            let kva = [(c"alg", c"composite")];
            let rv = fhsm_composite_sign(
                COMPOSITE_ALG,
                kv.as_ptr(),
                kv.len(),
                data.as_ptr(),
                data.len(),
                null(),
                0,
                s.as_mut_ptr(),
                &mut sl,
            );
            if rv != OK {
                *out_len = 0;
                return recorded(true, h, op, rv, &kva);
            }
            return emit(h, op, &s[..sl], out, out_len, &kva);
        }
        if let Some((alg, _, need)) = hmac_of(op.mech) {
            let kv = match object(t, op.key) {
                Ok((kv, ..)) => kv,
                Err(rv) => return op.end(rv),
            };
            if let Some(rv) = sized(out, out_len, need) {
                return rv;
            }
            let mut mac = [0u8; 64];
            let rv = match hmac(alg, kv, data, Some(&mut mac)) {
                Ok(m) => emit(h, op, &mac[..m], out, out_len, &[]),
                Err(rv) => recorded(true, h, op, rv, &[]),
            };
            cleanse(&mut mac);
            return rv;
        }
        if op.mech == CMAC || op.mech == GMAC {
            let (kv, _, kt) = match object(t, op.key) {
                Ok(o) => o,
                Err(rv) => return op.end(rv),
            };
            if kt != CKK_AES {
                return op.end(KEY_TYPE_INCONSISTENT);
            }
            let need = op.aes_mac_len();
            if let Some(rv) = sized(out, out_len, need) {
                return rv;
            }
            let gmac = op.mech == GMAC;
            if gmac && (!op.gcm_have || op.gcm_iv.is_empty()) {
                return op.end(ARGUMENTS_BAD);
            }
            // GMAC's tag computed whole, then truncated to the mechanism's length.
            return match aes_mac(gmac, kv, &op.gcm_iv, data) {
                Ok(mut tag) => {
                    let rv = emit(h, op, &tag[..need], out, out_len, &[]);
                    cleanse(&mut tag);
                    rv
                }
                Err(rv) => {
                    *out_len = need as c_ulong;
                    recorded(true, h, op, rv, &[])
                }
            };
        }
        // Asymmetric: a size query answers the key's exact length, or the family's bound.
        if out.is_null() {
            let e = exact_len(t, op);
            *out_len = if e != 0 { e } else { family_bound(op.mech) } as c_ulong;
            return OK;
        }
        let have = *out_len as usize;
        let mut s = vec![0u8; family_bound(op.mech)];
        match sign_asymmetric(t, op, data, &mut s) {
            Err(rv) => recorded(true, h, op, rv, &[]),
            // The one return that does not end the operation (§5.2); the retry signs again.
            Ok(sl) if have < sl => {
                *out_len = sl as c_ulong;
                BUFFER_TOO_SMALL
            }
            Ok(sl) => emit(h, op, &s[..sl], out, out_len, &[]),
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_Verify(
    h: c_ulong,
    data: *const u8,
    n: c_ulong,
    sig: *const u8,
    sig_len: c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(mut op) = active_slot(false, h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    if n > MAX_INPUT {
        return op.end(DATA_LEN_RANGE).into();
    }
    if data.is_null() && n != 0 {
        return op.end(ARGUMENTS_BAD).into();
    }
    // DIV-063: C read through it (a crash), or OpenSSL refused its length first (0xC0)
    if sig.is_null() && sig_len != 0 {
        return op.end(ARGUMENTS_BAD).into();
    }
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    // SAFETY: readable for n bytes (caller), n bounded above
    let data = unsafe { bytes(data, n as usize) };
    let sig = Sig {
        p: sig,
        n: sig_len as usize,
    };
    // SAFETY: sig as the caller passed it
    unsafe { verify_one(h, &mut op, tok, data, &sig) }.into()
}

/// C_Verify's mechanism paths (`:11572-11634`).
///
/// # Safety
/// As `Sig::get`.
unsafe fn verify_one(h: c_ulong, op: &mut Op, t: Tok, data: &[u8], sig: &Sig) -> u32 {
    let (kv, cl, kt) = match object(t, op.key) {
        Ok(o) => o,
        Err(rv) => return op.end(rv),
    };
    if op.mech == COMPOSITE {
        op.active = false;
        if cl != CKO_PUBLIC_KEY || kt != CKK_COMPOSITE {
            return KEY_TYPE_INCONSISTENT;
        }
        // SAFETY: each buffer readable for its length; the signature as the caller passed it,
        // so pki refuses a NULL one (0x7), as C
        let rv = unsafe {
            fhsm_composite_verify(
                COMPOSITE_ALG,
                kv.as_ptr(),
                kv.len(),
                data.as_ptr(),
                data.len(),
                null(),
                0,
                sig.p,
                sig.n,
            )
        };
        return recorded(false, h, op, rv, &[(c"alg", c"composite")]);
    }
    // The MACs are not audited, as C.
    let mut mac = [0u8; 64];
    let r = if let Some((alg, ..)) = hmac_of(op.mech) {
        hmac(alg, kv, data, Some(&mut mac))
    } else if op.mech == CMAC || op.mech == GMAC {
        if kt != CKK_AES {
            return op.end(KEY_TYPE_INCONSISTENT);
        }
        let gmac = op.mech == GMAC;
        if gmac && (!op.gcm_have || op.gcm_iv.is_empty()) {
            return op.end(ARGUMENTS_BAD);
        }
        aes_mac(gmac, kv, &op.gcm_iv, data).map(|mut tag| {
            mac[..16].copy_from_slice(&tag);
            cleanse(&mut tag);
            op.aes_mac_len()
        })
    } else {
        // SAFETY: the caller's
        return unsafe { verify_asymmetric(h, t, op, data, sig) };
    };
    op.active = false;
    let rv = match r {
        Err(rv) => rv,
        Ok(m) if sig.n != m => SIGNATURE_INVALID,
        // SAFETY: the caller's
        // SAFETY: the caller's, of the length just checked
        Ok(m) if ct_eq(&mac[..m], unsafe { sig.get() }) => OK,
        Ok(_) => SIGNATURE_INVALID,
    };
    cleanse(&mut mac);
    rv
}

/// `C_SignUpdate` and `C_VerifyUpdate` (`:12267`, `:12511`).
unsafe fn update(sign: bool, h: c_ulong, part: *const u8, n: c_ulong) -> u32 {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv;
    }
    let Some(mut op) = active_slot(sign, h) else {
        return OPERATION_NOT_INITIALIZED;
    };
    if sign && let Err(rv) = op.ctx_auth() {
        return rv;
    }
    if n > MAX_INPUT {
        return op.end(DATA_LEN_RANGE);
    }
    if part.is_null() && n != 0 {
        return op.end(ARGUMENTS_BAD);
    }
    // SAFETY: readable for n bytes (caller), n bounded above
    let part = unsafe { bytes(part, n as usize) };
    // C_VerifyUpdate looks the session up first; C_SignUpdate only before the MAC stream.
    let tok = TABLE.token(h);
    if !sign && tok.is_none() {
        return SESSION_HANDLE_INVALID;
    }
    if op.mech == COMPOSITE {
        // Its failures leave the operation active, as C.
        return composite_update(&mut op, part);
    }
    if op.hm_row != 0 {
        return match hm_ph_update(&mut op, part) {
            Ok(()) => OK,
            Err(rv) => op.hm_fail(rv),
        };
    }
    if buffered(op.mech) {
        return append(&mut op, part);
    }
    let Some(tok) = tok else {
        return SESSION_HANDLE_INVALID;
    };
    if op.mac.is_none() {
        match mac_open(tok, &op) {
            Ok(m) => op.mac = Some(m),
            Err(rv) => return op.end(rv),
        }
    }
    if !op.mac.as_mut().is_some_and(|m| m.update(part)) {
        op.mac = None;
        return op.end(FUNCTION_FAILED);
    }
    OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_SignUpdate(h: c_ulong, p: *const u8, n: c_ulong) -> c_ulong {
    // SAFETY: the caller's
    unsafe { update(true, h, p, n) }.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_VerifyUpdate(h: c_ulong, p: *const u8, n: c_ulong) -> c_ulong {
    // SAFETY: the caller's
    unsafe { update(false, h, p, n) }.into()
}

/// The MAC stream finished (`:12477-12489`, `:12642-12649`): the whole MAC into `full`, and
/// its length, or an rv. The stream is freed either way.
fn mac_final(h: c_ulong, op: &mut Op, full: &mut [u8; 64]) -> Result<usize, u32> {
    if op.mac.is_none() {
        // No Update: the MAC of the empty message, through the same stream.
        let t = TABLE.token(h).ok_or(SESSION_HANDLE_INVALID)?;
        op.mac = Some(mac_open(t, op)?);
    }
    op.mac
        .take()
        .and_then(|mut m| m.finish(full))
        .ok_or(FUNCTION_FAILED)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_SignFinal(
    h: c_ulong,
    out: *mut u8,
    out_len: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(mut op) = active_slot(true, h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    if let Err(rv) = op.ctx_auth() {
        return rv.into();
    }
    if out_len.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // SAFETY: out writable for *out_len bytes unless NULL, out_len a CK_ULONG (caller)
    unsafe { sign_final(h, &mut op, out, out_len) }.into()
}

/// C_SignFinal's mechanism paths (`:12348-12492`).
///
/// # Safety
/// As C_SignFinal's.
unsafe fn sign_final(h: c_ulong, op: &mut Op, out: *mut u8, out_len: *mut c_ulong) -> u32 {
    // SAFETY: the caller's; every write below is to *out_len or to out within *out_len
    unsafe {
        if op.mech == COMPOSITE {
            if let Some(rv) = sized(out, out_len, COMPOSITE_SIG) {
                return rv;
            }
            let Some(t) = TABLE.token(h) else {
                return SESSION_HANDLE_INVALID;
            };
            let (kv, cl, kt) = match object(t, op.key) {
                Ok(o) => o,
                Err(rv) => return op.end(rv),
            };
            if cl != CKO_PRIVATE_KEY || kt != CKK_COMPOSITE {
                return op.end(KEY_TYPE_INCONSISTENT);
            }
            let kva = [(c"alg", c"composite-multipart")];
            let mut ph = [0u8; 64];
            let mut s = vec![0u8; COMPOSITE_SIG];
            let mut sl = s.len();
            let rv = match composite_final(op, &mut ph) {
                Ok(l) => fhsm_composite_sign_prehashed(
                    COMPOSITE_ALG,
                    kv.as_ptr(),
                    kv.len(),
                    ph.as_ptr(),
                    l,
                    null(),
                    0,
                    s.as_mut_ptr(),
                    &mut sl,
                ),
                Err(rv) => rv,
            };
            cleanse(&mut ph);
            if rv != OK {
                *out_len = 0;
                return recorded(true, h, op, rv, &kva);
            }
            return emit(h, op, &s[..sl], out, out_len, &kva);
        }
        if buffered(op.mech) {
            let Some(t) = TABLE.token(h) else {
                return op.end(SESSION_HANDLE_INVALID);
            };
            if op.hm_row != 0
                && let Err(rv) = hm_ph_finish(op)
            {
                return op.hm_fail(rv);
            }
            // Size query: nothing is signed, so the length comes from the key.
            if out.is_null() {
                let e = exact_len(t, op);
                *out_len = if e != 0 { e } else { family_bound(op.mech) } as c_ulong;
                return OK;
            }
            let have = *out_len as usize;
            let kva = [(c"mode", c"multipart")];
            let mut s = vec![0u8; family_bound(op.mech)];
            return match sign_asymmetric(t, op, &op.mp.0, &mut s) {
                Err(rv) => {
                    op.mp = Secret::NONE;
                    recorded(true, h, op, rv, &kva)
                }
                // The buffered message stays for the retry.
                Ok(sl) if have < sl => {
                    *out_len = sl as c_ulong;
                    BUFFER_TOO_SMALL
                }
                Ok(sl) => {
                    op.mp = Secret::NONE;
                    emit(h, op, &s[..sl], out, out_len, &kva)
                }
            };
        }
        let fmac = op.stream_len();
        if fmac == 0 {
            op.mac = None;
            return op.end(MECHANISM_INVALID);
        }
        if let Some(rv) = sized(out, out_len, fmac) {
            return rv;
        }
        // Not audited, as C.
        let mut full = [0u8; 64];
        let rv = match mac_final(h, op, &mut full) {
            Ok(n) if n >= fmac => {
                copy_nonoverlapping(full.as_ptr(), out, fmac);
                *out_len = fmac as c_ulong;
                OK
            }
            Ok(_) => FUNCTION_FAILED,
            Err(rv) => rv,
        };
        if rv != OK {
            *out_len = 0;
        }
        cleanse(&mut full);
        op.end(rv)
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_VerifyFinal(
    h: c_ulong,
    sig: *const u8,
    sig_len: c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(mut op) = active_slot(false, h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    if sig.is_null() {
        return ARGUMENTS_BAD.into();
    }
    let sig = Sig {
        p: sig,
        n: sig_len as usize,
    };
    // SAFETY: non-NULL, readable for sig_len bytes (caller)
    unsafe { verify_final(h, &mut op, &sig) }.into()
}

/// C_VerifyFinal's mechanism paths (`:12580-12660`).
///
/// # Safety
/// `sig.p` non-NULL and readable for `sig.n` bytes.
unsafe fn verify_final(h: c_ulong, op: &mut Op, sig: &Sig) -> u32 {
    // SAFETY: the caller's
    let s = unsafe { bytes(sig.p, sig.n) };
    if op.mech == COMPOSITE {
        let Some(t) = TABLE.token(h) else {
            return SESSION_HANDLE_INVALID;
        };
        let got = object(t, op.key);
        op.active = false;
        let (kv, cl, kt) = match got {
            Ok(o) => o,
            Err(rv) => return rv,
        };
        if cl != CKO_PUBLIC_KEY || kt != CKK_COMPOSITE {
            return KEY_TYPE_INCONSISTENT;
        }
        let mut ph = [0u8; 64];
        let rv = match composite_final(op, &mut ph) {
            // SAFETY: each buffer readable for its length
            Ok(l) => unsafe {
                fhsm_composite_verify_prehashed(
                    COMPOSITE_ALG,
                    kv.as_ptr(),
                    kv.len(),
                    ph.as_ptr(),
                    l,
                    null(),
                    0,
                    s.as_ptr(),
                    s.len(),
                )
            },
            Err(rv) => rv,
        };
        cleanse(&mut ph);
        return recorded(false, h, op, rv, &[(c"alg", c"composite-multipart")]);
    }
    if buffered(op.mech) {
        let Some(t) = TABLE.token(h) else {
            op.mp = Secret::NONE;
            return op.end(SESSION_HANDLE_INVALID);
        };
        if op.hm_row != 0
            && let Err(rv) = hm_ph_finish(op)
        {
            return op.hm_fail(rv);
        }
        let mp = std::mem::replace(&mut op.mp, Secret::NONE);
        // SAFETY: as this function's
        let rv = unsafe { verify_asymmetric(h, t, op, &mp.0, sig) };
        return op.end(rv);
    }
    let fmac = op.stream_len();
    if fmac == 0 {
        op.mac = None;
        return op.end(MECHANISM_INVALID);
    }
    let mut mac = [0u8; 64];
    let r = mac_final(h, op, &mut mac);
    op.active = false;
    let rv = match r {
        Err(rv) => rv,
        Ok(n) if s.len() == fmac && n >= fmac && ct_eq(&mac[..fmac], s) => OK,
        Ok(_) => SIGNATURE_INVALID,
    };
    cleanse(&mut mac);
    rv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tables_match_c() {
        assert_eq!(hm_row_of(0x24), 2);
        assert_eq!(hm_row_of(0x3F), 12);
        assert_eq!(hm_row_of(0x1F), 0);
        assert!(hmldsa_is(HASH_SLH_DSA) && hm_slh(0x36) && !hm_slh(0x23));
        let bounds = (
            family_bound(0x3A),
            family_bound(0x27),
            family_bound(ML_DSA),
            family_bound(0x1041),
        );
        assert_eq!(bounds, (65536, 8192, 8192, 512));
        assert!(!buffered(CMAC) && !buffered(0x2D1) && !buffered(COMPOSITE) && buffered(EDDSA));
        assert_eq!(listed(0x49), Some(false));
        assert_eq!(listed(RSA_X_509), Some(true));
        assert_eq!(listed(0x1042), None);
        // HMAC: any key but RSA, EC and Edwards; SHA-224 RSA and HMAC-SHA512/224 unchecked
        assert!(
            key_type_ok(0x251, CKK_AES) && !key_type_ok(0x251, CKK_EC) && key_type_ok(0x46, CKK_EC)
        );
        assert!(key_type_ok(0x49, CKK_RSA) && !key_type_ok(0x1044, CKK_RSA));
    }

    #[test]
    fn hashml_message_is_c_s_m_prime() {
        let op = Op {
            mech: HASH_ML_DSA,
            hm_row: 2,
            ctx: Some(vec![0xAA]),
            ..Op::IDLE
        };
        let ph = [7u8; 32];
        let mp = hm_message(&op, &ph).unwrap();
        assert_eq!(&mp[..3], &[1, 1, 0xAA]);
        assert_eq!(&mp[3..13], &HMLDSA_OID_PREFIX);
        assert_eq!(mp[13], 1);
        assert_eq!(&mp[14..], &ph);
        assert_eq!(hm_message(&op, &ph[..31]), Err(DATA_LEN_RANGE));
        // SHAKE128 gives exactly 32 bytes of PH(M)
        let op = Op {
            mech: 0x2B,
            hm_row: 11,
            ..Op::IDLE
        };
        assert_eq!(hm_message(&op, b"abc").unwrap().len(), 2 + 10 + 1 + 32);
    }

    #[test]
    fn pss_arguments_follow_pss_apply_params() {
        let op = Op {
            pss: Some((2, 32)),
            ..Op::IDLE
        };
        assert!(matches!(op.pss_args(), (32, Mgf::Named(n)) if n == c"SHA256"));
        let op = Op {
            pss: Some((0x99, 0)),
            ..Op::IDLE
        };
        assert!(matches!(op.pss_args(), (0, Mgf::Unknown)));
        assert!(matches!(Op::IDLE.pss_args(), (-1, Mgf::Default)));
    }
}
