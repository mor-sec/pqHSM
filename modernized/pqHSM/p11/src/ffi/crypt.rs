//! Phase 4 slice 4: `C_EncryptInit`, `C_Encrypt`, `C_EncryptUpdate`, `C_EncryptFinal` and the
//! four `C_Decrypt*` (`src/fhsm_pkcs11.c:8506-8630, 9017-9620, 9761-10700, 12662-13030`), in C's
//! check order and with C's EVP call sequences (`pqhsm_crypto::cipher`). The encrypt and
//! decrypt operation tables (C's `g_op_enc`, `g_op_dec` and the OAEP tables) are this module's.
//!
//! Divergences: DIV-053's refusal is `gate`. DIV-050: a secret or private key is usable only
//! while the user is logged in, and `C_Logout` ends the operations under way on one. DIV-061: a
//! single-part AES-ECB, CBC, CBC-PAD or CTR call refuses a key that is not 16, 24 or 32 bytes
//! (C read 32 bytes from it). DIV-062: every Init starts a fresh cipher context (C continued
//! the one an error had left). DIV-001: a single-part success whose audit record fails returns
//! 0x30 and writes no output.

use std::ffi::{CStr, c_int, c_ulong};
use std::ptr::{copy_nonoverlapping, null, null_mut};
use std::sync::{Mutex, MutexGuard};

use pqhsm_core::session::MAX;
use pqhsm_crypto::cipher::{Aead, AeadCipher, Cipher, Fetched, Pkey, PkeyCtx, aead, cleanse, md_known};

use super::apilock::Held;
use super::digest::{Mech, bytes, sized};
use super::objects::{CKO_PRIVATE_KEY, CKO_SECRET_KEY, access_denied, gate};
use super::session::{TABLE, Tok, fhsm_session_role};
use super::sys::*;

const DATA_LEN_RANGE: u32 = 0x21;
const ENCRYPTED_DATA_INVALID: u32 = 0x40;
const ENCRYPTED_DATA_LEN_RANGE: u32 = 0x41;
const KEY_SIZE_RANGE: u32 = 0x62;
const KEY_TYPE_INCONSISTENT: u32 = 0x63;
const KEY_FUNCTION_NOT_PERMITTED: u32 = 0x68;
const MECHANISM_INVALID: u32 = 0x70;
const MECHANISM_PARAM_INVALID: u32 = 0x71;
const WRAPPING_KEY_SIZE_RANGE: u32 = 0x114;

const RSA_PKCS: c_ulong = 0x1;
const RSA_X_509: c_ulong = 0x3;
const OAEP: c_ulong = 0x9;
const DES3_CBC: c_ulong = 0x133;
const ECB: c_ulong = 0x1081;
const CBC: c_ulong = 0x1082;
const CBC_PAD: c_ulong = 0x1085;
const CTR: c_ulong = 0x1086;
const GCM: c_ulong = 0x1087;
const CCM: c_ulong = 0x1088;
const KW: c_ulong = 0x2109;
const KWP: c_ulong = 0x210B;

const CKO_PUBLIC_KEY: u32 = 2;
const CKK_RSA: u32 = 0;
const CKK_DES3: u32 = 0x15;
const CKK_AES: u32 = 0x1F;
const OBJF_ALWAYS_AUTH: u8 = 0x20;
const USAGE_ENCRYPT: u8 = 0x01;
const USAGE_DECRYPT: u8 = 0x02;
const USAGE_VALID: u8 = 0x80;
const EV_ENCRYPT: c_int = 40;
const EV_DECRYPT: c_int = 41;

/// C's 2 GiB ceiling on one call's input (#125 isize).
const MAX_INPUT: c_ulong = 0x7FFF_FFFF;
/// `FHSM_AAD_MAX`.
const AAD_MAX: usize = 1024 * 1024;
/// `sizeof(op->gcm_iv)`.
const GCM_IV_MAX: usize = 512;
/// `sizeof(label_copy)`.
const LABEL_MAX: usize = 64;
/// C_Decrypt's key-unwrap buffer.
const KW_MAX: usize = 4096;
const UL: usize = size_of::<c_ulong>();

/// Bytes zeroised when dropped: the AAD and the label, as C cleansed them, and every scratch
/// output.
struct Secret(Vec<u8>);

impl Secret {
    const NONE: Secret = Secret(Vec::new());
    fn zeroed(n: usize) -> Self {
        Self(vec![0; n])
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        cleanse(&mut self.0);
    }
}

/// One session's encrypt or decrypt operation (C's `fhsm_op_t`, the fields a cipher uses, and
/// the session's OAEP parameters).
struct Op {
    active: bool,
    mech: c_ulong,
    key: u32,
    /// DIV-050: the token and whether the key is the user's (secret or private), so a logout
    /// ends the operation.
    tok: Option<Tok>,
    private: bool,
    auth_required: bool,
    auth_done: bool,
    /// `have_iv` and `iv`: 16 bytes for CBC and CTR, 12 for a bare GCM IV, 8 or 4 for key wrap.
    iv: Option<[u8; 16]>,
    /// The GCM IV or CCM nonce, the AAD and the tag length in bytes.
    gcm_iv: Vec<u8>,
    aad: Secret,
    tag_len: usize,
    /// CK_RSA_PKCS_OAEP_PARAMS' hash and MGF, and the label as Init copied it.
    oaep: (c_ulong, c_ulong),
    label: Secret,
    /// The multipart context, made at the first Update or Final.
    ctx: Option<Cipher>,
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
        iv: None,
        gcm_iv: Vec::new(),
        aad: Secret::NONE,
        tag_len: 16,
        oaep: (0, 0),
        label: Secret::NONE,
        ctx: None,
    };

    /// C's `op->active = 0; return rv;`.
    fn end(&mut self, rv: u32) -> u32 {
        self.active = false;
        rv
    }

    /// `op_require_ctx_auth`: an ALWAYS_AUTHENTICATE key's decryption needs the context login.
    fn ctx_auth(&mut self) -> Result<(), u32> {
        if self.auth_required && !self.auth_done {
            return Err(self.end(USER_NOT_LOGGED_IN));
        }
        Ok(())
    }

    fn iv(&self) -> Option<&[u8]> {
        self.iv.as_ref().map(|v| &v[..])
    }

    /// The GCM tag or CCM MAC length; 16 when unset, as C's `gcm_tag_len ? : 16`.
    fn tag(&self) -> usize {
        if self.tag_len == 0 { 16 } else { self.tag_len }
    }
}

/// One slot per session handle, as C's tables; handle 0 and those past the table have none.
/// shortcut: a fork while another thread is inside an encrypt call deadlocks the child's
/// C_Initialize in `forget_all`, as digest.rs's slots (review M1); fix with them in the M3
/// atfork work.
static ENC: [Mutex<Op>; MAX] = [const { Mutex::new(Op::IDLE) }; MAX];
static DEC: [Mutex<Op>; MAX] = [const { Mutex::new(Op::IDLE) }; MAX];

fn lock(m: &'static Mutex<Op>) -> MutexGuard<'static, Op> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// `op_slot(g_op_enc or g_op_dec, h)`.
fn slot(enc: bool, h: c_ulong) -> Option<MutexGuard<'static, Op>> {
    let t = if enc { &ENC } else { &DEC };
    (h != 0 && (h as usize) < MAX).then(|| lock(&t[h as usize]))
}

fn active_slot(enc: bool, h: c_ulong) -> Option<MutexGuard<'static, Op>> {
    slot(enc, h).filter(|o| o.active)
}

/// This session's operations, freed (`fhsm_session_ops_reset`'s cipher part).
pub(super) fn reset(h: c_ulong) {
    for enc in [true, false] {
        if let Some(mut o) = slot(enc, h) {
            *o = Op::IDLE;
        }
    }
}

/// Is an encryption or decryption active in this session?
pub(super) fn active(h: c_ulong) -> bool {
    active_slot(true, h).is_some() || active_slot(false, h).is_some()
}

/// The context-specific login's grant to this session's active operations.
pub(super) fn grant(h: c_ulong) {
    for enc in [true, false] {
        if let Some(mut o) = active_slot(enc, h) {
            o.auth_done = true;
        }
    }
}

/// DIV-050: the logout of `t` ends every operation under way on one of its user's keys; the
/// next call answers 0x91. Under C_Logout's EXCLUSIVE lock, so no call holds a slot.
pub(super) fn end_private(t: Tok) {
    for s in ENC[1..].iter().chain(&DEC[1..]) {
        let mut o = lock(s);
        if o.active && o.private && o.tok == Some(t) {
            o.active = false;
        }
    }
}

/// At finalize: every session's operations freed.
pub(super) fn release_all() {
    (1..MAX as c_ulong).for_each(reset);
}

/// After a fork: every operation forgotten, its context not freed (the parent's).
pub(super) fn forget_all() {
    for s in ENC[1..].iter().chain(&DEC[1..]) {
        let mut o = lock(s);
        if let Some(c) = o.ctx.take() {
            c.forget();
        }
        *o = Op::IDLE;
    }
}

/// `fhsm_token_object_get`: the value, class and key type, or its rv.
fn object<'a>(t: Tok, k: u32) -> Result<(&'a [u8], u32, u32), u32> {
    let (mut v, mut vl, mut class, mut kt) = (null(), 0usize, 0u32, 0u32);
    // SAFETY: a token the registry holds; out pointers of our own
    let rv = unsafe { fhsm_token_object_get(t.0.as_ptr(), k, &mut v, &mut vl, &mut class, &mut kt) };
    if rv != OK {
        return Err(rv);
    }
    // SAFETY: the token's value of vl bytes. Alive for this call: whatever frees a value runs
    // under the EXCLUSIVE lock, or is parked by apilock.rs until no call is in flight
    Ok((unsafe { bytes(v, vl) }, class, kt))
}

/// The audit record of a single-part call (DIV-001: its result counts).
fn record(enc: bool, h: c_ulong, rv: u32) -> Result<(), u32> {
    let ev = if enc { EV_ENCRYPT } else { EV_DECRYPT };
    audit(ev, -1, h as c_int, fhsm_session_role(h), rv, &[])
}

/// A failing single-part call that C audits: the operation ends, the record is made, the
/// call's rv stands.
fn fail_recorded(enc: bool, h: c_ulong, op: &mut Op, rv: u32, recorded: u32) -> u32 {
    op.active = false;
    audited(rv, record(enc, h, recorded))
}

/// A single-part success: the operation ends, the record is made, and only then (DIV-001) do
/// the bytes and their length reach the caller.
///
/// # Safety
/// `out` writable for `b.len()` bytes, which C's checks before established.
unsafe fn emit(enc: bool, h: c_ulong, op: &mut Op, b: &[u8], out: *mut u8, out_len: *mut c_ulong) -> u32 {
    op.active = false;
    if let Err(e) = record(enc, h, OK) {
        return e;
    }
    // SAFETY: the caller's
    unsafe {
        copy_nonoverlapping(b.as_ptr(), out, b.len());
        *out_len = b.len() as c_ulong;
    }
    OK
}

fn strict() -> bool {
    // SAFETY: a constant the C build defines
    (unsafe { fhsm_build_fips_strict }) != 0
}

/// `fhsm_nonfips_enc_rejected`.
fn nonfips_rejected(m: c_ulong) -> bool {
    strict() && matches!(m, DES3_CBC | RSA_PKCS | RSA_X_509)
}

/// `fhsm_cipher_mech_valid`.
fn cipher_mech_valid(m: c_ulong) -> bool {
    matches!(m, ECB | CBC | CBC_PAD | CTR | GCM | CCM | DES3_CBC | RSA_PKCS | RSA_X_509 | OAEP | KW | KWP)
}

/// `fhsm_check_key_mech_type`'s cipher rows: the key type a mechanism needs, if any.
fn key_type_for(m: c_ulong) -> Option<u32> {
    match m {
        RSA_PKCS | RSA_X_509 | OAEP => Some(CKK_RSA),
        ECB | CBC | CBC_PAD | CTR | GCM | CCM => Some(CKK_AES),
        DES3_CBC => Some(CKK_DES3),
        _ => None,
    }
}

/// `oaep_md`.
fn oaep_md(m: c_ulong) -> Option<&'static CStr> {
    Some(match m {
        0x220 => c"SHA1",
        0x255 => c"SHA224",
        0x250 => c"SHA256",
        0x260 => c"SHA384",
        0x270 => c"SHA512",
        0x2B5 => c"SHA3-224",
        0x2B0 => c"SHA3-256",
        0x2C0 => c"SHA3-384",
        0x2D0 => c"SHA3-512",
        _ => return None,
    })
}

/// `mgf_md`.
fn mgf_md(g: c_ulong) -> Option<&'static CStr> {
    Some(match g {
        1 => c"SHA1",
        5 => c"SHA224",
        2 => c"SHA256",
        3 => c"SHA384",
        4 => c"SHA512",
        6 => c"SHA3-224",
        7 => c"SHA3-256",
        8 => c"SHA3-384",
        9 => c"SHA3-512",
        _ => return None,
    })
}

/// `N` CK_ULONGs at `p`, unaligned as the caller may pass them.
///
/// # Safety
/// `p` readable for `N` CK_ULONGs.
unsafe fn ulongs<const N: usize>(p: *const u8) -> [c_ulong; N] {
    // SAFETY: the caller's
    unsafe { p.cast::<[c_ulong; N]>().read_unaligned() }
}

/// A caller's buffer named by a pointer and a length inside a parameter block, copied.
///
/// # Safety
/// `p` readable for `n` bytes when `n` is not zero.
unsafe fn copied(p: c_ulong, n: usize) -> Vec<u8> {
    // SAFETY: the caller's
    unsafe { bytes(p as *const u8, n) }.to_vec()
}

/// `op_init`'s cipher half (`:9037-9580`), into a fresh operation: the parameters each
/// mechanism takes, in C's order, and the final IV checks.
///
/// # Safety
/// `m.param` readable for `m.param_len` bytes, and every pointer inside it for its length.
unsafe fn params(m: &Mech, op: &mut Op) -> Result<(), u32> {
    let (p, n) = (m.param.cast::<u8>().cast_const(), m.param_len as usize);
    let mut gcm_have = false;
    if m.mechanism == GCM && !p.is_null() {
        if n >= 6 * UL {
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
            // SAFETY: the caller's buffers of those lengths
            unsafe {
                op.gcm_iv = copied(iv, iv_len);
                op.aad = Secret(copied(aad, aad_len));
            }
            op.tag_len = tag_bits as usize / 8;
            gcm_have = true;
        } else if n >= 12 {
            // A bare 12-byte IV, as C read one from any shorter block (its first 12 bytes).
            let mut iv = [0u8; 16];
            // SAFETY: n >= 12 bytes (caller)
            iv[..12].copy_from_slice(unsafe { bytes(p, 12) });
            op.iv = Some(iv);
            op.gcm_iv = iv[..12].to_vec();
            gcm_have = true;
        }
    }
    if matches!(m.mechanism, CBC | CBC_PAD) && !p.is_null() && n == 16 {
        // SAFETY: 16 bytes (caller)
        op.iv = Some(unsafe { bytes(p, 16) }.try_into().expect("16 bytes"));
    }
    if m.mechanism == DES3_CBC {
        if p.is_null() || n != 8 {
            return Err(MECHANISM_PARAM_INVALID);
        }
        let mut iv = [0u8; 16];
        // SAFETY: 8 bytes (caller)
        iv[..8].copy_from_slice(unsafe { bytes(p, 8) });
        op.iv = Some(iv);
    }
    if m.mechanism == CTR {
        if p.is_null() {
            return Err(MECHANISM_PARAM_INVALID);
        }
        let at = if n == 16 {
            0
        } else if n >= UL + 16 {
            // SAFETY: n bytes (caller)
            let [bits] = unsafe { ulongs::<1>(p) };
            if bits == 0 || bits > 128 {
                return Err(MECHANISM_PARAM_INVALID);
            }
            UL
        } else {
            return Err(MECHANISM_PARAM_INVALID);
        };
        // SAFETY: at + 16 <= n bytes (caller)
        op.iv = Some(unsafe { bytes(p.add(at), 16) }.try_into().expect("16 bytes"));
    }
    if matches!(m.mechanism, KW | KWP) && !(p.is_null() && n == 0) {
        // kw_iv_from_mech: none, or exactly 8 (KW) or 4 (KWP) bytes
        let want = if m.mechanism == KW { 8 } else { 4 };
        if p.is_null() || n != want {
            return Err(MECHANISM_PARAM_INVALID);
        }
        let mut iv = [0u8; 16];
        // SAFETY: want bytes (caller)
        iv[..want].copy_from_slice(unsafe { bytes(p, want) });
        op.iv = Some(iv);
    }
    if m.mechanism == CCM {
        if p.is_null() || n < 6 * UL {
            return Err(MECHANISM_PARAM_INVALID);
        }
        // SAFETY: n bytes (caller)
        let [_, nonce, nonce_len, aad, aad_len, mac] = unsafe { ulongs::<6>(p) };
        let (nonce_len, aad_len) = (nonce_len as usize, aad_len as usize);
        if nonce == 0 || !(7..=13).contains(&nonce_len) {
            return Err(MECHANISM_PARAM_INVALID);
        }
        if !matches!(mac, 4 | 6 | 8 | 10 | 12 | 14 | 16) {
            return Err(MECHANISM_PARAM_INVALID);
        }
        if aad_len > AAD_MAX || (aad_len != 0 && aad == 0) {
            return Err(MECHANISM_PARAM_INVALID);
        }
        // SAFETY: the caller's buffers of those lengths
        unsafe {
            op.gcm_iv = copied(nonce, nonce_len);
            op.aad = Secret(copied(aad, aad_len));
        }
        op.tag_len = mac as usize;
    }
    if m.mechanism == OAEP {
        // fhsm_oaep_params_from_mech, then op_init's label copy
        if p.is_null() || n < 5 * UL {
            return Err(MECHANISM_PARAM_INVALID);
        }
        // SAFETY: n bytes (caller)
        let [hash, mgf, source, src, src_len] = unsafe { ulongs::<5>(p) };
        let labelled = source == 1 && src_len > 0;
        if labelled && src == 0 {
            return Err(MECHANISM_PARAM_INVALID);
        }
        let known = |n: Option<&CStr>| n.is_some_and(md_known);
        if !known(oaep_md(hash)) || !known(mgf_md(mgf)) {
            return Err(MECHANISM_PARAM_INVALID);
        }
        if labelled && src_len as usize > LABEL_MAX {
            return Err(MECHANISM_PARAM_INVALID);
        }
        op.oaep = (hash, mgf);
        if labelled {
            // SAFETY: the caller's label of src_len bytes
            op.label = Secret(unsafe { copied(src, src_len as usize) });
        }
    }
    if matches!(m.mechanism, CBC | CBC_PAD) && op.iv.is_none() {
        return Err(MECHANISM_PARAM_INVALID);
    }
    if m.mechanism == GCM && (!gcm_have || op.gcm_iv.len() < 12) {
        return Err(MECHANISM_PARAM_INVALID);
    }
    Ok(())
}

/// `C_EncryptInit` and `C_DecryptInit` (`:9761`, `:10165`).
unsafe fn init(enc: bool, h: c_ulong, m: *const Mech, key: c_ulong) -> u32 {
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
    if nonfips_rejected(m.mechanism) || !cipher_mech_valid(m.mechanism) {
        return MECHANISM_INVALID;
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
    if key_type_for(m.mechanism).is_some_and(|want| want != kt) {
        return KEY_TYPE_INCONSISTENT;
    }
    // SAFETY: a token the registry holds
    let rv = unsafe { fhsm_token_object_mech_allowed(t, k, m.mechanism as u32) };
    if rv != OK {
        return rv;
    }
    let mut u = 0u8;
    let bit = if enc { USAGE_ENCRYPT } else { USAGE_DECRYPT };
    // SAFETY: as above; an out byte of our own
    let usage = unsafe { fhsm_token_object_get_usage(t, k, &mut u) } == OK;
    if usage && u & USAGE_VALID != 0 && u & bit == 0 {
        return KEY_FUNCTION_NOT_PERMITTED;
    }
    let Some(mut slot) = slot(enc, h) else {
        return SESSION_HANDLE_INVALID;
    };
    if slot.active {
        return OPERATION_ACTIVE;
    }
    let mut f = 0u8;
    // SAFETY: as above
    let always = unsafe { fhsm_token_object_get_flags(t, k, &mut f) } == OK && f & OBJF_ALWAYS_AUTH != 0;
    // DIV-062: a fresh operation, so no context an earlier one left carries on.
    let mut op = Op {
        mech: m.mechanism,
        key: k,
        tok: Some(tok),
        private: class == CKO_SECRET_KEY || class == CKO_PRIVATE_KEY,
        auth_required: always,
        ..Op::IDLE
    };
    // SAFETY: the caller's CK_MECHANISM
    if let Err(rv) = unsafe { params(m, &mut op) } {
        return rv;
    }
    op.active = true;
    *slot = op;
    OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_EncryptInit(h: c_ulong, m: *const Mech, key: c_ulong) -> c_ulong {
    // SAFETY: the caller's
    unsafe { init(true, h, m, key) }.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_DecryptInit(h: c_ulong, m: *const Mech, key: c_ulong) -> c_ulong {
    // SAFETY: the caller's
    unsafe { init(false, h, m, key) }.into()
}

/// The OpenSSL name of AES in `mode` for a key of `n` bytes; `None` for another length.
fn aes_name(mode: &str, n: usize) -> Option<&'static CStr> {
    Some(match (mode, n) {
        ("ECB", 16) => c"AES-128-ECB",
        ("ECB", 24) => c"AES-192-ECB",
        ("ECB", 32) => c"AES-256-ECB",
        ("CBC", 16) => c"AES-128-CBC",
        ("CBC", 24) => c"AES-192-CBC",
        ("CBC", 32) => c"AES-256-CBC",
        ("CTR", 16) => c"AES-128-CTR",
        ("CTR", 24) => c"AES-192-CTR",
        ("CTR", 32) => c"AES-256-CTR",
        ("GCM", 16) => c"AES-128-GCM",
        ("GCM", 24) => c"AES-192-GCM",
        ("GCM", 32) => c"AES-256-GCM",
        ("WRAP", 16) => c"AES-128-WRAP",
        ("WRAP", 24) => c"AES-192-WRAP",
        ("WRAP", 32) => c"AES-256-WRAP",
        ("WRAP-PAD", 16) => c"AES-128-WRAP-PAD",
        ("WRAP-PAD", 24) => c"AES-192-WRAP-PAD",
        ("WRAP-PAD", 32) => c"AES-256-WRAP-PAD",
        _ => return None,
    })
}

/// A fetched cipher keyed and ready, in the single-part paths' order: MECHANISM_INVALID if the
/// fetch fails, HOST_MEMORY without a context, FUNCTION_FAILED if the init fails.
fn keyed(enc: bool, name: &CStr, key: &[u8], iv: Option<&[u8]>, wrap: bool) -> Result<Cipher, u32> {
    let c = Fetched::new(name).ok_or(MECHANISM_INVALID)?;
    let mut x = Cipher::new()?;
    if wrap {
        x.allow_wrap();
    }
    if !x.init2(enc, Some(&c), Some(key), iv) {
        return Err(FUNCTION_FAILED);
    }
    Ok(x)
}

/// The single-part AES-ECB, CBC, CBC-PAD and CTR context (`:9974-10000`, `:10479-10500`), or
/// DES3-CBC's (all-mechanisms build only).
fn block_ctx(enc: bool, op: &Op, kv: &[u8], kt: u32) -> Result<Cipher, u32> {
    if op.mech == DES3_CBC {
        if strict() {
            return Err(MECHANISM_INVALID);
        }
        if kt != CKK_DES3 {
            return Err(KEY_TYPE_INCONSISTENT);
        }
        if op.iv.is_none() {
            return Err(ARGUMENTS_BAD);
        }
        if kv.len() != 24 {
            return Err(KEY_SIZE_RANGE);
        }
        let mut x = keyed(enc, c"DES-EDE3-CBC", kv, op.iv(), false)?;
        x.set_padding(false);
        return Ok(x);
    }
    let ecb = op.mech == ECB;
    if kt != CKK_AES {
        return Err(KEY_TYPE_INCONSISTENT);
    }
    if !ecb && op.iv.is_none() {
        return Err(ARGUMENTS_BAD);
    }
    let mode = match op.mech {
        CTR => "CTR",
        ECB => "ECB",
        _ => "CBC",
    };
    // DIV-061: C took any other length for AES-256 and read 32 bytes of the value.
    let name = aes_name(mode, kv.len()).ok_or(KEY_SIZE_RANGE)?;
    let mut x = keyed(enc, name, kv, if ecb { None } else { op.iv() }, false)?;
    x.set_padding(op.mech == CBC_PAD);
    Ok(x)
}

/// Update and Final of a whole input into scratch with room for `cap` bytes and two blocks;
/// the bytes made.
fn run(enc: bool, x: &mut Cipher, inp: &[u8], cap: usize) -> Option<Secret> {
    let mut o = Secret::zeroed(cap + 32);
    // SAFETY: o has room for the input plus two blocks; inp readable; its length <= MAX_INPUT
    unsafe {
        let a = x.update(enc, o.0.as_mut_ptr(), inp.as_ptr(), inp.len())?;
        let b = x.finish(enc, o.0.as_mut_ptr().add(a))?;
        o.0.truncate(a + b);
    }
    Some(o)
}

/// The OAEP context for this operation's parameters.
fn oaep_ctx(op: &Op, k: &Pkey, enc: bool) -> Result<PkeyCtx, u32> {
    PkeyCtx::oaep(k, enc, oaep_md(op.oaep.0), mgf_md(op.oaep.1), &op.label.0)
}

/// The raw RSA context (all-mechanisms build only): PKCS#1 v1.5 or no padding.
fn raw_ctx(op: &Op, k: &Pkey, enc: bool) -> Result<PkeyCtx, u32> {
    let pad = if op.mech == RSA_PKCS { 1 } else { 3 };
    let mut x = PkeyCtx::new(k, enc).map_err(|_| FUNCTION_FAILED)?;
    if x.init() && x.padding(pad) { Ok(x) } else { Err(FUNCTION_FAILED) }
}

/// `Ok(v)`, or end the operation with the error.
macro_rules! or_end {
    ($op:expr, $r:expr) => {
        match $r {
            Ok(v) => v,
            Err(rv) => return $op.end(rv),
        }
    };
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_Encrypt(h: c_ulong, data: *const u8, n: c_ulong, out: *mut u8, out_len: *mut c_ulong) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(mut op) = active_slot(true, h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    let (kv, cl, kt) = match object(tok, op.key) {
        Ok(o) => o,
        Err(rv) => return op.end(rv).into(),
    };
    if out_len.is_null() || (data.is_null() && n != 0) {
        return op.end(ARGUMENTS_BAD).into();
    }
    if n > MAX_INPUT {
        return op.end(DATA_LEN_RANGE).into();
    }
    // SAFETY: readable for n bytes (caller), n bounded above
    let data = unsafe { bytes(data, n as usize) };
    // SAFETY: out writable for *out_len bytes unless NULL (caller)
    unsafe { encrypt(h, &mut op, kv, cl, kt, data, out, out_len) }.into()
}

/// C_Encrypt's mechanism paths (`:9800-10163`).
///
/// # Safety
/// As C_Encrypt's: `out` NULL or writable for `*out_len` bytes, `out_len` a CK_ULONG.
#[allow(clippy::too_many_arguments)]
unsafe fn encrypt(h: c_ulong, op: &mut Op, kv: &[u8], cl: u32, kt: u32, data: &[u8], out: *mut u8, out_len: *mut c_ulong) -> u32 {
    let n = data.len();
    match op.mech {
        OAEP | RSA_PKCS | RSA_X_509 => {
            let oaep = op.mech == OAEP;
            if !oaep && strict() {
                return op.end(MECHANISM_INVALID);
            }
            if cl != CKO_PUBLIC_KEY || kt != CKK_RSA {
                return op.end(KEY_TYPE_INCONSISTENT);
            }
            let Some(k) = Pkey::public(kv) else {
                return op.end(FUNCTION_FAILED);
            };
            let mut x = or_end!(op, if oaep { oaep_ctx(op, &k, true) } else { raw_ctx(op, &k, true) });
            if oaep {
                let (size, hl) = (k.size(), x.oaep_md_size());
                if size <= 0 || hl <= 0 {
                    return op.end(FUNCTION_FAILED);
                }
                if size < 2 * hl + 2 || n > (size - 2 * hl - 2) as usize {
                    return op.end(DATA_LEN_RANGE);
                }
            }
            let mut need = 0;
            // SAFETY: a NULL output asks for the length
            if !unsafe { x.run(null_mut(), &mut need, data) } {
                return op.end(FUNCTION_FAILED);
            }
            // SAFETY: out_len a CK_ULONG (caller)
            if let Some(rv) = unsafe { sized(out, out_len, need as c_ulong) } {
                return rv;
            }
            let mut o = Secret::zeroed(need);
            // SAFETY: o holds need bytes
            if !unsafe { x.run(o.0.as_mut_ptr(), &mut need, data) } {
                return op.end(FUNCTION_FAILED);
            }
            o.0.truncate(need);
            // SAFETY: *out_len >= need (checked above)
            unsafe { emit(true, h, op, &o.0, out, out_len) }
        }
        KW | KWP => {
            if kt != CKK_AES {
                return op.end(KEY_TYPE_INCONSISTENT);
            }
            if !matches!(kv.len(), 16 | 24 | 32) {
                return op.end(WRAPPING_KEY_SIZE_RANGE);
            }
            let need = if op.mech == KW {
                if n < 16 || !n.is_multiple_of(8) {
                    return op.end(DATA_LEN_RANGE);
                }
                n + 8
            } else {
                if n == 0 {
                    return op.end(DATA_LEN_RANGE);
                }
                n.div_ceil(8) * 8 + 8
            };
            // SAFETY: out_len a CK_ULONG (caller)
            if let Some(rv) = unsafe { sized(out, out_len, need as c_ulong) } {
                return rv;
            }
            let mode = if op.mech == KW { "WRAP" } else { "WRAP-PAD" };
            let name = aes_name(mode, kv.len()).expect("checked length");
            let mut x = or_end!(op, keyed(true, name, kv, op.iv(), true));
            match run(true, &mut x, data, need) {
                // SAFETY: *out_len >= need, the wrap's length (sized)
                Some(o) => unsafe { emit(true, h, op, &o.0, out, out_len) },
                None => op.end(FUNCTION_FAILED),
            }
        }
        ECB | CBC | CBC_PAD | CTR | DES3_CBC => {
            let mut x = or_end!(op, block_ctx(true, op, kv, kt));
            let need = n + if op.mech == CBC_PAD { 16 } else { 0 };
            // SAFETY: out_len a CK_ULONG (caller)
            if let Some(rv) = unsafe { sized(out, out_len, need as c_ulong) } {
                return rv;
            }
            match run(true, &mut x, data, need) {
                // SAFETY: *out_len >= need >= the bytes made (sized)
                Some(o) => unsafe { emit(true, h, op, &o.0, out, out_len) },
                None => op.end(FUNCTION_FAILED),
            }
        }
        CCM | GCM => {
            let gcm = op.mech == GCM;
            if kt != CKK_AES {
                return op.end(if gcm { MECHANISM_INVALID } else { KEY_TYPE_INCONSISTENT });
            }
            let tag = op.tag();
            // SAFETY: out_len a CK_ULONG (caller)
            if let Some(rv) = unsafe { sized(out, out_len, (n + tag) as c_ulong) } {
                return rv;
            }
            // GCM's random IV is unreachable: Init requires an IV of 12 bytes or more.
            let Some(c) = aead(if gcm { Aead::Gcm } else { Aead::Ccm }, kv.len()) else {
                return op.end(KEY_SIZE_RANGE);
            };
            let mut x = or_end!(op, Cipher::new());
            let mut o = Secret::zeroed(n + tag + 16);
            let Some(len) = aead_seal(gcm, &mut x, c, op, kv, data, &mut o.0) else {
                return fail_recorded(true, h, op, FUNCTION_FAILED, FUNCTION_FAILED);
            };
            o.0.truncate(len);
            // SAFETY: *out_len >= n + tag == len (sized)
            unsafe { emit(true, h, op, &o.0, out, out_len) }
        }
        _ => op.end(MECHANISM_INVALID),
    }
}

/// C's GCM and CCM encryption sequences (`:10074-10101`, `:10133-10155`) into `o`, which has
/// room for the input, a block and the tag; the length made.
#[allow(clippy::too_many_arguments)]
fn aead_seal(gcm: bool, x: &mut Cipher, c: AeadCipher, op: &Op, kv: &[u8], data: &[u8], o: &mut [u8]) -> Option<usize> {
    let (n, tag, iv) = (data.len(), op.tag(), &op.gcm_iv[..]);
    let p = o.as_mut_ptr();
    x.init(true, Some(c), None, None).then_some(())?;
    if gcm {
        (iv.len() == 12 || x.set_iv_len(iv.len())).then_some(())?;
    } else {
        x.set_iv_len(iv.len()).then_some(())?;
        x.set_tag(tag, None).then_some(())?;
    }
    x.init(true, None, Some(kv), Some(iv)).then_some(())?;
    // SAFETY: o has room for n + a block + tag; data and the AAD readable; lengths bounded
    let made = unsafe {
        if !gcm {
            x.update(true, null_mut(), null(), n)?;
        }
        if !op.aad.0.is_empty() {
            x.update(true, null_mut(), op.aad.0.as_ptr(), op.aad.0.len())?;
        }
        let a = x.update(true, p, data.as_ptr(), n)?;
        a + x.finish(true, p.add(a))?
    };
    x.get_tag(&mut o[made..made + tag]).then_some(made + tag)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_Decrypt(h: c_ulong, enc: *const u8, n: c_ulong, out: *mut u8, out_len: *mut c_ulong) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(mut op) = active_slot(false, h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    if let Err(rv) = op.ctx_auth() {
        return rv.into();
    }
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    if out_len.is_null() || (enc.is_null() && n != 0) {
        return op.end(ARGUMENTS_BAD).into();
    }
    if n > MAX_INPUT {
        return op.end(DATA_LEN_RANGE).into();
    }
    let (kv, cl, kt) = match object(tok, op.key) {
        Ok(o) => o,
        Err(rv) => return op.end(rv).into(),
    };
    // SAFETY: readable for n bytes (caller), n bounded above
    let enc = unsafe { bytes(enc, n as usize) };
    // SAFETY: out writable for *out_len bytes unless NULL (caller)
    unsafe { decrypt(h, &mut op, kv, cl, kt, enc, out, out_len) }.into()
}

/// `rsa_decrypt_sized`'s decryption: the plaintext, at most `max` bytes, or
/// ENCRYPTED_DATA_INVALID.
fn rsa_decrypt(x: &mut PkeyCtx, max: usize, enc: &[u8]) -> Result<Secret, u32> {
    if max == 0 {
        return Err(ENCRYPTED_DATA_INVALID);
    }
    let mut o = Secret::zeroed(max);
    let mut got = max;
    // SAFETY: o holds max bytes
    if !unsafe { x.run(o.0.as_mut_ptr(), &mut got, enc) } || got > max {
        return Err(ENCRYPTED_DATA_INVALID);
    }
    o.0.truncate(got);
    Ok(o)
}

/// A plaintext that may not fit: BUFFER_TOO_SMALL with its length, the operation kept for the
/// retry, or the output.
///
/// # Safety
/// `out` writable for `*out_len` bytes; `out_len` a CK_ULONG.
unsafe fn emit_or_retry(h: c_ulong, op: &mut Op, o: &Secret, out: *mut u8, out_len: *mut c_ulong) -> u32 {
    // SAFETY: the caller's
    unsafe {
        if (*out_len as usize) < o.0.len() {
            *out_len = o.0.len() as c_ulong;
            return BUFFER_TOO_SMALL;
        }
        emit(false, h, op, &o.0, out, out_len)
    }
}

/// C_Decrypt's mechanism paths (`:10248-10685`).
///
/// # Safety
/// As C_Decrypt's: `out` NULL or writable for `*out_len` bytes, `out_len` a CK_ULONG.
#[allow(clippy::too_many_arguments)]
unsafe fn decrypt(h: c_ulong, op: &mut Op, kv: &[u8], cl: u32, kt: u32, enc: &[u8], out: *mut u8, out_len: *mut c_ulong) -> u32 {
    let n = enc.len();
    match op.mech {
        OAEP | RSA_PKCS | RSA_X_509 => {
            let oaep = op.mech == OAEP;
            if !oaep && strict() {
                return op.end(MECHANISM_INVALID);
            }
            if cl != CKO_PRIVATE_KEY || kt != CKK_RSA {
                return op.end(KEY_TYPE_INCONSISTENT);
            }
            let Some(k) = Pkey::private(kv) else {
                return op.end(FUNCTION_FAILED);
            };
            if !oaep {
                let size = k.size();
                if size <= 0 {
                    return op.end(FUNCTION_FAILED);
                }
                if n != size as usize {
                    return op.end(ENCRYPTED_DATA_LEN_RANGE);
                }
            }
            let mut x = or_end!(op, if oaep { oaep_ctx(op, &k, false) } else { raw_ctx(op, &k, false) });
            let mut max = 0;
            // SAFETY: a NULL output asks for the length
            if !unsafe { x.run(null_mut(), &mut max, enc) } {
                return op.end(if oaep { FUNCTION_FAILED } else { ENCRYPTED_DATA_INVALID });
            }
            if out.is_null() {
                // SAFETY: out_len a CK_ULONG (caller); the size query keeps the operation
                unsafe { *out_len = max as c_ulong };
                return OK;
            }
            match rsa_decrypt(&mut x, max, enc) {
                // SAFETY: the caller's
                Ok(o) => unsafe { emit_or_retry(h, op, &o, out, out_len) },
                Err(rv) if oaep => fail_recorded(false, h, op, rv, ENCRYPTED_DATA_INVALID),
                Err(rv) => op.end(rv),
            }
        }
        KW | KWP => {
            if kt != CKK_AES {
                return op.end(KEY_TYPE_INCONSISTENT);
            }
            if !matches!(kv.len(), 16 | 24 | 32) {
                return op.end(WRAPPING_KEY_SIZE_RANGE);
            }
            let min = if op.mech == KW { 24 } else { 16 };
            if n < min || !n.is_multiple_of(8) {
                return op.end(ENCRYPTED_DATA_LEN_RANGE);
            }
            let upper = n - 8;
            // SAFETY: out_len a CK_ULONG (caller)
            if let Some(rv) = unsafe { sized(out, out_len, upper as c_ulong) } {
                return rv;
            }
            if upper > KW_MAX {
                return op.end(ENCRYPTED_DATA_LEN_RANGE);
            }
            let mode = if op.mech == KW { "WRAP" } else { "WRAP-PAD" };
            let name = aes_name(mode, kv.len()).expect("checked length");
            let mut x = or_end!(op, keyed(false, name, kv, op.iv(), true));
            match run(false, &mut x, enc, upper) {
                // SAFETY: the caller's
                Some(o) => unsafe { emit_or_retry(h, op, &o, out, out_len) },
                None => fail_recorded(false, h, op, ENCRYPTED_DATA_INVALID, ENCRYPTED_DATA_INVALID),
            }
        }
        ECB | CBC | CBC_PAD | CTR | DES3_CBC => {
            let mut x = or_end!(op, block_ctx(false, op, kv, kt));
            // SAFETY: out_len a CK_ULONG (caller)
            if let Some(rv) = unsafe { sized(out, out_len, n as c_ulong) } {
                return rv;
            }
            match run(false, &mut x, enc, n) {
                // SAFETY: *out_len >= n >= the bytes made (sized)
                Some(o) => unsafe { emit(false, h, op, &o.0, out, out_len) },
                None => op.end(ENCRYPTED_DATA_INVALID),
            }
        }
        CCM | GCM => {
            let gcm = op.mech == GCM;
            if kt != CKK_AES {
                return op.end(if gcm { MECHANISM_INVALID } else { KEY_TYPE_INCONSISTENT });
            }
            let tag = op.tag();
            if n < tag {
                return op.end(ENCRYPTED_DATA_INVALID);
            }
            let ct = n - tag;
            // SAFETY: out_len a CK_ULONG (caller)
            if let Some(rv) = unsafe { sized(out, out_len, ct as c_ulong) } {
                return rv;
            }
            let Some(c) = aead(if gcm { Aead::Gcm } else { Aead::Ccm }, kv.len()) else {
                return op.end(KEY_SIZE_RANGE);
            };
            let mut x = or_end!(op, Cipher::new());
            let mut o = Secret::zeroed(ct + 16);
            match aead_open(gcm, &mut x, c, op, kv, enc, &mut o.0) {
                Ok(len) => {
                    o.0.truncate(len);
                    // SAFETY: *out_len >= ct >= len (sized)
                    unsafe { emit(false, h, op, &o.0, out, out_len) }
                }
                Err(rv) => {
                    if rv == ENCRYPTED_DATA_INVALID {
                        // C zeroised the caller's whole buffer after the partial plaintext.
                        // SAFETY: out non-NULL and writable for *out_len bytes (sized, caller)
                        unsafe { std::ptr::write_bytes(out, 0, *out_len as usize) };
                    }
                    fail_recorded(false, h, op, rv, rv)
                }
            }
        }
        _ => op.end(MECHANISM_INVALID),
    }
}

/// C's GCM and CCM decryption sequences (`:10582-10600`, `:10640-10676`) into `o`, which has
/// room for the ciphertext and a block: the length, FUNCTION_FAILED for a setup failure,
/// ENCRYPTED_DATA_INVALID when the tag does not match.
#[allow(clippy::too_many_arguments)]
fn aead_open(gcm: bool, x: &mut Cipher, c: AeadCipher, op: &Op, kv: &[u8], enc: &[u8], o: &mut [u8]) -> Result<usize, u32> {
    let tag = op.tag();
    let (body, t) = enc.split_at(enc.len() - tag);
    let (ct, iv, p) = (body.len(), &op.gcm_iv[..], o.as_mut_ptr());
    let ff = |ok: bool| if ok { Ok(()) } else { Err(FUNCTION_FAILED) };
    ff(x.init(false, Some(c), None, None))?;
    if gcm {
        ff(iv.len() == 12 || x.set_iv_len(iv.len()))?;
    } else {
        ff(x.set_iv_len(iv.len()))?;
        ff(x.set_tag(tag, Some(t)))?;
    }
    ff(x.init(false, None, Some(kv), Some(iv)))?;
    // SAFETY: o has room for ct + a block; enc and the AAD readable; lengths bounded
    unsafe {
        if !gcm {
            x.update(false, null_mut(), null(), ct).ok_or(FUNCTION_FAILED)?;
        }
        if !op.aad.0.is_empty() {
            x.update(false, null_mut(), op.aad.0.as_ptr(), op.aad.0.len()).ok_or(FUNCTION_FAILED)?;
        }
        let a = x.update(false, p, body.as_ptr(), ct);
        if !gcm {
            // CCM checks the tag in the update.
            return a.ok_or(ENCRYPTED_DATA_INVALID);
        }
        let a = a.ok_or(FUNCTION_FAILED)?;
        ff(x.set_tag(tag, Some(t)))?;
        Ok(a + x.finish(false, p.add(a)).ok_or(ENCRYPTED_DATA_INVALID)?)
    }
}

/// `op_cipher_kind`: 0 GCM, 1 CTR, 2 ECB or CBC, 3 CBC-PAD; `None` for the single-part only.
fn kind(m: c_ulong) -> Option<u8> {
    match m {
        GCM => Some(0),
        CTR => Some(1),
        ECB | CBC => Some(2),
        CBC_PAD => Some(3),
        _ => None,
    }
}

/// `ensure_cipher_ctx` (`:12683-12732`): the multipart context, made at the first use.
fn ensure_ctx(op: &mut Op, t: Tok, enc: bool) -> Result<(), u32> {
    if op.ctx.is_some() {
        return Ok(());
    }
    let (kv, _, kt) = object(t, op.key)?;
    if kt != CKK_AES {
        return Err(MECHANISM_INVALID);
    }
    let k = kind(op.mech).ok_or(MECHANISM_INVALID)?;
    let mode = match (op.mech, k) {
        (ECB, _) => "ECB",
        (_, 0) => "GCM",
        (_, 1) => "CTR",
        _ => "CBC",
    };
    let name = aes_name(mode, kv.len()).ok_or(KEY_SIZE_RANGE)?;
    let c = Fetched::new(name).ok_or(MECHANISM_INVALID)?;
    let mut x = Cipher::new()?;
    let ok = if k == 0 {
        let iv = &op.gcm_iv[..];
        let aad = &op.aad.0;
        x.init2(enc, Some(&c), None, None)
            && (iv.len() == 12 || x.set_iv_len(iv.len()))
            && x.init2(enc, None, Some(kv), Some(iv))
            // SAFETY: the AAD readable for its length
            && (aad.is_empty() || unsafe { x.update(enc, null_mut(), aad.as_ptr(), aad.len()) }.is_some())
    } else {
        let ok = x.init2(enc, Some(&c), Some(kv), if op.mech == ECB { None } else { op.iv() });
        if ok {
            x.set_padding(k == 3);
        }
        ok
    };
    if !ok {
        return Err(FUNCTION_FAILED);
    }
    op.ctx = Some(x);
    Ok(())
}

/// `C_EncryptUpdate` and `C_DecryptUpdate` (`:12734`, `:12888`).
///
/// # Safety
/// `inp` readable for `n` bytes; `out` NULL or writable for `*out_len` bytes; `out_len` NULL
/// or a CK_ULONG.
unsafe fn update(enc: bool, h: c_ulong, inp: *const u8, n: c_ulong, out: *mut u8, out_len: *mut c_ulong) -> u32 {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv;
    }
    let Some(mut op) = active_slot(enc, h) else {
        return OPERATION_NOT_INITIALIZED;
    };
    if !enc && let Err(rv) = op.ctx_auth() {
        return rv;
    }
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID;
    };
    if out_len.is_null() || (inp.is_null() && n != 0) {
        return op.end(ARGUMENTS_BAD);
    }
    if n > MAX_INPUT {
        return op.end(DATA_LEN_RANGE);
    }
    or_end!(op, ensure_ctx(&mut op, tok, enc));
    // SAFETY: readable for n bytes (caller), n bounded above
    let inp = unsafe { bytes(inp, n as usize) };
    let need = inp.len() + if matches!(kind(op.mech), Some(2 | 3)) { 16 } else { 0 };
    // SAFETY: out_len a CK_ULONG (caller)
    let room = unsafe { *out_len } as usize;
    if enc || out.is_null() {
        // SAFETY: as above
        if let Some(rv) = unsafe { sized(out, out_len, need as c_ulong) } {
            return rv;
        }
    } else if room < need {
        // decrypt_update_exact_len: what this update would write, from a copy of the context
        let x = op.ctx.as_ref().expect("made above");
        let exact = x.try_clone().and_then(|mut p| {
            let mut o = Secret::zeroed(need.max(1));
            // SAFETY: o has room for the input plus a block; inp readable
            unsafe { p.update(false, o.0.as_mut_ptr(), inp.as_ptr(), inp.len()) }.ok_or(FUNCTION_FAILED)
        });
        match exact {
            Ok(e) if room < e => {
                // SAFETY: as above; the operation stays for the retry
                unsafe { *out_len = e as c_ulong };
                return BUFFER_TOO_SMALL;
            }
            Ok(_) => {}
            Err(rv) => return op.end(rv),
        }
    }
    let x = op.ctx.as_mut().expect("made above");
    // SAFETY: out has room for what the update writes (need, or the exact length); inp readable
    match unsafe { x.update(enc, out, inp.as_ptr(), inp.len()) } {
        Some(l) => {
            // SAFETY: as above
            unsafe { *out_len = l as c_ulong };
            OK
        }
        None => op.end(FUNCTION_FAILED),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_EncryptUpdate(h: c_ulong, p: *const u8, n: c_ulong, out: *mut u8, out_len: *mut c_ulong) -> c_ulong {
    // SAFETY: the caller's
    unsafe { update(true, h, p, n, out, out_len) }.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_DecryptUpdate(h: c_ulong, p: *const u8, n: c_ulong, out: *mut u8, out_len: *mut c_ulong) -> c_ulong {
    // SAFETY: the caller's
    unsafe { update(false, h, p, n, out, out_len) }.into()
}

/// The multipart context for a Final that had no Update.
fn final_ctx(h: c_ulong, op: &mut Op, enc: bool) -> Result<(), u32> {
    if op.ctx.is_none() {
        let tok = TABLE.token(h).ok_or(SESSION_HANDLE_INVALID)?;
        ensure_ctx(op, tok, enc)?;
    }
    Ok(())
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_EncryptFinal(h: c_ulong, out: *mut u8, out_len: *mut c_ulong) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(mut op) = active_slot(true, h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    if out_len.is_null() {
        return ARGUMENTS_BAD.into();
    }
    let k = kind(op.mech);
    let tag = if k == Some(0) { op.tag() } else { 0 };
    let max = if k == Some(3) { 16 } else { tag };
    // SAFETY: out_len a CK_ULONG (caller)
    if let Some(rv) = unsafe { sized(out, out_len, max as c_ulong) } {
        return rv.into();
    }
    if let Err(rv) = final_ctx(h, &mut op, true) {
        return op.end(rv).into();
    }
    let mut x = op.ctx.take().expect("made above");
    op.active = false;
    // SAFETY: out has room for max bytes, the padded block or the tag (sized)
    let Some(l) = (unsafe { x.finish(true, out) }) else {
        return FUNCTION_FAILED.into();
    };
    if tag != 0 {
        // SAFETY: as above: GCM's final writes nothing, then the tag fills max bytes
        let t = unsafe { std::slice::from_raw_parts_mut(out.add(l), tag) };
        if !x.get_tag(t) {
            return FUNCTION_FAILED.into();
        }
    }
    // SAFETY: as above
    unsafe { *out_len = (l + tag) as c_ulong };
    OK.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_DecryptFinal(h: c_ulong, out: *mut u8, out_len: *mut c_ulong) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(mut op) = active_slot(false, h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    if let Err(rv) = op.ctx_auth() {
        return rv.into();
    }
    if out_len.is_null() {
        return ARGUMENTS_BAD.into();
    }
    if let Err(rv) = final_ctx(h, &mut op, false) {
        return op.end(rv).into();
    }
    let bound = if kind(op.mech) == Some(3) { 16 } else { 0 };
    if out.is_null() {
        // SAFETY: out_len a CK_ULONG (caller)
        unsafe { *out_len = bound as c_ulong };
        return OK.into();
    }
    // SAFETY: as above
    let room = unsafe { *out_len } as usize;
    if room < bound {
        // decrypt_final_exact_len, from a copy of the context
        let x = op.ctx.as_ref().expect("made above");
        let exact = x.try_clone().and_then(|mut p| {
            let mut o = Secret::zeroed(bound);
            // SAFETY: o holds a block
            unsafe { p.finish(false, o.0.as_mut_ptr()) }.ok_or(ENCRYPTED_DATA_INVALID)
        });
        match exact {
            Err(ENCRYPTED_DATA_INVALID) => {
                op.ctx = None;
                // SAFETY: as above
                unsafe { *out_len = 0 };
                return op.end(ENCRYPTED_DATA_INVALID).into();
            }
            Err(rv) => return op.end(rv).into(),
            Ok(e) if room < e => {
                // SAFETY: as above; the operation and its context stay for the retry
                unsafe { *out_len = e as c_ulong };
                return BUFFER_TOO_SMALL.into();
            }
            Ok(_) => {}
        }
    }
    let mut x = op.ctx.take().expect("made above");
    op.active = false;
    // SAFETY: out has room for what the final writes: bound, or the exact length
    let r = unsafe { x.finish(false, out) };
    // SAFETY: as above
    unsafe { *out_len = r.unwrap_or(0) as c_ulong };
    if r.is_some() { OK } else { ENCRYPTED_DATA_INVALID }.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::c_void;

    fn parse(mech: c_ulong, p: &[u8]) -> Result<Op, u32> {
        let m = Mech {
            mechanism: mech,
            param: if p.is_empty() { null_mut() } else { p.as_ptr().cast_mut().cast::<c_void>() },
            param_len: p.len() as c_ulong,
        };
        let mut op = Op::IDLE;
        // SAFETY: p and every pointer in it alive for the call
        unsafe { params(&m, &mut op) }.map(|()| op)
    }

    fn block(v: &[c_ulong]) -> Vec<u8> {
        v.iter().flat_map(|x| x.to_ne_bytes()).collect()
    }

    #[test]
    fn gcm_parameters_take_c_s_shapes_and_bounds() {
        let iv = [9u8; 16];
        let aad = [1u8; 3];
        let (ivp, aadp) = (iv.as_ptr() as c_ulong, aad.as_ptr() as c_ulong);
        let op = parse(GCM, &block(&[ivp, 16, 128, aadp, 3, 0])).unwrap();
        assert_eq!((op.gcm_iv.len(), &op.aad.0[..], op.tag_len), (16, &aad[..], 16));
        assert_eq!(parse(GCM, &block(&[ivp, 12, 0, aadp, 3, 96])).unwrap().tag_len, 12);
        let bad = |v: &[c_ulong]| parse(GCM, &block(v)).err();
        assert_eq!(bad(&[ivp, 8, 0, 0, 0, 128]), Some(MECHANISM_PARAM_INVALID));
        assert_eq!(bad(&[ivp, 12, 0, 0, 3, 128]), Some(MECHANISM_PARAM_INVALID));
        assert_eq!(bad(&[ivp, 12, 0, 0, 0, 100]), Some(ARGUMENTS_BAD));
        assert_eq!(bad(&[ivp, 513, 0, 0, 0, 128]), Some(ARGUMENTS_BAD));
        // a shorter block is a bare IV, its first 12 bytes
        assert_eq!(parse(GCM, &iv[..12]).unwrap().gcm_iv, iv[..12].to_vec());
        assert_eq!(parse(GCM, &iv[..11]).err(), Some(MECHANISM_PARAM_INVALID));
        assert_eq!(parse(GCM, &[]).err(), Some(MECHANISM_PARAM_INVALID));
    }

    #[test]
    fn ctr_ccm_cbc_kw_and_oaep_parameters_follow_c() {
        let mut ctr = block(&[64]);
        ctr.extend([7u8; 16]);
        assert_eq!(parse(CTR, &ctr).unwrap().iv, Some([7u8; 16]));
        assert!(parse(CTR, &[3u8; 16]).is_ok());
        for bits in [0, 129] {
            let mut c = block(&[bits]);
            c.extend([7u8; 16]);
            assert_eq!(parse(CTR, &c).err(), Some(MECHANISM_PARAM_INVALID));
        }
        assert_eq!(parse(CTR, &[3u8; 10]).err(), Some(MECHANISM_PARAM_INVALID));
        let nonce = [5u8; 13];
        let np = nonce.as_ptr() as c_ulong;
        assert_eq!(parse(CCM, &block(&[0, np, 13, 0, 0, 4])).unwrap().tag_len, 4);
        for (len, mac) in [(6, 16), (14, 16), (12, 5), (12, 18)] {
            assert_eq!(parse(CCM, &block(&[0, np, len, 0, 0, mac])).err(), Some(MECHANISM_PARAM_INVALID));
        }
        assert_eq!(parse(CBC, &[1u8; 8]).err(), Some(MECHANISM_PARAM_INVALID));
        assert!(parse(CBC_PAD, &[1u8; 16]).is_ok());
        assert!(parse(KW, &[]).unwrap().iv.is_none());
        assert_eq!(parse(KW, &[1u8; 4]).err(), Some(MECHANISM_PARAM_INVALID));
        assert!(parse(KWP, &[1u8; 4]).unwrap().iv.is_some());
        let label = [8u8; 65];
        let lp = label.as_ptr() as c_ulong;
        assert_eq!(parse(OAEP, &block(&[0x250, 2, 1, lp, 20])).unwrap().label.0, label[..20].to_vec());
        assert!(parse(OAEP, &block(&[0x250, 2, 0, lp, 20])).unwrap().label.0.is_empty());
        for p in [[0x250, 2, 1, lp, 65], [0x210, 2, 1, 0, 0], [0x250, 0x77, 1, 0, 0], [0x250, 2, 1, 0, 20]] {
            assert_eq!(parse(OAEP, &block(&p)).err(), Some(MECHANISM_PARAM_INVALID));
        }
    }
}
