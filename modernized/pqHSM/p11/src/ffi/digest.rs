//! Phase 4 slice 3: `C_DigestInit`, `C_Digest`, `C_DigestUpdate`, `C_DigestKey` and
//! `C_DigestFinal` (`src/fhsm_pkcs11.c:2644-2735, 11932-12067`), in C's check order. The digest
//! operation table (C's `g_op_dig`) is this module's; DIV-053's refusal is `gate`, under the
//! API lock.

use std::ffi::{c_int, c_ulong, c_void};
use std::sync::{Mutex, MutexGuard};

use pqhsm_core::session::MAX;
use pqhsm_crypto::prim::{Hasher, hash_size, md_available};

use super::apilock::Held;
use super::attrs::OBJF_SENSITIVE;
use super::objects::{CKO_SECRET_KEY, access_denied, class_of, gate};
use super::session::TABLE;
use super::sys::*;

const MECHANISM_INVALID: u32 = 0x70;
const MECHANISM_PARAM_INVALID: u32 = 0x71;
const KEY_INDIGESTIBLE: u32 = 0x67;
const DATA_LEN_RANGE: u32 = 0x21;
/// C's 2 GiB ceiling on one call's input (#125 isize).
const MAX_INPUT: c_ulong = 0x7FFF_FFFF;

/// `CK_MECHANISM`.
#[repr(C)]
pub struct Mech {
    pub mechanism: c_ulong,
    pub param: *mut c_void,
    pub param_len: c_ulong,
}

/// `digest_mech_to_hash` (`:2644-2665`): the `fhsm_hash_t` and whether the strict build
/// withdraws it as a standalone digest (SHA-1 and MD5).
pub(super) fn hash_of(mech: c_ulong) -> Option<(u32, bool)> {
    Some(match mech {
        0x250 => (1, false),  // SHA256
        0x260 => (2, false),  // SHA384
        0x270 => (3, false),  // SHA512
        0x255 => (9, false),  // SHA224
        0x48 => (10, false),  // SHA512_224
        0x4C => (11, false),  // SHA512_256
        0x2B5 => (12, false), // SHA3_224
        0x2B0 => (4, false),  // SHA3_256
        0x2C0 => (5, false),  // SHA3_384
        0x2D0 => (6, false),  // SHA3_512
        0x220 => (7, true),   // SHA_1
        0x210 => (8, true),   // MD5
        _ => return None,
    })
}

/// One session's digest operation (C's `fhsm_op_t`, the fields a digest uses).
struct Dig {
    active: bool,
    alg: u32,
    mech: u32,
    /// The multipart context. Like C's `md_ctx` it outlives an operation that `C_Digest` ended
    /// on an error, until the next `C_DigestInit` or the session's reset releases it.
    ctx: Option<Hasher>,
}

impl Dig {
    const IDLE: Dig = Dig {
        active: false,
        alg: 0,
        mech: 0,
        ctx: None,
    };

    /// `digest_update_fail`: the error ends the operation and releases its context.
    fn fail(&mut self, rv: u32) -> u32 {
        self.ctx = None;
        self.active = false;
        rv
    }

    /// Feed the context, made on first use. A failure to make it ends the operation; a failed
    /// update does when `ends` (C_DigestUpdate), not otherwise (C_DigestKey), as in C.
    fn feed(&mut self, part: &[u8], ends: bool) -> u32 {
        if self.ctx.is_none() {
            match Hasher::new(self.alg) {
                Ok(c) => self.ctx = Some(c),
                Err(rv) => return self.fail(rv),
            }
        }
        match self.ctx.as_mut().map(|c| c.update(part)) {
            Some(Ok(())) => OK,
            _ if ends => self.fail(FUNCTION_FAILED),
            _ => FUNCTION_FAILED,
        }
    }
}

/// One slot per session handle, as C's table; handle 0 and those past the table have none.
/// shortcut: a fork while another thread is inside a digest call (up to 2 GiB of hashing) makes
/// the child's C_Initialize deadlock in `forget_all` (review M1); fix first in the M3 atfork
/// work: a prepare handler takes every slot in order, parent and child handlers release them.
static DIGESTS: [Mutex<Dig>; MAX] = [const { Mutex::new(Dig::IDLE) }; MAX];

/// `op_slot(g_op_dig, h)`.
fn slot(h: c_ulong) -> Option<MutexGuard<'static, Dig>> {
    if h == 0 || h as usize >= MAX {
        return None;
    }
    Some(
        DIGESTS[h as usize]
            .lock()
            .unwrap_or_else(|p| p.into_inner()),
    )
}

/// `slot`, if a digest is active in it.
fn active_slot(h: c_ulong) -> Option<MutexGuard<'static, Dig>> {
    slot(h).filter(|d| d.active)
}

/// This session's digest, freed (`fhsm_session_ops_reset`'s digest part).
pub(super) fn reset(h: c_ulong) {
    if let Some(mut d) = slot(h) {
        *d = Dig::IDLE;
    }
}

/// Is a digest active in this session (`fhsm_session_has_active_op`'s digest part)?
pub(super) fn active(h: c_ulong) -> bool {
    active_slot(h).is_some()
}

/// At finalize: every session's digest freed.
pub(super) fn release_all() {
    (1..MAX as c_ulong).for_each(reset);
}

/// After a fork: every digest forgotten, its context not freed (the parent's).
pub(super) fn forget_all() {
    for s in &DIGESTS[1..] {
        let mut d = s.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = d.ctx.take() {
            c.forget();
        }
        *d = Dig::IDLE;
    }
}

/// The caller's `n` bytes at `p`; empty for a zero length, whatever `p` is.
///
/// # Safety
/// `p` is readable for `n` bytes when `n` is not zero.
pub(super) unsafe fn bytes<'a>(p: *const u8, n: usize) -> &'a [u8] {
    if n == 0 {
        &[]
    } else {
        // SAFETY: the caller's
        unsafe { std::slice::from_raw_parts(p, n) }
    }
}

/// C's length query and short-buffer answer: `Some(rv)` when the call stops there.
///
/// # Safety
/// `out_len` points to a CK_ULONG.
pub(super) unsafe fn sized(out: *mut u8, out_len: *mut c_ulong, need: c_ulong) -> Option<u32> {
    // SAFETY: the caller's
    if !out.is_null() && unsafe { *out_len } >= need {
        return None;
    }
    // SAFETY: as above
    unsafe { *out_len = need };
    Some(if out.is_null() { OK } else { BUFFER_TOO_SMALL })
}

/// `fhsm_hash_oneshot` into the caller's buffer, which holds `*out_len >= hash_size` bytes.
///
/// # Safety
/// `data` readable for its length; `out` writable for `*out_len` bytes.
unsafe fn oneshot(alg: u32, data: Slice, out: *mut u8, out_len: *mut c_ulong) -> u32 {
    // SAFETY: the caller's
    let mut n = unsafe { *out_len } as usize;
    // SAFETY: as above
    let rv = unsafe { fhsm_hash_oneshot(alg as c_int, data, out, &mut n) };
    // SAFETY: as above
    unsafe { *out_len = n as c_ulong };
    rv
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_DigestInit(h: c_ulong, m: *const Mech) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if TABLE.token(h).is_none() {
        return SESSION_HANDLE_INVALID.into();
    }
    if m.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // SAFETY: non-NULL, and by the caller's contract a CK_MECHANISM
    let m = unsafe { &*m };
    let Some(mut d) = slot(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    if d.active {
        return OPERATION_ACTIVE.into();
    }
    // Digest mechanisms take no parameter.
    if !m.param.is_null() || m.param_len != 0 {
        return MECHANISM_PARAM_INVALID.into();
    }
    let Some((alg, withdrawn)) = hash_of(m.mechanism) else {
        return MECHANISM_INVALID.into();
    };
    if withdrawn && fhsm_build_fips_strict != 0 {
        return MECHANISM_INVALID.into();
    }
    // Refused here, as it is left out of the mechanism list, when no loaded provider has it.
    if !md_available(alg) {
        return MECHANISM_INVALID.into();
    }
    *d = Dig {
        active: true,
        alg,
        mech: m.mechanism as u32,
        ctx: None,
    };
    OK.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_Digest(
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
    if out_len.is_null() {
        return ARGUMENTS_BAD.into();
    }
    let Some(mut d) = active_slot(h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    // These errors end the operation; C keeps its context until the next init, and so does this.
    if n > MAX_INPUT {
        d.active = false;
        return DATA_LEN_RANGE.into();
    }
    if data.is_null() && n != 0 {
        d.active = false;
        return ARGUMENTS_BAD.into();
    }
    // SAFETY: out_len non-NULL, a CK_ULONG (caller)
    if let Some(rv) = unsafe { sized(out, out_len, hash_size(d.alg) as c_ulong) } {
        return rv.into();
    }
    let data = Slice {
        data,
        len: n as usize,
    };
    // SAFETY: data readable for n bytes and out writable for *out_len (caller)
    let rv = unsafe { oneshot(d.alg, data, out, out_len) };
    d.active = false;
    rv.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_DigestUpdate(h: c_ulong, p: *const u8, n: c_ulong) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(mut d) = active_slot(h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    if n > MAX_INPUT {
        return d.fail(DATA_LEN_RANGE).into();
    }
    if p.is_null() && n != 0 {
        return d.fail(ARGUMENTS_BAD).into();
    }
    // SAFETY: readable for n bytes (caller), n bounded above
    d.feed(unsafe { bytes(p, n as usize) }, true).into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_DigestKey(h: c_ulong, key: c_ulong) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(mut d) = active_slot(h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    let Some(tok) = TABLE.token(h) else {
        return SESSION_HANDLE_INVALID.into();
    };
    // C's narrowing: the token's handles are 32-bit.
    let (t, k) = (tok.0.as_ptr(), key as u32);
    // DIV-050: a secret or private key is the user's alone; before anything reads it (C let the
    // SO digest the user's keys). An object whose lookup fails goes on to C's checks.
    if class_of(tok, k).is_ok_and(|c| access_denied(tok, c)) {
        return KEY_HANDLE_INVALID.into();
    }
    // Digesting a key's value is a use of it, so its allowed mechanisms apply.
    // SAFETY: a token the registry holds
    let rv = unsafe { fhsm_token_object_mech_allowed(t, k, d.mech) };
    if rv != OK {
        return rv.into();
    }
    // A sensitive key's value never enters the digest.
    let mut f = 0u8;
    // SAFETY: as above; an out byte of our own
    if unsafe { fhsm_token_object_get_flags(t, k, &mut f) } == OK && f & OBJF_SENSITIVE != 0 {
        return KEY_INDIGESTIBLE.into();
    }
    let (mut v, mut vl, mut class, mut kt) = (std::ptr::null(), 0usize, 0u32, 0u32);
    // SAFETY: as above; out pointers of our own
    let rv = unsafe { fhsm_token_object_get(t, k, &mut v, &mut vl, &mut class, &mut kt) };
    if rv != OK {
        return rv.into();
    }
    // Only secret keys: a private key's digest would leak it.
    if class != CKO_SECRET_KEY {
        return KEY_INDIGESTIBLE.into();
    }
    // SAFETY: the token's value of vl bytes. Alive for this call: whatever frees a value runs
    // under the EXCLUSIVE lock, or is parked by apilock.rs until no call is in flight
    d.feed(unsafe { bytes(v, vl) }, false).into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_DigestFinal(
    h: c_ulong,
    out: *mut u8,
    out_len: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    let Some(mut d) = active_slot(h) else {
        return OPERATION_NOT_INITIALIZED.into();
    };
    if out_len.is_null() {
        return ARGUMENTS_BAD.into();
    }
    let need = hash_size(d.alg);
    // SAFETY: out_len non-NULL, a CK_ULONG (caller)
    if let Some(rv) = unsafe { sized(out, out_len, need as c_ulong) } {
        return rv.into();
    }
    d.active = false;
    match d.ctx.take() {
        // Final without any update is the digest of the empty input.
        None => {
            let empty = Slice {
                data: c"".as_ptr().cast(),
                len: 0,
            };
            // SAFETY: out writable for *out_len bytes (caller)
            unsafe { oneshot(d.alg, empty, out, out_len) }
        }
        Some(c) => {
            // SAFETY: out writable for *out_len >= need bytes (caller, sized)
            let o = unsafe { std::slice::from_raw_parts_mut(out, need) };
            match c.finish(o) {
                Ok(n) => {
                    // SAFETY: as above
                    unsafe { *out_len = n as c_ulong };
                    OK
                }
                Err(_) => FUNCTION_FAILED,
            }
        }
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_digest_mechanism_names_a_hash_of_its_size() {
        let sizes = [
            (0x250, 32),
            (0x260, 48),
            (0x270, 64),
            (0x255, 28),
            (0x48, 28),
            (0x4C, 32),
            (0x2B5, 28),
            (0x2B0, 32),
            (0x2C0, 48),
            (0x2D0, 64),
            (0x220, 20),
            (0x210, 16),
        ];
        for (m, size) in sizes {
            let (alg, _) = hash_of(m).unwrap();
            assert_eq!(hash_size(alg), size, "{m:#x}");
        }
        assert_eq!(hash_of(0x220).map(|h| h.1), Some(true));
        assert_eq!(hash_of(0x210).map(|h| h.1), Some(true));
        assert!(hash_of(0x251).is_none() && hash_of(0x1).is_none());
    }

    #[test]
    fn a_hasher_in_parts_equals_the_one_shot() {
        let mut c = Hasher::new(1).unwrap();
        c.update(b"ab").unwrap();
        c.update(b"").unwrap();
        c.update(b"c").unwrap();
        let mut o = [0u8; 32];
        assert_eq!(c.finish(&mut o), Ok(32));
        let mut w = [0u8; 32];
        assert_eq!(pqhsm_crypto::prim::digest(1, b"abc", &mut w), Ok(32));
        assert_eq!(o, w);
    }
}
