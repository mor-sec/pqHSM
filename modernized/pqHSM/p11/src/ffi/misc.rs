//! Phase 4 slice 8a: `C_GetMechanismList` and `C_GetMechanismInfo` over `pqhsm_core::mechs`,
//! `C_GenerateRandom`, `C_SeedRandom`, and the stubs `C_WaitForSlotEvent`,
//! `C_GetFunctionStatus` and `C_CancelFunction` (`src/fhsm_pkcs11.c:573-658, 1455-1653,
//! 2589-2596`), in C's order.
//!
//! Divergences, as the shim applied them before the C ran: DIV-051 (0x190 outside an
//! initialised process), DIV-053 (in ERROR every one but the two mechanism calls is 0x6), and
//! RULE-014 (in the strict build CKM_GENERIC_SECRET_KEY_GEN advertises 14 bytes at least).

use std::ffi::{c_ulong, c_void};

use pqhsm_core::mechs::{self, Mech};
use pqhsm_core::p11::MAX_SLOTS;
use pqhsm_crypto::keygen::ecm_available;
use pqhsm_crypto::prim::md_available;

use super::apilock::Held;
use super::crypt::strict;
use super::digest::hash_of;
use super::lifecycle::initialized;
use super::objects::gate;
use super::session::TABLE;
use super::sys::*;

const NO_EVENT: u32 = 0x8;
const FUNCTION_NOT_PARALLEL: u32 = 0x51;
const FUNCTION_NOT_SUPPORTED: u32 = 0x54;
const MECHANISM_INVALID: u32 = 0x70;
const RANDOM_SEED_NOT_SUPPORTED: u32 = 0x120;
const CKF_DONT_BLOCK: c_ulong = 0x1;
const CKM_GENERIC_SECRET_KEY_GEN: c_ulong = 0x350;

unsafe extern "C" {
    fn fhsm_rng_bytes(out: *mut u8, n: usize) -> u32;
}

/// `fhsm_mech_advertised`: dispatchable in this build, and operational in this process (the
/// providers serve X25519 and X448 for the ECM family, and the digest a digest names).
fn advertised(m: &Mech) -> bool {
    m.dispatchable(strict())
        && (m.family != "ECM" || ecm_available())
        && (m.op != "digest" || hash_of(m.ckm.into()).is_none_or(|(a, _)| md_available(a)))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_GetMechanismList(
    slot: c_ulong,
    list: *mut c_ulong,
    count: *mut c_ulong,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = initialized() {
        return rv.into();
    }
    if slot >= MAX_SLOTS {
        return SLOT_ID_INVALID.into();
    }
    if count.is_null() {
        return ARGUMENTS_BAD.into();
    }
    let ms: Vec<c_ulong> = mechs::all()
        .iter()
        .filter(|m| advertised(m))
        .map(|m| m.ckm.into())
        .collect();
    let n = ms.len() as c_ulong;
    // SAFETY: count non-NULL and writable (the caller's); list, when non-NULL, holds *count
    // entries, and only n <= *count are written
    unsafe {
        if !list.is_null() {
            if *count < n {
                *count = n;
                return BUFFER_TOO_SMALL.into();
            }
            std::ptr::copy_nonoverlapping(ms.as_ptr(), list, ms.len());
        }
        *count = n;
    }
    OK.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_GetMechanismInfo(
    slot: c_ulong,
    ty: c_ulong,
    info: *mut c_void,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = initialized() {
        return rv.into();
    }
    if slot >= MAX_SLOTS {
        return SLOT_ID_INVALID.into();
    }
    if info.is_null() {
        return ARGUMENTS_BAD.into();
    }
    // C looked the type up narrowed to 32 bits.
    let Some(m) = mechs::lookup(ty as u32).filter(|m| advertised(m)) else {
        return MECHANISM_INVALID.into();
    };
    let (mut min, max) = m.key_sizes();
    // RULE-014: what the strict build's key generation makes (HMAC and KMAC keep the 1).
    if ty == CKM_GENERIC_SECRET_KEY_GEN && strict() {
        min = 14;
    }
    // SAFETY: non-NULL, and by the caller's contract a CK_MECHANISM_INFO: three CK_ULONGs
    unsafe { info.cast::<[c_ulong; 3]>().write([min, max, m.flags()]) };
    OK.into()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn pqhsm_C_GenerateRandom(h: c_ulong, out: *mut u8, n: c_ulong) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if TABLE.token(h).is_none() {
        return SESSION_HANDLE_INVALID.into();
    }
    if out.is_null() || n == 0 {
        return ARGUMENTS_BAD.into();
    }
    // SAFETY: out writable for n bytes (the caller's)
    unsafe { fhsm_rng_bytes(out, n as usize) }.into()
}

#[unsafe(no_mangle)]
pub extern "C" fn pqhsm_C_SeedRandom(h: c_ulong, seed: *const u8, n: c_ulong) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if TABLE.token(h).is_none() {
        return SESSION_HANDLE_INVALID.into();
    }
    if seed.is_null() || n == 0 {
        return ARGUMENTS_BAD.into();
    }
    RANDOM_SEED_NOT_SUPPORTED.into()
}

/// A software token: no slot events, and a blocking wait is refused.
#[unsafe(no_mangle)]
pub extern "C" fn pqhsm_C_WaitForSlotEvent(
    flags: c_ulong,
    _slot: *mut c_ulong,
    reserved: *mut c_void,
) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if !reserved.is_null() {
        return ARGUMENTS_BAD.into();
    }
    if flags & CKF_DONT_BLOCK != 0 {
        return NO_EVENT.into();
    }
    FUNCTION_NOT_SUPPORTED.into()
}

#[unsafe(no_mangle)]
pub extern "C" fn pqhsm_C_GetFunctionStatus(h: c_ulong) -> c_ulong {
    not_parallel(h)
}

#[unsafe(no_mangle)]
pub extern "C" fn pqhsm_C_CancelFunction(h: c_ulong) -> c_ulong {
    not_parallel(h)
}

/// The legacy parallel-function calls: a valid session is CKR_FUNCTION_NOT_PARALLEL.
fn not_parallel(h: c_ulong) -> c_ulong {
    let _g = Held::shared();
    if let Err(rv) = gate() {
        return rv.into();
    }
    if TABLE.token(h).is_none() {
        return SESSION_HANDLE_INVALID.into();
    }
    FUNCTION_NOT_PARALLEL.into()
}
