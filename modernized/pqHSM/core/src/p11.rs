//! The pure parts of the lifecycle, slot and login entry points (`src/fhsm_pkcs11.c:353-1789`,
//! Phase 4 slice 1d): field packing, the PIN and label rules, and the session state. The calls
//! themselves are in `pqhsm-p11`'s `ffi`.

use std::ffi::{c_int, c_ulong};

use crate::session::{ROLE_SO, RW_SESSION};

/// `FHSM_PIN_MIN_LEN` and `FHSM_PIN_MAX_LEN` (`include/fhsm_common.h:388-391`).
pub const PIN_MIN_LEN: c_ulong = 4;
pub const PIN_MAX_LEN: c_ulong = 64;
pub const ROLE_USER: c_int = 2;
/// `FHSM_VERSION_MAJOR`, `FHSM_VERSION_MINOR`: the library and firmware version.
pub const VERSION: [u8; 2] = [2, 6];
/// `FHSM_MAX_SLOTS`.
pub const MAX_SLOTS: c_ulong = 4;

/// `fhsm_pack_field`: `src` then ASCII spaces, cut at the field width, never NUL-terminated.
pub fn pack_field(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    dst[n..].fill(b' ');
}

/// Whether a new or old PIN's length is in C's range.
pub fn pin_len_ok(len: c_ulong) -> bool {
    (PIN_MIN_LEN..=PIN_MAX_LEN).contains(&len)
}

/// `C_InitToken`'s label: the 32 bytes as a C string, trailing spaces cut. An embedded NUL
/// still ends the string where the token reads it, as in C.
pub fn label(field: &[u8; 32]) -> [u8; 33] {
    let mut l = [0u8; 33];
    l[..32].copy_from_slice(field);
    for b in l[..32].iter_mut().rev() {
        if *b != b' ' {
            break;
        }
        *b = 0;
    }
    l
}

/// `CK_USER_TYPE` to the role `fhsm_session_login` takes; `None` for anything but CKU_SO and
/// CKU_USER (CKU_CONTEXT_SPECIFIC is handled before).
pub fn role_of(user_type: c_ulong) -> Option<c_int> {
    match user_type {
        0 => Some(ROLE_SO),
        1 => Some(ROLE_USER),
        _ => None,
    }
}

/// `CK_SESSION_INFO.state` from the session's flags and the token's role (PKCS#11 §6.6.2).
pub fn session_state(role: c_int, flags: c_ulong) -> c_ulong {
    let rw = flags & RW_SESSION != 0;
    match role {
        ROLE_SO => 4,
        ROLE_USER if rw => 3,
        ROLE_USER => 1,
        _ if rw => 2,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packs_pads_and_cuts() {
        let mut f = [0u8; 8];
        pack_field(&mut f, b"abc");
        assert_eq!(&f, b"abc     ");
        pack_field(&mut f, b"0123456789");
        assert_eq!(&f, b"01234567");
    }

    #[test]
    fn label_cuts_only_trailing_spaces() {
        let mut f = [b' '; 32];
        f[..5].copy_from_slice(b"a b  ");
        assert_eq!(&label(&f)[..4], b"a b\0");
        assert_eq!(label(&[b' '; 32])[0], 0);
        let full = *b"abcdefghijklmnopqrstuvwxyz012345";
        assert_eq!(&label(&full)[..32], &full);
    }

    #[test]
    fn states() {
        assert_eq!(session_state(ROLE_SO, 4), 4);
        assert_eq!(session_state(ROLE_USER, 6), 3);
        assert_eq!(session_state(ROLE_USER, 4), 1);
        assert_eq!(session_state(0, 6), 2);
        assert_eq!(session_state(0, 4), 0);
        assert_eq!(session_state(7, 6), 2);
    }

    #[test]
    fn pin_range_and_roles() {
        assert!(!pin_len_ok(3) && pin_len_ok(4) && pin_len_ok(64) && !pin_len_ok(65));
        assert_eq!(role_of(0), Some(ROLE_SO));
        assert_eq!(role_of(1), Some(ROLE_USER));
        assert_eq!(role_of(2), None);
    }
}
