//! The mechanism table (`src/gen/fhsm_dispatch.c`'s advertisement data, generated into
//! `mechs/table.rs` from `scripts/gen_p11_thunks.py` by `scripts/gen_mechs_rs.py`) and what
//! `C_GetMechanismInfo` reads from it (`src/fhsm_pkcs11.c:1540-1620`).

use std::ffi::c_ulong;

mod table;

/// One row: the parts of C's `fhsm_mech_entry_t` the module reads.
#[derive(Debug)]
pub struct Mech {
    pub ckm: u32,
    pub family: &'static str,
    /// The operations, joined by '+'.
    pub op: &'static str,
    pub approved: bool,
    /// Has a handler of its own (not `dispatch_reject_fips` in the source table).
    pub handled: bool,
}

/// Every row, by value.
pub fn all() -> &'static [Mech] {
    table::TABLE
}

/// `fhsm_mechanism_lookup`, by the 32-bit value C narrowed the type to.
pub fn lookup(ckm: u32) -> Option<&'static Mech> {
    let t = table::TABLE;
    t.binary_search_by_key(&ckm, |m| m.ckm).ok().map(|i| &t[i])
}

impl Mech {
    /// Dispatchable in this build: the strict profile points every row that is not approved at
    /// the reject handler.
    pub fn dispatchable(&self, strict: bool) -> bool {
        self.handled && (self.approved || !strict)
    }

    /// `fhsm_mech_flags_for`: the CKF_ flags of each operation, ORed.
    pub fn flags(&self) -> c_ulong {
        self.op.split('+').fold(0, |f, op| {
            f | match op {
                "digest" => 0x400,
                "sign" => 0x800 | 0x2000,
                "encrypt" => 0x100 | 0x200,
                "encap" => 0x1000_0000 | 0x2000_0000,
                "wrap" => 0x2_0000 | 0x4_0000,
                "derive" => 0x8_0000,
                "keygen" => 0x8000,
                "keypair" => 0x1_0000,
                _ => 0,
            }
        })
    }

    /// `fhsm_mech_keysizes_for`: the family's minimum and maximum key size (0, 0 for others).
    pub fn key_sizes(&self) -> (c_ulong, c_ulong) {
        match self.family {
            "AES" => (16, 32),
            "TDES" => (24, 24),
            "DES" => (8, 8),
            "RSA" => (2048, 4096),
            "EC" | "EdDSA" | "ECM" => (256, 521),
            "HMAC" | "KMAC" | "GENERIC" => (1, 64),
            _ => (0, 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_sorted_and_every_row_is_found() {
        assert!(all().windows(2).all(|w| w[0].ckm < w[1].ckm));
        assert!(
            all()
                .iter()
                .all(|m| lookup(m.ckm).is_some_and(|f| f.ckm == m.ckm))
        );
        assert!(lookup(0x7FFF_FFFF).is_none());
    }

    #[test]
    fn flags_or_each_operation() {
        let kw = lookup(0x2109).expect("CKM_AES_KEY_WRAP");
        assert_eq!(kw.op, "wrap+encrypt");
        assert_eq!(kw.flags(), 0x2_0000 | 0x4_0000 | 0x100 | 0x200);
        assert_eq!(lookup(0x250).map(Mech::flags), Some(0x400));
    }

    #[test]
    fn the_strict_profile_dispatches_approved_rows_only() {
        let rsa = lookup(0x1).expect("CKM_RSA_PKCS");
        assert!(!rsa.approved && rsa.dispatchable(false) && !rsa.dispatchable(true));
        assert!(
            all()
                .iter()
                .filter(|m| !m.handled)
                .all(|m| !m.dispatchable(false))
        );
    }
}
