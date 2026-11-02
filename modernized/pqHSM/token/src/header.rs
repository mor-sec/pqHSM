//! The 317-byte token header (RULE-004), byte for byte as the layout comment at
//! `src/fhsm_token.c:289-311` and `write_atomic` (`:1098-1127`) define it:
//!
//! ```text
//!   0  4 magic "FHSM"        136  4 pbkdf2_iter LE     244 48 user_wrap_ct
//!   4  4 version = 1 LE      140 16 salt_so            292  1 user_initialized
//!   8 64 label (NUL-padded)  156 12 so_wrap_nonce      293  4 failed_so LE
//!  72 64 serial (NUL-padded) 168 48 so_wrap_ct         297  4 failed_user LE
//!                            216 16 salt_user          301  8 zero (throttle, ignored)
//!                            232 12 user_wrap_nonce    309  8 zero (throttle, ignored)
//! ```

use crate::Rv;

pub const LEN: usize = 317;
pub const MAGIC: [u8; 4] = *b"FHSM";
pub const VERSION: u32 = 1;
/// The only count C ever writes (`src/fhsm_token.c:1234`, `:1840`), and since DIV-011 the
/// only count a load accepts.
pub const PBKDF2_ITER: u32 = 200_000;

/// The decoded header. Throttle deadlines are not here: they are derived from the counters on
/// load (RULE-026) and written as zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub label: [u8; 64],
    pub serial: [u8; 64],
    pub pbkdf2_iter: u32,
    pub salt_so: [u8; 16],
    pub so_wrap_nonce: [u8; 12],
    pub so_wrap_ct: [u8; 48],
    pub salt_user: [u8; 16],
    pub user_wrap_nonce: [u8; 12],
    pub user_wrap_ct: [u8; 48],
    /// C reads any non-zero byte as 1 and writes 0 or 1.
    pub user_initialized: bool,
    pub failed_so: u32,
    pub failed_user: u32,
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn arr<const N: usize>(b: &[u8], o: usize) -> [u8; N] {
    b[o..o + N].try_into().unwrap()
}

impl Header {
    pub fn parse(file: &[u8]) -> Result<Header, Rv> {
        if file.len() < LEN || file[..4] != MAGIC || u32_at(file, 4) != VERSION {
            return Err(Rv::FUNCTION_FAILED);
        }
        let h = Header {
            label: arr(file, 8),
            serial: arr(file, 72),
            pbkdf2_iter: u32_at(file, 136),
            salt_so: arr(file, 140),
            so_wrap_nonce: arr(file, 156),
            so_wrap_ct: arr(file, 168),
            salt_user: arr(file, 216),
            user_wrap_nonce: arr(file, 232),
            user_wrap_ct: arr(file, 244),
            user_initialized: file[292] != 0,
            failed_so: u32_at(file, 293),
            failed_user: u32_at(file, 297),
        };
        if h.pbkdf2_iter != PBKDF2_ITER {
            return Err(Rv::FUNCTION_FAILED);
        }
        Ok(h)
    }

    pub fn to_bytes(&self) -> [u8; LEN] {
        let mut b = [0u8; LEN];
        b[..4].copy_from_slice(&MAGIC);
        b[4..8].copy_from_slice(&VERSION.to_le_bytes());
        b[8..72].copy_from_slice(&self.label);
        b[72..136].copy_from_slice(&self.serial);
        b[136..140].copy_from_slice(&self.pbkdf2_iter.to_le_bytes());
        b[140..156].copy_from_slice(&self.salt_so);
        b[156..168].copy_from_slice(&self.so_wrap_nonce);
        b[168..216].copy_from_slice(&self.so_wrap_ct);
        b[216..232].copy_from_slice(&self.salt_user);
        b[232..244].copy_from_slice(&self.user_wrap_nonce);
        b[244..292].copy_from_slice(&self.user_wrap_ct);
        b[292] = self.user_initialized as u8;
        b[293..297].copy_from_slice(&self.failed_so.to_le_bytes());
        b[297..301].copy_from_slice(&self.failed_user.to_le_bytes());
        b
    }
}
