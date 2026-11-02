//! The DRBG's generator, entropy sources and clock (`src/fhsm_drbg.c:142-275`).

use std::ffi::{c_int, c_void};
use std::ptr::{null, null_mut};

use openssl_sys::{
    EVP_DigestFinal_ex, EVP_DigestUpdate, EVP_MD, EVP_MD_CTX, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_fetch, EVP_MD_free, RAND_add, RAND_bytes,
};
use zeroize::Zeroizing;

use crate::drbg;

unsafe extern "C" {
    // OpenSSL 3; openssl-sys binds only EVP_DigestInit_ex
    fn EVP_DigestInit_ex2(ctx: *mut EVP_MD_CTX, md: *const EVP_MD, params: *const c_void) -> c_int;
}

/// An entropy source: fills the front of what is left of the pool, returns how much it wrote.
type Fill = fn(&mut [u8]) -> usize;

/// The DRBG's real source (`src/fhsm_drbg.c:142-275`): OpenSSL's generator, seeded from a
/// 512-byte pool that getrandom, RDRAND, `/dev/urandom` and clock jitter fill in that order, each
/// into what is left, conditioned with SHA2-384 through EVP. getrandom normally fills the whole
/// pool, so the others contribute only when it fails or returns short, as in C.
pub(crate) struct OsSource;

impl drbg::Source for OsSource {
    fn generate(&mut self, out: &mut [u8]) -> bool {
        let Ok(n) = c_int::try_from(out.len()) else {
            return false;
        };
        // SAFETY: out is writable for n bytes
        unsafe { RAND_bytes(out.as_mut_ptr(), n) == 1 }
    }

    fn seed(&mut self) -> (u32, bool) {
        let mut pool = Zeroizing::new([0u8; 512]);
        let (mut off, mut sources) = (0, 0);
        let fill: [(u32, Fill); 4] = [(1, getrandom), (2, rdrand), (4, urandom), (8, jitter)];
        for (bit, source) in fill {
            let n = source(&mut pool[off..]);
            if n > 0 {
                sources |= bit;
                off += n;
            }
        }
        // An unconditioned pool is never fed to the generator instead.
        let Some(cond) = (off > 0).then(|| sha384(&pool[..off])).flatten() else {
            return (sources, false);
        };
        // SAFETY: cond is 48 readable bytes. Entropy estimate 0: additional input only.
        unsafe { RAND_add(cond.as_ptr().cast(), 48, 0.0) };
        (sources, true)
    }

    fn now(&self) -> u64 {
        clock(libc::CLOCK_BOOTTIME).tv_sec as u64
    }
}

fn clock(id: libc::clockid_t) -> libc::timespec {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: ts is writable; both clocks exist on Linux
    unsafe { libc::clock_gettime(id, &mut ts) };
    ts
}

fn getrandom(dst: &mut [u8]) -> usize {
    // SAFETY: dst is writable for its length
    let n = unsafe { libc::getrandom(dst.as_mut_ptr().cast(), dst.len(), 0) };
    usize::try_from(n).unwrap_or(0)
}

fn urandom(dst: &mut [u8]) -> usize {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read(dst))
        .unwrap_or(0)
}

/// 64 samples of the low byte of the monotonic clock's nanoseconds, with a short busy wait
/// between them, folded into 8 bytes.
fn jitter(dst: &mut [u8]) -> usize {
    let Some(dst) = dst.get_mut(..8) else {
        return 0;
    };
    let mut acc = 0u64;
    for _ in 0..64 {
        acc = (acc << 1) ^ (clock(libc::CLOCK_MONOTONIC).tv_nsec as u64 & 0xff);
        for j in 0..17 {
            std::hint::black_box(j);
        }
    }
    dst.copy_from_slice(&acc.to_ne_bytes());
    8
}

/// Whole 8-byte RDRAND words, 10 tries each, stopping at the first word the CPU will not give.
#[cfg(target_arch = "x86_64")]
fn rdrand(dst: &mut [u8]) -> usize {
    #[target_feature(enable = "rdrand")]
    fn fill(dst: &mut [u8]) -> usize {
        let mut off = 0;
        for word in dst.as_chunks_mut::<8>().0 {
            let mut v = 0u64;
            if !(0..10).any(|_| std::arch::x86_64::_rdrand64_step(&mut v) == 1) {
                break;
            }
            word.copy_from_slice(&v.to_ne_bytes());
            off += 8;
        }
        off
    }
    if !std::arch::is_x86_feature_detected!("rdrand") {
        return 0;
    }
    // SAFETY: the CPU has RDRAND (checked above)
    unsafe { fill(dst) }
}

// shortcut: no RDRAND off x86_64 (C also takes it on i386); the hybrid builds x86_64 only.
#[cfg(not(target_arch = "x86_64"))]
fn rdrand(_dst: &mut [u8]) -> usize {
    0
}

/// SHA2-384 fetched through the providers, so a FIPS build conditions with the validated code.
fn sha384(data: &[u8]) -> Option<Zeroizing<[u8; 48]>> {
    let mut out = Zeroizing::new([0u8; 48]);
    let mut len = 0u32;
    // SAFETY: every pointer is checked before use or is one OpenSSL accepts as NULL; data and out
    // are valid for their lengths; ctx and md are freed once on every path.
    unsafe {
        let md = EVP_MD_fetch(null_mut(), c"SHA2-384".as_ptr(), null());
        let ctx = if md.is_null() {
            null_mut()
        } else {
            EVP_MD_CTX_new()
        };
        let ok = !ctx.is_null()
            && EVP_DigestInit_ex2(ctx, md, null()) == 1
            && EVP_DigestUpdate(ctx, data.as_ptr().cast(), data.len()) == 1
            && EVP_DigestFinal_ex(ctx, out.as_mut_ptr(), &mut len) == 1
            && len == 48;
        EVP_MD_CTX_free(ctx);
        EVP_MD_free(md);
        ok.then_some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drbg::Source;

    #[test]
    fn getrandom_seeds() {
        // C reports src=1 too (drbg.tsv): a full read leaves the other sources no room. A signal
        // can cut a read over 256 bytes short, and then they fill the rest, so only bit 1 is pinned.
        let (sources, seeded) = OsSource.seed();
        assert!(seeded && sources & 1 == 1, "{sources:#x}");
    }

    #[test]
    fn sources_fill_what_is_left() {
        assert_eq!(jitter(&mut [0; 7]), 0);
        assert_eq!(jitter(&mut [0; 9]), 8);
        assert_eq!(rdrand(&mut [0; 7]), 0);
        assert_eq!(urandom(&mut []), 0);
        assert_eq!(getrandom(&mut [0; 16]), 16);
    }

    #[test]
    fn sha384_is_sha2_384() {
        let d = sha384(b"abc").unwrap();
        assert_eq!(d[..4], [0xcb, 0x00, 0x75, 0x3f]);
        assert_eq!(d[44..], [0x34, 0xc8, 0x25, 0xa7]);
    }
}
