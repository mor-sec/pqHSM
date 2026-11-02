//! The secure heap, zeroisation and constant-time comparison (`src/fhsm_memory.c`; FIPS 140-3
//! §7.9). No business rule covers it (RULE-078 is its main user); `tests/golden/cases.tsv` is the
//! specification.
//!
//! The heap is OpenSSL's mlocked secure arena, one per process. It is created once, sized by
//! `secure_heap_kb` ([`conf::secure_heap_bytes`]), and refused unless the kernel locked it: an
//! arena that can reach swap is worse than none, so exhaustion and an unlocked arena both fail
//! instead of falling back to pageable memory (#127). A second copy of the module in the process
//! adopts the first copy's arena if the kernel reports it locked.

use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::conf;
use crate::ffi::sys;

/// `FHSM_SECURE_HEAP_MINSIZE` (`include/fhsm_common.h:299`).
const MIN_BLOCK: usize = 32;

static BYTES: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicBool = AtomicBool::new(false);

/// The arena's size and whether it is usable, creating it on first use. Once per process with
/// C's fork semantics: `pthread_once`, so a child forked while another thread is inside the init
/// runs it again, where `OnceLock` would wait forever (review M1).
fn arena() -> (usize, bool) {
    sys::heap_once(create_once);
    (BYTES.load(Ordering::Acquire), READY.load(Ordering::Acquire))
}

extern "C" fn create_once() {
    let (bytes, ready) = create();
    BYTES.store(bytes, Ordering::Release);
    READY.store(ready, Ordering::Release);
}

fn create() -> (usize, bool) {
    let bytes = conf::secure_heap_bytes();
    if sys::secure_heap_exists() {
        let adopted = adopt();
        if adopted.is_none() {
            sys::stderr(SHARED_UNLOCKED);
        }
        return adopted.map_or((bytes, false), |size| (size, true));
    }
    match sys::secure_heap_create(bytes, MIN_BLOCK) {
        1 => (bytes, true),
        rc => {
            sys::stderr(&failure_message(bytes, rc == 2, sys::memlock_soft_kb()));
            (bytes, false)
        }
    }
}

/// The arena another library or module copy created, if the kernel locked it: its size.
fn adopt() -> Option<usize> {
    let probe = sys::Block::alloc(16)?;
    if !probe.in_secure_heap() {
        return None;
    }
    let smaps = std::fs::read("/proc/self/smaps").ok()?;
    locked_mapping_size(&String::from_utf8_lossy(&smaps), probe.addr())
}

/// The size of the mapping in `smaps` that holds `addr`, when its `VmFlags` include `lo`.
/// DIV-038: C parsed this with `sscanf("%lx%c%lx")`, which overwrote the start address on lines
/// such as `AnonHugePages:`, and so reported an address-sized number as the arena size.
fn locked_mapping_size(smaps: &str, addr: usize) -> Option<usize> {
    let mut inside = None;
    for line in smaps.lines() {
        if let Some((lo, hi)) = mapping_range(line) {
            if inside.is_some() {
                return None; // past the mapping, and no VmFlags line in it
            }
            inside = (lo..hi).contains(&addr).then(|| hi - lo);
        } else if let (Some(size), Some(flags)) = (inside, line.strip_prefix("VmFlags:")) {
            return flags.split_whitespace().any(|f| f == "lo").then_some(size);
        }
    }
    None
}

fn mapping_range(line: &str) -> Option<(usize, usize)> {
    let (lo, hi) = line.split_once(' ')?.0.split_once('-')?;
    Some((
        usize::from_str_radix(lo, 16).ok()?,
        usize::from_str_radix(hi, 16).ok()?,
    ))
}

/// Creates the arena on first use; false when it could not be created locked.
pub fn init() -> bool {
    arena().1
}

/// The arena size: what was asked for, or the adopted arena's. Creates the arena on first use.
pub fn total() -> usize {
    arena().0
}

/// Bytes in use in the arena.
pub fn used() -> usize {
    sys::secure_heap_used()
}

/// `n` bytes in the arena, or null when it is exhausted or could not be created. The caller
/// decides whether that is an ERROR-state event: a search buffer may legitimately run out.
pub fn alloc(n: usize) -> *mut u8 {
    if init() {
        sys::secure_alloc(n)
    } else {
        null_mut()
    }
}

/// [`alloc`], zero-filled: OpenSSL's arena does not zero.
pub fn alloc_zeroed(n: usize) -> *mut u8 {
    if init() {
        sys::secure_alloc_zeroed(n)
    } else {
        null_mut()
    }
}

pub use sys::secure_free as free;

/// OR of the XOR of every byte pair: 0 when equal. The time depends on the length only, not on
/// where the first difference is; the only comparison for PINs, MAC tags and KAT outputs.
pub fn ct_diff(a: &[u8], b: &[u8]) -> u8 {
    // Unequal lengths never compare equal: an empty input must not match a tag (review M2a).
    let len = u8::from(a.len() != b.len());
    a.iter()
        .zip(b)
        .fold(len, |d, (x, y)| std::hint::black_box(d | (x ^ y)))
}

const SHARED_UNLOCKED: &str = "[freehsm-c] FATAL : the secure heap could not be created.\n  \
This process already has one -- another library, or another copy\n  \
of this module, created it first -- and it is NOT locked in\n  \
memory, or that could not be checked in /proc/self/smaps. An\n  \
unlocked arena is refused: key material there could reach swap.\n";

/// The operator's message when the arena cannot be created: the size asked for, which of the two
/// failures it was, and the limit in the way (`src/fhsm_memory.c:174-202`, text unchanged).
fn failure_message(bytes: usize, unlocked: bool, memlock_kb: u64) -> String {
    let mut m = format!(
        "[freehsm-c] FATAL : the secure heap could not be created.\n  \
         Asked for {} kB (secure_heap_kb in /etc/freehsm/freehsm.conf,\n  default {} kB).\n",
        bytes / 1024,
        conf::DEFAULT_HEAP_BYTES / 1024
    );
    m += if unlocked {
        "  OpenSSL allocated it but could NOT lock it in memory, and\n  \
         an unlocked arena is refused: key material there could be\n  \
         written to swap, which is exactly what this heap prevents.\n"
    } else {
        "  OpenSSL could not allocate it at all.\n"
    };
    m += &if memlock_kb != 0 {
        format!(
            "  Your locked-memory limit is {memlock_kb} kB (ulimit -l). The arena must\n  \
             fit inside it -- raising secure_heap_kb alone does not give you\n  \
             a bigger arena, it stops the module. Raise both, or neither.\n"
        )
    } else {
        "  Check `ulimit -l` : the arena must fit inside it.\n".to_owned()
    };
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMAPS: &str = "\
7f0000000000-7f0000001000 ---p 00000000 00:00 0
Size:                  4 kB
VmFlags: mr mw me ac
7f0000001000-7f0000101000 rw-p 00000000 00:00 0
Size:               1024 kB
AnonHugePages:         0 kB
FilePmdMapped:         0 kB
Locked:             1024 kB
VmFlags: rd wr mr mw me lo ac sd
7f0000101000-7f0000102000 ---p 00000000 00:00 0
VmFlags: mr mw me ac lo
";

    #[test]
    fn the_locked_mapping_size_is_its_range_div038() {
        assert_eq!(
            locked_mapping_size(SMAPS, 0x7f00_0000_1000 + 64),
            Some(1 << 20)
        );
    }

    #[test]
    fn an_unlocked_or_absent_mapping_is_refused() {
        assert_eq!(locked_mapping_size(SMAPS, 0x7f00_0000_0010), None);
        assert_eq!(locked_mapping_size(SMAPS, 0x1000), None);
        let no_flags =
            "1000-2000 rw-p 0 00:00 0\nSize: 4 kB\n3000-4000 rw-p 0 00:00 0\nVmFlags: lo\n";
        assert_eq!(locked_mapping_size(no_flags, 0x1800), None);
    }

    #[test]
    fn lo_must_be_a_whole_flag() {
        let s = "1000-2000 rw-p 0 00:00 0\nVmFlags: rd wr loc\n";
        assert_eq!(locked_mapping_size(s, 0x1800), None);
        let s = "1000-2000 rw-p 0 00:00 0\nVmFlags: rd wr lo";
        assert_eq!(locked_mapping_size(s, 0x1800), Some(0x1000));
    }

    #[test]
    fn ct_diff_ors_every_difference() {
        assert_eq!(ct_diff(b"", b""), 0);
        assert_eq!(ct_diff(&[1], &[3]), 2);
        assert_eq!(ct_diff(&[0x0f, 0xf0], &[0, 0]), 0xff);
        assert_eq!(ct_diff(&[0xa5; 3], &[0xa5, 0xa5, 0xa4]), 1);
        assert_ne!(ct_diff(b"", b"tag"), 0);
        assert_ne!(ct_diff(b"ta", b"tag"), 0);
    }

    #[test]
    fn the_limit_line_needs_a_known_nonzero_limit() {
        assert!(failure_message(1 << 26, true, 8192).contains("limit is 8192 kB"));
        assert!(
            failure_message(1 << 26, false, 0)
                .ends_with("Check `ulimit -l` : the arena must fit inside it.\n")
        );
    }
}
