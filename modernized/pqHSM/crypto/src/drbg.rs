//! The hardened DRBG front end (`src/fhsm_drbg.c`, `include/fhsm_drbg.h`; RULE-010..013).
//! OpenSSL's CTR_DRBG-AES-256 generates; this layer reseeds it periodically and runs the
//! SP 800-90B health tests on every byte it returns. `tests/golden/drbg.tsv` is the
//! specification, with DIV-032, DIV-033, DIV-036 and DIV-037 applied.
//!
//! [`Drbg`] is the logic; a [`Source`] is the generator, the seeding and the clock, so the
//! goldens can script failures. The module's one instance and the C ABI are in `ffi`.

use std::ffi::CStr;

use zeroize::Zeroize;

/// RCT cutoff: C = 1 + ceil(-log2(α) / H) = 6 for α = 2^-40, H = 8 (RULE-011).
const RCT_CUTOFF: u32 = 6;
/// APT window and cutoff (RULE-012, DIV-032): C = 1 + CRITBINOM(512, 2^-8, 1 - 2^-40) = 19,
/// failing when the window's first byte has occurred C times, counting itself.
const APT_WINDOW: u32 = 512;
const APT_CUTOFF: u32 = 19;
/// Reseed after more than this many bytes or seconds since the last seed (RULE-010).
const RESEED_BYTES: u64 = 1024 * 1024;
const RESEED_SECS: u64 = 3600;
/// SP 800-90A's max_number_of_bits_per_request, 2^19 bits: larger requests are served as a
/// sequence of these (#125).
const MAX_REQUEST: usize = 65536;
/// The continuous test's block (RULE-013).
const BLOCK: usize = 16;

/// What the DRBG layer is built on: OpenSSL's generator, its seeding, and a clock.
pub trait Source {
    /// Fills `out` from the generator (`RAND_bytes`); false when it failed.
    fn generate(&mut self, out: &mut [u8]) -> bool;
    /// Gathers entropy, conditions it and adds it to the generator: the bitmask of sources that
    /// gave bytes (`fhsm_drbg_stats_t.entropy_sources_active`), and whether it was added.
    fn seed(&mut self) -> (u32, bool);
    /// Seconds on a clock that never goes back and counts suspend (DIV-036).
    fn now(&self) -> u64;
}

/// `fhsm_drbg_stats_t`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub bytes_emitted: u64,
    pub reseeds: u32,
    pub rct_failures: u32,
    pub apt_failures: u32,
    pub crngt_failures: u32,
    pub entropy_sources_active: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The module is in the ERROR state, which the caller checks (it lives in `fhsm_state.c`).
    Halted,
    /// No output buffer, or an empty one.
    Arguments,
    /// `init` or `reseed` could not seed; nothing is latched, and a later call may retry.
    Seed,
    /// The generator or a health test failed: the module latches ERROR with this reason.
    Latch(&'static CStr),
    /// Seeding inside `bytes` failed, periodic (DIV-033) or first (DIV-044): the module latches
    /// ERROR.
    Reseed,
}

impl Error {
    /// The `fhsm_rv_t` returned for it.
    pub fn rv(self) -> u32 {
        match self {
            Self::Halted | Self::Reseed => 0x06, // FHSM_RV_FUNCTION_FAILED
            Self::Arguments => 0x07,             // FHSM_RV_ARGUMENTS_BAD
            Self::Seed | Self::Latch(_) => 0x8000_0008, // FHSM_RV_RNG_FAILURE
        }
    }

    /// The reason to latch the module ERROR with, if it must be.
    pub fn latch_reason(self) -> Option<&'static CStr> {
        match self {
            Self::Latch(reason) => Some(reason),
            Self::Reseed => Some(c"DRBG reseed failed"),
            _ => None,
        }
    }
}

pub struct Drbg<S> {
    source: S,
    seeded: bool,
    since_reseed: u64,
    last_reseed: u64,
    rct_byte: u8,
    rct_run: u32,
    apt_byte: u8,
    apt_samples: u32,
    apt_hits: u32,
    last_block: Option<[u8; BLOCK]>,
    stats: Stats,
}

impl<S: Source> Drbg<S> {
    pub const fn new(source: S) -> Self {
        Self {
            source,
            seeded: false,
            since_reseed: 0,
            last_reseed: 0,
            rct_byte: 0,
            rct_run: 0,
            apt_byte: 0,
            apt_samples: 0,
            apt_hits: 0,
            last_block: None,
            stats: Stats {
                bytes_emitted: 0,
                reseeds: 0,
                rct_failures: 0,
                apt_failures: 0,
                crngt_failures: 0,
                entropy_sources_active: 0,
            },
        }
    }

    /// Seeds the generator unless already done; the statistics restart with it.
    pub fn init(&mut self) -> Result<(), Error> {
        if !self.seeded {
            self.stats = Stats::default();
            self.seed()?;
            self.seeded = true;
        }
        Ok(())
    }

    /// Seeds the generator now (`fhsm_drbg_reseed`). Allowed in the ERROR state, as in C.
    pub fn reseed(&mut self) -> Result<(), Error> {
        self.seed()
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    /// Fills `out`, reseeding when due, in requests of at most [`MAX_REQUEST`] bytes, each
    /// health-tested before it counts. On any failure the request's output is cleansed
    /// (DIV-042), and any failure to seed latches ERROR (DIV-033, DIV-044).
    pub fn bytes(&mut self, out: &mut [u8]) -> Result<(), Error> {
        if out.is_empty() {
            return Err(Error::Arguments);
        }
        if !self.seeded {
            self.seed().map_err(|_| Error::Reseed)?;
            self.seeded = true;
        }
        let mut done = 0;
        while done < out.len() {
            let want = (out.len() - done).min(MAX_REQUEST);
            if self.reseed_due() && self.seed().is_err() {
                out[..done].zeroize();
                return Err(Error::Reseed);
            }
            let chunk = &mut out[done..done + want];
            if !self.source.generate(chunk) {
                out[..done + want].zeroize();
                return Err(Error::Latch(c"RAND_bytes failed"));
            }
            if let Err(e) = self.health(chunk) {
                out[..done + want].zeroize();
                return Err(e);
            }
            self.since_reseed += want as u64;
            self.stats.bytes_emitted += want as u64;
            done += want;
        }
        Ok(())
    }

    fn seed(&mut self) -> Result<(), Error> {
        let (sources, seeded) = self.source.seed();
        self.stats.entropy_sources_active |= sources;
        if !seeded {
            return Err(Error::Seed);
        }
        self.last_reseed = self.source.now();
        self.since_reseed = 0;
        self.stats.reseeds += 1;
        Ok(())
    }

    fn reseed_due(&self) -> bool {
        self.since_reseed > RESEED_BYTES
            || self.source.now().saturating_sub(self.last_reseed) > RESEED_SECS
    }

    /// RCT and APT on every byte, then the continuous test on every full block (DIV-037). The
    /// state carries across requests.
    fn health(&mut self, buf: &[u8]) -> Result<(), Error> {
        for &b in buf {
            if self.rct_run > 0 && b == self.rct_byte {
                self.rct_run += 1;
                if self.rct_run >= RCT_CUTOFF {
                    self.stats.rct_failures += 1;
                    return Err(Error::Latch(c"DRBG RCT alarm"));
                }
            } else {
                self.rct_byte = b;
                self.rct_run = 1;
            }

            if self.apt_samples == 0 {
                self.apt_byte = b;
                self.apt_hits = 1;
                self.apt_samples = 1;
            } else {
                self.apt_samples += 1;
                if b == self.apt_byte {
                    self.apt_hits += 1;
                    if self.apt_hits >= APT_CUTOFF {
                        self.stats.apt_failures += 1;
                        return Err(Error::Latch(c"DRBG APT alarm"));
                    }
                }
                if self.apt_samples >= APT_WINDOW {
                    self.apt_samples = 0;
                }
            }
        }
        for &block in buf.as_chunks::<BLOCK>().0 {
            if self.last_block == Some(block) {
                self.stats.crngt_failures += 1;
                return Err(Error::Latch(c"DRBG CRNGT repeated block"));
            }
            self.last_block = Some(block);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A generator that repeats `pattern`, always seeds, and never moves its clock.
    struct Fixed(Vec<u8>);

    impl Source for Fixed {
        fn generate(&mut self, out: &mut [u8]) -> bool {
            for (o, p) in out.iter_mut().zip(self.0.iter().cycle()) {
                *o = *p;
            }
            true
        }
        fn seed(&mut self) -> (u32, bool) {
            (1, true)
        }
        fn now(&self) -> u64 {
            0
        }
    }

    /// `hits` copies of 0xAA among 512 bytes, never adjacent; the other bytes are below 0x80.
    fn apt_window(hits: usize) -> Vec<u8> {
        (0..512usize)
            .map(|i| {
                if i % 2 == 0 && i / 2 < hits {
                    0xAA
                } else {
                    (i % 128) as u8
                }
            })
            .collect()
    }

    #[test]
    fn apt_passes_18_and_fails_19_div032() {
        let mut d = Drbg::new(Fixed(apt_window(18)));
        assert_eq!(d.bytes(&mut [0; 512]), Ok(()));
        let mut d = Drbg::new(Fixed(apt_window(19)));
        let mut out = [1; 512];
        assert_eq!(d.bytes(&mut out), Err(Error::Latch(c"DRBG APT alarm")));
        assert_eq!(out, [0; 512]);
        assert_eq!(d.stats().apt_failures, 1);
    }

    /// DIV-032's cutoff from the formula, and the formula against the non-binary rows of
    /// SP 800-90B Table 2 (W = 512, α = 2^-20): H = 8, 4, 2, 1 give 13, 62, 177, 311.
    #[test]
    fn the_apt_cutoff_formula_matches_table_2() {
        let cutoff = |h: f64, log2_alpha: f64| 1 + critbinom(512, 2f64.powf(-h), log2_alpha);
        assert_eq!(cutoff(8.0, -40.0), APT_CUTOFF);
        assert_eq!(cutoff(8.0, -20.0), 13);
        assert_eq!(cutoff(4.0, -20.0), 62);
        assert_eq!(cutoff(2.0, -20.0), 177);
        assert_eq!(cutoff(1.0, -20.0), 311);
    }

    /// The smallest k with P(X <= k) >= 1 - 2^log2_alpha for X ~ Binomial(n, p).
    fn critbinom(n: u32, p: f64, log2_alpha: f64) -> u32 {
        let alpha = 2f64.powf(log2_alpha);
        let mut term = (1.0 - p).powi(n as i32); // P(X = 0)
        let mut cdf = term;
        let mut k = 0;
        while 1.0 - cdf > alpha {
            term *= f64::from(n - k) / f64::from(k + 1) * p / (1.0 - p);
            k += 1;
            cdf += term;
        }
        k
    }

    #[test]
    fn crngt_compares_every_block_with_the_one_before_div037() {
        let block: Vec<u8> = (0..16).collect();
        let mut d = Drbg::new(Fixed([block.clone(), block].concat()));
        assert_eq!(
            d.bytes(&mut [0; 32]),
            Err(Error::Latch(c"DRBG CRNGT repeated block"))
        );
        // Under 16 bytes is never compared.
        let mut d = Drbg::new(Fixed((1..=8).collect()));
        assert_eq!(d.bytes(&mut [0; 8]), Ok(()));
        assert_eq!(d.bytes(&mut [0; 8]), Ok(()));
    }

    /// The health test `stream` trips, if any: one request of the stream's own length, so the
    /// generator never repeats it.
    fn trips(stream: Vec<u8>) -> Option<&'static CStr> {
        let mut out = vec![0; stream.len()];
        match Drbg::new(Fixed(stream)).bytes(&mut out) {
            Ok(()) => None,
            Err(Error::Latch(m)) => Some(m),
            Err(e) => panic!("{e:?}"),
        }
    }

    /// No run, no recurring first byte, no repeated block: none of the three tests trips.
    fn background(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 200) as u8).collect()
    }

    // Exit criterion 3 of Phase 3 (PHASE3_PLAN.md §4.4): each test trips exactly at its cutoff,
    // wherever the samples fall. The cutoffs are written out (6, 19), not the constants under
    // test. Inserted bytes are 200 or more, so the background never extends them.
    proptest! {
        /// RCT (RULE-011): a run of one byte fails at its 6th sample.
        #[test]
        fn rct_fails_exactly_at_its_cutoff(run in 1usize..12, at in 0usize..1000, x in 200u8..) {
            let mut s = background(1024);
            s[at..at + run].fill(x);
            let want = (run >= 6).then_some(c"DRBG RCT alarm");
            prop_assert_eq!(trips(s), want);
        }

        /// APT (RULE-012, DIV-032): the window's first byte fails at its 19th occurrence,
        /// counting itself. The copies sit on even samples, never adjacent, so the RCT stays quiet.
        #[test]
        fn apt_fails_exactly_at_its_cutoff(
            at in proptest::sample::subsequence((1..256usize).collect::<Vec<_>>(), 0..40),
            x in 200u8..,
        ) {
            let mut s = background(768);
            s[0] = x;
            for i in &at {
                s[2 * i] = x;
            }
            let want = (1 + at.len() >= 19).then_some(c"DRBG APT alarm");
            prop_assert_eq!(trips(s), want);
        }

        /// APT: the count starts again with each 512-sample window, from that window's first byte.
        #[test]
        fn apt_counts_one_window_at_a_time(first in 1usize..19, second in 1usize..19, x in 200u8..) {
            let mut s = background(1024);
            for k in 0..first {
                s[2 * k] = x;
            }
            for k in 0..second {
                s[512 + 2 * k] = x;
            }
            prop_assert_eq!(trips(s), None);
        }

        /// CRNGT (RULE-013, DIV-037): a 16-byte block equal to the one before fails; distinct
        /// neighbours never do. Block v is v, v+17, v+34, ...: no run longer than 2, and under
        /// 18 blocks no byte occurs 19 times.
        #[test]
        fn crngt_fails_exactly_on_a_repeated_block(v in proptest::collection::vec(0u8..4, 1..18)) {
            let s = v
                .iter()
                .flat_map(|&b| (0..16u8).map(move |j| b.wrapping_add(j.wrapping_mul(17))))
                .collect();
            let want = v.windows(2).any(|w| w[0] == w[1]).then_some(c"DRBG CRNGT repeated block");
            prop_assert_eq!(trips(s), want);
        }
    }
}
