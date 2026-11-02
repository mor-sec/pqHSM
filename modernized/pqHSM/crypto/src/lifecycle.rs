//! The crypto core's lifecycle (`src/fhsm_crypto.c:66-302`; RULE-074, RULE-076): the integrity
//! check, the provider loads, the DRBG and the KATs, once, before any service is used.
//! `tests/golden/core.tsv` is the specification, with DIV-034 and DIV-035 applied.
//!
//! [`Core`] is the logic; a [`Platform`] is everything it calls, so the goldens can script
//! failures. The module's one instance and the C ABI are in `ffi`.

use std::ffi::CStr;

use crate::rv;

/// The development bypasses (RULE-074), honoured only by a `dev-bypass` build (DIV-034).
pub const ALLOW_UNSIGNED: &str = "FHSM_INTEGRITY_ALLOW_UNSIGNED";
pub const KAT_ALLOW_FAIL: &str = "FHSM_KAT_ALLOW_FAIL";

/// What the lifecycle calls: the integrity check and KATs (C until slice 4), OpenSSL's
/// providers, the DRBG, the module state, the environment and stderr.
pub trait Platform {
    type Provider;
    fn integrity(&mut self) -> u32;
    fn load(&mut self, name: &CStr) -> Option<Self::Provider>;
    fn unload(&mut self, provider: Self::Provider);
    /// `EVP_default_properties_enable_fips`; false when it failed.
    fn enable_fips(&mut self, on: bool) -> bool;
    fn drbg_init(&mut self) -> u32;
    /// Runs the KATs, keeping their records for `fhsm_kat_results`: their code, and
    /// "algorithm / vector" for each that failed.
    fn kats(&mut self) -> (u32, Vec<String>);
    fn forget_kats(&mut self);
    fn latch(&mut self, reason: &CStr);
    fn var(&self, name: &str) -> Option<String>;
    fn eprint(&mut self, text: &str);
    /// `ERR_print_errors_fp(stderr)`.
    fn eprint_openssl_errors(&mut self);
}

pub struct Core<P: Platform> {
    platform: P,
    /// Whether the bypass variables are honoured (DIV-034): the `dev-bypass` feature.
    bypass: bool,
    /// The cached result of the last init; `None` until init runs and again after finalize
    /// (DIV-035).
    result: Option<u32>,
    told_ignored: bool,
    fips: Option<P::Provider>,
    base: Option<P::Provider>,
    default: Option<P::Provider>,
}

impl<P: Platform> Core<P> {
    pub const fn new(platform: P, bypass: bool) -> Self {
        Self {
            platform,
            bypass,
            result: None,
            told_ignored: false,
            fips: None,
            base: None,
            default: None,
        }
    }

    pub fn platform(&mut self) -> &mut P {
        &mut self.platform
    }

    /// `fhsm_crypto_init`: runs the self-tests unless they have run since the last finalize, and
    /// returns their result, OK or not.
    pub fn init(&mut self) -> u32 {
        if let Some(rv) = self.result {
            return rv;
        }
        let rv = self.run();
        self.result = Some(rv);
        rv
    }

    /// `fhsm_crypto_finalize`: unloads the providers and forgets the KATs, and the next init
    /// runs everything again (DIV-035).
    pub fn finalize(&mut self) {
        for p in [self.base.take(), self.fips.take(), self.default.take()]
            .into_iter()
            .flatten()
        {
            self.platform.unload(p);
        }
        self.platform.forget_kats();
        self.result = None;
    }

    /// Forgets the result, so the next init runs the self-tests again (DIV-035): what a fork
    /// child needs, being a new module instance. The providers stay loaded, and that init uses
    /// them rather than loading them again (slice 3 review M2): unloading is not for a fork
    /// handler.
    pub fn forget(&mut self) {
        self.result = None;
    }

    fn honoured(&mut self, name: &str) -> bool {
        let set = self.platform.var(name).is_some();
        if set && !self.bypass && !self.told_ignored {
            self.told_ignored = true;
            self.platform.eprint(&format!(
                "[freehsm-c] NOTE : {name} is set and ignored : this build does not honour the \
                 self-test bypass variables.\n"
            ));
        }
        set && self.bypass
    }

    /// The providers back out in C's order, base first.
    fn fail(&mut self, rv: u32, reason: &CStr) -> u32 {
        for p in [self.base.take(), self.fips.take()].into_iter().flatten() {
            self.platform.unload(p);
        }
        self.platform.latch(reason);
        rv
    }

    fn run(&mut self) -> u32 {
        // §7.10.2: integrity before any approved service. Its own failure latches ERROR.
        let dev = self.honoured(ALLOW_UNSIGNED);
        if self.platform.integrity() != rv::OK && !dev {
            return rv::INTEGRITY_FAILED;
        }

        if !dev {
            self.fips = self.fips.take().or_else(|| self.platform.load(c"fips"));
            if self.fips.is_none() {
                let conf = self.platform.var("OPENSSL_CONF");
                self.platform.eprint(&format!(
                    "[freehsm-c] FATAL : the OpenSSL FIPS provider would not load.\n  This module \
                     is signed, so it requires the provider ; only an\n  unsigned/dev build \
                     ({ALLOW_UNSIGNED}) skips it.\n  Check, in order :\n    openssl list \
                     -providers          fips must be active\n    OPENSSL_CONF                     \
                     currently {}\n  An OpenSSL upgrade invalidates fipsmodule.cnf : it holds \
                     the\n  MAC of the previous fips.so. See AGD_PRE 3.3.1.\n  OpenSSL says :\n",
                    conf.as_deref().unwrap_or("<unset, system default>")
                ));
                self.platform.eprint_openssl_errors();
                return self.fail(
                    rv::PROVIDER_UNAVAILABLE,
                    c"OpenSSL FIPS provider load failed",
                );
            }
            self.base = self.base.take().or_else(|| self.platform.load(c"base"));
            if self.base.is_none() {
                self.platform.eprint(
                    "[freehsm-c] FATAL : the OpenSSL base provider would not load.\n  It supplies \
                     the PEM/DER encoders ; without it no key can be\n  serialised to disk. \
                     OpenSSL says :\n",
                );
                self.platform.eprint_openssl_errors();
                return self.fail(
                    rv::PROVIDER_UNAVAILABLE,
                    c"OpenSSL base provider load failed",
                );
            }
            // Every fetch without a property query now goes to the FIPS provider.
            if !self.platform.enable_fips(true) {
                return self.fail(rv::PROVIDER_UNAVAILABLE, c"FIPS default property failed");
            }
        } else {
            // Not FIPS-conformant: the default provider serves the fetches. Loading "base"
            // elsewhere stops OpenSSL loading "default" by itself, hence the explicit load.
            self.platform.enable_fips(false);
            self.default = self
                .default
                .take()
                .or_else(|| self.platform.load(c"default"));
            self.platform.eprint(if self.default.is_none() {
                "[freehsm-c] WARNING : OpenSSL default provider failed to load --- AES-GCM and \
                 other primitives will fail.\n"
            } else {
                // "integrity bypass active" is grepped by scripts/run_fips_tests.sh (issue #6)
                "[freehsm-c] NOTE : integrity bypass active --- FHSM_INTEGRITY_ALLOW_UNSIGNED is \
                 set, so this\n  process skipped the integrity check and did not load the OpenSSL \
                 FIPS provider ;\n  EVP fetches are served by the default provider. This RUN is \
                 not FIPS-conformant.\n  The binary is unchanged : the same file, run without the \
                 variable, loads the\n  provider. Unset it to run inside the evaluated \
                 configuration --- or set\n  FHSM_EVIDENCE=1 if you are running the Wycheproof \
                 harness, which sets the\n  bypass itself.\n"
            });
        }

        // Before the KATs, some of which draw from the DRBG.
        let drbg = self.platform.drbg_init();
        if drbg != rv::OK {
            return self.fail(drbg, c"DRBG init failed");
        }

        let (kat, failed) = self.platform.kats();
        if kat != rv::OK {
            if !(dev && self.honoured(KAT_ALLOW_FAIL)) {
                return self.fail(rv::KAT_FAILED, c"KAT failed at module init");
            }
            self.platform.eprint(
                "[freehsm-c] WARNING : FHSM_KAT_ALLOW_FAIL active --- module exposes services \
                 WITHOUT a passing KAT. This is INVALID for any FIPS 140-3 / CC EAL4+ deployment.\n",
            );
            for f in failed {
                self.platform
                    .eprint(&format!("[freehsm-c]   KAT FAIL : {f}\n"));
            }
        }
        rv::OK
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything succeeds; the environment is `vars`; stderr and latches are recorded.
    #[derive(Default)]
    struct Fine {
        vars: Vec<&'static str>,
        loads: u32,
        runs: u32,
        kats: u32,
        err: String,
        latched: bool,
    }

    impl Platform for Fine {
        type Provider = ();
        fn integrity(&mut self) -> u32 {
            self.runs += 1;
            rv::OK
        }
        fn load(&mut self, _: &CStr) -> Option<()> {
            self.loads += 1;
            Some(())
        }
        fn unload(&mut self, (): ()) {}
        fn enable_fips(&mut self, _: bool) -> bool {
            true
        }
        fn drbg_init(&mut self) -> u32 {
            rv::OK
        }
        fn kats(&mut self) -> (u32, Vec<String>) {
            self.kats += 1;
            (rv::KAT_FAILED, vec!["SHA2-256 / abc".into()])
        }
        fn forget_kats(&mut self) {
            self.kats = 0;
        }
        fn latch(&mut self, _: &CStr) {
            self.latched = true;
        }
        fn var(&self, name: &str) -> Option<String> {
            self.vars.contains(&name).then(String::new)
        }
        fn eprint(&mut self, text: &str) {
            self.err.push_str(text);
        }
        fn eprint_openssl_errors(&mut self) {}
    }

    /// DIV-034: without `dev-bypass` both variables are ignored, and the first init says so once.
    #[test]
    fn a_release_build_ignores_the_bypass_variables_div034() {
        let vars = vec![ALLOW_UNSIGNED, KAT_ALLOW_FAIL];
        let mut core = Core::new(
            Fine {
                vars: vars.clone(),
                ..Fine::default()
            },
            false,
        );
        assert_eq!(core.init(), rv::KAT_FAILED);
        assert!(core.platform().latched);
        assert_eq!(core.platform().err.matches("is set and ignored").count(), 1);
        assert!(!core.platform().err.contains("integrity bypass active"));

        let mut core = Core::new(
            Fine {
                vars,
                ..Fine::default()
            },
            true,
        );
        assert_eq!(core.init(), rv::OK);
        assert!(core.platform().err.contains("KAT FAIL : SHA2-256 / abc"));
    }

    /// DIV-035: finalize forgets the result, so the self-tests run again.
    #[test]
    fn init_after_finalize_runs_the_self_tests_again_div035() {
        let mut core = Core::new(
            Fine {
                vars: vec![ALLOW_UNSIGNED, KAT_ALLOW_FAIL],
                ..Fine::default()
            },
            true,
        );
        assert_eq!((core.init(), core.init()), (rv::OK, rv::OK));
        assert_eq!(core.platform().runs, 1);
        core.finalize();
        assert_eq!(core.platform().kats, 0);
        assert_eq!(core.init(), rv::OK);
        assert_eq!((core.platform().runs, core.platform().kats), (2, 1));
    }

    /// DIV-035 in a fork child: the self-tests run again on the providers already loaded,
    /// with no second load to leak (slice 3 review M2).
    #[test]
    fn init_after_forget_runs_the_self_tests_on_the_loaded_providers() {
        let mut core = Core::new(
            Fine {
                vars: vec![ALLOW_UNSIGNED, KAT_ALLOW_FAIL],
                ..Fine::default()
            },
            true,
        );
        assert_eq!(core.init(), rv::OK);
        core.forget();
        assert_eq!(core.init(), rv::OK);
        let p = core.platform();
        assert_eq!((p.loads, p.runs, p.kats), (1, 2, 2));
    }
}
