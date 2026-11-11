//! The safe half of the PKCS#11 layer (PHASE4_PLAN.md §3): module state, sessions and, in
//! later slices, objects, templates and operations. No `unsafe`: the C ABI is `pqhsm-p11`'s.
#![forbid(unsafe_code)]

pub mod ecdsa;
pub mod mechs;
pub mod p11;
pub mod session;
pub mod state;
pub mod template;

/// Q18: the environment variable `FHSM_X` is read as `PQHSM_X` when that is set, the old name
/// being its fallback for one release. `name` is the old name.
pub fn env(name: &str) -> Option<std::ffi::OsString> {
    env_in(name, |k| std::env::var_os(k))
}

fn env_in(
    name: &str,
    get: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> Option<std::ffi::OsString> {
    let new = name.strip_prefix("FHSM_").map(|s| format!("PQHSM_{s}"));
    new.and_then(|n| get(&n)).or_else(|| get(name))
}

#[cfg(test)]
mod env_tests {
    #[test]
    fn the_new_name_wins_and_the_old_one_is_the_fallback() {
        let both = |k: &str| match k {
            "PQHSM_PIN" => Some("new".into()),
            "FHSM_PIN" | "FHSM_CONF" => Some("old".into()),
            _ => None,
        };
        assert_eq!(super::env_in("FHSM_PIN", both), Some("new".into()));
        assert_eq!(super::env_in("FHSM_CONF", both), Some("old".into()));
        assert_eq!(super::env_in("FHSM_MODE", both), None);
        assert_eq!(super::env_in("CREDENTIALS_DIRECTORY", both), None);
    }
}
