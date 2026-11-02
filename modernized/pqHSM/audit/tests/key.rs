//! `key::provision` (RULE-093) with a fake `KeyEnv`, one test per branch of
//! `fhsm_audit_key_provision` (src/fhsm_audit.c:268-367). Keys here are generated in-test;
//! no real `audit.key` is used.

use std::cell::{Cell, RefCell};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use pqhsm_audit::key::{KeyEnv, KeyError, provision};
use zeroize::Zeroizing;

const DRBG: [u8; 32] = [0xD1; 32];
const UNSEALED: [u8; 32] = [0x5E; 32];
const ON_DISK: [u8; 32] = [0x0D; 32];
const WINNER: [u8; 32] = [0x77; 32];

struct Fake {
    tpm: bool,
    random: Result<[u8; 32], u32>,
    seal: Result<Vec<u8>, u32>,
    unseal: Result<[u8; 32], u32>,
    random_calls: Cell<u32>,
    seal_calls: Cell<u32>,
    sealed_key: RefCell<Option<[u8; 32]>>,
    unsealed_blob: RefCell<Option<Vec<u8>>>,
    /// Runs inside `random`, i.e. between the failed read and the O_EXCL create.
    during_random: Option<Box<dyn Fn()>>,
}

impl Default for Fake {
    fn default() -> Self {
        Fake {
            tpm: false,
            random: Ok(DRBG),
            seal: Ok(b"SEALED-BLOB".to_vec()),
            unseal: Ok(UNSEALED),
            random_calls: Cell::new(0),
            seal_calls: Cell::new(0),
            sealed_key: RefCell::new(None),
            unsealed_blob: RefCell::new(None),
            during_random: None,
        }
    }
}

impl KeyEnv for Fake {
    fn tpm_required(&self) -> bool {
        self.tpm
    }
    fn random(&self, out: &mut [u8; 32]) -> Result<(), u32> {
        self.random_calls.set(self.random_calls.get() + 1);
        if let Some(f) = &self.during_random {
            f();
        }
        *out = self.random?;
        Ok(())
    }
    fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, u32> {
        self.seal_calls.set(self.seal_calls.get() + 1);
        *self.sealed_key.borrow_mut() = Some(*key);
        self.seal.clone()
    }
    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, u32> {
        *self.unsealed_blob.borrow_mut() = Some(blob.to_vec());
        self.unseal.map(Zeroizing::new)
    }
}

fn write_mode(p: &Path, data: &[u8], mode: u32) {
    std::fs::write(p, data).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn plain(d: &Path) -> PathBuf {
    d.join("audit.key")
}

fn blob(d: &Path) -> PathBuf {
    d.join("audit.key.tpm")
}

fn mode(p: &Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o7777
}

// ---- recover ---------------------------------------------------------------------------------

#[test]
fn existing_0600_key_is_used_without_calling_the_drbg() {
    // RULE-093
    let d = tempfile::tempdir().unwrap();
    write_mode(&plain(d.path()), &ON_DISK, 0o600);
    let env = Fake::default();
    let p = provision(d.path(), &env).unwrap();
    assert_eq!((*p.key, p.sealed), (ON_DISK, false));
    assert_eq!(env.random_calls.get(), 0);
}

#[test]
fn owner_only_modes_other_than_0600_are_accepted() {
    // RULE-093: only group/other bits are checked (S_IRWXG | S_IRWXO)
    for m in [0o400, 0o700] {
        let d = tempfile::tempdir().unwrap();
        write_mode(&plain(d.path()), &ON_DISK, m);
        assert_eq!(
            *provision(d.path(), &Fake::default()).unwrap().key,
            ON_DISK,
            "mode {m:o}"
        );
    }
}

#[test]
fn group_or_other_permission_on_the_key_is_refused_and_the_file_kept() {
    // RULE-093: read refused, O_EXCL create hits EEXIST, re-read refused again
    for m in [0o640, 0o604, 0o610, 0o601] {
        let d = tempfile::tempdir().unwrap();
        write_mode(&plain(d.path()), &ON_DISK, m);
        assert_eq!(
            provision(d.path(), &Fake::default()).err(),
            Some(KeyError::Failed),
            "mode {m:o}"
        );
        assert_eq!(
            std::fs::read(plain(d.path())).unwrap(),
            ON_DISK,
            "mode {m:o}: file untouched"
        );
    }
}

#[test]
fn key_of_31_or_33_bytes_is_refused() {
    // RULE-093: st_size must be exactly 32
    for len in [0usize, 31, 33] {
        let d = tempfile::tempdir().unwrap();
        write_mode(&plain(d.path()), &vec![1u8; len], 0o600);
        assert_eq!(
            provision(d.path(), &Fake::default()).err(),
            Some(KeyError::Failed),
            "{len} bytes"
        );
        assert_eq!(std::fs::read(plain(d.path())).unwrap().len(), len);
    }
}

// ---- generate --------------------------------------------------------------------------------

#[test]
fn missing_key_is_generated_from_the_drbg_and_written_0600() {
    // RULE-093
    let d = tempfile::tempdir().unwrap();
    let env = Fake::default();
    let p = provision(d.path(), &env).unwrap();
    assert_eq!((*p.key, p.sealed), (DRBG, false));
    assert_eq!(env.random_calls.get(), 1);
    assert_eq!(std::fs::read(plain(d.path())).unwrap(), DRBG);
    assert_eq!(mode(&plain(d.path())), 0o600);
    assert!(!blob(d.path()).exists());
}

#[test]
fn lost_race_uses_the_winners_key() {
    // RULE-093: another process creates audit.key between our read and our O_EXCL create
    let d = tempfile::tempdir().unwrap();
    let target = plain(d.path());
    let env = Fake {
        during_random: Some(Box::new(move || write_mode(&target, &WINNER, 0o600))),
        ..Fake::default()
    };
    let p = provision(d.path(), &env).unwrap();
    assert_eq!((*p.key, p.sealed), (WINNER, false));
    assert_eq!(
        std::fs::read(plain(d.path())).unwrap(),
        WINNER,
        "the winner's file is not overwritten"
    );
}

#[test]
fn lost_race_to_an_unusable_key_fails() {
    // RULE-093: the re-read applies the same mode check
    let d = tempfile::tempdir().unwrap();
    let target = plain(d.path());
    let env = Fake {
        during_random: Some(Box::new(move || write_mode(&target, &WINNER, 0o644))),
        ..Fake::default()
    };
    assert_eq!(provision(d.path(), &env).err(), Some(KeyError::Failed));
}

#[test]
fn drbg_failure_returns_its_rv_and_writes_nothing() {
    // RULE-093
    let d = tempfile::tempdir().unwrap();
    let env = Fake {
        random: Err(0x8000_0001),
        ..Fake::default()
    };
    assert_eq!(
        provision(d.path(), &env).err(),
        Some(KeyError::Env(0x8000_0001))
    );
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
}

#[test]
fn unwritable_directory_fails() {
    // RULE-093: create fails (not EEXIST), re-read fails
    let d = tempfile::tempdir().unwrap();
    let missing = d.path().join("no-such-dir");
    assert_eq!(
        provision(&missing, &Fake::default()).err(),
        Some(KeyError::Failed)
    );
}

// ---- TPM -------------------------------------------------------------------------------------

#[test]
fn tpm_required_and_blob_unseals_gives_the_sealed_key() {
    // RULE-093: the sealed blob wins over a plaintext key
    let d = tempfile::tempdir().unwrap();
    write_mode(&blob(d.path()), b"BLOB", 0o600);
    write_mode(&plain(d.path()), &ON_DISK, 0o600);
    let env = Fake {
        tpm: true,
        ..Fake::default()
    };
    let p = provision(d.path(), &env).unwrap();
    assert_eq!((*p.key, p.sealed), (UNSEALED, true));
    assert_eq!(env.unsealed_blob.borrow().as_deref(), Some(&b"BLOB"[..]));
    assert_eq!(env.random_calls.get(), 0);
}

#[test]
fn tpm_required_and_unseal_fails_returns_its_rv_with_no_fallback() {
    // RULE-093: no fallback to audit.key, no new key
    let d = tempfile::tempdir().unwrap();
    write_mode(&blob(d.path()), b"BLOB", 0o600);
    write_mode(&plain(d.path()), &ON_DISK, 0o600);
    let env = Fake {
        tpm: true,
        unseal: Err(0x0000_0030),
        ..Fake::default()
    };
    assert_eq!(provision(d.path(), &env).err(), Some(KeyError::Env(0x30)));
    assert_eq!(env.random_calls.get(), 0);
    assert_eq!(std::fs::read(blob(d.path())).unwrap(), b"BLOB");
}

#[test]
fn only_the_first_2048_bytes_of_the_blob_are_unsealed() {
    // RULE-093: uint8_t blob[2048]; one read()
    let d = tempfile::tempdir().unwrap();
    write_mode(&blob(d.path()), &[0xB0; 3000], 0o600);
    let env = Fake {
        tpm: true,
        ..Fake::default()
    };
    provision(d.path(), &env).unwrap();
    assert_eq!(
        env.unsealed_blob.borrow().as_ref().map(Vec::len),
        Some(2048)
    );
}

#[test]
fn tpm_required_and_empty_blob_falls_through_to_the_plaintext_key() {
    // RULE-093: n > 0 is required to try unsealing
    let d = tempfile::tempdir().unwrap();
    write_mode(&blob(d.path()), b"", 0o600);
    write_mode(&plain(d.path()), &ON_DISK, 0o600);
    let env = Fake {
        tpm: true,
        ..Fake::default()
    };
    let p = provision(d.path(), &env).unwrap();
    assert_eq!((*p.key, p.sealed), (ON_DISK, false));
    assert!(env.unsealed_blob.borrow().is_none());
}

#[test]
fn tpm_required_and_empty_blob_without_plaintext_key_fails_on_the_exclusive_create() {
    // RULE-093: seal succeeds, O_EXCL on the existing empty blob fails, no plaintext fallback
    let d = tempfile::tempdir().unwrap();
    write_mode(&blob(d.path()), b"", 0o600);
    let env = Fake {
        tpm: true,
        ..Fake::default()
    };
    assert_eq!(provision(d.path(), &env).err(), Some(KeyError::Failed));
    assert!(!plain(d.path()).exists());
    assert_eq!(std::fs::read(blob(d.path())).unwrap().len(), 0);
}

#[test]
fn tpm_required_and_seal_succeeds_writes_the_blob_0600_and_no_plaintext() {
    // RULE-093
    let d = tempfile::tempdir().unwrap();
    let env = Fake {
        tpm: true,
        ..Fake::default()
    };
    let p = provision(d.path(), &env).unwrap();
    assert_eq!((*p.key, p.sealed), (DRBG, true));
    assert_eq!(
        *env.sealed_key.borrow(),
        Some(DRBG),
        "the DRBG key is what gets sealed"
    );
    assert_eq!(std::fs::read(blob(d.path())).unwrap(), b"SEALED-BLOB");
    assert_eq!(mode(&blob(d.path())), 0o600);
    assert!(!plain(d.path()).exists());
}

#[test]
fn tpm_required_and_seal_fails_returns_its_rv_and_writes_no_plaintext() {
    // RULE-093: no downgrade to a plaintext key
    let d = tempfile::tempdir().unwrap();
    let env = Fake {
        tpm: true,
        seal: Err(0x0000_0005),
        ..Fake::default()
    };
    assert_eq!(provision(d.path(), &env).err(), Some(KeyError::Env(5)));
    assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
}

#[test]
fn tpm_not_required_ignores_an_existing_blob() {
    // RULE-093 edge: turning sealing off silently starts a new plaintext key
    let d = tempfile::tempdir().unwrap();
    write_mode(&blob(d.path()), b"BLOB", 0o600);
    let env = Fake::default();
    let p = provision(d.path(), &env).unwrap();
    assert_eq!((*p.key, p.sealed), (DRBG, false));
    assert!(env.unsealed_blob.borrow().is_none());
    assert_eq!(std::fs::read(plain(d.path())).unwrap(), DRBG);
}

// ---- path length -----------------------------------------------------------------------------

/// Create nested directories under `root` so the directory path is exactly `len` bytes.
fn dir_of_len(root: &Path, len: usize) -> PathBuf {
    let mut p = root.to_str().unwrap().to_owned();
    while p.len() < len {
        let room = len - p.len();
        let k = if room > 201 { 150 } else { room - 1 };
        p.push('/');
        p.push_str(&"d".repeat(k));
    }
    assert_eq!(p.len(), len);
    std::fs::create_dir_all(&p).unwrap();
    PathBuf::from(p)
}

#[test]
fn directory_whose_blob_path_is_511_bytes_is_accepted() {
    // RULE-093: "dir/audit.key.tpm" must be < 512 (snprintf >= sizeof plain)
    let root = tempfile::tempdir().unwrap();
    let d = dir_of_len(root.path(), 511 - "/audit.key.tpm".len());
    assert_eq!(*provision(&d, &Fake::default()).unwrap().key, DRBG);
}

#[test]
fn directory_whose_blob_path_is_512_bytes_is_arguments_bad() {
    // RULE-093
    let root = tempfile::tempdir().unwrap();
    let d = dir_of_len(root.path(), 512 - "/audit.key.tpm".len());
    let env = Fake::default();
    assert_eq!(provision(&d, &env).err(), Some(KeyError::ArgumentsBad));
    assert_eq!(env.random_calls.get(), 0);
    assert_eq!(std::fs::read_dir(&d).unwrap().count(), 0);
}
