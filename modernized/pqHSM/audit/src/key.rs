//! Chaining-key provisioning (RULE-093).

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

/// `eprintln!` panics when stderr cannot be written (a full disk, a closed pipe), and a panic
/// under `extern "C"` aborts: the operator message is best-effort, the return value is not.
macro_rules! warn {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

/// C path buffers are 512 bytes including the NUL.
const PATH_MAX: usize = 512;
/// The most of a sealed blob that is read or written.
const BLOB_MAX: u64 = 2048;

/// The services key provisioning needs from the rest of the module. In the hybrid build these
/// are the legacy C functions; tests supply fakes.
pub trait KeyEnv {
    /// `fhsm_token_tpm_required()`.
    fn tpm_required(&self) -> bool;
    /// 32 bytes from the module DRBG (`fhsm_drbg_bytes`). `Err(rv)` on failure.
    fn random(&self, out: &mut [u8; 32]) -> Result<(), u32>;
    /// Seal to the TPM (`fhsm_tpm_seal`); the blob is at most 2048 bytes.
    fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, u32>;
    /// Unseal a blob (`fhsm_tpm_unseal`).
    fn unseal(&self, blob: &[u8]) -> Result<Zeroizing<[u8; 32]>, u32>;
}

/// A provisioned key, and whether it came from or went to the TPM.
pub struct Provisioned {
    pub key: Zeroizing<[u8; 32]>,
    pub sealed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    /// `dir/audit.key.tpm` would be 512 bytes or longer.
    ArgumentsBad,
    /// A file could not be read, created or written (`FHSM_RV_FUNCTION_FAILED`).
    Failed,
    /// The environment refused, with its own return value (DRBG, seal or unseal).
    Env(u32),
}

/// Recover or create the chaining key in `dir`, exactly as `fhsm_audit_key_provision`:
///
/// 1. If the TPM is required and `dir/audit.key.tpm` exists and is non-empty (first 2048 bytes
///    read): unseal it. Success → `sealed = true`. Failure → `Env(rv)`, with **no** fallback.
/// 2. Read `dir/audit.key`: refused if group/other have any permission bit, or the size is not
///    exactly 32 bytes; a refused or missing file falls through to 3, where the `O_EXCL`
///    create then fails on a file that exists, so a refused key is never replaced.
/// 3. Generate 32 bytes from the DRBG (`Env(rv)` on failure).
///    - TPM required: seal and create `audit.key.tpm` with `O_EXCL`, 0600, `fsync`; any failure
///      → no plaintext fallback (`Env(rv)` from seal, `Failed` from the file).
///    - Otherwise create `audit.key` with `O_EXCL`, 0600, write + `fsync`. If that fails (lost
///      race), re-read `audit.key` and use the winner's key; if that also fails, `Failed`.
pub fn provision(dir: &Path, env: &dyn KeyEnv) -> Result<Provisioned, KeyError> {
    let d = dir.as_os_str().as_bytes();
    if d.len() + b"/audit.key.tpm".len() >= PATH_MAX {
        return Err(KeyError::ArgumentsBad);
    }
    let plain = in_dir(d, b"/audit.key");
    let blob_path = in_dir(d, b"/audit.key.tpm");
    let want_tpm = env.tpm_required();

    if want_tpm && let Some(blob) = read_blob(&blob_path) {
        return match env.unseal(&blob) {
            Ok(key) => Ok(Provisioned { key, sealed: true }),
            Err(rv) => {
                warn!(
                    "[pqhsm] audit key : {} exists and will not unseal (rv=0x{rv:x}).\n  \
                     The boot measurements changed, or this is not the TPM\n  \
                     that sealed it. A fresh key here would start a second\n  \
                     chain in the same log, so this refuses instead.",
                    blob_path.display()
                );
                Err(KeyError::Env(rv))
            }
        };
    }
    if let Some(key) = read_key(&plain) {
        return Ok(Provisioned { key, sealed: false });
    }

    let mut key = Zeroizing::new([0u8; 32]);
    env.random(&mut key).map_err(|rv| {
        warn!(
            "[pqhsm] audit key : the DRBG would not produce 32 bytes (rv=0x{rv:x}).\n  \
             Nothing about the key store is wrong; the generator is."
        );
        KeyError::Env(rv)
    })?;

    if want_tpm {
        let blob = Zeroizing::new(env.seal(&key).map_err(|rv| {
            warn!(
                "[pqhsm] audit key : sealing to the TPM failed (rv=0x{rv:x}), and sealing was required.\n  \
                 Writing the key in the clear instead would turn off a control\n  \
                 that was deliberately turned on, so this refuses. Unset the\n  \
                 TPM requirement if a plaintext key is what you want."
            );
            KeyError::Env(rv)
        })?);
        write_new(&blob_path, &blob).map_err(|_| KeyError::Failed)?;
        return Ok(Provisioned { key, sealed: true });
    }

    if write_new(&plain, &*key).is_err() {
        // Lost a race, most likely. Whoever won wrote a key; use theirs.
        return read_key(&plain)
            .map(|key| Provisioned { key, sealed: false })
            .ok_or(KeyError::Failed);
    }
    Ok(Provisioned { key, sealed: false })
}

fn in_dir(dir: &[u8], leaf: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from_vec([dir, leaf].concat()))
}

fn why(what: &str, path: &Path, e: &io::Error) {
    warn!("[pqhsm] audit key : {what} {}: {e}", path.display());
}

/// The first 2048 bytes of the blob, or `None` if it is missing, unreadable or empty.
fn read_blob(path: &Path) -> Option<Zeroizing<Vec<u8>>> {
    let mut blob = Zeroizing::new(Vec::new());
    File::open(path)
        .ok()?
        .take(BLOB_MAX)
        .read_to_end(&mut blob)
        .ok()?;
    (!blob.is_empty()).then_some(blob)
}

fn read_key(path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            if e.kind() != io::ErrorKind::NotFound {
                why("cannot open", path, &e);
            }
            return None;
        }
    };
    let md = f
        .metadata()
        .map_err(|e| why("cannot stat", path, &e))
        .ok()?;
    if md.mode() & 0o077 != 0 {
        warn!(
            "[pqhsm] audit key : {} is mode {:04o} -- readable by group\n  \
             or others, and refused on purpose. A log authenticated by a\n  \
             key others can read is not authenticated. chmod 600 it, or\n  \
             remove it to have a new one generated.",
            path.display(),
            md.mode() & 0o7777
        );
        return None;
    }
    if md.len() != 32 {
        warn!(
            "[pqhsm] audit key : {} is {} bytes, expected 32.",
            path.display(),
            md.len()
        );
        return None;
    }
    let mut key = Zeroizing::new([0u8; 32]);
    f.read_exact(&mut *key)
        .map_err(|e| why("short read on", path, &e))
        .ok()?;
    Some(key)
}

/// Create `path` with `O_EXCL`, mode 0600, and make `data` durable; on a failed write the
/// file is removed.
fn write_new(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .inspect_err(|e| {
            if e.kind() != io::ErrorKind::AlreadyExists {
                why("cannot create", path, e);
            }
        })?;
    if let Err(e) = f.write_all(data).and_then(|()| f.sync_all()) {
        why("cannot write", path, &e);
        drop(f);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}
