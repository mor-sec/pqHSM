//! TPM 2.0 sealing of the 32-byte token DEK through the `tpm2` CLI over memfds
//! (`src/fhsm_tpm.c`), and the `{tok}.tpm` companion file (`src/fhsm_token_tpm.c`).

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use crate::Rv;
use crate::ffi::sys;

const PCR_LIST: &str = "sha256:0,1,2,3,4,5,6,7";
const PARENT_HANDLE: &str = "0x81010001";
/// C's `TPM_DIR`: created by the first successful probe, used by nothing since #109.
const TPM_DIR: &str = "/var/lib/freehsm/tpm";
/// Largest pub or priv part C packs (DIV-018: a larger one is an error, not cut short).
const PART_MAX: usize = 512;
/// C's `char tpm_path[1024]`, NUL included.
const PATH_MAX: usize = 1024;
/// The companion file is read in one `read` of at most this many bytes, as C does.
const BLOB_MAX: usize = 2048;

/// How the `tpm2` CLI is started.
pub enum Cli {
    /// Production: exec this program directly with the subcommand argv (no shell).
    /// Its stdout and stderr go to /dev/null, as C's `>/dev/null 2>&1` did.
    Exec(PathBuf),
    /// Hooks mode only (DIV-017): `sh -c "<this string> <subcommand args>"`, exactly how
    /// C's `system()` split `FHSM_TPM_CMD`, so `"FOO=1 sh tests/tpm2-stub.sh"` works.
    #[cfg(feature = "tpm-test-hooks")]
    Shell(String),
}

/// One TPM: the device node probed by [`Tpm::available`] and the CLI used to reach it.
pub struct Tpm {
    device: PathBuf,
    cli: Cli,
    available: OnceLock<bool>,
}

/// A memfd and the `/proc/self/fd/N` path the child reaches it by.
struct Mem {
    file: File,
    path: String,
}

impl Mem {
    fn new(name: &str, data: &[u8]) -> Result<Mem, Rv> {
        let mut file = sys::memfd(name).map_err(|_| Rv::FUNCTION_FAILED)?;
        if !data.is_empty() {
            file.write_all(data).map_err(|_| Rv::FUNCTION_FAILED)?;
            file.rewind().map_err(|_| Rv::FUNCTION_FAILED)?;
        }
        let path = format!("/proc/self/fd/{}", file.as_raw_fd());
        Ok(Mem { file, path })
    }

    /// One `read` from offset 0, as C's `memfd_read` does.
    fn read(&mut self, out: &mut [u8]) -> Result<usize, Rv> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| Rv::FUNCTION_FAILED)?;
        self.file.read(out).map_err(|_| Rv::FUNCTION_FAILED)
    }
}

impl Tpm {
    /// C: `tpm_device()` / `tpm_cmd()`. Production is `/dev/tpmrm0` + `Cli::Exec("tpm2")`.
    pub fn new(device: impl Into<PathBuf>, cli: Cli) -> Tpm {
        Tpm {
            device: device.into(),
            cli,
            available: OnceLock::new(),
        }
    }

    /// Run one subcommand; true if it exited 0. Only `mems` reach the child.
    fn run(&self, args: &[&str], mems: &[&Mem]) -> bool {
        let mut cmd = match &self.cli {
            Cli::Exec(program) => {
                let mut c = Command::new(program);
                c.args(args);
                c
            }
            #[cfg(feature = "tpm-test-hooks")]
            Cli::Shell(line) => {
                let mut c = Command::new("sh");
                c.arg("-c").arg(format!("{line} {}", args.join(" ")));
                c
            }
        };
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
        sys::inherit(&mut cmd, &mems.iter().map(|m| &m.file).collect::<Vec<_>>());
        cmd.status().is_ok_and(|s| s.success())
    }

    /// `fhsm_tpm_available`: `access(device, F_OK)`, then `tpm2 startup -c` must exit 0.
    /// The answer, yes or no, is cached for the life of this `Tpm`. On the first yes it
    /// also runs C's `mkdir("/var/lib/freehsm/tpm", 0700)`, errors ignored.
    pub fn available(&self) -> bool {
        *self.available.get_or_init(|| {
            if !sys::access(&self.device, libc::F_OK) || !self.run(&["startup", "-c"], &[]) {
                return false;
            }
            let _ = DirBuilder::new().mode(0o700).create(TPM_DIR);
            true
        })
    }

    /// `fhsm_tpm_seal`: writes `TPS1 | pub_len u32le | priv_len u32le | pub | priv` into
    /// `out` and returns its length. Fails with `TPM_UNAVAILABLE` if `available()` is
    /// false, otherwise `FUNCTION_FAILED`, with `out` left untouched.
    pub fn seal(&self, secret: &[u8; 32], out: &mut [u8]) -> Result<usize, Rv> {
        if !self.available() {
            return Err(Rv::TPM_UNAVAILABLE);
        }
        let input = Mem::new("fhsm-seal-in", secret)?;
        let policy = Mem::new("fhsm-seal-policy", &[])?;
        let mut public = Mem::new("fhsm-seal-pub", &[])?;
        let mut private = Mem::new("fhsm-seal-priv", &[])?;
        let ok = self.run(
            &[
                "createpolicy",
                "--policy-pcr",
                "-l",
                PCR_LIST,
                "-L",
                &policy.path,
            ],
            &[&policy],
        ) && self.run(
            &[
                "create",
                "-C",
                PARENT_HANDLE,
                "-i",
                &input.path,
                "-u",
                &public.path,
                "-r",
                &private.path,
                "-L",
                &policy.path,
                "-g",
                "sha256",
            ],
            &[&input, &public, &private, &policy],
        );
        if !ok {
            return Err(Rv::FUNCTION_FAILED);
        }
        // one byte more than C kept, so that an output that does not fit is seen (DIV-018)
        let (mut pub_buf, mut priv_buf) = ([0u8; PART_MAX + 1], [0u8; PART_MAX + 1]);
        let pub_len = public.read(&mut pub_buf)?;
        let priv_len = private.read(&mut priv_buf)?;
        let total = 12 + pub_len + priv_len;
        if !(1..=PART_MAX).contains(&pub_len)
            || !(1..=PART_MAX).contains(&priv_len)
            || total > out.len()
        {
            return Err(Rv::FUNCTION_FAILED);
        }
        out[..4].copy_from_slice(b"TPS1");
        out[4..8].copy_from_slice(&(pub_len as u32).to_le_bytes());
        out[8..12].copy_from_slice(&(priv_len as u32).to_le_bytes());
        out[12..12 + pub_len].copy_from_slice(&pub_buf[..pub_len]);
        out[12 + pub_len..total].copy_from_slice(&priv_buf[..priv_len]);
        Ok(total)
    }

    /// `fhsm_tpm_unseal`. `out` is zeroed once the header checks pass, so every later
    /// failure leaves zeros. The earlier failures (`TPM_UNAVAILABLE`, `ARGUMENTS_BAD` for
    /// fewer than 12 bytes, `FUNCTION_FAILED` for bad magic or lengths) leave it untouched.
    pub fn unseal(&self, blob: &[u8], out: &mut [u8; 32]) -> Result<(), Rv> {
        if !self.available() {
            return Err(Rv::TPM_UNAVAILABLE);
        }
        if blob.len() < 12 {
            return Err(Rv::ARGUMENTS_BAD);
        }
        if &blob[..4] != b"TPS1" {
            return Err(Rv::FUNCTION_FAILED);
        }
        let pub_len = u32::from_le_bytes(blob[4..8].try_into().unwrap()) as u64;
        let priv_len = u32::from_le_bytes(blob[8..12].try_into().unwrap()) as u64;
        if 12 + pub_len + priv_len != blob.len() as u64 {
            return Err(Rv::FUNCTION_FAILED);
        }
        *out = [0; 32];
        let (public, private) = blob[12..].split_at(pub_len as usize);
        let public = Mem::new("fhsm-unseal-pub", public)?;
        let private = Mem::new("fhsm-unseal-priv", private)?;
        let policy = Mem::new("fhsm-unseal-policy", &[])?;
        let ctx = Mem::new("fhsm-unseal-ctx", &[])?;
        let mut secret = Mem::new("fhsm-unseal-out", &[])?;
        let pcr = format!("pcr:{PCR_LIST}");
        let ok = self.run(
            &[
                "createpolicy",
                "--policy-pcr",
                "-l",
                PCR_LIST,
                "-L",
                &policy.path,
            ],
            &[&policy],
        ) && self.run(
            &[
                "load",
                "-C",
                PARENT_HANDLE,
                "-u",
                &public.path,
                "-r",
                &private.path,
                "-c",
                &ctx.path,
            ],
            &[&public, &private, &ctx],
        ) && self.run(
            &["unseal", "-c", &ctx.path, "-p", &pcr, "-o", &secret.path],
            &[&ctx, &secret],
        );
        if !ok {
            return Err(Rv::FUNCTION_FAILED);
        }
        // exactly 32 bytes back, never the first 32 of more (DIV-018)
        let mut got = [0u8; 33];
        let n = secret.read(&mut got)?;
        if n == 32 {
            out.copy_from_slice(&got[..32]);
        }
        got.fill(0);
        if n == 32 {
            Ok(())
        } else {
            Err(Rv::FUNCTION_FAILED)
        }
    }

    /// `fhsm_token_tpm_seal`: seal `dek`, then create `{tok}.tpm.new` (0600, `O_EXCL|O_NOFOLLOW`,
    /// DIV-031), fsync it (DIV-015), and rename it to `{tok}.tpm`.
    pub fn seal_companion(&self, tok_path: &Path, dek: &[u8; 32]) -> Result<(), Rv> {
        if !self.available() {
            return Err(Rv::TPM_UNAVAILABLE);
        }
        let tpm_path = companion_path(tok_path).ok_or(Rv::ARGUMENTS_BAD)?;
        let mut blob = [0u8; BLOB_MAX];
        let n = self.seal(dek, &mut blob)?;
        let tmp = suffixed(&tpm_path, ".new");
        if tmp.as_os_str().len() >= PATH_MAX {
            return Err(Rv::FUNCTION_FAILED);
        }
        // DIV-031(b): a link (or anything) planted at the tmp name is removed, never written through
        let _ = fs::remove_file(&tmp);
        let written = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600)
            .open(&tmp)
            .and_then(|mut f| {
                f.write_all(&blob[..n])?;
                f.sync_all()
            });
        if written.is_err() || fs::rename(&tmp, &tpm_path).is_err() {
            let _ = fs::remove_file(&tmp);
            return Err(Rv::FUNCTION_FAILED);
        }
        Ok(())
    }

    /// `fhsm_token_tpm_unseal`: read at most 2048 bytes of `{tok}.tpm` in one read, then
    /// `unseal`.
    pub fn unseal_companion(&self, tok_path: &Path, out: &mut [u8; 32]) -> Result<(), Rv> {
        if !self.available() {
            return Err(Rv::TPM_UNAVAILABLE);
        }
        let tpm_path = companion_path(tok_path).ok_or(Rv::ARGUMENTS_BAD)?;
        let mut blob = [0u8; BLOB_MAX];
        let n = File::open(&tpm_path)
            .and_then(|mut f| f.read(&mut blob))
            .map_err(|_| Rv::FUNCTION_FAILED)?;
        if n == 0 {
            return Err(Rv::FUNCTION_FAILED);
        }
        self.unseal(&blob[..n], out)
    }
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    s.into()
}

/// `fhsm_token_tpm_required`, given the value of `FHSM_TPM_SEALING`. Only the first byte
/// counts.
pub fn sealing_required_value(value: Option<&OsStr>) -> bool {
    matches!(
        value.and_then(|v| v.as_bytes().first()),
        Some(b'1' | b'y' | b'Y')
    )
}

/// `build_tpm_path`: `{tok}.tpm`, or `None` when it would not fit C's 1024-byte buffer
/// with its NUL.
pub fn companion_path(tok_path: &Path) -> Option<PathBuf> {
    (tok_path.as_os_str().len() + ".tpm".len() < PATH_MAX).then(|| suffixed(tok_path, ".tpm"))
}

/// `fhsm_token_tpm_blob_exists`: `access({tok}.tpm, R_OK) == 0`.
pub fn companion_exists(tok_path: &Path) -> bool {
    companion_path(tok_path).is_some_and(|p| sys::access(&p, libc::R_OK))
}

/// `fhsm_token_tpm_dek_match`: constant-time equality.
pub fn dek_match(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// `fhsm_token_tpm_unlink`: best-effort `unlink({tok}.tpm)`.
pub fn unlink_companion(tok_path: &Path) {
    if let Some(p) = companion_path(tok_path) {
        let _ = fs::remove_file(p);
    }
}
