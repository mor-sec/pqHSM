//! Shared helpers for the pqhsm-token TPM characterization tests. Every expected value is in
//! `golden/tpm/`, produced by running the legacy C code: `legacy/hybrid/golden/regen_tpm.sh`.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};

use pqhsm_token::Rv;
use pqhsm_token::tpm::{Cli, Tpm};

/// The invented, non-secret secret every golden seals: bytes 0x00..=0x1f.
pub const S: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = i as u8;
        i += 1;
    }
    k
};

/// The PCR state the stub reports unless a case says otherwise (gen_tpm.c `PCR`).
pub const PCR: &str = "golden-pcr";

pub fn golden(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/tpm")
        .join(rel)
}

/// `golden/tpm/<rel>` as text, or "" when C produced no such file (the stub never ran).
pub fn golden_text(rel: &str) -> String {
    fs::read_to_string(golden(rel)).unwrap_or_default()
}

/// One row of `cases.tsv`: case, op, rv, then key=value columns.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub op: String,
    pub rv: String,
    kv: BTreeMap<String, String>,
}

impl Case {
    pub fn get(&self, k: &str) -> &str {
        self.opt(k)
            .unwrap_or_else(|| panic!("{}: no `{k}` column", self.name))
    }
    pub fn opt(&self, k: &str) -> Option<&str> {
        self.kv.get(k).map(String::as_str)
    }
    pub fn is(&self, k: &str, v: &str) -> bool {
        self.opt(k) == Some(v)
    }
}

pub fn cases() -> Vec<Case> {
    let text = fs::read_to_string(golden("cases.tsv"))
        .unwrap_or_else(|e| panic!("golden/tpm/cases.tsv: {e} (run regen_tpm.sh)"));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| {
            let mut f = l.split('\t');
            let (name, op, rv) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
            let kv = f
                .map(|c| {
                    let (k, v) = c.split_once('=').unwrap();
                    (k.to_owned(), v.to_owned())
                })
                .collect();
            Case {
                name: name.into(),
                op: op.into(),
                rv: rv.into(),
                kv,
            }
        })
        .collect()
}

pub fn case(name: &str) -> Case {
    cases()
        .into_iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("no golden row {name}"))
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// A result printed the way gen_tpm.c prints `fhsm_rv_t`: `0x%x`.
pub fn rv_text<T>(r: &Result<T, Rv>) -> String {
    match r {
        Ok(_) => "0x0".into(),
        Err(Rv(v)) => format!("{v:#x}"),
    }
}

// ---------------------------------------------------------------------------------------
// The stub-backed TPM fixture
// ---------------------------------------------------------------------------------------

/// A temp dir with a fake device node, the stub's log and the probe's log in it.
pub struct Fx {
    pub dir: tempfile::TempDir,
    pub device: PathBuf,
    pub log: PathBuf,
    pub probe_log: PathBuf,
}

impl Fx {
    pub fn new() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("tpmrm0");
        fs::write(&device, b"").unwrap();
        Fx {
            device,
            log: dir.path().join("fake.log"),
            probe_log: dir.path().join("probe.log"),
            dir,
        }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The `Tpm` a golden row ran against: its `device`, `cmd`, `cmd_prefix`, `env` and `stub`
    /// columns, plus the knobs gen_tpm.c sets for every case. Everything the stub reads is
    /// passed in the command line as shell assignments, never through this process's
    /// environment, so tests can run in parallel. `extra` is appended to the assignments.
    pub fn tpm(&self, c: &Case, extra: &str) -> Tpm {
        match c.opt("device") {
            Some("absent") => fs::remove_file(&self.device).unwrap(),
            Some("dir") => {
                fs::remove_file(&self.device).unwrap();
                fs::create_dir(&self.device).unwrap();
            }
            None => {}
            Some(d) => panic!("{}: device={d}", c.name),
        }
        if let Some(cmd) = c.opt("cmd") {
            return Tpm::new(&self.device, Cli::Shell(cmd.to_owned()));
        }
        let stub = golden("tpm2-stub.sh");
        let probe = c.is("stub", "probe");
        let mut cmd = format!(
            "FHSM_TPM_FAKE_LOG='{}' FHSM_TPM_FAKE_PCR={PCR} FHSM_TPM_REAL_STUB='{}'",
            self.log.display(),
            stub.display()
        );
        if probe {
            cmd += &format!(" FHSM_TPM_PROBE_LOG='{}'", self.probe_log.display());
        }
        for part in [
            c.opt("env").unwrap_or(""),
            extra,
            c.opt("cmd_prefix").unwrap_or(""),
        ] {
            if !part.is_empty() {
                cmd += " ";
                cmd += part;
            }
        }
        let script = if probe {
            golden("tpm2-probe-stub.sh")
        } else {
            stub
        };
        cmd += &format!(" sh '{}'", script.display());
        Tpm::new(&self.device, Cli::Shell(cmd))
    }

    /// gen_tpm.c `ready()`: probe once, then forget the logs, so a case's logs hold only its
    /// own subcommands. Skipped for rows with `device=absent` or `pre=not_available_yet`.
    pub fn ready(&self, c: &Case, tpm: &Tpm) {
        if c.is("device", "absent") || c.is("pre", "not_available_yet") {
            return;
        }
        assert!(
            tpm.available(),
            "{}: the stub TPM must be available",
            c.name
        );
        let _ = fs::remove_file(&self.log);
        let _ = fs::remove_file(&self.probe_log);
    }

    pub fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The case's subcommands match C's, argv for argv (fd numbers normalised), and nothing
    /// but anonymous memfds was handed over. With a probe golden, the probe checks too.
    pub fn check_logs(&self, c: &Case) {
        assert_eq!(
            normalise_log(&self.log()),
            normalise_log(&golden_text(&format!("log/{}.txt", c.name))),
            "{}: tpm2 subcommands",
            c.name
        );
        let probe = golden_text(&format!("probe/{}.txt", c.name));
        if !probe.is_empty() {
            check_probe(
                &c.name,
                &fs::read_to_string(&self.probe_log).unwrap_or_default(),
                &probe,
            );
        }
    }
}

/// FHSM_TPM_FAKE_LOG with each distinct `/proc/self/fd/N` renamed `fd#1`, `fd#2`, ... in order
/// of first appearance, so identity (the policy `createpolicy` writes is the one `create`
/// reads) is kept and the numbers are not. Panics on any other absolute path: #109, the DEK
/// must never be handed to tpm2 as a file on a filesystem.
pub fn normalise_log(log: &str) -> String {
    let mut seen: Vec<String> = Vec::new();
    let mut out = String::new();
    for line in log.lines() {
        let words: Vec<String> = line
            .split_whitespace()
            .map(|w| {
                if let Some(n) = w.strip_prefix("/proc/self/fd/") {
                    assert!(n.parse::<u32>().is_ok(), "not /proc/self/fd/N: {w}");
                    let i = seen.iter().position(|s| s == w).unwrap_or_else(|| {
                        seen.push(w.to_owned());
                        seen.len() - 1
                    });
                    format!("fd#{}", i + 1)
                } else {
                    assert!(
                        !w.starts_with('/'),
                        "a filesystem path was handed to tpm2: {w}"
                    );
                    w.to_owned()
                }
            })
            .collect();
        out += &words.join(" ");
        out.push('\n');
    }
    out
}

/// Probe lines: `argv|fd1=..|fd2=..|inherited=a,b,..`. argv (memfd names in place of paths)
/// and the child's stdout/stderr must be C's. DIV-017 lets the inherited set shrink: it must
/// still hold every memfd the argv names, and nothing C's child did not already see.
pub fn check_probe(case: &str, rust: &str, c: &str) {
    let parse = |s: &str| -> Vec<(String, String, String, Vec<String>)> {
        s.lines()
            .map(|l| {
                let f: Vec<&str> = l.split('|').collect();
                assert_eq!(f.len(), 4, "{case}: probe line {l}");
                let inh = f[3].strip_prefix("inherited=").unwrap();
                (
                    f[0].to_owned(),
                    f[1].to_owned(),
                    f[2].to_owned(),
                    inh.split(',')
                        .filter(|x| !x.is_empty())
                        .map(str::to_owned)
                        .collect(),
                )
            })
            .collect()
    };
    let (r, c) = (parse(rust), parse(c));
    assert_eq!(r.len(), c.len(), "{case}: number of tpm2 children");
    for ((ra, r1, r2, rin), (ca, c1, c2, cin)) in r.iter().zip(&c) {
        assert_eq!(ra, ca, "{case}: argv, memfd names in place of paths");
        assert_eq!((r1, r2), (c1, c2), "{case}: child stdout/stderr");
        for w in ra.split(' ').filter(|w| w.starts_with('<')) {
            let name = w.trim_start_matches('<').trim_end_matches('>');
            assert!(
                rin.iter().any(|x| x == name),
                "{case}: {name} named in argv but not inherited"
            );
        }
        for x in rin {
            assert!(
                cin.contains(x),
                "{case}: child inherited {x}, which C's did not"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// Companion-file fixtures (gen_tpm.c `tok_for`, `prepare`, `kvstate`)
// ---------------------------------------------------------------------------------------

/// A path exactly `n` bytes long under `base`, directories created. Mirrors gen_tpm.c
/// `tok_len`: 150-byte `d` directories while more than 200 bytes remain, then a `t` file name.
pub fn path_of_len(base: &Path, n: usize) -> PathBuf {
    let mut p = base.as_os_str().to_str().unwrap().to_owned();
    while n - p.len() > 200 {
        p.push('/');
        p += &"d".repeat(150);
        fs::create_dir_all(&p).unwrap();
    }
    p.push('/');
    let rest = n - p.len();
    p += &"t".repeat(rest);
    assert_eq!(p.len(), n);
    PathBuf::from(p)
}

pub fn with(tok: &Path, suffix: &str) -> PathBuf {
    let mut s = tok.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// The token path a row's `tok` column describes.
pub fn tok_for(base: &Path, c: &Case) -> PathBuf {
    match c.get("tok") {
        "plain" => base.join("t.tok"),
        "nodir" => base.join("nodir/t.tok"),
        spec => path_of_len(base, spec.strip_prefix("len:").unwrap().parse().unwrap()),
    }
}

/// Recreate the row's `pre` state next to `tok`. For `fifo_tmp` the returned file is the
/// FIFO's non-blocking read end, opened before the call as gen_tpm.c does.
pub fn prepare(tok: &Path, c: &Case) -> Option<fs::File> {
    let tpm = with(tok, ".tpm");
    match c.opt("pre") {
        None => None,
        Some("dir") => {
            fs::create_dir(&tpm).unwrap();
            None
        }
        Some("dir_nonempty") => {
            fs::create_dir(&tpm).unwrap();
            fs::write(tpm.join("keep"), b"k").unwrap();
            None
        }
        Some("fifo_tmp") => {
            let tmp = with(tok, ".tpm.new");
            let st = std::process::Command::new("mkfifo")
                .arg("-m")
                .arg("600")
                .arg(&tmp)
                .status()
                .unwrap();
            assert!(st.success(), "mkfifo");
            use std::os::unix::fs::OpenOptionsExt;
            const O_NONBLOCK: i32 = 0o4000; // Linux, every architecture the image builds for
            Some(
                fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(O_NONBLOCK)
                    .open(&tmp)
                    .unwrap(),
            )
        }
        Some(kind) => {
            let bytes = unhex(golden_text(&format!("input/{}.hex", c.name)).trim());
            fs::write(&tpm, bytes).unwrap();
            if kind == "unreadable" {
                fs::set_permissions(&tpm, fs::Permissions::from_mode(0o000)).unwrap();
            }
            None
        }
    }
}

/// gen_tpm.c `kvstate`: absent | dir | fifo | file:MODE:HEX | file:MODE:unreadable
pub fn state(path: &Path) -> String {
    let Ok(m) = fs::symlink_metadata(path) else {
        return "absent".into();
    };
    if m.is_dir() {
        return "dir".into();
    }
    if m.file_type().is_fifo() {
        return "fifo".into();
    }
    let head = format!("file:{:04o}:", m.permissions().mode() & 0o7777);
    match fs::read(path) {
        Ok(b) => head + &hex(&b),
        Err(_) => head + "unreadable",
    }
}

/// True when this process can read a mode-000 file (root with CAP_DAC_OVERRIDE). The
/// "unreadable companion" goldens were made without that capability.
pub fn privileged() -> bool {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("probe");
    fs::write(&p, b"x").unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
    fs::read(&p).is_ok()
}

pub fn require_unprivileged(case: &str) {
    assert!(
        !privileged(),
        "{case}: this process can read a mode-000 file, so it cannot reproduce the golden. \
         Run the container with --cap-drop=DAC_OVERRIDE,DAC_READ_SEARCH (tests/README.md)."
    );
}
