//! `fhsm-sign`: detached signatures with a key held in a PKCS#11 module (`tools/fhsm_sign.c`,
//! PHASE5_PLAN.md slice 4). Flags, messages and exit codes are C's; the PIN is FHSM_PIN's, or
//! asked for at a terminal (DIV-072); `cms-verify` names the signer and takes `--signer`
//! (DIV-075). There is no --pin: an argument is visible in `ps` to every user on the machine.

use std::ffi::{CStr, CString, OsStr, c_long};
use std::fs::File;
use std::io::{self, BufWriter, Read, Write};
use std::mem::ManuallyDrop;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::process::exit;

use pqhsm_cli::{fail, fill, init, perror_exit, pin};
use pqhsm_pkiops::ops::{self, Session};
use pqhsm_pkiops::sign::{self, Hash, Signing, Verdict, Verifying};
use pqhsm_pkiops::{Error, Intent, close, open, parse_slot, strerror};

const PROG: &str = "fhsm-sign";

/// 1 MiB: large enough that the syscall and PKCS#11 crossing cost nothing measurable, small
/// enough to sign from a pipe without buffering the whole stream.
const CHUNK: usize = 1 << 20;

/// `fhsm_sign.c`'s signature buffer: a file this size is larger than any signature.
const SIG_ROOM: usize = 65536;

const USAGE: &str = concat!(
    "fhsm-sign --- detached signatures with a key held in a PKCS#11 module\n\n",
    "  fhsm-sign sign       --label NAME [--in FILE] [--out FILE]\n",
    "  fhsm-sign verify     --label NAME --sig FILE [--in FILE]\n",
    "  fhsm-sign cms        --label NAME --cert FILE [--in FILE] [--out FILE]\n",
    "  fhsm-sign cms-verify --cms FILE [--in FILE] [--signer CERT]\n\n",
    "  --label NAME    label of the key inside the module. sign uses the\n",
    "                  private key of that label, verify the public one, each\n",
    "                  with the algorithm the key was generated for.\n",
    "  --in FILE       data to sign or check (default: standard input)\n",
    "  --out FILE      where to write the signature (default: standard output)\n",
    "  --sig FILE      the signature to check\n",
    "  --cert FILE     the signer's certificate (DER or PEM), for cms\n",
    "  --cms FILE      the CMS structure to check\n",
    "  --signer CERT   for cms-verify: the certificate (DER or PEM) the CMS must\n",
    "                  be signed under; one signed under any other exits 4\n",
    "  --module PATH   PKCS#11 module (default ./libfreehsm.so)\n",
    "  --slot N        slot to address. Default: the one slot holding a token.\n\n",
    "  The PIN is read from FHSM_PIN. There is no --pin option: an argument\n",
    "  is visible in ps to every user on the machine.\n\n",
    "  The signature is raw and detached -- the bytes, nothing around them.\n",
    "  It does not record which key or algorithm made it, so a verifier has\n",
    "  to be told. That is what cms, below, carries.\n",
    "  An ECDSA signature is written as DER, which openssl dgst -verify reads.\n\n",
    "  Input is streamed: this tool never holds it. The module may -- FreeHSM\n",
    "  hashes a composite signature's input as it arrives, and holds the\n",
    "  input of the other algorithms until the end. cms is never bounded:\n",
    "  only a digest reaches the module.\n\n",
    "  cms produces a detached RFC 5652 SignedData with signed attributes,\n",
    "  carrying the signer's certificate. Unlike the raw form it records\n",
    "  which key and which algorithm made it -- so cms-verify needs neither\n",
    "  the token nor a label, only the file and the data.\n\n",
    "  Exit codes: 0 success. 1 usage or FHSM_PIN unset. 2 module or I/O\n",
    "  failure. 3 no such key, or more than one with that label.\n",
    "  4 the signature does not match -- and only that.\n",
);

fn usage() -> ! {
    eprint!("{USAGE}");
    exit(1)
}

fn die(e: Error) -> ! {
    fail(PROG, &e)
}

/// Bytes on stderr: paths and labels need not be UTF-8.
fn say(parts: &[&[u8]]) {
    let mut w = io::stderr().lock();
    for p in parts {
        let _ = w.write_all(p);
    }
}

fn cannot(what: &[u8], path: &[u8], e: &io::Error) -> ! {
    say(&[
        b"fhsm-sign: cannot ",
        what,
        b" ",
        path,
        b": ",
        strerror(e).as_bytes(),
        b"\n",
    ]);
    exit(2)
}

#[derive(Default)]
struct Opts<'a> {
    module: &'a [u8],
    label: Option<&'a [u8]>,
    input: Option<&'a [u8]>,
    out: Option<&'a [u8]>,
    sig: Option<&'a [u8]>,
    cert: Option<&'a [u8]>,
    cms: Option<&'a [u8]>,
    signer: Option<&'a [u8]>,
    slot: c_long,
}

/// `parse`: every subcommand takes every option, and ignores what it does not use.
fn parse(args: &[Vec<u8>]) -> Opts<'_> {
    let mut o = Opts {
        module: b"./libfreehsm.so",
        slot: -1,
        ..Opts::default()
    };
    let mut i = 2;
    while i < args.len() {
        let a = &args[i][..];
        let next = args.get(i + 1).map(|v| &v[..]);
        match (a, next) {
            (b"--module", Some(v)) => o.module = v,
            (b"--label", Some(v)) => o.label = Some(v),
            (b"--in", Some(v)) => o.input = Some(v),
            (b"--out", Some(v)) => o.out = Some(v),
            (b"--sig", Some(v)) => o.sig = Some(v),
            (b"--cert", Some(v)) => o.cert = Some(v),
            (b"--cms", Some(v)) => o.cms = Some(v),
            (b"--signer", Some(v)) => o.signer = Some(v),
            (b"--slot", Some(v)) => o.slot = parse_slot(v).unwrap_or_else(|e| die(e)),
            _ if a.starts_with(b"--pin") => {
                eprint!(
                    "fhsm-sign: --pin is not accepted. Set FHSM_PIN instead:\n  an argument is visible in ps to every user on this machine.\n"
                );
                exit(1);
            }
            _ => usage(),
        }
        i += 2;
    }
    o
}

/// `open_in`: the input, or standard input for "-" or none.
fn open_in(path: Option<&[u8]>) -> Box<dyn Read> {
    match path {
        None | Some(b"-") => Box::new(io::stdin().lock()),
        Some(p) => match File::open(OsStr::from_bytes(p)) {
            Ok(f) => Box::new(f),
            Err(e) => cannot(b"read", p, &e),
        },
    }
}

/// `stream_into`: the whole stream to `feed`, in blocks. sign, verify and the digests share
/// it, so they cannot disagree about what they consumed.
fn stream(r: &mut dyn Read, mut feed: impl FnMut(&[u8])) {
    let mut buf = vec![0u8; CHUNK];
    loop {
        let (n, e) = fill(r, &mut buf);
        if n > 0 {
            feed(&buf[..n]);
        }
        if n < CHUNK {
            if let Some(e) = e {
                eprintln!("fhsm-sign: read failed: {}", strerror(&e));
                exit(2);
            }
            break; // a short read means the end
        }
    }
}

/// `open_session`: the PIN and the login, shared so the subcommands cannot drift on them.
fn open_session(module: &[u8], slot: c_long) -> Session {
    let pin = pin(
        PROG,
        "FHSM_PIN",
        "user PIN",
        "fhsm-sign: FHSM_PIN is not set.\n",
    );
    let module = CString::new(module).expect("no NUL in an argument");
    let sid = open(Some(&module), slot, Intent::WithToken).unwrap_or_else(|e| die(e));
    ops::session_user(sid, &pin).unwrap_or_else(|e| die(e))
}

fn close_session(s: Session) {
    ops::session_close(s);
    close();
}

/// glibc's stdio buffer: a write this size or larger goes straight to the file.
const STDIO_BUF: usize = 4096;

/// The signature or CMS to `path`, or standard output, as C's stdio writes it: through a
/// 4096-byte buffer, the file's close checked (where a buffered write fails), standard
/// output's flush not. A failure exits 2 with nothing closed, as C returns.
fn emit(path: Option<&[u8]>, data: &[u8]) {
    let Some(p) = path else {
        // SAFETY: fd 1, borrowed, never closed here; nothing has been written to it before.
        let fd1 = ManuallyDrop::new(unsafe { File::from_raw_fd(1) });
        let mut w = BufWriter::with_capacity(STDIO_BUF, &*fd1);
        if let Err(e) = w.write_all(data) {
            perror_exit("fhsm-sign: write", &e);
        }
        let _ = w.flush(); // C ignores what fflush returns
        return;
    };
    let f = File::create(OsStr::from_bytes(p)).unwrap_or_else(|e| cannot(b"write", p, &e));
    let mut w = BufWriter::with_capacity(STDIO_BUF, f);
    if let Err(e) = w.write_all(data) {
        perror_exit("fhsm-sign: write", &e);
    }
    // fclose: the buffered bytes, then the descriptor, each failure C's "close".
    let f = w
        .into_inner()
        .unwrap_or_else(|e| perror_exit("fhsm-sign: close", e.error()));
    // SAFETY: f's descriptor, closed once, here.
    if unsafe { libc::close(f.into_raw_fd()) } != 0 {
        perror_exit("fhsm-sign: close", &io::Error::last_os_error());
    }
}

fn read_der(path: &[u8]) -> Vec<u8> {
    sign::read_der(Path::new(OsStr::from_bytes(path))).unwrap_or_else(|e| die(e))
}

fn cmd_sign(o: &Opts) -> i32 {
    let Some(label) = o.label else { usage() };
    let mut input = open_in(o.input);
    let s = open_session(o.module, o.slot);
    let op = Signing::begin(s, label).unwrap_or_else(|e| die(e));
    stream(&mut *input, |b| op.update(b).unwrap_or_else(|e| die(e)));
    drop(input);
    let sig = op.end().unwrap_or_else(|e| die(e));
    emit(o.out, &sig);
    eprintln!("fhsm-sign: {}-byte detached signature.", sig.len());
    close_session(s);
    0
}

/// The signature file, whole: a file of `SIG_ROOM` bytes or more is not one.
fn read_sig(path: &[u8]) -> Vec<u8> {
    let mut f = File::open(OsStr::from_bytes(path)).unwrap_or_else(|e| cannot(b"read", path, &e));
    let mut buf = vec![0u8; SIG_ROOM];
    let (n, e) = fill(&mut f, &mut buf);
    let (lead, fault): (&[u8], &[u8]) = if e.is_some() {
        (b"fhsm-sign: reading ", b" failed\n")
    } else if n == 0 {
        (b"fhsm-sign: ", b" is empty\n")
    } else if n == SIG_ROOM {
        (
            b"fhsm-sign: ",
            b" is larger than any signature this tool produces\n",
        )
    } else {
        buf.truncate(n);
        return buf;
    };
    say(&[lead, path, fault]);
    exit(2)
}

fn cmd_verify(o: &Opts) -> i32 {
    let (Some(label), Some(sig_path)) = (o.label, o.sig) else {
        usage()
    };
    // The signature first: a missing or unreadable one fails before the operator is asked for
    // anything and before a stream is consumed.
    let sig = read_sig(sig_path);
    let mut input = open_in(o.input);
    let s = open_session(o.module, o.slot);
    let op = Verifying::begin(s, label).unwrap_or_else(|e| die(e));
    stream(&mut *input, |b| op.update(b).unwrap_or_else(|e| die(e)));
    drop(input);
    let r = op.end(&sig);
    close_session(s);
    // A bad signature is not a tool failure: its own exit code, so a script can tell "did
    // not verify" from "could not run".
    if !r.unwrap_or_else(|e| die(e)) {
        say(&[
            b"fhsm-sign: the signature does not match this data under key \"",
            label,
            b"\".\n",
        ]);
        return 4;
    }
    eprintln!("fhsm-sign: signature verified.");
    0
}

/// The CMS digests of a stream, all three in the one pass: which one a CMS uses depends on
/// the key that signs it or on the structure checked, and the data is read, perhaps from a
/// pipe, before either is known.
const DIGESTS: [&CStr; 3] = [c"SHA256", c"SHA384", c"SHA512"];

fn digest_stream(input: &mut dyn Read) -> [Vec<u8>; 3] {
    let mut h = DIGESTS.map(|n| Hash::begin(Some(n)).unwrap_or_else(|e| die(e)));
    stream(input, |b| {
        for x in &mut h {
            x.update(b).unwrap_or_else(|e| die(e));
        }
    });
    h.map(|x| x.end().unwrap_or_else(|e| die(e)))
}

/// The one of the three `name` names; SHA-512 for anything else.
fn pick(name: Option<&CStr>) -> usize {
    DIGESTS.iter().position(|d| Some(*d) == name).unwrap_or(2)
}

fn cmd_cms(o: &Opts) -> i32 {
    let (Some(label), Some(cert_path)) = (o.label, o.cert) else {
        usage()
    };
    let cert = read_der(cert_path);
    let mut input = open_in(o.input);
    let dg = digest_stream(&mut *input);
    drop(input);
    let s = open_session(o.module, o.slot);
    // The digest the key's algorithm signs with.
    let alg = ops::key_alg(s, label).unwrap_or_else(|e| die(e));
    let der = sign::cms_sign(s, label, &cert, &dg[pick(Some(alg.info().digest))])
        .unwrap_or_else(|e| die(e));
    emit(o.out, &der);
    eprintln!("fhsm-sign: {}-byte detached CMS SignedData.", der.len());
    close_session(s);
    0
}

fn cmd_cms_verify(o: &Opts) -> i32 {
    let Some(cms_path) = o.cms else { usage() };
    let cms = read_der(cms_path);
    // DIV-075: the certificate it must be signed under, read before the stream is.
    let want = o.signer.map(|p| {
        let der = read_der(p);
        if sign::describe_cert(&der).is_none() {
            say(&[b"fhsm-sign: ", p, b" is not a certificate\n"]);
            exit(2);
        }
        (p, der)
    });
    let mut input = open_in(o.input);
    let dg = digest_stream(&mut *input);
    drop(input);
    // No module, no token, no PIN: the signer's certificate travels inside the structure, and
    // the structure names the digest. One it cannot name falls through to the verdict.
    let k = pick(sign::cms_digest(&cms));
    match sign::cms_verify(&cms, &dg[k]).unwrap_or_else(|e| die(e)) {
        Verdict::Mismatch => {
            eprintln!("fhsm-sign: the CMS does not match this data.");
            4
        }
        Verdict::Unreadable => {
            say(&[
                b"fhsm-sign: ",
                cms_path,
                b" is not a CMS this tool can read.\n",
                b"  That is a different problem from a signature that does\n",
                b"  not match, and exits 2 rather than 4.\n",
            ]);
            2
        }
        Verdict::Verified { signer } => {
            let (subject, fp) = sign::describe_cert(&signer).unwrap_or_default();
            if let Some((p, der)) = want
                && der != signer
            {
                say(&[
                    b"fhsm-sign: the CMS is signed by ",
                    &subject,
                    b",\n  not by the certificate in ",
                    p,
                    b".\n",
                ]);
                return 4;
            }
            say(&[
                b"fhsm-sign: CMS verified.\n  signed by: ",
                &subject,
                b"\n  certificate SHA-256: ",
                fp.as_bytes(),
                b"\n",
            ]);
            0
        }
    }
}

fn main() {
    init();
    let args: Vec<Vec<u8>> = std::env::args_os().map(|a| a.into_vec()).collect();
    if args.len() < 2 {
        usage();
    }
    let rc = match &args[1][..] {
        b"sign" => cmd_sign(&parse(&args)),
        b"verify" => cmd_verify(&parse(&args)),
        b"cms" => cmd_cms(&parse(&args)),
        b"cms-verify" => cmd_cms_verify(&parse(&args)),
        _ => usage(),
    };
    exit(rc)
}
