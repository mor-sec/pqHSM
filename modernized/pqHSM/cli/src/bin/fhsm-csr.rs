//! `fhsm-csr`: certification requests and self-signed roots, with a key held in a PKCS#11
//! module (`tools/fhsm_csr.c`, PHASE5_PLAN.md slice 1). Flags, messages and exit codes are
//! C's; the PIN is FHSM_PIN's, or asked for at a terminal (DIV-072). There is no --pin: an
//! argument is visible in `ps` to every user on the machine.

use std::ffi::CString;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::process::exit;

use pqhsm_cli::{atoi, atol, fail, init, pem, perror_exit, pin};
use pqhsm_pkiops::keys::Alg;
use pqhsm_pkiops::{Error, Intent, close, open, ops, parse_slot};

const PROG: &str = "fhsm-csr";

const USAGE: &str = concat!(
    "fhsm-csr --- certification requests and roots, with a key held in a PKCS#11 module\n\n",
    "  fhsm-csr keygen --label NAME [--alg ALG] [--module PATH] [--slot N]\n",
    "  fhsm-csr csr    --label NAME --subject DN [--out FILE] [--pem] ...\n",
    "  fhsm-csr root   --label NAME --subject DN [--days N] [--serial N] ...\n\n",
    "  --alg ALG       keygen only: composite (the default), ecdsa-p256,\n",
    "                  ecdsa-p384, rsa-pss, rsa-pkcs1, ed25519, ml-dsa-44,\n",
    "                  ml-dsa-65, ml-dsa-87. csr and root take no algorithm:\n",
    "                  they sign with the key's own.\n",
    "  --module PATH   PKCS#11 module (default ./libfreehsm.so)\n",
    "  --slot N        slot to address. Default: the one slot holding a token.\n",
    "  --subject DN    e.g. \"/C=FR/O=Simorgh Labs/CN=example\"\n",
    "  --days N        validity in days for root (default 3650)\n",
    "  --serial N      certificate serial for root (default 1)\n",
    "  --out FILE      output file (default stdout)\n",
    "  --pem           PEM instead of DER\n\n",
    "  The PIN is read from FHSM_PIN. There is no --pin option: an argument\n",
    "  is visible in ps to every user on the machine.\n\n",
    "  Note: the composite algorithm is not yet implemented by general-purpose\n",
    "  tooling, so a request produced here can be parsed and transported but\n",
    "  not validated by anything off the shelf until the RFC publishes.\n",
);

fn usage() -> ! {
    eprint!("{USAGE}");
    exit(1)
}

fn die(e: Error) -> ! {
    fail(PROG, &e)
}

/// `emit`: DER or PEM to `path`, or stdout.
fn emit(der: &[u8], path: Option<&[u8]>, as_pem: bool, label: &str) {
    let mut f: Box<dyn Write> = match path {
        Some(p) => match File::create(std::ffi::OsStr::from_bytes(p)) {
            Ok(f) => Box::new(f),
            Err(e) => perror_exit("fhsm-csr: open", &e),
        },
        None => Box::new(io::stdout().lock()),
    };
    if as_pem {
        // C ignores what PEM_write_bio returns.
        let _ = f.write_all(&pem(label, der)).and_then(|()| f.flush());
    } else if let Err(e) = f.write_all(der).and_then(|()| f.flush()) {
        perror_exit("fhsm-csr: write", &e);
    }
}

fn main() {
    init();
    let args: Vec<Vec<u8>> = std::env::args_os().map(|a| a.into_vec()).collect();
    if args.len() < 2 {
        usage();
    }
    let cmd = &args[1][..];
    let mut module: &[u8] = b"./libfreehsm.so";
    let (mut label, mut subject, mut out, mut alg_name) = (None, None, None, None);
    let (mut as_pem, mut days, mut serial, mut slot) = (false, 3650, 1, -1);

    let mut i = 2;
    while i < args.len() {
        let a = &args[i][..];
        let next = args.get(i + 1).map(|v| &v[..]);
        match (a, next) {
            (b"--module", Some(v)) => module = v,
            (b"--label", Some(v)) => label = Some(v),
            (b"--subject", Some(v)) => subject = Some(v),
            (b"--alg", Some(v)) => alg_name = Some(v),
            (b"--out", Some(v)) => out = Some(v),
            (b"--slot", Some(v)) => slot = parse_slot(v).unwrap_or_else(|e| die(e)),
            (b"--days", Some(v)) => days = atoi(v),
            (b"--serial", Some(v)) => serial = atol(v),
            (b"--pem", _) => {
                as_pem = true;
                i += 1;
                continue;
            }
            _ if a == b"--pin" || a.starts_with(b"--pin=") => {
                eprint!(
                    "fhsm-csr: --pin is not accepted. Set FHSM_PIN instead:\n  an argument is visible in ps to every user on this machine.\n"
                );
                exit(1);
            }
            _ => usage(),
        }
        i += 2;
    }
    let Some(label) = label else { usage() };
    let signs = cmd == b"csr" || cmd == b"root";
    if signs && subject.is_none() {
        usage();
    }

    // The algorithm is chosen once, with the key, and read off it afterwards: an --alg on csr
    // or root could only agree with the key or contradict it.
    let mut alg = Alg::Composite;
    if let Some(n) = alg_name {
        if cmd != b"keygen" {
            let mut w = io::stderr().lock();
            let _ = w.write_all(b"fhsm-csr: --alg belongs to keygen. ");
            let _ = w.write_all(cmd);
            let _ = w.write_all(
                b" signs with the key's own\n  algorithm, chosen when the key was generated.\n",
            );
            exit(1);
        }
        alg = Alg::parse(Some(n)).unwrap_or_else(|e| die(e));
    }

    let pin = pin(
        PROG,
        "FHSM_PIN",
        "user PIN",
        "fhsm-csr: FHSM_PIN is not set.\n",
    );
    // An argument holds no NUL.
    let module = CString::new(module).expect("no NUL in an argument");
    let sid = open(Some(&module), slot, Intent::WithToken).unwrap_or_else(|e| die(e));
    let s = ops::session_user(sid, &pin).unwrap_or_else(|e| die(e));
    drop(pin);

    if cmd == b"keygen" {
        let (hp, hk) = ops::keygen_alg(s, label, alg).unwrap_or_else(|e| die(e));
        let mut w = io::stderr().lock();
        let _ = w.write_all(
            format!(
                "fhsm-csr: {} key pair \"",
                alg.info().name.to_str().expect("ASCII")
            )
            .as_bytes(),
        );
        let _ = w.write_all(label);
        let _ = w.write_all(format!("\" created (public {hp}, private {hk})\n").as_bytes());
    } else if signs {
        let subject = CString::new(subject.expect("checked above")).expect("no NUL in an argument");
        let der = if cmd == b"csr" {
            ops::csr(s, label, &subject)
        } else {
            ops::root(s, label, &subject, serial, days)
        }
        .unwrap_or_else(|e| die(e));
        emit(
            &der,
            out,
            as_pem,
            if cmd == b"csr" {
                "CERTIFICATE REQUEST"
            } else {
                "CERTIFICATE"
            },
        );
    } else {
        // An unknown command is found out here, after the login, as in C; nothing is closed.
        usage();
    }
    ops::session_close(s);
    close();
}
