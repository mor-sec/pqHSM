//! `fhsm-crypt`: keys that do not sign, and the objects on the token (`tools/fhsm_crypt.c`,
//! PHASE5_PLAN.md slice 3). Flags, messages and exit codes are C's. The PIN comes from FHSM_PIN
//! or is asked for at a terminal (DIV-072); never from an argument. `encrypt --cert` needs
//! neither the module nor the PIN.

use std::ffi::{CString, OsStr};
use std::io::{self, IsTerminal, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::process::exit;

use pqhsm_cli::{fail, init, pin};
use pqhsm_pkiops::keys::{SKEY_LIST, Skey};
use pqhsm_pkiops::objects::{self, Key, OBJS_ALL, OBJS_CERTS, OBJS_KEYS, Object};
use pqhsm_pkiops::ops::{self, text};
use pqhsm_pkiops::{Error, Intent, close, envelope, open, parse_slot};

const PROG: &str = "fhsm-crypt";

const USAGE: &str = concat!(
    "fhsm-crypt --- keys that do not sign, and the objects on the token\n\n",
    "  fhsm-crypt list   [--class key|cert|all] [--module PATH] [--slot N]\n",
    "  fhsm-crypt keygen --label NAME --alg ALG ...\n",
    "  fhsm-crypt show   --label NAME [--class key|cert|all] ...\n",
    "  fhsm-crypt encrypt --key LABEL --in FILE --out FILE.p7m ...\n",
    "  fhsm-crypt encrypt --cert CERT --in FILE --out FILE.p7m\n",
    "  fhsm-crypt decrypt --in FILE.p7m --out FILE ...\n",
    "  fhsm-crypt delete --label NAME [--class key|cert|all] [--yes] ...\n\n",
    "  --alg ALG       keygen: aes128, aes256 (encrypt and wrap), hmac (a\n",
    "                  32-byte secret for HMAC), or rsa-oaep (an RSA 3072 pair\n",
    "                  that encrypts with OAEP and cannot sign). Sensitive, not\n",
    "                  extractable.\n",
    "                  Signature keys are made by fhsm-csr keygen.\n",
    "  --class C       which objects: key (public, private and secret keys),\n",
    "                  cert, or all (the default)\n",
    "  --label NAME    show, delete: every object of the class carrying this label\n",
    "  --yes           delete: destroy them. Without it, delete lists what it\n",
    "                  would destroy and stops.\n",
    "  --key LABEL     encrypt: an AES key or an rsa-oaep pair on the token.\n",
    "                  decrypt finds the key itself, from the file.\n",
    "  --cert CERT     encrypt: for the holder of this certificate (PEM or DER,\n",
    "                  an RSA key). Needs neither the module nor FHSM_PIN.\n",
    "  --in, --out     encrypt, decrypt: the file read and the file written.\n",
    "                  An existing --out is never written over, and a file\n",
    "                  that does not authenticate leaves nothing behind.\n",
    "  --module PATH   PKCS#11 module (default ./libfreehsm.so)\n",
    "  --slot N        slot to address. Default: the one slot holding a token.\n\n",
    "  The PIN is read from FHSM_PIN. There is no --pin option: an argument\n",
    "  is visible in ps to every user on the machine.\n\n",
    "  Exit: 0 done, 1 usage or a file this does not read, 2 the module or the\n",
    "  file system, 3 no such key, 4 the file does not open with the key.\n",
);

fn usage() -> ! {
    eprint!("{USAGE}");
    exit(1)
}

fn die(e: Error) -> ! {
    fail(PROG, &e)
}

/// stderr as bytes: labels and paths need not be UTF-8.
fn say(parts: &[&[u8]]) {
    let _ = io::stderr().lock().write_all(&parts.concat());
}

/// `prog: msg`, without exiting: the error's code is returned.
fn report(e: &Error) -> i32 {
    say(&[PROG.as_bytes(), b": ", e.c_msg()]);
    e.code
}

/// `%-Ns` (left) or `%Ns` of bytes: printf pads by bytes.
fn pad(out: &mut Vec<u8>, s: &[u8], w: usize, left: bool) {
    let fill = w.saturating_sub(s.len());
    if !left {
        out.resize(out.len() + fill, b' ');
    }
    out.extend(s);
    if left {
        out.resize(out.len() + fill, b' ');
    }
}

/// `alg_of_object`: a key pair's algorithm from `keys`, a secret key's from the object; "-"
/// for a certificate.
fn alg_of_object<'a>(o: &'a Object, k: &'a [Key]) -> &'a [u8] {
    if o.alg[0] != 0 {
        return text(&o.alg);
    }
    k.iter()
        .find(|k| k.handle == o.handle && k.alg[0] != 0)
        .map_or(b"-", |k| text(&k.alg))
}

/// `print_object`.
fn print_object(out: &mut Vec<u8>, o: &Object, alg: &[u8]) {
    let (label, id) = (text(&o.label), text(&o.id));
    out.extend(b"  ");
    pad(out, o.cls.name().to_bytes(), 11, true);
    out.extend(b"  ");
    pad(out, o.handle.to_string().as_bytes(), 6, false);
    out.extend(b"  ");
    pad(
        out,
        if label.is_empty() {
            b"(no label)"
        } else {
            label
        },
        32,
        true,
    );
    out.extend(b"  ");
    pad(out, alg, 11, true);
    out.extend(b"  ");
    out.extend(if id.is_empty() { b"-" } else { id });
    out.push(b'\n');
}

fn path(p: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(p))
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

fn main() {
    init();
    let args: Vec<Vec<u8>> = std::env::args_os().map(|a| a.into_vec()).collect();
    if args.len() < 2 {
        usage();
    }
    let cmd = &args[1][..];
    let mut module: &[u8] = b"./libfreehsm.so";
    let mut cls_name: &[u8] = b"all";
    let (mut label, mut alg_name, mut key, mut cert, mut inp, mut outp) =
        (None, None, None, None, None, None);
    let (mut slot, mut yes) = (-1, false);

    let mut i = 2;
    while i < args.len() {
        let a = &args[i][..];
        match (a, args.get(i + 1).map(|v| &v[..])) {
            (b"--module", Some(v)) => module = v,
            (b"--label", Some(v)) => label = Some(v),
            (b"--class", Some(v)) => cls_name = v,
            (b"--alg", Some(v)) => alg_name = Some(v),
            (b"--key", Some(v)) => key = Some(v),
            (b"--cert", Some(v)) => cert = Some(v),
            (b"--in", Some(v)) => inp = Some(v),
            (b"--out", Some(v)) => outp = Some(v),
            (b"--slot", Some(v)) => slot = parse_slot(v).unwrap_or_else(|e| die(e)),
            (b"--yes", _) => {
                yes = true;
                i += 1;
                continue;
            }
            _ if a == b"--pin" || a.starts_with(b"--pin=") => {
                eprint!(
                    "fhsm-crypt: --pin is not accepted. Set FHSM_PIN instead:\n  an argument is visible in ps to every user on this machine.\n"
                );
                exit(1);
            }
            _ => usage(),
        }
        i += 2;
    }

    let classes = match cls_name {
        b"all" => OBJS_ALL,
        b"key" => OBJS_KEYS,
        b"cert" => OBJS_CERTS,
        _ => {
            say(&[
                b"fhsm-crypt: --class takes key, cert or all, not \"",
                cls_name,
                b"\"\n",
            ]);
            exit(1);
        }
    };

    let (is_list, is_delete, is_keygen) = (cmd == b"list", cmd == b"delete", cmd == b"keygen");
    let (is_show, is_enc, is_dec) = (cmd == b"show", cmd == b"encrypt", cmd == b"decrypt");
    if !(is_list || is_delete || is_keygen || is_show || is_enc || is_dec)
        || ((is_enc || is_dec) && (inp.is_none() || outp.is_none() || label.is_some() || yes))
        || (is_enc && key.is_none() == cert.is_none()) // --key or --cert, not both
        || (!is_enc && (key.is_some() || cert.is_some()))
        || (!is_enc && !is_dec && (inp.is_some() || outp.is_some()))
        || ((is_delete || is_keygen || is_show) && label.is_none())
        || (is_show && yes)
        || (is_list && (label.is_some() || yes))
    {
        usage();
    }
    if alg_name.is_some() && !is_keygen {
        eprintln!("fhsm-crypt: --alg belongs to keygen.");
        exit(1);
    }
    let mut skey = Skey::Aes256;
    if is_keygen {
        let Some(n) = alg_name else {
            eprintln!(
                "fhsm-crypt: keygen needs --alg: {}",
                SKEY_LIST.to_str().expect("ASCII")
            );
            exit(1);
        };
        skey = Skey::parse(Some(n)).unwrap_or_else(|e| die(e));
    }

    // For a certificate: a public operation, before the module and the PIN are so much as
    // looked at.
    if is_enc && let Some(cert) = cert {
        let (i, o) = (inp.expect("checked"), outp.expect("checked"));
        let rc = match envelope::encrypt_file_for_cert(path(cert), path(i), path(o)) {
            Ok(()) => {
                say(&[
                    b"fhsm-crypt: ",
                    i,
                    b" encrypted for the holder of ",
                    cert,
                    b" into ",
                    o,
                    b"\n",
                ]);
                0
            }
            Err(e) => report(&e),
        };
        exit(rc);
    }

    let pin = pin(
        PROG,
        "FHSM_PIN",
        "user PIN",
        "fhsm-crypt: FHSM_PIN is not set.\n",
    );
    // An argument holds no NUL.
    let module = CString::new(module).expect("no NUL in an argument");
    let sid = open(Some(&module), slot, Intent::WithToken).unwrap_or_else(|e| die(e));
    let s = ops::session_user(sid, &pin).unwrap_or_else(|e| die(e));
    drop(pin);
    let finish = |rc: i32| -> ! {
        ops::session_close(s);
        close();
        exit(rc)
    };

    if is_enc || is_dec {
        let (i, o) = (inp.expect("checked"), outp.expect("checked"));
        let mut used = None;
        let r = match key {
            Some(k) => envelope::encrypt_file(s, k, path(i), path(o)),
            None => envelope::decrypt_file(s, path(i), path(o), &mut used),
        };
        let rc = match r {
            Err(e) => report(&e),
            Ok(()) => {
                let mut used = used.unwrap_or_default();
                used.truncate(64); // C's used[65]
                let (verb, name): (&[u8], &[u8]) = match key {
                    Some(k) => (b" encrypted for \"", k),
                    None => (b" decrypted with \"", &used),
                };
                say(&[b"fhsm-crypt: ", i, verb, name, b"\" into ", o, b"\n"]);
                0
            }
        };
        finish(rc);
    }

    let label = label.unwrap_or_default();
    if is_keygen {
        // One label, one key: a second key under a label already in use is the ambiguity
        // every other operation then refuses to resolve.
        let v = objects::objects(s, OBJS_KEYS).unwrap_or_else(|e| die(e));
        if v.iter().any(|o| text(&o.label) == label) {
            say(&[
                b"fhsm-crypt: a key labelled \"",
                label,
                b"\" is already on the token\n",
            ]);
            exit(3);
        }
        let h = objects::keygen_secret(s, label, skey).unwrap_or_else(|e| die(e));
        let kind = if skey == Skey::RsaOaep {
            "key pair"
        } else {
            "key"
        };
        say(&[
            format!(
                "fhsm-crypt: {} {kind} \"",
                skey.info().name.to_str().expect("ASCII")
            )
            .as_bytes(),
            label,
            format!("\" created (object {h})\n").as_bytes(),
        ]);
        finish(0);
    }

    let v = objects::objects(s, classes).unwrap_or_else(|e| die(e));
    let k = objects::keys(s).unwrap_or_else(|e| die(e));
    let matching = || v.iter().filter(|o| text(&o.label) == label);
    // stdout as C's stdio holds it: line by line on a terminal, so a list comes before the
    // message after it; otherwise written at exit (C's block buffer, outputs here being
    // small). `flush_tty` is called before each stderr line that can follow stdout lines.
    let mut out = Vec::new();
    let tty = io::stdout().is_terminal();
    let flush_tty = |out: &mut Vec<u8>| {
        if tty {
            let _ = io::stdout().lock().write_all(out);
            out.clear();
        }
    };
    let mut rc = 0;
    if is_show {
        let mut shown = 0;
        for o in matching() {
            let a = match objects::object_attrs(s, o.handle) {
                Ok(a) => a,
                Err(e) => {
                    flush_tty(&mut out);
                    rc = report(&e);
                    continue;
                }
            };
            if shown > 0 {
                out.push(b'\n');
            }
            out.extend(o.cls.name().to_bytes());
            out.extend(format!(" {}\n", o.handle).as_bytes());
            for l in &a {
                out.extend(b"  ");
                pad(&mut out, text(&l.name), 24, true);
                out.push(b' ');
                out.extend(text(&l.value));
                out.push(b'\n');
            }
            shown += 1;
        }
        if shown == 0 && rc == 0 {
            say(&[b"fhsm-crypt: nothing labelled \"", label, b"\"\n"]);
            rc = 3;
        }
    } else if is_list {
        out.extend(b"  ");
        pad(&mut out, b"class", 11, true);
        out.extend(b"  handle  ");
        pad(&mut out, b"label", 32, true);
        out.extend(b"  ");
        pad(&mut out, b"algorithm", 11, true);
        out.extend(b"  CKA_ID\n");
        for o in &v {
            print_object(&mut out, o, alg_of_object(o, &k));
        }
        out.extend(format!("{} object{}\n", v.len(), plural(v.len())).as_bytes());
    } else {
        let n = matching().count();
        if n == 0 {
            let what: &[u8] = match classes {
                OBJS_CERTS => b"certificate",
                OBJS_KEYS => b"key",
                _ => b"object",
            };
            say(&[b"fhsm-crypt: no ", what, b" labelled \"", label, b"\"\n"]);
            rc = 3;
        } else if !yes {
            out.extend(format!("would destroy {n} object{} labelled \"", plural(n)).as_bytes());
            out.extend(label);
            out.extend(b"\":\n");
            for o in matching() {
                print_object(&mut out, o, alg_of_object(o, &k));
            }
            flush_tty(&mut out);
            eprintln!(
                "fhsm-crypt: nothing destroyed. Add --yes to destroy {}; it cannot be undone.",
                if n == 1 { "it" } else { "them" }
            );
            rc = 1;
        } else {
            for o in matching() {
                // Stop at the first refusal: what follows was named together with it, and a
                // partial deletion is reported as one, not carried on past.
                if let Err(e) = objects::destroy(s, o.handle) {
                    rc = report(&e);
                    break;
                }
                let class = o.cls.name().to_str().expect("ASCII");
                say(&[
                    format!("fhsm-crypt: destroyed {class} {} \"", o.handle).as_bytes(),
                    label,
                    b"\"\n",
                ]);
            }
        }
    }
    let mut w = io::stdout().lock();
    // C ignores what printf returns.
    let _ = w.write_all(&out).and_then(|()| w.flush());
    finish(rc);
}
