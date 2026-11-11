//! `fhsm-ca`: issue certificates from a request, keep the revocation database, sign its CRL
//! and answer OCSP requests, with a key held in a PKCS#11 module (`tools/fhsm_ca.c`,
//! PHASE5_PLAN.md slice 5). Flags, messages and exit codes are C's, but for DIV-072 (the PIN
//! asked for at a terminal), DIV-073 (`--days` a whole positive decimal that fits an `int`) and
//! DIV-074 (the database locked from load to save).

use std::ffi::{CString, OsStr, c_int, c_long};
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::Path;
use std::process::exit;

use pqhsm_cli::{fail, fill, init, pin, write_der};
use pqhsm_pki::revocation::{self as rev, Db, DbLock, Entry, LOCK_WAIT, Query, RevError};
use pqhsm_pkiops::ca::{self, Issue};
use pqhsm_pkiops::ops::{self, Session};
use pqhsm_pkiops::sign::pem_body;
use pqhsm_pkiops::{Error, Intent, close, open, parse_slot};
use zeroize::Zeroizing;

const PROG: &str = "pqhsm-ca";

/// `slurp`'s buffer: a larger file is cut here, and then fails to parse, as in C.
const SLURP_MAX: usize = 262_144;

/// `--crl-url` may be given this many times.
const CRL_URLS_MAX: usize = 8;

/// `fhsm_cert_profile_t`.
const END_ENTITY: c_int = 0;
const OCSP_RESPONDER: c_int = 1;

const USAGE: &str = concat!(
    "fhsm-ca --- issue and revoke certificates with a key held in a PKCS#11 module\n\n",
    "  fhsm-ca issue  --label NAME --ca-cert FILE --csr FILE\n",
    "                 [--profile end-entity|ocsp-responder]\n",
    "                 [--subject DN] [--san LIST] [--crl-url URL]...\n",
    "                 [--days N] [--out FILE] [--pem]\n",
    "  fhsm-ca revoke --db FILE --serial HEX [--reason NAME] [--date WHEN]\n",
    "  fhsm-ca crl    --label NAME --ca-cert FILE --db FILE\n",
    "                 [--days N] [--out FILE] [--pem]\n",
    "  fhsm-ca ocsp-respond --label NAME --ca-cert FILE --db FILE --req FILE\n",
    "                 [--responder-cert FILE] [--days N] [--out FILE]\n\n",
    "  --label NAME    label of the CA key inside the module. It signs with\n",
    "                  the algorithm it was generated for (fhsm-csr keygen\n",
    "                  --alg); the request it certifies may carry any key.\n",
    "  --ca-cert FILE  the CA's own certificate (DER or PEM)\n",
    "  --csr FILE      the request to sign (DER or PEM)\n",
    "  --db FILE       the revocation database (created on first revoke)\n",
    "  --serial HEX    serial to revoke, as it appears in the certificate\n",
    "  --reason NAME   unspecified, keyCompromise, cACompromise,\n",
    "                  affiliationChanged, superseded, cessationOfOperation,\n",
    "                  certificateHold, privilegeWithdrawn, aACompromise\n",
    "  --date WHEN     revocation date, YYYYMMDDHHMMSSZ (default: now)\n",
    "  --subject DN    replace the requested subject entirely\n",
    "  --san LIST      DNS:/IP:/email:/URI: entries, comma separated\n",
    "  --crl-url URL   where this certificate's revocation list is published.\n",
    "                  Repeat for several; they all describe the same list.\n",
    "                  http://... or ldap://...?attribute . https is refused:\n",
    "                  fetching a CRL over TLS can require a CRL, and the list\n",
    "                  is signed, so the transport protects nothing.\n",
    "  --req FILE      an OCSP request in DER (ocsp-respond)\n",
    "  --responder-cert FILE\n",
    "                  sign the response as a delegated responder rather\n",
    "                  than as the CA (RFC 6960 4.2.2.2). --label then names\n",
    "                  the delegate's key. Refused unless the certificate\n",
    "                  carries extendedKeyUsage OCSPSigning and was issued by\n",
    "                  the CA in --ca-cert.\n",
    "  --days N        validity in days (issue: 365, crl: 30, ocsp: 7)\n",
    "  --profile P     end-entity (default), or ocsp-responder for a\n",
    "                  delegated responder: extendedKeyUsage OCSPSigning\n",
    "                  plus id-pkix-ocsp-nocheck (RFC 6960 4.2.2.2). Such a\n",
    "                  certificate cannot be revoked in any way a verifier\n",
    "                  will notice, so issue it short.\n",
    "  --module PATH   PKCS#11 module (default ./libfreehsm.so)\n",
    "  --slot N        slot to address. Default: the one slot holding a token.\n",
    "  --out FILE      output file (default stdout)\n",
    "  --pem           PEM instead of DER\n\n",
    "  The PIN is read from FHSM_PIN. There is no --pin option: an argument\n",
    "  is visible in ps to every user on the machine.\n\n",
    "  `revoke` only records the revocation; it does not need the key and\n",
    "  produces nothing signed. `crl` is what signs, and it advances the\n",
    "  database's crlNumber as it goes -- so a list that has been issued is\n",
    "  never issued again under the same number.\n\n",
    "  `ocsp-respond` answers one request from the same database, as a file.\n",
    "  It echoes the client's nonce when there is one, and answers unknown --\n",
    "  not good -- for any certificate whose issuer is not this CA.\n",
);

fn usage() -> ! {
    eprint!("{USAGE}");
    exit(1)
}

fn die(e: Error) -> ! {
    fail(PROG, &e)
}

/// `db_load`'s and `db_save`'s exit: the library's diagnostic, and its status.
fn die_rev(e: RevError) -> ! {
    say(&[b"pqhsm-ca: ", e.msg.as_bytes()]);
    exit(e.code)
}

/// Bytes on stderr: paths and serials need not be UTF-8.
fn say(parts: &[&[u8]]) {
    let mut w = io::stderr().lock();
    for p in parts {
        let _ = w.write_all(p);
    }
}

fn path(p: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(p))
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// DIV-073: a whole positive decimal that fits an `int`, else 0, which every subcommand then
/// refuses as "--days must be positive."
fn parse_days(t: &[u8]) -> c_int {
    if t.is_empty() || !t.iter().all(u8::is_ascii_digit) {
        return 0;
    }
    std::str::from_utf8(t)
        .ok()
        .and_then(|s| s.parse::<c_int>().ok())
        .unwrap_or(0)
}

fn check_days(days: c_int) {
    if days <= 0 {
        eprintln!("pqhsm-ca: --days must be positive.");
        exit(2);
    }
}

fn user_pin() -> Zeroizing<Vec<u8>> {
    pin(
        PROG,
        "FHSM_PIN",
        "user PIN",
        "pqhsm-ca: FHSM_PIN is not set.\n",
    )
}

/// `slurp`: at most [`SLURP_MAX`] bytes of `p` (fread's: an error ends the read), PEM decoded.
fn slurp(p: &[u8]) -> Vec<u8> {
    let Ok(mut f) = File::open(path(p)) else {
        say(&[b"pqhsm-ca: cannot read ", p, b"\n"]);
        exit(2);
    };
    let mut buf = vec![0u8; SLURP_MAX];
    let (n, _) = fill(&mut f, &mut buf);
    buf.truncate(n);
    if n == 0 {
        say(&[b"pqhsm-ca: ", p, b" is empty\n"]);
        exit(2);
    }
    // Accept PEM as well as DER: an operator who received a PEM request should not have to
    // convert it first.
    if n > 11 && buf.starts_with(b"-----BEGIN ") {
        return pem_body(&buf).unwrap_or_else(|| {
            say(&[b"pqhsm-ca: ", p, b" looks like PEM but did not parse\n"]);
            exit(2)
        });
    }
    buf
}

/// The module and the user session, once the PIN is in hand and the files are read.
fn open_session(module: &[u8], slot: c_long, pin: Zeroizing<Vec<u8>>) -> Session {
    let module = CString::new(module).expect("no NUL in an argument");
    let sid = open(Some(&module), slot, Intent::WithToken).unwrap_or_else(|e| die(e));
    ops::session_user(sid, &pin).unwrap_or_else(|e| die(e))
}

fn close_session(s: Session) {
    ops::session_close(s);
    close();
}

/// DIV-074: the database's lock, or the refusal, exit 2 with nothing read or changed.
fn lock(db: &[u8], exclusive: bool) -> DbLock {
    DbLock::take(path(db), exclusive, LOCK_WAIT).unwrap_or_else(|e| die_rev(e))
}

fn db_load(db: &[u8]) -> Db {
    Db::load(path(db)).unwrap_or_else(|e| die_rev(e))
}

fn db_save(db: &[u8], d: &Db) {
    d.save(path(db)).unwrap_or_else(|e| die_rev(e));
}

/// The options the signing subcommands share.
struct Common<'a> {
    module: &'a [u8],
    label: Option<&'a [u8]>,
    ca_cert: Option<&'a [u8]>,
    out: Option<&'a [u8]>,
    slot: c_long,
    days: Option<c_int>,
    pem: bool,
}

impl<'a> Common<'a> {
    fn new() -> Self {
        Common {
            module: b"./libfreehsm.so",
            label: None,
            ca_cert: None,
            out: None,
            slot: -1,
            days: None,
            pem: false,
        }
    }

    /// One of the shared options at `a` (`next` its value), and how many arguments it took;
    /// `--pem` only where the subcommand has it.
    fn take(&mut self, a: &[u8], next: Option<&'a [u8]>, pem: bool) -> usize {
        match (a, next) {
            (b"--module", Some(v)) => self.module = v,
            (b"--label", Some(v)) => self.label = Some(v),
            (b"--ca-cert", Some(v)) => self.ca_cert = Some(v),
            (b"--out", Some(v)) => self.out = Some(v),
            (b"--slot", Some(v)) => self.slot = parse_slot(v).unwrap_or_else(|e| die(e)),
            (b"--days", Some(v)) => self.days = Some(parse_days(v)),
            (b"--pem", _) if pem => {
                self.pem = true;
                return 1;
            }
            _ => return 0,
        }
        2
    }
}

/// C's loop: from `argv[2]`, each option with its value when one follows; `own` takes this
/// subcommand's own options (always with a value); `--pin...` refused, anything else the
/// usage.
fn parse<'a>(
    args: &'a [Vec<u8>],
    c: &mut Common<'a>,
    pem: bool,
    mut own: impl FnMut(&'a [u8], Option<&'a [u8]>) -> bool,
) {
    let mut i = 2;
    while i < args.len() {
        let a = &args[i][..];
        let next = args.get(i + 1).map(|v| &v[..]);
        let n = match c.take(a, next, pem) {
            0 if own(a, next) => 2,
            n => n,
        };
        if n > 0 {
            i += n;
            continue;
        }
        if a.starts_with(b"--pin") {
            eprint!(
                "pqhsm-ca: --pin is not accepted. Set FHSM_PIN instead:\n  an argument is visible in ps to every user on this machine.\n"
            );
            exit(1);
        }
        usage();
    }
}

fn cmd_issue(args: &[Vec<u8>]) -> i32 {
    let mut c = Common::new();
    let (mut csr, mut subject, mut san) = (None, None, None);
    let mut crl_urls: Vec<Option<&[u8]>> = Vec::new();
    let mut profile = END_ENTITY;
    parse(args, &mut c, true, |a, next| {
        match (a, next) {
            (b"--csr", Some(v)) => csr = Some(v),
            (b"--subject", Some(v)) => subject = Some(v),
            (b"--san", Some(v)) => san = Some(v),
            // Repeatable rather than comma-separated like --san: an LDAP URI carries commas
            // inside its DN.
            (b"--crl-url", Some(v)) => {
                if crl_urls.len() == CRL_URLS_MAX {
                    eprintln!("pqhsm-ca: at most {CRL_URLS_MAX} --crl-url entries");
                    exit(1);
                }
                crl_urls.push(Some(v));
            }
            (b"--profile", Some(v)) => {
                profile = match v {
                    b"end-entity" => END_ENTITY,
                    b"ocsp-responder" => OCSP_RESPONDER,
                    _ => {
                        say(&[
                            b"pqhsm-ca: --profile ",
                            v,
                            b" is not a profile.\n  end-entity      the default\n  ocsp-responder  a delegated OCSP responder\n",
                        ]);
                        exit(1);
                    }
                }
            }
            _ => return false,
        }
        true
    });
    let (Some(label), Some(ca_p), Some(csr_p)) = (c.label, c.ca_cert, csr) else {
        usage()
    };
    // A delegated responder carries ocsp-nocheck, so a short validity is the only control
    // left: the default makes that choice, an explicit --days is only warned about.
    let days = match c.days {
        Some(d) => {
            check_days(d);
            d
        }
        None if profile == OCSP_RESPONDER => 30,
        None => 365,
    };
    if profile == OCSP_RESPONDER && days > 90 {
        eprint!(
            "pqhsm-ca: NOTE -- {days} days for a delegated responder.\n  It carries id-pkix-ocsp-nocheck, so revoking it is not something\n  a verifier will observe: for the whole of that period, whoever\n  holds the key can answer for this CA. Short validity is the only\n  control that remains. Issuing anyway.\n"
        );
    }

    let pin = user_pin();
    let ca_der = slurp(ca_p);
    let csr_der = slurp(csr_p);
    let s = open_session(c.module, c.slot, pin);

    let i = Issue {
        ca: &ca_der,
        csr: &csr_der,
        subject,
        san,
        crl_urls: &crl_urls,
        profile,
        days,
    };
    let Some(der) = ca::issue(s, label, &i).unwrap_or_else(|e| die(e)) else {
        eprint!(
            "pqhsm-ca: the request's signature does not match the key it carries.\n  Nothing was issued. Either the request was altered after signing,\n  or whoever produced it does not hold the private key it asks to\n  have certified.\n"
        );
        return 4;
    };
    write_der(PROG, &der, c.out, c.pem, "CERTIFICATE");
    close_session(s);
    0
}

/// `revoke`: record a revocation. No key, no signature, nothing to unlock.
fn cmd_revoke(args: &[Vec<u8>]) -> i32 {
    let (mut db, mut serial, mut reason, mut when) = (None, None, None, None);
    let mut i = 2;
    while i < args.len() {
        match (&args[i][..], args.get(i + 1).map(|v| &v[..])) {
            (b"--db", Some(v)) => db = Some(v),
            (b"--serial", Some(v)) => serial = Some(v),
            (b"--reason", Some(v)) => reason = Some(v),
            (b"--date", Some(v)) => when = Some(v),
            _ => usage(),
        }
        i += 2;
    }
    let (Some(db), Some(serial)) = (db, serial) else {
        usage()
    };

    // fhsm_rev_entry_t's 64 bytes
    let Some(serial_bytes) = rev::hex_to_bytes(serial, 64) else {
        eprint!(
            "pqhsm-ca: --serial must be an even number of hex digits,\n  exactly as the certificate carries it. openssl x509\n  -noout -serial prints it in that form.\n"
        );
        return 2;
    };
    let mut code = -1;
    if let Some(r) = reason {
        code = rev::reason_code(r);
        if code == -2 {
            say(&[b"pqhsm-ca: unknown reason \"", r, b"\".\n  Accepted: "]);
            eprint!(
                "{}.\n  removeFromCRL is not accepted: it belongs to delta CRLs,\n  which this tool does not produce.\n",
                rev::reason_list()
            );
            return 2;
        }
    }
    let date = match when {
        Some(w) if rev::date_to_time(w).is_some() => w.to_vec(),
        Some(_) => {
            eprintln!("pqhsm-ca: --date must be YYYYMMDDHHMMSSZ, in UTC.");
            return 2;
        }
        // SAFETY: time(NULL).
        None => match rev::time_to_date(unsafe { libc::time(std::ptr::null_mut()) }) {
            Some(d) => d.into_bytes(),
            None => {
                eprintln!("pqhsm-ca: unrepresentable date");
                return 2;
            }
        },
    };

    let held = lock(db, true);
    let mut d = db_load(db);
    // Already there? Change nothing: re-revoking would list it twice in every CRL or move its
    // date. Leading zeros are ignored on both sides, as the responder compares.
    if let Some(had) = d.find(&serial_bytes) {
        say(&[
            b"pqhsm-ca: serial ",
            serial,
            b" is already revoked, on ",
            &had.date,
            b".\n  The database was left unchanged. Remove the line\n  by hand if the date or reason must be corrected.\n",
        ]);
        return 5;
    }
    if let Err(e) = d.add(Entry {
        serial: serial_bytes,
        date,
        reason: code,
    }) {
        say(&[b"pqhsm-ca: ", e.msg.as_bytes()]);
        return e.code;
    }
    db_save(db, &d);
    drop(held);
    eprint!(
        "pqhsm-ca: recorded. {} revoked in total.\n  Nothing is signed yet -- run `fhsm-ca crl` to publish a\n  list that says so.\n",
        d.entries.len()
    );
    0
}

/// `crl`: sign and emit the revocation list.
fn cmd_crl(args: &[Vec<u8>]) -> i32 {
    let mut c = Common::new();
    let mut db = None;
    parse(args, &mut c, true, |a, next| match (a, next) {
        (b"--db", Some(v)) => {
            db = Some(v);
            true
        }
        _ => false,
    });
    let (Some(label), Some(ca_p), Some(db)) = (c.label, c.ca_cert, db) else {
        usage()
    };
    let days = c.days.unwrap_or(30);
    check_days(days);

    let pin = user_pin();
    let ca_der = slurp(ca_p);

    // DIV-074: the number is reserved under the lock (loaded, advanced, saved), and the list
    // signed from that snapshot after it, so a revoke never waits on the token. A failure from
    // here on leaves a gap, never two lists under one number.
    let d = {
        let _held = lock(db, true);
        let mut d = db_load(db);
        d.crl_number = d.crl_number.wrapping_add(1);
        db_save(db, &d);
        d
    };
    let s = open_session(c.module, c.slot, pin);
    let der = ca::crl(s, label, &ca_der, &d, days).unwrap_or_else(|e| die(e));

    write_der(PROG, &der, c.out, c.pem, "X509 CRL");
    eprintln!(
        "pqhsm-ca: CRL number {}, {} revoked, valid {days} days.",
        d.crl_number,
        d.entries.len()
    );
    close_session(s);
    0
}

/// `ocsp-respond`: answer one OCSP request from the database, file in, file out.
fn cmd_ocsp_respond(args: &[Vec<u8>]) -> i32 {
    let mut c = Common::new();
    let (mut db, mut req, mut rcert) = (None, None, None);
    parse(args, &mut c, false, |a, next| {
        match (a, next) {
            (b"--db", Some(v)) => db = Some(v),
            (b"--req", Some(v)) => req = Some(v),
            (b"--responder-cert", Some(v)) => rcert = Some(v),
            _ => return false,
        }
        true
    });
    let (Some(label), Some(ca_p), Some(db), Some(req_p)) = (c.label, c.ca_cert, db, req) else {
        usage()
    };
    let days = c.days.unwrap_or(7);
    check_days(days);

    let pin = user_pin();
    let ca_der = slurp(ca_p);
    // Checked here, before the delegation check reads its subject.
    if !ca::is_certificate(&ca_der) {
        eprintln!("pqhsm-ca: --ca-cert is not a certificate.");
        return 2;
    }
    // By default the CA answers for itself; a delegate only when a verifier would accept it.
    let responder = match rcert {
        None => ca_der.clone(),
        Some(rp) => {
            let r = slurp(rp);
            if let Err(e) = rev::check_responder(&r, &ca_der, Some(&lossy(rp)), Some(&lossy(ca_p)))
            {
                say(&[b"pqhsm-ca: ", e.msg.as_bytes()]);
                return e.code;
            }
            r
        }
    };
    let req_der = slurp(req_p);
    let d = {
        let _held = lock(db, false);
        db_load(db)
    };

    let s = open_session(c.module, c.slot, pin);
    let req_name = lossy(req_p);
    let q = Query {
        req: &req_der,
        ca: &ca_der,
        responder: &responder,
        db: &d,
        days,
        label: Some(&req_name),
        // SAFETY: time(NULL).
        now: unsafe { libc::time(std::ptr::null_mut()) },
    };
    let (resp, st) = match ca::ocsp(s, label, &q) {
        Ok(v) => v,
        Err(e) => {
            say(&[b"pqhsm-ca: ", e.c_msg()]);
            close_session(s);
            return e.code;
        }
    };
    write_der(PROG, &resp, c.out, false, "");
    eprintln!(
        "pqhsm-ca: {} asked, {} ours ({} revoked), {} unknown, valid {days} days{}.",
        st.asked,
        st.ours,
        st.revoked,
        st.unknown,
        if st.nonce_echoed {
            ", nonce echoed"
        } else {
            ", no nonce"
        }
    );
    close_session(s);
    0
}

fn main() {
    init();
    let args: Vec<Vec<u8>> = std::env::args_os().map(OsStringExt::into_vec).collect();
    let rc = match args.get(1).map(|a| &a[..]) {
        Some(b"issue") => cmd_issue(&args),
        Some(b"revoke") => cmd_revoke(&args),
        Some(b"crl") => cmd_crl(&args),
        Some(b"ocsp-respond") => cmd_ocsp_respond(&args),
        _ => usage(),
    };
    exit(rc)
}

#[cfg(test)]
mod tests {
    use super::parse_days;

    /// DIV-073: only a whole positive decimal that fits an int is a number of days.
    #[test]
    fn days() {
        for (t, d) in [
            (&b"365"[..], 365),
            (b"007", 7),
            (b"2147483647", 2_147_483_647),
            (b"abc", 0),
            (b"10x", 0),
            (b"0", 0),
            (b"-1", 0),
            (b"+5", 0),
            (b" 5", 0),
            (b"", 0),
            (b"2147483648", 0),
            (b"99999999999999999999", 0),
        ] {
            assert_eq!(parse_days(t), d, "{t:?}");
        }
    }
}
