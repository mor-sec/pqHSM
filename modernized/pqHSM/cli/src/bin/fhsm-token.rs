//! `fhsm-token`: initialise a token and say what state a slot is in (`tools/fhsm_token.c`,
//! PHASE5_PLAN.md slice 2). Flags, messages and exit codes are C's. Both PINs come from
//! FHSM_SO_PIN and FHSM_PIN, or are asked for at a terminal (DIV-072); never from an argument.

use std::ffi::{CString, c_long};
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt;
use std::process::exit;

use pqhsm_cli::{fail, init, new_pin};
use pqhsm_pkiops::ops;
use pqhsm_pkiops::{Error, Intent, close, open, parse_slot};

const PROG: &str = "pqhsm-token";

const USAGE: &str = concat!(
    "fhsm-token --- provision a token\n\n",
    "  fhsm-token init [--label TEXT] [--slot N] [--module PATH]\n",
    "  fhsm-token info [--slot N] [--module PATH]\n\n",
    "  --label TEXT    token label, at most 32 characters (default \"freehsm\")\n",
    "  --slot N        slot to address. Default: the lowest empty slot for\n",
    "                  init, the one initialised token for info.\n",
    "  --module PATH   PKCS#11 module (default ./libfreehsm.so)\n\n",
    "  init reads the Security Officer PIN from FHSM_SO_PIN and the user PIN\n",
    "  from FHSM_PIN. Neither can be passed as an argument: arguments are\n",
    "  visible in ps to every user on the machine.\n\n",
    "  WARNING: init on an already-initialised token DESTROYS every key it\n",
    "  holds. That is what C_InitToken means, and this tool refuses to run\n",
    "  it unless --force is given.\n\n",
    "  Exit codes: 0 success. 1 usage, or a PIN not set in the environment.\n",
    "  2 module or PKCS#11 failure. 5 the token is already initialised and\n",
    "  --force was not given.\n",
);

fn usage() -> ! {
    eprint!("{USAGE}");
    exit(1)
}

fn die(e: Error) -> ! {
    fail(PROG, &e)
}

/// stderr as bytes: labels need not be UTF-8.
fn say(parts: &[&[u8]]) {
    let _ = io::stderr().lock().write_all(&parts.concat());
}

fn cmd_info(module: &CString, slot: c_long) -> i32 {
    let sid = open(Some(module), slot, Intent::Any).unwrap_or_else(|e| die(e));
    let ti = ops::token_info(sid).unwrap_or_else(|e| die(e));
    let mut out = format!("slot {sid}\n").into_bytes();
    let mut row = |name: &str, v: &[u8]| {
        out.extend(format!("  {name:<14} ").as_bytes());
        out.extend(v);
        out.push(b'\n');
    };
    row("label", ops::text(&ti.label));
    row("manufacturer", ops::text(&ti.manufacturer));
    row("model", ops::text(&ti.model));
    row("serial", ops::text(&ti.serial));
    row(
        "initialised",
        if ti.initialised != 0 {
            b"yes"
        } else {
            b"no  -- run `fhsm-token init`"
        },
    );
    row(
        "user PIN",
        if ti.user_pin_set != 0 {
            b"set"
        } else {
            b"not set"
        },
    );
    if ti.so_pin_locked != 0 {
        row("warning", b"SO PIN is LOCKED");
    }
    if ti.user_pin_locked != 0 {
        row("warning", b"user PIN is LOCKED");
    }
    row(
        "PIN length",
        format!("{}..{}", ti.min_pin, ti.max_pin).as_bytes(),
    );
    let mut w = io::stdout().lock();
    // C ignores what printf returns.
    let _ = w.write_all(&out).and_then(|()| w.flush());
    close();
    0
}

fn cmd_init(module: &CString, slot: c_long, label: &[u8], force: bool) -> i32 {
    let so = new_pin(
        PROG,
        "FHSM_SO_PIN",
        "Security Officer PIN",
        concat!(
            "pqhsm-token: FHSM_SO_PIN is not set.\n",
            "  The Security Officer PIN initialises the token and can reset the\n",
            "  user PIN. It is read from the environment, never from an argument.\n",
        ),
    );
    let user = new_pin(
        PROG,
        "FHSM_PIN",
        "new user PIN",
        concat!(
            "pqhsm-token: FHSM_PIN is not set.\n",
            "  init sets the user PIN as well, so both are needed. Setting only\n",
            "  the SO PIN would leave a token no application can log into.\n",
        ),
    );
    // Resolved once, before anything is written: a slot the operator did not choose is the
    // one mistake here that cannot be undone.
    let sid = open(Some(module), slot, Intent::ForInit).unwrap_or_else(|e| die(e));

    // The module's own bounds, so a pasted placeholder PIN is explained, not a numeric code.
    let (mut lo, mut hi) = (4, 64);
    if let Ok(ti) = ops::token_info(sid)
        && ti.min_pin != 0
        && ti.min_pin <= ti.max_pin
    {
        (lo, hi) = (ti.min_pin, ti.max_pin);
    }
    let bad = |p: &[u8]| (p.len() as u64) < lo || p.len() as u64 > hi;
    let which = match (bad(&so), bad(&user)) {
        (true, true) => Some("FHSM_SO_PIN and FHSM_PIN are"),
        (true, false) => Some("FHSM_SO_PIN is"),
        (false, true) => Some("FHSM_PIN is"),
        (false, false) => None,
    };
    if let Some(which) = which {
        eprint!(
            "pqhsm-token: {which} outside the token's accepted length ({lo}..{hi} characters).\n  Nothing was changed. If you pasted a placeholder from a\n  manual, that is the usual cause.\n"
        );
        close();
        return 1;
    }
    if label.len() > 32 {
        eprintln!(
            "pqhsm-token: --label is at most 32 characters (PKCS#11 pads it to exactly that)."
        );
        close();
        return 1;
    }
    // C_InitToken destroys every object: an operator who typed init meaning info should not
    // lose a CA key to a four-character difference. Asked again, as C does.
    if !force
        && let Ok(ti) = ops::token_info(sid)
        && ti.initialised != 0
    {
        say(&[
            format!("pqhsm-token: slot {sid} already holds an initialised token (\"").as_bytes(),
            ops::text(&ti.label),
            b"\").\n  Re-initialising DESTROYS every key on it. If that is what you\n  want, pass --force. If you meant to look, use `fhsm-token info`.\n",
        ]);
        close();
        return 5;
    }
    ops::token_init(sid, &so, &user, label).unwrap_or_else(|e| die(e));
    drop((so, user));
    close();
    say(&[
        format!("pqhsm-token: slot {sid} initialised as \"").as_bytes(),
        label,
        b"\", user PIN set.\n  Next: fhsm-csr keygen --label NAME\n",
    ]);
    0
}

fn main() {
    init();
    let args: Vec<Vec<u8>> = std::env::args_os().map(|a| a.into_vec()).collect();
    if args.len() < 2 {
        usage();
    }
    let mut module: &[u8] = b"./libfreehsm.so";
    let mut label: &[u8] = b"freehsm";
    let (mut force, mut slot) = (false, -1);
    let mut i = 2;
    while i < args.len() {
        let a = &args[i][..];
        match (a, args.get(i + 1).map(|v| &v[..])) {
            (b"--module", Some(v)) => module = v,
            (b"--label", Some(v)) => label = v,
            (b"--slot", Some(v)) => slot = parse_slot(v).unwrap_or_else(|e| die(e)),
            (b"--force", _) => {
                force = true;
                i += 1;
                continue;
            }
            _ if a.starts_with(b"--pin") || a.starts_with(b"--so-pin") => {
                eprint!(
                    "pqhsm-token: PINs are not accepted as arguments. Set\n  FHSM_SO_PIN and FHSM_PIN instead: an argument is visible in\n  ps to every user on this machine.\n"
                );
                exit(1);
            }
            _ => usage(),
        }
        i += 2;
    }
    // An argument holds no NUL.
    let module = CString::new(module).expect("no NUL in an argument");
    let rc = match &args[1][..] {
        b"init" => cmd_init(&module, slot, label, force),
        b"info" => cmd_info(&module, slot),
        _ => usage(),
    };
    exit(rc)
}
