//! `pqhsm-token migrate-zero-dek <slotN.tok>` (DIV-010): the one offline way back for a store the
//! ≤2.5.0 bug sealed under 32 zero bytes. It asks for the user PIN on stdin (no echo on a
//! terminal) and re-seals the store under the token's real DEK. Run it with the module stopped.
//!
//!   cargo build --release -p pqhsm-token --features tool
#[cfg(feature = "ffi")]
compile_error!("pqhsm-token is offline: build it with --features tool, without ffi");

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use pqhsm_token::token::migrate_zero_dek;
use zeroize::Zeroizing;

fn stty(arg: &str) {
    let _ = Command::new("stty")
        .arg(arg)
        .stdin(Stdio::inherit())
        .status();
}

fn read_pin() -> std::io::Result<Zeroizing<String>> {
    let tty = std::io::stdin().is_terminal();
    if tty {
        std::io::stderr().write_all(b"User PIN: ")?;
        stty("-echo");
    }
    // Room up front, so no reallocation frees a copy of the PIN.
    let mut pin = Zeroizing::new(String::with_capacity(256));
    let r = std::io::stdin().lock().read_line(&mut pin);
    if tty {
        stty("echo");
        let _ = std::io::stderr().write_all(b"\n");
    }
    r?;
    let n = pin.trim_end_matches(['\r', '\n']).len();
    pin.truncate(n);
    Ok(pin)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let [_, cmd, path] = args.as_slice() else {
        eprintln!("usage: pqhsm-token migrate-zero-dek <slotN.tok>");
        return ExitCode::from(2);
    };
    if cmd != "migrate-zero-dek" {
        eprintln!("usage: pqhsm-token migrate-zero-dek <slotN.tok>");
        return ExitCode::from(2);
    }
    let pin = match read_pin() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("pqhsm-token: reading the PIN: {e}");
            return ExitCode::from(1);
        }
    };
    match migrate_zero_dek(Path::new(path), pin.as_bytes()) {
        Ok(n) => {
            println!("{path}: {n} objects re-sealed under the token's DEK");
            ExitCode::SUCCESS
        }
        Err(rv) => {
            eprintln!(
                "pqhsm-token: {path}: not migrated (rv=0x{:x}); the file is unchanged",
                rv.0
            );
            ExitCode::from(1)
        }
    }
}
