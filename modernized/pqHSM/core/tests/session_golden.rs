//! Replays `tests/golden/session.tsv`, recorded from the legacy `src/fhsm_session.c` by
//! `tests-support/golden/gen_session.c`, against the same stub token. Every result and every
//! token call must match, in order.

use std::cell::RefCell;
use std::ffi::{c_int, c_ulong};

use pqhsm_core::session::{OK, Table, Token};

thread_local! {
    static ROLES: RefCell<[c_int; 4]> = const { RefCell::new([0; 4]) };
    static TRACE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

/// Tokens 1-3 of the generator; 0 is NULL, which is `None` here.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Stub(usize);

impl Token for Stub {
    type Pin = &'static [u8];
    fn login(self, role: c_int, pin: &[u8]) -> u32 {
        let rv = ROLES.with_borrow_mut(|r| {
            if role != 1 && role != 2 {
                0x7
            } else if pin == b"bad" {
                0xA0
            } else if r[self.0] == role {
                0x100
            } else if r[self.0] != 0 {
                0x104
            } else {
                r[self.0] = role;
                0
            }
        });
        TRACE.with_borrow_mut(|t| t.push(format!("login({},{role})", self.0)));
        rv
    }
    fn logout(self) {
        ROLES.with_borrow_mut(|r| r[self.0] = 0);
        TRACE.with_borrow_mut(|t| t.push(format!("logout({})", self.0)));
    }
    fn role(self) -> c_int {
        ROLES.with_borrow(|r| r[self.0])
    }
}

fn tok(s: &str) -> Option<Stub> {
    match s.parse().unwrap() {
        0 => None,
        i => Some(Stub(i)),
    }
}

fn hex(rv: u32) -> String {
    if rv == 0 {
        "0".into()
    } else {
        format!("{rv:#x}")
    }
}

#[test]
fn replays_the_c_session_table() {
    let golden: &'static str = include_str!("golden/session.tsv");
    let table = Table::<Stub>::new();
    let mut rows = 0;
    for (n, line) in golden
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.starts_with('#'))
    {
        let [call, want, want_trace] = line.split('\t').collect::<Vec<_>>()[..] else {
            panic!("line {}: {line}", n + 1)
        };
        let a: Vec<&str> = call.split(' ').collect();
        let u = |i: usize| -> c_ulong { a[i].parse().unwrap() };
        let got = match a[0] {
            "open" => match table.open(u(1), u(2)) {
                Ok(h) => format!("0 {h}"),
                Err(rv) => format!("{} 0", hex(rv)),
            },
            "close" => hex(table.close(u(1))),
            "login" => hex(table.login(u(1), a[2].parse().unwrap(), a[3].as_bytes())),
            "logout" => hex(table.logout(u(1))),
            "attach" => hex(table.attach(u(1), tok(a[2]))),
            "token" => table.token(u(1)).map_or(0, |t| t.0).to_string(),
            "role" => table.role(u(1)).to_string(),
            "info" => match table.info(u(1)) {
                Ok((slot, flags, role)) => format!("{} {slot} {flags} {role}", hex(OK)),
                Err(rv) => format!("{} 99 99 99", hex(rv)),
            },
            "ro_exists" => (table.ro_exists(tok(a[1])) as u8).to_string(),
            "exists_on_slot" => (table.exists_on_slot(u(1)) as u8).to_string(),
            "reset_all" => {
                table.reset_all();
                "-".into()
            }
            "tokset" => {
                ROLES
                    .with_borrow_mut(|r| r[a[1].parse::<usize>().unwrap()] = a[2].parse().unwrap());
                "-".into()
            }
            op => panic!("line {}: unknown op {op}", n + 1),
        };
        let trace = TRACE.with_borrow_mut(std::mem::take);
        let trace = if trace.is_empty() {
            "-".into()
        } else {
            trace.join(",")
        };
        assert_eq!(
            (got.as_str(), trace.as_str()),
            (want, want_trace),
            "line {}: {call}",
            n + 1
        );
        rows += 1;
    }
    assert_eq!(rows, 274);
}
