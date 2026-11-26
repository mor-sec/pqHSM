//! Replays `tests/golden/state.tsv`, recorded from the legacy `src/fhsm_state.c` by
//! `legacy/hybrid/golden/gen_state.c`. Every result must match, and so must the audit event
//! the C ABI emits for it, rendered here from what [`State`] returns, as `p11`'s ABI does.

use pqhsm_core::state::{POWER_OFF, State};

fn hex(rv: u32) -> String {
    if rv == 0 {
        "0".into()
    } else {
        format!("{rv:#x}")
    }
}

#[test]
fn replays_the_c_state_machine() {
    let golden = include_str!("golden/state.tsv");
    let parent = State::new();
    // The rows between "fork" and "join" ran in a forked child of a POWER_OFF parent.
    let child = State::new();
    let mut in_child = false;
    let mut rows = 0;
    for (n, line) in golden
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.starts_with('#'))
    {
        let [call, want, want_events] = line.split('\t').collect::<Vec<_>>()[..] else {
            panic!("line {}: {line}", n + 1)
        };
        let (op, arg) = call.split_once(' ').unwrap_or((call, ""));
        let state = if in_child { &child } else { &parent };
        let (got, events) = match op {
            "fork" | "join" => {
                assert_eq!(parent.get(), POWER_OFF, "line {}", n + 1);
                in_child = op == "fork";
                ("-".into(), "-".into())
            }
            "get" => (state.get().to_string(), "-".to_string()),
            "set" => {
                let to = arg.parse().unwrap();
                match state.set(to) {
                    Ok(from) => ("0".into(), format!("ev6:rv=0:from={from}:to={to}")),
                    Err(rv) => (hex(rv), "-".into()),
                }
            }
            "reset_after_fork" => {
                state.reset_after_fork();
                ("-".into(), "-".into())
            }
            "latch" => {
                let reason = if arg == "NULL" { "(none)" } else { arg };
                let ev = if state.latch() {
                    format!("ev6:rv=0x6:to=ERROR:reason={reason}")
                } else {
                    "-".into()
                };
                ("-".into(), ev)
            }
            op => panic!("line {}: unknown op {op}", n + 1),
        };
        assert_eq!(
            (got.as_str(), events.as_str()),
            (want, want_events),
            "line {}: {call}",
            n + 1
        );
        rows += 1;
    }
    assert_eq!(rows, 186);
}
