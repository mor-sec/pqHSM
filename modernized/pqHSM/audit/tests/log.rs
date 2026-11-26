//! `log`: numbering (RULE-094), open/append/group commit and failure (RULE-007, RULE-096).
//! Numbering and stream expectations come from running the C module:
//! `golden/numbering.tsv` and `golden/streams/*.tsv`.

mod common;

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{KEY, field_hex, field_num, hex, lines, now_ns, tsv};
use pqhsm_audit::chain::chain_head;
use pqhsm_audit::log::{AuditError, AuditLog, Event, SEQ_DIGITS, Stats, highest_seq};
use pqhsm_audit::record::Role;
use pqhsm_audit::verify::verify_file;

const SIGN: Event<'static> = Event {
    code: 42,
    slot: 0,
    session: 1,
    role: Role::User,
    rv: 0,
    actor: None,
    params: &[(b"i", b"x")],
};

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

// ---- numbering (golden/numbering.tsv) --------------------------------------------------------

/// Lay out the scenario's existing files in a fresh directory; return it, the base, and the
/// leaf C created on each successive opening.
fn scenario(name: &str) -> (tempfile::TempDir, PathBuf, Vec<String>) {
    let rows = tsv("numbering.tsv");
    let row = rows
        .iter()
        .find(|r| r[0] == name)
        .unwrap_or_else(|| panic!("no scenario {name}"));
    let dir = tempfile::tempdir().unwrap();
    for f in row[1].split('/').filter(|f| !f.is_empty()) {
        std::fs::File::create(dir.path().join(f)).unwrap();
    }
    let base = dir.path().join("audit.log");
    let opened = row[2].split('/').map(str::to_owned).collect();
    (dir, base, opened)
}

fn numbering(name: &str, expected_highest: u64) {
    let (dir, base, c_opened) = scenario(name);
    assert_eq!(highest_seq(&base), expected_highest, "{name}: highest_seq");
    for leaf in c_opened {
        let log = AuditLog::open(&base, &KEY).unwrap();
        assert_eq!(
            log.path(),
            dir.path().join(&leaf),
            "{name}: C opened {leaf}"
        );
    }
}

macro_rules! numbering_case {
    ($($name:ident: $scenario:literal => $highest:expr;)*) => {$(
        #[test]
        fn $name() {
            // RULE-094
            numbering($scenario, $highest);
        }
    )*};
}

numbering_case! {
    first_opening_creates_000001_and_the_next_000002: "empty_dir" => 0;
    opening_after_000006_creates_000007: "after_000006" => 6;
    opening_steps_past_the_highest_not_into_a_hole: "after_000001_and_000003" => 3;
    five_digit_suffix_is_ignored: "five_digits_ignored" => 0;
    seven_digit_suffix_is_ignored: "seven_digits_ignored" => 0;
    other_prefixes_and_longer_names_are_ignored: "other_prefixes_ignored" => 0;
    non_numeric_suffixes_are_ignored: "non_numeric_ignored" => 0;
    strtoul_quirk_plus_sign_suffix_counts: "strtoul_plus_sign_counts" => 9;
    strtoul_quirk_leading_space_suffix_counts: "strtoul_leading_space_counts" => 9;
    strtoul_quirk_minus_suffix_is_ulong_max_and_next_wraps_to_000000: "strtoul_minus_wraps_to_000000" => u64::MAX;
    after_the_wrap_existing_files_are_stepped_over: "wrap_then_steps_past_existing" => u64::MAX;
    after_999999_the_suffix_grows_to_seven_digits_and_is_then_invisible: "after_999999_seven_digits" => 999_999;
}

#[test]
fn every_numbering_scenario_is_covered_by_a_named_test() {
    // RULE-094
    let src = include_str!("log.rs");
    for row in tsv("numbering.tsv") {
        assert!(
            src.contains(&format!("\"{}\"", row[0])),
            "untested scenario {}",
            row[0]
        );
    }
}

#[test]
fn highest_seq_of_an_unreadable_directory_is_zero() {
    // RULE-094: opendir fails -> 0
    assert_eq!(
        highest_seq(Path::new("/nonexistent-pqhsm-dir/audit.log")),
        0
    );
}

#[test]
fn open_in_a_missing_directory_is_an_open_error() {
    // RULE-094: C returns FUNCTION_FAILED (numbering.tsv: missing_directory rv=0x6)
    let row = tsv("numbering.tsv")
        .into_iter()
        .find(|r| r[0] == "missing_directory")
        .unwrap();
    assert_eq!(row[2], "rv=0x6");
    let dir = tempfile::tempdir().unwrap();
    let r = AuditLog::open(&dir.path().join("no-such-dir/audit.log"), &KEY);
    assert!(matches!(r, Err(AuditError::Open(_))), "{:?}", r.err());
}

#[test]
fn seq_digits_is_six() {
    // RULE-094
    assert_eq!(SEQ_DIGITS, 6);
}

// ---- open ------------------------------------------------------------------------------------

#[test]
fn opened_file_is_mode_0600_and_empty() {
    // RULE-094: O_EXCL, 0600; open writes nothing
    let dir = tempfile::tempdir().unwrap();
    let log = AuditLog::open(&dir.path().join("audit.log"), &KEY).unwrap();
    let md = std::fs::metadata(log.path()).unwrap();
    assert!(md.file_type().is_file());
    assert_eq!(md.permissions().mode() & 0o777, 0o600);
    assert_eq!(md.len(), 0);
}

#[test]
fn open_rejects_any_key_that_is_not_32_bytes() {
    // DIV-003: C accepted 1..=64; Rust accepts exactly 32
    let dir = tempfile::tempdir().unwrap();
    for len in [0usize, 1, 16, 31, 33, 64, 65] {
        let key = vec![7u8; len];
        let r = AuditLog::open(&dir.path().join("audit.log"), &key);
        assert!(
            matches!(r, Err(AuditError::ArgumentsBad)),
            "len {len}: {:?}",
            r.err()
        );
    }
    assert_eq!(
        std::fs::read_dir(dir.path()).unwrap().count(),
        0,
        "a rejected key creates no file"
    );
}

#[test]
fn audit_log_is_send_and_sync() {
    // RULE-096: one log shared by every thread
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AuditLog>();
}

// ---- append ----------------------------------------------------------------------------------

#[test]
fn seq_starts_at_1_and_the_first_prev_hmac_is_the_chain_head() {
    // RULE-007
    let dir = tempfile::tempdir().unwrap();
    let log = AuditLog::open(&dir.path().join("audit.log"), &KEY).unwrap();
    for _ in 0..3 {
        log.append(&SEQ_EVENT).unwrap();
    }
    let path = log.path().to_path_buf();
    drop(log);
    let data = read(&path);
    let ls = lines(&data);
    assert_eq!(
        ls.iter().map(|l| field_num(l, "seq")).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    assert_eq!(
        field_hex(ls[0], "prev_hmac"),
        hex(&chain_head(&KEY).unwrap())
    );
    assert_eq!(field_hex(ls[1], "prev_hmac"), field_hex(ls[0], "hmac"));
    assert_eq!(verify_file(&path, &KEY), Ok(()));
}

const SEQ_EVENT: Event<'static> = Event {
    code: 1,
    slot: -1,
    session: -1,
    role: Role::None,
    rv: 0,
    actor: None,
    params: &[],
};

#[test]
fn ts_is_wall_clock_nanoseconds_at_append() {
    // RULE-007: CLOCK_REALTIME in ns
    let dir = tempfile::tempdir().unwrap();
    let log = AuditLog::open(&dir.path().join("audit.log"), &KEY).unwrap();
    let before = now_ns();
    log.append(&SIGN).unwrap();
    let after = now_ns();
    let ts = field_num(&read(log.path()), "ts") as i64;
    assert!(before <= ts && ts <= after, "{before} <= {ts} <= {after}");
}

#[test]
fn sequential_appends_take_one_barrier_each() {
    // RULE-096: a lone writer always runs its own fdatasync
    let dir = tempfile::tempdir().unwrap();
    let log = AuditLog::open(&dir.path().join("audit.log"), &KEY).unwrap();
    assert_eq!(
        log.stats(),
        Stats {
            events: 0,
            barriers: 0
        }
    );
    for _ in 0..3 {
        log.append(&SIGN).unwrap();
    }
    assert_eq!(
        log.stats(),
        Stats {
            events: 3,
            barriers: 3
        }
    );
}

#[test]
fn eight_concurrent_writers_keep_one_chain_share_barriers_and_ts_follows_seq() {
    // RULE-007, RULE-096 group commit; DIV-002: ts non-decreasing in seq order
    const THREADS: usize = 8;
    const EACH: usize = 40;
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(AuditLog::open(&dir.path().join("audit.log"), &KEY).unwrap());
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let actor = format!("CN=writer{t}");
                for _ in 0..EACH {
                    log.append(&Event {
                        actor: Some(actor.as_bytes()),
                        ..SIGN
                    })
                    .unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let stats = log.stats();
    assert_eq!(stats.events, (THREADS * EACH) as u64);
    assert!(
        stats.barriers >= 1 && stats.barriers <= stats.events,
        "{stats:?}"
    );
    let path = log.path().to_path_buf();
    drop(log);
    assert_eq!(verify_file(&path, &KEY), Ok(()));
    let data = read(&path);
    let ts: Vec<i128> = lines(&data).iter().map(|l| field_num(l, "ts")).collect();
    assert_eq!(ts.len(), THREADS * EACH);
    assert!(
        ts.windows(2).all(|w| w[0] <= w[1]),
        "DIV-002: ts decreased between consecutive seq"
    );
}

#[test]
fn dropping_the_log_and_reopening_starts_a_new_numbered_file_and_a_new_chain() {
    // RULE-094, RULE-076 (close then re-init opens a new file)
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("audit.log");
    let log = AuditLog::open(&base, &KEY).unwrap();
    log.append(&SIGN).unwrap();
    let first = log.path().to_path_buf();
    drop(log);
    let log = AuditLog::open(&base, &KEY).unwrap();
    assert_eq!(log.path(), dir.path().join("audit.log.000002"));
    log.append(&SIGN).unwrap();
    let second = log.path().to_path_buf();
    drop(log);
    assert_eq!(first, dir.path().join("audit.log.000001"));
    for p in [&first, &second] {
        assert_eq!(verify_file(p, &KEY), Ok(()));
        assert_eq!(
            field_hex(&read(p), "prev_hmac"),
            hex(&chain_head(&KEY).unwrap())
        );
    }
}

// ---- failure and latch -----------------------------------------------------------------------

#[test]
fn latch_reasons_are_the_c_strings() {
    // RULE-096: the reason passed to fhsm_state_latch_error
    let io = || std::io::Error::other("x");
    assert_eq!(
        AuditError::LineTruncated.latch_reason(),
        Some("audit line truncated")
    );
    assert_eq!(AuditError::Hmac.latch_reason(), Some("audit HMAC failed"));
    assert_eq!(
        AuditError::SuffixTruncated.latch_reason(),
        Some("audit suffix truncated")
    );
    assert_eq!(
        AuditError::Write(io()).latch_reason(),
        Some("audit write failed")
    );
    assert_eq!(
        AuditError::SyncFailed.latch_reason(),
        Some("audit fsync failed")
    );
    assert_eq!(AuditError::ArgumentsBad.latch_reason(), None);
    assert_eq!(AuditError::Open(io()).latch_reason(), None);
}

/// `golden/streams/<name>.tsv` as a map.
fn stream_golden(name: &str) -> HashMap<String, String> {
    tsv(&format!("streams/{name}.tsv"))
        .into_iter()
        .map(|r| (r[0].clone(), r[1].clone()))
        .collect()
}

#[test]
fn dev_null_is_opened_unnumbered_and_its_failed_barrier_fails_every_append() {
    // RULE-094 stream base; RULE-096: fdatasync(/dev/null) is EINVAL on Linux
    let c = stream_golden("dev_null");
    assert_eq!(
        (c["open"].as_str(), c["current_path"].as_str()),
        ("0x0", "/dev/null")
    );
    assert_eq!((c["event1"].as_str(), c["event2"].as_str()), ("0x6", "0x6"));
    let log = AuditLog::open(Path::new("/dev/null"), &KEY).unwrap();
    assert_eq!(log.path(), Path::new("/dev/null"));
    assert!(matches!(log.append(&SIGN), Err(AuditError::SyncFailed)));
    assert!(matches!(log.append(&SIGN), Err(AuditError::SyncFailed)));
    let want = Stats {
        events: c["stats_events"].parse().unwrap(),
        barriers: c["stats_barriers"].parse().unwrap(),
    };
    assert_eq!(
        log.stats(),
        want,
        "C: one event written, one barrier, nothing after the failure"
    );
}

#[test]
fn dev_full_write_failure_is_a_write_error_and_counts_nothing() {
    // RULE-096 "audit write failed"
    let c = stream_golden("dev_full");
    assert_eq!((c["event1"].as_str(), c["event2"].as_str()), ("0x6", "0x6"));
    let log = AuditLog::open(Path::new("/dev/full"), &KEY).unwrap();
    assert_eq!(log.path(), Path::new("/dev/full"));
    assert!(matches!(log.append(&SIGN), Err(AuditError::Write(_))));
    assert!(log.append(&SIGN).is_err());
    let want = Stats {
        events: c["stats_events"].parse().unwrap(),
        barriers: c["stats_barriers"].parse().unwrap(),
    };
    assert_eq!(log.stats(), want);
}

#[test]
fn fifo_sync_failure_is_sticky_and_nothing_is_written_after_it() {
    // RULE-096: tests/test_audit_fsync.c technique. C (streams/fifo.tsv): 3 events all fail,
    // one line reaches the reader, 1 event and 1 barrier counted. C writes nothing after the
    // failure because fhsm_hmac refuses once ERROR is latched (src/fhsm_crypto.c:508).
    let c = stream_golden("fifo");
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("audit.fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert!(std::fs::metadata(&fifo).unwrap().file_type().is_fifo());
    let reader = {
        let fifo = fifo.clone();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            std::fs::File::open(fifo)
                .unwrap()
                .read_to_end(&mut buf)
                .unwrap();
            buf
        })
    };
    let log = AuditLog::open(&fifo, &KEY).unwrap();
    assert_eq!(log.path(), fifo, "a FIFO base is used as given, unnumbered");
    for i in 1..=3 {
        assert_eq!(c[&format!("event{i}")], "0x6");
        let r = log.append(&SIGN);
        assert!(
            matches!(r, Err(AuditError::SyncFailed)),
            "append {i}: {:?}",
            r.err()
        );
    }
    let want = Stats {
        events: c["stats_events"].parse().unwrap(),
        barriers: c["stats_barriers"].parse().unwrap(),
    };
    assert_eq!(log.stats(), want);
    drop(log);
    let drained = reader.join().unwrap();
    assert_eq!(lines(&drained).len().to_string(), c["drained_lines"]);
    let copy = dir.path().join("drained.log");
    std::fs::write(&copy, &drained).unwrap();
    assert_eq!(
        verify_file(&copy, &KEY),
        Ok(()),
        "the one line that was written is a valid chain"
    );
}

/// legacy/tests/test_audit_multiproc.c (Phase 6 slice 5c): two logs opened on one base at the
/// same moment get two numbered files (the EEXIST retry), numbered next to each other; each holds
/// its own events and verifies.
#[test]
fn two_simultaneous_opens_of_one_base_get_adjacent_files_that_each_verify() {
    const EACH: usize = 25;
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("audit.log");
    let go = Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|t| {
            let (base, go) = (base.clone(), Arc::clone(&go));
            std::thread::spawn(move || {
                go.wait();
                let log = AuditLog::open(&base, &KEY).unwrap();
                let actor = format!("CN=opener{t}");
                for _ in 0..EACH {
                    log.append(&Event { actor: Some(actor.as_bytes()), ..SIGN }).unwrap();
                }
                log.path().to_path_buf()
            })
        })
        .collect();
    let mut paths: Vec<PathBuf> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    paths.sort();
    assert_ne!(paths[0], paths[1]);
    let seq = |p: &Path| -> u64 { p.extension().unwrap().to_str().unwrap().parse().unwrap() };
    assert_eq!(seq(&paths[1]), seq(&paths[0]) + 1, "{paths:?}");
    for p in &paths {
        assert_eq!(verify_file(p, &KEY), Ok(()), "{}", p.display());
        assert_eq!(lines(&read(p)).len(), EACH, "{}", p.display());
    }
}
