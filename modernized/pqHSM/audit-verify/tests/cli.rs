//! The auditor tool must reproduce C `tools/freehsm-audit` byte for byte: stdout, stderr and
//! exit code (RULE-008). Every case under `tests/golden/cli/<case>/` was recorded by running
//! the C binary as `freehsm-audit` with this crate's root as its working directory, so the
//! relative paths it printed are the ones cargo's test cwd resolves. See
//! `legacy/hybrid/golden/regen.sh`.

use std::path::{Path, PathBuf};

use pqhsm_audit_verify::{dump_file, run, verify_dir, verify_file};

fn case_dir(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/cli")
        .join(name)
}

struct Recorded {
    args: Vec<String>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit: i32,
}

fn recorded(name: &str) -> Recorded {
    let d = case_dir(name);
    let read = |f: &str| {
        std::fs::read(d.join(f)).unwrap_or_else(|e| panic!("golden {name}/{f}: {e} (run regen.sh)"))
    };
    let args = String::from_utf8(read("args")).unwrap();
    Recorded {
        args: args
            .strip_suffix('\n')
            .unwrap_or(&args)
            .split('\n')
            .map(str::to_owned)
            .collect(),
        stdout: read("stdout"),
        stderr: read("stderr"),
        exit: String::from_utf8(read("exit"))
            .unwrap()
            .trim()
            .parse()
            .unwrap(),
    }
}

fn assert_same(what: &str, c: &Recorded, code: i32, out: &[u8], err: &[u8]) {
    assert_eq!(
        String::from_utf8_lossy(out),
        String::from_utf8_lossy(&c.stdout),
        "{what}: stdout"
    );
    assert_eq!(out, &c.stdout[..], "{what}: stdout bytes");
    assert_eq!(
        String::from_utf8_lossy(err),
        String::from_utf8_lossy(&c.stderr),
        "{what}: stderr"
    );
    assert_eq!(err, &c.stderr[..], "{what}: stderr bytes");
    assert_eq!(code, c.exit, "{what}: exit code");
}

/// DIV-008: cases where C reported `verify: 6 records OK` and the tool fails these lines,
/// which do not end with their MAC in lowercase and `"}`.
fn div008_failed_lines(name: &str) -> Option<&'static [u32]> {
    match name {
        "verify_log_crlf" | "verify_log_hmac_uppercase_all" => Some(&[1, 2, 3, 4, 5, 6]),
        "verify_log_hmac_plus_sign" => Some(&[1]),
        "verify_log_trailer_altered_line3" => Some(&[3]),
        _ => None,
    }
}

fn check(name: &str) {
    let mut c = recorded(name);
    if let Some(lines) = div008_failed_lines(name) {
        assert_eq!(
            (c.exit, &c.stdout[..]),
            (0, &b"verify: 6 records OK, chain intact\n"[..]),
            "{name}: C accepted it"
        );
        let mut err: String = lines
            .iter()
            .map(|n| {
                format!("line {n} : record does not end with its lowercase hmac (record altered)\n")
            })
            .collect();
        err += &format!("verify: {}/6 records FAILED\n", lines.len());
        (c.exit, c.stdout, c.stderr) = (1, Vec::new(), err.into_bytes());
    }
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = run(&c.args, &mut out, &mut err);
    assert_same(&format!("{name} via run"), &c, code, &out, &err);

    // The library entry points on their own give the same three results.
    let a: Vec<&str> = c.args.iter().map(String::as_str).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let direct = match a.as_slice() {
        [_, "verify", p, k] if Path::new(p).is_dir() => {
            Some(verify_dir(Path::new(p), k, &mut out, &mut err))
        }
        [_, "verify", p, k] => Some(verify_file(Path::new(p), k, &mut out, &mut err)),
        [_, "dump", p] => Some(dump_file(Path::new(p), &mut out, &mut err)),
        _ => None,
    };
    if let Some(code) = direct {
        assert_same(
            &format!("{name} via the library function"),
            &c,
            code,
            &out,
            &err,
        );
    }
}

macro_rules! cli_case {
    ($($name:ident,)*) => {
        $(
            #[test]
            fn $name() {
                // RULE-008
                check(stringify!($name));
            }
        )*
        const CASES: &[&str] = &[$(stringify!($name)),*];
    };
}

cli_case! {
    // usage
    usage_no_args,
    usage_dump_without_path,
    usage_verify_one_arg,
    usage_verify_too_many_args,
    usage_unknown_command,
    // keys
    verify_key_63_chars,
    verify_key_65_chars,
    verify_key_non_hex,
    verify_key_uppercase,
    verify_key_sscanf_plus_sign,
    verify_key_sscanf_leading_space,
    verify_key_sscanf_minus_sign,
    verify_key_checked_before_file,
    verify_wrong_key,
    verify_key16_log_cannot_be_verified,
    // files
    verify_missing_file,
    verify_baseline_fixture,
    verify_log_chain,
    verify_log_baseline,
    verify_log_body_flip_line3,
    verify_log_mac_flip_line3,
    verify_log_line3_deleted,
    verify_log_lines3_4_swapped,
    verify_log_seq_renumbered_line3,
    verify_log_hmac_uppercase_all,
    verify_log_prev_hmac_uppercase_line2,
    verify_log_field_missing_seq_line2,
    verify_log_field_missing_hmac_line4,
    verify_log_hmac_63_hex_line5,
    verify_log_hmac_plus_sign,
    verify_log_long_line_appended,
    verify_log_empty,
    verify_log_no_final_newline,
    verify_log_crlf,
    verify_log_tail_truncated,
    verify_log_line3_duplicated,
    verify_log_blank_line_inserted_before_3,
    verify_log_nul_in_body_line3,
    verify_log_trailer_altered_line3,
    verify_log_lines,
    verify_log_newline_key,
    verify_log_key16,
    verify_log_key64,
    verify_log_craft_fixed_ts,
    verify_log_craft_minimal_fields,
    verify_log_craft_prev_hmac_uppercase_in_body,
    verify_log_craft_seq_leading_zeros,
    verify_log_craft_seq_sign_and_space,
    verify_log_craft_seq_trailing_junk,
    // directories
    verify_dir_contiguous,
    verify_dir_hole,
    verify_dir_starts_at_000002,
    verify_dir_tampered_file,
    verify_dir_no_numbered_files,
    verify_dir_trailing_slash,
    verify_dir_bad_key,
    // dump
    dump_chain,
    dump_edge_case_lines,
    dump_long_line,
    dump_crafted_minimal_fields,
    dump_missing_file,
    dump_two_files_one_missing,
    dump_empty_file,
}

#[test]
fn every_recorded_case_has_a_named_test() {
    // RULE-008: a regen that adds a case must add its test
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/cli");
    let mut recorded: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    recorded.sort();
    let mut named: Vec<String> = CASES.iter().map(|s| s.to_string()).collect();
    named.sort();
    assert_eq!(named, recorded);
}
