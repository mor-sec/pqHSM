//! Characterization tests for Phase 2 slice 1: `src/fhsm_tpm.c` and `src/fhsm_token_tpm.c`
//! (RULE-089), against what the legacy C code did when driven through the
//! FHSM_TPM_TEST_HOOKS seam and `tests/tpm2-stub.sh`.
//!
//! Every expected value is a row of `golden/tpm/cases.tsv`, written by
//! `tests-support/golden/gen_tpm.c`. A test names its row, rebuilds the row's inputs, calls
//! the Rust API, and compares the return code, the bytes, the files left behind, and the
//! exact tpm2 subcommands (`golden/tpm/log/`). Where Rust is meant to differ (DIV-015,
//! DIV-017), the test first asserts what C did and then what Rust must do.
//!
//! Like the stub, these tests prove the plumbing on our side of the CLI. They prove nothing
//! about the TPM: PCR binding, the sealing crypto and tamper detection need real hardware.

mod common;

use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::*;
use pqhsm_token::tpm::{self, Cli, Tpm};

/// DIV-015(d) and DIV-031(b): C wrote the sealed blob into a FIFO staged at `{tok}.tpm.new`
/// (where `write` works and `fsync` fails with EINVAL, per tests/test_audit_fsync.c), never
/// checked the fsync, renamed the FIFO into place and reported OK. Rust removes whatever is at
/// the tmp name and creates a fresh file (DIV-031), so the FIFO gets nothing and the seal
/// succeeds normally. The fsync check DIV-015(d) added is still in `seal_companion`; staging a
/// FIFO no longer reaches it, as DIV-022 noted for the revocation DB's `/dev/full` row.
/// (case, C rv, Rust rv)
const DIV015: &[(&str, &str, &str)] = &[("tok_seal_stale_tmp_fifo", "0x0", "0x0")];

/// DIV-017: memfds are `MFD_CLOEXEC`. The flag is cleared only in the tpm2 child, so an
/// unrelated fork+exec made while a seal is in flight sees none of them. C's child saw all
/// four, the DEK input included. (case, what C's child saw, what Rust's must see)
const DIV017: &[(&str, &str, &str)] = &[(
    "div017_fork_during_seal",
    "fhsm-seal-in,fhsm-seal-policy,fhsm-seal-priv,fhsm-seal-pub",
    "none",
)];

/// DIV-018: a tpm2 output that does not fit is an error. C cut a pub or priv over 512 bytes
/// short and returned OK (a blob that can never unseal), and kept the first 32 of more than 32
/// bytes back from `tpm2 unseal`. (case, C rv, Rust rv)
const DIV018: &[(&str, &str, &str)] = &[
    ("seal_quirk_pub_513", "0x0", "0x6"),
    ("unseal_quirk_out_40", "0x0", "0x6"),
];

// ---------------------------------------------------------------------------------------
// Runners: one per C function, driven entirely by the row
// ---------------------------------------------------------------------------------------

fn run_available(name: &str) {
    let c = case(name);
    assert_eq!(c.op, "available");
    let fx = Fx::new();
    let t = fx.tpm(&c, "");
    assert_eq!(
        (t.available() as i32).to_string(),
        c.rv,
        "{name}: available()"
    );
    assert_eq!(
        fx.log()
            .lines()
            .filter(|l| l.starts_with("startup"))
            .count()
            .to_string(),
        c.get("startup_calls"),
        "{name}: probes run"
    );
    fx.check_logs(&c);
}

fn run_seal(name: &str) {
    let c = case(name);
    assert_eq!(c.op, "seal");
    let fx = Fx::new();
    let t = fx.tpm(&c, "");
    fx.ready(&c, &t);
    let mut out = vec![0xEE; c.get("cap").parse().unwrap()];
    let r = t.seal(&S, &mut out);
    let rv = div018(name, &c.rv);
    assert_eq!(rv_text(&r), rv, "{name}: rv");
    match r {
        Ok(n) => assert_eq!(hex(&out[..n]), c.get("blob"), "{name}: blob"),
        Err(_) => {
            assert!(c.opt("out") == Some("untouched") || rv != c.rv);
            assert!(
                out.iter().all(|b| *b == 0xEE),
                "{name}: out written on failure"
            );
        }
    }
    fx.check_logs(&c);
}

fn run_unseal(name: &str) {
    let c = case(name);
    assert_eq!(c.op, "unseal");
    let fx = Fx::new();
    let t = fx.tpm(&c, "");
    fx.ready(&c, &t);
    let mut out = [0xCC; 32];
    let r = t.unseal(&unhex(c.get("blob_in")), &mut out);
    let rv = div018(name, &c.rv);
    assert_eq!(rv_text(&r), rv, "{name}: rv");
    // a DIV-018 failure comes after the header checks, so it leaves zeros
    let want = if rv == c.rv {
        c.get("out").to_owned()
    } else {
        hex(&[0; 32])
    };
    assert_eq!(hex(&out), want, "{name}: caller's buffer afterwards");
    fx.check_logs(&c);
}

/// The Rust rv for a row: C's, unless DIV-018 changes it (C's value is checked first).
fn div018(name: &str, c_rv: &str) -> String {
    match DIV018.iter().find(|(n, _, _)| *n == name) {
        Some(&(_, c, rust)) => {
            assert_eq!(c_rv, c, "{name}: C's result");
            rust.into()
        }
        None => c_rv.into(),
    }
}

fn run_token(name: &str) {
    let c = case(name);
    if c.is("pre", "unreadable") {
        require_unprivileged(name);
    }
    let fx = Fx::new();
    let t = fx.tpm(&c, "");
    fx.ready(&c, &t);
    let tok = tok_for(fx.path(), &c);
    let fifo = prepare(&tok, &c);
    match c.op.as_str() {
        "token_seal" => {
            let r = t.seal_companion(&tok, &S);
            let (mut rv, mut after_tpm, mut after_tmp, mut drained) = (
                c.rv.clone(),
                c.get("after_tpm").to_owned(),
                c.get("after_tmp").to_owned(),
                c.opt("drained").unwrap_or_default().to_owned(),
            );
            if let Some(&(_, c_rv, rust_rv)) = DIV015.iter().find(|(n, _, _)| *n == name) {
                assert_eq!(
                    (rv.as_str(), after_tpm.as_str()),
                    (c_rv, "fifo"),
                    "{name}: C renamed the FIFO into place"
                );
                // the blob C pushed through the FIFO lands in a regular .tpm instead
                after_tpm = format!("file:0600:{drained}");
                (rv, after_tmp, drained) = (rust_rv.into(), "absent".into(), String::new());
            }
            if let Some(mut f) = fifo {
                let mut got = Vec::new();
                let _ = f.read_to_end(&mut got);
                assert_eq!(hex(&got), drained, "{name}: bytes written to the stale tmp");
            }
            assert_eq!(rv_text(&r), rv, "{name}: rv");
            assert_eq!(state(&with(&tok, ".tpm")), after_tpm, "{name}: {{tok}}.tpm");
            assert_eq!(
                state(&with(&tok, ".tpm.new")),
                after_tmp,
                "{name}: {{tok}}.tpm.new"
            );
            assert_eq!(state(&tok), c.get("after_tok"), "{name}: the .tok itself");
        }
        "token_unseal" => {
            let mut out = [0xCC; 32];
            let r = t.unseal_companion(&tok, &mut out);
            assert_eq!(rv_text(&r), c.rv, "{name}: rv");
            assert_eq!(
                hex(&out),
                c.get("out"),
                "{name}: caller's buffer afterwards"
            );
        }
        "blob_exists" => {
            assert_eq!(
                (tpm::companion_exists(&tok) as i32).to_string(),
                c.rv,
                "{name}"
            );
        }
        "unlink" => {
            tpm::unlink_companion(&tok);
            assert_eq!(
                state(&with(&tok, ".tpm")),
                c.get("after_tpm"),
                "{name}: after unlink"
            );
        }
        op => panic!("{name}: op {op}"),
    }
    fx.check_logs(&c);
}

fn run_required(name: &str) {
    let c = case(name);
    let bytes = c.opt("value_hex").map(unhex);
    let v = bytes.as_deref().map(OsStr::from_bytes);
    assert_eq!(
        (tpm::sealing_required_value(v) as i32).to_string(),
        c.rv,
        "{name}"
    );
}

fn run_dek(name: &str) {
    let c = case(name);
    let a: [u8; 32] = unhex(c.get("a")).try_into().unwrap();
    let b: [u8; 32] = unhex(c.get("b")).try_into().unwrap();
    assert_eq!((tpm::dek_match(&a, &b) as i32).to_string(), c.rv, "{name}");
}

macro_rules! golden {
    ($($test:ident => $run:ident($case:literal);)*) => {$(
        #[test]
        fn $test() {
            // RULE-089
            $run($case);
        }
    )*};
}

// ---------------------------------------------------------------------------------------
// fhsm_tpm_available
// ---------------------------------------------------------------------------------------
golden! {
    no_device_node_means_unavailable_without_running_tpm2 => run_available("avail_no_device");
    device_node_and_a_clean_startup_mean_available => run_available("avail_ok");
    failing_startup_means_unavailable => run_available("avail_startup_fails");
    missing_tpm2_command_means_unavailable => run_available("avail_cmd_missing");
    device_check_is_existence_only_so_a_directory_passes => run_available("avail_device_is_dir");
    first_seal_runs_the_startup_probe_before_createpolicy => run_seal("avail_first_seal_probes");
}

#[test]
fn exec_of_a_missing_tpm2_binary_is_unavailable() {
    // RULE-089: the production spawn path (no shell), against row avail_cmd_missing
    let c = case("avail_cmd_missing");
    let fx = Fx::new();
    let t = Tpm::new(&fx.device, Cli::Exec(c.get("cmd").into()));
    assert_eq!((t.available() as i32).to_string(), c.rv);
}

#[test]
fn a_yes_is_cached_even_after_the_device_disappears() {
    // RULE-089: g_tpm_available; one probe for the life of the cache
    let c = case("avail_cached_yes");
    let fx = Fx::new();
    let t = fx.tpm(&c, "");
    assert_eq!((t.available() as i32).to_string(), c.get("first"));
    fs::remove_file(&fx.device).unwrap();
    assert_eq!((t.available() as i32).to_string(), c.rv);
    assert_eq!(
        fx.log().matches("startup").count().to_string(),
        c.get("startup_calls")
    );
}

#[test]
fn a_no_is_cached_even_after_the_device_appears() {
    // RULE-089: a negative answer is cached too, so a TPM that appears later is not seen
    let c = case("avail_cached_no");
    let fx = Fx::new();
    let t = fx.tpm(&c, "");
    assert_eq!((t.available() as i32).to_string(), c.get("first"));
    fs::write(&fx.device, b"").unwrap();
    assert_eq!((t.available() as i32).to_string(), c.rv);
    assert_eq!(
        fx.log().matches("startup").count().to_string(),
        c.get("startup_calls")
    );
}

#[test]
#[ignore = "writes /var/lib/freehsm/tpm: run in a throwaway container (tests/README.md)"]
fn first_yes_creates_var_lib_freehsm_tpm_0700() {
    // RULE-089: residue of the pre-#109 temp files; nothing reads the directory now
    let c = case("avail_creates_tpm_dir");
    fs::create_dir_all("/var/lib/freehsm").unwrap();
    let _ = fs::remove_dir("/var/lib/freehsm/tpm");
    let fx = Fx::new();
    assert_eq!((fx.tpm(&c, "").available() as i32).to_string(), c.rv);
    assert_eq!(state(&PathBuf::from("/var/lib/freehsm/tpm")), "dir");
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata("/var/lib/freehsm/tpm")
        .unwrap()
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(format!("{mode:04o}"), c.get("tpm_dir"));
}

// ---------------------------------------------------------------------------------------
// fhsm_tpm_seal: subcommands, blob format, failures
// ---------------------------------------------------------------------------------------
golden! {
    seal_runs_createpolicy_then_create_and_packs_tps1_blob => run_seal("seal_ok");
    seal_fits_a_buffer_of_exactly_the_blob_length => run_seal("seal_cap_exact");
    seal_one_byte_short_fails_and_leaves_the_buffer => run_seal("seal_cap_short");
    seal_stops_when_createpolicy_fails => run_seal("seal_fail_createpolicy");
    seal_fails_when_create_fails => run_seal("seal_fail_create");
    seal_without_a_device_is_tpm_unavailable => run_seal("seal_no_device");
    seal_packs_a_512_byte_public_part => run_seal("seal_quirk_pub_512");
    seal_refuses_a_public_part_over_512_bytes_div018 => run_seal("seal_quirk_pub_513");
    seal_refuses_an_empty_public_part => run_seal("seal_quirk_empty_pub");
    seal_refuses_an_empty_private_part => run_seal("seal_quirk_empty_priv");
}

#[test]
fn hooks_cmd_is_run_through_sh_like_c_div017() {
    // DIV-017 keeps this: in hooks mode FHSM_TPM_CMD is split by `sh -c`, so an assignment
    // in the command wins over the environment (C sealed POLICY:from-cmd, not golden-pcr)
    let c = case("seal_cmd_env_prefix");
    assert!(
        c.get("blob").contains(&hex(b"POLICY:from-cmd")),
        "C: the shell applied it"
    );
    run_seal("seal_cmd_env_prefix");
}

#[test]
fn blob_layout_is_magic_lengths_pub_priv_little_endian() {
    // RULE-089: the layout comment at src/fhsm_tpm.c:271-276, checked on C's own blob
    let b = unhex(case("seal_ok").get("blob"));
    let pub_len = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
    let priv_len = u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize;
    assert_eq!(&b[..4], b"TPS1");
    assert_eq!(b.len(), 12 + pub_len + priv_len);
    assert_eq!(
        &b[12..12 + pub_len],
        format!("POLICY:{PCR}").as_bytes(),
        "stub: pub = policy"
    );
    assert_eq!(&b[12 + pub_len..], &S, "stub: priv = the secret, verbatim");
}

// ---------------------------------------------------------------------------------------
// fhsm_tpm_unseal: blob checks, subcommands, output buffer
// ---------------------------------------------------------------------------------------
golden! {
    unseal_runs_createpolicy_load_unseal_and_returns_the_secret => run_unseal("unseal_ok");
    unseal_of_an_empty_blob_is_arguments_bad => run_unseal("unseal_len0");
    unseal_of_4_bytes_is_arguments_bad => run_unseal("unseal_len4");
    unseal_of_11_bytes_is_arguments_bad => run_unseal("unseal_len11");
    unseal_rejects_a_wrong_magic_before_touching_the_buffer => run_unseal("unseal_bad_magic");
    unseal_magic_is_case_sensitive => run_unseal("unseal_lower_magic");
    unseal_rejects_a_blob_one_byte_short_of_its_lengths => run_unseal("unseal_truncated");
    unseal_rejects_a_blob_one_byte_longer_than_its_lengths => run_unseal("unseal_oversized");
    unseal_rejects_a_pub_len_of_u32_max_without_overflow => run_unseal("unseal_pub_len_max");
    unseal_of_a_bare_header_reaches_tpm2_and_zeroes_the_buffer => run_unseal("unseal_header_only");
    unseal_of_a_consistent_garbage_body_fails_in_tpm2_and_zeroes => run_unseal("unseal_garbage_body");
    unseal_accepts_a_2048_byte_blob => run_unseal("unseal_crafted_2048");
    unseal_fails_after_the_pcrs_move_and_zeroes_the_buffer => run_unseal("unseal_pcr_changed");
    unseal_stops_when_createpolicy_fails => run_unseal("unseal_fail_createpolicy");
    unseal_stops_when_load_fails => run_unseal("unseal_fail_load");
    unseal_fails_when_unseal_fails => run_unseal("unseal_fail_unseal");
    unseal_refuses_31_bytes_from_tpm2 => run_unseal("unseal_quirk_out_31");
    unseal_refuses_no_bytes_from_tpm2 => run_unseal("unseal_quirk_out_0");
    unseal_refuses_40_bytes_from_tpm2_div018 => run_unseal("unseal_quirk_out_40");
    unseal_without_a_device_is_tpm_unavailable_and_leaves_the_buffer => run_unseal("unseal_no_device");
}

#[test]
fn companion_seal_does_not_follow_a_link_at_the_tmp_div031() {
    // C: open(tmp, O_CREAT|O_TRUNC) follows the link (src/fhsm_token_tpm.c:91)
    let c = case("tok_seal_ok");
    let fx = Fx::new();
    let t = fx.tpm(&c, "");
    fx.ready(&c, &t);
    let tok = tok_for(fx.path(), &c);
    let victim = fx.path().join("victim");
    fs::write(&victim, b"untouched").unwrap();
    std::os::unix::fs::symlink(&victim, with(&tok, ".tpm.new")).unwrap();
    assert_eq!(rv_text(&t.seal_companion(&tok, &S)), "0x0");
    assert_eq!(fs::read(&victim).unwrap(), b"untouched");
    assert_eq!(state(&with(&tok, ".tpm")), c.get("after_tpm"));
    assert_eq!(state(&with(&tok, ".tpm.new")), "absent");
}

#[test]
fn unseal_works_again_once_the_pcrs_are_restored() {
    // RULE-089 / tests/test_tpm.c [C]: the failure is the policy, not a damaged blob
    let moved = case("unseal_pcr_changed");
    let fx = Fx::new();
    let blob = unhex(moved.get("blob_in"));
    let mut out = [0u8; 32];
    assert!(fx.tpm(&moved, "").unseal(&blob, &mut out).is_err());
    assert_eq!(
        rv_text(&fx.tpm(&case("unseal_ok"), "").unseal(&blob, &mut out)),
        case("unseal_ok").rv
    );
    assert_eq!(hex(&out), case("unseal_ok").get("out"));
}

// ---------------------------------------------------------------------------------------
// The child processes (probe stub): argv with memfd names, /dev/null output, DIV-017
// ---------------------------------------------------------------------------------------
golden! {
    seal_children_get_c_argv_memfd_names_and_dev_null_output => run_seal("probe_seal");
    unseal_children_get_c_argv_memfd_names_and_dev_null_output => run_unseal("probe_unseal");
}

#[test]
fn an_unrelated_fork_during_a_seal_inherits_no_memfd_div017() {
    let &(name, c_saw, rust_sees) = &DIV017[0];
    let c = case(name);
    assert_eq!(
        (c.rv.as_str(), c.get("seen")),
        ("0x0", c_saw),
        "C: the DEK memfd leaked"
    );
    let fx = Fx::new();
    let hold = fx.path().join("hold");
    let t = fx.tpm(&c, &format!("FHSM_TPM_PROBE_HOLD='{}'", hold.display()));
    assert!(t.available());
    std::thread::scope(|s| {
        let sealer = s.spawn(|| {
            let mut out = [0u8; 2048];
            t.seal(&S, &mut out).map(|_| ())
        });
        let ready = with(&hold, ".ready");
        let start = Instant::now();
        while !ready.exists() {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "the probe never reached create"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let ls = std::process::Command::new("sh")
            .args(["-c", "ls -l /proc/$$/fd"])
            .output()
            .unwrap();
        fs::write(with(&hold, ".go"), b"").unwrap();
        let mut seen: Vec<String> = String::from_utf8_lossy(&ls.stdout)
            .lines()
            .filter_map(|l| {
                l.split_once("/memfd:")
                    .map(|(_, m)| m.trim_end_matches(" (deleted)").to_owned())
            })
            .collect();
        seen.sort();
        let seen = if seen.is_empty() {
            "none".to_owned()
        } else {
            seen.join(",")
        };
        assert_eq!(rv_text(&sealer.join().unwrap()), c.rv);
        assert_eq!(seen, rust_sees, "memfds visible to an unrelated child");
    });
}

// ---------------------------------------------------------------------------------------
// fhsm_token_tpm_seal: the {tok}.tpm companion file
// ---------------------------------------------------------------------------------------
golden! {
    companion_seal_writes_the_blob_0600_and_no_tmp => run_token("tok_seal_ok");
    companion_seal_replaces_an_existing_companion => run_token("tok_seal_replaces_old");
    companion_seal_failure_keeps_the_old_companion => run_token("tok_seal_fail_keeps_old");
    companion_seal_without_a_device_writes_nothing => run_token("tok_seal_no_device");
    companion_seal_into_a_missing_directory_fails_after_sealing => run_token("tok_seal_missing_dir");
    companion_seal_onto_a_directory_fails_and_removes_the_tmp => run_token("tok_seal_rename_onto_dir");
    companion_seal_fsyncs_the_tmp_before_renaming_div015 => run_token("tok_seal_stale_tmp_fifo");
    companion_seal_at_1015_bytes_succeeds => run_token("tok_seal_len_1015");
    companion_seal_at_1016_bytes_fails_on_the_tmp_name_after_sealing => run_token("tok_seal_len_1016");
    companion_seal_at_1019_bytes_fails_on_the_tmp_name_after_sealing => run_token("tok_seal_len_1019");
    companion_seal_at_1020_bytes_is_arguments_bad_before_sealing => run_token("tok_seal_len_1020");
    companion_seal_checks_the_tpm_before_the_path_length => run_token("tok_seal_len_1020_no_device");
}

// ---------------------------------------------------------------------------------------
// fhsm_token_tpm_unseal
// ---------------------------------------------------------------------------------------
golden! {
    companion_unseal_returns_the_sealed_dek => run_token("tok_unseal_ok");
    companion_unseal_of_a_missing_file_fails => run_token("tok_unseal_missing");
    companion_unseal_of_an_empty_file_fails => run_token("tok_unseal_empty");
    companion_unseal_of_a_directory_fails => run_token("tok_unseal_directory");
    companion_unseal_of_an_unreadable_file_fails => run_token("tok_unseal_unreadable");
    companion_unseal_of_garbage_fails_without_touching_the_buffer => run_token("tok_unseal_garbage");
    companion_unseal_reads_only_the_first_2048_bytes => run_token("tok_unseal_2048_plus_junk");
    companion_unseal_of_a_2049_byte_blob_fails => run_token("tok_unseal_2049");
    companion_unseal_after_the_pcrs_move_fails_and_zeroes => run_token("tok_unseal_pcr_changed");
    companion_unseal_without_a_device_is_tpm_unavailable => run_token("tok_unseal_no_device");
    companion_unseal_at_1019_bytes_works => run_token("tok_unseal_len_1019");
    companion_unseal_at_1020_bytes_is_arguments_bad => run_token("tok_unseal_len_1020");
}

// ---------------------------------------------------------------------------------------
// fhsm_token_tpm_blob_exists, fhsm_token_tpm_unlink, build_tpm_path
// ---------------------------------------------------------------------------------------
golden! {
    exists_is_false_for_a_missing_companion => run_token("exists_missing");
    exists_is_true_for_a_companion_file => run_token("exists_file");
    exists_is_true_for_an_empty_companion => run_token("exists_empty");
    exists_is_true_for_a_directory => run_token("exists_directory");
    exists_is_false_for_an_unreadable_companion => run_token("exists_unreadable");
    exists_does_not_need_a_tpm => run_token("exists_no_device");
    exists_works_at_1019_bytes => run_token("exists_len_1019");
    exists_is_false_at_1020_bytes_even_though_the_file_is_there => run_token("exists_len_1020");
    unlink_removes_the_companion => run_token("unlink_present");
    unlink_of_a_missing_companion_is_quiet => run_token("unlink_missing");
    unlink_leaves_a_directory_alone => run_token("unlink_directory");
    unlink_works_at_1019_bytes => run_token("unlink_len_1019");
    unlink_does_nothing_at_1020_bytes => run_token("unlink_len_1020");
}

#[test]
fn companion_path_is_none_exactly_where_c_refused_the_path() {
    // RULE-089: build_tpm_path, 1024-byte buffer. Checked on every row with a sized token
    // path and a TPM present, so the expectation is C's, not arithmetic
    let mut seen = 0;
    for c in cases()
        .iter()
        .filter(|c| c.opt("tok").is_some_and(|t| t.starts_with("len:")))
    {
        if c.is("device", "absent") || !c.op.starts_with("token_") {
            continue;
        }
        let n: usize = c.get("tok")[4..].parse().unwrap();
        let tok = PathBuf::from("/".to_owned() + &"p".repeat(n - 1));
        let want = (c.rv != "0x7").then(|| with(&tok, ".tpm"));
        assert_eq!(tpm::companion_path(&tok), want, "{} (len {n})", c.name);
        seen += 1;
    }
    assert!(seen >= 5, "expected the len:* rows");
}

// ---------------------------------------------------------------------------------------
// fhsm_token_tpm_required, fhsm_token_tpm_dek_match
// ---------------------------------------------------------------------------------------
golden! {
    sealing_not_required_when_unset => run_required("required_unset");
    sealing_not_required_when_empty => run_required("required_empty");
    sealing_required_for_1 => run_required("required_1");
    sealing_required_for_lower_y => run_required("required_lower_y");
    sealing_required_for_upper_y => run_required("required_upper_Y");
    sealing_required_for_yes_by_its_first_byte => run_required("required_yes");
    sealing_required_for_capital_yes => run_required("required_capital_Yes");
    sealing_required_for_10_by_its_first_byte => run_required("required_10");
    sealing_not_required_for_0 => run_required("required_0");
    sealing_not_required_for_lower_n => run_required("required_lower_n");
    sealing_not_required_for_upper_n => run_required("required_upper_N");
    sealing_not_required_for_true => run_required("required_true");
    sealing_not_required_for_on => run_required("required_on");
    sealing_not_required_for_a_leading_space => run_required("required_space_1");
    dek_match_for_equal_keys => run_dek("dek_equal");
    dek_mismatch_in_the_first_byte => run_dek("dek_differ_first");
    dek_mismatch_in_the_last_byte => run_dek("dek_differ_last");
    dek_mismatch_in_every_byte => run_dek("dek_all_differ");
    dek_match_for_two_zero_keys => run_dek("dek_zero_equal");
}

// ---------------------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------------------

#[test]
fn every_golden_row_is_covered_by_a_named_test() {
    // RULE-089: guard against a regen adding a row nobody asserts
    let src = [
        include_str!("tpm.rs"),
        include_str!("tpm_ffi.rs"),
        include_str!("tpm_ffi_no_tpm.rs"),
    ]
    .concat();
    for c in cases() {
        assert!(
            src.contains(&format!("\"{}\"", c.name)),
            "untested golden row {}",
            c.name
        );
    }
}

#[test]
fn every_div_row_exists_in_the_goldens() {
    // the DIV tables must name real rows, or the override silently never applies
    let names: Vec<String> = cases().into_iter().map(|c| c.name).collect();
    for n in DIV015.iter().chain(DIV017).chain(DIV018).map(|d| d.0) {
        assert!(
            names.iter().any(|x| x == n),
            "DIV table names missing row {n}"
        );
    }
}
