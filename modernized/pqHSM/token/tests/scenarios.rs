//! Slice 3: the token store (`src/fhsm_token.c`) against the legacy C, scenario by scenario.
//!
//! `tests-support/golden/store_scenarios.txt` is run twice: by gen_store.c against the legacy
//! C (its output is `golden/store/steps.tsv`), and here against the Rust token by
//! `store_common/scenario.rs`. Every step's output must be identical, except at the steps in
//! [`DIVS`] and [`DIV024`]: there C's value is pinned first, then Rust's expected value is
//! checked. Divergences no golden can show are the Rust-only rows of `store_common::RUST_ONLY`.
//!
//! Masked on both sides (gen_store.c does it, the harness repeats it): the serial (shape only),
//! salts, nonces and ciphertext (provenance: same / new / zero against the previous `snap`),
//! and the remaining throttle (rounded up to C's 500 ms × 2^n ladder). Pinned byte for byte:
//! every other header byte, the ciphertext length, the decrypted blob plaintext
//! (`golden/store/pt/`), the cleartext public section (`golden/store/pub/`), the file set and
//! modes, and every audit record's event, role, rv and params.
//!
//!   cargo test -p pqhsm-token --test scenarios

mod store_common;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use store_common::scenario::{Div, check};
use store_common::*;

/// A Rust value that is C's `info` row for the untouched user_base token.
const INFO_USER_BASE: &str = "\tlabel=676f6c64656e2d75736572\tserial=ok\tfso=0\tfuser=0\tuinit=1\tlso=0\tluser=0\ttso=0\ttuser=0\trole=0";

/// Every approved divergence (DIVERGENCES.md) and plan amendment (PHASE2_PLAN.md §7) at a step.
/// `c` is C's value as the golden has it; `rust` what the Rust token must give instead.
/// Patterns: `*` any run, `&&` all of, `||` any of, `!` not. A row whose `c` equals `rust`
/// records that C already matches the target at that step.
pub const DIVS: &[Div] = &[
    // DIV-010: a store that fails GCM under the DEK is an error; the zero key is no longer tried.
    Div {
        scenario: "blob_bad_tag_div010",
        step: 3,
        div: "DIV-010",
        c: "\trv=0x0",
        rust: "\trv=0x6",
        same_file_as: 2,
    },
    Div {
        scenario: "zero_dek_store_div010",
        step: 2,
        div: "DIV-010",
        c: "\trv=0x0",
        rust: "\trv=0x6",
        same_file_as: 1,
    },
    Div {
        scenario: "zero_dek_store_div010",
        step: 3,
        div: "DIV-010",
        c: "\trv=0x0\tn=5\ths=1,2,3,4,5",
        rust: "\trv=0x0\tn=2\ths=3,4",
        same_file_as: 0,
    },
    Div {
        scenario: "zero_dek_store_div010",
        step: 4,
        div: "DIV-010",
        c: "*\tblob=new\tctlen=4803\tnonce=new\tpub=file:2007\tpt=ok:4803",
        rust: "*\tblob=same\tctlen=4803\tnonce=same\tpub=file:2007\tpt=zero:4803",
        same_file_as: 1,
    },
    // DIV-011: a pbkdf2_iter other than 200000 is a malformed file.
    Div {
        scenario: "iter_1000_div011",
        step: 2,
        div: "DIV-011",
        c: "\trv=0x0",
        rust: "\trv=0x6",
        same_file_as: 0,
    },
    Div {
        scenario: "iter_1000_div011",
        step: 3,
        div: "DIV-011",
        c: "\trv=0xa0",
        rust: "\tnotoken",
        same_file_as: 0,
    },
    Div {
        scenario: "iter_1000_div011",
        step: 4,
        div: "DIV-011",
        c: "*\tfso=1\t*",
        rust: "\tnotoken",
        same_file_as: 0,
    },
    Div {
        scenario: "iter_999_div011",
        step: 2,
        div: "DIV-011",
        c: "\trv=0x0",
        rust: "\trv=0x6",
        same_file_as: 0,
    },
    Div {
        scenario: "iter_999_div011",
        step: 3,
        div: "DIV-011",
        c: "\trv=0x80000003",
        rust: "\tnotoken",
        same_file_as: 0,
    },
    Div {
        scenario: "iter_999_div011",
        step: 4,
        div: "DIV-011",
        c: "\tlabel=*",
        rust: "\tnotoken",
        same_file_as: 0,
    },
    Div {
        scenario: "iter_0_div011",
        step: 2,
        div: "DIV-011",
        c: "\trv=0x0",
        rust: "\trv=0x6",
        same_file_as: 0,
    },
    Div {
        scenario: "iter_0_div011",
        step: 3,
        div: "DIV-011",
        c: "\trv=0x80000003",
        rust: "\tnotoken",
        same_file_as: 0,
    },
    Div {
        scenario: "iter_0_div011",
        step: 4,
        div: "DIV-011",
        c: "\tlabel=*",
        rust: "\tnotoken",
        same_file_as: 0,
    },
    Div {
        scenario: "iter_200001_div011",
        step: 2,
        div: "DIV-011",
        c: "\trv=0x0",
        rust: "\trv=0x6",
        same_file_as: 0,
    },
    Div {
        scenario: "iter_200001_div011",
        step: 3,
        div: "DIV-011",
        c: "\trv=0xa0",
        rust: "\tnotoken",
        same_file_as: 0,
    },
    Div {
        scenario: "iter_200001_div011",
        step: 4,
        div: "DIV-011",
        c: "*\tfso=1\t*",
        rust: "\tnotoken",
        same_file_as: 0,
    },
    // DIV-012: counters are re-read from disk under flock; a re-initialised file is refused.
    Div {
        scenario: "two_handles_bypass_lockout_div012",
        step: 5,
        div: "DIV-012",
        c: "\trv=0x0",
        rust: "\trv=0xa4",
        same_file_as: 0,
    },
    Div {
        scenario: "two_handles_bypass_lockout_div012",
        step: 6,
        div: "DIV-012",
        c: "*\tfso=0\tfuser=0\tuinit=1\tlso=0\tluser=0\ttso=0\ttuser=0\trole=2",
        rust: "*\tfso=0\tfuser=5\tuinit=1\tlso=0\tluser=1\ttso=0\ttuser=*\trole=0",
        same_file_as: 0,
    },
    Div {
        scenario: "two_handles_bypass_lockout_div012",
        step: 7,
        div: "DIV-012",
        c: "*\tfuser=0\t*",
        rust: "*\tfuser=5\t*",
        same_file_as: 0,
    },
    Div {
        scenario: "stale_handle_after_reinit_div012",
        step: 4,
        div: "DIV-012",
        c: "\trv=0x0",
        rust: "!\trv=0x0*",
        same_file_as: 0,
    },
    Div {
        scenario: "stale_handle_after_reinit_div012",
        step: 5,
        div: "DIV-012",
        c: "*\tlabel=676f6c64656e2d75736572\t*",
        rust: "*\tlabel=676f6c64656e2d62\t*",
        same_file_as: 3,
    },
    // DIV-013 (amended, H3): failed+1 is durable before PBKDF2; a reset that fails logs out.
    Div {
        scenario: "rodir_wrong_pin_div013",
        step: 3,
        div: "DIV-013",
        c: "\trv=0xa0",
        rust: "\trv=0x6",
        same_file_as: 2,
    },
    Div {
        scenario: "rodir_right_pin_div013",
        step: 3,
        div: "DIV-013",
        c: "\trv=0x0",
        rust: "\trv=0x6",
        same_file_as: 2,
    },
    Div {
        scenario: "rodir_right_pin_div013",
        step: 4,
        div: "DIV-013",
        c: "\trole=2",
        rust: "\trole=0",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_reset_write_fails_div013",
        step: 5,
        div: "DIV-013",
        c: "\trv=0x0\taudit=*",
        rust: "\trv=0x6||\trv=0x6\taudit=unseal_success/USER/0/{\"tpm-check-login\":\"0x0\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_reset_write_fails_div013",
        step: 6,
        div: "DIV-013",
        c: "\trole=2",
        rust: "\trole=0",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_reset_write_fails_div013",
        step: 7,
        div: "DIV-013",
        c: "\trv=0x60",
        rust: "!\trv=0x0*",
        same_file_as: 0,
    },
    // fuser=2 if the failed+1 write landed before the TPM stub made the directory read-only,
    // 1 if the token probed the TPM (and so ran the stub's prefix) before it.
    Div {
        scenario: "tpm_reset_write_fails_div013",
        step: 12,
        div: "DIV-013",
        c: "*\tfuser=1\t*",
        rust: "*\tfuser=1\t*\ttuser=500\t*||*\tfuser=2\t*\ttuser=1000\t*",
        same_file_as: 0,
    },
    // H4: build on a copy, audit, write, then swap; a failed write leaves memory unchanged.
    Div {
        scenario: "rodir_add_h4",
        step: 4,
        div: "H4",
        c: "\trv=0x6\taudit=object_create/USER/6/{\"label\":\"x\"}",
        rust: "\trv=0x6\taudit=*",
        same_file_as: 3,
    },
    Div {
        scenario: "rodir_add_h4",
        step: 5,
        div: "H4",
        c: "\trv=0x0\tn=1\ths=1",
        rust: "\trv=0x0\tn=0\ths=",
        same_file_as: 0,
    },
    Div {
        scenario: "rodir_reinit_h4",
        step: 3,
        div: "H4",
        c: "\trv=0x6\taudit=token_reinit/SO/6/*",
        rust: "\trv=0x6\taudit=*",
        same_file_as: 2,
    },
    Div {
        scenario: "rodir_reinit_h4",
        step: 4,
        div: "H4",
        c: "\tlabel=72\t*\tuinit=0\t*",
        rust: INFO_USER_BASE,
        same_file_as: 0,
    },
    // M4: the file set has no leftover .tmp.
    Div {
        scenario: "tokdir_init_leaves_tmp",
        step: 3,
        div: "M4",
        c: "\tfiles=slot0.tok/:755,slot0.tok.tmp:600",
        rust: "\tfiles=slot0.tok/:755",
        same_file_as: 0,
    },
    // M2: fhsm_token_label points at an inline [u8; 65]: a 64-byte label no longer runs on
    // into the serial.
    Div {
        scenario: "header_label_64_bytes",
        step: 3,
        div: "M2",
        c: "\tlabel=*+overrun:serial\t*",
        rust: "\tlabel=4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c\tserial=ok\tfso=0\tfuser=0\tuinit=0\tlso=0\tluser=0\ttso=0\ttuser=0\trole=0",
        same_file_as: 0,
    },
    // DIV-014: create and re-init leave the DEK zeroised and not live.
    Div {
        scenario: "init_then_add_div014",
        step: 3,
        div: "DIV-014",
        c: "\trv=0x0\th=1\taudit=object_create/NONE/0/{\"label\":\"early\"}",
        rust: "\trv=0x101",
        same_file_as: 0,
    },
    Div {
        scenario: "init_then_add_div014",
        step: 4,
        div: "DIV-014",
        c: "\trv=0x0\tn=1\ths=1",
        rust: "\trv=0x0\tn=0\ths=",
        same_file_as: 0,
    },
    Div {
        scenario: "reinit_then_add_div014",
        step: 3,
        div: "DIV-014",
        c: "\trv=0x0\th=1\taudit=object_create/NONE/0/{\"label\":\"early\"}",
        rust: "\trv=0x101",
        same_file_as: 2,
    },
    // DIV-015 (a): re-init reseals when sealing is required and removes .tpm otherwise.
    Div {
        scenario: "tpm_reinit_keeps_old_companion_div015",
        step: 3,
        div: "DIV-015",
        c: "\trv=0x0\taudit=token_reinit/*",
        rust: "\trv=0x0\taudit=*",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_reinit_keeps_old_companion_div015",
        step: 5,
        div: "DIV-015",
        c: "\trv=0x30\taudit=unseal_failure/SO/48/*",
        rust: "\trv=0x0\taudit=unseal_success/SO/0/{\"tpm-check-login\":\"0x0\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_reinit_unsealed_div015",
        step: 3,
        div: "DIV-015",
        c: "\trv=0x0\taudit=token_reinit/*",
        rust: "\trv=0x0\taudit=*",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_reinit_unsealed_div015",
        step: 4,
        div: "DIV-015",
        c: "\tfiles=slot0.tok:600,slot0.tok.tpm:600",
        rust: "\tfiles=slot0.tok:600",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_reinit_unsealed_div015",
        step: 5,
        div: "DIV-015",
        c: "\trv=0x30\taudit=*",
        rust: "\trv=0x0",
        same_file_as: 0,
    },
    // DIV-015 (c) and M4: no orphan .tpm (and no .tmp) when the .tok write fails.
    Div {
        scenario: "tpm_init_tok_write_fails_div015",
        step: 3,
        div: "DIV-015",
        c: "\trv=0x6\taudit=seal_success/*",
        rust: "\trv=0x6||\trv=0x6\taudit=seal_success/SO/0/{\"tpm-seal-init\":\"0x0\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_init_tok_write_fails_div015",
        step: 4,
        div: "DIV-015",
        c: "\tfiles=slot0.tok/:755,slot0.tok.tmp:600,slot0.tok.tpm:600",
        rust: "\tfiles=slot0.tok/:755",
        same_file_as: 0,
    },
    // DIV-015 (e) with DIV-014: after a failed TPM check nothing is written under a zeroised DEK.
    Div {
        scenario: "tpm_mismatch_keeps_dek_live_div015",
        step: 4,
        div: "DIV-015",
        c: "\trv=0x30\taudit=unseal_failure/SO/6/*",
        rust: "\trv=0x30\taudit=unseal_failure/SO/6/{\"tpm-unseal-failed\":\"0x6\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_mismatch_keeps_dek_live_div015",
        step: 5,
        div: "DIV-015",
        c: "\trv=0x0\th=1\taudit=object_create/NONE/0/*",
        rust: "\trv=0x101",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_mismatch_keeps_dek_live_div015",
        step: 6,
        div: "DIV-015",
        c: "*\tblob=new\tctlen=944\tnonce=new\tpub=file:20\tpt=zero:944",
        rust: "\tsize=317\t*\tblob=none\tpt=none",
        same_file_as: 2,
    },
    Div {
        scenario: "tpm_login_pcr_moved_div015",
        step: 7,
        div: "DIV-015",
        c: "\trv=0x101",
        rust: "\trv=0x101",
        same_file_as: 0,
    },
    // DIV-001: an audit record that is not durable fails the call with CKR_DEVICE_ERROR and
    // suppresses its effect (no object, no token-file change).
    Div {
        scenario: "audit_fail_init_div001",
        step: 2,
        div: "DIV-001",
        c: "\trv=0x0\taudit=token_init/SO/0/*",
        rust: "\trv=0x30\taudit=*",
        same_file_as: 0,
    },
    Div {
        scenario: "audit_fail_init_div001",
        step: 3,
        div: "DIV-001",
        c: "\tfiles=slot0.tok:600",
        rust: "\tfiles=",
        same_file_as: 0,
    },
    Div {
        scenario: "audit_fail_add_div001",
        step: 4,
        div: "DIV-001",
        c: "\trv=0x0\th=1\taudit=*",
        rust: "\trv=0x30\taudit=*&&!*\th=*",
        same_file_as: 3,
    },
    Div {
        scenario: "audit_fail_add_div001",
        step: 5,
        div: "DIV-001",
        c: "\trv=0x0\tn=1\ths=1",
        rust: "\trv=0x0\tn=0\ths=",
        same_file_as: 0,
    },
    Div {
        scenario: "audit_fail_add_div001",
        step: 6,
        div: "DIV-001",
        c: "*\tblob=new\t*",
        rust: "*\tblob=none\tpt=none",
        same_file_as: 3,
    },
    Div {
        scenario: "audit_fail_destroy_div001",
        step: 4,
        div: "DIV-001",
        c: "\trv=0x0\taudit=object_destroy/*",
        rust: "\trv=0x30\taudit=*",
        same_file_as: 3,
    },
    Div {
        scenario: "audit_fail_destroy_div001",
        step: 5,
        div: "DIV-001",
        c: "\trv=0x0\tn=4\ths=5,2,3,4",
        rust: "\trv=0x0\tn=5\ths=1,2,3,4,5",
        same_file_as: 0,
    },
    Div {
        scenario: "audit_fail_destroy_div001",
        step: 6,
        div: "DIV-001",
        c: "*\tpt=ok:3855",
        rust: "*\tpt=ok:4803",
        same_file_as: 3,
    },
    Div {
        scenario: "audit_fail_set_pin_div001",
        step: 3,
        div: "DIV-001",
        c: "\trv=0x0\taudit=set_pin/USER/0/{}",
        rust: "\trv=0x30\taudit=*",
        same_file_as: 2,
    },
    Div {
        scenario: "audit_fail_set_pin_div001",
        step: 4,
        div: "DIV-001",
        c: "*\tsalt_user=new\tuser_nonce=new\tuser_ct=new\t*",
        rust: "*\tsalt_user=same\tuser_nonce=same\tuser_ct=same\t*",
        same_file_as: 2,
    },
    Div {
        scenario: "audit_fail_reinit_div001",
        step: 3,
        div: "DIV-001",
        c: "\trv=0x0\taudit=token_reinit/*",
        rust: "\trv=0x30\taudit=*",
        same_file_as: 2,
    },
    Div {
        scenario: "audit_fail_reinit_div001",
        step: 4,
        div: "DIV-001",
        c: "\tlabel=676f6c64656e2d72\t*",
        rust: INFO_USER_BASE,
        same_file_as: 0,
    },
    Div {
        scenario: "audit_fail_reinit_div001",
        step: 5,
        div: "DIV-001",
        c: "*\tlabel=676f6c64656e2d72\t*",
        rust: "*\tlabel=676f6c64656e2d75736572\t*\tuinit=1\t*",
        same_file_as: 2,
    },
    Div {
        scenario: "audit_fail_tpm_init_div001",
        step: 3,
        div: "DIV-001",
        c: "\trv=0x0\taudit=seal_success/*",
        rust: "\trv=0x30\taudit=seal_success/SO/0/{\"tpm-seal-init\":\"0x0\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "audit_fail_tpm_init_div001",
        step: 4,
        div: "DIV-001",
        c: "\tfiles=slot0.tok:600,slot0.tok.tpm:600",
        rust: "\tfiles=",
        same_file_as: 0,
    },
    // Decided 2026-10-31 ("Error code when a failing call's audit also fails"): the original
    // error wins when the call already fails; 0x30 only for a call that would have succeeded.
    Div {
        scenario: "audit_fail_tpm_seal_failure_div001",
        step: 4,
        div: "DIV-001",
        c: "\trv=0x6\taudit=seal_failure/*",
        rust: "\trv=0x6\taudit=seal_failure/SO/6/{\"tpm-seal-init\":\"0x6\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "audit_fail_tpm_login_div001",
        step: 4,
        div: "DIV-001",
        c: "\trv=0x0\taudit=unseal_success/*",
        rust: "\trv=0x30\taudit=unseal_success/USER/0/{\"tpm-check-login\":\"0x0\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "audit_fail_tpm_login_div001",
        step: 5,
        div: "DIV-001",
        c: "\trole=2",
        rust: "\trole=0",
        same_file_as: 0,
    },
    Div {
        scenario: "audit_fail_tpm_unseal_failure_div001",
        step: 5,
        div: "DIV-001",
        c: "\trv=0x30\taudit=unseal_failure/USER/6/*",
        rust: "\trv=0x30\taudit=unseal_failure/USER/6/{\"tpm-unseal-failed\":\"0x6\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "audit_fail_tpm_mismatch_div001",
        step: 5,
        div: "DIV-001",
        c: "\trv=0x30\taudit=unseal_failure/USER/48/*",
        rust: "\trv=0x30\taudit=unseal_failure/USER/48/{\"tpm-dek-mismatch\":\"0x30\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "audit_fail_tpm_missing_div001",
        step: 4,
        div: "DIV-001",
        c: "\trv=0x30\taudit=unseal_failure/USER/2147483653/*",
        rust: "\trv=0x30\taudit=unseal_failure/USER/2147483653/{\"tpm-required-but-missing\":\"0x80000005\"}",
        same_file_as: 0,
    },
    // DIV-023: each TPM audit record carries the step's rv, as 0x%x, for its key (C read a
    // value past FHSM_AUDIT_END; the generator renders that as "INVALID"). Steps that already
    // have a row (DIV-001, DIV-013, DIV-015 above) check the value there.
    Div {
        scenario: "tpm_base",
        step: 2,
        div: "DIV-023",
        c: "\trv=0x0\taudit=seal_success/SO/0/{\"tpm-seal-init\":\"INVALID\"}\taudit=token_init/SO/0/{\"label\":\"golden-tpm\"}",
        rust: "C~:\"INVALID\"}~>:\"0x0\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_base",
        step: 4,
        div: "DIV-023",
        c: "\trv=0x0\taudit=unseal_success/SO/0/{\"tpm-check-login\":\"INVALID\"}",
        rust: "C~:\"INVALID\"}~>:\"0x0\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_base",
        step: 7,
        div: "DIV-023",
        c: "\trv=0x0\taudit=unseal_success/USER/0/{\"tpm-check-login\":\"INVALID\"}",
        rust: "C~:\"INVALID\"}~>:\"0x0\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_login_pcr_moved_div015",
        step: 4,
        div: "DIV-023",
        c: "\trv=0x30\taudit=unseal_failure/USER/6/{\"tpm-unseal-failed\":\"INVALID\"}",
        rust: "C~:\"INVALID\"}~>:\"0x6\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_login_unseal_fails",
        step: 4,
        div: "DIV-023",
        c: "\trv=0x30\taudit=unseal_failure/USER/6/{\"tpm-unseal-failed\":\"INVALID\"}",
        rust: "C~:\"INVALID\"}~>:\"0x6\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_login_dek_mismatch",
        step: 4,
        div: "DIV-023",
        c: "\trv=0x30\taudit=unseal_failure/USER/48/{\"tpm-dek-mismatch\":\"INVALID\"}",
        rust: "C~:\"INVALID\"}~>:\"0x30\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_required_but_missing",
        step: 3,
        div: "DIV-023",
        c: "\trv=0x30\taudit=unseal_failure/USER/2147483653/{\"tpm-required-but-missing\":\"INVALID\"}",
        rust: "C~:\"INVALID\"}~>:\"0x80000005\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_companion_without_sealing",
        step: 3,
        div: "DIV-023",
        c: "\trv=0x0\taudit=unseal_success/USER/0/{\"tpm-check-login\":\"INVALID\"}",
        rust: "C~:\"INVALID\"}~>:\"0x0\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_init_seal_fails",
        step: 3,
        div: "DIV-023",
        c: "\trv=0x6\taudit=seal_failure/SO/6/{\"tpm-seal-init\":\"INVALID\"}",
        rust: "C~:\"INVALID\"}~>:\"0x6\"}",
        same_file_as: 0,
    },
    Div {
        scenario: "tpm_mismatch_keeps_dek_live_div015",
        step: 2,
        div: "DIV-023",
        c: "\trv=0x0\taudit=seal_success/SO/0/{\"tpm-seal-init\":\"INVALID\"}\taudit=token_init/SO/0/{\"label\":\"x\"}",
        rust: "C~:\"INVALID\"}~>:\"0x0\"}",
        same_file_as: 0,
    },
    // DIV-026: a template keeps only `len` value bytes (C kept the caller's or the file's rest).
    Div {
        scenario: "policy_attrs_rule061",
        step: 30,
        div: "DIV-026",
        c: "\trv=0x0\tn=1\tv=0x162:1:1:01aabbcc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        rust: "C~01aabbcc~>01000000",
        same_file_as: 0,
    },
    Div {
        scenario: "policy_attrs_rule061",
        step: 35,
        div: "DIV-026",
        c: "*derive=0x162:1:1:01aabbcc*",
        rust: "C~01aabbcc~>01000000",
        same_file_as: 0,
    },
    Div {
        scenario: "parse_v4_ok",
        step: 4,
        div: "DIV-026",
        c: "*wrap=0x3:3:5:6c6162656c4a554e4b2d706173742d6c656e*",
        rust: "C~6c6162656c4a554e4b2d706173742d6c656e~>6c6162656c00000000000000000000000000",
        same_file_as: 0,
    },
    Div {
        scenario: "parse_v4_ok",
        step: 6,
        div: "DIV-026",
        c: "*wrap=0x3:3:5:6c6162656c4a554e4b2d706173742d6c656e*",
        rust: "C~6c6162656c4a554e4b2d706173742d6c656e~>6c6162656c00000000000000000000000000",
        same_file_as: 0,
    },
    Div {
        scenario: "parse_v4_trailing_bytes",
        step: 4,
        div: "DIV-026",
        c: "*wrap=0x3:3:5:6c6162656c4a554e4b2d706173742d6c656e*",
        rust: "C~6c6162656c4a554e4b2d706173742d6c656e~>6c6162656c00000000000000000000000000",
        same_file_as: 0,
    },
];

/// DIV-024: a store that authenticates but does not parse fails the login with 0x6, and the
/// token file is byte-identical to the one before the login (C logged in with no objects; the
/// `find` after it is 0x101 on both sides). Frame failures, which never reach GCM, stay C's.
const fn div024(scenario: &'static str) -> Div {
    Div {
        scenario,
        step: 3,
        div: "DIV-024",
        c: "\trv=0x0",
        rust: "\trv=0x6",
        same_file_as: 2,
    }
}

pub const DIV024: &[Div] = &[
    div024("parse_v1_count_1025"),
    div024("parse_v1_short"),
    div024("parse_v1_value_len_5501"),
    div024("parse_v1_id_len_33"),
    div024("parse_v2_count_1025"),
    div024("parse_v2_missing_record"),
    div024("parse_v2_rec_len_119"),
    div024("parse_v2_rec_len_over_max"),
    div024("parse_v2_rec_overrun"),
    div024("parse_v2_value_len_mismatch"),
    div024("parse_v2_id_len_33"),
    div024("parse_v3_start_len_9"),
    div024("parse_v3_end_len_9"),
    div024("parse_v3_app_len_65"),
    div024("parse_v4_allowed_9"),
    div024("parse_v4_wrap_count_5"),
    div024("parse_v4_unwrap_entry_len_49"),
    div024("parse_v4_derive_kind_0"),
    div024("parse_v4_wrap_kind_4"),
    div024("parse_v4_rec_len_911"),
    div024("parse_blob_7_bytes"),
    div024("parse_v4_magic_10_bytes"),
    div024("parse_unknown_magic"),
];

fn all_divs() -> Vec<Div> {
    DIVS.iter().chain(DIV024).copied().collect()
}

macro_rules! scenarios {
    ($($name:ident),* $(,)?) => {
        const NAMES: &[&str] = &[$(stringify!($name)),*];
        $(
            #[test]
            fn $name() {
                check(stringify!($name), &all_divs());
            }
        )*
    };
}

scenarios! {
    // creation and PINs (RULE-036, 079, 081, 083)
    init_fresh, init_so_pin_7_bytes, init_label_70_bytes, init_then_add_div014,
    init_user_pin_needs_so_login, user_base, multi_base,
    // login, counters, throttle (RULE-026, 083, 084, 085, 086, 088)
    login_conflicts, login_user_pin_not_initialized_rule083, wrong_pin_counts_and_resets,
    wrong_pin_keeps_blob_rule088, empty_pin_is_a_wrong_pin, fifth_failure_locks,
    locked_before_uninitialized_rule083, throttle_derived_on_load_rule026, verify_pin,
    logout_keeps_objects_rule086,
    // PIN admin and re-init (RULE-005, 036, 080, 081, 082)
    set_pin_logged_out_rule082, set_pin_while_logged_in_rule082,
    set_pin_so_does_not_rotate_dek_rule005, set_pin_short_new_pin,
    init_user_pin_unlocks_user_rule081, reinit_wipes_rule080, reinit_short_pin_rule036,
    reinit_then_add_div014,
    // objects and policy (RULE-057, 058, 061, 090, 091, 092)
    objects_crud, add_limits_rule091, policy_attrs_rule061, session_objects_rule090,
    handle_wraps_rule091, capacity_1024_rule091, destroy_compacts_rule092,
    // the public view (RULE-044)
    public_view_before_login, public_view_absent, public_view_bad_magic,
    public_view_length_short_of_file, public_view_secret_object, public_view_sensitive_public_key,
    public_view_v3_section, public_view_unparsable, public_view_empty_section,
    public_view_planted_trusted_key_rule044, empty_store_view,
    // the encrypted frame (RULE-003, 066)
    header_plus_10_bytes, blob_ct_len_zero, blob_ct_len_over_max_rule003,
    blob_ct_len_at_max_rule003, blob_truncated, blob_bad_tag_div010, zero_dek_store_div010,
    // the blob readers (RULE-003)
    parse_v1_ok, parse_v1_empty, parse_v1_count_1025, parse_v1_short, parse_v1_value_len_5501,
    parse_v1_id_len_33, parse_v2_ok, parse_v2_count_1025, parse_v2_missing_record,
    parse_v2_rec_len_119, parse_v2_rec_len_over_max, parse_v2_rec_overrun,
    parse_v2_value_len_mismatch, parse_v2_id_len_33, parse_v3_ok, parse_v3_start_len_9,
    parse_v3_end_len_9, parse_v3_app_len_65, parse_v4_ok, parse_v4_allowed_9,
    parse_v4_wrap_count_5, parse_v4_unwrap_entry_len_49, parse_v4_derive_kind_0,
    parse_v4_wrap_kind_4, parse_v4_rec_len_911, parse_v4_trailing_bytes, parse_blob_7_bytes,
    parse_v4_magic_10_bytes, parse_unknown_magic,
    // the header (RULE-004, 044; DIV-011)
    header_missing, header_316_bytes, header_bad_magic, header_version_2, header_version_0,
    header_user_initialized_byte_2, header_throttle_bytes_ignored, header_label_64_bytes,
    header_serial_edited, iter_1000_div011, iter_999_div011, iter_0_div011, iter_200001_div011,
    // the file transaction and write failures (DIV-012, DIV-013, H4, M4)
    two_handles_bypass_lockout_div012, stale_handle_after_reinit_div012, rodir_wrong_pin_div013,
    rodir_right_pin_div013, rodir_add_h4, rodir_reinit_h4, rodir_init, tokdir_init_leaves_tmp,
    // the TPM companion (RULE-089; DIV-015)
    tpm_base, tpm_login_pcr_moved_div015, tpm_login_unseal_fails, tpm_login_dek_mismatch,
    tpm_required_but_missing, tpm_companion_without_sealing, tpm_wrong_pin_never_reaches_tpm,
    tpm_init_seal_fails, tpm_reinit_keeps_old_companion_div015, tpm_reinit_unsealed_div015,
    tpm_init_tok_write_fails_div015, tpm_mismatch_keeps_dek_live_div015,
    tpm_reset_write_fails_div013,
    // audit fails closed (DIV-001)
    audit_fail_init_div001, audit_fail_add_div001, audit_fail_destroy_div001,
    audit_fail_set_pin_div001, audit_fail_reinit_div001, audit_fail_tpm_init_div001,
    audit_fail_tpm_seal_failure_div001, audit_fail_tpm_login_div001,
    audit_fail_tpm_unseal_failure_div001, audit_fail_tpm_mismatch_div001,
    audit_fail_tpm_missing_div001,
}

fn script_text(p: PathBuf) -> String {
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

#[test]
fn the_goldens_were_made_from_the_current_script() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../tests-support/golden/store_scenarios.txt");
    assert_eq!(
        script_text(src),
        script_text(store_golden("store_scenarios.txt")),
        "store_scenarios.txt changed since the goldens were made: run tests-support/golden/regen_store.sh"
    );
}

#[test]
fn every_scenario_has_a_test_and_every_test_a_scenario() {
    let s: BTreeSet<String> = script(&script_text(store_golden("store_scenarios.txt")))
        .into_iter()
        .map(|x| x.0)
        .collect();
    let t: BTreeSet<String> = NAMES.iter().map(|x| x.to_string()).collect();
    assert_eq!(s, t);
}

#[test]
fn every_golden_step_is_the_script_line_it_claims() {
    let text = script_text(store_golden("store_scenarios.txt"));
    let all = steps();
    for (name, _, lines) in script(&text) {
        let got: Vec<&Step> = all.iter().filter(|s| s.scenario == name).collect();
        assert_eq!(got.len(), lines.len(), "{name}: step count");
        for (s, l) in got.iter().zip(&lines) {
            assert_eq!(&s.line, l, "{name} step {}", s.step);
        }
    }
}

#[test]
fn every_div_row_names_a_golden_step_and_pins_c() {
    let all = steps();
    let divs = all_divs();
    for (i, d) in divs.iter().enumerate() {
        let s = all
            .iter()
            .find(|s| s.scenario == d.scenario && s.step == d.step)
            .unwrap_or_else(|| panic!("{d:?}: no such golden step"));
        assert!(matches(d.c, &s.out), "{d:?}: C's golden is {:?}", s.out);
        assert!(
            !divs[..i]
                .iter()
                .any(|e| e.scenario == d.scenario && e.step == d.step),
            "{d:?}: a second row for this step would never be checked"
        );
        if let Some((old, _)) = d.rust.strip_prefix("C~").and_then(|r| r.split_once("~>")) {
            assert!(
                s.out.contains(old),
                "{d:?}: C's golden has no {old:?} to replace"
            );
        }
        assert!(
            d.same_file_as < d.step,
            "{d:?}: same_file_as must be an earlier step"
        );
    }
}

/// Every DIV this table claims is in DIVERGENCES.md and decided (or done); every plan item is
/// in PHASE2_PLAN.md §7. A slice 3 DIV the table never mentions is a gap.
#[test]
fn the_div_table_matches_divergences_md() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../analysis/pqHSM");
    let divs = script_text(root.join("DIVERGENCES.md"));
    let plan = script_text(root.join("PHASE2_PLAN.md"));
    let divs_all = all_divs();
    let used: BTreeSet<&str> = divs_all
        .iter()
        .map(|d| d.div)
        .chain(RUST_ONLY.iter().map(|r| r.div))
        .collect();
    for id in &used {
        if id.starts_with("DIV-") {
            let at = divs
                .find(&format!("### {id} "))
                .unwrap_or_else(|| panic!("{id} is not in DIVERGENCES.md"));
            let status = divs[at..]
                .lines()
                .find(|l| l.contains("**Status:**"))
                .unwrap();
            assert!(
                status.contains("DECIDED") || status.contains("DONE"),
                "{id}: {status}"
            );
        } else {
            assert!(
                plan.contains(&format!("**{id}")) || plan.contains(&format!("{id}:")),
                "{id} is not in PHASE2_PLAN.md"
            );
        }
    }
    for id in [
        "DIV-001", "DIV-010", "DIV-011", "DIV-012", "DIV-013", "DIV-014", "DIV-015", "DIV-023",
        "DIV-024", "DIV-025", "DIV-026", "DIV-027", "DIV-028", "DIV-029", "DIV-030", "DIV-031",
        "H4", "M2", "M4",
    ] {
        assert!(
            used.contains(id),
            "{id} applies to fhsm_token.c but no step covers it"
        );
    }
}

/// The scenario names say which rule or DIV they cover; a `_divNNN` name with no row of that
/// DIV would be a scenario whose divergence nobody checks.
#[test]
fn every_div_named_scenario_has_a_row_of_that_div() {
    for n in NAMES {
        if let Some(i) = n.rfind("_div") {
            let id = format!("DIV-{}", &n[i + 4..]);
            assert!(
                all_divs().iter().any(|d| d.scenario == *n && d.div == id),
                "{n}: no {id} row"
            );
        }
    }
}

/// The Rust-only rows: each names a test that exists, and the DIV-025 rows between them cover
/// every `fhsm_rng_bytes` line DIVERGENCES.md lists.
#[test]
fn rust_only_rows_name_real_tests_and_cover_every_rng_site() {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    for r in RUST_ONLY {
        let src = script_text(here.join(r.file));
        assert!(
            src.contains(&format!("fn {}()", r.test)),
            "{}: no fn {} in {}",
            r.div,
            r.test,
            r.file
        );
    }
    let divs = script_text(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../analysis/pqHSM/DIVERGENCES.md"),
    );
    let at = divs
        .find("### DIV-025 ")
        .expect("DIV-025 in DIVERGENCES.md");
    let legacy = divs[at..]
        .lines()
        .find(|l| l.contains("**Legacy:**"))
        .unwrap();
    // `:1232-1233` is two lines
    let mut listed = BTreeSet::new();
    for tok in legacy.split(':').skip(1) {
        let t: String = tok
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        if t.is_empty() {
            continue;
        }
        let (a, b) = t.split_once('-').unwrap_or((&t, &t));
        for n in a.parse::<u32>().unwrap()..=b.parse::<u32>().unwrap() {
            listed.insert(n);
        }
    }
    let covered: BTreeSet<u32> = RUST_ONLY
        .iter()
        .filter(|r| r.div == "DIV-025")
        .flat_map(|r| r.c_sites.iter().copied())
        .collect();
    assert_eq!(covered, listed, "DIV-025 sites covered vs listed");
}
