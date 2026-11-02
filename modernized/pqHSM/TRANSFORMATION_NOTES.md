# Transformation Notes: Phase 1, audit trail (C → Rust)

*Brief: `analysis/pqHSM/MODERNIZATION_BRIEF.md` §3 Phase 1. Divergences: `analysis/pqHSM/DIVERGENCES.md`. Written 2026-10-30.*

## What was replaced

| Legacy | Lines | Rust | Lines |
|---|---:|---|---:|
| `src/fhsm_audit.c` | 838 | `audit/src/` (crate `pqhsm-audit`) + `audit/shim/audit_event.c` | 1,345 + 37 |
| `tools/freehsm_audit.c` | 386 | `audit-verify/src/` (crate `pqhsm-audit-verify`, binary `pqhsm-audit`) | 516 |

In the hybrid build, the module links the Rust code in place of `src/fhsm_audit.c`. The C sources stay untouched as the oracle until Phase 6 (brief Q4). The Rust is longer than the C for three reasons:
- the C ABI layer (`ffi/c_abi.rs`, 366 lines);
- doc comments that state each rule;
- a verifier that copies `strtoll`/`sscanf`/`fgets` quirks so its verdicts match C's exactly.

## How equivalence was proved

The legacy code builds and runs here, so equivalence is shown by **running both implementations**, not only by recorded traces.

1. **Characterization tests:** 205 tests in `audit/tests/` and `audit-verify/tests/`.
   - Their expected values come from running the C code. Regenerate them with `tests-support/golden/regen.sh`.
   - Records written by C are reproduced byte for byte. The only exceptions are the DIV-006 records, which are checked against the Rust rendering.
   - The C verifier's result and broken-line number are reproduced for 31 tampered and hand-made logs.
   - The C tool's stdout, stderr and exit code are reproduced for 63 cases.
   - Property tests check that both verifiers reject any flipped byte, deleted line or swapped pair.
   - Result: **203 pass, plus 2 opt-in tests that pass in the hybrid run.**
2. **Hybrid run** (`tests-support/hybrid/run.sh`). It builds `libfreehsm.so` with `hybrid.mk` on a copy of the tree, in `localhost/pqhsm-rust:1.99.1`:

   | Check | Result |
   |---|---|
   | Legacy `make tests` against the hybrid library | **106/106 pass**, as in the pure-C baseline (`analysis/pqHSM/BASELINE.md`) |
   | `nm -D` exported symbols, compared with the pure-C build | identical, 63 symbols |
   | `NEEDED` libraries | identical: `ld-linux`, `libc`, `libcrypto.so.3` |
   | Rust tool on the C-written baseline fixture | 3 records OK |
   | C tool and Rust tool on a log written by the hybrid module | both OK |
   | `cross_impl` tests (C tool run on Rust-written logs) | 2/2 |
3. **Lint and format:** `cargo clippy --all-targets -D warnings`, with and without `--features ffi`, and `cargo fmt --check` are clean.

## Mapping: legacy → Rust

| Behaviour | Rule | Legacy | Rust |
|---|---|---|---|
| Event code → name | RULE-007 | `src/fhsm_audit.c:91-135` | `audit/src/record.rs:39-82` |
| Safe-ASCII filter | RULE-027 | `src/fhsm_audit.c:147-155` | `audit/src/record.rs:85-94` |
| Actor: cut to 127 bytes, then check | RULE-027 | `src/fhsm_audit.c:161-171` | `record.rs:102-106`, `ffi/c_abi.rs:136-141` |
| Params rendering, `{}` collapse, missing `}` at 1023 bytes | RULE-027, DIV-004, DIV-006 | `src/fhsm_audit.c:612-641` | `audit/src/record.rs:118-136` |
| Line body and suffix, 2048-byte limit | RULE-007 | `src/fhsm_audit.c:643-683` | `audit/src/record.rs:172-200` |
| Chain head and HMAC (`EVP_MAC` "HMAC"/SHA256, default library context) | RULE-007 | `src/fhsm_audit.c:497-505`, `src/fhsm_crypto.c:506` | `audit/src/chain.rs`, `audit/src/ffi/libcrypto.rs` |
| Highest existing sequence number (`strtoul` quirks) | RULE-094 | `src/fhsm_audit.c:430-454` | `audit/src/log.rs:28-65` |
| Open: stream target, or numbered file with `O_EXCL`, mode 0600, 4096 attempts | RULE-094, DIV-003 | `src/fhsm_audit.c:456-525` | `log.rs:159-190`, `log.rs:291-310` |
| Append; group-commit barrier; sticky failure | RULE-007, RULE-096, DIV-002 | `src/fhsm_audit.c:587-783` | `audit/src/log.rs:202-276` |
| Latch reasons | RULE-096 | `src/fhsm_audit.c` (5 call sites) | `audit/src/log.rs:106-121` |
| Re-entry guard; events before open dropped; ERROR-state gate | RULE-096 | `src/fhsm_audit.c:565-596`, `src/fhsm_crypto.c:508` | `audit/src/ffi/c_abi.rs` (`pqhsm_audit_event_v`) |
| Close, process-wide counters, current path | RULE-094 | `src/fhsm_audit.c:527-570` | `audit/src/ffi/c_abi.rs:127-185` |
| Key provisioning (TPM blob, mode and size checks, `O_EXCL`, lost race) | RULE-093 | `src/fhsm_audit.c:199-367` | `key.rs:58-197`, `ffi/c_abi.rs:260-332` |
| In-module verifier | RULE-008, DIV-007 | `src/fhsm_audit.c:370-384`, `:785-838` | `audit/src/verify.rs:41-134` |
| Variadic `fhsm_audit_event`, `fhsm_audit_mandatory` | — | `src/fhsm_audit.c:562`, `:587` | `audit/shim/audit_event.c` |
| Tool `dump` | RULE-008 | `tools/freehsm_audit.c:71-180` | `audit-verify/src/lib.rs:66-214` |
| Tool `verify` for a file or a directory | RULE-008 | `tools/freehsm_audit.c:184-368` | `audit-verify/src/lib.rs:217-366` |
| Tool CLI and usage text | RULE-008 | `tools/freehsm_audit.c:290-386` | `audit-verify/src/lib.rs:40-62` |

## Deliberate deviations

**Registered and decided** (`analysis/pqHSM/DIVERGENCES.md`):
- **DIV-002:** `ts` is sampled after the chain lock.
- **DIV-003:** `open` accepts only 32-byte keys.
- **DIV-006:** an unsafe parameter name becomes `INVALID`.
- **DIV-007:** the in-module verifier fails on a read error instead of reporting OK.

**Invisible to the harness, listed for reviewers:**
- **Key-provisioning stderr prefix:** `[pqhsm]` instead of `[freehsm-c]`. The harness does not compare stderr. Operator scripts that grep for the old prefix will stop matching.
- **Counters:** the safe `AuditLog::stats()` counts per log. The C ABI keeps C's process-wide counters by adding in the counters of closed logs (`ffi/c_abi.rs:82-88`).
- **A failed `fhsm_audit_open` while a log is already open:** C clears the reported current path but keeps writing to the old file. Rust keeps both the old file and its path. Reaching this takes a second `C_Initialize` without a `C_Finalize` in between, and the second open must also fail: `src/fhsm_pkcs11.c` has no `CKR_CRYPTOKI_ALREADY_INITIALIZED` guard (RULE-072, the brief's Q13, Phase 4). A *successful* reopen behaves the same in both: the new file replaces the old one. C leaks the old descriptor; Rust closes it.
- **Zeroisation:** the key, chain state and sealed blob are zeroised on drop (`zeroize`). The actor and path buffers, which C also wipes, are dropped without wiping; neither holds secret data.
- **Pairs beyond 256 in one event:** the shim passes none, which renders `{}`, the same output C produces once the 1024-byte buffer overflows.

**HMAC path:** `chain.rs` calls `EVP_Q_mac` directly, not through the `openssl` crate, because:
- it takes the same `EVP_MAC_fetch(NULL, "HMAC", NULL)` route as `fhsm_hmac`, so the FIPS provider sees the same request;
- the `openssl` crate's initialisation would have added `libssl` to the module's dependencies.

## Not migrated, and why

- **`chain_resume`:** already removed from the C source (`src/fhsm_audit.c:386-428`, a comment only).
- **The unused `numbered` variable and the 64-byte key buffer:** both go away with DIV-003.
- **`fhsm_audit_mandatory`:** stays in C, in the shim, because it is the compile-time constant `FHSM_AUDIT_MANDATORY`.
- **The `make audit-switch` target:** builds the `FHSM_AUDIT_MANDATORY=0` variant with a recursive `$(MAKE)`, which falls back to the plain legacy Makefile. Under `hybrid.mk` it would therefore test C, not Rust. It is not in `make tests`, so the 106/106 result does not depend on it. See the follow-ups.

## Follow-ups

- **Phase 2:** `src/fhsm_token.c`'s 11 `(void)fhsm_audit_event` calls start failing closed with `CKR_DEVICE_ERROR` (DIV-001). Key provisioning still calls the C TPM and DRBG through `ffi/c_abi.rs` (`LegacyEnv`). Swap that implementation when Phase 2 and Phase 3 move them; no trait change is needed.
- **Phase 3:** run the hybrid proof under the FIPS provider configuration that the baseline deferred, so the `EVP_Q_mac` path is confirmed under FIPS.
- **Phase 4:** the 47 call sites in `pkcs11.c` and `state.c` start failing closed (DIV-001). Revisit params truncation (DIV-004) and correct the FATAL message (DIV-005).
- **Harness:**
  - Add a `hybrid-audit-switch` target that passes `-f modernized/pqHSM/hybrid.mk` to the recursive make.
  - Store `tests-support/hybrid/run.sh` results under `analysis/pqHSM/` as the Phase 1 exit evidence.
- **Standalone tool:** it still reports OK after a read error, as C does; DIV-007 covers only the module. It also does not model a `0x` prefix inside `sscanf("%2x")`. No valid log or key contains one there.
- **`Containerfile.rust`:** downloads rustup at build time and needs the network. Pin a rustup-init checksum, or vendor it, before using it in CI.

## Architecture review (Step 5)

The `code-modernization:architecture-critic` agent reviewed the port. Below is what was done with each finding.

**HIGH, applied:**
1. **Abort at exit.** The thread-local actor had a destructor. `C_Finalize` called from an `atexit` handler emits an event after TLS teardown, the access panicked, and the process aborted.
   - Reproduced on the pre-fix hybrid library with `tests-support/hybrid/atexit_finalize.c`.
   - Fixed: the actor is now a destructor-free `Cell<Option<([u8; 127], u8)>>`.
   - `panic = "abort"` is set for release builds (brief risk 1).
   - The probe is now part of `tests-support/hybrid/run.sh`.
4. **Exit criteria, partly applied:**
   - All `unsafe` now lives in `audit/src/ffi/`: the libcrypto bindings in `ffi/libcrypto.rs`, the C ABI in `ffi/c_abi.rs`.
   - `deny.toml` is added, and `cargo deny check` is clean.
   - The hybrid run checks that `EVP_Q_mac` is imported from the system `libcrypto`.
   - Still open: see the follow-ups.

**HIGH, inherited from C, decided and applied (user: "I agree with what you have proposed"):**
2. **Verifiers ignore bytes after the MAC:** DIV-008.
3. **A forked child appends to the parent's chain:** DIV-009. It shipped together with finding 5: the log is an `Arc` behind a short lock, never held across I/O.

**MEDIUM and LOW, applied because they were Rust-introduced aborts or wrong text:**
- **6.** `eprintln!` panics when stderr cannot be written. Key provisioning now writes its messages and ignores write errors.
- **7.** The re-entry-guard comment claimed the guard stops latch recursion. It now says what actually ends it (`src/fhsm_state.c:136`).
- **Dead code:** `LogPath` is removed.

**Not applied, carried into the follow-ups:**
- **8.** New log and key files are never directory-fsynced; this is inherited from C. Proposing it as a divergence for Phase 2, since key custody is in scope there.
- **9.** The standalone tool still reports OK after a read error; DIV-007 covers only the module.
- **10.** `verify <dir>` silently stops at 4,096 files, as C does. It should fail when the cap is reached.
- **LOW:**
  - An HMAC failure always returns `0x6`; C propagates `fhsm_hmac`'s own value. Visible only once ERROR is latched.
  - Unzeroised key copies are left on the stack by moves. Box the key.
  - The provisioning loser can read the winner's file while it is still empty. Use write-to-temp then `link()`.
  - The counter snapshot can double-count during a close.
  - Seven-digit file suffixes are invisible to the numbering scan. Inherited from C.
  - Link flags apply to every target in `hybrid.mk`. Phase 2 must merge all crates into one staticlib, because two Rust staticlibs in one `.so` duplicate `std`.
- **Unregistered improvement:** in C, `fhsm_audit_close` racing a writer that waits on the barrier can run `fdatasync(-1)` and latch ERROR. In Rust the log lock rules that out.

## Phase 1 exit criteria: status

| Criterion | Status |
|---|---|
| Hybrid `libfreehsm.so` passes the full `make tests` with the baseline's per-test results | **Met:** 106/106 |
| Harness shows zero unexplained diffs in audit records across the test corpus | **Met.** 68 commands wrote 8,913 records. 64 are identical; the 4 that differ are explained in `analysis/pqHSM/PILOT_PLAYBOOK.md` §4.10: three are C's own run-to-run variance, one is DIV-009 |
| Cross-verification both ways; property tests reject edits, deletions and reorders | **Met** |
| Every P0 rule gated at Phase 1 passes | **Met** for RULE-007, 008, 027, 093, 094 and 096 (library side); DIV-008 and DIV-009 are decided and implemented |
| `unsafe` only in the FFI module; clippy `-D warnings` and `cargo deny check` clean | **Met** |
| `PILOT_PLAYBOOK.md` written | **Met:** `analysis/pqHSM/PILOT_PLAYBOOK.md` |
| Brief regenerated or re-approved against the playbook | **Open:** needs the user |
| Risk mitigations: TSan run of the fork and concurrency tests on the hybrid build; `catch_unwind` | **Done:** 4/4 tests pass with 0 TSan reports, hybrid and C. Rust code is not instrumented. `panic = "abort"` is set; `catch_unwind` has no effect under abort |

## Representative behaviour, side by side

Params rendering: `src/fhsm_audit.c:612-641` (left) and `audit/src/record.rs:118-136` (right). Both overflow rules show here: a pair that does not fit the 1024-byte buffer collapses the object to `{}`, and a buffer filled to exactly 1023 bytes loses its closing `}`.

```text
                                                                                    |  pub fn render_params(pairs: &[(&[u8], &[u8])]) -> String {
    /* Variadic key/value params --- copied verbatim, only safe-ASCII               |      let mut out = String::from("{");
     * accepted. Length-only convention: callers never pass key material. */        |      for (i, (k, v)) in pairs.iter().enumerate() {
    va_list ap; va_start(ap, rv);                                                   |          let (k, v) = match (safe_str(k), safe_str(v)) {
    char params[1024]; size_t pp = 0;                                               |              (Some(k), Some(v)) => (k, v),
    int first = 1;                                                                  |              (Some(k), None) => (k, INVALID),
    params[pp++] = '{';                                                             |              (None, _) => (INVALID, INVALID),
    while (1) {                                                                     |          };
        const char *k = va_arg(ap, const char*);                                    |          let sep = if i == 0 { "" } else { "," };
        if (!k) break;                                                              |          let pair_len = sep.len() + k.len() + v.len() + 5; // 4 quotes and a colon
        const char *v = va_arg(ap, const char*);                                    |          if out.len() + pair_len >= PARAMS_MAX {
        if (!safe_ascii(k) || !safe_ascii(v)) {                                     |              return "{}".to_owned();
            v = "INVALID";                                                          <
        }                                                                                      }
        int n = snprintf(params + pp, sizeof(params) - pp,                          |          let _ = write!(out, "{sep}\"{k}\":\"{v}\"");
                          "%s\"%s\":\"%s\"", first ? "" : ",", k, v);               <
        if (n < 0 || (size_t)n >= sizeof(params) - pp) {                            <
            pp = 0; /* truncate --- evaluator sees an empty params object */        <
            break;                                                                  <
        }                                                                           <
        pp += (size_t)n;                                                            <
        first = 0;                                                                  <
    }                                                                                      }
    va_end(ap);                                                                     |      if out.len() < PARAMS_MAX - 1 {
    if (pp == 0) {                                                                  |          out.push('}');
        params[0] = '{'; params[1] = '}'; pp = 2;                                   <
    } else {                                                                        <
        if (pp < sizeof(params) - 1) { params[pp++] = '}'; }                        <
    }                                                                                      }
    params[pp] = '\0';                                                              |      out
```


---

# Transformation Notes: Phase 2, token store, TPM sealing, revocation DB (C → Rust)

*Brief: `analysis/pqHSM/MODERNIZATION_BRIEF.md` §3 Phase 2. Plan: `analysis/pqHSM/PHASE2_PLAN.md`. Divergences: `analysis/pqHSM/DIVERGENCES.md`. Written 2026-11-01.*

## What was replaced

| Legacy | Lines | Rust | Lines |
|---|---:|---|---:|
| `src/fhsm_token.c` | 2,687 | `token/src/` (crate `pqhsm-token`): `token.rs`, `store.rs`, `header.rs`, `crypto.rs`, `ffi/token_abi.rs`, `ffi/mem.rs`, `ffi/lock.rs`, `ffi/sys.rs`, `ffi/cprim.rs`, `ffi/libcrypto.rs` | 3,398 |
| `src/fhsm_tpm.c`, `src/fhsm_token_tpm.c` | 557 | `token/src/tpm.rs`, `token/src/ffi/c_abi.rs` | 517 |
| `src/fhsm_revocation.c` | 572 | `pki/src/` (crate `pqhsm-pki`) | 1,554 |

3,816 lines of C are retired in the hybrid build: `hybrid.mk` empties `fhsm_token.o`, `fhsm_tpm.o`, `fhsm_token_tpm.o` and `fhsm_revocation.o`, and the one staticlib `pqhsm-module` supplies the code. The C tree is unchanged (brief Q4). The Rust is longer mainly because of the C ABI layers (`token_abi.rs` 878, `pki/src/ffi/c_abi.rs` 650 lines), which reproduce C's argument checks in C's order, and the two crypto backends behind one seam.

## How equivalence was proved

The legacy code builds and runs here, so equivalence is shown by running both implementations.

1. **Characterization tests,** expected values from running C (`tests-support/golden/regen_{token,store,tpm,rev}.sh`):
   - `pqhsm-token`: 269 tests on the safe API; 289 with feature `ffi`, which adds the C-ABI row replay and the 14 RNG-failure sites (DIV-025). 131 store scenarios replay C step by step, with C's token file bytes after each step under a pinned RNG.
   - `pqhsm-pki`: 322 safe-API and 14 C-ABI tests.
   - Workspace: 829 pass, 0 fail, 3 ignored (opt-in, run by the harness).
2. **Golden corpus both ways** (§5.1). Rust loads every C-written file in `testdata/` with C's verdicts (`token/tests/corpus.rs`). The harness builds `gen_token` against the Rust store, has it write the same corpus, and has the pure-C `gen_token describe` read it back: C's reading equals `testdata/manifest.tsv` exactly, serials masked (17 of 17 lines, object values included, the TPM-sealed and zero-DEK tokens included).
3. **Token side effects** (§5.4). Every token file the 106 legacy test commands leave is read by C from both runs, and by Rust from the C run, PIN-free (size, `.tpm` presence, load code, label, counters, lock flags); see the exit-criteria table.
4. **Hybrid run** (`tests-support/hybrid/run.sh`): see the exit-criteria table.
5. **Fuzzing** (`token/fuzz/`, nightly `cargo fuzz`): `token_file` (header, blob framing, public view) and `store_plaintext` (store parse, with a write-and-reparse check), seeded from `testdata/*.tok`, the 131 golden token files, the crafted malformed inputs in `tests/golden/store/in/`, and the 19 C-written plaintexts. 5 minutes each: 18.4 M and 6.7 M runs, no crash, no artifact. Rerun 2026-11-02 on the code with all review fixes: 13.9 M and 6.4 M runs, no crash, no artifact.
6. **Divergence tests:** one per DIV, each failing on C and passing on Rust.

## Mapping: legacy → Rust

| Behaviour | Legacy | Rust |
|---|---|---|
| Header layout and read (RULE-004) | `src/fhsm_token.c:289-311`, `:1306-1334` | `token/src/header.rs:1-91` |
| Load and public view (RULE-062) | `src/fhsm_token.c:1021-1090`, `:1306-1355` | `token/src/token.rs:403-448`, `store.rs:449-506` |
| Init and re-init (RULE-079, RULE-080) | `src/fhsm_token.c:1214-1305`, `:1817-1897` | `token/src/token.rs:449-541`, `:822-876` |
| PIN check, counters, throttle, lock (RULE-084, RULE-085) | `src/fhsm_token.c:276`, `:1366-1644` | `token/src/token.rs:546-726` |
| Set PIN, init user PIN | `src/fhsm_token.c:1714-1816` | `token/src/token.rs:757-821` |
| The one token-file transaction (H1–H3, DIV-012, DIV-013) | `src/fhsm_token.c:1092-1213` (`write_atomic`) | `token/src/token.rs:186-300`, `:739-756` (`commit`, `Flock`) |
| Object store parse and serialise (RULE-090–092) | `src/fhsm_token.c:591-915`, `:916-1020` | `token/src/store.rs:188-448` |
| Value allocation and release (RULE-078, M2) | `src/fhsm_token.c:537-590` | `token/src/ffi/mem.rs:1-115`, `store.rs:24-60` |
| Object attributes, policy, templates (RULE-061, RULE-062) | `src/fhsm_token.c:1898-2687` | `token/src/token.rs:914-1283` |
| C ABI of `fhsm_token.h` | `include/fhsm_token.h` | `token/src/ffi/token_abi.rs` |
| TPM seal and unseal (RULE-089) | `src/fhsm_tpm.c:183-408`, `src/fhsm_token_tpm.c` | `token/src/tpm.rs:74-330`, `ffi/c_abi.rs` |
| Revocation DB load and save (RULE-024, RULE-100) | `src/fhsm_revocation.c:159-272` | `pki/src/revocation.rs:268-427` |
| Revocation dates | `src/fhsm_revocation.c:92-121` | `pki/src/revocation.rs:106-175` |
| OCSP responder check and answer | `src/fhsm_revocation.c:274-572` | `pki/src/revocation.rs:428-663` |
| Zero-DEK migration (DIV-010, replaces the silent fallback) | `src/fhsm_token.c:942-1020` (the fallback) | `token/src/token.rs:360-402` (`migrate_zero_dek`) |

## Deliberate deviations

**Decided divergences, all implemented and tested:** DIV-010 to DIV-016 and DIV-019 to DIV-027, and DIV-001's 11 token audit sites (an operation whose audit fails now fails; when the call is already failing, the original error wins). See `DIVERGENCES.md` for each entry's legacy behaviour, target and test.

**Recorded as DIV entries after the review (M-6, 2026-11-02):**
- **DIV-028:** login or `set_pin` with a role other than SO or user returns `ARGUMENTS_BAD`. C carried on: it used the user's counters and wrap key and recorded the bad role as the logged-in one.
- **DIV-029:** `FHSM_TPM_SEALING` is read when the token is loaded or created. C re-read it at every login.
- **DIV-030:** `-DFHSM_MAX_OBJECTS=` no longer reaches the store, whose cap is fixed at 1,024. No make target sets it.

**Not in a DIV entry; recorded here:**
- **Key custody:** object values and the DEK are allocated where C put them (the secure heap for sensitive values and the DEK, `malloc` otherwise) and released through `fhsm_api_free_value`. The reference implementation used to plan the port kept them in pageable Rust memory; that would have reversed review M2 and C's fix #127.
- **The token mutex** is a `pthread_mutex_t` under `ffi` (`token/src/ffi/lock.rs`), as C's `t->mu` was. With std's `Mutex`, ThreadSanitizer cannot see the locking in an uninstrumented staticlib and reported 35 false races in `test_concurrency_store`.

## Not migrated, and why

- **The zero-DEK fallback** (SEC-002) is gone, as Q6 decided. `migrate_zero_dek` is the explicit offline way back for tokens the ≤2.5.0 bug left.
- **Throttle deadlines in the header** (bytes 301–316) are still written as zero and ignored on read, as in C. They are derived from the counters at load.
- **Candidates 4 and 5** (`mech_allowed` RULE-061, `destroy_session_objects` RULE-090) are deferred to Phase 4, as decided; candidate 7 is kept as C.

## Follow-ups

1. **Token `.tmp` and `.tpm.new` files:** fixed 2026-11-02 as DIV-031 (a) and (b), the way DIV-022 fixed the revocation DB. A FIFO staged at `.tpm.new` is now replaced too, so the DIV-015(d) row no longer reaches the fsync-failure branch; the check stays in the code.
2. **`make ocsp-delegated`** is not in the harness: it runs `make clean` and rebuilds under another PROFILE.
3. **Phase 3:** the crypto seam (`token/src/crypto.rs`) calls C's `fhsm_pbkdf2`, `fhsm_aes_gcm_*` and `fhsm_rng_bytes` over FFI (plan §6.1). When `fhsm_crypto` moves, `ffi/cprim.rs` is the one file to replace.
4. **Phase 4:** DIV-001's 45 `fhsm_pkcs11.c` and 2 `fhsm_state.c` sites; deferred candidates 4 and 5.
5. **Fuzzing in CI** needs a nightly toolchain; the pinned image has none (the run above used the host's nightly inside the image).

## Architecture review (Step 5)

The architecture-critic reviewed `token/`, `pki/`, `hybrid.mk` and `token/fuzz/` on 2026-11-01: 3 HIGH, 6 MEDIUM, 6 LOW. Each HIGH was checked against the code before it was fixed. It confirmed as sound: the argument order of all 43 ABI functions, the TLS copies, the `PolicyAttr` layout, the variadic audit call, `Buf`'s `Send`/`Sync`, the lock after fork, the memfd flags and `hybrid.mk`.

**HIGH, applied:**
- **H-1 KEK and DEK left in unzeroised memory.** The KEK is now `Zeroizing<[u8; 32]>`, `unwrap_dek` returns a `Zeroizing` DEK, and `crypto::gcm_decrypt` returns `Zeroizing<Vec<u8>>` from both backends, so every decrypted DEK and store plaintext is wiped on drop.
- **H-2 `store::serialize` reallocating.** The output's exact length is computed first and allocated once; a debug assertion checks the capacity never changed. Before, each growth freed a prefix of the plaintext store, key values included.
- **H-3 The DIV-010 command was missing.** `pqhsm-token migrate-zero-dek <slotN.tok>` now exists (`token/src/bin/pqhsm-token.rs`, feature `tool`, never with `ffi`). It reads the PIN without echo into a `Zeroizing` buffer. `migrate_zero_dek` now takes the token-file lock before it reads. Tested end to end in `token/tests/tool.rs`.

**LOW, applied:** L-1, the `object_find` copy into a NULL `handles_out` (undefined behaviour even for 0 elements; `test_public_objects` passes NULL). Guarded.

**MEDIUM, applied 2026-11-02** (user: "fix M-1 to M-4 and M-6 before Phase 3"). The M-1 and M-2 tests assert exactly what the old code got wrong (the token's serial, the throttle deadline). M-4 has a unit test of the bounded wait. M-3 is checked by a unit test of `wipe` and a debug assertion that the DEK is not shared when it is wiped, not by inspecting freed memory. The DIV entries carry the amendments.
- **M-1** A failed reseal at re-init left the token with its old serial, so every later write failed the identity check, and no `SEAL_FAILURE` record was written. Now the token follows the re-initialised file, the stale `.tpm` is removed, and `SEAL_FAILURE` (`tpm-seal-reinit`) is written. The call still fails with the TPM's error (DIV-015 amendment).
- **M-2** `Flock::take` refreshed the failure counters from disk but not the throttle deadline. Now a changed count restarts the deadline, as load does, and every transaction carries the deadlines with the counters (DIV-012 amendment).
- **M-3** The DEK is zeroised in place (`Buf::wipe`) before it is released: at logout, after create and re-init, and on the DIV-013 forced logout. A debug assertion checks that nothing else holds it at that moment (DIV-014 amendment).
- **M-4** The `flock` wait gives up after 10 s (`FLOCK_WAIT`) with `FUNCTION_FAILED`, and `flock` is retried on EINTR (DIV-012 amendment).
- **M-6** The three undocumented behaviour changes are now DIV-028, DIV-029 and DIV-030, each with a Rust-only test row. They were recorded, not reverted.

**Recorded for later:**
- **M-5** Plan H1 asked for one transaction helper; `set_pin`, `init_user_pin`, `reinit` and `object_destroy` still write their own, and no second record is written when the write fails after the audit succeeded.
- **L-2** The pthread `Guard` should not be `Send`. **L-3** One SAFETY comment gives the wrong reason (re-init is safe because it runs under the exclusive API lock). **L-4** A fork while another thread holds a cloned store can keep key copies alive in the child. **L-5** A directory-fsync failure is reported after the rename. **L-6** Dead code: `Token::close`, test-only `Token::object_get`, a duplicated `PIN_MIN` check, and `CAudit` silently dropping all but one audit pair.

## Phase 2 exit criteria: status

Final hybrid run, 2026-11-02, after the HIGH, L-1 and MEDIUM (M-1 to M-4, M-6) review fixes, with the same results as the 2026-11-01 run:

| Brief exit criterion | Evidence | Status |
|---|---|---|
| Hybrid build passes `make tests` | 106/106; `nm -D` (63 symbols) and NEEDED identical; the C token, TPM and revocation objects are empty and the module's code is Rust | ✅ |
| File compatibility round-trip clean | Rust reproduces `manifest.tsv` and `revocation.tsv`; C's reading of the Rust-written corpus equals `manifest.tsv`; all 66 token files the tests leave load in both readers. Recorded exception: `zero_dek_2_5_0.tok` (DIV-010) | ✅ |
| Zero unexplained on-disk diffs | Audit logs: 64 same, the same 4 explained (playbook §4.10). Token files: 64 of 66 identical; `test_pkiops_algs` and `test_pkiops_envelope_rsa` differ in size by 1 byte, from the DER length of freshly generated keys. A C-only control, 3 runs each, varies 51,963–51,966 and 5,739–5,742 bytes; both Rust sizes fall inside | ✅ |
| `cargo-fuzz` header and blob parsers | `token/fuzz/`, 5 minutes each: 18.4 M and 6.7 M runs, no crash | ✅ |
| `test_concurrency_store`; SEC-004 as Q8 decided | Pass; TSan 0 races in all 4 concurrency tests; DIV-012 `flock` | ✅ |
| Every P0 rule gated at Phase 2 | All 30 covered by a characterization, corpus or DIV test; RULE-056 deferred to Phase 4 (Q12) | ✅ |

Also: workspace 834 pass, token 275 with `tool` and 294 with `ffi`. Rerun after DIV-031 (2026-11-02): workspace 836, token 277 / 296; harness unchanged (106/106, `nm -D` and NEEDED identical, TSan 0 races, corpus 64 same / 4 explained); token files 65 of 66 identical, the 66th `test_pkiops_envelope_rsa` at 5,740 bytes, inside the C-only range. Throughout: fmt and clippy `-D warnings` clean in every feature set, `cargo deny` clean, `unsafe` only in `ffi/`.

## Representative behaviour, side by side

The token header read: C `src/fhsm_token.c:1315-1334` (left) and Rust `token/src/header.rs:49-70` (right). The offsets are the same; Rust also refuses an iteration count other than 200,000 (DIV-011), and C's throttle re-imposition, which follows on the left, is in `Token::load` on the right.

```
    if (memcmp(buf, FHSM_TOK_MAGIC, 4) != 0) return FHSM_RV_FUNCTION_F	  |	    pub fn parse(file: &[u8]) -> Result<Header, Rv> {
    if (get_u32_le(buf + 4) != FHSM_TOK_VERSION) return FHSM_RV_FUNCTI	  |	        if file.len() < LEN || file[..4] != MAGIC || u32_at(file, 4) !
									  |	            return Err(Rv::FUNCTION_FAILED);
    fhsm_token_t *t = calloc(1, sizeof(*t));				  |	        }
    if (!t) return FHSM_RV_HOST_MEMORY;					  |	        let h = Header {
    pthread_mutex_init(&t->mu, NULL);					  |	            label: arr(file, 8),
									  |	            serial: arr(file, 72),
    snprintf(t->path, sizeof(t->path), "%s", path);			  |	            pbkdf2_iter: u32_at(file, 136),
    memcpy(t->label,  buf + 8,  sizeof(t->label));			  |	            salt_so: arr(file, 140),
    memcpy(t->serial, buf + 72, sizeof(t->serial));			  |	            so_wrap_nonce: arr(file, 156),
    t->pbkdf2_iter = get_u32_le(buf + 136);				  |	            so_wrap_ct: arr(file, 168),
    memcpy(t->salt_so,         buf + 140, 16);				  |	            salt_user: arr(file, 216),
    memcpy(t->so_wrap_nonce,   buf + 156, 12);				  |	            user_wrap_nonce: arr(file, 232),
    memcpy(t->so_wrap_ct,      buf + 168, 48);				  |	            user_wrap_ct: arr(file, 244),
    memcpy(t->salt_user,       buf + 216, 16);				  |	            user_initialized: file[292] != 0,
    memcpy(t->user_wrap_nonce, buf + 232, 12);				  |	            failed_so: u32_at(file, 293),
    memcpy(t->user_wrap_ct,    buf + 244, 48);				  |	            failed_user: u32_at(file, 297),
    t->user_initialized      = buf[292] ? 1 : 0;			  |	        };
    t->failed_so             = get_u32_le(buf + 293);			  |	        if h.pbkdf2_iter != PBKDF2_ITER {
    t->failed_user           = get_u32_le(buf + 297);			  |	            return Err(Rv::FUNCTION_FAILED);
									  >	        }
									  >	        Ok(h)
```

# Transformation Notes: Phase 3, crypto core (C → Rust)

Plan: `analysis/pqHSM/PHASE3_PLAN.md` (approved 2026-11-02). One section per slice.

## Slice 1 (pilot): secure heap and conf reader

### What was replaced

`src/fhsm_conf.c` (93 lines) and `src/fhsm_memory.c` (274 lines) are now `crypto/` (`pqhsm-crypto`), linked into the module through `pqhsm-module`. `hybrid.mk` empties `fhsm_conf.o` and `fhsm_memory.o`. The remaining C, including the token crate's `Buf`, calls the same ten `fhsm_conf_*`, `fhsm_secure_*`, `fhsm_zeroize` and `fhsm_ct_memcmp` symbols, which the Rust crate now defines. The heap is still OpenSSL's secure arena, one per process, as in C.

### How equivalence was proved

Equivalence is dual-execution: the legacy C was run in the pinned image.

1. **Goldens from the C:** `tests-support/golden/gen_crypto.c` (run by `regen_crypto.sh`) produces 127 rows in `crypto/tests/golden/`:
   - 39 `fhsm_conf_lookup` rows: exact and prefix keys, comments and sections, CRLF, NUL bytes, truncation with rtrim, a key hidden in the second 511-byte piece of a long line, and argument checks.
   - 23 `fhsm_conf_secure_heap_bytes` rows: bounds, power-of-two rounding, `strtoul`'s `+`, `-0` and wrap, the 31-byte cut, overflow.
   - 8 heap scenarios, one process each: default, lazy init, `FHSM_CONF=""`, a 100 kB arena exhausted with no fallback, mlock refused (rc 2), allocation refused (rc 0), adopting a locked arena, refusing an unlocked one. The stderr of each is kept and compared byte for byte.

   `crypto/tests/golden.rs` replays every row through the Rust C ABI, all 127 passing, one of them as Rust-only (DIV-038). Getting there caught one slip: a lost two-space indent in the operator message.
2. **Property tests:** `parse_ulong` against libc's `strtoul`, on random strings and on every `u64` with and without a sign.
3. **Hybrid harness** (2026-11-02):
   - 106/106; `nm -D` (63 symbols) and NEEDED identical.
   - Crypto swap: C objects with code 0; `fhsm_secure_malloc` in the module, from Rust.
   - Audit corpus 64 same / 4 explained; token files 65/66 identical, the 66th the known DER-length size variance; TSan 0 races.
   - `test_conf`, `test_smoke` and `test_secure_heap_shared` (two module copies, one arena adopted) pass.
   - New step 4b runs `test_secure_heap` and `probe_secure_heap`, which `make tests` does not, on C and hybrid.
     - `probe_secure_heap`: 8192 kB locked by `C_Initialize` on both builds, output identical.
     - `test_secure_heap`, as shipped, exits 2 on both builds before any heap check. It logs in as USER while SO is still logged in, and the token refuses with `0x104`. The harness adds the missing `fhsm_token_logout` to its copies; the C tree is untouched.
     - With the logout added, `test_secure_heap` passes on both, output identical: secure heap for sensitive values only, and a 64 kB `secure_heap_kb` arena exhausted to `DEVICE_MEMORY` before the object cap.
     - This step ran on the reviewed code in the rerun's work tree.
4. Workspace: 844 pass. fmt and clippy `-D warnings` clean with and without `ffi`.

### Mapping: legacy → Rust

| Behaviour | Legacy | Rust |
|---|---|---|
| Config path (`FHSM_CONF`, default) | `fhsm_conf.c:21-24` | `conf.rs:28` `path` |
| Key lookup, line rules, truncation, rtrim | `fhsm_conf.c:26-61` | `conf.rs:37` `lookup_in`, `:47` `value`; C ABI `ffi/c_abi.rs:18` |
| `secure_heap_kb` parse, bounds, rounding | `fhsm_conf.c:63-93` | `conf.rs:68` `secure_heap_bytes_in`, `:84` `parse_ulong` |
| Arena created once, refused unless locked | `fhsm_memory.c:104-203` | `mem.rs:20-53` `arena`, `create_once` (`pthread_once`, `ffi/sys.rs` `heap_once`), `create` |
| Adopt another copy's arena (smaps `lo`) | `fhsm_memory.c:72-102` | `mem.rs:56` `adopt`, `:68` `locked_mapping_size` |
| Operator messages | `fhsm_memory.c:110-116`, `:174-202` | `mem.rs:137`, `:145` (text unchanged) |
| init, malloc, zalloc, free, used, total | `fhsm_memory.c:205-253` | `mem.rs:92-125`; `ffi/sys.rs`; C ABI `ffi/c_abi.rs:45-77` |
| `fhsm_zeroize` | `fhsm_memory.c:255-261` | `ffi/c_abi.rs:80` (`zeroize` on `MaybeUninit<u8>`) |
| `fhsm_ct_memcmp` | `fhsm_memory.c:263-274` | `mem.rs:134` `ct_diff`; C ABI `ffi/c_abi.rs:90` |

### Deliberate deviations

- **DIV-038 (DECIDED, Fix):** the size reported after adopting another copy's arena is the mapping's real size, not C's address-sized number from a `sscanf` side effect.
- **DIV-039 (recorded):** `fhsm_conf_lookup` leaves `out` untouched when it returns 0. Checked by the golden replay.
- **DIV-030(b):** `-DFHSM_SECURE_HEAP_BYTES` and `-DFHSM_SECURE_HEAP_MINSIZE` no longer reach the arena; `secure_heap_kb` does.
- The Rust-only `ct_diff` returns non-zero for unequal lengths (review M2a). The C ABI always passes one length, so its results are C's, including the OR-of-XOR value.

### Not migrated

The `FHSM_SECURE_HEAP_*` build-time overrides (DIV-030(b)). The Makefile comment at `Makefile:761` ("promises a re-check ... and does not perform one") is stale in the C: the `== 1` test is that re-check. The C tree is left alone (Q4).

### Architecture review (Step 5)

No HIGH findings. Applied: M1 (user: "Fix now with pthread_once"; first use now runs under `pthread_once`, so a child forked while another thread is inside the init reruns it, as in C; `tests/fork_init.rs` failed on `OnceLock` and passes now), M2a (unequal lengths), L1 (no overflow on a malformed smaps line), L2 (zeroise through `MaybeUninit`), L8 (two citations), T1 (DIV-039 asserted), T4 (unequal-length test).

Recorded for later:

- **M2b:** `ct_diff` relies on `black_box`. `CRYPTO_memcmp` (as `audit/src/chain.rs`) would be constant-time by construction. Changing the C ABI's result to 0/1 would need a DIV entry; all three C callers test `== 0`.
- **L3:** the conf file is read whole; C read 512 bytes at a time and stopped at the first match. `/dev/zero` or a FIFO behaves differently.
- **L4:** 64-bit only. C's `unsigned long` wraps at 32 bits on ILP32; no 32-bit target in the tree.
- **L5:** `isspace` is always the C locale.
- **L6:** add `#![deny(unsafe_code)]` outside `ffi/`; the `strtoul` test helper is `unsafe` in `conf.rs`.
- **L7:** the raw-pointer `mem::alloc`/`free` are public, with no Rust caller yet.
- **T2:** fork during first use is tested (`fork_init`); concurrent first use from N threads is not.
- **T3:** an unreadable smaps is untested.
- **T5:** the heap scenarios assume no CAP_IPC_LOCK.
- **T6:** no differential fuzzing of the conf parser.

### Follow-ups for slice 2 (DRBG)

- The DRBG's buffers can use `mem::alloc`, or better a `sys::Block`-style owner. Any secret comparison uses `ct_diff` (equal lengths) or `CRYPTO_memcmp`.
- The DRBG's and the init latch's process-global state follow the same rule as the arena: `pthread_once` where C uses it, so fork behaves as in C.

## Slice 2: hardened DRBG

### What was replaced

`src/fhsm_drbg.c` (471 lines) is now `crypto/src/drbg.rs` (the logic), `crypto/src/ffi/entropy.rs` (OpenSSL's generator, the entropy pool, SHA2-384 conditioning, the clock) and the DRBG section of `crypto/src/ffi/c_abi.rs` (the four `include/fhsm_drbg.h` exports). `hybrid.mk` empties `fhsm_drbg.o`. `fhsm_rng_bytes` (`src/fhsm_crypto.c`, still C) and the audit key provisioning reach the Rust DRBG through those exports. The module state stays in C (`fhsm_state.c`, Phase 4): Rust calls `fhsm_state_get` and `fhsm_state_latch_error`.

### How equivalence was proved

Equivalence is dual-execution: the legacy C was run in the pinned image.

1. **Goldens from the C:** `tests-support/golden/gen_drbg.c` (run by `regen_crypto.sh`) links `fhsm_drbg.o` alone with `--wrap` seams. `RAND_bytes` becomes a fixed xorshift stream that can inject byte runs, APT patterns, repeated blocks and failures; `RAND_add` is counted; `time` is a scripted clock; `EVP_MD_fetch` can be made to fail the conditioner. It writes 127 rows over 25 scenarios, each in its own process: chunking, reseed by bytes and by time (inside one request too), lazy seeding and its failure, the RCT, APT and CRNGT edges, a generator failure mid-request, conditioner failures at init, at an explicit reseed and at a periodic one, and the ERROR state. Each output buffer is recorded as an FNV-1a sum (`sum=`); when a check cleansed it, what the generator produced is recorded too (`gen=`).
2. **Replay:** `crypto/tests/drbg_golden.rs` drives `Drbg` with a scripted source that mirrors the C seams byte for byte. All 127 rows pass; 15 of them are Rust-only rows for DIV-032, DIV-033 and DIV-037. Their expected sums are taken from the C rows (`gen=` for output C cleansed and Rust keeps, the zero-buffer sums for the reverse), not from the Rust code. Only `cond_fail_periodic_mid`'s `gen` has no C counterpart, and that one field is not compared.
3. **Unit tests:** APT 18 passes and 19 fails (DIV-032); the cutoff formula reproduces SP 800-90B Table 2 (W = 512, α = 2^-20: 13, 62, 177, 311) and 19 at α = 2^-40; CRNGT on every block and never under 16 bytes (DIV-037); `OsSource` seeds from getrandom (the C's `src=1`), each source fills only what is left, SHA2-384 against its test vector.
4. **Hybrid harness:** see below.
5. Workspace: 851 pass, five runs in a row. fmt and clippy `-D warnings` clean with and without `ffi`.

### Mapping: legacy → Rust

| Behaviour | Legacy | Rust |
|---|---|---|
| Cutoffs, limits | `fhsm_drbg.c:94-111` | `drbg.rs:14-26` |
| Module statics, `g_mtx` | `fhsm_drbg.c:116-131` | `drbg.rs:85` `Drbg`; `ffi/c_abi.rs:120` `DRBG` |
| Entropy sources, pool, SHA2-384, `RAND_add` | `fhsm_drbg.c:142-275` | `ffi/entropy.rs:26-57` `OsSource`, `:62-150` sources, `sha384` |
| Seed bookkeeping (time, counters) | `fhsm_drbg.c:271-274` | `drbg.rs:175` `seed` |
| RCT, APT | `fhsm_drbg.c:280-336` | `drbg.rs:194` `health` |
| CRNGT | `fhsm_drbg.c:338-351` | `drbg.rs:194` `health` (every block, DIV-037) |
| init, reseed, stats | `fhsm_drbg.c:356-370`, `:466-471` | `drbg.rs:124-140`; C ABI `ffi/c_abi.rs:141-175` |
| bytes: state, arguments, lazy seed, chunks, reseed, cleanse | `fhsm_drbg.c:372-464` | `drbg.rs:145` `bytes`, `:187` `reseed_due`; C ABI `ffi/c_abi.rs:153` |
| Return codes, latch reasons | throughout | `drbg.rs:65-82` `Error::rv`, `latch_reason` |

### Deliberate deviations

- **DIV-032 (APT C = 19, B ≥ C), DIV-033 (a failed periodic reseed latches ERROR, `CKR_FUNCTION_FAILED`, the request's output cleansed), DIV-036 (`CLOCK_BOOTTIME`), DIV-037 (every 16-byte block against the one before it):** DECIDED and done. DIV-037's `docs/FIPS_140_3.md:157` update waits for cutover (Q4).
- **DIV-040 (recorded):** `fhsm_drbg_bytes` zeroes the caller's buffer before filling it. A failed call leaves 0 where C left the old contents.
- Kept as C, and pinned by goldens: a generator failure mid-request latches without cleansing the earlier chunks (`rand_fail_mid`); a failed lazy seed returns `RNG_FAILURE` without latching (`lazy_fail`); `fhsm_drbg_reseed` works in ERROR (`error_state`); getrandom fills the whole 512-byte pool, so RDRAND, `/dev/urandom` and the jitter contribute only after a short read (`src=1` throughout).

### Not migrated

RDRAND off x86_64 (C also took it on i386); the hybrid builds x86_64 only. A `shortcut:` comment marks it in `ffi/entropy.rs`.

### Architecture review (Step 5)

No HIGH findings. Applied: M3 (golden scenario `lazy_fail` pins the failed lazy seed), L4 (DIV-040), L7 (the `OsSource` test no longer assumes a full 512-byte read, which a signal can cut short).

Recorded for later:

- **M1 → DIV-041 (PROPOSED):** a thread past the state check while another latches ERROR still gets output, as in C. Checking again under the lock closes it.
- **M2:** no test catches the C ABI failing to call `fhsm_state_latch_error`; the goldens model the latch from `latch_reason`. It needs a hybrid probe that injects a failure.
- **L5:** untested: CRNGT across a 64 KiB chunk boundary in one request (correct, since 65536 is a multiple of 16), an APT window spanning two requests, and the `CLOCK_BOOTTIME` choice itself.
- **L6:** `libc::getrandom` needs glibc 2.25 or later; C used `syscall(SYS_getrandom)`.
- **Nit:** `Error::Halted` is produced only by the C ABI and the replay.

### Follow-ups for slice 3 (crypto core)

- `fhsm_rng_bytes` and `fhsm_rng_reseed` (`src/fhsm_crypto.c:326-345`) move with slice 3 and call `drbg` directly.
- The probe's equal draws (RSA-2048 = RSA-4096 = P-256) show key generation uses OpenSSL's RAND, not this DRBG (`tests/probe_keygen_drbg.c`). Slice 3 owns `EVP_PKEY_Q_keygen(NULL, ...)`; closing that gap would change the probe's numbers and needs a DIV.
