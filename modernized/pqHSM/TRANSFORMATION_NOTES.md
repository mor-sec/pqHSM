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
2. **Replay:** `crypto/tests/drbg_golden.rs` drives `Drbg` with a scripted source that mirrors the C seams byte for byte. All 127 rows pass; 19 of them are Rust-only rows for DIV-032, DIV-033, DIV-037, DIV-042 and DIV-044. Their expected sums are taken from the C rows (`gen=` for output C cleansed and Rust keeps, the zero-buffer sums for the reverse), not from the Rust code. Only `cond_fail_periodic_mid`'s `gen` has no C counterpart, and that one field is not compared.
3. **Unit tests:** APT 18 passes and 19 fails (DIV-032); the cutoff formula reproduces SP 800-90B Table 2 (W = 512, α = 2^-20: 13, 62, 177, 311) and 19 at α = 2^-40; CRNGT on every block and never under 16 bytes (DIV-037); `OsSource` seeds from getrandom (the C's `src=1`), each source fills only what is left, SHA2-384 against its test vector.
4. **Hybrid harness** (2026-11-02):
   - 106/106; `nm -D` (63 symbols) and NEEDED identical.
   - DRBG swap: the C object has no code; `fhsm_drbg_bytes` in the module is Rust's.
   - Every earlier swap is unchanged. Audit corpus 64 same / 4 explained; token files: only the known DER-length size variance (one to two files a run); TSan 0 races; secure-heap test and probe identical on both builds.
   - New step 4c runs `tests/probe_keygen_drbg`, which has no Makefile rule, on C and hybrid. The token is provisioned first with `tools/fhsm-token init` (PINs invented for the harness), because the probe opens a session before `C_InitToken`. Both builds draw 96 / 96 / 96 bytes for RSA-2048, RSA-4096 and P-256, the legacy probe's own recorded figures; the output is identical.
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
- **DIV-041:** `fhsm_drbg_bytes` checks the module state again once it holds the DRBG lock, so no output follows another thread's latch (review M1).
- **DIV-042:** a generator failure cleanses the request's output (golden `rand_fail_mid`).
- **DIV-043:** each entropy source has a share of the pool (256/128/120/8 bytes); in C getrandom filled it all. The goldens' scripted source still reports C's `src=1`; `OsSource`'s own test pins the new mask.
- **DIV-044:** a failed first seed inside a request latches ERROR, as a failed reseed does (golden `lazy_fail`).
- Kept as C, and pinned by a golden: `fhsm_drbg_reseed` works in ERROR (`error_state`).

### Not migrated

RDRAND off x86_64 (C also took it on i386); the hybrid builds x86_64 only. A `shortcut:` comment marks it in `ffi/entropy.rs`.

### Architecture review (Step 5)

No HIGH findings. Applied: M1 (DIV-041, user: "Fix: re-check under lock"), M3 (golden scenario `lazy_fail`), L4 (DIV-040), L7 (the `OsSource` test no longer assumes a full 512-byte read, which a signal can cut short).

Recorded for later:

- **M2:** no test catches the C ABI failing to call `fhsm_state_latch_error`; the goldens model the latch from `latch_reason`. It needs a hybrid probe that injects a failure.
- **L5:** untested: CRNGT across a 64 KiB chunk boundary in one request (correct, since 65536 is a multiple of 16), an APT window spanning two requests, and the `CLOCK_BOOTTIME` choice itself.
- **L6:** `libc::getrandom` needs glibc 2.25 or later; C used `syscall(SYS_getrandom)`.
- **Nit:** `Error::Halted` is produced only by the C ABI and the replay.

### Follow-ups for slice 3 (crypto core)

- `fhsm_rng_bytes` and `fhsm_rng_reseed` (`src/fhsm_crypto.c:326-345`) move with slice 3 and call `drbg` directly.
- The probe's equal draws (RSA-2048 = RSA-4096 = P-256) show key generation uses OpenSSL's RAND, not this DRBG (`tests/probe_keygen_drbg.c`). Slice 3 owns `EVP_PKEY_Q_keygen(NULL, ...)`; closing that gap would change the probe's numbers and needs a DIV.

## Slice 3: crypto core

### What was replaced

`src/fhsm_crypto.c` (608 lines, 13 exports) is now:

- `crypto/src/lifecycle.rs`: init and finalize as pure logic over a `Platform`.
- `crypto/src/ffi/prim.rs`: digests, HMAC, AES-GCM and PBKDF2 over OpenSSL, with C's explicit fetches and C's argument checks in C's order.
- The crypto core section of `crypto/src/ffi/c_abi.rs`: the 13 exports, the real `Platform`, and the module's one `Core`.

`hybrid.mk` empties `fhsm_crypto.o` and builds the staticlib with `dev-bypass` (DIV-034).

Still C, called over FFI:
- Until slice 4: the integrity check (`fhsm_integrity_verify`) and the KATs (`fhsm_kat_run_all`).
- Until Phase 4: the module state.

`fhsm_rng_bytes` is `fhsm_drbg_bytes`. The DRBG's SHA2-384 conditioner now uses `prim::digest`.

The token crate's seam (`token/src/ffi/cprim.rs`) still declares the `fhsm_*` primitives as externs. In the hybrid those symbols now resolve to the Rust exports in the same staticlib, so the token reaches Rust crypto without a code change. Collapsing `cprim.rs` and `libcrypto.rs` onto `pqhsm_crypto::prim` is a follow-up (see below).

### How equivalence was proved

Equivalence is dual-execution: the legacy C was run in the pinned image.

1. **Goldens from the C.** `tests-support/golden/gen_core.c` (run by `regen_crypto.sh`) links `fhsm_crypto.o` with these seams:
   - The integrity check, the KATs, the DRBG and the module state are stubbed.
   - `--wrap` seams cover `OSSL_PROVIDER_load`/`unload`, `EVP_default_properties_enable_fips`, `RAND_status` and `RAND_add`. They record every call and fail on demand.

   It writes 162 rows over 19 scenarios, each in its own process, with each scenario's stderr kept:
   - Every branch of the init: the integrity, FIPS, base, property, DRBG and KAT failures; the dev mode with the default provider loaded or failing; the KAT bypass with and without the integrity bypass; finalize and re-init.
   - The RNG wrappers.
   - Every primitive, for each hash id 0 to 13. This includes NULL and short buffers, every GCM tamper (tag, AAD, ciphertext), the HMAC length query with a NULL `mac`, PBKDF2's iteration floor and length bounds, an 8-byte salt, and the ERROR state.
2. **Replay.** `crypto/tests/core_golden.rs` replays the rows in two ways:
   - The lifecycle scenarios run through `Core` on a platform scripted as the C seams are, comparing the call trace, the latch reason and stderr byte for byte.
   - The primitives run through the C ABI on OpenSSL's default provider.

   157 rows pass:
   - 2 are Rust-only, for DIV-035: init after finalize runs again.
   - Trace normalisation: C's `unload(NULL)` calls are dropped from its traces, because Rust holds no NULL handle to unload.
   - 5 RNG rows are not replayed. `fhsm_rng_bytes` is `fhsm_drbg_bytes`, whose own goldens are `drbg.tsv`, and a `RAND_status` failure cannot be injected into the real libcrypto.
3. **Unit tests.**
   - DIV-034: a build without `dev-bypass` ignores both variables, says so once, and latches ERROR on a failed KAT.
   - DIV-035: finalize forgets the result and the KAT records; after a fork child's `forget`, the self-tests run on the providers already loaded, with no second load.
   - In place: digest, HMAC, GCM encrypt and decrypt with one buffer as input and output give what two buffers give, and a refused call leaves the output untouched (review H1, L1).
4. **Fork test.** `crypto/tests/core_fork.rs` covers three cases:
   - A child forked while a parent thread holds the init runs its own init instead of hanging (slice 2 review M1's class of bug).
   - A child forked after the init runs the self-tests again (DIV-035).
   - A child forked while a parent thread holds the DRBG lock seeds the DRBG instead of hanging (slice 3 review M1).

   Mutation checks showed the tests detect the bugs: without the fork handler the first two cases fail; without the DRBG's reset the third does; with the output zeroed before the call, the in-place test does.
5. **Workspace:** 856 pass. fmt and clippy are clean with and without `ffi,dev-bypass`.
6. **Hybrid harness** (2026-11-02, after the review fixes):
   - 106/106; `nm -D` (63 symbols) and NEEDED identical.
   - Core swap: the C object defines only `fhsm_kat_results`, from `crypto/shim/kat_results.c`. The first run, before the shim, lost that export: it is the module's one non-PKCS#11 symbol, and `--exclude-libs,ALL` hides everything from the staticlib.
   - Every earlier swap is unchanged. Audit corpus 64 same / 4 explained; token files: only the known DER-length size variance; DIV-009's fork log intact on the hybrid; TSan 0 races.
   - New step 9, the FIPS provider (PHASE3_PLAN.md §4.3), installed offline from the cached `.deb`s. On both profiles the module is built and signed, `scripts/run_fips_tests.sh` passes with its 99 OK lines identical to `BASELINE.md` § FIPS (93/93 tests), and the signed KAT report (62/62), the operation probe (155 / 92 and 167 / 99) and the curve refusal are byte for byte the baseline's, timings aside. This is the first proof that the Rust provider loading gives the FIPS configuration C gave.
7. **Wycheproof** (PHASE3_PLAN.md §5.2), recorded at the start of slice 4 because it was missed here: the C baseline (`BASELINE.md` § Wycheproof, 0 violations over 10 adapters) and this slice's hybrid module print the same summary, every adapter's match, violation and skip counts equal. From slice 4 the harness runs it (step 10).

### Mapping: legacy → Rust

| Behaviour | Legacy | Rust |
|---|---|---|
| Init-once, cached result | `fhsm_crypto.c:53-54`, `:282-285` | `lifecycle.rs:69` `init`; lock `ffi/sys.rs:42` `ForkMutex`; `ffi/c_abi.rs:321` `CORE` |
| Integrity first, bypass | `fhsm_crypto.c:66-78` | `lifecycle.rs:118` `run`, `:97` `honoured` (DIV-034) |
| FIPS, base providers, FIPS default property, their failures and messages | `fhsm_crypto.c:94-185` | `lifecycle.rs:118` `run`, `:110` `fail` |
| Dev mode: default provider, the issue-#6 NOTE | `fhsm_crypto.c:186-227` | `lifecycle.rs:118` `run` |
| DRBG init, KATs, the KAT bypass | `fhsm_crypto.c:229-280` | `lifecycle.rs:118` `run`; `ffi/c_abi.rs:242` `OsPlatform` |
| Finalize | `fhsm_crypto.c:287-293` | `lifecycle.rs:80` `finalize` (DIV-035) |
| `fhsm_fips_mode`, `fhsm_kat_results` | `fhsm_crypto.c:295-306` | `ffi/c_abi.rs:394`, `:400` |
| `fhsm_rng_bytes`, `fhsm_rng_reseed` | `fhsm_crypto.c:325-344` | `ffi/c_abi.rs:412`, `:419` |
| Hash table, size, name | `fhsm_crypto.c:348-376` | `ffi/prim.rs:58` `HASHES`, `:82`, `:87` |
| AES-GCM encrypt, decrypt (tag mismatch cleanses the whole buffer) | `fhsm_crypto.c:378-475` | `ffi/prim.rs:201`, `:260`; C ABI `ffi/c_abi.rs:508`, `:543` |
| Hash, HMAC | `fhsm_crypto.c:477-548` | `ffi/prim.rs:121`, `:145`; C ABI `ffi/c_abi.rs:444`, `:473` |
| PBKDF2 | `fhsm_crypto.c:550-608` | `ffi/prim.rs:316` `check_pbkdf2`, `:328`; C ABI `ffi/c_abi.rs:585` |
| Return codes | `include/fhsm_common.h:150-214` | `lib.rs:14` `rv` |

### Deliberate deviations

- **DIV-034 (crypto core part):**
  - `FHSM_INTEGRITY_ALLOW_UNSIGNED` and `FHSM_KAT_ALLOW_FAIL` are honoured only by a `dev-bypass` build. A release build says once that it ignored them.
  - The hybrid builds with `dev-bypass`, so the harness shows no difference.
  - The integrity check's own bypass, and the release-build latch test, come with slice 4.
- **DIV-035:**
  - Finalize forgets the result, so the next init reloads the providers and re-runs the integrity check, the DRBG init and the KATs.
  - A fork child does the same at its first init, through the core's `pthread_atfork` child handler. The integrity check inside is still C's, cached per process until slice 4.
- **Output buffers (not a divergence on success):** OpenSSL writes into a buffer of the core's own, copied to the caller's on success and wiped either way. Callers pass one buffer for input and output (`C_Digest`, `C_Sign` over HMAC), which a Rust view of the output would alias (review H1). A call that fails leaves the caller's buffer as it was, where C could have left part of a result; GCM's tag mismatch still cleanses the whole buffer.
- **DIV-045 (recorded, mine):** a NULL pointer with a length, and HMAC's NULL `mac_len`, are `ARGUMENTS_BAD`. In C these crashed, failed inside OpenSSL, or, for a NULL GCM `ciphertext`, returned OK having treated the plaintext as AAD.
- **Kept as C:**
  - The HMAC length query with a NULL `mac`.
  - Failed inits are cached until finalize.
  - In dev mode, a DRBG or KAT failure leaves the default provider loaded until finalize.
  - `fhsm_kat_results` returns a pointer into module storage that is read without the lock.
- **Fork children (DIV-035, review M1, M2):** the DRBG's lock is reset in the child as the core's is, and a child forked by the thread holding either lock (fork+exec inside it) leaves that lock to the thread. The child's init uses the providers it inherited; it does not reload them.

### Representative behaviour, side by side

AES-GCM decrypt, `src/fhsm_crypto.c:425-473` against `crypto/src/ffi/c_abi.rs:560-602`:

```
delta --side-by-side <(sed -n 425,473p src/fhsm_crypto.c) <(sed -n 560,602p modernized/pqHSM/crypto/src/ffi/c_abi.rs)
```

- **Checks, same order:** ERROR state → `FUNCTION_FAILED`; key length not 16/24/32 → `KEY_SIZE_RANGE`; IV not 12 → `ARGUMENTS_BAD`; NULL `plaintext_len` or `tag` → `ARGUMENTS_BAD`; capacity under the ciphertext length → `ARGUMENTS_BAD`. Rust adds only DIV-045's NULL-with-length refusals, after these.
- **The cipher work:** C's `EVP_aes_*_gcm` getters, AAD update, ciphertext update, `SET_TAG`, final are in `prim::gcm_decrypt`, in the same calls.
- **Tag mismatch:** C zeroizes `*plaintext_len` bytes of the caller's buffer (§7.10.4) and returns `ENCRYPTED_DATA_INVALID`; Rust wipes its own buffer, then zeroes the same `cap` bytes of the caller's. The golden `prims` rows `gcm_dec:…:tag|aad|ct:8` (a 5-byte ciphertext, capacity 8) pin all 8 bytes zero.

### Architecture review (Step 5)

One HIGH, applied:

- **H1:** zeroing the caller's output before the call destroyed the input whenever one buffer was both, so an in-place `C_Digest` hashed zeros and returned OK, and the aliasing views were undefined behaviour. Now OpenSSL writes into a local buffer (see Deliberate deviations); test `in_place_buffers_give_what_separate_ones_do`.

Also applied:

- **M1:** a fork child's init could hang on the DRBG lock, which a parent thread held at the fork. The DRBG now uses the core's `ForkMutex` and the same child handler; third `core_fork` case.
- **M2:** a fork child's init loaded the providers again over the handles it inherited, leaking them. It now reuses them. DIV-035 says what a child does and does not re-run.
- **L1:** a refused call leaves the output untouched (follows from H1).
- **L2:** `ForkMutex` records its holder. A re-entrant call aborts with a message instead of deadlocking silently, and a child forked by the holder leaves the lock alone.
- **L3:** the DRBG exports latch ERROR after releasing the DRBG lock, since a latch reaches the audit log, which can draw from the DRBG.
- **Nit:** a NULL KAT string prints "(null)", as C's printf did.

Recorded for later:

- `gen_core.c` has no seam for a failing fetch, so the MECHANISM_INVALID and HOST_MEMORY paths are replayed only by the unit tests, not against C goldens, and the primitives only on the default provider (the FIPS step in the harness runs them on the FIPS provider through the module).
- Nits not applied: `prim` repeats checks the ABI layer has made; the `(|| {...})()` closures could be named helpers.

### Not migrated

Nothing in `fhsm_crypto.c`. The comment block at `:307-321` describes a CRNGT that now lives in the DRBG (slice 2).

### Follow-ups

- **Token seam:** collapse `token/src/ffi/cprim.rs` and `token/src/ffi/libcrypto.rs` (about 120 lines, which duplicate PBKDF2 and GCM with different error mapping) onto `pqhsm_crypto::prim`. The ERROR-state check this needs in Rust arrives with the module state in Phase 4.
- **Slice 4:**
  - The integrity check and the KATs move to Rust behind `Platform::integrity` and `Platform::kats`.
  - DIV-034's release-build test.
  - Integrity re-runs after finalize, which makes DIV-035 complete.
- **Phase 4:** key generation uses `EVP_PKEY_Q_keygen(NULL, ...)` in `fhsm_pkcs11.c:6646-6657`, so it draws from OpenSSL's RAND rather than the DRBG (slice 2's probe). This was listed as slice 3 work, but the code is in `fhsm_pkcs11.c`.

## Slice 4: self-tests

### What was replaced

3,055 legacy lines in four files are now the `pqhsm-selftest` crate:

- `src/fhsm_integrity.c` (425 lines) → `selftest/src/integrity.rs` (the check over a file's bytes: the `.fhsm_digest` section, the digest, the bypass and messages) and the integrity section of `selftest/src/ffi/c_abi.rs` (finding the module through `dl_iterate_phdr`, C's statics, the five exports). The 48-byte digest array stays a C definition, `selftest/shim/integrity_digest.c`, because `scripts/sign_module.sh` patches it in the built file.
- `kat/fhsm_kat_vectors.c` (379) → `selftest/src/kat/mod.rs` (`run_all`: the smoke KATs through the crypto core's primitives, the CAVP file, the DRBG stuck check), `selftest/src/kat/cavp.rs` (the `.rsp` reader, as glibc's `fgets`, `atoi` and `%2x` read it) and `selftest/src/kat/vectors.rs` (every vector table, generated byte for byte from the C arrays).
- `kat/cavp_extended.c` (1,997) → `selftest/src/ffi/evp.rs`: the 47 extended KATs over OpenSSL, in C's order with C's names.
- `src/fhsm_pairwise.c` (254) → `selftest/src/ffi/pairwise.rs` and `fhsm_pairwise_check` in `c_abi.rs`.

The crypto core's init now calls `pqhsm_integrity_run` (re-runs each init, DIV-035) and the Rust `fhsm_kat_run_all`. `hybrid.mk` empties `fhsm_integrity.o`, both `kat/*.o` and `fhsm_pairwise.o`. `C_GenerateKeyPair` (`fhsm_pkcs11.c:6769`, Phase 4) calls the Rust pair-wise check through the unchanged C ABI.

### How equivalence was proved

Dual execution: the legacy C was run in the pinned image (`tests-support/golden/regen_selftest.sh`).

1. **Integrity.** `make_integrity_elf.py` lays out ELF64 files, each breaking one bound the C checks; `gen_integrity.c` runs the legacy check on each in its own process (`--wrap` seams on `dl_iterate_phdr` and `EVP_MD_fetch`). `tests/integrity_golden.rs` replays the 76 rows and each scenario's stderr byte for byte through `integrity::verify`; `tests/integrity_abi.rs` runs the C ABI, including DIV-034's latch.
2. **KAT vectors.** `gen_kat vectors` dumps every C array (85 rows); `kat_golden.rs` checks each Rust table against it byte for byte, the repeated rows included.
3. **KAT runs.** `gen_kat runs` links the legacy KAT sources with recording stubs of the crypto primitives and plays 131 scenarios: each primitive failing, returning a flipped byte, accepting a bad tag or a fixed value at each call, every CAVP file shape (`make_kat_rsp.py`, 20 files: the installed path, empty, CRLF, no final newline, lines split past 2,047 bytes, signed, spaced and `0x` hex, odd and negative `Len`, records out of order, repeated or incomplete, more vectors than the report holds), the report full at every size, concurrent runs and the NULL arguments (2,146 rows). `kat_golden.rs` replays each through a fake with the same faults and compares the report and the whole call trace, every argument and capacity. DIV-046 changes nine scenarios' return code and nothing else; DIV-047 adds one Rust-only case.
4. **Pair-wise.** `gen_pairwise.c` runs the legacy check on 15 key types, each under ten family selectors (−1 to 8), its mismatched pair (another key's public half through `EVP_PKEY_fromdata`) under the same ten, and the NULL key: 247 rows, replayed by `tests/pairwise_golden.rs`.
5. **Mutation checks** (on a copy, against the goldens):
   - CAVP reader: every mutant killed. Two branches that could not be killed were equivalent to C (a header-line skip, a `0x` prefix) and were deleted; a duplicated line bound became one bound and a unit test.
   - Pair-wise: killed for the dispatch, EdDSA, the ECM recompute and the KEM compare. The KEM compare was first missed, so the mismatched pairs were extended to every family (a mismatched EC key reaches it through OpenSSL's DHKEM). Survivors: `== 1` against `> 0` for the verify calls (OpenSSL returns 1 or ≤ 0, equivalent), and RSA's plaintext compare, which a mismatched key never reaches because PKCS#1 v1.5 decryption fails first.
   - KATs: the PSS salt length survives on both sides (OpenSSL verifies with the length it was given).
6. **Workspace:** 869 pass; fmt and clippy clean, with and without `ffi`.
7. **Hybrid harness** (2026-11-03, after the review fixes):
   - 106/106; `nm -D` (63 symbols) and NEEDED identical.
   - New swap checks: the integrity object defines only `fhsm_module_integrity_digest`; both KAT objects and the pair-wise object define nothing, and the module's `fhsm_pairwise_check` is Rust's. Every earlier swap is unchanged.
   - `make test-integrity` output the same as C's (its filter was fixed: it had kept the compiler's command lines).
   - FIPS, both profiles: `run_fips_tests.sh` 99 OK lines identical, and the signed module's 62-KAT report, the operation probe and the curve refusal byte for byte the baseline's, timings aside. This is the first run with the Rust KATs on the FIPS provider.
   - Wycheproof: 0 violations, hybrid equal to C. TSan 0 races; audit corpus 64 same / 4 explained; token files: only the known DER-length size variance (`slot0.tok`, 2 bytes).

### Mapping: legacy → Rust

| Behaviour | Legacy | Rust |
|---|---|---|
| Find the module's own file | `fhsm_integrity.c:104-222` | `ffi/c_abi.rs:75` `locate` |
| Section lookup, bounds, digest, compare, bypass, messages | `fhsm_integrity.c:223-378` | `integrity.rs:50` `find_section`, `:106` `verify`, `:143` `check` |
| Once per process; the getters | `fhsm_integrity.c:379-425` | `ffi/c_abi.rs:150` `fhsm_integrity_verify`, `:163` `pqhsm_integrity_run` (DIV-035), `:172-183` |
| Smoke KATs, early returns | `fhsm_kat_vectors.c:161-284` | `kat/mod.rs:140` `run_all`, `:153` `smoke` |
| CAVP file | `fhsm_kat_vectors.c:286-349` | `kat/cavp.rs:23` `Reader`, `:118` `atoi`, `:140` `hex2`; DIV-047 |
| DRBG stuck check | `fhsm_kat_vectors.c:350-363` | `kat/mod.rs` `smoke` |
| Report, identifier pool | `fhsm_kat_vectors.c:151-158` | `ffi/c_abi.rs:336` `VIDS`, `:344` `report`, `:380` `fhsm_kat_run_all` |
| Extended KATs | `cavp_extended.c:1610-1997` | `ffi/evp.rs:158` `extended`; `ffi/c_abi.rs:417` |
| Pair-wise dispatch and checks | `fhsm_pairwise.c:65-254` | `ffi/pairwise.rs:47` `check`, `:71-207` |

### Deliberate deviations

- **DIV-034 (done):** the integrity bypass is honoured only by a `dev-bypass` build.
- **DIV-035 (done):** the integrity check re-runs with every init; `fhsm_integrity_verify` called on its own keeps C's cache.
- **DIV-046 (done):** a failed KAT record fails the init.
- **DIV-047 (done; decided Fix 2026-11-03, user: "Keep the fix"):** a CAVP `Len` past the 256-byte buffer, or negative, is a failed vector, where C read past its stack buffer.
- **Kept as C:** the CAVP identifiers live in a 64-slot pool rewritten by the next run; the extended set generates its RSA and PQ keys before checking for room; a missing CAVP file is no failure; `fhsm_kat_cavp_extended` advances the caller's cursor only on OK.

### Architecture review (Step 5)

No HIGH. Applied:

- **M1:** the CAVP identifier pool's lock had no fork-child reset, so a child forked while a parent thread was writing the report would hang at its own init's KATs (DIV-035), the class of slice 3's M1. The child handler now resets it, and the report registers the handler.
- **M2:** the integrity messages went through `eprint!`, which panics (an abort, inside `C_Initialize`) if stderr cannot be written. Now a write whose error is ignored, as the audit crate does.
- **M3:** nothing showed an extended KAT could fail; the C goldens cannot inject faults into direct OpenSSL calls. Unit tests in `ffi/evp.rs` now refuse a flipped expected value for every comparison and a key of the wrong type for every round trip.
- **L1:** the harness checks the pair-wise swap.
- **L3:** a re-run whose `locate` failed read the previous run's path; now it has no path, as C's first run would.
- **N3:** a NULL program-header pointer gives an empty table instead of an undefined slice.

Recorded for later:

- **M1's test:** there is no fork test for the pool's reset; holding that lock from a thread at the fork needs a seam the crate does not have. The fix is the slice 3 pattern line for line.
- **L2:** a signed module loaded with `dlopen` and checked without the bypass runs only in the FIPS step, skipped when the `.deb`s are absent. A default-harness step (sign a copy, expect OK, flip a byte, expect INTEGRITY_FAILED, compare with C) would cover it.
- **N1:** the getters return pointers into storage a DIV-035 re-run rewrites; C wrote it once per process. The strings stay NUL-terminated.
- **N2:** checked: the workspace run includes `integrity_abi` and `kat_abi` through feature unification; `cargo test -p pqhsm-selftest` alone skips them.

### Not migrated

Nothing. The comment at `cavp_extended.c:37` saying a mismatch latches ERROR was false in C; DIV-046 makes it true.

### Follow-ups

- The token crate's crypto seam consolidation (slice 3 follow-up) is still open.
- **Slice 5 (PKI):** Wycheproof is re-run after it, as the plan says.

## Slice 5: PKI encoders

### What was replaced

`src/fhsm_composite.c` (2,917 lines) is now in the `pqhsm-pki` crate, ported in four parts (5a-5d) and swapped in once at the end:

- **5a** (`:1-481`, composite ML-DSA-65 + Ed25519 parameters, M', keys, sign, verify): `pki/src/composite.rs` (blob layout, pure) and `pki/src/ffi/composite.rs` (OpenSSL).
- **5b** (`:482-1450`, raw and SPKI key forms, PKCS#10, self-signed roots, issuance): `pki/src/ffi/x509.rs` `csr`, `selfsigned`, `issue`. The extension values (SAN, CRL distribution points, key identifiers) are DER-encoded in safe Rust in `pki/src/x509.rs`. OpenSSL still assembles names, validity and the SPKI slot.
- **5c** (`:1451-2128`, CRL, OCSP; and `fhsm_pki_algid`, `:2678`): `x509.rs` `crl_tbs`, `ocsp_single`, `ocsp_tbs` and `ffi/x509.rs` `crl`, `ocsp`. The OCSP responder (`pki/src/revocation.rs`, Phase 2) now calls the Rust encoder; its two C-encoder test doubles are gone.
- **5d** (`:2129-2917`, ECDSA raw-to-DER, CMS encode and verify): `x509.rs` `ecdsa_sig`, `cms_signerinfo`, `cms_wrap`, `cms_signed_attrs`, and the DER reader `tlv_at` / `cms_signed_attrs_of`; `ffi/x509.rs` `cms`, `cms_digest`, `composite_cms_verify`, `pki_cms_verify`.

All 38 symbols the C object defined are exported from `pki/src/ffi/c_abi.rs` with C's signatures. `hybrid.mk` empties `fhsm_composite.o`, so the module, the five PKI tools and the `test_pkiops*` links take the staticlib's code.

### How equivalence was proved

Dual execution: the legacy C was run in the pinned image (`tests-support/golden/regen_composite.sh`).

1. **Goldens.** `gen_composite.c` (140 rows) and `gen_x509.c` (571 rows) drive every C entry point, including NULL and empty arguments, each `der_len` ceiling on both sides (a cap of 1 reports the size without a 16 MiB buffer), every signer kind and every buffer size boundary. A deterministic stand-in signer and a `time()` defined in both the generator and the test pin every byte. `composite_golden.rs` and `x509_golden.rs` replay the rows in order. For CMS verification, the generator verifies 61 structures: 29 real signatures and their tampered copies, and 32 assembled by hand: wrong digest or signature, attributes out of order or missing, two signers, two certificates, PSS parameters, an unknown algorithm, a SignerIdentifier naming another certificate. Each structure and its digest are fixtures, so all three readers answer as C did on inputs C never produced itself.
2. **The OCSP responder:** `revocation_ffi.rs` replays all 56 non-synth answer rows through the Rust encoder (clock pinned, C's signatures handed back). Each response is C's bytes.
3. **Mutation checks** (on a copy, against the goldens): 5a 13 with 12 killed, 5b 25/24, 5c 31/30, 5d 39/38. The survivors: the digest-failure path (unreachable without fault injection); one equivalent mutant in 5b; the nextUpdate time failure (unreachable with an `int` days); and `fhsm_composite_cms`'s digest-length check, which repeats the one `fhsm_pki_cms` makes for SHA-512. Three 5d survivors of the first round (`tlv_at`'s four-octet limit, the last-element tag) were killed by unit tests in `x509.rs`.
4. **Fuzzing** (PHASE3_PLAN.md §4.6): `pki/fuzz/`, two targets (`pki/tests/README.md`). Before the review: 5 minutes each, 31.5 M and 1.39 M runs, no crash. With the review's selectors (M3) the SPKI selector found a 26-byte leak C shares (a tag-0 parameter, see Deliberate deviations); after its fix, 5 minutes each: 29.7 M and 1.52 M runs, no crash, no leak. There is no PEM parser in `src/fhsm_composite.c`, so the plan's "PEM" has nothing to fuzz.
5. **Workspace:** 873 pass; fmt and the three clippy runs clean.
6. **Hybrid harness** (2026-11-03):
   - 106/106; `nm -D` (63 symbols) and NEEDED identical.
   - The composite swap: `fhsm_composite.o` defines nothing, the module's `fhsm_composite_sign` and `fhsm-ca`'s `fhsm_pki_issue` are Rust's. Every earlier swap is unchanged.
   - New PKI step (§4.3, `tests-support/hybrid/pki_artifacts.c`): a root, a request, a leaf, a CRL, an OCSP response (and its BasicOCSPResponse) and a CMS for Ed25519, P-256 (RFC 6979 nonces) and RSA PKCS#1 v1.5 keys made in the container, through the C object and the staticlib. First run: 18 files, 0 differ; `openssl req -verify`, `verify`, `crl`, `ocsp` and `cms -verify` all OK on both. After the review fixes (M2): 21 files (the BasicOCSPResponses added), 0 differ; the tampered Ed25519 set is refused for every signed part, as expected.
   - Wycheproof re-run (the plan's "after slice 5"): 0 violations, hybrid equal to C. FIPS, both profiles: 99 OK lines, the KAT report, the probe and the curve refusal identical. TSan 0 races; audit corpus 64 same / 4 explained (the same four commands as slice 4; `test_cbc_pad_oracle`'s timing-dependent log was order-only in the second run, DIFF in the first); token files: only the known 2-byte DER-length variance.

### Mapping: legacy → Rust

| Behaviour | Legacy | Rust |
|---|---|---|
| Parameters, M', blob layout | `fhsm_composite.c:60-238` | `composite.rs:46` `params`, `:65` `layout`, `:83` `pack`; `c_abi.rs:744` `fhsm_composite_mprime*` |
| Keygen, split, sign, verify | `:239-522` | `ffi/composite.rs:144` `keygen`, `:158` `ph`, `:311` `verify_mprime`; `c_abi.rs:867`, `:926`, `:1047` |
| Raw and SPKI key forms | `:523-728`, `:1007-1102` | `ffi/x509.rs:521` `raw_pub`, `:544` `pub_from_raw`, `pub_from_slot`, `spki_into_slot`; `x509.rs:76` `composite_spki` |
| PKCS#10, self-signed | `:729-1006` | `ffi/x509.rs:436` `csr`, `:485` `selfsigned` |
| Issuance (PoP, profile, SAN, CRL DP, serial) | `:1105-1470` | `ffi/x509.rs:682` `issue`; `x509.rs:119` `san`, `:185` `crl_dp`, `:81` `ski`, `:86` `akid` |
| CRL | `:1471-1827` | `x509.rs:226` `crl_tbs`, `:258` `crl_extensions`; `ffi/x509.rs:881` `crl` |
| OCSP | `:1828-2150` | `x509.rs:284` `ocsp_single`, `:320` `ocsp_tbs`; `ffi/x509.rs:965` `ocsp` |
| `fhsm_pki_algid` | `:2678-2697` | `x509.rs:17` `pki_algid` |
| CMS SignerInfo, ContentInfo, signed attributes | `:2151-2531` | `x509.rs:403` `cms_signerinfo`, `:432` `cms_wrap`, `:457` `cms_signed_attrs`; `ffi/x509.rs:1049` `cms` |
| CMS readers | `:2532-2677`, `:2759-2917` | `x509.rs:469` `tlv_at`, `:497` `cms_signed_attrs_of`; `ffi/x509.rs:1151` `cms_digest`, `:1201` `composite_cms_verify`, `:1339` `pki_cms_verify` |
| ECDSA r ‖ s to DER | `:2698-2758` | `x509.rs:517` `ecdsa_sig`; `c_abi.rs:2242` |

### Representative behaviour, side by side

`fhsm_pki_ecdsa_raw_to_der` (`src/fhsm_composite.c:2698-2725`) against `ecdsa_sig` (`pki/src/x509.rs:515-529`): C builds two BIGNUMs and an `ECDSA_SIG` to have OpenSSL write two minimal INTEGERs; Rust strips leading zeros and prefixes one where the top bit is set. The argument checks and the out/out_len contract stay in `c_abi.rs:2242`, as C's.

```
fhsm_rv_t fhsm_pki_ecdsa_raw_to_der(const uint8_t *rs, ...)   |  pub fn ecdsa_sig(rs: &[u8]) -> Vec<u8> {
    BIGNUM *r = BN_bin2bn(rs, (int)h, NULL);                  |      let int = |b: &[u8]| {
    BIGNUM *s = BN_bin2bn(rs + h, (int)h, NULL);              |          let b = &b[b.iter().take_while(|&&x| x == 0).count()..];
    if (ECDSA_SIG_set0(sig, r, s) != 1) goto out;             |          match b.first() {
    int n = i2d_ECDSA_SIG(sig, NULL);                         |              None => tlv(0x02, &[&[0]]),
    if (*out_len < (size_t)n) { ... BUFFER_TOO_SMALL; }       |              Some(x) if x & 0x80 != 0 => tlv(0x02, &[&[0], b]),
    if (i2d_ECDSA_SIG(sig, &p) != n) goto out;                |              Some(_) => tlv(0x02, &[b]),
                                                              |      ...
                                                              |      tlv(0x30, &[&int(r), &int(s)])
```

### Deliberate deviations

- **DIV-048 (done; decided Fix 2026-11-03, user: "keep refusing a signer callback that reports a longer signature than its buffer"):** a signer callback that reports more signature than its room fails with FUNCTION_FAILED; C read past its 8 KiB buffer.
- **DIV-049 (done; review M1, reproduced on C; decided Fix 2026-11-03, user: "keep refusing BOOLEAN key parameters"):** a public key whose AlgorithmIdentifier parameters are a BOOLEAN is ARGUMENTS_BAD; C crashed copying it, also from an issued request's key after proof of possession.
- **Not observable:** C's `static` buffers in the CMS verifier and issuance (`pubblob`, `reqpub`) are locals, so concurrent calls no longer share them. A NULL signature AlgorithmIdentifier is checked before use where C would dereference it (unreachable from a parsed structure). OIDs are compared through 128-byte `OBJ_obj2txt` buffers where C used 64 in one place; every OID in play fits both. A key whose parameters have tag 0 (EOC) leaked their copy (C has the same code; its leak inferred, not measured), because `X509_ALGOR_set0` neither takes nor frees a type-0 parameter; Rust frees it (found by the fuzzer after review M3, 26 bytes per call; the output is unchanged).
- **Kept as C:** both CMS verifiers trust whichever certificate the file carries, and the composite path ignores the SignerIdentifier and the digestAlgorithm (golden rows `assembled/composite_names_other_cert`, `assembled/composite_digalg_sha1`; review H1, below). `fhsm_pki_cms` returns BUFFER_TOO_SMALL without updating `*out_len` when the SignerInfo alone exceeds 16,384 bytes (row `pki_cms:big_issuer`); a caller that grows its buffer to `*out_len` would loop.

### Architecture review (Step 5)

No memory-safety defect, leak or double free found; every return code and byte matched C apart from DIV-048. Applied:

- **H1** (a design property kept from C, not a port defect): "CMS verified" means "signed by the certificate inside the file". C's behaviour is pinned by two new golden rows so a change is deliberate. The fix (return the signer certificate or its fingerprint, print it in `fhsm-sign`, accept a pinned CA, check the SignerIdentifier on the composite path) is a Phase 5 decision; see Follow-ups.
- **M1:** DIV-049.
- **M2:** the harness's tampered OCSP response still verified: its last byte belongs to the embedded responder certificate, which `-VAfile` does not need. The OCSP tamper now flips a byte of producedAt, inside tbsResponseData; the tampered line is compared with the expected one and says UNEXPECTED otherwise; and `fhsm_pki_ocsp`'s own BasicOCSPResponse is written and compared, not only OpenSSL's re-encoding of it.
- **M3:** the fuzz targets could not reach the SPKI copy behind M1 (a mutated request fails proof of possession first). `der_inputs` now also fuzzes the signer's SPKI and AlgorithmIdentifier through `fhsm_pki_csr` and a raw composite public key, and asserts the verifiers answer only OK, SIGNATURE_INVALID or ARGUMENTS_BAD. The README's coverage claim is corrected.
- **M4 (part):** the SignerIdentifier and SHA-1 digestAlgorithm rows above.
- **L1:** `revocation::tlv` wrote a truncated three-octet length past 16 MiB; it now writes the four-octet form OpenSSL writes (reachable only through the Rust API; the C ABI refuses earlier).
- **L2:** `tagged` indexed an empty slice (a panic, so an abort, through the safe Rust API); it now refuses it.
- **L4:** DIV-048 said "stack buffer"; C's is `OPENSSL_malloc`'d.

Recorded for later:

- **M4 (rest):** no golden row for an embedded certificate with a non-composite OID but a 1,984-byte key under the composite verifier, nor for a third-party `openssl cms -sign` structure (three or more signed attributes) through `fhsm_pki_cms_verify`.
- **L3:** two RAII wrappers (`Own<T>` in `ffi/composite.rs`, an untyped `Own` in `ffi/x509.rs`) and two identical `refused()`; about 140 libcrypto prototypes declared as `*mut c_void` where `openssl-sys` has typed ones (each checked against the OpenSSL 3 headers, none wrong); `ffi::x509` calls the exported `c_abi::fhsm_composite_verify` and `fhsm_composite_ph_len` instead of a safe helper; the magic index `pki_algid(3)`.
- **M1's second half:** a composite key's parameters MUST be absent; `pub_from_slot` checks only the OID, as C does. Refusing present parameters refuses inputs C accepts.

### Not migrated

`fhsm_ocsp_answer`'s "no composite AlgorithmIdentifier" branch (slice 5c): unreachable, because `fhsm_pki_algid` never fails for the composite. Its ALGID_FAIL test is removed.

### Follow-ups

- **Phase 5:** CMS signer identity (H1): the verifier should report who signed and the tool print it or check it against a pinned certificate. A DIV and a user decision.
- **Phase 5:** DIV-021/069 clamping (the plan's slice 5 row) is still Phase 5.
- The harness has no gate: its summary is read, not asserted. Step 4e's tampered line now says UNEXPECTED when wrong, like the others say DIFF.
- Still open from earlier slices: the token crate's crypto seam consolidation; slice 4's L2 and N1.

## Phase 3 exit criteria: status

Closed 2026-11-03 (user: "Close Phase 3 (Recommended)"). Final hybrid run `p3x2`, after slice 5's commit (`2e1fedb`) and the two additions below.

| Brief exit criterion | Evidence | Status |
|---|---|---|
| KAT, CAVP and Wycheproof byte for byte, default mode and FIPS provider | The KAT goldens (slice 4) replay in default mode. The FIPS step's KAT report (62 vectors, CAVP and extended set included) is the same as `BASELINE.md` on both profiles. Wycheproof: hybrid = C = baseline in default mode, 0 violations. **New:** Wycheproof again on a C and a hybrid build of each profile, signed, with the provider active: hybrid = C on both, 0 violations. The runner needs `FHSM_EVIDENCE=1` for this; without it, it sets the integrity bypass itself, and the module never loads the provider (the first try, run `p3x1`, measured that by mistake). Without a bypass, init loads the provider and makes it the default for every fetch, or fails (`crypto/src/lifecycle.rs:128-161`, as C). The counts equal default mode's, as `docs/PQC_VEILLE.md` found for C | ✅ |
| Composite, X.509, CSR, CRL, OCSP: `make tests` and the `openssl` CLI | The 17 `test_composite_*`, `test_pki_classic` and `test_pkiops*` tests pass. PKI step: 21 DER files C = hybrid; the CLI verifies all 18 artifacts on both builds; the tampered set is refused | ✅ |
| DRBG health tests pass property tests at their cutoffs | **New:** four `proptest` properties in `crypto/src/drbg.rs`: the RCT fails exactly at a run of 6 wherever it sits; the APT fails exactly at the window's 19th occurrence and counts each 512-sample window afresh; the CRNGT fails exactly on a block equal to the one before. The cutoffs are written out, not the constants under test: a first version that read the constants missed both RCT mutants. 7 of 7 mutants killed (RCT 5 and 7, APT 18 and 20, the window doubled, the CRNGT off, the CRNGT not carried over) | ✅ |
| Self-test bypasses as Q11; integrity against the Rust module | Slice 4: DIV-034, DIV-035, DIV-046; integrity swap and FIPS step | ✅ |
| Secure heap mlocked and zeroed on free | Slice 1, harness step 4b | ✅ |
| Every P0 rule gated at Phase 3 | All 15 are covered. RULE-001, 002: core goldens, the token's vectors, DIV-011, DIV-045. RULE-006: core rows (999 iterations, output 0 and 257, the PRF codes); its PKCS#11 part is Phase 4. RULE-009: integrity goldens. RULE-010 to 013: DRBG goldens, the properties above, DIV-032/033/036/037/042 to 044. RULE-021, 022: x509 rows (days, serials, CRL numbers 0 to 6), byte for byte with the clock pinned; the `fhsm-ca` database parts are Phase 5. RULE-025: composite rows (M′ 127, signature lengths, ctx 256), DIV-048. RULE-069: DIV-049. RULE-073: DIV-041. RULE-074: KAT runs, DIV-034, DIV-046, DIV-047. RULE-076: lifecycle goldens, DIV-035 | ✅ |

Also in `p3x2`: 106/106, `nm -D` (63 symbols) and NEEDED identical, all swaps, TSan 0 races, corpus 64 same / 4 explained, FIPS identical on both profiles. Workspace 877 pass, 0 fail; fmt and clippy `-D warnings` clean in the three feature sets. Token files: 64 of 66 identical. The other two are the pair Phase 2 explained, whose size follows the DER length of freshly generated keys: `test_pkiops_envelope_rsa` at 5,741 bytes, inside the C-only range, and `test_pkiops_algs` at 51,962, one byte under the 51,963–51,966 that three C runs gave. Every field but the size is identical.

**Not done in Phase 3, and why:** the token crate's crypto seam still declares the `fhsm_*` primitives as externs. In the hybrid they resolve to the Rust exports, so the token already runs on Rust crypto. Collapsing the seam into the crate would bypass those exports' check of the module state, which is C until Phase 4. It moves with the state, in Phase 4.

# Phase 4: PKCS#11 API layer (PHASE4_PLAN.md, approved 2026-11-03)

## Slice 0: takeover of the function tables

### What was replaced

`src/fhsm_pkcs11.c:13050-13386`: the v2.40, v3.0 and v3.2 function tables and `C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface`. New crate `pqhsm-p11` (`p11/src/ffi.rs`). The tables are constants; C filled them at run time under `pthread_once`. Every other slot still names the C entry point, which `fhsm_pkcs11.o` still exports.

`hybrid.mk` makes C's three table calls local in `fhsm_pkcs11.o` (`objcopy --localize-symbol`) and links `p11/shim/interface.c` into the same object with `ld -r`. The shim defines the three exports, because `--exclude-libs,ALL` hides every symbol from the staticlib; neither a version script nor `--export-dynamic-symbol` overrides that (checked with GNU ld 2.44).

### How equivalence was proved

- `tests-support/hybrid/p11_tables.c`, harness step 4f: every slot of the three tables by exported symbol name ("unexported" for the not-supported stub), the stub's return code, and the argument checks of the three calls: NULL outputs, interface names, versions 3.2, 3.0, 2.40, 3.1, 3.3 and 0.0, flags, a short buffer, and that a returned record is not rewritten by a later call. C: 292 lines, 84 not-supported slots (0x54), one stub address. Hybrid: identical (run `p4s0b`).
- Mutation: slots 50 and 51 swapped in the Rust table; the probe reports both lines in all three tables.
- `p4s0b`: 106/106, `nm -D` (63 symbols) and NEEDED identical, TSan 0 races in the four tests (`test_concurrency_store --tables` among them), Wycheproof 0 violations hybrid = C, all-mechanisms FIPS identical. Token, fork-log and corpus lines as in `p3x2`.
- **Open:** in the nist-approved-only FIPS run, `test_composite_cms` was filed under "opens the signed .so" instead of "signed copy" (`run_fips_tests.sh` decides by the binary's `.fhsm_digest` section), so the OK lines differ from the baseline; 99 OK and 93 of 93 against the provider either way. Two strict-profile builds of the same tree (parallel, and serial with `make integrity`) give the section in that binary and 28 embedded tests, as the baseline. Not reproduced; the rerun (`p4s0c`) was stopped by the system for low memory before it finished.
- Workspace: 877 pass, 0 fail; the three clippy sets clean.

### Deliberate deviations

The tables are read-only statics; C's were writable. No legacy test, tool or script writes to them (grep of `tests/`, `tools/`).

### Follow-ups

- The first commit of the shim (`294e3d6`) lacks prototypes, and the legacy `-Werror=missing-prototypes` breaks the build; fixed in the working tree (uncommitted).
- The FIPS classification line above.

## Slice 1: lifecycle, sessions and login (the pilot)

Split as slice 5 of Phase 3 was: 1a the session table, 1b the module state, 1c the API lock, then the entry points. Each support file's code moves to `pqhsm-core` (safe) with its C ABI in `pqhsm-p11/src/ffi/`, and `hybrid.mk` empties its object; the C callers in `fhsm_pkcs11.c` and the Rust crates' externs reach the same symbols.

### 1a: the session table (`src/fhsm_session.c`, 267 lines)

`core/src/session.rs`, generic over the token it names (a trait with `login`, `logout`, `role`); `p11/src/ffi/session.rs` instantiates it with the C token pointer and calls `fhsm_token_*`. The PIN passes through as C's pointer and length, so the token still decides what a NULL PIN means. The cap is fixed at 128: no build sets `-DFHSM_MAX_SESSIONS`.

- Golden: `tests-support/golden/gen_session.c` links the legacy file alone against a scripted stub token and records 274 calls, results and token calls (`core/tests/golden/session.tsv`, `regen_session.sh`). It covers handles 0, 128, 129 and `ULONG_MAX` on every call, the lowest-free reuse, the cap, the read-only refusal of an SO login, the last close logging the token out, the post-fork reset, and the two quirks below. Rust replays all 274.
- Mutation: 12 mutants, 12 killed. The first run let one survive (setting the entry's role on `USER_ALREADY_LOGGED_IN`), because the role is visible only once the token is detached; the generator gained that case.
- Quirks kept: an unattached session keeps its own role field, which `role` and `info` show; `logout` on it clears the field and still returns `USER_NOT_LOGGED_IN`.
- Unreachable difference: `fhsm_session_open` with a NULL out pointer returns `ARGUMENTS_BAD`; C wrote through it. `C_OpenSession`, its one caller, refuses NULL first.

### 1b: the module state (`src/fhsm_state.c`, 143 lines)

`core/src/state.rs` (the whitelist, the latch, the fork reset); `p11/src/ffi/state.rs` emits the transition events through `fhsm_audit_event` after the lock is released, as C did.

- Golden: `gen_state.c` links the legacy file alone against a recording `fhsm_audit_event`: every from/to pair of states 0-3 plus 4, 5 and -1, the fork reset from each state, and the latch with NULL (in a forked child, marked by `fork`/`join` rows), a 200-byte reason and an empty one. 186 rows with their events (`core/tests/golden/state.tsv`); Rust replays all.
- Mutation: 10 mutants, 9 killed. The survivor is equivalent: no whitelisted transition starts from ERROR, so the explicit latch check in `set` never changes a result. It stays, because it states the FIPS latch directly.
- Not carried over: `g_error_reason`, a copy of the latch reason that nothing reads.
- Harness `p4s1ab` (1a and 1b swapped): 106/106, `nm -D` (63 symbols) and NEEDED identical, p11 tables identical, TSan 0 races in the four tests, corpus 64 same / 4 explained, token and fork-log lines as in `p3x2`. Wycheproof and FIPS skipped: the `.deb` and vector caches of the earlier runs are gone, and re-fetching them needs the user (Phase 3 approved them "once").

### 1c: the API lock (`src/fhsm_apilock.c`, 178 lines)

`p11/src/ffi/apilock.rs`, all of it: the lock is taken in `fhsm_api_enter` and released in `fhsm_api_leave`, two C calls apart, which no `std` guard spans, so it stays a pthread rwlock (writer-preferring, `PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP`, defined locally because the libc crate has it only for uClibc). Nothing safe is left for `pqhsm-core::apilock`, which the plan named. Kept from C: the per-thread mode (a nested call takes nothing), the drain at each EXCLUSIVE entry and at a SHARED exit that wins `trywrlock`, the fork-child reset (fresh lock and mutex; parked values zeroized, non-secure ones freed), newest-first release, and the leak when the parking list cannot grow.

- No new golden: `tests/test_apilock.c` already drives the API directly (mode nesting, parking, the drain on the last SHARED exit) and runs in `make tests` and under TSan, with `test_concurrency_store --destroy` for the use-after-free it exists to prevent.
- Harness `p4s1c` (1a, 1b and 1c swapped): as `p4s1ab`, with `test_apilock` passing plain and under TSan (0 races, as the other three). Token files: the Phase 2 pair only (`envrsa` 5,740 C / 5,741 Rust-written, `algs` 51,964 / 51,962; C alone gave 51,963 in `p4s1ab`), size only.
- Workspace: 879 pass, 0 fail (877 plus the two goldens), run as the harness does: root without `DAC_OVERRIDE`/`DAC_READ_SEARCH`, with `analysis/` mounted for the DIV-table tests. Clippy `-D warnings` clean for p11 and core in both feature sets and for the module.

### 1d: the entry points (`src/fhsm_pkcs11.c:393-1789`)

Fifteen `C_*` move: `C_Initialize`, `C_Finalize`, `C_GetInfo`, `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_InitToken`, `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`, `C_Login`, `C_Logout`, `C_InitPIN`, `C_SetPIN`, with the slot registry and the fork and finalize teardowns. `p11/src/ffi/lifecycle.rs`, `slots.rs`, `login.rs`; the pure parts (field packing, the label and PIN rules, the session state) in `core/src/p11.rs`. Faithful port: every DIV of slice 1 comes after, each with its own test. `C_GetMechanismList`/`Info`, `C_WaitForSlotEvent`, `C_SeedRandom`, `C_GetFunctionStatus` and `C_CancelFunction` are not in the plan's slice 1 and stay C.

- **How the Rust reaches C's statics** (the decision 1c left open). The operation, find and OAEP tables stay C's until their slices. `p11/shim/pkcs11_tu.c` `#include`s the legacy `fhsm_pkcs11.c` unchanged and appends five accessors (`pqhsm_c_session_ops_reset`, `_has_active_op`, `_ctx_auth_grant`, and the two halves of the teardowns, in C's order), plus `pqhsm_c_audit_mandatory`, so `-DFHSM_AUDIT_MANDATORY=0` (`make audit-switch`) still reaches `C_Initialize`. `hybrid.mk` compiles that file in place of `fhsm_pkcs11.c` and localises C's fifteen with slice 0's three; `p11/shim/interface.c` exports Rust's under the same names (`--exclude-libs` hides the staticlib's). `-fvisibility=hidden` keeps the accessors out of `nm -D`. No legacy file changes, and no C outside the fifteen called them.
- **Kept from C:** the slot table built once per process at C's first-use points (C reset a flag its `pthread_once` never read again, so a deleted `.tok` stays "present"); a token loaded on first use and retried if it fails to load; the check order of every call, so each bad argument gets C's code; the `char[16]` cut of `pin_len` in the login event; `snprintf`'s 511-byte bound on the log and slot paths; every stderr message, word for word.
- **Golden:** `tests-support/hybrid/p11_lifecycle.c`, written against the C first, drives fifteen scenarios in forked children (each its own tokens dir), 244 rows of return codes and output bytes (outputs pre-filled with `0xAA`, so untouched bytes show; serials masked): every call before `C_Initialize` and after `C_Finalize`, slot lists and infos for slots 0-4, every `C_InitToken`, `C_InitPIN`, `C_SetPIN` argument refusal, the role and read-only rules, `CKU_CONTEXT_SPECIFIC` with and without an operation, operation state across a closed handle and a restart, lockout of both PINs, a forked child, and each `C_Initialize` refusal (audit off, `0`, an unusable dir, a group-readable key, an unparsable log, `/dev/null`). Harness step 4g runs it on C and hybrid and compares output and every scenario's audit log. The raw diff is three recorded divergences and nothing else, so the step suppresses exactly those: DIV-035 (the integrity NOTE again in a forked child and after a restart), the Phase 1 `[pqhsm]` key-message prefix, and DIV-009 (the fork scenario's child keeps its own log; step 5 checks it).
- **Mutation:** 23 mutants of the three Rust files, each built into the module and run through the driver with step 4g's suppressions; 22 killed. The first round left three alive and the driver gained rows for two: a `CKA_ALWAYS_AUTHENTICATE` EC key whose `C_Sign` refuses without `C_Login(CKU_CONTEXT_SPECIFIC)` and signs after it (the grant), and `C_DigestUpdate` on a handle just closed (the close's operation reset; `C_DigestUpdate` checks only the operation table). On the way: C stores the flag on private keys only, so `C_GenerateKey` and a secret `C_CreateObject` ignore it (slice 6 and 2's to judge). The survivor is equivalent at the API: finalize's release of the operation contexts, whose only effect beyond the reset every `C_OpenSession` does is freeing them, a leak a leak checker would see and the driver cannot.
- **Bugs found on the way, both mine:** a `\`-continued Rust string drops the next line's indentation, which would have cut the two spaces in C's messages (rewritten as `concat!`); the driver first masked `flags` instead of the serial.

### DIV-051: "not initialized" is enforced

- **Where:** `lifecycle::initialized()` (`p11/src/ffi/lifecycle.rs`): refused while the state is POWER_OFF or the caller is not the process that initialised (`INIT_PID`), which covers before `C_Initialize`, after `C_Finalize` and a forked child that has not re-initialised. Rust's fourteen check it after taking the API lock; `C_Finalize` checks `pReserved` first. The 44 entry points still in C get it from `p11/shim/interface.c`: `hybrid.mk` renames each `C_X` in the C object to `pqhsm_c_C_X` (`objcopy --redefine-sym`) and the shim's `C_X` calls `pqhsm_p11_gate()` and then it. The Rust function tables name the exported symbols, so they reach the wrappers too. The exported set is unchanged.
- **Shortcut, recorded:** in the wrappers the gate is read before the C takes its lock, so a call racing `C_Finalize` on another thread can pass it. PKCS#11 makes that race the application's; the check moves under the lock as each slice brings its entry points into Rust.
- **Test:** `tests-support/hybrid/p11_notinit.c`, harness step 4h: all 59 calls in each of the three states. C: 0 of 59 refused in each state (`C_OpenSession` and `C_Login` return CKR_OK after `C_Finalize`, the reproduced defect). Hybrid: 59 of 59.
- **Golden changes:** step 4g sets aside, and nothing more, scenario 0's calls before its first `C_Initialize` with that scenario's log, `C_Finalize(pReserved)`, and the forked child's call before its `C_Initialize`. Those rows were C's defect; step 4h checks what replaces them.
- **Two things the first harness run caught:** the renamed C symbols stayed in `nm -D` (C declares its entry points visible), so `hybrid.mk` makes them local after linking the shim; and TSan reported a race in `test_concurrency --cold` between the thread that built the slot paths and one reading them. The hand-over was synchronised, but by std's `OnceLock` and `Mutex`, which TSan cannot see because the Rust is not instrumented (slice 1d's run passed by timing). The registry now sits under a pthread mutex, as the rest of `ffi` does.
- **Harness `p4d51b`:** 106/106, `nm -D` (63 symbols) and NEEDED identical, p11 tables identical, step 4g identical less the recorded rows, step 4h C fails and hybrid passes, TSan 0 races in the four tests, corpus 64 same / 4 explained, token files the Phase 2 size pair only (`envrsa`, `algs`). Workspace 883 pass, 0 fail; clippy `-D warnings` clean.

### RULE-071, RULE-083, DIV-059

- **RULE-071:** a second `C_Initialize` in the process that initialised, while INITIALIZED, is 0x191. In ERROR it stays C's 0x6 (`fhsm_state_set` refuses ERROR to INITIALIZING); DIV-053 decides ERROR.
- **RULE-083:** `C_Login(CKU_USER)` maps the token's 0x101 to 0x102 when the token's user PIN was never set. Done where `C_Login` returns, not in the token crate, so `fhsm_token_login`'s Phase 2 contract and goldens stay as they are; the LOGIN_FAIL event records 0x102.
- **DIV-059:** `new_pin_len_ok` (8..64) for every PIN being set: `C_InitToken` (fresh and re-init), `C_InitPIN`, `C_SetPIN`'s new one; `ulMinPinLen` 8. `pin_len_ok` (C's 4..64) stays for a PIN checked against the token.
- **Tests:** `tests-support/hybrid/p11_divs.c`, one function per DIV, each in its own child and tokens dir; harness step 4h. On C: RULE-071 0x6, RULE-083 0x101, DIV-059 five checks off (0xA0 for a fresh 7-byte SO PIN, InitPIN accepting 7, `ulMinPinLen` 4, ...). Hybrid: all pass.
- **Step 4g from here:** `p11_lifecycle_expect.py` turns C's output into what Rust must print, one table row per changed call (DIV, label, rv) plus `ulMinPinLen` in every `tokinfo` row, and both sides get DIV-035's and the key prefix's normalisation. It replaces the awk filter, so each later DIV adds its rows there.
- **Audit in step 4g:** scenarios 1 and 2 leave the exact log comparison (with 0 and 5): a short new PIN is now refused before the token layer, so C's TOKEN_INIT or SET_PIN event for it is not written and every later sequence number moves, and the 0x102 login is logged as such. Rewriting C's records to match would be guesswork about which record came from which call; the rows of those scenarios still compare, and the remaining ten scenarios' logs must match exactly.
- **Intended test change:** `test_input_validation`'s `ulMinPinLen != 4` is patched to 8 in the harness's copy (the plan's §4.2); the original is the C's.
- **Harness `p4s1e2`:** 106/106, `nm -D` and NEEDED identical, step 4g identical after the recorded rows (logs: ten scenarios exact), step 4h: every DIV test fails on C and passes on the hybrid, TSan 0 races, corpus 64 same / 4 explained, token files the Phase 2 size pair only. Workspace 883 pass; clippy clean.

### DIV-055: `C_CloseAllSessions` per slot

- Slots 0-3 accepted, past 3 0x3; each session whose slot (`Table::info`) is the one given goes through the same `close_session` as `C_CloseSession`, so its operations, session objects and the last-session logout of that slot's token follow C's per-session path. As in C, only sessions with a token attached are visited.
- **Test:** `p11_divs.c` DIV-055: SO sessions on slots 0 and 1, `closeall 4` 0x3, `closeall 1` closes slot 1's session only and slot 0's stays logged in as SO, then `closeall 0`. C: `closeall 1` is 0x3 and the session survives.
- **Golden:** step 4g's `closeall 1` row is 0 and the slot-1 session after it is gone (0xB3, output untouched); `p11_lifecycle_expect.py` gained an optional printed-output column for that row.

- **Harness `p4d55`:** as `p4s1e2`, with DIV-055 failing on C and passing on the hybrid; token files the Phase 2 size variance only.

### RULE-084: the PIN warning flags

- `C_GetTokenInfo` sets `CKF_USER_PIN_COUNT_LOW`/`CKF_SO_PIN_COUNT_LOW` while 1 <= failures < 5 and `*_FINAL_TRY` at 4, from `fhsm_token_failed_count` (`core::p11::pin_warning`, unit-tested). Locked (5) shows `*_PIN_LOCKED` only, as before.
- The dead mapping goes: the token never returns `FHSM_RV_PIN_THROTTLED` (a throttled login waits and then answers), so `login_event`'s arm for it and `EV_LOGIN_THROTTLED` are removed. `audit-verify` keeps the name, to read old logs.
- **Test:** `p11_divs.c` RULE-084: the user flags after 0-5 wrong logins (0, LOW, LOW, LOW, LOW|FINAL, LOCKED), the SO's after 1 and 4, cleared by a good SO login. C: no warning bit ever.
- **Golden:** five `tokinfo` rows of step 4g gain the bits, recorded in `p11_lifecycle_expect.py`'s `FLAGS` table.

### DIV-054: `C_SetPIN` works

- **Token:** a new `Token::change_pin(role, old, new)`: the role must be the one logged in with its DEK live (else 0x101), the old PIN goes through `verify_pin` (the counter, throttle and lock a login applies, without logging in again), then the shared `rewrap` wraps the live DEK under the new PIN with a fresh salt and nonce, audits SET_PIN, and writes through the locked transaction. `set_pin` keeps C's log-in-first behaviour: the token's Phase 2 golden (`set_pin_logged_out_rule082`) pins it, and only the token's own callers use it. ABI: `pqhsm_token_change_pin`, PINs by length (PKCS#11 does not terminate them).
- **`C_SetPIN`:** the handle, then a login (0x101), then a read-write session (0xB5, PKCS#11's `CKR_SESSION_READ_ONLY`), then `change_pin` for the session's role. The new PIN's length is DIV-059's.
- **Audit:** one SET_PIN event a call. A success is the token's (role, OK; session -1, since the token does not know it), written before the file so a failed audit suppresses the change (DIV-001); a refusal from the token (0xA0, 0xA4, ...) is `C_SetPIN`'s, with the session. Argument and session refusals write none, as before.
- **Tests:** `token_props.rs` `change_pin_rewraps_for_the_logged_in_role`; `p11_divs.c` DIV-054: nobody logged in 0x101, SO change then old refused and new accepted, a wrong old user PIN counted (COUNT_LOW), a read-only session 0xB5, user change with the session still logged in, and the new PIN after `C_Finalize` and a fresh `C_Initialize` (it is on disk). C: every change 0x100.
- **Golden:** three step 4g rows recorded (`setpin so` 0, `setpin so wrong old` 0xA0, `setpin user` on a read-only session 0xB5).

- **Harness `p4d54`:** as `p4r84`, with DIV-054 failing on C and passing on the hybrid. Workspace 885 pass, 0 fail; clippy clean (workspace default, token `ffi` and `tool`, p11 `ffi`).

### DIV-053: what ERROR refuses

- `pqhsm_p11_gate(status)`: after DIV-051's check, ERROR refuses with C's 0x6 unless `status`. The shim's `GATE` passes 0 and `STATUS` 1 (`C_GetMechanismList`, `C_GetMechanismInfo`); Rust's fifteen already refused, the four status calls among them excepted, and `C_Finalize` runs. An operation under way refuses at its next call because its next call is gated.
- **Test:** `p11_notinit.c` DIV-053. ERROR is latched from outside: a digest started, then `RLIMIT_FSIZE` at the open log's size and an audited call, whose failed write latches "audit write failed". Then the digest's update and final and every entry point: 0x6 for all but the six status calls the driver exercises and `C_Finalize`. C: 29 calls run on, among them the digest (0x0), `C_FindObjects*` and the key-use Inits (0x70, they reach the mechanism check).
- **DIV-052** moves to slice 6 whole (`PHASE4_PLAN.md` revised): its one call site is the pairwise check in `C_GenerateKeyPair`, and only fault injection there reaches it.
- **Harness `p4d5350`** (with DIV-050): tests 106/106, `nm -D` and NEEDED identical, 4g identical less recorded DIVs, every step 4h test fails on C and passes on the hybrid, TSan 0 races. Workspace 886 pass, 0 fail.

### DIV-050, the logout half: logout drops the private objects

- **Token:** `Token::logout` drops the private token objects, the classes RULE-055 hides (`store::is_private_class`: secret and private keys; C derives CKA_PRIVATE from the class), keeps every other token object and the session objects, and marks the store unloaded with what is left visible. (First cut used the file's public view, which also dropped data objects and sensitive public keys; the slice 2 golden caught it, 2026-11-05.) Each dropped object goes from the store; its value's `Buf` is zeroised when its last reader lets go. Every logout goes through it: `C_Logout`, the last session closing, and re-init. The next login reloads the file, as a first login does, and puts the kept session objects back, with `next_handle` past their handles so none is reused (also on the DIV-010 and DIV-024 refusals, which fall back to the public view).
- **Recorded:** the token goldens `logout_keeps_objects_rule086` steps 5-7 (the AES key is 0x60, `find` returns the three public-class objects) and `session_objects_rule090` step 19 (the user's secret token key is gone, the public session key stays). RULE-086's "logout keeps objects" is superseded for the private ones.
- **Test:** `p11_divs.c` DIV-050, SEC-001's reproduction: an AES token key works logged in; after `C_Logout`, `C_EncryptInit` is 0x60 and `C_FindObjects` does not return it; after a new login it works again. C: 0x0 after logout, and the operation left active gives 0x90 later. The key-use refusals, and an operation continued past the logout, are left to the slices that own those entry points.
- **Harness `p4d5350`:** as for DIV-053 above, with DIV-050 failing on C and passing on the hybrid; no other diff, as expected.

### Slice 1 review (architecture-critic, 2026-11-05)

Range `e956620..7ac859e`. Two HIGH, four MEDIUM, five LOW; each checked against the code.

| # | Finding | Done |
|---|---|---|
| H1 | DIV-001 not applied at the audit sites slice 1 moved | Fixed: `audit` returns its result, `audited` maps it; see DIVERGENCES § DIV-001 in Phase 4. Test `p11_divs.c` DIV-001. One legacy assertion changes (a stream audit target: `C_Initialize` 0x30), recorded (user: "Record it (Recommended)"). |
| H2 | `C_Logout` SHARED, so the objects DIV-050 drops wait for the shared readers before they are zeroised | Fixed: `C_Logout` takes the lock EXCLUSIVE. |
| M1 | Private session objects survive logout, still usable by the C key-use paths | As DIV-050's Target; stated in its status. The key-use slices close it. |
| M2 | In ERROR nobody can log out or close a session, so the keys stay loaded until `C_Finalize` | Decided (user: "Allow the three (Recommended)"): the three run in ERROR; DIV-053 amended, `p11_notinit.c` checks they are not refused. |
| M3 | No atfork reset for the registry, session-table and state mutexes; a fork while another thread holds one deadlocks the child's `C_Initialize` | Follow-up, as C (`g_slots_mu`, `g_sess_mu`). For the slice that makes the module `pqhsm-p11`'s cdylib. |
| M4 | RULE-035: a read-only session can open during an SO login's PIN check | Fixed: `Table::login` checks again after a successful SO login, and logs out with 0xB7. |
| L1 | `change_pin` checks the role and rewraps under separate locks | Fixed: `rewrap` checks again. |
| L2 | PIN copies zeroised by hand on every path | Fixed: `PinBuf` zeroises on drop. |
| L3 | The slot registry's pthread mutex while the session table uses std | Kept: the registry is the one the C still calls; noted for the cdylib slice. |
| L4 | `p11_notinit.c` accepts any 0x6 in ERROR; DIV-050's find check does not separate C from Rust | Noted: the 0x6 is the decided code; DIV-050's distinguishing check is the 0x60. |
| L5 | `Table::with` asks the token for its role under the session-table mutex | Slice 2's object calls copy the token handle out first. |


### Slice 2a: find, size and destroy in Rust

- `p11/src/ffi/objects.rs`: `C_FindObjectsInit`, `C_FindObjects`, `C_FindObjectsFinal`, `C_GetObjectSize`, `C_DestroyObject`, in C's check order over the token's C ABI, as C called it. Each applies DIV-051's and DIV-053's gate itself, as the shim's wrapper did. `hybrid.mk` moves the five from the gated list to the Rust-owned one; `p11/shim/interface.c` forwards them.
- **Find state:** C's `g_finds` becomes `objects::FINDS`, reset where C reset it (finalize, after a fork). Kept as C: a find is set active even when the token's search fails (that rv is returned); the result is clamped to the store's 1,024; an object whose class lookup fails is not hidden; a CKA_ID over 32 bytes is no filter at all; the label is cut at 63 bytes.
- **Candidate defect, kept (wrong: C clears it, `:8987`; fixed after slice 8b-ii, below):** a session's find is not cleared when the session closes, so the next session on that handle inherits it (`C_FindObjectsInit` 0x90, or the old results). C's `fhsm_session_ops_reset` clears the operation tables, not `g_finds`.
- **Destroy:** as C, no visibility check yet. That is DIV-050's destroy part (0x82), the next commit, with its test.
- **Golden:** step 4i identical before and after the port (1,877 rows).

### DIV-050, the destroy part

- `C_DestroyObject` looks the object's class up first, and a secret or private key is 0x82 unless the token is logged in as the user: the SO could destroy the user's keys in C. The check comes before the read-only-session check, so a read-only session's 0xB5 does not tell a caller the key exists. An object whose lookup fails goes on to C's checks unchanged (its rv stays C's 0x60 until RULE-092's commit).
- **Golden fixed first:** the driver's three SO logins ran with a read-only session open, so they failed (0xB7) and the "so" rows tested nobody. Each now closes it first; with the fix, only the two rows it changes differ from C. Step 4i records the two rows the fix changes, by exact match.

### Slice 2b: get and set attribute in Rust

- `p11/src/ffi/attrs.rs`: `C_GetAttributeValue` (every arm of C's switch: the withheld CKA_VALUE and its 0x11, the nested templates filled in the caller's own buffers, the usage defaults by class, the CK_UNAVAILABLE_INFORMATION shapes) and `C_SetAttributeValue` (validate every row, then apply; the one-way SENSITIVE, EXTRACTABLE, COPYABLE and WRAP_WITH_TRUSTED rules; CKA_TRUSTED only by the SO). C's order of checks and of the three error codes is kept.
- **Still C, through `p11/shim/pkcs11_tu.c` (ported in slice 8b-ii, below):** the OpenSSL readbacks: `extract_pubkey_attr` (RSA and EC components), `extract_cert_attr` (subject, issuer, serial), `fhsm_pset_selector_of`, and the raw PQC public key the CKA_VALUE arm decoded inline (`pqhsm_c_pqc_raw_pub`, the same five lines). They move with the PKI side, by slice 5.
- **Kept as C in the port:** `C_SetAttributeValue` checks no visibility (`C_GetAttributeValue` and `C_GetObjectSize` do), so the SO may relabel the user's key or turn on its CKA_SENSITIVE. Decided 2026-11-05 as a new part of DIV-050 (user: "Fix, under DIV-050 (Recommended)"); the next commit.
- **Golden:** step 4i identical (all rows but the two DIV-050 records).

### DIV-050, the set-attribute part

- `C_SetAttributeValue` answers 0x82 for a secret or private key unless the token is logged in as the user, after the argument checks and before the read-only check, as `C_DestroyObject` does. Decided 2026-11-05 when the 2b port found it (user: "Fix, under DIV-050 (Recommended)").
- **Test:** `p11_divs.c` DIV-050, the SO's relabel, placed before the SO's destroy: on C the destroy succeeds, and a relabel after it would have answered 0x82 for a missing key and passed for the wrong reason. The first run showed exactly that.

### Slice 2c-i: the create-template parser in Rust

- `src/fhsm_create_attrs.c` becomes `pqhsm_core::template` (safe, no `unsafe`), exported under C's own `fhsm_parse_create_attrs` by `p11/src/ffi/create_attrs.rs`; `hybrid.mk` empties the C object. `C_CreateObject`, still C, calls the Rust parser through the same header.
- **Kept as C:** the paths, the order of checks, the partial fill before a failure, the pointers into the caller's template (identity kept, so a zero-length value keeps its pointer). One difference, unreachable from `C_CreateObject` (its `fhsm_check_template` refuses it first): a NULL value with a length counts as no bytes, where C read through it.
- **Proof:** harness step 4j, `tests-support/hybrid/create_attrs_diff.c`, built once with the C file and once with the staticlib, over the 273-file fuzz corpus and 200,000 seeded templates biased to the parser's types (all eight paths and all five rvs reached): every field and pointer offset identical. Plan §6.6's proptest properties are `fuzz_create_attrs.c`'s invariants (`parse_holds_c_s_invariants`, 4,096 cases); cargo-fuzz still waits on the network fetch.
- **Harness hygiene, again:** `run.sh` snapshots the tree, but the container runs `tests-support/hybrid/inner.sh` from the live repo, and sh reads a script as it goes; adding step 4j during run p4d50s cut it off ("Syntax error: "done" unexpected"). The set-attribute part was rerun alone from a git worktree (HEAD plus that change), which also keeps each commit's tested state exact. No edits to `inner.sh` while a run is going.

### Slice 2d: copy in Rust

- `C_CopyObject` is `p11/src/ffi/copy.rs`, in C's order: the ERROR and not-initialized gate, NULL out, `check_template`, CKA_TRUSTED (SO only), the read-only check, the session, CKA_COPYABLE=FALSE on the source (0x1B) before the login check, then the source read, the override template, the add, and the helpers. Any helper's failure destroys the copy.
- **The helpers** C's other creation paths apply after the object exists are here too: `check_trusted`, `check_ro_token`, `apply_allowed_mechs`, `apply_nested_all` (unwrap, derive, wrap), `apply_encap_flags`, `apply_obj_meta`. `C_CreateObject`, generate, unwrap and derive keep calling C's static copies until they move (slice 6, plan §6 revised 2026-11-05, user: "Helpers + copy now (Recommended)").
- **Kept as C:**
  - ~~a nonzero source flags2 byte replaces the copy's~~: fixed as DIV-060 (the next commit; a copy asked to be uncopyable came out copyable from a restricted source). flags3 is still copied as C copies it.
  - the session marking's result is ignored (RULE-091, a later commit).
  - a mechanism list truncates each CK_ULONG to the record's u32.
- **Golden first:** `p11_objects.c`'s copy scenario gained 19 cases and shows 16 attributes of each copy (1,995 rows). They showed that copy's override loop refuses, as 0x12, every attribute outside its list: dates, CKA_APPLICATION, CKA_ALLOWED_MECHANISMS, the nested templates and CKA_DECAPSULATE. A copy keeps the source's dates and application but cannot set its own, and the helpers, called after the add as C calls them, find nothing to apply. **Their logic is therefore not yet exercised by any golden**; that comes when create, generate, unwrap and derive call them (slice 6). Recorded with the defect above: a copy template cannot restrict a copy the way the spec allows (candidate, not fixed).

### DIV-060, a copy keeps its restrictions

- `copy.rs` ORs the source's flags2 into the copy's instead of replacing it. Test `p11_divs.c` DIV-060 (C fails, Rust passes); step 4i's sed records the one golden row (`copy made uncopyable attr 0x171`, 01→00).

### DIV-056, a copy keeps its source's usage and policy

- `copy.rs` reads the source's usage byte and mechanism list before the override template, and writes them, with the three nested templates, to the copy after the add. The template may narrow: a usage attribute TRUE→FALSE (`attrs.rs`'s `usage_of` and `usage_defaults`, shared with get-attribute), or a mechanism list that is a subset of the source's. Widening is 0x10, a nested template 0xD1. A copy inheriting CKA_TOKEN from a token object needs a read-write session (0xB5), checked before CKA_COPYABLE.
- Step 4i's recorded rows moved from inline `sed -e` into `tests-support/hybrid/p11_objects_expect.sed`, one commented block per DIV. DIV-056's 74 lines: SIGN FALSE and the list carried on every copy of the source, the new codes, the narrowing copy's 16 attribute rows, and the handles of the copies after it, each one more.
- `apply_nested_all` has no caller now (copy refuses nested templates); kept, marked, for slice 6. With it go `apply_nested_tmpl`, `policy_kind`, `wrap_tmpl_supported` and their tables, reachable only through it. `apply_encap_flags` and `apply_obj_meta` are called but never act yet: copy's override loop refuses ENCAPSULATE, DECAPSULATE, the dates and APPLICATION (0x12) before they run. All of it is first exercised in slice 6.

### RULE-092 and RULE-091

- **RULE-092:** `C_DestroyObject`'s result goes through `lookup_rv`, as every other object lookup does, so an unknown handle is 0x82, not 0x60. Test `p11_divs.c` RULE-092; three golden rows recorded.
- **RULE-091, sessions:** C advertised 128 sessions and held 127 (handles 1 to `FHSM_MAX_SESSIONS - 1`). `core::session::MAX` is 129, and `hybrid.mk` builds C's five per-session operation tables, its find table and `C_CloseAllSessions` loop with `-DFHSM_MAX_SESSIONS=129`, so handle 128 is inside every table on both sides. Test `p11_divs.c` RULE-091 opens 128 and digests on the last. `session.tsv` was regenerated by `regen_session.sh` from the legacy C at 129 (`gen_token.mk`), 275 rows: the same scenario at the new size.
- **RULE-091, marking:** copy destroys a copy it cannot mark as a session object and returns the error. Untested: the marking fails only when the store's rewrite does. The destroy rewrites the store too, so when the marking fails it likely fails as well, leaving a token object the caller holds no handle to; and the copy is in the token file before it is marked, as in C. The fix guarantees the error is returned, not that nothing persists.

### RULE-061

- `Token::object_mech_allowed` (`token/src/token.rs`) refused nothing it could not find: an unknown handle and a token with nothing loaded both answered OK, as C's `fhsm_token_object_mech_allowed` does. It now returns the lookup's own error: 0x60 for an unknown handle, 0x101 when nothing is visible. The decision assumed every caller looks the key up first. Seven of the eleven `fhsm_check_allowed_mech` sites do (the encrypt, decrypt, sign and verify inits; encapsulate and decapsulate). `C_DeriveKey`, `C_WrapKey`, `C_UnwrapKey` and `C_DigestKey` do not: C let an unknown key through to later checks, so which error comes back can change, though every such call still fails. Recorded with the user ("Keep, record"); test `p11_divs.c` RULE-061: logged out with the public view loaded, `C_UnwrapKey` with an unknown key is 0x60 (C: 0x101). No harness golden changed.
- Token test: three steps of the token golden (`token/tests/scenarios.rs` `DIVS`, RULE-061) pin C's 0x0 and require Rust's error. `the_div_table_matches_divergences_md` now also accepts a RULE id listed in DIVERGENCES.md's rule table, since Phase 4 rules are not in PHASE2_PLAN.md.

### RULE-059 (in part)

- ALWAYS_SENSITIVE and NEVER_EXTRACTABLE were read from the current flags, so a key created readable and later made sensitive answered "always sensitive". History is lost only where a flag moves, and the only moves allowed are SENSITIVE on and EXTRACTABLE off, in set-attribute and copy, both Rust now. `attrs.rs` `history(before, after)` gives the bits a move must record, `OBJF3_WAS_NOT_SENSITIVE` (0x02) and `OBJF3_WAS_EXTRACTABLE` (0x04) in the third flags byte; set-attribute writes them before the flags, copy ORs them into the source's byte. The getter is the flag and not its history bit.
- Not in the token layer: setting the bits at `object_add` would rewrite the record of every key created readable and break the byte-for-byte token golden, for no change in what anyone reads, since at creation the flags are the history. Old records have both bits clear and read as before (Q5); a build older than the third byte clears them on its next write (`fhsm_token.h`).
- Left for slice 6: imported and unwrapped keys start with both bits set (PKCS#11), which needs `C_CreateObject`'s and `C_UnwrapKey`'s own code; and DIV-057's derived keys, which take the base key's history.
- Test `p11_divs.c` RULE-059: set-attribute and copy, C answers TRUE for all four reads. Four `p11_objects` rows recorded.

### Slice 2 review (architecture critic, 2026-11-05)

No HIGH findings. Applied:
- **M2:** copy works out each flags byte whole and writes it once, checked, undoing the copy on failure; the source metadata write is checked too. Before, a failed flags2 or flags3 write returned OK with a copy that had lost a DIV-060 restriction or read ALWAYS_SENSITIVE TRUE. Two of the three flags2 read-modify-writes, each a full token-file rewrite, are gone.
- **M1:** `div_056` now checks that a copy keeps its source's wrap template (C: no rows; DIVERGENCES.md already claimed the test covered it).
- **L4:** `rule_059` copies the locked key with no template and expects the history inherited.
- **L3:** `hybrid.mk`'s `-DFHSM_MAX_SESSIONS=129` is `override`, so a `CFLAGS=` on the make command line cannot drop it.
- **L5, M3:** recorded above (RULE-091's undo; what in copy.rs is dead until slice 6).

Not applied: L1 (copy computes its scope twice, with opposite defaults on a failed lookup) and L2 (a failed mechanism-list read skips the subset check); neither is reachable, since the source's value lookup fails first.

## Slice 3: digest

### 3a: golden first

- `tests-support/hybrid/p11_digest.c` (harness step 4k), written from the C before the port: C_DigestInit's checks in order and every digest mechanism (12, plus an HMAC and RSA) one-shot and in parts, with size queries and 1-byte buffers; C_Digest's and C_DigestUpdate's argument checks and which of them end the operation; C_DigestKey over secret, sensitive, non-private, session, mechanism-restricted, data and unknown objects, logged in and out, mixed with data; two sessions at once, a closed and reused handle, context login, logout, finalize and a fork. 385 rows on C.
- Against the hybrid before the port it differed in 12 lines, all recorded: DIV-050 (logged out, C digested the user's secret keys; the hybrid answers 0x60) and DIV-051 (0x190 after `C_Finalize`). `p11_digest_expect.sed` records the five rows by exact match.

### 3b: the five entry points in Rust

- `p11/src/ffi/digest.rs`: `C_DigestInit`, `C_Digest`, `C_DigestUpdate`, `C_DigestKey`, `C_DigestFinal`, in C's check order. Each takes the API lock shared and applies DIV-051's and DIV-053's gate under it, so for these five the shim's shortcut (gate read before the lock) is gone. `hybrid.mk` moves them from the gated list to the Rust-owned one; `interface.c` forwards them.
- **The table:** C's `g_op_dig` becomes `digest::DIGESTS`, one `Mutex` per session handle, so two threads on one session (an application error) cannot race on the context as they could in C. Reset where C reset it: session open and close, finalize (contexts freed), after a fork (forgotten, not freed: the parent's). `C_Login(CKU_CONTEXT_SPECIFIC)` counts an active digest as C did. C's `g_op_dig` stays in the TU, always idle. C's context-auth grant is not carried over for digests: no digest path reads it.
- **Crypto:** the multipart context is `pqhsm_crypto::prim::Hasher` (EVP, C's lazy-init order and error codes: HOST_MEMORY, then FUNCTION_FAILED), and `md_available` is C's `fhsm_md_available`, both beside `prim::digest`. The one-shot paths call `fhsm_hash_oneshot` through its C ABI, as the C did, which keeps its ERROR check. `pqhsm-p11` now depends on `pqhsm-crypto`.
- **Kept as C:** `C_Digest` after updates hashes only its own data; its DATA_LEN_RANGE and NULL-data errors end the operation but leave the context for the next `C_DigestInit` to free; a NULL length pointer to `C_Digest` or `C_DigestFinal` does not end it; `C_DigestKey`'s refusals (allowed mechanisms, sensitive, lookup, class) and its failed update do not end it; the key handle is narrowed to 32 bits.
- **Candidate defect, kept:** PKCS#11 says any error but BUFFER_TOO_SMALL ends a digest; `C_DigestKey`'s refusals and the NULL length pointer do not. No DIV; recorded for a decision.
- shortcut: a fork while another thread is inside a digest call makes the child's `C_Initialize` deadlock (it locks every slot to forget it), and a digest call can hash 2 GiB. Worse than the find state's window (review M1); first in M3's atfork work.
- **Golden:** step 4k identical to C, less the recorded rows, before and after the port. Unit tests: every digest mechanism names a hash of its size; a `Hasher` in parts equals the one-shot.

### DIV-050, the C_DigestKey part

- `C_DigestKey` answers 0x60 for a secret or private key unless the token is logged in as the user, before the allowed-mechanism check and the value read; a key whose lookup fails goes on to C's checks. In C (and the 3b port, which kept it) the SO could digest the user's non-sensitive secret keys, and anyone a private session key after logout: a digest of a key is a test of a guess at it. Found by the automated security review of 3b; decided 2026-11-05 (user: "Fix, under DIV-050 (Recommended)").
- **Test:** `p11_divs.c` DIV-050, the SO's `C_DigestKey` on the user's key (C 0, hybrid 0x60). The digest golden has no SO scenario, so step 4k is unchanged.
- **Test** (review M2): `p11_divs.c` DIV-050 also digests a private session key after logout (C 0, hybrid 0x60); the logged-out golden rows use token objects, which logout already unloads.

### Slice 3 review (architecture critic, 2026-11-05)

No HIGH findings. Applied: M1 (the fork shortcut is a deadlock of the child's `C_Initialize`, not a stuck slot; text corrected, first in M3's atfork work), M2 (the session-key test above), L4 (the SAFETY comment on the token value cites apilock.rs's parking).
Recorded, not applied:
- **L2:** a digest that has absorbed a key with `C_DigestKey` survives logout, so `C_DigestFinal` gives H(key) afterwards. In scope for DIV-050's "operations under way end at logout" work (slices 4-7).
- **L1:** golden gaps: handles 128 and 129 on all five calls, a key handle above 32 bits, `*pulDigestLen` on the error paths, a threaded digest test. The build is the strict profile, so SHA-1 and MD5 are only refused, and the provider-missing branch is not reached.
- **L3:** not observable: on an EVP failure in `C_DigestFinal`, C writes back the length cast to 32 bits; Rust leaves it.

## Slice 4: encrypt and decrypt

### 4a: golden first

- `tests-support/hybrid/p11_crypt.c` (harness step 4l), written from the C before the port: Init's checks in order and every parameter shape; single-part round trips for AES-ECB, CBC, CBC-PAD, CTR, GCM, CCM, KW and KWP at three key sizes, with size queries, 1-byte buffers and tampered input; the same in parts; RSA-OAEP over nine digests, labels and length limits; key classes, usage, allowed mechanisms, logged out and as SO; two sessions, close and reuse, context login, logout, finalize, a fork, and a multipart context left by an error. 2142 rows on C. `p11_crypt_expect.sed` records the DIV rows.

### 4b: the eight entry points in Rust

- `p11/src/ffi/crypt.rs`: `C_EncryptInit`, `C_Encrypt`, `C_EncryptUpdate`, `C_EncryptFinal` and the four `C_Decrypt*`, in C's check order, each under the shared API lock with DIV-051's and DIV-053's gate. `hybrid.mk` moves them to the Rust-owned list; `interface.c` forwards them.
- **The tables:** C's `g_op_enc` and `g_op_dec` (and the OAEP parameters) become `crypt::ENC` and `DEC`, one `Mutex<Op>` per handle. Reset at session open and close, finalize, after a fork (contexts forgotten); `C_Login(CKU_CONTEXT_SPECIFIC)` counts them and grants them (`grant`), and decryption of an ALWAYS_AUTHENTICATE key needs that grant, as C.
- **Crypto:** `pqhsm_crypto::cipher` holds thin EVP wrappers (cipher context, RSA key and OAEP context), so the call sequences and each failure's code stay in `crypt.rs`, where C had them. The AAD, the label and every scratch output are cleansed on drop.
- **Kept as C:** GCM tag_bits 0 is taken as 128; the bare 12-byte GCM IV from any block of 12-47 bytes; GCM and CCM are always audited, a failure with its rv; a tag mismatch zeroes the caller's whole buffer; `C_Decrypt` checks its arguments before looking up the key, `C_Encrypt` after; the RSA PKCS#1 v1.5, X.509 and DES3 paths are ported but refused in the strict build (MECHANISM_INVALID, as C). Multipart GCM decryption never succeeds: nothing sets the tag, so `C_DecryptFinal` is 0x40 after `C_DecryptUpdate` has returned unauthenticated plaintext (step 4l records it). A candidate defect, no DIV.
- **DIV-001:** a single-part success is computed into scratch, recorded, then copied out, so a failed record writes nothing.
- shortcut: the same fork window as the digest slots (review M1 of slice 3); first in M3's atfork work.
- **Golden:** step 4l identical to C less the recorded rows: DIV-050 (logged-out and SO key use 0x60, operations ended at logout 0x91), DIV-051, DIV-061, DIV-062. Unit tests: the parameter parser's shapes and bounds for GCM, CTR, CCM, CBC, KW and OAEP; ECB in parts equals one call; a GCM tag round trip.
- **Untested by the harness:** the all-mechanisms profile's RSA PKCS#1, X.509 and DES3 paths (the harness builds only strict).

### DIV-050, the encrypt and decrypt part

- Init answers 0x60 for a secret or private key, token or session, unless the user is logged in, right after the key lookup. `C_Logout` ends every encryption and decryption under way on such a key of that token (`crypt::end_private`, under C_Logout's exclusive lock). The logged-out session key is the SEC-001 hole that slice 1 left (review M1); sign and the rest close it in slices 5-7.
- **Test:** `p11_divs.c` DIV-050, the session key logged out and as SO (C 0, hybrid 0x60) and an encryption across a logout (C 0, hybrid 0x91).

### DIV-061 and DIV-062

- DIV-061: single-part AES-ECB, CBC, CBC-PAD and CTR with a key of another length is 0x62 (C read 32 bytes of it). DIV-062: each Init builds a fresh operation, so no context an error left carries on. Both found by the 4a golden; tests `p11_divs.c` DIV-061 and DIV-062.

### Slice 4 review (architecture critic, 2026-11-06)

No HIGH findings. Applied:
- **M1:** `end_private` frees the operation whole (`Op::IDLE`), so the logout drops the user's key schedule in the cipher context, not only the operation's flag.
- **M2:** recorded under DIV-001: a failing single-part call writes nothing (C left partial plaintext); test `p11_divs.c` DIV-001 case 5.
- **M3:** scratch is allocated with `try_reserve_exact`; failure is HOST_MEMORY, not an abort of the host. A cost of DIV-001: a single-part call holds a second copy of its output.
- **L1:** the DIV-001 login rollback also ends operations begun on the user's keys meanwhile.
- **L2:** scratch is cleansed over its whole allocation.
- **L3:** the `C_DigestKey`-after-logout item joins DIV-050's remaining list; multipart GCM decryption is listed above.
- **L4 (in part):** `p11_divs.c` DIV-050 checks that a logout ends another session's encryption and a decryption in parts.
- Nit: `rv::MECHANISM_PARAM_INVALID` in place of the bare 0x71.
Recorded, not applied:
- **L4 rest:** no test that an operation on a public key survives logout (needs an RSA key in `p11_divs.c`), or that another token's survive.
- Nits: `cipher::cleanse` beside `sys::zeroize` (the second calls C, which the unit tests cannot link); `kind()` keeps C's integer codes; `object`'s lifetime is not tied to the `Held` guard.


## Slice 5: sign and verify

### 5a: golden first

- `tests-support/hybrid/p11_sign.c` (harness step 4m), written from the C before the port: every Init check and parameter shape (GMAC, PSS, ML-DSA, HashML-DSA, EdDSA); eleven HMACs, CMAC and GMAC at each key size; ECDSA P-256/384/521, Ed25519, Ed448, RSA PKCS#1 and PSS, raw RSA, ML-DSA-44/65/87 with contexts, HashML-DSA per hash and generic, SLH-DSA SHA2-128f and SHAKE-128f; size queries, 1-byte buffers, tampered and short signatures, the same in parts; ALWAYS_AUTHENTICATE, the 16 MiB multipart ceiling, a reused handle, logout, SO, a fork and finalize. Randomised signatures print as `rnd:<len>` and are checked by verifying. 3994 rows on C, the same twice. `p11_sign_expect.sed` records the DIV rows.

### 5b: the eight entry points in Rust

- `p11/src/ffi/sign.rs`: `C_SignInit`, `C_Sign`, `C_SignUpdate`, `C_SignFinal` and the four `C_Verify*`, in C's check order, under the shared API lock with DIV-051's and DIV-053's gate. `hybrid.mk` moves them to the Rust-owned list; `interface.c` forwards them.
- **The tables:** C's `g_op_sig` and `g_op_ver` become `sign::SIG` and `VER`, with the same hooks as `crypt.rs` (session open and close, finalize, fork, the context login's count and grant, DIV-050's logout).
- **Crypto:** `pqhsm_crypto::sig` holds thin EVP wrappers: the MAC and digest streams, DigestSign/DigestVerify contexts with their init and post-init OSSL_PARAMs, the raw `EVP_PKEY_sign`/`verify` context, `pss_apply_params`, the raw ML-DSA public key import and a constant-time compare. The call sequences and each failure's code stay in `sign.rs`.
- **ECDSA raw r||s and DER:** `src/fhsm_ecdsa_raw.c` becomes `pqhsm_core::ecdsa`, pure Rust. The plan had core call pqhsm-pki's raw-to-DER; core does not depend on pki, and the twenty lines each way were smaller than the dependency. The C file stays in the build while other C calls it.
- **Composite (all-mechanisms profile only):** ported over pqhsm-pki's `fhsm_composite_*` exports; the strict build refuses it at both Inits, as C (Q17; step 4m's composite rows are those refusals).
- **Kept as C:** OPERATION_ACTIVE after the key, type, allowed-mechanism and usage checks; GMAC's struct form reading any block of 48 bytes or more, and its raw IV of 12 to 512 bytes; PSS with an unknown MGF accepted at Init and FUNCTION_FAILED at the signature (0x71 at a hashed verification); an HMAC key created with CKA_ALWAYS_AUTHENTICATE signs without the context login (step 4m's `sign without context login` is 0 on both); composite updates that fail leave the operation active; a too-long ML-DSA context refused at SignInit and false at Verify; MACs not audited, asymmetric signatures and verifications audited; a short buffer keeps the operation and the retry signs again.
- **Not observable:** CMAC's and GMAC's key length is checked before the MAC is fetched (C: after the fetch and the context, whose failures cannot happen); a NULL DigestSign context in the hashed path is FUNCTION_FAILED, as C, elsewhere HOST_MEMORY, as C.
- **DIV-063 (review M1):** a NULL signature with a length at `C_Verify` is 0x7 up front; C crashed at the right length and answered 0xC0 at a wrong one.
- **DIV-001:** every signature is made in scratch, recorded, then copied out; a verification that succeeds but cannot be recorded is 0x30.
- shortcut: the same fork window as the digest and cipher slots (review M1 of slice 3); first in M3's atfork work.
- **Golden:** step 4m identical to C less the recorded rows: DIV-050 (logged-out and SO key use 0x60, operations ended at logout 0x91, and two rows that follow from them), DIV-051, DIV-062. Unit tests: the mechanism tables, M' for HashML-DSA, the PSS arguments, the MAC and digest wrappers, raw r||s to DER and back.
- **Untested by the harness:** the all-mechanisms profile's SHA1-RSA, raw RSA X.509 and composite paths.

### DIV-050, the sign and verify part

- SignInit and VerifyInit answer 0x60 for a secret or private key, token or session, unless the user is logged in, right after the key lookup. `C_Logout` ends every signature and verification under way on such a key of that token. A verification with a public key goes on.
- **Test:** `p11_divs.c` DIV-050, HMAC with the session key logged out, across a logout and as SO.

### DIV-062, the sign and verify part

- C's `op_init` never freed an operation's MAC stream, so after an update and a single-part `C_Sign` (which ends the operation and leaves the stream), the next Init's update went on with the old stream. Each Init now starts afresh. Found by the 5a golden (`life verify needs no context login`, 0xC0 on C); test `p11_divs.c` DIV-062's HMAC case.

### Slice 5 review (architecture critic, 2026-11-06)

No HIGH findings. Applied:
- **M1:** DIV-063 above (user: "0x7 up front, new DIV (Recommended)"); the per-path refusals are gone, and the composite gets the caller's pointer, so pki refuses a NULL one at length 0, as C.
- **M2:** the buffered message is a cleansed `crypt::Secret`, grown by hand so no reallocation leaves an uncleansed copy (C cleansed `mp_buf`).
- **M3:** the logout frees ended operations on the user's keys too: their MAC stream or cipher context held the key. In `crypt.rs` as well.
- **L1:** `Md::finish` copies only after a digest that fits (it sliced before checking).
- **L2:** `Params` keeps its ints in a Vec behind one raw pointer and carries the octets' lifetime.
- **L3:** every use of an operation on a user's key, logged out or as SO, ends it (0x91), a backstop to the logout's sweep that a concurrent Init could slip past on the DIV-001 login rollback. In `crypt.rs` as well.
- **L4 (in part):** `p11_divs.c` DIV-001 cases 7 and 8 (an audited verification, a signature in parts).
- **N2:** the ECDSA DER parser's unreachable two-byte length is gone.
Recorded, not applied:
- **L4 rest:** no asymmetric private-key operation is taken across a logout in `p11_divs.c` (step 4m's `life signfinal ed after logout` is one).
- **N1:** the slot code is the second copy of `crypt.rs`'s; one generic table before slice 6 makes a third.
- **N3:** a failing HMAC leaves `*pulSignatureLen` as passed, where C set it; that failure cannot happen.

## Slice 6: key generation, creation, wrap and derive

### 6a: C_GenerateKey and C_GenerateKeyPair

- **Golden first:** `tests-support/hybrid/p11_keys.c` (harness step 4n), written from the C before the port: every argument and template check in order, each secret mechanism and length (AES, generic, HKDF, DES3, PBKDF2 with each PRF and parameter shape), each pair mechanism (RSA bits and exponents, EC curves by OID and the refusals, Ed and X curves by OID and name, ML-KEM, ML-DSA and SLH-DSA by selector and name), the flags and nested templates, sessions, roles, fork and finalize; each key's 41 attributes. A handle prints as its distance from the last handle written and a refusal as the change in the object count, so a key that a DIV now refuses renumbers no later row, while a key added and destroyed on the way still shows as a gap.
- **The port:** `p11/src/ffi/keygen.rs`, in C's check order, under the shared API lock with DIV-051's and DIV-053's gate; `hybrid.mk` moves both to the Rust-owned list, `interface.c` forwards them. The template helpers only these two use (`fhsm_compute_usage`, `fhsm_apply_token_scope`, `fhsm_parse_unwrap_template`, `fhsm_apply_ed_curve_name`, the length checks, the parameter sets) are here; the ones copy already had (`check_trusted`, `check_ro_token`, the allowed mechanisms, the nested templates, the encapsulation flags, the dates) are `copy.rs`'s, now `pub(super)`.
- **Crypto:** `pqhsm_crypto::keygen`: EVP keygen by name, EC by curve, RSA by bits and exponent, the DER encodings (cleansed before they are freed), and C's curve matcher (`match_curve_ex`, `fhsm_ec_curve_refusal`: P-256/384/521, any other prime curve of 256-521 bits OpenSSL serves except SM2, the named refusals 0x140).
- **Kept as C:** the handle written before the nested templates and scope are applied (a failure there destroys the key but leaves the handle); the SO can generate keys; an unknown template KEY_TYPE for AES or generic keygen ignored; DES3 in the all-mechanisms build only; a private key's DERIVE by default (not PQC, #125).
- **DIVs:** DIV-052 (a pairwise failure latches ERROR), DIV-064 (PBKDF2 key type and length), RULE-006 (iterations past 32 bits 0x71), RULE-014 (strict: generic under 14 bytes 0x62, and `C_GetMechanismInfo` advertises 14-64 through the shim's wrapper, user: "Advertise 14-64 (Recommended)"), RULE-015 (RSA e odd, 2^16 < e < 2^256, and used), RULE-017 (a parameter-set name of another family 0x13, before any key is made). DIV-001: the pairwise check's record before the pair is stored.
- **Tests:** `p11_divs.c` DIV-052, DIV-064, RULE-006, RULE-014, RULE-015, RULE-017 and DIV-001 case 9, each failing on C. DIV-052's fault: the test binary is linked `-rdynamic` and defines `EVP_PKEY_decapsulate`, which the module's libcrypto calls bind to first; nothing in the module changes for it. Unit tests: the parameter sets, the exponent bounds, the usage defaults, the curve matcher, both DER halves.
- **Golden:** step 4n identical to C less the recorded rows (DIV-050's SO handles and token key, DIV-051, and each DIV above). Harness p4s6c: 106/106, the 25 DIV tests each failing on C, TSan 0; audit corpus 62 same and 6 DIFF, the five before plus `test_generic_secret_len` (RULE-014: C makes 13 more keys).
- **Untested by the harness:** the all-mechanisms profile's DES3, X25519/X448 and composite pairs.

### Slice 6a review (architecture critic, 2026-11-06)

No High findings. Applied:
- **M1:** in the strict build, CKA_EC_PARAMS holding a known curve's OID with bytes after it was 0x140; C's `fhsm_ec_curve_refusal` takes only a whole OID as a curve, so it is 0x13. `ec_curve` now takes `strict` and follows C's match-then-refuse; unit test both builds.
- **M2:** a key OpenSSL does not make prints C's `[freehsm-c] C_GenerateKeyPair: key generation failed.` with the mechanism and OpenSSL's reasons (field issue #5), which also empties the thread's error queue (`keygen::report_keygen_failure`).
- **M3:** the golden printed a stored handle as `h`, which could not tell refuse-before-store from store-then-destroy. Each handle is now its distance from the last handle written: a key a DIV refuses renumbers nothing, a transient object shows as a gap (step 4n's `unwrap templates` and `dates` start at +4 after the destroyed `allowed mechanisms` keys, on both). DIV-050's token key after the logout reload is recorded (+4 on C, +0 on the hybrid).
- **L1 (hardening):** the DIV-052 interposer aborts if it cannot find libcrypto's own function, instead of recursing into itself.
- **L2:** the private DER is made after the public and goes straight into the zeroizing `Pair`.
- **L5:** the class, key-type, flag and usage constants come from `attrs.rs` instead of being redefined.
- **L6:** RULE-014's test detects the build (DES3 keygen is 0x70 only in the strict one) and expects 1-64 in the other.
- **Nits:** the curve matcher's C names in these notes; `state::cnum` shared; the RSA unit test asks for e = 2^17+1, which a FIPS provider also makes.
- **L3 (decision):** RULE-014's floor stays on `CKM_GENERIC_SECRET_KEY_GEN` (user: "Record as limited (Recommended)"); see DIVERGENCES.

Recorded, not applied:
- **M3, DIV-001 case 9's object count:** the failed audit write latches ERROR, which refuses a find, and the pair would be session objects a restart drops; the unwritten handles are what the test can see.
- **L1, the audit record of DIV-052's KAT_REPORT:** the code writes it before the latch; no test reads `audit.log` for it.
- **L4:** `composite_pair`, X25519/X448 and DES3 run in no test (the all-mechanisms build is not in the harness).
- **Nit:** `ED_CURVES`/`ECM_CURVES` move next to `APPROVED` when 6b's `C_CreateObject` needs them; RULE-014's 14 is in `keygen.rs` and the shim.

### 6b: `C_CreateObject`

- **Golden:** step 4n scenario 3 (`p11_keys.c` `s_create`), written from `src/fhsm_pkcs11.c:3559-4138` before the port: every builder (EC public, bare, off the curve, on another or an unsupported curve; EC private from its scalar, zero, on a larger curve, unsupported curves, no curve; Edwards by OID and by curveName; X25519; RSA public and components; ML-KEM, ML-DSA and SLH-DSA raw and SPKI, the parameter set agreeing or not; the SO's trusted keys), each new object dumped. The keys are made in the driver by libcrypto, so their material prints as its length and step 4n links `-lcrypto`. C is deterministic run to run.
- **Port:** `p11/src/ffi/create.rs` in C's order (token, template, RO, private login, trusted, attribute lengths, parse, the PQC parameter-set requirement), then C's three builders. Each ends in `Store::finish`: the handle written, then allowed mechanisms, nested templates, encapsulation flags (DIV-066: C skipped them on a rebuilt key), the Edwards curveName (not for a certificate), scope, metadata, usage, the object destroyed if a step fails. The libcrypto half is `crypto/src/ffi/import.rs`: `Pkey::raw_private`, `from_data` over `OSSL_PARAM_BLD`, `ec_from_scalar` (`fhsm_ec_priv_from_scalar`), `check`; `raw_public` and `is_a` are slice 5's (`sig.rs`), `ec_curve` slice 6a's. `fhsm_ec_curve_refusal` is `ec_curve(der, true)`: anything but `Invalid` is a curve. `fhsm_parse_create_attrs` stays for `fuzz/fuzz_create_attrs.c`.
- **DIV-065:** an RSA public key passes `EVP_PKEY_public_check` (C ran it for EC and Edwards only), an RSA private key `EVP_PKEY_pairwise_check` (C trusted `EVP_PKEY_KEYPAIR` to check), and one without all five CRT components is 0xD0 before OpenSSL (C: 0x6 at `i2d_PrivateKey`). Test `p11_divs.c` DIV-065, which now links `-lcrypto` for its keys (libcrypto declared by hand there: `evp.h`'s `EVP_PKEY_decapsulate` would clash with DIV-052's interposer).
- **RULE-017 reaches here:** `pset_read_in` (6a's `pset_read` with C's buffer size: 64 here, 32 for key generation) is shared, so a parameter-set name of another family is unknown on import too (C took any of the eighteen, then compared names or lengths). No golden row names one.
- **Shortcuts:** a BIGNUM or builder allocation failure in `from_data` is `None`, so 0x13 (C: HOST_MEMORY or FUNCTION_FAILED), reachable only out of memory. `ED_CURVES`/`ECM_CURVES` and the other helpers create shares with keygen stay in `keygen.rs`, now `pub(super)`.

### Slice 6b review (architecture critic, 2026-11-07)

The unsafe code in `import.rs` was found correct (builder lifetimes, BIGNUM ownership, every early return freed, the DER wiped after `add`). Applied:
- **H1 (decision):** DIV-065's checks are the loaded provider's; under the FIPS provider they are SP 800-56B's, so a signed module also refuses e = 3, short moduli and a d computed mod φ(n). Recorded per provider in DIVERGENCES (user: "Record per provider (Recommended)"); unverified until a FIPS run.
- **H2:** C's create reads CKA_PARAMETER_SET into 64 bytes, key generation into 32. `pset_read` had 32 everywhere, so a NUL-padded `char[32]` name was 0xD1 on import; `pset_read_in` takes the size, unit test.
- **M1:** the golden's `rsa priv extractable` gave only n, e and d, so no successful row set EXTRACTABLE or ALWAYS_AUTHENTICATE on a rebuilt private key; it now has the CRT five (0 on both, SENSITIVE, EXTRACTABLE and ALWAYS_AUTH read 01).
- **M2 (decision):** C dropped CKA_ENCAPSULATE FALSE on a rebuilt public key: DIV-066 (user: "Fix as DIV-066 (Recommended)"). `Store::finish` lost its `encap` switch.
- **L1:** the key type is compared whole (`key_type`), as C compared the CK_ULONG; it is narrowed only where C narrowed it, at the store.
- **Nits:** `first_set` was `bbool` once `check_lengths` has run, so it went; the RSA parameter names are `import::RSA_PARAMS`, once.

Recorded, not applied:
- **L2:** the OSSL_PARAM array holding d, the primes or an EC scalar is freed without wiping (C the same). libcrypto 3.5 exports no `OSSL_PARAM_clear_free`; the BIGNUMs and the DER are wiped.

### 6c: `C_WrapKey` and `C_UnwrapKey`

- **Golden first:** step 4n's scenario 4 (`p11_keys.c` `s_wrap`, commit before the port): wrap by AES-KW, KWP and RSA-OAEP over keys made from fixed bytes, so each AES blob prints whole; every refusal in C's order, the wrapping key's and the unwrapping key's templates, WRAP_WITH_TRUSTED under an SO-made trusted key, the SO and the logged-out session; then the unwrap template, each blob and length, and each new key's attributes. It found DIV-067. RSA PKCS#1 v1.5 and X.509 wrap are refused by the strict build the harness runs (0x70), so their bodies are covered only by reading.
- **Port** (`p11/src/ffi/wrap.rs`): both entry points in C's order, the RSA transports (`:8631-8829`) inline. AES-KW runs on `crypt.rs`'s `keyed` and `run`; OAEP on `PkeyCtx::oaep`. Its own: `fhsm_check_wrap_tmpl` with `fhsm_read_obj_attr` (`obj_attr`), `fhsm_check_nested_tmpl` for the unwrap, `kw_iv_from_mech`, and `fhsm_oaep_params_from_mech`, which takes a label of any length (Init's copy caps it at 64, the wrap's never did; unit test).
- **DIV-050:** both keys of a wrap and the unwrapping key are refused (0x60) before C's first key check, so a logged-out wrap is 0x60 where C said 0x101, and the SO's is 0x60 where C wrapped. In the unwrap the check runs where the token is first there, before C's three key checks, which C ran without one.
- **DIV-058:** a target without EXTRACTABLE is 0x6A where C checked only SENSITIVE and not EXTRACTABLE. That also refuses a public key and a data object, which carry no EXTRACTABLE; C wrapped both.
- **DIV-067:** CKA_CLASS other than CKO_SECRET_KEY is 0xD1, a key type outside the five secret types 0x13; both checked on the whole CK_ULONG, after the unwrap, where C read the type.
- **DIV-001:** a wrap's blob is made in scratch and recorded (EV_WRAP 44) before it reaches the caller; an unwrapped key whose record (EV_UNWRAP 45) fails is destroyed and the call is 0x30. A size query has no record, as C. Tests: `p11_divs.c` DIV-001 cases 10 and 11.
- **RULE-059 completed:** a key from `C_CreateObject` (secret or private) or `C_UnwrapKey` starts with both history bits (`attrs.rs` `imported`), so it reads ALWAYS_SENSITIVE and NEVER_EXTRACTABLE FALSE, per PKCS#11. Slice 6b missed the create half; it lands here. Recorded rows: step 4n scenarios 3 and 4, step 4i's `aes-s` and `gen`.
- **Shortcut:** an RSA unwrap whose blob length exceeds `isize::MAX` is 0x110 without being read (a caller lying about its buffer; C handed it to OpenSSL).

### Slice 6c review (architecture critic, 2026-11-07)

Nothing high: every path traced against C, the five divergences where their entries put them, the unsafe code sound. Applied:
- **M1:** no test refused the key being wrapped (every DIV-050 case wrapped under a user key, refused first). `p11_divs.c` DIV-050 now has the SO wrap the user's key under an RSA public key with OAEP: 0x60. Without the target check, the hybrid would answer 0x6A (DIV-058). C answers 0x60 here only because its SO had destroyed the key earlier in the test.
- **L3:** the OAEP digests are fetched (`md_known`), as C's `fhsm_oaep_params_from_mech` and `crypt.rs` do, so an unfetchable one is 0x71 before the size query.
- **L4:** a label past C's `(int)` cast is 0x6 before it is read, a recorded shortcut.
- **Nits:** `aes_name(..).ok_or(..)` in place of `expect` (no panic site across the FFI); `audited` for the unwrap's record; `imported` before `set_usage`, as in `create.rs`; `OBJF_UNWRAP_SENS` from `keygen.rs`; DIV-067's entry states the whole-CK_ULONG comparison, with a test (2^32 + CKK_AES: 0x13; C stored it as AES).

Recorded, not applied:
- **M2:** DIV-001 case 11 checks the 0x30 but not that the key is gone. The failed write latches ERROR, which refuses every later find in that process, and the destroy's result is ignored as C ignored it.
- **L5:** `kw_iv`, `oaep_params`, `raw_ctx` and `rsa_run` repeat `crypt.rs`'s Init-side code with different codes and no label cap. Merging them means giving the Init parse optional switches; left until slice 7 needs a third caller.
- **L6:** RSA PKCS#1 v1.5 and X.509 wrap and unwrap are refused by the strict build the harness runs, so their bounds (11 bytes, the 1024 cap, the zero strip, the blob length) are checked by reading only. A unit test needs a token. Due with the all-mechanisms harness.
- **Nit 10:** the OAEP label is a plain `Vec`, as C did not wipe it either.
- **Gaps:** no rows for OAEP parameter refusals other than none at all, or for a KW blob of exactly 4104 bytes.

### 6d: `C_DeriveKey`

- **Golden first:** step 4n's scenario 5 (`p11_keys.c` `s_derive`, commit 3afecfb before the port): HKDF (every parameter check, salt kind, digest, length bound, class and key type), the concatenation family (each operand form, the 4096 bound, XOR's data-sets-the-length) and ECDH (each peer-point form: SPKI, bare, compressed, short and long DER OCTET STRING; off-curve, garbage, wrong curve), over keys made from fixed bytes and EC points computed from fixed scalars, so each derived value prints whole. A key that becomes sensitive on one side is also wrapped under a fixed key, so its value shows as the blob. It found DIV-068 and the second-key half of DIV-057.
- **Port** (`p11/src/ffi/derive.rs`): the entry point and `derive_store_secret` (`Store::store`) in C's order. HKDF is `pqhsm-crypto`'s new `prim::hkdf` (checked against RFC 5869's first vector); ECDH is `Pkey::derive` and `Pkey::group`, also new, over `sig.rs`'s and `import.rs`'s `Pkey` helpers for the peer. `fhsm_check_key_mech_type` reduces, for the combiners, to "the base is CKK_GENERIC_SECRET", inline. `wrap.rs`'s nested-template check now takes which template (`check_nested`), and `attrs.rs`'s `imported` is `mark` with both bits.
- **DIV-050:** the base is refused (0x60) where the token is first there, before C's three key checks, as the unwrap: logged out is 0x60 where C said 0x101, the SO's derive 0x60 where C derived. The salt key and the second key are read only after the base, which is always a secret or private key, so they need no check of their own.
- **DIV-057:** a derived secret key is SENSITIVE if a secret input is (the base; for CKM_CONCATENATE_BASE_AND_KEY the second key too, §6.20.1); SENSITIVE FALSE from such an input is 0xD1. It is ALWAYS_SENSITIVE and NEVER_EXTRACTABLE only if every input was, kept as RULE-059's history bits (`mark`) after the object's metadata. CKA_CLASS = CKO_DATA is 0xD1 but for CKM_HKDF_DATA, whose data object reads as C (no history). Every EC private key is sensitive, so `test_ecdh_peer_point` and `probe_ecdh_curves` derive with SENSITIVE FALSE and get 0xD1: the harness runs patched copies (`inner.sh`). The probe's leaves SENSITIVE out; the peer-point test's also reads each secret through a wrap and an unwrap (`div057_peer_value.c`), so its three value checks still run. DIV-057's entry had planned only the first change, which would have left the value reads at 0x11.
- **DIV-068:** a CKA_KEY_TYPE outside the five secret types is 0x13, compared whole; a CKK_AES value that is not 16, 24 or 32 bytes, or a CKK_DES3 value that is not 24, is 0x62. Both at C's key-type read, before the object is added.
- **DIV-001:** a derived object whose record (EV_DERIVE 46) fails is destroyed and the call is 0x30. Test: `p11_divs.c` DIV-001 case 12.
- **RULE-020:** the derive bounds (HKDF 1..255·HashLen, extract-only HashLen; the combiners 1..4096) are kept as C has them; the rule's fix is at the ML-KEM truncation, slice 7.
- **Tests:** `p11_divs.c` DIV-057, DIV-068, DIV-050's derive step, DIV-001 case 12. `user_key` and DIV-050's session key now carry CKA_DERIVE, which no other check reads.
- **Shortcut:** an ECDH peer point longer than `isize::MAX` breaks `from_raw_parts`' contract (a caller lying about its buffer; C handed it to d2i).

### Slice 6d review (architecture critic, 2026-11-07)

Every path traced against C (:4277-4878); the four divergences where their entries put them; no memory-safety finding. A background security review raised H1 too. Applied:
- **H1:** the combiners could copy a sensitive, non-extractable base into an extractable key (empty data, or XOR with zeros), which `C_WrapKey` then exported. Now 0xD1, recorded as a widening of DIV-057's scope (PKCS#11 §6.20). Test: `p11_divs.c` DIV-057 (C: 0).
- **M1:** `div_057` now checks NEVER_EXTRACTABLE both ways (the derived key's own EXTRACTABLE TRUE clears it) and two clean inputs (both keys generated sensitive: ALWAYS_SENSITIVE and NEVER_EXTRACTABLE TRUE, the no-`mark` path the golden never reaches); `div_068` checks DES3's size (16 bytes: 0x62).
- **L1:** an input whose flags cannot be read fails the derive (C ignored it; read as 0, the key would have been neither sensitive nor ever extractable).
- **L2:** the AES/DES3 size rule is `wrap.rs` `size_ok`, for unwrap (0x63, DIV-067) and derive (0x62, DIV-068).
- **L3:** DIV-068 applies to keys only, as its entry says; a data object's KEY_TYPE is stored as C. ECDH on P-384 with CKK_AES is 0x62, now in DIV-068's entry.
- **Nits:** `secret` borrows for the caller's lifetime, not `'static`; `TEMPLATE_INCOMPLETE` from `keygen.rs`.

Found by the harness, not the review: the patched `probe_ecdh_curves` left `t_false` unused, which `-Werror` refused, and the failed build skipped every test binary after it (p4s6k: 70/106). The patch now drops the declaration too, and both copies are compiled with the build's flags before a run.

Recorded, not applied:
- **M1 (part):** DIV-001 case 12 does not check that the object is gone: the failed write latches ERROR, so no later call can look (as 6c's M2).
- **L4:** the history bits are written after the object is stored; recorded in RULE-059's row.
- **Security review, second finding:** the salt key and second key get no DIV-050 check of their own. Both are read only after the base passes it, so the session is already the user's; a mechanism allow-list check on them would go past C and the spec.
- **Nits:** `check_nested` still takes `bit` beside `which`; the two `store` calls in `derive_concat`; `param`/`guarded` beside the inline readers in `keygen.rs`, `wrap.rs` and `crypt.rs`. The fragment does no `dlsym` NULL checks (a missing symbol crashes the test, which fails it); AES-KW fits the P-256 and P-384 secrets the test uses.

### 7: `C_EncapsulateKey` and `C_DecapsulateKey`

- **Golden first:** step 4n's scenario 6 (`p11_keys.c` `s_kem`, committed before the port): ML-KEM keys of all three parameter sets from fixed seeds, imported raw, and each one's ciphertext from an encapsulation with fixed entropy (OpenSSL's `ikme`), so every decapsulated secret prints whole beside libcrypto's own; the module's random encapsulations print their length, and two round trips (a seeded key, a generated pair) compare the two secrets. Then every check in C's order for both entry points, the ciphertext's size query and bounds, an altered ciphertext (ML-KEM's implicit rejection, a fixed secret too), the new key's template one attribute at a time and what it then allows, the read-only session, logged out and the SO. It found DIV-069. DIV-066 shows here too: the key imported with ENCAPSULATE FALSE, now kept FALSE by the Rust `C_CreateObject`, is refused (0x68) where C's encapsulated.
- **Port** (`p11/src/ffi/kem.rs`): both entry points in C's order, sharing `key` (the guards up to the key's flag). OpenSSL's KEM calls are `PkeyCtx::kem_init`, `encapsulate` and `decapsulate`, new in `pqhsm-crypto`; the private key loads as DER, else by C's raw fallback (`expanded`, the parameter set by the length). The secret is stored by `derive.rs`'s `Store`, now shared, whose audit record became optional (`event`: the KEM calls have none, as C).
- **DIV-050:** the key of either call is refused (0x60) if it is a secret or private key and the token is not the user's, where the token is first there, before the role check, as derive's base: a decapsulation logged out is 0x60 where C said 0x101, the SO's 0x60 where C made the key; a private key handed to encapsulate logged out or as the SO is 0x60 too (C: 0x101, 0x63). A public key is anyone's, so encapsulation to one keeps C's answers.
- **RULE-037(a):** CKA_TOKEN TRUE from a read-only session is 0xB5, among the template guards, before the encapsulation; C made a token object.
- **DIV-069** (RULE-020's ML-KEM site): `Store::store` refuses a class other than CKO_SECRET_KEY (0xD1), a key type outside the secret types compared whole (0x13), an AES or DES3 key of the wrong size (0x62), and applies the template's usage and metadata, which C's copies of the store dropped: `decap encrypt false` reads ENCRYPT FALSE and may not encrypt (0x68); dates read back; a malformed date is 0x13 after the add (the handle written, the key destroyed). CKA_VALUE_LEN keeps C's truncation, before the store so the size check sees the truncated key.
- **RULE-058:** preserved: no sensitivity is inherited, so a KEM secret is SENSITIVE FALSE unless the template says otherwise, and readable when EXTRACTABLE. C's comment saying otherwise (`:5459`) is not carried over.
- **Tests:** `p11_divs.c` DIV-069 (CKO_DATA 0xD1, CKK_EC 0x13, a 5-byte AES key 0x62, an AES-128 key with ENCRYPT FALSE then 0x68 at EncryptInit, a token object from a read-only session 0xB5) and DIV-050's decapsulation step; `kem_pair` makes their keys.
- **Shortcut:** the ciphertext becomes a slice only after its length is checked against the key's parameter set, so a lying length is 0x41 as in C; only a key of no known set (none reaches here) would skip that check.

### Slice 7 review (architecture critic, 2026-11-07)

Nothing high: every path's order and codes as C's, the four divergences where their entries put them, nothing `Store` does with the mechanism firing for CKM_ML_KEM, no legacy test affected by a DIV. Applied:
- **M1:** DIV-069 records usage, so a KEM secret derives only with CKA_DERIVE TRUE (PKCS#11's default, as every other secret key; C allowed any). Recorded in DIV-069's scope, tested in `p11_divs.c` DIV-069 (HKDF from a decapsulated secret: 0x68 without CKA_DERIVE, 0 with it; C: 0, 0).
- **M2:** C's raw-key fallback pointed its parameter at the stored key; the port's went through `Pkey::from_data`, whose parameter block copied the 1632-3168 byte key and freed it unwiped. Now `Pkey::expanded_private` (`sig.rs`, sharing `raw_public`'s body) points at the key, as C. (`OSSL_PARAM_clear_free`, the other fix offered, is not in this libcrypto.)
- **L1:** the ciphertext is made a slice only after its length is checked against the key's parameter set, so a length past `isize::MAX` is 0x41, as C, not undefined behaviour.
- **L2:** `pulCiphertextLen` stays a pointer, read and written where C did: a caller passing one address for it and `phNewKey` no longer aliases a `&mut`.
- **L3:** DIV-050's status and these notes say what the code does: a secret or private key handed to either call is refused for anyone but the user.
- **L4:** no audit record for the KEM calls, as C, now stated in DIV-069's scope.
- **Nits:** the storage constants come from `attrs.rs`; `PkeyCtx::new`'s errors pass through; its `enc` documented for a KEM; `div_069` makes its session with `user_key` without keeping the key.

Recorded, not applied: `from_data`'s unwiped parameter block also holds the RSA private parts `C_CreateObject` imports (`create.rs`); it needs a builder that wipes, due with the next change there.

### 8a: the mechanism calls, random and the stubs

- **Golden first:** step 4o (`p11_misc.c`, committed before the port): the mechanism list (slot, NULL count, size query, short and fitting buffers), the info of every advertised mechanism and the refusal of every other type below 0x4400, random and seed (bad, closed and read-only sessions, NULL, zero), the three stubs, each after `C_Finalize` and in ERROR. C prints the same twice; the hybrid less RULE-014's, DIV-051's and DIV-053's rows (`p11_misc_expect.sed`).
- **The table:** `scripts/gen_mechs_rs.py` imports `MECHANISMS` from the legacy `scripts/gen_p11_thunks.py` (unchanged, Q4; no bytecode left behind) and writes `core/src/mechs/table.rs` (105 rows: value, family, operations, approved, whether the source gives it a handler), sorted as C's. `--check` says whether the checked-in file is current. `core/src/mechs.rs` is `fhsm_mechanism_lookup` (the type narrowed to 32 bits, as C), `fhsm_mech_flags_for` and `fhsm_mech_keysizes_for`; a row is dispatchable when it has a handler and, in the strict build, is approved (C's generator pointed the rest at `dispatch_reject_fips`).
- **Port** (`p11/src/ffi/misc.rs`): the seven entry points in C's order. `advertised` is C's: dispatchable, the ECM family only if X25519 and X448 load (`ecm_available`), a digest only if its hash fetches (`md_available`). The list is computed once per call where C walked the table twice; the same answer.
- **DIV-051 and DIV-053:** now the entry points' own checks under the lock (`initialized` for the two mechanism calls, `gate` for the other five), which retires the shim's GATE/STATUS wrappers and `pqhsm_p11_gate`; `hybrid.mk` renames nothing any more.
- **RULE-014:** the 14-byte minimum for CKM_GENERIC_SECRET_KEY_GEN in the strict build moved from the shim into `pqhsm_C_GetMechanismInfo`.
- **Tests:** `p11_notinit.c` DIV-051 and DIV-053 (C fails, hybrid passes), `p11_divs.c` RULE-014, `core` `mechs::tests` (sorted and found, flags ORed, the strict profile).

### Slice 8a review (architecture critic, 2026-11-07)

Nothing high: every path's order, codes and writes as C's; the profile rule equals the generator's substitution row for row (`src/gen/fhsm_dispatch.c` against `table.rs`: only the 13 rows not approved differ, `dispatch_reject_fips` there, `approved: false` here); flags and key sizes arm for arm; no C entry point left ungated (all 62 are in `PQHSM_P11_RUST`); the gate now under the lock, which closes the race the shim's shortcut admitted. Applied (user: "keep going and select the recommended option"):
- **M1:** step 4o ran only the strict profile, where the non-strict arm of `dispatchable`, TDES's key sizes and the ECM probe are never reached. New step 4p runs `p11_misc` on unsigned all-mechanisms builds of C and the hybrid, against the same recorded rows less RULE-014's (the finalized rows' counts made profile-free). Not applied: the same run in step 9's FIPS loop, which alone reaches the probes' provider-absent branches; it needs `/debs`, which this environment does not have (the fetch is not approved), so it would be code no run checks. Due when the FIPS provider is available.
- **M2:** a stale `table.rs` printed STALE and failed nothing; the 4o line now says FAIL.
- **L1:** the golden pins the 32-bit narrowing: `0x100000250` is SHA-256's info, `0x100000350` the GENERIC family's minimum 1 (RULE-014 compares the type whole).
- **L2:** stale comments in `hybrid.mk` and `p11_misc_expect.sed`.
- **Nits:** the generator refuses an unknown argument rather than overwrite the table; `misc.rs` cites `:1455-1653`.

### 8b-i: the operation-table hooks removed

- `pqhsm_c_session_ops_reset`, `_has_active_op`, `_ctx_auth_grant`, `pqhsm_c_ops_forget_all` and `_release_all` (`p11/shim/pkcs11_tu.c`) reached C's operation tables, find state and OAEP tables. Only C's entry points fill those, and since 8a none runs, so every hook read zeros and reset nothing. Removed with their calls (`login.rs`, `lifecycle.rs`) and declarations (`sys.rs`).
- The one answer they gave that could differ, `fhsm_session_has_active_op`'s -1 for handle 0 or one past its tables (`:2161-2165`), is now `context_login`'s own check against `core::session::MAX`, the 129 C's tables were built with (RULE-091, `hybrid.mk`). Golden: step 4h's `s_context` ("context bad handle 0", "context bad handle 999").

### 8b-ii: the attribute readbacks in Rust

- `crypto/src/ffi/readback.rs`: the OpenSSL calls of `extract_pubkey_attr` (`:6951-7120`), `extract_cert_attr` (`:7128-7151`), `fhsm_pset_selector_of` (`:6505-6526`) and the shim's `pqhsm_c_pqc_raw_pub`: `Pkey::bn`, `octets`, `group_oid`, `raw_pub`, and `cert_field`. `p11/src/ffi/attrs.rs` keeps C's branches (`pubkey_attr`, the CKA_VALUE, CKA_PARAMETER_SET and certificate arms); the four wrappers leave `pkcs11_tu.c`, which keeps only the audit switch.
- C's -1/-2/0 contract is `Option<Vec<u8>>`: `two_pass` answers the length to a size query, copies into a buffer that fits, and answers CK_UNAVAILABLE_INFORMATION with rv unchanged otherwise. -1 and -2 differed only in the size query, where None is unavailable and Some its length.
- Golden: step 4n scenario 7 (`s_attrs`, committed first): fixed RSA, EC (P-256, P-384, P-521's long-form point, secp256k1), Edwards by OID and by name, Montgomery, ML-DSA, ML-KEM raw and SPKI keys and a fixed certificate, each read-back attribute sized, read one byte short and read whole. Identical less RULE-059's history bits on its 11 private keys.

### Slice 8b review (architecture critic, 2026-11-07)

Covering 8b-i and 8b-ii. No defect in the port: every branch, failure and edge (an empty or over-256-byte point, a failed flags3 read, a raw key over 2592 bytes, the SLH-DSA order) as C's, every pattern constant a const. Applied (user: "keep going and select the recommended option"):
- **H1:** a session's find is not cleared when its handle is reused; C clears `g_finds[h]` in `fhsm_session_ops_reset` at open and close (`:8987`, `:786`, `:798`). Slice 2a's note said the opposite. Fixed in the next commit, with its golden row.
- **M1:** a buffer too small for these ten attributes answers CKR_OK with CK_UNAVAILABLE_INFORMATION, where every other attribute answers 0x150. A DIV, after H1.
- **M2:** stale comments in `sys.rs`, `hybrid.mk` and the slice 2a/2b notes.
- **L1:** the certificate subject from the DER: kept as C (`DIVERGENCES.md`, Phase 4 table).
- **L2-L5:** `group_oid`'s lookups stop at the first, as C's; flags3 read for Edwards keys only; the functions openssl-sys binds imported, not redeclared; a test of `octet_string`'s long form.

### Slice 8b review H1: a session's find cleared at open and close

- C's `fhsm_session_ops_reset` (`:8975-8989`), called by `C_OpenSession` (`:786`) and `C_CloseSession` (`:798`), clears `g_finds[h]` with the operation tables. Since slice 2a the find state is `objects::FINDS`, and only finalize and fork cleared it, so a handle's next session inherited a find left open: `C_FindObjectsInit` answered 0x90, and `C_FindObjects` the old session's handles, found under its login. Slice 2a's note read C the wrong way round (corrected above).
- `objects::reset_find(h)`, called beside `digest`/`crypt`/`sign::reset` in `pqhsm_C_OpenSession` and `close_session` (`login.rs`), where C reset.
- Golden: step 4i `s_find` gains "ro find left open" ... "reopened find init" (C 0; the hybrid answered 0x90 before the fix). A port fix, not a DIV: the hybrid now answers as C.

### DIV-070: a short buffer for an OpenSSL readback is 0x150

- The slice 8b review's M1. C's two-pass extractors answered a buffer too small with CK_UNAVAILABLE_INFORMATION and CKR_OK, where every other attribute answers 0x150. The modulus, its bits, the exponent, the EC params and point and the certificate's subject, issuer and serial now give their bytes to `C_GetAttributeValue`'s common copy, so `two_pass` is gone: a size query, a fitting buffer and a short one are answered as for every other attribute.
- Test: `p11_divs.c` DIV-070 (C fails, hybrid passes). Recorded rows: step 4i's ten 1-byte reads, step 4n scenario 7's 36 short reads.

### 8c: the unlink

- `hybrid.mk` compiles no C of `src/fhsm_pkcs11.c`: `fhsm_pkcs11.o` is the export shim (`p11/shim/interface.c`) and `p11/shim/build_config.c`, which defines the two constants the Rust read from the C: `pqhsm_c_audit_mandatory` (`FHSM_AUDIT_MANDATORY`, `include/fhsm_common.h`'s default, 0 under `make audit-switch`) and `fhsm_build_fips_strict` (0 for `PROFILE=all-mechanisms`, else 1: the formula the Makefile's `check-profile` asserts the generated `src/gen/fhsm_dispatch.c` holds; the object depends on the generated `src/gen/fhsm_dispatch.c`, which regenerates on a change of profile, as the legacy chain through `gen/fhsm_dispatch.o` did, so `check-profile` still holds: review H1). Recommended over cargo features, whose build a change of profile would not invalidate. `p11/shim/pkcs11_tu.c` is deleted.
- Emptied with §1's: `fhsm_ecdsa_raw.o`, `fhsm_pq_params.o`, `gen/fhsm_dispatch.o`, and (Q16: not ported) `fhsm_mode.o` and the twelve `src/dispatch/*.o`. `tests/test_conf` unit-tests `fhsm_mode.c` through `$(LIB_OBJ)`; its link alone takes the C object (`fhsm_mode_unit.o`), so the module carries none.
- `-DFHSM_MAX_SESSIONS=129` is gone: nothing compiled reads it (`tests/test_session_cap.c` names it in comments only).
- Exit (§1): `nm -D` 63 symbols, the same list as C's; NEEDED identical; no object of the legacy C files in the module (each emptied object holds no symbol, `fhsm_pkcs11.o` the export forwarders and the two constants). The C linked is the shims: export (`interface.c`, `build_config.c`), audit's variadic entry point, the KAT results export, and the integrity digest section.

### Slice 8c review (architecture critic, 2026-11-07)

`PQHSM_FIPS_STRICT` equals the generator's value for every profile and alias; `test_conf`'s link order, the flag's removal and the C still linked (the shims, and the service's read of `fhsm_build_fips_strict`, now `build_config.c`'s) checked. Applied (user: "keep going and select the recommended option"):
- **H1:** with `gen/fhsm_dispatch.o` emptied nothing depended on `src/gen/fhsm_dispatch.c`, so a hybrid build that changed profile (step 4p) never regenerated it and stopped at `check-profile`. `fhsm_pkcs11.o` now depends on the generated source instead of the stamp.
- **M1:** nothing ran the hybrid with `-DFHSM_AUDIT_MANDATORY=0` (`make audit-switch` recurses without `-f`). New step 4q: C and the hybrid built that way on fresh copies, `tests/audit_switch.sh optional` on each.
- **M2:** §1's exit sentence says what the 8c note does: no object compiled from the legacy C sources; the shims stay C.
- **L1-L3:** RULE-091's record notes the flag's removal; `hybrid.mk`'s header says "in the module"; an emptied object holds no symbol.

### Contract tests (harness step 11, 2026-11-07)

PHASE4_PLAN §5.3, user: "Fetch once (Recommended)". The seven .debs (OpenSC 0.26.1 with libeac3, pkcs11-provider 1.0, p11-kit 0.25.5 with its modules, libglib) were already in `netcache/debs`; `run.sh` checks them against `netcache/debs.sha256` and mounts them read-only, and step 11 installs them offline. It runs before steps 10 and 9, since step 9 replaces the container's OpenSSL configuration.
- `contract.sh LIB` runs, on a fresh token: pkcs11-tool init token, init PIN, `-L`, `-M`, an EC P-256 pair and `-O`; `openssl storeutl` through pkcs11-provider; `p11-kit server` (it needs `XDG_RUNTIME_DIR`), then `-L`, `-M` and `-O` through `p11-kit-client.so`. It prints one transcript with what is random per run replaced (serials, key bytes, PEM, paths).
- Run pct: C 10/10 rc=0, hybrid 10/10. The raw diff is 8 lines, the two recorded divergences a consumer sees, each direct and through p11-kit: DIV-059 (`pin min/max 8/64`) and RULE-014 (generic secret from 14 bytes). Less those, it is identical (`contract_expect.sed`).
- Not covered: signing through a consumer (neither earlier measurement did it), and a token holding a composite key, which pkcs11-provider refuses in its entirety (`docs/THIRD_PARTY_CONSUMERS.md`; upstream's limit).

## Phase 4 exit criteria: status (2026-11-07)

Evidence run `pct`, after the contract tests (`8348cff`): 106/106, `nm -D` (63 symbols) and NEEDED identical, every PKCS#11 probe (steps 4f to 4n) identical less recorded DIVs, all-mechanisms build identical, audit optional C = hybrid, contract 10/10 both, TSan 0 races, corpus 61 same / 7 expected DIFF, 32 DIV and RULE tests "C fails, hybrid passes".

| Brief exit criterion | Evidence | Status |
|---|---|---|
| No C object in the module; `nm -D` the exports plus the documented extras | Slice 8c: no object compiled from the legacy C sources; what stays C is the export shim (`p11/shim/interface.c`) and `build_config.c`'s two constants, as the Phase 1 and 3 shims. `nm -D` = C's 63 | ✅ (shims as noted) |
| Zero unexplained diffs over the call-sequence corpus and the mechanism probe | Steps 4f-4n, 4p (105-row table; all-mechanisms 0x65), corpus: every diff is a recorded DIV, each suppressed by its own `*_expect.sed` rule | ✅ |
| A test failing on C and passing on Rust for every intended divergence | DIV-050 to DIV-070 and the fixed RULE rows in `p11_divs.c` (32 lines); DIV-051, DIV-001 and the fork rows in `p11_lifecycle.c` | ✅ |
| Contract tests: pkcs11-tool, pkcs11-provider, p11-kit | Step 11 | ✅ (enumeration and keygen) |
| `test_concurrency` and `test_apilock` under TSan; cargo-fuzz on the parsers | TSan: step 7, 0 races. cargo-fuzz: **not run**, it needs nightly and cargo-fuzz, not fetched (no approval) | ❌ fuzzing |
| Every P0 rule gated at Phase 4 | All 50, below | ✅ |

**The 50 P0 rules.** Fixed, each with its DIV or RULE test in `p11_divs.c`: RULE-005 and 082 (DIV-054), 006, 014, 015, 017, 020 (DIV-067, 068, 069), 036 (DIV-059), 037 (DIV-056, 069), 041 (DIV-056), 056 and 086 (DIV-050), 059 (DIV-057), 061, 063 (DIV-058), 064 (DIV-057), 071, 072 (DIV-051), 073 (DIV-053), 075 (DIV-052), 076 and 077 (DIV-051, DIV-009, `test_fork_child`), 079 and 080 (DIV-014, 015, 059), 083, 084 (DIV-012, 028, 059), 090 (DIV-055), 091, 092 (DIV-050, 053), 096 (DIV-001: `p11_lifecycle.c` `s_bad_log`, `s_stream`). RULE-035: fixed by construction (the login re-checks under the API lock), with `test_login_conflicts`' 0xB7 and 0xB8. Preserved, each with a C golden plus its legacy test: RULE-016 (`p11_keys` `s_pair`, `test_ec_curve_bounds`, `test_ec_curve_refusal`), 018 (`p11_crypt` `s_init`, `test_gmac_params`), 019 (core goldens, `p11_sign` `s_asym`, `test_ecdsa_verify_edge`), 038 (`p11_objects` `s_set`, `test_wrap_with_trusted`), 039 (`p11_objects` `s_attrs`, `test_sensitive_value`), 040 (`s_set`, `test_copyable_oneway`), 042 and 060 (`p11_crypt` `s_keys`, `p11_sign` `s_init`, `test_attributes`), 043 (`p11_keys` `s_wrap`, `test_unwrap_len`), 055 (`p11_objects` `s_find`, `test_public_objects`), 057 (`p11_objects`, `p11_keys` 0x101 rows), 058 (`p11_keys` `s_attrs`), 062 (`s_wrap`, `s_derive`, `test_nested_templates`), 065 (strict table in 4p and `p11_misc` `s_mechs`; the service part is Phase 6), 070 (`p11_lifecycle` `s_preinit`, `p11_misc` `s_error`), 078 (`token/src/ffi/mem.rs`, `p11/src/ffi/apilock.rs`; `test_concurrency_store` under TSan), 081 (`p11_lifecycle` `s_lockout`, `test_pin_length`), 087 (the CONTEXT_SPECIFIC rows of the crypt, sign and keys probes, `test_always_authenticate`), 095 (step 4q, `s_audit_off`, `s_audit_zero`).

**Open at exit:** fuzzing (above); the older review items (6c L5 and L6, DIV-001's destroy checks, RULE-059's write window, RSA `from_data` parameters left unwiped in `create.rs`); the 8a FIPS-loop run, which needs `FIPS_DEBS`.
