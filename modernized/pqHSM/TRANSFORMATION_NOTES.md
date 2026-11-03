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
