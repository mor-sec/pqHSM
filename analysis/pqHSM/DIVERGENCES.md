# Divergence Register — pqHSM (C → Rust)

*Created 2026-10-30. Required by `MODERNIZATION_BRIEF.md`: each phase's entry criteria need a
preserve-or-fix decision here for every suspected-defect rule gated at that phase.
`/modernize-transform` and the dual-execution harness read this file. The harness suppresses
**only** the exact diffs listed under "Expected harness diff"; any other C-vs-Rust difference is
a failure.*

**Status values**
- **DRAFT:** proposed by Claude, awaiting a human decision.
- **DECIDED:** a human chose. Record who and when.
- **DONE:** implemented, and the divergence test passes.

To decide an entry, set its Status and Decision lines. **An entry left at DRAFT does not satisfy a
phase entry criterion.**

---

## Phase 1 — audit trail (`src/fhsm_audit.c`, `tools/freehsm_audit.c`)

I re-read the cited code for every entry in this section on 2026-10-30.

### DIV-001 · RULE-096 Audit write failure: fail closed

- **Status:** DECIDED (brief Q3, 2026-10-30, mor-sec): fail closed.
- **Legacy:** `fhsm_audit_event` returns `FHSM_RV_FUNCTION_FAILED` and latches ERROR when a write or `fdatasync` fails (`src/fhsm_audit.c:690-737`). All 73 call sites discard that result with `(void)fhsm_audit_event(...)`:

  | File | Call sites |
  |---|---:|
  | `src/fhsm_pkcs11.c` | 45 |
  | `src/fhsm_token.c` | 11 |
  | `src/fhsm_state.c` | 2 |
  | `service/fhsm_service.c` | 15 |

  So the operation that could not be audited still succeeds.
- **Target:** a security-relevant operation whose audit record cannot be made durable returns an error, and its effect is suppressed. No signature, ciphertext or derived key is returned, and no object is created or persisted.
- **Delivery is split by phase, because the call sites live outside the audit module:**
  - **Phase 1 (audit library): preserve.** The Rust `fhsm_audit_event` keeps the C contract exactly: same return code, same ERROR latch, and the sticky `g_sync_failed`. There is no diff in Phase 1.
  - **Phase 2:** the 11 `fhsm_token.c` sites stop discarding the result. **DONE 2026-10-31 (slice 3):** the Rust token fails the operation when its audit fails; when the call is already failing, the original error wins.
  - **Phase 4:** the 45 `fhsm_pkcs11.c` sites and the 2 `fhsm_state.c` sites stop discarding the result.
  - **Phase 6:** the 15 `fhsm_service.c` sites stop discarding the result.
- **Return code: DECIDED 2026-10-30, `CKR_DEVICE_ERROR` (0x30).** PKCS#11 defines it as "a problem has occurred with the token and/or slot", which matches a module that has just latched ERROR. The alternative is `CKR_FUNCTION_FAILED` (0x6), which is what the internal code returns today.
- **Expected harness diff** (Phases 2, 4 and 6, with audit-write failure injected, e.g. `test_audit_fsync`'s FIFO technique):
  - the operation's return code changes from `CKR_OK` to the chosen code;
  - its output buffer is not written;
  - no object handle or token-file change appears.
- **Divergence test:** with injected fsync failure, `C_Sign` returns the chosen code and leaves the signature buffer untouched. The test fails on C and passes on Rust.

### DIV-002 · RULE-007 The timestamp is sampled before the audit lock

- **Status:** DECIDED (2026-10-30, mor-sec: "approve, all as proposed"). **Fix.**
- **Legacy:** `clock_gettime(CLOCK_REALTIME)` runs before `pthread_mutex_lock(&g_audit_mu)` (`src/fhsm_audit.c:606-610`). Under concurrency, a record with a higher `seq` can carry an earlier `ts`.
- **Target:** sample `ts` after taking the lock, so `ts` never decreases while `seq` increases, apart from wall-clock steps.
- **Why fix:** an auditor ordering records by time gets the same order as by `seq`. Nothing reads `ts` for verification: the verifier checks MACs, `prev_hmac` and `seq` only (`tools/freehsm_audit.c:224-286`). The change is therefore invisible to verification.
- **Expected harness diff:** none. The harness already normalises `ts` and the MACs that depend on it.
- **Divergence test:** a property test over N concurrent writers checks that `ts` is non-decreasing in `seq` order. It is a flaky failure on C and passes on Rust; mark it `#[ignore]` against the C build.
- **If preserved instead:** nothing changes. This is cosmetic, and low risk either way.

### DIV-003 · RULE-008 Audit key length: the module accepts 1–64 bytes, the verifier only 32

- **Status:** DECIDED (2026-10-30, mor-sec: "approve, all as proposed"). **Fix in the module (accept exactly 32 bytes).**
- **Legacy:** `fhsm_audit_open` accepts any key length from 1 to `sizeof g_audit_key` (`src/fhsm_audit.c:456-458`). Key provisioning only ever produces 32 bytes (RULE-093). The verifier hard-codes 32 (`tools/freehsm_audit.c:225-227`).
- **Target:** `fhsm_audit_open` returns `FHSM_RV_ARGUMENTS_BAD` unless the key is exactly 32 bytes.
- **Why fix:** a log written under a key of any other length could never be verified offline. Every real caller already passes 32: `src/fhsm_pkcs11.c:495` and all 8 test call sites (checked 2026-10-30).
- **Expected harness diff:** none through the PKCS#11 ABI. It is visible only to a direct internal call with a non-32-byte key, and no existing test makes one.
- **Divergence test:** a Rust unit test checks that `fhsm_audit_open` with a 16-byte key returns `ARGUMENTS_BAD`.
- **Verifier line length** (the other half of RULE-008): `fgets` with a 4095-byte buffer splits longer lines, but the module caps lines at 2048. **Preserve the cap and the split.** Both Rust verifiers read lines the way `fgets(…, 4096)` does, so a physical line longer than 4095 bytes counts as several lines and is reported broken at its first chunk (characterised from C: `audit/tests/verify.rs`, `line_longer_than_4095_bytes_is_broken_at_its_first_fgets_chunk`). No diff. *(Corrected 2026-10-30: an earlier draft said the Rust verifier reads whole lines; running C showed the split is observable.)*

### DIV-004 · RULE-027 Oversized audit parameters collapse silently to `{}` (P1)

- **Status:** DECIDED (2026-10-30, mor-sec: "approve, all as proposed"). **Preserve in Phase 1; reconsider in Phase 4.**
- **Legacy:** if the serialised params would exceed 1024 bytes, the whole object becomes `{}` with no marker (`src/fhsm_audit.c:626-635`). Unsafe values become `"INVALID"`.
- **Why preserve for now:** the record format is a contract with the verifier and with whatever reads the logs. Phase 1's job is to prove a faithful port of that contract. The callers that could produce oversized params are in Phase 4 code, so whether truncation happens in practice is a Phase 4 question.
- **Option for Phase 4:** keep the parameters that fit and append `"truncated":"1"`. The verifier is unaffected, because it MACs raw bytes, but log consumers would see a new key.
- **Expected harness diff:** none.

### DIV-005 · RULE-094 The FATAL message describes behaviour the code no longer has

- **Status:** DECIDED (2026-10-30, mor-sec: "approve, all as proposed"). **Preserve the behaviour; correct the message in Phase 4.**
- **Legacy:** each `C_Initialize` opens a new numbered file with `O_EXCL`; nothing parses existing files (`src/fhsm_audit.c:427-525`). But the FATAL text at `src/fhsm_pkcs11.c:518-520` says "an existing log whose last line cannot be parsed is refused".
- **Target:** identical file behaviour. The stderr message is rewritten to state the real causes: `O_EXCL` collision, permissions, or a missing directory.
- **Expected harness diff:** stderr text only. The harness does not compare stderr.

### DIV-006 · RULE-027 Unsafe parameter names are written raw

- **Status:** DECIDED (2026-10-30, mor-sec). **Fix.**
- **Legacy:** when a parameter's name or value is unsafe (outside 0x20–0x7E, or `"` or `\`), C replaces the value with `INVALID` and writes the name unchanged (`src/fhsm_audit.c:623-627`). A `"` or a newline in a name corrupts the record. A newline splits it into two physical lines, and the C verifier then reports the log broken. Found by running C during Phase 1 characterisation.
- **Target:** an unsafe name is also replaced with `INVALID`, before the length check, the same as an unsafe value. A pair with an unsafe name renders as `"INVALID":"INVALID"`.
- **Why fix:** the module must not be able to write a record its own verifier rejects. Today every caller passes safe literal names (checked 2026-10-30), so the bug can't be reached yet. The fix closes it before Phase 4 moves the callers.
- **Expected harness diff:** none, because no caller passes an unsafe name.
- **Divergence tests:**
  - `audit/tests/record.rs`: `params_unsafe_key_becomes_invalid_div006` and `params_unsafe_long_key_is_replaced_before_the_length_check_div006`.
  - `audit/tests/golden_lines.rs`: C golden records 82–86 and 96, and `newline_key`, are checked against the DIV-006 rendering. All other records stay byte-identical to C.

### DIV-007 · RULE-008 The in-module verifier reports OK after a read error

- **Status:** DECIDED (2026-10-30, mor-sec: "keep DIV-007"). **Fix.**
- **Legacy:** `fhsm_audit_verify` loops on `fgets`. A read error mid-file ends the loop like end-of-file, and the function returns `FHSM_RV_OK` for a chain it never finished reading (`src/fhsm_audit.c:802-833`). The standalone tool behaves the same way.
- **Proposed:** in the module, a read error returns `FHSM_RV_FUNCTION_FAILED` (`VerifyError::Open`). The standalone tool stays byte-compatible with C, because it shares no code with the module and its output is a contract.
- **Why fix:** a verifier must not report "intact" for bytes it never checked.
- **Expected harness diff:** none, because no test injects a read error.
- **Implemented in:** `audit/src/verify.rs`.

### DIV-008 · RULE-008 The verifiers report "intact" for bytes after the MAC

- **Status:** DECIDED, Fix (2026-10-30, user: "I agree with what you have proposed"). Raised by the Phase 1 architecture review.
- **Implemented:** `audit/src/verify.rs` (`check_line`) and `audit-verify/src/lib.rs` (`ends_with_its_mac`). The tool reports `line N : record does not end with its lowercase hmac (record altered)`, but only when the HMAC itself matched, so the output for every other tampered file is still C's byte for byte. Tests: four CLI cases and three module cases now expect broken, plus `nul_after_the_closing_brace_is_broken_div008`.
- **Legacy:** both C verifiers authenticate only the bytes before the first `"hmac":"` and the 64 hex characters after it (`src/fhsm_audit.c:802-826`, `tools/freehsm_audit.c:244-278`). They ignore:
  - anything after the MAC;
  - anything after an embedded NUL;
  - the case of the hex.

  So `…"hmac":"<mac>","result":"OK","event":"logout"}` verifies, and a JSON reader that keeps the last duplicate key sees an OK logout where a failed login was recorded. Characterised in the Phase 1 tests: `trailer_altered_line3` and `hmac_uppercase_all` both return OK.
- **Proposed:** after the trailing `\n` is removed, a line must equal `body + "\"hmac\":\"" + lowercase_hex(mac) + "\"}"` exactly, with no NUL. Apply this in both Rust verifiers. The writer already produces only that form, so logs written by C and by Rust still verify.
- **Cost:**
  - The Rust tool's verdict and output differ from the C tool's for tampered files.
  - About six characterization tests change from expecting OK to expecting broken.
  - The C tool stays as it is (the oracle), so the two tools disagree on tampered logs.
- **Expected harness diff:** none, because the harness only feeds logs the writers produced.

### DIV-009 · RULE-077 A forked child appends to the parent's chain

- **Status:** DECIDED, Fix (2026-10-30, same approval). Raised by the Phase 1 architecture review.
- **Implemented:** `audit/src/ffi/c_abi.rs`. The log is held as `Arc<Opened { pid, log }>` behind a mutex that is held only to clone or swap the `Arc`, which also applies review finding 5. A process whose PID differs from the opener's sees no open log. The child's `fhsm_audit_open` drops the inherited log without counting it. Regression: `tests-support/hybrid/fork_parent_log.c`, run by `run.sh`.
- **Legacy:**
  - After `fork`, the child still holds the parent's open log: the descriptor, `seq` and `prev_hmac`.
  - In the child, `C_Initialize` runs `reset_after_fork` and then `fhsm_state_set(INITIALIZING)`. The state change emits an event *before* `fhsm_audit_open`, and that event is written to the parent's file with the parent's next `seq` and `prev_hmac` (`src/fhsm_pkcs11.c:398-406`, `src/fhsm_state.c:88`).
  - The parent's log then fails verification at its next line.
  - `tests/test_fork_child.c` follows exactly this path but never verifies the parent's log.
- **Proposed:**
  - Record the opener's PID in the log state. In a process with a different PID, treat the log as not open: events are dropped, as before any open.
  - The child's `fhsm_audit_open` abandons the inherited log without touching it, since its lock may have been held at fork time.
  - Add "the parent's log verifies after the child re-initialises" to the hybrid run.
- **Expected harness diff:** none in the return codes of `make tests`. The parent's log verifies, where under C it would not.

### Preserved without change (no suspected defect)

| Rule | What the port must keep |
|---|---|
| RULE-093 Audit key provisioning | `audit.key.tpm` when TPM sealing is required, otherwise `audit.key`: mode 0600 or stricter, exactly 32 bytes, created with `O_EXCL` from the module DRBG, and the race winner's key re-read. Calls the C TPM and DRBG code over FFI until Phases 2 and 3. |
| RULE-095 The audit-off switch | `FHSM_AUDIT=off` (or `0`) latches ERROR in a mandatory build. With `FHSM_AUDIT_MANDATORY=0` it prints a notice and opens no log. |
| RULE-007 chain construction | Head is `HMAC(K, "FHSM-AUDIT-INIT\|seq=0")`; each line is MACed over its bytes before `"hmac":"`; `prev_hmac` advances *before* the group-commit barrier (`src/fhsm_audit.c:695-702`); a failed barrier is sticky. |
| Events before `fhsm_audit_open` | Dropped, returning OK (`src/fhsm_audit.c:590-596`). Preserved. Once the brief's Q13 fix (RULE-072, the "not initialized" gate) lands in Phase 4, no entry point can emit events before initialisation, so this path only covers events raised while the log is being opened. |

### Referenced here, decided elsewhere

- **RULE-076** (`C_Finalize` and re-initialisation): the audit part is to close the log, zeroise the key and open a new file on re-init. It has no defect and is preserved. The defects are the provider reload and the self-test re-run (brief Q11, Phase 3) and the `pReserved` check (Phase 4).

---

## Phase 2 onwards

Not yet drafted. Each phase's entries are added before that phase starts, from the rules gated at
it in `MODERNIZATION_BRIEF.md` §5. Brief decisions already taken that become entries then:
- Q3 fail-closed call sites in Phases 2, 4 and 6 (DIV-001).
- The recommended fixes for Q6, Q11–Q13 and Q15, once their questions are answered.

---

## Phase 2 — persistence and key custody (`src/fhsm_token.c`, `fhsm_token_tpm.c`, `fhsm_tpm.c`, `fhsm_revocation.c`)

I re-read the cited code for every entry in this section on 2026-10-30. Q5 (stay
byte-compatible on disk) constrains every fix: none of them changes a file format.

### DIV-010 · RULE-066, RULE-003 The zero-DEK fallback (SEC-002)

- **Status:** DONE (2026-10-31, slice 3, `token/src/token.rs`). DECIDED, Fix (2026-10-30, Q6: "Drop + offline migration").
- **Legacy:** if the object store fails GCM under the real DEK, it is decrypted again under 32 zero bytes, and the login succeeds either way. A store that fails under both keys also logs in, with no objects loaded and no error (`src/fhsm_token.c:987-1003`, `:1529-1531`).
- **Fix:**
  - A store that fails under the DEK is an error. `C_Login` returns `CKR_FUNCTION_FAILED`, the DEK is zeroised, and the file is left untouched.
  - A separate offline command, `pqhsm-token migrate-zero-dek <slotN.tok>`, asks for the user PIN, opens a store sealed under the zero key, and rewrites it under the real DEK. This is the only remaining reader of the zero key.
- **Expected harness diff:** none. `tests/test_wrong_pin_store.c` asserts that no store is *written* under the zero key, and no test reads one. The golden corpus includes one ≤2.5.0 zero-key token for the migration test.

### DIV-011 · RULE-001, RULE-004, RULE-044 The PBKDF2 iteration count is read from an unauthenticated header

- **Status:** DONE (2026-10-31, slice 3, `token/src/token.rs`). DECIDED, Fix (2026-10-30, user: "Approve all as proposed").
- **Legacy:** only the serial is GCM AAD. `pbkdf2_iter` at offset 136 is read back with no floor except the primitive's 1000 (`src/fhsm_token.c:1325`, `src/fhsm_crypto.c:561`). Someone who can write the file can change it, and the legitimate PIN then fails five times and locks the role. The C code only ever writes 200000 (`:1234`, `:1840`).
- **Proposed:** refuse to load a token whose `pbkdf2_iter` is not 200000, as a malformed file. Every other unauthenticated header field (label, counters, `user_initialized`) and the unauthenticated public section stay as they are, because Q5 keeps the format. Authenticating the header needs a new format version, which is out of scope until Q5 is revisited.
- **Expected harness diff:** none. The C writer has only ever produced 200000.

### DIV-012 · RULE-084 PIN failure counters across processes (SEC-004)

- **Status:** DONE (2026-10-31, slice 3, `token/src/token.rs`). DECIDED, Fix (2026-10-30, Q8: "Fix: lock the token file").
- **Legacy:** the counters are read when the process loads the token and never re-read (`src/fhsm_token.c:1340-1346`), so each process gets five attempts.
- **Fix:** every login attempt takes an exclusive `flock` on `slotN.tok`. Under the lock it re-reads the counters, checks the lock and throttle, runs PBKDF2, and writes the new counters through tmp + fsync + rename before it unlocks. The lock is on the token file itself, not the tmp file, so the rename doesn't drop it for waiters.
- **Expected harness diff:** none in `make tests`. A new test fails on C and passes on Rust: two processes make three wrong attempts each, and the sixth attempt returns `CKR_PIN_LOCKED`.
- **Amended 2026-10-30 (architecture review H1/H2, user: "Approve plan + amendments"):** the lock is not specific to login. Every one of the 21 token writes goes through one transaction:
  - open with `O_CLOEXEC`, then `flock`;
  - check the inode, comparing `fstat` with `stat`, and retry if a rename replaced it;
  - re-read the header and take the counters from disk; fail if the serial or wraps changed;
  - write tmp, fsync, rename, then fsync the directory;
  - `LOCK_UN`.

  The throttle sleep releases both the flock and the mutex. Lock order: apilock, then token mutex, then flock, then audit mutex. See `PHASE2_PLAN.md` §7.
- **Amended 2026-11-02 (architecture review M-2, M-4; user: "fix M-1 to M-4 and M-6 before Phase 3"):**
  - When the counters re-read under the lock differ from the process's own, the throttle deadline restarts from them, as it does at load. Before, a second process saw the count but not the wait, so two processes taking turns could guess without waiting. Test: `another_handles_failure_throttles_this_one_m2`.
  - The lock wait gives up after 10 s (`FLOCK_WAIT`) with `CKR_FUNCTION_FAILED`, because the token mutex is held while waiting. The holder runs at most one PBKDF2, one TPM unseal and two fsyncs. `flock` is retried on `EINTR`. Test: `lock_ex_gives_up_after_the_wait_then_takes_a_free_lock`.

### DIV-013 · RULE-085, RULE-088 Counter and token writes whose failure is ignored

- **Status:** DONE (2026-10-31, slice 3, `token/src/token.rs`). DECIDED, Fix (2026-10-30, user: "Approve all as proposed").
- **Legacy:**
  - The counter write after a wrong PIN (`src/fhsm_token.c:1543`) and after a correct one (`:1532`) ignore `write_atomic`'s result. With a full disk, a wrong PIN is never counted and the lockout can be avoided across restarts.
  - `fsync` before the rename is unchecked (`:1206`), and the directory is not fsynced after it.
- **Proposed:** fail closed, as Q3 did for audit. A counter that cannot be made durable fails the call with `CKR_FUNCTION_FAILED`, and a correct PIN in that state does not log in. Check `fsync` and fsync the directory after the rename.
- **Expected harness diff:** none, because no test fills the disk. A new fault-injection test covers it.
- **Amended 2026-10-30 (architecture review H3, user: "Approve plan + amendments"):**
  - Login makes `failed+1` durable *before* PBKDF2, and refuses without checking the PIN if that write fails. A correct PIN then resets the counter to 0.
  - If the reset write fails, the objects are unloaded, the DEK is zeroised, `dek_live` and `logged_in` are cleared, and the call returns `CKR_FUNCTION_FAILED`.
  - Cost: a correct login makes two writes instead of one, and a crash between them leaves one extra failure counted.
  - It closes the timing oracle a check-then-write order leaves when the disk refuses writes.

### DIV-014 · RULE-079(b), RULE-080(b) The DEK stays live after C_InitToken with nobody logged in

- **Status:** DONE (2026-10-31, slice 3, `token/src/token.rs`). DECIDED, Fix (2026-10-30, user: "Approve all as proposed").
- **Legacy:** create and re-init leave `dek_live = 1` and `objects_loaded = 1` with `logged_in = NONE` (`src/fhsm_token.c:1214-1299`, `:1880-1885`). The DEK stays in memory with nobody logged in, and public objects can be created without a login.
- **Proposed:** after create and re-init, zeroise the DEK and set `dek_live = 0`, as logout does.
- **Expected harness diff:** not yet known. I have not confirmed that no test creates an object between `C_InitToken` and `C_Login`. The day-1 harness run settles it, and any test that does will be listed here before the code lands.
- **Amended 2026-11-02 (architecture review M-3; user: "fix M-1 to M-4 and M-6 before Phase 3"):** the DEK is zeroised in place before it is released, at logout, after create and re-init, and when a failed counter reset logs out (DIV-013), as C's logout did (`src/fhsm_token.c:1650`). Before, it went to `fhsm_api_free_value`, which can defer the wipe while a reader holds the API lock.

### DIV-015 · RULE-080(a), RULE-089 The TPM companion file

- **Status:** DONE (2026-10-31, slice 3, `token/src/token.rs`). DECIDED, Fix (2026-10-30, user: "Approve all as proposed").
- **Legacy:**
  - (a) Re-init never reseals or removes `.tpm`, so every later login fails the TPM cross-check with `CKR_DEVICE_ERROR`. `fhsm_token_tpm_unlink` has no callers.
  - (c) On create, the seal is written before the `.tok` (`src/fhsm_token.c:1275-1286`). If the `.tok` write fails, an orphan `.tpm` stays behind.
  - (d) `.tpm.new` is not fsynced before its rename (`src/fhsm_token_tpm.c:59-107`).
  - (e) The TPM failure paths zeroise the DEK but leave `dek_live` set.
- **Proposed:**
  - Reseal on re-init when sealing is required, and remove `.tpm` otherwise.
  - Remove the new `.tpm` if the `.tok` write fails.
  - fsync `.tpm.new`.
  - Clear `dek_live` on every TPM failure path.
  - Keep `CKR_DEVICE_ERROR` on mismatch, which is what the code does today. Item (b) of RULE-089, the header comment that says `PIN_INCORRECT`, is wrong.
- **Progress:** (d) DONE 2026-10-31 in `token/src/tpm.rs` (`companion_seal_fsyncs_the_tmp_before_renaming_div015`). Since DIV-031(b) (2026-11-02) a FIFO staged at `.tpm.new` is removed before the tmp is created, so that row now seals normally and no longer reaches the fsync-failure branch; the check stays in the code. (a), (c) and (e) are in `fhsm_token.c` and land in slice 3.
- **Expected harness diff:** none. The container has no TPM, so these paths run only in new tests that use the `FHSM_TPM_TEST_HOOKS` seam (`src/fhsm_tpm.c:126-140`), as `tests/test_tpm.c` does. Q13 listed (a) for Phase 4. It moves here because the code is in `fhsm_token.c`.
- **Amended 2026-11-02 (architecture review M-1; user: "fix M-1 to M-4 and M-6 before Phase 3"):** if the reseal at re-init fails, the call still fails with the TPM's error, but the token now follows the re-initialised file instead of keeping its old serial, which failed every later write. The stale `.tpm` is removed and a `SEAL_FAILURE` record (`tpm-seal-reinit`) is written, as create writes one. Test: `a_failed_reseal_at_reinit_is_audited_and_leaves_the_token_usable_m1`.

### DIV-017 · RULE-089 TPM memfds carrying the DEK are inherited by any fork

- **Status:** DONE (2026-10-31). DECIDED, Fix (2026-10-30, architecture review M1, user: "Approve plan + amendments"). Implemented in `token/src/ffi/sys.rs` (`memfd`, `inherit`); test `an_unrelated_fork_during_a_seal_inherits_no_memfd_div017`.
- **Legacy:** `memfd_create(name, 0)`, deliberately without `MFD_CLOEXEC` so that the `tpm2` child inherits it (`src/fhsm_tpm.c:242`). Any fork/exec on another thread inherits the DEK descriptor too, for as long as it is open.
- **Fix:** create the memfds with `MFD_CLOEXEC`, and clear the flag only in the `tpm2` child's `pre_exec`. In hooks mode only, `FHSM_TPM_CMD` keeps C's `sh -c` splitting.
- **Expected harness diff:** none. `test_tpm`'s "/proc/self/fd only" path assertion still holds.

### DIV-018 · RULE-089 TPM outputs are truncated or over-read silently

- **Status:** DONE (2026-10-31). DECIDED, Fix (2026-10-31, user: "Fix as DIV-018"). Found by the slice 1 characterization tests. Implemented in `token/src/tpm.rs`; tests `seal_refuses_a_public_part_over_512_bytes_div018` and `unseal_refuses_40_bytes_from_tpm2_div018`.
- **Legacy:**
  - Seal reads at most 512 bytes of each of the `tpm2 create` pub and priv outputs (`src/fhsm_tpm.c:316-319`). A larger output is cut short and the seal returns OK, producing a companion file that can never be unsealed.
  - Unseal accepts more than 32 bytes back from `tpm2 unseal` and keeps the first 32.
- **Fix:** seal returns `FHSM_RV_FUNCTION_FAILED` when either output exceeds 512 bytes. Unseal returns `FHSM_RV_FUNCTION_FAILED` unless exactly 32 bytes come back.
- **Expected harness diff:** none. Real tpm2 outputs are well under 512 bytes, and the stub returns exactly 32.

### DIV-023 · RULE-089, RULE-096 TPM audit records read past their arguments

- **Status:** DONE (2026-10-31, slice 3, `token/src/token.rs`). DECIDED, Fix (2026-10-31, user: "Fix 1,2,3,6,8"). Found by the slice 3 characterization tests.
- **Legacy:** six `fhsm_audit_event` calls pass a parameter key with no value (`src/fhsm_token.c:1279`, `:1284`, `:1497`, `:1505`, `:1509`, `:1516`), so the variadic reader takes whatever follows on the stack (`src/fhsm_audit.c:620`). This is undefined behaviour; it crashed the golden generator.
- **Fix:** each record carries the TPM step's status as the value of its key.
- **Expected harness diff:** none; the container has no TPM, so these records are never written there.

### DIV-024 · RULE-003, RULE-096 A store that decrypts but does not parse still logs in

- **Status:** DONE (2026-10-31, slice 3, `token/src/token.rs`). DECIDED, Fix (2026-10-31, user: "Fix 1,2,3,6,8").
- **Legacy:** after AES-GCM authenticates the object store, a parse or frame failure leaves zero objects loaded and the login succeeds (`src/fhsm_token.c:1529-1531`, `:1006`). Every object silently disappears for the session, and the next write would persist the empty store.
- **Fix:** the login fails with `CKR_FUNCTION_FAILED`; the DEK is zeroised and nothing is written.
- **Expected harness diff:** none; the corpus parses.

### DIV-025 · RULE-003, RULE-013 Random-number failures are ignored

- **Status:** DONE (2026-10-31, slice 3, `token/src/token.rs`). DECIDED, Fix (2026-10-31, user: "Fix 1,2,3,6,8").
- **Legacy:** the result of `fhsm_rng_bytes` is ignored at 12 call sites, including salts, nonces, the DEK and the serial (`src/fhsm_token.c:1169`, `:1226`, `:1232-1233`, `:1239`, `:1255`, `:1724-1725`, `:1784-1785`, `:1833`, `:1839`, `:1847`, `:1868`). A failed DRBG leaves the buffer as it was, so keys or nonces can repeat.
- **Fix:** a failed draw fails the call with the DRBG's code before anything is written.
- **Expected harness diff:** none; the DRBG does not fail in the harness.

### DIV-026 · RULE-062 `get_tmpl` returns bytes past `len`

- **Status:** DONE (2026-10-31, slice 3, `token/src/token.rs`). DECIDED, Fix (2026-10-31, user: "Fix 1,2,3,6,8").
- **Legacy:** an attribute template set with `len` shorter than the caller's buffer keeps the caller's whole buffer, so `get_tmpl` returns bytes past `len` until the token is reloaded (`src/fhsm_token.c:2408`).
- **Fix:** only `len` bytes are stored and returned.
- **Expected harness diff:** none.

### DIV-027 · RULE-003 `object_add` with a NULL value and a length

- **Status:** DONE (2026-10-31, slice 3, `token/src/token.rs`). DECIDED, Fix (2026-10-31, user: "Fix 1,2,3,6,8").
- **Legacy:** `object_add` accepts a NULL value with `len > 0` and later copies from NULL (`src/fhsm_token.c:1923-1925`, `:659`). Undefined behaviour; not exercised by any test.
- **Fix:** `CKR_ARGUMENTS_BAD`, nothing added.
- **Expected harness diff:** none.

### DIV-028 · RULE-084 Login and `set_pin` with a role other than SO or user

- **Status:** DONE (2026-10-31, slice 3, `token/src/ffi/token_abi.rs`). Recorded 2026-11-02 (architecture review M-6; user: "fix M-1 to M-4 and M-6 before Phase 3").
- **Legacy:** any role other than SO is treated as the user's (`src/fhsm_token.c:1395-1415`). Role 3 is checked against the user's wrap, counts a user failure, and on success is recorded as the logged-in role (`:1525`). No legacy caller passes such a role. `verify_pin` already refused it, with `CKR_ARGUMENTS_BAD`.
- **Fix:** login and `set_pin` refuse it with `CKR_ARGUMENTS_BAD`. Nothing is counted or written.
- **Expected harness diff:** none. Test: `login_or_set_pin_with_an_unknown_role_is_arguments_bad_div028`.

### DIV-029 · RULE-089 `FHSM_TPM_SEALING` is read when the token is opened

- **Status:** DONE (2026-10-31, slice 3, `token/src/ffi/token_abi.rs`). Recorded 2026-11-02 (architecture review M-6; user: "fix M-1 to M-4 and M-6 before Phase 3").
- **Legacy:** `fhsm_token_tpm_required()` reads the variable at create (`src/fhsm_token.c:1275`) and again at every login (`:1510`). Setting it under an open, unsealed token makes that token's next login fail with `CKR_DEVICE_ERROR`.
- **Target:** read when the token is created or loaded, and kept with the token; re-init uses that value. A token loaded after the change requires the seal. No legacy test changes the variable while a token is open.
- **Expected harness diff:** none. Test: `sealing_is_read_at_load_not_at_login_div029`.

### DIV-030 · RULE-003 `-DFHSM_MAX_OBJECTS` no longer sizes the token store

- **Status:** DONE (2026-10-31, slice 3, `token/src/store.rs`). Recorded 2026-11-02 (architecture review M-6; user: "fix M-1 to M-4 and M-6 before Phase 3").
- **Legacy:** `make FHSM_MAX_OBJECTS=N` sets the store's capacity at compile time (`include/fhsm_token.h:133`, `src/fhsm_token.c:233`, `:668`, `:712`, `:753`, `:850`). No make target sets it; `pkcs11-check` builds at the default since #125.
- **Target:** the cap is 1024, the C default, whatever the C build flags say. The secure-heap size check at `src/fhsm_token.c:109` still reads the macro on the C side.
- **Expected harness diff:** none. Test: `constants_are_c_s`.
- **(b) Phase 3 slice 1 (2026-11-02, `crypto/src/mem.rs`, `conf.rs`):** the same for `-DFHSM_SECURE_HEAP_BYTES` (default arena, 8 MiB) and `-DFHSM_SECURE_HEAP_MINSIZE` (32), `include/fhsm_common.h:280-300`. No make target sets either; operators size the arena with `secure_heap_kb` (#128), which Rust reads as C does.

### DIV-031 · RULE-085 The token write follows a symlink planted at `<path>.tmp`

- **Status:** DONE (2026-11-02, `token/src/token.rs` `Inner::write`). DECIDED, Fix (2026-11-02, user: "Fix token .tmp symlink").
- **Legacy:** every token write opens `<path>.tmp` with `O_WRONLY|O_CREAT|O_TRUNC` (`src/fhsm_token.c:1185`), which follows a symlink, writes the token through it, and renames the link over `slotN.tok`. Anyone who can write the token directory can redirect the write and leave the token as a link to another file. The same weakness as DIV-022.
- **Fix:** as DIV-022: remove whatever is at `<path>.tmp`, then create it `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600. A stale regular tmp is still replaced. Writes run under the token-file lock (DIV-012), so a concurrent writer of the same token cannot remove another's tmp.
- **Expected harness diff:** none. Test: `a_link_planted_at_the_tmp_name_is_not_written_through_div031`.
- **(b) `.tpm.new`, DECIDED, Fix (2026-11-02, user: "Fix like DIV-031"):** the TPM companion's `<path>.tpm.new` was opened the same way, in C (`src/fhsm_token_tpm.c:91`) and in Rust (`token/src/tpm.rs`). It is now removed first and created `O_EXCL|O_NOFOLLOW`. Test: `companion_seal_does_not_follow_a_link_at_the_tmp_div031`.

### Error code when a failing call's audit also fails (decision, 2026-10-31)

- **Decided** (user: "Original error"): when a token call is already failing (wrong PIN, locked, bad arguments) and its audit record also fails to write, the caller gets the original error. The token's state is unchanged either way. A mutating call that would otherwise succeed still fails with `CKR_DEVICE_ERROR` (0x30) when its audit fails (DIV-001, review H4).

### DIV-016 · RULE-024 Revocation dates out of range

- **Status:** DONE (2026-10-31, `pki/src/revocation.rs` `date_to_time`). DECIDED, Fix (2026-10-30, user: "Approve all as proposed").
- **Legacy:** `fhsm_rev_date_to_time` checks 14 digits plus `Z`, then passes the fields to `timegm`. That normalises `20261340990000Z` (month 13, hour 99) to a different instant (`src/fhsm_revocation.c:93-107`).
- **Proposed:** reject a field outside its calendar range. Any bad line already rejects the whole file, so this adds a reason, not a new path.
- **Expected harness diff:** none. The tools write only normalised dates.

- **Edge cases (2026-10-31, user: "Keep both"):** second 60 is out of range, so a leap second is refused (the tools never write one). An entry added in memory with a bad date, never loaded, is answered by OCSP as revoked at 1970-01-01: C ignores the parser's result (`src/fhsm_revocation.c:490`), and 1970 distrusts more signatures than C's normalised instant, not fewer.

### DIV-019 · RULE-024 A carriage return inside a line hides the rest of it

- **Status:** DONE (2026-10-31, `pki/src/revocation.rs` `Db::load`). DECIDED, Fix (2026-10-31, user: "Fix those 4"). Found by the slice 2 characterization tests.
- **Legacy:** load cuts each line at its first `\r` (`src/fhsm_revocation.c:181`). A file with CR-only line endings reads as one line: its first entry or crlNumber is kept and every later entry is dropped, and the load returns OK.
- **Fix:** a `\r` anywhere but directly before the `\n` (or at the end of the file) refuses the whole file, with C's diagnostic and the reason "carriage return inside a line". CRLF files load as before.
- **Expected harness diff:** none. The tools write LF only.

### DIV-020 · RULE-024 A line over 510 bytes is split, and its tail parsed as a new line

- **Status:** DONE (2026-10-31, `pki/src/revocation.rs` `Db::load`). DECIDED, Fix (2026-10-31, user: "Fix those 4").
- **Legacy:** load reads with `fgets` into 512 bytes (`src/fhsm_revocation.c:176-177`). The rest of a longer line comes back as the next line, so a long comment can carry an entry that loads, and a long entry line loads with its tail silently dropped.
- **Fix:** a line longer than 510 bytes, not counting its newline, refuses the whole file, with the reason "line is longer than 510 bytes".
- **Expected harness diff:** none. The tools' lines are under 200 bytes.

### DIV-021 · RULE-024 A read error loads as end of file

- **Status:** DONE (2026-10-31, `pki/src/revocation.rs` `Db::load`). DECIDED, Fix (2026-10-31, user: "Fix those 4").
- **Legacy:** `fgets` returning NULL ends the loop whether it hit the end or an error (`src/fhsm_revocation.c:177`). A directory loads as an empty database, and an I/O error part way through gives a partial one, both with OK.
- **Fix:** a read error is `FHSM_REV_EIO`, "cannot read PATH: REASON", the same text as an open failure.
- **Expected harness diff:** none.

### DIV-022 · RULE-100 Save follows a symlink planted at `<path>.tmp`

- **Status:** DONE (2026-10-31, `pki/src/revocation.rs` `Db::save`). DECIDED, Fix (2026-10-31, user: "Fix those 4").
- **Legacy:** save opens `<path>.tmp` with `fopen(…, "w")`, which follows a symlink, writes the database through it, and renames the link over the database (`src/fhsm_revocation.c:229`, `:247`). Anyone who can write the directory can redirect the write to another file and leave the database as a link to it.
- **Fix:** remove whatever is at `<path>.tmp`, then create it with `O_CREAT|O_EXCL|O_NOFOLLOW`. A stale regular tmp is still replaced, as before. A link planted between the two steps makes the save fail instead of being followed.
- **Consequence for the tests:** the `/dev/full` row (a symlink at the tmp name) now saves normally, so the write-failure branch is no longer reached by a golden row.
- **Expected harness diff:** none.

### Candidates found in slice 2, kept as C does them (decision: preserve)

- **Status:** DECIDED, Preserve (2026-10-31, user: "Fix those 4": the other 11 stay as C). Pinned by the slice 2 tests; each is a candidate for the phase that owns the caller (Phase 5 for the database, Phase 6 for OCSP).

| # | Behaviour | Where in `src/fhsm_revocation.c` |
|---|---|---|
| 4 | `crlNumber -1` and an overflowing value load as 18446744073709551615; `crlNumber` with no digits loads as 0 | `:187-188` |
| 5 | `19691231235959Z` is refused, because `timegm`'s error value is -1 | `:103-104` |
| 6 | `time_to_date` prints a negative year with a sign and reports success | `:114-117` |
| 7b | A failed rename leaves the `.tmp` behind, and a failed flush leaks the open file | `:244-246` |
| 8 | Save writes entries that load refuses, because add validates nothing | `:236-241`, `:253-259` |
| 9 | Add at the 100,000-entry cap returns EPARSE (3); the header says EIO | `:253-259`, header `:164` |
| 10 | A nonce extension over 65,535 bytes gets a truncated length header (tool only; the service caps requests at 64 KiB) | `:521-527` |
| 11 | The encoder buffer size is a guess: a 41 kB request with 20 large-serial CertIDs fails with 0x150 | `:533` |
| 12 | Past year 9999, nextUpdate becomes a 16- or 18-character time instead of an error | `:441-444` |
| 14 | A negative serial in a request matches the revoked positive serial of the same size | `:485-487` |
| 15 | When the algorithm-ID lookup fails, the answer returns without resetting `*out`, `*out_len` or the stats (read from the code; the real lookup cannot fail) | `:394-395` |

### Deferred to the phase that owns the calling code (decision: defer)

- **Status:** DECIDED, Defer (2026-10-30, user: "Approve all as proposed").

Each of these is a token- or revocation-layer rule, but the defect lives in, or can only be fixed together with, C code that stays C until a later phase. Phase 2 preserves the behaviour.

| Rule | Defect | Phase, and why |
|---|---|---|
| RULE-082, RULE-005 | `C_SetPIN` can never succeed | 4 (Q13). The guard is in `fhsm_pkcs11.c:1775`. Phase 2 keeps the existing `fhsm_token_verify_pin`, which the fix will call. |
| RULE-083 | 0x101 where PKCS#11 says 0x102 | 4 (Q13). `fhsm_rv_t` has no value for it, so the mapping in `fhsm_pkcs11.c` changes too. |
| RULE-086, RULE-056 | Logout leaves decrypted objects usable (SEC-001) | 4 (Q12). Unloading at logout alone breaks public-object access in the C layer, and the role check is in `fhsm_pkcs11.c`. |
| RULE-084 | `CKF_*_PIN_COUNT_LOW` and `FINAL_TRY` are never set | 4. They are set in `C_GetTokenInfo`. |
| RULE-090, RULE-091, RULE-092 | `C_CloseAllSessions` slot filter, session-object marking, destroy checks | 4. All in `fhsm_pkcs11.c`. |
| RULE-099, RULE-100 | No locking on the revocation DB, which loses one of two concurrent revokes | 5. The lock must span load, modify and save, and the tools drive that sequence. |
| RULE-023 | OCSP answers "good" for unknown serials | 6 (Q20). |
| RULE-003(1) | `FHSM_OBJ_BLOB_MAX` exceeds `INT_MAX` in the GCM call | 3. The cast is in `fhsm_crypto.c`. |
| RULE-061 (slice 3 candidate 4) | `fhsm_token_mech_allowed` returns OK for an unknown handle (`src/fhsm_token.c:2354`) and when nothing is loaded (`:2334`) | 4 (2026-10-31, user: "defer 4,5"). The callers that rely on it are in `fhsm_pkcs11.c`. |
| RULE-090 (slice 3 candidate 5) | `fhsm_token_destroy_session_objects` checks no login (`src/fhsm_token.c:2036`) | 4 (2026-10-31, user: "defer 4,5"). The login state it should check is the PKCS#11 layer's. |
| RULE-036, RULE-079(a) | PIN minimum 4 against 8 | 4 (Q7, 2026-10-30: "Keep 4; decide 8 at Phase 4"). Phase 2 keeps 8 for a fresh token's SO PIN and 4 elsewhere. |

RULE-096 (DIV-001, fail closed): the 11 call sites in `src/fhsm_token.c` become checked in this phase.

Slice 3 candidate 7, kept as C (2026-10-31, user: "keep 7"): the `object_create` audit record logs the caller's label before it is truncated to the stored length (`src/fhsm_token.c:1941`). Candidate 9 (the store written under a zeroised key after a failed TPM check, `:944`) is already removed by DIV-014 and DIV-015(e).

### Preserved without change (no suspected defect)

| Rule | What the port must keep |
|---|---|
| RULE-002 DEK wrap | AES-256-GCM wrap of the 32-byte DEK under each role's KEK, at the header offsets in `DATA_OBJECTS.md`. |
| RULE-057, RULE-061 | The token-layer checks behind login-required and `CKA_ALLOWED_MECHANISMS`. |
| RULE-078 | Deferred zeroisation of values freed under the shared lock. |
| RULE-081 | `C_InitPIN` sets the user PIN, clears `failed_user` and sets `user_initialized`. |

---

## Phase 3 — crypto core, DRBG, self-tests, PKI encoders (`src/fhsm_crypto.c`, `fhsm_drbg.c`, `fhsm_integrity.c`, `fhsm_composite.c`, …)

Drafted 2026-11-02 for the Phase 3 entry gate ("a decision for every suspected-defect rule gated at Phase 3"). I re-read the cited code for every entry. No legacy test pins the APT, CRNGT or reseed behaviour, and the self-tests write no audit records, so none of these entries is expected to change `make tests` or the audit corpus.

### DIV-032 · RULE-012 Adaptive Proportion Test cutoff

- **Status:** DONE (2026-11-02, Phase 3 slice 2, `crypto/src/drbg.rs` `APT_CUTOFF`; unit tests `apt_passes_18_and_fails_19_div032`, `the_apt_cutoff_formula_matches_table_2`; goldens `apt_19`, `apt_51`). DECIDED, Fix (2026-11-02, Q9, user: "19, α=2^-40").
- **Legacy:** the window's first byte may occur 51 times in 512; the 52nd latches ERROR (`src/fhsm_drbg.c:94-95`, `:313-333`). The comment's "Appendix C gives C = 51" matches nothing in SP 800-90B.
- **Fix:** C = 19, failing when B ≥ C with the first sample counted as 1 (SP 800-90B §4.4.2; C = 1 + CRITBINOM(512, 2^-8, 1 − 2^-40)). The window, counting and reset are unchanged.
- **Test:** a property test pins the cutoff and the comparison: 18 occurrences pass, 19 latch ERROR. The formula is checked against the non-binary rows of Table 2 at α = 2^-20 (13, 62, 177, 311).
- **Expected harness diff:** none.

### DIV-033 · RULE-010(1) A failed reseed latches ERROR

- **Status:** DONE (2026-11-02, Phase 3 slice 2, `crypto/src/drbg.rs` `Drbg::bytes`, `Error::Reseed`; latch reason "DRBG reseed failed"; goldens `cond_fail_periodic`, `cond_fail_periodic_mid`). DECIDED, Fix (2026-11-02, Q10, user: "Latch ERROR").
- **Legacy:** a periodic reseed's result is ignored, "best effort; not fatal" (`src/fhsm_drbg.c:431`). Output continues, and `g_last_reseed_t` is not advanced, so a reseed is retried before every later chunk.
- **Fix:** a failed periodic reseed latches ERROR and the request fails with `CKR_FUNCTION_FAILED`. Nothing of the request is returned, and output already produced in it is cleansed, as for a health-test failure. `condition_and_seed` fails when the four sources give 0 bytes (practically unreachable, because the TSC-jitter source always gives some) or when the SHA2-384 conditioner cannot run (`:241-270`). The init-time seed already fails `fhsm_drbg_init`.
- **Test:** fault injection on the conditioner.
- **Expected harness diff:** none.

### DIV-034 · RULE-074 Self-test bypass variables only in non-release builds

- **Status:** DONE (2026-11-03, Phase 3 slice 4). Slice 3 did the crypto core's part, `crypto/src/lifecycle.rs` (`Core::new`'s `bypass`, the `dev-bypass` feature; unit test `a_release_build_ignores_the_bypass_variables_div034`). Slice 4 moved the integrity check's own bypass behind the same feature (`selftest/src/integrity.rs`, `ALLOW_UNSIGNED`); the release-build latch test is `selftest/tests/integrity_abi.rs` `an_unsigned_module_latches_unless_the_bypass_is_built_in_div034`. DECIDED, Fix (2026-11-02, Q11, user: "Brief's recommendation").
- **Legacy:** `FHSM_INTEGRITY_ALLOW_UNSIGNED` (`src/fhsm_integrity.c:393`, and the provider skip in `fhsm_crypto.c`) and `FHSM_KAT_ALLOW_FAIL` are honoured by every build. The comment at `:390` says production refuses them; no build-time gate exists.
- **Fix:** both are honoured only when the crate is built with a `dev-bypass` cargo feature, off by default. The hybrid and test builds turn it on, because every `make tests` recipe sets the integrity bypass. A release build ignores both variables, and its first initialisation logs that it did.
- **Test:** a release-feature build with the variable set latches ERROR on an unsigned module.
- **Expected harness diff:** none, because the harness builds with `dev-bypass`.

### DIV-035 · RULE-076(b), RULE-077 Self-tests re-run after re-initialisation and in fork children

- **Status:** DONE (2026-11-02, Phase 3 slice 3): `Core::finalize` and `Core::forget` (`crypto/src/lifecycle.rs`); the fork child handler in `crypto/src/ffi/c_abi.rs` forgets the result, so no Phase 4 fork detection is needed for this part. What re-runs: after finalize, everything (providers reloaded); in a fork child, the DRBG init and the KATs on the providers inherited from the parent, which are not reloaded (an atfork handler may not unload them), so the FIPS provider's own power-on self-test does not run again. Tests: golden rows `fips_ok` #6 and `dev_ok` #4 (Rust-only), `init_after_finalize_runs_the_self_tests_again_div035`, `init_after_forget_runs_the_self_tests_on_the_loaded_providers`, `tests/core_fork.rs`. Slice 4 (2026-11-03): the integrity check inside the re-run is Rust's and runs again too (`selftest/src/ffi/c_abi.rs` `pqhsm_integrity_run`); `fhsm_integrity_verify`, called outside the init, keeps C's once-per-process cache. DECIDED, Fix (2026-11-02, Q11, user: "Brief's recommendation").
- **Legacy:** `fhsm_crypto_init` runs once per process under `pthread_once` (`src/fhsm_crypto.c:282-285`). After `C_Finalize` unloads the providers (`:287-293`), `C_Initialize` returns the cached OK without reloading them or re-running integrity and the KATs. A fork child inherits the parent's result.
- **Fix:** `C_Finalize` resets the init state, so the next `C_Initialize` reloads the providers and re-runs integrity, provider load and KATs. A fork child re-runs them at its first `C_Initialize`. The fork detection itself is Phase 4 (`fhsm_state.c`); Phase 3 provides the reset.
- **Expected harness diff:** none in output. Tests that re-initialise get slower by one self-test run each.

### DIV-036 · RULE-010(2) The reseed interval uses wall-clock time

- **Status:** DONE (2026-11-02, Phase 3 slice 2, `crypto/src/ffi/entropy.rs` `OsSource::now`). DECIDED, Fix (2026-11-02, user: "Fix: CLOCK_BOOTTIME").
- **Legacy:** the 3600 s interval compares `time(NULL)` values (`src/fhsm_drbg.c:428-430`), so setting the clock back postpones the reseed indefinitely, and setting it forward forces one.
- **Fix:** measure the interval on `CLOCK_BOOTTIME`, which counts suspend and never goes backwards. The byte limit (1 MiB, `>`) is unchanged.
- **Expected harness diff:** none.

### DIV-037 · RULE-013 CRNGT checks one block per chunk

- **Status:** DONE (2026-11-02, Phase 3 slice 2, `crypto/src/drbg.rs` `Drbg::health`; goldens `crngt_first_block`, `crngt_within_request`, `crngt_last_block`). The `docs/FIPS_140_3.md:157` update waits for cutover: the C tree is not modified (Q4). DECIDED, Fix (2026-11-02, user: "Fix: every 16-byte block").
- **Legacy:** the continuous test compares only the first 16-byte block of each chunk of up to 64 KiB with the previous chunk's first block (`src/fhsm_drbg.c:338-351`). Requests under 16 bytes are never tested. The two descriptions disagree: the comment at `src/fhsm_crypto.c:315-320` says every new 16-byte block is compared with the one before it, while `docs/FIPS_140_3.md:157` says a block is "compared between calls", which is what the code does.
- **Fix:** what the code comment says: compare every full 16-byte block with its predecessor, across chunk and request boundaries. Update `docs/FIPS_140_3.md:157` to match. The alternative is to preserve C and correct the comment. Requests under 16 bytes stay untested. The false-alarm rate is 2^-128 per block.
- **Expected harness diff:** none.

### DIV-038 · `fhsm_secure_heap_total` after adopting another copy's arena

- **Status:** DONE (2026-11-02, slice 1, `crypto/src/mem.rs` `locked_mapping_size`). DECIDED, Fix (2026-11-02, user: "Approve fix").
- **Legacy:** when a second copy of the module adopts an existing locked arena, it reads the arena's size from `/proc/self/smaps` with `sscanf(line, "%lx%c%lx")` (`src/fhsm_memory.c:83-96`). `sscanf` stores the first number before it fails, so the `AnonHugePages:` and `FilePmdMapped:` lines overwrite the mapping's start with 0xA or 0xF. `fhsm_secure_heap_total()` then returns the mapping's end address minus 15: 126,072,694,165,489 in one golden run, and a different number each run (ASLR). The locked check itself is right. The only reader is the diagnostic `printf` at `tests/test_secure_heap.c:98`.
- **Fix:** the size of the mapping that holds the probe, 1,048,576 for a 1 MiB arena. The C value cannot be reproduced: it is an address.
- **Expected harness diff:** none (no test compares it). Tests: golden row `heap_adopt_locked total` (`RUST_ONLY`, which also fails if C starts giving the same value), unit test `the_locked_mapping_size_is_its_range_div038`.

### DIV-039 · `fhsm_conf_lookup` leaves `out` untouched when it returns 0

- **Status:** DONE (2026-11-02, slice 1, `crypto/src/ffi/c_abi.rs`). Recorded: not part of the header's contract.
- **Legacy:** when the key matches but the value is empty (`mode =`), C writes a NUL into `out` and returns 0, or keeps searching and may then return 1 (`src/fhsm_conf.c:49-56`). When nothing matches, `out` is untouched.
- **Target:** on 0, `out` is never written. `include/fhsm_conf.h` describes `out` only on success, and the one caller (`src/fhsm_mode.c:117`) returns before reading it. The search after an empty match is kept (golden row `empty_then_set`).
- **Expected harness diff:** none.

### DIV-040 · `fhsm_drbg_bytes` zeroes the caller's buffer before filling it

- **Status:** DONE (2026-11-02, Phase 3 slice 2, `crypto/src/ffi/c_abi.rs` `fhsm_drbg_bytes`). Recorded: found by the slice 2 review (L4).
- **Legacy:** C writes only what the generator produced. After a failed lazy seed the buffer is untouched; after a `RAND_bytes` failure the unproduced tail keeps its old contents (`src/fhsm_drbg.c:377-440`).
- **Target:** the buffer is zeroed first, because Rust may not view possibly uninitialised caller memory as bytes. A successful call returns the same bytes. A failed one leaves 0 where C left the old contents. The cost is one extra write of the buffer.
- **Expected harness diff:** none.

### DIV-041 · RULE-073 DRBG output after another thread latched ERROR

- **Status:** DONE (2026-11-02, Phase 3 slice 2, `crypto/src/ffi/c_abi.rs` `fhsm_drbg_bytes`). DECIDED, Fix (2026-11-02, user: "Fix: re-check under lock"). Found by the slice 2 review (M1). Untested: no test races a latch, and the Rust tests do not link `fhsm_state.c`.
- **Legacy:** `fhsm_drbg_bytes` checks the module state before taking `g_mtx` (`src/fhsm_drbg.c:373-375`). A thread that passed the check while another thread was failing a health test waits on the mutex, then generates and returns output after the module latched ERROR.
- **Proposed fix:** check the state again once the lock is held. One line in `crypto/src/ffi/c_abi.rs`; such a request then returns `FHSM_RV_FUNCTION_FAILED` with nothing written. FIPS 140-3 forbids data output in the error state.
- **Alternative:** preserve. The window is one health-test failure wide, and the failing thread's own output is cleansed.
- **Expected harness diff:** none, because no test races a latch.

### DIV-042 · RULE-013 A generator failure cleanses the request's output

- **Status:** DONE (2026-11-02, Phase 3 slice 2, `crypto/src/drbg.rs` `Drbg::bytes`; golden `rand_fail_mid`). DECIDED, Fix (2026-11-02, user: "(a) Wipe on generator failure").
- **Legacy:** when `RAND_bytes` fails, C latches ERROR and returns, leaving the request's earlier chunks in the caller's buffer (`src/fhsm_drbg.c:433-437`). Every other failure cleanses them (`:445-456`).
- **Target:** the request's output, the failed chunk included, is cleansed before the error returns.
- **Expected harness diff:** none.

### DIV-043 · RULE-010 Every entropy source contributes to the seed

- **Status:** DONE (2026-11-02, Phase 3 slice 2, `crypto/src/ffi/entropy.rs` `SHARES`; unit test `every_source_contributes_div043`). DECIDED, Fix (2026-11-02, user: "(b) Give each source a share").
- **Legacy:** getrandom is asked for the whole 512-byte pool and fills it, so RDRAND, `/dev/urandom` and the clock jitter get no room (`src/fhsm_drbg.c:241-247`); `entropy_sources_active` is 1. The header and `docs/RNG.md` describe a four-source seed.
- **Target:** shares of 256 (getrandom), 128 (RDRAND), 120 (`/dev/urandom`) and 8 (jitter) bytes, hashed together as before. A source that gives less leaves its share short. `entropy_sources_active` becomes 15, or 13 without RDRAND. 256 bytes is also the largest getrandom read a signal cannot cut short.
- **Expected harness diff:** none; no test prints the source mask.

### DIV-044 · RULE-010 A failed first seed inside a request latches ERROR

- **Status:** DONE (2026-11-02, Phase 3 slice 2, `crypto/src/drbg.rs` `Drbg::bytes`; golden `lazy_fail`). DECIDED, Fix (2026-11-02, user: "(c) Latch on lazy seed failure").
- **Legacy:** `fhsm_drbg_bytes` before any `fhsm_drbg_init` seeds lazily; if that fails it returns `FHSM_RV_RNG_FAILURE` and latches nothing (`src/fhsm_drbg.c:379-385`), so later calls retry.
- **Target:** as a failed periodic reseed (DIV-033): ERROR is latched ("DRBG reseed failed") and the request returns `FHSM_RV_FUNCTION_FAILED`. `fhsm_drbg_init` and `fhsm_drbg_reseed` still return `FHSM_RV_RNG_FAILURE` without latching.
- **Expected harness diff:** none; `C_Initialize` seeds through `fhsm_drbg_init` first.

### DIV-045 · RULE-001, RULE-002 A NULL pointer with a length is ARGUMENTS_BAD in the crypto core

- **Status:** DONE (2026-11-02, Phase 3 slice 3, `crypto/src/ffi/c_abi.rs` `input`, `output`, `fhsm_hmac`). Recorded: mine, found while porting; not yet confirmed by the user.
- **Legacy:** `src/fhsm_crypto.c` hands a `fhsm_slice_t` with `data == NULL` and `len > 0`, a NULL output buffer with a non-zero length, and (in `fhsm_hmac`) a NULL `mac_len` straight to OpenSSL or dereferences them. Depending on the call that crashes, fails inside OpenSSL, or (`fhsm_aes_gcm_encrypt` with `ciphertext == NULL`) returns OK with no ciphertext, because `EVP_EncryptUpdate` with a NULL output treats the plaintext as AAD.
- **Target:** each is `FHSM_RV_ARGUMENTS_BAD`, checked after C's own checks so every code C returned is still returned first. A NULL pointer with length 0 is an empty input, as before; for an HMAC key that means an empty key, where C handed NULL to `EVP_MAC_init` (not characterised).
- **Expected harness diff:** none; no caller passes such arguments.

### DIV-046 · RULE-074 Every failed power-on KAT fails the module init

- **Status:** DONE (2026-11-03, Phase 3 slice 4, `selftest/src/kat/mod.rs` `run_all`). DECIDED, Fix (2026-11-03, user: "Fix: any failure fails init"). Recorded: found while reading the KATs for slice 4. Test: `selftest/tests/kat_golden.rs` replays every C fault scenario; the nine whose report had a failed record and C's OK (`fail_1`, `flip_1`, `fail_5`, `flip_5`, `fail_6`, `flip_6`, `fail_17`, `fail_18`, `stuck_rng`) expect KAT_FAILED, the rest C's code. A flipped byte in one DRBG draw (`flip_17`, `flip_18`) still passes the stuck check in C and in Rust: the draws still differ.
- **Legacy:** `fhsm_kat_run_all` returns `FHSM_RV_KAT_FAILED` only when the GCM decrypt KAT, the PBKDF2 smoke KAT or a CAVP SHA-256 file vector fails (`kat/fhsm_kat_vectors.c:228`, `:278`, `:341`). Every other KAT, including GCM encrypt, SHA-256, HMAC, the DRBG stuck check (`:181`, `:239`, `:253`, `:361`) and all of `fhsm_kat_cavp_extended` (`kat/cavp_extended.c:1610-1997`), only records `passed = 0`, and the function returns OK, so `C_Initialize` succeeds with a failed self-test. `kat/cavp_extended.c:37` says a mismatch latches ERROR; RULE-074's specification assumed the same.
- **Target:** every KAT still runs and is recorded in C's order, with C's names; if any record failed, `fhsm_kat_run_all` returns `FHSM_RV_KAT_FAILED`, so the init latches ERROR ("KAT failed at module init", FIPS 140-3 §7.10.3). The four early returns stay where C has them. `FHSM_KAT_ALLOW_FAIL` in a `dev-bypass` build still lets the module start (DIV-034).
- **Expected harness diff:** none. All 62 KATs pass in every recorded run: the default provider and both FIPS profiles (`baseline/smoke_kat_report.txt`, `baseline/fips/smoke_kat_report-*.txt`).

### DIV-047 · RULE-074 A CAVP vector longer than the message buffer is a failed vector

- **Status:** DONE (2026-11-03, Phase 3 slice 4, `selftest/src/kat/cavp.rs` `Vector::msg`, `selftest/src/kat/mod.rs`). DECIDED, Fix (2026-11-03, user: "Keep the fix"). Recorded: mine, found while porting. Test: `selftest/tests/kat_golden.rs` `a_length_past_the_message_buffer_is_a_failed_vector_div047`.
- **Legacy:** `kat/fhsm_kat_vectors.c` reads `Len = <bits>` with `atoi` and hashes `(bits + 7) / 8` bytes of its 256-byte message buffer. A `Len` above 2048 bits reads past the buffer (a stack over-read into the digest compared); a negative `Len` becomes a huge `size_t`. The file is the module's own (`/opt/freehsm/share/kat`, then `kat/cavp/` beside the sources), so only a damaged or replaced file reaches this.
- **Target:** such a vector is recorded as failed, so `fhsm_kat_run_all` returns `FHSM_RV_KAT_FAILED` at that vector, as for a wrong digest. Every other line of the file is read as C reads it: glibc's `atoi` and `%2x`, 2047-byte lines.
- **Expected harness diff:** none; the shipped file's longest vector is 896 bits (`kat/cavp/sha2_256_short.rsp`).

### DIV-048 · RULE-021, RULE-025 A signer that reports more signature than it was given room for fails the build

- **Status:** DONE (2026-11-03, Phase 3 slice 5, `pki/src/ffi/c_abi.rs` `c_sign`). DECIDED, Fix (2026-11-03, user: "keep refusing a signer callback that reports a longer signature than its buffer"). Recorded: mine, found while porting. No golden row: on C the case is an out-of-bounds read. Test: `pki/tests/x509_golden.rs`, after the replay.
- **Legacy:** every builder in `src/fhsm_composite.c` hands the signer callback an 8,192-byte heap buffer (`FHSM_PKI_SIG_MAX`, `OPENSSL_malloc` at `:762`, `:900`, `:1753`, `:2056`, `:2400`) with `*sig_len` set to its size, then copies `*sig_len` bytes from it, whatever the callback wrote there (`:765`, `:904`, `:1756`, `:2061`, `:2404`). A callback that returns OK with a larger length makes C read past the buffer into the structure it signs.
- **Target:** that call fails with `FHSM_RV_FUNCTION_FAILED` and nothing is written. A length within the room is used as before, so every signer the project has (the PKCS#11 callbacks in `tools/pkiops.c`, the composite signer) behaves as before.
- **Expected harness diff:** none; no callback reports more than it wrote.

### DIV-049 · RULE-069 A public key whose AlgorithmIdentifier parameters are a BOOLEAN is refused

- **Status:** DONE (2026-11-03, Phase 3 slice 5, `pki/src/ffi/x509.rs` `spki_into_slot`). DECIDED, Fix (2026-11-03, user: "keep refusing BOOLEAN key parameters"). Recorded: found by the slice 5 architecture review (M1) and reproduced on the C object. No golden row: on C it crashes. Test: `pki/tests/x509_golden.rs`, after the replay; fuzz seed `pki/fuzz/seeds/der_inputs/csr_spki_div049_boolean.bin`.
- **Legacy:** `spki_into_slot` (`src/fhsm_composite.c:658-684`) copies a SubjectPublicKeyInfo's parameters with `ASN1_STRING_dup` for every type but OBJECT, NULL and absent. For a BOOLEAN, `X509_ALGOR_get0` hands back the value itself (0xFF for TRUE) as the pointer, and the copy faults. The same copy takes the signer's key (`fhsm_pki_csr`, `fhsm_pki_selfsigned`) and an issued request's key (`fhsm_pki_issue`, `:1320`). `pub_from_slot` (`:1040-1054`) checks only the composite OID, so a request whose key carries `BOOLEAN TRUE` and is properly composite-signed passes proof of possession and then crashes the issuing tool. Reproduced: a composite-OID SPKI with BOOLEAN parameters given to `fhsm_pki_csr` segfaults the C object.
- **Target:** such a key is `FHSM_RV_ARGUMENTS_BAD`, before anything is built. Every other parameter type is copied as before. Requiring absent parameters on a composite key (they MUST be absent) would refuse more inputs C accepts; it is left for Phase 5.
- **Expected harness diff:** none; no test uses such a key.

### Phase 3 rules kept as C does them, or deferred (decision: as below, 2026-11-02, user: "Approve as drafted")

| Rule | Suspected defect | Proposed |
|---|---|---|
| RULE-001 (Phase 3 part) | `fhsm_pbkdf2`'s header comment says a 200,000 minimum; the code's floor is SP 800-132's 1,000, deliberately (`src/fhsm_crypto.c:542-561`). The token's 200,000 is DIV-011 (Phase 2). | Preserve; the stale comment is not carried over. |
| RULE-006 | The primitive's bounds (≥ 1,000 iterations, 1–256 output bytes, any salt) are as intended. The `(uint32_t)` narrowing of the mechanism's iteration count is in `fhsm_pkcs11.c:2829`. | Preserve the primitive; the narrowing goes to Phase 4. |
| RULE-010(3), (4) | `docs/RNG.md` says SHA-256 conditioning; the code uses SHA2-384. `RAND_add` with entropy 0 is additional input, not a reseed of OpenSSL's DRBG, which reseeds itself from its own seed source. | Preserve the code; describe it as additional input. |
| RULE-021, RULE-069 (`fhsm_composite.c` part) | A certificate's notAfter is not clamped to the issuing CA's. Clamping changes certificate bytes, and Phase 3's exit compares PKI output. | Preserve in Phase 3; decide at Phase 5 with `tools/fhsm_ca.c`. That phase also owns the unchecked `memcpy` of the CA file into a 256 KiB buffer (RULE-069) and `--days` parsed with `atoi` (RULE-021). |
| RULE-022 | The comment at `tools/fhsm_ca.c:398-402` is wrong (no number is consumed on a signing failure); thisUpdate is not backdated. | Preserve. |
| RULE-073 (Phase 3 part) | The crypto primitives already refuse in ERROR (`src/fhsm_crypto.c:388`, `:432`, `:480`, `:508`, `:546`; `fhsm_drbg.c:373`). The calls that keep working in ERROR are in `fhsm_pkcs11.c`. | Preserve the Phase 3 checks; the rest is Phase 4 (Q13). |
| RULE-076(a), (c) | `pReserved` is not checked; Finalize in POWER_OFF returns OK. Both are in `fhsm_pkcs11.c`. | Phase 4. |

## Phase 4 — PKCS#11 API layer, lifecycle and sessions (`src/fhsm_pkcs11.c`, `fhsm_session.c`, `fhsm_state.c`, `fhsm_apilock.c`, …)

Drafted 2026-11-03 for the Phase 4 entry gate ("a decision for every suspected-defect rule gated at Phase 4; every intended divergence lists the exact expected harness diff, as return code and call"). Brief answers Q12–Q15 (2026-11-03) settle DIV-050 to DIV-058. DIV-053's scope, DIV-054's no-rotation, DIV-059 and the table at the end were proposed and then decided by the user (2026-11-03, quoted in each). Q17 needs no entry: C already refuses the composite in the strict build, and Phase 4 keeps that. Each expected diff was found by reading every `make tests` test that calls the changed entry point (106 commands, `p3x2/results/commands.txt`). "None" means no legacy test reaches the changed branch, and the harness run confirms it. Return codes: `CKR_KEY_HANDLE_INVALID` 0x60, `CKR_KEY_UNEXTRACTABLE` 0x6A, `CKR_OBJECT_HANDLE_INVALID` 0x82, `CKR_PIN_LEN_RANGE` 0xA2, `CKR_TEMPLATE_INCONSISTENT` 0xD1, `CKR_USER_NOT_LOGGED_IN` 0x101, `CKR_CRYPTOKI_NOT_INITIALIZED` 0x190.

### DIV-050 · RULE-056, RULE-086, RULE-092(c) Keys need a USER login, and logout drops decrypted objects (SEC-001)

- **Status:** DECIDED, Fix (2026-11-03, Q12, user: "SEC-001: require login before a key can be used, and drop decrypted objects at logout.").
- **Legacy:** `fhsm_require_key` checks only that the handle exists among loaded objects (`src/fhsm_pkcs11.c:9017-9024`), so every key-use Init (`:9761`, `:10165`, `:10793`, `:11487`, and the wrap, unwrap, derive and KEM paths) accepts a private key while nobody, or the SO, is logged in. `fhsm_token_logout` zeroises the DEK but leaves `objects_loaded` set and every decrypted value in memory (`src/fhsm_token.c:1645-1654`). Reproduced: after `C_Logout`, `C_EncryptInit` + `C_Encrypt` with the user's AES token key return CKR_OK. `C_DestroyObject` applies no visibility check either, so the SO can destroy the user's keys.
- **Target:** an object of class CKO_SECRET_KEY or CKO_PRIVATE_KEY (the classes RULE-055 already hides) is usable only while the token's role is USER. Otherwise every key-use Init, `C_WrapKey`'s wrapping key and target, `C_UnwrapKey`'s key, `C_DeriveKey`'s base, `C_EncapsulateKey`'s and `C_DecapsulateKey`'s key, and `C_DestroyObject` return `CKR_KEY_HANDLE_INVALID` (0x60; `C_DestroyObject` 0x82, per the table). That is what C already returns for such a handle in a fresh process with no login. At logout (explicit, last session closed, or forced by re-init), every private token object's value is zeroised and unloaded, public objects stay usable, and operations active on a private key in any session of that token end (the next call returns `CKR_OPERATION_NOT_INITIALIZED`, 0x91). Private session objects stay, unusable until USER logs in again.
- **Test:** the SEC-001 reproduction (fails on C, passes on Rust); the SO's `C_SignInit` on a user key; an operation started before logout and continued after it.
- **Expected harness diff:** none. No legacy test uses a key after `C_Logout` or as SO. Every logout in the nine tests that call it is the SO stepping out during setup, before the user logs in.

### DIV-051 · RULE-072, RULE-076(a)(c), RULE-077(b) "Not initialized" is enforced

- **Status:** DONE (2026-11-04, Phase 4 slice 1, `p11/src/ffi/lifecycle.rs` `initialized`; the C entry points through `p11/shim/interface.c`; test `tests-support/hybrid/p11_notinit.c`, harness step 4h). DECIDED, Fix (2026-11-03, Q13, user: "Fix the five reproduced lifecycle defects."). RULE-076(a) and RULE-077(b) are the same gate and are included.
- **Legacy:** `FHSM_RV_CRYPTOKI_NOT_INITIALIZED` is defined (`include/fhsm_common.h:198`) and never returned. Every `C_*` checks only `== FHSM_STATE_ERROR`. Reproduced: after `C_Finalize`, `C_OpenSession` and `C_Login(CKU_USER)` return CKR_OK, with self-tests and audit bypassed. `C_Finalize` returns OK in POWER_OFF and ignores `pReserved`. A forked child that never calls `C_Initialize` keeps the parent's sessions and login.
- **Target:** while the state is POWER_OFF, or the caller is a forked child that has not called `C_Initialize` (`getpid() != g_init_pid`), every `C_*` except `C_Initialize`, `C_GetFunctionList`, `C_GetInterfaceList` and `C_GetInterface` returns 0x190, `C_Finalize` included. `C_Finalize` with a non-NULL `pReserved` returns `CKR_ARGUMENTS_BAD` (0x7) before the state check.
- **Test:** each entry point before `C_Initialize`, after `C_Finalize`, and in an uninitialised child.
- **Expected harness diff:** none. Every test, both fork tests' children and the harness helpers (`atexit_finalize.c`, `fork_parent_log.c`) call `C_Initialize` first. Step 4g's own golden (`p11_lifecycle.c`, written in slice 1d) records the defect in three places, which it sets aside: scenario 0 before its first `C_Initialize` with its log, `C_Finalize(pReserved)`, the forked child before `C_Initialize`.

### DIV-052 · RULE-075 A pairwise failure latches ERROR

- **Status:** DECIDED, Fix (2026-11-03, Q13).
- **Legacy:** a failed pairwise check frees the key and returns 0x6, but calls `fhsm_state_set(FHSM_STATE_ERROR)` (`src/fhsm_pkcs11.c:6783`), which the transition table refuses (INITIALIZED→ERROR is not whitelisted, `src/fhsm_state.c:40-47`). The module stays usable, against its own comment at `:6766`.
- **Target:** `fhsm_state_latch_error("pairwise consistency failure")`; the call still returns 0x6 and writes the KAT_REPORT event; afterwards the module is in ERROR (DIV-053 says what that refuses).
- **Test:** fault injection on the pairwise check.
- **Expected harness diff:** none; no legacy key pair fails its check.

### DIV-053 · RULE-073 What ERROR refuses

- **Status:** DECIDED, Fix (2026-11-03, Q13). Scope DECIDED as proposed (2026-11-03, user: "Status calls only (Recommended)").
- **Legacy:** about 25 entry points refuse in ERROR with 0x6; signing, verification, encryption, decryption, every `*Update`/`*Final`, digests, `C_DestroyObject`, `C_GetAttributeValue` and `C_FindObjects*` keep running (`:11309`, `:9761`, `:4140`). Asymmetric signing calls EVP directly and still produces signatures. The Phase 3 primitives already refuse (DIV-041).
- **Target:** in ERROR every `C_*` returns `CKR_FUNCTION_FAILED` (0x6, C's existing code) except `C_Finalize` and the status calls that output no key material: `C_GetInfo`, `C_GetFunctionList`, `C_GetInterfaceList`, `C_GetInterface`, `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetMechanismList`, `C_GetMechanismInfo`. An operation already active refuses at its next call. FIPS 140-3 §7.10.5: no data output in the error state.
- **Test:** latch ERROR, then call every entry point.
- **Expected harness diff:** none. No legacy test continues with crypto after ERROR (`test_audit_fsync` drives the audit library, not the API; `audit_switch.sh mandatory` checks only that `C_Initialize` refuses).

### DIV-054 · RULE-082, RULE-005 `C_SetPIN` works

- **Status:** DECIDED, Fix (2026-11-03, Q13). No DEK rotation DECIDED (2026-11-03, user: "Re-wrap only (Recommended)").
- **Legacy:** `C_SetPIN` requires the session's role to hold the token, then `fhsm_token_set_pin` calls `fhsm_token_login` for that role, which returns `CKR_USER_ALREADY_LOGGED_IN` (0x100). The PIN can never change. Reproduced. The comments and `docs/EAL4_PLUS.md:20` say an SO `C_SetPIN` rotates the DEK; no code does.
- **Target:** with USER logged in, `C_SetPIN` changes the user PIN; with SO, the SO PIN. The old PIN is verified against that role with the RULE-084 counter, throttle and lock, without logging in again; a wrong one is `CKR_PIN_INCORRECT` (0xA0). The DEK is re-wrapped under a fresh salt and nonce and written through the DIV-012 locked transaction; a SET_PIN audit event records the result. Nobody logged in: 0x101, as C. A read-only session: `CKR_SESSION_READ_ONLY` (0xB5), per PKCS#11. The new PIN's length follows DIV-059.
- **No DEK rotation.** A PIN change is not a key compromise, and rotation means re-encrypting every object and the user wrap in one atomic write. The stale comments are not carried over, and `docs/EAL4_PLUS.md:20` goes on the documentation list for the cutover.
- **Test:** user and SO PIN changes, the old PIN refused and the new accepted afterwards, a wrong old PIN counted.
- **Expected harness diff:** none; no legacy test calls `C_SetPIN`.

### DIV-055 · RULE-090 `C_CloseAllSessions` takes any valid slot, and closes only that slot's sessions

- **Status:** DONE (2026-11-04, Phase 4 slice 1, `p11/src/ffi/login.rs` `pqhsm_C_CloseAllSessions`; test `p11_divs.c` DIV-055, harness step 4h). DECIDED, Fix (2026-11-03, Q13).
- **Legacy:** only slot 0 is accepted (`C_CloseAllSessions(1..3)` returns `CKR_SLOT_ID_INVALID`, 0x3; reproduced), and slot 0 closes every session on every slot. `C_OpenSession` accepts slots 0–3.
- **Target:** slots 0–3 are accepted; only that slot's sessions close, with RULE-090's per-session cleanup and the last-session logout of that slot's token. A slot ≥ 4 is 0x3.
- **Test:** sessions on two slots, close one slot, the other's sessions survive.
- **Expected harness diff:** none. `test_apilock`, the only caller, opens sessions on slot 0 only.

RULE-080(a), the `.tpm` file on re-init (the fifth Q13 item), is already fixed in the token layer: DIV-015, done in Phase 2. Phase 4 calls that code.

### DIV-056 · RULE-041, RULE-037(b) A copy keeps its source's usage and policy

- **Status:** DECIDED, Fix (2026-11-03, Q14, user: "C_CopyObject should keep the source's usage and policy unchanged (RULE-041).").
- **Legacy:** `C_CopyObject` copies the flag bytes, dates and label (`src/fhsm_pkcs11.c:7995-8292`) but not the usage byte, so a key with `CKA_SIGN` FALSE yields a copy that signs. It copies only the "present" bits of the allowed-mechanism list and the nested templates, so the copy's templates are empty and pass every check, and `CKA_ALLOWED_MECHANISMS` in the copy template replaces the source's list. The read-only check reads only the template, while `CKA_TOKEN` is inherited from the source (`:8193-8204`).
- **Target:** the copy carries the usage byte, the allowed-mechanism list and the three nested templates in full. A copy template may only narrow: a usage attribute FALSE→TRUE, or a `CKA_ALLOWED_MECHANISMS` that is not a subset of the source's, is `CKR_ATTRIBUTE_READ_ONLY` (0x10), the code C already uses for SENSITIVE 1→0 and EXTRACTABLE 0→1. A nested template in a copy template is 0xD1, as C does for CKA_CLASS. A copy that will be a token object (inherited or asked for) from a read-only session is 0xB5.
- **Test:** a `CKA_SIGN`=FALSE key's copy refuses to sign; a widened mechanism list is refused; the copy's wrap template is enforced.
- **Expected harness diff:** none. `test_copyable_oneway` and `test_encap_flags` already require a copy to be as restricted as its source.

### DIV-057 · RULE-064 Derived keys inherit sensitivity; CKO_DATA only from `CKM_HKDF_DATA`

- **Status:** DECIDED, Fix (2026-11-03, Q14, user: "Derived keys must inherit SENSITIVE and ALWAYS_SENSITIVE, and CKO_DATA is allowed only for CKM_HKDF_DATA (RULE-064).").
- **Legacy:** a derived key defaults to SENSITIVE FALSE whatever its base (`src/fhsm_pkcs11.c:4824-4834`), and any derive mechanism accepts `CKA_CLASS=CKO_DATA`, whose value anyone can read without login (`:4789-4860`). A secret derived from a sensitive key can therefore be read in clear.
- **Target:** a key derived from a SENSITIVE base is SENSITIVE; a template asking for `CKA_SENSITIVE` FALSE from such a base is 0xD1. ALWAYS_SENSITIVE of the derived key is the base's ALWAYS_SENSITIVE and its own SENSITIVE (PKCS#11 §4.10), kept as stored history (table: RULE-059). `CKA_CLASS=CKO_DATA` is 0xD1 for every mechanism but `CKM_HKDF_DATA`. Recorded: as decided, `CKM_HKDF_DATA` from a sensitive base still yields a readable data object.
- **Test:** each derive mechanism from a sensitive and a non-sensitive base; CKO_DATA with `CKM_HKDF_DERIVE`.
- **Expected harness diff (intended, two tests):**
  - `test_ecdh_peer_point`: `C_DeriveKey(CKM_ECDH1_DERIVE, base = a generated EC private key, template CKA_SENSITIVE=FALSE)` returns 0xD1 instead of CKR_OK (`tests/test_ecdh_peer_point.c:83-86`). Its value checks fail, and the test exits 1 instead of 0.
  - `probe_ecdh_curves`: the same call returns 0xD1 on every curve, for the generated key (`:143-146`) and the imported one (`:180-183`, a private key, always sensitive under RULE-058). Its table prints 0xd1 in both derive columns, the X25519 agreement prints FAIL, and the probe exits 1 instead of 0 (`:194-196`, `:290`).
  - The harness carries a patched copy of each, deriving with the template's SENSITIVE left out, so the peer-point checks still run. The unpatched originals are the DIV tests: they fail on Rust as recorded and pass on C.
  - The HKDF, concatenation and nested-template tests derive from bases created non-sensitive and are unchanged.

### DIV-058 · RULE-063 `C_WrapKey` refuses a non-extractable key (SEC-003)

- **Status:** DECIDED, Fix (2026-11-03, Q15, user: "SEC-003: refuse C_WrapKey whenever EXTRACTABLE is false.").
- **Legacy:** only SENSITIVE=TRUE with EXTRACTABLE=FALSE is refused (`src/fhsm_pkcs11.c:4984-5030`). A key that is neither sensitive nor extractable (the derive and KEM default) wraps under a key the caller imported, and leaves the token. The comment at `:7215-7217` claims otherwise.
- **Target:** a target with EXTRACTABLE=FALSE is `CKR_KEY_UNEXTRACTABLE` (0x6A), at the position of today's check.
- **Test:** wrap a non-sensitive, non-extractable key.
- **Expected harness diff:** none. Every wrap target in the five tests that call `C_WrapKey` is created with `CKA_EXTRACTABLE` TRUE.

### DIV-059 · RULE-036, RULE-079(a) PIN minimum

- **Status:** DONE (2026-11-04, Phase 4 slice 1, `core/src/p11.rs` `new_pin_len_ok`; test `p11_divs.c` DIV-059, harness step 4h; `test_input_validation` patched in the harness copy). DECIDED, Fix (2026-11-03, Q7's Phase 4 half, user: "8 everywhere (Recommended)"). An old PIN (`C_SetPIN`'s first, `C_Login`'s) keeps C's 4, so a short PIN set before can still log in and be changed. A re-init checks the SO PIN it is given as a new PIN, as decided: a token whose SO PIN is 4-7 bytes cannot be re-initialised; deleting the file stays the recovery (RULE-079).
- **Legacy:** 4 for `C_InitPIN`, `C_SetPIN`, a re-init's SO PIN and `C_GetTokenInfo`'s `ulMinPinLen`; 8 for a fresh token's SO PIN, reported as `CKR_PIN_INCORRECT` (0xA0) instead of 0xA2. `docs/FIPS_140_3.md:63` says 8.
- **Target:** a new PIN under 8 bytes is 0xA2 on every path (`C_InitToken` fresh and re-init, `C_InitPIN`, `C_SetPIN`'s new PIN); `ulMinPinLen` is 8. `C_Login` is unchanged, so an existing token whose PIN is 4–7 bytes still logs in.
- **Expected harness diff (intended, one test):** `test_input_validation` checks `ti.ulMinPinLen != 4 || ti.ulMaxPinLen != 64` after `C_GetTokenInfo` (`tests/test_input_validation.c:197`), and fails with 8. Every PIN in the legacy tests and scripts is 8 bytes or more. The alternative, 4 everywhere, changes the fresh-token SO PIN instead and has no harness diff.

### DIV-001 in Phase 4

The 45 `fhsm_pkcs11.c` and 2 `fhsm_state.c` audit call sites stop discarding the result (DIV-001, decided Q3): an operation whose audit record cannot be made durable returns `CKR_DEVICE_ERROR` (0x30) with its effect suppressed. **Expected harness diff:** none; the one test that fails an audit write (`test_audit_fsync`) drives the audit library directly, with no PKCS#11 call.

### Phase 4 rules kept as C does them, fixed, or deferred (decision: as below, 2026-11-03, user: "Approve as drafted (Recommended)")

| Rule | Suspected defect | Proposed | Expected harness diff |
|---|---|---|---|
| RULE-006 | `(uint32_t)p.iterations` narrows before the floor check (`:2829`): 2^32 + 2000 runs 2000 iterations | Fix: a count over 0xFFFFFFFF is `CKR_MECHANISM_PARAM_INVALID` (0x71) | none |
| RULE-014 | GENERIC_SECRET of 1–13 bytes in the strict build (< 112 bits, SP 800-131A) | Fix in `nist-approved-only` only: `CKR_KEY_SIZE_RANGE` (0x62) | none found; the FIPS step confirms |
| RULE-015 | A requested public exponent is replaced by 65537 and CKR_OK returned; e = 3 accepted | Fix: generate with the requested e when odd and 2^16 < e < 2^256 (FIPS 186-5), else `CKR_ATTRIBUTE_VALUE_INVALID` (0x13); absent stays 65537 | none (`test_rsa_oaep` sets the exponent on import only) |
| RULE-017 | A string `CKA_PARAMETER_SET` is checked against all 18 names, not the family: ML-KEM keygen with "ML-DSA-65" stores an ML-DSA key as CKK_ML_KEM | Fix: a name outside the mechanism's family is 0x13 | none |
| RULE-018 | GCM tags of 8–88 bits in the strict build | Preserve. SP 800-38D allows 32 and 64 under conditions the module cannot check; `test_gmac_params` uses 32 | none |
| RULE-020 | ML-KEM truncation checks 1..32 but not the key type: CKK_AES of 5 bytes is stored | Fix: an AES length other than 16, 24, 32 is 0x62 | none |
| RULE-035 | A read-only session opened during the SO's PBKDF2 is missed | Fix by construction: Rust re-checks under the API lock when the login commits | none |
| RULE-037(a) | `C_EncapsulateKey` and `C_DecapsulateKey` create token objects from a read-only session | Fix: 0xB5 ((b) is DIV-056) | none |
| RULE-055 | `CKA_PRIVATE` is not stored; visibility follows the class (a private CKO_DATA is public) | Preserve in Phase 4: storing it changes every object record and every visibility path. Recorded for after the cutover | none |
| RULE-058 | KEM secrets default to SENSITIVE FALSE, against the comment at `:5459`; a decapsulated secret from a sensitive private key is readable | Preserve, and drop the comment. Applying DIV-057's rule to `C_DecapsulateKey` would fail `mlkem_e2e`, which reads the secret. Say if you want it anyway | none |
| RULE-059 | ALWAYS_SENSITIVE and NEVER_EXTRACTABLE are computed from current flags, not history | Fix (DIV-057 needs it): two history bits in the free part of `flags3`, set when a key is ever non-sensitive or ever extractable. Both are 0 in every existing file, so old objects read as today (Q5); unwrapped and imported keys start with them set, per PKCS#11 | none (`test_attributes` reads a generated key: TRUE, TRUE as before) |
| RULE-061 (Phase 2 candidate 4) | `fhsm_token_mech_allowed` answers OK for an unknown handle or nothing loaded | Fix: the policy check refuses what it cannot find; its callers check the handle first, so no reachable result changes | none |
| RULE-065 | The strict build's `fhsm-service` always signs with the composite mechanism, so `/sign` returns 500 | Phase 6, with the service | none |
| RULE-070 | AUTHENTICATED is whitelisted but never set | Preserve; nothing changes behaviour | none |
| RULE-071 | A second `C_Initialize` returns 0x6, not `CKR_CRYPTOKI_ALREADY_INITIALIZED` (0x191) | Fix: 0x191. DONE 2026-11-04, slice 1 (`lifecycle.rs`; `p11_divs.c` RULE-071). In ERROR it stays 0x6 | none (no test initialises twice; a forked child's `C_Initialize` is a fresh initialisation) |
| RULE-079 (VAL-12) | A locked SO cannot re-initialise; `docs/FIPS_140_3.md:63` says `C_InitToken` clears the lock | Preserve: the lock is the control, deleting the file the recovery. The doc goes on the cutover list | none |
| RULE-083 | 0x101 where PKCS#11 says `CKR_USER_PIN_NOT_INITIALIZED` (0x102) | Fix: 0x102. DONE 2026-11-04, slice 1 (`login.rs`, mapped where `C_Login` returns; the token layer keeps 0x101; `p11_divs.c` RULE-083) | none |
| RULE-084 | `CKF_*_PIN_COUNT_LOW` and `CKF_*_PIN_FINAL_TRY` never set; `PIN_THROTTLED` is mapped but never returned | Fix: COUNT_LOW while 1 ≤ failures < 5, FINAL_TRY at 4, for USER and SO; the dead mapping is not carried over | none |
| RULE-090 (Phase 2 candidate 5) | `fhsm_token_destroy_session_objects` checks no login | Preserve: closing a session must clean up whoever is logged in | none |
| RULE-091 | A session object's marking result is ignored (`:2554`), so a failed rewrite leaves it a token object; 128 sessions advertised, 127 possible | Fix: a failed marking destroys the object and returns the error; 128 sessions open | none |
| RULE-092 | No ERROR check; no session ownership check; no visibility check; an unknown handle is 0x60 | ERROR: DIV-053. Visibility: DIV-050. Ownership: preserve (PKCS#11 shares session objects among the application's sessions). Unknown handle: Fix, `CKR_OBJECT_HANDLE_INVALID` (0x82) | none (no test destroys an unknown handle) |
