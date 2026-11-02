# Phase 2 transform plan: token store, TPM sealing, revocation DB

*Written 2026-10-30 for `/modernize-transform` Step 0b. Binding inputs: `MODERNIZATION_BRIEF.md`
Phase 2 (approved for Phases 1 and 2), `DIVERGENCES.md` DIV-010 to DIV-016 and the deferral
table, and `PILOT_PLAYBOOK.md`. No code is written until this plan is approved.*

**Approved 2026-10-30, with the §7 amendments** (mor-sec, in session: "Approve plan + amendments").

## 1. Source in scope

| C file | Lines | Exported symbols | Linked into |
|---|---|---|---|
| `src/fhsm_tpm.c` | 408 | 3 (`fhsm_tpm_available`, `_seal`, `_unseal`) | `libfreehsm.so` |
| `src/fhsm_token_tpm.c` | 149 | 6 | `libfreehsm.so` |
| `src/fhsm_revocation.c` | 572 | 13 (DB and OCSP) | **not** the module: `$(REVOCATION_OBJ)` goes into `fhsm-ca`, the service and tests |
| `src/fhsm_token.c` | 2,687 | 39 | `libfreehsm.so` |

Their C dependencies stay C and are called over FFI until their own phases:
- Phase 3: `fhsm_pbkdf2`, `fhsm_aes_gcm_*`, `fhsm_rng_bytes`, `fhsm_secure_*` and `fhsm_zeroize`.
- Phase 4: `fhsm_api_free_value`, the deferred zeroisation behind the API lock (RULE-078).

The C callers are `fhsm_pkcs11.c`, `fhsm_session.c`, `fhsm_apilock.c`, `fhsm_audit` (Rust now), the tools, the service and 18 test sources.

## 2. Order: three slices, one plan

1. **TPM** (`fhsm_tpm.c` and `fhsm_token_tpm.c`, about 560 lines). It has the smallest surface. The audit key provisioning and the token store both call it.
2. **Revocation** (`fhsm_revocation.c`). It is self-contained, but it is a different link point: the tools, not the module.
3. **Token store** (`fhsm_token.c`). This is the bulk of the phase, and it carries the risk.

Each slice runs the playbook recipe on its own: characterization tests, then code, then the harness.

**Progress:**
- **Slice 1 (TPM): done 2026-10-31.**
  - 104 + 8 + 3 TPM tests pass, and the workspace passes 308.
  - Hybrid harness: 106/106; `nm -D` and NEEDED are identical; the C TPM objects are empty; `FHSM_TPM_CMD` is in `test_tpm` only.
  - Corpus: 64 same and 4 DIFF, the same four explained commands. TSan: 4/4 with 0 races.
- **Slice 2 (revocation): done 2026-10-31.**
  - `pqhsm-pki`: 322 safe-API and 14 C-ABI tests pass; the workspace passes 655. DIV-016 and DIV-019 to DIV-022 are implemented; 11 more candidates are recorded as preserved.
  - Hybrid harness: 106/106; `nm -D` and NEEDED identical; the C revocation object is empty and `libfreehsm.so` carries no `fhsm_rev_*`/`OCSP_*`; `fhsm-ca` links the Rust code; `make revocation-db` (newly in the harness) 17 OK, 0 FAIL.
  - Corpus: 64 same and the same 4 DIFF. TSan: 4/4 with 0 races.
  - Not run: `make ocsp-delegated` (it cleans and rebuilds under another PROFILE).
  - Also fixed: `module/Cargo.toml` gets `publish = false`, which `cargo deny` needs for the slice 1 crate's path dependencies.
- **Slice 3 (token store): done 2026-10-31.**
  - `pqhsm-token`: 269 safe-API tests, 289 with the C ABI; the workspace passes 829. DIV-010 to DIV-015 (token parts), DIV-001's 11 token sites and DIV-023 to DIV-027 are implemented.
  - Object values and the DEK live in C's secure heap and are freed through `fhsm_api_free_value` (review M2, RULE-078); the reference implementation kept them in pageable memory.
  - Hybrid harness: 106/106; `nm -D` and NEEDED identical; the C token object is empty and the module's 43 `fhsm_token_*` are Rust; `revocation-db` 17 OK.
  - Corpus: 64 same and the same 4 DIFF. TSan: 4/4 with 0 races, after the token lock became a `pthread_mutex_t` under `ffi` (`token/src/ffi/lock.rs`): TSan cannot see std's futex mutex in an uninstrumented staticlib and reported 35 false races.
  - `-DFHSM_MAX_OBJECTS=` no longer reaches the store (fixed at 1024).
- **Exit criteria: met 2026-11-01** (ticked in the brief; evidence in `modernized/pqHSM/TRANSFORMATION_NOTES.md`, Phase 2).
  - Added for the evidence: `gen_token describe` and `public` modes, built over both stores in the harness (step 8); `token/fuzz/`.
  - Architecture review: 3 HIGH applied (key custody in `unwrap_dek`, `gcm_decrypt` and `serialize`; the missing `pqhsm-token migrate-zero-dek` command), L-1 applied; 6 MEDIUM and 5 LOW recorded for a decision.
- **Review MEDIUM findings, 2026-11-02** (user: "fix M-1 to M-4 and M-6 before Phase 3"): M-1 to M-4 applied as amendments to DIV-012, DIV-014 and DIV-015; M-6 recorded as DIV-028 to DIV-030. M-5 is left for Phase 4, which rewrites those call sites.
- **Next:** Phase 3, per `PHASE3_PLAN.md` (approved 2026-11-02). The token `.tmp` and `.tpm.new` symlink fixes landed as DIV-031.

## 3. Target structure

```
modernized/pqHSM/
  module/      NEW  pqhsm-module: the ONE staticlib linked into libfreehsm.so (playbook §2.2).
                    Depends on pqhsm-audit[ffi] and pqhsm-token[ffi]. No code of its own.
  audit/            crate-type becomes rlib only. Its c_abi stays where it is.
  token/       NEW  pqhsm-token: header.rs (the 317-byte layout), store.rs (the v4 object
                    blob and public section), token.rs (load, init, login, counters, flock),
                    tpm.rs (tpm2-tools subprocess over memfd), ffi/ (C ABI plus the Phase 3/4
                    imports; all unsafe code goes here). Feature `tpm-test-hooks` mirrors
                    -DFHSM_TPM_TEST_HOOKS. bin/pqhsm-token: `migrate-zero-dek` (DIV-010).
  pki/         NEW  pqhsm-pki: revocation.rs (DB and OCSP via openssl-sys, as in Q2).
                    rlib only, linked through pqhsm-module (review H5). Phase 3 adds the
                    encoders here.
  testdata/         the golden corpus (done, see regen_token.sh).
```

`hybrid.mk` changes:
- (a) `PQHSM_LIB` points at `libpqhsm_module.a`.
- (b) Empty-TU recipes for `fhsm_token.o`, `fhsm_token_tpm.o` and `fhsm_tpm.o`.
- (c) An explicit empty-TU recipe for `$(OBJDIR)/src/fhsm_revocation.o` that depends on `PQHSM_LIB`. Setting `REVOCATION_OBJ` after `include` would not work, because the prerequisite lists are already expanded (review H5). The harness also checks that `libfreehsm.so` imports no `OCSP_*` or `fhsm_rev_*` symbols.
- (d) `$(OBJDIR)/tests/fhsm_tpm_testhooks.o` becomes an empty TU, and `tests/test_tpm` links a module staticlib built with `tpm-test-hooks` into its **own `--target-dir`**, through `tests/test_tpm: PQHSM_LIB := …`. Otherwise the seam's object and the Rust TPM both define `fhsm_tpm_*` and the link fails. The separate target dir means the shipped `.a` is never the hooks build: the harness asserts that `strings libfreehsm.so` contains no `FHSM_TPM_CMD` (review H6).
- (e) The `PQHSM_LIB` prerequisites are every `*.rs` under the workspace, found with `find` (review L2). `module/lib.rs` names each crate with `extern crate`, so that their `#[no_mangle]` symbols are linked (review L1).

C-visible types keep their layout as `#[repr(C)]`: `fhsm_rev_db_t` and `fhsm_rev_entry_t`. `fhsm_token_t` stays opaque. Some lifetime contracts are reproduced exactly:
- pointers from `fhsm_token_object_get` are valid until the next mutation;
- label and id getters return a per-thread copy, held in a `const`-initialised array with no destructor (playbook: TLS teardown).

## 4. Rules implemented

- **P0, preserved:** RULE-001 (the iteration floor changes, per DIV-011), 002, 003, 004, 044, 057, 061, 078, 081, 088, 089 and 093 (via Rust TPM).
- **Revocation:** RULE-024 and 099/100 (the parsing part).
- **Divergences implemented here:** DIV-010 to DIV-016, plus the DIV-001 fail-closed call sites in the token store (11).
- **Deferred:** as tabled in `DIVERGENCES.md`.

## 5. How equivalence is proved

1. **Golden corpus, both directions.**
   - Rust loads every file in `testdata/` and reproduces `manifest.tsv` and `revocation.tsv` exactly. Paths in error text are normalised.
   - C loads every file Rust writes: `gen_token` gains a `describe DIR` mode, and its output must equal the same manifest after the random fields are masked (serial, salts, nonces, ciphertext).
2. **Header pinning.** A test writes each field through the Rust writer and checks the byte offsets against the C layout comment (`src/fhsm_token.c:289-311`). This mitigates Phase 2 risk 1.
3. **Hybrid `make tests`, 106/106,** including the token-linked tests (`test_v3_fixture`, `test_throttle_reboot`, `test_pin_length`, `test_token_capacity`, `test_wrong_pin_store`, `test_tpm` and the others).
4. **Harness from day 1** (new brief criterion). The corpus diff of step 6 extends from audit logs to on-disk token side effects. The token file left by each command is compared after normalisation: the header's non-random fields, plus C's `describe` of the decrypted objects. C-against-C runs as the control. TSan runs `test_concurrency_store` (Phase 2 exit criterion) on every run.
5. **Divergence tests.** One per DIV. Each fails on C and passes on Rust, in the style of the `DIV008` table.
6. **Fuzz:** `cargo-fuzz` targets for the header and blob parsers. **Brief gap:** the exit criterion says "survive the existing `fuzz/corpus`", but that corpus has no token inputs (it holds `attr_template`, `create_attrs`, `ecdsa_raw` and `pq_params`). Proposed: seed from `testdata/*.tok`, and edit the criterion to say so.

## 6. Decisions needed now

1. **Crypto path until Phase 3.** Recommended: call the C `fhsm_pbkdf2`, `fhsm_aes_gcm_*` and `fhsm_rng_bytes` over FFI, so that the self-test gate, the ERROR state and the DRBG health tests stay in one place. The alternative is calling libcrypto directly, as the audit HMAC does, which would bypass `fhsm_crypto`'s approved-mode checks for key custody.
2. **The aggregate staticlib** (`pqhsm-module`), as the playbook recommends, rather than adding the token crate into `pqhsm-audit`.
3. **The fuzz-corpus edit to the brief** in §5.6.

## 7. Architecture review (2026-10-30, before the tests) and the amendments it forces

The plan was reviewed by the architecture-critic before any characterization test was written, as the brief now requires. I checked its main factual claims against the code: 21 `write_atomic` sites; `PQHSM_LIB` appended to `LDFLAGS`, which every tool link inherits; the revocation object as a prerequisite in the tool rules (`Makefile:329-342`); memfds created without `MFD_CLOEXEC` (`src/fhsm_tpm.c:242`). All of them hold.

**HIGH, applied to this plan:**
- **H1, H2, H3 → one token file transaction.** Every token write goes through a single helper. This is an amendment to DIV-012 and DIV-013, which you need to confirm. The helper:
  1. opens `slotN.tok` with `O_CLOEXEC` and takes `flock`;
  2. checks `fstat(fd)` against `stat(path)` on st_dev and st_ino, and retries if a rename replaced the inode;
  3. re-reads the header and takes the counters from disk. If the serial or the wraps differ from memory (another process re-initialised the token), the call fails;
  4. writes tmp, then fsync, then rename, then fsyncs the directory;
  5. calls `LOCK_UN` explicitly before closing.

  The throttle sleep releases both the flock and the mutex, then derives the deadline again from the re-read count.

  **Login counts before it checks** (DIV-013 amended). Under the lock, `failed+1` is made durable *before* PBKDF2. If that write fails, the call is refused without looking at the PIN. A correct PIN then writes the counter back to 0. If that reset write fails, the objects are unloaded, the DEK is zeroised, `dek_live` and `logged_in` are cleared, and the call returns `CKR_FUNCTION_FAILED`.

  This closes the timing oracle a "fail after checking" design leaves when the disk refuses writes. Two costs:
  - A correct login now makes two writes, where C makes one.
  - A crash between them leaves one extra failure counted.
- **H4: fail-closed order and the lock order.** A mutation is built on a copy, then audited, then written, then swapped into memory. If the audit fails, nothing changes. If the audit succeeds and the write then fails, memory stays unchanged and the call fails; the audit record then describes an attempt that did not take effect, and a second record logs the write failure. The lock order is fixed and documented: apilock, then token mutex, then flock, then the audit mutex.
- **H5: a single staticlib.** pki goes inside `pqhsm-module`, with an empty-TU `fhsm_revocation.o`; see §3(c). Two Rust staticlibs in one executable would duplicate the Rust runtime symbols. I did not test that link, because the single-staticlib design avoids it.
- **H6: the test-hooks build is isolated.** See §3(d).

**MEDIUM, applied:**
- **M1, TPM subprocess.** In hooks mode only, `FHSM_TPM_CMD` keeps C's `sh -c` splitting, so `test_tpm` passes unchanged. Memfds are created `MFD_CLOEXEC`, and the flag is cleared only in `pre_exec` for the `tpm2` child, so no other fork inherits the DEK. This is DIV-017; you confirm it at the plan gate.
- **M2, pointer contracts.**
  - The per-thread copies cover `get_label`, `get_id` and `get_meta`.
  - `fhsm_token_label` and `fhsm_token_serial` point at inline `[u8; 65]` fields of a boxed struct that never moves.
  - Object values are C allocations, released only through `fhsm_api_free_value`.
  - The DEK lives in `fhsm_secure_zalloc` memory.
- **M3, fork.** `fhsm_token_close` never locks, because the fork-child reset calls it (`src/fhsm_pkcs11.c:2081-2088`). DIV-012 knowingly breaks the playbook's "no lock across I/O" rule for the flock. It is safe only because flock is per open file description and the child never reuses it. A new test forks during a login.
- **M4, a stronger side-effect diff.**
  - Byte for byte: the cleartext public section, the ciphertext length, the file set (no leftover `.tmp` or `.tpm.new`) and mode 0600.
  - A property test: every write draws a fresh nonce, and `salt_so` differs from `salt_user`.
  - The harness gets each command's PIN from the test's own source constants. Nothing from the legacy tree becomes a fixture: the harness only re-runs the tests, as the C build does.
  - §5.1 stands, with one stated exception: the `zero_dek_2_5_0.tok` row fails to log in under Rust (DIV-010).
- **M5, order on re-init.** Reseal (DIV-015) before the DEK is zeroised (DIV-014).

**LOW, applied:** L1 and L2 go into §3(e). L3: `fhsm_rev_db_load` never reads the caller's struct, and `_free` accepts NULL. L4: TPM availability is cached in a `OnceLock`.

**Decisions in §6, with the reviewer's view:**
1. **C crypto over FFI.** The reviewer agrees. Under `cargo test` (no `ffi`), an openssl-sys backend stands in, and a test checks that both backends give the same output on the same vectors. `migrate-zero-dek` is offline, so it uses openssl-sys and links no C.
2. **Aggregate staticlib.** The reviewer agrees, with pki included.
3. **Fuzz corpus.** The reviewer agrees. Seed from `testdata/*.tok` and mutated headers, and also run the existing corpus.
