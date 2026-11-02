# Modernization Assessment — pqHSM (FreeHSM 2.6.0, C11)

*Generated 2026-10-30 by `/code-modernization:modernize-assess pqHSM`. The system under study is
the repository root `~/Projects/pqHSM` (there is no `legacy/` dir; see `PREFLIGHT.md`). Target
named by the requester: **a full cross-stack rewrite to Rust, renamed pqHSM**.*

**Tools used (to reproduce the figures):**
- `scc` 3.7.0 for LOC and file complexity. It is at `~/go/bin/scc`. Its COCOMO cost, schedule and people lines were ignored.
- `cloc` 2.08 as a cross-check; it agrees with `scc` within 1%.
- `lizard` 1.24.3 for per-function cyclomatic complexity (CCN).
- Build and test verification ran in the project's own pinned image (`Dockerfile.build`, OpenSSL 3.5.7).
- Three parallel analysis agents produced the domain map, technical-debt and security findings. I re-checked every High finding and every claim that contradicted earlier statements against the code.

---

## Executive Summary

pqHSM is a software hardware-security module: one shared library, `libfreehsm.so`, that
implements the industry-standard PKCS#11 v3.2 interface. It offers 92 cryptographic mechanisms,
including the new NIST post-quantum algorithms, and is written in C on top of the OpenSSL 3.5
FIPS provider. Around it sit an HTTP signing/OCSP service, five PKI command-line tools and a
desktop GUI.

It is **mid-sized but very concentrated**:
- 30k lines of shipping C code, plus 23k lines of tests.
- A single 13,400-line file holds 37% of all code complexity and every one of the 62 API entry points.

It is **well tested**: the full suite of 110+ tests passes here. But it carries **two
High-severity security defects**:
- A logged-out session can still use secret keys. I reproduced this.
- A token file tampered with offline can inject keys at the next legitimate login.

It also has a layer of generated "dispatch" code and runtime configuration that looks
authoritative but does nothing.

**Recommendation:** *Rearchitect* to Rust behind the **unchanged PKCS#11 C interface**, replacing
the internals leaf-first (audit, token store, crypto core, then the API layer). Validate every
step by running the same PKCS#11 call sequences against the C library and the Rust library and
comparing the results. Fix the two High defects as **deliberate, recorded divergences**, not as
behaviour to preserve.

---

## System Inventory

### Size (`scc --exclude-dir analysis,dist,fuzz/corpus .`)

| Language | Files | Lines | Blanks | Comments | Code | Complexity |
|---|---:|---:|---:|---:|---:|---:|
| C | 177 | 67,770 | 4,856 | 16,472 | 46,442 | 16,325 |
| Markdown | 104 | 30,474 | 6,583 | 0 | 23,891 | 0 |
| Shell | 37 | 7,548 | 766 | 2,189 | 4,593 | 768 |
| Python | 31 | 6,816 | 576 | 1,511 | 4,729 | 807 |
| C Header | 28 | 5,653 | 499 | 3,065 | 2,089 | 135 |
| YAML | 11 | 2,030 | 135 | 752 | 1,143 | 0 |
| Makefile | 2 | 1,809 | 193 | 735 | 881 | 33 |
| Other (text, patch, licence, systemd, TOML, Bazel) | 14 | 1,482 | 134 | 192 | 1,156 | 4 |
| **Total** | **404** | **123,582** | **13,742** | **24,916** | **84,924** | **18,072** |

**Shipping code** (`src/`, `include/`, `service/`, `tools/`, `kat/`) is **30,178 lines** of C
and headers (72 files). **Tests, fuzz harnesses and probes** add 23,280 lines (`cloc`).

### Highest-complexity files (`scc --by-file -s complexity`, C/H only)

| File | Lines | Code | Complexity | Note |
|---|---:|---:|---:|---|
| `src/fhsm_pkcs11.c` | 13,386 | 8,034 | **3,831** | All 62 `C_*` entry points; 37% of shipping complexity |
| `src/fhsm_composite.c` | 2,917 | 2,151 | 1,040 | Composite ML-DSA + X.509/CSR/CRL/OCSP/CMS encoders |
| `tools/pkiops.c` | 2,465 | 2,076 | 799 | Shared PKI tool operations |
| `service/fhsm_service.c` | 2,812 | 1,772 | 660 | Hand-written HTTP/1.1 server |
| `src/fhsm_token.c` | 2,687 | 1,787 | 563 | On-disk token store, PIN, DEK |
| `tools/fhsm_gui.c` | 3,240 | 2,726 | 511 | GTK 4 GUI |
| `kat/cavp_extended.c` | 1,997 | 1,376 | 300 | Extended CAVP vectors |

### Per-function complexity (`lizard`)

- 1,118 functions, mean CCN 8.6, max 159.
- 27 functions have CCN > 50, 58 are in 21–50 and 137 in 11–20.

The worst are all PKCS#11 entry points:

| Function | Location | CCN |
|---|---|---:|
| `C_CreateObject` | `src/fhsm_pkcs11.c:3559` | 159 |
| `C_Encrypt` | `src/fhsm_pkcs11.c:9777` | 141 |
| `C_Decrypt` | `src/fhsm_pkcs11.c:10231` | 136 |
| `C_DeriveKey` | `src/fhsm_pkcs11.c:4277` | 135 |
| `op_init` | `src/fhsm_pkcs11.c:9037` | 129 |
| `main` | `service/fhsm_service.c:2409` | 125 |
| `C_GetAttributeValue` | `src/fhsm_pkcs11.c:7155` | 123 |

### Technology fingerprint

| Aspect | Finding | Evidence |
|---|---|---|
| Language / standard | C11, `-Werror` with an extensive hardening flag set, `-fvisibility=hidden` | `Makefile:38-103` |
| Crypto runtime | OpenSSL **3.5.7** (pinned via a Debian snapshot), FIPS provider, `OPENSSL_API_COMPAT=0x30000000L`; no deprecated APIs in live code | `Dockerfile.build:41-84`, `Makefile:86` |
| Interface | PKCS#11 **v3.2** (`C_GetInterface`) plus a v2.40 function list | `src/fhsm_pkcs11.c:13165`, `:13301-13316` |
| Version | 2.6.0 | `include/fhsm_common.h:136` |
| Build | GNU Make (1,778 lines). `generate` runs `scripts/gen_p11_thunks.py`. Build profiles `nist-approved-only` (default) and `all-mechanisms`. `make integrity` signs a `.fhsm_digest` section. | `Makefile:296`, `:405-539`, `:1577` |
| Reproducible build | Debian trixie pinned by digest plus `snapshot.debian.org/20261006T000000Z`; `SOURCE_DATE_EPOCH`; `dist-verify` against `dist/refs/*.sha256` | `Dockerfile.build`, `scripts/build_reproducible.sh` |
| CI | 10 GitHub workflows: build, lint, static analysis, ASan/UBSan, TSan, coverage matrix, FIPS provider, GUI smoke, reproducibility, pkcs11-check, Wycheproof, nightly fuzz, release, mirror | `.github/workflows/` |
| Data stores | **Binary token file** `slotN.tok` (317-byte header + AES-GCM object blob + public section). **HMAC-chained JSON-lines audit log** with a separate `audit.key`. Revocation DB (text). Optional `.tpm` sealed blobs. | `docs/TOKEN_STORE_FORMAT.md`, `include/fhsm_audit.h`, `src/fhsm_revocation.c:165` |
| Integration points | PKCS#11 C ABI, consumed via `dlopen` by OpenSC `pkcs11-tool`, OpenSSL `pkcs11-provider`, p11-kit and the in-repo tools. HTTP over a unix socket behind an mTLS reverse proxy (`/sign`, `/verify`) plus a public listener (`/certificates`, `/ocsp`). The `tpm2` CLI. systemd. | `docs/THIRD_PARTY_CONSUMERS.md`, `service/fhsm_service.c:1578-1637`, `:1961-1988`, `src/fhsm_tpm.c:172` |
| Config | `/etc/freehsm/freehsm.conf` (`mode`, `secure_heap_kb`); about 22 `getenv` variables (`FHSM_TOKENS_DIR`, `FHSM_AUDIT_LOG`, `FHSM_MODE`, `FHSM_INTEGRITY_ALLOW_UNSIGNED`, …) | `Makefile:1663`, `src/fhsm_conf.c` |
| Tests | 116 C tests (110 wired into `make tests`), 17 shell harnesses, CAVP `.rsp`, ML-DSA/SLH-DSA KAT vectors, Wycheproof adapters, 4 libFuzzer harnesses. **`make tests` passes: exit 0 in 213s, 0 failures.** The `test_advertised_operational` probe found 92 mechanisms advertised and 155 operations probed, with 0 gaps. | `Makefile:1170-1480`; run log from preflight |
| Coverage signal | No `make coverage` target exists, although `docs/ARCHITECTURE.md` §9 claims one with a ≥95% target. Coverage is unmeasured. | `docs/ARCHITECTURE.md` §9, `Makefile` |

---

## Architecture-at-a-Glance

Eleven functional domains. The dependency diagram is in [`ARCHITECTURE.mmd`](ARCHITECTURE.mmd).
An interactive code map from an earlier pass is in the session scratchpad
(`freehsm-map.html`).

| # | Domain | Responsibility | Key files | Code LOC |
|---|---|---|---|---:|
| D1 | PKCS#11 API & object model | All `C_*` entry points, attribute and template engine, object policy, per-mechanism switches | `src/fhsm_pkcs11.c`, `src/fhsm_create_attrs.c`, `src/fhsm_pq_params.c`, `src/fhsm_ecdsa_raw.c` | 8,658 |
| D2 | Lifecycle, sessions, concurrency | State machine, API rwlock (`FHSM_API_EXCLUSIVE/SHARED`, 59 uses), session table | `src/fhsm_state.c`, `src/fhsm_apilock.c`, `src/fhsm_session.c` | 388 |
| D3 | Token store + TPM sealing | `slotN.tok` persistence, PIN throttle, DEK wrap, object blob; optional TPM sealing via the `tpm2` CLI | `src/fhsm_token.c`, `src/fhsm_token_tpm.c`, `src/fhsm_tpm.c` | 2,229 |
| D4 | Crypto core, DRBG, secure heap, config | EVP wrappers, provider loading, SP 800-90B DRBG, mlocked heap, conf reader | `src/fhsm_crypto.c`, `src/fhsm_drbg.c`, `src/fhsm_memory.c`, `src/fhsm_conf.c` | 897 |
| D5 | Mechanism registry & dispatch | Generated `fhsm_mechanism_table[]` (**advertisement only**), `dispatch_*` handlers (**never called**), runtime mode (**inert**) | `scripts/gen_p11_thunks.py`, `src/gen/fhsm_dispatch.c`, `src/dispatch/*`, `src/fhsm_mode.c` | 3,460 |
| D6 | Self-tests & integrity | Power-on KATs, extended CAVP, pairwise test, `.fhsm_digest` check | `kat/fhsm_kat_vectors.c`, `kat/cavp_extended.c`, `src/fhsm_integrity.c`, `src/fhsm_pairwise.c` | 2,073 |
| D7 | Audit trail | HMAC-chained JSON-lines; key sealed via D3's TPM path; standalone verifier shares no code (format contract only) | `src/fhsm_audit.c`, `tools/freehsm_audit.c` | 873 |
| D8 | Composite ML-DSA, PKI encoding, revocation | X.509/CSR/CRL/OCSP/CMS behind a signer callback; revocation DB is outside the module | `src/fhsm_composite.c`, `src/fhsm_revocation.c`, `include/fhsm_pki.h` | 2,942 |
| D9 | HTTP signing/OCSP service | Private listener (`/health`, `/token`, `/sign`, `/verify`) and public listener (`/certificates`, `/ocsp`); statically links the module objects | `service/fhsm_service.c`, `systemd/fhsm-service.service` | 1,772 |
| D10 | PKI CLI tools & GTK GUI | `fhsm-csr/-ca/-sign/-token/-crypt`, `fhsm-gui` over `pkiops`; load the module via `dlopen` | `tools/*` | 6,924 |
| D11 | Build, verification & release | Makefile, generator, signing, sanitizers, reproducible dist, CI | `Makefile`, `scripts/*`, `tests/*`, `fuzz/*`, `.github/workflows/*` | ~4,200 + 23,280 tests |

**Structural facts the rewrite depends on:**
- **The PKCS#11 ABI is the only contract external consumers see**, and it is fixed by the OASIS standard. That makes it the natural seam for a strangler migration and for differential testing.
- **D5 is mostly dead weight.** Nothing dereferences `fhsm_mechanism_table[].handler`; the only use is a pointer comparison at `src/fhsm_pkcs11.c:1541`. Real dispatch is 11 hand-written `switch` blocks in D1. Port behaviour from D1's switches, not from `src/dispatch/`.
- **D1 is one translation unit.** Per-session operation state lives in five global arrays indexed by session handle (`g_op_enc/dec/sig/dig/ver[FHSM_MAX_SESSIONS]`, `src/fhsm_pkcs11.c:2066-2070`) and is set up by `op_init` (CCN 129). That state is the core of PKCS#11 multi-part semantics.
- **Three link models must be preserved or consciously changed:**
  - tools load the module at runtime with `dlopen`;
  - the service links the module objects statically, because it needs the non-exported `fhsm_audit_set_actor`;
  - the revocation code is kept out of the module on purpose (`Makefile:270-277`).

---

## Production Runtime Profile

**No telemetry is available.** There is no APM or observability source for this system, no
production deployment logs, and the connected CloudWatch MCP isn't relevant. The only runtime
evidence is committed lab measurements:
- `probes/rest/` latency, login-cost and concurrency probes;
- `tests/bench_*.c`;
- `tests/service_budget.sh`;
- `docs/RATE_LIMIT.md`.

Without production p50/p99 figures, no domain can be ranked by operational variance. Static risk
ranking (below) stands in.

Suggested substitute: run `probes/rest/01_latency` and `04_concurrency` against the built C
module and record the results as the performance baseline the Rust build must meet.

---

## Technical Debt (top 10, ranked by value to the Rust rewrite)

| # | Finding | Evidence | Impact on the rewrite |
|---|---|---|---|
| 1 | **Generated mechanism layer that does not drive behaviour.** `fhsm_mechanism_table[]` only controls what is advertised. The 64 strong `dispatch_*` handlers (about 2.4k LOC) and 79 weak stubs are never called (the only caller is the unbuilt `tests/test_dispatch.c`). Real dispatch is 11 hand-written switches (107 `case CKM_*`, 33 raw-hex labels). **Consequence:** runtime `FHSM_MODE` / `mode = strict` has **no effect on any entry point**. `fhsm_mode_is_fips()`'s only caller is the never-called `dispatch_reject_fips`, yet the installed `freehsm.conf` says `strict` "refuses the thirteen mechanisms NIST has not approved". | `src/fhsm_pkcs11.c:1428-1433`, `:1541`; `src/gen/fhsm_dispatch.c:21-31`; `src/fhsm_mode.c:136`; `Makefile:1663`; `scripts/gen_p11_thunks.py:26-29` | Make one mechanism enum and table drive advertising, policy and dispatch (a Rust `match` generated by a build script). Do **not** port `src/dispatch/`. Decide explicitly whether a runtime mode exists in pqHSM. |
| 2 | **God file `src/fhsm_pkcs11.c`.** 13,386 lines: 62 entry points, 188 functions, 294 `#define`s, 19 globals; 14 functions over 200 lines (`C_CreateObject` 580). | `src/fhsm_pkcs11.c:1020` (`g_slots`), `:3559`, `:9037`, `:4277`, `:7155` | Split by PKCS#11 function group. Write characterization tests per entry point before porting; the policy rules are buried in 400–600-line functions. |
| 3 | **The test harness overstates assurance.** CI's smoke step (`\| head -30`) and build step (`\| tee`) run without `pipefail`, so failures can pass. The ML-KEM, ML-DSA and SLH-DSA end-to-end tests are never built, so the coverage matrix always records them as SKIP. 6 C tests and 6 shell harnesses are wired into nothing. There is no coverage measurement. | `.github/workflows/ci.yml:204-208`, `:228-230`; `tests/coverage_matrix.sh:479-481`; `Makefile` (no coverage target) | The equivalence oracle must be `make tests` plus explicitly wired PQ e2e tests, **not** CI history. Add `pipefail` before using CI as a gate. |
| 4 | **Environment variables disable self-tests in the production library.** `FHSM_INTEGRITY_ALLOW_UNSIGNED` (plain `getenv`, presence-only) skips the integrity check **and the FIPS provider load**. `FHSM_KAT_ALLOW_FAIL` lets KAT failures pass. `make tests` sets the first for almost every test, so **most tests never exercise the FIPS provider**. | `src/fhsm_crypto.c:84-106`, `:253-254`; `src/fhsm_integrity.c:267` | Put the Rust equivalent behind a non-default cargo feature that release builds reject. Add a CI lane that really loads the FIPS provider. |
| 5 | **PKCS#11 constants re-declared in 6 places**, plus a hand-mirrored copy of `fhsm_mech_entry_t` that must "MUST match" the generated header. | `src/fhsm_pkcs11.c:1442-1468`; `include/fhsm_pkcs11_mechanisms.h:48`; `service/fhsm_service.c:112-119`; `tools/p11_util.h` | Use `cryptoki-sys` or one generated constants crate. |
| 6 | **Comments and docs contradict the code**, so prose is not a spec. PBKDF2 minimum is documented as 200k but the floor is 1,000. PIN minimum is 8 in `EAL4_PLUS.md` but 4 in code. "Digest: SHA-2 one-shot only" is false. "Fourteen" advertised-but-broken mechanisms is now 0. `ARCHITECTURE.md` still says the token store is JSON, references a nonexistent `make coverage`, `tests/fuzz/` and `fhsm_pkcs11.in.h`. | `src/fhsm_crypto.c:542` vs `:561`; `docs/EAL4_PLUS.md:90` vs `include/fhsm_common.h:388`; `src/fhsm_pkcs11.c:1434` vs `tests/test_advertised_operational.c:117-130` | Derive the Rust spec from code and tests (`/modernize-extract-rules`), and reconcile the security-target docs before reuse. |
| 7 | **TPM sealing runs the `tpm2` CLI through `system()`**, with commands assembled by `snprintf` into 2,560-byte buffers. The header says fork+exec. `TPM_DIR` is hardcoded and its `mkdir` result is unchecked. | `src/fhsm_tpm.c:21`, `:63`, `:165-176`, `:194` | Replace with `tss-esapi`. Decide whether existing `.tpm` blobs (tpm2-tools format) must stay readable. |
| 8 | **The HTTP service ignores short writes.** 9 `(void)!write` calls under `SO_SNDTIMEO`, so a truncated signature or OCSP response is still audited as delivered. The HTTP/1.1 server is hand-written. | `service/fhsm_service.c:1423-1426`, `:1876-1877`, `:1982-1983`, `:2181` | Use hyper/axum with `write_all`. The audit verdict must reflect what was actually delivered. |
| 9 | **Config and limits are scattered.** About 22 `getenv` calls and no `secure_getenv`. The literal 200000 appears twice. The per-token `pbkdf2_iter` is read from the header with no minimum beyond 1,000. Compile-time caps: 4 slots, 128 sessions, 1,024 objects, 16 MiB multipart. | `src/fhsm_token.c:1234`, `:1840`, `:1325`; `src/fhsm_pkcs11.c:1024-1026`; `include/fhsm_common.h:424` | Move everything into one typed config. Read `pbkdf2_iter` from header offset 136 to keep on-disk compatibility, and enforce a minimum. |
| 10 | **Dead, duplicated and unpackaged code.** `kat/fhsm_kat_rsp.c` is never compiled, yet `make install` copies all `.rsp` files and only one is read. `disabled/` holds dead code. The root `audit_switch.sh` duplicates `tests/audit_switch.sh`. ECDSA raw↔DER conversion is implemented twice. `make dist` leaves out `tools/`, `service/` and `systemd/`, so the tarball cannot run `make`. **No target installs or signs `fhsm-service`**, so under systemd it would likely fail its integrity check (inferred, not run). | `Makefile:1667`, `:1740-1741`, `:1657-1671`; `src/fhsm_ecdsa_raw.c:41-65` vs `src/fhsm_composite.c:2697-2722`; `systemd/fhsm-service.service:63-64` | Don't port any of this. Define the pqHSM packaging (cdylib, service, tools) from scratch. |

---

## Security Findings

*Credential inventory is in `SECRETS.local.md` (kept outside the project tree at
`~/.modernize/pqHSM/` because the repo has no VCS; not for sharing). It holds only test-fixture
PINs; no production credentials were found.*

**Count:** 2 High, 5 Medium, 7 Low (14 total).

The **Verified** column records what I checked myself, beyond the security agent's own reading:
- **Reproduced:** run against the built library in the pinned container.
- **Code-confirmed:** I re-read the cited code.
- **Agent:** the security agent's code reading only.

| ID | CWE | Sev. | Finding | Evidence | Verified |
|---|---|---|---|---|---|
| SEC-001 | CWE-862 | **High** | **Key use is not gated on login.** `fhsm_require_key` only checks that the handle exists. `fhsm_token_logout` zeroizes the DEK but leaves decrypted objects loaded (`objects_loaded` stays 1). So a **logged-out session can `C_EncryptInit`/`C_Encrypt` (and Sign/Decrypt/Verify) with a secret or private key**. Handles are small sequential integers. SO login also decrypts the user store, and Wrap/Derive/CreateObject only reject role NONE, so the SO can use the user's keys. | `src/fhsm_pkcs11.c:9017-9023`, `:9768-9774`, `:10838-10844`; `src/fhsm_token.c:1645-1653`, `:1945-1966` | **Reproduced**: after `C_Logout`, `C_EncryptInit` and `C_Encrypt` returned `CKR_OK` with a 32-byte ciphertext under a user AES token key. |
| SEC-002 | CWE-354 | **High** | **Zero-DEK fallback.** If the object blob fails to decrypt under the real DEK, `objects_decrypt_load` retries under an all-zero key, with a plaintext serial as the AAD. Anyone who can write `slotN.tok` (no PIN needed) can plant a blob of chosen objects. It is accepted at the next legitimate login and re-encrypted under the real DEK. | `src/fhsm_token.c:987-1003`, `:1529-1532` | **Code-confirmed.** It is a deliberate recovery path for a ≤2.5.0 bug. |
| SEC-003 | CWE-693 | Medium | `C_WrapKey` refuses only keys that are SENSITIVE ∧ ¬EXTRACTABLE. A ¬SENSITIVE ∧ ¬EXTRACTABLE key can be wrapped under a caller-chosen AES key, which exports it in the clear. | `src/fhsm_pkcs11.c:5027-5029` | Agent |
| SEC-004 | CWE-362 / CWE-307 | Medium | PIN failure counters are read once per process with no file lock, so N processes (e.g. p11-kit forking) get N×5 guesses. The fixed `.tmp` name with `O_TRUNC` and no `O_EXCL` lets concurrent writers corrupt the token. | `src/fhsm_token.c:1333-1334`, `:1398-1405`, `:1184-1207` | Agent |
| SEC-005 | CWE-916 / CWE-522 | Medium | TPM sealing is a cross-check, not a factor: the DEK is unwrappable from `.tok` and the PIN alone. A 4-character PIN with PBKDF2 at 200k iterations and a GCM-tag oracle allows offline brute force of a stolen token. | `src/fhsm_token.c:1417-1448`, `:1234`; `include/fhsm_common.h:388` | Agent |
| SEC-006 | CWE-426 / CWE-403 | Medium | `system()` resolves `tpm2` through `$PATH` in the host process. memfds holding the DEK or audit key are created without `MFD_CLOEXEC`. | `src/fhsm_tpm.c:157-176`, `:242-243` | Agent (`system()` call code-confirmed at `:172`) |
| SEC-007 | CWE-489 / CWE-15 | Medium | The runtime env var `FHSM_INTEGRITY_ALLOW_UNSIGNED` (plain `getenv`) skips integrity and the FIPS provider; `FHSM_KAT_ALLOW_FAIL` ignores KAT failures. | `src/fhsm_crypto.c:84-106`, `:253-254` | **Code-confirmed** |
| SEC-008 | CWE-532 | Low | The PIN length is written to the audit log on every login attempt. | `src/fhsm_pkcs11.c:933-941`, `:963-970` | Agent |
| SEC-009 | CWE-345 | Low | The pre-login public section of `.tok` is unauthenticated, so planted public keys or certificates are visible before login (acknowledged in a code comment). | `src/fhsm_token.c:1053-1086` | Agent |
| SEC-010 | CWE-770 | Low | The public OCSP listener signs on every unauthenticated request with no rate limit, and echoes nonces with no 32-byte cap. A stale comment says it never signs. | `service/fhsm_service.c:828-830`, `:1881-1935` | Agent |
| SEC-011 | CWE-526 | Low | CLI tools read PINs from `FHSM_PIN` / `FHSM_SO_PIN` env vars. | `tools/fhsm_sign.c:122`, `tools/fhsm_token.c:94-95` | Agent |
| SEC-012 | CWE-59 / CWE-377 | Low | Fixed-name temp files without `O_EXCL`/`O_NOFOLLOW`; paths taken from plain `getenv`. | `src/fhsm_token.c:1184-1185`, `service/fhsm_service.c:669-673` | Agent |
| SEC-013 | CWE-20 | Low | HTTP header *names* are not character-validated, although a comment says they are. Latent smuggling risk behind non-nginx proxies. | `service/fhsm_service.c:1007-1009`, `:1215-1231` | Agent (**Unconfirmed**) |
| SEC-014 | CWE-1104 | Low | The OpenSSL version is never asserted. The FIPS provider is not in the build image. The snapshot freezes security fixes at 2026-10-06. The test image is unpinned and has a broad sudoers rule. | `Dockerfile.build:41-84`, `Dockerfile.test:29` | Agent |

**Checked and sound** (per the security agent):
- CK_ULONG→int truncation guards;
- HTTP parser bounds and duplicate-identity refusal;
- the CMS/DER readers;
- the `.tok` header parser;
- constant-time MAC comparisons;
- audit JSON escaping;
- `C_SetAttributeValue` one-way flags;
- the API rwlock against use-after-free.

**Implication for the rewrite.** SEC-001 to SEC-005 are behaviours a call-for-call differential
test **will flag as differences** once Rust implements them correctly. They must be listed up
front as *intended divergences* in the behaviour contract, so a correct Rust implementation is
not "fixed" back to match the C library.

---

## Documentation Gaps (top 5)

1. **Runtime mode is documented as a control but does nothing.** The installed `freehsm.conf` (`Makefile:1663`), `docs/AGD_PRE.md` and `ARCHITECTURE.md` §11.4 describe `mode = strict` refusing unapproved mechanisms. No entry point consults it. Only the build profile (`fhsm_build_fips_strict`) gates mechanisms.
2. **How a mechanism is actually dispatched.** `ARCHITECTURE.md` §4–5 describes the generated table invoking `dispatch_*` handlers. In reality, 11 hand-written switches in `fhsm_pkcs11.c` decide everything, and `src/dispatch/` is unreachable reference code. The same document also still claims a JSON token store (§3, §10), `make coverage` (§9), `tests/fuzz/` and `include/fhsm_pkcs11.in.h`; none of these exist.
3. **The key-use access-control model.** Comments and docs say private objects are invisible to a session that is not logged in (`src/fhsm_pkcs11.c:9005-9009`). That holds for `FindObjects`/`GetAttributeValue` only. Nothing documents which operations are gated, what the SO role may do with user keys, or that logout leaves objects resident (SEC-001).
4. **Per-session operation state.** The five global `g_op_*` arrays, `op_init` and the multi-part context lifecycle (the core of PKCS#11 Init/Update/Final semantics) appear in no design document; they are mentioned only in plan and finding notes (`docs/ROADMAP.md`, `docs/PKCS11_CHECK_FINDINGS.md`).
5. **Deploying the service.**
   - The systemd unit expects `/usr/libexec/fhsm-service`, which no target installs.
   - Nothing signs the service binary, though the statically linked integrity check hashes `/proc/self/exe` (`src/fhsm_integrity.c:126-133`).
   - `make uninstall` and `docs/AGD_PRE.md:693` name a `freehsm-bound-service` unit that doesn't exist.

---

## Relative Scale

| Scope | KSLOC (scc) | COCOMO-II index = 2.94 × KSLOC^1.10 |
|---|---:|---:|
| Shipping code (`src/`, `include/`, `service/`, `tools/`, `kat/`, C/H) | 30.178 | **124.7** |
| All code (excludes Markdown, plain text, licence, patches) | 60.069 | **266.0** |

These are **relative size and complexity indices** for ranking this system against others and
for sizing phases against each other. **They are not a timeline or a cost.** The COCOMO model
assumes traditional human-team productivity, which agentic transformation does not follow, so no
person-months, schedule, cost or date is implied or should be derived from them.

The index understates one thing: complexity is unusually concentrated. One file carries 37% of
shipping complexity, so the API-layer phase will dominate any phase split.

---

## Recommended Modernization Pattern

**Rearchitect (cross-stack, C → Rust) → `/modernize-transform`.**

The requester asked for a full rewrite in Rust. Rearchitect, not Rebuild, is the right shape,
for four reasons:

1. **The external contract is fixed and standard.** The PKCS#11 v3.2 C ABI, `C_GetFunctionList` and `C_GetInterface` must be exported unchanged from a Rust `cdylib`. `pkcs11-tool`, `pkcs11-provider`, p11-kit and the in-repo tools all depend on it. A greenfield redesign (`/modernize-reimagine`) would gain nothing at that boundary and would lose the strongest asset this system has.
2. **The behaviour oracle is unusually strong and executable.** There are 110+ passing tests, CAVP, KAT and Wycheproof vectors, and a probe that covers all 92 advertised mechanisms. All of it drives the module through the ABI and can be pointed at either library. The legacy build runs here, so **dual execution** is available: run the same call sequence against `libfreehsm.so` and the Rust library and diff the results.
3. **Domains D2–D8 are separable leaves behind D1**, so the internals can be replaced leaf-first:
   - first the audit log, revocation and token-store format (with on-disk compatibility for `slotN.tok` v3 and the audit chain);
   - then the crypto core and DRBG;
   - then the PKCS#11 layer, split by function group;
   - with D9 (service, onto hyper/axum) and D10 (tools/GUI) as independent tracks.
4. **The debt and defects argue against a line-by-line port.** D5 and runtime mode should be dropped, D1 restructured, and SEC-001/002 fixed. Each of these is a **recorded, intentional divergence**, which `/modernize-transform`'s per-module equivalence gates are built to handle.

**Questions the brief must settle** (raised by the agents; for an SME):
- Must existing `slotN.tok` files, `.tpm` blobs and audit chains stay readable by pqHSM?
- Is runtime mode deprecated in favour of the build profile?
- Which PIN minimum is right, 4 or 8?
- Is a composite (non-FIPS) mechanism in scope for a FIPS-profile pqHSM build?
- Where are `fhsm-service` and its signature meant to be installed?
- What rename obligations apply under Apache-2.0 §4/§6 (recorded in `PREFLIGHT.md`)?

**Next commands:** `/modernize-map pqHSM` (topology and persona flows), then
`/modernize-extract-rules pqHSM` (behaviour contract, where SEC-001–005 become explicit rules),
then `/modernize-brief pqHSM rust`.
