# Phase 6 plan: HTTP service and cutover

Status: **APPROVED 2026-11-11** (user: "Approve, std HTTP (Recommended)"; drafted on "Draft Phase 6 plan (Recommended)"). Phase 5 stays open until the GUI's manual UAT is reported. Brief: `MODERNIZATION_BRIEF.md` Phase 6. Method: `/modernize-transform`, slice by slice, as in Phases 2 to 5: C goldens first, the Rust against them, a harness run clean apart from recorded divergences, an architecture-critic review per slice, commit.

## 1. Scope

| Item | Size | Target |
|---|---|---|
| `service/fhsm_service.c` | 2,812 lines, one file | `pqhsm-service` (new crate, one binary), built under the C name until Q18 |
| `systemd/fhsm-service.service` | 1 unit | kept, with the missing install rule (its `ExecStart=/usr/libexec/fhsm-service` is installed by nothing today) |
| CI (`.github/workflows/`, 10 files; `ci.yml` 11 jobs) | | Cargo jobs; the C build out of the default pipeline |
| The C tree | | retired at exit (the oracle until then, Q4) |
| Rename (Q18) | about 750 files outside `modernized/` and `analysis/` mention `freehsm` or `fhsm`; 119 doc lines name `libfreehsm` | `pqhsm` names, plus the compatibility names Q18 picks |
| Licence (Q19), `docs/` evidence set | | `NOTICE` and attributions kept; brand assets dropped; docs rewritten for the Rust build |

**How the service reaches the module.** Today it links the library objects statically and calls `C_*` directly (`Makefile:772-775`), so `--profile` describes the binary itself. `pqhsm-service` keeps that: it links `pqhsm-module` as an rlib and goes through `pqhsm-pkiops`' safe API (sessions, handles, sign and verify, the slice 1 to 5 newtypes), loaded with `pkiops::load(None)`. That is `dlopen(NULL)`, the program itself, which the loader already supports, so the binary must export `C_GetFunctionList` (an export list or `-rdynamic`, slice 0). No new loader code, and the module's exports and Phase 4's shims are unchanged.

**The HTTP layer (decision needed, §4).** The brief names axum/hyper. The C service parses HTTP by hand (`read_request`, `:1136`) on two Unix sockets, with an acceptor thread holding idle connections and fixed worker pools (`:2157-2310`). Its answers (status line, header order, bodies, `Retry-After`) are the goldens. hyper 1.9 and tokio are in the offline cache; axum is not (it would need a fetch).

## 2. Slices

The C service stays the shipped binary until slice 3's exit. Each slice adds routes to the Rust binary, and the harness compares the routes it has.

| # | Slice | Covers | Rules and DIVs |
|---|---|---|---|
| 0 | **Goldens and scaffold.** `modernized/pqHSM/tests-support/hybrid/service_transcripts.sh` (beside the other harness scripts, so the C tree stays untouched, Q4): raw requests over the socket (a `python3 -I` client) for every route, with the refusal, policy, budget, peer-credential and malformed cases the brief lists; status, headers and body recorded; run twice on C to prove the masking (signatures, timing fields). The `pqhsm-service` crate, the exported function list, `hybrid.mk` building it beside the C service | the brief's golden-transcript entry criterion | none |
| 1 | **Pilot: start-up and the read-only side.** Arguments and usage, start-up order and one-shot PIN login, the session pool, the listeners and SO_PEERCRED, the acceptor and workers, the request reader, `GET /health`, `GET /token` | RULE-067, RULE-097; DIV-001 (start and stop audit) | |
| 2 | **Signing.** `POST /sign`, `POST /verify`, the policy file and SIGHUP reload, the identity table and in-flight cap, the refusal budget and its file, the 15 audit sites failing closed | RULE-068, 098, 065; RULE-096 (DIV-001's Phase 6 part) | decided before the slice (§4) |
| 3 | **Public listener.** `GET /certificates`, `POST /ocsp`, the database re-read on change, the delegated responder's start-up checks. At exit `hybrid.mk` ships the Rust service, and C and Rust run in parallel on the same request stream | RULE-023 and 054 (Q20), RULE-024 | Q20 |
| 4 | **Rename and packaging.** Q18's names and compatibility links, `CK_INFO` strings, the env var policy; the install rule and unit (Q21); licence files (Q19) | the brief's risk 1 | Q18, Q19, Q21 |
| 5 | **Cutover.** CI on Cargo (keeping the reproducible-build, Wycheproof, fuzz and GUI-smoke jobs), the C build out of the default pipeline, the C tree retired, the docs rewritten; the §4 persona walkthroughs on the all-Rust build (manual UAT). Part 1 done (`867a3be` before the history rewrite: Rust pinned, `ci.yml` rust job); the rest is planned in §8 | the brief's exit criteria 2 to 4 | §8.4 |

## 3. Evidence per slice

- **Transcripts:** `service_transcripts.sh` on the C and the Rust service, diffed less recorded DIV rows. The legacy `service_guards.sh`, `service_budget.sh` and `service_public.sh` (1,464 lines) run unchanged on both.
- **Audit side effects:** each request's audit records compared as the corpus step compares them (sequence, event, fields).
- **Parallel run (slice 3 on):** the same request stream to both services over copies of one token; zero unexplained diffs.
- **Signatures:** randomised ones cross-verified, not byte-compared, as in Phase 5.
- **Concurrency:** the in-flight cap, budget and pool under the harness's TSan step; the acceptor's queue depth and its 503 by test.
- **Unit tests** for the request reader (header limits, duplicate headers, lengths, deadlines), the policy parser and the budget arithmetic; cargo-fuzz on the request reader.

## 4. Decisions, each asked singly with a recommendation

| When | Decision | Recommendation |
|---|---|---|
| With this plan (**decided 2026-11-11: std**, user: "Approve, std HTTP (Recommended)") | **HTTP layer:** axum/hyper as the brief says, or a hand-written reader on std (`UnixListener`, threads) as in C | **std, no new crates.** The transcripts are the exit criterion, and C's reader defines them (header order, error bodies, limits, deadlines). The acceptor and worker model maps to threads one to one. hyper would answer some malformed requests itself, differently. Recorded against the brief's D9, as Phase 5 recorded its loader |
| Before slice 2 (**decided 2026-11-11, re-asked after the slice 2 review: reuse the oldest idle identity, evict the fewest refusals**, user: "Reuse oldest idle (Recommended)", "Fewest refusals (Recommended)"; first "Fail closed (Recommended)"; DIV-078) | RULE-068: the identity and budget tables fail open when full (`:537`, `:773`) | fail closed: 503 when the identity table is full; a full budget table evicts the entry with the least refusal time owed |
| Before slice 2 (**decided 2026-11-11: audit it**, user: "Audit it, keep old policy (Recommended)"; DIV-079) | RULE-098: a failed policy reload goes to stderr only | also audit it (one record); keep the old policy, as C does |
| Before slice 2 (**decided 2026-11-11: refuse to start**, user: "Refuse to start (Recommended)", re-asked with corrected facts after a first answer of "Preserve C (500 per request)"; DIV-081) | RULE-065: the strict build's service always signs with the composite mechanism, so `/sign` is 500 | refuse to start in the strict build, with a message, rather than serve a route that always fails |
| Before slice 3 (**decided 2026-11-11: keep "good", documented**, user: "Keep 'good', document (Recommended)"; no DIV) | Q20 (RULE-023, 054): "good" for unknown serials | keep "good" (an issuance record is state the tools do not keep) and document it |
| Before slice 4 | Q18 (decided 2026-11-11: as recommended): library and binary names, `CK_INFO` strings, `FHSM_*` | `libpqhsm.so` plus a `libfreehsm.so` link; `pqhsm-*` binaries with `fhsm-*` links for one release; `FHSM_*` read as fallbacks; `CK_INFO` strings changed (consumers matching the manufacturer string are recorded as a risk) |
| Before slice 4 | Q19 (decided 2026-11-11: as recommended): licence | as the brief says: keep `NOTICE` and the attributions, drop the brand assets |
| Before slice 4 | Q21 (decided 2026-11-11: as recommended): install path and CI duration | `/usr/libexec/pqhsm-service`, with the unit's `ExecStart` to match; CI duration measured at slice 5 |
| Slice 5 (**decided 2026-11-24: move it**, user: "Move to legacy/ (Recommended)") | Retiring the C tree: delete it, or move it under `legacy/` out of every build | move it, so the oracle stays runnable for a release |

## 5. Entry criteria (the brief's), and where each stands

| Criterion | State |
|---|---|
| Phase 4 and Phase 5 exit criteria met | Phase 4 closed 2026-11-07; Phase 5 open on the GUI's manual UAT |
| Q18 to Q21 ticked | open (§4), needed before slices 3 and 4; slices 0 to 2 need none of them |
| A decision for every suspected-defect rule gated at Phase 6 | RULE-067, 097: preserve (brief §5). RULE-096: fix (DIV-001). RULE-068, 098, 065, 023: open (§4) |
| Golden HTTP transcripts from the C service | slice 0 |

So slices 0 and 1 can start once this plan and the HTTP layer are approved. Slice 2 waits on its three DIV decisions, slice 3 on Q20, and slice 4 on Q18, Q19 and Q21.

## 6. Exit criteria (the brief's), and where each is shown

| Criterion | Shown by |
|---|---|
| The Rust service reproduces the golden transcripts, audit side effects included; C and Rust in parallel with zero unexplained diffs | §3, slices 1 to 3 |
| Every §4 persona walkthrough passes on the all-Rust build (manual UAT) | slice 5 |
| CI entirely on Cargo, reproducible build green, the C build out of the default pipeline | slice 5 |
| Consumers that keep the old library name still work | slice 4: the contract tests (step 11) against the installed layout, under both names |
| Every P0 rule gated at Phase 6 | RULE-023, 065, 067, 068, 096, 097, 098; the service parts of RULE-024 and 054 |

## 7. Risks

1. *The rename breaks consumers that set the module path or match `CK_INFO` strings* (the brief's risk 1). Compatibility links, contract tests under both names, and the string change recorded as a divergence.
2. *HTTP edge cases* (the brief's risk 2). The transcripts cover the malformed cases and the reader is fuzzed; on std, no library answers a request the goldens never saw.
3. *The acceptor, workers and in-flight cap under load.* TSan and the legacy scripts' concurrency cases, on both services.
4. *Retiring the C removes the oracle.* It goes only at slice 5, after the parallel run, and stays runnable under `legacy/` (§4).

## 8. Slice 5 plan: the cutover

Status: **APPROVED 2026-11-24** (user: "Approve, Cargo alone (Recommended)"; drafted on "yes, draft the slice 5 plan"). Lands as one PR, `phase6-slice5` into `main` on github.com/mor-sec/pqHSM, one commit per sub-slice. Method as before: evidence first, an architecture-critic review per sub-slice, a harness run clean apart from recorded divergences.

### 8.1 Where the C still is (facts, 2026-11-24)

No C of `src/` is in the module any more: `hybrid.mk` compiles every `LIB_SRC` object from `module/empty.c` or a shim. But the shipped artifacts are still made by the C build.

| Artifact | Made today by | C still in it |
|---|---|---|
| `libpqhsm.so` | the legacy `Makefile`'s `$(LIB)` rule (`hybrid.mk` includes it), linking the `pqhsm-module` staticlib | five shims in `modernized/pqHSM` (201 lines): `p11/shim/interface.c` (re-exports the three `C_Get*` because `--exclude-libs,ALL` hides Rust's), `p11/shim/build_config.c` (`fhsm_build_fips_strict`, the audit switch), `crypto/shim/kat_results.c` (the `fhsm_kat_results` export), `selftest/shim/integrity_digest.c` (the `.fhsm_digest` section), `audit/shim/audit_event.c` (the variadic `fhsm_audit_event`, for C callers only). They include `include/fhsm_*.h`. The flags, soname, profile (`PROFILE_CANON`, `check-profile`, `src/gen/`) and signing (`scripts/sign_module.sh`) are the C build's |
| `pqhsm-csr`, `-token`, `-crypt`, `-sign`, `-ca` | Cargo (`pqhsm-cli`), copied by `hybrid.mk` | none |
| `pqhsm-service` | `hybrid.mk`: `service/shim/main.c` plus `$(LIB_OBJ)` plus the `pqhsm-service` staticlib | `main.c` (7 lines) and the module shims |
| `pqhsm-audit` (installed as `freehsm-audit` plus link) | the legacy `Makefile`: **`tools/freehsm_audit.c`, the C verifier**. The Rust verifier (`audit-verify`, binary `pqhsm-audit`, Phase 1) is built but not installed | all of it |
| `pqhsm-gui` / `fhsm-gui` | `hybrid.mk`: `tools/fhsm_gui.c` (3,240 lines) over `pqhsm-pkiops` | all of it, by decision (Phase 5 slice 6, user: "Keep C GUI on Rust (Recommended)") |
| The C tests (116 sources, 97 binaries) | the legacy `Makefile`, run by `make tests` on the hybrid | about 71 use only the PKCS#11 ABI (`dlopen`, `C_GetFunctionList`, types from `tools/p11_util.h`); about 25 call internal `fhsm_*` symbols that only the hybrid's `ffi` features provide; about 20 to sort by hand |
| CI (`ci.yml` 12 jobs; `release`, `pkcs11-check`, `wycheproof`, `baseline`, `dist-verify`, `fuzz`) | `make integrity`, `make tests`, `make lint` (cppcheck), `make dist-verify`, `fuzz/Makefile.fuzz`, in the `freehsm-c-build` image | the C build throughout, except the `rust` job |
| Fuzzing | `fuzz/*.c` (4 libFuzzer targets) and cargo-fuzz (7 targets) | `fuzz_pq_params` has no Rust twin yet |

So retiring the C is not a move: the module, the service and the audit verifier first have to be built without it.

### 8.2 Sub-slices

| # | Sub-slice | Done when |
|---|---|---|
| 5a | **The module on Cargo alone.** `pqhsm-module` gains `cdylib`, named and sonamed `libpqhsm.so`, with a version script exporting exactly the dynamic symbols the hybrid module exports today (63 at `3010b17`'s check). The `C_Get*` and `fhsm_kat_results` are `#[no_mangle]` Rust; the digest is a `#[used] #[link_section = ".fhsm_digest"]` static that `sign_module.sh` patches unchanged; the profile and the audit switch become Cargo features (`all-mechanisms`, `audit-optional`) whose consts replace `build_config.c`. The four module shims are deleted; `audit_event.c` moves with the C callers that need it (5d) | `nm -D` identical to the hybrid's; `readelf` shows RELRO, BIND_NOW, no exec stack, the soname, `NEEDED` a subset of today's; both profiles build; the signed module passes its self-test and a patched byte fails it; an unsigned release build latches (DIV-034); the ABI C tests (5c) pass on it |
| 5b | **The binaries on Cargo alone.** `pqhsm-service` becomes a Cargo `[[bin]]` (no `main.c`), exporting `C_GetFunctionList` by link argument as today. The installed audit verifier becomes the Rust `pqhsm-audit`, `freehsm-audit` its link for one release (Q18's pattern); the C verifier goes to `legacy/`. The GUI's C (`tools/fhsm_gui.c` and the headers it includes) moves under `modernized/pqHSM/gui/` with its own short build, decision §8.4 | service transcripts and the parallel run as at slice 3; both verifiers agree on the audit corpus and the tampered-chain cases (DIV-007/008 rows as recorded); `gui-smoke` passes |
| 5c | **Tests.** The ABI-only C tests, with `tools/p11_util.h` and `p11_err.h`, move to `tests/abi/` and build against `libpqhsm.so` from a short makefile. The internal-symbol tests go to `legacy/` with the oracle. The 20 mixed ones are sorted one by one, each listed in the commit. Rust twins added where a legacy test was the only cover (start with `fuzz_pq_params`) | every ABI test passes on the all-Rust module; the hybrid harness, pointed at `legacy/`, runs C against the all-Rust build one last time with every step identical less recorded DIVs |
| 5d | **The move.** `git mv` (history kept) of `src/`, `include/`, `kat/`, `tools/` (less the GUI), `service/`, `fuzz/` (C), the internal tests, the C-only `scripts/`, the legacy `Makefile`, `Dockerfile.test`, `probes/`, `disabled/`, the root `RELEASE_v*.md` and `CHANGELOG.md` to `legacy/`, with a `legacy/README.md`: what it is, how to build the oracle (`make -C legacy`), and that it goes one release after the first pqHSM release. A new top-level `Makefile` of a few targets (`build`, `sign`, `test`, `install`, `uninstall`) wraps Cargo and takes over `install-pqhsm`'s layout | a clean checkout builds, signs, tests and installs without entering `legacy/`; `git grep` finds no default build path into it; `make -C legacy` still builds the oracle |
| 5e | **CI and images.** `ci.yml` rewritten on Cargo: clippy, rustfmt and cargo-deny for `lint`; build, sign and integrity; the ABI tests in both profiles and with the audit switch; the sanitizer jobs (decision §8.4); Wycheproof, pkcs11-check and fuzz against the all-Rust module; reproducibility as two builds with identical SHA-256. Images renamed `pqhsm-build` and `pqhsm-test`. `mirror.yml` deleted (upstream's GitLab and Codeberg mirrors). The oracle gets a manual `legacy.yml`. Actions re-enabled on the repository once the PR is green. CI duration measured (Q21's open item) | every workflow green on the PR; two CI builds byte-identical |
| 5f | **Docs.** Scope decided in §8.4. At least: the build, install and deployment docs, `ARCHITECTURE.md`, `REPRODUCIBLE_BUILD.md` and the tool docs describe the Rust build; the README's status note updated | `scripts/check_doc_twins.py` and `doc_audit.py` pass; no operator doc tells anyone to run the legacy build |

Then the phase exit: the §4 persona walkthroughs on the all-Rust build (manual UAT, the user), with Phase 5's GUI UAT, and the phase closed by the user.

### 8.3 Evidence

- **ABI:** `nm -D`, soname, `NEEDED` and the hardening bits compared by script against the last hybrid build, in CI.
- **Behaviour:** the last full harness run, C under `legacy/` against the all-Rust build, is the slice's main evidence and is recorded in `TRANSFORMATION_NOTES.md`. After it, the ABI C tests and the Rust suites are the regression suite.
- **Consumers:** the contract tests (harness step 11: `pkcs11-tool`, `pkcs11-provider`, p11-kit) against the installed layout, under `libpqhsm.so` and `libfreehsm.so`.
- **Integrity and profiles:** signed and tampered modules, both profiles, the strict build's service refusing to start (DIV-081).
- **Reproducibility:** two builds in the pinned image, path prefixes remapped, identical SHA-256 for the module and every binary.

### 8.4 Decisions, each asked singly with a recommendation

| When | Decision | Recommendation |
|---|---|---|
| With this plan (**decided 2026-11-24: Cargo alone**, user: "Approve, Cargo alone (Recommended)") | How the module is built: Cargo alone (`cdylib`, version script, features), or Cargo plus a minimal C link step for the exports and the digest section | **Cargo alone.** Every shim exists only because the staticlib went through the C link; Rust can export, version and place a section itself, and `sign_module.sh` takes the library path as its argument |
| Before 5b | Where the GUI's C lives: `modernized/pqHSM/gui/` with its own short build, or ported to gtk4-rs as the brief first said | **Move it, unchanged.** Phase 5 decided to keep it C; a port is its own slice, and its manual UAT is still open |
| Before 5b | The installed audit verifier: the Rust `pqhsm-audit`, or the C one under its new name | **The Rust one,** once both agree on the corpus; it carries the DIV-007/008 fixes the C verifier lacks |
| Before 5c | The ABI-only C tests: kept as `tests/abi/` against the Rust module, or retired to `legacy/` with the rest | **Keep them.** They are consumers of the one contract (the brief's §1) and cost no Rust code |
| Before 5e | Sanitizers: a pinned nightly in the build image for ASan and TSan on the Rust (`-Zsanitizer`), or C-side sanitizers over the ABI tests only | **Pinned nightly, sanitizer jobs only.** Stable 1.99.1 still builds everything shipped; without it the Rust gets no TSan at all |
| Before 5d | Workspace location: keep `modernized/pqHSM/`, or move the Cargo workspace to the repository root | **Keep it for this PR,** and move it in its own PR after: the move touches every path in docs and scripts, and mixing it into the cutover makes the review unreadable |
| Before 5f | Docs scope: rewrite the operator docs now and mark the FIPS 140-3 and CC worked examples as describing the C (rewritten in a later phase), or rewrite everything now | **Operator docs now, evaluation docs marked.** 33 of the 60 docs name the C build; the evaluation set is the largest and the least time-critical |

### 8.5 Risks

1. *The export set or the hardening changes when rustc links instead of cc.* Compared by script on every build (§8.3), not assumed from rustc defaults.
2. *The linker drops or moves the digest section.* `#[used]`, the signing script's own size check, and the tamper test.
3. *The oracle stops being runnable once it leaves every build.* `legacy.yml` builds it on demand until it is removed, one release after the first pqHSM release.
4. *Rust builds are less reproducible than the C's.* Remapped path prefixes, one codegen unit if needed, the pinned image; proven by the two-build check before 5e closes.
5. *A large diff hides a regression.* One commit per sub-slice, `git mv` for every move, and the harness run (5c) before the move (5d).

### 8.6 Progress

- **5a done (2026-11-24):** the module on Cargo alone; the ABI report identical to the hybrid's for both profiles; review H1 (the service's export) fixed. The export set is held by `--exclude-libs` and forwarders in the module crate rather than a version script (`TRANSFORMATION_NOTES.md`, slice 5a).
