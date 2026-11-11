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
| 0 | **Goldens and scaffold.** `tests/service_transcripts.sh`: raw requests over the socket (a `python3 -I` client) for every route, with the refusal, policy, budget, peer-credential and malformed cases the brief lists; status, headers and body recorded; run twice on C to prove the masking (signatures, timing fields). The `pqhsm-service` crate, the exported function list, `hybrid.mk` building it beside the C service | the brief's golden-transcript entry criterion | none |
| 1 | **Pilot: start-up and the read-only side.** Arguments and usage, start-up order and one-shot PIN login, the session pool, the listeners and SO_PEERCRED, the acceptor and workers, the request reader, `GET /health`, `GET /token` | RULE-067, RULE-097; DIV-001 (start and stop audit) | |
| 2 | **Signing.** `POST /sign`, `POST /verify`, the policy file and SIGHUP reload, the identity table and in-flight cap, the refusal budget and its file, the 15 audit sites failing closed | RULE-068, 098, 065; RULE-096 (DIV-001's Phase 6 part) | decided before the slice (§4) |
| 3 | **Public listener.** `GET /certificates`, `POST /ocsp`, the database re-read on change, the delegated responder's start-up checks. At exit `hybrid.mk` ships the Rust service, and C and Rust run in parallel on the same request stream | RULE-023 and 054 (Q20), RULE-024 | Q20 |
| 4 | **Rename and packaging.** Q18's names and compatibility links, `CK_INFO` strings, the env var policy; the install rule and unit (Q21); licence files (Q19) | the brief's risk 1 | Q18, Q19, Q21 |
| 5 | **Cutover.** CI on Cargo (keeping the reproducible-build, Wycheproof, fuzz and GUI-smoke jobs), the C build out of the default pipeline, the C tree retired, the docs rewritten; the §4 persona walkthroughs on the all-Rust build (manual UAT) | the brief's exit criteria 2 to 4 | |

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
| Before slice 2 | RULE-068: the identity and budget tables fail open when full (`:537`, `:773`) | fail closed: 503 when the identity table is full; a full budget table evicts the entry with the least refusal time owed |
| Before slice 2 | RULE-098: a failed policy reload goes to stderr only | also audit it (one record); keep the old policy, as C does |
| Before slice 2 | RULE-065: the strict build's service always signs with the composite mechanism, so `/sign` is 500 | refuse to start in the strict build, with a message, rather than serve a route that always fails |
| Before slice 3 | Q20 (RULE-023, 054): "good" for unknown serials | keep "good" (an issuance record is state the tools do not keep) and document it |
| Before slice 4 | Q18: library and binary names, `CK_INFO` strings, `FHSM_*` | `libpqhsm.so` plus a `libfreehsm.so` link; `pqhsm-*` binaries with `fhsm-*` links for one release; `FHSM_*` read as fallbacks; `CK_INFO` strings changed (consumers matching the manufacturer string are recorded as a risk) |
| Before slice 4 | Q19: licence | as the brief says: keep `NOTICE` and the attributions, drop the brand assets |
| Before slice 4 | Q21: install path and CI duration | `/usr/libexec/pqhsm-service`, with the unit's `ExecStart` to match; CI duration measured at slice 5 |
| Slice 5 | Retiring the C tree: delete it, or move it under `legacy/` out of every build | move it, so the oracle stays runnable for a release |

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
