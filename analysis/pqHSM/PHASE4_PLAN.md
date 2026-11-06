# Phase 4 plan: PKCS#11 API layer, lifecycle and sessions

Status: **APPROVED 2026-11-03** (user: "I approve the plan"; drafted after "continue with recommended approach"). §5 item 2 decided 2026-11-03 (DIV-053 "Status calls only", DIV-054 "Re-wrap only", DIV-059 "8 everywhere", table "Approve as drafted"). Item 3, the contract-test tools, decided 2026-11-06 (user: "Fetch once (Recommended)"): opensc 0.26.1-2 (pkcs11-tool), pkcs11-provider 1.0-3 and p11-kit 0.25.5-3, with the four packages the image lacks for them, fetched once from the image's Debian snapshot into `netcache/debs` (git-ignored; checksums in `netcache/debs.sha256`) and installed offline with `dpkg -i` (checked with `--network=none`).
Brief: `MODERNIZATION_BRIEF.md` Phase 4. Entry criteria: Phase 3 exit met and Q12–Q17 ticked (2026-11-03). Still open: the `DIVERGENCES.md` decisions (drafted, § Phase 4; four parts await the user, §5 below), and the pilot slice, which is slice 1 here.
Method: `/modernize-transform`, slice by slice, as in Phases 2 and 3: characterisation goldens from the C, the Rust implementation behind the same ABI, the C object emptied in `hybrid.mk`, a harness run, then a review.

## 1. Scope

| File | Lines | Target |
|---|---|---|
| `src/fhsm_pkcs11.c` | 13,386 | `pqhsm-p11` (the `C_*` entry points, argument checks, return-code mapping) and `pqhsm-core` (the operations behind them) |
| `src/fhsm_create_attrs.c` | 432 | `pqhsm-core::template` |
| `src/fhsm_pq_params.c` | 64 | `pqhsm-core::template` |
| `src/fhsm_ecdsa_raw.c` | 65 | `pqhsm-core` (revised at slice 5: its own twenty lines each way, not `pqhsm-pki`'s raw-to-DER, so core takes no pki dependency) |
| `src/fhsm_state.c` | 143 | `pqhsm-core::state` |
| `src/fhsm_session.c` | 267 | `pqhsm-core::session` |
| `src/fhsm_apilock.c` | 178 | `pqhsm-core::apilock` |
| `src/gen/fhsm_dispatch.c`: the advertisement table only | 964 | `pqhsm-core::mechs` (data) |
| **Total** | **15,499** | |

Not ported (Q16, confirmed): `src/fhsm_mode.c` (160) and the 12 `src/dispatch/*` handlers. The build profile is the only mode switch. Behaviour comes from the hand-written `switch` blocks in `fhsm_pkcs11.c`, never from `src/dispatch/` (brief).

At the exit no C object is linked into the module, and `nm -D` shows only the PKCS#11 exports plus the documented extras (today 63 symbols, identical between C and hybrid).

## 2. Slices, in the brief's order

The brief fixes the mechanics: at the start, Rust owns `C_GetFunctionList` and `C_GetInterface`, and routes every group not yet ported to the C implementation, linked in under a renamed symbol. Groups then move one at a time.

| # | Slice | `fhsm_pkcs11.c` entry points | DIVs |
|---|---|---|---|
| 0 | **Takeover.** Rust exports every `C_*`, the function lists and the interfaces; each forwards to the renamed C function. Rust owns the session and operation tables from here on; the remaining C reaches them through accessor symbols (brief, risk 1). | all, as forwarders | none |
| 1 | **Pilot: lifecycle, sessions and login** (named in the brief) | `C_Initialize`, `C_Finalize`, `C_GetInfo`, slot and token info, `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`, `C_Login`, `C_Logout`, `C_InitToken`, `C_InitPIN`, `C_SetPIN`; `fhsm_state.c`, `fhsm_session.c`, `fhsm_apilock.c` | 050 (logout half), 051, 053's gate, 054, 055, 059; RULE-071, 083, 084 |
| 2 | Object management | `C_CreateObject`, `C_CopyObject`, `C_DestroyObject`, `C_GetAttributeValue`, `C_SetAttributeValue`, `C_GetObjectSize`, `C_FindObjects*`; `fhsm_create_attrs.c` | 050 (destroy), 056, RULE-037(b), RULE-059's history bits, RULE-061, 091, 092 |
| 3 | Digest | `C_Digest*` | 053 |
| 4 | Encrypt and decrypt | `C_Encrypt*`, `C_Decrypt*`, message-based | 050 (key use), 053 |
| 5 | Sign and verify | `C_Sign*`, `C_Verify*`; `fhsm_ecdsa_raw.c` | 050, 053; Q17 (composite refused in the strict build, preserved, with a test at each of C's three sites) |
| 6 | Key generation, wrap and derive | `C_GenerateKey`, `C_GenerateKeyPair`, `C_WrapKey`, `C_UnwrapKey`, `C_DeriveKey`; `fhsm_pq_params.c` | 052 (moved from slice 1, 2026-11-04: its one call site is here), 057, 058; RULE-006, 014, 015, 017, 020 |
| 7 | KEM | `C_EncapsulateKey`, `C_DecapsulateKey` | 050, RULE-037(a) |

Each slice's exit is the harness clean apart from recorded divergences. The pilot's exit gates the rest (brief). DIV-001's audit call sites move with the slice that owns each one. As in Phases 2 and 3, the pilot is expected to revise this plan before slice 2 starts.

## 3. Technical choices (mine; say if you disagree)

- **Crates:** `pqhsm-core` (safe Rust: state, sessions, objects, templates, mechanism table, operations) and `pqhsm-p11` (every `unsafe` and `extern "C"`: the PKCS#11 ABI, pointer and length checks in C's order, `CK_RV` mapping). Same split as the earlier crates' `ffi/`.
- **PKCS#11 types:** written by hand from the project's own headers (`include/pkcs11*.h`, with the v3.2 PQC mechanisms and the vendor ones), and checked against them by a C `_Static_assert` file for every `sizeof` and `offsetof`. No `cryptoki-sys`: it lacks the v3.2 PQC types and the vendor mechanisms, and would be a second source of truth.
- **Linking during the phase:** the module stays the one `libfreehsm.so` the hybrid build links today. The C entry points are renamed in the copy's build (`objcopy --redefine-sym` on `fhsm_pkcs11.o`, in `hybrid.mk`), and the Rust exports take their names. The exported set and NEEDED stay identical. At the exit, with no C left, the module is `pqhsm-p11`'s `cdylib`.
- **One lock:** the C `apilock` rwlock becomes Rust's, from the pilot, and the C still running takes it through an accessor, so the two halves never hold different locks.

## 4. How equivalence is proved

1. **Goldens from the C,** as before. A new `tests-support/golden/gen_p11.c` drives call sequences through the C module's function list, NULL and out-of-range arguments included, with every return code and output byte recorded. Rust replays them in order, per slice.
2. **The harness** at every slice: `make tests` 106/106, `nm -D`, NEEDED, the audit corpus, TSan, FIPS on both profiles and Wycheproof (in both modes). **New:** the harness reads `DIVERGENCES.md`'s recorded call and return-code pairs and suppresses only those; any other diff fails (brief, risk 2). The three intended test changes are listed there (DIV-057: `test_ecdh_peer_point`, `probe_ecdh_curves`; DIV-059 if approved: `test_input_validation`). The harness runs patched copies, and the originals become those DIVs' tests.
3. **One new test per intended divergence,** failing on the C library and passing on Rust (brief exit criterion). For SEC-001 it is the reproduction itself.
4. **The 92-mechanism probe:** C and hybrid identical, on both profiles.
5. **Contract tests** (`docs/THIRD_PARTY_CONSUMERS.md`): OpenSC `pkcs11-tool`, OpenSSL `pkcs11-provider`, and p11-kit with `contrib/p11-kit/`, against the C module first (a new baseline), then the hybrid at each slice from 5 on.
6. **Fuzzing:** cargo-fuzz targets for the attribute and template parsers (`fhsm_create_attrs.c`, the nested templates, `CKA_PARAMETER_SET`), from slice 2.
7. **Concurrency:** `test_concurrency` and `test_apilock` under TSan at every slice.

## 5. Needs a decision now

1. **Approve the plan:** the slice order (fixed by the brief), the takeover in slice 0, and the choices in §3.
2. **The proposed divergence parts** (`DIVERGENCES.md` § Phase 4):
   - DIV-053: what ERROR refuses. Proposed: everything except `C_Finalize` and the nine status calls.
   - DIV-054: an SO `C_SetPIN` re-wraps the DEK but does not rotate it.
   - DIV-059: PIN minimum 8 on every path, at the cost of one legacy assertion (`test_input_validation`, `ulMinPinLen == 4`), or 4 everywhere.
   - The 21-row table of keep / fix / defer.
3. **Contract-test tools, once:** none of `pkcs11-tool`, `pkcs11-provider` or p11-kit is in the build image. Proposal: fetch their Debian packages once, cache them beside the FIPS ones (`netcache/debs`), and install them offline in each harness run, as for the FIPS provider.

## 6. Revision after the pilot (2026-11-05)

Slice 1 closed: harness clean apart from recorded DIVs, every slice 1 DIV with a test that fails on C and passes on Rust, the architecture-critic review applied (TRANSFORMATION_NOTES § Slice 1 review). What it changes for the slices left:

1. **The gate.** The C entry points not yet ported are renamed `pqhsm_c_*` and wrapped by `GATE`/`STATUS` in `p11/shim/interface.c`, which apply DIV-051's and DIV-053's refusals before the C runs. Each slice removes its wrappers as its entry points move.
2. **DIV-001 moves with each site, from the start.** `audit` returns its result; a slice that moves an audited call fails it closed in the same commit (`audited`), and says how its effect is undone. Slice 1 missed this until the review.
3. **Sub-slices, then one commit per DIV.** Slice 2 as: 2a find, size, destroy; 2b get and set attribute; 2c create with `fhsm_create_attrs.c`; 2d copy; (revised 2026-11-05, user: "Helpers + copy now (Recommended)": 2c is the parser only, 2c-i; `C_CreateObject`'s entry and its OpenSSL key builders move in slice 6 beside generate, unwrap and derive, which build keys the same way; 2d ports copy whole, with the template helpers every creation path applies); then DIV-050 (destroy), DIV-056, RULE-059's history bits, RULE-061, 091, 092.
4. **A golden per slice, first.** Slice 2's is `p11_objects.c` (harness step 4i, 1,883 rows, every attribute of every kind of object; C and hybrid identical before any port). It already caught a DIV-050 error (data objects dropped at logout).
5. **Locks.** Shared state the C still reaches stays on pthread primitives (std's are invisible to TSan); the session-table-then-token order holds, and new code copies the token handle out of the table before calling it (review L5).
6. **Fuzzing (§4.6, from slice 2).** The image has `proptest` but no cargo-fuzz, `libfuzzer-sys` or nightly. Slice 2 starts with proptest properties over the template parser; cargo-fuzz waits for the same one-time fetch as §5 item 3 (both need network, not yet approved).
7. **DIV-052** moves whole to slice 6 (its one trigger is there).
8. **Harness hygiene.** One run per output directory, and a failed `cargo test` stops the chain before the harness (one run was lost to both).
