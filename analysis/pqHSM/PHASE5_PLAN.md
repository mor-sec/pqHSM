# Phase 5 plan: PKI CLI tools and desktop GUI

Status: **APPROVED 2026-11-09** (user: "Approve the plan (Recommended)"). Brief: `MODERNIZATION_BRIEF.md` Phase 5. Entry criteria: Phase 3 exit met; the Phase 5 decisions recorded (`DIVERGENCES.md` § Phase 5, DIV-072 to 075, 2026-11-09); the pilot is slice 1 below. Method: `/modernize-transform`, slice by slice, as in Phases 2 to 4: characterisation goldens from the C, the Rust behind the same C ABI, the C object dropped from `hybrid.mk`, a harness run clean apart from recorded divergences, an architecture-critic review per slice.

## 1. Scope

| File | Lines | Target |
|---|---|---|
| `tools/p11_util.h` | 590 | `pqhsm-pkiops::p11`: dlopen, `C_GetFunctionList`, the calls the tools make (user: "Own loader, no new crates (Recommended)") |
| `tools/pkiops.c`, `pkiops.h` | 2,465 | `pqhsm-pkiops`: the tools' operations, over `pqhsm-pki` and the module; exported under `pkiops.h`'s C ABI |
| `tools/cms_env.c`, `cms_env.h` | 430 | `pqhsm-pkiops::cms_env` (AuthEnvelopedData, streamed) |
| `tools/fhsm_{csr,token,crypt,sign,ca}.c` | 1,561 | `pqhsm-cli`: one binary per tool, built under the C names (`fhsm-csr`, ...) |
| `tools/fhsm_gui.c` | 3,240 | slice 6, decided there (§4) |
| **Total** | **8,286** | |

**Why `pqhsm-pkiops` keeps a C ABI.** `tests/test_pkiops*.c` (six programs) and the GUI call `pkiops_*` directly, and the exit criterion re-points those tests at the Rust. Exporting `pkiops.h` from the Rust, as Phases 2 to 4 exported their headers, links the unchanged C tests, the C tools not yet ported and the C GUI against it, so each slice is checked twice: by the C callers on the Rust library, and by the Rust tool against the C tool.

**Names.** The Rust binaries are built as `fhsm-csr`, `fhsm-token`, `fhsm-crypt`, `fhsm-sign` and `fhsm-ca`, with the same flags, messages and exit codes, so the shell tests, `pki_tools_characterize.sh` and operator scripts run unchanged. The pqHSM rename is Q18, Phase 6.

**Dependencies.** None new: `libc` (dlopen, termios for DIV-072's prompt, flock for DIV-074), `openssl`, `zeroize`, and the workspace's crates. Arguments are parsed by hand, as in C, so usage text and exit codes match byte for byte.

## 2. Slices, in the brief's order

Each slice ports the `pkiops_*` functions its tool calls (functions shared with a later tool move with the first), drops their C from `hybrid.mk`, and replaces the tool's `main`.

| # | Slice | `pkiops` functions (count) | DIVs |
|---|---|---|---|
| 0 | **Scaffold.** `pqhsm-pkiops` (staticlib + rlib) and `pqhsm-cli`; the loader; `hybrid.mk` links the C tools and `test_pkiops*` against the Rust archive, which forwards every function not yet ported to the C, renamed (slice 0 of Phase 4's pattern) | the loader, `pkiops_load`, `pkiops_open`, `pkiops_close`, error reporting | none |
| 1 | **Pilot: `fhsm-csr`** (named in the brief): the whole recipe end to end, the shared PIN helper | session open and user login, root, algorithm parse and name, `keygen_alg`, `csr` (12) | 072 |
| 2 | `fhsm-token` | `token_info`, `token_init`, slot parsing (6) | 072 (SO PIN) |
| 3 | `fhsm-crypt` and `cms_env` | objects, attributes, secret keygen, file encrypt and decrypt, envelope for a certificate (22) | |
| 4 | `fhsm-sign` | hashing, streamed sign and verify, CMS sign, digest and verify (22) | 075 |
| 5 | `fhsm-ca` | `issue`, `crl`, `ocsp`; the revocation database through `pqhsm-pki` | 073, 074 |
| 6 | GUI | what remains of the 48 the GUI calls | §4 |

At slice 5's exit no `tools/*.c` but `fhsm_gui.c` is compiled into a shipped tool, and `test_pkiops*` link no C from `pkiops.c` or `cms_env.c`.

## 3. Evidence per slice

- **Goldens:** `tests/pki_tools_characterize.sh` (every subcommand of csr, token, ca and sign, and their main refusals; exit codes, messages, ASN.1 shape, masked bytes) and `tests/fhsm_crypt_cli.sh`, each run on the C tools and on the hybrid, diffed less recorded DIV rows. First, before slice 1: run it twice on the C to prove its masking (its own instruction), and add the rows the decisions need (DIV-073's bad `--days`, DIV-075's `--signer`, DIV-074's concurrency).
- **C callers on the Rust:** `test_pkiops`, `_algs`, `_objects`, `_secret`, `_envelope`, `_envelope_rsa` linked against `pqhsm-pkiops`, as many of their checks passing as on C.
- **Interoperability:** the existing `openssl` CLI checks (`pki_artifacts`, `cms`, `-VAfile`), and `test_pkiops_envelope*`'s OpenSSL round trip for `cms_env`.
- **Signatures:** randomised ones (ECDSA, ML-DSA hedged, composite) are cross-verified, each tool's output by the other, not byte-compared.
- **Unit tests** for the parsers the port adds (`--days`, slot, algorithm names) and the lock (DIV-074).

## 4. Decided later, at its slice

- **The GUI (slice 6).** `pqhsm-gui` on gtk4-rs needs gtk4-rs and its tree fetched (network approval) and the GTK 4 development libraries in the build image. The alternative is to keep `fhsm_gui.c` and link it against `pqhsm-pkiops`, so every operation it runs is Rust and only GTK glue stays C. Asked at slice 6, after slices 1 to 5 show what the GUI's 48 calls have become. Either way its exit is the brief's manual UAT (`docs/FHSM_GUI.md`, `tests/gui_smoke.sh`).
- **RULE-021/022 `fhsm-ca` parts** (the Phase 3 table): run at slice 5 over the database, with the clock pinned.

## 5. Exit criteria (the brief's), and where each is shown

| Criterion | Shown by |
|---|---|
| Each tool's output matches C's for the same inputs and token; random signatures cross-verified | §3 goldens, per slice |
| `test_pkiops*` pass re-pointed at the Rust | §3, linked against `pqhsm-pkiops` |
| Flags and exit codes equivalent, or renamed under Q18 | same names and hand-parsed flags (§1); the usage and refusal rows |
| GUI manual UAT | slice 6 |
| Every P0 rule gated at Phase 5 | RULE-021, 022, 069, 099, 100 (RULE-023 Phase 6, Q20); RULE-067, 068, 097, 098 regated to Phase 6 (2026-11-09) |

## 6. Risks

1. *`cms_env` and CMS output differs in encoding order or optional fields* (brief, risk 1): byte goldens on the deterministic parts and OpenSSL's reading of every file, both ways.
2. *Hand-written FFI in the loader*: the calls are declared once from `pkcs11.h`'s layout, and every slice's harness runs them on both libraries; the harness's TSan run covers the loader too.
3. *Masking in the characterisation script hides a real difference*: proven by two C runs first (§3), and each masked field is compared another way (signatures verified, serials monotonic, dates within the pinned window).
