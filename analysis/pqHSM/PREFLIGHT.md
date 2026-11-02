# Preflight — pqHSM (formerly FreeHSM), C11 → Rust cross-stack rewrite

*Generated 2026-10-29T23:57+10:00 by `/code-modernization:modernize-preflight`. Updated 2026-10-30
after the human restored `Makefile` and `.github/workflows/`. Checks 3a, 3b, 4 and the verdicts
were re-run and are current.*

**Invocation, verbatim:** `freehsm, rename to pqHSM and do a full cross-stack rewrite to Rust`
The argument parser produced `$1 = "rename"`. That is not a system name, so this report reads
the request as **system = FreeHSM → renamed pqHSM, target stack = Rust, full rewrite** and
writes to `analysis/pqHSM/`. **Correct this if it's wrong.**

**Source location:** there is no `legacy/` directory. The system under study is the repository
root `~/Projects/pqHSM` itself. Symlinking it into `legacy/pqHSM` inside the same tree would
create a recursive loop, so downstream commands should take the repo root as the legacy source.

---

## Check 0 — The human's answers (verbatim)

Given during the run, recorded exactly as typed.

1. **Scope** — Is the system the complete system, or one slice of a larger codebase? If a slice: what *outside* it depends on code *inside* it, and is breaking those consumers acceptable?
   > **"the complete system"**
2. **Build & test locally** — Can this environment restore, build, and run the tests? Roughly how long does the full CI pipeline take?
   > **"yes"**
   >
   > ✅ *Confirmed 2026-10-30.* After the `Makefile` and `.github/` were restored, the CI build job reproduced here in the pinned image (Check 3b-L2), and `make tests` passed.
   > **OPEN sub-item:** CI duration wasn't answered. Local measurement for reference: build image 5m31s (one-time), build + sign + integrity about 30s, full `make tests` 213s. CI also runs sanitizers (timeout 45m), TSan (30m), pkcs11-check, Wycheproof, fuzz and reproducibility jobs, which were not timed here.
3. **Bespoke build infrastructure** — Is there organization-specific build or dependency-resolution machinery (an internal package feed, a custom binary store, a code generator, a wrapper around the standard build tool) that someone new to this codebase would not guess? Where is it documented?
   > **"no"**
   >
   > *Source note, consistent with the answer:* the in-tree code generator `scripts/gen_p11_thunks.py` is documented in `docs/ARCHITECTURE.md` §8. Builds are pinned to a Debian snapshot in `Dockerfile.build`. Both are in the repo and documented, so neither is hidden machinery.
4. **Prior attempts** — Has anyone tried to modernize any of this before? What went wrong?
   > **"no"**
   >
   > *Source note, not overriding the answer:* the tree records that the C code is itself a port of a Python proof-of-concept (README §"Why C ?"). It also records a rename `freehsm-c` → `freehsm` in July 2026; `REBRAND_CHECKLIST.md` and `scripts/post_rename.sh` document the friction (mirror URLs hard-coded, GitLab not redirecting git remotes). A rename to pqHSM would be the second rebrand.
5. **Off limits** — Is anything not allowed to change in this pass (a component another team owns, a frozen branch, generated code)?
   > **"no"**

**Ownership note (source fact, decision for the human):** every file is
`Copyright 2026 Afchine Madjlessi`, Apache-2.0, upstream `github.com/afchine1337/freehsm`. A
renamed Rust rewrite is a derivative work. Apache-2.0 §4 requires keeping `NOTICE` and the
attributions. §6 grants no rights to the "FreeHSM" or "Simorgh Labs" names, which supports the
rename but means the brand assets under `docs/assets/` should not carry over.

---

## Check 6 — Scope boundary

**Standalone, and the human confirms it is "the complete system".** `~/Projects/pqHSM` is not
inside a git repository, and no parent directory is one. No in-tree manifest, script or include
points outside the tree. Grepping the sibling projects under `~/Projects` (including `pqagent`
and `pqaudit`) for `libfreehsm`, `freehsm`, `fhsm_` or `pqHSM` found no inbound references.

- **Outbound:** none in source. The external dependencies are system ones: OpenSSL 3.5.x with the FIPS provider, GTK (for `fhsm-gui` only), and the `tpm2` CLI.
- **Inbound:** no source-level consumers. **But this is a PKCS#11 module, so its consumers are binary consumers of the C ABI.** `docs/THIRD_PARTY_CONSUMERS.md` measures OpenSC `pkcs11-tool` and OpenSSL `pkcs11-provider`, and `contrib/p11-kit/` carries upstream patches. The Rust rewrite must keep exporting the same `C_GetFunctionList`/`C_GetInterface` ABI from a `cdylib`, or every one of those consumers breaks. `/modernize-brief` must treat **the PKCS#11 ABI as the contract**, not as an implementation detail.

---

## Status table

| # | Check | Status | Found | Fix |
|---|---|---|---|---|
| 0 | Human answers | ✅ | 5/5 answered; Q2 now confirmed by Check 3b-L2. CI duration still open. | State how long CI takes. |
| 1 | Stack | ✅ | **C11** (177 `.c` / 28 `.h` repo-wide). `cloc` over the shipping code (`src/`, `include/`, `service/`, `tools/`, `kat/`): **27,886 C + 1,988 header lines of code**, plus 14,120 comment lines (a ratio of roughly 1 comment line to 2 code lines; the earlier "about 55k" was a raw `wc` count including comments and blanks); 37 `.sh` and 31 `.py` (generator, release, test harnesses); 104 `.md` (FIPS/CC evaluation docs). Libraries: OpenSSL 3.x EVP + FIPS provider, pthreads, GTK 3 (GUI). Deployment: `systemd/fhsm-service.service`. | — |
| 2 | Analysis tooling | ✅ | *Re-checked 2026-10-30.* `cloc` **2.08** ✅ (covers the `scc`/`cloc` row), `lizard` **1.24.3** ✅ (`~/.local/bin`, smoke-tested on `src/fhsm_session.c`: 11 functions, avg CCN 5.4), `glow` ✅, `delta` **0.19.2** ✅, `scc` **3.7.0** ✅ (installed to `~/go/bin`, **not on PATH**; call it by full path, or add `~/go/bin` to PATH). | Optional: `export PATH="$HOME/go/bin:$PATH"` in your shell profile. |
| 3a | Build definition | ✅ | **Restored 2026-10-30.** `Makefile` (1,778 lines) is the build: `make` → `generate` → `libfreehsm.so` + tests + tools. `PROFILE ?= nist-approved-only` (aliases `fips-strict`/`interop`/`all-mechanisms`). `OPENSSL_PREFIX ?= /usr/local/ssl`. Strict `-Werror` hardening and reproducibility flags. `.github/workflows/` holds 10 workflows; the files mention `publish-test-image.yml`, but `build-image.yml` and `pkcs11-check.yml` are what exist. CI's `build` job runs in `ghcr.io/<owner>/freehsm-c-build:debian13-20261006`, which is `Dockerfile.build` (Debian trixie pinned by digest + `snapshot.debian.org` `20261006T000000Z`). **Dependency source:** Debian apt only; no private feed (consistent with Q3 "no"). | — |
| 3b-L1 | Legacy syntax compile | ✅ | Superseded by L2. (On the bare host, `libssl-dev` isn't installed, so OpenSSL files fail `-fsyntax-only`. The host's OpenSSL is 4.0.3, not the pinned 3.5.x. **Build only in the container.**) | — |
| 3b-L2 | Legacy unit build | ✅ | **The CI build job, reproduced** in `podman build -f Dockerfile.build -t freehsm-build:1.2.0 .` (OpenSSL **3.5.7**), on a scratch copy: `make clean && make` ✅ → `make integrity` ✅ (signed, readback matches) → `make test-integrity` ✅ (unsigned / signed / tampered all correct) → **`make tests` ✅ EXIT=0 in 213s**, every per-test summary `0 failure(s)`. ⚠️ Two findings: **(a)** `ossl-modules/` in the image holds only `legacy.so`. The **FIPS provider isn't in the build image**; CI installs it separately in `test-fips-provider` (`scripts/ci_install_openssl_fips.sh`), which wasn't run here. **(b)** CI's "Smoke test" step (`ci.yml`) runs `/tmp/smoke 2>&1 \| head -30` without `pipefail`, and `test_smoke` statically links an unsigned digest slot. Run that way it fails (`C_Initialize returned 0x80000002`, "module is unsigned"), **but the step passes anyway**. `make tests` runs it correctly, with `FHSM_INTEGRITY_ALLOW_UNSIGNED=1`. | (a) Run `bash scripts/ci_install_openssl_fips.sh` in the container to get a FIPS-provider baseline. (b) Not this pass's job, but the transform must not copy CI's masked smoke step as an oracle; use `make tests`. |
| 3c | Target toolchain (Rust) | ✅ | `rustc`/`cargo` **1.99.1** stable, `clippy`, `rustfmt`; a fresh crate passes `cargo test`; **crates.io reachable** (fetched `cryptoki 0.10`); `libclang-22` present for `bindgen`. Missing: `cargo-audit`, `cargo-fuzz`, `cargo-deny`. | `cargo install cargo-audit cargo-deny cargo-fuzz` (cargo-fuzz needs a nightly toolchain: `rustup toolchain install nightly`). |
| 4 | Source completeness | ⚠️ | **Includes:** every project-internal `#include` resolves; the only unresolved headers are system ones (23 distinct `openssl/*.h`, top `evp.h` ×36, `x509.h` ×16, `core_names.h` ×15; plus `gtk/gtk.h`). **Generated code is checked in** (`src/gen/fhsm_dispatch.c`) next to its generator. Comments mention `include/fhsm_pkcs11.h` and a `.in.h` template, but neither exists and nothing `#include`s them, so this is doc drift, not a missing file. **Descriptors:** systemd unit present; `/etc/freehsm/freehsm.conf` is read by `fhsm_conf.c`/`fhsm_mode.c` but no sample ships. **Data definitions:** `docs/TOKEN_STORE_FORMAT.md` (binary `.tok` layout), fixture `tests/fixtures/token-v3.tok`, `include/fhsm_audit.h` (audit line format). **Binary-only artifacts:** none, apart from two logo PNGs and 12 release `sha256` refs. **Test corpus:** 116 C tests, 17 shell harnesses, CAVP `.rsp` (`kat/cavp/`), ML-DSA/SLH-DSA KAT vectors (2.1 MB), Wycheproof adapters, fuzz corpora: a strong behavioral oracle. | Write a sample `freehsm.conf` from `src/fhsm_conf.c`. |
| 5a | Production telemetry | ⚠️ | None. No APM server for this system; the connected CloudWatch MCP isn't relevant. Runtime evidence exists only as committed measurements (`probes/rest/README.md`, `tests/bench_*.c`, `tests/service_budget.sh`). | Optional. Recorded probe output from a built legacy module would stand in. |
| 5b | VCS history | ❌ | Still not a git repository (`Makefile` and `.github/` were restored; `.git` was not). No change-frequency data. `CHANGELOG.md` (425 KB) and 27 `RELEASE_v*.md` are a partial substitute. | Copy `.git` from an upstream clone (`git clone https://github.com/afchine1337/freehsm`), or accept CHANGELOG-only risk ranking. |
| 6 | Scope boundary | ✅ | Standalone (human: "the complete system"); no source-level crossings. **The binary ABI (PKCS#11 v3.2 C exports) is the inbound contract.** | Record the ABI-preservation decision in the brief. |

---

## Verdict per command

| Command | Verdict | Why |
|---|---|---|
| `assess` + `map` + `extract-rules` | **Ready-with-gaps** | Stack detected, all source present, no project includes missing, the `Makefile` gives `map` the real build graph, and `cloc` gives real LOC for the COCOMO index. `lizard` gives real per-function complexity. Remaining gap: no git, so no change-frequency risk signal. |
| `brief` | **Not ready** | Needs `ASSESSMENT.md`, `topology.json` and `BUSINESS_RULES.md`; none exist yet. No delta catalog is needed: this is cross-stack, not an uplift. |
| `transform` + `reimagine` | **Ready** (one gap) | Both sides are green: the Rust target (Check 3c) and the legacy module, built and fully tested in its pinned image (Check 3b-L2). **Dual execution is available**: the same `C_*` call sequence can run against the C `libfreehsm.so` and the Rust `cdylib` through the PKCS#11 ABI and the results compared. The remaining gap: there's no FIPS-provider baseline yet (see 3b-L2 (a)), so FIPS-mode behaviour has no recorded oracle until that job is run. |
| `harden` | **Ready-with-gaps** | No SAST installed here (`cppcheck`, `clang-tidy` and `semgrep` are missing; `Dockerfile.build` installs the first two). On the Rust side, `cargo-audit`/`cargo-deny` are missing. |
| `uplift` | **N/A** | Cross-stack rewrite, not a same-stack version bump. |

---

## Single most important fix

~~Make the legacy module buildable.~~ **Done 2026-10-30.** It builds and passes `make tests`
in the pinned image.

~~Install the analysis tools.~~ **Done 2026-10-30** (`cloc`, `lizard`, `glow`, `delta`).

The one remaining red item: **restore `.git`** (Check 5b) for change-frequency risk ranking.
It isn't a blocker; `/modernize-assess` can run without it.
