# legacy/

FreeHSM's C, which pqHSM replaced, and the hybrid build that replaced it one module at a time.
Nothing in the default build reads this directory: the top-level `Makefile` builds, signs, tests
and installs with Cargo alone. It stays as the oracle the Rust was compared against, and goes one
release after the first pqHSM release (`analysis/pqHSM/PHASE6_PLAN.md` §8.2, slice 5d).

## Building the oracle

```bash
make -C legacy           # libfreehsm.so, the C tools and service (OpenSSL 3.5 under /usr/local/ssl)
make -C legacy tests     # the C test suite, against that build
```

The legacy `Makefile` runs from here, so its own tree is `./` and the rest of the repository is
`../`. The C reads some files relative to its working directory; links here point at the copies
that stayed at the root: `kat/cavp`, `fuzz/corpus`, `tests/vectors`, `tests/fixtures`,
`tests/wycheproof` and `tests/tpm2-stub.sh`. The shell tests it runs are the root's `tests/*.sh`, and `make generate` writes
its `docs/MECHANISMS.md` here, in `legacy/docs/` (ignored), leaving the root's alone.

## What is here

| Path | What |
|---|---|
| `src/`, `include/`, `kat/`, `tools/`, `service/`, `fuzz/` | the C module, its KATs, tools, service and libFuzzer targets |
| `tests/` | the C tests that call internal `fhsm_*` symbols (slice 5c); the ABI-only ones are the root's `tests/abi/`, the pkiops ones `modernized/pqHSM/gui/tests/` |
| `scripts/` | the C build's and release's scripts; the ones pqHSM still uses (`sign_module.sh`, the pkcs11-check ones, `ci_install_openssl_fips.sh`, the docs checks) stayed in the root's `scripts/` |
| `Makefile`, `Dockerfile.test`, `probes/`, `disabled/`, `dist/`, `CHANGELOG.md`, `RELEASE_v*.md` | the C build, its test image, spikes, disabled diagnostics, the release references and upstream's release history |
| `hybrid/` | the hybrid build, frozen (below) |

## hybrid/: frozen

`hybrid.mk`, the differential harness (`harness/`), the golden generators (`golden/`) and the two
C files the hybrid compiled (`audit_event.c`, `empty.c`). They assume the layout before slice 5d,
so they do not run at this commit (user decision, 2026-11-26: "Freeze into legacy/
(Recommended)"). They run at commit `0f481e9`, slice 5c, the last hybrid state:

```bash
git worktree add ../pqhsm-5c 0f481e9    # then follow analysis/pqHSM/PILOT_PLAYBOOK.md there
```

The last full harness run, run 39, is recorded in `modernized/pqHSM/TRANSFORMATION_NOTES.md`
(slice 5c). Since then the regression suite is `make test`: the Rust suites, `tests/abi/` and the
GUI's tests.
