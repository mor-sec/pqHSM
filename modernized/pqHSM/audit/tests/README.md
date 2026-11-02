# Characterization tests: audit trail (Phase 1)

These tests define "done" for `pqhsm-audit` and `pqhsm-audit-verify`. They record what the
legacy C code **does** (`src/fhsm_audit.c`, `tools/freehsm_audit.c`). They do not record
what its comments say it does. Two places expect non-C behaviour, both approved and named in
the test: DIV-002 (`ts` non-decreasing in `seq` order) and DIV-003 (`AuditLog::open` takes
only a 32-byte key).

## Running

From `modernized/pqHSM`:

```sh
podman run --rm -v $PWD:/ws:Z -v <cargo-registry>:/opt/rust/cargo/registry:Z -w /ws \
    localhost/pqhsm-rust:1.99.1 cargo test
```

Run them in the container, not as root on the host. The `/dev/null`, `/dev/full` and FIFO
tests need Linux. While the crates are still `todo!()`, every test that calls into them
panics with `not yet implemented: RULE-…`.

The C cross-check is opt-in. It runs the legacy tool on logs written by Rust:

```sh
FHSM_C_AUDIT_TOOL=/path/to/tools/freehsm-audit \
    cargo test -p pqhsm-audit --test cross_impl -- --ignored
```

## Layout

| File | What it pins |
|---|---|
| `audit/tests/record.rs` | event names, roles, safe ASCII, actor, params, body/line layout, TooLong at 2047/2048 |
| `audit/tests/golden_lines.rs` | every C-written line reproduced byte for byte from its inputs; `append` writes the same bytes apart from `ts` and the MACs |
| `audit/tests/chain.rs` | chain head (baseline fixture) and the record MAC |
| `audit/tests/verify.rs` | `verify::verify_file` against what C `fhsm_audit_verify` returned (rv, `broken_at_line`) |
| `audit/tests/log.rs` | numbering (including the `strtoul` quirks), open, append, group commit, streams, sticky failure, latch reasons |
| `audit/tests/key.rs` | every branch of `fhsm_audit_key_provision`, through a fake `KeyEnv` |
| `audit/tests/props.rs` | proptest: random logs verify in both verifiers; deletions, swaps and byte flips are rejected by both |
| `audit/tests/cross_impl.rs` | `#[ignore]`: the C tool verifies logs written by Rust |
| `audit-verify/tests/cli.rs` | the tool's stdout, stderr and exit code, byte for byte, for every recorded C run |

## Goldens

Every expected value under `*/tests/golden/` comes from running the C code in the pinned
legacy image. Nothing in it is hand-computed. To rebuild them all:

```sh
tests-support/golden/regen.sh                       # builds the legacy tree first
LEGACY_BUILD=/path/to/built/tree tests-support/golden/regen.sh
```

- `gen_audit.c` is linked against the legacy objects. It writes logs through
  `fhsm_audit_event`, records the inputs of each line (`lines/*.tsv`, with bytes in hex),
  runs `fhsm_audit_verify`, and probes numbering and streams.
- `make_goldens.py` lays out inputs, mutates C-written logs into tampered variants, and
  records the C tool's three outputs for each CLI case.

C-written logs carry real timestamps, so a regen changes their bytes but none of the
expectations. The only fixed-`ts` lines are the `craft_*.log` files. Their bodies were
written by hand and MACed by the C module's `fhsm_hmac`.

The only key anywhere is the non-secret test key, bytes `0x00..0x1f`
(`analysis/pqHSM/baseline/TEST_KEY_HEX`), or a prefix of `0x00..0x3f`. Do not add a real
`audit.key`.

## Adding a case

- **A tampered log for both verifiers:**
  1. Add a mutation to `mutate()` in `make_goldens.py`.
  2. Run `regen.sh`.
  3. Add one line to the `verify_case!` list in `verify.rs` and one to the `cli_case!`
     list in `cli.rs` (`verify_log_<name>`).

  Guard tests fail until both are named.
- **A CLI invocation:** add it to `cases` in `make_goldens.py`, run `regen.sh`, then add its
  name to `cli_case!`.
- **A line-format input:** add an event to `mode_lines()` in `gen_audit.c` and run
  `regen.sh`. `golden_lines.rs` picks it up with no Rust change.
- **A numbering layout:** add it to `scen` in `make_goldens.py`, run `regen.sh`, then add a
  `numbering_case!` line in `log.rs`.

Name each test after the behaviour it pins, and put the `RULE-`/`DIV-` id in a one-line
comment.
