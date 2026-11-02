# pqHSM pilot playbook: Phase 1, audit trail (C → Rust)

This is the recipe Phase 1 proved, written for whoever runs Phases 2 to 5. Phase 1 is the pilot
in the brief (`MODERNIZATION_BRIEF.md` §3), and the brief asks for this file as an exit
criterion. The detail of the port itself is in `modernized/pqHSM/TRANSFORMATION_NOTES.md`.

## 1. Recipe, per module

1. **Characterise first.** Write tests against goldens produced by the *C* code, never against
   values worked out by hand.
   - Generators live in `modernized/pqHSM/tests-support/golden/`. `gen_audit.c` links the
     legacy objects, `make_goldens.py` mutates the logs, and `regen.sh` runs both in the pinned
     image.
   - Commit the generated files under `<crate>/tests/golden/`. Rust tests read them; nothing
     regenerates them at test time.
   - Have a meta-test fail when a golden row has no named test (as in
     `every_golden_row_is_covered_by_a_named_test`).
2. **Register every behaviour change before writing the code.** A C quirk the tests pin down is
   either preserved, or registered as a `DIV-NNN` in `DIVERGENCES.md` with the user's decision.
   - The test for a DIV keeps C's result visible: assert what C did, then what Rust does. See
     `DIV008` in `audit/tests/verify.rs`.
3. **Write the crate from the specification.** Reproduce C's parsing quirks only where output
   depends on them: `strtoull`, `sscanf("%2x")`, `fgets` splitting, `perror` text.
4. **Prove it three ways:**
   - `cargo test` against the goldens;
   - the hybrid run (§3);
   - the architecture-critic review, with its HIGH findings applied before the phase closes.
5. **Write `TRANSFORMATION_NOTES.md`:** mapping table, deviations, what was not migrated,
   follow-ups.

## 2. Link swap: replacing a C object with Rust

`modernized/pqHSM/hybrid.mk` includes the unchanged legacy `Makefile`. A new module needs three
edits in it:

1. **An explicit recipe for `$(OBJDIR)/src/<module>.o`.** It outranks the pattern rule. Point
   it at a C shim, or at an empty translation unit when no shim is needed.
2. **Build the Rust code into the one staticlib.** Add it to the same `staticlib` crate, or to
   one aggregate crate. Two Rust staticlibs in one `.so` each carry their own copy of `std`.
3. **Leave the link line alone.** `LDFLAGS` already carries `-static-libgcc
   -Wl,--exclude-libs,ALL <lib> -Wl,--push-state,--as-needed <native libs> -Wl,--pop-state`.
   Every legacy `$(LIB_OBJ)` link appends `$(LDFLAGS)`, so tests that link internal symbols
   pick up the Rust code too.

Rules that the pilot paid for:
- **No panic may cross `extern "C"`.** It aborts the host process.
  - Release builds use `panic = "abort"`.
  - Use no thread-local with a destructor: it panics during TLS teardown, and `C_Finalize`
    from `atexit` runs exactly then. Use a `Cell` of plain `Copy` data.
  - Use no `eprintln!`: it panics on a failed stderr write. Use `let _ = writeln!(stderr(), ..)`.
- **Call libcrypto directly through `openssl-sys` / `extern "C"`,** not through the `openssl`
  crate. The crate's init pulls in `libssl` and adds a NEEDED entry. Direct calls also use
  the same default library context as C, which keeps FIPS-provider behaviour identical. The
  hybrid run checks that `EVP_Q_mac` stays an undefined dynamic symbol.
- **Keep every `unsafe` in `src/ffi/`.** It is an exit criterion. Non-ABI bindings, such as
  libcrypto, go in `ffi/` too, outside the `ffi` feature.
- **Variadic C functions cannot be defined in stable Rust.** Keep a C shim of about 20 lines
  that flattens the argument list.
- **Module state belongs to the ABI layer, not the safe API:** process-wide counters, the
  ERROR-state gate, thread-local actor.
- **Forks.** Tag process-wide state with the PID that created it, and treat it as absent in
  any other process. Never hold a lock across I/O, because a fork taken mid-I/O leaves the
  child holding it.
- **Recursive `$(MAKE)` builds pure C.** Targets such as `audit-switch`, `asan` and
  `tsan-concurrency` call `$(MAKE)` without `-f hybrid.mk`. Run their steps one by one with
  `make -f modernized/pqHSM/hybrid.mk`, as `inner.sh` does for TSan.

## 3. Harness

```
modernized/pqHSM/tests-support/hybrid/run.sh <pure-C build dir> <out dir>
```

The runner copies the repository; nothing in the tree is written. It runs
`tests-support/hybrid/inner.sh` in `localhost/pqhsm-rust:1.99.1` and prints `summary.txt`.

| Step | What it proves |
|---|---|
| 1 | Every `make -n tests` command passes against the hybrid build. Each command gets its own `TMPDIR`. |
| 2 | `nm -D` and NEEDED are identical to the C build. |
| 3 | Cross-verification: the C tool verifies Rust logs, the Rust tool verifies C logs, plus the ignored `cross_impl` tests. |
| 4 | Review regressions: `EVP_Q_mac` comes from libcrypto; `C_Finalize` at exit does not abort. |
| 5 | DIV-009: the parent's log verifies after a forked child re-initialises. |
| 6 | Corpus diff: every command is re-run on the C tree, and each command's audit logs are compared after `corpus_norm.py` normalises `ts` and the MACs. Verdicts are `same`, `order-only` or `DIFF`; each `DIFF` is in `corpus_diff/<n>.diff`. |
| 7 | TSan on the concurrency and fork tests (see §4, surprise 9). |

Audit keys never leave the container. Only normalised logs, which have no MACs, are written
to the output directory.

## 4. Surprises met

Each of these cost a run or a review round. In order of discovery:

1. **The suffix is 75 bytes, not 74.** A boundary test was written from reading the code
   rather than from a golden. Derive limits from C output.
2. **`fgets` splits lines in the verifier.** It does not read whole lines, and the first
   DIV-003 text claimed it did. Read the I/O loop before describing it.
3. **`u8::from_str_radix` accepts `+`;** C's hex parser does not. Rust's lenient parsers are
   not C's.
4. **The Rust tool chain added NEEDED `libgcc_s.so.1`.** That is a visible change to the
   module's dependencies. Fixed with `-static-libgcc`.
5. **The `openssl` crate pulled in `libssl` and its init.** It was replaced with direct
   libcrypto calls.
6. **`C_Initialize` has no "already initialised" guard,** so a second call reopens the log.
   An earlier note claimed otherwise.
7. **TLS teardown abort.** `C_Finalize` from `atexit` aborted the process. It was found by
   review, not by any test. `tests-support/hybrid/atexit_finalize.c` now covers it.
8. **Two C defects that tests characterised as correct:**
   - the verifiers ignored bytes after the MAC (DIV-008);
   - forked children wrote into the parent's chain (DIV-009).

   Characterisation pins down behaviour, including wrong behaviour; the review step is what
   questions it.
9. **TSan did not run at first,** and reported nothing. On this kernel's mmap ASLR it aborts
   at start with `FATAL: ThreadSanitizer: unexpected memory mapping`, and make treated the
   plain-built `test_fork_child` as up to date.
   - Fixed by running the tests under `setarch -R` (container seccomp relaxed) and by removing
     the binaries before the TSan build.
   - Result: `test_apilock`, `test_concurrency`, `test_concurrency_store` and `test_fork_child`
     pass with 0 reports, on both the hybrid and the pure-C build.
   - The Rust staticlib is not instrumented: stable has no `-Zsanitizer`, and the image has no
     nightly. Check that a sanitizer found nothing *because it ran*, not because it never
     started.
10. **The corpus diff needs a control run.** 68 of the 106 commands write audit logs, 8,913
    records in all. 64 are identical after normalisation. The other 4 differ, and every one is
    explained:
    - `test_concurrency`: thread order. C against C differs in the same way, with the same
      multiset of events.
    - `test_cbc_pad_oracle`: random ciphertexts by design. C against C differs too; only the
      number of `decrypt OK` records changes.
    - `test_concurrency_store`: threads racing for objects. C against C differs too; only the
      counts of `object_create`, `object_destroy` and `sign` records change.
    - `test_fork_child`: DIV-009. Under C, three children each wrote a `state_transition` into
      the parent's log; Rust drops them. C against C is identical.

    A `DIFF` verdict is meaningless until the same command has been run C against C.

## 5. What Phase 2 should change in this recipe

- **Start with the corpus diff and TSan in the harness from day 1,** not at the end of the
  phase.
- **Run the architecture review before** the characterization tests are approved, not after
  the port. Both inherited defects would have been decided up front.
- **Commit the C golden corpus of token-store files first.** It is a Phase 2 entry criterion.
