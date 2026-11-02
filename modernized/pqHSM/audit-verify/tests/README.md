# Characterization tests: auditor tool

`cli.rs` replays every C `tools/freehsm-audit` run recorded in `golden/cli/<case>/`, and
asserts the same stdout, stderr and exit code byte for byte. Each case directory holds
`args` (one per line, `args[0]` first), `stdout`, `stderr` and `exit`.

To run the tests, regenerate the goldens or add a case, see `../../audit/tests/README.md`.
