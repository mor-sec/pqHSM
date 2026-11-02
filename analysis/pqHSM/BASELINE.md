# Baseline — pure-C pqHSM (FreeHSM 2.6.0)

*Recorded 2026-10-30 for `MODERNIZATION_BRIEF.md` Phase 1 entry criteria. This is the oracle every
hybrid and Rust build is compared against. Regenerate only if the C tree changes, which Q4 says it
will not.*

## Environment

| | |
|---|---|
| Image | `localhost/freehsm-build:1.2.0` (pinned Debian snapshot, `Dockerfile.build`), run as container root, entrypoint overridden |
| Compiler | gcc (Debian 14.2.0-19) 14.2.0 |
| OpenSSL | OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026) (default provider; **no FIPS provider in the image**) |
| `libfreehsm.so` SHA-256 | `4f784fc2fbcb8b8620d7a90b308d5ecd501f8775361f7523c379f77bf2700e29` (built with `make all` from a scratch copy of the repo) |
| Profile | default (`nist-approved-only`), `FHSM_INTEGRITY_ALLOW_UNSIGNED=1` exactly as the `tests` recipe sets it |

## Results

| Suite | Result |
|---|---|
| `make tests`, run one command at a time (`baseline/make_tests_commands.txt`) | **106 / 106 commands pass**, 0 fail |
| Power-on KATs (`test_smoke` report, `baseline/smoke_kat_report.txt`) | **62 / 62 vectors pass**: SHA-2 and SHA-3 (including CAVP SHA-256), AES-256 CBC/CTR/GCM/CMAC/GMAC, HMAC, HKDF, PBKDF2, CTR_DRBG, RSA-2048 OAEP/PSS, ECDSA P-256/384/521, ECDH and Ed25519 export round-trips, ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128f |
| Mechanism probe (`test_advertised_operational`, `baseline/probe_advertised_operational.txt`) | **155 operations across 92 mechanisms**, 0 known gaps, "all good" |
| SLH-DSA NIST vectors (`test_slh_dsa_kat`) | 14 generations + 14 verifications, 0 failures |
| Audit fixture (`baseline/audit.log.000001`) | 3 records from `test_smoke`, written under a **fixed, non-secret test key** (bytes 0x00..0x1f, `baseline/TEST_KEY_HEX`); the C verifier reports "3 records OK, chain intact" in both file and directory mode |

## FIPS-provider baseline (recorded 2026-11-02, Phase 3 entry gate)

Run in a throwaway root container from the pinned image, on a copy of the C tree. It followed CI's `test-fips-provider` job (`.github/workflows/ci.yml:456-486`) for both profiles: `scripts/ci_install_openssl_fips.sh`, then `make clean && make && make test-bins && make integrity`, then `scripts/run_fips_tests.sh`. `FHSM_INTEGRITY_ALLOW_UNSIGNED`, `FHSM_KAT_ALLOW_FAIL` and `OPENSSL_CONF` were unset. The image itself was not changed. Fixtures are in `baseline/fips/`.

| Item | nist-approved-only (default) | all-mechanisms |
|---|---|---|
| Provider (`install.txt`) | Debian `openssl-provider-fips` 3.5.7-1~deb13u3, libssl3t64 3.5.7-1~deb13u3; `fips` and `default` active from `/etc/ssl/openssl.cnf` | same |
| Signed module loads the provider (`probe_fips_loaded`) | "fips provider available after C_Initialize" | same |
| Suite against the provider (`run_fips_tests-*.txt`) | **93 / 93**: 65 that open the signed `.so`, 28 signed copies of tests that embed the module; none fell back to the bypass | **93 / 93**, same split |
| Power-on self-test and KATs (`smoke_kat_report-*.txt`, signed copy of `test_smoke`) | `C_Initialize` 0x0; **62 / 62 vectors pass**, the same 62 as the default-provider report | 62 / 62 |
| Mechanism probe (`probe_advertised_operational-*.txt`) | **155 operations across 92 mechanisms**, 0 gaps, "all good"; identical to the default-provider probe apart from the bypass notice | **167 operations across 99 mechanisms**, 0 gaps, "all good" |
| Approved-mode refusal (`ec_curve_refusal-*.txt`) | PASS, 0 failures | PASS, 0 failures |

Not covered: the other refusal tests (`test_fips_*`, `test_*_refusal`) appear only as pass lines in `run_fips_tests-*.txt`, with no output kept. Timings vary from run to run and are not a fixture.

## Wycheproof (recorded 2026-11-02, Phase 3 slice 4 start)

The pure-C module (`baseline/src`) under `tests/wycheproof/run_wycheproof.py`, full mode, as CI's nightly job runs it (`FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_KAT_ALLOW_FAIL=1 OPENSSL_CONF=/dev/null`). Offline: `python-pkcs11` 0.10.1 from the cached wheel, the vectors from the one-time fetch (PHASE3_PLAN.md §5.2), in `localhost/pqhsm-rust:1.99.1`. Kept: `baseline/wycheproof/run_wycheproof-c.txt` (elapsed time removed) and `full-c.json`.

| Adapter | match | viol | skip |
|---|---|---|---|
| aes_cmac | 306 | 0 | 5 |
| aes_gcm | 310 | 0 | 6 |
| aes_gmac | 414 | 0 | 0 |
| ecdsa | 3,098 | 0 | 18,794 |
| eddsa | 236 | 0 | 0 |
| hmac | 522 | 0 | 0 |
| mldsa | 629 | 0 | 0 |
| mlkem | 21 | 0 | 0 |
| rsa_oaep | 788 | 0 | 420 |
| rsa_pss | 1,083 | 0 | 1,323 |

0 violations. The hybrid must print the same summary (harness step 10).

## Not recorded here, and why

- ~~FIPS-provider baseline~~: recorded 2026-11-02, above.
- ~~Wycheproof~~: recorded 2026-11-02, below.
- **Per-test timings:** the image has no `bc`, so the runner's timing column is empty. The earlier full `make tests` run took 213 s (PREFLIGHT).
- **all-mechanisms profile:** recorded under the FIPS provider (above). The default-provider `make tests` run covers only the default profile.

## Per-command results

| # | Command | Result |
|---|---|---|
| 1 | `cmd1` | pass |
| 2 | `cmd2` | pass |
| 3 | `cmd3` | pass |
| 4 | `cmd4` | pass |
| 5 | `cmd5` | pass |
| 6 | `cmd6` | pass |
| 7 | `./tests/test_conf` | pass |
| 8 | `./tests/test_smoke` | pass |
| 9 | `./tests/test_tpm` | pass |
| 10 | `./tests/test_cbc_pad_oracle` | pass |
| 11 | `./tests/test_composite_mprime` | pass |
| 12 | `./tests/test_composite_sign` | pass |
| 13 | `./tests/test_composite_p11` | pass |
| 14 | `./tests/test_composite_x509` | pass |
| 15 | `./tests/test_composite_csr` | pass |
| 16 | `./tests/test_composite_issue` | pass |
| 17 | `./tests/test_pki_classic` | pass |
| 18 | `./tests/test_composite_crl` | pass |
| 19 | `./tests/test_composite_prehash` | pass |
| 20 | `./tests/test_composite_cms` | pass |
| 21 | `./tests/test_composite_ocsp` | pass |
| 22 | `./tests/test_audit_key` | pass |
| 23 | `./tests/test_audit_backpressure` | pass |
| 24 | `./tests/test_pin_length` | pass |
| 25 | `./tests/test_throttle_reboot` | pass |
| 26 | `./tests/test_wrong_pin_store` | pass |
| 27 | `./tests/test_public_objects` | pass |
| 28 | `./tests/test_audit_fsync` | pass |
| 29 | `./tests/test_audit_concurrent` | pass |
| 30 | `./tests/test_audit_multiproc` | pass |
| 31 | `./tests/test_audit_switch` | pass |
| 32 | `tests/audit_switch.sh mandatory` | pass |
| 33 | `./tests/test_audit_verify` | pass |
| 34 | `./tests/test_p11_loader` | pass |
| 35 | `./tests/test_token_capacity` | pass |
| 36 | `./tests/test_decrypt_null_args` | pass |
| 37 | `./tests/test_robustness_args` | pass |
| 38 | `./tests/test_op_state` | pass |
| 39 | `./tests/test_unwrap_len` | pass |
| 40 | `./tests/test_hmac_multipart` | pass |
| 41 | `./tests/test_cipher_final_no_update` | pass |
| 42 | `./tests/test_eddsa_params` | pass |
| 43 | `./tests/test_digest_multipart` | pass |
| 44 | `./tests/test_sensitive_value` | pass |
| 45 | `./tests/test_hash_ml_dsa` | pass |
| 46 | `./tests/test_slh_dsa_sets` | pass |
| 47 | `./tests/test_slh_dsa_kat` | pass |
| 48 | `./tests/test_ec_curve_refusal` | pass |
| 49 | `./tests/test_ecdsa_verify_edge` | pass |
| 50 | `./tests/test_copyable_oneway` | pass |
| 51 | `./tests/test_generic_secret_len` | pass |
| 52 | `./tests/test_aes_cmac_multipart` | pass |
| 53 | `./tests/test_hash_slh_dsa` | pass |
| 54 | `./tests/test_aes_gmac_multipart` | pass |
| 55 | `./tests/test_pqc_params` | pass |
| 56 | `./tests/test_aes_sizes` | pass |
| 57 | `./tests/test_rsa_oaep` | pass |
| 58 | `./tests/test_advertised_operational` | pass |
| 59 | `./tests/test_derive_concat` | pass |
| 60 | `./tests/test_ecdh_peer_point` | pass |
| 61 | `./tests/test_derive_hkdf` | pass |
| 62 | `./tests/probe_ecdh_curves` | pass |
| 63 | `./tests/probe_hkdf_data` | pass |
| 64 | `./tests/test_pbkd2` | pass |
| 65 | `./tests/test_always_authenticate` | pass |
| 66 | `./tests/test_interface_v32` | pass |
| 67 | `./tests/test_pqc_pub_import` | pass |
| 68 | `./tests/test_gmac_params` | pass |
| 69 | `./tests/test_encap_flags` | pass |
| 70 | `./tests/test_encap_flags_store` | pass |
| 71 | `./tests/test_v3_fixture` | pass |
| 72 | `./tests/test_allowed_mechanisms` | pass |
| 73 | `./tests/test_nested_templates` | pass |
| 74 | `./tests/test_wrap_with_trusted` | pass |
| 75 | `./tests/test_finalize_release` | pass |
| 76 | `./tests/test_apilock` | pass |
| 77 | `./tests/test_concurrency` | pass |
| 78 | `./tests/test_concurrency_store` | pass |
| 79 | `./tests/test_fips_digests` | pass |
| 80 | `./tests/test_attributes` | pass |
| 81 | `./tests/test_set_dates` | pass |
| 82 | `./tests/test_init_token_session` | pass |
| 83 | `./tests/test_input_validation` | pass |
| 84 | `./tests/test_session_objects` | pass |
| 85 | `./tests/test_mech_advertise` | pass |
| 86 | `./tests/test_legacy_digest` | pass |
| 87 | `./tests/test_legacy_cipher` | pass |
| 88 | `./tests/test_legacy_rsa` | pass |
| 89 | `./tests/test_ec_curve_bounds` | pass |
| 90 | `./tests/test_oaep_decrypt_size` | pass |
| 91 | `./tests/test_sign_multipart` | pass |
| 92 | `./tests/test_cbc_pad_update_size` | pass |
| 93 | `./tests/test_audit_key_diag` | pass |
| 94 | `./tests/test_kw_iv` | pass |
| 95 | `./tests/test_login_conflicts` | pass |
| 96 | `./tests/test_session_cap` | pass |
| 97 | `./tests/test_fork_child` | pass |
| 98 | `./tests/test_pkiops` | pass |
| 99 | `./tests/test_pkiops_algs` | pass |
| 100 | `./tests/test_pkiops_objects` | pass |
| 101 | `./tests/test_pkiops_secret` | pass |
| 102 | `./tests/test_pkiops_envelope` | pass |
| 103 | `./tests/test_pkiops_envelope_rsa` | pass |
| 104 | `tests/fhsm_crypt_cli.sh` | pass |
| 105 | `tests/pki_tools_algs.sh` | pass |
| 106 | `./tests/test_secure_heap_shared` | pass |
