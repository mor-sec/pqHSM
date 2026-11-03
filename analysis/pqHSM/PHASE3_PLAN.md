# Phase 3 plan: crypto core, DRBG, secure heap, self-tests, PKI encoders

Status: **APPROVED 2026-11-02** (user: "Approve plan"; network: "Wycheproof, once", "FIPS .debs, once"). Slice 1 (pilot) implemented 2026-11-02: goldens 127/127, harness 106/106 (`modernized/pqHSM/TRANSFORMATION_NOTES.md` § Phase 3). DIV-038 decided (Fix); review M1 fixed with `pthread_once` (user: "Fix now with pthread_once"). Slice 2 (DRBG) implemented (user: "Start slice 2"): 127/127 C goldens (19 Rust-only for DIV-032/033/037/042/044), harness clean, review applied; DIV-041 to DIV-044 decided and done (user, 2026-11-02). Slice 3 (crypto core) implemented (user: "Start slice 3"): 157/157 C golden rows replayed (2 Rust-only for DIV-035), harness clean including the new FIPS step (§4.3) on both profiles, review applied (H1, M1, M2, L1-L3); DIV-034 partly done, DIV-035 done, DIV-045 recorded. Slice 4 (self-tests) implemented 2026-11-03 (user: "commit it and start slice 4"): goldens from the legacy C replayed (integrity 76 rows, KAT vectors 85, KAT runs 2,146 over 131 scenarios with the full call trace, pair-wise 247), harness clean including FIPS on both profiles and Wycheproof, review applied (M1-M3, L1, L3, N3; no HIGH); DIV-034, DIV-035 and DIV-046 done; DIV-047 decided Fix and done (user: "Keep the fix"). Slice 5 (PKI encoders) started (user: "Commit, then start slice 5"), split 5a-5d with the `fhsm_composite.o` swap once at the end: 5a (params, M', keys, sign, verify; `src/fhsm_composite.c:1-481`) ported, all 140 C golden rows replayed, 13 mutations with 12 killed (the survivor is the digest-failure path, unreachable without fault injection). 5b (raw/SPKI key forms, PKCS#10, self-signed, issuance; `:482-1450`) ported: all 199 C golden rows replayed byte for byte (validity dates pinned by a `time()` defined in both the generator and the test), 25 mutations with 24 killed (the survivor is equivalent). Extension values are DER-encoded in safe Rust (`pki/src/x509.rs`); OpenSSL still assembles names, validity and the SPKI slot. 5c (CRL, OCSP, `fhsm_pki_algid`; `:1451-2128`) ported: 190 more C golden rows replayed byte for byte (388 in x509.tsv). The OCSP responder's C ABI now calls the Rust encoder; the two C-encoder doubles are gone, and all 56 non-synth answer rows reproduce C's response bytes through it (clock pinned, C's signatures replayed). 31 mutations with 30 killed; the survivor is the nextUpdate time failure, unreachable with an `int` `days`. Not carried over: `fhsm_ocsp_answer`'s "no composite AlgorithmIdentifier" branch, unreachable because `fhsm_pki_algid` never fails for the composite. Its ALGID_FAIL test is removed. 5d (ECDSA raw-to-DER, CMS encode and verify; `:2129-2917`) ported: 183 more C golden rows replayed (571 in x509.tsv), including 61 CMS structures, real and hand-assembled, run through all three verifiers. 39 mutations with 38 killed; the survivor is equivalent (`fhsm_composite_cms`'s digest-length check repeats the one `fhsm_pki_cms` makes for SHA-512). Fuzzing (§4.6): `pki/fuzz/`, two targets; there is no PEM parser in `src/fhsm_composite.c`, so none is fuzzed. Swap done (`hybrid.mk` empties `fhsm_composite.o`): harness clean, including the new PKI step (§4.3: 21 DER files from C and hybrid identical, every artifact verified by the openssl CLI, a tampered set refused), the Wycheproof re-run (0 violations, hybrid equal to C) and FIPS on both profiles. Review applied (H1 pinned as C, Phase 5; M1-M3, L1, L2, L4); DIV-048 decided Fix (user: "keep refusing a signer callback that reports a longer signature than its buffer"); DIV-049 decided Fix (user: "keep refusing BOOLEAN key parameters"). Slice 5 committed (`2e1fedb`). **Phase 3 exit criteria met 2026-11-03** (user: "Close Phase 3 (Recommended)"): DRBG property tests added, Wycheproof re-run with the FIPS provider active on both profiles; see TRANSFORMATION_NOTES § Phase 3 exit criteria. See TRANSFORMATION_NOTES.md, Phase 3, Slices 3 and 4.
Brief: `MODERNIZATION_BRIEF.md` Phase 3. All four entry criteria are ticked (2026-11-02).
Method: `/modernize-transform`, slice by slice, as in Phase 2 (`PHASE2_PLAN.md`). Each slice runs the same steps:
1. Characterisation goldens from the C.
2. The Rust implementation behind the same C ABI.
3. `hybrid.mk` empties the C object.
4. A harness run, then a review.

## 1. Scope

| File | Lines | Exported | Target |
|---|---|---|---|
| `src/fhsm_conf.c` | 93 | 2 | `pqhsm-crypto::conf` |
| `src/fhsm_memory.c` | 274 | 8 (`fhsm_secure_*`, `fhsm_zeroize`, `fhsm_ct_memcmp`) | `pqhsm-crypto::heap` |
| `src/fhsm_drbg.c` | 471 | 4 | `pqhsm-crypto::drbg` |
| `src/fhsm_crypto.c` | 608 | 13 (init/finalize, hash, HMAC, AES-GCM, PBKDF2, RNG) | `pqhsm-crypto` |
| `src/fhsm_integrity.c` | 425 | 4 | `pqhsm-selftest::integrity` |
| `kat/fhsm_kat_vectors.c`, `kat/cavp_extended.c` | 379 + 1,997 | 2 | `pqhsm-selftest::kat` |
| `src/fhsm_pairwise.c` | 254 | 1 | `pqhsm-selftest::pairwise` |
| `src/fhsm_composite.c` | 2,917 | 38 | `pqhsm-pki` (the existing crate) |
| **Total** | **7,418** | | |

`fhsm_pkcs11.c` and the other callers stay C until Phase 4, so every Rust replacement exports the C symbols with C's argument checks in C's order. That is what Phase 2 did.

## 2. Slices, in dependency order

| # | Slice | C retired | Why here | DIVs |
|---|---|---|---|---|
| 1 | **Pilot: secure heap + conf** | 367 | A leaf (it includes only `fhsm_conf.h`), used by 16 files, the token crate's `Buf` among them. It exercises everything the later slices need: C-ABI export, mlock, zeroise, the empty TU, and the `test_secure_heap` exit criterion. | none |
| 2 | **DRBG** | 471 | Health tests (RCT, APT, CRNGT), reseed and chunking. Self-contained apart from `RAND_bytes` and the SHA2-384 conditioner. | 032, 033, 036, 037 |
| 3 | **Crypto core** | 608 | Provider load order, init-once and finalise, the primitives. Init still calls the C integrity check and KATs over FFI until slice 4, as Phase 2's token called C crypto. At the end, the token crate's crypto seam (`token/src/ffi/cprim.rs`) switches to Rust. | 034 (provider skip), 035 |
| 4 | **Self-tests** | 3,055 | Integrity, KAT, CAVP and pairwise tests. The vectors move as data, byte for byte. | 034 (integrity bypass) |
| 5 | **PKI encoders** | 2,917 | Composite ML-DSA-65 + Ed25519, X.509, CSR, CRL and OCSP. Must stay byte-identical and cross-verify with the `openssl` CLI. | none (021/069 clamping is Phase 5) |

The pilot is expected to revise this plan. As in Phase 2, what it surfaces is written back here before slice 2 starts.

**What the pilot surfaced (2026-11-02):** (1) `make tests` does not run `test_secure_heap` or `probe_secure_heap`; the harness now does (step 4b), on C and hybrid. (2) Process-global state (the arena, later the DRBG and the init latch) needs one process per scenario: goldens fork per scenario, and the Rust replay uses `harness = false` and re-executes itself. Slices 2 and 3 reuse that. (3) `OnceLock` is not `pthread_once` across `fork` (review M1): use `pthread_once` wherever C does. No reordering of slices.

## 3. Technical choices (mine; say if you disagree)

- **OpenSSL binding:** use raw `openssl-sys`, kept in each crate's `ffi/`, not the `openssl` crate. C fetches explicitly (`EVP_MD_fetch(NULL, "SHA2-384", NULL)` and so on); the `openssl` crate fetches implicitly through the legacy getters. Mirroring C's fetch names and property queries exactly is the brief's mitigation for "FIPS-mode drift" (risk 1). The `openssl` crate is used in tests only, as an independent check.
- **One libcrypto:** dynamic `libcrypto.so.3`, as now. The harness's `NEEDED` comparison stays identical.
- **Secure heap:** the same mlocked arena design and sizes (`fhsm_conf` `secure_heap_bytes`), not a Rust allocator crate. Exhaustion still fails instead of falling back to pageable memory (#127).

## 4. How equivalence is proved

1. **Goldens from the C,** as in Phase 2:
   - New `tests-support/golden/gen_crypto.c` drives the C ABI, including NULL and out-of-range arguments, ERROR-state refusal, heap exhaustion and DRBG fault injection.
   - Rust replays the rows in order.
2. **Vectors:** every KAT and CAVP vector, byte for byte, in default mode and with the FIPS provider (exit criterion 1).
3. **Hybrid harness:** `make tests` 106/106, `nm -D`, `NEEDED`, the audit corpus and TSan, as now. Two additions:
   - **A FIPS step:** the hybrid module is signed and run under `run_fips_tests.sh` for both profiles, and must match `BASELINE.md` § FIPS (93/93, 62 KATs, 155/92 and 167/99 probes).
   - **A PKI step:** certificates, CSRs, CRLs and OCSP responses from C and from Rust are compared byte for byte (with fixed RNG and time), and each is verified with the `openssl` CLI.
4. **Property tests** for the DRBG health tests at their configured cutoffs (exit criterion 3): APT 18 passes and 19 fails, RCT at 6, CRNGT on every block.
5. **Divergence tests:** one per DIV-032 to DIV-037, each failing on C and passing on Rust.
6. **Fuzzing:** the DER and PEM parsers in slice 5.

## 5. Needs a decision now

1. **Approve the plan:** the slice order, with secure heap + conf as the pilot.
2. **Wycheproof** (exit criterion 1 names it). CI runs `pip install python-pkcs11` and `tests/wycheproof/fetch_vectors.sh`, both from the network (`.github/workflows/wycheproof.yml`). Proposal: do both once, in a throwaway container, and cache the vectors and the wheel under the scratch registry. Record the C baseline first, then run the same harness against the hybrid module after slices 3, 4 and 5.
3. **FIPS provider in the harness:** download the three Debian packages (`openssl`, `libssl3t64`, `openssl-provider-fips`, 3.5.7-1~deb13u3) once and install them offline in every harness run, instead of reaching apt each time.
