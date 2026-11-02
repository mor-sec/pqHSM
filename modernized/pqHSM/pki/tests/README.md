# Characterization tests: revocation DB and OCSP responder body (Phase 2, slice 2)

These tests define "done" for `pqhsm-pki`. They record what the legacy C code **does**
(`src/fhsm_revocation.c`, run in `localhost/freehsm-build:1.2.0`), not what its comments or
header say. Five places expect non-C behaviour, approved in `analysis/pqHSM/DIVERGENCES.md`:

- **DIV-016** (DECIDED, Fix): `fhsm_rev_date_to_time` refuses any field outside its calendar
  range. The tables `DIV016_DATE`, `DIV016_LOAD`, `DIV016_ANSWER` and `DIV016_CORPUS` in
  `revocation.rs` assert C's value first and Rust's second. `testdata/rev_month13.db`, which C
  loads, must be refused with the same text C gives `rev_bad_date.db`. Second = 60 is out of
  range, and the in-memory bad date answers "revoked at 1970" (both confirmed 2026-10-31).
- **DIV-019 to DIV-021** (DECIDED, Fix): a CR inside a line, a line over 510 bytes, and a read
  error each refuse the whole file. Table `DIV_LOAD_REFUSED`.
- **DIV-022** (DECIDED, Fix): save never writes through a symlink at `<path>.tmp`. Table
  `DIV022_SAVE`. The `/dev/full` row now saves normally, so no row reaches the write-failure
  branch any more.

RULE-023 ("good" for an unknown serial of our CA) and RULE-099/100 (no locking) are deferred,
so they are pinned exactly as C behaves.

## Running

From the repository root, so that the meta-test can read `analysis/pqHSM/DIVERGENCES.md`:

```sh
podman run --rm --cap-drop=DAC_OVERRIDE,DAC_READ_SEARCH \
    -v $PWD:/repo:z -v <cargo-registry>:/opt/rust/cargo/registry:Z \
    -w /repo/modernized/pqHSM localhost/pqhsm-rust:1.99.1 \
    cargo test --offline -p pqhsm-pki                    # 322 tests
#   ... cargo test --offline -p pqhsm-pki --features ffi   # + 14 C ABI tests
```

- **`--cap-drop` is required.** Root in the container can read a mode-000 file and write into
  a mode-555 directory, and the goldens were made without that capability. Without the flag,
  the "unreadable" and "read-only dir" tests fail with a message saying so.
- **The repository root is mounted**, not only the workspace: `the_div_tables_match_divergences_md`
  reads `analysis/pqHSM/DIVERGENCES.md` and fails with a message if it cannot.
- The save tests set umask 022, as the generator did, and one uses `/dev/full`.
- With the stub `src/`, 318 tests fail with `not yet implemented: RULE-…`. The 4 meta-tests
  pass, because they read only the goldens. The `ffi` binary aborts on its first call, because
  a panic cannot unwind out of `extern "C"`.

## How the OCSP answer is reached (and what is pinned)

`fhsm_pki_ocsp` (the BasicOCSPResponse encoder in `src/fhsm_composite.c`) stays C until
Phase 3. **The Rust API takes the encoder as an argument:**
`revocation::answer(&Query { req, ca, responder, db, days, label, now }, &mut encode)`, where
`encode(&Tbs) -> Result<Vec<u8>, fhsm_rv_t>`. The `ffi` C ABI passes an encoder that calls the C
`fhsm_pki_ocsp` with the caller's signer, and takes `now` from `time(NULL)`.

The generator links the legacy code with `-Wl,--wrap=fhsm_pki_ocsp`, which records exactly
what C handed the real encoder (`ocsp/CASE.enc`) and what the encoder returned
(`ocsp/CASE.basic.der`). It also links with `-Wl,--wrap=time`, which pins `now` to
2027-01-01T00:00:00Z. Ed25519 signatures are deterministic, so every answer is byte-stable.

- **Pinned, byte for byte (`revocation.rs`):** every argument to the encoder: the responder
  certificate, producedAt, thisUpdate and nextUpdate; each CertID as re-encoded, with its
  status, revocation time and reason; the responseExtensions bytes (the nonce); and the buffer
  cap C offers. The output must also match: Rust wraps C's BasicOCSPResponse and must produce
  C's whole OCSPResponse (`ocsp/CASE.resp.der`). The stats, `err` text and return code are
  pinned too.
- **Cross-checked:** `the_answers_agree_with_openssl_s_reading_of_c_s_responses` compares the
  decisions with OpenSSL's parse of C's response. The generator recorded that parse as the
  `resp_*` columns.
- **Masked:** nothing in `revocation.rs`. In `revocation_ffi.rs` the C ABI reads the real
  clock, so the replay double (`common/c_doubles.rs`) checks producedAt against the call's time
  window, checks that thisUpdate equals producedAt and that nextUpdate is `days` later, and then
  masks those three. It also checks the signer: the algid (composite or Ed25519), spki NULL,
  and the sign callback and ctx passed through unchanged.
- **Not reached by these tests:** the real C encoder called *from Rust*. Under
  `cargo test --features ffi`, `c_doubles.rs` defines `fhsm_pki_ocsp` and `fhsm_pki_algid`. The
  real path is exercised only by the hybrid build (`hybrid.mk`, the C tests that call
  `fhsm_ocsp_answer*`).

## Layout

| File | What it pins |
|---|---|
| `revocation.rs` | every row of `golden/rev/cases.tsv` through the safe API, `testdata/revocation.tsv`, the DIV-016 tables, meta-tests |
| `revocation_ffi.rs` | the C ABI: `#[repr(C)]` layout, partial writes and untouched outputs, `err` NULL and truncation, `cap` growth, `stats` NULL, `*out` ownership, encoder arguments |
| `common/mod.rs` | golden reader and unescaper, input rebuilders (`load_input`, `long_path`, `db_from_spec`), `state`, encoder text |
| `common/c_doubles.rs` | (`ffi`) replay doubles for the two C encoder imports |
| `golden/rev/` | generated by `tests-support/golden/regen_rev.sh`. Do not edit by hand |

### `golden/rev/`

- `cases.tsv` has one row per case: `case`, `op`, `rv`, then `key=value` columns. Text columns
  are escaped (`\\ \t \n \r \xHH`), and the generator's work dir is written `{dir}`.
  - `load`: `file` (`db/NAME.db`, `saved/CASE.db`, `missing`, `dir`, `unreadable`, `notdir`,
    `gen:N` = N lines `%08X 20260101000000Z -`), `err_mode=null`, `err_cap`, then the struct
    afterwards (`crl_number n cap e_null`), `err` (`untouched` = still `@`) and `entries`
    (`serialhex/date/reason,…`).
  - `save`: `db` spec (`crl=N;e=SERIAL,DATE,REASON;…`, built without validation), `target`
    (`plain replace tmp_exists missing_dir ro_dir is_dir tmp_full tmp_symlink len:N`),
    `after`/`after_tmp`/`victim` (`absent | dir | symlink:T | file:MODE:HEX`).
  - `answer`: `req ca responder` (`der/NAME.der`), `db` spec (default: C's load of
    `db/ocsp.db`, row `load_ocsp`), `days label sign err_mode err_cap stats synth`, then
    `encoder_called stats out_null out_len err`, plus `resp_*` (OpenSSL's parse) or, for the
    `synth` wrap rows, `prefix` (the OCSPResponse header C wrote around N pattern bytes).
- `der/`: invented Ed25519 certificates (seeds `0x40.., 0x60.., 0x80.., 0xA0..`) and OCSP
  requests. `db/`: crafted database files. `saved/`: what each save row wrote.
  `ocsp/`: `.enc`, `.basic.der`, `.resp.der` per answer row.

No credential, key or certificate from the legacy tree is a fixture.

## Candidate DIVs (decided 2026-10-31: 1, 2, 3 and 7 became DIV-019 to DIV-022; the rest are preserved)

Each is asserted exactly as C does it. None is in `DIVERGENCES.md` yet.

1. **A CR-only file loses entries silently.** The line is cut at its first `\r`, so a
   CR-separated file reads as one line (`src/fhsm_revocation.c:181`). See `load_cr_only`
   (crlNumber 3 and 0 entries) and `load_cr_only_entries`.
2. **Lines over 511 bytes are split by `fgets`** (`:176-177`). The tail is parsed as a new
   line, and line numbers count the pieces. A long *comment* can revive a revocation hidden
   after byte 511 (`load_long_comment_revives_an_entry`), or fail the file (`load_long_comment`).
3. **Read errors count as end of file.** `ferror` is never checked (`:177`), so a directory
   loads as an empty database (`load_directory_reads_as_empty`), and a mid-file I/O error would
   give a partial one. That is the outcome the header says must never happen.
4. **`crlNumber` goes through `strtoull`** (`:187-188`). `-1` and an overflow both load as
   18446744073709551615, and `crlNumber ` with no digits loads as 0 (`load_crl_negative`,
   `_overflow`, `_empty_value`).
5. **`19691231235959Z` is refused**, because `timegm`'s -1 is also its error value
   (`:103-104`). See `date_one_second_before_epoch` and `load_date_one_second_before_epoch`.
6. **`time_to_date` prints negative years with a sign** and reports success:
   `-0011231235959Z` (`:114-117`). See `time_last_of_year_minus_1`.
7. **Save follows a symlink at `<path>.tmp`.** `fopen("w")` has no `O_EXCL` or `O_NOFOLLOW`,
   and the rename then puts the link itself over the database (`:229,247`). See
   `save_follows_a_tmp_symlink`. Related: a failed rename leaves the `.tmp` behind
   (`save_onto_a_directory`); the `FILE` leaks when the flush fails (`:244-246`); and a 0600
   database comes back 0644 under umask 022 (`save_replaces_and_resets_mode`).
8. **Save writes what load refuses.** `fhsm_rev_db_add` validates nothing (`:253-259`), and
   save writes an empty serial or a bad date verbatim (`:236-241`). See `roundtrip_empty_serial`
   and `roundtrip_unvalidated_date`.
9. **`fhsm_rev_db_add` at the cap returns EPARSE (3)** (`:148-150`), where the header says
   EIO (`include/fhsm_revocation.h:164`). See `add_past_the_cap_is_eparse`.
10. **A nonce extension over 65535 bytes gets a 2-byte length** (`0x82`, truncated,
    `:521-527`). The response is then one OpenSSL cannot parse
    (`answer_nonce_ext_65536_header_truncated`). The tool can reach this; the service cannot,
    because it caps bodies at 64 KiB (`service/fhsm_service.c:142`).
11. **The encoder buffer is a guess** (16384 + certificates + 512 per CertID + exts, `:533`).
    A 41 kB request (20 CertIDs with 2000-byte serials, under the service's cap) fails with
    `building the OCSP response failed (0x150)`. See
    `answer_big_request_overflows_the_encoder_buffer`.
12. **`days` has no upper bound here.** Past 9999-12-31, nextUpdate becomes a 16- or
    18-character GeneralizedTime instead of an error. With OpenSSL 3.5.7, "cannot encode the
    time" (`:441-444`) is unreachable. See `answer_days_into_year_10000_emits_a_16_char_time`
    and `answer_days_int_max_emits_an_18_char_time`. The service bounds `days` to 1..365.
13. **An entry with an unparseable date is answered "revoked at 1970-01-01T00:00:00Z"**,
    because `date_to_time`'s result is ignored (`:490`). Only entries made through `add` can
    have such a date. Under DIV-016 the in-memory month-13 entry falls into this case, which is
    why `DIV016_ANSWER`'s Rust value is 1970 (`answer_div016_unvalidated_dates`).
14. **A negative serial matches the revoked serial of the same magnitude**, because the
    ASN1_INTEGER data carries no sign (`:485-487`). See `answer_negative_serial`.
15. **`fhsm_ocsp_answer` returns early without resetting `*out`, `*out_len` and `stats`**
    when `fhsm_pki_algid` fails (`:394-395`), unlike every other failure. This one is read from
    the code, because the real `fhsm_pki_algid` cannot fail. See
    `answer_without_a_composite_algid_touches_nothing_else`.

## Not covered, and why

- These branches are unreachable without fault injection, with OpenSSL 3.5.7 and these
  inputs:
  - `malformed CertID` (`:459-460`), because `OCSP_id_get0_info` cannot fail on a parsed
    request;
  - `cannot re-encode a CertID` (`:462-463`);
  - `cannot encode the time` and `cannot encode a revocation date` (`:444`, `:494`), because
    years 0000 and 9999 encode, and so do years past 9999 (item 12);
  - `cannot wrap the response` (`:551`), because the buffer is always large enough;
  - every `out of memory`.
- A failing `fsync` or `fclose` separate from the flush: only the flush failure (`/dev/full`)
  is pinned.
- Requests with `requestorName` or `optionalSignature`: C ignores both, and the generator
  does not build them.
- Two concurrent writers (RULE-099/100). The behaviour is deferred to Phase 5 and has no
  deterministic golden.
- The real C encoder called from Rust: see above.

## Adding a case

1. Add a row to `main()` in `tests-support/golden/gen_rev.c`: a `CRAFT` + `LOAD`, `save_row`,
   `ANS(...)`, `check_row`, or a pure-helper call. Give any new input a column the runners in
   `common/mod.rs` can rebuild it from.
2. Run `tests-support/golden/regen_rev.sh` (podman and `localhost/freehsm-build:1.2.0`). Run it
   twice and `diff -r` the output: the goldens must be byte-identical.
3. Name the row in a `golden!` table in `revocation.rs`. Until you do,
   `every_golden_row_is_covered_by_a_named_test` fails.
4. If Rust is meant to differ, register a DIV in `DIVERGENCES.md` first. Then add the row to a
   `DIV016`-style table, so that the test asserts C's value before Rust's.
