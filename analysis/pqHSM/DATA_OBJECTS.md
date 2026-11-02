# Data Objects — pqHSM (FreeHSM 2.6.0)

*Companion to `BUSINESS_RULES.md`, generated 2026-10-30 by `/code-modernization:modernize-extract-rules pqHSM`. Core records, their fields, and the rules that consume or produce them. The PKCS#11 ABI types (CK_ATTRIBUTE, CK_MECHANISM, …) are fixed by the OASIS standard and not repeated here.*

## Rule cross-reference

Rules are matched to a record by the record's name or the concepts it carries (e.g. OCSP, revocation DB, session open/close) appearing in the rule card, so treat this as an index, not a proof of data flow.

| Record | Rules that read or change it |
|---|---|
| `fhsm_token_s` | RULE-001, RULE-004, RULE-026, RULE-079, RULE-080, RULE-081, RULE-084, RULE-085, RULE-086, RULE-089, RULE-109 |
| `fhsm_object_t` | RULE-037, RULE-045, RULE-055, RULE-057, RULE-058, RULE-062, RULE-091 |
| `fhsm_session_entry_t` | RULE-035, RULE-037, RULE-072, RULE-073, RULE-083, RULE-090, RULE-091, RULE-092, RULE-101, RULE-102, RULE-103 |
| `fhsm_op_t` | RULE-042, RULE-051, RULE-056, RULE-060, RULE-061, RULE-073, RULE-086, RULE-087, RULE-104, RULE-105, RULE-106 |
| `fhsm_find_state_t` | RULE-055, RULE-073, RULE-104 |
| `fhsm_slot_t` | RULE-044, RULE-079, RULE-102, RULE-109 |
| `fhsm_module_state_t` | RULE-007, RULE-010, RULE-011, RULE-012, RULE-013, RULE-070, RULE-071, RULE-072, RULE-073, RULE-074, RULE-075, RULE-093, RULE-095, RULE-096 |
| `fhsm_create_attrs_t` | RULE-038, RULE-045, RULE-057, RULE-058, RULE-073, RULE-091 |
| `fhsm_policy_attr_t` | RULE-041 |
| `fhsm_retired_t` | RULE-077, RULE-078 |
| `fhsm_drbg_stats_t` | RULE-001, RULE-002, RULE-003, RULE-010, RULE-011, RULE-012, RULE-013, RULE-073, RULE-074, RULE-093 |
| `fhsm_rev_entry_t` | RULE-022, RULE-023, RULE-054, RULE-099 |
| `fhsm_rev_db_t` | RULE-054 |
| `fhsm_composite_params_t` | RULE-065 |
| `fhsm_composite_ocsp_single_t` | RULE-021, RULE-054, RULE-069 |
| `request_t` | RULE-053 |
| `policy_rule_t` | RULE-068, RULE-098 |
| `budget_t` | RULE-097 |
| `ident_t` | — |

## On-disk formats the Rust build must read or write (if existing deployments must migrate)

| Format | Layout summary | Source | Rules |
|---|---|---|---|
| Token file `slotN.tok` | 317-byte little-endian header (magic `FHSM`, version 1, serial, label, salts, PBKDF2 iterations at offset 136, SO/user DEK wraps, failure counters; throttle fields written as 0) → `u32 ct_len ‖ nonce[12] ‖ ct ‖ tag[16]` object blob (blob magic v4 0xF5B40004, 912-byte fixed record) → public section (`u32 0xF5B5B001 ‖ u32 len ‖ objects`) | `src/fhsm_token.c:289-316`, `:455-476` | RULE-001, RULE-002, RULE-003, RULE-004, RULE-044, RULE-088 |
| TPM companion `slotN.tok.tpm` | tpm2-tools sealed blob of the 32-byte DEK (≤ 2048 bytes), written via `.tpm.new` + rename | `src/fhsm_token_tpm.c:59-135` | RULE-089 |
| Audit log `audit.log.NNNNNN` | one JSON line per event: seq, ts (ns), event, slot, session, role, actor (≤128), result, rv, params (≤1024), prev_hmac (hex64), hmac (hex64); chain head = HMAC(key, "FHSM-AUDIT-INIT\|seq=0") | `src/fhsm_audit.c:427-525`, `:643-680` | RULE-007, RULE-008, RULE-094, RULE-096 |
| Audit key `audit.key` / `audit.key.tpm` | 32 raw bytes, mode 0600, created O_EXCL; or TPM-sealed | `src/fhsm_audit.c:199-367` | RULE-093 |
| Revocation DB | text; per entry serial (hex), revocation date YYYYMMDDHHMMSSZ, reason; plus the CRL number | `src/fhsm_revocation.c:165-250` | RULE-024, RULE-099, RULE-100 |

## Field catalogs (as reported by each extraction lens)

The three lenses described overlapping records from different angles; they are kept side by side rather than merged so no field note is lost. Where they disagree on a line number, trust the source file.

### From the Calculations lens

| Name | Key fields (types) | Location |
|---|---|---|
| `struct fhsm_token_s` | label[64], serial[64], salt_so/salt_user[16], pbkdf2_iter u32, so/user_wrap_nonce[12], so/user_wrap_ct[48], user_initialized, failed_so/failed_user u32, throttle_*_until_ms u64 (monotonic, derived), dek* (32 B secure heap), dek_live, objects[1024], object_count, next_handle u32 | `src/fhsm_token.c:198-243` |
| `fhsm_object_t` | handle, class, key_type, value*/value_len (≤ 2 MiB), label[64], id[32]/id_len, flags/flags2/flags3, policy (≤ 8 mechs, 3 templates × 4 × 48 B) | `src/fhsm_token.c:128-196` |
| Token file | 317-B header (RULE-004), then `u32 ct_len ‖ nonce[12] ‖ ct ‖ tag[16]`, then `u32 0xF5B5B001 ‖ u32 len ‖ public objects`; blob magic v4 0xF5B40004, record fixed part 912 B | `src/fhsm_token.c:289-316`, `src/fhsm_token.c:455-476` |
| `fhsm_op_t` | mechanism, key_handle, iv[16]/have_iv, gcm_iv[512]/gcm_iv_len, gcm_aad*/len, gcm_tag_len (bytes), pq_ctx/pq_ctx_len/pq_ctx_toolong, mp_buf/mp_len/mp_cap | `src/fhsm_pkcs11.c:1916-2043` |
| Audit record | JSON line: seq u64, ts i64 ns, event, slot, session, role, actor (≤ 128), result, rv u32, params (≤ 1024), prev_hmac hex64, hmac hex64 | `src/fhsm_audit.c:643-680` |
| `fhsm_drbg_stats_t` | reseeds, bytes_emitted, rct/apt/crngt_failures, entropy_sources_active bitmask | `include/fhsm_drbg.h:68-75` |
| `fhsm_rev_entry_t` / `fhsm_rev_db_t` | serial bytes + len, date char[16] "YYYYMMDDHHMMSSZ", reason int (−1 none); db: e[], n, cap, crl_number u64 | `include/fhsm_revocation.h:136-148` |
| `fhsm_composite_params_t` | alg, name, oid, label, label_len 30, ph_name "SHA512", ph_len 64 | `include/fhsm_composite.h:62-70`, `src/fhsm_composite.c:41-50` |
| `fhsm_composite_ocsp_single_t` | cert_id, status, this_upd, next_upd, revoked_at, reason | `include/fhsm_composite.h:659-666` |
| `ident_t` / `budget_t` | ident: subject, in_flight, last_seen, limited, suppressed, limited_since, last_refusal; budget: subject[128], count, last (monotonic), used, announced | `service/fhsm_service.c:435-444`, `service/fhsm_service.c:631-637` |

### From the Validations & eligibility lens

- **`fhsm_object_t`** (`src/fhsm_token.c:128-196`), one record per object:
  - identity: `handle` u32, `class` u32 (CKO), `key_type` u32 (CKK, or the certificate type for certificates)
  - value: `value*` with `value_len` u32, `label[]`, `id[32]` with `id_len`
  - policy flags: `flags` u8 (SENSITIVE 0x01, EXTRACTABLE 0x02, UNMODIFIABLE 0x04, UNDESTROYABLE 0x08, LOCAL 0x10, ALWAYS_AUTH 0x20, TRUSTED 0x40, UNWRAP_SENS 0x80), `flags2` u8 (NO_ENCAP 0x01, NO_DECAP 0x02, NOT_COPYABLE 0x04, HAS_ALLOWED_MECH 0x08, HAS_WRAP/UNWRAP/DERIVE_TMPL 0x10/0x20/0x40, WRAP_WITH_TRUSTED 0x80), `flags3` u8
  - usage and ownership: `usage_flags` u8, `owner_session` u32 (0 means token object)
  - metadata: `start_date` and `end_date` [8], `application`
  - policy lists: `allowed[8]` with `allowed_count`, `wrap`/`unwrap`/`derive` [4] of `fhsm_policy_attr_t`
  - Flag bit values are in `include/fhsm_token.h:243-339`.
- **`fhsm_token_t`** (`src/fhsm_token.c:198-`), one per token:
  - identity: `path`, `label[64]`, `serial[64]`
  - key wrapping: `salt_so[16]`, `salt_user[16]`, `pbkdf2_iter` u32, `so_wrap_nonce[12]`/`so_wrap_ct[48]`, `user_wrap_nonce[12]`/`user_wrap_ct[48]`
  - PIN state: `user_initialized` int, `failed_so` and `failed_user` u32, `throttle_*_until_ms` u64
  - login state: `dek*` (32 bytes), `dek_live` int, `logged_in` role
  - object store: `objects[1024]`, `object_count`, `objects_loaded`, `objects_public`
- **`fhsm_session_entry_t`** (`src/fhsm_session.c:37-43`): `in_use` int, `slot` ulong, `flags` ulong (CKF_RW 0x2, CKF_SERIAL 0x4), `role`, `token*`.
- **`fhsm_op_t`** (`src/fhsm_pkcs11.c:1916-2043`), per-session operation state:
  - `active`, `mechanism` u32, `key_handle` u32
  - re-authentication: `ctx_auth_required`, `ctx_auth_done`
  - IV and GCM: `iv`, `gcm_iv`/`gcm_iv_len`, `gcm_aad*`, `gcm_tag_len`
  - PSS: `pss_saltlen` long, `pss_mgf`
  - PQ signing: `pq_ctx`/`pq_ctx_len`, `pq_ctx_toolong`, `pq_hedge`
- **`fhsm_create_attrs_t`** (`include/fhsm_create_attrs.h:~100-142`): `cko`, `ckk`, `path` enum, `label`, `id_data`/`id_len`, `value_data`/`value_len`, `pqc_alg`, `ec_group`, `ec_point`, RSA components, `cert_type`.
- **`fhsm_policy_attr_t`** (`include/fhsm_token.h:~390-398`): `type` u32, `kind` u8 (BOOL/ULONG/BYTES), `len` u8, `value[48]`.
- **`request_t`** (`service/fhsm_service.c:~1035-1057`): `method`, `target[256]`, `subject` with `have_subject`/`subject_repeated`, `key` with `have_key`/`key_repeated`, `siglen` long with flags, `content_length` long, `saw_transfer_encoding`, `body[65536]`, `body_len`.
- **`policy_rule_t`** (`service/fhsm_service.c:171-174`): `subject[FHSM_AUDIT_ACTOR_MAX]`, `key[64]`.
- **`budget_t`** (`service/fhsm_service.c:630-636`): `subject`, `count` unsigned, `last` time_t (monotonic), `used`, `announced`.
- **`fhsm_rev_entry_t`** (`include/fhsm_revocation.h:136-141`): `serial[64]` with `serial_len`, `date[16]` (YYYYMMDDHHMMSSZ), `reason` int (−1 means none).

### From the State & lifecycle lens

- **fhsm_module_state_t**: enum POWER_OFF=0, INITIALIZING=1, INITIALIZED=2, AUTHENTICATED=3, ERROR=4. `include/fhsm_common.h:244-250`. Globals `g_state` and `g_error_reason[128]` at `src/fhsm_state.c:33-35`.
- **fhsm_token_s**: `mu`; `path[512]`, `label[64]`, `serial[64]`; `salt_so[16]`, `salt_user[16]`; `pbkdf2_iter` u32; `so_wrap_nonce[12]`/`so_wrap_ct[48]`, `user_wrap_nonce[12]`/`user_wrap_ct[48]`; `user_initialized` int; `failed_so`/`failed_user` u32; `throttle_*_until_ms` u64; `dek` u8* (secure heap); `dek_live` int; `logged_in` fhsm_role_t; `objects[1024]`; `object_count`, `next_handle` u32; `objects_dirty`, `objects_loaded`, `objects_public` int. `src/fhsm_token.c:198-243`.
- **fhsm_object_t**: `handle`, `class`, `key_type`, `value_len` u32; `label[64]`; `value` u8* plus `value_secure`; `id[32]`/`id_len`; `flags`/`flags2`/`flags3` u8; `owner_session` u32 (0 = token object, in memory only); `usage_flags` u8; date and application fields; policy arrays (allowed mechs, wrap/unwrap/derive templates). `src/fhsm_token.c:128-196`.
- **fhsm_session_entry_t**: `in_use` int, `slot` ulong, `flags` ulong, `role` fhsm_role_t (cache), `token` ptr. `src/fhsm_session.c:37-43`. Table `g_sessions[128]`.
- **fhsm_op_t**: `active`, `key_handle`, `mechanism`, IV/GCM fields, `gcm_aad` (heap) and length, `md_ctx`/`mac_ctx`/`cipher_ctx`, PSS params, `ctx_auth_required`/`ctx_auth_done`, `mp_buf`/`mp_len`/`mp_cap`. `src/fhsm_pkcs11.c:1916-2043`. Tables `g_op_enc/dec/sig/dig/ver[128]` at :2066-2070.
- **fhsm_find_state_t**: `handles[1024]`, `count`, `next`, `active`. `src/fhsm_pkcs11.c:1907-1913`.
- **fhsm_slot_t**: `present` int, `path[512]`, `token` ptr. `src/fhsm_pkcs11.c:1014-1018`.
- **fhsm_retired_t**: `p`, `len`, `secure`, `next`. `src/fhsm_apilock.c:41-46`.
- **Audit globals**: `g_audit_fd`, `g_audit_key[32]`, `g_prev_hmac[32]`, `g_audit_seq`, `g_audit_path`, `g_sync_*`. `src/fhsm_audit.c` (before line 91).
- **policy_rule_t**: `subject[FHSM_AUDIT_ACTOR_MAX]`, `key[MAX_KEY_LABEL]`. `service/fhsm_service.c:171-174`.
- **budget_t**: `subject`, `count` unsigned, `last` time_t (monotonic, never persisted), `used`, `announced`. `service/fhsm_service.c:631-637`.
- **fhsm_rev_entry_t / fhsm_rev_db_t**: `serial[64]` + `serial_len`, `date[16]`, `reason` int; `crl_number` ull, `e*`, `n`, `cap`. `include/fhsm_revocation.h:136-148`.
- **On-disk token header**: 317 bytes, layout at `src/fhsm_token.c:290-313`, then a 16-byte blob header, the ciphertext, a 16-byte tag, and the public section (magic 0xF5B5B001).

