# Business Rules — pqHSM (FreeHSM 2.6.0)

*Generated 2026-10-30 by `/code-modernization:modernize-extract-rules pqHSM` (Method B: three business-rules-extractor agents — calculations, validations & eligibility, state & lifecycle — merged and verified by the orchestrator). System root: the repository root (no `legacy/` dir).*

**What a "business rule" is here.** pqHSM moves no money; its business is key custody. The rules are the security policy a relying party depends on: who may use a key and when, what the module refuses, how secrets are derived, stored and zeroized, what is audited, and what the HTTP service will sign. **P0 = guards key secrecy, access control, data integrity or a FIPS 140-3 requirement.**

**Scope.** Only code reachable in production (per `topology.json`). Verified-dead code — `src/dispatch/*`, the `src/gen/fhsm_dispatch.c` handlers, `src/fhsm_mode.c`, `kat/fhsm_kat_rsp.c`, `disabled/` — was excluded. Not covered in depth: the GTK GUI, `tools/cms_env.c`, RSA-PSS/OAEP/ECDH/EdDSA internals, TPM driver internals, and the full body of every multipart Update/Final path.

## How these rules were verified

- **Every citation machine-checked** (131 cards before merging): the file exists, the line range is inside the file, and the range contains executable code, not only comments. This proves the citation points at real code; it does not prove the code does what the card says. The result is on each card's **Verified:** line.
- **Reproduced against the built library** (pinned build container, OpenSSL 3.5.7): SEC-001 key use after logout; `C_SetPIN` never succeeding; no `CKR_CRYPTOKI_NOT_INITIALIZED` after `C_Finalize`; `C_CloseAllSessions(1)` refused.
- **Code-read by the orchestrator:** the pairwise-failure latch, the zero-DEK fallback, the integrity bypass.
- Everything else is the extractor agent's reading of the code — citation-checked, not re-derived.
- 22 cards found by more than one lens were merged into one canonical card; the merged card's sources and defect notes are kept under **Merged from**.

**Instruction-shaped content in source:** none. All three extractors grepped for directive patterns aimed at automated analysis; the only hits (`src/fhsm_crypto.c:318`, `src/fhsm_pkcs11.c:886`) are ordinary engineering comments.

**Credentials:** none appear in this file; PINs are described by length only.

## Summary

**109 rules** — 34 Calculation, 20 Validation, 15 Policy, 40 Lifecycle · 81 P0, 27 P1, 1 P2 · 3 need SME confirmation (Medium/Low) · 69 carry a suspected defect (index at the end).

| ID | Rule | Category | Priority | Source | Confidence |
|---|---|---|---|---|---|
| RULE-001 | Key-encryption key derived from a PIN | Calculation | P0 | `src/fhsm_token.c:1231-1252` (create), … | High |
| RULE-002 | DEK wrap under the KEK | Calculation | P0 | `src/fhsm_token.c:1225-1265`, `src/fhsm_token.c:1428-1446`, … | High |
| RULE-003 | Encrypted object-store blob | Calculation | P0 | `src/fhsm_token.c:1136-1212` (write), … | High |
| RULE-004 | Token header binary layout | Calculation | P0 | `src/fhsm_token.c:289-316`, `src/fhsm_token.c:1092-1128`, … | High |
| RULE-005 | PIN re-wrap (C_InitPIN, C_SetPIN, reinit) | Calculation | P0 | `src/fhsm_token.c:1714-1752`, `src/fhsm_token.c:1765-1810`, … | High |
| RULE-006 | PBKDF2 primitive bounds and CKM_PKCS5_PBKD2 | Calculation | P0 | `src/fhsm_crypto.c:544-608`, `include/fhsm_crypto.h:147`, … | High |
| RULE-007 | Audit chain head and record MAC | Calculation | P0 | `src/fhsm_audit.c:500-512`, `src/fhsm_audit.c:599-680`, … | High |
| RULE-008 | Offline audit verification | Calculation | P0 | `tools/freehsm_audit.c:224-286`, `tools/freehsm_audit.c:325-367` | High |
| RULE-009 | Module integrity digest | Calculation | P0 | `src/fhsm_integrity.c:50-51`, `src/fhsm_integrity.c:222-302`, … | High |
| RULE-010 | DRBG chunking, reseed interval, conditioning | Calculation | P0 | `src/fhsm_drbg.c:97-112`, `src/fhsm_drbg.c:241-289`, … | High |
| RULE-011 | Repetition Count Test | Calculation | P0 | `src/fhsm_drbg.c:84-93`, `src/fhsm_drbg.c:293-312` | High |
| RULE-012 | Adaptive Proportion Test | Calculation | P0 | `src/fhsm_drbg.c:89-95`, `src/fhsm_drbg.c:313-333` | Medium |
| RULE-013 | Continuous RNG test (CRNGT) | Calculation | P0 | `src/fhsm_drbg.c:338-351`, `src/fhsm_drbg.c:441-442` | High |
| RULE-014 | Secret-key generation lengths | Calculation | P0 | `src/fhsm_pkcs11.c:2875-2960` | High |
| RULE-015 | RSA key-pair generation | Calculation | P0 | `src/fhsm_pkcs11.c:6626-6646` | High |
| RULE-016 | EC curve acceptance | Calculation | P0 | `src/fhsm_pkcs11.c:6353-6386` | High |
| RULE-017 | PQC parameter sets | Calculation | P0 | `src/fhsm_pkcs11.c:6447-6500`, `src/fhsm_pkcs11.c:6711-6734`, … | High |
| RULE-018 | AES-GCM / GMAC / CCM parameters and output length | Calculation | P0 | `src/fhsm_pkcs11.c:9095-9156`, `src/fhsm_pkcs11.c:9574-9576`, … | High |
| RULE-019 | ECDSA raw ↔ DER conversion | Calculation | P0 | `src/fhsm_ecdsa_raw.c:24-65`, `src/fhsm_pkcs11.c:11288-11298`, … | High |
| RULE-020 | Derived-key output bounds | Calculation | P0 | `src/fhsm_pkcs11.c:4428-4456`, `src/fhsm_pkcs11.c:4269`, … | High |
| RULE-021 | Certificate serial and validity | Calculation | P0 | `src/fhsm_composite.c:1277-1306`, `src/fhsm_composite.c:938-948`, … | High |
| RULE-022 | CRL validity and number | Calculation | P0 | `src/fhsm_composite.c:1613`, `src/fhsm_composite.c:1639-1646`, … | High |
| RULE-023 | OCSP response times and status | Calculation | P0 | `src/fhsm_revocation.c:424`, `src/fhsm_revocation.c:436-499`, … | High |
| RULE-024 | Revocation database parsing | Calculation | P0 | `src/fhsm_revocation.c:75-107`, `src/fhsm_revocation.c:122-126`, … | High |
| RULE-025 | Composite ML-DSA-65 + Ed25519 signing | Calculation | P0 | `src/fhsm_composite.c:41-50`, `src/fhsm_composite.c:60-100`, … | High |
| RULE-026 | Throttle deadline re-derived at load | Calculation | P1 | `src/fhsm_token.c:1335-1346`, `src/fhsm_token.c:1114-1127` | High |
| RULE-027 | Audit parameter sanitisation | Calculation | P1 | `src/fhsm_audit.c:147-153`, `src/fhsm_audit.c:155-170`, … | High |
| RULE-028 | Advertised mechanism key-size table | Calculation | P1 | `src/fhsm_pkcs11.c:1599-1620`, `src/fhsm_pkcs11.c:1640-1653` | High |
| RULE-029 | AES ECB / CBC / CBC-PAD / CTR output length | Calculation | P1 | `src/fhsm_pkcs11.c:9972-10023`, `src/fhsm_pkcs11.c:10475-10520`, … | High |
| RULE-030 | AES key-wrap output length | Calculation | P1 | `src/fhsm_pkcs11.c:5067-5091` | High |
| RULE-031 | Signature length query | Calculation | P1 | `src/fhsm_pkcs11.c:11070-11108`, `src/fhsm_pkcs11.c:11436-11445` | High |
| RULE-032 | Per-identity concurrency cap | Calculation | P1 | `service/fhsm_service.c:425-433`, `service/fhsm_service.c:469-552` | High |
| RULE-033 | Refusal budget | Calculation | P1 | `service/fhsm_service.c:626-664`, `service/fhsm_service.c:733-807`, … | High |
| RULE-034 | Service request limits and option ranges | Calculation | P2 | `service/fhsm_service.c:138-143`, `service/fhsm_service.c:301`, … | High |
| RULE-035 | SO and read-only sessions are mutually exclusive | Validation | P0 | `src/fhsm_pkcs11.c:778-780`, `src/fhsm_session.c:131-138` | High |
| RULE-036 | PIN length and character rules | Validation | P0 | `src/fhsm_pkcs11.c:1687-1689`, `src/fhsm_pkcs11.c:1741-1743`, … | High |
| RULE-037 | Read-only session restrictions | Validation | P0 | `src/fhsm_pkcs11.c:2456-2465`, `src/fhsm_pkcs11.c:7724-7733`, … | High |
| RULE-038 | CKA_TRUSTED can only be set to TRUE by the SO | Validation | P0 | `src/fhsm_pkcs11.c:3194-3201`; called at 2853, 3570, 4303, 5196, … | High |
| RULE-039 | CKA_VALUE read refusal | Validation | P0 | `src/fhsm_pkcs11.c:7209-7243`, `src/fhsm_pkcs11.c:7629-7633` | High |
| RULE-040 | One-way flags and immutable attributes in C_SetAttributeValue | Validation | P0 | `src/fhsm_pkcs11.c:7700-7972` | High |
| RULE-041 | C_CopyObject rules | Validation | P0 | `src/fhsm_pkcs11.c:7995-8292` | Medium |
| RULE-042 | Key type vs mechanism | Validation | P0 | `src/fhsm_pkcs11.c:9642-9712`; `src/fhsm_pkcs11.c:5041`, … | High |
| RULE-043 | C_UnwrapKey rules | Validation | P0 | `src/fhsm_pkcs11.c:5174-5444` | High |
| RULE-044 | Token file load validation | Validation | P0 | `src/fhsm_token.c:1306-1355`, `src/fhsm_token.c:1058-1090` | High |
| RULE-045 | Creation-template structural checks | Validation | P1 | `src/fhsm_pkcs11.c:2247-2249`, `src/fhsm_pkcs11.c:2334-2347`, … | High |
| RULE-046 | C_CreateObject class, type and required attributes | Validation | P1 | `src/fhsm_create_attrs.c:324-432`, … | High |
| RULE-047 | KEM encapsulate/decapsulate permission | Validation | P1 | `src/fhsm_pkcs11.c:5462-5560`, `src/fhsm_pkcs11.c:5666-5760`, … | High |
| RULE-048 | C_DigestKey refuses sensitive keys | Validation | P1 | `src/fhsm_pkcs11.c:11998-12019` | High |
| RULE-049 | Symmetric mechanism parameters (IV, tag, nonce) | Validation | P1 | `src/fhsm_pkcs11.c:9095-9233`, `src/fhsm_pkcs11.c:9271-9346`, … | High |
| RULE-050 | RSA key generation, OAEP and PSS parameters | Validation | P1 | `src/fhsm_pkcs11.c:6625-6648`, `src/fhsm_pkcs11.c:8516-8629`, … | High |
| RULE-051 | PQ signature context and hedging parameters | Validation | P1 | `src/fhsm_pkcs11.c:9437-9458`, `src/fhsm_pkcs11.c:10845-10851` | High |
| RULE-052 | PBKDF2 and HKDF parameters | Validation | P1 | `src/fhsm_pkcs11.c:2778-2832`, `src/fhsm_pkcs11.c:4298-4360` | High |
| RULE-053 | HTTP request parsing limits and routes | Validation | P1 | `service/fhsm_service.c:138-143`, … | High |
| RULE-054 | OCSP request and responder rules | Validation | P1 | `service/fhsm_service.c:1881-1939`, … | High |
| RULE-055 | Private-object visibility is decided by object class | Policy | P0 | `src/fhsm_pkcs11.c:9010-9015`, `src/fhsm_pkcs11.c:7173-7174`, … | High |
| RULE-056 | Key-use Init paths only check that the handle exists (SEC-001) | Policy | P0 | `src/fhsm_pkcs11.c:9017-9024`, `src/fhsm_pkcs11.c:9761-9775`, … | High |
| RULE-057 | Login required for key-management operations | Policy | P0 | `src/fhsm_pkcs11.c:2860`, `src/fhsm_pkcs11.c:4317`, … | High |
| RULE-058 | Sensitivity and extractability defaults per creation path | Policy | P0 | `src/fhsm_pkcs11.c:2995-3008` (C_GenerateKey), … | High |
| RULE-059 | ALWAYS_SENSITIVE and NEVER_EXTRACTABLE come from current flags | Policy | P0 | `src/fhsm_pkcs11.c:7528-7535` | High |
| RULE-060 | Key-usage flags: defaults and enforcement | Policy | P0 | `src/fhsm_pkcs11.c:2401-2422`, … | High |
| RULE-061 | CKA_ALLOWED_MECHANISMS | Policy | P0 | `src/fhsm_pkcs11.c:3264-3275`, `src/fhsm_token.c:2328-2354` | High |
| RULE-062 | Nested WRAP / UNWRAP / DERIVE templates | Policy | P0 | `src/fhsm_pkcs11.c:3315-3373`, `src/fhsm_pkcs11.c:3393-3418`, … | High |
| RULE-063 | C_WrapKey eligibility (SEC-003) | Policy | P0 | `src/fhsm_pkcs11.c:4984-5030`, `src/fhsm_pkcs11.c:5039-5101` | High |
| RULE-064 | C_DeriveKey output class and sensitivity | Policy | P0 | `src/fhsm_pkcs11.c:4789-4860`, `src/fhsm_pkcs11.c:4489-4493` | Medium |
| RULE-065 | The NIST-approved-only build refuses non-approved mechanisms | Policy | P0 | `src/fhsm_pkcs11.c:9587-9600`, `src/fhsm_pkcs11.c:10830-10834`, … | High |
| RULE-066 | Object-store tag failure and zero-DEK fallback (SEC-002) | Policy | P0 | `src/fhsm_token.c:942-1019`, `src/fhsm_token.c:1527-1531` | High |
| RULE-067 | Peer-credential gate on both listeners | Policy | P0 | `service/fhsm_service.c:1522-1531`, `service/fhsm_service.c:1946-1953` | High |
| RULE-068 | Client identity, signing policy, refusal budget and in-flight cap | Policy | P0 | `service/fhsm_service.c:184-278`, … | High |
| RULE-069 | CSR proof-of-possession and issuance constraints | Policy | P0 | `src/fhsm_composite.c:1203-1240`, `src/fhsm_composite.c:1242-1421`, … | High |
| RULE-070 | Module state whitelist and the latched ERROR state | Lifecycle | P0 | `src/fhsm_state.c:40-47, 56-92, 119-143` | High |
| RULE-071 | C_Initialize sequence and double initialization | Lifecycle | P0 | `src/fhsm_pkcs11.c:393-532` | High |
| RULE-072 | No "not initialized" gate on any entry point | Lifecycle | P0 | `include/fhsm_common.h:198` (defined, … | High |
| RULE-073 | What the ERROR state refuses, and what it does not | Lifecycle | P0 | ERROR checks in `src/fhsm_pkcs11.c` (e.g. :576, :605, :636, :762, … | High |
| RULE-074 | Power-on self-tests and environment bypasses | Lifecycle | P0 | `src/fhsm_crypto.c:79-285`; `src/fhsm_integrity.c:380-406` | High |
| RULE-075 | A pairwise consistency failure does not latch ERROR | Lifecycle | P0 | `src/fhsm_pkcs11.c:6762-6787`; `src/fhsm_state.c:65-77` | High |
| RULE-076 | C_Finalize teardown and re-initialization | Lifecycle | P0 | `src/fhsm_pkcs11.c:534-547, … | High |
| RULE-077 | Fork handling | Lifecycle | P0 | `src/fhsm_pkcs11.c:398-402, … | High |
| RULE-078 | Deferred zeroization of object values freed under the shared lock | Lifecycle | P0 | `src/fhsm_apilock.c:98-170`; `src/fhsm_token.c:514-521` | High |
| RULE-079 | Creating a token on an empty slot | Lifecycle | P0 | `src/fhsm_pkcs11.c:1681-1731`; `src/fhsm_token.c:1214-1299` | High |
| RULE-080 | Re-initializing an existing token wipes it | Lifecycle | P0 | `src/fhsm_pkcs11.c:1697, … | High |
| RULE-081 | C_InitPIN sets the user PIN and unlocks the user | Lifecycle | P0 | `src/fhsm_pkcs11.c:1736-1756`; `src/fhsm_token.c:1714-1753` | High |
| RULE-082 | C_SetPIN cannot succeed | Lifecycle | P0 | `src/fhsm_pkcs11.c:1761-1789`; `src/fhsm_token.c:1765-1809, … | High |
| RULE-083 | Login state belongs to the token and has conflict rules | Lifecycle | P0 | `src/fhsm_pkcs11.c:890-972`; `src/fhsm_session.c:117-151`; `src/fhs, … | High |
| RULE-084 | PIN failure counter, throttle and lock | Lifecycle | P0 | `src/fhsm_token.c:256-281, 1393-1405, 1537-1546, 1340-1346, … | High |
| RULE-085 | Side effects of a successful login | Lifecycle | P0 | `src/fhsm_token.c:1417-1535, 942-1019` | High |
| RULE-086 | Logout zeroizes the DEK but leaves decrypted objects usable | Lifecycle | P0 | `src/fhsm_token.c:1645-1654, … | High |
| RULE-087 | Re-authentication for CKA_ALWAYS_AUTHENTICATE keys | Lifecycle | P0 | `src/fhsm_pkcs11.c:917-946, 2161-2206, 9056-9064` | High |
| RULE-088 | Token file persistence (save points) | Lifecycle | P0 | `src/fhsm_token.c:1092-1209, 591-593` | High |
| RULE-089 | TPM-sealed DEK companion file | Lifecycle | P0 | `src/fhsm_token_tpm.c:59-135`; `src/fhsm_token.c:1275-1285, 1455-1522` | High |
| RULE-090 | Closing sessions destroys session objects and logs out on the last one | Lifecycle | P0 | `src/fhsm_pkcs11.c:603-613, 793-813, … | High |
| RULE-091 | Object creation, handles and capacity | Lifecycle | P0 | `src/fhsm_token.c:1898-1943, … | High |
| RULE-092 | Object destruction | Lifecycle | P0 | `src/fhsm_pkcs11.c:4140-4165`; `src/fhsm_token.c:2658-2687` | High |
| RULE-093 | Audit key provisioning | Lifecycle | P0 | `src/fhsm_audit.c:199-367` | High |
| RULE-094 | One audit file per opening | Lifecycle | P0 | `src/fhsm_audit.c:427-525` | High |
| RULE-095 | The audit-off switch | Lifecycle | P0 | `src/fhsm_pkcs11.c:443-463`; `include/fhsm_common.h:366-368`; `src/, … | High |
| RULE-096 | Audit write failure | Lifecycle | P0 | `src/fhsm_audit.c:585-743`; every call site uses `(void)fhsm_audit_, … | High |
| RULE-097 | Service startup order and one-shot PIN login | Lifecycle | P0 | `service/fhsm_service.c:2557-2569, 2628, 2637-2665, 2669-2684, … | High |
| RULE-098 | Policy reload on SIGHUP keeps the old policy if the new one fails | Lifecycle | P0 | `service/fhsm_service.c:184-266, 953, 2184` | High |
| RULE-099 | Revocation is one-way, and duplicates are refused | Lifecycle | P0 | `src/fhsm_revocation.c:47-58, 165-269`; `tools/fhsm_ca.c:278-359` | High |
| RULE-100 | Database save, load and CRL numbering | Lifecycle | P0 | `src/fhsm_revocation.c:165-251`; `tools/fhsm_ca.c:395-413`; `servic, … | High |
| RULE-101 | Exclusive and shared entry modes | Lifecycle | P1 | `src/fhsm_apilock.c:118-145`; `include/fhsm_apilock.h:78-83`; lock , … | High |
| RULE-102 | Opening a session | Lifecycle | P1 | `src/fhsm_pkcs11.c:755-791`; `src/fhsm_session.c:48-65`; `include/f, … | High |
| RULE-103 | Session state is derived, not stored | Lifecycle | P1 | `src/fhsm_pkcs11.c:842-880`; `src/fhsm_session.c:244-267` | High |
| RULE-104 | Operation slots: Init, active, not initialized | Lifecycle | P1 | `src/fhsm_pkcs11.c:2066-2070, 9037-9050, 9577-9579, 2668-2700, … | High |
| RULE-105 | When an operation ends | Lifecycle | P1 | `src/fhsm_pkcs11.c:11313-11479` (C_Sign), … | High |
| RULE-106 | Multipart and AAD buffer caps | Lifecycle | P1 | `src/fhsm_pkcs11.c:2060, 8910-8969` | High |
| RULE-107 | The refusal budget survives restarts | Lifecycle | P1 | `service/fhsm_service.c:626-801, 685-717, 2628` | High |
| RULE-108 | Service shutdown | Lifecycle | P1 | `service/fhsm_service.c:941-953, 2163-2173, 2219-2220, 2301-2308, … | High |
| RULE-109 | Slot registry: presence and lazy token load | Lifecycle | P1 | `src/fhsm_pkcs11.c:1014-1081, 1723-1725` | High |

## Calculation rules

### RULE-001: Key-encryption key derived from a PIN
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_token.c:1231-1252` (create), `src/fhsm_token.c:1838-1865` (reinit), `src/fhsm_token.c:1325` (iteration count read from file), `src/fhsm_token.c:1417-1422` (login), `src/fhsm_crypto.c:544-608` (primitive)
**Plain English:** Each role's 32-byte KEK is PBKDF2-HMAC-SHA-256 over the PIN bytes, using that role's 16-byte random salt and the iteration count stored in the token header.
**Specification:**
  Given a new token is created (C_InitToken on an empty slot) or re-initialised
  When the SO PIN is turned into a KEK
  Then salt_so = 16 DRBG bytes, pbkdf2_iter = 200000, KEK = PBKDF2(SHA-256, PIN, salt_so, 200000, dkLen=32)
  And at every later login, verify, InitPIN or SetPIN the iteration count is the u32 LE at header offset 136, not the constant
**Parameters:** iterations 200000 (written at create/reinit only); salt 16 B per role (salt_so, salt_user); KEK 32 B; PRF HMAC-SHA-256; primitive floor 1000 (`fhsm_crypto.c:561`).
**Edge cases handled:** The KEK is zeroised after use. A PBKDF2 failure returns before the counters are touched. PIN bytes are taken as length-delimited at login (pin_len) and as strlen at set.
**Suspected defect:**
- The iteration count is read from the file with no lower bound other than the primitive's 1000. The header is not authenticated (only the serial is AAD). Anyone who can write the file can change offset 136. The legitimate PIN then fails to unwrap, and each attempt counts as a failure, so after 5 tries the role is permanently locked (see RULE-084).
- InitPIN and SetPIN re-wrap at whatever count is in the file.
- Comment/code conflict: `src/fhsm_crypto.c:542` says "minimum 200_000 iterations" and `include/fhsm_crypto.h:162` says "Minimum iteration count : 200_000". The code floor is 1000 (`fhsm_crypto.c:561`). The 200000 policy exists only in the two assignments `fhsm_token.c:1234,1840`.
**Confidence:** High — explicit code.
**Verified:** citations checked ✓ · extracted as CALC-01 (Calculations)

### RULE-002: DEK wrap under the KEK
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_token.c:1225-1265`, `src/fhsm_token.c:1428-1446`, `src/fhsm_crypto.c:380-420`, `src/fhsm_crypto.c:424-470`
**Plain English:** The 32-byte DEK is encrypted under each role's KEK with AES-256-GCM. The nonce is 12 random bytes, the AAD is the token serial string, and the output is 32-byte ciphertext plus a 16-byte tag.
**Specification:**
  Given serial = "FHSM-" + lowercase hex of 8 DRBG bytes (for example "FHSM-0123456789abcdef", 21 bytes) and a fresh 32-byte DRBG DEK
  When the DEK is wrapped for the SO
  Then so_wrap_nonce = 12 DRBG bytes and so_wrap_ct[0..31] ‖ so_wrap_ct[32..47] = AES-256-GCM(KEK, nonce, AAD = 21 serial bytes (no NUL), DEK)
  And unwrap succeeds only if the tag verifies and the plaintext length is exactly 32
**Parameters:** DEK_LEN 32; WRAP_LEN 48; nonce 12; tag 16; the wrapper refuses an IV ≠ 12 and a key ∉ {16, 24, 32}.
**Edge cases handled:** A tag failure zeroises the partial DEK (`fhsm_token.c:1536-1538`). With a TPM companion file, an unwrap that succeeds must also match the TPM-unsealed DEK. A mismatch gives CKR_DEVICE_ERROR and does not change the PIN counter (`1450-1505`).
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-02 (Calculations)

### RULE-003: Encrypted object-store blob
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_token.c:1136-1212` (write), `src/fhsm_token.c:943-1013` (read), `src/fhsm_token.c:475-476` (cap)
**Plain English:** On each write the serialised object store gets a fresh 12-byte nonce and is AES-256-GCM-encrypted under the DEK with AAD = serial. It is appended after the 317-byte header as `u32 ct_len ‖ nonce[12] ‖ ct ‖ tag[16]`, followed by a plaintext public-objects section.
**Specification:**
  Given a logged-in token with at least one object
  When any mutation persists the store
  Then the plaintext is the v4 serialisation, blob_nonce = 12 fresh DRBG bytes, and ct = GCM(DEK, blob_nonce, AAD = serial, pt), with ct_len = pt length
  And a section `u32 0xF5B5B001 ‖ u32 len ‖ public objects` is written in clear after the tag
  And on load, ct_len must be in 1..FHSM_OBJ_BLOB_MAX, otherwise CKR_FUNCTION_FAILED
**Parameters:** FHSM_OBJ_BLOB_MAX = 12 + 1024 × (4 + 912 + 2 097 152) = 2 148 421 644 B; FHSM_OBJ_REC_V4_FIXED = 912 (static assert, `:465`).
**Edge cases handled:**
- An empty store writes no blob.
- When the DEK is not live (wrong PIN, before login), the existing blob is copied byte for byte, not re-encrypted.
- If decryption under the real DEK fails, the code retries under a 32-byte all-zero DEK (`:986-1001`). This recovers stores damaged by a ≤2.5.0 bug, and the next write re-encrypts them under the real DEK.
**Suspected defect:**
1. FHSM_OBJ_BLOB_MAX exceeds INT_MAX by about 938 KB, and `fhsm_aes_gcm_decrypt` casts the length to `int` (`fhsm_crypto.c:454`). A maximal store would fail to decrypt.
2. The comment at `:468-473` still describes the v2 bound "12 + 64 × (4+120+16384)".
3. The public section is not covered by any MAC, so pre-login public-object answers can be tampered with.
4. The zero-key fallback is a permanent acceptance path. A blob forged under the all-zero key with the right serial decrypts after any successful login. The forger needs file write access, but no secret.

Rewrite must decide whether to keep this.
**Confidence:** High for the computation. SME question: "Must the zero-DEK recovery path survive the rewrite, and for how many releases?"
**Verified:** **Code-read** (assessment SEC-002): zero-DEK fallback at `src/fhsm_token.c:987-1003`. · citations checked ✓ · extracted as CALC-03 (Calculations)

### RULE-004: Token header binary layout
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_token.c:289-316`, `src/fhsm_token.c:1092-1128`, `src/fhsm_token.c:1306-1346`
**Plain English:** The token file starts with a fixed 317-byte little-endian header.

| Offset | Field |
|---|---|
| 0 | "FHSM" |
| 4 | version = 1 |
| 8 | label[64] |
| 72 | serial[64] |
| 136 | iter u32 |
| 140 | salt_so[16] |
| 156 | so_nonce[12] |
| 168 | so_ct[48] |
| 216 | salt_user[16] |
| 232 | user_nonce[12] |
| 244 | user_ct[48] |
| 292 | user_initialized u8 |
| 293 | failed_so u32 |
| 297 | failed_user u32 |
| 301 | u64 zeros |
| 309 | u64 zeros |

**Specification:**
  Given a token file whose first read returns fewer than 317 bytes, or wrong magic, or a version other than 1
  When it is loaded
  Then load fails with CKR_FUNCTION_FAILED
  And offsets 301 and 309 are always written as 0 and ignored on read
**Parameters:** FHSM_TOK_FILE_SZ 317; FHSM_TOK_VERSION 1.
**Edge cases handled:** The file is written atomically (tmp file, fsync, rename).
**Suspected defect:** Only the serial is bound into the GCM AAD. Label, iteration count, the failure counters and user_initialized can all be edited undetected. Setting failed_* to 0 resets lockout. Offline, PBKDF2 at 200k over a 4-digit PIN space (about 2×10⁹ HMACs) is brute-forceable in minutes once the file is stolen.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-04 (Calculations)

### RULE-005: PIN re-wrap (C_InitPIN, C_SetPIN, reinit)
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_token.c:1714-1752`, `src/fhsm_token.c:1765-1810`, `src/fhsm_token.c:1818-1893`, `src/fhsm_pkcs11.c:1763-1793`, `src/fhsm_session.c:237-238`
**Plain English:**
- InitPIN creates a fresh salt_user and nonce, and wraps the live DEK under PBKDF2(user PIN).
- SetPIN is meant to verify the old PIN and then re-wrap the same DEK under a fresh salt and nonce.
- Reinit generates a new serial, salt_so, DEK and nonce, resets iter to 200000, and empties the store.
**Specification:**
  Given a USER-logged-in session
  When C_SetPIN(old="<credential — masked, test fixture>", new=…) is called
  Then `fhsm_token_set_pin` calls `fhsm_token_login(t, role, old)`, which returns CKR_USER_ALREADY_LOGGED_IN (0x100) because t->logged_in == role
  And therefore C_SetPIN never changes a PIN
**Parameters:** New salt 16 B, new nonce 12 B, same pbkdf2_iter as the file.
**Edge cases handled:** Reinit wipes the old wraps and salts before regenerating them.
**Suspected defect:**
1. C_SetPIN appears unable to succeed. C_SetPIN requires a logged-in role (session role = token role), and the inner login refuses an already-logged-in role. No test exercises a successful C_SetPIN.
2. `include/fhsm_token.h:34-36` and `:140`, `src/fhsm_token.c:1756-1762` and `docs/EAL4_PLUS.md:20` say an SO C_SetPIN rotates the DEK. The code never regenerates the DEK in set_pin.
3. A reinit leaves salt_user zeroed and user_initialized = 0, which is correct.
**Confidence:** High for the code reading. SME question: "Should SO C_SetPIN rotate the DEK (and re-encrypt the store and user wrap), as the security target claims?"
**Verified:** citations checked ✓ · extracted as CALC-09 (Calculations)

### RULE-006: PBKDF2 primitive bounds and CKM_PKCS5_PBKD2
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_crypto.c:544-608`, `include/fhsm_crypto.h:147`, `src/fhsm_pkcs11.c:2795-2831`, `src/fhsm_pkcs11.c:2890-2913`
**Plain English:**
- PBKDF2 refuses fewer than 1000 iterations and outputs of 0 or more than 256 bytes.
- It accepts any salt length, including empty, because OpenSSL's SP 800-132 limits are relaxed with pkcs5 = 1.
- The PKCS#11 mechanism maps PRF codes 1, 3, 4, 5, 6, 7, 8 to SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256.
**Specification:**
  Given CKM_PKCS5_PBKD2 with iterations = 999
  When C_GenerateKey runs
  Then CKR_MECHANISM_PARAM_INVALID (mapped from FHSM_RV_FIPS_NOT_APPROVED)
  And CKA_VALUE_LEN must be present and in 1..256, otherwise CKR_TEMPLATE_INCOMPLETE or CKR_KEY_SIZE_RANGE
  And PRF code 2 (GOST) or any unknown code gives CKR_MECHANISM_PARAM_INVALID
**Parameters:** floor 1000; FHSM_PBKDF2_MAX_OUT 256; ulPrfDataLen ≤ 0x7FFFFFFF.
**Edge cases handled:** A NULL pointer with non-zero length is refused.
**Suspected defect:** `(uint32_t)p.iterations` at `fhsm_pkcs11.c:2829` narrows before the check. On LP64, iterations = 2^32 + 2000 runs 2000 iterations and returns CKR_OK. This is the same narrow-then-check pattern the code fixed for CKA_VALUE_LEN at `:2946-2955`.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-10 (Calculations)

### RULE-007: Audit chain head and record MAC
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_audit.c:500-512`, `src/fhsm_audit.c:599-680`, `src/fhsm_audit.c:691`
**Plain English:**
- Each JSON line is MACed with HMAC-SHA-256 under the audit key.
- The MAC input is the line text up to and including `"prev_hmac":"<hex>",`.
- The record's MAC becomes the next record's prev_hmac.
- The chain head is HMAC(key, "FHSM-AUDIT-INIT|seq=0").
**Specification:**
  Given a freshly opened log and a 32-byte key K
  When the first event is written
  Then prev_hmac = hex(HMAC-SHA256(K, "FHSM-AUDIT-INIT|seq=0")) (21 bytes, no NUL)
  And the line body is `{"seq":1,"ts":<ns>,"event":"…","slot":…,"session":…,"role":"SO|USER|NONE","actor":"…","result":"OK|FAIL","rv":<u32>,"params":{…},"prev_hmac":"<64 hex>",`
  And hmac = HMAC-SHA256(K, body), the line ends `"hmac":"<64 hex>"}\n`, and g_prev_hmac := hmac before the fdatasync
**Parameters:** HMAC-SHA-256; key 1..64 B accepted (provisioned 32 B, `:316`); line buffer 2048; ts = CLOCK_REALTIME ns.
**Edge cases handled:** Overflow of the line or suffix, an HMAC failure, a write failure or an fdatasync failure all latch the module into ERROR. Events before `audit_open` are silently dropped. Nested events are refused.
**Suspected defect:** `ts` is sampled before the mutex is taken (`:606-609`), so timestamps can run backwards relative to seq. This is minor.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-11 (Calculations)

### RULE-008: Offline audit verification
**Category:** Calculation
**Priority:** P0
**Source:** `tools/freehsm_audit.c:224-286`, `tools/freehsm_audit.c:325-367`
**Plain English:** For each line n (from 1) the verifier checks three things: HMAC(K, bytes before the first `"hmac":"`) equals the recorded hmac; prev_hmac equals the previous hmac (or the INIT head for line 1); seq = n. In directory mode, files are sorted by numeric suffix and must be contiguous.
**Specification:**
  Given a file whose line 3 was deleted
  When `freehsm-audit verify` runs
  Then the old line 4, now line 3, fails "prev_hmac does not follow" and "seq is not 3", and the exit code is 1
**Parameters:** key exactly 64 hex characters (32 B); LINE_MAX_LEN 4096; directory cap 4096 files.
**Edge cases handled:** Constant-time comparisons.
**Suspected defect:** The module accepts audit keys of 1–64 B (`fhsm_audit.c:457-458`), but the verifier hard-codes 32. Lines longer than 4095 B would be split by fgets; the module caps lines at 2048, so this cannot happen today.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-13 (Calculations)

### RULE-009: Module integrity digest
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_integrity.c:50-51`, `src/fhsm_integrity.c:222-302`, `src/fhsm_integrity.c:344-376`, `include/fhsm_integrity.h:89-92`, `scripts/sign_module.sh:85-91`
**Plain English:** The expected value is a plain SHA-384 (not an HMAC) of the entire on-disk module file, with every byte of the `.fhsm_digest` section zeroed. It is compared in constant time with the 48 bytes embedded in that section.
**Specification:**
  Given libfreehsm.so with .fhsm_digest at file offset X and size 48
  When the power-on integrity test runs
  Then D = SHA-384(file with bytes [X, X+48) set to 0), and the test passes only if D == embedded digest
  And an all-zero embedded digest ("unsigned") or a mismatch returns FHSM_RV_INTEGRITY_FAILED
**Parameters:** FHSM_INTEGRITY_DIGEST_LEN 48; section name ".fhsm_digest"; ELF64 section-table parse with bounds checks.
**Edge cases handled:** A missing section, or one shorter than 48 B, fails. A section that runs past the end of the file is refused.
**Suspected defect / conflict:**
1. Setting `FHSM_INTEGRITY_ALLOW_UNSIGNED` turns all three failure modes (missing section, unsigned, mismatch) into OK (`:267, :347, :364, :394`). The mismatch message says it "deliberately does NOT offer the bypass", but the code honours it.
2. The runtime zeroes the whole section (sh_size), while the signing script zeroes only DIGEST_LEN bytes. If the section were ever padded past 48 B they would disagree.
3. Header comments in `scripts/sign_module.sh:12-18` still say SHA-256 with a 32-byte slot; the code uses SHA-384 with 48 bytes.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-15 (Calculations)

### RULE-010: DRBG chunking, reseed interval, conditioning
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_drbg.c:97-112`, `src/fhsm_drbg.c:241-289`, `src/fhsm_drbg.c:372-463`
**Plain English:**
- Output is produced in chunks of at most 65536 bytes.
- Before each chunk, the code reseeds if more than 1 MiB has been emitted since the last reseed, or more than 3600 s of wall-clock time has passed.
- Reseed means: concatenate up to 512 B from getrandom, RDRAND, /dev/urandom and TSC jitter, hash them with SHA-384, and feed the 48-byte result into RAND_add with entropy estimate 0.
**Specification:**
  Given 1 048 576 bytes emitted since the last reseed
  When a request for 100 000 bytes arrives
  Then chunk 1 (65 536 B) is produced without reseed (1 048 576 is not > 1 MiB), then chunk 2 (34 464 B) triggers a reseed first
  And the maximum output between reseeds is 1 MiB + 64 KiB
**Parameters:** FHSM_DRBG_MAX_REQUEST 65536; FHSM_RESEED_BYTES_MAX 1 048 576; FHSM_RESEED_SECS_MAX 3600 (time(), wall clock); conditioner SHA2-384; pool 512 B.
**Edge cases handled:** n = 0 or out = NULL gives ARGUMENTS_BAD. A RAND_bytes failure latches ERROR. A health failure cleanses all output produced so far.
**Suspected defect:**
1. A reseed failure is ignored ("best effort", `:431`). g_last_reseed_t is then not updated, so a reseed is attempted before every chunk.
2. The interval uses wall-clock time() and is subject to `date -s`.
3. `docs/RNG.md:25,89` says SHA-256 conditioning; the code uses SHA-384.
4. RAND_add with entropy 0 is additional input, not a true reseed of OpenSSL's DRBG.
**Confidence:** High. SME question: "Must a failed reseed latch ERROR or refuse output?"
**Verified:** citations checked ✓ · extracted as CALC-16 (Calculations)

### RULE-011: Repetition Count Test
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_drbg.c:84-93`, `src/fhsm_drbg.c:293-312`
**Plain English:** If the same byte value appears 6 times in a row in DRBG output, the module latches ERROR. Run state carries across calls.
**Specification:**
  Given the previous call ended with 3 × 0x41
  When the next chunk starts with 3 × 0x41
  Then the run reaches 6, the "DRBG RCT alarm" latches ERROR, and FHSM_RV_RNG_FAILURE is returned
**Parameters:** FHSM_RCT_CUTOFF 6 (C = 1 + ⌈40/8⌉; α = 2^-40, H = 8).
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-17 (Calculations)

### RULE-012: Adaptive Proportion Test
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_drbg.c:89-95`, `src/fhsm_drbg.c:313-333`
**Plain English:** In each 512-byte window, count occurrences of the window's first byte. A 52nd occurrence (count > 51) latches ERROR.
**Specification:**
  Given a window whose first byte is 0x00
  When 0x00 occurs 52 times within those 512 samples
  Then "DRBG APT alarm" latches ERROR
**Parameters:** FHSM_APT_WINDOW 512; FHSM_APT_CUTOFF 51; the comparison is `>`, so it fails at 52.
**Suspected defect:** Checked against SP 800-90B §4.4.2 and Table 2 (pp. 26–27) on 2026-11-02. C = 1 + CRITBINOM(W, 2^-H, 1−α), B starts at 1, and the test fails when B ≥ C. For H = 8 and W = 512, Table 2 (α = 2^-20) gives C = 13; at the code's stated α = 2^-40 the formula gives C = 19. The code fails at B > 51, an effective C of 52. That fits a source of about 4–5 bits per byte at α = 2^-40, not 8. Nothing in the standard gives 51; the comment cites an "Appendix C". (An earlier version of this card said "about 13" at α = 2^-40; 13 is the α = 2^-20 value.)
**Confidence:** Medium. SME question: "Confirm the APT cutoff for H = 8, W = 512 per SP 800-90B Table 2, and whether the comparison is ≥ or >."
**Verified:** citations checked ✓ · extracted as CALC-18 (Calculations)

### RULE-013: Continuous RNG test (CRNGT)
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_drbg.c:338-351`, `src/fhsm_drbg.c:441-442`
**Plain English:** The first 16 bytes of each chunk are compared with the first 16 bytes of the previous chunk. Equality latches ERROR. Chunks shorter than 16 bytes skip the test.
**Specification:**
  Given the previous chunk began with block B
  When the next chunk (≥ 16 B) also begins with B
  Then "DRBG CRNGT repeated block" latches ERROR
**Parameters:** FHSM_CRNGT_BLOCK_SZ 16.
**Suspected defect:** Coverage is one block per chunk. `src/fhsm_crypto.c:315-320` and `docs/FIPS_140_3.md:157` describe every new 16-byte block being compared. Requests under 16 B are never tested.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-19 (Calculations)

### RULE-014: Secret-key generation lengths
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:2875-2960`
**Plain English:** C_GenerateKey takes the key length from CKA_VALUE_LEN, which is required except for DES3.

| Mechanism | Allowed length |
|---|---|
| AES | 16, 24 or 32 |
| GENERIC_SECRET | 1–64 |
| HKDF_KEY_GEN | 1–256 |
| PKCS5_PBKD2 | 1–256 |
| DES3 | exactly 24 (all-mechanisms build only) |

**Specification:**
  Given CKM_AES_KEY_GEN with CKA_VALUE_LEN = 20
  When C_GenerateKey runs
  Then CKR_KEY_SIZE_RANGE
  And CKA_VALUE_LEN = 0x1_0000_0010 is checked as a whole CK_ULONG, giving KEY_SIZE_RANGE, not truncated to 16
**Parameters:** GENERIC 1..64 (from the advertised table); FHSM_PBKDF2_MAX_OUT 256.
**Edge cases handled:** An attribute length other than sizeof(CK_ULONG) gives ATTRIBUTE_VALUE_INVALID. An absent CKA_VALUE_LEN gives ATTRIBUTE_VALUE_INVALID for AES/GENERIC/HKDF and TEMPLATE_INCOMPLETE for PBKD2.
**Suspected defect:** GENERIC_SECRET keys of 1–13 bytes (under 112 bits) are generated in the FIPS-only build. SP 800-131A / SP 800-107 require at least 112 bits for HMAC keys.
**Confidence:** High. SME question: "Should the FIPS profile enforce GENERIC ≥ 14 bytes?"
**Verified:** citations checked ✓ · extracted as CALC-20 (Calculations)
**Merged from VAL-42** (Validations & eligibility: "Secret-key generation sizes") — Source: `src/fhsm_pkcs11.c:2890-2980`, `src/fhsm_pkcs11.c:1602-1620`.

### RULE-015: RSA key-pair generation
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:6626-6646`
**Plain English:** The modulus must be exactly 2048, 3072 or 4096 bits (default 2048). A supplied public exponent must be odd and greater than 1. Generation always uses e = 65537.
**Specification:**
  Given CKA_MODULUS_BITS = 3072 and CKA_PUBLIC_EXPONENT = 0x03
  When C_GenerateKeyPair runs
  Then the exponent passes validation, but the key is generated with e = 65537 and CKR_OK is returned
  And CKA_MODULUS_BITS = 1024 gives CKR_KEY_SIZE_RANGE, and e = 4 gives CKR_ATTRIBUTE_VALUE_INVALID
**Parameters:** allowed sizes {2048, 3072, 4096}; default 2048; generated e = 65537.
**Suspected defect:** The requested exponent is silently overridden, the same "answers done to a request it did not carry out" pattern the code removed for 3DES. FIPS 186-5 requires 2^16 < e < 2^256, so e = 3 should be refused rather than accepted.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-22 (Calculations)

### RULE-016: EC curve acceptance
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:6353-6386`
**Plain English:** A curve is accepted only if it is a prime-field curve with group degree between 256 and 521 bits, and is not SM2.
**Specification:**
  Given CKA_EC_PARAMS naming brainpoolP224r1
  When a key is generated or imported
  Then the curve is refused (degree 224 < 256)
  And brainpoolP256r1, P-256, P-384 and P-521 are accepted, and secp112r1, sect571k1 and SM2 are refused
**Parameters:** degree 256..521; field type NID_X9_62_prime_field.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-23 (Calculations)

### RULE-017: PQC parameter sets
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:6447-6500`, `src/fhsm_pkcs11.c:6711-6734`, `src/fhsm_pkcs11.c:3546-3558`, `src/fhsm_pkcs11.c:5739-5741`, `src/fhsm_pkcs11.c:5784-5793`, `src/fhsm_pq_params.c` (context ≤ 255), `src/fhsm_pkcs11.c:6096-6106`
**Plain English:**
- Defaults: ML-KEM-768, ML-DSA-65, SLH-DSA-SHA2-128s.
- CKA_PARAMETER_SET is either a CK_ULONG selector or an ASCII name.
- Selectors: ML-KEM 1–3 = 512/768/1024; ML-DSA 1–3 = 44/65/87; SLH-DSA 1–12 in the order SHA2-128s, SHAKE-128s, SHA2-128f, SHAKE-128f, then the same four for 192 and for 256.
- Imported private-key length implies the set: 1632/2400/3168 → ML-KEM-512/768/1024; 2560/4032/4896 → ML-DSA-44/65/87.
- Decapsulation ciphertext must be 768/1088/1568 bytes.
- The ML-DSA/SLH-DSA context is at most 255 bytes.
**Specification:**
  Given an ML-KEM-1024 private key
  When C_DecapsulateKey receives a 1088-byte ciphertext
  Then CKR_ENCRYPTED_DATA_LEN_RANGE
  And selector 0 or ≥ table size gives CKR_ATTRIBUTE_VALUE_INVALID
**Parameters:** as above.
**Suspected defect:** The string form is validated against the union of all 18 names (`fhsm_pset_valid`), not the family. CKM_ML_KEM_KEY_PAIR_GEN with CKA_PARAMETER_SET = "ML-DSA-65" would generate an ML-DSA key stored as CKK_ML_KEM.
**Confidence:** High for the code. SME question: "Confirm the CKP_SLH_DSA_* ordering against PKCS#11 v3.2 headers."
**Verified:** citations checked ✓ · extracted as CALC-24 (Calculations)
**Merged from VAL-22** (Validations & eligibility: "PQ parameter set required and consistent") — Source: `src/fhsm_pkcs11.c:3630-3634`, `src/fhsm_pkcs11.c:3738-3753`, `src/fhsm_pkcs11.c:6447-6503`, `src/fhsm_pkcs11.c:3547-3557`. Suspected defect: A set given as a string is checked against all 18 names regardless of family. For example, C_GenerateKeyPair(CKM_ML_KEM_KEY_PAIR_GEN, set "ML-DSA-65") would generate an ML-DSA key and store it as CKK_ML_KEM. SLH-DSA import has the same issue.

### RULE-018: AES-GCM / GMAC / CCM parameters and output length
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:9095-9156`, `src/fhsm_pkcs11.c:9574-9576`, `src/fhsm_pkcs11.c:9330-9345`, `src/fhsm_pkcs11.c:8910`, `src/fhsm_pkcs11.c:1942`, `src/fhsm_pkcs11.c:10119-10154`, `src/fhsm_pkcs11.c:10618-10625`, `src/fhsm_pkcs11.c:12208-12215`
**Plain English:**
- GCM encrypt output = plaintext length + tag bytes.
- ulTagBits must be a multiple of 8 and at most 128; 0 means 128.
- The IV must be 12–512 bytes. AAD is at most 1 MiB.
- Decrypt plaintext = ciphertext length − tag.
- CCM nonce is 7–13 bytes and the MAC is 4–16 bytes, even only.
- A 12-byte raw parameter is accepted as a legacy form: IV only, tag 16.
**Specification:**
  Given CK_GCM_PARAMS{ivLen 12, aadLen 20, tagBits 96} and 100 bytes of plaintext
  When C_Encrypt(pEnc = NULL) is called
  Then *pulEncLen = 112, and the real call returns ciphertext ‖ 12-byte tag
  And an 8-byte IV gives CKR_MECHANISM_PARAM_INVALID at Init
  And GCM decrypt of 10 bytes with a 16-byte tag gives CKR_ENCRYPTED_DATA_INVALID
**Parameters:** FHSM_AAD_MAX 1 048 576; IV max 512; default tag 16; CCM tags {4, 6, 8, 10, 12, 14, 16}.
**Suspected defect:** Tag lengths of 8–88 bits are accepted in the FIPS build. SP 800-38D permits 128/120/112/104/96, and 64/32 only under restrictions. The IV is always caller-supplied for GCM encryption (no module-generated-IV path), which is a FIPS IG C.H concern.
**Confidence:** High. SME question: "Restrict ulTagBits to {96..128 step 8} (plus 32/64?) in the FIPS profile?"
**Verified:** citations checked ✓ · extracted as CALC-25 (Calculations)

### RULE-019: ECDSA raw ↔ DER conversion
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_ecdsa_raw.c:24-65`, `src/fhsm_pkcs11.c:11288-11298`, `src/fhsm_pkcs11.c:11798-11812`
**Plain English:**
- Signing: OpenSSL's DER signature is converted to r and s, each left-padded with zeros to nlen = ⌈bits/8⌉, then concatenated.
- Verifying: input must be exactly 2·nlen bytes and is re-encoded as DER.
**Specification:**
  Given a P-256 signature with r of 31 significant bytes
  When it is converted to raw
  Then the output is 64 bytes with r occupying bytes 1..31 and byte 0 = 0x00
  And on verify, a 63-byte signature gives CKR_SIGNATURE_INVALID
**Parameters:** raw buffer 132 (P-521).
**Edge cases handled:** r or s longer than nlen gives failure. Malformed DER gives failure.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-29 (Calculations)

### RULE-020: Derived-key output bounds
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:4428-4456`, `src/fhsm_pkcs11.c:4269`, `src/fhsm_pkcs11.c:4558-4561`, `src/fhsm_pkcs11.c:5604-5629`
**Plain English:**
- HKDF output must be 1..255·HashLen when expanding, or exactly up to HashLen for extract-only.
- Concatenation/XOR derivations must produce 1..4096 bytes.
- An ML-KEM shared secret (32 B) is truncated to CKA_VALUE_LEN (1..32).
**Specification:**
  Given HKDF-SHA-256 with bExpand and CKA_VALUE_LEN = 8161
  When C_DeriveKey runs
  Then CKR_ATTRIBUTE_VALUE_INVALID (max 8160)
  And an ML-KEM decapsulation with CKA_VALUE_LEN = 16 and CKA_KEY_TYPE = CKK_AES stores the first 16 bytes of the secret
**Parameters:** FHSM_DERIVE_MAX 4096; 255 × HashLen; ss_len 32.
**Suspected defect:** ML-KEM truncation checks only 1..ss_len, not the length against the key type. CKK_AES with 5 bytes is stored.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-31 (Calculations)

### RULE-021: Certificate serial and validity
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_composite.c:1277-1306`, `src/fhsm_composite.c:938-948`, `include/fhsm_pki.h:46`, `tools/fhsm_ca.c:171`, `tools/fhsm_ca.c:191`, `tools/fhsm_ca.c:218-226`
**Plain English:**
- Issued serial = 20 RNG bytes with the top bit cleared; a zero first byte becomes 1.
- notBefore = now − 3600 s; notAfter = now + days × 86400 s.
- Defaults: 365 days for end-entity, 30 for the OCSP-responder profile, with a warning if more than 90.
- Self-signed certificates take an explicit serial, which must be > 0.
**Specification:**
  Given `fhsm-ca issue --days 10` at 2026-10-30T12:00:00Z
  When the certificate is built
  Then notBefore = 2026-10-30T11:00:00Z and notAfter = 2026-11-09T12:00:00Z
**Parameters:** FHSM_PKI_BACKDATE_SECONDS 3600; serial 20 B; days > 0.
**Suspected defect:** notAfter is not clamped to the CA certificate's notAfter. `--days` is parsed with atoi, so no range check beyond > 0.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-33 (Calculations)

### RULE-022: CRL validity and number
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_composite.c:1613`, `src/fhsm_composite.c:1639-1646`, `tools/fhsm_ca.c:367`, `tools/fhsm_ca.c:386`, `tools/fhsm_ca.c:398-413`
**Plain English:** thisUpdate = now and nextUpdate = now + days × 86400, default 30 days. crlNumber = stored value + 1. The CRL is signed, then the database is saved, then the CRL is written out. revokedCertificates is omitted when empty.
**Specification:**
  Given a database with crlNumber 41
  When `fhsm-ca crl` succeeds
  Then the CRL carries number 42 and the database now says 42
**Suspected defect:** The comment at `:398-402` says that if signing fails "a number has been consumed". In code, a signing failure exits before db_save, so the number is not consumed. This is harmless but the comment is wrong. thisUpdate is not backdated, unlike certificates.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-34 (Calculations)

### RULE-023: OCSP response times and status
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_revocation.c:424`, `src/fhsm_revocation.c:436-499`, `src/fhsm_revocation.c:505-529`, `service/fhsm_service.c:877`, `service/fhsm_service.c:2456-2458`, `tools/fhsm_ca.c:451`
**Plain English:**
- producedAt = thisUpdate = now and nextUpdate = now + days × 86400, all as GeneralizedTime.
- days defaults to 7 and must be 1..365 in the service.
- Status: unknown if the issuer hash does not match this CA; revoked (with time and reason) if the serial is in the database; otherwise good.
- The request nonce is echoed when present.
**Specification:**
  Given --ocsp-days 7 and a request for serial 0x0A that is not in the database, issued by this CA
  When /ocsp answers
  Then status = good, thisUpdate = now, nextUpdate = now + 604 800 s
**Suspected defect:** "good" is returned for any serial not listed, including serials never issued. There is no clock-skew backdate on thisUpdate.
**Confidence:** High. SME question: "Should unissued serials answer unknown, which needs an issuance database?"
**Verified:** citations checked ✓ · extracted as CALC-35 (Calculations)

### RULE-024: Revocation database parsing
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_revocation.c:75-107`, `src/fhsm_revocation.c:122-126`, `src/fhsm_revocation.c:146-158`, `src/fhsm_revocation.c:165-216`
**Plain English:**
- Lines are `SERIALHEX DATE [REASON|-]` plus one optional `crlNumber N`.
- DATE must be 14 digits followed by Z.
- Serials compare equal after stripping leading zero bytes.
- At most 100 000 entries; any bad line rejects the whole file.
**Specification:**
  Given entries 00A1 and A1
  When serials are compared
  Then they are equal
  And "20261340990000Z" (month 13, hour 99) is accepted and normalised by timegm to a different instant
**Parameters:** FHSM_REV_MAX_ENTRIES 100000; serial hex even-length.
**Suspected defect:** There is no range check on month, day, hour, minute or second.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-36 (Calculations)
**Merged from VAL-51** (Validations & eligibility: "Revocation DB format") — Source: `src/fhsm_revocation.c:47-126`, `src/fhsm_revocation.c:165-221`.

### RULE-025: Composite ML-DSA-65 + Ed25519 signing
**Category:** Calculation
**Priority:** P0
**Source:** `src/fhsm_composite.c:41-50`, `src/fhsm_composite.c:60-100`, `src/fhsm_composite.c:189-226`, `src/fhsm_composite.c:330-380`, `include/fhsm_composite.h:39-44`
**Plain English:**
- M′ = "CompositeAlgorithmSignatures2025" (32 B) ‖ "COMPSIG-MLDSA65-Ed25519-SHA512" (30 B) ‖ len(ctx) (1 B) ‖ ctx ‖ SHA-512(M) (64 B).
- The signature is ML-DSA-65(M′, ctx = Label) (3309 B) followed by Ed25519(M′) (64 B).
- The private blob is "FCMP" ‖ ver 1 ‖ alg ‖ u16le len ‖ pq ‖ u16le len ‖ trad.
**Specification:**
  Given an empty ctx
  When a message is signed
  Then |M′| = 127 and |sig| = 3373; verification rejects any length other than 3373
  And ctx > 255 gives CKR_DATA_LEN_RANGE
**Parameters:** OID 1.3.6.1.5.5.7.6.48; CTX_MAX 255; SIG_MAX 4096.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-37 (Calculations)

### RULE-026: Throttle deadline re-derived at load
**Category:** Calculation
**Priority:** P1
**Source:** `src/fhsm_token.c:1335-1346`, `src/fhsm_token.c:1114-1127`
**Plain English:** On load, a role's throttle deadline is recomputed as now_monotonic + delay(failed_count). It is never read from the file.
**Specification:**
  Given a token file with failed_user = 2
  When a fresh process loads it
  Then throttle_user_until = now + 1000 ms, so a correct PIN entered 10 ms later waits about 990 ms first
**Parameters:** as RULE-084.
**Edge cases handled:** Avoids monotonic-clock deadlines surviving a reboot.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-08 (Calculations)

### RULE-027: Audit parameter sanitisation
**Category:** Calculation
**Priority:** P1
**Source:** `src/fhsm_audit.c:147-153`, `src/fhsm_audit.c:155-170`, `src/fhsm_audit.c:614-641`
**Plain English:** Parameter keys and values, and the actor, must be printable ASCII 0x20–0x7E with no `"` or `\`. A failing value is replaced by "INVALID". If the params object would exceed 1024 B it collapses to `{}`.
**Specification:**
  Given a parameter value containing a double quote
  When the event is logged
  Then the value is written as "INVALID"
  And if the params would overflow 1024 bytes, `"params":{}` is written and no error is raised
**Parameters:** params buffer 1024; FHSM_AUDIT_ACTOR_MAX 128.
**Suspected defect:** Silent loss of evidence on truncation.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-14 (Calculations)

### RULE-028: Advertised mechanism key-size table
**Category:** Calculation
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:1599-1620`, `src/fhsm_pkcs11.c:1640-1653`
**Plain English:** C_GetMechanismInfo reports min/max key sizes by family:

| Family | Min | Max |
|---|---|---|
| AES | 16 | 32 |
| TDES | 24 | 24 |
| DES | 8 | 8 |
| RSA | 2048 | 4096 |
| EC / EdDSA / ECM | 256 | 521 |
| HMAC / KMAC / GENERIC | 1 | 64 |
| anything else (PQC included) | 0 | 0 |

**Specification:**
  Given CKM_RSA_PKCS_KEY_PAIR_GEN
  When C_GetMechanismInfo runs
  Then ulMinKeySize = 2048 and ulMaxKeySize = 4096
**Parameters:** FHSM_EC_MIN_BITS 256; FHSM_EC_MAX_BITS 521.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-21 (Calculations)

### RULE-029: AES ECB / CBC / CBC-PAD / CTR output length
**Category:** Calculation
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:9972-10023`, `src/fhsm_pkcs11.c:10475-10520`, `src/fhsm_pkcs11.c:9571-9573`, `src/fhsm_pkcs11.c:9195-9222`
**Plain English:**
- Encrypt size query returns data length + 16 for CBC-PAD and data length otherwise. The actual call returns the true length.
- Decrypt size query returns the ciphertext length.
- CBC and CBC-PAD need a 16-byte IV. CTR takes a raw 16-byte block or CK_AES_CTR_PARAMS with ulCounterBits in 1..128.
**Specification:**
  Given CBC-PAD and 30 bytes of plaintext
  When C_Encrypt(pEnc = NULL) is called
  Then 46 is reported, and the real call returns 32 bytes
  And CBC (no pad) with 30 bytes fails in EncryptFinal and returns CKR_FUNCTION_FAILED, not CKR_DATA_LEN_RANGE
**Edge cases handled:** Bad padding on decrypt gives CKR_ENCRYPTED_DATA_INVALID.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-26 (Calculations)

### RULE-030: AES key-wrap output length
**Category:** Calculation
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:5067-5091`
**Plain English:** KW (RFC 3394) needs input that is a multiple of 8 and at least 16 bytes, and outputs input + 8. KWP (RFC 5649) needs at least 1 byte and outputs roundup8(input) + 8.
**Specification:**
  Given a 20-byte key wrapped with KWP
  When the size is queried
  Then 32 (24 + 8)
  And KW of a 20-byte key gives CKR_KEY_SIZE_RANGE, while KW of a 24-byte key gives 32
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-27 (Calculations)

### RULE-031: Signature length query
**Category:** Calculation
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:11070-11108`, `src/fhsm_pkcs11.c:11436-11445`
**Plain English:** With pSignature = NULL the query returns the exact length: 2 × ⌈order_bits/8⌉ for ECDSA (raw r‖s), and EVP_PKEY_get_size otherwise. If the key cannot be read it falls back to a family bound: SLH-DSA 65536, ML-DSA 8192, other 512.
**Specification:**
  Given a P-521 ECDSA key
  When C_Sign(pSignature = NULL) is called
  Then 132 (2 × 66). RSA-2048 gives 256, P-256 gives 64, P-384 gives 96
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-28 (Calculations)

### RULE-032: Per-identity concurrency cap
**Category:** Calculation
**Priority:** P1
**Source:** `service/fhsm_service.c:425-433`, `service/fhsm_service.c:469-552`
**Plain English:**
- An identity may have at most W requests in flight (W = --workers). If any other identity is present, the limit drops to W − 1, as long as W > 1.
- "Present" means a request in flight or a request served within the last 30 s.
- A brand-new identity is never refused.
- The first refusal in a burst is logged. The burst closes once 5 s pass with no refusal.
**Specification:**
  Given workers = 4, identity A with 3 in flight, and identity B served 10 s ago
  When A sends another request
  Then 429 "too_many_in_flight" with Retry-After: 1
**Parameters:** IDENT_WINDOW_S 30; BURST_COOLDOWN_S 5; IDENT_MAX 128.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-38 (Calculations)

### RULE-033: Refusal budget
**Category:** Calculation
**Priority:** P1
**Source:** `service/fhsm_service.c:626-664`, `service/fhsm_service.c:733-807`, `service/fhsm_service.c:1545-1554`, `service/fhsm_service.c:1665-1684`, `service/fhsm_service.c:1715-1718`
**Plain English:**
- Only "not_authorised" refusals count.
- Effective count n = count − ⌊quiet seconds / 600⌋, floored at 0.
- Delay is 0 when n ≤ 4, otherwise min(2^(n−5), 60) s.
- A request is refused with 429 while (now − last refusal) < delay, and Retry-After = delay − elapsed.
- The count is persisted to `<dir>/budget` once past 4.
**Specification:**
  Given count = 8 with the last refusal 2 s ago
  When the identity retries
  Then delay = 8 s and the response is 429 with Retry-After: 6
  And with count 7 and 1300 s of quiet, n = 5, delay = 1 s, and the request is admitted
**Parameters:** BUDGET_FREE 4; BUDGET_DECAY_S 600; BUDGET_CAP_S 60; BUDGET_MAX 256.
**Edge cases handled:** Budget refusals do not update `last`. On restart the decay clock restarts from the load time.
**Suspected defect:** If all 256 slots hold non-decayed identities, a new identity is not charged at all (fail-open, `:779`).
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-39 (Calculations)

### RULE-034: Service request limits and option ranges
**Category:** Calculation
**Priority:** P2
**Source:** `service/fhsm_service.c:138-143`, `service/fhsm_service.c:301`, `service/fhsm_service.c:2412-2458`
**Plain English:**

| Item | Limit |
|---|---|
| Headers | ≤ 8192 B in total |
| Request line | ≤ 1024 B |
| Header count | ≤ 32 |
| Target | ≤ 256 B |
| Body | ≤ 65536 B |
| --workers | 1..256 (default 4) |
| --pool-max | 1..127 (default 32) |
| --public-workers | 1..256 (default 2) |
| --queue-depth | 1..65536 (default 256) |
| --ocsp-days | 1..365 (default 7) |

A full queue returns 503 with Retry-After: 1.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as CALC-40 (Calculations)

## Validation rules

### RULE-035: SO and read-only sessions are mutually exclusive
**Category:** Validation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:778-780`, `src/fhsm_session.c:131-138`
**Plain English:** A read-only session cannot be opened while the SO is logged in, and the SO cannot log in while any read-only session exists on the token.
**Specification:**
  Given the SO is logged in on token T
  When C_OpenSession is called without CKF_RW_SESSION
  Then it returns CKR_SESSION_READ_WRITE_SO_EXISTS
  Given one read-only session is open on T
  When C_Login(CKU_SO) is called
  Then it returns CKR_SESSION_READ_ONLY_EXISTS
**Parameters:** CKF_RW_SESSION = 0x2
**Edge cases handled:** None beyond the two directions above.
**Suspected defect:** A known race: a read-only session opened during the SO's PBKDF2 step is not seen (documented in the code).
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-06 (Validations & eligibility)

### RULE-036: PIN length and character rules
**Category:** Validation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:1687-1689`, `src/fhsm_pkcs11.c:1741-1743`, `src/fhsm_pkcs11.c:1767-1771`, `include/fhsm_common.h:386-391`, `src/fhsm_token.c:1217`
**Plain English:** Any PIN being set must be 4–64 bytes with no NUL byte. A brand-new token's SO PIN additionally needs at least 8 bytes, and failing that returns a misleading code.
**Specification:**
  Given a 3-byte PIN
  When C_InitToken, C_InitPIN or C_SetPIN is called
  Then it returns CKR_PIN_LEN_RANGE (0xA2)
  Given a 6-byte PIN containing a 0x00 byte
  Then it returns CKR_PIN_INVALID (0xA1)
  Given a 6-byte SO PIN and a slot with no token yet
  When C_InitToken is called
  Then it returns CKR_PIN_INCORRECT (0xA0)
**Parameters:** `FHSM_PIN_MIN_LEN = 4`; `FHSM_PIN_MAX_LEN = 64`; hidden minimum of 8 on first init; C_GetTokenInfo advertises 4/64 (`src/fhsm_pkcs11.c:1258-1259`)
**Edge cases handled:** C_Login does not check length.
**Suspected defect:**
- `docs/FIPS_140_3.md:63` says "at least 8 characters"; the code enforces 4.
- First-time C_InitToken enforces 8 but reports it as "incorrect PIN".
- Re-initialisation (`src/fhsm_token.c:1820`) enforces only 4.
**Confidence:** High
**SME question:** Is the regulatory minimum 4 or 8, and should all paths agree and return CKR_PIN_LEN_RANGE?
**Verified:** citations checked ✓ · extracted as VAL-11 (Validations & eligibility)
**Merged from CALC-05** (Calculations: "PIN length bounds") — Source: `include/fhsm_common.h:388-392`, `src/fhsm_pkcs11.c:1687-1689`, `src/fhsm_pkcs11.c:1741-1743`, `src/fhsm_pkcs11.c:1767-1771`, `src/fhsm_pkcs11.c:1258-1259`, `src/fhsm_token.c:1217`, `src/fhsm_token.c:1716`, `src/fhsm_token.c:1768`, `src/fhsm_token.c:1820`.

### RULE-037: Read-only session restrictions
**Category:** Validation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:2456-2465`, `src/fhsm_pkcs11.c:7724-7733`, `src/fhsm_pkcs11.c:4144-4156`; creation callers at 2857, 3568, 4308, 5207, 6559-6560, 8023
**Plain English:** A read-only session cannot create a token object (CKA_TOKEN = TRUE), modify one, or destroy one. Session objects remain usable.
**Specification:**
  Given a read-only session
  When C_GenerateKey is called with CKA_TOKEN = TRUE
  Then it returns CKR_SESSION_READ_ONLY (0xB5)
  When C_SetAttributeValue or C_DestroyObject targets a token object
  Then it returns CKR_SESSION_READ_ONLY
  When the template omits CKA_TOKEN (default FALSE)
  Then it is allowed and creates a session object
**Parameters:** CKF_RW_SESSION = 0x2
**Edge cases handled:** None beyond the above.
**Suspected defect:**
- C_EncapsulateKey and C_DecapsulateKey never call `fhsm_check_ro_token`, so a read-only session can create token objects through them.
- C_CopyObject inherits CKA_TOKEN = TRUE from the source when the template omits it (`src/fhsm_pkcs11.c:8193-8204`), while the read-only check reads only the template, so a token object can be created from a read-only session.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-18 (Validations & eligibility)

### RULE-038: CKA_TRUSTED can only be set to TRUE by the SO
**Category:** Validation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:3194-3201`; called at 2853, 3570, 4303, 5196, 5498, 5689, 6538, 6553, 7737, 8019
**Plain English:** Any create, generate, derive, unwrap, KEM, copy or set-attribute template that sets CKA_TRUSTED = TRUE is refused unless the SO is logged in.
**Specification:**
  Given USER is logged in
  When C_CreateObject is called with CKA_TRUSTED = TRUE
  Then it returns CKR_ATTRIBUTE_READ_ONLY (0x10)
  Given CKA_TRUSTED = FALSE or absent, it is allowed
**Parameters:** none
**Edge cases handled:** A malformed (non-1-byte) value is skipped here and caught by the length check in RULE-045.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-19 (Validations & eligibility)

### RULE-039: CKA_VALUE read refusal
**Category:** Validation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:7209-7243`, `src/fhsm_pkcs11.c:7629-7633`
**Plain English:** The value of a private or secret key is withheld if the key is sensitive or not extractable. Any object flagged sensitive is also withheld.
**Specification:**
  Given an AES key with SENSITIVE = 0 and EXTRACTABLE = 0
  When C_GetAttributeValue(CKA_VALUE) is called
  Then ulValueLen = -1 and it returns CKR_ATTRIBUTE_SENSITIVE (0x11)
  Given SENSITIVE = 0 and EXTRACTABLE = 1, the value is returned
  Given a public key, the value is always returned (ML-KEM/ML-DSA as the raw key)
**Parameters:** none
**Edge cases handled:**
- If the flags cannot be read, a key is treated as sensitive.
- Error precedence: BUFFER_TOO_SMALL, then ATTRIBUTE_SENSITIVE, then TYPE_INVALID.
- CKO_DATA values are always returned.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-24 (Validations & eligibility)

### RULE-040: One-way flags and immutable attributes in C_SetAttributeValue
**Category:** Validation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:7700-7972`
**Plain English:** SENSITIVE and WRAP_WITH_TRUSTED can only go from false to true. EXTRACTABLE and COPYABLE can only go from true to false. Identity and provenance attributes cannot be changed, and an unmodifiable object cannot be changed at all.
**Specification:**
  Given a key with SENSITIVE = 1
  When it is set to SENSITIVE = 0
  Then it returns CKR_ATTRIBUTE_READ_ONLY (0x10)
  Given EXTRACTABLE = 0, setting it to 1 returns 0x10
  Setting CKA_CLASS, KEY_TYPE or VALUE returns 0x10
  Setting TOKEN, PRIVATE, LOCAL, ALWAYS_SENSITIVE, NEVER_EXTRACTABLE, MODIFIABLE, DESTROYABLE or ALWAYS_AUTH returns 0x10
  Setting a usage flag such as CKA_SIGN, or any unlisted attribute, returns CKR_ATTRIBUTE_TYPE_INVALID (0x12)
  Given CKA_MODIFIABLE = FALSE on the object, any set returns CKR_ACTION_PROHIBITED (0x1B)
  Given CKA_ID longer than 32 bytes, it returns CKR_ATTRIBUTE_VALUE_INVALID
  Given CKA_APPLICATION on a non-data object, or dates on a data object, it returns 0x12
**Parameters:** CKA_ID ≤ 32 bytes; CKA_APPLICATION ≤ 64; label truncated to 63; dates must be YYYYMMDD with month 1–12 and day 1–31 (`src/fhsm_pkcs11.c:2506-2515`)
**Edge cases handled:** The template is validated completely before anything is written, so it applies all-or-nothing.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-25 (Validations & eligibility)

### RULE-041: C_CopyObject rules
**Category:** Validation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:7995-8292`
**Plain English:** A copy is refused if the source is not copyable or no one is logged in. The copy follows the same one-way flag rules as C_SetAttributeValue, but drops most of the source's usage and policy data.
**Specification:**
  Given a source with CKA_COPYABLE = FALSE, it returns CKR_ACTION_PROHIBITED
  Given CKA_CLASS, KEY_TYPE or VALUE in the template, it returns CKR_TEMPLATE_INCONSISTENT (0xD1)
  Given SENSITIVE 1→0 or EXTRACTABLE 0→1, it returns 0x10
**Parameters:** none
**Edge cases handled:** The source's flags2/flags3 bytes, dates and label are copied.
**Suspected defect:** These were found by reading the code, not by running it.
- The usage byte is never copied, so the copy has no usage restriction. A key with CKA_SIGN = FALSE yields a copy that can sign.
- The source's allowed-mechanism list and nested templates are not copied; only their "present" bits are.
  - The copy's wrap/unwrap/derive templates are therefore empty, and every check against them passes.
  - CKA_ALLOWED_MECHANISMS in the copy template replaces the source's list, which allows widening it.
**Confidence:** Medium
**SME question:** Must a copy carry the source's usage and policy unchanged?
**Verified:** citations checked ✓ · extracted as VAL-27 (Validations & eligibility)

### RULE-042: Key type vs mechanism
**Category:** Validation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:9642-9712`; `src/fhsm_pkcs11.c:5041`, `src/fhsm_pkcs11.c:5125-5126`, `src/fhsm_pkcs11.c:5251`, `src/fhsm_pkcs11.c:5319-5320`
**Plain English:** A mechanism needs a key of the matching family. HMAC accepts any symmetric key but refuses RSA, EC and EdDSA keys.
**Specification:**
  Given a CKK_GENERIC_SECRET key, C_EncryptInit(CKM_AES_CBC) returns CKR_KEY_TYPE_INCONSISTENT
  Given an RSA key, CKM_SHA256_HMAC returns CKR_KEY_TYPE_INCONSISTENT
  Given C_WrapKey(OAEP) with an AES wrapping key, it returns CKR_WRAPPING_KEY_TYPE_INCONSISTENT (0x115)
  Given C_UnwrapKey(OAEP) with an unwrapping key that is not an RSA private key, it returns 0xF2
**Parameters:** the mechanism→key-type table at `src/fhsm_pkcs11.c:9648-9686`
**Edge cases handled:** Unknown mechanisms skip this check. Montgomery (X25519/X448) keys are not in the HMAC refusal list.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-30 (Validations & eligibility)

### RULE-043: C_UnwrapKey rules
**Category:** Validation
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:5174-5444`
**Plain English:** An unwrapped key is always a secret key. Its length must fit its declared type, and a sensitivity downgrade is refused if the unwrapping key's template requires sensitivity.
**Specification:**
  Given an AES-KW blob of 20 bytes (not a multiple of 8, or < 24), it returns CKR_WRAPPED_KEY_LEN_RANGE (0x112)
  Given a blob that fails to decrypt, it returns CKR_WRAPPED_KEY_INVALID (0x110)
  Given CKA_KEY_TYPE = CKK_AES and 20 recovered bytes, it returns CKR_KEY_TYPE_INCONSISTENT
  Given CKK_DES3 and other than 24 bytes, it returns CKR_KEY_TYPE_INCONSISTENT
  Given CKA_VALUE_LEN = 32 and 16 recovered bytes, it returns CKR_ATTRIBUTE_VALUE_INVALID
  Given template SENSITIVE = 0 and an unwrapping key with an UNWRAP_TEMPLATE requiring SENSITIVE = 1, it returns CKR_ATTRIBUTE_READ_ONLY
  Given template SENSITIVE = 0 and no such policy, the downgrade is allowed (Tookan §3.3, a documented limitation)
**Parameters:** recovered-plaintext buffer 4096 bytes; KW minimum blob 24, KWP minimum 16
**Edge cases handled:** CKA_CLASS in the template is ignored. RSA v1.5/X.509 unwrap is refused in the NIST-approved-only build.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-34 (Validations & eligibility)

### RULE-044: Token file load validation
**Category:** Validation
**Priority:** P0
**Source:** `src/fhsm_token.c:1306-1355`, `src/fhsm_token.c:1058-1090`
**Plain English:** A token file must start with a 317-byte header with magic "FHSM" and version 1. Public objects are read before login from a plaintext section that is not authenticated.
**Specification:**
  Given a file shorter than 317 bytes, a wrong magic, or a version other than 1
  When the token is loaded
  Then it returns CKR_FUNCTION_FAILED
  Given a missing file, it returns CKR_TOKEN_NOT_PRESENT
  Given a public section with a bad magic or length, or containing a non-public object, the pre-login view is left empty
**Parameters:** magic "FHSM"; `FHSM_TOK_VERSION = 1`; header 317 bytes; `FHSM_OBJ_BLOB_MAX`; failure counters at offsets 293 and 297
**Edge cases handled:** None beyond the above.
**Suspected defect:**
- The header is not authenticated. `pbkdf2_iter` is taken from the file without a range check.
- The public section is plaintext and unauthenticated (acknowledged at `src/fhsm_token.c:1053-1057`). Anyone who can write the file can plant public keys or certificates, including ones flagged CKA_TRUSTED, and they are used by pre-login C_Verify.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-44 (Validations & eligibility)

### RULE-045: Creation-template structural checks
**Category:** Validation
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:2247-2249`, `src/fhsm_pkcs11.c:2334-2347`, `src/fhsm_pkcs11.c:2357-2388`, `src/fhsm_pkcs11.c:7166-7167`
**Plain English:** Templates are bounded in size, and boolean and ulong attributes must have exactly the right length.
**Specification:**
  Given ulCount = 1025, it returns CKR_ARGUMENTS_BAD
  Given pTemplate = NULL with count 2, it returns CKR_ARGUMENTS_BAD
  Given an attribute with pValue = NULL and length 4 in a creation template, it returns CKR_ATTRIBUTE_VALUE_INVALID
  Given CKA_SENSITIVE with length 8, it returns CKR_ATTRIBUTE_VALUE_INVALID
  Given CKA_VALUE_LEN with length 4 on LP64, it returns CKR_ATTRIBUTE_VALUE_INVALID
**Parameters:** `FHSM_MAX_TEMPLATE_ATTRS = 1024`. Boolean attributes: 0x001, 0x002, 0x086, 0x103–0x10C, 0x162–0x165, 0x170–0x172, 0x202, 0x210. Ulong attributes: 0x000, 0x100, 0x161, 0x121, 0x080.
**Edge cases handled:** C_GetAttributeValue allows NULL pValue as a size query.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-20 (Validations & eligibility)

### RULE-046: C_CreateObject class, type and required attributes
**Category:** Validation
**Priority:** P1
**Source:** `src/fhsm_create_attrs.c:324-432`, `src/fhsm_create_attrs.c:165-318`, `src/fhsm_pkcs11.c:3559-3618`, `src/fhsm_pkcs11.c:3707-3772`
**Plain English:** Import accepts only the data, certificate, public-key, private-key and secret-key classes, and each class/type pair has required attributes.
**Specification:**
  Given CKA_CLASS = CKO_HW_FEATURE, it returns CKR_TEMPLATE_INCONSISTENT
  Given no CKA_CLASS, or a key class with no CKA_KEY_TYPE, it returns CKR_TEMPLATE_INCOMPLETE
  Given a certificate with type other than X.509 (0), it returns CKR_TEMPLATE_INCONSISTENT
  Given a certificate with an empty CKA_VALUE, it returns CKR_TEMPLATE_INCOMPLETE
  Given an EC private key with no CKA_EC_PARAMS, it returns CKR_TEMPLATE_INCONSISTENT
  Given an EC public key missing CKA_EC_POINT, it returns CKR_TEMPLATE_INCOMPLETE
  Given an EC curve not in the table, it returns the curve refusal code
  Given an RSA private key given as components missing n, e or d, it returns CKR_TEMPLATE_INCOMPLETE
  Given an Ed25519 public point that is neither 32 raw bytes nor a DER OCTET STRING of 32, it returns CKR_ATTRIBUTE_VALUE_INVALID
  Given an X25519/X448 private key on a FIPS build, it returns CKR_CURVE_NOT_SUPPORTED
**Parameters:** EC import curves P-256/384/521 (`src/fhsm_create_attrs.c:55-64`); Ed25519 key 32 bytes, Ed448 57 bytes
**Edge cases handled:** A data object's CKA_VALUE is optional. No length check is made on imported secret-key values.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-21 (Validations & eligibility)

### RULE-047: KEM encapsulate/decapsulate permission
**Category:** Validation
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:5462-5560`, `src/fhsm_pkcs11.c:5666-5760`, `src/fhsm_pkcs11.c:2869-2871`
**Plain English:** C_EncapsulateKey needs an ML-KEM public key not marked CKA_ENCAPSULATE = FALSE, and C_DecapsulateKey needs an ML-KEM private key not marked CKA_DECAPSULATE = FALSE. C_GenerateKey refuses either attribute in its template.
**Specification:**
  Given a public key with CKA_ENCAPSULATE = FALSE, it returns CKR_KEY_FUNCTION_NOT_PERMITTED
  Given an RSA key, it returns CKR_KEY_TYPE_INCONSISTENT
  Given a mechanism other than CKM_ML_KEM, it returns CKR_MECHANISM_INVALID
  Given C_GenerateKey with CKA_ENCAPSULATE in the template, it returns CKR_ATTRIBUTE_TYPE_INVALID
**Parameters:** shared secret ≤ 64 bytes
**Edge cases handled:** None beyond the above.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-36 (Validations & eligibility)

### RULE-048: C_DigestKey refuses sensitive keys
**Category:** Validation
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:11998-12019`
**Plain English:** A key flagged sensitive cannot be fed into a digest.
**Specification:**
  Given SENSITIVE = 1, it returns CKR_KEY_INDIGESTIBLE (0x67)
**Parameters:** none
**Edge cases handled:** None.
**Suspected defect:** A key that is non-sensitive but not extractable can be digested. This is the same gap as SEC-003.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-37 (Validations & eligibility)

### RULE-049: Symmetric mechanism parameters (IV, tag, nonce)
**Category:** Validation
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:9095-9233`, `src/fhsm_pkcs11.c:9271-9346`, `src/fhsm_pkcs11.c:9571-9575`, `src/fhsm_pkcs11.c:9608-9631`
**Plain English:** Each cipher mode has fixed rules for its IV, nonce and tag lengths.
**Specification:**
  Given AES-CBC without a 16-byte IV, it returns CKR_MECHANISM_PARAM_INVALID
  Given AES-GCM with IV < 12 bytes, it returns PARAM_INVALID
  Given ulTagBits > 128 or not a multiple of 8, it returns CKR_ARGUMENTS_BAD
  Given ulTagBits = 0, it is treated as 128
  Given AES-CTR with ulCounterBits of 0 or > 128, it returns PARAM_INVALID
  Given 3DES-CBC with an IV that is not 8 bytes, it returns PARAM_INVALID
  Given AES-CCM with nonce outside 7–13 bytes or MAC length outside {4,6,8,…,16}, it returns PARAM_INVALID
  Given GMAC with IV < 12, it returns PARAM_INVALID
  Given an encrypt mechanism outside the allowed list (for example CKM_SHA256), it returns CKR_MECHANISM_INVALID
**Parameters:** `FHSM_AAD_MAX = 1 MiB`; GCM default tag 16 bytes; data length ≤ 0x7FFFFFFF, otherwise CKR_DATA_LEN_RANGE
**Edge cases handled:** None beyond the above.
**Suspected defect:** GCM tags of 8–56 bits are accepted, while NIST SP 800-38D allows only 128, 120, 112, 104, 96 and, restricted, 64 and 32.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-38 (Validations & eligibility)

### RULE-050: RSA key generation, OAEP and PSS parameters
**Category:** Validation
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:6625-6648`, `src/fhsm_pkcs11.c:8516-8629`, `src/fhsm_pkcs11.c:9403-9415`, `src/fhsm_pkcs11.c:11024-11040`
**Plain English:** RSA keys must be 2048, 3072 or 4096 bits. The public exponent must be odd and > 1. OAEP and PSS hashes and MGFs must be from the known list, and the PSS salt must be 0–1024 bytes.
**Specification:**
  Given CKA_MODULUS_BITS = 1024, it returns CKR_KEY_SIZE_RANGE
  Given CKA_PUBLIC_EXPONENT = 0x04, it returns CKR_ATTRIBUTE_VALUE_INVALID
  Given CKA_PUBLIC_EXPONENT = 0x03, the value passes the check, but the generated key uses e = 65537
  Given an OAEP hashAlg outside SHA-1/2/3, it returns PARAM_INVALID
  Given a PSS parameter block shorter than 3 words, or sLen = 2000, it returns PARAM_INVALID
**Parameters:** default size 2048; generated DER ≤ 5500 bytes
**Edge cases handled:** None beyond the above.
**Suspected defect:**
- The requested public exponent is validated and then ignored (`EVP_PKEY_Q_keygen` at line 6646).
- The PSS hashAlg is not checked against the mechanism's hash.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-39 (Validations & eligibility)

### RULE-051: PQ signature context and hedging parameters
**Category:** Validation
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:9437-9458`, `src/fhsm_pkcs11.c:10845-10851`
**Plain English:** An ML-DSA or SLH-DSA signing context longer than 255 bytes is refused at C_SignInit. Verification accepts it and reports the signature invalid. The hedging variant must be 0–2.
**Specification:**
  Given ulContextLen = 256, C_SignInit returns CKR_MECHANISM_PARAM_INVALID
  Given ulContextLen = 10 with a NULL pointer, it returns PARAM_INVALID
  Given a hedge variant of 3, it returns PARAM_INVALID
**Parameters:** maximum context length 255
**Edge cases handled:** None beyond the above.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-40 (Validations & eligibility)

### RULE-052: PBKDF2 and HKDF parameters
**Category:** Validation
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:2778-2832`, `src/fhsm_pkcs11.c:4298-4360`
**Plain English:** PBKDF2 needs a caller-supplied salt and a supported PRF. HKDF needs extract or expand set and an approved PRF hash.
**Specification:**
  Given PBKDF2 with saltSource other than CKZ_SALT_SPECIFIED, it returns PARAM_INVALID
  Given prf = 2 (GOSTR3411), it returns PARAM_INVALID
  Given a length > 0x7FFFFFFF, or a NULL pointer with a non-zero length, it returns PARAM_INVALID
  Given HKDF with both bExtract and bExpand false, it returns PARAM_INVALID
  Given an HKDF salt key that is not CKO_SECRET_KEY, it returns CKR_KEY_TYPE_INCONSISTENT
**Parameters:** PRF codes 1, 3–8 (SHA-1/224/256/384/512/512-224/512-256)
**Edge cases handled:** A FIPS refusal from PBKDF2 is reported as PARAM_INVALID.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-43 (Validations & eligibility)

### RULE-053: HTTP request parsing limits and routes
**Category:** Validation
**Priority:** P1
**Source:** `service/fhsm_service.c:138-143`, `service/fhsm_service.c:1109-1110`, `service/fhsm_service.c:1136-1297`, `service/fhsm_service.c:1580-1660`, `service/fhsm_service.c:1955-1992`
**Plain English:** Requests must be strict, small HTTP/1.1 messages, and each listener serves a fixed set of routes.
**Specification:**
  Given a method other than GET/POST, it returns 400 "method"
  Given a protocol other than "HTTP/1.1", it returns 400 "version"
  Given a target not starting with "/", longer than 255, or containing bytes outside 0x21–0x7E, it returns 400 "target"
  Given more than 32 headers, a header name over 64 bytes, a value over 256 bytes, or control characters, it returns 400
  Given more than 8192 bytes of headers, it returns 400 "headers_too_large"
  Given a duplicate or non-numeric Content-Length, it returns 400
  Given a body over 65536 bytes, it returns 413
  Given any Transfer-Encoding, it returns 400
  Given no first byte within 1 s, or an incomplete request after 10 s, it returns 408
  Routes on the private listener: GET /health, GET /token, POST /sign, POST /verify (wrong method returns 405, anything else 404)
  Routes on the public listener: GET /health, GET /certificates, POST /ocsp (GET returns 405 with Allow: POST)
**Parameters:** request line ≤ 1024; MAX_BODY 65536; Content-Length ≤ 9 digits
**Edge cases handled:** /certificates and /ocsp on the private listener return 404 with a Link header.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-47 (Validations & eligibility)

### RULE-054: OCSP request and responder rules
**Category:** Validation
**Priority:** P1
**Source:** `service/fhsm_service.c:1881-1939`, `src/fhsm_revocation.c:274-324`, `src/fhsm_revocation.c:401-503`, `src/fhsm_revocation.c:165-174`
**Plain English:** OCSP requests are POST only and must parse. A serial is answered "good" unless it is in the revocation DB. Questions about other issuers get "unknown". A delegated responder must carry the OCSPSigning extended key usage and be issued by the CA.
**Specification:**
  Given an empty body, it returns OCSP malformedRequest (1)
  Given a body that does not parse, it returns malformedRequest
  Given a revocation DB refresh failure or no free session, it returns tryLater (3)
  Given no responder key, it returns internalError (2)
  Given a CertID for this CA whose serial is not in the DB, the status is "good"
  Given a CertID for a different issuer or an unknown hash, the status is "unknown"
  Given a responder certificate without the OCSPSigning EKU, or with an issuer that does not match the CA, it is refused
**Parameters:** `--ocsp-days` 1–365 (default 7); a nonce in the request is echoed
**Edge cases handled:** None beyond the above.
**Suspected defect:** A missing revocation DB file (ENOENT) loads as empty, so every serial, including never-issued ones, is reported "good".
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-49 (Validations & eligibility)

## Policy rules

### RULE-055: Private-object visibility is decided by object class
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:9010-9015`, `src/fhsm_pkcs11.c:7173-7174`, `src/fhsm_pkcs11.c:7665-7666`, `src/fhsm_pkcs11.c:8345-8366`, `src/fhsm_pkcs11.c:7485-7487`
**Plain English:** Secret and private keys are invisible unless USER is logged in. C_GetAttributeValue and C_GetObjectSize act as if the handle does not exist, and C_FindObjects skips them.
**Specification:**
  Given an AES secret key on the token and a session with no login (or with SO logged in)
  When C_GetAttributeValue(handle) is called
  Then it returns CKR_OBJECT_HANDLE_INVALID
  When C_FindObjectsInit({CKA_CLASS=CKO_SECRET_KEY}) and C_FindObjects are called
  Then 0 handles are returned
**Parameters:** hidden classes are CKO_SECRET_KEY (4) and CKO_PRIVATE_KEY (3)
**Edge cases handled:** C_FindObjectsInit filters only on CKA_CLASS, CKA_LABEL and CKA_ID; all other template attributes are ignored.
**Suspected defect:**
- The CKA_PRIVATE value in a template is never stored. Visibility and the C_GetAttributeValue result both come from class alone.
- A CKO_DATA object with CKA_PRIVATE = TRUE is visible to everyone, while a secret key with CKA_PRIVATE = FALSE is hidden.
- The SO cannot see private keys but can use them (RULE-056).
**Confidence:** High
**SME question:** Must CKA_PRIVATE be stored per object and enforced for data objects?
**Verified:** citations checked ✓ · extracted as VAL-15 (Validations & eligibility)

### RULE-056: Key-use Init paths only check that the handle exists (SEC-001)
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:9017-9024`, `src/fhsm_pkcs11.c:9761-9775`, `src/fhsm_pkcs11.c:10165-10179`, `src/fhsm_pkcs11.c:10793-10853`, `src/fhsm_pkcs11.c:11487-11545`, `src/fhsm_token.c:1645-1654`
**Plain English:** C_EncryptInit, C_DecryptInit, C_SignInit and C_VerifyInit check that the key exists, its type, its allowed mechanisms and its usage flags. They do not check login state or private-object visibility.
**Specification:**
  Given USER logged in and then out in the same process (objects stay loaded), and a private AES token key with handle 5
  When a session with no login calls C_EncryptInit(CKM_AES_GCM, 5) and then C_Encrypt
  Then both return CKR_OK and ciphertext is produced
  Given SO is logged in
  When C_SignInit is called on the user's private key
  Then it succeeds
**Parameters:** none
**Edge cases handled:** In a fresh process with no login, only public objects are loaded, so private handles return CKR_KEY_HANDLE_INVALID.
**Suspected defect:** SEC-001, which you report as reproduced. The fix is to apply `fhsm_object_access_denied`, or a USER-role requirement for private keys, in `fhsm_require_key`, and to unload objects at logout.
**Confidence:** High
**Verified:** **Reproduced** (SEC-001): after `C_Logout`, `C_EncryptInit` + `C_Encrypt` with the user's AES token key → CKR_OK. · citations checked ✓ · extracted as VAL-16 (Validations & eligibility)

### RULE-057: Login required for key-management operations
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:2860`, `src/fhsm_pkcs11.c:4317`, `src/fhsm_pkcs11.c:5015`, `src/fhsm_pkcs11.c:5216`, `src/fhsm_pkcs11.c:5508`, `src/fhsm_pkcs11.c:5698`, `src/fhsm_pkcs11.c:6578`, `src/fhsm_pkcs11.c:7709`, `src/fhsm_pkcs11.c:8037`, `src/fhsm_pkcs11.c:2472-2483`, `src/fhsm_token.c:2661-2664`
**Plain English:** Key generation, derive, wrap, unwrap, KEM, set-attribute and copy need some logged-in role (USER or SO). C_CreateObject needs a login only when the object would be private.
**Specification:**
  Given no login
  When C_GenerateKey(CKM_AES_KEY_GEN, VALUE_LEN 32) is called
  Then it returns CKR_USER_NOT_LOGGED_IN
  When C_CreateObject({CLASS=CKO_SECRET_KEY, …}) is called with no CKA_PRIVATE
  Then it returns CKR_USER_NOT_LOGGED_IN (secret and private keys default to private)
  When C_CreateObject({CLASS=CKO_PUBLIC_KEY, …}) is called
  Then it is allowed
  When C_DestroyObject is called
  Then it returns CKR_USER_NOT_LOGGED_IN (the DEK is not live)
**Parameters:** none
**Edge cases handled:** The check is "role != NONE", so the SO passes everywhere, including wrapping the user's extractable keys.
**Confidence:** High
**SME question:** Should the SO be allowed to wrap, copy or modify user keys?
**Verified:** citations checked ✓ · extracted as VAL-17 (Validations & eligibility)

### RULE-058: Sensitivity and extractability defaults per creation path
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:2995-3008` (C_GenerateKey), `src/fhsm_pkcs11.c:6834-6842` (key pair), `src/fhsm_pkcs11.c:3652-3672` (import), `src/fhsm_pkcs11.c:5348-5394` (unwrap), `src/fhsm_pkcs11.c:4824-4834` (derive), `src/fhsm_pkcs11.c:5571-5584` (KEM)
**Plain English:** Each creation path starts from different sensitive/extractable defaults.
**Specification:**
  Given C_GenerateKey with no flags, then SENSITIVE = 1, EXTRACTABLE = 0, LOCAL = 1 (the template can turn SENSITIVE off and EXTRACTABLE on)
  Given C_GenerateKeyPair, the private key is always SENSITIVE = 1, EXTRACTABLE = 0, LOCAL = 1, and the template cannot change this
  Given C_CreateObject of a secret key, then SENSITIVE and EXTRACTABLE are as stated in the template, default 0/0
  Given C_CreateObject of a private key, it is always sensitive, and extractable only if the template says so
  Given C_UnwrapKey, then SENSITIVE = 1, EXTRACTABLE = 0 by default
  Given C_DeriveKey or C_Encapsulate/C_DecapsulateKey, then SENSITIVE = 0, EXTRACTABLE = 0 by default
**Parameters:** flag bits SENSITIVE 0x01, EXTRACTABLE 0x02, LOCAL 0x10 (`include/fhsm_token.h:243-278`)
**Edge cases handled:** None beyond the above.
**Suspected defect:**
- The comment at `src/fhsm_pkcs11.c:5459-5460` says the KEM shared secret is "marked sensitive"; the code does not mark it.
- Keys that are non-sensitive and non-extractable by default become exportable through SEC-003 (RULE-063).
- The comment in the object struct (`src/fhsm_token.c:128-196`) says "bit 0 = CKA_PRIVATE"; the code uses bit 0 as SENSITIVE.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-23 (Validations & eligibility)

### RULE-059: ALWAYS_SENSITIVE and NEVER_EXTRACTABLE come from current flags
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:7528-7535`
**Plain English:** These provenance attributes are computed from the key's current flags, not its history.
**Specification:**
  Given a key imported with SENSITIVE = 0 and EXTRACTABLE = 1, later changed to SENSITIVE = 1 and EXTRACTABLE = 0
  When C_GetAttributeValue(CKA_ALWAYS_SENSITIVE, CKA_NEVER_EXTRACTABLE) is called
  Then both read TRUE
**Parameters:** none
**Edge cases handled:** None.
**Suspected defect:** The spec defines both attributes historically. An imported or unwrapped key can claim a provenance it does not have, which can mislead policy engines.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-26 (Validations & eligibility)

### RULE-060: Key-usage flags: defaults and enforcement
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:2401-2422`, `src/fhsm_pkcs11.c:9029-9035`; call sites 9771, 10175, 10841, 11534 (verify), 5014, 5213, 4323
**Plain English:** Each operation needs its usage bit on the key. The default bits depend on the key class.
**Specification:**
  Given an AES key created with CKA_ENCRYPT = FALSE
  When C_EncryptInit is called
  Then it returns CKR_KEY_FUNCTION_NOT_PERMITTED (0x68)
  Defaults: secret keys have encrypt, decrypt, sign, verify, wrap and unwrap (no derive); public keys have encrypt, verify and wrap; private keys have decrypt, sign, unwrap and derive
**Parameters:** one usage byte with a VALID bit
**Edge cases handled:** Keys written before the usage byte existed (VALID bit clear) are allowed every use.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-29 (Validations & eligibility)

### RULE-061: CKA_ALLOWED_MECHANISMS
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:3264-3275`, `src/fhsm_token.c:2328-2354`
**Plain English:** If a key lists allowed mechanisms, every other mechanism is refused. An empty list allows nothing.
**Specification:**
  Given allowed = [CKM_AES_GCM]
  When C_EncryptInit(CKM_AES_CBC) is called
  Then it returns CKR_MECHANISM_INVALID
  Given more than 8 entries, or a length that is not a multiple of sizeof(CK_ULONG), creation returns CKR_ATTRIBUTE_VALUE_INVALID
**Parameters:** `FHSM_POLICY_MECH_MAX = 8`
**Edge cases handled:** Absent means unrestricted. If the store is not loaded, the check passes. Applied at Encrypt/Decrypt/Sign/Verify Init, Derive, Wrap, Unwrap, Encapsulate, Decapsulate and DigestKey.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-31 (Validations & eligibility)

### RULE-062: Nested WRAP / UNWRAP / DERIVE templates
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:3315-3373`, `src/fhsm_pkcs11.c:3393-3418`, `src/fhsm_pkcs11.c:3470-3495`
**Plain English:** A wrapping, unwrapping or base key can carry a template that the produced or exported key must match exactly. Omitting an attribute counts as a mismatch.
**Specification:**
  Given an unwrapping key with UNWRAP_TEMPLATE {CKA_LABEL = "x"}
  When C_UnwrapKey is called with no CKA_LABEL
  Then it returns CKR_TEMPLATE_INCONSISTENT
  Given a wrapping key with WRAP_TEMPLATE {CKA_EXTRACTABLE = TRUE} and a target key that is not extractable, C_WrapKey returns 0xD1
  Given a WRAP_TEMPLATE naming an attribute outside {CLASS, KEY_TYPE, VALUE_LEN, LABEL, ID, SENSITIVE, EXTRACTABLE}, creation returns CKR_ATTRIBUTE_VALUE_INVALID
**Parameters:** `FHSM_POLICY_ATTR_MAX = 4` entries; `FHSM_POLICY_VALUE_MAX = 48` bytes per entry
**Edge cases handled:** An attribute that cannot be read is treated as not matching. An unknown key handle passes this check (`src/fhsm_pkcs11.c:3398-3399`).
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-32 (Validations & eligibility)

### RULE-063: C_WrapKey eligibility (SEC-003)
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:4984-5030`, `src/fhsm_pkcs11.c:5039-5101`
**Plain English:** A key is refused for wrapping only if it is both sensitive and not extractable. A key marked wrap-with-trusted needs a trusted wrapping key.
**Specification:**
  Given a target with SENSITIVE = 1 and EXTRACTABLE = 0, it returns CKR_KEY_UNEXTRACTABLE (0x6A)
  Given a target with SENSITIVE = 0 and EXTRACTABLE = 0 (the derived or KEM default)
  When it is wrapped under a non-sensitive AES key the caller imported
  Then it returns CKR_OK and the key leaves the token
  Given a target with WRAP_WITH_TRUSTED and a wrapping key without CKA_TRUSTED, it returns CKR_KEY_NOT_WRAPPABLE (0x69), checked before the size query
  Given an AES-KW wrapping key that is not 16, 24 or 32 bytes, it returns 0x114
  Given AES-KW with a target length < 16 or not a multiple of 8, it returns CKR_KEY_SIZE_RANGE (0x62)
  Given AES-KWP with a 0-byte target, it returns 0x62
  Given an IV that is not 8 bytes (KW) or 4 bytes (KWP), it returns CKR_MECHANISM_PARAM_INVALID
**Parameters:** output size: KW is n+8; KWP is roundup8(n)+8
**Edge cases handled:** Order: allowed mechanisms, then wrap template, then trusted check, then usage, then login.
**Suspected defect:** SEC-003. Per the spec, wrapping must also be refused when EXTRACTABLE = FALSE. The comment at `src/fhsm_pkcs11.c:7215-7217` claims C_WrapKey refuses non-extractable keys; the code does not.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-33 (Validations & eligibility)

### RULE-064: C_DeriveKey output class and sensitivity
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:4789-4860`, `src/fhsm_pkcs11.c:4489-4493`
**Plain English:** A derived object is a secret key or a data object. Its sensitivity comes only from the template and is never inherited from the base key.
**Specification:**
  Given a sensitive base key and C_DeriveKey(CKM_HKDF_DERIVE) with template CKA_CLASS = CKO_DATA
  Then a data object is created, its value is readable by C_GetAttributeValue, and it is visible without login
  Given CKA_CLASS = CKO_PRIVATE_KEY, it returns CKR_TEMPLATE_INCONSISTENT
  Given CKA_VALUE in the template, it returns CKR_TEMPLATE_INCONSISTENT
**Parameters:** default class CKO_SECRET_KEY (CKO_DATA for CKM_HKDF_DATA); default type CKK_GENERIC_SECRET
**Edge cases handled:** None beyond the above.
**Suspected defect:** Secrets derived from a sensitive base key can be exported in clear, either through the CKO_DATA class or through the non-sensitive default plus SEC-003.
**Confidence:** Medium
**SME question:** Must derived keys inherit SENSITIVE and ALWAYS_SENSITIVE from the base key, and should CKO_DATA be allowed only for CKM_HKDF_DATA?
**Verified:** citations checked ✓ · extracted as VAL-35 (Validations & eligibility)

### RULE-065: The NIST-approved-only build refuses non-approved mechanisms
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:9587-9600`, `src/fhsm_pkcs11.c:10830-10834`, `src/fhsm_pkcs11.c:11524-11528`, `src/fhsm_pkcs11.c:2684`, `src/fhsm_pkcs11.c:2916`, `src/fhsm_pkcs11.c:4340`, `src/fhsm_pkcs11.c:4628`, `src/fhsm_pkcs11.c:5150`, `src/fhsm_pkcs11.c:5330`, `src/fhsm_pkcs11.c:6606`, `src/fhsm_pkcs11.c:6689`, `src/fhsm_pkcs11.c:6403`
**Plain English:** When the build constant `fhsm_build_fips_strict` = 1, the listed non-approved mechanisms return CKR_MECHANISM_INVALID.
**Specification:**
  Given the strict build
  When any of the following is requested, it returns CKR_MECHANISM_INVALID:
  - encrypt/decrypt with CKM_DES3_CBC, CKM_RSA_PKCS or CKM_RSA_X_509
  - sign/verify with SHA1_RSA_PKCS, RSA_X_509 or the composite ML-DSA65+Ed25519 mechanism
  - DES3 key generation, composite or Montgomery key-pair generation
  - RSA v1.5 wrap or unwrap
  - a non-approved digest
  When HKDF uses a non-approved HMAC hash, it returns CKR_MECHANISM_PARAM_INVALID
**Parameters:** `fhsm_build_fips_strict` is a build-time constant (`src/gen/fhsm_dispatch.c:839`)
**Edge cases handled:** The runtime `FHSM_MODE` / `mode=` setting has no effect (excluded as instructed). AES-ECB is allowed.
**Suspected defect:** In the strict build, `fhsm-service` always signs with the composite mechanism `0x80004202` (`service/fhsm_service.c:1390`), so every /sign request returns 500.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-41 (Validations & eligibility)

### RULE-066: Object-store tag failure and zero-DEK fallback (SEC-002)
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_token.c:942-1019`, `src/fhsm_token.c:1527-1531`
**Plain English:** After a correct PIN, the encrypted object store is decrypted with the DEK. If that fails, the store is decrypted again under an all-zero key, and login succeeds either way.
**Specification:**
  Given a correct PIN and an object blob whose GCM tag fails under the real DEK but verifies under 32 zero bytes
  When C_Login is called
  Then it returns CKR_OK, the zero-key objects are loaded and trusted, and the next write re-encrypts them under the real DEK
  Given a blob that fails under both keys
  Then C_Login returns CKR_OK, the store stays not-loaded, object calls return CKR_USER_NOT_LOGGED_IN, and the blob on disk is preserved
**Parameters:** DEK 32 bytes; additional authenticated data is the token serial; blob ct_len must be between 1 and `FHSM_OBJ_BLOB_MAX`
**Edge cases handled:** None beyond the above.
**Suspected defect:** SEC-002. Anyone who can write the file and knows the serial can inject arbitrary objects, including trusted wrapping keys, by encrypting them under the zero key. A failed decrypt is also not reported to the caller.
**Confidence:** High
**Verified:** **Code-read** (assessment SEC-002): `src/fhsm_token.c:987-1003`. · citations checked ✓ · extracted as VAL-45 (Validations & eligibility)

### RULE-067: Peer-credential gate on both listeners
**Category:** Policy
**Priority:** P0
**Source:** `service/fhsm_service.c:1522-1531`, `service/fhsm_service.c:1946-1953`
**Plain English:** Only the configured proxy user may connect, checked through SO_PEERCRED on the Unix socket.
**Specification:**
  Given a peer uid of 1001 with `--proxy-uid 1000`, the private listener returns 403 "peer_not_proxy" and the public listener returns 403
  Given getsockopt fails, it returns 403 "peercred_unavailable"
**Parameters:** `--proxy-uid` is required and ≥ 0; socket mode 0660 (umask 0117)
**Edge cases handled:** None beyond the above.
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-46 (Validations & eligibility)

### RULE-068: Client identity, signing policy, refusal budget and in-flight cap
**Category:** Policy
**Priority:** P0
**Source:** `service/fhsm_service.c:184-278`, `service/fhsm_service.c:1352-1386`, `service/fhsm_service.c:1449-1473`, `service/fhsm_service.c:1538-1565`, `service/fhsm_service.c:626-833`, `service/fhsm_service.c:470-545`
**Plain English:**
- The proxy must assert one subject in `X-FHSM-Client-Subject`.
- A subject may sign or verify only with key labels paired with it in the policy file.
- Repeated refusals earn an exponential delay.
- Each subject has a cap on concurrent requests.
**Specification:**
  Given no subject header, it returns 403 "no_identity"; two subject headers return 400
  Given policy line "svc-a<TAB>ca-key" and subject "svc-b" requesting /sign with X-FHSM-Key "ca-key", it returns 403 "not_authorised" (the same answer as for an unknown key)
  Given a 6th not_authorised refusal, the next request returns 429 with Retry-After of 2 s (the 5th gives 1 s, the 11th or later caps at 60 s)
  Given /verify with X-FHSM-Signature-Length ≥ body length, it returns 400
  Given a subject with `workers` requests in flight, it returns 429 "too_many_in_flight" (the cap is workers − 1 when other subjects are present)
**Parameters:**
- POLICY_MAX 512 rules; label < 64 bytes.
- Policy file format is SUBJECT<TAB>KEY-LABEL; one malformed line rejects the whole file; a failed reload on SIGHUP keeps the old policy; a missing policy at start-up is fatal.
- BUDGET_FREE 4, BUDGET_DECAY_S 600 (one refusal forgiven per 10 quiet minutes), BUDGET_CAP_S 60, BUDGET_MAX 256; the budget is persisted to `<dir>/budget`.
- Signing mechanism is fixed to 0x80004202.
**Edge cases handled:** Only "not_authorised" refusals are charged to the budget.
**Suspected defect:** The budget and identity tables fail open when full. If 256 budget entries exist, refusals are not counted (line 773). If the identity table has no spare slot, the request is admitted uncounted (line 537).
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-48 (Validations & eligibility)

### RULE-069: CSR proof-of-possession and issuance constraints
**Category:** Policy
**Priority:** P0
**Source:** `src/fhsm_composite.c:1203-1240`, `src/fhsm_composite.c:1242-1421`, `tools/pkiops.c:1314-1335`, `tools/fhsm_ca.c:212-253`, `src/fhsm_composite.c:928-948`
**Plain English:** A certificate is issued only if the CSR's signature verifies under its own key. The CA's fixed extensions are used, and the request's extensions are ignored.
**Specification:**
  Given a CSR whose signature does not verify, fhsm-ca exits with code 4 and issues nothing
  Given a valid CSR asking for CA:TRUE, the certificate has critical CA:FALSE and critical KeyUsage digitalSignature + nonRepudiation
  The serial is 20 random bytes with the top bit cleared and a non-zero first byte
  notBefore is now − 3600 s and notAfter is now + days
  Given days ≤ 0, it returns CKR_ARGUMENTS_BAD
  Given the ocsp-responder profile with no --days, days = 30; over 90 gives a warning only; the profile adds the OCSPSigning EKU and ocsp-nocheck
  For a self-signed root, serial ≤ 0 or days ≤ 0 returns CKR_ARGUMENTS_BAD
**Parameters:** `FHSM_PKI_BACKDATE_SECONDS = 3600`; issue default 365 days; serials come from the token's C_GenerateRandom
**Edge cases handled:** The PIN is accepted only from the environment; `--pin` is refused.
**Suspected defect:**
- There is no check that the certificate's validity stays within the CA certificate's validity.
- `tools/fhsm_ca.c` copies the CA file into a 256 KiB static buffer without a length check (the `memcpy` near line 233).
**Confidence:** High
**Verified:** citations checked ✓ · extracted as VAL-50 (Validations & eligibility)

## Lifecycle rules

### RULE-070: Module state whitelist and the latched ERROR state
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_state.c:40-47, 56-92, 119-143`
**Plain English:** The module only moves along a fixed list of transitions; once it enters ERROR it can never leave in the same process, and entering ERROR is audited once.
**Specification:**
  Given module state INITIALIZED
  When `fhsm_state_set(X)` is called with X not in {POWER_OFF, AUTHENTICATED}
  Then it returns FHSM_RV_FUNCTION_FAILED (0x6) and the state is unchanged
  And given state ERROR, every `fhsm_state_set` returns 0x6
  And `fhsm_state_latch_error(reason)` sets ERROR, stores the first reason (max 127 chars) and writes one STATE_TRANSITION audit event {to:ERROR, reason}. Latching again changes nothing and writes no event.
  And each legal transition writes a STATE_TRANSITION event {from, to}
**Parameters:** whitelist = {0→1, 1→2, 2→3, 3→2, 2→0, 3→0}; reason buffer = 128 bytes
**Edge cases handled:** The latch emits its audit event outside the mutex. Re-latching stays silent, which avoids recursion when an audit write fails.
**Suspected defect:** AUTHENTICATED (3) is whitelisted but nothing ever sets it. The module state never tracks login.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-01 (State & lifecycle)

### RULE-071: C_Initialize sequence and double initialization
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:393-532`
**Plain English:** Initialization sets up the secure heap, runs the crypto self-tests, ensures the tokens directory exists (0700), provisions the audit key, opens the audit log, and only then declares the module INITIALIZED; any failure after the self-tests begin latches ERROR.
**Specification:**
  Given state POWER_OFF and a writable `FHSM_TOKENS_DIR`
  When `C_Initialize(NULL)` runs
  Then state goes 0→1, `fhsm_crypto_init` runs, the audit log opens, state goes 1→2, a MODULE_INIT audit event is written, and CKR_OK is returned
  And given state INITIALIZED (a second call in the same process)
  When `C_Initialize` is called
  Then it returns CKR_FUNCTION_FAILED (0x6), not CKR_CRYPTOKI_ALREADY_INITIALIZED (0x191)
  And if crypto init, directory creation, audit key provisioning or audit open fails, the module latches ERROR and returns the specific code (e.g. 0x80000001 for a failed KAT, 0x80000009 when the provider is unavailable)
**Parameters:** tokens dir = `$FHSM_TOKENS_DIR` or `/var/lib/freehsm/tokens`; log base = `$FHSM_AUDIT_LOG` or `<dir>/audit.log`; mkdir mode 0700
**Edge cases handled:** `pInitArgs` is ignored completely: no mutex or locking flags are validated and `CKR_ARGUMENTS_BAD` is never returned. A crypto self-test failure cannot be audited because the log is not open yet.
**Suspected defect:** 0x191 is never returned. Callers that treat a second `C_Initialize` as harmless will see a hard failure instead.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-02 (State & lifecycle)

### RULE-072: No "not initialized" gate on any entry point
**Category:** Lifecycle
**Priority:** P0
**Source:** `include/fhsm_common.h:198` (defined, never used); every `C_*` in `src/fhsm_pkcs11.c` checks only `== FHSM_STATE_ERROR` (e.g. :762, :893)
**Plain English:** No function refuses to run because the module is uninitialised; before `C_Initialize` or after `C_Finalize`, sessions, logins and crypto operations all proceed.
**Specification:**
  Given state POWER_OFF (never initialized, or after `C_Finalize`)
  When `C_OpenSession(0, CKF_SERIAL_SESSION|CKF_RW_SESSION, …)` is called on a slot holding a token
  Then it succeeds. `C_Login` and `C_Sign` succeed as well.
  And the audit log is closed, so `fhsm_audit_event` drops every event silently (RULE-097)
**Parameters:** FHSM_RV_CRYPTOKI_NOT_INITIALIZED = 0x190 (never returned)
**Edge cases handled:** none
**Suspected defect:** AGD_OPE.md:67 and :423 say 0x190 is returned; the code never returns it. Self-tests and auditing can be bypassed simply by not calling `C_Initialize`.
**Confidence:** High (the code never returns 0x190). SME question: "Must every `C_*` other than C_Initialize/C_GetFunctionList/C_GetInterface* return CKR_CRYPTOKI_NOT_INITIALIZED when the module state is POWER_OFF, as AGD_OPE documents?"
**Verified:** **Reproduced**: after `C_Finalize`, `C_OpenSession` and `C_Login(CKU_USER)` both return CKR_OK. · citations checked ✓ · extracted as LIFE-03 (State & lifecycle)

### RULE-073: What the ERROR state refuses, and what it does not
**Category:** Lifecycle
**Priority:** P0
**Source:** ERROR checks in `src/fhsm_pkcs11.c` (e.g. :576, :605, :636, :762, :795, :844, :893, :976, :1684, :1739, :1765); none in C_Sign :11309-11313, C_EncryptInit :9761-9775, C_DestroyObject :4140-4165; `src/fhsm_crypto.c:388,432,480,508,546`; `src/fhsm_drbg.c:373`; `sign_asymmetric` :11113+ calls EVP directly
**Plain English:** In ERROR the module refuses session, login, token admin, object creation, key generation, derivation, wrapping and random generation with CKR_FUNCTION_FAILED, but the per-operation crypto calls never check the state.
**Specification:**
  Given the module latched ERROR (e.g. an audit fsync failed)
  When the caller invokes C_OpenSession, C_CloseSession, C_CloseAllSessions, C_Login, C_Logout, C_InitToken, C_InitPIN, C_SetPIN, C_GetSessionInfo, C_CreateObject, C_CopyObject, C_SetAttributeValue, C_GetObjectSize, C_GenerateKey(Pair), C_DeriveKey, C_WrapKey, C_UnwrapKey, C_Encapsulate/DecapsulateKey, C_DigestInit, C_GenerateRandom, C_SeedRandom or C_WaitForSlotEvent
  Then each returns CKR_FUNCTION_FAILED (0x6)
  And when it invokes C_SignInit+C_Sign, C_VerifyInit/Verify, C_EncryptInit/Encrypt, C_DecryptInit/Decrypt, any *Update/*Final, C_Digest*, C_DestroyObject, C_GetAttributeValue, C_FindObjects* or C_GetTokenInfo
  Then the call runs normally. Asymmetric signing goes straight to OpenSSL EVP and produces a signature.
  And AES-GCM, hash-oneshot, HMAC, PBKDF2 and DRBG primitives refuse with 0x6
**Parameters:** —
**Edge cases handled:** C_Finalize also runs in ERROR (RULE-076).
**Suspected defect:** Approved crypto keeps working in the error state, which breaks the FIPS 140-3 §7.10.5 rule that no data is output while in error.
**Confidence:** High for the code paths. SME question: "Must every C_* except C_Finalize/C_GetInfo/C_GetFunctionList refuse in ERROR?"
**Verified:** citations checked ✓ · extracted as LIFE-04 (State & lifecycle)
**Merged from VAL-03** (Validations & eligibility: "ERROR state refuses calls, but only at some entry points") — Source: `src/fhsm_pkcs11.c` state checks at 576, 605, 636, 762, 795, 844, 893, 976, 1684, 1739, 1765, 2592, 2670, 2838, 3563, 4281, 4988, 5180, 5468, 5672, 6534, 7652, 7704, 7999; pairwise latch at `src/fhsm_pkcs11.c:6782-6786`; other latches in `src/fhsm_drbg.c:305,325,343,435` and `src/fhsm_audit.c:657-737`. Suspected defect: A DRBG, pairwise or audit failure that happens mid-run does not stop signing or encryption in sessions that are already open.

### RULE-074: Power-on self-tests and environment bypasses
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_crypto.c:79-285`; `src/fhsm_integrity.c:380-406`
**Plain English:** First initialization runs, in order, the module integrity check, OpenSSL FIPS provider load, base provider load, FIPS default property, DRBG health/seed, and the KAT suite; any failure latches ERROR — unless developer environment variables are set.
**Specification:**
  Given `FHSM_INTEGRITY_ALLOW_UNSIGNED` is unset and one KAT fails
  When `C_Initialize` runs
  Then ERROR latches with reason "KAT failed at module init" and C_Initialize returns 0x80000001
  And given `FHSM_INTEGRITY_ALLOW_UNSIGNED` is set
  Then an integrity failure only prints a warning: no latch, rv OK. The FIPS and base providers are skipped and the default provider is used. `C_GetInfo.libraryDescription` reads "FreeHSM C - TEST MODE, NOT PROD" (:739-742).
  And given both `FHSM_INTEGRITY_ALLOW_UNSIGNED` and `FHSM_KAT_ALLOW_FAIL` are set, KAT failures are printed but do not latch
**Parameters:** env `FHSM_INTEGRITY_ALLOW_UNSIGNED`, `FHSM_KAT_ALLOW_FAIL`; result codes 0x80000001 KAT, 0x80000002 integrity, 0x80000009 provider unavailable
**Edge cases handled:** `crypto_init_once` runs inside `pthread_once`, so the result is computed once per process image (see RULE-076/08).
**Suspected defect:** The comment at integrity.c:391 says the bypass "is REFUSED in production". No build-time gate exists; any build honours the variable.
**Confidence:** High.
**Verified:** **Code-read** (assessment SEC-007): bypass at `src/fhsm_crypto.c:84-106`. · citations checked ✓ · extracted as LIFE-05 (State & lifecycle)
**Merged from VAL-01** (Validations & eligibility: "Integrity self-test gates start-up") — Source: `src/fhsm_crypto.c:79-90`, `src/fhsm_integrity.c:345-374`, `src/fhsm_integrity.c:379-402`. Suspected defect: The bypass is not limited to unsigned builds. It also accepts a digest mismatch, i.e. a binary modified after signing (`src/fhsm_integrity.c:364-366`), and it is triggered by the variable merely existing. One environment variable therefore disables tamper detection, and no build flag limits it to dev builds.
**Merged from VAL-02** (Validations & eligibility: "Power-on known-answer tests gate start-up") — Source: `src/fhsm_crypto.c:243-275`.

### RULE-075: A pairwise consistency failure does not latch ERROR
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:6762-6787`; `src/fhsm_state.c:65-77`
**Plain English:** After key-pair generation (non-composite), a sign/verify or encrypt/decrypt pairwise test runs and is audited; on failure the key is discarded and CKR_FUNCTION_FAILED returned, but the attempted move to ERROR is rejected by the whitelist, so the module stays operational.
**Specification:**
  Given state INITIALIZED and a freshly generated non-composite key pair that fails `fhsm_pairwise_check`
  When `C_GenerateKeyPair` completes
  Then a KAT_REPORT audit event {pairwise_family} with the failing rv is written, the key is freed and not stored, and the call returns 0x6
  And `fhsm_state_set(FHSM_STATE_ERROR)` returns 0x6 (INITIALIZED→ERROR is not whitelisted), so the module stays INITIALIZED
**Parameters:** —
**Edge cases handled:** Composite keys skip the pairwise test entirely.
**Suspected defect:** The comment at :6766-6767 says "we latch the module ERROR state". The code should call `fhsm_state_latch_error`.
**Confidence:** High.
**Verified:** **Code-read**: the transition table `src/fhsm_state.c:40-47` has no INITIALIZED→ERROR entry; the pairwise path calls `fhsm_state_set(FHSM_STATE_ERROR)` at `src/fhsm_pkcs11.c:6783`. · citations checked ✓ · extracted as LIFE-06 (State & lifecycle)

### RULE-076: C_Finalize teardown and re-initialization
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:534-547, 2141-2158`; `src/fhsm_crypto.c:282-293`; `src/fhsm_audit.c:527-541`
**Plain English:** Finalize records a MODULE_FINALIZE event, frees every operation context, clears find state and the session table, closes every token (zeroizing DEKs and object values), unloads providers, closes the audit log (zeroizing its key), and drops to POWER_OFF; it always returns CKR_OK.
**Specification:**
  Given state INITIALIZED with a USER logged in and 3 open sessions
  When `C_Finalize(NULL)` runs
  Then MODULE_FINALIZE is audited, then the ops are released, the sessions wiped (no per-session LOGOUT events), tokens closed, providers unloaded, KAT results zeroized, the audit log closed, and the state set to POWER_OFF. The call returns CKR_OK.
  And a later `C_Initialize` comes up logged out: the token is reloaded from disk on next use
  And given state ERROR or POWER_OFF, the same teardown runs, the state change fails silently (ERROR stays ERROR), and CKR_OK is returned
**Parameters:** —
**Edge cases handled:** Contexts are freed (not just zeroized) because this process owns them. `g_init_pid` is reset to 0.
**Suspected defect:** (a) `pReserved` is not checked; PKCS#11 requires CKR_ARGUMENTS_BAD when it is not NULL. (b) `fhsm_crypto_init` is guarded by `pthread_once`. On re-init it returns the cached OK without re-running integrity/KAT and without reloading the FIPS/base providers that `fhsm_crypto_finalize` unloaded. (c) Finalize in POWER_OFF still returns OK, not 0x190.
**Confidence:** High for (a) and (c). Medium for the practical effect of (b). SME question: "After C_Finalize→C_Initialize in one process, must the self-tests re-run and the FIPS provider be reloaded?"
**Verified:** citations checked ✓ · extracted as LIFE-07 (State & lifecycle)

### RULE-077: Fork handling
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:398-402, 2083-2116`; `src/fhsm_state.c:113-117`; `src/fhsm_apilock.c:79-95`; `src/fhsm_session.c:219-223`
**Plain English:** When `C_Initialize` runs in a process whose PID differs from the one that initialized, all inherited tokens (DEK and values zeroized), sessions, find state and operation tables are wiped (zeroized, not freed) and state is forced to POWER_OFF — unless it is ERROR, which is inherited.
**Specification:**
  Given a parent that initialized, logged in as USER and then forked
  When the child calls `C_Initialize`
  Then the child's copies of the tokens are closed, sessions wiped, ops zeroized and state reset to POWER_OFF, then normal init proceeds. The child must log in itself.
  And given the parent was in ERROR, the child stays in ERROR and `C_Initialize` returns 0x6
  And at fork time (`pthread_atfork` child handler) only the API rwlock is rebuilt, and parked retired values are zeroized and plain-heap ones freed
**Parameters:** fork detection key = `getpid()` vs `g_init_pid`
**Edge cases handled:** Secure-heap retired values are zeroized but not freed in the child, because the allocator lock may be inconsistent.
**Suspected defect:** (a) The comment at fhsm_state.c:103-106 says the child "re-runs fhsm_crypto_init: integrity check and power-on self-tests". The `pthread_once` in crypto.c is inherited as done, so they do not re-run. (b) A child that does not call `C_Initialize` keeps the parent's sessions and logged-in token, and every call works (RULE-072). (c) The inherited audit fd is overwritten without being closed.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-08 (State & lifecycle)

### RULE-078: Deferred zeroization of object values freed under the shared lock
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_apilock.c:98-170`; `src/fhsm_token.c:514-521`
**Plain English:** An object value freed while the thread holds the shared lock is parked; it is zeroized and freed when the next exclusive call enters, or when a shared call exits and can momentarily take the lock exclusively; under exclusive or no lock it is zeroized and freed immediately.
**Specification:**
  Given a session object value released during a shared call (e.g. at re-login, `objects_free_all`)
  When the shared call exits and no other call is in flight
  Then the value is zeroized (full length) and freed (secure heap or malloc)
  And if allocating the retire record fails, the value is leaked rather than zeroized or freed early
**Parameters:** —
**Edge cases handled:** The fork child handling is in RULE-077.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-10 (State & lifecycle)

### RULE-079: Creating a token on an empty slot
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:1681-1731`; `src/fhsm_token.c:1214-1299`
**Plain English:** C_InitToken on a slot with no `slotN.tok` creates one: random serial, random salts, PBKDF2 at 200,000 iterations, a fresh random 32-byte DEK wrapped under the SO PIN, user PIN uninitialized, empty object store, optional TPM seal, atomic write.
**Specification:**
  Given slot 0 has no `slot0.tok`, no session is open, and the SO PIN is 10 bytes with no NUL
  When `C_InitToken(0, pin, 10, label32)` is called
  Then `slot0.tok` is written atomically, serial = "FHSM-" + 16 hex digits, two TOKEN_INIT audit events (library and API layer), CKR_OK
  And with a 6-byte SO PIN, `C_InitToken` passes its 4..64 range check but `fhsm_token_init` rejects it: CKR_PIN_INCORRECT (0xA0)
  And with ulPinLen < 4 or > 64 the result is CKR_PIN_LEN_RANGE (0xA2); an embedded NUL gives CKR_PIN_INVALID (0xA1); slotID ≥ 4 gives CKR_SLOT_ID_INVALID
**Parameters:** FHSM_PIN_MIN_LEN = 4; FHSM_PIN_MAX_LEN = 64; fresh-token SO PIN minimum = 8 (literal at token.c:1217); pbkdf2_iter = 200000; DEK_LEN = 32; FHSM_MAX_SLOTS = 4; label is 32 bytes with trailing spaces stripped
**Edge cases handled:** The token stays attached to the slot without a reload.
**Suspected defect:** (a) The SO PIN minimum is 8 on a fresh token but 4 on re-init and in C_GetTokenInfo. (b) After init the token has `dek_live=1` and `objects_loaded=1` with `logged_in=NONE`: the DEK stays in memory with nobody logged in, and public objects can be created without a login until something clears `dek_live`.
**Confidence:** High. SME question: "Which SO PIN minimum is authoritative, 4 or 8? And must the DEK be dropped after C_InitToken?"
**Verified:** citations checked ✓ · extracted as LIFE-11 (State & lifecycle)
**Merged from VAL-12** (Validations & eligibility: "C_InitToken guards") — Source: `src/fhsm_pkcs11.c:1681-1731`, `src/fhsm_token.c:1817-1881`. Suspected defect: If the SO role is locked (5 failures), the SO PIN check returns CKR_PIN_LOCKED, so re-initialisation is impossible. `docs/FIPS_140_3.md:63` says C_InitToken clears the lock.

### RULE-080: Re-initializing an existing token wipes it
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:1697, 1714-1718`; `src/fhsm_token.c:1817-1893`; `src/fhsm_session.c:97-104`
**Plain English:** Re-initialization is refused while any session is open on the slot; otherwise the presented PIN is verified as the current SO PIN (counted and throttled like a login), then every object is destroyed and a new serial, SO salt, DEK, label and SO wrap are created, the user PIN becomes uninitialized, both failure counters reset to 0, and the token is logged out.
**Specification:**
  Given a token with 12 objects, user PIN set, `failed_user=3`
  When `C_InitToken` is called with any session open on that slot
  Then it returns CKR_SESSION_EXISTS (0xB6) before the PIN is checked, so no attempt is counted
  And with no session open and a wrong SO PIN: CKR_PIN_INCORRECT, `failed_so` goes up by 1 and is persisted
  And with the correct SO PIN: the store becomes empty (values zeroized), user_initialized=0, failed_so=failed_user=0, new serial, TOKEN_REINIT audit event, CKR_OK
  And with the SO PIN locked (failed_so ≥ 5): CKR_PIN_LOCKED. There is no in-module recovery; only deleting the file helps.
**Parameters:** as RULE-079
**Edge cases handled:** Old wraps and salts are zeroized before regeneration.
**Suspected defect:** (a) The `.tpm` companion file is neither resealed nor removed (`fhsm_token_tpm_unlink` has no callers), so it still holds the old DEK. Every later login hits the TPM cross-check and fails with CKR_DEVICE_ERROR (RULE-089). (b) As in RULE-079, the DEK stays live after re-init with nobody logged in.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-12 (State & lifecycle)

### RULE-081: C_InitPIN sets the user PIN and unlocks the user
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:1736-1756`; `src/fhsm_token.c:1714-1753`
**Plain English:** Only when the token is logged in as SO (with a live DEK), the user PIN is (re)set by wrapping the DEK under a fresh salt; the user failure count and throttle reset to zero, which is the only way to unlock a locked user PIN.
**Specification:**
  Given SO logged in and the user locked (failed_user=5)
  When `C_InitPIN(h, pin, 6)` is called
  Then user_initialized=1, failed_user=0, the token file is rewritten, a SET_PIN audit event is written, CKR_OK
  And with no SO login the result is CKR_USER_NOT_LOGGED_IN (0x101); length outside 4..64 gives 0xA2; an embedded NUL gives 0xA1
**Parameters:** min 4, max 64
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-13 (State & lifecycle)
**Merged from VAL-13** (Validations & eligibility: "C_InitPIN guards") — Source: `src/fhsm_pkcs11.c:1736-1756`, `src/fhsm_token.c:1714-1753`.

### RULE-082: C_SetPIN cannot succeed
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:1761-1789`; `src/fhsm_token.c:1765-1809, 1376-1379`; `src/fhsm_session.c:225-242`
**Plain English:** C_SetPIN requires the session's role (which is the token's logged-in role) to be SO or USER, then verifies the old PIN by calling the login routine for that same role — which immediately returns "already logged in".
**Specification:**
  Given USER logged in on session h
  When `C_SetPIN(h, old, 6, new, 6)` is called
  Then `fhsm_token_login(t, USER, old)` sees `logged_in == USER` and returns CKR_USER_ALREADY_LOGGED_IN (0x100). C_SetPIN returns 0x100 and the PIN does not change. A SET_PIN audit event is written with that failure.
  And with nobody logged in the result is CKR_USER_NOT_LOGGED_IN (0x101)
**Parameters:** min 4, max 64
**Suspected defect:** The PIN can never be changed. Also, the comment at token.c:1756-1763 says an SO C_SetPIN "also rotates the DEK"; the code only re-wraps.
**Confidence:** High. No test covers a successful C_SetPIN. SME question: "Should SO C_SetPIN rotate the DEK (and re-encrypt the store)?"
**Verified:** **Reproduced** (built library, pinned container): `C_SetPIN(old,new)` as logged-in USER → 0x100; afterwards the new PIN is refused (0xA0) and the old PIN still logs in. · citations checked ✓ · extracted as LIFE-14 (State & lifecycle)
**Merged from VAL-14** (Validations & eligibility: "C_SetPIN can never succeed") — Source: `src/fhsm_pkcs11.c:1761-1789`, `src/fhsm_token.c:1765-1776`, `src/fhsm_token.c:1376-1379`. Suspected defect: The guard at `src/fhsm_pkcs11.c:1775` requires a login, and `fhsm_token_login` then returns early with 0x100 because the role already holds the token. PIN rotation is unreachable. No test exercises a successful C_SetPIN.

### RULE-083: Login state belongs to the token and has conflict rules
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:890-972`; `src/fhsm_session.c:117-151`; `src/fhsm_token.c:1366-1410`
**Plain English:** One role at a time per token, shared by all sessions; checks run in a fixed order before any PIN work.
**Specification:**
  Given USER logged in through session 1
  When session 2 calls `C_Login(CKU_USER)` → CKR_USER_ALREADY_LOGGED_IN (0x100), and session 2's cached role is set to USER
  When any session calls `C_Login(CKU_SO)` → CKR_USER_ANOTHER_ALREADY_LOGGED_IN (0x104), with no attempt counted
  And given a read-only session exists on the token, `C_Login(CKU_SO)` → CKR_SESSION_READ_ONLY_EXISTS (0xB7)
  And given the user PIN was never initialized, `C_Login(CKU_USER)` → CKR_USER_NOT_LOGGED_IN (0x101), not CKR_USER_PIN_NOT_INITIALIZED (0x102)
  And a userType other than 0, 1 or 2 → CKR_ARGUMENTS_BAD
  And every attempt writes LOGIN_OK, LOGIN_FAIL or LOGIN_LOCKED with role and pin_len (never the PIN)
**Parameters:** check order = already-logged-in → other-role → locked → throttle wait → user PIN not set → PBKDF2
**Edge cases handled:** The lock check comes before the user-PIN-not-set check, so a locked but uninitialized user PIN returns 0xA4.
**Suspected defect:** 0x101 is returned where PKCS#11 specifies 0x102 (token.c:1406-1409).
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-15 (State & lifecycle)
**Merged from VAL-07** (Validations & eligibility: "Login role exclusivity; login is per token") — Source: `src/fhsm_pkcs11.c:948-951`, `src/fhsm_token.c:1376-1391`, `src/fhsm_token.c:1406-1410`, `src/fhsm_session.c:225-242`. Suspected defect: For an uninitialised user PIN the spec code is CKR_USER_PIN_NOT_INITIALIZED (0x102); the code returns 0x101.

### RULE-084: PIN failure counter, throttle and lock
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_token.c:256-281, 1393-1405, 1537-1546, 1340-1346, 1114-1127`; `include/fhsm_common.h:373-396`; `src/fhsm_pkcs11.c:1248-1253`
**Plain English:** Each wrong PIN adds one to that role's persisted counter and sets a delay; the next attempt sleeps until the delay passes (it is not refused); at 5 failures the role is locked.
**Specification:**
  Given failed_user = 0
  When 4 wrong USER PINs are presented
  Then each returns CKR_PIN_INCORRECT (0xA0), the counter reaches 4, and the delays before the next attempt are 0.5 s, 1 s, 2 s and 4 s
  And the 5th wrong PIN returns CKR_PIN_LOCKED (0xA4); later attempts return 0xA4 at once with no PBKDF2
  And a correct PIN before the lock sets the counter and delay to 0 and persists them
  And after a process restart the counter is reloaded and the delay re-derived from it (delays are never written to disk)
  And `C_GetTokenInfo` sets CKF_USER_PIN_LOCKED or CKF_SO_PIN_LOCKED when the counter is ≥ 5
**Parameters:** FHSM_PIN_MAX_FAILED = 5; FHSM_PIN_THROTTLE_BASE_MS = 500; FHSM_PIN_THROTTLE_MAX_MS = 60000 (unreachable while MAX_FAILED=5); delay = 500 × 2^(n-1) ms; monotonic clock
**Edge cases handled:** C_Login(CKU_CONTEXT_SPECIFIC) and the SO-PIN check in C_InitToken use the same counter.
**Suspected defect:** CKF_USER_PIN_COUNT_LOW, CKF_USER_PIN_FINAL_TRY and their SO equivalents are never set. FHSM_RV_PIN_THROTTLED is never returned any more (the throttle waits instead), yet C_Login still maps it.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-16 (State & lifecycle)
**Merged from CALC-06** (Calculations: "PIN throttle delay") — Source: `src/fhsm_token.c:256-264`, `include/fhsm_common.h:374-378`. Suspected defect: With MAX_FAILED = 5 the largest reachable delay is 4 s (the deadline set at the 5th failure, 8 s, is never waited because the lock check comes first). The 60 s cap and the doc formula (`docs/FIPS_140_3.md:66`) imply more. This is informational.
**Merged from CALC-07** (Calculations: "PIN failure counter and lockout") — Source: `src/fhsm_token.c:1393-1405`, `src/fhsm_token.c:1519-1546`, `src/fhsm_token.c:1572-1642`, `src/fhsm_token.c:1693-1695`, `src/fhsm_token.c:1745-1747`, `src/fhsm_token.c:1881-1883`, `src/fhsm_pkcs11.c:1250-1253`. Suspected defect: A locked SO is unrecoverable. Reinit of an existing token first calls `fhsm_token_verify_pin(SO)` (`fhsm_pkcs11.c:1718`), which returns PIN_LOCKED. That contradicts `docs/FIPS_140_3.md:63` ("C_InitToken (for both) clears the lock").
**Merged from VAL-08** (Validations & eligibility: "PIN failure counter, throttle and lockout") — Source: `src/fhsm_token.c:257-264`, `src/fhsm_token.c:1393-1405`, `src/fhsm_token.c:1523-1546`, `src/fhsm_token.c:1580-1642`, `src/fhsm_token.c:1340-1346`, `include/fhsm_common.h:373-394`.

### RULE-085: Side effects of a successful login
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_token.c:1417-1535, 942-1019`
**Plain English:** A correct PIN unwraps the DEK into the secure heap, marks it live, sets the role, decrypts the object store the first time, and rewrites the token file.
**Specification:**
  Given a token loaded with only its public view
  When the correct USER PIN is presented
  Then the DEK is unwrapped (PBKDF2-SHA256 KEK, AES-256-GCM, AAD = serial), dek_live=1, logged_in=USER, the store is decrypted and loaded once (objects_loaded=1), and `write_atomic` persists the reset counter
  And if the blob does not decrypt under the real DEK but does under 32 zero bytes, it is loaded and re-encrypted under the real DEK on the next write
  And if loading the store fails, login still succeeds with an empty or partial view
**Parameters:** DEK_LEN = 32; GCM tag = 16
**Suspected defect:** The return value of `write_atomic` after login is ignored (:1532), so a counter that failed to persist is not reported.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-17 (State & lifecycle)

### RULE-086: Logout zeroizes the DEK but leaves decrypted objects usable
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_token.c:1645-1654, 1945-1966`; `src/fhsm_session.c:166-186`; `src/fhsm_pkcs11.c:974-981, 9010-9023, 10793-10850`
**Plain English:** Logout zeroizes the 32-byte DEK in place (buffer stays allocated), clears dek_live and the role; it does not unload decrypted object values or end active operations.
**Specification:**
  Given USER logged in, holding private key handle 7
  When `C_Logout(h)` is called
  Then the DEK is zeroized, dek_live=0, logged_in=NONE, a LOGOUT audit event (role NONE) is written, CKR_OK
  And with nobody logged in the result is CKR_USER_NOT_LOGGED_IN (0x101), and the calling session's cached role is cleared
  And afterwards object mutations (create, destroy, set usage or flags, mark session) return 0x101 because dek_live=0
  And `C_GetAttributeValue` / `C_GetObjectSize` on handle 7 return CKR_OBJECT_HANDLE_INVALID (role ≠ USER)
  But `C_SignInit(h, mech, 7)` followed by `C_Sign` succeeds, because the key lookup only checks objects_loaded=1. Decrypt behaves the same way, and operations started before logout keep running.
**Parameters:** —
**Suspected defect:** SEC-001: `fhsm_token_logout` leaves `objects_loaded` set and decrypted private key values in memory. Combined with Init functions that never check the role, private keys stay usable after logout. Separately, a logged-in SO can initialise sign/decrypt with private keys, because there is no role check.
**Confidence:** High.
**Verified:** **Reproduced** (SEC-001): after `C_Logout`, `C_EncryptInit` + `C_Encrypt` with the user's AES token key → CKR_OK. · citations checked ✓ · extracted as LIFE-18 (State & lifecycle)
**Merged from VAL-10** (Validations & eligibility: "Logout rules") — Source: `src/fhsm_session.c:166-186`, `src/fhsm_session.c:85-90`, `src/fhsm_token.c:1645-1654`. Suspected defect: Objects stay loaded after logout. This is the root of SEC-001 (RULE-056).

### RULE-087: Re-authentication for CKA_ALWAYS_AUTHENTICATE keys
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:917-946, 2161-2206, 9056-9064`
**Plain English:** Each operation records at Init whether its key requires per-operation authentication; C_Login(CKU_CONTEXT_SPECIFIC) verifies the user PIN without changing login state and marks every active operation of that session as authenticated; sign and decrypt calls refuse and terminate an unauthenticated operation.
**Specification:**
  Given USER logged in and C_SignInit done with a key that has CKA_ALWAYS_AUTHENTICATE=TRUE
  When `C_Sign` is called without re-authentication → CKR_USER_NOT_LOGGED_IN (0x101) and the operation is terminated
  When `C_Login(h, 2, pin)` is called first (correct PIN) → CKR_OK, ctx_auth_done=1 on all active operations, and the next C_Sign proceeds
  And with no active operation → CKR_OPERATION_NOT_INITIALIZED; if the token role is not USER → 0x101; a wrong PIN counts toward the lock
**Parameters:** CKU_CONTEXT_SPECIFIC = 2
**Edge cases handled:** No TPM cross-check on re-authentication. Single-call C_UnwrapKey and C_DeriveKey are not gated.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-19 (State & lifecycle)
**Merged from VAL-09** (Validations & eligibility: "CKA_ALWAYS_AUTHENTICATE re-authentication") — Source: `src/fhsm_pkcs11.c:917-946`, `src/fhsm_pkcs11.c:2200-2206`, `src/fhsm_pkcs11.c:9056-9064`, `src/fhsm_pkcs11.c:11315`.

### RULE-088: Token file persistence (save points)
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_token.c:1092-1209, 591-593`
**Plain English:** Every state change writes the full token image to `<path>.tmp` (mode 0600), fsyncs, and renames over the original; when the DEK is not live, the existing encrypted blob is copied byte-for-byte instead of being re-encrypted; session objects are never written.
**Specification:**
  Given a wrong PIN on a token never logged in during this process
  When the counter is persisted
  Then the 317-byte header holds the new counter and the encrypted blob is copied unchanged from disk
  And given a live DEK with 3 token objects and 1 session object, the blob holds the 3 token objects under a fresh 12-byte nonce, plus a cleartext public section (non-sensitive public keys and certificates)
  And throttle deadline fields (offsets 301 and 309) are always written as 0
**Parameters:** header 317 bytes; magic "FHSM"; version 1
**Edge cases handled:** A failed write deletes the tmp file and returns 0x6.
**Suspected defect:** The `fsync` return value is ignored (:1206) and the directory is not fsynced after the rename.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-20 (State & lifecycle)

### RULE-089: TPM-sealed DEK companion file
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_token_tpm.c:59-135`; `src/fhsm_token.c:1275-1285, 1455-1522`
**Plain English:** With `FHSM_TPM_SEALING` = 1/y/Y, token creation seals the DEK to the TPM in `<tok>.tpm` (fails hard if no TPM); at login, if `<tok>.tpm` exists it must unseal and match the PIN-unwrapped DEK, otherwise login fails closed with CKR_DEVICE_ERROR without touching the PIN counter.
**Specification:**
  Given `slot0.tok.tpm` exists and the TPM is unavailable
  When the correct USER PIN is presented
  Then the DEK is zeroized, an UNSEAL_FAILURE audit event ("tpm-unseal-failed") is written, the result is CKR_DEVICE_ERROR (0x30), and failed_user is unchanged
  And if it unseals but the DEKs differ → UNSEAL_FAILURE ("tpm-dek-mismatch"), 0x30
  And if `FHSM_TPM_SEALING=1` but no `.tpm` file exists → 0x30 ("tpm-required-but-missing")
  And if sealing is required at token creation and the TPM is unavailable → SEAL_FAILURE event, creation fails with 0x80000005 and no token is created
**Parameters:** env `FHSM_TPM_SEALING`; temp file `<tok>.tpm.new`, renamed; blob ≤ 2048 bytes
**Suspected defect:** (a) The header comment (:37-40) says a mismatch returns PIN_INCORRECT; the code returns DEVICE_ERROR. (b) Re-init never reseals (RULE-080). (c) The seal file is written before the `.tok`; if writing the `.tok` fails, an orphan `.tpm` remains. (d) `.tpm.new` is not fsynced. (e) The TPM-failure paths zeroize the DEK but leave `dek_live` as it was; right after C_InitToken that is still 1.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-21 (State & lifecycle)

### RULE-090: Closing sessions destroys session objects and logs out on the last one
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:603-613, 793-813, 8971-8989`; `src/fhsm_session.c:67-93`; `src/fhsm_token.c:2036-2062`
**Plain English:** Closing a session frees its operation contexts, zeroizes its find/OAEP state, destroys every session object it owns, zeroizes the table entry, and if no other session references the token, logs the token out and audits LOGOUT with cause "last-session-closed".
**Specification:**
  Given USER logged in, session 5 is the only session, owning 2 session objects
  When `C_CloseSession(5)` is called
  Then both objects are zeroized and removed (no audit event for them), the token is logged out (DEK zeroized; objects stay loaded per SEC-001), LOGOUT {cause:last-session-closed} is audited, CKR_OK
  And an invalid or closed handle → CKR_SESSION_HANDLE_INVALID (0xB3), though ops reset still runs on that slot index first
  And `C_CloseAllSessions(0)` closes every session that has a token attached, on any slot; `C_CloseAllSessions(1..3)` → CKR_SLOT_ID_INVALID (0x3)
**Parameters:** —
**Suspected defect:** C_CloseAllSessions has no slot filter and only accepts slot 0, yet C_OpenSession accepts slots 0–3.
**Confidence:** High.
**Verified:** **Reproduced** (slot part): `C_CloseAllSessions(1)` → 0x3 CKR_SLOT_ID_INVALID. · citations checked ✓ · extracted as LIFE-24 (State & lifecycle)

### RULE-091: Object creation, handles and capacity
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_token.c:1898-1943, 2010-2031`; `src/fhsm_pkcs11.c:2456-2484, 2551-2554`; `include/fhsm_token.h:133-135`
**Plain English:** Objects can only be added while the DEK is live and the store is loaded; handles are sequential and never reused (next_handle persists); every creation rewrites the token file and audits OBJECT_CREATE; a session object (CKA_TOKEN false, the default) is first added (and written) as a token object, then marked as owned by the session and the file rewritten without it.
**Specification:**
  Given USER logged in, next_handle = 41, 1023 objects in the store
  When C_CreateObject makes a session data object → handle 41, owner = session, CKR_OK
  When another object is created → CKR_DEVICE_MEMORY (0x31)
  And a private object from a public session → CKR_USER_NOT_LOGGED_IN; CKA_TOKEN=TRUE from a read-only session → CKR_SESSION_READ_ONLY (0xB5); a value over 2 MiB → CKR_KEY_SIZE_RANGE; CKA_ID over 32 bytes → ARGUMENTS_BAD
**Parameters:** FHSM_MAX_OBJECTS = 1024 (session and token objects share the cap); FHSM_OBJ_VALUE_MAX = 2 MiB; sensitive values go in the secure heap, and when it is exhausted the result is 0x31
**Suspected defect:** A session object's value is briefly persisted (encrypted) before being marked. The marking result is ignored (`(void)` at :2554), so if that rewrite fails the object stays a persistent token object.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-28 (State & lifecycle)
**Merged from CALC-32** (Calculations: "Capacities and handle allocation") — Source: `include/fhsm_common.h:424`, `src/fhsm_session.c:46-56`, `src/fhsm_pkcs11.c:345`, `src/fhsm_pkcs11.c:1254-1256`, `include/fhsm_token.h:134`, `src/fhsm_token.c:89-93`, `src/fhsm_token.c:1900-1937`. Suspected defect: 128 is advertised but at most 127 sessions can be opened. Handles wrap at 2^32 with no collision check.

### RULE-092: Object destruction
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:4140-4165`; `src/fhsm_token.c:2658-2687`
**Plain English:** A token object cannot be destroyed from a read-only session; an object marked CKA_DESTROYABLE=FALSE is never destroyable; destruction needs a live DEK, zeroizes the value and record, compacts the array, rewrites the file and audits OBJECT_DESTROY.
**Specification:**
  Given USER logged in through a read-only session
  When `C_DestroyObject` targets a token object → CKR_SESSION_READ_ONLY (0xB5)
  When it targets a CKA_DESTROYABLE=FALSE object → CKR_ACTION_PROHIBITED (0x1B)
  When nobody is logged in → CKR_USER_NOT_LOGGED_IN; for an unknown handle → CKR_KEY_HANDLE_INVALID (0x60)
**Suspected defect:** No ERROR-state check. No check that a session object belongs to the calling session. The private-object visibility check is not applied (an SO can destroy private keys). An unknown handle returns 0x60 rather than CKR_OBJECT_HANDLE_INVALID (0x82).
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-29 (State & lifecycle)
**Merged from VAL-28** (Validations & eligibility: "C_DestroyObject guards") — Source: `src/fhsm_pkcs11.c:4140-4166`, `src/fhsm_token.c:2658-2687`. Suspected defect: There is no private-object visibility check, so the SO can destroy user keys.

### RULE-093: Audit key provisioning
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_audit.c:199-367`
**Plain English:** The 32-byte chaining key is read from `<dir>/audit.key.tpm` (when TPM sealing is required) or `<dir>/audit.key` (mode must be 0600 or stricter, exactly 32 bytes); on first use it is generated from the module DRBG and created with O_EXCL; if creation races, the winner's key is re-read; failures stop C_Initialize (ERROR).
**Specification:**
  Given `audit.key` has mode 0640
  When C_Initialize runs → the read is refused, O_EXCL creation hits EEXIST, the re-read is refused again, provisioning fails, ERROR latches, and C_Initialize returns 0x6
  And given sealing is required and `audit.key.tpm` will not unseal → refused, with no fallback to a new key
  And given sealing is required and sealing fails → refused, with no plaintext fallback
**Parameters:** key 32 bytes; files created 0600 with fsync
**Edge cases handled:** If sealing is turned off and only `audit.key.tpm` exists, a new plaintext key is generated. That silently starts a new key.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-30 (State & lifecycle)

### RULE-094: One audit file per opening
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_audit.c:427-525`
**Plain English:** Each C_Initialize creates a new file `<base>.NNNNNN` (next sequence number above the highest existing) with O_EXCL and mode 0600, starting a fresh HMAC chain at HMAC(key, "FHSM-AUDIT-INIT|seq=0"); a base that exists and is not a regular file is used as a stream, without numbering.
**Specification:**
  Given `audit.log.000006` exists
  When the module initializes → it creates `audit.log.000007`, seq starts at 1, and the first prev_hmac is the chain head
  And on an EEXIST race it steps to the next number (up to 4096 attempts)
  And given base = /dev/null → lines are written, with nothing durable or verifiable, and a NOTE is printed on stderr
**Parameters:** FHSM_AUDIT_SEQ_DIGITS = 6; line max 2048 bytes; params max 1024 bytes
**Suspected defect:** The C_Initialize FATAL text (pkcs11.c:518-520) mentions "an existing log whose last line cannot be parsed". The code no longer resumes or parses existing files.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-31 (State & lifecycle)
**Merged from CALC-12** (Calculations: "Audit file numbering and sequence") — Source: `src/fhsm_audit.c:427-454`, `src/fhsm_audit.c:465-487`, `src/fhsm_audit.c:508`, `src/fhsm_audit.c:610`. Suspected defect: Deleting the newest file(s) is undetectable. The verifier only notices gaps and a start that is not 000001.

### RULE-095: The audit-off switch
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_pkcs11.c:443-463`; `include/fhsm_common.h:366-368`; `src/fhsm_audit.c:562`; `Makefile:1511-1516`
**Plain English:** `FHSM_AUDIT=off` or `0` is refused in a mandatory build (the default) by latching ERROR; in a build compiled with FHSM_AUDIT_MANDATORY=0 it is honoured with a loud stderr notice and no log is opened.
**Specification:**
  Given the default build (FHSM_AUDIT_MANDATORY=1) and `FHSM_AUDIT=off`
  When C_Initialize runs → ERROR latches ("audit switched off in a mandatory build") and it returns 0x6
  And given a build with -DFHSM_AUDIT_MANDATORY=0 → C_Initialize succeeds and every event is silently dropped
**Parameters:** FHSM_AUDIT_MANDATORY = 1
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-32 (State & lifecycle)
**Merged from VAL-04** (Validations & eligibility: "The audit log is mandatory") — Source: `src/fhsm_pkcs11.c:443-455`, `src/fhsm_pkcs11.c:470-494`, `src/fhsm_pkcs11.c:515-524`.

### RULE-096: Audit write failure
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_audit.c:585-743`; every call site uses `(void)fhsm_audit_event(...)`
**Plain English:** A failed audit line (truncation, HMAC failure, short write, failed fdatasync) latches ERROR; the operation that produced the event still returns its own result; while ERROR is latched, the module refuses only the calls listed in RULE-073; events emitted while the log is closed are dropped with success.
**Specification:**
  Given the disk fills during `C_GenerateKey` audit
  When `fdatasync` fails
  Then ERROR latches ("audit fsync failed"), the key is still created, and C_GenerateKey returns CKR_OK. The next C_GenerateKey returns 0x6.
  And a nested event raised during the failure (the latch's own STATE_TRANSITION) is dropped on that thread
  And events before C_Initialize or after C_Finalize return OK and are not written
**Parameters:** group-commit barrier with `fdatasync`; latched ERROR is sticky
**Suspected defect:** The action that could not be audited is still carried out and reported as successful.
**Confidence:** High. SME question: "Must a security-relevant operation fail (and be rolled back) when its audit record cannot be made durable?"
**Verified:** citations checked ✓ · extracted as LIFE-33 (State & lifecycle)

### RULE-097: Service startup order and one-shot PIN login
**Category:** Lifecycle
**Priority:** P0
**Source:** `service/fhsm_service.c:2557-2569, 2628, 2637-2665, 2669-2684, 1746-1815, 2736-2742`
**Plain English:** The service loads its policy (refuses to start if it cannot), loads the refusal budget, installs signal handlers, calls C_Initialize, requires exactly one slot with a token, reads the PIN once from `$CREDENTIALS_DIRECTORY/fhsm-pin` (or `--pin-file`), logs in as USER exactly once (no retry), keeps that session as pool slot 0, opens the sockets (mode 0660), audits SERVICE_START, then starts the workers.
**Specification:**
  Given a PIN file containing the PIN followed by "\n"
  When the service starts → trailing CR/LF is trimmed, C_Login(CKU_USER) is called once, and the PIN buffer is zeroized right after
  And if C_Login fails → that session is closed, an error naming the rv is printed, and the process exits 1 without retrying
  And with no `CREDENTIALS_DIRECTORY` and no `--pin-file` → exit 1. The PIN is never read from the environment.
  And 0 or more than 1 slot with a token → exit 1
**Parameters:** PIN read ≤ 128 bytes; pool cap 127; listen backlog 64
**Edge cases handled:** A PIN file longer than 128 bytes is silently truncated, and the resulting failure counts toward the lock. Failures after C_Initialize exit without C_Finalize.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-34 (State & lifecycle)

### RULE-098: Policy reload on SIGHUP keeps the old policy if the new one fails
**Category:** Lifecycle
**Priority:** P0
**Source:** `service/fhsm_service.c:184-266, 953, 2184`
**Plain English:** SIGHUP only sets a flag; the next authenticated request reloads the policy file; if the file is missing or any line is malformed, too long, or beyond 512 rules, the whole file is rejected and the previous policy stays in force.
**Specification:**
  Given 10 rules in force and an edited file whose line 4 has no tab
  When SIGHUP is sent and a request arrives → stderr says "reloading … failed; the previous policy is still in force", and the 10 rules still apply
  And a valid file with 0 rules is accepted, and all requests are then refused
**Parameters:** POLICY_MAX = 512; rule = SUBJECT<TAB>KEY-LABEL; `#` starts a comment
**Edge cases handled:** The public listener never triggers a reload. An idle service applies the new policy only when a request arrives.
**Suspected defect:** A reload failure is reported only on stderr and is not audited.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-35 (State & lifecycle)

### RULE-099: Revocation is one-way, and duplicates are refused
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_revocation.c:47-58, 165-269`; `tools/fhsm_ca.c:278-359`
**Plain English:** A serial is "good" until `fhsm-ca revoke` records it with a date (default now, UTC) and an optional RFC 5280 reason; a serial already recorded (leading zeros ignored) is refused with exit 5 and the database is unchanged; nothing removes an entry.
**Specification:**
  Given the DB holds 4A3B2C1D
  When `fhsm-ca revoke --serial 004A3B2C1D --reason keyCompromise` → "already revoked", exit 5, file unchanged
  And `--reason removeFromCRL` (8) or an unknown name → exit 2
  And a new serial → appended, the DB saved atomically, exit 0
**Parameters:** reasons {0,1,2,3,4,5,6,9,10}; -1 = no reason; FHSM_REV_MAX_ENTRIES = 100000 (exceeding it → exit 3); date YYYYMMDDHHMMSSZ
**Edge cases handled:** certificateHold (6) is accepted but there is no release path.
**Suspected defect:** No file locking. Two concurrent `revoke` runs both load, add and save, and one revocation is lost (last rename wins).
**Confidence:** High for the code. SME question: "Is a hold release needed for certificateHold?"
**Verified:** citations checked ✓ · extracted as LIFE-38 (State & lifecycle)

### RULE-100: Database save, load and CRL numbering
**Category:** Lifecycle
**Priority:** P0
**Source:** `src/fhsm_revocation.c:165-251`; `tools/fhsm_ca.c:395-413`; `service/fhsm_service.c:889-933, 2550-2554`
**Plain English:** The database is saved to `<db>.tmp`, flushed, fsynced and renamed; a missing file loads as empty (first run); any malformed line rejects the whole file; `fhsm-ca crl` increments crlNumber, signs, and saves the database only after signing succeeds; the service keeps its previous database when a reload fails to parse.
**Specification:**
  Given crlNumber 7
  When `fhsm-ca crl` signing fails → the process exits through `fail()` before `db_save`, and crlNumber stays 7 on disk
  When signing succeeds → crlNumber 8 is saved before the CRL bytes are written out
  And the service, given a corrupted DB after a good one → logs the error, keeps the old in-memory DB, and does not re-read the same broken file (mtime and size recorded); at startup an unreadable DB → exit 2
**Parameters:** —
**Suspected defect:** The comment at fhsm_ca.c:398-402 says the number is "consumed" even when signing fails. The code consumes it only on success. With no locking, two concurrent `crl` runs can publish two different CRLs under the same number, which is exactly what the comment says the ordering prevents.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-39 (State & lifecycle)

### RULE-101: Exclusive and shared entry modes
**Category:** Lifecycle
**Priority:** P1
**Source:** `src/fhsm_apilock.c:118-145`; `include/fhsm_apilock.h:78-83`; lock sites in `src/fhsm_pkcs11.c` (394, 535, 604, 794, 1683, 4141 exclusive)
**Plain English:** Six functions take the module-wide writer lock exclusively — C_Initialize, C_Finalize, C_CloseAllSessions, C_CloseSession, C_InitToken, C_DestroyObject; every other C_* (including C_Login, C_Logout, C_InitPIN, C_SetPIN, C_OpenSession, all crypto) takes it shared; C_GetFunctionList/C_GetInterface/C_GetInterfaceList take none.
**Specification:**
  Given thread A inside `C_Sign` (shared) and thread B calling `C_DestroyObject`
  When B arrives
  Then B waits until A leaves. While B waits, new shared callers also wait (writer-preferring).
  And given a nested `C_*` call on the same thread (C_CloseAllSessions→C_CloseSession), the inner call does not lock again
**Parameters:** lock kind `PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP`
**Edge cases handled:** A thread-local mode prevents self-deadlock on nested calls.
**Suspected defect:** C_Login sleeps through the PIN throttle (up to 4 s; see RULE-084) while holding the shared lock. A queued exclusive caller then stalls the whole module for that time.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-09 (State & lifecycle)

### RULE-102: Opening a session
**Category:** Lifecycle
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:755-791`; `src/fhsm_session.c:48-65`; `include/fhsm_common.h:423-424`
**Plain English:** A session needs CKF_SERIAL_SESSION, a slot below 4 with a token present, and must be read-write if the SO is logged in; it gets the lowest free handle in 1..127, starts with clean operation state, and is attached to the slot's token.
**Specification:**
  Given handles 1–3 are open and handle 2 is then closed
  When `C_OpenSession(0, CKF_SERIAL_SESSION, …)` is called
  Then handle 2 is reused
  And with flags lacking 0x4 → CKR_SESSION_PARALLEL_NOT_SUPPORTED (0xB4); with no token → CKR_TOKEN_NOT_PRESENT (0xE0); a read-only open while the SO is logged in → CKR_SESSION_READ_WRITE_SO_EXISTS (0xB8); a 128th concurrent session → CKR_HOST_MEMORY (0x2)
**Parameters:** FHSM_MAX_SESSIONS = 128 (usable handles 1..127); C_GetTokenInfo reports ulMaxSessionCount = 128 and session counts = 0 (pkcs11.c:1254-1257)
**Suspected defect:** Exhaustion returns 0x2 rather than CKR_SESSION_COUNT (0xB1). The advertised maximum (128) is one more than usable, and the live session counts are always reported as 0.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-22 (State & lifecycle)
**Merged from VAL-05** (Validations & eligibility: "C_OpenSession guards") — Source: `src/fhsm_pkcs11.c:755-791`.

### RULE-103: Session state is derived, not stored
**Category:** Lifecycle
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:842-880`; `src/fhsm_session.c:244-267`
**Plain English:** C_GetSessionInfo derives CKS_* from the session's RW flag and the token's current role.
**Specification:**
  Given a read-only session and USER logged in through another session → state 1 (CKS_RO_USER_FUNCTIONS)
  RO + none → 0; RW + none → 2; RW + USER → 3; any + SO → 4; ulDeviceError = 0
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-23 (State & lifecycle)

### RULE-104: Operation slots: Init, active, not initialized
**Category:** Lifecycle
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:2066-2070, 9037-9050, 9577-9579, 2668-2700, 8295-8410`
**Plain English:** Each session has five independent operation slots (encrypt, decrypt, sign, digest, verify) plus a find slot; an Init on an active slot is refused, a continuation on an inactive slot is refused.
**Specification:**
  Given C_SignInit succeeded on session 3
  When C_SignInit is called again → CKR_OPERATION_ACTIVE (0x90), and the existing operation is untouched
  When C_EncryptInit is called on session 3 → allowed (separate slot)
  When C_Sign or C_SignUpdate is called with no active sign operation → CKR_OPERATION_NOT_INITIALIZED (0x91). This also happens for a closed session handle (op state reset), instead of 0xB3.
  And Init releases the previous AAD, multipart buffer and digest context before reusing the slot; the find snapshot is taken at C_FindObjectsInit
**Parameters:** —
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-25 (State & lifecycle)

### RULE-105: When an operation ends
**Category:** Lifecycle
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:11313-11479` (C_Sign), `:12046-12067` (C_DigestFinal), `:9781-9791` (C_Encrypt)
**Plain English:** A successful single-part call or Final ends the operation; a length query (NULL output) and CKR_BUFFER_TOO_SMALL (0x150) leave it active; other errors end it.
**Specification:**
  Given an active ECDSA sign operation
  When `C_Sign(h, data, 32, NULL, &len)` → CKR_OK with the required length, operation still active
  When it is retried with an 8-byte buffer → 0x150, operation still active
  When it is retried with an adequate buffer → signature, operation ended
  When `pData == NULL` with ulDataLen = 5 → CKR_ARGUMENTS_BAD, operation ended
**Edge cases handled:** A key destroyed between Init and use gives the lookup error and ends the operation.
**Suspected defect:** In C_Sign and C_DigestFinal, a NULL `pulSignatureLen` / `pulDigestLen` returns CKR_ARGUMENTS_BAD without ending the operation (:11328, :12049). C_Encrypt ends it in the same case (:9788). The behaviour is inconsistent.
**Confidence:** High for the cited paths. The other 20+ entry points I did not read line by line; Medium that they all follow the same pattern.
**Verified:** citations checked ✓ · extracted as LIFE-26 (State & lifecycle)

### RULE-106: Multipart and AAD buffer caps
**Category:** Lifecycle
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:2060, 8910-8969`
**Plain English:** Buffered multipart signing accumulates at most 16 MiB in total; exceeding it, or running out of memory while growing, zeroizes the buffer and ends the operation. Caller AAD is capped at 1 MiB.
**Specification:**
  Given 16,777,000 bytes already buffered
  When C_SignUpdate adds 1,000 bytes → CKR_DATA_LEN_RANGE (0x21), the buffer is zeroized and freed, the operation ended
  And per-call lengths above 0x7FFFFFFF → 0x21, operation ended
**Parameters:** FHSM_MULTIPART_MAX = 16 MiB; initial capacity 4 KiB, doubling; FHSM_AAD_MAX = 1 MiB
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-27 (State & lifecycle)
**Merged from CALC-30** (Calculations: "Multipart accumulation cap") — Source: `src/fhsm_pkcs11.c:2060`, `src/fhsm_pkcs11.c:8943-8967`.

### RULE-107: The refusal budget survives restarts
**Category:** Lifecycle
**Priority:** P1
**Source:** `service/fhsm_service.c:626-801, 685-717, 2628`
**Plain English:** Each authorisation refusal charges the subject; the first 4 are free, after that the subject must wait an escalating interval (1 s doubling, capped at 60 s) between attempts; one refusal is forgiven per 10 quiet minutes; only the count is persisted (`$FHSM_TOKENS_DIR/budget`, tmp+fsync+rename), written on every charge past the free allowance, and on restart the decay clock restarts.
**Specification:**
  Given subject S has count 7 and its last refusal 3 s ago
  When S requests → 429 "refusal_budget" with 1 s still to wait (count 7 needs 4 s)
  And after 1,200 s of quiet the count decays to 5
  And after a restart, a count of 7 is restored and the decay starts again from the restart
**Parameters:** BUDGET_MAX = 256; BUDGET_FREE = 4; BUDGET_DECAY_S = 600; BUDGET_CAP_S = 60
**Edge cases handled:** Refusals made by the budget itself are not charged. Decay below the free allowance is not persisted.
**Suspected defect:** When all 256 entries hold non-decayed counts, a new subject is not charged at all (it fails open, :773). If `FHSM_TOKENS_DIR` is unset, nothing is persisted.
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-36 (State & lifecycle)

### RULE-108: Service shutdown
**Category:** Lifecycle
**Priority:** P1
**Source:** `service/fhsm_service.c:941-953, 2163-2173, 2219-2220, 2301-2308, 2786-2811`
**Plain English:** SIGINT or SIGTERM stops accepting; requests already queued are still served; connections that have not yet sent anything are closed without a reply; then all pooled sessions are closed (the last close logs the token out and is audited), SERVICE_STOP is audited, the socket is unlinked, and C_Finalize runs.
**Specification:**
  Given 2 requests queued and 1 silent connection
  When SIGTERM arrives → the 2 are served, the silent one is closed, then LOGOUT {last-session-closed}, SERVICE_STOP, C_Finalize, exit 0
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-37 (State & lifecycle)

### RULE-109: Slot registry: presence and lazy token load
**Category:** Lifecycle
**Priority:** P1
**Source:** `src/fhsm_pkcs11.c:1014-1081, 1723-1725`
**Plain English:** Slots 0–3 map to `<dir>/slotN.tok`; whether a token is present is decided once per process when the slot table is first built (pthread_once), and the token is loaded lazily under a mutex on first use; C_InitToken of a fresh slot marks it present.
**Specification:**
  Given `slot1.tok` is created by another process after this process built its slot table
  When `C_GetSlotList(1, …)` is called → slot 1 is not listed until the process restarts
  And after C_Finalize the tokens are freed but the presence flags remain, and tokens reload from disk on next use
**Parameters:** FHSM_MAX_SLOTS = 4
**Confidence:** High.
**Verified:** citations checked ✓ · extracted as LIFE-40 (State & lifecycle)

## Suspected defects — preserve or fix?

Each is current legacy behaviour that looks wrong. Dual-execution diffing will flag every one the Rust build fixes, so each needs a recorded decision (intended divergence vs. preserved quirk) before its phase starts.

| Rule | Priority | Defect (short) |
|---|---|---|
| RULE-001 Key-encryption key derived from a PIN | P0 | - The iteration count is read from the file with no lower bound other than the primitive's 1000. The header is not authenticated (only the serial is AAD). Anyone who can write the file can change offset 136. The legit… |
| RULE-003 Encrypted object-store blob | P0 | 1. FHSM_OBJ_BLOB_MAX exceeds INT_MAX by about 938 KB, and `fhsm_aes_gcm_decrypt` casts the length to `int` (`fhsm_crypto.c:454`). A maximal store would fail to decrypt. |
| RULE-004 Token header binary layout | P0 | Only the serial is bound into the GCM AAD. Label, iteration count, the failure counters and user_initialized can all be edited undetected. Setting failed_* to 0 resets lockout. Offline, PBKDF2 at 200k over a 4-digit P… |
| RULE-005 PIN re-wrap (C_InitPIN, C_SetPIN, reinit) | P0 | 1. C_SetPIN appears unable to succeed. C_SetPIN requires a logged-in role (session role = token role), and the inner login refuses an already-logged-in role. No test exercises a successful C_SetPIN. |
| RULE-006 PBKDF2 primitive bounds and CKM_PKCS5_PBKD2 | P0 | `(uint32_t)p.iterations` at `fhsm_pkcs11.c:2829` narrows before the check. On LP64, iterations = 2^32 + 2000 runs 2000 iterations and returns CKR_OK. This is the same narrow-then-check pattern the code fixed for CKA_V… |
| RULE-007 Audit chain head and record MAC | P0 | `ts` is sampled before the mutex is taken (`:606-609`), so timestamps can run backwards relative to seq. This is minor. |
| RULE-008 Offline audit verification | P0 | The module accepts audit keys of 1–64 B (`fhsm_audit.c:457-458`), but the verifier hard-codes 32. Lines longer than 4095 B would be split by fgets; the module caps lines at 2048, so this cannot happen today. |
| RULE-010 DRBG chunking, reseed interval, conditioning | P0 | 1. A reseed failure is ignored ("best effort", `:431`). g_last_reseed_t is then not updated, so a reseed is attempted before every chunk. |
| RULE-012 Adaptive Proportion Test | P0 | For H = 8, W = 512 and α = 2^-40, my reading of SP 800-90B §4.4.2 (Table 2) gives a cutoff of about 13, not 51. The comment cites "Appendix C". SP 800-90B tests "≥ C"; the code tests "> C". |
| RULE-013 Continuous RNG test (CRNGT) | P0 | Coverage is one block per chunk. `src/fhsm_crypto.c:315-320` and `docs/FIPS_140_3.md:157` describe every new 16-byte block being compared. Requests under 16 B are never tested. |
| RULE-014 Secret-key generation lengths | P0 | GENERIC_SECRET keys of 1–13 bytes (under 112 bits) are generated in the FIPS-only build. SP 800-131A / SP 800-107 require at least 112 bits for HMAC keys. |
| RULE-015 RSA key-pair generation | P0 | The requested exponent is silently overridden, the same "answers done to a request it did not carry out" pattern the code removed for 3DES. FIPS 186-5 requires 2^16 < e < 2^256, so e = 3 should be refused rather than … |
| RULE-017 PQC parameter sets | P0 | The string form is validated against the union of all 18 names (`fhsm_pset_valid`), not the family. CKM_ML_KEM_KEY_PAIR_GEN with CKA_PARAMETER_SET = "ML-DSA-65" would generate an ML-DSA key stored as CKK_ML_KEM. |
| RULE-018 AES-GCM / GMAC / CCM parameters and output length | P0 | Tag lengths of 8–88 bits are accepted in the FIPS build. SP 800-38D permits 128/120/112/104/96, and 64/32 only under restrictions. The IV is always caller-supplied for GCM encryption (no module-generated-IV path), whi… |
| RULE-020 Derived-key output bounds | P0 | ML-KEM truncation checks only 1..ss_len, not the length against the key type. CKK_AES with 5 bytes is stored. |
| RULE-021 Certificate serial and validity | P0 | notAfter is not clamped to the CA certificate's notAfter. `--days` is parsed with atoi, so no range check beyond > 0. |
| RULE-022 CRL validity and number | P0 | The comment at `:398-402` says that if signing fails "a number has been consumed". In code, a signing failure exits before db_save, so the number is not consumed. This is harmless but the comment is wrong. thisUpdate … |
| RULE-023 OCSP response times and status | P0 | "good" is returned for any serial not listed, including serials never issued. There is no clock-skew backdate on thisUpdate. |
| RULE-024 Revocation database parsing | P0 | There is no range check on month, day, hour, minute or second. |
| RULE-035 SO and read-only sessions are mutually exclusive | P0 | A known race: a read-only session opened during the SO's PBKDF2 step is not seen (documented in the code). |
| RULE-036 PIN length and character rules | P0 | - `docs/FIPS_140_3.md:63` says "at least 8 characters"; the code enforces 4. |
| RULE-037 Read-only session restrictions | P0 | - C_EncapsulateKey and C_DecapsulateKey never call `fhsm_check_ro_token`, so a read-only session can create token objects through them. |
| RULE-041 C_CopyObject rules | P0 | These were found by reading the code, not by running it. |
| RULE-044 Token file load validation | P0 | - The header is not authenticated. `pbkdf2_iter` is taken from the file without a range check. |
| RULE-055 Private-object visibility is decided by object class | P0 | - The CKA_PRIVATE value in a template is never stored. Visibility and the C_GetAttributeValue result both come from class alone. |
| RULE-056 Key-use Init paths only check that the handle exists (SEC-001) | P0 | SEC-001, which you report as reproduced. The fix is to apply `fhsm_object_access_denied`, or a USER-role requirement for private keys, in `fhsm_require_key`, and to unload objects at logout. |
| RULE-058 Sensitivity and extractability defaults per creation path | P0 | - The comment at `src/fhsm_pkcs11.c:5459-5460` says the KEM shared secret is "marked sensitive"; the code does not mark it. |
| RULE-059 ALWAYS_SENSITIVE and NEVER_EXTRACTABLE come from current flags | P0 | The spec defines both attributes historically. An imported or unwrapped key can claim a provenance it does not have, which can mislead policy engines. |
| RULE-063 C_WrapKey eligibility (SEC-003) | P0 | SEC-003. Per the spec, wrapping must also be refused when EXTRACTABLE = FALSE. The comment at `src/fhsm_pkcs11.c:7215-7217` claims C_WrapKey refuses non-extractable keys; the code does not. |
| RULE-064 C_DeriveKey output class and sensitivity | P0 | Secrets derived from a sensitive base key can be exported in clear, either through the CKO_DATA class or through the non-sensitive default plus SEC-003. |
| RULE-065 The NIST-approved-only build refuses non-approved mechanisms | P0 | In the strict build, `fhsm-service` always signs with the composite mechanism `0x80004202` (`service/fhsm_service.c:1390`), so every /sign request returns 500. |
| RULE-066 Object-store tag failure and zero-DEK fallback (SEC-002) | P0 | SEC-002. Anyone who can write the file and knows the serial can inject arbitrary objects, including trusted wrapping keys, by encrypting them under the zero key. A failed decrypt is also not reported to the caller. |
| RULE-068 Client identity, signing policy, refusal budget and in-flight cap | P0 | The budget and identity tables fail open when full. If 256 budget entries exist, refusals are not counted (line 773). If the identity table has no spare slot, the request is admitted uncounted (line 537). |
| RULE-069 CSR proof-of-possession and issuance constraints | P0 | - There is no check that the certificate's validity stays within the CA certificate's validity. |
| RULE-070 Module state whitelist and the latched ERROR state | P0 | AUTHENTICATED (3) is whitelisted but nothing ever sets it. The module state never tracks login. |
| RULE-071 C_Initialize sequence and double initialization | P0 | 0x191 is never returned. Callers that treat a second `C_Initialize` as harmless will see a hard failure instead. |
| RULE-072 No "not initialized" gate on any entry point | P0 | AGD_OPE.md:67 and :423 say 0x190 is returned; the code never returns it. Self-tests and auditing can be bypassed simply by not calling `C_Initialize`. |
| RULE-073 What the ERROR state refuses, and what it does not | P0 | Approved crypto keeps working in the error state, which breaks the FIPS 140-3 §7.10.5 rule that no data is output while in error. |
| RULE-074 Power-on self-tests and environment bypasses | P0 | The comment at integrity.c:391 says the bypass "is REFUSED in production". No build-time gate exists; any build honours the variable. |
| RULE-075 A pairwise consistency failure does not latch ERROR | P0 | The comment at :6766-6767 says "we latch the module ERROR state". The code should call `fhsm_state_latch_error`. |
| RULE-076 C_Finalize teardown and re-initialization | P0 | (a) `pReserved` is not checked; PKCS#11 requires CKR_ARGUMENTS_BAD when it is not NULL. (b) `fhsm_crypto_init` is guarded by `pthread_once`. On re-init it returns the cached OK without re-running integrity/KAT and wit… |
| RULE-077 Fork handling | P0 | (a) The comment at fhsm_state.c:103-106 says the child "re-runs fhsm_crypto_init: integrity check and power-on self-tests". The `pthread_once` in crypto.c is inherited as done, so they do not re-run. (b) A child that … |
| RULE-079 Creating a token on an empty slot | P0 | (a) The SO PIN minimum is 8 on a fresh token but 4 on re-init and in C_GetTokenInfo. (b) After init the token has `dek_live=1` and `objects_loaded=1` with `logged_in=NONE`: the DEK stays in memory with nobody logged i… |
| RULE-080 Re-initializing an existing token wipes it | P0 | (a) The `.tpm` companion file is neither resealed nor removed (`fhsm_token_tpm_unlink` has no callers), so it still holds the old DEK. Every later login hits the TPM cross-check and fails with CKR_DEVICE_ERROR (RULE-0… |
| RULE-082 C_SetPIN cannot succeed | P0 | The PIN can never be changed. Also, the comment at token.c:1756-1763 says an SO C_SetPIN "also rotates the DEK"; the code only re-wraps. |
| RULE-083 Login state belongs to the token and has conflict rules | P0 | 0x101 is returned where PKCS#11 specifies 0x102 (token.c:1406-1409). |
| RULE-084 PIN failure counter, throttle and lock | P0 | CKF_USER_PIN_COUNT_LOW, CKF_USER_PIN_FINAL_TRY and their SO equivalents are never set. FHSM_RV_PIN_THROTTLED is never returned any more (the throttle waits instead), yet C_Login still maps it. |
| RULE-085 Side effects of a successful login | P0 | The return value of `write_atomic` after login is ignored (:1532), so a counter that failed to persist is not reported. |
| RULE-086 Logout zeroizes the DEK but leaves decrypted objects usable | P0 | SEC-001: `fhsm_token_logout` leaves `objects_loaded` set and decrypted private key values in memory. Combined with Init functions that never check the role, private keys stay usable after logout. Separately, a logged-… |
| RULE-088 Token file persistence (save points) | P0 | The `fsync` return value is ignored (:1206) and the directory is not fsynced after the rename. |
| RULE-089 TPM-sealed DEK companion file | P0 | (a) The header comment (:37-40) says a mismatch returns PIN_INCORRECT; the code returns DEVICE_ERROR. (b) Re-init never reseals (RULE-080). (c) The seal file is written before the `.tok`; if writing the `.tok` fails, … |
| RULE-090 Closing sessions destroys session objects and logs out on the last one | P0 | C_CloseAllSessions has no slot filter and only accepts slot 0, yet C_OpenSession accepts slots 0–3. |
| RULE-091 Object creation, handles and capacity | P0 | A session object's value is briefly persisted (encrypted) before being marked. The marking result is ignored (`(void)` at :2554), so if that rewrite fails the object stays a persistent token object. |
| RULE-092 Object destruction | P0 | No ERROR-state check. No check that a session object belongs to the calling session. The private-object visibility check is not applied (an SO can destroy private keys). An unknown handle returns 0x60 rather than CKR_… |
| RULE-094 One audit file per opening | P0 | The C_Initialize FATAL text (pkcs11.c:518-520) mentions "an existing log whose last line cannot be parsed". The code no longer resumes or parses existing files. |
| RULE-096 Audit write failure | P0 | The action that could not be audited is still carried out and reported as successful. |
| RULE-098 Policy reload on SIGHUP keeps the old policy if the new one fails | P0 | A reload failure is reported only on stderr and is not audited. |
| RULE-099 Revocation is one-way, and duplicates are refused | P0 | No file locking. Two concurrent `revoke` runs both load, add and save, and one revocation is lost (last rename wins). |
| RULE-100 Database save, load and CRL numbering | P0 | The comment at fhsm_ca.c:398-402 says the number is "consumed" even when signing fails. The code consumes it only on success. With no locking, two concurrent `crl` runs can publish two different CRLs under the same nu… |
| RULE-027 Audit parameter sanitisation | P1 | Silent loss of evidence on truncation. |
| RULE-033 Refusal budget | P1 | If all 256 slots hold non-decayed identities, a new identity is not charged at all (fail-open, `:779`). |
| RULE-048 C_DigestKey refuses sensitive keys | P1 | A key that is non-sensitive but not extractable can be digested. This is the same gap as SEC-003. |
| RULE-049 Symmetric mechanism parameters (IV, tag, nonce) | P1 | GCM tags of 8–56 bits are accepted, while NIST SP 800-38D allows only 128, 120, 112, 104, 96 and, restricted, 64 and 32. |
| RULE-050 RSA key generation, OAEP and PSS parameters | P1 | - The requested public exponent is validated and then ignored (`EVP_PKEY_Q_keygen` at line 6646). |
| RULE-054 OCSP request and responder rules | P1 | A missing revocation DB file (ENOENT) loads as empty, so every serial, including never-issued ones, is reported "good". |
| RULE-101 Exclusive and shared entry modes | P1 | C_Login sleeps through the PIN throttle (up to 4 s; see RULE-084) while holding the shared lock. A queued exclusive caller then stalls the whole module for that time. |
| RULE-102 Opening a session | P1 | Exhaustion returns 0x2 rather than CKR_SESSION_COUNT (0xB1). The advertised maximum (128) is one more than usable, and the live session counts are always reported as 0. |
| RULE-105 When an operation ends | P1 | In C_Sign and C_DigestFinal, a NULL `pulSignatureLen` / `pulDigestLen` returns CKR_ARGUMENTS_BAD without ending the operation (:11328, :12049). C_Encrypt ends it in the same case (:9788). The behaviour is inconsistent. |
| RULE-107 The refusal budget survives restarts | P1 | When all 256 entries hold non-decayed counts, a new subject is not charged at all (it fails open, :773). If `FHSM_TOKENS_DIR` is unset, nothing is persisted. |

## Rules requiring SME confirmation

### Medium / Low confidence (blocking where P0)

- [ ] **RULE-012 Adaptive Proportion Test** (P0, Medium) — Medium. SME question: "Confirm the APT cutoff for H = 8, W = 512 per SP 800-90B Table 2, and whether the comparison is ≥ or >."
- [ ] **RULE-041 C_CopyObject rules** (P0, Medium) — Medium SME question: Must a copy carry the source's usage and policy unchanged?
- [ ] **RULE-064 C_DeriveKey output class and sensitivity** (P0, Medium) — Medium SME question: Must derived keys inherit SENSITIVE and ALWAYS_SENSITIVE from the base key, and should CKO_DATA be allowed only for CKM_HKDF_DATA?

### High confidence in what the code does — intended behaviour needs a decision

- [ ] **RULE-003 Encrypted object-store blob** (P0) — SME question: "Must the zero-DEK recovery path survive the rewrite, and for how many releases?"
- [ ] **RULE-005 PIN re-wrap (C_InitPIN, C_SetPIN, reinit)** (P0) — SME question: "Should SO C_SetPIN rotate the DEK (and re-encrypt the store and user wrap), as the security target claims?"
- [ ] **RULE-010 DRBG chunking, reseed interval, conditioning** (P0) — SME question: "Must a failed reseed latch ERROR or refuse output?"
- [ ] **RULE-014 Secret-key generation lengths** (P0) — SME question: "Should the FIPS profile enforce GENERIC ≥ 14 bytes?"
- [ ] **RULE-017 PQC parameter sets** (P0) — SME question: "Confirm the CKP_SLH_DSA_* ordering against PKCS#11 v3.2 headers."
- [ ] **RULE-018 AES-GCM / GMAC / CCM parameters and output length** (P0) — SME question: "Restrict ulTagBits to {96..128 step 8} (plus 32/64?) in the FIPS profile?"
- [ ] **RULE-023 OCSP response times and status** (P0) — SME question: "Should unissued serials answer unknown, which needs an issuance database?"
- [ ] **RULE-072 No "not initialized" gate on any entry point** (P0) — SME question: "Must every `C_*` other than C_Initialize/C_GetFunctionList/C_GetInterface* return CKR_CRYPTOKI_NOT_INITIALIZED when the module state is POWER_OFF, as AGD_OPE documents?"
- [ ] **RULE-073 What the ERROR state refuses, and what it does not** (P0) — SME question: "Must every C_* except C_Finalize/C_GetInfo/C_GetFunctionList refuse in ERROR?"
- [ ] **RULE-076 C_Finalize teardown and re-initialization** (P0) — SME question: "After C_Finalize→C_Initialize in one process, must the self-tests re-run and the FIPS provider be reloaded?"
- [ ] **RULE-079 Creating a token on an empty slot** (P0) — SME question: "Which SO PIN minimum is authoritative, 4 or 8? And must the DEK be dropped after C_InitToken?"
- [ ] **RULE-082 C_SetPIN cannot succeed** (P0) — SME question: "Should SO C_SetPIN rotate the DEK (and re-encrypt the store)?"
- [ ] **RULE-096 Audit write failure** (P0) — SME question: "Must a security-relevant operation fail (and be rolled back) when its audit record cannot be made durable?"
- [ ] **RULE-099 Revocation is one-way, and duplicates are refused** (P0) — SME question: "Is a hold release needed for certificateHold?"
