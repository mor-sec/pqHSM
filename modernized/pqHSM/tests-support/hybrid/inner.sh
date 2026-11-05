#!/bin/sh
# Runs inside the pqhsm-rust image: /work = repo copy, /c = pure-C build, /out = results.
set -u
cd /work
M="make -f modernized/pqHSM/hybrid.mk"
# Intended test changes, each under its DIV (PHASE4_PLAN.md §4.2); the copy is patched, the
# original stays the C's. DIV-059: ulMinPinLen is 8.
sed -i 's/ti\.ulMinPinLen != 4 ||/ti.ulMinPinLen != 8 ||/' tests/test_input_validation.c
grep -q 'ulMinPinLen != 8' tests/test_input_validation.c || echo "DIV-059 patch did not apply" >&2
# DIV-001: a stream audit target fails its first fdatasync, so C_Initialize reports 0x30 (C
# returned OK into a module already in ERROR). Still announced as a stream.
sed -i 's/^ok \$rc "a stream target still starts the module"$/[ $rc -ne 0 ]; ok $? "a stream target: C_Initialize reports the failed audit (DIV-001)"/' tests/audit_switch.sh
grep -q 'DIV-001' tests/audit_switch.sh || echo "DIV-001 patch did not apply" >&2
{ $M all 2>&1 | tail -5; echo "build rc=$?"
  $M test-bins tools/fhsm-token tools/fhsm-csr tools/fhsm-ca tools/fhsm-sign tools/fhsm-crypt 2>&1 | tail -3; } > /out/build.log 2>&1

# 1. The legacy test list, one command at a time, exactly as the baseline ran it. Each command
#    gets its own TMPDIR so its token dirs, and so its audit logs, can be found for step 6.
$M -n tests 2>/dev/null | awk '/\\$/{sub(/\\$/,""); buf=buf $0; next} {print buf $0; buf=""}' \
    | grep -vE '^(cc|gcc|echo|:|make|cargo)' > /out/commands.txt
n=0; : > /out/results.tsv
while IFS= read -r cmd; do
  n=$((n+1)); name=$(printf '%s' "$cmd" | grep -oE '(\./tests/[A-Za-z0-9_]+|tests/[A-Za-z0-9_.]+\.sh( [a-z]+)?|\./tools/[a-z-]+)' | head -1)
  mkdir -p /tmp/corpus/hybrid/$n; TMPDIR=/tmp/corpus/hybrid/$n sh -c "$cmd" > /out/log_$n.txt 2>&1; printf '%s\t%s\t%s\n' "$n" "${name:-cmd$n}" "$?" >> /out/results.tsv
done < /out/commands.txt

# 2. Same module surface: exported symbols and NEEDED libraries.
syms() { nm -D --defined-only "$1" | awk '{print $3}' | sort; }
need() { readelf -d "$1" | awk '/NEEDED/{print $5}' | sort; }
syms /c/libfreehsm.so > /out/nm_c.txt; syms libfreehsm.so > /out/nm_hybrid.txt
need /c/libfreehsm.so > /out/needed_c.txt; need libfreehsm.so > /out/needed_hybrid.txt
nm libfreehsm.so | grep -cE ' [tT] pqhsm_audit_event_v$' > /out/rust_linked.txt
# Phase 2 slice 1: the C TPM objects are empty, and the FHSM_TPM_CMD seam is only in test_tpm
# (review H6: the shipped module must never be the hooks build).
{ printf 'C objects with code: %s; ' "$(nm --defined-only .obj/src/fhsm_tpm.o .obj/src/fhsm_token_tpm.o .obj/tests/fhsm_tpm_testhooks.o 2>/dev/null | grep -c ' [TtDdBb] ')"
  printf 'FHSM_TPM_CMD in module: %s, in test_tpm: %s' "$(strings libfreehsm.so | grep -c FHSM_TPM_CMD)" "$(strings tests/test_tpm | grep -c FHSM_TPM_CMD)"
} > /out/tpm_swap.txt
# Phase 2 slice 2: the C revocation object is empty; the tools get the Rust code, and the module
# neither carries nor imports it (PHASE2_PLAN.md §3(c)).
{ printf 'C object with code: %s; ' "$(nm --defined-only .obj/src/fhsm_revocation.o | grep -c ' [TtDdBb] ')"
  printf 'module fhsm_rev_*/OCSP_*: %s; ' "$(nm libfreehsm.so | grep -cE ' (fhsm_rev_|fhsm_ocsp_|OCSP_)')"
  printf 'fhsm-ca rust db_load: %s' "$(nm tools/fhsm-ca | grep -c ' [Tt] fhsm_rev_db_load$')"
} > /out/rev_swap.txt
# Phase 2 slice 3: the C token store object is empty and the module's fhsm_token_* are Rust.
{ printf 'C object with code: %s; ' "$(nm --defined-only .obj/src/fhsm_token.o | grep -c ' [TtDdBb] ')"
  printf 'module fhsm_token_login: %s; rust token code in module: %s' "$(nm libfreehsm.so | grep -c ' [Tt] fhsm_token_login$')" "$(nm libfreehsm.so | grep -c 'pqhsm_token5token5Token')"
} > /out/token_swap.txt
# Phase 3 slice 1: the secure heap and the conf reader.
{ printf 'C objects with code: %s; ' "$(nm --defined-only .obj/src/fhsm_memory.o .obj/src/fhsm_conf.o | grep -c ' [TtDdBb] ')"
  printf 'module fhsm_secure_malloc: %s; rust heap code in module: %s' "$(nm libfreehsm.so | grep -c ' [Tt] fhsm_secure_malloc$')" "$(nm libfreehsm.so | grep -c 'pqhsm_crypto3mem')"
} > /out/crypto_swap.txt
# Phase 3 slice 2: the DRBG.
{ printf 'C object with code: %s; ' "$(nm --defined-only .obj/src/fhsm_drbg.o | grep -c ' [TtDdBb] ')"
  printf 'module fhsm_drbg_bytes: %s; rust drbg code in module: %s' "$(nm libfreehsm.so | grep -c ' [Tt] fhsm_drbg_bytes$')" "$(nm libfreehsm.so | grep -c 'pqhsm_crypto4drbg')"
} > /out/drbg_swap.txt
{ printf 'C object defines only: %s; ' "$(nm --defined-only .obj/src/fhsm_crypto.o | awk '$2 ~ /[TtDdBb]/ {print $3}' | tr '\n' ' ')"
  printf 'module fhsm_crypto_init: %s; rust core code in module: %s' "$(nm libfreehsm.so | grep -c ' [Tt] fhsm_crypto_init$')" "$(nm libfreehsm.so | grep -c 'pqhsm_crypto[0-9]*\(lifecycle\|ffi4prim\)')"
} > /out/core_swap.txt
# Phase 3 slice 4: the integrity check; its object keeps only the digest array the signer patches.
{ printf 'C object defines only: %s; ' "$(nm --defined-only .obj/src/fhsm_integrity.o | awk '$2 ~ /[TtDdBbRr]/ {print $3}' | tr '\n' ' ')"
  printf 'rust integrity code in module: %s' "$(nm libfreehsm.so | grep -c 'pqhsm_selftest[0-9]*integrity')"
} > /out/integrity_swap.txt
# ... and the KATs, wholly in Rust.
{ printf 'C objects with code: %s; ' "$(nm --defined-only .obj/kat/fhsm_kat_vectors.o .obj/kat/cavp_extended.o | grep -c ' [TtDdBbRr] ')"
  printf 'rust kat code in module: %s' "$(nm libfreehsm.so | grep -c 'pqhsm_selftest[0-9]*kat')"
} > /out/kat_swap.txt
# ... and the pair-wise check after key generation.
{ printf 'C object with code: %s; ' "$(nm --defined-only .obj/src/fhsm_pairwise.o | grep -c ' [TtDdBbRr] ')"
  printf 'module fhsm_pairwise_check: %s; ' "$(nm libfreehsm.so | grep -c ' [Tt] fhsm_pairwise_check$')"
  printf 'rust pairwise code in module: %s' "$(nm libfreehsm.so | grep -c 'pqhsm_selftest3ffi8pairwise')"
} > /out/pairwise_swap.txt
# Phase 3 slice 5: the PKI encoders, in the module and in the tools.
{ printf 'C object with code: %s; ' "$(nm --defined-only .obj/src/fhsm_composite.o | grep -c ' [TtDdBbRr] ')"
  printf 'module fhsm_composite_sign: %s; fhsm-ca rust fhsm_pki_issue: %s' "$(nm libfreehsm.so | grep -c ' [Tt] fhsm_composite_sign$')" "$(nm tools/fhsm-ca | grep -c ' [Tt] fhsm_pki_issue$')"
} > /out/composite_swap.txt
# fhsm-ca end to end over the revocation DB (not in `make tests`). ocsp-delegated is left out:
# it runs `make clean` and rebuilds the tree under another PROFILE.
$M revocation-db > /out/revocation_db.txt 2>&1; echo "rc=$?" >> /out/revocation_db.txt

# 3. Cross-verification, both ways. Keys never leave the container.
cargo build -q --release --locked -p pqhsm-audit-verify --manifest-path modernized/pqHSM/Cargo.toml
RTOOL=modernized/pqHSM/target/release/pqhsm-audit
$RTOOL verify /fixture/audit.log.000001 "$(cat /fixture/TEST_KEY_HEX)" > /out/x_rust_tool_on_c_fixture.txt 2>&1
echo "rc=$?" >> /out/x_rust_tool_on_c_fixture.txt
tok=$(mktemp -d)
FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$tok FHSM_AUDIT_LOG=$tok/audit.log LD_LIBRARY_PATH=. \
    ./tests/test_smoke > /out/smoke.txt 2>&1; echo "smoke rc=$?" >> /out/smoke.txt
key=$(od -An -tx1 -v "$tok/audit.key" 2>/dev/null | tr -d ' \n')
: > /out/x_on_rust_written_logs.txt
for f in "$tok"/audit.log.*; do
  [ -f "$f" ] || continue
  echo "== $(basename "$f"): $(wc -l < "$f") lines" >> /out/x_on_rust_written_logs.txt
  ./tools/freehsm-audit verify "$f" "$key" >> /out/x_on_rust_written_logs.txt 2>&1; echo "C tool rc=$?" >> /out/x_on_rust_written_logs.txt
  $RTOOL verify "$f" "$key" >> /out/x_on_rust_written_logs.txt 2>&1; echo "Rust tool rc=$?" >> /out/x_on_rust_written_logs.txt
done
FHSM_C_AUDIT_TOOL=/work/tools/freehsm-audit cargo test -q --locked --manifest-path modernized/pqHSM/Cargo.toml \
    -p pqhsm-audit --test cross_impl -- --ignored > /out/x_cross_impl.txt 2>&1; echo "rc=$?" >> /out/x_cross_impl.txt

# 4. Regressions from the architecture review: HMAC must come from the system libcrypto (one
#    OpenSSL state, its FIPS provider), and C_Finalize at exit must not abort (finding 1).
if nm -D libfreehsm.so | grep -qE ' U EVP_Q_mac(@|$)'; then echo yes; else echo no; fi > /out/evp_q_mac_dynamic.txt
cc -o /tmp/atexit_finalize modernized/pqHSM/tests-support/hybrid/atexit_finalize.c -ldl
for lib in /c/libfreehsm.so /work/libfreehsm.so; do
  t=$(mktemp -d)
  FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$t FHSM_AUDIT_LOG=$t/audit.log /tmp/atexit_finalize "$lib" > /tmp/ax.txt 2>&1
  echo "$lib rc=$? $(grep -o 'C_Finalize at exit: 0x[0-9a-f]*' /tmp/ax.txt)" >> /out/atexit_finalize.txt
done

# 4b. Phase 3 slice 1: test_secure_heap and probe_secure_heap are built but not in `make tests`
#     (Makefile:640, :764); the brief's exit criterion names the first. Run both on C and hybrid.
LDP=$(grep -oE 'LD_LIBRARY_PATH=[^ ]+' /out/commands.txt | head -1)
# The legacy test logs in as USER while SO is still logged in, which the token refuses (0x104)
# before any heap check runs, on C and hybrid alike. Both copies get the missing logout.
fix_heap_test() { sed -i '/fhsm_token_login(t, FHSM_ROLE_USER/i\    fhsm_token_logout(t);' "$1/tests/test_secure_heap.c"; }
cp -a /c /tmp/cb && fix_heap_test /tmp/cb && fix_heap_test /work
make -s -C /tmp/cb tests/test_secure_heap tests/probe_secure_heap > /out/heap_build.log 2>&1
$M tests/test_secure_heap tests/probe_secure_heap >> /out/heap_build.log 2>&1
for d in /tmp/cb /work; do
  tag=$([ "$d" = /work ] && echo hybrid || echo c); t=$(mktemp -d)
  (cd $d && env $LDP FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$t FHSM_AUDIT_LOG=$t/audit.log ./tests/test_secure_heap > /out/heap_test_$tag.txt 2>&1; echo "rc=$?" >> /out/heap_test_$tag.txt
   env $LDP FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$t FHSM_AUDIT_LOG=$t/audit.log ./tests/probe_secure_heap ./libfreehsm.so > /out/heap_probe_$tag.txt 2>&1; echo "rc=$?" >> /out/heap_probe_$tag.txt)
done
{ for f in test probe; do
    printf '%s: C %s, hybrid %s, output %s; ' "$f" "$(tail -1 /out/heap_${f}_c.txt)" "$(tail -1 /out/heap_${f}_hybrid.txt)" \
      "$(cmp -s /out/heap_${f}_c.txt /out/heap_${f}_hybrid.txt && echo same || echo DIFF)"
  done; } > /out/heap_tests.txt

# 4c. Phase 3 slice 2: probe_keygen_drbg reads fhsm_drbg_get_stats around key generation and has
#     no Makefile rule; it links like test_secure_heap. C and hybrid must draw the same counts.
#     PINs are invented for the harness.
PROBE_RULE='tests/probe_keygen_drbg: tests/probe_keygen_drbg.c $(LIB_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LIB_OBJ) $(LDFLAGS)'
make -s -C /tmp/cb --eval "$PROBE_RULE" tests/probe_keygen_drbg > /out/drbg_build.log 2>&1
$M --eval "$PROBE_RULE" tests/probe_keygen_drbg >> /out/drbg_build.log 2>&1
for d in /tmp/cb /work; do
  tag=$([ "$d" = /work ] && echo hybrid || echo c); t=$(mktemp -d)
  # the probe opens a session before C_InitToken, so the token must exist already
  (cd $d && export $LDP FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$t FHSM_AUDIT_LOG=$t/audit.log FHSM_SO_PIN=pq-probe-so-7319 FHSM_PIN=pq-probe-usr-4826 \
     && ./tools/fhsm-token init --slot 0 --module ./libfreehsm.so > /out/drbg_token_$tag.txt 2>&1 \
     && ./tests/probe_keygen_drbg > /out/drbg_probe_$tag.txt 2>&1; echo "rc=$?" >> /out/drbg_probe_$tag.txt)
done
printf 'probe_keygen_drbg: C %s, hybrid %s, output %s' "$(tail -1 /out/drbg_probe_c.txt)" "$(tail -1 /out/drbg_probe_hybrid.txt)" \
  "$(cmp -s /out/drbg_probe_c.txt /out/drbg_probe_hybrid.txt && echo same || echo DIFF)" > /out/drbg_tests.txt

# 4d. Phase 3 slice 4: `make test-integrity` (not in `make tests`, Makefile:568) signs and
#     tampers a statically linked binary and runs the check without the bypass, on C and hybrid.
for d in /tmp/cb /work; do
  tag=$([ "$d" = /work ] && echo hybrid || echo c)
  (cd $d && if [ $d = /work ]; then $M test-integrity; else make test-integrity; fi > /out/integrity_test_$tag.txt 2>&1
   echo "rc=$?" >> /out/integrity_test_$tag.txt)
done
pass() { grep -E '^(test_integrity|  |\[)' "$1" | grep -v -e '^cc ' -e '^\[gen_p11_thunks\]'; }
printf 'test-integrity: C %s, hybrid %s, output %s' "$(tail -1 /out/integrity_test_c.txt)" "$(tail -1 /out/integrity_test_hybrid.txt)" \
  "$(pass /out/integrity_test_c.txt > /tmp/a; pass /out/integrity_test_hybrid.txt > /tmp/b; cmp -s /tmp/a /tmp/b && echo same || echo DIFF)" > /out/integrity_tests.txt

# 4e. Phase 3 slice 5 (PHASE3_PLAN.md §4.3): pki_artifacts.c makes a root, a request, a leaf, a
#     CRL, an OCSP response and a CMS through fhsm_pki_* for Ed25519, P-256 and RSA keys made here,
#     on C and hybrid. Deterministic signers, a counter RNG and a pinned clock: the DER must be
#     the same, and pass the openssl CLI. A tampered copy of the Ed25519 set must fail it, all
#     but the root (the trust anchor): one byte flipped inside each signed part.
K=$(mktemp -d)
{ openssl genpkey -algorithm ED25519 -out $K/ed25519.pem
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $K/p256.pem
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $K/rsa.pem; } > /out/pki_build.log 2>&1
head -c 5000 /dev/urandom > $K/data.bin
PKI_RULE='tests/pki_artifacts: /work/modernized/pqHSM/tests-support/hybrid/pki_artifacts.c .obj/src/fhsm_composite.o .obj/src/fhsm_revocation.o
	$(CC) $(CFLAGS) -o $@ $< .obj/src/fhsm_composite.o $(REVOCATION_OBJ) $(LDFLAGS)'
make -s -C /tmp/cb --eval "$PKI_RULE" tests/pki_artifacts >> /out/pki_build.log 2>&1
$M --eval "$PKI_RULE" tests/pki_artifacts >> /out/pki_build.log 2>&1
for d in /tmp/cb /work; do
  tag=$([ "$d" = /work ] && echo hybrid || echo c); mkdir -p /tmp/pki_$tag
  $d/tests/pki_artifacts $K /tmp/pki_$tag $K/data.bin > /out/pki_artifacts_$tag.txt 2>&1; echo "rc=$?" >> /out/pki_artifacts_$tag.txt
done
pki_cli() {  # dir: one line per signer, each structure checked by the openssl CLI at the pinned time
  T=1798761600
  v() { if "$@" > /dev/null 2>&1; then echo ok; else echo FAIL; fi; }
  g() { p=$1; shift; if "$@" 2>&1 | grep -q "$p"; then echo ok; else echo FAIL; fi; }
  for a in ed25519 p256 rsa; do
    [ -f $1/${a}_ca.der ] || continue
    openssl x509 -inform DER -in $1/${a}_ca.der -out $1/${a}_ca.pem; openssl x509 -inform DER -in $1/${a}_leaf.der -out $1/${a}_leaf.pem
    echo "$a: csr $(v openssl req -inform DER -in $1/${a}_csr.der -verify -noout)," \
      "root $(v openssl verify -attime $T -CAfile $1/${a}_ca.pem $1/${a}_ca.pem)," \
      "leaf $(v openssl verify -attime $T -CAfile $1/${a}_ca.pem $1/${a}_leaf.pem)," \
      "crl $(g 'verify OK' openssl crl -inform DER -in $1/${a}_crl.der -CAfile $1/${a}_ca.pem -noout)," \
      "ocsp $(g 'Response verify OK' openssl ocsp -respin $1/${a}_ocsp.der -VAfile $1/${a}_ca.pem -CAfile $1/${a}_ca.pem -attime $T)," \
      "cms $(v openssl cms -verify -binary -inform DER -in $1/${a}_cms.der -content $K/data.bin -CAfile $1/${a}_ca.pem -attime $T -purpose any -out /dev/null)"
  done
}
pki_cli /tmp/pki_c > /out/pki_cli_c.txt; pki_cli /tmp/pki_hybrid > /out/pki_cli_hybrid.txt
# The tampered set: the signature's last byte, except in the OCSPResponse, which ends in the
# responder's certificate; there producedAt, inside tbsResponseData.
mkdir -p /tmp/pki_bad; cp /tmp/pki_hybrid/ed25519_* /tmp/pki_bad/
for w in csr leaf crl ocsp cms; do f=/tmp/pki_bad/ed25519_$w.der
  python3 -c "import sys; b=bytearray(open(sys.argv[1],'rb').read()); i=b.find(b'20270101000000Z')+13 if sys.argv[2]=='ocsp' else -1; b[i]^=1; open(sys.argv[1],'wb').write(b)" $f $w; done
pki_cli /tmp/pki_bad > /out/pki_cli_tampered.txt
TAMPERED_WANT='ed25519: csr FAIL, root ok, leaf FAIL, crl FAIL, ocsp FAIL, cms FAIL'
printf 'pki_artifacts: C %s, hybrid %s; %s DER files, %s differ; openssl CLI: C %s ok, hybrid %s ok, FAIL %s; tampered Ed25519: %s' \
  "$(tail -1 /out/pki_artifacts_c.txt)" "$(tail -1 /out/pki_artifacts_hybrid.txt)" "$(ls /tmp/pki_hybrid/*.der 2>/dev/null | wc -l)" \
  "$(n=0; for f in /tmp/pki_c/*.der; do cmp -s $f /tmp/pki_hybrid/$(basename $f) || n=$((n+1)); done; echo $n)" \
  "$(grep -o ' ok' /out/pki_cli_c.txt | wc -l)" "$(grep -o ' ok' /out/pki_cli_hybrid.txt | wc -l)" "$(cat /out/pki_cli_c.txt /out/pki_cli_hybrid.txt | grep -o FAIL | wc -l)" \
  "$([ "$(cat /out/pki_cli_tampered.txt)" = "$TAMPERED_WANT" ] && echo 'every signed part refused, as expected' || echo "UNEXPECTED: $(cat /out/pki_cli_tampered.txt)")" > /out/pki_tests.txt

# 4f. Phase 4 slice 0 (PHASE4_PLAN.md §2): the function tables are Rust's. p11_tables.c prints
#     every slot of the v2.40, v3.0 and v3.2 tables by symbol name, and the argument checks of
#     the three calls that return them; C and hybrid must print the same.
cc -o /tmp/p11_tables modernized/pqHSM/tests-support/hybrid/p11_tables.c -ldl
for lib in /c/libfreehsm.so /work/libfreehsm.so; do
  tag=$([ "$lib" = /work/libfreehsm.so ] && echo hybrid || echo c)
  FHSM_INTEGRITY_ALLOW_UNSIGNED=1 /tmp/p11_tables $lib > /out/p11_tables_$tag.txt 2>&1; echo "rc=$?" >> /out/p11_tables_$tag.txt
done
printf 'p11 tables: C %s, hybrid %s, %s lines, %s' "$(tail -1 /out/p11_tables_c.txt)" "$(tail -1 /out/p11_tables_hybrid.txt)" \
  "$(wc -l < /out/p11_tables_c.txt)" \
  "$(cmp -s /out/p11_tables_c.txt /out/p11_tables_hybrid.txt && echo identical || echo "DIFFER: $(diff /out/p11_tables_c.txt /out/p11_tables_hybrid.txt | grep -c '^[<>]') lines")" > /out/p11_tables.txt

# 4g. Phase 4 slice 1d: p11_lifecycle.c drives C_Initialize ... C_SetPIN through fifteen
#     scenarios on C and hybrid: return codes, output bytes and the module's stderr, then every
#     scenario's audit log normalised as in step 6. Both must match. One base path for both runs,
#     because the messages print it.
cc -o /tmp/p11_lifecycle modernized/pqHSM/tests-support/hybrid/p11_lifecycle.c -ldl
for lib in /c/libfreehsm.so /work/libfreehsm.so; do
  tag=$([ "$lib" = /work/libfreehsm.so ] && echo hybrid || echo c)
  mkdir /tmp/p11lc
  FHSM_INTEGRITY_ALLOW_UNSIGNED=1 /tmp/p11_lifecycle $lib /tmp/p11lc > /out/p11_lifecycle_$tag.txt 2>&1; echo "rc=$?" >> /out/p11_lifecycle_$tag.txt
  python3 modernized/pqHSM/tests-support/hybrid/corpus_norm.py /tmp/p11lc > /out/p11_lifecycle_audit_$tag.txt
  mv /tmp/p11lc /tmp/p11lc_$tag
done
# Recorded differences, applied and nothing else (p11_lifecycle_expect.py lists them): C's output
# becomes what Rust must print under each DIV, both are normalised for DIV-035 and the Phase 1
# key-message prefix. Scenario 5's logs are left out (DIV-009: the child keeps its own log; step
# 5 checks it), scenario 0's (DIV-051: C logged calls made before C_Initialize), and 1's and 2's
# (DIV-059 and RULE-083: a short new PIN is refused before the token, so C's event for it is not
# written and the sequence numbers after it move; 0x101 becomes 0x102). Their rows still compare.
pl_norm() { python3 -I modernized/pqHSM/tests-support/hybrid/p11_lifecycle_expect.py "$2" "$1"; }
pl_same() { if cmp -s "$1" "$2"; then echo identical; else echo "DIFFER: $(diff "$1" "$2" | grep -c '^[<>]') lines"; fi; }
for tag in c hybrid; do
  pl_norm /out/p11_lifecycle_$tag.txt $tag > /out/p11_lifecycle_${tag}_norm.txt
  for sc in 0 1 2 5; do mv /tmp/p11lc_$tag/$sc /tmp/p11lc_${tag}_set_aside_$sc; done
  python3 modernized/pqHSM/tests-support/hybrid/corpus_norm.py /tmp/p11lc_$tag > /out/p11_lifecycle_audit_${tag}_nofork.txt
done
printf 'p11 lifecycle: C %s, hybrid %s, %s rows, raw %s, less recorded DIVs %s; audit %s records, less scenarios 0, 1, 2 and 5 %s' \
  "$(tail -1 /out/p11_lifecycle_c.txt)" "$(tail -1 /out/p11_lifecycle_hybrid.txt)" \
  "$(grep -c "$(printf '\t')" /out/p11_lifecycle_c.txt)" "$(pl_same /out/p11_lifecycle_c.txt /out/p11_lifecycle_hybrid.txt)" \
  "$(pl_same /out/p11_lifecycle_c_norm.txt /out/p11_lifecycle_hybrid_norm.txt)" \
  "$(grep -vc '^=== log' /out/p11_lifecycle_audit_c.txt)" \
  "$(pl_same /out/p11_lifecycle_audit_c_nofork.txt /out/p11_lifecycle_audit_hybrid_nofork.txt)" > /out/p11_lifecycle.txt

# 4h. Phase 4 slice 1, DIV-051: p11_notinit.c calls every entry point but C_Initialize and the
#     list calls before C_Initialize, after C_Finalize and in an uninitialised forked child;
#     each must answer 0x190 (C_Finalize with pReserved 0x7); and DIV-053, every call in ERROR
#     0x6 but C_Finalize and the status calls. p11_divs.c: the other slice 1
#     DIVs, one test each. The C must fail every one; the hybrid pass.
cc -std=gnu17 -o /tmp/p11_notinit modernized/pqHSM/tests-support/hybrid/p11_notinit.c -ldl
for lib in /c/libfreehsm.so /work/libfreehsm.so; do
  tag=$([ "$lib" = /work/libfreehsm.so ] && echo hybrid || echo c)
  d=$(mktemp -d)
  FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$d /tmp/p11_notinit $lib > /out/p11_notinit_$tag.txt 2>/dev/null
  echo "rc=$?" >> /out/p11_notinit_$tag.txt
done
cc -std=gnu17 -o /tmp/p11_divs modernized/pqHSM/tests-support/hybrid/p11_divs.c -ldl
for lib in /c/libfreehsm.so /work/libfreehsm.so; do
  tag=$([ "$lib" = /work/libfreehsm.so ] && echo hybrid || echo c)
  d=$(mktemp -d)
  FHSM_INTEGRITY_ALLOW_UNSIGNED=1 /tmp/p11_divs $lib $d > /out/p11_divs_$tag.txt 2>/dev/null
done
printf %s "DIV tests: 051 C $(grep -q '^DIV-051: FAIL' /out/p11_notinit_c.txt && echo fails || echo 'PASSES (wrong)'), hybrid $(grep -q '^DIV-051: pass' /out/p11_notinit_hybrid.txt && echo passes || echo FAILS)" > /out/div_tests.txt
printf '; DIV-053 C %s, hybrid %s' "$(grep -q '^DIV-053: FAIL' /out/p11_notinit_c.txt && echo fails || echo 'PASSES (wrong)')" "$(grep -q '^DIV-053: pass' /out/p11_notinit_hybrid.txt && echo passes || echo FAILS)" >> /out/div_tests.txt
for t in $(grep -o '^[A-Z]*-[0-9]*: ' /out/p11_divs_c.txt | tr -d ': '); do
  c=$(grep "^$t: " /out/p11_divs_c.txt | cut -d' ' -f2); r=$(grep "^$t: " /out/p11_divs_hybrid.txt | cut -d' ' -f2)
  printf '; %s C %s, hybrid %s' "$t" "$([ "$c" = FAIL ] && echo fails || echo 'PASSES (wrong)')" "$([ "$r" = pass ] && echo passes || echo FAILS)"
done >> /out/div_tests.txt

# 4i. Phase 4 slice 2: p11_objects.c drives the nine object entry points (create, copy,
#     destroy, get/set attribute, size, find) over every attribute of every kind of object;
#     randomly drawn bytes print as their length. C and hybrid must print the same, less the
#     recorded rows in p11_objects_expect.sed (DIV-050, 056, 060; exact rows, nothing else).
cc -std=gnu17 -o /tmp/p11_objects modernized/pqHSM/tests-support/hybrid/p11_objects.c -ldl
for lib in /c/libfreehsm.so /work/libfreehsm.so; do
  tag=$([ "$lib" = /work/libfreehsm.so ] && echo hybrid || echo c)
  d=$(mktemp -d)
  FHSM_INTEGRITY_ALLOW_UNSIGNED=1 /tmp/p11_objects $lib $d > /out/p11_objects_$tag.txt 2>/dev/null
  echo "rc=$?" >> /out/p11_objects_$tag.txt
done
printf 'p11 objects: C %s, hybrid %s, %s rows, %s' "$(tail -1 /out/p11_objects_c.txt)" \
  "$(tail -1 /out/p11_objects_hybrid.txt)" "$(grep -c "$(printf '\t')" /out/p11_objects_c.txt)" \
  "$(pl_same /out/p11_objects_c.txt /out/p11_objects_hybrid.txt)" > /out/p11_objects.txt
sed -f modernized/pqHSM/tests-support/hybrid/p11_objects_expect.sed \
  /out/p11_objects_c.txt > /out/p11_objects_c_expect.txt
printf ', less recorded DIVs %s' \
  "$(pl_same /out/p11_objects_c_expect.txt /out/p11_objects_hybrid.txt)" >> /out/p11_objects.txt

# 4j. Phase 4 slice 2c: fhsm_parse_create_attrs, C's file against the staticlib's Rust, over
#     the fuzz corpus and 200,000 seeded templates (every path and rv). Must be identical.
CAD=modernized/pqHSM/tests-support/hybrid/create_attrs_diff.c
cc -std=gnu17 -O1 -Iinclude -o /tmp/cad_c $CAD src/fhsm_create_attrs.c
cc -std=gnu17 -O1 -Iinclude -o /tmp/cad_r $CAD modernized/pqHSM/target/release/libpqhsm_module.a \
  -Wl,--gc-sections -lssl -lcrypto -lpthread -ldl -lm
/tmp/cad_c 200000 fuzz/corpus/create_attrs/* > /out/create_attrs_c.txt; echo "rc=$?" >> /out/create_attrs_c.txt
/tmp/cad_r 200000 fuzz/corpus/create_attrs/* > /out/create_attrs_rust.txt; echo "rc=$?" >> /out/create_attrs_rust.txt
printf 'create attrs: C %s, Rust %s, %s cases, %s' "$(tail -1 /out/create_attrs_c.txt)" \
  "$(tail -1 /out/create_attrs_rust.txt)" "$(grep -c '^rv=' /out/create_attrs_c.txt)" \
  "$(pl_same /out/create_attrs_c.txt /out/create_attrs_rust.txt)" > /out/create_attrs.txt

# 4k. Phase 4 slice 3: p11_digest.c drives the five digest entry points over every digest
#     mechanism, their argument checks, C_DigestKey's refusals and the session and module
#     lifetimes. C and hybrid must print the same, less the recorded rows in
#     p11_digest_expect.sed (DIV-050, 051; exact rows, nothing else).
cc -std=gnu17 -o /tmp/p11_digest modernized/pqHSM/tests-support/hybrid/p11_digest.c -ldl
for lib in /c/libfreehsm.so /work/libfreehsm.so; do
  tag=$([ "$lib" = /work/libfreehsm.so ] && echo hybrid || echo c)
  d=$(mktemp -d)
  FHSM_INTEGRITY_ALLOW_UNSIGNED=1 /tmp/p11_digest $lib $d > /out/p11_digest_$tag.txt 2>/dev/null
  echo "rc=$?" >> /out/p11_digest_$tag.txt
done
sed -f modernized/pqHSM/tests-support/hybrid/p11_digest_expect.sed \
  /out/p11_digest_c.txt > /out/p11_digest_c_expect.txt
printf 'p11 digest: C %s, hybrid %s, %s rows, raw %s, less recorded DIVs %s' \
  "$(tail -1 /out/p11_digest_c.txt)" "$(tail -1 /out/p11_digest_hybrid.txt)" \
  "$(grep -c "$(printf '\t')" /out/p11_digest_c.txt)" \
  "$(pl_same /out/p11_digest_c.txt /out/p11_digest_hybrid.txt)" \
  "$(pl_same /out/p11_digest_c_expect.txt /out/p11_digest_hybrid.txt)" > /out/p11_digest.txt

# 5. DIV-009: a forked child that re-initialises must leave its parent's log intact.
cc -o /tmp/fork_parent_log modernized/pqHSM/tests-support/hybrid/fork_parent_log.c -ldl
for lib in /c/libfreehsm.so /work/libfreehsm.so; do
  t=$(mktemp -d); bad=0
  FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$t FHSM_AUDIT_LOG=$t/audit.log /tmp/fork_parent_log "$lib" > /dev/null 2>&1
  key=$(od -An -tx1 -v "$t/audit.key" | tr -d ' \n')
  for f in "$t"/audit.log.*; do
    ./tools/freehsm-audit verify "$f" "$key" > /dev/null 2>&1 || bad=$((bad+1))
    $RTOOL verify "$f" "$key" > /dev/null 2>&1 || bad=$((bad+1))
  done
  echo "$lib: $(ls "$t"/audit.log.* | wc -l) logs, $bad failed verifications" >> /out/fork_parent_log.txt
done

# 6. Corpus diff: the same commands on the pure-C tree, then every audit log of each command
#    compared, ts and MACs normalised (brief, Phase 1 exit criterion 2).
cp -a /c /tmp/cwork
n=0; : > /out/corpus.tsv
while IFS= read -r cmd; do
  n=$((n+1)); mkdir -p /tmp/corpus/c/$n
  (cd /tmp/cwork && TMPDIR=/tmp/corpus/c/$n sh -c "$cmd" > /dev/null 2>&1)
  N=modernized/pqHSM/tests-support/hybrid/corpus_norm.py
  python3 $N /tmp/corpus/c/$n > /tmp/c.txt; python3 $N /tmp/corpus/hybrid/$n > /tmp/h.txt
  logs=$(grep -c '^=== log' /tmp/c.txt); recs=$(grep -vc '^=== log' /tmp/c.txt)
  if cmp -s /tmp/c.txt /tmp/h.txt; then v=same
  elif [ "$(python3 $N /tmp/corpus/c/$n --lines)" = "$(python3 $N /tmp/corpus/hybrid/$n --lines)" ]; then v=order-only
  else v=DIFF; mkdir -p /out/corpus_diff; diff /tmp/c.txt /tmp/h.txt > /out/corpus_diff/$n.diff; fi
  printf '%s\t%s\t%s\t%s\t%s\n' "$n" "$(awk -F'\t' -v n=$n '$1==n{print $2}' /out/results.tsv)" "$logs" "$recs" "$v" >> /out/corpus.tsv
done < /out/commands.txt

# 7. TSan (brief, Phase 1 risk 2): the concurrency and fork tests on a TSan build of the hybrid
#    module, in a copy. The Rust staticlib itself is not instrumented (stable toolchain). TSan
#    aborts under this kernel's mmap ASLR ("unexpected memory mapping"), so tests run under
#    `setarch -R`, which needs the container's seccomp relaxed (run.sh). The binaries are removed
#    first: make thinks a plain-built test binary is up to date.
cp -a /work /tmp/tsan && cd /tmp/tsan
rm -f tests/test_apilock tests/test_concurrency tests/test_concurrency_store tests/test_fork_child
{ $M TSAN=1 all && $M TSAN=1 tests/test_apilock tests/test_concurrency tests/test_concurrency_store tests/test_fork_child; } > /out/tsan_build.log 2>&1
echo "tsan build rc=$?" >> /out/tsan_build.log
: > /out/tsan.tsv
grep -E 'tests/test_(apilock|concurrency|concurrency_store|fork_child)( |$)' /out/commands.txt | while IFS= read -r cmd; do
  name=$(printf '%s' "$cmd" | grep -oE 'tests/test_[a-z_]+' | head -1)
  setarch -R sh -c "$cmd" > /out/tsan_$(basename $name).txt 2>&1; rc=$?
  printf '%s\t%s\t%s\n' "$name" "$rc" "$(grep -c 'WARNING: ThreadSanitizer' /out/tsan_$(basename $name).txt)" >> /out/tsan.tsv
done
cd /work

# 8. Token files both ways (brief Phase 2 exit criteria 2 and 3, PHASE2_PLAN.md §5.1 and §5.4).
#    gen_token is built on the pure-C tree (CG) and on the hybrid tree (RG, the Rust token store).
#    a) RG writes the golden corpus, CG describes it: C's reading of Rust-written tokens must equal
#       testdata/manifest.tsv (C's reading of C-written ones), serials masked.
#    b) The token files every test command left, from both runs, through both readers.
G=/work/modernized/pqHSM/tests-support/golden
{ (cd /tmp/cwork && make -f $G/gen_token.mk GEN_DIR=$G gen_token) && \
  make -f $G/gen_token.mk GEN_BASE=modernized/pqHSM/hybrid.mk GEN_DIR=$G gen_token; } > /out/gen_token_build.log 2>&1
echo "gen_token build rc=$?" >> /out/gen_token_build.log
CG=/tmp/cwork/gen_token RG=/work/gen_token
: > /tmp/fake_tpmrm0
tenv() { d=$1; shift; FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=$d FHSM_TPM_CMD="sh tests/tpm2-stub.sh" \
         FHSM_TPM_DEVICE=/tmp/fake_tpmrm0 FHSM_TPM_FAKE_PCR=golden-pcr "$@"; }
mask() { sed -E 's/serial=FHSM-[0-9a-f]+/serial=*/' "$1"; }
rt=$(mktemp -d)
(cd /work && tenv $rt $RG make $rt) > /out/rust_corpus.log 2>&1
cp $rt/manifest.tsv /out/manifest_rust_reads_rust.tsv 2>/dev/null
(cd /tmp/cwork && tenv $rt $CG describe $rt) >> /out/rust_corpus.log 2>&1
mask $rt/manifest.tsv > /tmp/m_cr.txt; mask modernized/pqHSM/testdata/manifest.tsv > /tmp/m_cc.txt
if [ -s /tmp/m_cr.txt ] && cmp -s /tmp/m_cc.txt /tmp/m_cr.txt; then echo same; else echo DIFF; diff /tmp/m_cc.txt /tmp/m_cr.txt; fi > /out/tok_rust_written_corpus.txt
pub() {  # reader, run dir: one sorted line per token file, keyed by command number and file name
  find /tmp/corpus/$2 -name '*.tok' | sort | while IFS= read -r f; do
    rel=${f#/tmp/corpus/$2/}; key="${rel%%/*}/$(basename "$f")"
    $1 public "$f" | sed "s#^$f#$key#"
  done | sort
}
(cd /tmp/cwork && pub $CG c) > /out/tok_c_reads_c.txt
(cd /tmp/cwork && pub $CG hybrid) > /out/tok_c_reads_rust.txt
(cd /work && pub $RG c) > /out/tok_rust_reads_c.txt

# 10. Wycheproof (PHASE3_PLAN.md §5.2, BASELINE.md § Wycheproof), from Phase 3 slice 4: the
#     legacy runner, full mode, as CI's nightly job, on the C and the hybrid module. Offline:
#     python-pkcs11 from the cached wheel, the vectors from the one-time fetch (run.sh,
#     WYCHEPROOF_CACHE). Before step 9, which replaces the libcrypto configuration.
if [ -d /wyche/wheels ]; then
  python3 -m venv /tmp/venv > /dev/null && /tmp/venv/bin/pip install -q --no-index --find-links /wyche/wheels python-pkcs11 > /out/wycheproof_install.log 2>&1
  rm -rf /tmp/wy && cp -a /work/tests/wycheproof /tmp/wy && rm -rf /tmp/wy/vectors && cp -a /wyche/wycheproof-vectors /tmp/wy/vectors
  for lib in /c/libfreehsm.so /work/libfreehsm.so; do
    tag=$([ $lib = /c/libfreehsm.so ] && echo c || echo hybrid)
    (cd $(dirname $lib) && env FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_KAT_ALLOW_FAIL=1 OPENSSL_CONF=/dev/null FHSM_TOKENS_DIR=$(mktemp -d) \
      /tmp/venv/bin/python3 /tmp/wy/run_wycheproof.py --module $lib) > /out/wycheproof_$tag.txt 2>&1
    echo "rc=$?" >> /out/wycheproof_$tag.txt
  done
  wsum() { sed -n '/WYCHEPROOF SUMMARY/,$p' "$1" | sed -E '/elapsed   :|module    :|report    :/d'; }
  wsum /fixture/wycheproof/run_wycheproof-c.txt > /tmp/w_base.txt
  for t in c hybrid; do wsum /out/wycheproof_$t.txt > /tmp/w_$t.txt; done
  printf 'C %s, hybrid %s; violations C %s, hybrid %s; C vs baseline %s, hybrid vs C %s' \
    "$(tail -1 /out/wycheproof_c.txt)" "$(tail -1 /out/wycheproof_hybrid.txt)" \
    "$(awk '/viol=/{sub(/.*viol= */,""); v+=$1} END{print v+0}' /tmp/w_c.txt)" \
    "$(awk '/viol=/{sub(/.*viol= */,""); v+=$1} END{print v+0}' /tmp/w_hybrid.txt)" \
    "$(cmp -s /tmp/w_base.txt /tmp/w_c.txt && echo same || echo DIFF)" \
    "$(cmp -s /tmp/w_c.txt /tmp/w_hybrid.txt && echo same || echo DIFF)" > /out/wycheproof.txt
else
  echo "skipped: no WYCHEPROOF_CACHE" > /out/wycheproof.txt
fi

# 9. The FIPS provider (PHASE3_PLAN.md §4.3, BASELINE.md § FIPS), from Phase 3 slice 3, which
#    moves the provider loads to Rust: both profiles, the hybrid module signed and run under
#    scripts/run_fips_tests.sh as CI's test-fips-provider job runs it, plus the three reports the
#    baseline kept. The provider is installed offline from /debs (run.sh, FIPS_DEBS). Last,
#    because it replaces the container's libcrypto configuration. A GNUmakefile makes every plain
#    `make` in the scripts the hybrid build. Phase 3 exit: Wycheproof again with the provider
#    active, on a C and a hybrid build of each profile, signed, with no bypass; hybrid must equal C.
#    FHSM_EVIDENCE=1: without it the runner sets the integrity bypass itself, and the module then
#    never loads the provider (tests/wycheproof/adapters/_p11.py).
if ls /debs/*.deb > /dev/null 2>&1; then
  { dpkg -i /debs/*.deb && sed '/^apt-get /d' scripts/ci_install_openssl_fips.sh | bash; echo "install rc=$?"; } > /out/fips_install.log 2>&1
  F=/fixture/fips
  rm -rf /tmp/tsan   # one tree copy at a time
  ok_lines() { sed 's/\x1b\[[0-9;]*m//g' "$1" | grep -aE '^ +(OK|NON) ' | sed -E 's/digest [0-9a-f]+/digest */'; }  # the run colours its marks
  for p in nist-approved-only all-mechanisms; do
    rm -rf /tmp/fips && cp -a /work /tmp/fips && cd /tmp/fips && cp modernized/pqHSM/hybrid.mk GNUmakefile
    export PROFILE=$p
    unset FHSM_INTEGRITY_ALLOW_UNSIGNED FHSM_KAT_ALLOW_FAIL OPENSSL_CONF
    { make clean && make && make test-bins && make integrity; echo "build rc=$?"; } > /out/fips_build_$p.log 2>&1
    bash scripts/run_fips_tests.sh > /out/fips_run_$p.txt 2>&1; echo "run_fips_tests rc=$?" >> /out/fips_run_$p.txt
    T=$(mktemp -d); cp tests/test_smoke $T/ && bash scripts/sign_module.sh $T/test_smoke > /dev/null 2>&1
    D=$(mktemp -d); LD_LIBRARY_PATH=. FHSM_TOKENS_DIR=$D $T/test_smoke > /out/fips_smoke_$p.txt 2>&1
    D=$(mktemp -d); LD_LIBRARY_PATH=. FHSM_TOKENS_DIR=$D ./tests/test_advertised_operational > /out/fips_probe_$p.txt 2>&1
    D=$(mktemp -d); LD_LIBRARY_PATH=. FHSM_TOKENS_DIR=$D ./tests/test_ec_curve_refusal > /out/fips_curve_$p.txt 2>&1
    untimed() { sed -E 's/ +[0-9]+ us$//' "$1"; }
    { printf '%s: %s; run_fips_tests %s, OK/NON lines %s (%s OK); ' "$p" "$(tail -1 /out/fips_build_$p.log)" \
        "$(tail -1 /out/fips_run_$p.txt | sed 's/run_fips_tests //')" \
        "$(ok_lines /out/fips_run_$p.txt > /tmp/a; ok_lines $F/run_fips_tests-$p.txt > /tmp/b; cmp -s /tmp/a /tmp/b && echo same || echo DIFF)" \
        "$(grep -c ' OK ' /tmp/a)"
      printf 'KAT report %s, probe %s, curve refusal %s\n' \
        "$(untimed /out/fips_smoke_$p.txt > /tmp/a; untimed $F/smoke_kat_report-$p.txt > /tmp/b; cmp -s /tmp/a /tmp/b && echo same || echo DIFF)" \
        "$(cmp -s /out/fips_probe_$p.txt $F/probe_advertised_operational-$p.txt && echo same || echo DIFF)" \
        "$(cmp -s /out/fips_curve_$p.txt $F/ec_curve_refusal-$p.txt && echo same || echo DIFF)"
    } >> /out/fips.txt
    if [ -d /tmp/wy ]; then
      rm -rf /tmp/cfips && cp -a /c /tmp/cfips
      (cd /tmp/cfips && { make clean && make && make integrity; echo "build rc=$?"; }) > /out/fips_cbuild_$p.log 2>&1
      for t in c hybrid; do
        d=$([ $t = c ] && echo /tmp/cfips || echo /tmp/fips)
        (cd $d && FHSM_EVIDENCE=1 FHSM_TOKENS_DIR=$(mktemp -d) /tmp/venv/bin/python3 /tmp/wy/run_wycheproof.py --module $d/libfreehsm.so) > /out/fips_wycheproof_${t}_$p.txt 2>&1
        echo "rc=$?" >> /out/fips_wycheproof_${t}_$p.txt
        wsum /out/fips_wycheproof_${t}_$p.txt > /tmp/fw_$t.txt
      done
      printf '%s: wycheproof with the provider: C %s (%s), hybrid %s; violations C %s, hybrid %s; hybrid vs C %s\n' "$p" \
        "$(tail -1 /out/fips_wycheproof_c_$p.txt)" "$(tail -1 /out/fips_cbuild_$p.log)" "$(tail -1 /out/fips_wycheproof_hybrid_$p.txt)" \
        "$(awk '/viol=/{sub(/.*viol= */,""); v+=$1} END{print v+0}' /tmp/fw_c.txt)" \
        "$(awk '/viol=/{sub(/.*viol= */,""); v+=$1} END{print v+0}' /tmp/fw_hybrid.txt)" \
        "$(cmp -s /tmp/fw_c.txt /tmp/fw_hybrid.txt && echo same || echo DIFF)" >> /out/fips.txt
      rm -rf /tmp/cfips
    fi
    cd /work
  done
  rm -rf /tmp/fips
  unset PROFILE
else
  echo "skipped: no FIPS_DEBS" > /out/fips.txt
fi
rm -rf /tmp/wy /tmp/venv

{ echo "build: $(grep -c 'build rc=0' /out/build.log) ok"
  echo "tests: $(awk -F'\t' '$3==0' /out/results.tsv | wc -l)/$(wc -l < /out/results.tsv) pass"
  awk -F'\t' '$3!=0{print "  FAIL " $2 " (rc " $3 ", log_" $1 ".txt)"}' /out/results.tsv
  if cmp -s /out/nm_c.txt /out/nm_hybrid.txt; then echo "nm -D: identical ($(wc -l < /out/nm_c.txt) symbols)"; else echo "nm -D: DIFFERS"; diff /out/nm_c.txt /out/nm_hybrid.txt | head; fi
  if cmp -s /out/needed_c.txt /out/needed_hybrid.txt; then echo "NEEDED: identical ($(tr '\n' ' ' < /out/needed_c.txt))"; else echo "NEEDED: DIFFERS"; diff /out/needed_c.txt /out/needed_hybrid.txt; fi
  echo "rust code linked into module: $(cat /out/rust_linked.txt)"
  echo "tpm swap: $(cat /out/tpm_swap.txt)"
  echo "revocation swap: $(cat /out/rev_swap.txt)"
  echo "token swap: $(cat /out/token_swap.txt)"
  echo "crypto swap (heap, conf): $(cat /out/crypto_swap.txt)"
  echo "drbg swap: $(cat /out/drbg_swap.txt)"
  echo "core swap: $(cat /out/core_swap.txt)"
  echo "integrity swap: $(cat /out/integrity_swap.txt)"
  echo "kat swap: $(cat /out/kat_swap.txt)"
  echo "pairwise swap: $(cat /out/pairwise_swap.txt)"
  echo "composite swap: $(cat /out/composite_swap.txt)"
  echo "secure heap: $(cat /out/heap_tests.txt)"
  echo "drbg: $(cat /out/drbg_tests.txt)"
  echo "integrity: $(cat /out/integrity_tests.txt)"
  echo "pki: $(cat /out/pki_tests.txt)"
  echo "$(cat /out/p11_tables.txt)"
  echo "$(cat /out/p11_lifecycle.txt)"
  echo "$(cat /out/div_tests.txt)"
  cat /out/p11_objects.txt; echo
  cat /out/create_attrs.txt; echo
  cat /out/p11_digest.txt; echo
  echo "gen_token: $(grep -c 'gen_token build rc=0' /out/gen_token_build.log) build ok; C reads the Rust-written corpus: $(head -1 /out/tok_rust_written_corpus.txt)"
  same() { if cmp -s "$1" "$2"; then echo same; else echo "DIFF ($(diff "$1" "$2" | grep -c '^[<>]') lines)"; fi; }
  echo "token files left by tests: C run $(wc -l < /out/tok_c_reads_c.txt), hybrid run $(wc -l < /out/tok_c_reads_rust.txt); C reading Rust-written vs C-written: $(same /out/tok_c_reads_c.txt /out/tok_c_reads_rust.txt); Rust reading C-written vs C: $(same /out/tok_c_reads_c.txt /out/tok_rust_reads_c.txt); load failures: $(cat /out/tok_*_reads_*.txt | grep -vc 'load=0x0')"
  echo "revocation-db: $(grep -c " OK$" /out/revocation_db.txt) OK, $(grep -c " FAIL$" /out/revocation_db.txt) FAIL, $(tail -1 /out/revocation_db.txt)"
  echo "rust tool on C fixture: $(tail -2 /out/x_rust_tool_on_c_fixture.txt | tr '\n' ' ')"
  echo "rust-written logs: $(grep -c '^==' /out/x_on_rust_written_logs.txt) file(s); C tool fails: $(grep -c 'C tool rc=[^0]' /out/x_on_rust_written_logs.txt); Rust tool fails: $(grep -c 'Rust tool rc=[^0]' /out/x_on_rust_written_logs.txt)"
  echo "EVP_Q_mac imported from libcrypto: $(cat /out/evp_q_mac_dynamic.txt)"
  echo "C_Finalize at exit: $(tr '\n' ';' < /out/atexit_finalize.txt)"
  echo "fork, parent log: $(tr '\n' ';' < /out/fork_parent_log.txt)"
  echo "corpus: $(awk -F'\t' '$3>0' /out/corpus.tsv | wc -l) commands wrote audit logs ($(awk -F'\t' '{r+=$4} END{print r}' /out/corpus.tsv) records); same $(awk -F'\t' '$5=="same" && $3>0' /out/corpus.tsv | wc -l), order-only $(grep -c 'order-only$' /out/corpus.tsv), DIFF $(grep -c 'DIFF$' /out/corpus.tsv)"
  echo "tsan: $(grep -c 'rc=0' /out/tsan_build.log) build ok; $(awk -F'\t' '{printf "%s rc=%s races=%s; ", $1, $2, $3}' /out/tsan.tsv)"
  echo "wycheproof: $(cat /out/wycheproof.txt)"
  echo "fips: $(grep 'install rc' /out/fips_install.log 2>/dev/null)"; sed 's/^/  /' /out/fips.txt
  echo "cross_impl (C tool on Rust logs): $(grep -E 'test result|rc=' /out/x_cross_impl.txt | tr '\n' ' ')"
} > /out/summary.txt
