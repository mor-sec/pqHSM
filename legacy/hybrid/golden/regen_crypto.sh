#!/usr/bin/env bash
# Rebuild the Phase 3 slice 1 (conf + secure heap) and slice 2 (DRBG) goldens in modernized/pqHSM/crypto/tests/golden/
# by RUNNING the legacy src/fhsm_conf.c, src/fhsm_memory.c and src/fhsm_drbg.c in the pinned image.
#
#   tests-support/golden/regen_crypto.sh
#
# Writes only crypto/tests/golden/. The repository is copied, never written.
#
# The heap scenarios lower RLIMIT_MEMLOCK and need mlock to obey it: no CAP_IPC_LOCK (podman's
# default set has none). The Rust replay runs the same way (crypto/tests/golden.rs).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WS=$(cd "$HERE/../.." && pwd)                 # modernized/pqHSM
REPO=$(cd "$WS/../.." && pwd)
IMAGE=${FHSM_BUILD_IMAGE:-localhost/freehsm-build:1.2.0}
OUT="$WS/crypto/tests/golden"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pqhsm-gencrypto.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
tar -C "$REPO" --exclude=./modernized --exclude=./analysis --exclude=./.obj -cf - . | tar -C "$WORK" -xf -
rm -rf "$OUT" && mkdir -p "$OUT"

podman run --rm --user root --entrypoint /bin/sh \
    -v "$WORK":/work:Z -v "$HERE":/gen:Z,ro -v "$OUT":/out:Z -w /work "$IMAGE" -c '
set -e
make -j"$(nproc)" -f /gen/gen_token.mk GEN_DIR=/gen gen_crypto gen_drbg gen_core >/dev/null
test ! -e /etc/freehsm/freehsm.conf        # the env_empty scenario reads the default path
OPENSSL_PREFIX=$(make -s -f Makefile -p 2>/dev/null | sed -n "s/^OPENSSL_PREFIX *[:?]*= *//p" | head -1)
LD_LIBRARY_PATH=$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib ./gen_crypto make /out
LD_LIBRARY_PATH=$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib ./gen_drbg make /out
LD_LIBRARY_PATH=$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib ./gen_core make /out
chown -R "$(stat -c %u:%g /gen)" /out'
echo "$(grep -vc "^#" "$OUT/cases.tsv") rows in $OUT/cases.tsv, $(grep -vc "^#" "$OUT/drbg.tsv") in $OUT/drbg.tsv, $(grep -vc "^#" "$OUT/core.tsv") in $OUT/core.tsv"
