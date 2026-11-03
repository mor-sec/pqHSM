#!/usr/bin/env bash
# Rebuild the Phase 3 slice 5 (PKI encoders) goldens in modernized/pqHSM/pki/tests/golden/composite/
# by RUNNING the legacy src/fhsm_composite.c in the pinned image.
#
#   tests-support/golden/regen_composite.sh
#
# Writes only pki/tests/golden/composite/ (PQHSM_GOLDEN_OUT: another directory, for a dry run to
# compare). The repository is copied, never written.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WS=$(cd "$HERE/../.." && pwd)                 # modernized/pqHSM
REPO=$(cd "$WS/../.." && pwd)
IMAGE=${FHSM_BUILD_IMAGE:-localhost/freehsm-build:1.2.0}
OUT=${PQHSM_GOLDEN_OUT:-$WS/pki/tests/golden/composite}

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pqhsm-gencomp.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
tar -C "$REPO" --exclude=./modernized --exclude=./analysis --exclude=./.obj -cf - . | tar -C "$WORK" -xf -
rm -rf "$OUT" && mkdir -p "$OUT"

podman run --rm --user root --entrypoint /bin/sh \
    -v "$WORK":/work:Z -v "$HERE":/gen:Z,ro -v "$OUT":/out:Z -w /work "$IMAGE" -c '
set -e
make -j"$(nproc)" -f /gen/gen_token.mk GEN_DIR=/gen gen_composite gen_x509 >/dev/null
OPENSSL_PREFIX=$(make -s -f Makefile -p 2>/dev/null | sed -n "s/^OPENSSL_PREFIX *[:?]*= *//p" | head -1)
LD_LIBRARY_PATH=$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib ./gen_composite /out
LD_LIBRARY_PATH=$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib ./gen_x509 /out
chown -R "$(stat -c %u:%g /gen)" /out'
echo "$(grep -vc "^#" "$OUT/composite.tsv") rows in $OUT/composite.tsv"
echo "$(grep -vc "^#" "$OUT/x509.tsv") rows in $OUT/x509.tsv"
