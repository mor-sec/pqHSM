#!/usr/bin/env bash
# Rebuild the Phase 2 slice 3 goldens in token/tests/golden/store/ by RUNNING the legacy C token
# store (src/fhsm_token.c) in the pinned image, against store_scenarios.txt.
#
#   tests-support/golden/regen_store.sh
#
# Writes only token/tests/golden/store/. The repository is copied, never written. The container
# drops DAC_OVERRIDE so the scenarios' read-only token directories bind root too.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WS=$(cd "$HERE/../.." && pwd)                 # modernized/pqHSM
REPO=$(cd "$WS/../.." && pwd)
IMAGE=${FHSM_BUILD_IMAGE:-localhost/freehsm-build:1.2.0}
OUT="$WS/token/tests/golden/store"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pqhsm-genstore.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
tar -C "$REPO" --exclude=./modernized --exclude=./analysis --exclude=./.obj -cf - . | tar -C "$WORK" -xf -
rm -rf "$OUT" && mkdir -p "$OUT"

podman run --rm --user root --cap-drop=DAC_OVERRIDE,DAC_READ_SEARCH --entrypoint /bin/sh \
    -v "$WORK":/work:Z -v "$HERE":/gen:Z,ro -v "$WS/testdata":/corpus:Z,ro -v "$OUT":/out:Z \
    -w /work "$IMAGE" -c '
set -e
make -j"$(nproc)" -f /gen/gen_token.mk GEN_DIR=/gen gen_store >/dev/null
: > /tmp/fake_tpmrm0
OPENSSL_PREFIX=$(make -s -f Makefile -p 2>/dev/null | sed -n "s/^OPENSSL_PREFIX *[:?]*= *//p" | head -1)
LD_LIBRARY_PATH=.:$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib \
FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TPM_DEVICE=/tmp/fake_tpmrm0 \
    ./gen_store make /out /gen/store_scenarios.txt /work/tests/tpm2-stub.sh
chown -R "$(stat -c %u:%g /gen)" /out'
cp "$HERE/store_scenarios.txt" "$OUT/"
( cd "$OUT" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
echo "$(wc -l < "$OUT/steps.tsv") step rows, $(find "$OUT" -type f | wc -l) files in $OUT"
