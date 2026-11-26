#!/usr/bin/env bash
# Rebuild the Phase 2 slice 1 (TPM sealing) goldens in modernized/pqHSM/token/tests/golden/tpm/
# by RUNNING the legacy src/fhsm_tpm.c (through the FHSM_TPM_TEST_HOOKS seam) and
# src/fhsm_token_tpm.c against tests/tpm2-stub.sh, in the pinned image.
#
#   tests-support/golden/regen_tpm.sh
#
# Writes only token/tests/golden/tpm/. The repository is copied, never written.
#
# DAC_OVERRIDE and DAC_READ_SEARCH are dropped so that root in the container cannot read a
# mode-000 file: the "unreadable companion" cases need what an unprivileged service sees.
# The Rust tests must run the same way (token/tests/README.md).
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WS=$(cd "$HERE/../.." && pwd)                 # modernized/pqHSM
REPO=$(cd "$WS/../.." && pwd)
IMAGE=${FHSM_BUILD_IMAGE:-localhost/freehsm-build:1.2.0}
OUT="$WS/token/tests/golden/tpm"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pqhsm-gentpm.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
tar -C "$REPO" --exclude=./modernized --exclude=./analysis --exclude=./.obj -cf - . | tar -C "$WORK" -xf -
rm -rf "$OUT" && mkdir -p "$OUT"

podman run --rm --user root --entrypoint /bin/sh \
    --cap-drop=DAC_OVERRIDE,DAC_READ_SEARCH \
    -v "$WORK":/work:Z -v "$HERE":/gen:Z,ro -v "$OUT":/out:Z -w /work "$IMAGE" -c '
set -e
make -j"$(nproc)" -f /gen/gen_token.mk GEN_DIR=/gen gen_tpm >/dev/null
mkdir -p /var/lib/freehsm /tmp/gw
OPENSSL_PREFIX=$(make -s -f Makefile -p 2>/dev/null | sed -n "s/^OPENSSL_PREFIX *[:?]*= *//p" | head -1)
LD_LIBRARY_PATH=.:$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib FHSM_INTEGRITY_ALLOW_UNSIGNED=1 \
    ./gen_tpm make /out /work/tests/tpm2-stub.sh /gen/tpm2-probe-stub.sh /tmp/gw
# The stubs the goldens were made with travel with them: the Rust tests run these copies.
cp tests/tpm2-stub.sh /gen/tpm2-probe-stub.sh /out/
chown -R "$(stat -c %u:%g /gen)" /out'
echo "$(grep -vc "^#" "$OUT/cases.tsv") rows in $OUT/cases.tsv"
