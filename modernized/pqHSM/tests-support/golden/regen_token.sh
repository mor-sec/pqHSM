#!/usr/bin/env bash
# Rebuild the Phase 2 golden corpus in modernized/pqHSM/testdata/ by RUNNING the
# legacy C token store, TPM companion and revocation code in the pinned image.
#
#   tests-support/golden/regen_token.sh
#
# Writes only modernized/pqHSM/testdata/. The repository is copied, never written.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WS=$(cd "$HERE/../.." && pwd)                 # modernized/pqHSM
REPO=$(cd "$WS/../.." && pwd)
IMAGE=${FHSM_BUILD_IMAGE:-localhost/freehsm-build:1.2.0}
OUT="$WS/testdata"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pqhsm-gentoken.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
tar -C "$REPO" --exclude=./modernized --exclude=./analysis --exclude=./.obj -cf - . | tar -C "$WORK" -xf -
rm -rf "$OUT" && mkdir -p "$OUT"

podman run --rm --user root --entrypoint /bin/sh \
    -v "$WORK":/work:Z -v "$HERE":/gen:Z,ro -v "$OUT":/out:Z -w /work "$IMAGE" -c '
set -e
make -j"$(nproc)" -f /gen/gen_token.mk GEN_DIR=/gen gen_token >/dev/null
: > /tmp/fake_tpmrm0
OPENSSL_PREFIX=$(make -s -f Makefile -p 2>/dev/null | sed -n "s/^OPENSSL_PREFIX *[:?]*= *//p" | head -1)
LD_LIBRARY_PATH=.:$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib \
FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_TOKENS_DIR=/out \
FHSM_TPM_CMD="sh tests/tpm2-stub.sh" FHSM_TPM_DEVICE=/tmp/fake_tpmrm0 FHSM_TPM_FAKE_PCR=golden-pcr \
    ./gen_token make /out
chown -R "$(stat -c %u:%g /gen)" /out'
ls -l "$OUT"
