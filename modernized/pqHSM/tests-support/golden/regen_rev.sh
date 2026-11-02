#!/usr/bin/env bash
# Rebuild the Phase 2 slice 2 (revocation) goldens in modernized/pqHSM/pki/tests/golden/rev/
# by RUNNING the legacy src/fhsm_revocation.c, and src/fhsm_composite.c's OCSP encoder, in
# the pinned image.
#
#   tests-support/golden/regen_rev.sh
#
# Writes only pki/tests/golden/rev/. The repository is copied, never written.
#
# DAC_OVERRIDE and DAC_READ_SEARCH are dropped so that root in the container cannot read a
# mode-000 file or write into a mode-555 directory: the "unreadable" and "read-only dir" rows
# need what an unprivileged service sees. The Rust tests must run the same way.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WS=$(cd "$HERE/../.." && pwd)                 # modernized/pqHSM
REPO=$(cd "$WS/../.." && pwd)
IMAGE=${FHSM_BUILD_IMAGE:-localhost/freehsm-build:1.2.0}
OUT="$WS/pki/tests/golden/rev"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pqhsm-genrev.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
tar -C "$REPO" --exclude=./modernized --exclude=./analysis --exclude=./.obj -cf - . | tar -C "$WORK" -xf -
rm -rf "$OUT" && mkdir -p "$OUT"

podman run --rm --user root --entrypoint /bin/sh \
    --cap-drop=DAC_OVERRIDE,DAC_READ_SEARCH \
    -v "$WORK":/work:Z -v "$HERE":/gen:Z,ro -v "$OUT":/out:Z -w /work "$IMAGE" -c '
set -e
make -j"$(nproc)" -f /gen/gen_token.mk GEN_DIR=/gen gen_rev >/dev/null
mkdir -p /tmp/gr
OPENSSL_PREFIX=$(make -s -f Makefile -p 2>/dev/null | sed -n "s/^OPENSSL_PREFIX *[:?]*= *//p" | head -1)
LD_LIBRARY_PATH=.:$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib FHSM_INTEGRITY_ALLOW_UNSIGNED=1 \
    ./gen_rev make /out /tmp/gr
chown -R "$(stat -c %u:%g /gen)" /out'
echo "$(grep -vc "^#" "$OUT/cases.tsv") rows in $OUT/cases.tsv"
