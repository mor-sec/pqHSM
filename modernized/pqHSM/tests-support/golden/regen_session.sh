#!/usr/bin/env bash
# Rebuild the Phase 4 slice 1a (session table) golden, core/tests/golden/session.tsv, by
# RUNNING the legacy src/fhsm_session.c against gen_session.c's stub token in the pinned image.
#
#   tests-support/golden/regen_session.sh
#
# Writes only core/tests/golden/. The repository is copied, never written.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WS=$(cd "$HERE/../.." && pwd)                 # modernized/pqHSM
REPO=$(cd "$WS/../.." && pwd)
IMAGE=${FHSM_BUILD_IMAGE:-localhost/freehsm-build:1.2.0}
OUT="$WS/core/tests/golden"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pqhsm-gensess.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
tar -C "$REPO" --exclude=./modernized --exclude=./analysis --exclude=./.obj -cf - . | tar -C "$WORK" -xf -
mkdir -p "$OUT"

podman run --rm --user root --entrypoint /bin/sh \
    -v "$WORK":/work:Z -v "$HERE":/gen:Z,ro -v "$OUT":/out:Z -w /work "$IMAGE" -c '
set -e
make -f /gen/gen_token.mk GEN_DIR=/gen gen_session >/dev/null
./gen_session /out/session.tsv
chown -R "$(stat -c %u:%g /gen)" /out'
echo "$(grep -vc "^#" "$OUT/session.tsv") rows in $OUT/session.tsv"
