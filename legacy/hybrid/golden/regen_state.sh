#!/usr/bin/env bash
# Rebuild the Phase 4 slice 1b (module state) golden, core/tests/golden/state.tsv, by
# RUNNING the legacy src/fhsm_state.c against gen_state.c's recording audit in the pinned image.
#
#   tests-support/golden/regen_state.sh
#
# Writes only core/tests/golden/. The repository is copied, never written.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WS=$(cd "$HERE/../.." && pwd)                 # modernized/pqHSM
REPO=$(cd "$WS/../.." && pwd)
IMAGE=${FHSM_BUILD_IMAGE:-localhost/freehsm-build:1.2.0}
OUT="$WS/core/tests/golden"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pqhsm-genstate.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
tar -C "$REPO" --exclude=./modernized --exclude=./analysis --exclude=./.obj -cf - . | tar -C "$WORK" -xf -
mkdir -p "$OUT"

podman run --rm --user root --entrypoint /bin/sh \
    -v "$WORK":/work:Z -v "$HERE":/gen:Z,ro -v "$OUT":/out:Z -w /work "$IMAGE" -c '
set -e
make -f /gen/gen_token.mk GEN_DIR=/gen gen_state >/dev/null
./gen_state /out/state.tsv
chown -R "$(stat -c %u:%g /gen)" /out'
echo "$(grep -vc "^#" "$OUT/state.tsv") rows in $OUT/state.tsv"
