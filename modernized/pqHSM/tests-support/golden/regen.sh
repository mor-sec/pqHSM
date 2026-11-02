#!/usr/bin/env bash
# Rebuild every golden file used by the pqhsm-audit / pqhsm-audit-verify
# characterization tests, by RUNNING the legacy C code (src/fhsm_audit.c and
# tools/freehsm_audit.c) in the pinned legacy build image.
#
#   tests-support/golden/regen.sh                  # builds the legacy tree first
#   LEGACY_BUILD=/path/to/built/tree regen.sh      # reuse a tree that has .obj/ and
#                                                  # tools/freehsm-audit already built
#
# Writes only:
#   audit/tests/golden/{lines,verify,baseline,streams}/, audit/tests/golden/numbering.tsv
#   audit-verify/tests/golden/
# The legacy tree and analysis/ are mounted read-only.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WS=$(cd "$HERE/../.." && pwd)                 # modernized/pqHSM
REPO=$(cd "$WS/../.." && pwd)                 # the legacy repository root
IMAGE=${FHSM_BUILD_IMAGE:-localhost/freehsm-build:1.2.0}

if [ -z "${LEGACY_BUILD:-}" ]; then
    LEGACY_BUILD=$(mktemp -d "${TMPDIR:-/tmp}/pqhsm-legacy.XXXXXX")
    echo "[regen] building the legacy tree in $LEGACY_BUILD"
    tar -C "$REPO" --exclude=./modernized --exclude=./analysis --exclude=./.obj -cf - . \
        | tar -C "$LEGACY_BUILD" -xf -
    podman run --rm --user root --entrypoint /bin/sh \
        -v "$LEGACY_BUILD":/work:Z -w /work "$IMAGE" \
        -c 'make -j"$(nproc)" tools/freehsm-audit tests/test_audit_verify >/dev/null'
fi

mkdir -p "$WS/audit/tests/golden" "$WS/audit-verify/tests/golden"
podman run --rm --user root --entrypoint /bin/sh \
    -v "$LEGACY_BUILD":/legacy:Z,ro \
    -v "$HERE":/gen:Z,ro \
    -v "$WS/audit/tests/golden":/g-audit:Z \
    -v "$WS/audit-verify":/av:Z \
    -v "$REPO/analysis/pqHSM/baseline":/baseline:Z,ro \
    "$IMAGE" -c 'python3 -I /gen/make_goldens.py && chown -R "$(stat -c %u:%g /av)" /g-audit /av/tests/golden'
