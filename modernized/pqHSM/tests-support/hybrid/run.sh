#!/usr/bin/env bash
# Phase 1 proof run: build the hybrid module (legacy Makefile + hybrid.mk) on a COPY of the
# repository and run the legacy test list against it, then compare it with the pure-C build.
#
#   tests-support/hybrid/run.sh <pure-C build dir> <out dir>
#
# <pure-C build dir> is a legacy tree already built by `make all` (the baseline). Nothing in the
# repository is written: the copy and all results live under <out dir>.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../../.." && pwd)
C_BUILD=$(cd "$1" && pwd)
OUT=$(mkdir -p "$2" && cd "$2" && pwd)
IMAGE=${PQHSM_RUST_IMAGE:-localhost/pqhsm-rust:1.99.1}
REGISTRY=${CARGO_REGISTRY_CACHE:-$OUT/cargo-registry}
mkdir -p "$OUT/work" "$OUT/results" "$REGISTRY"
tar -C "$REPO" --exclude=./analysis --exclude=./.obj --exclude=./modernized/pqHSM/target -cf - . \
    | tar -C "$OUT/work" -xf -
# seccomp=unconfined: only for `setarch -R` in the TSan step (personality(ADDR_NO_RANDOMIZE)).
podman run --rm --user root --security-opt seccomp=unconfined \
    -v "$OUT/work":/work:Z -v "$OUT/results":/out:Z -v "$C_BUILD":/c:ro,Z \
    -v "$REPO/analysis/pqHSM/baseline":/fixture:ro,Z -v "$REGISTRY":/opt/rust/cargo/registry:Z \
    -v "$HERE/inner.sh":/inner.sh:ro,Z "$IMAGE" sh /inner.sh
cat "$OUT/results/summary.txt"
