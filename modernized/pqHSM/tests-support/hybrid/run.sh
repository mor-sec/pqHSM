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
tar -C "$REPO" --exclude=./analysis --exclude=./netcache --exclude=./.obj --exclude=./modernized/pqHSM/target -cf - . \
    | tar -C "$OUT/work" -xf -
# seccomp=unconfined: only for `setarch -R` in the TSan step (personality(ADDR_NO_RANDOMIZE)).
# FIPS_DEBS: a directory holding the openssl, libssl3t64 and openssl-provider-fips .debs of the
# image's OpenSSL version; with it, step 9 runs the FIPS-provider suite offline (BASELINE.md).
# WYCHEPROOF_CACHE: a directory holding wheels/ (python-pkcs11) and wycheproof-vectors/; with
# it, step 10 runs Wycheproof on both modules offline (BASELINE.md).
# CONTRACT_DEBS: the pkcs11-tool, pkcs11-provider and p11-kit .debs and their dependencies, fetched
# once (PHASE4_PLAN.md §5.3); by default netcache/debs, checked against netcache/debs.sha256.
# With them, step 11 runs the contract tests offline.
CONTRACT_DEBS=${CONTRACT_DEBS:-$REPO/netcache/debs}
if [ -d "$CONTRACT_DEBS" ]; then (cd "$CONTRACT_DEBS" && sha256sum -c --quiet "$REPO/netcache/debs.sha256"); else CONTRACT_DEBS=; fi
# The tree copy (about 1 GB) is removed afterwards unless KEEP_WORK=1; results/ stays.
rc=0
podman run --rm --user root --security-opt seccomp=unconfined \
    -v "$OUT/work":/work:Z -v "$OUT/results":/out:Z -v "$C_BUILD":/c:ro,Z \
    -v "$REPO/analysis/pqHSM/baseline":/fixture:ro,Z -v "$REGISTRY":/opt/rust/cargo/registry:Z \
    ${FIPS_DEBS:+-v "$FIPS_DEBS":/debs:ro,Z} \
    ${CONTRACT_DEBS:+-v "$CONTRACT_DEBS":/cdebs:ro,Z} \
    ${WYCHEPROOF_CACHE:+-v "$WYCHEPROOF_CACHE":/wyche:ro,Z} \
    -v "$HERE/inner.sh":/inner.sh:ro,Z "$IMAGE" sh /inner.sh || rc=$?
# files the container created belong to subordinate ids, hence unshare
[ "${KEEP_WORK:-}" = 1 ] || podman unshare rm -rf "$OUT/work"
cat "$OUT/results/summary.txt"
exit $rc
