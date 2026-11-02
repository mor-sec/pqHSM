#!/usr/bin/env bash
# Rebuild the Phase 3 slice 4 (self-tests) goldens in modernized/pqHSM/selftest/tests/golden/ by
# RUNNING the legacy src/fhsm_integrity.c, kat/*.c and src/fhsm_pairwise.c in the pinned image.
#
#   tests-support/golden/regen_selftest.sh
#
# Writes only selftest/tests/golden/. The repository is copied, never written.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
WS=$(cd "$HERE/../.." && pwd)                 # modernized/pqHSM
REPO=$(cd "$WS/../.." && pwd)
IMAGE=${FHSM_BUILD_IMAGE:-localhost/freehsm-build:1.2.0}
OUT=${PQHSM_GOLDEN_OUT:-$WS/selftest/tests/golden}   # another directory: a dry run to compare

WORK=$(mktemp -d "${TMPDIR:-/tmp}/pqhsm-genself.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
tar -C "$REPO" --exclude=./modernized --exclude=./analysis --exclude=./.obj -cf - . | tar -C "$WORK" -xf -
rm -rf "$OUT" && mkdir -p "$OUT"

podman run --rm --user root --entrypoint /bin/sh \
    -v "$WORK":/work:Z -v "$HERE":/gen:Z,ro -v "$OUT":/out:Z -w /work "$IMAGE" -c '
set -e
make -j"$(nproc)" -f /gen/gen_token.mk GEN_DIR=/gen gen_integrity gen_kat gen_pairwise >/dev/null
python3 /gen/make_integrity_elf.py /out/integrity
python3 /gen/make_kat_rsp.py kat/cavp/sha2_256_short.rsp /out/kat
cp kat/cavp/sha2_256_short.rsp /out/kat/
OPENSSL_PREFIX=$(make -s -f Makefile -p 2>/dev/null | sed -n "s/^OPENSSL_PREFIX *[:?]*= *//p" | head -1)
LD_LIBRARY_PATH=$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib ./gen_integrity make /out
LD_LIBRARY_PATH=$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib ./gen_kat vectors /out
LD_LIBRARY_PATH=$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib ./gen_kat runs /out /out/kat
LD_LIBRARY_PATH=$OPENSSL_PREFIX/lib64:$OPENSSL_PREFIX/lib ./gen_pairwise /out
rm -f /out/integrity/cached.elf          # the cached scenario removes it; never committed
chown -R "$(stat -c %u:%g /gen)" /out'
echo "$(grep -vc "^#" "$OUT/integrity.tsv") rows in $OUT/integrity.tsv, $(grep -vc "^#" "$OUT/kat_vectors.tsv") in kat_vectors.tsv, $(grep -vc "^#" "$OUT/kat.tsv") in kat.tsv, $(grep -vc "^#" "$OUT/pairwise.tsv") in pairwise.tsv"
