#!/bin/sh
# tests/abi/check.sh BIN MODULE --- every line of runs.txt against MODULE (a signed libpqhsm.so:
# the release module ignores FHSM_INTEGRITY_ALLOW_UNSIGNED). Each program dlopens ./libfreehsm.so
# and three read tests/vectors/, so each line runs in a fresh directory holding a copy of MODULE
# and a link to the repository's tests/. Every program runs; exit 1 if any failed, or if a built
# program neither ran nor is on runs.txt's "built only" line.
set -u
bin=$(cd "$1" && pwd) mod=$2 here=$(cd "$(dirname "$0")" && pwd)
openssl=${OPENSSL_PREFIX:-/usr/local/ssl}
n=0 failed= ran=
mkdir -p "$bin/logs"
while IFS= read -r line; do
    case $line in ''|'#'*) continue ;; esac
    prog=$(printf '%s' "$line" | sed -n 's|.*\$B/\([a-z_0-9]*\).*|\1|p')
    run=$(mktemp -d)
    cp "$mod" "$run/libfreehsm.so" && ln -s "$here/.." "$run/tests"
    # exported: an assignment before eval does not reach its commands under dash (review M4)
    (cd "$run" && export B=$bin LD_LIBRARY_PATH="$run:$openssl/lib64:$openssl/lib" &&
        eval "$line") < /dev/null > "$bin/logs/$prog.txt" 2>&1 || failed="$failed $prog"
    rm -rf "$run"; n=$((n + 1)); ran="$ran $prog "
done < "$here/runs.txt"
only=$(sed -n 's/^# built only: / /p' "$here/runs.txt")
for p in "$bin"/*; do
    p=${p##*/}; [ -f "$bin/$p" ] && [ -x "$bin/$p" ] || continue
    case "$ran$only " in *" $p "*) ;; *) failed="$failed $p(no-run-line)" ;; esac
done
if [ -n "$failed" ]; then
    echo "tests/abi: $n run, failed:$failed (logs in $bin/logs)"; exit 1
fi
echo "tests/abi: $n run, all passed"
