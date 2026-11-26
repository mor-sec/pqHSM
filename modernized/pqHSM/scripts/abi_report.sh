#!/bin/sh
# The module's outside surface as one sorted text report (PHASE6_PLAN.md §8.3): what a consumer
# or the loader can see, so the Cargo-built libpqhsm.so can be diffed against the hybrid one.
#
#   modernized/pqHSM/scripts/abi_report.sh <libpqhsm.so>
#
# Reports: the soname, NEEDED, full RELRO, BIND_NOW, a non-executable stack, no text
# relocations, the .fhsm_digest section's size, and the exported symbols. Exit 0 with the report
# on stdout; exit 2 if the file is missing or is not an ELF shared object.
set -eu
lib=${1:?usage: abi_report.sh <libpqhsm.so>}
[ -f "$lib" ] || { echo "abi_report: $lib: no such file" >&2; exit 2; }
readelf -h "$lib" 2>/dev/null | grep -q 'Type:.*DYN' || { echo "abi_report: $lib: not an ELF shared object" >&2; exit 2; }

dyn=$(readelf -dW "$lib")
seg=$(readelf -lW "$lib")
has() { if printf '%s\n' "$1" | grep -qE "$2"; then echo yes; else echo no; fi; }

echo "soname: $(printf '%s\n' "$dyn" | sed -n 's/.*(SONAME).*\[\(.*\)\]/\1/p')"
printf '%s\n' "$dyn" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/needed: \1/p' | sort
echo "relro: $(has "$seg" 'GNU_RELRO')"
echo "bind_now: $(has "$dyn" '\(BIND_NOW\)|\(FLAGS\).*BIND_NOW|\(FLAGS_1\).*NOW')"
# GNU_STACK's flags column: RWE when the stack is executable.
echo "exec_stack: $(printf '%s\n' "$seg" | awk '$1 == "GNU_STACK" { print (index($0, "RWE") ? "yes" : "no"); f = 1 } END { if (!f) print "missing" }')"
echo "textrel: $(has "$dyn" 'TEXTREL')"
# Section rows read "[Nr] Name Type Address Off Size ...", and "[ 1]" splits in two: match by name.
size=$(readelf -SW "$lib" | sed -n 's/.*\] \.fhsm_digest  *[A-Z_]*  *[0-9a-f]*  *[0-9a-f]*  *\([0-9a-f]*\) .*/\1/p')
echo "fhsm_digest_size: $(if [ -n "$size" ]; then printf '%d' "0x$size"; else echo missing; fi)"
nm -D --defined-only "$lib" | awk '{ print "export: " $2 " " $3 }' | sort
