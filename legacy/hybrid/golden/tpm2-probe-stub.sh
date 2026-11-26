#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Observation wrapper around the legacy tests/tpm2-stub.sh, for the Phase 2 TPM goldens
# (token/tests/golden/tpm/). Like the stub it wraps, it is not a TPM and does no crypto.
# The same script is used to generate the C goldens and to run the Rust tests.
#
# Knobs, all via environment:
#   FHSM_TPM_REAL_STUB   path of tests/tpm2-stub.sh (required; every call is delegated to it)
#   FHSM_TPM_PROBE_LOG   append one line per call:
#                          <argv, each /proc/self/fd/N shown as <memfd name>>|fd1=..|fd2=..|inherited=..
#                        `inherited` lists every fhsm memfd this process can see, sorted.
#   FHSM_TPM_PROBE_HOLD  on `create`: touch "$HOLD.ready", then wait until "$HOLD.go" exists
#   FHSM_TPM_QUIRK       pub-size=N   `create` leaves the -u file exactly N bytes long
#                        empty-pub    `create` leaves the -u file empty
#                        empty-priv   `create` leaves the -r file empty
#                        unseal-out=N `unseal` leaves the -o file exactly N bytes long

sub=$1
real=${FHSM_TPM_REAL_STUB:?FHSM_TPM_REAL_STUB not set}

flag_val() {
    _want=$1; shift
    while [ $# -gt 0 ]; do
        if [ "$1" = "$_want" ]; then echo "$2"; return 0; fi
        shift
    done
    return 0
}

memfd_name() { readlink "$1" 2>/dev/null | sed -n 's|^/memfd:\(.*\) (deleted)$|\1|p'; }

if [ -n "$FHSM_TPM_PROBE_LOG" ]; then
    line=""
    for a in "$@"; do
        case "$a" in
            /proc/self/fd/*)
                n=$(memfd_name "/proc/$$/fd/${a#/proc/self/fd/}")
                a="<${n:-not-a-memfd}>" ;;
        esac
        line="$line $a"
    done
    inh=$(for f in /proc/$$/fd/*; do memfd_name "$f"; done | sort | tr '\n' ',')
    echo "${line# }|fd1=$(readlink /proc/$$/fd/1)|fd2=$(readlink /proc/$$/fd/2)|inherited=${inh%,}" \
        >> "$FHSM_TPM_PROBE_LOG"
fi

if [ -n "$FHSM_TPM_PROBE_HOLD" ] && [ "$sub" = create ]; then
    : > "$FHSM_TPM_PROBE_HOLD.ready"
    while [ ! -e "$FHSM_TPM_PROBE_HOLD.go" ]; do sleep 0.02; done
fi

case "$FHSM_TPM_QUIRK:$sub" in
    pub-size=*:create|empty-pub:create|empty-priv:create|unseal-out=*:unseal) ;;
    *) exec sh "$real" "$@" ;;
esac

sh "$real" "$@" || exit $?
shift
case "$FHSM_TPM_QUIRK" in
    pub-size=*)   truncate -s "${FHSM_TPM_QUIRK#pub-size=}" "$(flag_val -u "$@")" ;;
    empty-pub)    truncate -s 0 "$(flag_val -u "$@")" ;;
    empty-priv)   truncate -s 0 "$(flag_val -r "$@")" ;;
    unseal-out=*) truncate -s "${FHSM_TPM_QUIRK#unseal-out=}" "$(flag_val -o "$@")" ;;
esac
