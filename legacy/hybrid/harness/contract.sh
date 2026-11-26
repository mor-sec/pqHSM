#!/bin/sh
# contract.sh LIB: the consumers docs/THIRD_PARTY_CONSUMERS.md and docs/P11_KIT_REMOTING.md
# measured, run against LIB on a fresh token (Phase 4 exit criterion; harness step 11):
#   OpenSC pkcs11-tool: init token and PIN, slots, mechanisms, an EC P-256 pair, its objects;
#   OpenSSL pkcs11-provider: `openssl storeutl` over that token (no composite object in it);
#   p11-kit: `p11-kit server` publishing LIB, pkcs11-tool through p11-kit-client.so.
# Prints one transcript, each command's rc after it, with what is random per run (the token
# serial, key bytes, PEM) replaced, so the C and the hybrid transcripts compare with diff.
L=$1
T=$(mktemp -d); mkdir -m 700 $T.run
export FHSM_TOKENS_DIR=$T FHSM_INTEGRITY_ALLOW_UNSIGNED=1 XDG_RUNTIME_DIR=$T.run  # p11-kit server needs one
export LD_LIBRARY_PATH=/usr/local/ssl/lib64:/usr/local/ssl/lib
P="pkcs11-tool --module $L"
U=userpin1234
SO=so-pin-1234
CLIENT=/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so
run() { echo "\$ $*"; "$@" 2>&1; echo "rc=$?"; }
{
  run $P --init-token --slot 0 --so-pin $SO --label freehsm
  run $P --init-pin --login --login-type so --so-pin $SO --pin $U
  run $P -L
  run $P -M
  run $P --login --pin $U --keypairgen --key-type EC:prime256v1 --label ec-plain
  run $P --login --pin $U -O
  echo "\$ openssl storeutl (pkcs11-provider)"
  PKCS11_PROVIDER_MODULE=$L openssl storeutl -provider pkcs11 -provider default -text \
      "pkcs11:?pin-value=$U" 2>&1; echo "rc=$?"
  echo "\$ p11-kit server"
  eval "$(p11-kit server --provider "$L" "pkcs11:" 2>/dev/null)"
  [ -n "${P11_KIT_SERVER_PID:-}" ] && echo "server: started" || echo "server: not started"
  run pkcs11-tool --module $CLIENT -L
  run pkcs11-tool --module $CLIENT -M
  run pkcs11-tool --module $CLIENT --login --pin $U -O
  [ -n "${P11_KIT_SERVER_PID:-}" ] && kill "$P11_KIT_SERVER_PID"
} | sed -e '/^\[freehsm-[a-z]*\] NOTE/,/bypass itself\./d' \
        -e 's/FHSM-[0-9a-f]\{6,\}/FHSM-<serial>/g' \
        -e 's/[0-9a-f]\{32,\}/<hex>/g' \
        -e 's/^\( *\)[0-9a-f][0-9a-f]\(:[0-9a-f][0-9a-f]\)*:\{0,1\}$/\1<hexdump>/' \
        -e 's|^[A-Za-z0-9+/=]\{40,\}$|<base64>|' \
        -e "s|$L|LIB|g; s|$T.run|RUNDIR|g; s|$T|TOKENS|g; s|unix:path=[^;\" ]*|unix:path=<socket>|g"
