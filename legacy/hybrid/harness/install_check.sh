#!/bin/sh
# Phase 6 slice 4 (Q18, Q21; review H1, M3, L5): `install-pqhsm` as an operator runs it. Prints
# one line per mode.
#   sh install_check.sh install SRC   a copy of the all-mechanisms tree SRC without its target
#        dirs (a release build, no dev-bypass), installed under a scratch prefix twice; refused
#        in SRC itself (the harness's dev-bypass build); the layout checked.
#   sh install_check.sh run           the installed tools, module and service, with no bypass in
#        the environment and the FIPS provider active (harness step 9: a signed module requires
#        it), up to /health: they pass their own integrity check, so the signing is proved by use.
set -u
I=/tmp/inst M="make -f modernized/pqHSM/hybrid.mk"

if [ "$1" = install ]; then
  SRC=$2 T=/tmp/instree
  mkdir -p $T
  (cd $SRC && tar --exclude=./modernized/pqHSM/target --exclude=./modernized/pqHSM/target-hooks \
    --exclude=./modernized/pqHSM/target-release -cf - .) | tar -C $T -xf -
  inst() { d=$1; shift; (cd $d && $M PROFILE=all-mechanisms PREFIX=$I ETCDIR=$I/etc STATEDIR=$I/state SYSUSER=root UNITDIR=$I/unit "$@" install-pqhsm); }
  inst $T PQHSM_FEATURES= > /out/install_1.log 2>&1; r1=$?
  inst $T PQHSM_FEATURES= > /out/install_2.log 2>&1; r2=$?
  refused=$(inst $SRC 2>&1 | grep -c '^install-pqhsm: refused')
  ok() { if "$@"; then echo ok; else echo BAD; fi; }
  lib=$(ok sh -c "[ -f $I/lib/libpqhsm.so ] && [ ! -L $I/lib/libpqhsm.so ] && [ \"\$(readlink $I/lib/libfreehsm.so)\" = libpqhsm.so ]")
  tools=$(for t in csr ca sign crypt token; do
    [ -f $I/bin/pqhsm-$t ] && [ ! -L $I/bin/pqhsm-$t ] && [ "$(readlink $I/bin/fhsm-$t)" = pqhsm-$t ] || echo "$t BAD"; done)
  # Slice 5b: the Rust verifier, not the C one the legacy install put there first.
  audit=$(ok sh -c "[ -f $I/bin/pqhsm-audit ] && [ \"\$(readlink $I/bin/freehsm-audit)\" = pqhsm-audit ] && cmp -s $I/bin/pqhsm-audit $T/modernized/pqHSM/target-release/release/pqhsm-audit && ! cmp -s $I/bin/pqhsm-audit $T/tools/freehsm-audit")
  unit=$(grep -c "^ExecStart=$I/libexec/pqhsm-service " $I/unit/pqhsm-service.service 2>/dev/null)
  uenv=$(grep -c '^Environment=PQHSM_TOKENS_DIR=' $I/unit/pqhsm-service.service 2>/dev/null)
  soname=$(readelf -d $I/lib/libpqhsm.so 2>&1 | grep -o 'soname: \[[^]]*\]')
  docs=$(ok sh -c "[ -f $I/share/doc/pqhsm/NOTICE ] && [ -f $I/share/doc/pqhsm/LICENSES/MIT.txt ]")
  # a third install under its own prefix, then uninstall-pqhsm: nothing may be left
  U=/tmp/inst-u; inst $T PQHSM_FEATURES= PREFIX=$U ETCDIR=$U/etc STATEDIR=$U/state UNITDIR=$U/unit > /out/install_u.log 2>&1
  (cd $T && $M PROFILE=all-mechanisms PREFIX=$U ETCDIR=$U/etc STATEDIR=$U/state SYSUSER=pqhsm-nouser UNITDIR=$U/unit uninstall-pqhsm) >> /out/install_u.log 2>&1; ru=$?
  left=$(find $U \( -type f -o -type l \) | sed "s|^$U/||" | tr '\n' ' ')
  rm -rf $T
  echo "install-pqhsm: release build rc=$r1, again rc=$r2, refused in a dev-bypass tree: $refused; libpqhsm.so $lib; tools ${tools:-ok}; freehsm-audit $audit; unit ExecStart $unit, Environment=PQHSM_ $uenv; $soname; LICENSE and NOTICE $docs; uninstall-pqhsm rc=$ru, left: ${left:-nothing}"
  exit 0
fi

D=$(mktemp -d)
E="env -u FHSM_INTEGRITY_ALLOW_UNSIGNED -u PQHSM_INTEGRITY_ALLOW_UNSIGNED -u FHSM_KAT_ALLOW_FAIL -u OPENSSL_CONF FHSM_TOKENS_DIR=$D FHSM_PIN=userpin1234"
$E FHSM_SO_PIN=sopin1234 $I/bin/pqhsm-token init --label inst --module $I/lib/libfreehsm.so > $D/k.log 2>&1 &&
  $E $I/bin/pqhsm-csr keygen --label tls-web01 --module $I/lib/libfreehsm.so >> $D/k.log 2>&1; k=$?
printf 'userpin1234\n' > $D/pin; chmod 600 $D/pin
printf 'CN=web01\ttls-web01\n' > $D/policy
$E $I/libexec/pqhsm-service --socket $D/s.sock --proxy-uid "$(id -u)" --pin-file $D/pin --policy $D/policy 2> $D/svc.err &
P=$!
for _ in $(seq 50); do grep -q 'listening on' $D/svc.err && break; sleep 0.2; done
health=$(python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(10); s.connect(sys.argv[1])
s.sendall(b"GET /health HTTP/1.1\r\nX-FHSM-Client-Subject: CN=web01\r\n\r\n"); s.shutdown(socket.SHUT_WR)
print(s.recv(200).split(b"\r\n")[0].decode())' $D/s.sock 2>&1 | tail -1)
kill -TERM $P 2>/dev/null; wait $P; src=$?
# Without the provider (no FIPS_DEBS), C_Initialize stops at it, which it reaches only once the
# integrity check has passed (crypto/src/lifecycle.rs `run`): the signing is proved that far.
fips() { grep -c 'the OpenSSL FIPS provider would not load' "$1"; }
if grep -q 'listening on' $D/svc.err; then
  echo "installed, run with no bypass and the FIPS provider: token init and keygen rc=$k, service listening, /health: $health, exit $src"
else
  echo "installed, run with no bypass, no FIPS provider here: tool and service integrity passed, each stopped at the provider: tool $(fips $D/k.log), service $(fips $D/svc.err)$([ "$(fips $D/k.log)$(fips $D/svc.err)" = 11 ] || echo "; UNEXPECTED: $(tail -2 $D/k.log | tr '\n' ' ') $(tail -3 $D/svc.err | tr '\n' ' ')")"
fi
# Slice 5c (legacy/tests/test_integrity.c's tampered case): a copy of the installed module with
# one .text byte flipped is refused by the integrity check, with its message; an untouched copy run
# the same way, the control, gets as far as the provider (review M3: any failure passed before).
X=$(mktemp -d); Y=$(mktemp -d); cp $I/lib/libpqhsm.so $X/libfreehsm.so; cp $I/lib/libpqhsm.so $Y/libfreehsm.so
off=$(readelf -SW $X/libfreehsm.so | sed -n 's/.* \.text *PROGBITS *[0-9a-f]* \([0-9a-f]*\) .*/\1/p')
python3 -I -c 'import sys; f = open(sys.argv[1], "r+b"); o = int(sys.argv[2], 16) + 64; f.seek(o); b = f.read(1); f.seek(o); f.write(bytes([b[0] ^ 1]))' $X/libfreehsm.so "$off"
for d in $X $Y; do
  $E FHSM_TOKENS_DIR=$d FHSM_SO_PIN=sopin1234 $I/bin/pqhsm-token init --label x --module $d/libfreehsm.so > $d/t.log 2>&1; echo $? > $d/rc
done
refused=$(grep -c 'does not match its signature' $X/t.log)
if grep -q "listening on" $D/svc.err; then ctl=$(cat $Y/rc); else ctl="provider $(fips $Y/t.log)"; fi
echo "tampered copy (.text at 0x$off): rc=$(cat $X/rc), refused by the signature check $refused; untouched copy: ${ctl}$([ "$(cat $X/rc)" != 0 ] && [ "$refused" = 1 ] && { [ "$ctl" = 0 ] || [ "$ctl" = 'provider 1' ]; } || echo "; FAIL: $(tail -2 $X/t.log | tr '\n' ' ')")"
