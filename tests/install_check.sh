#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 mor-sec <192092408+mor-sec@users.noreply.github.com>
#
# `make` and `make install` as an operator runs them (slice 5d; the hybrid's install check,
# legacy/hybrid/harness/install_check.sh, rewritten for the Cargo-only Makefile). As root, in the
# pinned image (localhost/pqhsm-rust), from the repository root. One line per mode; logs in $L.
#   sh tests/install_check.sh install   a copy of this tree without its target dirs, built (the
#        all-mechanisms profile, so the service is installed too) and installed under a scratch
#        prefix twice; the layout checked; a third install under its own prefix, then uninstall.
#   sh tests/install_check.sh run       the installed tools, module and service, with no bypass in
#        the environment, up to /health: they pass their own integrity check, so the signing is
#        proved by use; then a copy of the module with one .text byte flipped is refused.
set -u
I=/tmp/inst L=${L:-/tmp/install-logs}
mkdir -p $L

if [ "$1" = install ]; then
  T=/tmp/instree
  mkdir -p $T
  tar --exclude=./modernized/pqHSM/target --exclude=./modernized/pqHSM/target-release --exclude=./out \
    -cf - . | tar -C $T -xf -
  (cd $T && make PROFILE=all-mechanisms) > $L/build.log 2>&1; rb=$?
  inst() { (cd $T && make PREFIX=$I ETCDIR=$I/etc STATEDIR=$I/state SYSUSER=root UNITDIR=$I/unit "$@" install); }
  inst > $L/install_1.log 2>&1; r1=$?
  inst > $L/install_2.log 2>&1; r2=$?
  ok() { if "$@"; then echo ok; else echo BAD; fi; }
  lib=$(ok sh -c "[ -f $I/lib/libpqhsm.so ] && [ ! -L $I/lib/libpqhsm.so ] && [ \"\$(readlink $I/lib/libfreehsm.so)\" = libpqhsm.so ]")
  tools=$(for t in csr ca sign crypt token; do
    [ -f $I/bin/pqhsm-$t ] && [ ! -L $I/bin/pqhsm-$t ] && [ "$(readlink $I/bin/fhsm-$t)" = pqhsm-$t ] || echo "$t BAD"; done)
  audit=$(ok sh -c "[ \"\$(readlink $I/bin/freehsm-audit)\" = pqhsm-audit ] && cmp -s $I/bin/pqhsm-audit $T/modernized/pqHSM/target-release/release/pqhsm-audit")
  unit=$(grep -c "^ExecStart=$I/libexec/pqhsm-service " $I/unit/pqhsm-service.service 2>/dev/null)
  uenv=$(grep -c '^Environment=PQHSM_TOKENS_DIR=' $I/unit/pqhsm-service.service 2>/dev/null)
  soname=$(readelf -d $I/lib/libpqhsm.so 2>&1 | grep -o 'soname: \[[^]]*\]')
  docs=$(ok sh -c "[ -f $I/share/doc/pqhsm/NOTICE ] && [ -f $I/share/doc/pqhsm/LICENSES/MIT.txt ] && [ -f $I/share/kat/sha2_256_short.rsp ] && [ -f $I/etc/freehsm.conf ]")
  U=/tmp/inst-u; inst PREFIX=$U ETCDIR=$U/etc STATEDIR=$U/state UNITDIR=$U/unit > $L/install_u.log 2>&1
  (cd $T && make PREFIX=$U ETCDIR=$U/etc STATEDIR=$U/state SYSUSER=pqhsm-nouser UNITDIR=$U/unit uninstall) >> $L/install_u.log 2>&1; ru=$?
  left=$(find $U \( -type f -o -type l \) | sed "s|^$U/||" | tr '\n' ' ')
  echo "make install: build rc=$rb, install rc=$r1, again rc=$r2; libpqhsm.so $lib; tools ${tools:-ok}; freehsm-audit $audit; unit ExecStart $unit, Environment=PQHSM_ $uenv; $soname; LICENSE, NOTICE, KAT file and conf $docs; uninstall rc=$ru, left: ${left:-nothing}"
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
# Without the provider, C_Initialize stops at it, which it reaches only once the integrity check
# has passed (crypto/src/lifecycle.rs `run`): the signing is proved that far.
fips() { grep -c 'the OpenSSL FIPS provider would not load' "$1"; }
if grep -q 'listening on' $D/svc.err; then
  echo "installed, run with no bypass and the FIPS provider: token init and keygen rc=$k, service listening, /health: $health, exit $src"
else
  echo "installed, run with no bypass, no FIPS provider here: tool and service integrity passed, each stopped at the provider: tool $(fips $D/k.log), service $(fips $D/svc.err)$([ "$(fips $D/k.log)$(fips $D/svc.err)" = 11 ] || echo "; UNEXPECTED: $(tail -2 $D/k.log | tr '\n' ' ') $(tail -3 $D/svc.err | tr '\n' ' ')")"
fi
# A copy of the installed module with one .text byte flipped is refused by the integrity check,
# with its message; an untouched copy run the same way, the control, gets as far as the provider.
X=$(mktemp -d); Y=$(mktemp -d); cp $I/lib/libpqhsm.so $X/libfreehsm.so; cp $I/lib/libpqhsm.so $Y/libfreehsm.so
off=$(readelf -SW $X/libfreehsm.so | sed -n 's/.* \.text *PROGBITS *[0-9a-f]* \([0-9a-f]*\) .*/\1/p')
python3 -I -c 'import sys; f = open(sys.argv[1], "r+b"); o = int(sys.argv[2], 16) + 64; f.seek(o); b = f.read(1); f.seek(o); f.write(bytes([b[0] ^ 1]))' $X/libfreehsm.so "$off"
for d in $X $Y; do
  $E FHSM_TOKENS_DIR=$d FHSM_SO_PIN=sopin1234 $I/bin/pqhsm-token init --label x --module $d/libfreehsm.so > $d/t.log 2>&1; echo $? > $d/rc
done
refused=$(grep -c 'does not match its signature' $X/t.log)
if grep -q "listening on" $D/svc.err; then ctl=$(cat $Y/rc); else ctl="provider $(fips $Y/t.log)"; fi
echo "tampered copy (.text at 0x$off): rc=$(cat $X/rc), refused by the signature check $refused; untouched copy: ${ctl}$([ "$(cat $X/rc)" != 0 ] && [ "$refused" = 1 ] && { [ "$ctl" = 0 ] || [ "$ctl" = 'provider 1' ]; } || echo "; FAIL: $(tail -2 $X/t.log | tr '\n' ' ')")"
