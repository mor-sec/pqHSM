#!/bin/sh
# RULE-021/022 over fhsm-ca (PHASE5_PLAN.md §4), run in a built tree: issue --days 10 and
# crl --days 7 on a database at crlNumber 41, under the real clock, bounded by the times
# taken before and after. Expect notAfter - notBefore = 10 d + 3600 s (the backdate),
# notBefore in [t0 - 3600, t1 - 3600], nextUpdate - thisUpdate = 7 d, thisUpdate in [t0, t1],
# CRL number 42, database 42. Prints one line.
set -u
export FHSM_TOKENS_DIR=$(mktemp -d) FHSM_INTEGRITY_ALLOW_UNSIGNED=1 FHSM_PIN=userpin1234
W=$FHSM_TOKENS_DIR
FHSM_SO_PIN=sopin1234 tools/fhsm-token init --label dates > /dev/null 2>&1 &&
  tools/fhsm-csr keygen --label ca > /dev/null 2>&1 &&
  tools/fhsm-csr keygen --label ee > /dev/null 2>&1 &&
  tools/fhsm-csr root --label ca --subject /CN=ca --days 3650 --serial 1 --out $W/ca.der > /dev/null 2>&1 &&
  tools/fhsm-csr csr --label ee --subject /CN=ee --out $W/ee.csr > /dev/null 2>&1 ||
  { echo "setup failed"; exit 1; }
printf '# fhsm-ca revocation database v1\ncrlNumber 41\n' > $W/rev.db
ep() { date -u -d "$1" +%s; }
t0=$(date -u +%s)
tools/fhsm-ca issue --label ca --ca-cert $W/ca.der --csr $W/ee.csr --days 10 --out $W/ee.der > /dev/null 2>&1 &&
  tools/fhsm-ca crl --label ca --ca-cert $W/ca.der --db $W/rev.db --days 7 --out $W/ca.crl > /dev/null 2>&1 ||
  { echo "issue or crl failed"; exit 1; }
t1=$(date -u +%s)
nb=$(ep "$(openssl x509 -inform DER -in $W/ee.der -noout -startdate | cut -d= -f2)")
na=$(ep "$(openssl x509 -inform DER -in $W/ee.der -noout -enddate | cut -d= -f2)")
lu=$(ep "$(openssl crl -inform DER -in $W/ca.crl -noout -lastupdate | cut -d= -f2)")
nu=$(ep "$(openssl crl -inform DER -in $W/ca.crl -noout -nextupdate | cut -d= -f2)")
num=$(openssl crl -inform DER -in $W/ca.crl -noout -crlnumber | cut -d= -f2)
num=${num#0x}
ok() { [ "$@" ] && echo ok || echo BAD; }
echo "issue span $(ok $((na - nb)) -eq $((10 * 86400 + 3600))), notBefore" \
  "$(ok $nb -ge $((t0 - 3600)) -a $nb -le $((t1 - 3600))); crl span $(ok $((nu - lu)) -eq $((7 * 86400)))," \
  "thisUpdate $(ok $lu -ge $t0 -a $lu -le $t1), number $((0x$num)), database $(sed -n 's/^crlNumber //p' $W/rev.db)"
rm -rf "$W"
