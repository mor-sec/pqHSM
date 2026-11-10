#!/bin/sh
# ===========================================================================
# Copyright 2026 Afchine Madjlessi <afchine.mad@gmail.com>
# SPDX-License-Identifier: Apache-2.0
# ===========================================================================
# pki_tools_characterize.sh --- what the five PKI tools do, written down.
#
# Not a test that passes or fails. It drives every subcommand of fhsm-token,
# fhsm-csr, fhsm-ca, fhsm-sign and fhsm-crypt -- and their main refusals -- and prints a
# normalised transcript: each command's exit code, its messages, and the ASN.1
# shape of what it wrote. Run it before a change and after it, and diff:
#
#     sh tests/pki_tools_characterize.sh > reports/gui/before.txt
#     ...change...
#     sh tests/pki_tools_characterize.sh > reports/gui/after.txt
#     diff reports/gui/before.txt reports/gui/after.txt
#
# Written for docs/fhsm-gui-plan.md stage 0, which moves the tools'
# orchestration into a library: the tools must behave exactly as before, and
# the existing tests reach only part of what they do -- nothing ran
# `fhsm-sign sign`, `cms` or `cms-verify`.
#
# What is masked, because it differs between two runs of unchanged code:
# signature and key bytes, serial numbers (drawn from the token's DRBG),
# dates, and temporary paths. What is kept: exit codes, every message's text,
# and the structure of every artefact -- types, nesting, object identifiers,
# names. Run it twice on the same tree first; if the two transcripts differ,
# this script masks too little, and that has to be fixed before it is trusted.
#
# Needs a module with the composite mechanism: make PROFILE=all-mechanisms all
# ===========================================================================
set -u

LIB="${LIB:-./libfreehsm.so}"
TOK="${TOK:-./tools/fhsm-token}"
CSR="${CSR:-./tools/fhsm-csr}"
CA="${CA:-./tools/fhsm-ca}"
SIGN="${SIGN:-./tools/fhsm-sign}"
CRYPT="${CRYPT:-./tools/fhsm-crypt}"

for t in "$TOK" "$CSR" "$CA" "$SIGN" "$CRYPT"; do
    [ -x "$t" ] || { echo "pki_tools_characterize.sh: $t is not built -- make PROFILE=all-mechanisms all" >&2; exit 2; }
done
for c in openssl python3 flock; do
    command -v $c >/dev/null || { echo "pki_tools_characterize.sh: $c is not on PATH" >&2; exit 2; }
done

export FHSM_INTEGRITY_ALLOW_UNSIGNED=1
export OPENSSL_CONF=/dev/null
FHSM_TOKENS_DIR=$(mktemp -d); export FHSM_TOKENS_DIR
W=$(mktemp -d)
trap 'rm -rf "$FHSM_TOKENS_DIR" "$W"' EXIT

# Values that change between runs of the same code, replaced by placeholders.
mask() {
    sed -E \
        -e 's#^(   out\| )[A-Za-z0-9+/]{16,}={0,2}$#\1<BASE64>#' \
        -e "s#$W#<W>#g" -e "s#$FHSM_TOKENS_DIR#<TOKENS>#g" \
        -e 's#/tmp/tmp\.[A-Za-z0-9]+#<TMP>#g' \
        -e 's/[0-9]{12,14}Z/<TIME>/g' \
        -e 's/[A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4} GMT/<DATE>/g' \
        -e 's/[0-9A-Fa-f]{8,}/<HEX>/g' \
        -e 's/(public|private) [0-9]+/\1 <H>/g'
}
# The PEM body lines carry the key and the signature, which change every run;
# their number, which follows from the size, does not, and is kept.
# The module's own notices (the integrity-bypass NOTE among them) are left in:
# they are the same on every run, and deleting a multi-line block by pattern
# is how a script ends up deleting the messages it exists to compare.

# The ASN.1 shape of a DER file: nesting, types, OIDs and names, no bytes.
shape() {
    f=$1
    if [ ! -s "$f" ]; then echo "    (no file)"; return; fi
    openssl asn1parse -inform DER -in "$f" 2>&1 \
      | sed -E 's/^ *[0-9]+:d= *([0-9]+) +hl= *[0-9]+ +l= *[0-9]+ +(cons|prim): */    d=\1 \2 /' \
      | sed -E -e 's/(INTEGER|BIT STRING|OCTET STRING|UTCTIME|GENERALIZEDTIME) *:.*/\1 :<V>/' \
               -e 's/\[HEX DUMP\]:.*/[HEX DUMP]/' \
      | mask
}

n=0
# run NAME CMD...  -- one step: exit code, then stdout and stderr, masked.
run() {
    name=$1; shift
    n=$((n+1))
    "$@" >"$W/out" 2>"$W/err"; rc=$?
    echo "== $n. $name"
    echo "   exit $rc"
    if [ -s "$W/out" ] && ! LC_ALL=C grep -q "[^[:print:][:space:]]" "$W/out"; then
        sed 's/^/   out| /' "$W/out" | mask
    elif [ -s "$W/out" ]; then
        echo "   out| ($(wc -c < "$W/out" | tr -d ' ') bytes, binary)"
    fi
    [ -s "$W/err" ] && sed 's/^/   err| /' "$W/err" | mask
    return 0
}

echo "pki_tools_characterize: $(basename "$TOK") $(basename "$CSR") $(basename "$CA") $(basename "$SIGN") $(basename "$CRYPT")"
echo

# --- fhsm-token --------------------------------------------------------------
run "token info, nothing initialised"        "$TOK" info --module "$LIB"
run "token init without FHSM_SO_PIN"         env -u FHSM_SO_PIN FHSM_PIN=userpin1234 "$TOK" init --module "$LIB"
run "token init, PIN too short"              env FHSM_SO_PIN=1 FHSM_PIN=userpin1234 "$TOK" init --module "$LIB"
run "token init, --pin refused"              "$TOK" init --pin x --module "$LIB"
run "token init"                             env FHSM_SO_PIN=sopin1234 FHSM_PIN=userpin1234 "$TOK" init --label char --module "$LIB"
run "token init again, no --force"           env FHSM_SO_PIN=sopin1234 FHSM_PIN=userpin1234 "$TOK" init --label char --module "$LIB" --slot 0
run "token info"                             "$TOK" info --module "$LIB"

export FHSM_PIN=userpin1234

# --- fhsm-csr ----------------------------------------------------------------
run "csr without FHSM_PIN"                   env -u FHSM_PIN "$CSR" keygen --label ca --module "$LIB"
run "csr --pin refused"                      "$CSR" keygen --label ca --pin x --module "$LIB"
run "keygen ca"                              "$CSR" keygen --label ca --module "$LIB"
run "keygen ee"                              "$CSR" keygen --label ee --module "$LIB"
run "keygen resp"                            "$CSR" keygen --label resp --module "$LIB"
run "keygen dup (1)"                         "$CSR" keygen --label dup --module "$LIB"
run "keygen dup (2)"                         "$CSR" keygen --label dup --module "$LIB"
run "csr for a missing key"                  "$CSR" csr --label nope --subject "/CN=x" --module "$LIB"
run "csr for an ambiguous label"             "$CSR" csr --label dup --subject "/CN=x" --module "$LIB"
run "csr ee"                                 "$CSR" csr --label ee --subject "/C=FR/O=Simorgh Labs/CN=ee" --out "$W/ee.csr" --module "$LIB"
echo "   shape ee.csr"; shape "$W/ee.csr"
run "csr resp"                               "$CSR" csr --label resp --subject "/CN=Responder" --out "$W/resp.csr" --module "$LIB"
run "csr ee, PEM to stdout"                  "$CSR" csr --label ee --subject "/CN=ee" --pem --module "$LIB"
run "root ca"                                "$CSR" root --label ca --subject "/C=FR/O=Simorgh Labs/CN=Test CA" --days 3650 --serial 1 --out "$W/ca.der" --module "$LIB"
echo "   shape ca.der"; shape "$W/ca.der"

# --- fhsm-ca -----------------------------------------------------------------
run "issue ee"                               "$CA" issue --label ca --ca-cert "$W/ca.der" --csr "$W/ee.csr" --san "DNS:ee.example,IP:192.0.2.1" --crl-url http://example.org/ca.crl --days 365 --out "$W/ee.der" --module "$LIB"
echo "   shape ee.der"; shape "$W/ee.der"
run "issue with an https CRL URL"            "$CA" issue --label ca --ca-cert "$W/ca.der" --csr "$W/ee.csr" --crl-url https://example.org/ca.crl --out "$W/bad.der" --module "$LIB"
run "issue responder"                        "$CA" issue --label ca --ca-cert "$W/ca.der" --csr "$W/resp.csr" --profile ocsp-responder --out "$W/resp.der" --module "$LIB"
echo "   shape resp.der"; shape "$W/resp.der"
serial=$(openssl x509 -inform DER -in "$W/ee.der" -noout -serial 2>/dev/null | cut -d= -f2)
run "revoke, unknown reason"                 "$CA" revoke --db "$W/rev.db" --serial "$serial" --reason nonsense
run "revoke ee"                              "$CA" revoke --db "$W/rev.db" --serial "$serial" --reason keyCompromise --date 20260101000000Z
run "revoke ee again"                        "$CA" revoke --db "$W/rev.db" --serial "$serial" --reason keyCompromise --date 20260101000000Z
echo "   rev.db"; mask < "$W/rev.db" | sed 's/^/    /'
run "crl"                                    "$CA" crl --label ca --ca-cert "$W/ca.der" --db "$W/rev.db" --days 30 --out "$W/ca.crl" --module "$LIB"
echo "   shape ca.crl"; shape "$W/ca.crl"
echo "   rev.db after crl"; mask < "$W/rev.db" | sed 's/^/    /'
openssl ocsp -issuer "$W/ca.der" -cert "$W/ee.der" -reqout "$W/req.der" -no_nonce >/dev/null 2>&1
run "ocsp-respond as the CA"                 "$CA" ocsp-respond --label ca --ca-cert "$W/ca.der" --db "$W/rev.db" --req "$W/req.der" --days 7 --out "$W/direct.ocsp" --module "$LIB"
echo "   shape direct.ocsp"; shape "$W/direct.ocsp"
run "ocsp-respond delegated"                 "$CA" ocsp-respond --label resp --ca-cert "$W/ca.der" --db "$W/rev.db" --req "$W/req.der" --responder-cert "$W/resp.der" --out "$W/deleg.ocsp" --module "$LIB"
echo "   shape deleg.ocsp"; shape "$W/deleg.ocsp"
run "ocsp-respond, responder without EKU"    "$CA" ocsp-respond --label ca --ca-cert "$W/ca.der" --db "$W/rev.db" --req "$W/req.der" --responder-cert "$W/ca.der" --out "$W/no.ocsp" --module "$LIB"

# --- fhsm-sign ---------------------------------------------------------------
printf 'The quick brown fox jumps over the lazy dog\n' > "$W/data"
printf 'The quick brown fox jumps over the lazy cat\n' > "$W/other"
run "sign"                                   "$SIGN" sign --label ee --in "$W/data" --out "$W/data.sig" --module "$LIB"
echo "   data.sig: $(wc -c < "$W/data.sig" | tr -d ' ') bytes"
run "verify"                                 "$SIGN" verify --label ee --sig "$W/data.sig" --in "$W/data" --module "$LIB"
run "verify, other data"                     "$SIGN" verify --label ee --sig "$W/data.sig" --in "$W/other" --module "$LIB"
run "verify, missing key"                    "$SIGN" verify --label nope --sig "$W/data.sig" --in "$W/data" --module "$LIB"
run "cms"                                    "$SIGN" cms --label ee --cert "$W/ee.der" --in "$W/data" --out "$W/data.cms" --module "$LIB"
echo "   shape data.cms"; shape "$W/data.cms"
run "cms-verify"                             "$SIGN" cms-verify --cms "$W/data.cms" --in "$W/data"
run "cms-verify, other data"                 "$SIGN" cms-verify --cms "$W/data.cms" --in "$W/other"
run "sign --pin refused"                     "$SIGN" sign --label ee --pin x --module "$LIB"

# --- usage -------------------------------------------------------------------
run "token, no arguments"                    "$TOK"
run "csr, no arguments"                      "$CSR"
run "ca, no arguments"                       "$CA"
run "sign, no arguments"                     "$SIGN"

# --- Phase 5 decisions (analysis/pqHSM/DIVERGENCES.md DIV-073 to 075) ---------
# What C does today with the inputs each decision changes. Each row runs on a
# copy of the database, so no row moves the ones above it.
cp "$W/rev.db" "$W/days.db"
for d in abc 10x 0 -1 2147483648; do       # DIV-073
    run "issue --days $d"                    "$CA" issue --label ca --ca-cert "$W/ca.der" --csr "$W/ee.csr" --days "$d" --out "$W/days.der" --module "$LIB"
    run "crl --days $d"                      "$CA" crl --label ca --ca-cert "$W/ca.der" --db "$W/days.db" --days "$d" --out "$W/days.crl" --module "$LIB"
    run "ocsp-respond --days $d"             "$CA" ocsp-respond --label ca --ca-cert "$W/ca.der" --db "$W/days.db" --req "$W/req.der" --days "$d" --out "$W/days.ocsp" --module "$LIB"
done
# DIV-075. badsid.cms is data.cms with the last byte of the serial in its
# SignerInfo flipped: the identifier names a certificate the CMS does not carry.
openssl x509 -inform DER -in "$W/ee.der" -out "$W/ee.pem"
python3 -c 'import sys; b = bytearray(open(sys.argv[1], "rb").read()); s = bytes.fromhex(sys.argv[2]); i = b.rfind(s); assert i > 0; b[i + len(s) - 1] ^= 1; open(sys.argv[3], "wb").write(b)' \
    "$W/data.cms" "$serial" "$W/badsid.cms" || echo "   (could not build badsid.cms)"
run "cms-verify --signer, its own cert"      "$SIGN" cms-verify --cms "$W/data.cms" --in "$W/data" --signer "$W/ee.der"
run "cms-verify --signer, PEM"               "$SIGN" cms-verify --cms "$W/data.cms" --in "$W/data" --signer "$W/ee.pem"
run "cms-verify --signer, another cert"      "$SIGN" cms-verify --cms "$W/data.cms" --in "$W/data" --signer "$W/resp.der"
run "cms-verify, identifier names another"   "$SIGN" cms-verify --cms "$W/badsid.cms" --in "$W/data"
# DIV-074. Two writers racing is not repeatable on C, which has no lock and only
# sometimes loses an update. Holding the lock here is: C goes ahead, a tool that
# locks waits its 10 seconds and refuses with the database unchanged.
cp "$W/rev.db" "$W/lock.db"
rserial=$(openssl x509 -inform DER -in "$W/resp.der" -noout -serial 2>/dev/null | cut -d= -f2)
run "revoke while the db is locked"          flock -x "$W/lock.db" "$CA" revoke --db "$W/lock.db" --serial "$rserial" --reason superseded --date 20260102000000Z
run "crl while the db is locked"             flock -x "$W/lock.db" "$CA" crl --label ca --ca-cert "$W/ca.der" --db "$W/lock.db" --days 30 --out "$W/lock.crl" --module "$LIB"
run "ocsp-respond while the db is locked"    flock -x "$W/lock.db" "$CA" ocsp-respond --label ca --ca-cert "$W/ca.der" --db "$W/lock.db" --req "$W/req.der" --out "$W/lock.ocsp" --module "$LIB"
echo "   lock.db"; mask < "$W/lock.db" | sed 's/^/    /'

# --- fhsm-crypt (Phase 5 slice 3) ----------------------------------------------
# Appended, so no row above moves. Deletions come last: they change what the
# rows before them would list.
leftovers() { echo "   temporary files left: $(ls "$W" | grep -c '\.[A-Za-z0-9]\{6\}$')"; }
same() { cmp -s "$1" "$2" && echo "   $(basename "$2"): the same as $(basename "$1")" || echo "   $(basename "$2"): DIFFERS from $(basename "$1")"; }
run "crypt, no arguments"                    "$CRYPT"
run "crypt --pin refused"                    "$CRYPT" list --pin x --module "$LIB"
run "crypt, bad --class"                     "$CRYPT" list --class foo --module "$LIB"
run "crypt --alg outside keygen"             "$CRYPT" list --alg aes128 --module "$LIB"
run "crypt keygen without --alg"             "$CRYPT" keygen --label k --module "$LIB"
run "crypt keygen, a signature algorithm"    "$CRYPT" keygen --label k --alg ecdsa-p256 --module "$LIB"
run "crypt keygen, unknown algorithm"        "$CRYPT" keygen --label k --alg des --module "$LIB"
run "crypt encrypt, --key and --cert"        "$CRYPT" encrypt --key k --cert "$W/ee.der" --in "$W/data" --out "$W/x" --module "$LIB"
run "crypt decrypt without --out"            "$CRYPT" decrypt --in "$W/data" --module "$LIB"
run "crypt without FHSM_PIN"                 env -u FHSM_PIN "$CRYPT" list --module "$LIB"
run "crypt keygen aes128"                    "$CRYPT" keygen --label k128 --alg aes128 --module "$LIB"
run "crypt keygen aes256"                    "$CRYPT" keygen --label k256 --alg aes256 --module "$LIB"
run "crypt keygen hmac"                      "$CRYPT" keygen --label mac --alg hmac --module "$LIB"
run "crypt keygen rsa-oaep"                  "$CRYPT" keygen --label oaep --alg rsa-oaep --module "$LIB"
run "crypt keygen, label taken"              "$CRYPT" keygen --label k256 --alg aes128 --module "$LIB"
run "crypt keygen, a signing key's label"    "$CRYPT" keygen --label ee --alg aes256 --module "$LIB"
run "crypt list"                             "$CRYPT" list --module "$LIB"
run "crypt list --class key"                 "$CRYPT" list --class key --module "$LIB"
run "crypt list --class cert"                "$CRYPT" list --class cert --module "$LIB"
run "crypt show ee"                          "$CRYPT" show --label ee --module "$LIB"
run "crypt show k256"                        "$CRYPT" show --label k256 --module "$LIB"
run "crypt show mac"                         "$CRYPT" show --label mac --module "$LIB"
run "crypt show oaep"                        "$CRYPT" show --label oaep --module "$LIB"
run "crypt show, nothing labelled"           "$CRYPT" show --label nope --module "$LIB"
run "crypt show --class cert ee"             "$CRYPT" show --label ee --class cert --module "$LIB"
run "crypt encrypt k256"                     "$CRYPT" encrypt --key k256 --in "$W/data" --out "$W/data.p7m" --module "$LIB"
echo "   shape data.p7m"; shape "$W/data.p7m"
run "crypt decrypt k256"                     "$CRYPT" decrypt --in "$W/data.p7m" --out "$W/data.dec" --module "$LIB"
same "$W/data" "$W/data.dec"
run "crypt encrypt over an existing file"    "$CRYPT" encrypt --key k256 --in "$W/data" --out "$W/data.p7m" --module "$LIB"
python3 -c 'import sys; b = bytearray(open(sys.argv[1], "rb").read()); b[-20] ^= 1; open(sys.argv[2], "wb").write(b)' "$W/data.p7m" "$W/alt.p7m"
run "crypt decrypt, altered"                 "$CRYPT" decrypt --in "$W/alt.p7m" --out "$W/alt.dec" --module "$LIB"
[ -e "$W/alt.dec" ] && echo "   alt.dec: left behind" || echo "   alt.dec: none"
leftovers
run "crypt decrypt, not CMS"                 "$CRYPT" decrypt --in "$W/data" --out "$W/plain.dec" --module "$LIB"
run "crypt encrypt k128"                     "$CRYPT" encrypt --key k128 --in "$W/data" --out "$W/data128.p7m" --module "$LIB"
run "crypt decrypt k128"                     "$CRYPT" decrypt --in "$W/data128.p7m" --out "$W/data128.dec" --module "$LIB"
same "$W/data" "$W/data128.dec"
run "crypt encrypt with the hmac key"        "$CRYPT" encrypt --key mac --in "$W/data" --out "$W/mac.p7m" --module "$LIB"
run "crypt encrypt, missing key"             "$CRYPT" encrypt --key nope --in "$W/data" --out "$W/nope.p7m" --module "$LIB"
run "crypt encrypt with a signing key"       "$CRYPT" encrypt --key ee --in "$W/data" --out "$W/ee.p7m" --module "$LIB"
run "crypt encrypt oaep"                     "$CRYPT" encrypt --key oaep --in "$W/data" --out "$W/oaep.p7m" --module "$LIB"
echo "   shape oaep.p7m"; shape "$W/oaep.p7m"
run "crypt decrypt oaep"                     "$CRYPT" decrypt --in "$W/oaep.p7m" --out "$W/oaep.dec" --module "$LIB"
same "$W/data" "$W/oaep.dec"
run "crypt encrypt --cert, not RSA"          "$CRYPT" encrypt --cert "$W/ee.der" --in "$W/data" --out "$W/cert.p7m"
run "crypt encrypt --cert, not a cert"       "$CRYPT" encrypt --cert "$W/data" --in "$W/data" --out "$W/cert.p7m"
"$CSR" keygen --label rsa --alg rsa-pkcs1 --module "$LIB" >/dev/null 2>&1
"$CSR" root --label rsa --subject "/CN=RSA signer" --out "$W/rsa.der" --module "$LIB" >/dev/null 2>&1
run "crypt encrypt --cert, a signing RSA key's" "$CRYPT" encrypt --cert "$W/rsa.der" --in "$W/data" --out "$W/rsa.p7m"
echo "   shape rsa.p7m"; shape "$W/rsa.p7m"
run "crypt decrypt, the token key may not"   "$CRYPT" decrypt --in "$W/rsa.p7m" --out "$W/rsa.dec" --module "$LIB"
# A certificate without subjectKeyIdentifier is named by issuer and serial,
# and OpenSSL opens what fhsm-crypt made for it.
printf '[req]\ndistinguished_name = dn\nprompt = no\nx509_extensions = ext\n[dn]\nCN = holder\n[ext]\nsubjectKeyIdentifier = none\nauthorityKeyIdentifier = none\nbasicConstraints = CA:FALSE\n' > "$W/req.cnf"
openssl req -x509 -config "$W/req.cnf" -newkey rsa:2048 -nodes -keyout "$W/holder.key" -out "$W/holder.pem" -days 30 >/dev/null 2>&1 \
    || echo "   (could not make holder.pem)"
run "crypt encrypt --cert, no SKI"           "$CRYPT" encrypt --cert "$W/holder.pem" --in "$W/data" --out "$W/holder.p7m"
echo "   shape holder.p7m"; shape "$W/holder.p7m"
openssl cms -decrypt -inform DER -in "$W/holder.p7m" -recip "$W/holder.pem" -inkey "$W/holder.key" -out "$W/holder.dec" >/dev/null 2>&1 \
    || echo "   openssl cms -decrypt holder.p7m: failed"
same "$W/data" "$W/holder.dec"
run "crypt delete k128, no --yes"            "$CRYPT" delete --label k128 --module "$LIB"
run "crypt delete oaep --class key, no --yes" "$CRYPT" delete --label oaep --class key --module "$LIB"
run "crypt delete --class cert ee"           "$CRYPT" delete --label ee --class cert --module "$LIB"
run "crypt delete, nothing labelled"         "$CRYPT" delete --label nope --module "$LIB"
run "crypt delete k128 --yes"                "$CRYPT" delete --label k128 --yes --module "$LIB"
run "crypt decrypt, its key deleted"         "$CRYPT" decrypt --in "$W/data128.p7m" --out "$W/gone.dec" --module "$LIB"
run "crypt list after delete"                "$CRYPT" list --class key --module "$LIB"
