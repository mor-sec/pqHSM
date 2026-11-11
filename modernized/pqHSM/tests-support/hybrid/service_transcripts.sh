#!/bin/sh
# Phase 6 slice 0 (PHASE6_PLAN.md §2, the brief's golden-transcript entry criterion): the HTTP
# service's transcript, run in a built all-mechanisms tree (service/fhsm-service, tools/,
# libfreehsm.so). Every route on both listeners with its refusals, the request reader's limits,
# peer credentials, the refusal budget, the SIGHUP reload, the start-up refusals, and the audit
# records the service wrote. Each response is printed whole (status line, headers, body);
# binary bodies by length, a signature checked through /verify, a certificate against its file,
# an OCSP response through openssl. Run twice on C to prove the masking, then C against Rust.
#   (cd TREE && sh service_transcripts.sh)
set -u
T=$(pwd)
H=$(cd "$(dirname "$0")" && pwd)
SVC=${SVC:-$T/service/fhsm-service}
LIB=$T/libfreehsm.so
TOK=$T/tools/fhsm-token CSR=$T/tools/fhsm-csr CA=$T/tools/fhsm-ca
for f in "$SVC" "$TOK" "$CSR" "$CA"; do [ -x "$f" ] || { echo "service_transcripts.sh: $f is not built" >&2; exit 2; }; done

export FHSM_INTEGRITY_ALLOW_UNSIGNED=1 OPENSSL_CONF=/dev/null FHSM_PIN=userpin1234
W=$(mktemp -d)
export FHSM_TOKENS_DIR=$W/tok TMPDIR=$W/tmp
mkdir -p "$FHSM_TOKENS_DIR" "$TMPDIR" "$W/empty"
cd "$W" || exit 2
ME=$(id -u)
PIDS=""
trap 'for p in $PIDS; do kill $p 2>/dev/null; done; cd /; rm -rf "$W"' EXIT

mask() { sed -E -e "s#$W#<W>#g" -e "s/uid $ME only/uid <UID> only/" -e 's/(serial=FHSM-)[0-9a-f]+/\1<HEX>/'; }
# A held identity's Retry-After counts down in whole seconds from its restored 32 s; asked for
# right after start-up it is 30 to 32. Masked in the rows that set RA=1, and only there: the
# value is what tells the budget's 429 from the in-flight cap's (always 1).
ra() { if [ "${RA:-}" ]; then awk '{ if (match($0, /Retry-After: [0-9]+$/)) { v = substr($0, RSTART + 13) + 0;
  $0 = "   | Retry-After: " ((v >= 30 && v <= 32) ? "<30..32>" : v) } print }'; else cat; fi; }

# --- the token, keys, CA, revocation database, PIN and policy ----------------------------------
{ FHSM_SO_PIN=sopin1234 $TOK init --label svc --module $LIB &&
  for k in tls-web01 secret-ca ca; do $CSR keygen --label $k --module $LIB || exit 1; done &&
  $CSR root --label ca --subject /CN=svc-ca --days 3650 --serial 1 --out ca.der --module $LIB &&
  $CA revoke --db rev.db --serial 0A --reason keyCompromise --date 20260101000000Z &&
  $CSR keygen --label resp --module $LIB && $CSR csr --label resp --subject /CN=svc-responder --out resp.csr --module $LIB &&
  $CA issue --label ca --ca-cert ca.der --csr resp.csr --profile ocsp-responder --out resp.der --module $LIB; } > setup.log 2>&1 ||
  { echo "setup failed:"; cat setup.log; exit 1; }
printf 'userpin1234\n' > pin && chmod 600 pin && : > emptypin && chmod 600 emptypin
printf 'wrongpin99\n' > badpin && chmod 600 badpin
POL='# fhsm-service authorisation policy v1\n# SUBJECT\tKEY-LABEL\nCN=web01\ttls-web01\nCN=web01\tghost-key\nCN=web02\ttls-web01\n'
printf "$POL" > policy
printf '# fhsm-service authorisation policy v1\nno tab on this line\n' > badpolicy
printf 'the quick brown fox' > msg
openssl ocsp -issuer ca.der -serial 0x0A -reqout revoked.req -no_nonce > /dev/null 2>&1
openssl ocsp -issuer ca.der -serial 0x0B -reqout good.req -no_nonce > /dev/null 2>&1
audit_from=$(python3 -I $H/corpus_norm.py "$FHSM_TOKENS_DIR" | wc -l)

# --- helpers -----------------------------------------------------------------------------------
# The row number is kept in a file: req runs at the end of a pipeline, in a subshell.
echo 0 > n
num() { n=$(($(cat n) + 1)); echo $n > n; }
# show FILE: the response, its head line by line, its body as text or by length (hex if short).
show() {
    python3 -I - "$1" <<'PY'
import sys
b = open(sys.argv[1], "rb").read()
if not b:
    print("   (no response)"); sys.exit()
head, sep, body = b.partition(b"\r\n\r\n")
if not sep:
    head, body = b, b""
for l in head.split(b"\r\n"):
    print("   | " + l.decode("latin-1"))
open(sys.argv[1] + ".body", "wb").write(body)
if not body:
    pass
elif all(32 <= c < 127 or c == 10 for c in body):
    for l in body.decode().split("\n")[:-1] if body.endswith(b"\n") else body.decode().split("\n"):
        print("   > " + l)
elif len(body) <= 16:
    print("   > (%d bytes) %s" % (len(body), body.hex()))
else:
    print("   > (%d bytes, binary)" % len(body))
PY
}
# req NAME SOCKET [MODE] < request: one exchange, printed.
req() {
    num
    python3 -I $H/service_client.py "$2" r.out "${3:-send}"
    echo "== $n. $1"
    show r.out | mask | ra
}
# runx NAME ARGS...: a start-up that must refuse; exit code and stderr.
runx() {
    num; name=$1; shift
    timeout 20 "$SVC" "$@" > x.out 2> x.err; rc=$?
    echo "== $n. start: $name"; echo "   exit $rc"
    if [ -s usage.txt ] && cmp -s x.err usage.txt; then echo "   err| (the usage text)"
    else sed 's/^/   err| /' x.err | mask; fi
    [ -s x.out ] && sed 's/^/   out| /' x.out | mask
    return 0
}
# start NAME SOCKET ARGS...: the service in the background, waited for by its socket.
start() {
    name=$1 sock=$2; shift 2
    "$SVC" --socket $sock "$@" > $name.log 2>&1 &
    eval "P_$name=$!"; PIDS="$PIDS $!"
    # "listening on" is written once every socket is bound, the public one included.
    i=0; while ! grep -q 'listening on' $name.log && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
    grep -q 'listening on' $name.log || { echo "== service $name never listened"; mask < $name.log; }
}
stop() {
    eval "p=\$P_$1"; kill -TERM $p; wait $p; rc=$?
    echo "== service $1 stopped, exit $rc"; sed 's/^/   log| /' $1.log | mask
}
crlf() { printf '%b' "$1"; }
ID='X-FHSM-Client-Subject: CN=web01\r\n'
A=$(printf 'a%.0s' $(seq 1 300))

echo "service_transcripts: $(basename "$SVC")"

# --- start-up -----------------------------------------------------------------------------------
"$SVC" > /dev/null 2> usage.txt
echo "== usage"; sed 's/^/   err| /' usage.txt
U="--proxy-uid $ME --pin-file pin --policy policy"
runx "--profile" --profile
runx "no arguments"
runx "--workers 0" --socket s.sock $U --workers 0
runx "--proxy-uid -1" --socket s.sock --proxy-uid -1 --policy policy
runx "--ocsp-days 366" --socket s.sock $U --ocsp-days 366
runx "unknown option" --socket s.sock $U --frobnicate
runx "--ca-cert without --public-socket" --socket s.sock $U --ca-cert ca.der
runx "--ca-cert missing" --socket s.sock $U --public-socket q.sock --ca-cert nope.der
runx "--ocsp-label without --public-socket" --socket s.sock $U --ocsp-label ca
runx "--revocation-db without --ocsp-label" --socket s.sock $U --public-socket q.sock --ca-cert ca.der --revocation-db rev.db
runx "--revocation-db without --ca-cert" --socket s.sock $U --public-socket q.sock --revocation-db rev.db --ocsp-label ca
runx "--responder-cert without a responder" --socket s.sock $U --public-socket q.sock --ca-cert ca.der --responder-cert ca.der
runx "--responder-cert without the OCSP EKU" --socket s.sock $U --public-socket q.sock --ca-cert ca.der --revocation-db rev.db --ocsp-label ca --responder-cert ca.der
runx "revocation database unreadable" --socket s.sock $U --public-socket q.sock --ca-cert ca.der --revocation-db badpolicy --ocsp-label ca
runx "policy missing" --socket s.sock --proxy-uid $ME --pin-file pin --policy nope
runx "policy malformed" --socket s.sock --proxy-uid $ME --pin-file pin --policy badpolicy
runx "--pool-max below the workers" --socket s.sock $U --workers 4 --pool-max 2
runx "--pool-max below workers + public" --socket s.sock $U --workers 4 --pool-max 5 --public-socket q.sock
num; (ulimit -n 1024; timeout 20 "$SVC" --socket s.sock $U --queue-depth 4096 > x.out 2> x.err; echo "rc=$?" > x.rc)
echo "== $n. start: --queue-depth past the descriptor limit (1024)"; echo "   exit $(sed 's/rc=//' x.rc)"; sed 's/^/   err| /' x.err | mask
(export FHSM_TOKENS_DIR=$W/empty; runx "no token" --socket s.sock $U)
runx "PIN file missing" --socket s.sock --proxy-uid $ME --pin-file nopin --policy policy
runx "PIN file empty" --socket s.sock --proxy-uid $ME --pin-file emptypin --policy policy
runx "wrong PIN" --socket s.sock --proxy-uid $ME --pin-file badpin --policy policy
runx "socket path too long" --socket "$W/$A.sock" $U

# --- the main service: both listeners, OCSP on ---------------------------------------------------
# CN=held starts with ten refusals restored from the budget file: 32 s held from start-up.
printf '# fhsm-service refusal budget v1 -- count<TAB>subject\n10\tCN=held\n' > "$FHSM_TOKENS_DIR/budget"
start main p.sock $U --workers 4 --pool-max 8 --queue-depth 32 \
  --public-socket q.sock --public-workers 2 --ca-cert ca.der --revocation-db rev.db --ocsp-label ca
echo "== socket modes: $(stat -c %a p.sock) $(stat -c %a q.sock)"
crlf "POST /sign HTTP/1.1\r\nX-FHSM-Client-Subject: CN=held\r\nX-FHSM-Key: tls-web01\r\nContent-Length: 3\r\n\r\nabc" | RA=1 req "budget: held (restored)" p.sock
crlf "GET /health HTTP/1.1\r\nX-FHSM-Client-Subject: CN=held\r\n\r\n" | RA=1 req "budget: held on any route" p.sock

crlf "GET /health HTTP/1.1\r\n$ID\r\n" | req "health" p.sock
crlf "GET /health HTTP/1.1\r\n\r\n" | req "health, no identity" p.sock
crlf "GET /token HTTP/1.1\r\n$ID\r\n" | req "token" p.sock
crlf "GET /health HTTP/1.1\r\n${ID}X-FHSM-Client-Subject: CN=web02\r\n\r\n" | req "two subjects" p.sock
crlf "GET /health HTTP/1.1\r\nX-FHSM-Client-Subject: $(printf 'c%.0s' $(seq 1 128))\r\n\r\n" | req "subject of 128 bytes" p.sock
crlf "GET /health HTTP/1.1\r\nX-FHSM-Client-Subject: $(printf 'c%.0s' $(seq 1 127))\r\n\r\n" | req "subject of 127 bytes" p.sock
crlf "GET /health HTTP/1.1\r\nX-FHSM-Client-Subject:\r\n\r\n" | req "subject empty" p.sock
crlf "PUT /health HTTP/1.1\r\n$ID\r\n" | req "method PUT" p.sock
crlf "OPTIONSX /health HTTP/1.1\r\n$ID\r\n" | req "method of 8 bytes" p.sock
crlf " /health HTTP/1.1\r\n$ID\r\n" | req "method empty" p.sock
crlf "GET health HTTP/1.1\r\n$ID\r\n" | req "target without /" p.sock
crlf "GET /$(printf 'h%.0s' $(seq 1 255)) HTTP/1.1\r\n$ID\r\n" | req "target of 256 bytes" p.sock
crlf "GET /he\001lth HTTP/1.1\r\n$ID\r\n" | req "target with a control byte" p.sock
crlf "GET /$A$A$A$A HTTP/1.1\r\n$ID\r\n" | req "request line past 1024" p.sock
crlf "GET\r\n$ID\r\n" | req "request line without spaces" p.sock
crlf "GET /health\r\n$ID\r\n" | req "request line without a version" p.sock
crlf "GET /health HTTP/1.0\r\n$ID\r\n" | req "HTTP/1.0" p.sock
crlf "GET /health HTTP/1.1\r\n${ID}no colon\r\n\r\n" | req "header without a colon" p.sock
crlf "GET /health HTTP/1.1\r\n$ID: empty name\r\n\r\n" | req "header name empty" p.sock
crlf "GET /health HTTP/1.1\r\n$ID$(printf 'n%.0s' $(seq 1 65)): x\r\n\r\n" | req "header name of 65 bytes" p.sock
crlf "GET /health HTTP/1.1\r\n${ID}X-Long: $(printf 'v%.0s' $(seq 1 257))\r\n\r\n" | req "header value of 257 bytes" p.sock
crlf "GET /health HTTP/1.1\r\n${ID}X-Long: $(printf 'v%.0s' $(seq 1 256))   \r\n\r\n" | req "header value of 256 bytes, trailing blanks" p.sock
crlf "GET /health HTTP/1.1\r\n${ID}X-Ctl: a\001b\r\n\r\n" | req "header value with a control byte" p.sock
crlf "GET /health HTTP/1.1\r\n$ID$(for i in $(seq 1 32); do printf 'X-H%d: v\\r\\n' $i; done)\r\n" | req "33 headers" p.sock
crlf "GET /health HTTP/1.1\r\n$ID$(for i in $(seq 1 31); do printf 'X-H%d: v\\r\\n' $i; done)\r\n" | req "32 headers" p.sock
{ crlf "GET /health HTTP/1.1\r\n$ID"; for i in $(seq 1 40); do printf 'X-Pad: %s\r\n' "$(printf 'p%.0s' $(seq 1 250))"; done; } | req "headers past 8192 bytes" p.sock
crlf "POST /sign HTTP/1.1\r\n${ID}Content-Length: 3\r\nContent-Length: 3\r\n\r\nabc" | req "Content-Length twice" p.sock
crlf "POST /sign HTTP/1.1\r\n${ID}Content-Length: 3x\r\n\r\nabc" | req "Content-Length not a number" p.sock
crlf "POST /sign HTTP/1.1\r\n${ID}Content-Length: 0000000003\r\n\r\nabc" | req "Content-Length of 10 digits" p.sock
crlf "POST /sign HTTP/1.1\r\n${ID}Content-Length: 65537\r\n\r\nabc" | req "Content-Length 65537" p.sock
crlf "POST /sign HTTP/1.1\r\n${ID}Transfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n" | req "Transfer-Encoding" p.sock
crlf "POST /sign HTTP/1.1\r\n${ID}X-FHSM-Key: tls-web01\r\nContent-Length: 10\r\n\r\nabc" | req "body shorter than declared" p.sock
crlf "GET /health HTTP/1.1\r\n$ID" | req "closed before the blank line" p.sock
crlf "GET /health HTTP/1.1\r\nx-fhsm-client-subject: CN=web01\r\n\r\n" | req "header name in lower case" p.sock
crlf "GET /health HTTP/1.1\r\nX-Fhsm-CLIENT-Subject: CN=web01\r\n\r\n" | req "header name in mixed case" p.sock
crlf "GET /health HTTP/1.1\r\nX-FHSM-Client-Subject:CN=web01\r\n\r\n" | req "no space after the colon" p.sock
crlf "GET /health HTTP/1.1\r\nX-FHSM-Client-Subject: \t CN=web01 \t\r\n\r\n" | req "value with blanks around it" p.sock
crlf "GET /health HTTP/1.1\n${ID}\n" | req "bare LF line endings" p.sock
crlf "GET /health HTTP/1.1\r\n$ID\r\nGET /token HTTP/1.1\r\n$ID\r\n" | req "two requests on one connection" p.sock
crlf "POST /sign HTTP/1.1\r\n${ID}content-length: 3\r\nx-fhsm-key: tls-web01\r\n\r\nabc" | req "sign, header names in lower case" p.sock
crlf "GET /nope HTTP/1.1\r\n$ID\r\n" | req "unknown route" p.sock
crlf "GET /health?x=1 HTTP/1.1\r\n$ID\r\n" | req "health with a query" p.sock
crlf "POST /health HTTP/1.1\r\n$ID\r\n" | req "POST /health" p.sock
crlf "GET /certificates HTTP/1.1\r\n$ID\r\n" | req "certificates on the private socket" p.sock
crlf "POST /ocsp HTTP/1.1\r\n$ID\r\n" | req "ocsp on the private socket" p.sock
crlf "GET /sign HTTP/1.1\r\n$ID\r\n" | req "GET /sign" p.sock
crlf "GET /verify HTTP/1.1\r\n$ID\r\n" | req "GET /verify" p.sock

S="POST /sign HTTP/1.1\r\n$ID"
crlf "${S}Content-Length: 3\r\n\r\nabc" | req "sign, no key" p.sock
crlf "${S}X-FHSM-Key: tls-web01\r\nX-FHSM-Key: tls-web01\r\nContent-Length: 3\r\n\r\nabc" | req "sign, key twice" p.sock
crlf "${S}X-FHSM-Key: $(printf 'k%.0s' $(seq 1 64))\r\nContent-Length: 3\r\n\r\nabc" | req "sign, key of 64 bytes" p.sock
crlf "${S}X-FHSM-Key: tls-web01\r\n\r\n" | req "sign, empty body" p.sock
crlf "${S}X-FHSM-Key: secret-ca\r\nContent-Length: 3\r\n\r\nabc" | req "sign, key not in the policy" p.sock
crlf "${S}X-FHSM-Key: ghost-key\r\nContent-Length: 3\r\n\r\nabc" | req "sign, key in the policy, absent" p.sock
crlf "${S}X-FHSM-Key: tls-web01\r\nContent-Length: $(wc -c < msg)\r\n\r\n$(cat msg)" | req "sign" p.sock
cp r.out.body sig
SL=$(wc -c < sig)

V="POST /verify HTTP/1.1\r\n$ID"
crlf "${V}X-FHSM-Signature-Length: 1\r\nContent-Length: 3\r\n\r\nabc" | req "verify, no key" p.sock
crlf "${V}X-FHSM-Key: tls-web01\r\nContent-Length: 3\r\n\r\nabc" | req "verify, no signature length" p.sock
crlf "${V}X-FHSM-Key: tls-web01\r\nX-FHSM-Signature-Length: 1\r\nX-FHSM-Signature-Length: 1\r\nContent-Length: 3\r\n\r\nabc" | req "verify, signature length twice" p.sock
crlf "${V}X-FHSM-Key: tls-web01\r\nX-FHSM-Key: tls-web01\r\nX-FHSM-Signature-Length: 1\r\nContent-Length: 3\r\n\r\nabc" | req "verify, key twice" p.sock
for l in 0 -1 1x 65537 99999999999999999999; do
  crlf "${V}X-FHSM-Key: tls-web01\r\nX-FHSM-Signature-Length: $l\r\nContent-Length: 3\r\n\r\nabc" | req "verify, signature length $l" p.sock
done
crlf "${V}X-FHSM-Key: tls-web01\r\nX-FHSM-Signature-Length: 1\r\n\r\n" | req "verify, empty body" p.sock
crlf "${V}X-FHSM-Key: tls-web01\r\nX-FHSM-Signature-Length: 3\r\nContent-Length: 3\r\n\r\nabc" | req "verify, signature length covers the body" p.sock
{ crlf "${V}X-FHSM-Key: tls-web01\r\nX-FHSM-Signature-Length: $SL\r\nContent-Length: $((SL + $(wc -c < msg)))\r\n\r\n"; cat sig msg; } | req "verify the signature" p.sock
{ crlf "${V}X-FHSM-Key: tls-web01\r\nX-FHSM-Signature-Length: $SL\r\nContent-Length: $((SL + 3))\r\n\r\n"; cat sig; printf 'cat'; } | req "verify, other message" p.sock
{ crlf "POST /verify HTTP/1.1\r\nX-FHSM-Client-Subject: CN=web02\r\nX-FHSM-Key: secret-ca\r\nX-FHSM-Signature-Length: $SL\r\nContent-Length: $((SL + 3))\r\n\r\n"; cat sig; printf 'cat'; } | req "verify, key not in the policy" p.sock
{ crlf "${V}X-FHSM-Key: secret-ca\r\nX-FHSM-Signature-Length: $SL\r\nContent-Length: $((SL + 3))\r\n\r\n"; cat sig; printf 'cat'; } | req "verify, a key not the signer's" p.sock

# The refusal budget: four refusals free, the fifth earns a delay (identity_limited). Whether
# the next request lands inside that 1 s depends on the second boundary, so holding is shown
# with CN=held, restored at ten refusals, right after start-up (above).
P="POST /sign HTTP/1.1\r\nX-FHSM-Client-Subject: CN=prober\r\nX-FHSM-Key: tls-web01\r\nContent-Length: 3\r\n\r\nabc"
for i in 1 2 3 4 5; do crlf "$P" | req "budget: refusal $i" p.sock; done
crlf "GET /health HTTP/1.1\r\n$ID\r\n" | req "budget: another subject unaffected" p.sock

req "silent connection" p.sock silent < /dev/null
req "connect and hang up" p.sock hangup < /dev/null
# The burst closes BURST_COOLDOWN_S (5) after its last event: wait for that record, so it lands
# here and not at stop.
i=0; while ! grep -qs hung_up_early_over "$FHSM_TOKENS_DIR"/audit.log* && [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done
echo "== hung_up_early_over recorded: $([ $i -lt 100 ] && echo yes || echo no)"

# SIGHUP: a new policy takes effect at the next request; a malformed one leaves it in force.
K="POST /sign HTTP/1.1\r\nX-FHSM-Client-Subject: CN=web02\r\nX-FHSM-Key: secret-ca\r\nContent-Length: 3\r\n\r\nabc"
{ printf "$POL"; printf 'CN=web02\tsecret-ca\n'; } > policy.new && mv policy.new policy
kill -HUP $P_main; sleep 0.2
crlf "$K" | req "after SIGHUP with a new rule" p.sock
cp badpolicy policy
kill -HUP $P_main; sleep 0.2
crlf "$K" | req "after SIGHUP with a malformed policy" p.sock
printf "$POL" > policy

# The public listener.
crlf "GET /health HTTP/1.1\r\n\r\n" | req "public: health" q.sock
crlf "GET /health HTTP/1.1\r\n$ID\r\n" | req "public: health, an identity offered" q.sock
crlf "GET /certificates HTTP/1.1\r\n\r\n" | req "public: certificates" q.sock
cmp -s r.out.body ca.der && echo "   > = ca.der" || echo "   > differs from ca.der"
crlf "POST /certificates HTTP/1.1\r\n\r\n" | req "public: POST /certificates" q.sock
crlf "GET /ocsp HTTP/1.1\r\n\r\n" | req "public: GET /ocsp" q.sock
crlf "POST /ocsp HTTP/1.1\r\n\r\n" | req "public: ocsp, empty body" q.sock
crlf "POST /ocsp HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello" | req "public: ocsp, not DER" q.sock
for s in revoked good; do
  { crlf "POST /ocsp HTTP/1.1\r\nContent-Type: application/ocsp-request\r\nContent-Length: $(wc -c < $s.req)\r\n\r\n"; cat $s.req; } | req "public: ocsp, $s serial" q.sock
  openssl ocsp -respin r.out.body -resp_text -noverify 2>&1 | grep -E "Response Status|Cert Status|Serial Number|Revocation (Time|Reason)|Responder Id|Response Type" | sed 's/^ */   ocsp| /' | mask
done
crlf "GET /nope HTTP/1.1\r\n\r\n" | req "public: unknown route" q.sock
crlf "POST /sign HTTP/1.1\r\n${ID}X-FHSM-Key: tls-web01\r\nContent-Length: 3\r\n\r\nabc" | req "public: POST /sign" q.sock
crlf "POST /verify HTTP/1.1\r\n${ID}X-FHSM-Key: tls-web01\r\nX-FHSM-Signature-Length: 1\r\nContent-Length: 3\r\n\r\nabc" | req "public: POST /verify" q.sock
crlf "GET /token HTTP/1.1\r\n$ID\r\n" | req "public: GET /token" q.sock
crlf "GET /health HTTP/1.0\r\n\r\n" | req "public: HTTP/1.0" q.sock
req "public: silent connection" q.sock silent < /dev/null
crlf "POST /sign HTTP/1.1\r\n${ID}X-FHSM-Key: tls-web01\r\nContent-Length: 10\r\n\r\nabc" | req "body not finished within 10 s" p.sock hold
stop main

# The delegated responder: the same answers signed by CN=svc-responder, its certificate attached.
start deleg d.sock $U --public-socket dq.sock --ca-cert ca.der --revocation-db rev.db --ocsp-label resp --responder-cert resp.der
for s in revoked good; do
  { crlf "POST /ocsp HTTP/1.1\r\nContent-Type: application/ocsp-request\r\nContent-Length: $(wc -c < $s.req)\r\n\r\n"; cat $s.req; } | req "delegated: ocsp, $s serial" dq.sock
  openssl ocsp -respin r.out.body -resp_text -noverify 2>&1 | grep -E "Response Status|Cert Status|Serial Number: 0|Revocation (Time|Reason)|Responder Id|Response Type|Subject: |Issuer: |OCSP Signing" | sed 's/^ */   ocsp| /' | mask
done
stop deleg

# The queue: one connection held silent fills a depth of 1, and the next is refused at once.
start tight t.sock $U --queue-depth 1
num; python3 -I $H/service_client.py t.sock held.out silent < /dev/null & HELD=$!
sleep 0.3
python3 -I $H/service_client.py t.sock r.out send < /dev/null
echo "== $n. queue of 1 full"; show r.out | mask
wait $HELD; num; echo "== $n. the connection that filled it"; show held.out | mask
stop tight

# Without a certificate or a responder, and with a proxy uid that is not ours.
start bare b.sock $U --public-socket bq.sock
crlf "GET /certificates HTTP/1.1\r\n\r\n" | req "bare: certificates" bq.sock
crlf "POST /ocsp HTTP/1.1\r\nContent-Length: 1\r\n\r\nx" | req "bare: ocsp" bq.sock
stop bare
start peer c.sock --proxy-uid $((ME + 1)) --pin-file pin --policy policy --public-socket cq.sock
crlf "GET /health HTTP/1.1\r\n$ID\r\n" | req "another proxy uid: private" c.sock
crlf "GET /health HTTP/1.1\r\n\r\n" | req "another proxy uid: public" cq.sock
stop peer

# --- what the service wrote to the audit log (ts and MACs normalised) ---------------------------
echo "== audit, after setup"
python3 -I $H/corpus_norm.py "$FHSM_TOKENS_DIR" | tail -n +$((audit_from + 1)) | sed 's/^/   /' | mask
echo "== budget file"; [ -f "$FHSM_TOKENS_DIR/budget" ] && sed 's/^/   /' "$FHSM_TOKENS_DIR/budget" | mask || echo "   (none)"
