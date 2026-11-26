"""Phase 6 slice 3's parallel run (PHASE6_PLAN.md §3): one request stream to the C and the Rust
service at once, each over its own copy of one token, the answers compared request by request.

    (cd ALL-MECHANISMS-C-TREE && python3 -I parallel_run.py C-SERVICE RUST-SERVICE)

Both services start with the same arguments, each in its own directory under the same relative
socket names (both listeners, the CA certificate, an OCSP responder over one shared revocation
database). The stream mixes every route: /health, /token, /sign of random messages, /verify of
each side's signature by both sides (randomised signatures are cross-verified, not compared), a
tampered message, refusals (no identity, a key outside the policy, a bad header, a wrong
method, an unknown route), /certificates, and OCSP for a revoked serial, a good one and a
malformed request; half way, `fhsm-ca revoke` revokes the good one, so the database's re-read
is in the stream. Compared: text bodies, certificates and status-only OCSP responses byte for
byte; signed OCSP responses by what openssl reads in them, times aside; signatures by length.
After a SIGTERM both must exit 0 and the records each token's audit log gained must match
(sorted, sequence numbers masked). Prints one line, "parallel run: PASS ..." or "... FAIL ...";
exits 1 on FAIL.
"""
import os, random, re, shutil, signal, socket, subprocess, sys, tempfile, threading, time

C_SVC, R_SVC = sys.argv[1], sys.argv[2]
T, H = os.getcwd(), os.path.dirname(os.path.abspath(__file__))
LIB, TOK, CSR, CA = (f"{T}/{p}" for p in ("libfreehsm.so", "tools/fhsm-token", "tools/fhsm-csr", "tools/fhsm-ca"))
W = tempfile.mkdtemp()
env = dict(os.environ, FHSM_INTEGRITY_ALLOW_UNSIGNED="1", OPENSSL_CONF="/dev/null", FHSM_PIN="userpin1234",
           FHSM_TOKENS_DIR=f"{W}/tok", TMPDIR=f"{W}/tmp")
env.pop("FHSM_AUDIT_LOG", None)  # the log lives in each token directory
os.makedirs(f"{W}/tok")
os.makedirs(f"{W}/tmp")
os.chdir(W)


def fail(why):
    print(f"parallel run: FAIL: {why}")
    sys.exit(1)


def sh(cmd):
    return subprocess.run(cmd, shell=True, env=env, capture_output=True)


for c in [f"FHSM_SO_PIN=sopin1234 {TOK} init --label svc --module {LIB}",
          f"{CSR} keygen --label tls-web01 --module {LIB}", f"{CSR} keygen --label ca --module {LIB}",
          f"{CSR} root --label ca --subject /CN=svc-ca --days 3650 --serial 1 --out ca.der --module {LIB}",
          f"{CA} revoke --db rev.db --serial 0A --reason keyCompromise --date 20260101000000Z",
          "openssl ocsp -issuer ca.der -serial 0x0A -reqout revoked.req -no_nonce",
          "openssl ocsp -issuer ca.der -serial 0x0B -reqout good.req -no_nonce"]:
    if sh(c).returncode:
        fail(f"setup: {c}")
with open("pin", "w") as f:
    f.write("userpin1234\n")
os.chmod("pin", 0o600)
with open("policy", "w") as f:
    f.write("CN=web01\ttls-web01\nCN=web02\ttls-web01\n")


def log_lines(side):
    return sh(f"python3 -I {H}/corpus_norm.py {W}/tok_{side}").stdout.splitlines()


procs = {}
for side, svc in (("c", C_SVC), ("r", R_SVC)):
    shutil.copytree(f"{W}/tok", f"{W}/tok_{side}")
    os.makedirs(f"{W}/{side}")
mark = len(log_lines("c"))
for side, svc in (("c", C_SVC), ("r", R_SVC)):
    args = [svc, "--socket", "s.sock", "--public-socket", "p.sock", "--proxy-uid", str(os.getuid()),
            "--pin-file", f"{W}/pin", "--policy", f"{W}/policy", "--workers", "4", "--pool-max", "8",
            "--ca-cert", f"{W}/ca.der", "--revocation-db", f"{W}/rev.db", "--ocsp-label", "ca"]
    procs[side] = subprocess.Popen(args, cwd=f"{W}/{side}", env=dict(env, FHSM_TOKENS_DIR=f"{W}/tok_{side}"),
                                   stdout=subprocess.DEVNULL, stderr=open(f"{W}/{side}.log", "wb"))
for side in "cr":
    for _ in range(100):
        if b"listening on" in open(f"{W}/{side}.log", "rb").read():
            break
        time.sleep(0.1)
    else:
        for p in procs.values():
            p.kill()
        fail(f"the {side} service never listened: {open(f'{W}/{side}.log').read()[-300:]!r}")


def exchange(path, data):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(15)
    got = b""
    try:
        s.connect(path)
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        while b := s.recv(65536):
            got += b
    except OSError:
        return None
    finally:
        s.close()
    return got


def shape(resp):
    """What must match between the two answers to one request."""
    head, _, body = resp.partition(b"\r\n\r\n")
    if all(32 <= c < 127 or c == 10 for c in body) or len(body) <= 16 or b"pkix-cert" in head:
        return resp
    if b"ocsp-response" in head:
        text = subprocess.run(["openssl", "ocsp", "-respin", "/dev/stdin", "-resp_text", "-noverify"],
                              input=body, capture_output=True).stdout
        keep = rb"Response Status|Cert Status|Serial Number|Revocation (Time|Reason)|Responder Id|Response Type"
        return head + b"\n" + b"\n".join(l.strip() for l in text.splitlines() if re.search(keep, l))
    return head + b"\r\n\r\n<%d bytes>" % len(body)


n = same = lost = signed = crossed = 0
diffs = []


def check(name, public, data):
    """The same request to both services at once; {side: response}."""
    global n, same, lost
    out = {}
    path = "p.sock" if public else "s.sock"
    ts = [threading.Thread(target=lambda s=s: out.__setitem__(s, exchange(f"{W}/{s}/{path}", data))) for s in "cr"]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    n += 1
    if None in out.values():
        lost += 1
        out = {s: v or b"" for s, v in out.items()}
    elif shape(out["c"]) == shape(out["r"]):
        same += 1
    if shape(out["c"]) != shape(out["r"]) and len(diffs) < 5:
        diffs.append(f"{name}: C {shape(out['c'])[:160]!r} / Rust {shape(out['r'])[:160]!r}")
    return out


def post(route, subject, key, body, extra=b""):
    h = b"POST " + route + b" HTTP/1.1\r\n"
    if subject:
        h += b"X-FHSM-Client-Subject: " + subject + b"\r\n"
    if key:
        h += b"X-FHSM-Key: " + key + b"\r\n"
    return h + extra + b"Content-Length: %d\r\n\r\n" % len(body) + body


def verify(sig, msg):
    return post(b"/verify", b"CN=web01", b"tls-web01", sig + msg, b"X-FHSM-Signature-Length: %d\r\n" % len(sig))


rng = random.Random(6)
ocsp = [open(p, "rb").read() for p in ("revoked.req", "good.req")] + [b"not DER"]
ID = b"X-FHSM-Client-Subject: CN=web01\r\n"
revoked_good = None
for i in range(240):
    if i == 120:  # the database changes under both responders
        sh(f"{CA} revoke --db rev.db --serial 0B --reason superseded --date 20260102000000Z")
    k = i % 12
    if k == 0:
        check("health", False, b"GET /health HTTP/1.1\r\n" + ID + b"\r\n")
    elif k == 1:
        check("token", False, b"GET /token HTTP/1.1\r\nX-FHSM-Client-Subject: CN=web02\r\n\r\n")
    elif k in (2, 3, 4):
        msg = rng.randbytes(rng.randint(1, 4000))
        r = check("sign", False, post(b"/sign", b"CN=web01", b"tls-web01", msg))
        if all(r[s].startswith(b"HTTP/1.1 200 ") for s in "cr"):
            signed += 1
            # each side's signature verified by both sides, then a tampered message
            sigs = [r[s].partition(b"\r\n\r\n")[2] for s in "cr"]
            v = [check("verify", False, verify(sig, msg)) for sig in sigs]
            crossed += all(x[s].startswith(b"HTTP/1.1 200 ") for x in v for s in "cr")
            check("verify, tampered", False, verify(sigs[0], msg + b"!"))
    elif k == 5:
        check("certificates", True, b"GET /certificates HTTP/1.1\r\n\r\n")
    elif k in (6, 7):
        q = ocsp[(i // 6) % 3]
        r = check("ocsp", True, b"POST /ocsp HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(q) + q)
        if q is ocsp[1] and i > 120:
            revoked_good = revoked_good is not False and b"Cert Status: revoked" in shape(r["r"])
    elif k == 8 and i < 40:  # three refusals: the budget's first four are free
        check("key outside the policy", False, post(b"/sign", b"CN=web02", b"ca", b"m"))
    elif k == 8:
        check("no identity", False, post(b"/sign", None, b"tls-web01", b"m"))
    elif k == 9:
        check("wrong method", False, b"GET /sign HTTP/1.1\r\n" + ID + b"\r\n")
    elif k == 10:
        check("bad length", False, b"POST /sign HTTP/1.1\r\n" + ID + b"Content-Length: x\r\n\r\n")
    else:
        check("unknown route", False, b"GET /nope HTTP/1.1\r\n" + ID + b"\r\n")

rcs = {}
for side, p in procs.items():
    p.send_signal(signal.SIGTERM)
    try:
        rcs[side] = p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        p.kill()
        rcs[side] = "hung"
seq = re.compile(rb'"seq":[0-9]+')
audit = {s: sorted(seq.sub(b'"seq":0', l) for l in log_lines(s)[mark:]) for s in "cr"}
os.chdir("/")
shutil.rmtree(W, ignore_errors=True)
ok = (same == n and lost == 0 and signed > 0 and crossed == signed and revoked_good is True
      and rcs == {"c": 0, "r": 0} and audit["c"] and audit["c"] == audit["r"])
print(f"parallel run: {'PASS' if ok else 'FAIL'}: {n} requests to both, {same} answered alike, {lost} unanswered, "
      f"{crossed}/{signed} signature pairs valid on both sides, the re-read seen: {revoked_good}, "
      f"exit C {rcs['c']} Rust {rcs['r']}, audit records gained {len(audit['c'])} vs {len(audit['r'])} "
      f"{'same' if audit['c'] == audit['r'] else 'DIFF'}" + (f"; differences: {' | '.join(diffs)}" if diffs else ""))
sys.exit(0 if ok else 1)
