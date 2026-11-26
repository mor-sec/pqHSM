"""DIV-084: the Rust build's names mapped back to C's in Rust output, before it is compared with
C. Only the decided forms are mapped, so anything else the rename touched still shows.

    python3 -I rename_back.py FILE...      rewrites each file in place
    python3 -I rename_back.py              runs its self-check

Mapped: a message prefix `pqhsm-X:` (the name with its colon; usage text and hints keep the
fhsm-* names, so a pqhsm-* there is a difference); the CK_INFO, slot and token strings as words
in text, with no padding touched; and, inside a run of hex digits (the harness prints PKCS#11
structures as hex), the same strings as space-padded fields, at the field's own width. A field
too narrow for C's string is left as it is, so the difference shows.
"""
import re, sys

PREFIX = rb"\bpqhsm-(service|ca|sign|crypt|token|csr):"
# (new, old), longest first, so a shorter name never matches inside a longer one
NAMES = [(b"pqHSM - TEST MODE, NOT PROD", b"FreeHSM C - TEST MODE, NOT PROD"),
         (b"pqHSM PKCS#11 module", b"FreeHSM C PKCS#11 module"),
         (b"pqHSM-TESTMODE", b"FreeHSM-TESTMODE"),
         (b"pqHSM-v1", b"FreeHSM-C-v1"),
         (b"pqHSM", b"Simorgh Labs")]
WORD = (rb"(?<![-A-Za-z0-9/_%])", rb"(?![-A-Za-z0-9/_%])")
SLOT = rb"pqHSM slot (\d+) \(([a-z]+)\)"


def slot(m):
    return b"FreeHSM slot %s (%s)" % (m[1], m[2])


def in_fields(b):
    def fit(old):
        return lambda m: old.ljust(len(m[0])) if len(m[0]) >= len(old) else m[0]
    # fields abut (a full 32-byte label runs straight into the manufacturer): no lookbehind
    b = re.sub(SLOT + rb" *", lambda m: fit(slot(m))(m), b)
    for new, old in NAMES:
        b = re.sub(re.escape(new) + WORD[1] + rb" *", fit(old), b)
    return b


def in_text(b):
    b = re.sub(PREFIX, rb"fhsm-\1:", b)
    b = b.replace(b"manufacturer=pqHSM;", b"manufacturer=Simorgh%20Labs;")  # a pkcs11 URI
    b = re.sub(rb"(?<![0-9a-f])(?:[0-9a-f]{2}){8,}(?![0-9a-f])",
               lambda m: in_fields(bytes.fromhex(m[0].decode())).hex().encode(), b)
    b = re.sub(WORD[0] + SLOT + WORD[1], slot, b)
    for new, old in NAMES:
        b = re.sub(WORD[0] + re.escape(new) + WORD[1], old, b)
    return b


if len(sys.argv) > 1:
    for p in sys.argv[1:]:
        with open(p, "rb") as f:
            out = in_text(f.read())
        with open(p, "wb") as f:  # written only once mapped: a failure leaves the file whole
            f.write(out)
else:
    hx = lambda s, n: s.ljust(n).hex().encode()
    t = in_text
    assert t(hx(b"pqHSM", 32) + hx(b"pqHSM-TESTMODE", 16)) == hx(b"Simorgh Labs", 32) + b"FreeHSM-TESTMODE".hex().encode()
    assert t(hx(b"pqHSM slot 0 (initialized)", 64)) == hx(b"FreeHSM slot 0 (initialized)", 64)
    assert t(hx(b"pqHSM", 8)) == hx(b"pqHSM", 8), "a field too narrow for C's string is left"
    assert t((b"z" * 32 + b"pqHSM".ljust(32)).hex().encode()) == (b"z" * 32 + b"Simorgh Labs".ljust(32)).hex().encode()
    assert t(b"pqhsm-ca: x; pqHSM slot 2 (empty) ok\nmodel=pqHSM-v1;manufacturer=pqHSM;") == \
        b"fhsm-ca: x; FreeHSM slot 2 (empty) ok\nmodel=FreeHSM-C-v1;manufacturer=Simorgh%20Labs;"
    assert t(b"run pqhsm-token init; service/pqhsm-service") == b"run pqhsm-token init; service/pqhsm-service"
    assert t(b"manufacturer: pqHSM   \n") == b"manufacturer: Simorgh Labs   \n", "padding in text is kept"
    assert t(b"/modernized/pqHSM/x pqHSM2 pqHSM%20slot") == b"/modernized/pqHSM/x pqHSM2 pqHSM%20slot"
    print("rename_back: self-check ok")
