"""The Phase 5 decisions on a tests/pki_tools_characterize.sh transcript from the C tools:
what the Rust tools print instead.

DIV-075 (fhsm-sign, slice 4): cms-verify names the signer when it verifies; --signer is an
option, so the rows giving it no longer print the usage; a composite CMS whose SignerInfo names
another certificate is not one the tool can read. The usage gains --signer.
DIV-073 (fhsm-ca, slice 5): every --days that is not a whole positive decimal fitting an int is
refused before the module is opened, issue's and "10x" too.
DIV-074 (fhsm-ca, slice 5): with the database locked, revoke, crl and ocsp-respond wait their 10
seconds and refuse, so lock.db keeps the crlNumber and the one entry it was copied with.

    phase5_expect.py < C_TRANSCRIPT > EXPECTED
"""
import sys

SUBJECT = "C = FR, O = Simorgh Labs, CN = ee"
VERIFIED = [
    "   exit 0",
    "   err| fhsm-sign: CMS verified.",
    f"   err|   signed by: {SUBJECT}",
    "   err|   certificate SHA-256: <HEX>",
]
ROWS = {
    "cms-verify": VERIFIED,
    "cms-verify --signer, its own cert": VERIFIED,
    "cms-verify --signer, PEM": VERIFIED,
    "cms-verify --signer, another cert": [
        "   exit 4",
        f"   err| fhsm-sign: the CMS is signed by {SUBJECT},",
        "   err|   not by the certificate in <W>/resp.der.",
    ],
    "cms-verify, identifier names another": [
        "   exit 2",
        "   err| fhsm-sign: <W>/badsid.cms is not a CMS this tool can read.",
        "   err|   That is a different problem from a signature that does",
        "   err|   not match, and exits 2 rather than 4.",
    ],
}
DAYS = ["   exit 2", "   err| fhsm-ca: --days must be positive."]
for d in ["abc", "10x", "0", "-1", "2147483648"]:
    for sub in ["issue", "crl", "ocsp-respond"]:
        ROWS[f"{sub} --days {d}"] = DAYS
LOCKED = [
    "   exit 2",
    "   err| fhsm-ca: <W>/lock.db is locked by another process; gave up after 10 seconds.",
    "   err|   Nothing was changed.",
]
for sub in ["revoke", "crl", "ocsp-respond"]:
    ROWS[f"{sub} while the db is locked"] = LOCKED
USAGE = {
    "   err|   fhsm-sign cms-verify --cms FILE [--in FILE]":
        ["   err|   fhsm-sign cms-verify --cms FILE [--in FILE] [--signer CERT]"],
    "   err|   --cms FILE      the CMS structure to check": [
        "   err|   --cms FILE      the CMS structure to check",
        "   err|   --signer CERT   for cms-verify: the certificate (DER or PEM) the CMS must",
        "   err|                   be signed under; one signed under any other exits 4",
    ],
}

BODY = ("   exit ", "   err|", "   out|")
out, seen, skipping, lockdb = [], set(), False, False
for line in sys.stdin.read().splitlines():
    if line.startswith("== "):
        name = line.split(". ", 1)[1]
        skipping = name in ROWS
        out.append(line)
        if skipping:
            seen.add(name)
            out.extend(ROWS[name])
        continue
    # A row's body is its exit, err and out lines; its shape lines stay.
    if skipping and line.startswith(BODY):
        continue
    skipping = False
    # DIV-074: lock.db as it was copied, before C's revoke and crl ran on it.
    if line == "   lock.db":
        lockdb = True
    elif lockdb and line.startswith("    "):
        if line == "    crlNumber 2":
            line = "    crlNumber 1"
        elif line.endswith(" superseded"):
            continue
    else:
        lockdb = False
    out.extend(USAGE.get(line, [line]))
missing = set(ROWS) - seen
if missing:
    sys.exit(f"phase5_expect: no row {sorted(missing)}")
print("\n".join(out))
