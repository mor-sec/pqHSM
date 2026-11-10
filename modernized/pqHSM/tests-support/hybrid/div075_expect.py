"""DIV-075 on a tests/pki_tools_characterize.sh transcript from the C tools: what the Rust
fhsm-sign (Phase 5 slice 4) prints instead. cms-verify names the signer when it verifies;
--signer is an option, so the rows giving it no longer print the usage; a composite CMS whose
SignerInfo names another certificate is not one the tool can read. The usage gains --signer.

    div075_expect.py < C_TRANSCRIPT > EXPECTED
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
USAGE = {
    "   err|   fhsm-sign cms-verify --cms FILE [--in FILE]":
        ["   err|   fhsm-sign cms-verify --cms FILE [--in FILE] [--signer CERT]"],
    "   err|   --cms FILE      the CMS structure to check": [
        "   err|   --cms FILE      the CMS structure to check",
        "   err|   --signer CERT   for cms-verify: the certificate (DER or PEM) the CMS must",
        "   err|                   be signed under; one signed under any other exits 4",
    ],
}

out, seen, skipping = [], set(), False
for line in sys.stdin.read().splitlines():
    if line.startswith("== "):
        name = line.split(". ", 1)[1]
        skipping = name in ROWS
        out.append(line)
        if skipping:
            seen.add(name)
            out.extend(ROWS[name])
        continue
    # A row's body is its indented lines; anything else ends it.
    if skipping and line.startswith("   ") and not line.startswith("   shape"):
        continue
    skipping = False
    out.extend(USAGE.get(line, [line]))
missing = set(ROWS) - seen
if missing:
    sys.exit(f"div075_expect: no row {sorted(missing)}")
print("\n".join(out))
