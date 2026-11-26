"""Normalise every audit log under a directory for the Phase 1 corpus diff.

`ts` and the MACs that depend on it are replaced. Prints one block per log file, the blocks
sorted (directory names are random). With --lines, prints every record sorted with `seq`
normalised too: equal output then means the same records in a different order (threads).
"""
import pathlib, re, sys

SUBS = [(re.compile(rb'"ts":-?[0-9]+'), b'"ts":0'),
        (re.compile(rb'"(prev_hmac|hmac)":"[0-9a-fA-F]{64}"'), rb'"\1":"-"')]
SEQ = (re.compile(rb'"seq":[0-9]+'), b'"seq":0')

def norm(b, subs):
    for rx, rep in subs:
        b = rx.sub(rep, b)
    return b

root, lines = pathlib.Path(sys.argv[1]), "--lines" in sys.argv
files = sorted(p for p in root.rglob("audit.log*") if p.is_file())
if lines:
    out = sorted(l for p in files for l in norm(p.read_bytes(), SUBS + [SEQ]).splitlines())
    sys.stdout.buffer.write(b"\n".join(out) + b"\n")
else:
    blocks = sorted(norm(p.read_bytes(), SUBS) for p in files)
    sys.stdout.buffer.write(b"".join(b"=== log\n" + b for b in blocks))
