"""Lay out the CAVP response files the KAT goldens run the legacy parser on (Phase 3 slice 4).

  python3 make_kat_rsp.py <real sha2_256_short.rsp> <out dir>

kat/fhsm_kat_vectors.c:286-349 reads Len/Msg/MD records with fgets(2048), atoi and
sscanf("%2x"). Each file isolates one quirk of that parser. Every MD is either copied from the
real file or all zero: nothing here computes a digest. gen_kat.c records what the C hashed and
what it concluded.
"""
import os
import sys

ZERO = "00" * 32


def records(real):
    """The real file's (Len, Msg, MD) triples, as text."""
    out, cur = [], {}
    for line in open(real):
        for k in ("Len", "Msg", "MD"):
            if line.startswith(k + " = "):
                cur[k] = line.split(" = ", 1)[1].strip()
        if len(cur) == 3:
            out.append((cur["Len"], cur["Msg"], cur["MD"]))
            cur = {}
    return out


def rec(ln, msg, md):
    return f"Len = {ln}\nMsg = {msg}\nMD = {md}\n\n"


def main():
    real, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    r = {ln: (msg, md) for ln, msg, md in records(real)}
    abc, a, empty = r["24"], r["8"], r["0"]
    files = {
        # the /opt copy, preferred over the cwd one when both exist
        "opt": rec(24, *abc),
        "fail_md": rec(0, *empty) + rec(8, *a) + rec(24, abc[0], ZERO) + rec(8, *a),
        # Msg shorter than Len, or not hex: the rest keeps the previous record's bytes
        "stale_msg": rec(24, *abc) + rec(24, "61", ZERO),
        "bad_hex": rec(24, *abc) + rec(24, "61zz63", ZERO),
        "short_md": rec(24, *abc) + rec(24, abc[0], "ba78"),
        "space_hex": rec(8, " 61", a[1]),
        "sign_hex": rec(16, "+1ff", ZERO),
        "prefix_hex": rec(16, "0x41", ZERO),
        "odd_bits": rec(5, "61", a[1]),
        "neg_len": rec(-1, "00", empty[1]) + rec(-8, "00", empty[1]),
        "md_first": f"Len = 24\nMD = {abc[1]}\nMsg = {abc[0]}\n\n",
        "twice": f"Len = 24\nMsg = 616161\nMsg = {abc[0]}\nMD = {abc[1]}\n\n",
        "incomplete": f"Len = 8\nMsg = 61\n\nLen = 24\nMsg = {abc[0]}\nMD = {abc[1]}\n",
        "no_newline": f"Len = 24\nMsg = {abc[0]}\nMD = {abc[1]}",
        "crlf": rec(24, *abc).replace("\n", "\r\n"),
        "skipped": f"[L = 32]\n Len = 8\n# Len = 8\nLen = 24\nMsg = {abc[0]}\nMD = {abc[1]}\n",
        # fgets(2048) hands the rest of a long line over as a line of its own
        "long_msg": rec(8, "61" + "0" * 3000, a[1]),
        "split_md": "Len = 24\nMsg = " + abc[0] + "\n# " + "x" * 2045 + "MD = " + abc[1] + "\n",
        "max_len": rec(2048, "ab" * 256, ZERO),
        # more vectors than the 64 report slots
        "many": rec(0, *empty) * 70,
        "empty": "",
    }
    for name, text in files.items():
        with open(os.path.join(out, name + ".rsp"), "w", newline="") as f:
            f.write(text)


if __name__ == "__main__":
    main()
