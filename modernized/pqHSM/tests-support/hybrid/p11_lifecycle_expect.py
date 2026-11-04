"""Harness step 4g: p11_lifecycle.c's output, normalised, and for the C run turned into what
Rust must print once Phase 4's recorded divergences apply. Nothing else is changed, so any
other difference between the two still fails the step.

    python3 -I p11_lifecycle_expect.py c|hybrid FILE > OUT

Both: DIV-035 (the integrity-bypass NOTE prints again after a restart or in a forked child)
and the Phase 1 `[pqhsm]` key-message prefix. C only: the rows below, each under its DIV.
"""
import re
import sys

# (DIV, row label, rv Rust returns[, output it prints]). The rows are C's defect; each DIV's own
# test checks it. An output of 'a' * n is the driver's untouched 0xAA fill.
RV = [
    ("DIV-051", "finalize reserved", "0x7"),
    ("RULE-071", "initialize again", "0x191"),
    ("RULE-083", "login user not initialised", "0x102"),
    ("DIV-059", "inittoken len 4 fresh", "0xa2"),
    ("DIV-059", "inittoken len 7 fresh", "0xa2"),
    ("DIV-059", "initpin len 4", "0xa2"),
    ("DIV-055", "closeall 1", "0"),
    ("DIV-055", "sessinfo slot 1 after closeall 1", "0xb3", "a" * 64),
]
# DIV-051: rows dropped from both, C's answers outside an initialised process.
DROP_CHILD = "child sessinfo before initialize"


def tokinfo(hexs: str) -> str:
    """DIV-059: CK_TOKEN_INFO.ulMinPinLen (offset 144) is 8."""
    return hexs[:288] + "0800000000000000" + hexs[304:]


def norm(lines, expect):
    out, skip, pre = [], 0, False
    for line in lines:
        if line.startswith("[freehsm-c] NOTE : integrity bypass active"):
            skip = 7
        if skip:
            skip -= 1
            continue
        line = re.sub(r"^\[pqhsm\] audit key :", "[freehsm-c] audit key :", line)
        # DIV-051: scenario 0 before its first C_Initialize.
        if line.startswith("=== 0 preinit"):
            out.append(line)
            pre = True
            continue
        if pre and line.startswith("initialize\t"):
            pre = False
        if pre or line.startswith(DROP_CHILD + "\t"):
            continue
        f = line.split("\t")
        if expect and len(f) == 3:
            for _div, label, rv, *printed in RV:
                if f[0] == label:
                    f[1] = rv
                    if printed:
                        f[2] = printed[0]
            if f[0].startswith("tokinfo") and f[1] == "0":
                f[2] = tokinfo(f[2])
            line = "\t".join(f)
        out.append(line)
    return out


def main():
    which, path = sys.argv[1], sys.argv[2]
    with open(path, encoding="utf-8", errors="surrogateescape") as fh:
        lines = fh.read().split("\n")
    sys.stdout.write("\n".join(norm(lines, which == "c")))


if __name__ == "__main__":
    main()
