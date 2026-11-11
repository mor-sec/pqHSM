"""Compare two service transcripts row by row (service_transcripts.sh's "== NAME" rows).

    python3 -I service_rows.py C.txt RUST.txt PENDING.txt

PENDING lists, one per line, the rows the Rust service is not yet expected to match (their
routes are a later Phase 6 slice's). "NAME<TAB>REGEX" excuses only the lines of that row
matching REGEX: the rest must match, audit sequence numbers aside. Prints one line: the counts,
and every row that differs outside PENDING or matches inside it. Either is UNEXPECTED: a
regression, or a pending entry that can now come off the list.
"""
import re
import sys


def rows(path):
    out, name = {}, None
    for line in open(path, errors="replace"):
        if line.startswith("== "):
            name = line.rstrip("\n")[3:]
            out.setdefault(name, [])
        elif name is not None:
            out[name].append(line)
    return out


c, r = rows(sys.argv[1]), rows(sys.argv[2])
pending, owed = set(), {}
for l in open(sys.argv[3]):
    if l.strip() and not l.startswith("#"):
        name, _, rx = l.rstrip("\n").partition("\t")
        pending.add(name)
        if rx:
            owed[name] = re.compile(rx)


def kept(name, lines):
    if name not in owed:
        return lines
    return [re.sub(r'"seq":[0-9]+,', "", l) for l in lines if not owed[name].search(l)]


differ = {k for k in c if c[k] != r.get(k)}
filtered = {k for k in owed if k in c and kept(k, c[k]) != kept(k, r.get(k, []))}
extra = sorted(set(r) - set(c))
bad = sorted(differ - pending) + sorted(pending - differ) + extra
bad += [f"{k} (outside the owed lines)" for k in sorted(filtered)]
print(f"{len(c)} rows, {len(c) - len(differ)} same, {len(differ)} differ, "
      + (f"UNEXPECTED: {'; '.join(bad)}" if bad else "every difference pending"))
