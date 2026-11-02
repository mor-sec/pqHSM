#!/usr/bin/env python3
"""Topology extractor for pqHSM (FreeHSM 2.6.0, C11).

Run from anywhere:  python3 analysis/pqHSM/extract_topology.py
Writes analysis/pqHSM/topology.json, call-graph.mmd, data-lineage.mmd and critical-path.mmd,
and prints a human summary.  Needs `lizard` on PATH (function spans).

How edges are found (each is re-derived from the tree on every run):
  * Link units come from the Makefile (LIB_SRC, per-binary prerequisites), so a call only
    resolves to a definition that is linked into the same binary as the caller. Static
    functions resolve inside their own file (or to includers of the header that holds them).
  * Direct calls: identifiers followed by '(' inside each function span, plus calls hidden
    in function-like macros (#define bodies in include/ and the .c files).
  * Dispatch: (a) function addresses taken in live code (callbacks, atfork, GTK signals),
    (b) file-scope pointer tables (function lists, command tables), (c) `->C_xxx(` calls
    through a CK_FUNCTION_LIST obtained by dlopen() (the tools), (d) the HTTP router's
    strcmp(r.target, ...) chains, (e) GTK notebook tabs, (f) deployment config: the
    systemd unit's ExecStart and the Makefile targets.
  * Data stores: STORE_RULES below; the function holding the matching I/O line gets the edge.
  * Dead ends: modules with no function reachable from a production entry point (exported
    C_* ABI, each binary's main, routes). Tests do not count as reachability. Address-taken
    functions are treated as live (conservative), except the generated mechanism table,
    whose `handler` field this script verifies is never invoked.
"""
import csv
import io
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
SYSTEM = "pqHSM (FreeHSM 2.6.0)"

SOURCES = ["src/*.c", "src/dispatch/*.c", "src/gen/*.c", "kat/*.c", "service/*.c",
           "tools/*.c", "tools/p11_util.h"]
SCRIPTS = {"scripts/gen_p11_thunks.py": "python", "scripts/sign_module.sh": "shell"}

DOMAINS = [  # (id, name, path regexes) -- from ASSESSMENT.md "Architecture-at-a-Glance"
    ("D1", "D1 PKCS#11 API & object model", [r"src/fhsm_(pkcs11|create_attrs|pq_params|ecdsa_raw)\.c"]),
    ("D2", "D2 Lifecycle, sessions, concurrency", [r"src/fhsm_(state|apilock|session)\.c"]),
    ("D3", "D3 Token store + TPM sealing", [r"src/fhsm_(token|token_tpm|tpm)\.c"]),
    ("D4", "D4 Crypto core, DRBG, secure heap, config", [r"src/fhsm_(crypto|drbg|memory|conf)\.c"]),
    ("D5", "D5 Mechanism registry & dispatch", [r"src/(gen|dispatch)/", r"src/fhsm_mode\.c", r"scripts/gen_p11"]),
    ("D6", "D6 Self-tests & integrity", [r"kat/", r"src/fhsm_(integrity|pairwise)\.c", r"scripts/sign_module"]),
    ("D7", "D7 Audit trail", [r"src/fhsm_audit\.c", r"tools/freehsm_audit\.c"]),
    ("D8", "D8 Composite / PKI encoding / revocation", [r"src/fhsm_(composite|revocation)\.c"]),
    ("D9", "D9 HTTP signing & OCSP service", [r"service/", r"^route:"]),
    ("D10", "D10 PKI CLI tools & GTK GUI", [r"tools/", r"^gui:"]),
    ("D11", "D11 Build, deploy & verification", [r"^job:"]),
]

# (store id, display name, file glob, function-name regex or None, mode, line regex on comment-stripped text)
STORE_RULES = [
    ("token_file", "slotN.tok token file", "src/fhsm_token.c", None, "read", r"open\(\s*(t->)?path\s*,\s*O_RDONLY"),
    ("token_file", "slotN.tok token file", "src/fhsm_token.c", None, "write", r'"%s\.tmp"'),
    ("token_tpm_blob", "slotN.tok.tpm sealed DEK", "src/fhsm_token_tpm.c", None, "read", r"open\(tpm_path, O_RDONLY"),
    ("token_tpm_blob", "slotN.tok.tpm sealed DEK", "src/fhsm_token_tpm.c", None, "write", r"rename\(tmp_path, tpm_path\)"),
    ("tpm", "TPM via tpm2 CLI", "src/fhsm_tpm.c", None, "read", r"\bsystem\("),
    ("tpm", "TPM via tpm2 CLI", "src/fhsm_tpm.c", None, "write", r"\bsystem\("),
    ("audit_log", "audit log (HMAC-chained JSON lines)", "src/fhsm_audit.c", None, "write", r"O_APPEND"),
    ("audit_log", "audit log (HMAC-chained JSON lines)", "tools/freehsm_audit.c", None, "read", r'fopen\(path, "r"\)'),
    ("audit_key", "audit.key / audit.key.tpm", "src/fhsm_audit.c", None, "read", r"open\((p|blob_p), O_RDONLY"),
    ("audit_key", "audit.key / audit.key.tpm", "src/fhsm_audit.c", None, "write", r"O_CREAT \| O_EXCL \| O_CLOEXEC, 0600"),
    ("conf", "freehsm.conf", "src/fhsm_conf.c", None, "read", r"fopen\("),
    ("revocation_db", "revocation DB", "src/fhsm_revocation.c", None, "read", r'fopen\(path, "r"\)'),
    ("revocation_db", "revocation DB", "src/fhsm_revocation.c", None, "write", r"rename\(tmp, path\)"),
    ("service_policy", "service signing policy", "service/fhsm_service.c", r"policy_load", "read", r"fopen\("),
    ("refusal_budget", "service refusal budget", "service/fhsm_service.c", None, "read", r"fopen\(g_budget_path"),
    ("refusal_budget", "service refusal budget", "service/fhsm_service.c", None, "write", r"rename\(tmp, g_budget_path\)"),
    ("service_certs", "CA + OCSP responder certificates", "service/fhsm_service.c", r"ca_cert_load|main", "read", r'fopen\(\w+, "rb"\)'),
    ("pin_credential", "service PIN credential", "service/fhsm_service.c", None, "read", r'"%s/fhsm-pin"'),
    ("cavp_vectors", "CAVP .rsp vectors", "kat/fhsm_kat_vectors.c", None, "read", r"\.rsp\""),
    ("module_digest", ".fhsm_digest (module signature)", "src/fhsm_integrity.c", None, "read", r"open\(g_so_path"),
    ("pki_files", "PKI files (certs, CSRs, CRLs, signatures)", "tools/*.c", None, "read", r'fopen\([^)]*"rb"\)'),
    ("pki_files", "PKI files (certs, CSRs, CRLs, signatures)", "tools/*.c", None, "write", r'fopen\([^)]*"wb"\)|fdopen\(fd, "wb"\)'),
]
# shortcut: field name of the generated mechanism table is hardcoded; extend if more pointer tables appear.
HANDLER_TABLES = {"fhsm_mechanism_table": "handler"}

KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "defined", "__attribute__", "_Static_assert",
            "case", "do", "else", "typeof", "__typeof__", "alignof", "_Alignof", "offsetof"}

TOKRE = re.compile(r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S)


def strip(text, keep_strings):
    """Blank comments (and optionally strings) but keep every newline so line numbers hold."""
    def rep(m):
        s = m.group(0)
        if keep_strings and s[0] in "\"'":
            return s
        return re.sub(r"[^\n]", " ", s)
    return TOKRE.sub(rep, text)


def rel(p):
    return str(Path(p).resolve().relative_to(ROOT))


# ---------------------------------------------------------------- Makefile link units
def makefile_vars(mk):
    joined = re.sub(r"\\\n", " ", mk)
    v = {}
    for m in re.finditer(r"^([A-Z_]+)\s*([+?:]?)=\s*(.*)$", joined, re.M):
        if m.group(2) == "?" and m.group(1) in v:
            continue
        v[m.group(1)] = (v.get(m.group(1), "") + " " + m.group(3)) if m.group(2) == "+" else m.group(3)
    v["OBJDIR"] = ""   # object paths map back to their sources
    return v


def expand(s, v, depth=0):
    if depth > 5:
        return s
    s = re.sub(r"\$\(([A-Z_]+)\)", lambda m: expand(v.get(m.group(1), ""), v, depth + 1), s)
    return re.sub(r"\$\(patsubst %\.c,[^,]*%\.o,([^)]*)\)", r"\1", s)


def link_units(mk):
    v = makefile_vars(mk)
    units = {"libfreehsm.so": set(expand(v["LIB_SRC"], v).split())}
    for m in re.finditer(r"^((?:tools|service)/[\w-]+):\s*(.*)$", mk, re.M):
        deps = set()
        for d in expand(m.group(2), v).split():
            d = re.sub(r"\.o$", ".c", d.lstrip("/"))
            if d.endswith((".c", ".h")):
                deps.add(d)
        units[m.group(1)] = deps
    return units


# ---------------------------------------------------------------- function spans (lizard)
def lizard_functions(files):
    out = subprocess.run(["lizard", "--csv", *files], cwd=ROOT, capture_output=True, text=True).stdout
    funcs = []
    for row in csv.reader(io.StringIO(out)):
        if len(row) < 11 or not row[9].isdigit():
            continue
        funcs.append({"name": row[7].split("::")[-1], "file": row[6], "start": int(row[9]), "end": int(row[10])})
    return funcs


def top_level(code_text):
    """Split comment/string-stripped C into depth-0 statements: (start_line, end_line, text, ends_with_brace)."""
    text = re.sub(r"^[ \t]*#(?:[^\n]*\\\n)*[^\n]*", lambda m: re.sub(r"[^\n]", " ", m.group(0)), code_text, flags=re.M)
    out, depth, start, line, start_line, open_pos = [], 0, 0, 1, 1, 0
    for i, ch in enumerate(text):
        if ch == "\n":
            line += 1
        elif ch == "{":
            if depth == 0:
                open_pos = i
            depth += 1
        elif ch == "}":
            depth -= 1
            head = text[start:open_pos]
            # a body closes the statement; initializers and struct/enum definitions run on to ';'
            if depth == 0 and not re.search(r"=\s*$", head) \
                    and not re.search(r"\b(struct|union|enum)\b[\w\s]*$", head):
                out.append((start_line, line, text[start:i + 1], True))
                start, start_line = i + 1, line
        elif ch == ";" and depth == 0:
            out.append((start_line, line, text[start:i + 1], False))
            start, start_line = i + 1, line
    return out


def macro_calls(texts):
    """Macro name -> identifiers in its body (calls and address uses such as cleanup(fn));
    only names that resolve to a visible function become edges. Expanded transitively at use."""
    mac = {}
    for t in texts:
        joined = re.sub(r"\\\n", " ", t)
        for m in re.finditer(r"^[ \t]*#[ \t]*define[ \t]+(\w+)(\([^)]*\))?[ \t]*(.*)$", joined, re.M):
            calls = {c for c in re.findall(r"(?<![\w.>])([A-Za-z_]\w*)", m.group(3)) if c not in KEYWORDS}
            if calls:
                mac.setdefault(m.group(1), set()).update(calls)
    return mac


def main():
    mk = (ROOT / "Makefile").read_text()
    units = link_units(mk)
    files = sorted({rel(p) for g in SOURCES for p in ROOT.glob(g)})
    file_units = defaultdict(set)
    for u, deps in units.items():
        for f in deps:
            file_units[f].add(u)
    raw = {f: (ROOT / f).read_text(errors="replace") for f in files}
    code = {f: strip(t, keep_strings=False) for f, t in raw.items()}
    withstr = {f: strip(t, keep_strings=True) for f, t in raw.items()}
    includes = {f: {Path(h).name for h in re.findall(r'#\s*include\s*"([^"]+)"', raw[f])} for f in files}
    headers = sorted((ROOT / "include").glob("*.h")) + sorted((ROOT / "tools").glob("*.h")) \
        + sorted((ROOT / "src/dispatch").glob("*.h"))
    macros = macro_calls([strip(p.read_text(errors="replace"), False) for p in headers] + list(code.values()))

    funcs = lizard_functions(files)
    if not funcs:
        sys.exit("lizard returned no functions -- is it installed? (pipx install lizard)")
    lines = {f: code[f].split("\n") for f in files}
    rawlines = {f: raw[f].split("\n") for f in files}
    for fn in funcs:
        src = "\n".join(lines[fn["file"]][max(0, fn["start"] - 4):fn["start"]])
        head = src[: src.rfind(fn["name"])] if fn["name"] in src else src
        head = re.split(r"[;}]", head)[-1]
        fn["static"] = bool(re.search(r"\bstatic\b", head))
        fn["weak"] = "weak" in "\n".join(rawlines[fn["file"]][max(0, fn["start"] - 3):fn["start"]])
        fn["id"] = f'{fn["file"]}:{fn["name"]}'
    by_name = defaultdict(list)
    span_of = defaultdict(list)
    for fn in funcs:
        by_name[fn["name"]].append(fn)
        span_of[fn["file"]].append(fn)

    def visible(caller_file, name):
        cands = []
        for d in by_name.get(name, []):
            if d["static"]:
                if d["file"] == caller_file or Path(d["file"]).name in includes[caller_file]:
                    cands.append(d)
            elif d["file"] == caller_file or file_units[d["file"]] & file_units[caller_file]:
                cands.append(d)
        strong = [d for d in cands if not d["weak"]]
        return strong or cands

    def enclosing(f, lineno):
        for fn in span_of[f]:
            if fn["start"] <= lineno <= fn["end"]:
                return fn
        return None

    # ---- file-scope definitions (tables) and the function addresses they hold
    tables = {}
    handler_invoked = {fld: False for fld in HANDLER_TABLES.values()}
    missed_bodies = []
    for f in files:
        for fld in handler_invoked:
            if re.search(rf"(\.|->)\s*{fld}\s*\)?\s*\(", code[f]):
                handler_invoked[fld] = True
        for s_line, e_line, stmt, braced in top_level(code[f]):
            if braced:   # a function body: make sure lizard saw it
                if not any(fn["start"] <= e_line and fn["end"] >= s_line for fn in span_of[f]):
                    missed_bodies.append(f"{f}:{s_line}")
                continue
            m = re.match(r"\s*((?:static|const|extern|volatile|\s)*)[A-Za-z_][\w\s\*]*?\b([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*=", stmt)
            if not m or "extern" in m.group(1):
                continue
            tid = f"{f}#{m.group(2)}"
            tables[tid] = {"name": m.group(2), "file": f, "static": "static" in m.group(1), "refs": set()}
            for ident in re.findall(r"(?<![\w.>])([A-Za-z_]\w*)\b(?!\s*\()", stmt[m.end():]):
                for d in visible(f, ident):
                    tables[tid]["refs"].add(d["id"])
    skipped_table_refs = 0
    for t in tables.values():
        fld = HANDLER_TABLES.get(t["name"])
        if fld and not handler_invoked[fld]:
            skipped_table_refs += len(t["refs"])
            t["refs"] = set()
    tables_by_name = defaultdict(list)
    for tid, t in tables.items():
        tables_by_name[t["name"]].append(tid)

    # ---- the tools' dlsym table maps struct members to exports: S(Sign,"C_Sign") -> p11.Sign(...) is C_Sign
    abi_alias = dict(re.findall(r'\bS\((\w+),\s*"(C_[A-Z]\w+)"\)', raw.get("tools/p11_util.h", "")))
    dlopen_units = [u for u, d in units.items() if any("p11_util.h" in includes.get(x, set()) for x in d)]

    # ---- per-function outgoing references
    fcalls, fptr, ftab, fabi = defaultdict(set), defaultdict(set), defaultdict(set), defaultdict(set)
    for fn in funcs:
        f = fn["file"]
        body = "\n".join(lines[f][fn["start"] - 1:fn["end"]])
        names = {c for c in re.findall(r"(?<![\w.>])(\w+)\s*\(", body) if c not in KEYWORDS}
        frontier, seen = set(names), set()
        for _ in range(4):
            nxt = set()
            for n in frontier - seen:
                seen.add(n)
                nxt |= macros.get(n, set())
            frontier = nxt
            names |= nxt
        for n in names - {fn["name"]}:
            for d in visible(f, n):
                fcalls[fn["id"]].add(d["id"])
        for m in re.finditer(r"(?<![\w.>])([A-Za-z_]\w*)\b(?!\s*\()", body):
            ident = m.group(1)
            if ident in KEYWORDS or body[:m.start()].rstrip()[-2:] in ("==", "!="):
                continue
            for d in visible(f, ident):
                if d["id"] != fn["id"]:
                    fptr[fn["id"]].add(d["id"])
            for tid in tables_by_name.get(ident, []):
                t = tables[tid]
                if t["file"] == f or (not t["static"] and file_units[t["file"]] & file_units[f]):
                    ftab[fn["id"]].add(tid)
        fabi[fn["id"]] = set(re.findall(r"(?:->|\.)\s*(C_[A-Z]\w+)\s*\(", body)) \
            | {abi_alias[m] for m in re.findall(r"(?:->|\.)\s*(\w+)\s*\(", body) if m in abi_alias}

    lib = units["libfreehsm.so"]
    exports = {fn["name"]: fn for fn in funcs
               if fn["file"] in lib and re.match(r"^C_[A-Z]\w+$", fn["name"]) and not fn["static"]}

    # ---- production roots and reachability
    mains = {}
    for u, deps in units.items():
        for d in deps:
            for fn in span_of.get(d, []):
                if fn["name"] == "main":
                    mains[u] = fn
    def reach(start, unit=None):
        """Functions reachable from `start`; with `unit`, stay inside that binary (no dlopen hop)."""
        seen, work = set(), list(start)
        while work:
            x = work.pop()
            if x in seen:
                continue
            seen.add(x)
            nxt = fcalls[x] | fptr[x]
            if unit is None:
                nxt = nxt | {exports[c]["id"] for c in fabi[x] if c in exports}
            for tid in ftab[x]:
                nxt = nxt | tables[tid]["refs"]
            if unit:
                nxt = {n for n in nxt if unit in file_units[fn_by_id[n]["file"]] or fn_by_id[n]["file"].endswith(".h")}
            work.extend(nxt - seen)
        return seen

    fn_by_id = {fn["id"]: fn for fn in funcs}
    roots = {fn["id"] for fn in exports.values()} | {fn["id"] for fn in mains.values()}
    live = reach(roots)
    live_by_unit = {u: reach([mains[u]["id"]] if u in mains else [exports[n]["id"] for n in exports], u) for u in units}

    # ---- module nodes
    def loc_of(f):
        if f in lines:
            return sum(1 for ln in lines[f] if ln.strip())
        return sum(1 for ln in (ROOT / f).read_text().split("\n") if ln.strip() and not ln.lstrip().startswith("#"))

    nodes = {f: {"id": f, "name": Path(f).name, "kind": "module", "language": "c", "loc": loc_of(f), "file": f}
             for f in files}
    for f, lang in SCRIPTS.items():
        nodes[f] = {"id": f, "name": Path(f).name, "kind": "module", "language": lang, "loc": loc_of(f), "file": f}

    edges = {}

    def add_edge(s, t, kind, label=None):
        if s != t and (s, t, kind) not in edges:
            edges[(s, t, kind)] = {"source": s, "target": t, "kind": kind, **({"label": label} if label else {})}

    for fid, ts in fcalls.items():
        for t in ts:
            add_edge(fn_by_id[fid]["file"], fn_by_id[t]["file"], "call")
    for fid, ts in fptr.items():
        for t in ts:
            add_edge(fn_by_id[fid]["file"], fn_by_id[t]["file"], "dispatch", "function pointer")
    for fid, tids in ftab.items():
        for tid in tids:
            add_edge(fn_by_id[fid]["file"], tables[tid]["file"], "call", f"reads {tables[tid]['name']}")
            for t in tables[tid]["refs"]:
                add_edge(tables[tid]["file"], fn_by_id[t]["file"], "dispatch", f"via {tables[tid]['name']}")
    for fid, names in fabi.items():
        if names & exports.keys() and fn_by_id[fid]["file"] not in lib:
            add_edge(fn_by_id[fid]["file"], "src/fhsm_pkcs11.c", "dispatch", "PKCS#11 function list (dlopen)")
    if "dlopen(" in code.get("tools/p11_util.h", "") and "C_GetFunctionList" in raw.get("tools/p11_util.h", ""):
        add_edge("tools/p11_util.h", "src/fhsm_pkcs11.c", "dispatch", "dlopen + C_GetFunctionList")

    # ---- data stores
    stores, store_hits, rule_misses = {}, defaultdict(list), []
    for sid, sname, glob, fnre, mode, rx in STORE_RULES:
        stores[f"ds:{sid}"] = sname
        hit = False
        for f in ([rel(p) for p in sorted(ROOT.glob(glob))] if "*" in glob else [glob]):
            for i, ln in enumerate(withstr.get(f, "").split("\n"), 1):
                if re.search(rx, ln):
                    fn = enclosing(f, i)
                    if fnre and not (fn and re.fullmatch(fnre, fn["name"])):
                        continue
                    hit = True
                    add_edge(f, f"ds:{sid}", mode)
                    store_hits[(f"ds:{sid}", mode)].append((f, i, fn["id"] if fn else None))
        if not hit:
            rule_misses.append(f"{sid}/{mode} in {glob}")

    # ---- deployment config: systemd, Makefile targets, generator, tests, CI
    jobs = {}
    unit_txt = (ROOT / "systemd/fhsm-service.service").read_text()
    exec_bin = Path(re.search(r"^ExecStart=(\S+)", unit_txt, re.M).group(1)).name
    svc_target = next((u for u in units if Path(u).name == exec_bin), None)
    jobs["job:systemd"] = "systemd fhsm-service.service"
    if svc_target in mains:
        add_edge("job:systemd", mains[svc_target]["file"], "dispatch", "ExecStart")
    if re.search(r"^LoadCredentialEncrypted=fhsm-pin", unit_txt, re.M):
        add_edge("job:systemd", "ds:pin_credential", "write", "LoadCredentialEncrypted")
    installed_service = bool(re.search(rf"^\t.*install\b.*{re.escape(exec_bin)}", mk, re.M))
    jobs["job:generate"] = "make generate"
    if re.search(r"^generate:[\s\S]{0,600}?gen_p11_thunks\.py", mk, re.M):
        add_edge("job:generate", "scripts/gen_p11_thunks.py", "call")
    if "fhsm_dispatch.c" in (ROOT / "scripts/gen_p11_thunks.py").read_text():
        add_edge("scripts/gen_p11_thunks.py", "src/gen/fhsm_dispatch.c", "write", "generates")
    jobs["job:integrity"] = "make integrity (sign)"
    if "sign_module.sh" in mk:
        add_edge("job:integrity", "scripts/sign_module.sh", "call")
    if "fhsm_digest" in (ROOT / "scripts/sign_module.sh").read_text():
        add_edge("scripts/sign_module.sh", "ds:module_digest", "write")
    jobs["job:install"] = "make install"
    if "freehsm.conf" in mk:
        add_edge("job:install", "ds:conf", "write", "writes default conf")
    if re.search(r"\.rsp", mk):
        add_edge("job:install", "ds:cavp_vectors", "write", "copies vectors")
    jobs["job:tests"] = "make tests"
    abi_tests = [p for p in (ROOT / "tests").glob("*.c")
                 if re.search(r"libfreehsm|C_GetFunctionList|C_Initialize", p.read_text(errors="replace"))]
    if abi_tests:
        add_edge("job:tests", "src/fhsm_pkcs11.c", "dispatch", f"{len(abi_tests)} C tests drive the ABI")
    sh = "\n".join(p.read_text(errors="replace") for p in (ROOT / "tests").glob("*.sh"))
    for u, fn in mains.items():
        if re.search(rf"\b{re.escape(Path(u).name)}\b", sh):
            add_edge("job:tests", fn["file"], "dispatch", "shell harness")
    wf = sorted((ROOT / ".github/workflows").glob("*.yml"))
    jobs["job:ci"] = f"CI ({len(wf)} GitHub workflows)"
    if any(re.search(r"make[^\n]*\btests\b", p.read_text()) for p in wf):
        add_edge("job:ci", "job:tests", "call")

    # ---- service routes and GUI tabs (screens)
    screens, route_ids = {}, []
    for i, ln in enumerate(withstr["service/fhsm_service.c"].split("\n"), 1):
        for path in re.findall(r'strcmp\(r\.target, "(/[\w/]*)"\)', ln):
            fn = enclosing("service/fhsm_service.c", i)
            listener = "public" if fn and "public" in fn["name"] else "private"
            rid = f"route:{listener}{path}"
            if rid not in screens:
                screens[rid] = f"{path} ({listener} listener)"
                route_ids.append(rid)
                add_edge(rid, "service/fhsm_service.c", "dispatch", f"router in {fn['name'] if fn else '?'}")
    for tab in re.findall(r'gtk_notebook_append_page\([^;]*gtk_label_new\("([^"]+)"\)', withstr["tools/fhsm_gui.c"]):
        screens[f"gui:{tab}"] = f"GUI tab: {tab}"
        add_edge(f"gui:{tab}", "tools/fhsm_gui.c", "dispatch", "GTK notebook tab")

    # ---- dead ends (production reachability)
    live_files = {fn_by_id[x]["file"] for x in live}
    dead = [f for f in files if f not in live_files]
    unlinked = [f for f in files if not file_units[f] and not any(includes[g] & {Path(f).name} for g in files)]

    # ---- assemble tree
    leaves = list(nodes.values()) + [{"id": k, "name": v, "kind": "job"} for k, v in jobs.items()] \
        + [{"id": k, "name": v, "kind": "screen"} for k, v in screens.items()]
    dom_children = defaultdict(list)
    for leaf in leaves:
        did = next((d for d, _, pats in DOMAINS if any(re.search(p, leaf["id"]) for p in pats)), None)
        assert did, f"no domain for {leaf['id']}"
        dom_children[did].append(leaf)
    children = [{"id": f"dom:{d}", "name": n, "kind": "domain", "children": sorted(dom_children[d], key=lambda x: x["id"])}
                for d, n, _ in DOMAINS if dom_children[d]]
    children.append({"id": "dom:data", "name": "Data stores", "kind": "domain",
                     "children": [{"id": k, "name": v, "kind": "datastore"} for k, v in sorted(stores.items())]})
    leaf_name = {l["id"]: l["name"] for c in children for l in c["children"]}
    leaf_ids = set(leaf_name)
    edge_list = sorted(edges.values(), key=lambda e: (e["source"], e["target"], e["kind"]))
    for e in edge_list:
        assert e["source"] in leaf_ids and e["target"] in leaf_ids, f"dangling edge {e}"
    entry = sorted({fn["file"] for fn in mains.values()} | {"src/fhsm_pkcs11.c"} | set(route_ids) | set(jobs))

    # ---- metrics used by observations
    fan_in, fan_out = defaultdict(set), defaultdict(set)
    for e in edge_list:
        if e["kind"] in ("call", "dispatch") and e["source"] in nodes and e["target"] in nodes:
            fan_in[e["target"]].add(e["source"])
            fan_out[e["source"]].add(e["target"])
    writers = defaultdict(set)
    for (sid, mode), hits in store_hits.items():
        if mode == "write":
            for f, _, fid in hits:
                writers[sid] |= {Path(u).name for u, lv in live_by_unit.items() if fid in lv}
    dispatch_dead = [f for f in dead if f.startswith(("src/dispatch/", "src/gen/"))]
    pk = "src/fhsm_pkcs11.c"
    total_c_loc = sum(nodes[f]["loc"] for f in files)

    observations = [
        f"Hub: src/fhsm_pkcs11.c ({nodes[pk]['loc']:,} code lines, {round(100 * nodes[pk]['loc'] / total_c_loc)}% of mapped C) "
        f"is the only module external consumers reach. It calls into {len(fan_out[pk])} modules and is called by "
        f"{len(fan_in[pk])}. Every token, crypto, audit and lifecycle path crosses it, so it is the coupling cluster "
        f"to split first in Rust.",
        f"Dead dispatch layer: the generated mechanism table holds {skipped_table_refs} handler addresses, but no code invokes "
        f"its `handler` field (verified by this script). {len(dispatch_dead)} dispatch modules "
        f"({sum(nodes[f]['loc'] for f in dispatch_dead):,} code lines) are unreachable from every production entry point; "
        f"only the unbuilt tests/test_dispatch.c calls them. This is verified dead code, not an unresolved dynamic call.",
        f"Three link models in one codebase: {len(dlopen_units)} tool binaries dlopen() the module and reach it only "
        f"through the PKCS#11 function list ({len(abi_alias)} entry points resolved from the dlsym table in "
        f"tools/p11_util.h); fhsm-service statically links all "
        f"{len(lib)} module objects (it calls non-exported audit functions); those same tool binaries "
        f"also link fhsm_composite.c and fhsm_revocation.c directly. The Rust cdylib must keep the first; the other two are choices to revisit.",
        "Revocation DB has several writers and no single owner: live code in "
        + ", ".join(sorted(writers.get("ds:revocation_db", []))) + " writes it through fhsm_revocation.c, and fhsm-service "
        "reads it to answer OCSP. This is a service-extraction candidate: one revocation component owning the file.",
        "Key-custody single point of failure: unlocking the token (slotN.tok.tpm) and loading the audit key both go "
        "through fhsm_tpm.c, which shells out to the tpm2 CLI from inside the library process. A missing or slow tpm2 "
        "binary blocks login and auditing together.",
        ("Deployment gap: no Makefile install rule produces the binary named in the systemd unit's ExecStart, so the "
         "service's entry point exists in deployment config with no install path." if not installed_service
         else "The systemd ExecStart binary has an install rule."),
    ]
    if unlinked:
        observations.append("Not linked into any binary (dead by build graph): " + ", ".join(unlinked) + ".")

    flows = [
        {"name": "A business application gets a document signed",
         "persona": "Relying application (calls the signing service)",
         "description": "An internal application sends data to the signing service and receives a signature made "
                        "with a key that never leaves the HSM.",
         "steps": [
             {"label": "Service starts, reads its PIN from an encrypted systemd credential and logs in to the token",
              "nodes": ["job:systemd", "service/fhsm_service.c", "ds:pin_credential", "src/fhsm_token.c",
                        "src/fhsm_token_tpm.c", "src/fhsm_tpm.c", "ds:tpm", "ds:token_file"]},
             {"label": "Application posts the data to be signed", "nodes": ["route:private/sign", "service/fhsm_service.c"]},
             {"label": "Service checks the signing policy and request budget",
              "nodes": ["service/fhsm_service.c", "ds:service_policy", "ds:refusal_budget"]},
             {"label": "HSM signs with the token's private key",
              "nodes": ["src/fhsm_pkcs11.c", "src/fhsm_crypto.c", "src/fhsm_token.c"]},
             {"label": "The signing event is written to the tamper-evident audit log",
              "nodes": ["src/fhsm_audit.c", "ds:audit_log"]},
             {"label": "Signature is returned to the application", "nodes": ["service/fhsm_service.c"]},
         ]},
        {"name": "A PKI operator issues a certificate",
         "persona": "PKI operator (CA administrator)",
         "description": "An operator turns a certificate request into a signed certificate using the CA key held in the HSM.",
         "steps": [
             {"label": "Operator runs the CA tool with a certificate request", "nodes": ["tools/fhsm_ca.c", "ds:pki_files"]},
             {"label": "Tool loads the HSM module and opens a session",
              "nodes": ["tools/pkiops.c", "tools/p11_util.h", "src/fhsm_pkcs11.c"]},
             {"label": "Operator logs in and the token's keys are decrypted",
              "nodes": ["src/fhsm_pkcs11.c", "src/fhsm_token.c", "ds:token_file"]},
             {"label": "Certificate is built and signed by the CA key",
              "nodes": ["tools/pkiops.c", "src/fhsm_composite.c", "src/fhsm_pkcs11.c", "src/fhsm_crypto.c"]},
             {"label": "Signed certificate is written out and the operation audited",
              "nodes": ["ds:pki_files", "src/fhsm_audit.c", "ds:audit_log"]},
         ]},
        {"name": "A relying party checks whether a certificate was revoked",
         "persona": "Relying party (any client validating a certificate)",
         "description": "After an operator revokes a certificate, any client can ask the public OCSP endpoint and "
                        "get a signed answer.",
         "steps": [
             {"label": "Operator revokes the certificate",
              "nodes": ["tools/fhsm_ca.c", "src/fhsm_revocation.c", "ds:revocation_db"]},
             {"label": "Client asks the public OCSP endpoint", "nodes": ["route:public/ocsp", "service/fhsm_service.c"]},
             {"label": "Service looks the serial number up in the revocation DB",
              "nodes": ["service/fhsm_service.c", "src/fhsm_revocation.c", "ds:revocation_db"]},
             {"label": "Answer is built and signed by the OCSP responder key",
              "nodes": ["src/fhsm_revocation.c", "src/fhsm_composite.c", "service/fhsm_service.c", "src/fhsm_pkcs11.c",
                        "ds:service_certs", "ds:token_file"]},
             {"label": "Signed status is returned to the client", "nodes": ["service/fhsm_service.c"]},
         ]},
        {"name": "An auditor verifies the HSM's activity record",
         "persona": "Auditor / compliance officer",
         "description": "An auditor confirms that the record of every key use is complete and has not been altered.",
         "steps": [
             {"label": "Every login, key use and admin action appends a chained record",
              "nodes": ["src/fhsm_pkcs11.c", "src/fhsm_audit.c", "ds:audit_log"]},
             {"label": "The chaining key is kept sealed",
              "nodes": ["src/fhsm_audit.c", "ds:audit_key", "src/fhsm_tpm.c", "ds:tpm"]},
             {"label": "Auditor runs the standalone verifier over the log",
              "nodes": ["tools/freehsm_audit.c", "ds:audit_log"]},
         ]},
    ]
    for fl in flows:
        for st in fl["steps"]:
            for n in st["nodes"]:
                assert n in leaf_ids, f"flow node missing: {n}"

    topo = {"system": SYSTEM, "root": {"id": "sys", "name": SYSTEM, "kind": "system", "children": children},
            "edges": edge_list, "entryPoints": entry, "deadEnds": sorted(dead),
            "observations": observations, "flows": flows}
    (OUT / "topology.json").write_text(json.dumps(topo, indent=1) + "\n")

    # ---------------------------------------------------------------- Mermaid
    dom_of = {l["id"]: c["id"] for c in children for l in c["children"]}
    dd = defaultdict(set)
    for e in edge_list:
        a, b = dom_of[e["source"]], dom_of[e["target"]]
        if a != b and e["kind"] in ("call", "dispatch") and b != "dom:data":
            dd[(a, b)].add(e["kind"])
    mid = lambda d: d.replace("dom:", "")
    cg = ["%% Domain-level call graph, generated by extract_topology.py.",
          "%% Solid = direct call, dashed = dispatch only (dlopen, routes, pointers). Orange outline = holds entry points.",
          "graph TD"]
    for c in children:
        if c["id"] != "dom:data":
            cg.append(f'  {mid(c["id"])}["{c["name"]}"]')
    for (a, b), kinds in sorted(dd.items()):
        cg.append(f"  {mid(a)} {'-.->' if kinds == {'dispatch'} else '-->'} {mid(b)}")
    cg.append("  classDef entry stroke-width:4px,stroke:#cc785c")
    cg.append("  class " + ",".join(sorted({mid(dom_of[x]) for x in entry})) + " entry")
    assert len(dd) <= 40, f"call-graph.mmd has {len(dd)} edges"
    (OUT / "call-graph.mmd").write_text("\n".join(cg) + "\n")

    sid_ = lambda x: re.sub(r"\W", "_", x)
    lin = defaultdict(set)
    for e in edge_list:
        if e["kind"] in ("read", "write") and e["target"].startswith("ds:"):
            lin[(e["source"], e["target"])].add(e["kind"])
    dl = ["%% Data lineage: modules -> data stores. Solid = writes, dashed = read only. Generated by extract_topology.py.",
          "graph LR"]
    dl += [f'  {sid_(n)}["{Path(n).name if "/" in n else n}"]' for n in sorted({a for a, _ in lin})]
    dl += [f'  {sid_(n)}[("{stores[n]}")]' for n in sorted({b for _, b in lin})]
    for (a, b), k in sorted(lin.items()):
        if "write" in k:
            dl.append(f'  {sid_(a)} -->|{"read+write" if "read" in k else "write"}| {sid_(b)}')
        else:
            dl.append(f"  {sid_(a)} -.->|read| {sid_(b)}")
    assert len(lin) <= 40, f"data-lineage.mmd has {len(lin)} edges"
    (OUT / "data-lineage.mmd").write_text("\n".join(dl) + "\n")

    fl = flows[0]
    cp = [f"%% Critical path: {fl['name']} ({fl['persona']}).",
          "%% No production telemetry is available, so steps carry no p50/p99 annotations.", "flowchart TD"]
    for i, st in enumerate(fl["steps"], 1):
        cp.append(f'  S{i}["{i}. {st["label"]}<br/><small>{", ".join(leaf_name[n] for n in st["nodes"])}</small>"]')
        if i > 1:
            cp.append(f"  S{i - 1} --> S{i}")
    (OUT / "critical-path.mmd").write_text("\n".join(cp) + "\n")

    # ---------------------------------------------------------------- summary
    kinds = defaultdict(int)
    for e in edge_list:
        kinds[e["kind"]] += 1
    print(f"== {SYSTEM} topology: {len(nodes)} modules, {len(stores)} data stores, {len(jobs)} jobs, {len(screens)} screens")
    print(f"   functions: {len(funcs)} parsed, {len(live)} reachable from {len(roots)} production roots")
    print("   edges: " + ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())))
    print("\n-- link units (Makefile)")
    for u, d in sorted(units.items()):
        print(f"   {u:22} {sum(1 for x in d if x.endswith('.c')):2} .c files" + (f"  main={mains[u]['file']}" if u in mains else ""))
    print("\n-- entry points")
    for x in entry:
        print("   " + x)
    print("\n-- dead-end modules (no function reachable from production entry points)")
    for f in dead:
        print(f"   {f:40} {nodes[f]['loc']:5} lines  {'not linked into any binary' if f in unlinked else 'linked, never reached'}")
    print("\n-- data stores (R = read, W = write; binaries whose live code writes)")
    for s in sorted(stores):
        r = sorted({e["source"] for e in edge_list if e["target"] == s and e["kind"] == "read"})
        w = sorted({e["source"] for e in edge_list if e["target"] == s and e["kind"] == "write"})
        print(f"   {stores[s]:42} R: {', '.join(r) or '-'}")
        print(f"   {'':42} W: {', '.join(w) or '-'}" + (f"   [{', '.join(sorted(writers[s]))}]" if writers.get(s) else ""))
    print("\n-- highest fan-in + fan-out (module call/dispatch edges)")
    for f in sorted(nodes, key=lambda f: -(len(fan_in[f]) + len(fan_out[f])))[:8]:
        print(f"   {f:40} in={len(fan_in[f]):2} out={len(fan_out[f]):2}")
    dead_in_live = sorted(fn["id"] for fn in funcs if fn["file"] in live_files and fn["file"] in lib
                          and fn["id"] not in live)
    print(f"\n-- unreachable functions inside live library files: {len(dead_in_live)} (first 25)")
    for x in dead_in_live[:25]:
        print("   " + x)
    print(f"\n-- dispatch resolution: table handler field invoked = {handler_invoked}; "
          f"{skipped_table_refs} table handler addresses excluded from reachability")
    if rule_misses:
        print("!! store rules that matched nothing (rule rot): " + "; ".join(rule_misses))
    if missed_bodies:
        print(f"!! {len(missed_bodies)} top-level bodies lizard did not span (calls inside are unmapped): "
              + ", ".join(missed_bodies[:10]))
    print(f"\nwrote {rel(OUT / 'topology.json')}, call-graph.mmd, data-lineage.mmd, critical-path.mmd")


if __name__ == "__main__":
    main()
