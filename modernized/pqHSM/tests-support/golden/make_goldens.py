"""Produce every golden file from the legacy C code. Runs inside the legacy
build image (see regen.sh), with:

  /legacy    a built legacy tree (.obj/**.o, tools/freehsm-audit, include/)
  /gen       this directory (read-only)
  /g-audit   modernized/pqHSM/audit/tests/golden        (rewritten)
  /av        modernized/pqHSM/audit-verify               (tests/golden rewritten;
             the CLI runs with this as its cwd so printed paths match cargo's)
  /baseline  analysis/pqHSM/baseline                     (read-only)

Nothing here computes an expected value: every expected value is what the C
module or the C tool printed. Python only lays out inputs and mutates files.
"""
import os
import shutil
import subprocess
import sys

KEY32 = bytes(range(32)).hex()
KEYS = {
    "test32": KEY32,
    "test16": bytes(range(16)).hex(),
    "test64": bytes(range(64)).hex(),
    "wrong32": bytes(range(1, 33)).hex(),
    "empty": "",
}
GEN = "/tmp/gen_audit"
TOOL = "/tmp/bin/freehsm-audit"
ENV = dict(os.environ, FHSM_INTEGRITY_ALLOW_UNSIGNED="1", PATH="/tmp/bin:/usr/bin:/bin")


def sh(*args, cwd=None):
    return subprocess.run(args, cwd=cwd, env=ENV, check=True, capture_output=True).stdout.decode()


def fresh(d):
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)


def build():
    objs = []
    for root, _, files in os.walk("/legacy/.obj"):
        if root.startswith("/legacy/.obj/tests"):
            continue
        objs += [os.path.join(root, f) for f in files if f.endswith(".o")]
    subprocess.run(["cc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-I/legacy/include",
                    "/gen/gen_audit.c", *sorted(objs), "-lcrypto", "-ldl", "-pthread", "-o", GEN],
                   check=True)
    os.makedirs("/tmp/bin", exist_ok=True)
    shutil.copy("/legacy/tools/freehsm-audit", TOOL)


def c_log(base, keylen=32, n=6):
    """Open base under the test key prefix, write n standard events, return the file."""
    return sh(GEN, "chain", base, str(keylen), str(n)).strip()


# ---- mutations (bytes in, bytes out) ----------------------------------------
def lines_of(b):
    return b.split(b"\n")[:-1]          # C logs always end with \n


def join(ls):
    return b"".join(l + b"\n" for l in ls)


def field_span(line, name):
    i = line.index(b'"%s":"' % name) + len(name) + 4
    return i, i + 64


def mutate(src):
    L = lines_of(src)
    v = {}

    def with_line(i, new):
        ls = list(L); ls[i] = new; return join(ls)

    l3 = bytearray(L[2]); d = l3[20]; l3[20] = ord("0") + (d - ord("0") + 1) % 10
    v["body_flip_line3"] = with_line(2, bytes(l3))
    l3 = bytearray(L[2]); s, _ = field_span(L[2], b"hmac")
    l3[s] = ord("0") if l3[s] != ord("0") else ord("1")
    v["mac_flip_line3"] = with_line(2, bytes(l3))
    v["line3_deleted"] = join(L[:2] + L[3:])
    v["lines3_4_swapped"] = join(L[:2] + [L[3], L[2]] + L[4:])
    v["seq_renumbered_line3"] = with_line(2, L[2].replace(b'"seq":3,', b'"seq":7,', 1))

    def up(line, name):
        s, e = field_span(line, name)
        return line[:s] + line[s:e].upper() + line[e:]
    v["hmac_uppercase_all"] = join([up(l, b"hmac") for l in L])
    v["prev_hmac_uppercase_line2"] = with_line(1, up(L[1], b"prev_hmac"))
    v["field_missing_seq_line2"] = with_line(1, L[1].replace(b'"seq":2,', b"", 1))
    v["field_missing_hmac_line4"] = with_line(3, L[3].replace(b'"hmac":"', b'"hmax":"', 1))
    s, e = field_span(L[4], b"hmac")
    v["hmac_63_hex_line5"] = with_line(4, L[4][:s] + L[4][s:e - 1] + L[4][e:])
    v["long_line_appended"] = src + b"x" * 5000 + b"\n"
    v["empty"] = b""
    v["no_final_newline"] = src[:-1]
    v["crlf"] = b"".join(l + b"\r\n" for l in L)
    v["tail_truncated"] = join(L[:-1])
    v["line3_duplicated"] = join(L[:3] + [L[2]] + L[3:])
    v["blank_line_inserted_before_3"] = join(L[:2] + [b""] + L[2:])
    l3 = bytearray(L[2]); l3[20] = 0
    v["nul_in_body_line3"] = with_line(2, bytes(l3))
    v["trailer_altered_line3"] = with_line(2, L[2][:-1] + b"]")
    # A hex pair "0X" in a recorded hmac rewritten "+X": sscanf("%2x") in the
    # tool reads the same byte, unhex32 in the module refuses the '+'.
    for i, l in enumerate(L):
        s, _ = field_span(l, b"hmac")
        pair = next((s + 2 * p for p in range(32) if l[s + 2 * p] == ord("0")), None)
        if pair is not None:
            v["hmac_plus_sign"] = with_line(i, l[:pair] + b"+" + l[pair + 1:])
            break
    return v


def main():
    build()
    ga = "/g-audit"
    for sub in ("lines", "verify", "baseline", "streams"):
        fresh(f"{ga}/{sub}")
    av = "/av/tests/golden"
    fresh(av)

    # 1. line rendering ---------------------------------------------------------
    sh(GEN, "lines", f"{ga}/lines")

    # 2. in-module verifier -----------------------------------------------------
    vd = f"{ga}/verify"
    os.rename(c_log(f"{vd}/c"), f"{vd}/chain.log")
    os.rename(c_log(f"{vd}/k16", 16, 3), f"{vd}/key16.log")
    os.rename(c_log(f"{vd}/k64", 64, 3), f"{vd}/key64.log")
    for name, data in mutate(open(f"{vd}/chain.log", "rb").read()).items():
        open(f"{vd}/{name}.log", "wb").write(data)
    sh(GEN, "craft", vd)
    for f in ("lines.log", "newline_key.log"):
        shutil.copy(f"{ga}/lines/{f}", f"{vd}/{f}")
    shutil.copy("/baseline/audit.log.000001", f"{ga}/baseline/audit.log.000001")
    shutil.copy("/baseline/TEST_KEY_HEX", f"{ga}/baseline/TEST_KEY_HEX")

    logs = sorted(f for f in os.listdir(vd) if f.endswith(".log"))
    rows = [(f, "test32") for f in logs]
    rows += [("chain.log", "wrong32"), ("chain.log", "test16"), ("chain.log", "empty"),
             ("key16.log", "test16"), ("key64.log", "test64"), ("missing.log", "test32")]
    with open(f"{vd}/expected.tsv", "w") as out:
        out.write("# file\tkey\trv\tbroken_at_line   (C fhsm_audit_verify)\n")
        for f, k in rows:
            got = sh(GEN, "verify", KEYS[k], f"{vd}/{f}").strip().split("\t")
            out.write(f"{f}\t{k}\t{got[1]}\t{got[2]}\n")
    base_ok = sh(GEN, "verify", KEY32, f"{ga}/baseline/audit.log.000001").strip().split("\t")
    with open(f"{ga}/baseline/expected.tsv", "w") as out:
        out.write("# file\tkey\trv\tbroken_at_line   (C fhsm_audit_verify)\n")
        out.write(f"audit.log.000001\ttest32\t{base_ok[1]}\t{base_ok[2]}\n")

    # 3. numbering: what file each opening creates --------------------------------
    scen = {
        "empty_dir": [],
        "after_000006": ["audit.log.000006"],
        "after_000001_and_000003": ["audit.log.000001", "audit.log.000003"],
        "five_digits_ignored": ["audit.log.00009"],
        "seven_digits_ignored": ["audit.log.0000009"],
        "other_prefixes_ignored": ["other.log.000009", "audit.logx000009", "xaudit.log.000009",
                                   "audit.log2.000009", "audit.log.000009.bak"],
        "non_numeric_ignored": ["audit.log.00009a", "audit.log.0x0009", "audit.log.abcdef"],
        "strtoul_plus_sign_counts": ["audit.log.+00009"],
        "strtoul_leading_space_counts": ["audit.log. 00009"],
        "strtoul_minus_wraps_to_000000": ["audit.log.-00001"],
        "wrap_then_steps_past_existing": ["audit.log.-00001", "audit.log.000000", "audit.log.000001"],
        "after_999999_seven_digits": ["audit.log.999999"],
    }
    twice = {"empty_dir", "after_999999_seven_digits"}
    with open(f"{ga}/numbering.tsv", "w") as out:
        out.write("# scenario\texisting files ('/'-separated)\tfile each C opening created ('/'-separated)\n")
        for name, files in scen.items():
            d = f"/tmp/num/{name}"
            os.makedirs(d)
            for f in files:
                open(f"{d}/{f}", "w").close()
            opened = [sh(GEN, "open", f"{d}/audit.log").strip() for _ in range(2 if name in twice else 1)]
            out.write(f"{name}\t{'/'.join(files)}\t{'/'.join(opened)}\n")
        opened = sh(GEN, "open", "/tmp/num/no-such-dir/audit.log").strip()
        out.write(f"missing_directory\t\t{opened}\n")

    # 4. streams -------------------------------------------------------------------
    open(f"{ga}/streams/dev_null.tsv", "w").write(sh(GEN, "stream", "/dev/null", "2"))
    open(f"{ga}/streams/dev_full.tsv", "w").write(sh(GEN, "stream", "/dev/full", "2"))
    open(f"{ga}/streams/fifo.tsv", "w").write(sh(GEN, "fifo", "/tmp/audit.fifo", "3"))

    # 5. CLI -----------------------------------------------------------------------
    lg = f"{av}/logs"
    os.makedirs(lg)
    for f in os.listdir(vd):
        if f.endswith(".log"):
            shutil.copy(f"{vd}/{f}", f"{lg}/{f}")
    shutil.copy(f"{ga}/baseline/audit.log.000001", f"{lg}/baseline.log")

    dd = f"{av}/dirs"
    for name, n in (("contiguous", 2), ("hole", 3), ("from2", 3), ("tampered", 2)):
        os.makedirs(f"{dd}/{name}")
        for _ in range(n):
            c_log(f"{dd}/{name}/audit.log", 32, 3)
    os.remove(f"{dd}/hole/audit.log.000002")
    os.remove(f"{dd}/from2/audit.log.000001")
    t = bytearray(open(f"{dd}/tampered/audit.log.000002", "rb").read())
    t[20] = ord("0") + (t[20] - ord("0") + 1) % 10
    open(f"{dd}/tampered/audit.log.000002", "wb").write(bytes(t))
    os.makedirs(f"{dd}/none")
    for f in ("README.txt", "audit.log.12345", "audit.log.00000a"):
        open(f"{dd}/none/{f}", "w").write("not a numbered log\n")

    G = "tests/golden"
    chain = f"{G}/logs/chain.log"
    cases = {
        "usage_no_args": [],
        "usage_dump_without_path": ["dump"],
        "usage_verify_one_arg": ["verify", chain],
        "usage_verify_too_many_args": ["verify", chain, KEY32, "extra"],
        "usage_unknown_command": ["list", chain],
        "verify_key_63_chars": ["verify", chain, KEY32[:63]],
        "verify_key_65_chars": ["verify", chain, KEY32 + "0"],
        "verify_key_non_hex": ["verify", chain, "zz" + KEY32[2:]],
        "verify_key_uppercase": ["verify", chain, KEY32.upper()],
        "verify_key_sscanf_plus_sign": ["verify", chain, "+0" + KEY32[2:]],
        "verify_key_sscanf_leading_space": ["verify", chain, " 0" + KEY32[2:]],
        "verify_key_sscanf_minus_sign": ["verify", chain, "-1" + KEY32[2:]],
        "verify_key_checked_before_file": ["verify", f"{G}/logs/missing.log", KEY32[:63]],
        "verify_wrong_key": ["verify", chain, KEYS["wrong32"]],
        "verify_missing_file": ["verify", f"{G}/logs/missing.log", KEY32],
        "verify_key16_log_cannot_be_verified": ["verify", f"{G}/logs/key16.log", KEY32],
        "verify_baseline_fixture": ["verify", f"{G}/logs/baseline.log", KEY32],
        "verify_dir_contiguous": ["verify", f"{G}/dirs/contiguous", KEY32],
        "verify_dir_hole": ["verify", f"{G}/dirs/hole", KEY32],
        "verify_dir_starts_at_000002": ["verify", f"{G}/dirs/from2", KEY32],
        "verify_dir_tampered_file": ["verify", f"{G}/dirs/tampered", KEY32],
        "verify_dir_no_numbered_files": ["verify", f"{G}/dirs/none", KEY32],
        "verify_dir_trailing_slash": ["verify", f"{G}/dirs/contiguous/", KEY32],
        "verify_dir_bad_key": ["verify", f"{G}/dirs/contiguous", "zz"],
        "dump_chain": ["dump", chain],
        "dump_edge_case_lines": ["dump", f"{G}/logs/lines.log"],
        "dump_long_line": ["dump", f"{G}/logs/long_line_appended.log"],
        "dump_crafted_minimal_fields": ["dump", f"{G}/logs/craft_minimal_fields.log"],
        "dump_missing_file": ["dump", f"{G}/logs/missing.log"],
        "dump_two_files_one_missing": ["dump", f"{G}/logs/missing.log", f"{G}/logs/key16.log"],
        "dump_empty_file": ["dump", f"{G}/logs/empty.log"],
    }
    for f in sorted(os.listdir(lg)):
        if f.endswith(".log") and f != "chain.log":
            cases.setdefault(f"verify_log_{f[:-4]}", ["verify", f"{G}/logs/{f}", KEY32])
    cases["verify_log_chain"] = ["verify", chain, KEY32]
    for name, args in cases.items():
        d = f"{av}/cli/{name}"
        os.makedirs(d)
        argv = ["freehsm-audit"] + args
        r = subprocess.run(argv, cwd="/av", env=ENV, capture_output=True)
        open(f"{d}/args", "w").write("".join(a + "\n" for a in argv))
        open(f"{d}/stdout", "wb").write(r.stdout)
        open(f"{d}/stderr", "wb").write(r.stderr)
        open(f"{d}/exit", "w").write(f"{r.returncode}\n")
    print(f"goldens written: {len(cases)} CLI cases, {len(rows)} verifier rows")


if __name__ == "__main__":
    sys.exit(main())
