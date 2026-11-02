"""Lay out the ELF64 files the integrity goldens run the legacy check on (Phase 3 slice 4).

  python3 make_integrity_elf.py <out dir>

Each file is a minimal little-endian ELF64 image: a header, then .shstrtab, .fhsm_digest and
.data, then the section table. Every variant breaks one bound that src/fhsm_integrity.c
find_section_offset (:173-221) or do_verify (:223-282) checks. Nothing here computes an
expected value; gen_integrity.c records what the C makes of each file.
"""
import os
import struct
import sys

EHDR = 64
SHDR = 64
NAMES = b"\0.shstrtab\0.fhsm_digest\0.data\0"
N_SHSTRTAB, N_DIGEST, N_DATA = 1, 11, 24


def shdr(name, typ, off, size):
    return struct.pack("<IIQQQQIIQQ", name, typ, 0, 0, off, size, 0, 0, 1, 0)


def image(digest_len=48, digest_name=N_DIGEST, *, magic=b"\x7fELF", cls=2, shoff=None,
          shentsize=SHDR, shnum=None, shstrndx=1, strtab_size=None, digest_off=None,
          cut=None):
    digest = bytes((0xA0 + i) & 0xFF for i in range(digest_len))  # not zero: zeroing must matter
    data = bytes(range(64))
    o_names = EHDR
    o_digest = o_names + len(NAMES)
    o_data = o_digest + len(digest)
    o_tab = o_data + len(data)
    sections = [
        shdr(0, 0, 0, 0),
        shdr(N_SHSTRTAB, 3, o_names, len(NAMES) if strtab_size is None else strtab_size),
        shdr(digest_name, 1, o_digest if digest_off is None else digest_off, len(digest)),
        shdr(N_DATA, 1, o_data, len(data)),
    ]
    head = struct.pack(
        "<4sBBBB8xHHIQQQIHHHHHH", magic, cls, 1, 1, 0, 3, 62, 1, 0, 0,
        o_tab if shoff is None else shoff, 0, EHDR, 0, 0, shentsize,
        len(sections) if shnum is None else shnum, shstrndx)
    out = head + NAMES + digest + data + b"".join(sections)
    return out if cut is None else out[:cut]


FILES = {
    "good": image(),
    "wide_section": image(digest_len=64),          # zeroed whole, as sh_size says
    "short_section": image(digest_len=32),
    "no_section": image(digest_name=N_DATA),       # two sections named .data
    "bad_magic": image(magic=b"\x7fELG"),
    "elf32": image(cls=1),
    "no_table": image(shoff=0),
    "bad_shentsize": image(shentsize=40),
    "table_past_end": image(shnum=200),
    "shstrndx_out": image(shstrndx=9),
    "strtab_past_end": image(strtab_size=4096),
    "name_past_strtab": image(digest_name=len(NAMES) + 5),
    "name_unterminated": image(strtab_size=N_DIGEST + 4),  # ".fhs" ends the table
    "section_past_end": image(digest_off=1 << 20),
    "tiny": image(cut=40),
    "empty": b"",
}


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    for name, data in FILES.items():
        with open(os.path.join(out, name + ".elf"), "wb") as f:
            f.write(data)


if __name__ == "__main__":
    main()
