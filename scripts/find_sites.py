#!/usr/bin/env python3
"""Stream a generated dump.cs and report every site matching a defect regex,
attributed to the method (RVA + signature) that contains it.

Streaming line-by-line matters: the dump is ~190 MB with a handful of
pathological lines, so slurping it and running a nested-quantifier regex over
the whole string either blows the backtracking budget or the memory budget.

Usage: find_sites.py <dump.cs> <regex> [--limit N] [--ctx CHARS] [--methods]
"""
import re
import sys
from collections import Counter

RVA = re.compile(r"^\s*// RVA: 0x([0-9A-Fa-f]+)")
DECL = re.compile(r"^\s*(?:\[[^\]]*\]\s*)*[A-Za-z_].*\(.*\)\s*\{?\s*$")


def main():
    path = sys.argv[1]
    rx = re.compile(sys.argv[2])
    limit = 20
    ctx = 90
    group_by_method = False
    args = sys.argv[3:]
    i = 0
    while i < len(args):
        if args[i] == "--limit":
            limit = int(args[i + 1]); i += 2
        elif args[i] == "--ctx":
            ctx = int(args[i + 1]); i += 2
        elif args[i] == "--methods":
            group_by_method = True; i += 1
        else:
            i += 1

    cur_rva = None
    cur_sig = ""
    words = 0
    per_method = Counter()
    sig_of = {}
    shown = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = RVA.match(line)
                if m:
                    cur_rva = int(m.group(1), 16)
                    cur_sig = ""
                    continue
                if cur_rva is not None and not cur_sig and "(" in line and not line.lstrip().startswith(("/*", "//", "*")):
                    cur_sig = line.strip()
                    sig_of[cur_rva] = cur_sig
                if "__unknown" not in line and "t4294967" not in line and not rx.search(line):
                    continue
                for mm in rx.finditer(line):
                    words += 1
                    if cur_rva is not None:
                        per_method[cur_rva] += 1
                    if shown < limit:
                        s = max(0, mm.start() - ctx)
                        e = min(len(line), mm.end() + ctx)
                        print(f"0x{cur_rva:X} | ...{line[s:e].strip()}...")
                        shown += 1
    except (KeyboardInterrupt, BrokenPipeError):
        pass

    print(f"\ntotal sites: {words}   distinct methods: {len(per_method)}")
    if group_by_method:
        print("\n--- worst methods ---")
        for rva, n in per_method.most_common(limit):
            print(f"{n:6d}  0x{rva:<9X} {sig_of.get(rva,'')[:110]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
