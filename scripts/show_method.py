#!/usr/bin/env python3
"""Print one method from a generated dump.cs by its RVA.

The dump is ~190 MB with stray non-UTF8 bytes, so grep/awk on it is fragile.
This reads it once and prints the requested methods. `--body-only` strips the
`/* C pseudo-code */` comment block, which repeats the whole method and doubles
every line when you are eyeballing a defect.

Usage: show_method.py <dump.cs> <rva> [<rva> ...] [--body-only]
"""
import re
import sys

RVA = re.compile(r"^\s*// RVA: 0x([0-9A-Fa-f]+)")


def methods(path):
    cur = None
    buf = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = RVA.match(line)
            if m:
                if cur is not None:
                    yield cur, buf
                cur = int(m.group(1), 16)
                buf = [line]
                continue
            if cur is not None:
                buf.append(line)
    if cur is not None:
        yield cur, buf


def main():
    path = sys.argv[1]
    wants = set()
    body_only = False
    for a in sys.argv[2:]:
        if a == "--body-only":
            body_only = True
        else:
            wants.add(int(a, 16))
    for rva, buf in methods(path):
        if rva not in wants:
            continue
        if body_only:
            out = []
            in_comment = False
            for line in buf:
                s = line.strip()
                if s.startswith("/* C pseudo-code"):
                    in_comment = True
                    continue
                if in_comment:
                    if s.endswith("*/"):
                        in_comment = False
                    continue
                if len(s) > 400:
                    continue  # the `// locals:` line
                out.append(line.rstrip("\n"))
            print("\n".join(out))
        else:
            for line in buf:
                s = line.strip()
                if len(s) > 400:
                    continue
                print(line.rstrip("\n"))
        print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
