#!/usr/bin/env python3
"""Per-method defect census over a generated dump.cs.

Splits the dump on the `// RVA: 0x...` marker that precedes every method body,
then tallies each observable defect class inside each method. Prints a global
tally plus the worst offenders, so "some methods are broken" becomes a ranked,
reproducible worklist instead of an anecdote.

Usage: dump_census.py <dump.cs> [--top N] [--class NAME] [--grep SUBSTR]
"""
import re
import sys
from collections import Counter, defaultdict

DEFECTS = [
    # name, regex, weight
    ("unknown", re.compile(r"__unknown"), 1),
    ("abi", re.compile(r"__abi\b"), 1),
    ("fnptr", re.compile(r"fnptr_0x[0-9a-f]+"), 1),
    ("methodinfo", re.compile(r'MethodInfo\("'), 1),
    ("selfcmp", re.compile(r"op_{1,2}\w+\(([^,()]*(?:\([^()]*\))?[^,()]*), \1\)"), 1),
    ("this_bitand", re.compile(r"\(this & \d+\)"), 1),
    ("goto", re.compile(r"^\s*goto L\d+;"), 1),
    ("label", re.compile(r"^\s*L\d+:\s*$"), 1),
    ("emptytry", re.compile(r"catch \(Il2CppExceptionWrapper /\* managed catch \*/\)"), 1),
    ("raw_deref_cat", re.compile(r"\*\(nint\*\)\([^)]*\+[^)]*\+[^)]*\+"), 1),
    ("unknown_cond", re.compile(r"(?:if|while) \([^)]*__unknown[^)]*\)"), 3),
]

RVA = re.compile(r"^\s*// RVA: 0x([0-9A-Fa-f]+)")


def split_methods(path):
    """Yield (rva, first_line, body_text) per method body."""
    cur_rva = None
    cur_hdr = ""
    buf = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = RVA.match(line)
            if m:
                if cur_rva is not None:
                    yield cur_rva, cur_hdr, "".join(buf)
                cur_rva = m.group(1)
                # signature is on the following lines until the opening brace
                cur_hdr = ""
                buf = []
                continue
            if cur_rva is None:
                continue
            # The declaration line is the one carrying the opening brace; the
            # `/* C pseudo-code */` block that follows repeats the whole body
            # in a comment, so it must not be mistaken for the header.
            if not cur_hdr and "{" in line and not line.strip().startswith("/*"):
                cur_hdr = line.strip()
            buf.append(line)
    if cur_rva is not None:
        yield cur_rva, cur_hdr, "".join(buf)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    path = sys.argv[1]
    top = 25
    only_cls = None
    grep_sub = None
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--top":
            top = int(args[i + 1]); i += 2
        elif args[i] == "--class":
            only_cls = args[i + 1]; i += 2
        elif args[i] == "--grep":
            grep_sub = args[i + 1]; i += 2
        else:
            i += 1

    totals = Counter()
    methods = 0
    bad = []
    per_class_weight = Counter()
    classes = Counter()

    for rva, hdr, body in split_methods(path):
        methods += 1
        cls = "unknown"
        m = re.search(r"\b([A-Za-z_]\w*)\.([A-Za-z_]\w*)\(", hdr)
        if m:
            cls = m.group(1)
        else:
            m = re.search(r"\b([A-Za-z_]\w*)\s*\(", hdr)
            if m:
                cls = m.group(1)
        count = Counter()
        weight = 0
        for name, rx, w in DEFECTS:
            n = len(rx.findall(body))
            if n:
                count[name] = n
                totals[name] += n
                weight += n * w
        if weight:
            classes[cls] += weight
            if only_cls and only_cls not in cls:
                continue
            if grep_sub and grep_sub not in body:
                continue
            bad.append((weight, rva, cls, hdr, count))

    print(f"methods: {methods}")
    print(f"{'class':22s} {'count':>10s}")
    for name, _, _ in sorted(DEFECTS, key=lambda d: -totals[d[0]]):
        if totals[name]:
            print(f"{name:22s} {totals[name]:>10d}")
    print()
    print(f"--- worst {top} methods by weighted defect score ---")
    bad.sort(reverse=True, key=lambda t: t[0])
    for weight, rva, cls, hdr, count in bad[:top]:
        detail = " ".join(f"{k}={v}" for k, v in count.most_common())
        print(f"{weight:6d}  0x{rva:<9s} {cls:<40s} {detail}")
        if hdr and weight > 0:
            print(f"         {hdr[:160]}")
    print()
    print(f"--- worst {min(top, 20)} classes by weighted defect score ---")
    for cls, w in classes.most_common(20):
        print(f"{w:8d}  {cls}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
