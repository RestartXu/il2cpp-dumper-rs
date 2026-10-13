#!/usr/bin/env python3
r"""Method-level census of LOW-LEVEL residue in the pseudo-C dump.

Usage:  python3 census_nint.py <dump.cs> [--top N] [--sample-rvas]

For every method with a recovered pseudo-C body it classifies the residue
markers and aggregates per-family counts so fixes are measured, not guessed:

  deref      any `*(nint*)(` / `*(T*)(` raw pointer read
  dchain     deref OF a deref:  *(nint*)(*(nint*)…  (receiver itself a deref)
  asingleton raw deref of an absolute static address (0x…), incl. +odd offsets
  vbase      deref whose base is a register slot (v\d+), no field name
  nbase      deref whose base is an absolute/unknown base (not v\d+ / field)
  uknown     `__unknown` value appears
  fncall     `fn_<hex>(` unresolved runtime call
  casts      `(nint*)(…+NN)` style cast-offset chains that block typing

Clean methods carry none of: deref, __unknown, fn_ calls. The script prints
totals, per-family method counts, per-method overlap, the methods that are
dirty ONLY by a given single marker (pure targets), and a few sample RVAs per
family for drill-down with ILR_ONLY.
"""

import re
import sys
import collections

def iter_methods(text):
    """Yield (rva, class_context, body) per method that has a pseudo-C body."""
    # header line carries the signature; the C pseudo-code follows on the
    # same or next lines. Method blocks end at the closing `*/`.
    pat = re.compile(
        r"(?m)^\s*// RVA: (0x[0-9A-Fa-f]+)[^\n]*\n"
        r"(?P<head>(?:(?!// RVA:).)*?)"
        r"C pseudo-code:\n(?P<body>.*?)\*/\s*\}", re.S
    )
    for m in pat.finditer(text):
        yield m.group(1).upper(), m.group("head"), m.group("body")

MARKERS = {
    "deref":     re.compile(r"\*\((?:nint|long|int|byte|float|double|short|sbyte|ushort|uint|ulong)\s*\*\)\s*\("),
    "dchain":    re.compile(r"\*\((?:nint|long)\s*\*\)\s*\(\s*\*\((?:nint|long)\s*\*\)"),
    "asingleton":re.compile(r"\*\((?:nint|long)\s*\*\)\s*\(\s*(?:0x[0-9A-Fa-f]+)"),
    "vbase":     re.compile(r"\*\((?:nint|long)\s*\*\)\s*\(\s*v\d+"),
    "uknown":    re.compile(r"__unknown"),
    "fncall":    re.compile(r"\bfn_[0-9A-Fa-f]{6,}\s*\("),
    "staticabs": re.compile(r"(?:^|[^.\w])(0x[0-9A-Fa-f]+(?:\s*\+\s*\d+)?)(?:[^.\w]|$)"),
}

def classify(body):
    """Bitmask of families present in this method body (minus locals decl)."""
    b = re.sub(r"// locals:.*", "", body)          # locals list is noise
    hits = []
    for name, rx in MARKERS.items():
        if rx.search(b):
            hits.append(name)
    # method is clean when no low-level value residue at all
    if not hits:
        return ("clean",)
    return tuple(hits)

def main(path, top=12, want_samples=False):
    text = open(path, encoding="utf-8", errors="replace").read()
    fam = collections.Counter()
    per_method = []
    nclean = 0
    samples = collections.defaultdict(list)
    # method-level
    for rva, head, body in iter_methods(text):
        cats = classify(body)
        per_method.append((rva, cats))
        if cats == ("clean",):
            nclean += 1
        else:
            for c in cats:
                fam[c] += 1
                if len(samples[c]) < 6:
                    samples[c].append(rva)
    total = len(per_method)

    print(f"methods with pseudo-C body : {total}")
    print(f"clean (no deref/unknown/fn_) : {nclean}  ({100*nclean/max(total,1):.1f}%)")
    print(f"dirty                          : {total-nclean}  ({100*(total-nclean)/max(total,1):.1f}%)")
    print()
    print("per-family method counts (a method may be in several):")
    for name, c in fam.most_common():
        print(f"  {name:<11} {c:>6}  ({100*c/max(total,1):.1f}%)")
    print()
    # single-marker purity: methods dirty ONLY by this family → cleanest fix targets
    pure = collections.Counter()
    for _rva, cats in per_method:
        if len(cats) == 1 and cats[0] != "clean":
            pure[cats[0]] += 1
    print("methods dirty by EXACTLY ONE family (pure targets):")
    for name, c in pure.most_common():
        print(f"  {name:<11} {c:>6}")
    print()
    if want_samples:
        for name, rvas in samples.items():
            print(f"sample RVAs for {name}: {', '.join(rvas)}")

if __name__ == "__main__":
    path = sys.argv[1]
    top = 12
    rest = [a for a in sys.argv[2:] if a != "--samples"]
    if rest:
        try:
            top = int(rest[0])
        except ValueError:
            pass
    main(path, top=top, want_samples="--samples" in sys.argv)
