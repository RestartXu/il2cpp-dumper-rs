#!/usr/bin/env python3
"""One-shot migration: add the `width` field to `Operand::Memory` LITERALS.

Run once after `width: u8` was added to the `Operand::Memory` variant. For
every `Operand::Memory {` occurrence it finds the matching closing brace and,
if neither `width` nor `..` appears inside, inserts `width: 0,` immediately
after the opening brace.

Occurrences that already use `..` are PATTERNS with a rest-pattern: they
already cover the new field and must NOT be touched — inserting `width: 0`
there would turn a catch-all into a literal pattern requiring `width == 0`,
silently narrowing every match.

Exhaustive patterns (no `..`) are deliberately left for the compiler to
report; they are fixed by hand so the choice between `..` and a real binding
is made per site rather than guessed.
"""

import os
import sys


def migrate(path: str) -> int:
    src = open(path, encoding="utf-8", errors="surrogateescape").read()
    out = []
    i = 0
    needle = "Operand::Memory {"
    changed = 0
    while True:
        j = src.find(needle, i)
        if j < 0:
            out.append(src[i:])
            break
        open_brace = j + len(needle) - 1
        # walk to the matching close brace
        depth = 0
        k = open_brace
        while k < len(src):
            c = src[k]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        body = src[open_brace + 1 : k]
        out.append(src[i : open_brace + 1])
        if ".." not in body and "width" not in body:
            out.append(" width: 0,")
            changed += 1
        i = open_brace + 1
    if changed:
        open(path, "w", encoding="utf-8", errors="surrogateescape").write("".join(out))
    return changed


def main() -> int:
    total = 0
    for root, _dirs, files in os.walk("src"):
        for f in files:
            if f.endswith(".rs") and f != "ir.rs":
                p = os.path.join(root, f)
                n = migrate(p)
                if n:
                    print(f"{p}: {n}")
                    total += n
    print(f"total literals updated: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
