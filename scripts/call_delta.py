#!/usr/bin/env python3
"""Per-method call-expression delta between two dump.cs files.

`audit_dump.py` counts the undefined-local defect; this answers the other half
of the same question — did a renderer change remove a CALL from any method's
text? It is the manual counterpart of the concordance's `dropped-call methods`
line, kept as a script because comparing two dumps needs no disassembly.

What counts as a call
---------------------
One token per call expression: the identifier chain immediately before the `(`,
with dotted member access kept (`sf0.get_Item`, `InternedString.op_Equality`) and
any generic argument list dropped (`List<int>.Add(` -> `List.Add`). `new T(...)`
counts as one call, token `T`: an object creation IS a call to a constructor,
and dropping it from the count would HIDE a real loss.

The only exclusions are the C# language itself:

  * control-flow / operator keywords (`if`, `while`, `for`, `foreach`,
    `switch`, `return`, `throw`, `catch`, `using`, `lock`, `fixed`, `do`, ...).
    This is the defect this script used to have: `CALL = \\b\\w+\\s*\\(` matched
    `return (` and `if (` as calls, so a method that lost nothing could be
    reported as losing a call. That produced two false hunts in this project's
    history (`0xf9f880`, `0x12244b0` — both were keyword artefacts);
  * the builtin type keywords (`int`, `nint`, `long`, `string`, ...), which the
    renderer emits in casts — `(nint)(v0 + 40)` names no callee;
  * `typeof` / `sizeof` / `nameof` / `checked` / `unchecked` / `default`, which
    are operators in call syntax.

Nothing from the dumper's own namespace is excluded. `__smulh(a, b)`,
`__vector_add(...)`, `fnptr_0x1234(...)` and `internal_*` ARE calls: the value
they produce is a stub, but a statement that calls one is a call statement and
losing it is exactly the defect this tool exists to find. (The bare
placeholders `__unknown` and `__abi` are values, not callees — they carry no
`(`, so they never enter the multiset.)

Normal strings (with backslash escapes) and verbatim strings (`@"..."`, where
`""` is the escape and `\\` is literal) are removed before anything is counted,
so call-shaped text in the decompiled program's own data cannot masquerade as a
call. A method's own signature line is skipped for the same reason: a method
does not call itself.

Comparison
----------
Per method, as a MULTISET of callee tokens, not a line count — a method that
loses `Foo()` and gains `Bar()` is reported, not silently clean, and a callee
mentioned twice is two calls.

A dump can carry more than one body for one RVA (a stub plus the recovered
body), so bodies are paired in file order and any body with no counterpart is
reported separately instead of being counted as a loss: a body that was ADDED
or REMOVED is not a method that lost a call.

Exit status
-----------
  0   compared successfully; no method lost a call
  1   compared successfully; at least one method lost a call (see the report)
  2   usage error, or an input could not be read, or the file has no method
      headers at all (a dump without `// RVA:` lines says nothing about calls)

so a caller can tell "clean" from "found losses" from "did not run".

Usage: call_delta.py BEFORE.cs AFTER.cs [--top N] [--all]
"""

import argparse
import re
import sys
from collections import Counter

IDENT_CH = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"
)

# C# keywords, contextual keywords and builtin types: tokens that look like a
# callee to a regex but are the language, not a call.
KEYWORDS = frozenset(
    """
    abstract as base bool break byte case catch char checked class const
    continue decimal default delegate do double else enum event explicit extern
    false finally fixed float for foreach goto if implicit in int interface
    internal is lock long namespace new null object operator out override params
    private protected public readonly ref return sbyte sealed short sizeof
    stackalloc static string struct switch this throw true try typeof uint
    ulong unchecked unsafe ushort using virtual void volatile while
    """.split()
) | frozenset(
    """
    add alias and ascending async await by descending dynamic equals file from
    get global group init into join let managed nameof nint not notnull nuint on
    or orderby partial record remove required scoped select set unmanaged value
    var when where with yield
    """.split()
)

# A method header, as `output/decompiler.rs` writes it:
#     {indent}\t// RVA: 0x… Offset: 0x… VA: 0x…     (the method has a body)
#     {indent}\t// RVA: -1 Offset: -1               (no pointer — no body)
# `{indent}` is empty only at the top level, so the indentation must be matched
# loosely. The previous pattern here was `^\t// RVA: (0x…)`, which silently
# ignored every method of a nested type (its line starts `\t\t// …`) and every
# `-1` method — those bodies were attributed to the preceding method instead.
RVA_HEADER = re.compile(
    r"^\s*//\s*RVA: (?:(0x[0-9A-Fa-f]+) Offset: 0x[0-9A-Fa-f]+"
    r"(?: VA: 0x[0-9A-Fa-f]+)?|-1 Offset: -1)"
)
# An abstract/interface method's header carries no RVA text at all:
#     {indent}\t//            (and ` Slot: N` appended when the slot is known)
# Its next line is still a real signature, which is what confirms it.
BODYLESS_HEADER = re.compile(r"^\s*//\s*(?:Slot: \d+)?\s*$")
# A method SIGNATURE emitted as real C# (`public static void Foo(int a)`), i.e.
# `[attrs] modifiers return-type name (`. Only the first line after a header is
# ever tested against this.
DECL = re.compile(
    r"^\s*(?:\[[^\]]*\]\s*)*"
    r"(?:\w+\s+)*"
    r"[\w\.<>\[\],\?]+\s+[\w<>\[\],\.]+\s*\("
)

# Verbatim first: inside `@"…"` a backslash does not escape and `""` is a quote.
VERBATIM = re.compile(r'@"(?:[^"]|"")*"')
NORMAL = re.compile(r'"(?:\\.|[^"\\])*"')


def strip_literals(line):
    """Remove string literals so a literal cannot masquerade as a call."""
    return NORMAL.sub('""', VERBATIM.sub('""', line))


def callees(code):
    """Callee token of every call expression on one line of CODE (no literals).

    A token is the identifier chain immediately before the `(`. Scanning
    backwards from each `(` is what makes a cast (`(nint)(v0 + 40)`) and a
    parenthesised expression (`return (v13 - A);`) produce no token at all:
    there is either a `)` or a space before the `(`, not an identifier.
    """
    out = []
    i = code.find("(")
    while i >= 0:
        j = i - 1
        if j >= 0 and code[j] == ">":
            # `Foo<int>(` or `new List<int>(`: step over the generic argument
            # list. Only a BALANCED `<…>` directly preceded by an identifier
            # counts — otherwise `x > (y)` would swallow the `(y)`.
            depth = 0
            k = j
            while k >= 0:
                c = code[k]
                if c == ">":
                    depth += 1
                elif c == "<":
                    depth -= 1
                    if depth == 0:
                        break
                k -= 1
            if k > 0 and code[k] == "<" and code[k - 1] in IDENT_CH:
                j = k - 1
        end = j
        while j >= 0 and (code[j] in IDENT_CH or code[j] == "."):
            j -= 1
        chain = code[j + 1:end + 1]
        i = code.find("(", i + 1)
        if not chain or chain.startswith("."):
            continue
        tail = chain.rsplit(".", 1)[-1]
        if not tail or tail[0].isdigit() or tail in KEYWORDS:
            continue
        out.append(chain)
    return out


def _with_lookahead(fh):
    """Yield `(line, next_line)` so a boundary can be confirmed by its follower."""
    it = iter(fh)
    cur = next(it, None)
    if cur is None:
        return
    for nxt in it:
        yield cur, nxt
        cur = nxt
    yield cur, None


def per_method(path):
    """Return `(bodies, n_headers)`.

    `bodies` maps an RVA to the list of that method's bodies in file order, each
    a `Counter` of callee tokens. A bodyless method (abstract/interface, or a
    `-1` pointer) contributes an empty `Counter`; those have no RVA to key on and
    are collected under `-1`, where index pairing is trivially correct.
    """
    bodies = {}
    n_headers = 0
    cur = None
    expect_sig = False
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line, nxt in _with_lookahead(fh):
            m = RVA_HEADER.match(line)
            if m is not None:
                key = -1 if m.group(1) is None else int(m.group(1), 16)
            elif BODYLESS_HEADER.match(line) and nxt is not None and DECL.match(nxt):
                key = -1
            else:
                key = None
            if key is not None:
                cur = Counter()
                bodies.setdefault(key, []).append(cur)
                n_headers += 1
                expect_sig = True
                continue
            if cur is None:
                continue
            code = strip_literals(line)
            if expect_sig:
                if not code.strip() or code.lstrip().startswith("["):
                    continue  # blank or attribute line: still before the signature
                expect_sig = False
                if DECL.match(code):
                    continue  # the method's own signature is not a call
            for tok in callees(code):
                cur[tok] += 1
    return bodies, n_headers


def compare(before, after):
    """Per-RVA losses/gains plus the bodies that could not be paired."""
    lost = {}
    gained = {}
    only_before = only_after = unpaired = 0
    for key in sorted(set(before) | set(after)):
        bl = before.get(key, [])
        al = after.get(key, [])
        if not bl:
            only_after += len(al)
            continue
        if not al:
            only_before += len(bl)
            continue
        n = min(len(bl), len(al))
        unpaired += (len(bl) - n) + (len(al) - n)
        d = Counter()
        g = Counter()
        for i in range(n):
            d += bl[i] - al[i]
            g += al[i] - bl[i]
        if d:
            lost[key] = d
        if g:
            gained[key] = g
    return lost, gained, only_before, only_after, unpaired


def fmt(counts):
    """`Name` / `Name xN` list, sorted by count then name — deterministic."""
    return ", ".join(
        f"{tok} x{c}" if c > 1 else tok
        for tok, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    )


def label(key):
    return "-1" if key < 0 else f"{key:#x}"


def main():
    ap = argparse.ArgumentParser(
        description="Per-method call-expression delta between two dump.cs files."
    )
    ap.add_argument("before", help="the dump.cs produced BEFORE the change")
    ap.add_argument("after", help="the dump.cs produced AFTER the change")
    ap.add_argument("--top", type=int, default=15, help="how many methods to detail")
    ap.add_argument(
        "--all",
        action="store_true",
        help="detail every changed method, not just the top N",
    )
    args = ap.parse_args()

    try:
        before, nb = per_method(args.before)
        after, na = per_method(args.after)
    except OSError as exc:
        print(f"cannot read dump: {exc}", file=sys.stderr)
        return 2
    if not nb or not na:
        # Without headers the whole file is one body and every comparison is
        # meaningless; say so instead of printing "no method lost a call".
        print(
            "no `// RVA:` method headers found — this file is not a dump.cs with "
            "method offsets (or recovery disabled every body)",
            file=sys.stderr,
        )
        return 2

    tot_b = sum(sum(c.values()) for lst in before.values() for c in lst)
    tot_a = sum(sum(c.values()) for lst in after.values() for c in lst)
    lost, gained, only_b, only_a, unpaired = compare(before, after)
    total_lost = sum(sum(c.values()) for c in lost.values())
    total_gained = sum(sum(c.values()) for c in gained.values())

    print(f"{args.before}: {tot_b:,} call expressions in {nb:,} bodies")
    print(
        f"{args.after}: {tot_a:,} call expressions in {na:,} bodies"
        f"  ({tot_a - tot_b:+,})"
    )
    print(
        f"bodies only in one file: {only_b + only_a:,}"
        f" (before {only_b:,}, after {only_a:,})"
        f"   unpaired bodies at a shared RVA: {unpaired:,}"
    )
    print(
        f"methods losing call expressions: {len(lost):,}"
        f"   gaining: {len(gained):,}"
        f"   (total lost {total_lost:,}, gained {total_gained:,})"
    )

    if not lost:
        print("\nno method lost a call.")
        return 0

    shown = sorted(lost.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))
    if not args.all:
        shown = shown[: args.top]
    print(f"\nby call expressions LOST ({len(shown)} of {len(lost)} shown):")
    for key, d in shown:
        print(f"  {label(key)}  {sum(d.values())} lost")
        print(f"      lost   : {fmt(d)}")
        print(f"      gained : {fmt(gained[key]) if key in gained else '(none)'}")

    if not args.all:
        gshown = sorted(gained.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))
        gshown = [x for x in gshown if x[0] not in lost][: args.top]
        if gshown:
            print("\nby call expressions GAINED (methods that lost none):")
            for key, g in gshown:
                print(f"  {label(key)}  {sum(g.values())} gained")
                print(f"      gained : {fmt(g)}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
