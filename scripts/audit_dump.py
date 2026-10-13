#!/usr/bin/env python3
"""Decompilation-fidelity audit for a `dump.cs` produced by il2cpp_dumper.

Counts the defect classes that are visible in the generated text, so a change to
the lifter/recovery pipeline can be measured on a real binary instead of judged
by eye.

Usage:
    python scripts/audit_dump.py out-final-and/Dump0/dump.cs
    python scripts/audit_dump.py out-final-ios/Dump0/dump.cs --top 25

The counters map onto the layered model of the pipeline:

  * `unmodelled <name>`      — an instruction the lifter has no arm for. The
    VALUE is preserved (`__smulh(a, b)`) and the mnemonic is named, so these are
    readable-but-unmodelled, not silent corruption. A name that no user-mode
    compiler emits (`smc`, `swp`, `cdp2`, `mrc2`, `msr spsr_*`) is almost always
    DATA decoded as instructions, not code.
  * `undefined-local`        — `tNNNNNNNNNN` leak: an internal scratch slot name
    that escaped into the output, i.e. a value with no reaching definition.
  * `missing-condition`      — `if (? != 0)`-shaped tests: the branch is real,
    its condition is not.
  * `abi-hole`               — `__abi`, an ABI argument slot whose value could
    not be recovered.
  * `body-not-recoverable`   — no statements were produced for the method.
  * `fnptr-<addr>`           — an indirect call kept as its address.
"""

import argparse
import re
import sys
from collections import Counter

STUB = re.compile(r"__+([A-Za-z][A-Za-z0-9_]*)\(")
SCRATCH = re.compile(r"\bt[0-9]{6,}\b")
UNKNOWN_TOKEN = re.compile(r"__unknown\b")
ABI_TOKEN = re.compile(r"__abi\b")
FNPTR = re.compile(r"\bfnptr_(0x[0-9a-fA-F]+|\d+)")
# Two DIFFERENT defects, deliberately counted separately.
#
# `(? != 0)` — the branch is real but the compare behind it is gone: the lifter
# lost the flags entirely (dropped compare across a flag-preserving shuffle).
# This is the wrong-logic class.
LOST_COND = re.compile(r"\(\?\s*(!=|==|>=|<=|>|<)")
# `__unknown` (or a leaked scratch name) as a CONDITION operand — the compare is
# present and correctly shaped, but the VALUE it compares was never resolved.
# Still wrong in the output, but a different root cause (value resolution).
UNRESOLVED_COND = re.compile(
    r"(?:if|while)\s*\(\s*(?:__unknown|t[0-9]{6,}|[a-zA-Z_][\w]*\s*(?:\+|-|\*|&|\|)[^)]*?)"
    r"\s*(?:!=|==|>=|<=|>|<)"
)
RVA_HDR = re.compile(r"^\s*// RVA: 0x([0-9A-Fa-f]+)")
# `v123` — a rendered local slot. `v123 =` defines it; any other mention uses it.
V_LOCAL = re.compile(r"\bv(\d+)\b")
# A plain `v12 =` OR a compound `v12 +=` (both define the slot).
V_DEF = re.compile(r"\bv(\d+)\s*(?:=(?!=)|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=)")

# Names that are not lifter stubs at all — they are ordinary C# identifiers
# (`__Finally1`, `__updateTimer`, SWIG wrappers) that merely start with `__`.
NOT_A_STUB = {
    "unknown",
    "abi",
    "Finally1",
    "Finally2",
    "Finally3",
    "Finally4",
    "this",
    "ctor",
}

LOWER_MNEMONIC = re.compile(r"^[a-z][a-z0-9_]*$")

# A C#/C string literal, honouring backslash escapes: `"..."`.
#
# Every token counter below is a REGEX over the emitted text, and the text
# contains the decompiled program's OWN string literals — which routinely hold
# code-shaped text. The `lost conditions` counter was reporting 16 hits that were
# all regexes in the metadata (`"(?<=\\b=')[^']*"`, `"(?<id>#[-]?\\w...)"`):
# `(?<=` matches the `\(\?\s*(!=|==|…)` pattern, so the harness was reporting a
# WRONG-LOGIC defect class that did not exist, while a real one could hide in the
# same count. Literals are therefore removed before any counter runs.
STRING_LITERAL = re.compile(r'"(?:\\.|[^"\\])*"')


def strip_literals(line: str) -> str:
    """Remove string literals so a literal cannot masquerade as a defect."""
    return STRING_LITERAL.sub('""', line)


def is_lifter_stub(name: str) -> bool:
    """A stub name that is a MNEMONIC rather than a shadowed C# identifier.

    The ARM32/ARM64 lifters name their stubs with the decoder's own lowercase
    mnemonic (`__adc`, `__smulh`, `__smlaltt`), while x86 uses iced's CamelCase
    Debug spelling (`__Adc`, `__Shld`). Names that are neither — `SWIG_1`,
    `onAdClickedEvent`, `Unmanaged` — are members of the decompiled program that
    happen to start with two underscores, and counting them as decompiler
    defects would inflate the number by hundreds.
    """
    if name in NOT_A_STUB or name.startswith("_"):
        return False
    if LOWER_MNEMONIC.match(name):
        return True
    # CamelCase with no lowercase run longer than a word: x86-style mnemonic.
    return name[0].isupper() and not any(c == "_" or c.islower() for c in name[1:])


def audit(path: str, top: int) -> int:
    stubs: Counter = Counter()
    not_stubs: Counter = Counter()
    n_methods = 0
    n_bodies_empty = 0
    n_scratch = 0
    n_unknown = 0
    n_abi = 0
    n_fnptr = 0
    n_lost_cond = 0
    n_unresolved_cond = 0
    # Locals that are READ in a method body but never assigned anywhere in it:
    # the reaching-definition was lost, so the reader sees a name with no value.
    # This is the largest single defect class in the pipeline (it is what makes
    # `v2 + 28 -100`-style addresses appear). It is reported BOTH ways and the
    # two numbers answer different questions: `n_undef_local_uses` counts the
    # occurrences (how much of the output is unusable) and
    # `n_methods_with_undef` counts the distinct methods (how many bodies are
    # affected). Reporting only the occurrence total let one broken method
    # swamp it, which is why both are printed.
    n_undef_local_uses = 0
    n_methods_with_undef = 0
    body_defs = set()
    body_uses = Counter()
    cur_rva = None
    body_lines = 0
    method_bodies_with_code = 0

    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            m = RVA_HDR.match(line)
            if m:
                # A new method header. The previous method's body is complete.
                undef = [v for v in body_uses if v not in body_defs]
                if undef:
                    n_methods_with_undef += 1
                    n_undef_local_uses += sum(body_uses[v] for v in undef)
                body_defs = set()
                body_uses = Counter()
                n_methods += 1
                if cur_rva is not None and body_lines == 0:
                    n_bodies_empty += 1
                if body_lines:
                    method_bodies_with_code += 1
                cur_rva = m.group(1)
                body_lines = 0
                continue
            if cur_rva is None:
                continue
            body_lines += 1
            # Count tokens in the CODE, not in the program's own string data: a
            # literal like `"(?<=x)"` or `"__unknown"` is not a decompiler
            # defect, and counting it either invents a defect class or hides a
            # real one in the same total. EVERY counter below reads `code`, never
            # `line` — including `V_DEF`/`V_LOCAL`, so a `v12` inside a literal
            # can neither define nor use a slot.
            #
            # Comments are not stripped, and do not need to be: the emitter's
            # only comment shapes in a body (`output/decompiler.rs`) are
            # `// RVA: …`, `// Namespace: …`, `// Dll : …`, `// Fields`,
            # `// Properties`, `// Methods`, `// 0x…`, `// FieldRVA: …`,
            # `// ThreadStatic …` — none of which carries a `vN`, `tNNN…`,
            # `__unknown`, `__abi` or `fnptr_` token.
            #
            # `open(…, errors="replace")` iterating `fh` cannot skip a line, which
            # is why the published numbers must come from this script and not
            # from `grep -o` (grep drops lines that look binary in dump.cs).
            code = strip_literals(line)
            for name in STUB.findall(code):
                (stubs if is_lifter_stub(name) else not_stubs)[name] += 1
            n_scratch += len(SCRATCH.findall(code))
            n_unknown += len(UNKNOWN_TOKEN.findall(code))
            n_abi += len(ABI_TOKEN.findall(code))
            n_fnptr += len(FNPTR.findall(code))
            n_lost_cond += len(LOST_COND.findall(code))
            defs = set(V_DEF.findall(code))
            body_defs |= defs
            for v in V_LOCAL.findall(code):
                if v not in defs:
                    body_uses[v] += 1
            if "__unknown" in code and ("if (" in code or "while (" in code):
                n_unresolved_cond += code.count("__unknown")

    if cur_rva is not None and body_lines == 0:
        n_bodies_empty += 1
    undef = [v for v in body_uses if v not in body_defs]
    if undef:
        n_methods_with_undef += 1
        n_undef_local_uses += sum(body_uses[v] for v in undef)
    if body_lines:
        method_bodies_with_code += 1

    stub_total = sum(stubs.values())
    print(f"file                     {path}")
    print(
        f"(ignored {sum(not_stubs.values()):,} `__name(` hits that are C# identifiers,"
        " not lifter stubs)"
    )
    print(f"methods (RVA headers)    {n_methods:,}")
    print(f"methods with a body      {method_bodies_with_code:,}")
    print(f"bodies not recoverable   {n_bodies_empty:,}")
    print(f"unmodelled stubs         {stub_total:,}  ({len(stubs)} distinct)")
    print(f"undefined locals (tNNN)  {n_scratch:,}")
    print(f"__unknown                {n_unknown:,}")
    print(
        f"undefined locals (v*)     {n_undef_local_uses:,}"
        f"  in {n_methods_with_undef:,} methods"
    )
    print(f"__abi holes              {n_abi:,}")
    print(f"fnptr_<addr> calls       {n_fnptr:,}")
    print(f"lost conditions          {n_lost_cond:,}  (`(? != 0)` — compare gone)")
    print(
        f"unresolved conditions    {n_unresolved_cond:,}"
        "  (__unknown as the compared value)"
    )
    if stubs:
        print(f"\ntop {top} unmodelled mnemonics:")
        for name, count in stubs.most_common(top):
            print(f"  {count:>8,}  {name}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dump", help="path to Dump0/dump.cs")
    ap.add_argument("--top", type=int, default=20, help="how many stub names to list")
    args = ap.parse_args()
    try:
        return audit(args.dump, args.top)
    except FileNotFoundError:
        print(f"no such dump: {args.dump}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
