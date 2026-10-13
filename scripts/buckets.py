#!/usr/bin/env python3
"""4-bucket fidelity census: (clean|dirty) x (complete|dropped) per method.

Joins the pseudo-C dump.cs with the ILR_AUDIT jsonl. A method is:
  clean   — body free of low-level residue (derefs, fn_ calls, __unknown,
            raw vN locals in conditions, `+offset` reads on bare locals)
  dirty   — contains such residue
  complete— audit says every semantic op was accounted for (sem_un == 0)
  dropped — some semantic ops were not (sem_un > 0)

Usage: python3 buckets.py <dump.cs> <audit.jsonl>
"""
import re
import sys
import json


def method_blocks(path):
    """rva -> (name, stripped body) — tolerant of attributes before sigs."""
    txt = open(path).read()
    out = {}
    # Split on method signature lines; each carries its preceding RVA.
    pat = re.compile(
        r'// RVA: (0x[0-9A-Fa-f]+)[^\n]*\n'
        r'(?:\s*\[[^\]]*\]\n)*'
        r'\s*(?:public|private|internal|protected)[^\n]*?'
        r'\b([A-Za-z_][\w.]*)\([^)]*\)\s*\{\n'
        r'\s*/\* C pseudo-code:\n(.*?)\n\s*\*/\s*\}',
        re.S,
    )
    for m in pat.finditer(txt):
        body = m.group(3)
        # drop the locals comment
        body = re.sub(r'// locals:.*\n', '', body)
        out[m.group(1).lower()] = (m.group(2), body)
    return out


DIRTY = re.compile(
    r'\*\s*\(n?int\*\)|fn_[0-9a-f]+|__unknown|'
    r'\+\s*\d+\)|v\d+\s*\+|Delegate\.(Combine|Remove)\(v\d+, v\d+\)'
)


def main(dump, audit):
    blocks = method_blocks(dump)
    audit_lines = [json.loads(l) for l in open(audit) if l.strip()]
    stats = {"clean_complete": 0, "clean_dropped": 0,
             "dirty_complete": 0, "dirty_dropped": 0, "no_audit": 0}
    for a in audit_lines:
        rva = a["rva"].lower()
        if rva not in blocks:
            stats["no_audit"] += 1
            continue
        _name, body = blocks[rva]
        dirty = bool(DIRTY.search(body))
        dropped = a["sem_un"] > 0
        key = ("dirty" if dirty else "clean") + "_" + ("dropped" if dropped else "complete")
        stats[key] += 1
    tot = sum(v for k, v in stats.items() if k != "no_audit")
    print(f"{'bucket':16} {'methods':>7} {'%':>6}")
    for k in ("clean_complete", "clean_dropped", "dirty_complete", "dirty_dropped"):
        v = stats[k]
        print(f"{k:16} {v:7d} {100.0*v/tot:5.1f}%")
    print(f"{'methods':16} {tot:7d}")
    print(f"no_audit(attr blocks skipped): {stats['no_audit']}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
