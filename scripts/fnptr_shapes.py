#!/usr/bin/env python3
"""Classify the native shape at every unresolved indirect call in a dump.

The dumper renders an indirect call whose callee it could not name as
`fnptr_<call-site-rva>(...)`. Reading the *native* instruction at that RVA
says what the callee actually was — which is the only honest way to tell
which resolution mechanism is missing. Written for the v108 PE build; the
PE section table is parsed here so no external tool is needed.

Usage: fnptr_shapes.py <GameAssembly.dll> <dump.cs> [limit]
"""
import re
import struct
import sys
from collections import Counter

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

FNPTR = re.compile(rb"fnptr_0x([0-9a-f]+)")


def pe_sections(data):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[e_lfanew:e_lfanew + 4] == b"PE\0\0", "not a PE"
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt = e_lfanew + 24
    opt_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    sec = opt + opt_size
    out = []
    for i in range(nsec):
        off = sec + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", data, off + 8)
        out.append((name, vaddr, max(vsize, raw_size), raw_ptr))
    return out


def rva_to_off(sections, rva):
    for _name, vaddr, vsize, raw in sections:
        if vaddr <= rva < vaddr + vsize:
            return raw + (rva - vaddr)
    return None


def classify(md, off, data):
    """Disassemble half a dozen instructions back from `off` and describe the
    call's operand form plus the register's provenance."""
    start = max(0, off - 24)
    insns = list(md.disasm(data[start:off + 16], 0))
    call = None
    for k, ins in enumerate(insns):
        if ins.address == off - start:
            call = (k, ins)
            break
    if call is None:
        return "call-not-decoded", ""
    k, ins = call
    target = ins.op_str.split(",")[0].strip()
    # operand forms of a `call`
    if target.startswith("qword ptr") or target.startswith("["):
        form = "call [mem]"
    elif re.fullmatch(r"r[a-z0-9]+", target):
        form = "call reg"
    else:
        form = "call " + target
    # provenance of the called register / base of the called memory
    regs = re.findall(r"[re][a-z]{2}|r\d+[dbw]?", target)
    prov = []
    for r in set(regs):
        for j in range(k - 1, max(-1, k - 8), -1):
            src = insns[j]
            if not src.op_str.startswith(r + ","):
                continue
            rhs = src.op_str.split(",", 1)[1].strip()
            prov.append(f"{src.mnemonic} {r},{rhs}")
            break
    return form, " | ".join(prov[:2])


def main():
    dll, dump = sys.argv[1], sys.argv[2]
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 100000
    data = open(dll, "rb").read()
    sections = pe_sections(data)
    sites = sorted({int(m.group(1), 16) for m in FNPTR.finditer(open(dump, "rb").read())})
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    forms = Counter()
    provs = Counter()
    seen = 0
    for rva in sites:
        off = rva_to_off(sections, rva)
        if off is None:
            forms["not-in-image"] += 1
            continue
        form, prov = classify(md, off, data)
        forms[form] += 1
        if prov:
            norm = re.sub(r"0x[0-9a-f]+", "0xN", prov)
            norm = re.sub(r"\b[re][a-z]{2}\b", "R", norm)
            provs[norm] += 1
        seen += 1
        if seen >= limit:
            break
    print(f"sites {seen} of {len(sites)}")
    print("--- call operand form")
    for k, v in forms.most_common(12):
        print(f"{v:7d}  {k}")
    print("--- called-register provenance (register <- X)")
    for k, v in provs.most_common(20):
        print(f"{v:7d}  {k}")


if __name__ == "__main__":
    main()
