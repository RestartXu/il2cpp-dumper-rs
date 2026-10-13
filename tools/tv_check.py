#!/usr/bin/env python3
"""Independent translation-validation check for the IL2CPP recovery engine.

The engine's own verifier (`src/recovery/verify.rs`) judges the recovered IR
against an oracle built from the SAME decoder crates the lifter uses
(yaxpeax-arm / iced-x86), so a decode bug both sides share is invisible to it.
This script re-decodes each method's native bytes with **Capstone** -- a
different disassembler -- and re-derives the control-flow facts from the
encoding, then compares them against the final IR the engine emitted (dumped by
`ILR_TV_DUMP=<path>`).

The sweep is manual and per-word on purpose: Capstone's Python `disasm`
generator STOPS at the first word it cannot decode, and IL2CPP embeds literal
pools inside method bodies -- a single embedded constant would truncate the
whole listing and fabricate thousands of false gaps. A failed word advances
exactly one instruction slot (the engine's own oracle does the same).

Reported:

  * `oracle_gap`       -- Capstone decodes a real instruction where the engine's
                          oracle has NO entry (the engine ran with no ground
                          truth). Tallied by mnemonic.
  * `decode_diff`      -- both have an entry but disagree on the mnemonic
                          (after arch-specific normalisation). Tallied by pair;
                          this is where an independent decoder earns its keep.
  * `branch_mismatch`  -- an in-body conditional/unconditional branch whose IR
                          target differs from Capstone's independently computed
                          one, after allowing the engine's absorbed-landing
                          slide over folded (flag-setting / no-op) instructions.

Architectures (`--arch`):

  * `arm32` -- CS_ARCH_ARM / CS_MODE_ARM (default)
  * `arm64` -- CS_ARCH_ARM64 / CS_MODE_LITTLE_ENDIAN
  * `x86`   -- CS_ARCH_X86 / CS_MODE_64

Usage:
    ILR_VERIFY=1 ILR_TV_DUMP=/tmp/tv.jsonl ./target/release/il2cpp_dumper ...
    python3 tools/tv_check.py --arch arm64 --jsonl /tmp/tv.jsonl
"""
import argparse
import collections
import json
import re
import sys

try:
    import capstone
except ImportError:
    print("capstone not installed (pip install capstone)", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Per-architecture tables
# ---------------------------------------------------------------------------

# ARM32: `b<cond>` / `bl<cond>`; the flag-setting `s` can trail the mnemonic.
A32_CONDS = ["eq", "ne", "hs", "lo", "cs", "cc", "mi", "pl", "vs", "vc",
             "hi", "ls", "ge", "lt", "gt", "le"]
A32_FOLDED = {"cmp", "cmn", "tst", "teq", "vmrs", "vmsr", "vcmp", "vcmpe",
              "nop", "bkpt", "dmb", "dsb", "isb", "svc"}

# ARM64: `b` unconditional, `b.<cond>` conditional, plus the compare-and-branch
# and test-bit-and-branch forms (all with an in-body target).
A64_COND = re.compile(r"^b\.(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)$")
A64_BRANCH = re.compile(r"^(b|b\.[a-z]{2}|cbz|cbnz|tbz|tbnz|bl|blr|ret|br)$")
A64_FOLDED = {"cmp", "cmn", "tst", "ccmp", "ccmn", "fcmp", "fccmp",
              "nop", "dmb", "dsb", "isb", "brk", "hlt", "msr", "mrs"}

# x86-64: `jmp` unconditional; `j<cc>` conditional; loop/jcxz are conditional.
X86_JCC = {
    "ja", "jae", "jb", "jbe", "jc", "jcxz", "jecxz", "je", "jg", "jge", "jl",
    "jle", "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl",
    "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo", "js", "jz",
    "jrcxz",
}
X86_BRANCH = X86_JCC | {"jmp"}
X86_FOLDED = {"cmp", "test", "nop", "cmpxchg", "ucomiss", "ucomisd",
              "comiss", "comisd", "bt"}

SYNTH = {"neon", "vfp"}
EXT = {"sxtb16", "sxtb", "sxth", "uxtb16", "uxtb", "uxth"}
INDEX_RE = re.compile(r"^(?:CondJump|Jump)\((\d+)\)$")


def make_md(arch):
    if arch == "arm32":
        md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
    elif arch == "arm64":
        md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
    elif arch == "x86":
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    else:
        raise SystemExit(f"unknown arch {arch}")
    md.detail = True
    return md


def norm(m, arch):
    """Text identity of a mnemonic under its architecture's conventions."""
    m = m.split()[0]
    if arch == "arm32":
        # drop a condition suffix then the flag-setting `s` (`cmps` == `cmp`)
        for c in A32_CONDS:
            if len(m) > len(c) and m.endswith(c):
                m = m[: -len(c)]
                break
        if len(m) > 1 and m.endswith("s"):
            m = m[:-1]
    elif arch == "arm64":
        # `b.eq` -> `b` ; keep compare-and-branch names distinct
        if m.startswith("b."):
            m = "b"
    # x86: no normalisation (`jne` != `jz` semantically)
    return m


def branch_target(ins, arch, cap_by_addr):
    """Return (kind, target) for a control-flow instruction, or None.

    kind is "jmp" (unconditional) or "cond" (conditional). target is the
    in-memory branch destination, or None when the form has no direct target
    (register/indirect, return).
    """
    m = ins.mnemonic
    if arch == "arm32":
        if not re.match(r"^b(eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)?$", m):
            return None
        if m in ("bl", "blx") or m.startswith("bl"):
            return None
        if not ins.operands:
            return None
        op = ins.operands[0]
        if op.type != capstone.arm.ARM_OP_IMM:
            return None
        return ("jmp" if m == "b" else "cond", op.imm)
    if arch == "arm64":
        if not A64_BRANCH.match(m):
            return None
        if m in ("bl", "blr", "ret"):
            return None
        if m in ("br",):
            return None
        # cbz/cbnz: target is operand[1]; tbz/tbnz: operand[2]
        idx = 0
        if m in ("cbz", "cbnz"):
            idx = 1
        elif m in ("tbz", "tbnz"):
            idx = 2
        if len(ins.operands) <= idx:
            return None
        op = ins.operands[idx]
        if op.type != capstone.arm64.ARM64_OP_IMM:
            return None
        kind = "cond" if (m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz")) else "jmp"
        return (kind, op.imm)
    if arch == "x86":
        if m not in X86_BRANCH:
            return None
        if not ins.operands:
            return None
        op = ins.operands[0]
        if op.type != capstone.x86.X86_OP_IMM:
            return None
        return ("jmp" if m == "jmp" else "cond", op.imm)
    return None


def folded_set(arch):
    return {"arm32": A32_FOLDED, "arm64": A64_FOLDED, "x86": X86_FOLDED}[arch]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arch", choices=["arm32", "arm64", "x86"], default="arm32")
    ap.add_argument("--jsonl", required=True)
    ap.add_argument("--max-report", type=int, default=20)
    args = ap.parse_args()

    arch = args.arch
    md = make_md(arch)
    FOLDED = folded_set(arch)

    methods = cap_insns = oracle_gap = decode_diff = synth_diff = 0
    undecodable = 0
    cond_branches = out_of_body = branch_match = branch_absorbed = 0
    branch_mismatch = no_ir_branch = 0
    gap_mnem = collections.Counter()
    diff_pairs = collections.Counter()
    examples = []

    # The dump can hold MORE THAN ONE record per rva: the C#/`dump.cs` path and
    # the DummyDll path each drive the pipeline once, with different seeds, and
    # `verify_method` fires the dump for both. They are tagged `src` ("cs" /
    # "dll"); keep the `cs` one, since that IR is what the emitted `dump.cs`
    # renders. Older dumps predate the tag — those fall back to first-wins.
    unique = {}
    for line in open(args.jsonl):
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        rv = rec['rva']
        prev = unique.get(rv)
        if prev is None or (rec.get('src') == 'cs' and prev[0] != 'cs'):
            unique[rv] = (rec.get('src'), line)

    for _src, line in unique.values():
        rec = json.loads(line)
        methods += 1
        base = rec["base"]
        data = bytes.fromhex(rec["bytes"])
        lo, hi = base, base + len(data)
        ir = rec["ir"]
        ir_addrs = [e["a"] for e in ir]
        ir_by_addr = collections.defaultdict(list)
        for e in ir:
            ir_by_addr[e["a"]].append(e)
        oracle = {d["a"]: d["m"] for d in rec["decoded"]}

        # Manual slot sweep: on a rejected word, advance one instruction slot
        # and keep going.
        #
        # WINDOW: an ARM instruction is exactly 4 bytes, so a 4-byte window
        # decodes one of them and the old code was correct there. An x86-64
        # instruction runs 1..15 bytes, and feeding only 4 made every `mov
        # [rsp+8], rbx` (5 bytes) UNDECODABLE — the sweep then advanced 4 and
        # desynchronised for the rest of the body. The engine's listing has
        # `mov [rsp+8], rbx` at 0x14EB20 while the old sweep produced
        # `or byte ptr [rdi+0x48], dl` at 0x14EB24 and never agreed with ANY
        # address afterwards, which is what fabricated the x86 "branch target
        # mismatch" count and most of its `oracle_gap`.
        #
        # Feed 16 bytes and keep the first instruction; fall back to one fixed
        # slot on failure (4 for ARM's fixed width, 1 for x86's variable one).
        # ARM keeps the original 4-byte window (its instruction width is
        # exactly that, and the arm32/arm64 counts are the validated baseline);
        # only x86 needs the wide window.
        win = 16 if arch == "x86" else 4
        fail_step = 1 if arch == "x86" else 4
        cap = []
        i = 0
        addr = base
        n = len(data)
        while i + fail_step <= n:
            chunk = data[i:i + win]
            consumed = fail_step
            for ins in md.disasm(chunk, addr):
                cap.append(ins)
                consumed = ins.size
                break
            i += consumed
            addr += consumed
        undecodable += max(0, len(data) // 4 - len(cap))
        cap_by_addr = {ins.address: ins for ins in cap}

        def absorbed(native, landing):
            cur = native
            while cur < landing:
                ci = cap_by_addr.get(cur)
                if ci is None or ci.mnemonic.split(".")[0] not in FOLDED:
                    return False
                cur += ci.size
            return cur == landing

        for ins in cap:
            cap_insns += 1
            a = ins.address
            om = oracle.get(a)
            if om is None:
                oracle_gap += 1
                gap_mnem[norm(ins.mnemonic, arch)] += 1
            else:
                om_base = norm(om, arch)
                if om_base != norm(ins.mnemonic, arch):
                    if om_base in SYNTH or om_base in EXT:
                        synth_diff += 1
                    else:
                        decode_diff += 1
                        diff_pairs[(om_base, norm(ins.mnemonic, arch))] += 1
            bt = branch_target(ins, arch, cap_by_addr)
            if bt is None:
                continue
            kind, native_target = bt
            if native_target is None or not (lo <= native_target < hi):
                out_of_body += 1
                continue
            cond_branches += 1
            want = "Jump" if kind == "jmp" else "CondJump"
            cj = [e for e in ir_by_addr.get(a, []) if e["op"].startswith(want)]
            if not cj:
                no_ir_branch += 1
                continue
            mm = INDEX_RE.match(cj[0]["op"])
            ir_target = None
            if mm:
                idx = int(mm.group(1))
                if 0 <= idx < len(ir_addrs):
                    ir_target = ir_addrs[idx]
            if ir_target == native_target:
                branch_match += 1
            elif ir_target is not None and absorbed(native_target, ir_target):
                branch_absorbed += 1
            else:
                branch_mismatch += 1
                if len(examples) < args.max_report:
                    examples.append((rec["rva"], a, ins.mnemonic, native_target, ir_target, cj[0]["op"]))

    print(f"== independent translation-validation check ({arch}, Capstone) ==")
    print(f"methods                 : {methods}")
    print(f"native insns (capstone) : {cap_insns}   (+{undecodable} undecodable slots)")
    print(f"oracle_gap              : {oracle_gap}   (capstone decodes, engine oracle has no entry)")
    print(f"decode_diff             : {decode_diff}   (both entries, different mnemonic)")
    print(f"synthesized_diff        : {synth_diff}   (engine labeled neon/vfp/EXT on purpose)")
    print(f"branches (in-body tgt)  : {cond_branches}")
    print(f"  out-of-body           : {out_of_body}")
    print(f"  target match          : {branch_match}")
    print(f"  absorbed-landing OK   : {branch_absorbed}")
    print(f"  target MISMATCH       : {branch_mismatch}")
    print(f"  no IR branch          : {no_ir_branch}")
    if gap_mnem:
        print("-- top 'oracle_gap' capstone mnemonics (engine had NO entry) --")
        for m, n in gap_mnem.most_common(12):
            print(f"     {n:6d}  {m}")
    if diff_pairs:
        print("-- top decode disagreements (engine -> capstone) --")
        for (e, c), n in diff_pairs.most_common(12):
            print(f"     {n:6d}  {e} -> {c}")
    if examples:
        print("-- first branch mismatches (method, addr, mnemonic, native->, ir->, ir op) --")
        for rva, a, m, nt, it, op in examples:
            print(f"  m={rva:#x} @{a:#x} {m} native={nt:#x} ir={it if it is None else hex(it)} {op}")


if __name__ == "__main__":
    main()
