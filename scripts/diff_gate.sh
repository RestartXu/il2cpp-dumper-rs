#!/usr/bin/env bash
# Round-trip differential gate.
#
# The full round trip is C# -> managed IL -> IL2CPP native -> recovered CIL.
# Both ENDS of it are real .NET assemblies, so with no IL2CPP toolchain we can
# still compare them: the corpus ships the original managed assemblies
# (`Managed/*.dll`) next to the IL2CPP binary, and the dumper writes recovered
# CIL into `Dump*/DummyDll/*.dll`. This script runs the dumper with
# `--il-recovery` and then drives the ignored Rust test that reads BOTH sides
# with `dotnetdll` and compares each method's named references (calls, field
# accesses, string literals).
#
# What it certifies:
#   * every recovered assembly re-parses (a writer bug here fails the gate),
#   * the recovered method bodies still reference the same operations the
#     original IL does,
#   * the divergence set does not grow between changes.
#
# Exit codes:
#   0  the differential ran and met the (optional) agreement floor
#   1  the test failed (parse failure, or below RT_MIN_EXACT_PCT)
#   2  harness problem (missing dumper / binary / metadata / managed dir)
#
# Usage:
#   scripts/diff_gate.sh [BINARY] [METADATA] [MANAGED_DIR] [OUT]
#
# The default corpus is the x64 v24.5 PE. Set RT_MIN_EXACT_PCT to turn the
# measured agreement rate into a hard floor once a baseline is chosen, e.g.
#   RT_MIN_EXACT_PCT=9 scripts/diff_gate.sh ...
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="${1:-../Cpp2IL/TestFiles/Simple_2019_4_34/GameAssembly.dll}"
META="${2:-../Cpp2IL/TestFiles/Simple_2019_4_34/Simple_2019_4_34_Data/il2cpp_data/Metadata/global-metadata.dat}"
MANAGED="${3:-../Cpp2IL/TestFiles/Simple_2019_4_34/Managed}"
OUT="${4:-$ROOT/out-diffgate}"

DUMPER="${ILR_DUMPER:-target/release/il2cpp_dumper}"
if [ ! -x "$DUMPER" ] && [ -x "$DUMPER.exe" ]; then DUMPER="$DUMPER.exe"; fi

for f in "$DUMPER" "$BIN" "$META"; do
  if [ ! -e "$f" ]; then
    echo "diff-gate: missing $f — run 'cargo build --release' and check the paths" >&2
    exit 2
  fi
done
if [ ! -d "$MANAGED" ]; then
  echo "diff-gate: missing managed dir $MANAGED" >&2
  exit 2
fi

rm -rf "$OUT"
mkdir -p "$OUT"

echo "diff-gate: dumping with IL recovery..."
"$DUMPER" -b "$BIN" -m "$META" -o "$OUT" --il-recovery > "$OUT/dump.log" 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then
  echo "diff-gate: dumper exited $rc — see $OUT/dump.log" >&2
  exit 2
fi

RECOVERED="$(find "$OUT" -type d -name DummyDll | head -1)"
if [ -z "$RECOVERED" ]; then
  echo "diff-gate: no DummyDll produced — see $OUT/dump.log" >&2
  exit 2
fi

echo "diff-gate: comparing $RECOVERED against $MANAGED"
RT_MANAGED_DIR="$MANAGED" RT_RECOVERED_DIR="$RECOVERED" \
  cargo test --release --test roundtrip_difftest -- --ignored --nocapture
rc=$?

if [ "$rc" -ne 0 ]; then
  echo
  echo "diff-gate: FAILED (exit $rc)"
  exit 1
fi

echo
echo "diff-gate: OK — report at target/roundtrip-report.txt"
exit 0
