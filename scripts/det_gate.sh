#!/usr/bin/env bash
# Determinism gate for the native C# recovery pipeline.
#
# Runs the decompiler TWICE IN TWO SEPARATE PROCESSES over the same binary and
# compares a per-method content digest manifest.
#
# Why this is the right test rather than "we fixed the HashMaps we found":
# Rust's std HashMap seeds its hasher per process, so any hash-order leak in the
# pipeline shows up here as a differing digest beside the RVA that produced it.
# So does any wall-clock cut-off that fires at a load-dependent point. The gate
# does not need to know what the leak was, or where it lives — it fails, and it
# names the methods. Fixing four maps last round was necessary; only this makes
# it sufficient, and it stops the class from returning.
#
# Exit codes:
#   0  deterministic (identical manifests)
#   1  divergent (offending RVAs listed)
#   2  harness problem (missing dumper / no manifest / non-zero run)
#
# Usage:
#   scripts/det_gate.sh [BINARY] [METADATA] [LIMIT]
#
# LIMIT is the method-count cap (strided across the binary, deterministic).
# Use 0 for the exhaustive check over every method — that is the real gate and
# what CI should run; the default 4000 is the fast developer loop.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="${1:-libs/ios/UnityFramework}"
META="${2:-libs/ios/global-metadata.dat}"
LIMIT="${3:-${ILR_DET_LIMIT:-4000}}"

DUMPER="${ILR_DUMPER:-target/release/il2cpp_dumper}"
if [ ! -x "$DUMPER" ]; then
  if [ -x "$DUMPER.exe" ]; then DUMPER="$DUMPER.exe"; fi
fi

if [ ! -x "$DUMPER" ]; then
  echo "gate: no dumper at $DUMPER — run 'cargo build --release' first" >&2
  exit 2
fi
if [ ! -f "$BIN" ]; then
  echo "gate: missing binary $BIN" >&2
  exit 2
fi
if [ ! -f "$META" ]; then
  echo "gate: missing metadata $META" >&2
  exit 2
fi

# A wall-clock limit would make the two runs diverge by construction, which
# would make this gate measure the wrong thing. Refuse rather than mislead.
if [ -n "${ILR_TIME_LIMIT:-}" ]; then
  echo "gate: ILR_TIME_LIMIT is set — determinism cannot hold with a wall-clock cut-off" >&2
  echo "gate: unset it (a gate run must be reproducible by definition)" >&2
  exit 2
fi

OUT="$ROOT/out-detgate"
rm -rf "$OUT"
mkdir -p "$OUT"

for run in 1 2; do
  env ILR_DET_MANIFEST="$OUT/manifest-$run.txt" ILR_DET_LIMIT="$LIMIT" \
    "$DUMPER" "$BIN" "$META" "$OUT/run$run" > "$OUT/run$run.log" 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "gate: run$run exited $rc — see $OUT/run$run.log" >&2
    exit 2
  fi
  if [ ! -s "$OUT/manifest-$run.txt" ]; then
    echo "gate: run$run produced no manifest — see $OUT/run$run.log" >&2
    exit 2
  fi
done

n1=$(wc -l < "$OUT/manifest-1.txt")
n2=$(wc -l < "$OUT/manifest-2.txt")

if cmp -s "$OUT/manifest-1.txt" "$OUT/manifest-2.txt"; then
  echo "DETERMINISTIC — $n1 methods, byte-identical digests across two processes (limit=$LIMIT)"
  echo "manifest: $OUT/manifest-1.txt"
  exit 0
fi

echo "NONDETERMINISTIC OUTPUT"
echo "  run1 methods: $n1"
echo "  run2 methods: $n2"
echo "  differing methods (rva  run1-digest -> run2-digest):"

awk '
  FNR==NR { a[$1]=$2; order1[++n1]=$1; next }
  { b[$1]=$2 }
  END {
    shown = 0
    for (i = 1; i <= n1; i++) {
      k = order1[i]
      if (!(k in b)) {
        total_missing++
        if (shown < 40) { printf "    missing-in-run2 %s\n", k; shown++ }
      } else if (a[k] != b[k]) {
        total_diff++
        if (shown < 40) { printf "    %s  %s -> %s\n", k, a[k], b[k]; shown++ }
      }
    }
    for (k in b) if (!(k in a)) total_missing++
    printf "\n  SUMMARY: %d differing, %d present in only one run\n", total_diff, total_missing
    if (total_diff + total_missing > 40) printf "  (list truncated to 40)\n"
  }
' "$OUT/manifest-1.txt" "$OUT/manifest-2.txt"

echo
echo "Next step: pick one RVA above and reproduce it alone, e.g."
echo "  ILR_ONLY=<that-rva> $DUMPER \"$BIN\" \"$META\" out-det-one"
echo "then bisect the passes for that method. The manifest digest is FNV-1a of the"
echo "rendered body, so any pass that changes statement text or order is a suspect."

exit 1
