#!/usr/bin/env bash
# Fail on a mutant that survives and is not in the baseline.
#
# usage: mutants-baseline-check.sh BASELINE OUTDIR
#   BASELINE  crates/agent-guard/mutants-baseline.txt: one known survivor per
#             line, `file<TAB>function<TAB>mutation<TAB>why`. `why` says
#             either that the mutant is equivalent (no test can see it, and
#             why) or that it is not killed yet (found on a date, to burn
#             down). Lines starting with `#` are comments.
#   OUTDIR    a cargo-mutants output directory (holding missed.txt and
#             timeout.txt).
#
# A survivor is keyed without its line and column, so an edit above it does
# not turn it into a new one. The same mutation can appear more than once in
# one function; each key is counted, and the run may not hold more of a key
# than the baseline does. A timeout counts as a survivor: with the timeout
# relative to the baseline test time, a mutant that runs out of it ran the
# whole suite unseen, or hung.
#
# Exit 0 when every survivor is known, 1 when one is new (each is printed),
# 2 on a usage error.
set -euo pipefail

baseline=${1:?baseline file}
outdir=${2:?cargo-mutants output directory}
[ -f "$baseline" ] || { echo "no baseline file: $baseline" >&2; exit 2; }

key_of_mutant() {
  # `crates/x.rs:12:5: replace + with - in f` -> `crates/x.rs<TAB>f<TAB>replace + with -`
  sed -E 's/^([^:]+):[0-9]+:[0-9]+: (.*) in (.*)$/\1\t\3\t\2/'
}

survivors=$(cat "$outdir/missed.txt" "$outdir/timeout.txt" 2>/dev/null | grep -v '^$' | key_of_mutant || true)
known=$(grep -v -E '^\s*(#|$)' "$baseline" | cut -f1-3)

new=$(
  awk -F'\t' '
    NR == FNR { allowed[$1 FS $2 FS $3]++; next }
    { key = $1 FS $2 FS $3; seen[key]++; if (seen[key] > allowed[key]) print }
  ' <(printf '%s\n' "$known") <(printf '%s\n' "$survivors" | grep -v '^$' || true)
)

if [ -n "$new" ]; then
  echo "Survivors not in $baseline (a line the tests do not check, or an equivalent to record with its reason):"
  printf '%s\n' "$new" | sed 's/^/  /'
  exit 1
fi
echo "Every survivor in $outdir is in the baseline ($(printf '%s\n' "$survivors" | grep -c . || true) of them)."
