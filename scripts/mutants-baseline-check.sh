#!/usr/bin/env bash
# Fail on a mutant that survives and is not in the baseline.
#
# usage: mutants-baseline-check.sh BASELINE OUTDIR
#        mutants-baseline-check.sh --keys OUTDIR
#   BASELINE  crates/agent-guard/mutants-baseline.txt: one known survivor per
#             line, `file<TAB>function<TAB>mutation<TAB>why`. `why` says
#             either that the mutant is equivalent (no test can see it, and
#             why) or that it is not killed yet (found on a date, to burn
#             down). Lines starting with `#` are comments.
#   OUTDIR    a cargo-mutants output directory (holding missed.txt and
#             timeout.txt).
#   --keys    print the key of every survivor in OUTDIR followed by a tab and
#             `missed` or `timeout`, the form the baseline is generated from,
#             so the list and the check can never key a mutant differently.
#
# A survivor is keyed without its line and column, so an edit above it does
# not turn it into a new one. A mutant inside a function is named
# `file:line:col: <mutation> in <function>`; one that replaces the whole
# function is named `file:line:col: replace <function> -> <type> with <value>`
# (or `replace <function> with ()`), with no `in`, and keeps the whole text as
# its mutation. The same mutation can appear more than once in one function;
# each key is counted, and the run may not hold more of a key than the
# baseline does. A timeout counts as a survivor: with the timeout relative to
# the baseline test time, a mutant that runs out of it ran the whole suite
# unseen, or hung.
#
# Exit 0 when every survivor is known, 1 when one is new (each is printed),
# 2 on a usage error or when OUTDIR holds no report to check.
set -euo pipefail

key_of_mutant() {
  awk '
    match($0, /^[^:]+:[0-9]+:[0-9]+: /) {
      file = substr($0, 1, RLENGTH - 2)
      sub(/:[0-9]+:[0-9]+$/, "", file)
      rest = substr($0, RLENGTH + 1)
      # The last " in " ends the mutation and starts the function.
      at = 0
      for (i = index(rest, " in "); i > 0; i = index(substr(rest, at + 1), " in ")) at += i
      if (at > 0) { print file "\t" substr(rest, at + 4) "\t" substr(rest, 1, at - 1); next }
      fn = rest
      sub(/^replace /, "", fn)
      arrow = index(fn, " -> "); with = index(fn, " with ")
      cut = (arrow > 0 && (with == 0 || arrow < with)) ? arrow : with
      if (cut > 0) fn = substr(fn, 1, cut - 1)
      print file "\t" fn "\t" rest
      next
    }
    # Unparseable: kept whole, so it can only ever match itself.
    { print "?\t?\t" $0 }
  '
}

survivor_keys() {
  local outdir=$1 kind
  for kind in missed timeout; do
    if [ -f "$outdir/$kind.txt" ]; then
      grep -v '^$' "$outdir/$kind.txt" | key_of_mutant | sed "s/\$/	$kind/" || true
    fi
  done
}

if [ "${1:-}" = "--keys" ]; then
  outdir=${2:?cargo-mutants output directory}
  survivor_keys "$outdir"
  exit 0
fi

baseline=${1:?baseline file}
outdir=${2:?cargo-mutants output directory}
[ -f "$baseline" ] || { echo "no baseline file: $baseline" >&2; exit 2; }
# A sweep that left no report has not been checked: that is not "no survivor".
[ -f "$outdir/missed.txt" ] || [ -f "$outdir/timeout.txt" ] || {
  echo "no missed.txt and no timeout.txt in $outdir: the sweep left no report to check" >&2
  exit 2
}

survivors=$(survivor_keys "$outdir" | cut -f1-3)
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
