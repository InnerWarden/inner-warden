#!/usr/bin/env bash
# Verdict of one shard of the nightly diff mutation run
# (.github/workflows/nightly-deep.yml, job mutants-diff).
#
# usage: mutants-diff-verdict.sh <cargo-mutants exit> <mutants.out> <mutants in shard> <label>
#
# Exit 0 when the shard passes or ran out of time with nothing found in what it
# tested (a warning says how much it tested), 1 otherwise. The verdicts:
#   0          clean
#   2          a mutant survived                          -> fails
#   3          a mutant timed out (a hang)                -> fails
#   5|6        the diff does not apply to this tree       -> fails
#   124|137    the shard budget ran out (`timeout`): what was tested decides.
#              A survivor or a hang among it fails as 2 or 3 would; otherwise
#              the shard passes with a warning "tested X of Y". The budget is
#              a property of the runner, not of the code, so it never turns
#              the run red; but a partial run is never reported as a clean one.
#   anything else is an error of cargo-mutants           -> fails
# When GITHUB_STEP_SUMMARY is set, one line is added to the job summary.
set -euo pipefail

code=$1
out=$2
planned=$3
label=$4

tested=0 missed=0 timeouts=0 baseline=no
if [ -s "$out/outcomes.json" ]; then
  # Every outcome but the baseline is a mutant tested.
  tested=$(jq '[.outcomes[] | select(.scenario != "Baseline")] | length' "$out/outcomes.json")
  missed=$(jq '[.outcomes[] | select(.summary == "MissedMutant")] | length' "$out/outcomes.json")
  timeouts=$(jq '[.outcomes[] | select(.summary == "Timeout")] | length' "$out/outcomes.json")
  if jq -e '.outcomes | any(.scenario == "Baseline")' "$out/outcomes.json" >/dev/null; then
    baseline=yes
  fi
fi

summary() {
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "- $label: $1" >> "$GITHUB_STEP_SUMMARY"
  fi
  echo "$label: $1"
}

case "$code" in
  0)
    echo "No surviving mutants in the changed lines."
    summary "tested $tested of $planned, no survivor"
    exit 0 ;;
  2)
    echo "::error::A mutant survived in code changed since yesterday: the tests do not check that line. See the uploaded report."
    summary "tested $tested of $planned, $missed survived"
    exit 1 ;;
  3)
    echo "::error::cargo-mutants hit its own per-mutant timeout; the sweep is incomplete."
    summary "tested $tested of $planned, $timeouts timed out"
    exit 1 ;;
  5|6)
    echo "::error::The diff no longer applies to this tree (rebase or force-push). Not a test failure, but this check did NOT run."
    summary "did not run: the diff does not apply"
    exit 1 ;;
  124|137)
    if [ "$missed" -gt 0 ]; then
      echo "::error::A mutant survived in code changed since yesterday: the tests do not check that line. See the uploaded report. (The shard budget also ran out: tested $tested of $planned.)"
      summary "tested $tested of $planned before the budget ran out, $missed survived"
      exit 1
    fi
    if [ "$timeouts" -gt 0 ]; then
      echo "::error::cargo-mutants hit its own per-mutant timeout; the sweep is incomplete. (The shard budget also ran out: tested $tested of $planned.)"
      summary "tested $tested of $planned before the budget ran out, $timeouts timed out"
      exit 1
    fi
    if [ "$baseline" = no ]; then
      echo "::warning::$label: the budget ran out before the unmutated baseline finished: tested 0 of $planned mutants. Nothing was checked."
      summary "tested 0 of $planned: the budget ran out before the baseline finished"
      exit 0
    fi
    echo "::warning::$label: tested $tested of $planned mutants before the budget ran out; none of them survived. The other $((planned - tested)) were not tested tonight."
    summary "tested $tested of $planned before the budget ran out, no survivor among them"
    exit 0 ;;
  *)
    echo "::error::cargo-mutants exited $code."
    summary "cargo-mutants exited $code (tested $tested of $planned)"
    exit 1 ;;
esac
