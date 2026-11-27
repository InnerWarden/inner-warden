#!/usr/bin/env bash
# Sum of the nightly diff mutation shards, for the run's summary page.
#
# usage: mutants-diff-summary.sh <folder of downloaded reports> <mutants in the diff> <shards>
#
# Each shard uploads mutants.out as mutants-report-diff-shard-<k>. This says how
# many of the diff's mutants were tested tonight across all shards, how many
# survived or timed out, and which shards left no report. It warns whenever
# fewer were tested than the diff holds; it never fails on its own: each shard
# fails its own job for what it found.
set -euo pipefail

reports=$1
total=$2
shards=$3

tested=0 missed=0 timeouts=0 caught=0 unviable=0 absent=()
for k in $(seq 0 $((shards - 1))); do
  f="$reports/mutants-report-diff-shard-$k/outcomes.json"
  if [ ! -s "$f" ]; then
    absent+=("$k")
    continue
  fi
  tested=$((tested + $(jq '[.outcomes[] | select(.scenario != "Baseline")] | length' "$f")))
  missed=$((missed + $(jq '[.outcomes[] | select(.summary == "MissedMutant")] | length' "$f")))
  timeouts=$((timeouts + $(jq '[.outcomes[] | select(.summary == "Timeout")] | length' "$f")))
  caught=$((caught + $(jq '[.outcomes[] | select(.summary == "CaughtMutant")] | length' "$f")))
  unviable=$((unviable + $(jq '[.outcomes[] | select(.summary == "Unviable")] | length' "$f")))
done

line="Mutants of the last day's diff: tested $tested of $total in $shards shards ($caught caught, $missed survived, $timeouts timed out, $unviable unviable)."
echo "$line"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### cargo-mutants on the last day's diff"
    echo
    echo "$line"
    if [ "${#absent[@]}" -gt 0 ]; then
      echo
      echo "No report from shard(s): ${absent[*]}."
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi
if [ "${#absent[@]}" -gt 0 ]; then
  echo "::warning::No report from shard(s) ${absent[*]}: their mutants are not counted as tested."
fi
if [ "$tested" -lt "$total" ]; then
  echo "::warning::Tested $tested of $total mutants of the last day's diff; the rest were not tested tonight (see each shard's summary for why)."
fi
