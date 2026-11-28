#!/usr/bin/env bash
# Mutation test of what a branch changes in the screening engine
# (crates/agent-guard/src), run before its pull request opens. A pull request
# that changes the engine opens only with this green (CONTRIBUTING.md).
#
# usage: scripts/mutants-pre-pr.sh [base]
#   base  what the branch is compared with (default origin/main). The diff is
#         from the merge base to the working tree, so uncommitted edits count.
#
# Exit 0  every mutant of the change was caught, or the change has none.
#      1  a mutant survived or timed out: each is printed. A timeout counts: a
#         mutant that runs out of three times the unmutated test time ran the
#         whole suite unseen, or hung.
#      2  the run could not be made (a tool missing, the unmutated tests fail,
#         the diff does not apply, the memory cap was not on). Nothing was
#         judged, so this is not a pass.
#
# Where it runs:
#   - here, when MUTANTS_HOST is unset. It needs cargo-mutants 25.
#   - on MUTANTS_HOST (an ssh destination) otherwise: the working tree and the
#     diff are copied there with rsync, the run happens there, and the report
#     comes back to target/mutants-pre-pr/.
#   - MUTANTS_VM=<resource group>/<name> (with MUTANTS_HOST): an Azure VM that
#     is kept deallocated. The script starts it, runs, and deallocates it at the
#     end, unless another run or a runner job is still using it then.
#
# Other settings: MUTANTS_JOBS (scripts/mutants-env.sh), MUTANTS_OUT (report
# folder, default target/mutants-pre-pr).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$here"
out=${MUTANTS_OUT:-$here/target/mutants-pre-pr}
mkdir -p "$out"

if [ -z "${MUTANTS_DIFF:-}" ]; then
  base=${1:-origin/main}
  if ! mb=$(git merge-base "$base" HEAD 2>/dev/null); then
    echo "mutants-pre-pr: cannot find the merge base of HEAD and $base" >&2
    exit 2
  fi
  git diff "$mb" -- crates/agent-guard/src/ > "$out/pr.diff"
  if [ ! -s "$out/pr.diff" ]; then
    echo "mutants-pre-pr: the screening engine does not change against $base ($mb); nothing to mutate."
    exit 0
  fi
  MUTANTS_DIFF=$out/pr.diff
  echo "mutants-pre-pr: diff against $base ($mb), $(wc -l < "$MUTANTS_DIFF") lines."
fi

# --- on another machine --------------------------------------------------------
if [ -n "${MUTANTS_HOST:-}" ] && [ -z "${MUTANTS_REMOTE:-}" ]; then
  key="$(id -un)-$(git rev-parse --short HEAD)-$$"
  remote="mutants-pre-pr/$key"
  vm_rg="" vm_name=""
  if [ -n "${MUTANTS_VM:-}" ]; then
    vm_rg=${MUTANTS_VM%%/*} vm_name=${MUTANTS_VM#*/}
    echo "mutants-pre-pr: starting $vm_name"
    az vm start -g "$vm_rg" -n "$vm_name" >/dev/null
    for _ in $(seq 1 40); do
      ssh -o ConnectTimeout=10 -o BatchMode=yes "$MUTANTS_HOST" true </dev/null 2>/dev/null && break
      sleep 10
    done
  fi
  # shellcheck disable=SC2329 # called by the EXIT trap below
  finish() {
    ssh -o ConnectTimeout=20 "$MUTANTS_HOST" "rm -rf ~/'$remote' ~/mutants-pre-pr/.in-use/'$key'" </dev/null || true
    if [ -n "$vm_name" ]; then
      # Another session's run (its marker) or a runner job keeps the VM up;
      # it powers itself off when idle.
      users=$(ssh -o ConnectTimeout=20 "$MUTANTS_HOST" \
        'n=$(ls ~/mutants-pre-pr/.in-use 2>/dev/null | wc -l); pgrep -x Runner.Worker >/dev/null && n=$((n+1)); echo $n' \
        </dev/null 2>/dev/null || echo 0)
      if [ "${users:-0}" -eq 0 ]; then
        echo "mutants-pre-pr: deallocating $vm_name"
        az vm deallocate -g "$vm_rg" -n "$vm_name" --no-wait
      else
        echo "mutants-pre-pr: $vm_name left running: $users other run(s) on it"
      fi
    fi
  }
  trap finish EXIT
  # shellcheck disable=SC2029 # $remote and $key are meant to expand here, on this side
  ssh "$MUTANTS_HOST" "mkdir -p ~/'$remote' ~/mutants-pre-pr/.in-use && touch ~/mutants-pre-pr/.in-use/'$key'" </dev/null
  git ls-files -z -co --exclude-standard | rsync -a --from0 --files-from=- ./ "$MUTANTS_HOST:$remote/"
  rsync -a "$MUTANTS_DIFF" "$MUTANTS_HOST:$remote/pr.diff"
  set +e
  # shellcheck disable=SC2029 # as above
  ssh "$MUTANTS_HOST" "cd ~/'$remote' && MUTANTS_REMOTE=1 MUTANTS_DIFF=pr.diff MUTANTS_OUT=\$HOME/'$remote'/target/mutants-pre-pr \
    ${MUTANTS_JOBS:+MUTANTS_JOBS=$MUTANTS_JOBS} bash scripts/mutants-pre-pr.sh" </dev/null
  code=$?
  set -e
  rsync -a --include='*/' --include='*.txt' --include='*.json' --include='*.log' --exclude='*' \
    "$MUTANTS_HOST:$remote/target/mutants-pre-pr/" "$out/" || true
  exit "$code"
fi

# --- here -----------------------------------------------------------------------
# shellcheck source=scripts/mutants-env.sh
. "$here/scripts/mutants-env.sh" "$out"
if ! cargo mutants --version 2>/dev/null | grep -q '^cargo-mutants 25\.'; then
  echo "mutants-pre-pr: cargo-mutants 25 is not installed (cargo install cargo-mutants --locked --version ^25)" >&2
  exit 2
fi
planned=$(cargo mutants --package innerwarden-agent-guard --in-diff "$MUTANTS_DIFF" --list | wc -l)
echo "mutants-pre-pr: $planned mutants, $MUTANTS_JOBS jobs, ${MUTANTS_ARGS[*]}"
started=$(date +%s)
set +e
cargo mutants --package innerwarden-agent-guard --in-diff "$MUTANTS_DIFF" "${MUTANTS_ARGS[@]}" -o "$out"
code=$?
set -e
report=$out/mutants.out
tested=0
if [ -s "$report/outcomes.json" ]; then
  tested=$(jq '[.outcomes[] | select(.scenario != "Baseline")] | length' "$report/outcomes.json")
  if jq -e '.outcomes | any(.scenario == "Baseline")' "$report/outcomes.json" >/dev/null \
    && [ ! -s "$MUTANTS_TEST_RUNNER_LOG" ]; then
    echo "mutants-pre-pr: the tests ran but no test binary ran under the memory cap: nothing is judged." >&2
    exit 2
  fi
fi
echo "mutants-pre-pr: $tested of $planned mutants tested in $(( $(date +%s) - started )) s."
case "$code" in
  0)
    echo "mutants-pre-pr: no mutant of the change survived."
    exit 0 ;;
  2 | 3)
    echo "mutants-pre-pr: mutants the tests do not catch (kill each with a test; a mutant that is"
    echo "equivalent goes to .cargo/mutants.toml exclude_re with the reason):"
    cat "$report/missed.txt" 2>/dev/null | sed 's/^/  MISSED  /'
    cat "$report/timeout.txt" 2>/dev/null | sed 's/^/  TIMEOUT /'
    exit 1 ;;
  4)
    echo "mutants-pre-pr: the unmutated tests fail ($report/log/baseline.log): fix them first." >&2
    exit 2 ;;
  5 | 6)
    echo "mutants-pre-pr: the diff does not apply to this tree." >&2
    exit 2 ;;
  *)
    echo "mutants-pre-pr: cargo-mutants exited $code." >&2
    exit 2 ;;
esac
