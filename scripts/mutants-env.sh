# shellcheck shell=bash
# Environment of every cargo-mutants run of the screening engine: the nightly
# run on the day's changes, the Sunday sweep (nightly-deep.yml) and the run
# before a pull request (scripts/mutants-pre-pr.sh). One file, so the three
# test the same mutants the same way and a survivor in one is a survivor in
# the others.
#
# usage: . scripts/mutants-env.sh <report folder>
#
# Sets:
#   - the memory cap on every test binary (scripts/mutants-test-runner.sh as
#     cargo's target runner), and its log in <report folder>/test-runner.log,
#     which the callers read to prove the cap was on;
#   - IW_NO_WALL_CLOCK_CEILINGS=1: a test with a time ceiling would "catch" a
#     mutant only because the machine was busy (nightly-deep.yml says what two
#     sweeps of the same mutants measured);
#   - TMPDIR outside the tree: cargo-mutants copies the tree there and tests
#     there, and a test that searches upward from where it runs must not find
#     the real tree or its own home above the copy (nightly-deep.yml,
#     TEMPORARY FOLDER);
#   - MUTANTS_JOBS: one job per four processors unless set; each job builds and
#     tests one mutant in its own copy of the tree;
#   - the speed tools this machine has. They change how fast a mutant is
#     built, never which mutants live: mold links the 135 test binaries each
#     mutant needs, and sccache keeps the dependencies every job's copy of the
#     tree builds once. Each is used only when it is installed and the caller
#     did not set RUSTC_WRAPPER or RUSTFLAGS. cargo-nextest is NOT used unless
#     MUTANTS_TEST_TOOL=nextest: it runs each test in its own process, and on
#     the same 33 mutants (2026-11-28) it caught one that `cargo test` lets
#     live, so a run with it would not judge what the nightly judges.
#   - MUTANTS_ARGS: the arguments every run passes to cargo mutants.

mutants_out=${1:?usage: . scripts/mutants-env.sh <report folder>}
mkdir -p "$mutants_out"
mutants_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if ! command -v cargo >/dev/null 2>&1 && [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  . "$HOME/.cargo/env"
fi
mutants_triple=$(rustc -vV | sed -n 's/^host: //p')
mutants_triple_env=$(printf '%s' "$mutants_triple" | tr 'a-z-' 'A-Z_')

export "CARGO_TARGET_${mutants_triple_env}_RUNNER=$mutants_root/scripts/mutants-test-runner.sh"
export MUTANTS_TEST_RUNNER_LOG="$mutants_out/test-runner.log"
: > "$MUTANTS_TEST_RUNNER_LOG"
export IW_NO_WALL_CLOCK_CEILINGS=1

# sccache keeps a server that outlives this run: start it with a temporary
# folder that also outlives it, or the next run finds a server whose folder is
# gone and every compile fails.
if [ -z "${RUSTC_WRAPPER:-}" ] && command -v sccache >/dev/null 2>&1; then
  mkdir -p "$HOME/.cache/sccache-tmp"
  TMPDIR="$HOME/.cache/sccache-tmp" sccache --start-server >/dev/null 2>&1 || true
  if sccache --show-stats >/dev/null 2>&1; then
    export RUSTC_WRAPPER=sccache
  fi
fi
if [ -z "${RUSTFLAGS:-}" ] && command -v mold >/dev/null 2>&1 && [ "$(uname -s)" = Linux ]; then
  export "CARGO_TARGET_${mutants_triple_env}_RUSTFLAGS=-C link-arg=-fuse-ld=mold"
fi

export TMPDIR="${MUTANTS_TMPDIR:-${RUNNER_TEMP:-$HOME/.cache/iw-mutants}/tmp}"
mkdir -p "$TMPDIR"

if [ -z "${MUTANTS_JOBS:-}" ]; then
  mutants_cpus=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
  MUTANTS_JOBS=$((mutants_cpus / 4))
  [ "$MUTANTS_JOBS" -ge 1 ] || MUTANTS_JOBS=1
fi
export MUTANTS_JOBS

MUTANTS_ARGS=(--timeout-multiplier 3 -j "$MUTANTS_JOBS")
if [ "${MUTANTS_TEST_TOOL:-cargo}" = nextest ]; then
  MUTANTS_ARGS+=(--test-tool nextest)
fi
