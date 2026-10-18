#!/usr/bin/env bash
# Run `cargo test` with a name filter, and fail unless at least MIN tests
# passed.
#
# WHY THIS EXISTS
#
# libtest exits 0 when a name filter matches no test: it prints
# "0 passed; ... N filtered out" and the step is green. A CI step that picks
# its tests by name (`--lib seccomp`, `--bin innerwarden the_launcher_...`)
# then checks nothing the day a test is renamed or its module moves, and no
# one sees it. That happened once already: moving the sandbox filter's module
# left the arm64 job's old filter matching zero tests, and only a hand edit
# kept the job alive. A gate that cannot run must fail, so this one counts.
#
# Usage: cargo-test-at-least.sh MIN [cargo test arguments...]
#   MIN  the fewest tests that must pass, a whole number of at least 1. Set
#        it to what the filter runs today: a test that goes away fails the
#        step until MIN is lowered on purpose.

set -uo pipefail

min="${1:-}"
case "$min" in
  '' | *[!0-9]*)
    echo "REFUSED: MIN must be a whole number, got '${min}'." >&2
    echo "Usage: cargo-test-at-least.sh MIN [cargo test arguments...]" >&2
    exit 2
    ;;
esac
if [ "$min" -lt 1 ]; then
  echo "REFUSED: MIN is ${min}. A step that may run no test checks nothing." >&2
  exit 2
fi
shift

out="$(mktemp)"
trap 'rm -f "$out"' EXIT

cargo test "$@" </dev/null 2>&1 | tee "$out"
status="${PIPESTATUS[0]}"
if [ "$status" -ne 0 ]; then
  exit "$status"
fi

# One "test result" line per test binary the command ran.
passed="$(sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed;.*/\1/p' "$out" |
  awk '{ total += $1 } END { print total + 0 }')"

if [ "$passed" -lt "$min" ]; then
  {
    echo "REFUSED: cargo test $* passed ${passed} test(s); at least ${min} must run."
    echo
    echo "A name filter that matches fewer tests than it did is a step that"
    echo "stopped checking what it was written for: a test was renamed, or its"
    echo "module moved. Point the filter at the tests again. Lower MIN only when"
    echo "a test was removed on purpose."
  } >&2
  exit 1
fi
echo "cargo-test-at-least: ${passed} test(s) passed (at least ${min})."
