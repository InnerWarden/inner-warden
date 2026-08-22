#!/usr/bin/env bash
# Refuse an em dash (U+2014) on any line this change ADDS.
#
# WHY THIS SHAPE
#
# Ported from the paid repo, which had no guard at all until an em dash reached
# its default branch through a fully green CI. This repo is PUBLIC, so the same
# rule matters more here and had even less enforcing it: 16 files already carry
# the character.
#
# The scope is the DIFF, not the tree, for the same reason it is there: a
# full-text scan would fail on everything that already exists. New lines are
# held to the rule; the existing 16 files are left for a deliberate copy pass
# rather than a mechanical rewrite nobody asked for.
#
# Read the missing-base note below before changing anything: in the paid repo
# that branch exited 0 and the gate was green for its entire life without ever
# making a single comparison.
#
# Usage: no-em-dash-in-new-lines.sh [base-ref]   (default: origin/main)

set -uo pipefail

base="${1:-origin/main}"

# The character is built at runtime so this file cannot trip its own scan.
dash="$(printf '\\u2014' | python3 -c 'import sys; print(sys.stdin.read().strip().encode().decode("unicode_escape"), end="")')"

# A MISSING BASE IS A FAILURE, NOT A SKIP.
#
# This branch used to print "nothing to compare against" and exit 0, and that is
# how this gate spent its entire life green without ever running once. GitHub's
# `actions/checkout` defaults to `fetch-depth: 1`, which fetches the PR merge
# commit and no remote-tracking branches, so `origin/master` does not exist in
# a CI checkout. Every run printed the skip line and passed. Found 2026-08-22
# when an em dash added by PR #316 reached master through a green `validate`
# job; the log for that run reads:
#
#   no-em-dash: base ref 'origin/master' not found; nothing to compare against.
#
# So: try to fetch the base, and if that cannot be done, REFUSE. A gate that
# reports success on a comparison it did not make is worse than no gate,
# because the green check is read as evidence.
if ! git rev-parse --verify "${base}" >/dev/null 2>&1; then
  # `origin/master` -> `master`. Shallow, no tags: the diff needs the base
  # commit, not its history.
  remote_branch="${base#origin/}"
  echo "no-em-dash: '${base}' not present (shallow checkout?), fetching it..." >&2
  if git fetch --no-tags --depth=1 origin "${remote_branch}" >/dev/null 2>&1; then
    base="FETCH_HEAD"
  fi
fi

if ! git rev-parse --verify "${base}" >/dev/null 2>&1; then
  {
    echo "REFUSED: cannot establish a base to diff against ('${base}')."
    echo
    echo "This gate compares the lines your change ADDS, so without a base there"
    echo "is nothing to compare and no answer to give. It fails rather than"
    echo "passing: reporting clean on a comparison that did not happen is how"
    echo "this check previously stayed green for its whole life."
    echo
    echo "In CI: the checkout is shallow and the fetch above did not work."
    echo "Locally: run 'git fetch origin' first, or pass an explicit base ref."
  } >&2
  exit 1
fi

# `-U0` so only changed lines appear, and `^+` minus `^+++` is exactly the set
# of added lines. A line that merely MOVED still counts as added, which is
# correct: if it is being rewritten, it can be rewritten without the character.
#
# Two dots against the WORKING TREE, not `base...HEAD`. Three-dot-HEAD compares
# committed history only, so it silently misses staged and unstaged work: my
# first version used it, I fed it a deliberate em dash to check, and it
# reported clean. A guard that cannot see uncommitted work is useless as a
# local pre-push check and fires only after the fact.
added="$(git diff -U0 "${base}" -- '*.rs' '*.sh' '*.ts' '*.tsx' '*.md' '*.toml' \
  | grep -E '^\+' | grep -v '^+++' || true)"

offenders="$(printf '%s\n' "${added}" | grep -F "${dash}" || true)"

if [ -z "${offenders}" ]; then
  echo "no-em-dash: no em dash in the lines this change adds."
  exit 0
fi

{
  echo "REFUSED: this change adds em dashes (U+2014)."
  echo
  echo "The house rule bans the character. These are lines YOU are adding, so"
  echo "they can be written without it; a colon, a comma or a full stop almost"
  echo "always reads better anyway."
  echo
  printf '%s\n' "${offenders}" | head -20 | sed 's/^/    /'
  echo
  echo "Only added lines are checked. Existing ones are not your problem here."
} >&2
exit 1
