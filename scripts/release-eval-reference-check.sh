#!/usr/bin/env bash
# The release safety suite's reference changes only with a reason.
#
# crates/agent-guard/corpus/reference.tsv holds the verdict of every case in the
# release safety suite at the last accepted state, and the suite fails when the
# guard does worse than it. Rewriting the reference is how a loosening would be
# made to pass, so a change that touches it must also add a line to
# crates/agent-guard/corpus/REFERENCE-CHANGES.md saying which cases moved and
# why. The same holds for the corpora: a case taken out leaves the reference too.
#
# A missing base is a failure, not a skip, as in no-em-dash-in-new-lines.sh.
#
# Usage: release-eval-reference-check.sh [base-ref]   (default: origin/main)

set -uo pipefail

base="${1:-origin/main}"
reference="crates/agent-guard/corpus/reference.tsv"
reasons="crates/agent-guard/corpus/REFERENCE-CHANGES.md"

if ! git rev-parse --verify "${base}" >/dev/null 2>&1; then
  remote_branch="${base#origin/}"
  echo "reference-check: '${base}' not present (shallow checkout?), fetching it..." >&2
  if git fetch --no-tags --depth=1 origin "${remote_branch}" >/dev/null 2>&1; then
    base="FETCH_HEAD"
  fi
fi
if ! git rev-parse --verify "${base}" >/dev/null 2>&1; then
  echo "REFUSED: cannot establish a base to compare the reference against ('${base}')."
  exit 1
fi

# The base may not hold the reference yet (the change that adds it).
if ! git cat-file -e "${base}:${reference}" 2>/dev/null; then
  echo "reference-check: the base has no reference yet; nothing to compare."
  exit 0
fi

if git diff --quiet "${base}" HEAD -- "${reference}"; then
  echo "reference-check: the reference is unchanged."
  exit 0
fi

added_reasons="$(git diff "${base}" HEAD -- "${reasons}" | grep -c '^+[^+]' || true)"
if [ "${added_reasons}" -eq 0 ]; then
  echo "REFUSED: ${reference} changed and ${reasons} gained no line."
  echo
  echo "The reference is what the release safety suite holds the guard to."
  echo "Add a dated line to ${reasons} naming the cases whose verdict moved"
  echo "and why, so the change is read as a decision and not as a test edited"
  echo "to stay green."
  echo
  git diff --stat "${base}" HEAD -- "${reference}"
  exit 1
fi

echo "reference-check: the reference changed, with a reason:"
git diff "${base}" HEAD -- "${reasons}" | grep '^+[^+]' | sed 's/^+/  /'
