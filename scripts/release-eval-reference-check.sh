#!/usr/bin/env bash
# The release safety suite's reference changes only with a reason.
#
# crates/agent-guard/corpus/reference.tsv holds the verdict of every case in the
# release safety suite at the last accepted state, and the suite fails when the
# guard does worse than it. Rewriting the reference is how a loosening would be
# made to pass, so a change that touches it must also add a dated line to
# crates/agent-guard/corpus/REFERENCE-CHANGES.md that names every case whose
# line moved, and why. The same holds for the corpora: a case taken out
# leaves the reference too.
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

# Every case whose line moved in the reference must be named in a dated line
# added to the reasons: `- YYYY-MM-DD: ...` with the line indented under it.
# A case is named as `corpus/id` or `id`; a run of one corpus may be written
# `a11-001..a11-040`.
git diff -U0 "${base}" HEAD -- "${reference}" | grep -E '^[-+][^-+#]' | cut -c2- | cut -f1,2 | sort -u > "${TMPDIR:-/tmp}/ref-moved.$$"
git diff -U0 "${base}" HEAD -- "${reasons}" | grep -E '^\+[^+]' | cut -c2- > "${TMPDIR:-/tmp}/ref-reasons.$$"
python3 -I -c '
import re, sys
moved = [l.rstrip("\n").split("\t") for l in open(sys.argv[1]) if l.strip()]
added = open(sys.argv[2]).read()
dated = re.findall(r"(?m)^- \d{4}-\d{2}-\d{2}: .*(?:\n[ \t]+\S.*)*", added)
if not dated:
    print("REFUSED: %s changed and %s gained no dated line (- YYYY-MM-DD: ...)." % (sys.argv[3], sys.argv[4]))
    sys.exit(1)
text = "\n".join(dated)
named = set()
for a, b in re.findall(r"([A-Za-z0-9]+-\d+)\.\.([A-Za-z0-9]+-\d+)", text):
    pa, na = a.rsplit("-", 1); pb, nb = b.rsplit("-", 1)
    if pa == pb and int(na) <= int(nb):
        for n in range(int(na), int(nb) + 1):
            named.add("%s-%0*d" % (pa, len(na), n))
for w in re.findall(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?", text):
    named.add(w.split("/")[-1])
    named.add(w)
missing = [c + "/" + i for c, i in moved if i not in named and (c + "/" + i) not in named]
if missing:
    print("REFUSED: %d case(s) moved in %s and no dated line in %s names them:" % (len(missing), sys.argv[3], sys.argv[4]))
    for m in missing[:50]:
        print("  " + m)
    if len(missing) > 50:
        print("  ... and %d more" % (len(missing) - 50))
    print()
    print("Name each moved case (corpus/id, or a run a11-001..a11-040) and why its")
    print("new verdict is right, so the change is read as a decision and not as a")
    print("test edited to stay green.")
    sys.exit(1)
print("reference-check: %d moved case(s), each named in a dated reason:" % len(moved))
for d in dated:
    print("  " + d.splitlines()[0])
' "${TMPDIR:-/tmp}/ref-moved.$$" "${TMPDIR:-/tmp}/ref-reasons.$$" "${reference}" "${reasons}"
status=$?
rm -f "${TMPDIR:-/tmp}/ref-moved.$$" "${TMPDIR:-/tmp}/ref-reasons.$$"
exit "${status}"
