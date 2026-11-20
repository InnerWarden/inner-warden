#!/usr/bin/env bash
# Refuse a raw control byte in the code and the rules.
#
# WHY
#
# A raw control byte in source is invisible in review and in most diffs: two
# backspace bytes (0x08) sat inside a regex in this repo, where they changed
# what the pattern matched and nobody could see them. Escapes (\x08, \t) are
# fine; the raw byte is not.
#
# Refused: 0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F and 0x7F. Tab (0x09), newline
# (0x0A) and carriage return (0x0D) are text.
#
# Scope: every file under crates/*/src and rules/ (the whole tree, not the
# diff: there is none today, and none may come in).
#
# Usage: check-control-bytes.sh [root]   (default: the repo root)
# Exit: 0 clean, 1 a byte found (each one printed as file:line:column and its
# hex), 2 nothing to scan.

set -uo pipefail

root="${1:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$root" || exit 2

shopt -s nullglob
places=(crates/*/src rules)
existing=()
for place in "${places[@]}"; do
  [ -d "$place" ] && existing+=("$place")
done
if [ "${#existing[@]}" -eq 0 ]; then
  echo "control-bytes: nothing to scan under $root (no crates/*/src, no rules/)" >&2
  exit 2
fi

python3 -I -c '
import os, sys
bad = set(range(0x00, 0x09)) | {0x0B, 0x0C} | set(range(0x0E, 0x20)) | {0x7F}
found = 0
scanned = 0
for top in sys.argv[1:]:
    for folder, dirs, files in os.walk(top):
        dirs.sort()
        for name in sorted(files):
            path = os.path.join(folder, name)
            if os.path.islink(path):
                continue
            with open(path, "rb") as f:
                data = f.read()
            scanned += 1
            line, col = 1, 1
            for byte in data:
                if byte in bad:
                    print("%s:%d:%d: raw control byte 0x%02x" % (path, line, col, byte))
                    found += 1
                if byte == 0x0A:
                    line, col = line + 1, 1
                else:
                    col += 1
if scanned == 0:
    print("control-bytes: no file to scan", file=sys.stderr)
    sys.exit(2)
if found:
    print("control-bytes: %d raw control byte(s); write it as an escape (\\x08) instead" % found, file=sys.stderr)
    sys.exit(1)
print("control-bytes: %d files clean" % scanned)
' "${existing[@]}"
