#!/usr/bin/env bash
# check-control-bytes.sh refuses each raw control byte it is meant to and
# passes text (tab, newline, carriage return, escapes).
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
check="$here/check-control-bytes.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
fail=0

mkdir -p "$work/clean/crates/a/src" "$work/clean/rules"
printf 'let a = "\\x08\\t";\r\n\tlet b = 1;\n' > "$work/clean/crates/a/src/lib.rs"
printf 'value: "a\\x00b"\n' > "$work/clean/rules/r.yaml"
if ! bash "$check" "$work/clean" >/dev/null; then
  echo "FAIL: clean text refused"; fail=1
fi

for byte in 00 01 08 0b 0c 0e 1b 1f 7f; do
  dir="$work/b$byte"
  mkdir -p "$dir/crates/a/src"
  printf "let r = \"a\\x$byte\";\n" | sed 's/x/\\x/' > /dev/null
  printf "ok\nr = \"a\x$byte\"\n" > "$dir/crates/a/src/lib.rs"
  out="$(bash "$check" "$dir" 2>&1)"; code=$?
  if [ "$code" -ne 1 ] || ! printf '%s' "$out" | grep -q "lib.rs:2:7: raw control byte 0x$byte"; then
    echo "FAIL: 0x$byte not refused (exit $code): $out"; fail=1
  fi
done

mkdir -p "$work/rulesonly/rules"
printf 'x\x08\n' > "$work/rulesonly/rules/r.yaml"
bash "$check" "$work/rulesonly" >/dev/null 2>&1
[ $? -eq 1 ] || { echo "FAIL: a byte in rules/ not refused"; fail=1; }

mkdir -p "$work/empty"
bash "$check" "$work/empty" >/dev/null 2>&1
[ $? -eq 2 ] || { echo "FAIL: nothing to scan did not exit 2"; fail=1; }

[ "$fail" -eq 0 ] && echo "check-control-bytes self-test: ok"
exit "$fail"
