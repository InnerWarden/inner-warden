#!/usr/bin/env bash
# check-guard-lowering.sh: drive the installed PreToolUse hook with the
# guard-lowering corpus and assert the verdict of every line.
#
# This is the host proof of what tests/guard_lowering_corpus.rs proves in the
# unit suite: an AI agent cannot lower its own guard, in any name, wrapper or
# command string the corpus holds. It runs the REAL hook (`innerwarden hook`),
# the same program the agent's PreToolUse calls, under an agent shell's
# environment, so it is what an agent would meet. No VM, no server: the hook
# runs in process.
#
# Every release from Active Defence 0.17.4 to 0.17.8 was cut by a spelling of
# this class found by hand on a VM. This replaces that by hand step.
#
# Usage:
#   scripts/check-guard-lowering.sh [innerwarden-binary] [corpus-file]
#
# Defaults: the `innerwarden` on PATH, and the committed corpus beside this
# repository. Exit 0 when every line matched, 1 on any mismatch, 2 on a setup
# error. A DENY line must give exit 2 from the hook (blocks the tool call); an
# ALLOW line must give exit 0.
set -uo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
bin="${1:-$(command -v innerwarden || true)}"
corpus="${2:-$here/crates/agent-guard/tests/data/guard-lowering-corpus.txt}"

if [ -z "$bin" ] || ! command -v "$bin" >/dev/null 2>&1; then
    echo "check-guard-lowering: no innerwarden binary (pass its path)" >&2
    exit 2
fi
if [ ! -r "$corpus" ]; then
    echo "check-guard-lowering: no corpus at $corpus" >&2
    exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "check-guard-lowering: python3 is needed to build the hook payloads" >&2
    exit 2
fi

# The agent shell the hook expects: Claude Code sets these, and the CLI's own
# refusal keys off them. The hook screens the tool call regardless, so a deny
# does not depend on them, but running as the agent does keeps the proof honest.
export CLAUDECODE=1
export CLAUDE_CODE_ENTRYPOINT=cli

payload() {
    python3 -c 'import json,sys; print(json.dumps({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":sys.argv[1]},"session_id":"guard-lowering-selftest"}))' "$1"
}

pass=0
fail=0
while IFS=$'\t' read -r verdict command; do
    case "$verdict" in
        DENY) want=2 ;;
        ALLOW) want=0 ;;
        *) continue ;;
    esac
    payload "$command" | "$bin" hook >/dev/null 2>&1
    got=$?
    if [ "$got" = "$want" ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
        printf 'MISMATCH want=%s got=%s [%s] %s\n' "$want" "$got" "$verdict" "$command"
    fi
done < "$corpus"

printf 'check-guard-lowering: %d matched, %d mismatched (%s)\n' "$pass" "$fail" "$("$bin" --version 2>/dev/null || echo "unknown version")"
[ "$fail" -eq 0 ]
