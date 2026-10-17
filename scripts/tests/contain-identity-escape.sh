#!/usr/bin/env bash
# contain-identity-escape.sh: prove an identified jail keeps its agent in.
#
# Runs `innerwarden contain --identity` with a probe as the jailed command.
# From inside the jail the probe tries to leave the instance's scope the three
# ways a process of the same user normally can:
#
#   a) systemd-run --user true     start a unit outside the scope (user manager)
#   b) busctl --user list          reach the user's bus at all
#   c) echo $$ > .../cgroup.procs  move itself into another cgroup (and mkdir one)
#
# and it reads the record the launcher mounted at /run/innerwarden/instance.json.
#
# The run FAILS (exit 1) when any of a, b or c works, when the jail's cgroup
# changed, when the record is missing, writable from inside, or not the
# launcher's own copy, when the PID or mount namespace inside is not the one
# the record names, when the launcher's records folder is visible inside, when
# the hook is not told the agent, when the agent's command line or the jail's environment did not reach
# the jail as the launcher set them, or when the instance has no user scope
# (set IW_ESCAPE_ALLOW_NO_SCOPE=1 on a host with no user service manager, where
# that is the expected fallback).
# d) /run inside, f) abstract sockets visible inside and g) whether the jail
# can make a user namespace of its own are printed, not judged.
#
# Usage:
#   scripts/tests/contain-identity-escape.sh [path/to/innerwarden]
#
# Run it as an ordinary user in a login session (an ssh session keeps the
# user's manager alive), never as root. It starts no service, arms nothing and
# changes nothing outside a temporary project under $HOME, which it removes.
# The launcher's own copy of the record stays in the state home; its path is
# printed.

set -uo pipefail

iw="${1:-$(command -v innerwarden || true)}"
if [ -z "$iw" ] || [ ! -x "$iw" ]; then
    echo "contain-identity-escape: no innerwarden binary (pass its path)" >&2
    exit 2
fi
if [ "$(id -u)" = "0" ]; then
    echo "contain-identity-escape: run as an ordinary user, not root" >&2
    exit 2
fi

work="$(mktemp -d "$HOME/iw-escape.XXXXXX")" || exit 2
trap 'rm -rf "$work"' EXIT
project="$work/proj"
mkdir -p "$project"

# The probe runs INSIDE the jail, under /bin/sh. One key=value per line.
cat >"$project/probe.sh" <<'PROBE'
rec=/run/innerwarden/instance.json
echo "ns=$(readlink /proc/self/ns/pid)"
echo "mnt=$(readlink /proc/self/ns/mnt)"
echo "hook_agent=${IW_HOOK_AGENT:-}"
state="${XDG_STATE_HOME:-}"
case "$state" in /*) ;; *) state="$HOME/.local/state" ;; esac
echo "records_seen=$(ls -A "$state/innerwarden/instances" 2>/dev/null | wc -l | tr -d ' ')"
if unshare -Urm true >/dev/null 2>&1; then echo "g_nested_userns=1"; else echo "g_nested_userns=0"; fi
before=$(sed -n 's/^0:://p' /proc/self/cgroup)
echo "cgroup_before=$before"
if [ -r "$rec" ]; then echo "record=$(cat "$rec")"; else echo "record="; fi

systemd-run --user --quiet true >/dev/null 2>&1
echo "a_systemd_run_rc=$?"
busctl --user list >/dev/null 2>&1
echo "b_busctl_rc=$?"

moved=0
for target in "/sys/fs/cgroup$before/../cgroup.procs" \
              "/sys/fs/cgroup$before/cgroup.procs" \
              "/sys/fs/cgroup/cgroup.procs"; do
    if ( echo $$ >"$target" ) 2>/dev/null; then moved=1; echo "c_wrote=$target"; fi
done
if mkdir "/sys/fs/cgroup$before/iw-escape" 2>/dev/null; then
    moved=1; echo "c_mkdir=/sys/fs/cgroup$before/iw-escape"
fi
echo "c_moved=$moved"
echo "cgroup_after=$(sed -n 's/^0:://p' /proc/self/cgroup)"

if ( : >"$rec" ) 2>/dev/null; then echo "record_writable=1"; else echo "record_writable=0"; fi
echo "argv_literal=$1"
echo "env_graph=${IW_GRAPH_FILE:-}"
echo "d_run_entries=$(ls -A /run | tr '\n' ' ')"
echo "f_abstract_sockets=$(grep -c ' @' /proc/net/unix 2>/dev/null || echo 0)"
PROBE

out="$work/out"
err="$work/err"
# The probe's argument is a literal `$NAME` with NAME set: a scope wrapper that
# rewrote `$NAME` in the agent's command line would hand the jail "expanded".
# shellcheck disable=SC2016
literal='$IW_ESCAPE_LITERAL'
IW_ESCAPE_LITERAL=expanded \
    "$iw" contain --identity --project "$project" -- /bin/sh "$project/probe.sh" "$literal" \
    >"$out" 2>"$err"
rc=$?

value() { sed -n "s/^$1=//p" "$out" | head -n 1; }

fails=0
check() { # check <name> <ok:0|1> <detail>
    if [ "$2" = "0" ]; then
        printf 'PASS  %-34s %s\n' "$1" "$3"
    else
        printf 'FAIL  %-34s %s\n' "$1" "$3"
        fails=$((fails + 1))
    fi
}

echo "== innerwarden contain --identity (exit $rc) =="
sed 's/^/  | /' "$err"
echo

check "jail ran" "$([ "$rc" = "0" ] && echo 0 || echo 1)" "exit $rc"

record="$(value record)"
check "record present inside" "$([ -n "$record" ] && echo 0 || echo 1)" "/run/innerwarden/instance.json"

a="$(value a_systemd_run_rc)"
check "a) systemd-run --user refused" "$([ -n "$a" ] && [ "$a" != "0" ] && echo 0 || echo 1)" "rc=${a:-none}"
b="$(value b_busctl_rc)"
check "b) busctl --user refused" "$([ -n "$b" ] && [ "$b" != "0" ] && echo 0 || echo 1)" "rc=${b:-none}"
c="$(value c_moved)"
check "c) cgroup.procs not writable" "$([ "$c" = "0" ] && echo 0 || echo 1)" "$(value c_wrote)$(value c_mkdir)"

before="$(value cgroup_before)"
after="$(value cgroup_after)"
check "cgroup unchanged" "$([ -n "$before" ] && [ "$before" = "$after" ] && echo 0 || echo 1)" "$before"

ns="$(value ns | sed -n 's/^pid:\[\([0-9]*\)\]$/\1/p')"
recorded_ns="$(printf '%s' "$record" | sed -n 's/.*"pid_ns":\([0-9]*\).*/\1/p')"
check "pid_ns inside = record" "$([ -n "$ns" ] && [ "$ns" = "$recorded_ns" ] && echo 0 || echo 1)" "inside ${ns:-none}, record ${recorded_ns:-none}"
host_ns="$(readlink /proc/self/ns/pid | sed -n 's/^pid:\[\([0-9]*\)\]$/\1/p')"
check "pid_ns inside != host" "$([ -n "$ns" ] && [ "$ns" != "$host_ns" ] && echo 0 || echo 1)" "host $host_ns"
mnt="$(value mnt | sed -n 's/^mnt:\[\([0-9]*\)\]$/\1/p')"
recorded_mnt="$(printf '%s' "$record" | sed -n 's/.*"mnt_ns":\([0-9]*\).*/\1/p')"
check "mnt_ns inside = record" "$([ -n "$mnt" ] && [ "$mnt" = "$recorded_mnt" ] && echo 0 || echo 1)" "inside ${mnt:-none}, record ${recorded_mnt:-none}"
host_mnt="$(readlink /proc/self/ns/mnt | sed -n 's/^mnt:\[\([0-9]*\)\]$/\1/p')"
check "mnt_ns inside != host" "$([ -n "$mnt" ] && [ "$mnt" != "$host_mnt" ] && echo 0 || echo 1)" "host $host_mnt"
seen_records="$(value records_seen)"
check "launcher records hidden inside" "$([ "$seen_records" = "0" ] && echo 0 || echo 1)" "entries=${seen_records:-none}"
hook_agent="$(value hook_agent)"
check "hook told the agent" "$([ "$hook_agent" = "claude-code" ] && echo 0 || echo 1)" "IW_HOOK_AGENT=${hook_agent:-unset}"

w="$(value record_writable)"
check "record read-only inside" "$([ "$w" = "0" ] && echo 0 || echo 1)" "writable=${w:-none}"

seen="$(value argv_literal)"
check "agent argv reaches jail as typed" "$([ "$seen" = "$literal" ] && echo 0 || echo 1)" "got ${seen:-nothing}"
graph="$(value env_graph)"
real_project="$(cd "$project" && pwd -P)"
check "jail env survives the scope" "$([ "$graph" = "$real_project/.innerwarden/graph.json" ] && echo 0 || echo 1)" "IW_GRAPH_FILE=${graph:-unset}"

id="$(printf '%s' "$record" | sed -n 's/.*"instance_id":"\([0-9a-z-]*\)".*/\1/p')"
state="${XDG_STATE_HOME:-}"
case "$state" in /*) ;; *) state="$HOME/.local/state" ;; esac
copy="$state/innerwarden/instances/$id.json"
same=1
if [ -n "$id" ] && [ -f "$copy" ] && [ "$(cat "$copy")" = "$record" ]; then same=0; fi
check "record = launcher's copy" "$same" "$copy"

unit="innerwarden-contain-$id.scope"
user_cgroup="$(printf '%s' "$record" | sed -n 's/.*"user":{"unit":"[^"]*","cgroup_path":"\([^"]*\)"}.*/\1/p')"
system_cgroup="$(printf '%s' "$record" | sed -n 's/.*"system":{"unit":"[^"]*","cgroup_path":"\([^"]*\)"}.*/\1/p')"
if [ -n "$user_cgroup" ] || [ -n "$system_cgroup" ]; then
    in_scope=1
    case "$before" in */"$unit") in_scope=0 ;; esac
    check "jail is in the recorded scope" "$in_scope" "user=${user_cgroup:-none} system=${system_cgroup:-none}"
elif [ "${IW_ESCAPE_ALLOW_NO_SCOPE:-0}" = "1" ]; then
    check "no scope (allowed fallback)" 0 "IW_ESCAPE_ALLOW_NO_SCOPE=1"
else
    check "instance has a scope" 1 "none recorded (IW_ESCAPE_ALLOW_NO_SCOPE=1 to accept)"
fi

echo
echo "INFO  d) /run inside: $(value d_run_entries)"
echo "INFO  f) abstract unix sockets visible inside: $(value f_abstract_sockets)"
echo "INFO  g) jail can make its own user namespace (unshare -Urm): $(value g_nested_userns)"
echo "INFO  systemd: $(systemd-run --version 2>/dev/null | head -n 1) / bwrap: $(bwrap --version 2>/dev/null)"
echo "INFO  kernel: $(uname -r)"

echo
if [ "$fails" -eq 0 ]; then
    echo "contain-identity-escape: PASS"
    exit 0
fi
echo "contain-identity-escape: FAIL ($fails check(s))"
exit 1
