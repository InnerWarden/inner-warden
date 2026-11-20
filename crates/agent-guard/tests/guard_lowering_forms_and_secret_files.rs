//! The forms of stopping the guard that main still let through, and the
//! secret files a read of was allowed.
//!
//! Measured 2026-11-20 on main 7b75f88 (analyze_command, empty home):
//! `pkill -f 'hook --agent claude-code'`, `pkill -f 'proxy -- '`,
//! `pgrep -f 'proxy -- npx' | xargs kill`, `systemctl stop>&2
//! innerwarden-agent`, `launchctl unload>/dev/null
//! ~/Library/LaunchAgents/com.innerwarden.agent.plist` and a D-Bus
//! `RestartUnit` of `innerwarden-sensor.service` were `allow`;
//! `kill $(pgrep -f 'hook --agent claude-code')` was `review`. `cat` of
//! `~/.pgpass`, `~/.vault-token`, `~/.my.cnf` and a `.kdbx` was `allow`.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

#[test]
fn a_process_pattern_that_matches_a_line_the_guard_runs_is_refused() {
    for command in [
        "pkill -f 'hook --agent claude-code'",
        "pkill -f 'hook --monitor --agent gemini'",
        "pkill -f 'proxy -- '",
        "pkill -f 'proxy --label claude-code --agent claude-code --mode guard'",
        "pkill -f 'agent claude-code --mode advisory'",
        "pkill -9 -f 'mode guard -- npx'",
        "pgrep -f 'proxy -- npx' | xargs kill",
        "pgrep -f 'proxy -- npx' | xargs -r kill -9",
        "kill $(pgrep -f 'hook --agent claude-code')",
        "kill -9 `pgrep -f 'proxy -- uvx'`",
    ] {
        assert_eq!(verdict(command), "deny", "{command}");
    }
}

#[test]
fn a_pattern_on_another_programs_part_or_on_none_is_not_the_guards() {
    // The agent's own name, the MCP server the proxy runs, a listing, and a
    // pattern that matches no line the guard runs (its proxy is `proxy`,
    // not `mcp-proxy`).
    for command in [
        "pkill -f claude",
        "pkill -f npx",
        "pkill -f 'node server.js'",
        "pkill -f 'vite --port 5173'",
        "pgrep -f 'hook --agent claude-code'",
        "pgrep -f 'cargo build' | xargs kill",
        "pkill -f 'mcp-proxy -- npx'",
    ] {
        assert_eq!(verdict(command), "allow", "{command}");
    }
}

#[test]
fn a_redirection_glued_to_the_verb_is_no_end_of_the_command() {
    for command in [
        "systemctl stop>&2 innerwarden-agent",
        "systemctl stop>/dev/null innerwarden-sensor",
        "systemctl stop 2>/dev/null innerwarden-agent",
        "systemctl --user --no-block --quiet --no-ask-password stop  innerwarden-agent.service",
        "launchctl unload>/dev/null ~/Library/LaunchAgents/com.innerwarden.agent.plist",
        "launchctl bootout>&2 gui/501 ~/Library/LaunchAgents/com.innerwarden.agent.plist",
    ] {
        assert_eq!(verdict(command), "deny", "{command}");
    }
    for command in [
        "systemctl stop>&2 nginx",
        "systemctl stop>&2 nginx && echo ok",
        "systemctl status innerwarden-agent",
        "echo done >&2 && ls",
    ] {
        assert_eq!(verdict(command), "allow", "{command}");
    }
}

#[test]
fn systemd_over_dbus_taking_a_guard_unit_down_is_stopping_the_guard() {
    const MANAGER: &str =
        "org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager";
    for command in [
        format!("busctl call {MANAGER} StopUnit ss innerwarden-agent.service replace"),
        format!("busctl call {MANAGER} KillUnit ssi innerwarden-agent.service all 9"),
        format!("busctl call {MANAGER} RestartUnit ss innerwarden-sensor.service replace"),
        format!("busctl call {MANAGER} MaskUnitFiles asbb 1 innerwarden-agent.service false true"),
        "busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/innerwarden_2dagent_2eservice org.freedesktop.systemd1.Unit Stop s replace".to_owned(),
        "dbus-send --system --print-reply --dest=org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager.StopUnit string:innerwarden-agent.service string:replace".to_owned(),
        "gdbus call --system --dest org.freedesktop.systemd1 --object-path /org/freedesktop/systemd1 --method org.freedesktop.systemd1.Manager.RestartUnit innerwarden-agent.service replace".to_owned(),
    ] {
        assert_eq!(verdict(&command), "deny", "{command}");
    }
    for command in [
        format!("busctl call {MANAGER} GetUnit s innerwarden-agent.service"),
        format!("busctl call {MANAGER} RestartUnit ss nginx.service replace"),
        "busctl status".to_owned(),
    ] {
        assert_eq!(verdict(&command), "allow", "{command}");
    }
}

#[test]
fn files_that_hold_a_password_or_a_token_are_secret() {
    for command in [
        "cat ~/.pgpass",
        "cat ~/.vault-token",
        "cat ~/.my.cnf",
        "cat ~/Documents/passwords.kdbx",
        "base64 ~/.pgpass",
        "cp ~/vault/team.kdbx /tmp/x",
    ] {
        assert_eq!(verdict(command), "deny", "{command}");
    }
    for command in ["grep -r kdbx docs/", "ls ~/projects", "psql -h db -U app"] {
        assert_eq!(verdict(command), "allow", "{command}");
    }
}
