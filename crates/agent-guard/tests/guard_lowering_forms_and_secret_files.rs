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
    // The agent's own name, the MCP server the proxy runs, a listing, and
    // patterns that match no line the guard runs.
    for command in [
        "pkill -f claude",
        "pkill -f npx",
        "pkill -f 'node server.js'",
        "pkill -f 'vite --port 5173'",
        "pgrep -f 'hook --agent claude-code'",
        "pgrep -f 'cargo build' | xargs kill",
        "pkill -f innerwarden-docs-server",
        "pkill node",
        "pkill -f x",
        "killall node",
        "killall -r nginx",
    ] {
        assert_eq!(verdict(command), "allow", "{command}");
    }
}

#[test]
fn a_piece_of_the_name_reaches_the_guard_through_any_launcher_and_reader() {
    // Main refused these; the first reading of this change let them through.
    for command in [
        "pkill -f warden",
        "pkill -f inner",
        "pkill -f innerwar",
        "env pkill -f warden",
        "command pkill -f warden",
        "exec pkill -f warden",
        "nice pkill -f warden",
        "echo x | xargs pkill -f warden",
        "pgrep -f warden | xargs kill",
        "kill $(pgrep -f warden)",
        "pkill warden",
        "pgrep warden | xargs kill -9",
        "kill $(pidof innerwarden)",
        "pidof innerwarden | xargs kill",
        // The layout older wrappers ran with, killed or started by the agent.
        "pkill -f 'mcp-proxy -- npx'",
        "innerwarden mcp-proxy -- node server.js",
        "innerwarden mcp-proxy -- npx -y some-mcp-server",
    ] {
        assert_eq!(verdict(command), "deny", "{command}");
    }
}

#[test]
fn a_backslash_before_a_letter_is_read_in_every_dialect() {
    // glibc's and the BSDs' ERE read `\d` as `d`.
    for command in [
        r"pkill -f 'innerwar\den'",
        r"pkill -f 'inner\warden'",
        r"pgrep -f 'innerwar\den' | xargs kill",
        r"killall -r 'innerwar\den'",
    ] {
        assert_eq!(verdict(command), "deny", "{command}");
    }
}

#[test]
fn killall_by_name_or_by_pattern_is_read_as_pkill_is() {
    for command in [
        "killall -r warden",
        "killall -r 'inner.arden'",
        "killall -m warden",
        "killall -I INNERWARDEN",
        "killall -9 innerwarden-agent",
        "sudo killall -r warden",
    ] {
        assert_eq!(verdict(command), "deny", "{command}");
    }
    assert_eq!(verdict("killall -r agent"), "review");
}

#[test]
fn a_whole_word_of_the_guard_without_its_name_is_left_to_a_person() {
    for command in [
        "pkill -f proxy",
        "pkill -f hook",
        "pkill -f dashboard",
        "pkill -f guard",
        "pkill -f /usr/local/bin",
        "pgrep -f proxy | xargs kill",
    ] {
        assert_eq!(verdict(command), "review", "{command}");
    }
}

#[test]
fn a_unit_glob_that_matches_a_guard_unit_is_stopping_the_guard() {
    for command in [
        "systemctl stop 'innerwar*'",
        "systemctl stop '*warden*'",
        "systemctl disable --now 'inner?arden-agent'",
        "systemctl mask 'innerwarden-[a-z]*'",
        "systemctl kill 'inner[warden'",
        "sudo systemctl stop 'innerwarden-*.service'",
    ] {
        assert_eq!(verdict(command), "deny", "{command}");
    }
    for command in ["systemctl stop 'nginx*'", "systemctl restart 'php*-fpm'"] {
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
    // In any case: on a disk that ignores it (APFS) these are the same files.
    for command in [
        "cat ~/.PGPASS",
        "cat ~/.My.Cnf",
        "cat ~/.Vault-Token",
        "cat ~/Passwords.KDBX",
    ] {
        assert_eq!(verdict(command), "deny", "{command}");
    }
    // Another file whose name ends the same way.
    for command in [
        "cat backup.my.cnf",
        "cat ~/backup.pgpass",
        "cat notes/my.cnf",
        "grep -r kdbx docs/",
        "ls ~/projects",
        "psql -h db -U app",
    ] {
        assert_eq!(verdict(command), "allow", "{command}");
    }
}
