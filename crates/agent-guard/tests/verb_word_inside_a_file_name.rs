//! A verb inside a file name is not a command.
//!
//! Measured 2026-11-20 on main with `analyze_command`: lines that only name
//! a file whose name holds a verb (`probe-kill.json`, `disable-check.py`,
//! `remove-old/`, `stop.log`) beside a path with the guard's name were
//! refused as `disable InnerWarden (flags between verb and target)`. The
//! first was a test run on a lab host, refused by the hook. A verb counts
//! only as a word of a command: a name, a path's last part, or an option
//! spelled with it (`--stop`).

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

/// FAILS ON REVERT: drop `verb_stands_as_a_word` from
/// `disable_verb_before` and each is refused.
#[test]
fn a_verb_inside_a_file_name_beside_the_guards_folder_is_not_a_kill() {
    for line in [
        r##"cd crates/agent-guard && PROBE_LINES=/home/u/innerwarden/scripts-local/probe-kill.json PROBE_OUT=/home/u/innerwarden/scripts-local/o.tsv cargo test -q --test zz_probe"##,
        r##"mv /home/u/innerwarden/scripts-local/probe-kill.json /home/u/innerwarden/scripts-local/probe-k.json"##,
        r##"F=probe-kill.json; cat ~/innerwarden/scripts-local/$F"##,
        r##"cat ~/notes/stop-words.txt ~/innerwarden/README.md"##,
        r##"python3 tools/disable-check.py ~/innerwarden/inner-warden/Cargo.toml"##,
        r##"ls ~/innerwarden/remove-old/ ~/innerwarden/x"##,
        r##"cp ./kill-list.json ~/innerwarden/data/"##,
        r##"wc -l logs/stop.log /var/log/innerwarden/agent.log"##,
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// The verbs as words of a command, however spelt, keep their refusal.
#[test]
fn a_verb_standing_as_a_word_still_reaches_the_guard() {
    for line in [
        r##"systemctl stop innerwarden-agent"##,
        r##"/usr/bin/pkill -9 innerwarden-agent"##,
        r##"sudo /bin/kill -9 $(pidof innerwarden)"##,
        r##"start-stop-daemon --stop --name innerwarden-agent"##,
        r##"systemctl --now disable innerwarden-sensor"##,
        r##"(pkill innerwarden)"##,
        r##"x;pkill -9 innerwarden-agent"##,
        r##"nohup pkill -9 innerwarden-agent &"##,
        r##""pkill" -9 innerwarden-agent"##,
        r##"'systemctl' stop innerwarden-agent"##,
        r##"echo|xargs pkill innerwarden"##,
        r##"env -i pkill -9 innerwarden-agent"##,
        r##"p\kill -9 innerwarden-agent"##,
        r##"systemctl stop innerwarden-agent.service"##,
        r##"X=stop; systemctl $X innerwarden-agent"##,
        r##"sudo systemctl mask innerwarden-sensor"##,
        r##"innerwarden uninstall"##,
        r##"/usr/local/bin/innerwarden disable"##,
        r##"killall -9 innerwarden-agent"##,
        r##"systemctl kill --signal=KILL innerwarden-agent"##,
        r##"sudo service innerwarden-agent stop"##,
        r##"pkill -9 falco"##,
        r##"systemctl stop auditd"##,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}
