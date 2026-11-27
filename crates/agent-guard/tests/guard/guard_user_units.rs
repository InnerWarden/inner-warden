//! The guard's own systemd units in a home are the guard's files.
//!
//! Measured 2026-11-24 on main 30ce33d: `rm -f
//! ~/.config/systemd/user/innerwarden-agent.service` (and through `$HOME`)
//! was allowed, and so were `mv`, `echo x >` and `sed -i` of it, while
//! the same removal of `/etc/systemd/system/innerwarden-agent.service` was
//! refused. `sed -i` of the system's unit was allowed too. Each is now
//! refused; a unit of another program in the same folder stays free, and so
//! does reading the guard's.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

const UNITS: &[&str] = &[
    "~/.config/systemd/user/innerwarden-agent.service",
    "$HOME/.config/systemd/user/innerwarden-agent.service",
    "\"$HOME/.config/systemd/user/innerwarden-agent.service\"",
    "${HOME}/.config/systemd/user/innerwarden-guard.timer",
    "$XDG_CONFIG_HOME/systemd/user/innerwarden-agent.service",
    "/home/dev/.config/systemd/user/innerwarden-sensor.service",
    "~/.config/systemd/user/default.target.wants/innerwarden-agent.service",
];

/// FAILS ON REVERT: drop `GUARD_USER_UNITS`, the redirect onto it and
/// `sed_edits_guard_file` and `rm`, `mv`, `echo x >` and `sed -i` of
/// each are allowed again.
#[test]
fn removing_or_rewriting_a_unit_of_the_guard_in_a_home_is_refused() {
    for unit in UNITS {
        for line in [
            format!("rm -f {unit}"),
            format!("rm {unit}"),
            format!("mv {unit} /tmp/old"),
            format!("unlink {unit}"),
            format!("shred -u {unit}"),
            format!("truncate -s 0 {unit}"),
            format!(": > {unit}"),
            format!("echo x > {unit}"),
            format!("echo x >> {unit}"),
            format!("sed -i s/a/b/ {unit}"),
            format!("sed -i.bak s/a/b/ {unit}"),
            format!("sed -Ei s/a/b/ {unit}"),
            format!("sed --in-place -e s/a/b/ {unit}"),
        ] {
            assert_eq!(verdict(&line), "deny", "{line}");
        }
    }
}

/// FAILS ON REVERT: drop `sed_edits_guard_file` and `sed -i` of the
/// system's unit is allowed again.
#[test]
fn editing_a_unit_of_the_guard_in_place_is_refused_on_the_system_too() {
    for line in [
        "sed -i s/a/b/ /etc/systemd/system/innerwarden-agent.service",
        "sudo sed -i 's/^ExecStart=.*/ExecStart=\\/bin\\/true/' /etc/systemd/system/innerwarden-sensor.service",
        "sed -i -e s/a/b/ /etc/systemd/system/innerwarden-agent.service",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// Another program's units in the same folder, a read of the guard's, and a
/// `sed` whose script only names the guard's path stay allowed.
#[test]
fn other_units_and_reads_of_the_guards_stay_allowed() {
    for line in [
        "rm -f ~/.config/systemd/user/myapp.service",
        "mv ~/.config/systemd/user/myapp.service /tmp/old",
        "sed -i s/a/b/ ~/.config/systemd/user/myapp.service",
        "echo x > ~/.config/systemd/user/myapp.service",
        "cat ~/.config/systemd/user/innerwarden-agent.service",
        "cat ~/.config/systemd/user/innerwarden-agent.service > /tmp/copy",
        "cp ~/.config/systemd/user/innerwarden-agent.service /tmp/copy",
        "sed -n p ~/.config/systemd/user/innerwarden-agent.service",
        "ls ~/.config/systemd/user/",
        "systemctl --user status innerwarden-agent",
        "sed -i 's|systemd/user/innerwarden-agent|x|' notes.md",
        "sed -i s/a/b/ notes.txt && cat ~/.config/systemd/user/innerwarden-agent.service",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
