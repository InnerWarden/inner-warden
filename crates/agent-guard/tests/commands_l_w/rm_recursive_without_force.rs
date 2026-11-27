//! A recursive `rm` of the root, a home or a top-level system folder is a
//! wipe with or without `-f`, and whatever other letters share the option
//! group with `r` or `R`.
//!
//! Measured on main on 2026-11-20: `rm -rm /`, `rm -rx ~`, `rm -Rz /`,
//! `rm -mr /`, `rm -r -m /`, `rm -r /` and `rm -R ~` were allowed, while
//! `rm -rf /` and `rm -fr /etc` were denied. The flags were read as
//! recursive; the rule also wanted `-f`. With no terminal on stdin, as an
//! agent runs it, `rm -r` asks nothing and takes the same tree.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

#[test]
fn an_option_group_with_r_and_an_unknown_letter_is_recursive() {
    for line in [
        "rm -rm /",
        "rm -rx ~",
        "rm -Rz /",
        "rm -mr /",
        "rm -r -m /",
        "rm -rm /etc",
        "rm -Rq $HOME",
        "sudo rm -rm /usr",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

#[test]
fn a_recursive_rm_of_root_home_or_system_needs_no_force() {
    for line in [
        "rm -r /",
        "rm -R ~",
        "rm --recursive /",
        "rm -r ~/*",
        "rm -rv /etc",
        "rm -r /bin",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

#[test]
fn the_forced_forms_stay_refused() {
    for line in ["rm -rf /", "rm -fr /etc", "rm -rf ~", "rm -r -f /"] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// A scoped path keeps its verdict: the change is about the flags, not the
/// targets.
#[test]
fn a_recursive_rm_of_a_scoped_path_is_not_a_wipe() {
    for line in [
        "rm -rm ./build",
        "rm -r ~/project/build",
        "rm -r /tmp/cache-dir",
        "rm -r target",
        "rm -rv node_modules",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
