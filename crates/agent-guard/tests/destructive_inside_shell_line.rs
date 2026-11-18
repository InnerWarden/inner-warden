//! A destructive line handed to a shell to run is judged as the line itself.
//!
//! Measured on the published 1.6.13 (2026-11-18): `rm -rf /` and `rm -rf ~`
//! were refused, while `bash -c 'rm -rf /'`, `sh -c "rm -rf ~"` and
//! `foo -ex 'shell rm -rf /'` were allowed with "no rule matched", and the
//! Claude Code hook in enforce let them run. The rules for a download that
//! runs already read the line inside `-c`; the rules for what the line
//! destroys did not. Every line a shell or a runner is handed (`-c`, `-lc`,
//! `su -c`, a debugger's `shell`, behind `env`, `sudo`, `xargs` or
//! `find -exec`) now goes through every rule, and earns the verdict the
//! same line typed out earns.
//!
//! Each case comes with the everyday lines it must keep allowing.

use innerwarden_agent_guard::mcp::{analyze_command, analyze_command_in, WorkingContext};

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

/// Each `(handed, direct)` pair: the handed form earns the direct form's
/// verdict, and the direct form is refused.
fn assert_same_as_direct(pairs: &[(&str, &str)]) {
    let differing: Vec<(&str, String, &str, String)> = pairs
        .iter()
        .map(|(handed, direct)| (*handed, verdict(handed), *direct, verdict(direct)))
        .filter(|(_, handed, _, direct)| handed != direct || direct == "allow")
        .collect();
    assert!(
        differing.is_empty(),
        "handed form differs from the direct form: {differing:#?}"
    );
}

fn assert_allowed(lines: &[&str]) {
    let refused: Vec<(&str, String)> = lines
        .iter()
        .map(|line| (*line, verdict(line)))
        .filter(|(_, verdict)| verdict != "allow")
        .collect();
    assert!(refused.is_empty(), "everyday lines refused: {refused:#?}");
}

#[test]
fn a_shell_c_line_is_judged_as_the_line() {
    assert_same_as_direct(&[
        ("bash -c 'rm -rf /'", "rm -rf /"),
        ("sh -c 'rm -rf /'", "rm -rf /"),
        ("bash -c \"rm -rf ~\"", "rm -rf ~"),
        ("sh -c \"rm -rf ~\"", "rm -rf ~"),
        ("dash -c 'rm -rf $HOME'", "rm -rf $HOME"),
        ("zsh -c 'rm -rf /*'", "rm -rf /*"),
        ("bash -lc 'rm -rf /'", "rm -rf /"),
        ("bash -l -c 'rm -rf ~'", "rm -rf ~"),
        ("/bin/sh -c 'rm -rf /'", "rm -rf /"),
    ]);
}

#[test]
fn a_shell_c_line_with_several_commands_is_judged_as_the_line() {
    assert_same_as_direct(&[
        ("sh -c 'cd /tmp; rm -rf ~'", "cd /tmp; rm -rf ~"),
        ("sh -c 'true && rm -rf /'", "true && rm -rf /"),
        ("bash -c 'ls || rm -rf ~'", "ls || rm -rf ~"),
        ("bash -c 'echo hi\nrm -rf /'", "echo hi\nrm -rf /"),
    ]);
}

#[test]
fn a_shell_behind_a_wrapper_is_judged_as_the_line() {
    assert_same_as_direct(&[
        ("env bash -c 'rm -rf /'", "rm -rf /"),
        ("env FOO=1 sh -c 'rm -rf ~'", "rm -rf ~"),
        ("sudo sh -c 'rm -rf /'", "sudo rm -rf /"),
        ("sudo -u root bash -c 'rm -rf ~'", "rm -rf ~"),
        ("nohup sh -c 'rm -rf /' &", "rm -rf /"),
        ("timeout 5 bash -c 'rm -rf ~'", "rm -rf ~"),
        ("echo x | xargs sh -c 'rm -rf ~'", "rm -rf ~"),
        ("xargs -0 bash -c 'rm -rf /' < list", "rm -rf /"),
        ("find . -maxdepth 0 -exec sh -c 'rm -rf ~' \\;", "rm -rf ~"),
        ("find . -execdir bash -c 'rm -rf /' {} +", "rm -rf /"),
        ("su -c 'rm -rf /'", "rm -rf /"),
        ("su root -c 'rm -rf ~'", "rm -rf ~"),
    ]);
}

#[test]
fn a_debugger_shell_line_is_judged_as_the_line() {
    assert_same_as_direct(&[
        ("foo -ex 'shell rm -rf /'", "rm -rf /"),
        ("gdb -batch -ex 'shell rm -rf ~'", "rm -rf ~"),
        ("gdb -ex '!rm -rf /'", "rm -rf /"),
    ]);
}

#[test]
fn every_rule_reads_the_handed_line_not_only_rm() {
    assert_same_as_direct(&[
        ("bash -c 'rm -rf ~/.ssh'", "rm -rf ~/.ssh"),
        (
            "sh -c 'dd if=/dev/zero of=/dev/sda'",
            "dd if=/dev/zero of=/dev/sda",
        ),
        ("bash -c 'mkfs.ext4 /dev/sda1'", "mkfs.ext4 /dev/sda1"),
        ("sh -c ':(){ :|:& };:'", ":(){ :|:& };:"),
    ]);
}

#[test]
fn a_line_handed_twice_is_still_read() {
    assert_same_as_direct(&[
        ("bash -c \"sh -c 'rm -rf /'\"", "rm -rf /"),
        ("sudo bash -c \"sh -c 'rm -rf ~'\"", "rm -rf ~"),
    ]);
}

/// The hook judges a command with its working directory; the handed line is
/// read there too, so `sh -c 'rm -rf *'` from the home is the wipe that
/// `rm -rf *` from the home is.
#[test]
fn the_handed_line_is_read_where_it_runs() {
    let home = WorkingContext {
        cwd: "/home/u".into(),
        home: Some("/home/u".into()),
        project_root: "/home/u".into(),
        related_roots: Vec::new(),
        enclosing_dirs: Vec::new(),
    };
    let direct = analyze_command_in("rm -rf *", None, Some(&home)).recommendation;
    assert_eq!(direct, "deny");
    for line in ["sh -c 'rm -rf *'", "bash -c \"rm -rf ./*\""] {
        assert_eq!(
            analyze_command_in(line, None, Some(&home)).recommendation,
            direct,
            "{line}"
        );
    }
    let project = WorkingContext {
        cwd: "/home/u/proj".into(),
        home: Some("/home/u".into()),
        project_root: "/home/u/proj".into(),
        related_roots: Vec::new(),
        enclosing_dirs: Vec::new(),
    };
    assert_eq!(
        analyze_command_in("sh -c 'rm -rf *'", None, Some(&project)).recommendation,
        "allow"
    );
}

#[test]
fn everyday_shell_lines_stay_allowed() {
    assert_allowed(&[
        "bash -c 'cargo test'",
        "sh -c 'rm -rf target/debug'",
        "bash -c \"rm -rf ./build\"",
        "bash -lc 'cd crates && cargo build'",
        "sh -c 'rm -rf node_modules && npm ci'",
        "bash -c 'rm -rf ~/.cache/pip'",
        "sudo sh -c 'apt-get update'",
        "env CI=1 bash -c 'make test'",
        "find . -name '*.o' -exec sh -c 'rm -f \"$1\"' _ {} \\;",
        "printf '%s\\n' a b | xargs sh -c 'echo \"$@\"' _",
        "su -c 'systemctl status nginx'",
        "gdb -batch -ex 'shell ls'",
        "bash -c 'echo rm -rf /'",
        "git commit -m \"guard: read sh -c 'rm -rf /' as the line\"",
    ]);
}
