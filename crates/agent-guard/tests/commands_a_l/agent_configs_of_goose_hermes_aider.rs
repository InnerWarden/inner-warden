//! The settings of Goose, Hermes and Aider are held as the other agents'
//! settings are: each says which tools and servers its agent loads and what
//! it may run without asking, so an agent that rewrites its own (or
//! another's) can loosen what it is let do. Writing them by a file tool or
//! by the shell is refused; reading them is not.
//!
//! Measured on main on 2026-11-19 (a069bf1): `echo x >> ~/.hermes/config.yaml`,
//! `sed -i`, `cp`, `mv` and `rm` onto each of the three, and a file tool
//! write to each, were allowed.

use std::path::Path;

use innerwarden_agent_guard::file_tools::{privileged_file_write, WriteContext};
use innerwarden_agent_guard::mcp::analyze_command;

const CONFIGS: [&str; 3] = [
    ".config/goose/config.yaml",
    ".hermes/config.yaml",
    ".aider.conf.yml",
];

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

/// FAILS ON REVERT: take the three out of the guard's settings group (and
/// the shell's needles) and every line here is allowed.
#[test]
fn a_shell_write_to_goose_hermes_or_aider_settings_is_refused() {
    for config in CONFIGS {
        for line in [
            format!("echo 'x: 1' >> ~/{config}"),
            format!("printf 'x: 1\\n' > ~/{config}"),
            format!("sed -i 's/a/b/' ~/{config}"),
            format!("cp /tmp/c.yaml ~/{config}"),
            format!("mv /tmp/c.yaml ~/{config}"),
            format!("tee -a ~/{config} < /tmp/c.yaml"),
            format!("rm -f ~/{config}"),
            format!("echo 'x: 1' >> \"$HOME/{config}\""),
        ] {
            assert_eq!(verdict(&line), "deny", "{line}");
        }
    }
}

/// FAILS ON REVERT: take them out of the home files the file tools judge
/// and out of the settings group, and these are `None`.
#[test]
fn a_file_tool_write_to_goose_hermes_or_aider_settings_is_refused() {
    let context = WriteContext {
        cwd: Some(Path::new("/home/u/p")),
        home: Some(Path::new("/home/u")),
        guard_program: None,
    };
    for config in CONFIGS {
        for path in [format!("/home/u/{config}"), format!("~/{config}")] {
            assert!(privileged_file_write(&path, &context).is_some(), "{path}");
        }
    }
    for path in [
        "/home/u/.hermes/notes.md",
        "/home/u/p/aider.conf.yml.example",
        "/home/u/p/goose/config.yaml",
    ] {
        assert!(privileged_file_write(path, &context).is_none(), "{path}");
    }
}

/// Reading them by the shell stays free. (A file tool read is not judged by
/// the settings group: the hook holds only writes there.)
#[test]
fn reading_goose_hermes_or_aider_settings_stays_free() {
    for config in CONFIGS {
        for line in [
            format!("cat ~/{config}"),
            format!("grep -n model ~/{config}"),
            format!("head -n 20 ~/{config}"),
        ] {
            assert_eq!(verdict(&line), "allow", "{line}");
        }
    }
}
