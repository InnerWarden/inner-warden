//! An agent's settings written outside the account's real home (a
//! throwaway HOME made for a measurement, `mktemp -d` or a folder in a
//! work tree) stay the guard's configuration to the agent's file tools.
//!
//! Asked for in the BI item NEW-20261118-guard-refuses-settings-fixture-in-
//! temp-home: hold them as agent settings only under the real home (or the
//! agent's `CLAUDE_CONFIG_DIR` / `CODEX_HOME`). Decided against, and
//! pinned here, because the same paths are settings an agent reads where it
//! runs: Claude Code reads a project's `.claude/settings.json` (which can
//! switch every hook off), Codex the `.codex/config.toml` of a trusted
//! project over the user's file, Cursor a project's `.cursor/mcp.json`, and
//! a folder made by `mktemp -d` is a folder an agent can be started in. A
//! throwaway HOME's `.codex/config.toml` cannot be told from a project's;
//! an agent started there, or with `HOME=` pointed there, loads it. Such a
//! fixture is written from a test (a `tempfile` folder inside `cargo
//! test`), which no file tool of the agent writes.
//!
//! Both ends: under the real home and outside it, each path is the guard's
//! configuration; starting an agent with `HOME` moved stays refused.

use std::path::Path;

use innerwarden_agent_guard::file_tools::{privileged_file_write, WriteContext};
use innerwarden_agent_guard::mcp::analyze_command;

fn what(path: &str) -> Option<&'static str> {
    privileged_file_write(
        path,
        &WriteContext {
            cwd: Some(Path::new("/home/dev/work")),
            home: Some(Path::new("/home/dev")),
            guard_program: None,
        },
    )
}

#[test]
fn agent_settings_in_a_throwaway_home_are_still_the_guards_configuration() {
    for settings in [
        ".codex/config.toml",
        ".codex/hooks.json",
        ".claude/settings.json",
        ".cursor/mcp.json",
        ".gemini/settings.json",
    ] {
        for home in [
            "/home/dev",
            "/tmp/tmp.k3J9xQ",
            "/home/dev/innerwarden/t185-home",
            "/home/dev/work/proj",
        ] {
            let path = format!("{home}/{settings}");
            assert!(
                what(&path).is_some_and(|what| what.starts_with("the guard's own configuration")),
                "{path}: {:?}",
                what(&path)
            );
        }
    }
}

#[test]
fn an_agent_started_with_its_home_moved_stays_refused() {
    for line in [
        "HOME=/tmp/tmp.k3J9xQ codex exec 'run the tests'",
        "HOME=$HOME/innerwarden/t185-home claude -p 'fix the test'",
        "env HOME=/tmp/h codex",
    ] {
        assert_eq!(analyze_command(line, None).recommendation, "deny", "{line}");
    }
}
