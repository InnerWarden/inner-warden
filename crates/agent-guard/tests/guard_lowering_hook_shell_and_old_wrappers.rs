//! What a review of the reading of the guard's own command lines found
//! left out, measured 2026-11-21 on main 8191a16 (analyze_command, empty
//! home), each allowed:
//!
//! * a `pkill -f` pattern of the shell that runs the fail-closed hook of
//!   Codex, Gemini CLI or Hermes Agent (`pkill -f 'refusing this tool call'`,
//!   `pkill -f 'hook --agent codex; s='`): killed, the agent reads no
//!   refusal and runs the call;
//! * a pattern of an MCP wrapper layout an older CLI wrote (`proxy --mode
//!   advisory`, `proxy --agent claude-code --mode guard`);
//! * a pattern no regular expression reader here compiles though glibc does
//!   (`innerwarde{,1}n hook`), a piece of a word of the guard's (`roxy`,
//!   `hoo`), a path of the guard's program in a folder not listed
//!   (`/opt/iw/bin/innerwarden`);
//! * the Cursor CLI started with its configuration folder moved
//!   (`CURSOR_CONFIG_DIR`, `HOME`), and `export CLAUDE_${X:-CONFIG}_DIR=...`
//!   before `claude`.
//!
//! Nothing here is executed: every line is only screened.

use innerwarden_agent_guard::agent_hooks::{CODEX, GEMINI};
use innerwarden_agent_guard::hermes_hook;
use innerwarden_agent_guard::hook::hook_command_for;
use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::rules::RuleEngine;
use std::path::Path;

fn verdict(command: &str) -> String {
    analyze_command(command, Some(&RuleEngine::load_embedded())).recommendation
}

/// The scripts of the hook lines the CLI writes that run the guard under
/// a shell, from the functions that write them (Codex, Gemini CLI, Hermes
/// Agent and Claude Code, every mode): today Codex and Gemini CLI in
/// enforce, Gemini's fail-open monitor line, and Claude Code's fail-closed
/// line. Hermes runs the guard with no shell (its fail-closed is a
/// setting), so it adds none.
fn hook_scripts() -> Vec<String> {
    let bin = Path::new("/usr/local/bin/innerwarden");
    let mut scripts = Vec::new();
    for (block_review, monitor) in [(false, false), (true, false), (false, true)] {
        for line in [
            CODEX.command(bin, block_review, monitor),
            GEMINI.command(bin, block_review, monitor),
            hermes_hook::command(bin, block_review, monitor),
        ] {
            if let Some(script) = line
                .strip_prefix("/bin/sh -c '")
                .and_then(|rest| rest.rsplit_once("' "))
                .map(|(script, _)| script.to_owned())
            {
                if !scripts.contains(&script) {
                    scripts.push(script);
                }
            }
        }
        // Claude Code's enforcing line is the script its own `sh -c` runs.
        let claude = hook_command_for(bin, block_review, monitor, Some("claude-code"));
        if claude.contains("s=$?") && !scripts.contains(&claude) {
            scripts.push(claude);
        }
    }
    assert!(scripts.len() >= 3, "{scripts:#?}");
    scripts
}

/// Every run of three words of each script, as a pattern that matches it
/// as written (its regular expression characters escaped).
fn script_fragments() -> Vec<String> {
    let mut fragments = Vec::new();
    for script in hook_scripts() {
        let words: Vec<&str> = script.split(' ').collect();
        for window in words.windows(3) {
            let fragment = regex::escape(&window.join(" "));
            if !fragments.contains(&fragment) {
                fragments.push(fragment);
            }
        }
    }
    fragments
}

/// Shell-quote `text` as one word.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

#[test]
fn a_pattern_of_the_fail_closed_hook_shell_is_refused() {
    let fragments = script_fragments();
    assert!(fragments.len() > 40, "{fragments:?}");
    for fragment in &fragments {
        for line in [
            format!("pkill -f {}", quoted(fragment)),
            format!("pgrep -f {} | xargs kill", quoted(fragment)),
        ] {
            assert_eq!(verdict(&line), "deny", "{line}");
        }
    }
}

#[test]
fn a_pattern_of_an_older_wrapper_layout_is_refused() {
    for pattern in [
        "proxy --mode guard --",
        "proxy --mode advisory",
        "proxy --mode advisory -- npx",
        "proxy --agent claude-code --mode guard",
        "proxy --agent codex --mode guard",
        "proxy --label codex --mode guard",
        "proxy --label claude-code --error-response",
        "--agent gemini --mode advisory --",
        "--label cursor --agent cursor --mode guard",
    ] {
        let line = format!("pkill -f -- {}", quoted(pattern));
        assert_eq!(verdict(&line), "deny", "{line}");
    }
}

/// Review of #341: a pattern no reader here compiles is read as glibc
/// reads `{,n}`; a piece of a word of the guard's is broad; a path of
/// the guard's program in any folder names it.
#[test]
fn what_the_review_of_the_pattern_reading_found() {
    for line in [
        "pkill -f 'innerwarde{,1}n hook'",
        "pkill -f 'innerwarden{,3} hook'",
        "pkill -f /opt/iw/bin/innerwarden",
        "pkill -f /home/me/bin/innerwarden-agent",
        "pgrep -f /opt/iw/bin/innerwarden | xargs kill",
        "killall /opt/iw/bin/innerwarden",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "pkill -f roxy",
        "pkill -f hoo",
        "pkill -f ashboar",
        // No reading compiles (an unclosed group): a person decides.
        "pkill -f 'innerw(arden'",
    ] {
        assert_eq!(verdict(line), "review", "{line}");
    }
}

/// The Cursor CLI, by the same table as the other agents: its
/// configuration folder moved, the MCP wiring of the guard stays behind.
#[test]
fn the_cursor_cli_started_with_its_folder_moved_is_refused() {
    for line in [
        "CURSOR_CONFIG_DIR=/tmp/c cursor-agent -p x",
        "env CURSOR_CONFIG_DIR=/tmp/c cursor-agent",
        "export CURSOR_CONFIG_DIR=/tmp/c; cursor-agent -p x",
        "D=/tmp/c; CURSOR_CONFIG_DIR=$D cursor-agent",
        "HOME=/tmp/h cursor-agent -p x",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in ["cursor-agent -p x", "cursor-agent --help"] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// A second Claude Code with a folder of its own: every spelling of the
/// variable before it, including a name built at run time.
#[test]
fn a_second_claude_code_with_its_own_folder_is_refused_in_every_spelling() {
    for line in [
        "CLAUDE_CONFIG_DIR=/tmp/c claude -p x",
        "export CLAUDE_CONFIG_DIR=/tmp/c; claude -p x",
        "env CLAUDE_CONFIG_DIR=/tmp/c claude -p x",
        "V=CLAUDE_CONFIG_DIR; export $V=/tmp/c; claude -p x",
        "n=CLAUDE_CONFIG; export ${n}_DIR=/tmp/c; claude",
        "export CLAUDE_${X:-CONFIG}_DIR=/tmp/c; claude",
        "declare -x \"CLAUDE_${Y}_DIR=/tmp/c\"; claude",
        "export -- CLAUDE_CONFIG_DIR=/tmp/c; claude",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
    for line in [
        "CLAUDE_CONFIG_DIR=~/.claude claude -p x",
        "export BUILD_${X:-DIR}=out; make",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// Our own processes that have nothing to do with the guard stay ours to
/// stop.
#[test]
fn stopping_a_process_of_ours_unrelated_to_the_guard_stays_allowed() {
    for line in [
        "pkill -f 'node server.js'",
        "pkill -f vite",
        "pkill -f 'python -m http.server'",
        "pkill -f 'cargo watch'",
        "pkill -f claude",
        "pkill -f npx",
        "pkill -f codex",
        "pkill node",
        "pkill -f webpack",
        "pkill -f 'next dev'",
        "pkill -f jest",
        "pkill -f uvicorn",
        "pkill -f postgres",
        "pkill -f 'tsc --watch'",
        "pkill -f innerwarden-docs-server",
        "pkill -f program",
        "pkill -f 'npm run dev'",
        "killall node",
        "pgrep -f vite | xargs kill",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
