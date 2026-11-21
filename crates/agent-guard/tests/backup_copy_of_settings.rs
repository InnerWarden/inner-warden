//! A copy onto a file named like an agent's settings is a write of the
//! settings only in a folder an agent reads them from.
//!
//! Measured 2026-11-21: `python3 - <<EOF` with
//! `shutil.copyfile('.claude/settings.json', 'backup/settings.json')` was
//! refused, because `interpreter_code_puts_file_onto_settings` (threats.rs)
//! judged the destination by its file name alone. A copy onto
//! `~/.codex/config.toml` was only held for review.

use innerwarden_agent_guard::mcp::analyze_command;
use innerwarden_agent_guard::rules::{AtrSource, RuleEngine};

fn verdict(command: &str) -> (String, String) {
    let engine = RuleEngine::load_embedded_for(AtrSource::ShellCommand);
    let analysis = analyze_command(command, Some(&engine));
    (analysis.recommendation, analysis.explanation)
}

/// The same program given inline and fed as a here-document.
fn both_ways(code: &str) -> [String; 2] {
    [
        format!("python3 -c \"{code}\""),
        format!("python3 - <<EOF\n{}\nEOF", code.replace("; ", "\n")),
    ]
}

/// FAILS ON REVERT of `copy_destination_is_agent_settings` (threats.rs):
/// each was refused as a rewrite of an agent's configuration.
#[test]
fn a_backup_copy_in_another_folder_is_not_a_settings_write() {
    let python = [
        "import shutil; shutil.copyfile('.claude/settings.json', 'backup/settings.json')",
        "import shutil; shutil.copy2('/home/u/.claude/settings.json', '/home/u/bkp/claude/settings.local.json')",
        "import shutil; d='backup/settings.json'; shutil.copyfile('.claude/settings.json', d)",
        "import shutil; shutil.copyfile('.mcp.json', 'backup/.mcp.json')",
        "import shutil; shutil.copyfile('/home/u/.claude.json', '/home/u/backup/.claude.json')",
        "import shutil; shutil.copyfile('/home/u/.codex/config.toml', 'backup/config.toml')",
    ];
    for code in python {
        for line in both_ways(code) {
            let (recommendation, why) = verdict(&line);
            assert_eq!(recommendation, "allow", "{line:?}: {why}");
        }
    }
    let line =
        "node -e \"require('fs').copyFileSync('.claude/settings.json', 'backup/settings.json')\"";
    let (recommendation, why) = verdict(line);
    assert_eq!(recommendation, "allow", "{line:?}: {why}");
}

/// The other direction: a copy or link onto the settings in an agent's
/// folder, or onto a bare settings name whose folder is not known, stays
/// refused. `.codex/config.toml` was review before and is refused now.
#[test]
fn a_copy_onto_settings_in_an_agent_folder_stays_refused() {
    let python = [
        "import shutil; shutil.copyfile('/tmp/e.json', '.claude/settings.json')",
        "import shutil; shutil.copyfile('/tmp/e.json', '/home/u/.claude/settings.json')",
        "import shutil; shutil.copyfile('/tmp/c.toml', '/home/u/.codex/config.toml')",
        "import shutil,os; shutil.copyfile('/tmp/c.toml', os.path.expanduser('~/.codex/config.toml'))",
        "import shutil; shutil.copyfile('/tmp/c.toml', '.codex/config.toml')",
        "import shutil; shutil.copyfile('/tmp/e.json', '/home/u/.gemini/settings.json')",
        "import shutil; shutil.copyfile('/tmp/e.json', '/home/u/.cursor/mcp.json')",
        "import shutil; shutil.copyfile('/tmp/e.json', '/home/u/.config/claude/settings.json')",
        "import shutil; shutil.copyfile('/tmp/e.json', 'settings.json')",
        "import shutil; shutil.copyfile('/tmp/e.json', '.mcp.json')",
        "import shutil; shutil.copyfile('/tmp/e.json', './.mcp.json')",
        "import shutil; shutil.copyfile('/tmp/e.json', '/home/u/.claude.json')",
        "import shutil,os; shutil.copyfile('/tmp/e.json', os.path.expanduser('~/.claude.json'))",
        "import shutil; d='/home/u/.claude/settings.json'; shutil.copyfile('/tmp/e.json', d)",
        "import os; os.symlink('/tmp/e.json', '/home/u/.claude/settings.json')",
    ];
    for code in python {
        for line in both_ways(code) {
            let (recommendation, why) = verdict(&line);
            assert_eq!(recommendation, "deny", "{line:?}: {why}");
        }
    }
    let line = "node -e \"require('fs').copyFileSync('/tmp/e.json', process.env.HOME + '/.claude/settings.json')\"";
    let (recommendation, why) = verdict(line);
    assert_eq!(recommendation, "deny", "{line:?}: {why}");
}
