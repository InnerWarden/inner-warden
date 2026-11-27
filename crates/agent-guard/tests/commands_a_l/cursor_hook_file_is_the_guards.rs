//! Cursor reads the guard's hook from `~/.cursor/hooks.json`. A shell line
//! that removes, rewrites or moves that file takes the guard out of Cursor,
//! so it is refused as the other agents' hook files are; reading it is not.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

/// FAILS ON REVERT: take `.cursor/hooks.json` out of the guard's settings in
/// `threats` and these lines are no longer refused.
#[test]
fn a_shell_line_that_changes_cursors_hook_file_is_refused() {
    for line in [
        "rm -f ~/.cursor/hooks.json",
        "rm /home/dev/.cursor/hooks.json",
        "mv ~/.cursor/hooks.json /tmp/h.json",
        "echo '{}' > ~/.cursor/hooks.json",
        "printf '{\"version\":1,\"hooks\":{}}' > $HOME/.cursor/hooks.json",
        "cp /tmp/empty.json ~/.cursor/hooks.json",
        "python3 -c \"import json;p='/home/u/.cursor/hooks.json';json.dump({},open(p,'w'))\"",
        "node -e \"require('fs').writeFileSync(process.env.HOME+'/.cursor/hooks.json','{}')\"",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// Reading the file is how a person or an agent sees what is wired.
#[test]
fn reading_cursors_hook_file_is_not_refused() {
    for line in ["cat ~/.cursor/hooks.json", "jq . ~/.cursor/hooks.json"] {
        assert_ne!(verdict(line), "deny", "{line}");
    }
}
