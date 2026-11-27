//! A shell line a search hands its finds to removes them by any name it
//! binds them to.
//!
//! Measured on main on 2026-11-19: `find ~/.ssh -exec sh -c 'rm -f "$1"' _
//! {} \;` was denied, and `find ~/.ssh -exec sh -c 'for f; do rm -f "$f";
//! done' _ {} +` was allowed: the loop variable holds the same finds as
//! `$1`. Any name the `-c` line binds to its positional arguments (`for
//! f`, `for f in "$@"`, `read f` beside them, `f=$1`) is the root of the
//! search when a removal takes it.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

#[test]
fn a_name_bound_to_what_the_search_hands_over_is_the_search_root() {
    for line in [
        "find ~/.ssh -exec sh -c 'for f; do rm -f \"$f\"; done' _ {} +",
        "find ~/.ssh -exec sh -c 'for f do rm -f \"$f\"; done' _ {} +",
        "find ~/.ssh -exec sh -c 'for f in \"$@\"; do rm -f \"$f\"; done' _ {} +",
        "find ~/.ssh -exec sh -c 'printf \"%s\\n\" \"$@\" | while read f; do rm -f \"$f\"; done' _ {} +",
        "find ~/.ssh -exec sh -c 'printf \"%s\\n\" \"$@\" | while IFS= read -r f; do rm -f -- \"$f\"; done' _ {} +",
        "find ~/.ssh -exec bash -c 'f=$1; rm -f \"$f\"' _ {} \\;",
        "find ~/.ssh -exec bash -c 'f=\"$1\"; g=$f; rm -f \"$g\"' _ {} \\;",
        "find ~/.ssh -exec sh -c 'for f; do shred -u \"${f}\"; done' _ {} +",
        "find ~ -exec sh -c 'for f; do rm -rf \"$f\"; done' _ {} +",
        "find / -maxdepth 1 -exec sh -c 'for d; do rm -rf \"$d\"; done' sh {} +",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

#[test]
fn a_bound_name_in_a_narrowed_search_or_a_project_folder_is_not() {
    for line in [
        "find . -name '*.pyc' -exec sh -c 'for f; do rm -f \"$f\"; done' _ {} +",
        "find ~ -name '*.tmp' -exec sh -c 'for f; do rm -f \"$f\"; done' _ {} +",
        "find ./dist -exec sh -c 'for f; do rm -rf \"$f\"; done' _ {} +",
        "find . -exec sh -c 'for f; do echo \"$f\"; done' _ {} +",
        "find . -type f -exec sh -c 'for f; do mv \"$f\" \"$f.bak\"; done' _ {} +",
        // A loop over a list of its own removes that list, not the finds.
        "find ~/.ssh -exec sh -c 'for f in /tmp/a; do rm -f \"$f\"; done' _ {} +",
        // A name not bound to the finds (`$fx` is not `$f`).
        "find ~/.ssh -exec sh -c 'for f; do rm -f \"$fx\"; done' _ {} +",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}
