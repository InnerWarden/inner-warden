//! Two readings of a line the shell runs before the guard's own words are
//! reached.
//!
//! * `HOME` given by `read` (the text of a here-string, a here-document or
//!   an `echo` piped in) or by `printf -v`, the name spelled whole or by
//!   braces, is the `HOME` that `~` and `$HOME` stand for afterwards, as
//!   one given by `export` already was: `read -r HOME <<< /etc; rm -rf
//!   ~/innerwarden` removes the guard's configuration folder.
//! * A here-document whose delimiter is not quoted runs its backtick
//!   substitutions before `cat` reads the body, as it runs `$(...)`: they
//!   are commands. A quoted delimiter, or an escaped backtick, keeps the
//!   body text.
//!
//! Measured 2026-11-26 on the branch before the change: every refused line
//! below was allowed. Asserted through [`analyze_command`], the entry point
//! the hook uses.

use innerwarden_agent_guard::mcp::analyze_command;

/// The value is read where `export` was read: a removal of the guard's
/// folder under the `HOME` the line set.
const HOME_SET: &[&str] = &[
    "read -r HOME <<< /etc; rm -rf ~/innerwarden",
    "read -r HOME <<< /etc; cd ~ && rm -rf innerwarden",
    "IFS= read -r HOME <<< /etc; rm -rf ~/innerwarden",
    "IFS= read -r HOME <<< /etc; cd ~ && rm -rf innerwarden",
    "read -r {HO,}ME <<< /etc; rm -rf ~/innerwarden",
    "read -r {HO,}ME <<< /etc; cd ~ && rm -rf innerwarden",
    "printf -v HOME /etc; rm -rf ~/innerwarden",
    "printf -v HOME /etc; cd ~ && rm -rf innerwarden",
    "printf -v HOME %s /etc; rm -rf ~/innerwarden",
    "read HOME <<< /etc; rm -rf $HOME/innerwarden",
    "read -r HOME <<'X'\n/etc\nX\nrm -rf ~/innerwarden",
    "echo /etc | { read -r HOME; rm -rf ~/innerwarden; }",
];

/// Another name read, or a folder that holds nothing of the guard's.
const HOME_KEPT: &[&str] = &[
    "read -r name <<< /etc; rm -rf ~/build",
    "printf -v NAME %s /etc; rm -rf ~/build",
    "read -r HOME_DIR <<< /etc; rm -rf ~/build",
    "read -r HOME <<< /tmp/x; rm -rf ~/build",
    "printf -v HOME /tmp/x; rm -rf ~/innerwarden",
];

/// Backticks in a body the shell expands.
const BACKTICKS_RUN: &[&str] = &[
    "cat <<EOF\n`innerwarden uninstall --yes`\nEOF",
    "cat <<EOF\nnote: `innerwarden uninstall --yes`\nEOF",
    "cat > notes.md <<EOF\n`innerwarden uninstall --yes`\nEOF",
    "cat > notes.md <<EOF\n`rm -rf ~`\nEOF",
    "cat <<EOF\n`systemctl stop innerwarden-agent`\nEOF",
];

/// A body the shell hands over as it is.
const BACKTICKS_TEXT: &[&str] = &[
    "cat <<'EOF'\n`innerwarden uninstall --yes` removes the guard\nEOF",
    "cat <<\"EOF\"\n`innerwarden uninstall --yes`\nEOF",
    "cat <<\\EOF > notes.md\nrun `innerwarden uninstall --yes` to remove it\nEOF",
    "cat > notes.md <<EOF\nrun \\`innerwarden uninstall --yes\\` to remove it\nEOF",
    "cat <<EOF\nbuilt on `date`\nEOF",
];

/// FAILS ON REVERT of `read_gives_home` and `printf_gives_home` in
/// `threats/guard_file_targets.rs` (the value was one the text did not
/// show): every line is allowed.
#[test]
fn home_given_by_read_or_printf_is_where_the_tilde_points() {
    for line in HOME_SET {
        let analysis = analyze_command(line, None);
        assert_eq!(analysis.recommendation, "deny", "{line}: {analysis:?}");
    }
}

#[test]
fn another_name_or_another_folder_stays_allowed() {
    for line in HOME_KEPT {
        let analysis = analyze_command(line, None);
        assert_eq!(analysis.recommendation, "allow", "{line}: {analysis:?}");
    }
}

/// FAILS ON REVERT of the backtick runs `mask_data_heredoc` puts back
/// (`heredoc_body_expands`, `backtick_runs` in `shell.rs`): the bodies
/// are masked as data and every line is allowed.
#[test]
fn backticks_in_an_unquoted_here_document_are_commands() {
    for line in BACKTICKS_RUN {
        let analysis = analyze_command(line, None);
        assert_eq!(analysis.recommendation, "deny", "{line}: {analysis:?}");
    }
}

#[test]
fn a_quoted_delimiter_or_an_escaped_backtick_keeps_the_body_text() {
    for line in BACKTICKS_TEXT {
        let analysis = analyze_command(line, None);
        assert_eq!(analysis.recommendation, "allow", "{line}: {analysis:?}");
    }
}
