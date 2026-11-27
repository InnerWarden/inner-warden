//! Tests that kill mutants the nightly diff run found surviving in
//! `shell.rs` (2026-11-27): the notes `cat` writes, the commands that only
//! show files, and the code an interpreter is handed with `-c`.

use super::*;

/// The first command of `line` as the word reader gives it.
fn first(line: &str) -> crate::shell_words::Command {
    crate::shell_words::read_line(line)
        .commands
        .into_iter()
        .next()
        .expect("a command")
}

#[test]
fn cat_with_an_operand_or_a_lone_dash_writes_no_notes() {
    assert!(text_written_by_cat_blanked("cat <<'EOF' > NOTES.md\nhi\nEOF").is_some());
    assert!(text_written_by_cat_blanked("cat -s <<'EOF' > NOTES.md\nhi\nEOF").is_some());
    assert_eq!(
        text_written_by_cat_blanked("cat other.txt <<'EOF' > NOTES.md\nhi\nEOF"),
        None
    );
    assert_eq!(
        text_written_by_cat_blanked("cat - <<'EOF' > NOTES.md\nhi\nEOF"),
        None
    );
}

#[test]
fn a_command_that_shows_files_is_plain_unpiped_and_reads_nothing() {
    assert!(command_shows_files_only(&first("cat notes.md")));
    assert!(command_shows_files_only(&first("head -n 3 notes.md")));
    assert!(!command_shows_files_only(&first("cat notes.md | head")));
    assert!(!command_shows_files_only(&first("cat $F")));
    assert!(!command_shows_files_only(&first("cat < notes.md")));
    assert!(!command_shows_files_only(&first("cat <<< hi")));
}

#[test]
fn code_an_interpreter_is_handed_with_c_is_read_for_the_file_written() {
    assert!(inline_shell_program_stages_stdin_ast(
        "cat > /tmp/x.sh; python3 -c 'import os; os.system(\"/tmp/x.sh\")'"
    ));
    assert!(!inline_shell_program_stages_stdin_ast(
        "cat > /tmp/x.sh; python3 -c 'print(1)'"
    ));
}
