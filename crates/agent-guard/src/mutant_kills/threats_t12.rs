//! Tests that kill mutants the nightly diff run found surviving in
//! `threats.rs` (2026-11-27): names spelled out of their braces, the
//! pattern words of `grep` and `rg`, the command `arch` starts and the
//! folder a download is put in.

use super::*;

use std::sync::mpsc;
use std::time::Duration;

fn words(line: &str) -> Vec<String> {
    line.split(' ').map(str::to_owned).collect()
}

#[test]
fn a_parameter_expansion_is_no_brace_group() {
    assert_eq!(
        names_spelled_out("echo ${HO,ME}").as_deref(),
        Some("echo ${HO,ME}")
    );
    assert_eq!(
        names_spelled_out("echo ${X:-{a,b}}").as_deref(),
        Some("echo ${X:-{a,b}}")
    );
    assert_eq!(
        names_spelled_out("echo {HO,}ME").as_deref(),
        Some("echo HOME ME")
    );
}

#[test]
fn a_line_that_may_give_the_home_a_value_is_told_from_one_that_reads_it() {
    assert!(names_home_besides_reading("export HOME=/tmp"));
    assert!(names_home_besides_reading("export {HO,}ME=/tmp"));
    assert!(!names_home_besides_reading("ls $HOME/x ${HOME}/y"));
}

#[test]
fn grep_patterns_given_by_option_are_the_only_patterns() {
    // Two `--regexp`: the first word left is a path, not a pattern.
    assert_eq!(
        search_pattern_words(&words("grep --regexp=a --regexp=b x y")),
        vec![1, 2]
    );
    assert_eq!(search_pattern_words(&words("grep -e foo x y")), vec![2]);
    assert_eq!(
        search_pattern_words(&words("grep -e foo -e bar x y")),
        vec![2, 4]
    );
}

#[test]
fn grep_option_values_are_not_patterns() {
    assert_eq!(
        search_pattern_words(&words("grep --include *.rs foo src")),
        vec![3]
    );
    assert_eq!(search_pattern_words(&words("grep -A 3 foo x")), vec![3]);
    // A lone dash is the input, a path.
    assert_eq!(search_pattern_words(&words("grep foo -")), vec![1]);
}

/// Where the command `arch` (at 0 in `words`) starts runs on a thread: a
/// walk that stops advancing fails the test instead of hanging the run.
fn arch_start(line: &str) -> Option<usize> {
    let owned = words(line);
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(arch_command_start(&owned, 0));
    });
    match done_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(start) => start,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("reading the options of `{line}` never returned")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            panic!("reading the options of `{line}` panicked")
        }
    }
}

#[test]
fn arch_starts_its_command_past_every_option() {
    assert_eq!(arch_start("arch -64 rm -rf x"), Some(2));
    assert_eq!(arch_start("arch -32 -c rm x"), Some(3));
    assert_eq!(arch_start("arch -arch x86_64 -e A=1 rm x"), Some(5));
    assert_eq!(arch_start("arch -x86_64 rm"), Some(2));
    assert_eq!(arch_start("arch -64"), None);
}

#[test]
fn a_download_folder_takes_only_a_name_of_the_downloaders_own() {
    assert_eq!(
        download_output_targets(&words("curl --output-dir /tmp/d -o /etc/x https://ev.io/a")),
        vec!["/etc/x".to_owned()]
    );
    assert_eq!(
        download_output_targets(&words(
            "curl --output-dir /tmp/d -o ~/.ssh/k https://ev.io/a"
        )),
        vec!["~/.ssh/k".to_owned()]
    );
    assert_eq!(
        download_output_targets(&words("curl --output-dir /tmp/d -o k https://ev.io/a")),
        vec!["/tmp/d/k".to_owned()]
    );
}
