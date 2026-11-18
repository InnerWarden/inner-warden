//! Tests that kill mutants the weekly cargo-mutants sweep found surviving in
//! `threats.rs` (run 42585938875, 2026-11-09), all in
//! `lexical_sensitive_output_redirect`: the bounded lexical scan that still
//! refuses a write into a login key, a password file or the sudo rules when
//! the structural redirect walk runs out of budget.

use super::*;

/// The reason `check_sensitive_download_write` gives for a write into an
/// authentication or shell startup file.
const OVERWRITE: Option<(&str, u32)> = Some((
    "command overwrites authentication or shell startup file",
    50,
));

/// Runs `check` on `content` on a thread of its own and hands back what it
/// returned.
///
/// Most mutants of the scan move its index backwards or not at all, so the
/// scan never returns. An older test in `threats.rs` runs the same scan on a
/// padded command, and a scan that never returns there keeps the whole test
/// binary from ever exiting, so failing only this test would not be enough:
/// the run would still end in a timeout. A scan that has not returned after
/// ten seconds (it takes microseconds) therefore ends the test binary with a
/// failing status, after saying why on stderr.
fn within_deadline<T: Send + 'static>(content: &str, check: fn(&str) -> T) -> T {
    use std::io::Write;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::Duration;

    let owned = content.to_string();
    let (done_tx, done_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done_tx.send(check(&owned));
    });
    match done_rx.recv_timeout(Duration::from_secs(10)) {
        Ok(verdict) => verdict,
        Err(RecvTimeoutError::Disconnected) => {
            panic!("the redirect scan panicked on {content:?}")
        }
        Err(RecvTimeoutError::Timeout) => {
            let _ = writeln!(
                std::io::stderr(),
                "the lexical redirect scan never returned on {content:?}: its index \
                 does not advance; ending the test binary so the hang cannot stall the run"
            );
            std::process::exit(101);
        }
    }
}

/// The lexical scan's verdict on `content`, under the deadline.
fn lexical(content: &str) -> bool {
    within_deadline(content, lexical_sensitive_output_redirect)
}

/// `content` followed by enough empty commands that the structural redirect
/// walk runs out of budget before it reaches `content`, so only the lexical
/// scan can see what `content` writes.
fn past_the_walk_budget(content: &str) -> String {
    let padded = format!("{content};{}", "true;".repeat(1_500));
    assert!(
        !shell_output_redirect_targets(&padded).1,
        "premise: the structural walk must give up on the padded command, \
         or the lexical scan is never asked: {content}"
    );
    padded
}

/// An unquoted `>` followed by a credential path is a write into that path,
/// with or without blanks between the operator and the path. This is the
/// whole purpose of the scan: each step that reads the operator, skips the
/// blanks and reads the destination has to move forward, and the scan has to
/// stop at the end of the text without reading past it.
///
/// FAILS ON REVERT: replace lexical_sensitive_output_redirect -> bool with
/// false; replace < with ==, or with >, in `while index < bytes.len()`;
/// replace += with -= in the `index += 1` after the `>`; replace += with -=,
/// or with *=, in the blank skip and in the destination read; replace < with
/// ==, or with >, in `start < index`; replace == with != in the `>>` check.
#[test]
fn an_unquoted_redirect_into_a_credential_file_is_a_write() {
    for content in [
        "echo k > /etc/shadow",
        "echo k >/etc/shadow",
        "echo k > \t /etc/shadow",
        "printf key > ~/.ssh/authorized_keys",
        "cat new >/etc/sudoers.d/agent",
    ] {
        assert!(
            lexical(content),
            "a redirect into a credential file was not seen as a write: {content}"
        );
    }
}

/// `>>` appends to the file it names, which is as much a write into a login
/// key as `>`. The second `>` is consumed with the first, and the path right
/// after it is the destination even when no blank separates them.
///
/// FAILS ON REVERT: replace += with -= in the `index += 1` that consumes the
/// second `>`; replace == with != in the `>>` check.
#[test]
fn an_append_redirect_into_a_credential_file_is_a_write() {
    for content in [
        "printf key >> /root/.ssh/authorized_keys",
        "printf key >>/root/.ssh/authorized_keys",
        "cat rule >>/etc/sudoers",
    ] {
        assert!(
            lexical(content),
            "an append into a credential file was not seen as a write: {content}"
        );
    }
}

/// Text with no redirect is read to its end and comes back clean. The scan
/// must step over every ordinary byte and stop at the last one.
///
/// FAILS ON REVERT: replace lexical_sensitive_output_redirect -> bool with
/// true; replace < with <= in `while index < bytes.len()` (it reads past the
/// end); replace += with -=, or with *=, in the `index += 1` that steps over
/// an ordinary byte.
#[test]
fn text_with_no_redirect_is_read_to_its_end_and_is_clean() {
    for content in ["echo hello", "true", "ls -la /tmp"] {
        assert!(
            !lexical(content),
            "text with no redirect was reported as a credential write: {content}"
        );
    }
}

/// A credential path that is only an argument is read or printed, not
/// written: `cat /etc/shadow` and `grep root /etc/shadow` change nothing.
/// Only the byte `>` starts a redirect; read any other byte as one and every
/// command that merely names a key file is refused as an overwrite.
///
/// FAILS ON REVERT: replace != with == in `byte != b'>' || single_quoted ||
/// double_quoted`; replace || with && at either `||` of that condition.
#[test]
fn a_credential_path_given_only_as_an_argument_is_not_a_write() {
    for content in [
        "cat /etc/shadow",
        "grep root /etc/shadow",
        "ls ~/.ssh/authorized_keys",
        "cp ~/.ssh/id_rsa backup",
    ] {
        assert!(
            !lexical(content),
            "a command that only names a credential file was refused as a write: {content}"
        );
    }
}

/// A redirect into an ordinary file is not a credential write, even when the
/// command names a credential path elsewhere: only the destination decides.
/// A bare `>` with nothing after it has no destination at all.
///
/// FAILS ON REVERT: replace && with || in `start < index &&
/// is_authentication_write_target(..)`; replace != with == in `byte != b'>'
/// || ...`.
#[test]
fn a_redirect_into_an_ordinary_file_is_not_a_credential_write() {
    for content in [
        "echo k > out.txt",
        "echo k > /tmp/shadow",
        "echo ~/.ssh/authorized_keys > notes.txt",
        "echo k >",
    ] {
        assert!(
            !lexical(content),
            "a redirect into an ordinary file was refused as a credential write: {content}"
        );
    }
}

/// The destination of a redirect ends at a blank or at the next shell
/// operator (`;`, `|`, `&`, `<`, `>`), so a write into `/etc/shadow` glued to
/// the command after it is still a write into `/etc/shadow`. Read the
/// destination to the end of the text instead, and `>/etc/shadow;id` names a
/// file that does not exist.
///
/// FAILS ON REVERT: replace || with && in `current.is_ascii_whitespace() ||
/// matches!(current, ...)`.
#[test]
fn a_destination_ends_at_a_blank_or_at_the_next_shell_operator() {
    for content in [
        "echo k > /etc/shadow && echo done",
        "echo k >/etc/shadow;id",
        "echo k >/etc/shadow|cat",
        "echo k >/etc/shadow&&id",
        "echo k >/etc/shadow</dev/null",
        "echo k >/etc/shadow>/dev/null",
    ] {
        assert!(
            lexical(content),
            "the destination ran on past where it ends and the write was missed: {content}"
        );
    }
}

/// `>&2` duplicates a descriptor: it opens no file, so a credential path
/// after it is an argument (`echo x >&2 /etc/shadow` prints the path). The
/// scan steps past the `&` and keeps reading, so a real redirect later in
/// the same command is still found.
///
/// FAILS ON REVERT: replace += with -= in the `index += 1` that steps past
/// the `&` or `|` after a `>`; replace += with -= in the `index += 1` after
/// the `>`.
#[test]
fn a_duplicated_descriptor_opens_no_file_and_hides_no_later_redirect() {
    assert!(
        !lexical("echo x >&2 /etc/shadow"),
        "a descriptor duplication was read as a write into the path after it"
    );
    assert!(
        lexical("echo x 2>&1 > /etc/shadow"),
        "a redirect into /etc/shadow after a descriptor duplication was missed"
    );
    assert!(
        lexical("echo x >&2; cat k >/etc/shadow"),
        "a redirect into /etc/shadow in a later command was missed"
    );
}

/// Outside quotes a backslash makes the next byte literal. An escaped `"`
/// opens no quoted span, so the `>` after it is a real redirect; an escaped
/// `>` is a literal character handed to the program, not a redirect.
/// Without this an agent hides a credential overwrite behind `\"`, or an
/// escaped `>` in an argument is refused as a write.
///
/// FAILS ON REVERT: delete ! in `byte == b'\\' && !single_quoted`; replace
/// += with -=, or with *=, in the `index += 1` that sets the escape and in
/// the one that steps over the escaped byte.
#[test]
fn a_backslash_outside_quotes_makes_the_next_byte_literal() {
    assert!(
        lexical(r#"echo \" > /etc/shadow"#),
        "an escaped double quote opened a quoted span and hid the redirect after it"
    );
    assert!(
        lexical(r"echo \' > /etc/shadow"),
        "an escaped single quote opened a quoted span and hid the redirect after it"
    );
    assert!(
        !lexical(r"echo \> /etc/shadow"),
        "an escaped `>` is a literal character, not a redirect"
    );
}

/// Inside single quotes a backslash is an ordinary character: `'C:\'` is a
/// complete quoted word, and the `>` after it is a real redirect. Read the
/// backslash as an escape there and it swallows the closing quote, the
/// single-quoted span never ends, and the redirect into `/etc/shadow` is
/// hidden inside it.
///
/// FAILS ON REVERT: delete ! in `byte == b'\\' && !single_quoted`.
#[test]
fn a_backslash_inside_single_quotes_does_not_keep_the_quote_open() {
    assert!(
        lexical(r"echo 'C:\' > /etc/shadow"),
        "a backslash inside single quotes swallowed the closing quote and hid the redirect"
    );
}

/// A single quote opens a span outside double quotes and only there: a `>`
/// inside `'...'` is data, while an apostrophe inside `"..."` is an ordinary
/// character and does not stop the double-quoted span from closing.
///
/// FAILS ON REVERT: delete ! in `byte == b'\'' && !double_quoted`; delete !
/// in `single_quoted = !single_quoted`; replace && with || and replace ==
/// with != in `byte == b'\'' && !double_quoted`; replace += with -=, or with
/// *=, in the `index += 1` after a single quote.
#[test]
fn a_single_quote_opens_a_span_only_outside_double_quotes() {
    assert!(
        !lexical("echo 'x > /etc/shadow'"),
        "a `>` inside single quotes is data, not a redirect"
    );
    assert!(
        lexical(r#"echo "it's" > /etc/shadow"#),
        "an apostrophe inside double quotes kept the quote open and hid the redirect"
    );
    assert!(
        lexical("echo 'x' > /etc/shadow"),
        "a closed single-quoted word hid the redirect after it"
    );
}

/// A double quote opens a span outside single quotes and only there: a `>`
/// inside `"..."` is data, while a `"` inside `'...'` is an ordinary
/// character and does not stop the single-quoted span from closing.
///
/// FAILS ON REVERT: delete ! in `byte == b'"' && !single_quoted`; delete !
/// in `double_quoted = !double_quoted`; replace == with != in `byte == b'"'
/// && !single_quoted`; replace += with -=, or with *=, in the `index += 1`
/// after a double quote.
#[test]
fn a_double_quote_opens_a_span_only_outside_single_quotes() {
    assert!(
        !lexical(r#"echo "x > /etc/shadow""#),
        "a `>` inside double quotes is data, not a redirect"
    );
    assert!(
        lexical(r#"echo 'say "hi' > /etc/shadow"#),
        "a double quote inside single quotes kept the quote open and hid the redirect"
    );
    assert!(
        lexical(r#"echo "x" > /etc/shadow"#),
        "a closed double-quoted word hid the redirect after it"
    );
}

/// A quoted destination is read from its opening quote to its closing
/// quote, blanks included, so `> "/home/a b/.ssh/authorized_keys"` is a
/// write into that login key and `> "/etc/shadow"` a write into the password
/// file.
///
/// FAILS ON REVERT: replace == with != in `if current == active`; replace +=
/// with -=, or with *=, in the `index += 1` inside the quoted span and in the
/// one after the opening quote.
#[test]
fn a_quoted_destination_is_read_to_its_closing_quote() {
    for content in [
        r#"echo k > "/etc/shadow""#,
        "echo k > '/etc/shadow'",
        r#"echo k > "/home/a b/.ssh/authorized_keys""#,
        "echo k > '/home/a b/.ssh/authorized_keys'",
    ] {
        assert!(
            lexical(content),
            "the quoted destination was not read whole and the write was missed: {content}"
        );
    }
}

/// The screening verdict, when the structural walk gives up: a command that
/// starts with a write into `/etc/shadow` and is padded with empty commands
/// is still refused as a credential overwrite. Only the lexical scan sees
/// the write there, and it sees it because the destination ends at the `;`.
///
/// FAILS ON REVERT: replace lexical_sensitive_output_redirect -> bool with
/// false; replace || with && in `current.is_ascii_whitespace() ||
/// matches!(current, ...)`.
#[test]
fn a_padded_credential_overwrite_is_still_refused() {
    for content in [
        "printf k > /etc/shadow",
        "printf key >>~/.ssh/authorized_keys",
    ] {
        let padded = past_the_walk_budget(content);
        assert_eq!(
            within_deadline(&padded, check_sensitive_download_write),
            OVERWRITE,
            "a credential overwrite past the structural walk's budget was let through: {content}"
        );
    }
}

/// The screening verdict, when the structural walk gives up: a padded
/// command that only reads a credential file, or writes an ordinary one, is
/// not an overwrite. Without this every long command that names a key file
/// would be refused.
///
/// FAILS ON REVERT: replace lexical_sensitive_output_redirect -> bool with
/// true; replace != with == in `byte != b'>' || ...`; replace || with && at
/// either `||` of that condition; replace && with || in `start < index &&
/// ...`.
#[test]
fn a_padded_read_of_a_credential_file_is_not_an_overwrite() {
    for content in [
        "cat ~/.ssh/authorized_keys",
        "grep root /etc/shadow > out.txt",
    ] {
        let padded = past_the_walk_budget(content);
        assert_eq!(
            within_deadline(&padded, check_sensitive_download_write),
            None,
            "a padded read of a credential file was refused as an overwrite: {content}"
        );
    }
}
