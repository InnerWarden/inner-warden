//! Tests that kill mutants the weekly cargo-mutants sweep found surviving in
//! `threats.rs` (run 42450235934, 2026-11-08).

use super::*;

/// An obfuscated data-destruction command is judged on its de-obfuscated form.
///
/// `check_data_destruction` tries the raw text first and only normalises when
/// nothing matched. The `normalized == content` test is the shortcut for "there
/// was nothing to de-obfuscate". Inverted, every command that normalisation
/// DID change is dropped as clean, so `my''sql` (empty quotes the shell
/// removes) walks past the database-wipe pattern that `mysql` trips.
///
/// FAILS ON REVERT: `normalized == content` replaced with `normalized != content`
/// in `check_data_destruction`.
#[test]
fn data_destruction_hidden_by_empty_quotes_is_still_caught() {
    let plain = check_data_destruction("rm -rf /var/lib/mysql");
    let hidden = check_data_destruction("rm -rf /var/lib/my''sql");
    assert!(
        plain.is_some(),
        "the plain database wipe must be caught for this test to mean anything"
    );
    assert_eq!(
        hidden, plain,
        "empty quotes inside the path must not hide a database wipe: the \
         de-obfuscated form was never checked"
    );
}

/// An obfuscated untrusted package source is judged on its de-obfuscated form.
///
/// Same shape as the data-destruction check: raw first, normalised only when
/// the raw text matched nothing, and `normalized == content` means there was
/// nothing to rewrite. Inverted, `http''://` (the shell reads it as `http://`)
/// hides a plaintext package index from the screen.
///
/// FAILS ON REVERT: `normalized == content` replaced with `normalized != content`
/// in `check_untrusted_software_source`.
#[test]
fn untrusted_package_index_hidden_by_empty_quotes_is_still_caught() {
    let plain = check_untrusted_software_source(
        "pip install --index-url http://pypi.example.internal/simple requests",
    );
    let hidden = check_untrusted_software_source(
        "pip install --index-url http''://pypi.example.internal/simple requests",
    );
    assert!(
        plain.is_some(),
        "the plain plaintext-HTTP index must be caught for this test to mean anything"
    );
    assert_eq!(
        hidden, plain,
        "empty quotes inside the URL must not hide a plaintext package index: \
         the de-obfuscated form was never checked"
    );
}

/// A command longer than one piece is cut into pieces no longer than
/// `NORMALIZE_BLOCK_BYTES`, each ending at a command separator.
///
/// `limit >= s.len()` is what decides that the current piece is the last one.
/// Inverted, the very first piece of any long command is declared the last
/// and swallows the whole input, so the per-piece bound on rewrite work is
/// gone and nothing is ever cut at a separator.
///
/// FAILS ON REVERT: `limit >= s.len()` replaced with `limit < s.len()` in
/// `normalize_blocks`.
#[test]
fn a_long_command_is_cut_into_pieces_at_separators() {
    // `a;` repeated: a separator ends every second byte, so the first piece
    // ends exactly at the piece limit and the rest is a second piece.
    let repeats = NORMALIZE_BLOCK_BYTES / 2 + NORMALIZE_BLOCK_BYTES / 4;
    let s = "a;".repeat(repeats);
    let pieces = normalize_blocks(&s);
    let expected = [
        (0, NORMALIZE_BLOCK_BYTES, false),
        (NORMALIZE_BLOCK_BYTES, s.len(), false),
    ];
    assert_eq!(
        pieces, expected,
        "a command of one and a half pieces must be cut in two at the last \
         separator in reach, not handed over as one piece"
    );
    for (start, end, _) in &pieces {
        assert!(
            end - start <= NORMALIZE_BLOCK_BYTES,
            "piece {start}..{end} is longer than NORMALIZE_BLOCK_BYTES"
        );
    }
}

/// After a forced cut, the next piece starts just after a real space, so it
/// begins at a whole word.
///
/// The test is `(i == 0 || bytes[i - 1] != b'\\')`: a space counts unless a
/// backslash escapes it. With `||` turned into `&&` no space past offset 0
/// ever counts, and the piece starts at the raw fallback offset in the middle
/// of a word, which is how an overlap once invented `rm -rf /` out of the
/// tail of `confirm`.
///
/// FAILS ON REVERT: `i == 0 || bytes[i - 1] != b'\\'` replaced with
/// `i == 0 && bytes[i - 1] != b'\\'` in `overlap_start`.
#[test]
fn overlap_after_a_forced_cut_starts_after_an_unescaped_space() {
    let s = format!(
        "{} {}",
        "a".repeat(NORMALIZE_BLOCK_OVERLAP),
        "b".repeat(NORMALIZE_BLOCK_OVERLAP)
    );
    let end = NORMALIZE_BLOCK_OVERLAP + NORMALIZE_BLOCK_OVERLAP / 2;
    assert_eq!(
        overlap_start(&s, end),
        NORMALIZE_BLOCK_OVERLAP + 1,
        "the overlap must start at the word after the space, not at the \
         fallback offset in the middle of a word"
    );
}

/// After a forced cut, a backslash-escaped space is part of a word and is not
/// where the next piece may start.
///
/// `bytes[i - 1] != b'\\'` is what skips an escaped space. Flipped to `==`,
/// ONLY escaped spaces count, so the piece starts inside the escaped word and
/// every real space is ignored.
///
/// FAILS ON REVERT: `bytes[i - 1] != b'\\'` replaced with `bytes[i - 1] == b'\\'`
/// in `overlap_start`.
#[test]
fn overlap_after_a_forced_cut_never_starts_after_an_escaped_space() {
    // a...a, backslash, space, ten b, space, c...c: the escaped space sits at
    // OVERLAP + 1, the first real space at OVERLAP + 12.
    let s = format!(
        "{}\\ {} {}",
        "a".repeat(NORMALIZE_BLOCK_OVERLAP),
        "b".repeat(10),
        "c".repeat(NORMALIZE_BLOCK_OVERLAP)
    );
    let end = NORMALIZE_BLOCK_OVERLAP + NORMALIZE_BLOCK_OVERLAP / 2;
    assert_eq!(
        overlap_start(&s, end),
        NORMALIZE_BLOCK_OVERLAP + 13,
        "the overlap must start after the first unescaped space; an escaped \
         space is inside a word"
    );
}

/// An environment assignment needs a valid shell name, and a name cannot
/// start with a digit.
///
/// `(i > 0 && c.is_ascii_digit())` allows digits only after the first
/// character. With `>=` a leading digit is accepted, so `1X=y` is skipped as
/// an assignment and the `rm` after it is taken as the program, while the
/// shell itself would try to run a command literally named `1X=y`.
///
/// FAILS ON REVERT: `i > 0` replaced with `i >= 0` in `is_env_assign`.
#[test]
fn an_assignment_name_cannot_start_with_a_digit() {
    assert!(
        !is_env_assign("1X=y"),
        "`1X` is not a shell name, so `1X=y` is not an assignment"
    );
    assert!(
        is_env_assign("X1=y"),
        "a digit after the first character is a valid name"
    );
    let tokens: Vec<String> = ["1X=y", "rm", "-rf", "/"]
        .iter()
        .map(|t| t.to_string())
        .collect();
    assert_eq!(
        rm_command_index(&tokens),
        None,
        "with `1X=y` as the command word the segment does not run rm"
    );
    let tokens: Vec<String> = ["X1=y", "rm", "-rf", "/"]
        .iter()
        .map(|t| t.to_string())
        .collect();
    assert_eq!(
        rm_command_index(&tokens),
        Some(1),
        "a valid assignment prefix is skipped and rm is the program"
    );
}

/// `timeout` options before the duration are skipped, so the `rm` behind
/// `timeout --preserve-status 5` is still found.
///
/// `while i < tokens.len() && tokens[i].starts_with('-')` walks past the
/// options. With `==` the walk never runs (and indexes past the end when it
/// does), the option is taken as the duration, the real duration as the
/// program, and the system wipe behind it is not recognised.
///
/// FAILS ON REVERT: `i < tokens.len()` replaced with `i == tokens.len()` in the
/// `timeout` arm of `rm_command_index`.
#[test]
fn rm_behind_timeout_with_an_option_is_still_recognised() {
    let tokens: Vec<String> = ["timeout", "--preserve-status", "5", "rm", "-rf", "/etc"]
        .iter()
        .map(|t| t.to_string())
        .collect();
    assert_eq!(
        rm_command_index(&tokens),
        Some(3),
        "the option before the duration must be skipped to reach rm"
    );
    assert!(
        destructive_rm_root("timeout --preserve-status 5 rm -rf /etc"),
        "an rm of /etc behind `timeout --preserve-status 5` is a system wipe"
    );
}

/// `/.` is the root directory spelled another way, and a recursive forced
/// delete of it is a root wipe.
///
/// The first test is `target == "/" || target == "/*" || target == "/."`. With
/// the second `||` turned into `&&`, `/*` is still caught further down but
/// `/.` falls through to the system-directory list, where `.` is not a
/// directory name, and the wipe passes.
///
/// FAILS ON REVERT: `target == "/*" || target == "/."` replaced with
/// `target == "/*" && target == "/."` in `rm_target_is_root_or_system`.
#[test]
fn rm_of_root_spelled_slash_dot_is_a_root_wipe() {
    assert!(
        rm_target_is_root_or_system("/."),
        "`/.` is the root itself and must be a root or system target"
    );
    assert!(
        destructive_rm_root("rm -rf /."),
        "`rm -rf /.` must be recognised as a root wipe"
    );
}

/// Two backtick substitutions in one command are two bodies, and the text
/// between them is not a third.
///
/// After a closing backtick the scan resumes at `j + 1`, just past it. With
/// `j * 1` it resumes ON the closing backtick, reads it as an opening one, and
/// returns the plain text between the two substitutions as code. Then an
/// `echo` with a backtick `date` on each side of the words `rm -rf /`, which
/// only prints those words, is reported as a root wipe.
///
/// FAILS ON REVERT: `(j + 1).min(bytes.len())` replaced with
/// `(j * 1).min(bytes.len())` in `substitution_bodies`.
#[test]
fn text_between_two_backtick_substitutions_is_not_a_body() {
    assert_eq!(
        substitution_bodies("`a` `b`"),
        vec!["a", "b"],
        "two backtick substitutions must give exactly their two bodies"
    );
    assert!(
        !destructive_rm_root("echo `date` rm -rf / `date`"),
        "the words between two substitutions are echo's arguments, not a command"
    );
}

/// A segment ending in a bare `-o` is screened without a crash.
///
/// `tok == "-o" && idx + 1 < tokens.len()` reads the token after `-o` only
/// when there is one. With `||` the bound no longer protects the read, and a
/// trailing `-o` indexes past the end of the token list: the screen panics on
/// a truncated ssh command instead of judging it.
///
/// FAILS ON REVERT: `tok == "-o" && idx + 1 < tokens.len()` replaced with
/// `tok == "-o" || idx + 1 < tokens.len()` in `ssh_identity_use_only`.
#[test]
fn ssh_command_ending_in_a_bare_dash_o_is_screened_without_a_crash() {
    assert!(
        ssh_identity_use_only("ssh -i ~/.ssh/id_rsa deploy@host -o", &|_: &str| false),
        "the key is only used as the identity, so this is key use, not a read"
    );
    assert_eq!(
        check_sensitive_read("ssh -i ~/.ssh/id_rsa deploy@host -o"),
        None,
        "identity-flag key use with a dangling `-o` is not a credential read"
    );
}

/// A backslash escapes the character after it, so `secret\.env` is the path
/// `secret.env` once quotes and escapes are stripped.
///
/// The `b'\\' if i + 1 < b.len()` arm is what drops the backslash and keeps
/// the escaped character. With the guard forced to `false` every backslash is
/// kept as written, and a protected path spelled with an escaped dot (which
/// the shell reads as a plain dot) no longer matches.
///
/// FAILS ON REVERT: match guard `i + 1 < b.len()` replaced with `false` in
/// `strip_quotes_escapes`.
#[test]
fn an_escaped_character_in_a_protected_path_is_unescaped() {
    assert_eq!(
        strip_quotes_escapes("sec\\ret\\.env"),
        "secret.env",
        "each backslash must be dropped and the character after it kept"
    );
    assert_eq!(
        strip_quotes_escapes("end\\"),
        "end\\",
        "a trailing backslash escapes nothing and stays"
    );
    assert_eq!(
        check_protected_read(
            "cat /home/lab/secret\\.env",
            &["/home/lab/secret.env".to_string()],
        ),
        Some("/home/lab/secret.env".to_string()),
        "an escaped dot must not hide a read of a protected path"
    );
}

/// `mktemp -d -p DIR` and `mktemp -d --tmpdir DIR` create the directory under
/// DIR, and a relative execution after `cd` into it is a temp execution there.
///
/// `arguments.get(index + 1)` is the word after `-p` or `--tmpdir`. With
/// `index * 1` it is the flag itself, so the directory becomes `-p/mktemp.d`,
/// which is in no temp directory, and `./x` run from it is no longer seen.
///
/// FAILS ON REVERT: `arguments.get(index + 1)` replaced with
/// `arguments.get(index * 1)` in `mktemp_directory`.
#[test]
fn mktemp_with_a_parent_directory_creates_it_under_that_parent() {
    assert_eq!(
        mktemp_directory("$(mktemp -d -p /dev/shm)"),
        Some("/dev/shm/mktemp.d".to_string()),
        "`-p DIR` names the parent of the new directory"
    );
    assert_eq!(
        mktemp_directory("$(mktemp -d --tmpdir /var/tmp)"),
        Some("/var/tmp/mktemp.d".to_string()),
        "`--tmpdir DIR` names the parent of the new directory"
    );
    assert_eq!(
        check_tmp_execution("cd \"$(mktemp -d -p /dev/shm)\" && ./x"),
        Some(("/dev/shm/", 30)),
        "running ./x after cd into a mktemp directory under /dev/shm is temp execution"
    );
}
