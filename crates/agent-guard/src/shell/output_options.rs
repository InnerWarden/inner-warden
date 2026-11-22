//! The files a command writes through an option of its own, read as the
//! redirections they are, and a redirection into another process's open
//! file. Measured 2026-11-21 on main d6e444f, each allowed:
//!
//! - `sort -o /etc/passwd x`, `sort --output=/etc/passwd x`, `tcpdump -w
//!   /etc/passwd` and `rsync --log-file=/etc/passwd a b` write the file the
//!   option names, as `sort x > /etc/passwd` does, which is refused.
//! - `echo hi > /proc/1234/fd/0` writes into a stream of another process,
//!   which the line does not show.

/// Long options that name the file a program writes, for any program:
/// `--output=FILE` or `--output FILE`. A program that takes `--output` for
/// a format (`--output=json`) is read as writing a file of that name in
/// its folder, which no rule holds against it.
const LONG_OUTPUTS: &[&str] = &[
    "--output",
    "--outfile",
    "--output-file",
    "--output-document",
    "--log-file",
    "--logfile",
    "--write-batch",
    "--only-write-batch",
    "--dump-header",
    "--cookie-jar",
    "--stderr",
    "--trace",
    "--trace-ascii",
    "--append-output",
];

/// A program whose short options name the file it writes: the letters that
/// do, and the other letters that take a value (so a cluster ends there).
struct ShortOutputs {
    program: &'static str,
    output: &'static str,
    valued: &'static str,
}

/// Compilers and linkers are not here: `cc -o app main.c` writes a program
/// the line may then run, and that file is not text the line printed.
const SHORT_OUTPUTS: &[ShortOutputs] = &[
    ShortOutputs {
        program: "sort",
        output: "o",
        valued: "kStT",
    },
    ShortOutputs {
        program: "curl",
        output: "oDc",
        valued: "AbCdeEFHKmPQrTuUwxXyYz",
    },
    ShortOutputs {
        program: "wget",
        output: "Ooa",
        valued: "eBiPtTwQUlADIXRhY",
    },
    ShortOutputs {
        program: "tcpdump",
        output: "w",
        valued: "BcCDEFGiIjJmMrsTVWyzZ",
    },
    ShortOutputs {
        program: "tshark",
        output: "w",
        valued: "aAbBcCdDeEfFhHiKlLMNoOrRsSTuYzX",
    },
    ShortOutputs {
        program: "dumpcap",
        output: "w",
        valued: "aAbBcdfiNsy",
    },
    ShortOutputs {
        program: "ssh",
        output: "E",
        valued: "bBcDeFiIJlLmOopQRSwW",
    },
];

/// The files the command `words` runs (from `at`, its program) writes
/// through an option: [`LONG_OUTPUTS`], the letters of [`SHORT_OUTPUTS`],
/// `dd`'s `of=` is not here: the rules that read where a line writes
/// read it already, each in its own way (a startup file written by `dd`
/// from a file is held for review, as `cp` is).
fn option_outputs(words: &[String], at: usize) -> Vec<String> {
    let program = crate::threats::token_basename(&words[at]).to_ascii_lowercase();
    let short = SHORT_OUTPUTS.iter().find(|row| row.program == program);
    let mut found = Vec::new();
    let mut index = at + 1;
    while let Some(word) = words.get(index) {
        index += 1;
        if word == "--" {
            break;
        }
        if let Some(long) = word.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value.to_owned())),
                None => (long, None),
            };
            if LONG_OUTPUTS.contains(&format!("--{name}").as_str()) {
                match value {
                    Some(value) => found.push(value),
                    None => {
                        if let Some(next) = words.get(index) {
                            found.push(next.clone());
                            index += 1;
                        }
                    }
                }
            }
            continue;
        }
        let Some(row) = short else { continue };
        let Some(letters) = word.strip_prefix('-').filter(|letters| !letters.is_empty()) else {
            continue;
        };
        for (offset, letter) in letters.char_indices() {
            let output = row.output.contains(letter);
            if !output && !row.valued.contains(letter) {
                continue;
            }
            let rest = &letters[offset + letter.len_utf8()..];
            let value = if rest.is_empty() {
                index += 1;
                words.get(index - 1).cloned()
            } else {
                Some(rest.to_owned())
            };
            if output {
                found.extend(value);
            }
            break;
        }
    }
    found
}

/// A file name written back into a line as a redirection's target as it
/// stands: one with a blank, a quote, an escape, a pattern or an operator
/// in it is not.
fn plain_target(file: &str) -> bool {
    !file.is_empty()
        && !file.starts_with('-')
        && file.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '/' | '.'
                        | '_'
                        | '-'
                        | '~'
                        | '+'
                        | ':'
                        | ','
                        | '@'
                        | '%'
                        | '$'
                        | '{'
                        | '}'
                        | '='
                )
        })
}

/// The line with each command that writes a file through an option
/// followed by a redirection of its output to that file (`sort -o F x` is
/// read as `sort -o F x > F`), so every rule that reads where a line
/// writes reads it. A segment with a here-document or a line break, or a
/// file name that is not plain ([`plain_target`]), is left as written.
/// `None` when nothing changes.
pub(crate) fn outputs_as_redirections(line: &str) -> Option<String> {
    let base = line.as_ptr() as usize;
    let mut additions: Vec<(usize, String)> = Vec::new();
    for segment in crate::threats::shell_command_segments(line) {
        let Some(offset) = (segment.as_ptr() as usize).checked_sub(base) else {
            continue;
        };
        if line.get(offset..offset + segment.len()) != Some(segment)
            || segment.contains("<<")
            || segment.contains('\n')
        {
            continue;
        }
        let words = crate::threats::shell_tokens(segment);
        let Some(at) = crate::threats::effective_command_index(&words) else {
            continue;
        };
        let files: Vec<String> = option_outputs(&words, at)
            .into_iter()
            .filter(|file| plain_target(file))
            .collect();
        if files.is_empty() {
            continue;
        }
        let redirections: String = files.iter().map(|file| format!(" > {file}")).collect();
        additions.push((offset + segment.len(), redirections));
    }
    if additions.is_empty() {
        return None;
    }
    let mut read = line.to_owned();
    for (at, with) in additions.into_iter().rev() {
        read.insert_str(at, &with);
    }
    Some(read)
}

/// The first file of `/proc/<pid>/fd/` (or `/proc/<pid>/task/<tid>/fd/`) the
/// line writes into, through a redirection or `tee`, for a process that is
/// not the shell's own: `self`, `thread-self`, `$$` and `$BASHPID` are the
/// line's own; any other number or name is another process, whose stream
/// the line does not show.
pub(crate) fn writes_into_another_process(line: &str) -> Option<String> {
    let mut targets = crate::threats::lexical_output_redirect_targets(line);
    for segment in crate::threats::shell_command_segments(line) {
        targets.extend(crate::threats::tee_write_targets(
            &crate::threats::shell_tokens(segment),
        ));
    }
    targets
        .into_iter()
        .find(|target| another_process_stream(target))
}

/// Whether `target` names an open file of a process that is not the
/// line's own.
fn another_process_stream(target: &str) -> bool {
    let target = target.trim_matches(|c| c == '"' || c == '\'');
    let Some(rest) = target.strip_prefix("/proc/") else {
        return false;
    };
    let mut parts = rest.split('/').filter(|part| !part.is_empty());
    let Some(process) = parts.next() else {
        return false;
    };
    let mut next = parts.next();
    if next == Some("task") {
        parts.next();
        next = parts.next();
    }
    next == Some("fd")
        && !matches!(
            process,
            "self" | "thread-self" | "$$" | "${$}" | "$BASHPID" | "${BASHPID}"
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_output_option_is_read_as_a_redirection() {
        assert_eq!(
            outputs_as_redirections("sort -o /etc/passwd x").as_deref(),
            Some("sort -o /etc/passwd x > /etc/passwd")
        );
        assert_eq!(
            outputs_as_redirections("sort -uo/etc/passwd x; ls").as_deref(),
            Some("sort -uo/etc/passwd x > /etc/passwd; ls")
        );
        assert_eq!(
            outputs_as_redirections("sort -k 2 -o out x").as_deref(),
            Some("sort -k 2 -o out x > out")
        );
        assert_eq!(
            outputs_as_redirections("curl -sSLo f https://x").as_deref(),
            Some("curl -sSLo f https://x > f")
        );
        assert_eq!(outputs_as_redirections("dd if=a of=b bs=1"), None);
        assert_eq!(
            outputs_as_redirections("rsync --log-file /tmp/l a b").as_deref(),
            Some("rsync --log-file /tmp/l a b > /tmp/l")
        );
        // `-t` of sort takes the separator: the `o` is its value.
        assert_eq!(outputs_as_redirections("sort -to x"), None);
        assert_eq!(outputs_as_redirections("ls -o /etc"), None);
        assert_eq!(outputs_as_redirections("sort -- -o x"), None);
        assert_eq!(outputs_as_redirections("sort -o 'a b' x"), None);
    }

    #[test]
    fn only_another_process_stream_is_found() {
        for line in [
            "echo hi > /proc/1234/fd/0",
            "echo hi >/proc/1/fd/1",
            "echo hi >> /proc/$PPID/fd/1",
            "echo hi | tee /proc/77/fd/2",
            "echo hi > /proc/9/task/9/fd/1",
        ] {
            assert!(writes_into_another_process(line).is_some(), "{line}");
        }
        for line in [
            "echo hi > /proc/self/fd/1",
            "echo hi > /proc/$$/fd/2",
            "echo hi > /dev/fd/2",
            "cat /proc/1234/fd/0",
            "echo hi 2>&1",
            "echo '> /proc/1/fd/1'",
        ] {
            assert!(writes_into_another_process(line).is_none(), "{line}");
        }
    }
}
