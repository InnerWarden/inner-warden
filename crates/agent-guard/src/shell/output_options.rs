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

/// Whether `--{name}` is one of [`LONG_OUTPUTS`] or, as GNU getopt reads
/// it, an abbreviation of one: `--out=F` and `--o F` are `--output`. An
/// abbreviation of three characters or more, dashes counted, is read as the
/// entry it begins, whether or not another option of the program begins the
/// same way.
fn long_output(name: &str) -> bool {
    let option = format!("--{name}");
    option.len() >= 3 && LONG_OUTPUTS.iter().any(|entry| entry.starts_with(&option))
}

/// The file xxd writes: its second operand, the bytes back from a dump
/// with `-r` (`xxd -r hex.txt out`) or the dump without it.
/// Options come before the operands, as xxd reads them; `-c`, `-g`,
/// `-l`, `-n`, `-o`, `-s` and `-R` (and their long forms) take a value,
/// in the same word or the next. An operand `-` is the standard stream.
fn xxd_output(words: &[String], at: usize) -> Option<String> {
    const VALUED: &[&str] = &[
        "-c",
        "-cols",
        "-g",
        "-groupsize",
        "-l",
        "-len",
        "-n",
        "-name",
        "-o",
        "-offset",
        "-s",
        "-seek",
        "-R",
    ];
    let mut index = at + 1;
    while let Some(word) = words.get(index) {
        if word == "--" {
            index += 1;
            break;
        }
        if word == "-" || !word.starts_with('-') {
            break;
        }
        index += 1;
        // xxd reads `--name` as `-name`.
        let option = word
            .strip_prefix('-')
            .filter(|rest| rest.starts_with('-'))
            .unwrap_or(word);
        if VALUED.contains(&option) {
            index += 1;
        }
    }
    let output = words.get(index + 1)?;
    (output != "-").then(|| output.clone())
}

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
    if program == "xxd" {
        found.extend(xxd_output(words, at));
    }
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
            if long_output(name) {
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

/// The file of `/proc/<pid>/fd/` (or `/proc/<pid>/task/<tid>/fd/`) the
/// line writes into, through a redirection or `tee`, for a process that is
/// not the shell's own: `self`, `thread-self`, `$$` and `$BASHPID` are the
/// line's own; any other number or name is another process, whose stream
/// the line does not show. Of the files the line writes into, one that is
/// not the standard output or error of that process (`fd/0`, its input)
/// is named before one that is; [`ProcessStream::injects`] says which.
pub(crate) fn writes_into_another_process(line: &str) -> Option<ProcessStream> {
    let mut targets = crate::threats::lexical_output_redirect_targets(line);
    // The folder an earlier `cd` to a path written out moved to: a relative
    // target after it is read from there (`cd /proc && echo x > 1/fd/0`).
    let mut folder: Option<String> = None;
    for segment in crate::threats::shell_command_segments(line) {
        let tokens = crate::threats::shell_tokens(segment);
        if let [cd, to] = tokens.as_slice() {
            if cd == "cd" {
                folder = to.starts_with('/').then(|| to.clone());
                continue;
            }
        }
        let mut written = crate::threats::tee_write_targets(&tokens);
        written.extend(copy_destinations(&tokens));
        if let Some(folder) = &folder {
            written.extend(
                crate::threats::lexical_output_redirect_targets(segment)
                    .into_iter()
                    .chain(written.clone())
                    .filter(|target| {
                        let target = target.trim_matches(|c| c == '"' || c == '\'');
                        !target.is_empty() && !target.starts_with(['/', '~', '$', '&'])
                    })
                    .map(|target| format!("{}/{target}", folder.trim_end_matches('/'))),
            );
        }
        targets.extend(written);
    }
    targets
        .into_iter()
        .filter_map(|target| {
            another_process_stream(&target).map(|injects| ProcessStream { target, injects })
        })
        .max_by_key(|stream| stream.injects)
}

/// Where a copy writes, as [`writes_into_another_process`] asks it: the
/// last operand of `cp`, `install`, `mv` and `rsync` (with two operands
/// or more), the folder of `-t` / `--target-directory`, and `dd`'s `of=`.
fn copy_destinations(tokens: &[String]) -> Vec<String> {
    let Some(at) = crate::threats::effective_command_index(tokens) else {
        return Vec::new();
    };
    let command = crate::threats::token_basename(&tokens[at]).to_ascii_lowercase();
    let args = &tokens[at + 1..];
    match command.as_str() {
        "dd" => args
            .iter()
            .filter_map(|word| word.strip_prefix("of="))
            .map(str::to_string)
            .collect(),
        "cp" | "install" | "mv" | "rsync" => {
            let mut found = Vec::new();
            let mut operands = Vec::new();
            let mut index = 0;
            while let Some(word) = args.get(index) {
                if word == "-t" || word == "--target-directory" {
                    found.extend(args.get(index + 1).cloned());
                    index += 2;
                    continue;
                }
                if let Some(folder) = word.strip_prefix("--target-directory=") {
                    found.push(folder.to_string());
                } else if word == "--" {
                    operands.extend(args[index + 1..].iter().cloned());
                    break;
                } else if !word.starts_with('-') || word == "-" {
                    operands.push(word.clone());
                }
                index += 1;
            }
            if operands.len() >= 2 {
                found.extend(operands.pop());
            }
            found
        }
        _ => Vec::new(),
    }
}

/// A file of another process the line writes into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessStream {
    /// The target as the line wrote it.
    pub(crate) target: String,
    /// True when it is not that process's standard output or error
    /// (`fd/1`, `fd/2`): its input, `fd/0`, or any other open file. A
    /// write into `/proc/1/fd/1` is how a job in a container logs to it.
    pub(crate) injects: bool,
}

/// The components of an absolute path with `.` and `..` resolved as
/// written (`/proc/self/../1/fd/0` is `/proc/1/fd/0`); `None` for a path
/// that is not absolute.
fn lexical_components(path: &str) -> Option<Vec<&str>> {
    let rest = path.strip_prefix('/')?;
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => parts.push(part),
        }
    }
    Some(parts)
}

/// Whether `target` names an open file of a process that is not the
/// line's own: `Some(false)` for its standard output or error, `Some(true)`
/// for any other of its files.
fn another_process_stream(target: &str) -> Option<bool> {
    let target = target.trim_matches(|c| c == '"' || c == '\'');
    let parts = lexical_components(target)?;
    let mut parts = parts.into_iter();
    if parts.next() != Some("proc") {
        return None;
    }
    let process = parts.next()?;
    let mut next = parts.next();
    if next == Some("task") {
        parts.next();
        next = parts.next();
    }
    if next != Some("fd")
        || matches!(
            process,
            "self" | "thread-self" | "$$" | "${$}" | "$BASHPID" | "${BASHPID}"
        )
    {
        return None;
    }
    Some(!matches!(parts.next(), Some("1" | "2")))
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

    /// FAILS ON REVERT of `long_output`: GNU getopt reads an abbreviation
    /// as the option it begins.
    #[test]
    fn an_abbreviated_output_option_is_read_as_the_option() {
        assert_eq!(
            outputs_as_redirections("sort --out=/etc/passwd x").as_deref(),
            Some("sort --out=/etc/passwd x > /etc/passwd")
        );
        assert_eq!(
            outputs_as_redirections("sort --o /etc/passwd x").as_deref(),
            Some("sort --o /etc/passwd x > /etc/passwd")
        );
        assert_eq!(
            outputs_as_redirections("wget --output-doc=f https://x").as_deref(),
            Some("wget --output-doc=f https://x > f")
        );
        assert_eq!(outputs_as_redirections("git diff --stat"), None);
        assert_eq!(outputs_as_redirections("sort --outputs=f x"), None);
    }

    /// FAILS ON REVERT of `xxd_output`: the second operand is written.
    #[test]
    fn the_second_operand_of_xxd_is_read_as_its_output() {
        assert_eq!(
            outputs_as_redirections("xxd -r hex.txt /etc/passwd").as_deref(),
            Some("xxd -r hex.txt /etc/passwd > /etc/passwd")
        );
        assert_eq!(
            outputs_as_redirections("xxd -c 16 -r -p hex out").as_deref(),
            Some("xxd -c 16 -r -p hex out > out")
        );
        assert_eq!(
            outputs_as_redirections("xxd --revert -- hex out").as_deref(),
            Some("xxd --revert -- hex out > out")
        );
        assert_eq!(outputs_as_redirections("xxd -r hex.txt"), None);
        assert_eq!(outputs_as_redirections("xxd -r hex.txt -"), None);
        assert_eq!(outputs_as_redirections("xxd -l 16 app.bin"), None);
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

    /// FAILS ON REVERT of `lexical_components`: `.` and `..` resolved
    /// before the process is read.
    #[test]
    fn dots_in_the_path_are_resolved_before_the_process_is_read() {
        for line in [
            "echo hi > /proc/self/../1/fd/0",
            "echo hi > /proc/self/fd/../../1/fd/0",
            "echo hi > /proc/1/./fd/0",
            "echo hi > //proc//1/fd/0",
            "echo hi > /proc/../proc/1/fd/0",
        ] {
            let stream = writes_into_another_process(line);
            assert!(stream.is_some_and(|s| s.injects), "{line}");
        }
        assert!(writes_into_another_process("echo hi > /proc/self/../self/fd/1").is_none());
    }

    /// FAILS ON REVERT of `ProcessStream::injects`: only the standard
    /// output and error of the other process are its output.
    #[test]
    fn the_output_of_another_process_is_told_from_its_input() {
        for line in [
            "/app/job.sh > /proc/1/fd/1 2>/proc/1/fd/2",
            "echo hi >> /proc/$PPID/fd/1",
            "echo hi | tee /proc/77/fd/2",
        ] {
            let stream = writes_into_another_process(line);
            assert!(stream.is_some_and(|s| !s.injects), "{line}");
        }
        for line in [
            "echo hi > /proc/1234/fd/0",
            "echo hi > /proc/1/fd/3",
            "echo hi > /proc/1/fd/1 2>/proc/1/fd/0",
            "echo hi > /proc/1/fd/$N",
        ] {
            let stream = writes_into_another_process(line);
            assert!(stream.is_some_and(|s| s.injects), "{line}");
        }
    }
}
