//! The SQL client a container or a remote host runs.
//!
//! `docker exec`, `podman exec` and `kubectl exec ... --` run the program
//! written after their own options and the container's name; `ssh` runs
//! the line its words after the destination make. When that program is a
//! SQL client by name ([`sql_text::is_sql_client`]), what it is handed is
//! read as the same client run here would be: SQL that is only data
//! ([`sql_text::sql_text_is_data`]) is data, and nothing else of the line
//! is hidden. Measured 2026-11-25 on the branch at 0e34ac3: `ssh host "sudo
//! docker exec -i c psql ..." <<'SQL'` with an `INSERT` naming the guard,
//! and `docker exec c psql -c "INSERT ..."`, were refused as the guard
//! switched off: `exec` is a program that runs its words, so the
//! projection was in doubt and the line was read as written. Any other
//! program inside (`sh -c`, `bash`, an option this reader does not know)
//! is read as before.

use super::{
    collect_nodes_of_kind, command_arguments, command_words, effective_command_words,
    node_contains_kind, normalized_command_name, parse_bash, project, shell_word, sql_text,
    ssh_client,
};
use std::ops::Range;

/// How many runners deep a client is looked for (`sudo docker exec c sudo
/// psql`).
const RUNNERS_READ: u8 = 4;

/// The name of the SQL client `words` (a command's words, its name first)
/// runs, and where in `words` that name stands: the command itself, behind
/// the wrappers the guard reads through, or behind `docker exec`,
/// `podman exec` or `kubectl exec ... --`.
pub(super) fn sql_client_at(words: &[String], depth: u8) -> Option<(String, usize)> {
    if depth > RUNNERS_READ {
        return None;
    }
    let effective = effective_command_words(words, 0)?;
    let at = words.len() - effective.len();
    let name = normalized_command_name(effective.first()?);
    if sql_text::is_sql_client(&name) {
        return Some((name, at));
    }
    let args: Vec<String> = effective[1..].iter().map(|word| shell_word(word)).collect();
    let program = match name.as_str() {
        "docker" | "podman" => container_exec_program(&args)?,
        "kubectl" => kubectl_exec_program(&args)?,
        _ => return None,
    };
    let at = at + 1 + program;
    let (client, inner) = sql_client_at(&words[at..], depth + 1)?;
    Some((client, at + inner))
}

/// `docker exec` and `podman exec` options that take a value.
const CONTAINER_VALUED: &[&str] = &[
    "-e",
    "--env",
    "--env-file",
    "-u",
    "--user",
    "-w",
    "--workdir",
    "--detach-keys",
];

/// `docker exec` and `podman exec` options that take none.
const CONTAINER_FLAGS: &[&str] = &[
    "-i",
    "--interactive",
    "-t",
    "--tty",
    "-d",
    "--detach",
    "--privileged",
];

/// Where in `args` (the words after `docker` or `podman`) the program
/// `exec` runs stands: after `exec` (or `container exec`), its options and
/// the container. An option not known here, or none of it, is `None`.
fn container_exec_program(args: &[String]) -> Option<usize> {
    let mut index = match args {
        [container, exec, ..] if container == "container" && exec == "exec" => 2,
        [exec, ..] if exec == "exec" => 1,
        _ => return None,
    };
    while let Some(arg) = args.get(index) {
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        if let Some((option, _)) = arg.split_once('=') {
            if !option.starts_with("--") || !CONTAINER_VALUED.contains(&option) {
                return None;
            }
            index += 1;
        } else if CONTAINER_VALUED.contains(&arg.as_str()) {
            index += 2;
        } else if CONTAINER_FLAGS.contains(&arg.as_str())
            || (!arg.starts_with("--") && arg[1..].chars().all(|c| matches!(c, 'i' | 't' | 'd')))
        {
            index += 1;
        } else {
            return None;
        }
    }
    let container = args.get(index)?;
    if container.starts_with('-') {
        return None;
    }
    args.get(index + 1)?;
    Some(index + 1)
}

/// `kubectl` options, before or after `exec`, that take a value.
const KUBECTL_VALUED: &[&str] = &[
    "-n",
    "--namespace",
    "-c",
    "--container",
    "--context",
    "--cluster",
    "--user",
    "--kubeconfig",
    "-s",
    "--server",
    "--request-timeout",
    "--pod-running-timeout",
];

/// `kubectl exec` options that take none.
const KUBECTL_FLAGS: &[&str] = &["-i", "--stdin", "-t", "--tty", "-q", "--quiet"];

/// Where in `args` (the words after `kubectl`) the program `exec` runs
/// stands: the word after `--`, with only known options, `exec` and one
/// pod before it.
fn kubectl_exec_program(args: &[String]) -> Option<usize> {
    let mut index = 0;
    let mut exec = false;
    let mut pod = false;
    while let Some(arg) = args.get(index) {
        if arg == "--" {
            args.get(index + 1)?;
            return (exec && pod).then_some(index + 1);
        }
        if let Some(flags) = arg.strip_prefix('-') {
            if let Some((option, _)) = arg.split_once('=') {
                if !KUBECTL_VALUED.contains(&option) {
                    return None;
                }
                index += 1;
            } else if KUBECTL_VALUED.contains(&arg.as_str()) {
                index += 2;
            } else if KUBECTL_FLAGS.contains(&arg.as_str())
                || (!flags.is_empty()
                    && !flags.starts_with('-')
                    && flags.chars().all(|c| matches!(c, 'i' | 't' | 'q')))
            {
                index += 1;
            } else {
                return None;
            }
            continue;
        }
        if !exec && arg == "exec" {
            exec = true;
        } else if exec && !pod {
            pod = true;
        } else {
            return None;
        }
        index += 1;
    }
    None
}

/// The line the remote shell of an `ssh` command reads (its words after the
/// destination, quotes taken off, joined by a blank), and for each byte of
/// it the byte of `source` it came from. `None` for any other command, or
/// where a word holds an expansion, a glob or an escaped line end, whose
/// text the line does not show as it is sent.
pub(super) fn ssh_remote_line(
    command: tree_sitter::Node<'_>,
    source: &[u8],
) -> Option<(String, Vec<Option<usize>>)> {
    remote_line_of(command, source).map(|(line, map, _)| (line, map))
}

/// [`ssh_remote_line`] with the bytes of `source` its words stand in, from
/// the first to the last: the line `ssh` runs on the other host, and where
/// the command holds it.
pub(super) fn ssh_remote_words(
    command: tree_sitter::Node<'_>,
    source: &[u8],
) -> Option<(String, Range<usize>)> {
    remote_line_of(command, source).map(|(line, _, range)| (line, range))
}

/// The lines every `ssh` command of `line` runs on another host
/// ([`ssh_remote_line`]), in the order they are written: the line itself,
/// a pipeline, a list, a substitution or a loop holds them. A command
/// whose remote line holds what the text does not show (an expansion in
/// double quotes, a glob, an escaped line end) gives none.
pub(crate) fn ssh_remote_lines(line: &str) -> Vec<String> {
    if !line.contains("ssh") {
        return Vec::new();
    }
    let Some(tree) = parse_bash(line) else {
        return Vec::new();
    };
    let mut commands = Vec::new();
    collect_nodes_of_kind(tree.root_node(), "command", &mut commands, 0);
    commands
        .into_iter()
        .filter_map(|command| ssh_remote_line(command, line.as_bytes()))
        .map(|(remote, _)| remote)
        .collect()
}

/// `line` with the words of each `ssh` command that hands another host a
/// line ([`ssh_remote_words`]) blanked, where that line is one of `judged`:
/// the lines the analysis reads as lines of their own. The guard's own
/// checks read a remote line there, as the line it is (a search pattern, a
/// message, a value in it is data), and not here again as text. `None`
/// where nothing is blanked, or the line does not parse whole.
pub(crate) fn ssh_remote_words_blanked(line: &str, judged: &[String]) -> Option<String> {
    if judged.is_empty() || !line.contains("ssh") {
        return None;
    }
    let tree = parse_bash(line)?;
    if tree.root_node().has_error() {
        return None;
    }
    let mut commands = Vec::new();
    collect_nodes_of_kind(tree.root_node(), "command", &mut commands, 0);
    let mut out = line.as_bytes().to_vec();
    let mut changed = false;
    for command in commands {
        let Some((remote, range)) = ssh_remote_words(command, line.as_bytes()) else {
            continue;
        };
        if !judged.contains(&remote) {
            continue;
        }
        for byte in out.get_mut(range).into_iter().flatten() {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        changed = true;
    }
    if !changed {
        return None;
    }
    String::from_utf8(out).ok()
}

/// [`ssh_remote_line`], [`ssh_remote_words`]: the line, the map of its
/// bytes and the range of its words.
fn remote_line_of(
    command: tree_sitter::Node<'_>,
    source: &[u8],
) -> Option<(String, Vec<Option<usize>>, Range<usize>)> {
    let words = command_words(command, source)?;
    let effective = effective_command_words(&words, 0)?;
    if normalized_command_name(effective.first()?) != "ssh" {
        return None;
    }
    let skip = words.len() - effective.len();
    let arguments = command_arguments(command);
    let arguments = arguments.get(skip..)?;
    let unquoted: Vec<String> = effective[1..].iter().map(|word| shell_word(word)).collect();
    let start = ssh_client::ssh_command_start(&unquoted)?;
    let remote = arguments.get(start..)?;
    let mut line = Vec::new();
    let mut map = Vec::new();
    for (count, argument) in remote.iter().enumerate() {
        if count > 0 {
            line.push(b' ');
            map.push(None);
        }
        let text = source.get(argument.byte_range())?;
        unquote_mapped(text, argument.start_byte(), &mut line, &mut map)?;
    }
    let range = remote.first()?.start_byte()..remote.last()?.end_byte();
    String::from_utf8(line).ok().map(|line| (line, map, range))
}

/// `text`, one shell word written at byte `base`, with its quotes taken
/// off, onto `out`, each byte's place in the source onto `map`. `None`
/// where the word holds an expansion, a substitution, a glob or an escaped
/// line end.
fn unquote_mapped(
    text: &[u8],
    base: usize,
    out: &mut Vec<u8>,
    map: &mut Vec<Option<usize>>,
) -> Option<()> {
    let mut at = 0;
    while let Some(&byte) = text.get(at) {
        match byte {
            b'\'' => {
                at += 1;
                loop {
                    let byte = *text.get(at)?;
                    at += 1;
                    if byte == b'\'' {
                        break;
                    }
                    out.push(byte);
                    map.push(Some(base + at - 1));
                }
            }
            b'"' => {
                at += 1;
                loop {
                    let byte = *text.get(at)?;
                    match byte {
                        b'"' => {
                            at += 1;
                            break;
                        }
                        b'$' | b'`' => return None,
                        b'\\' => {
                            let next = *text.get(at + 1)?;
                            if matches!(next, b'"' | b'\\' | b'$' | b'`') {
                                out.push(next);
                                map.push(Some(base + at + 1));
                                at += 2;
                            } else if next == b'\n' {
                                return None;
                            } else {
                                out.push(byte);
                                map.push(Some(base + at));
                                at += 1;
                            }
                        }
                        _ => {
                            out.push(byte);
                            map.push(Some(base + at));
                            at += 1;
                        }
                    }
                }
            }
            b'\\' => {
                let next = *text.get(at + 1)?;
                if next == b'\n' {
                    return None;
                }
                out.push(next);
                map.push(Some(base + at + 1));
                at += 2;
            }
            b'$' | b'`' | b'*' | b'?' | b'[' | b'{' | b'~' => return None,
            _ => {
                out.push(byte);
                map.push(Some(base + at));
                at += 1;
            }
        }
    }
    Some(())
}

/// The SQL client `line` (a remote shell line) runs, with the words after
/// its name, quotes taken off: the line is one simple command, with no
/// expansion, substitution, redirection, pipe or list, whose program is a
/// SQL client ([`sql_client_at`]).
pub(super) fn line_sql_client(line: &str) -> Option<(String, Vec<String>)> {
    let tree = parse_bash(line)?;
    let root = tree.root_node();
    if root.has_error() || root.named_child_count() != 1 {
        return None;
    }
    let command = root.named_child(0)?;
    if command.kind() != "command"
        || [
            "command_substitution",
            "process_substitution",
            "expansion",
            "simple_expansion",
            "variable_assignment",
        ]
        .iter()
        .any(|kind| node_contains_kind(command, kind, 0))
    {
        return None;
    }
    let words = command_words(command, line.as_bytes())?;
    let (name, at) = sql_client_at(&words, 0)?;
    Some((
        name,
        words[at + 1..]
            .iter()
            .map(|word| shell_word(word))
            .collect(),
    ))
}

/// The bytes of an `ssh` command's remote line that its own projection
/// hides, as ranges of `source`: the SQL that is only data in a line that
/// runs a SQL client ([`line_sql_client`]). `None` where the line is not
/// one, or its projection is in doubt or does not keep its bytes in place.
pub(super) fn ssh_sql_masks(
    command: tree_sitter::Node<'_>,
    source: &[u8],
) -> Option<Vec<Range<usize>>> {
    let (line, map) = ssh_remote_line(command, source)?;
    line_sql_client(&line)?;
    let projection = project(&line);
    if !projection.parsed || projection.masks_in_doubt || projection.scan.len() != line.len() {
        return None;
    }
    let mut masks = Vec::new();
    for ((written, shown), from) in line.bytes().zip(projection.scan.bytes()).zip(&map) {
        if written == shown {
            continue;
        }
        if shown != b' ' {
            return None;
        }
        if let Some(at) = from {
            masks.push(*at..*at + 1);
        }
    }
    Some(masks)
}

/// Whether `command` runs a SQL client: by name, behind a container
/// runner, or as the remote line of `ssh`.
pub(super) fn runs_sql_client(command: tree_sitter::Node<'_>, source: &[u8]) -> bool {
    command_words(command, source).is_some_and(|words| sql_client_at(&words, 0).is_some())
        || ssh_remote_line(command, source)
            .is_some_and(|(line, _)| line_sql_client(&line).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn the_program_behind_a_container_runner_is_found() {
        for (line, client, at) in [
            ("docker exec -i pg psql -U postgres", "psql", 4),
            ("sudo docker exec -it --user=postgres db psql", "psql", 6),
            ("podman container exec -u postgres db mysql -e", "mysql", 6),
            ("kubectl -n db exec -i pg-0 -c pg -- psql -d app", "psql", 9),
            ("docker exec db sudo -u postgres psql", "psql", 6),
        ] {
            assert_eq!(
                sql_client_at(&words(line), 0),
                Some((client.to_owned(), at)),
                "{line}"
            );
        }
        for line in [
            "docker exec db sh -c x",
            "docker run db psql",
            "docker exec --unknown db psql",
            "podman exec -l psql -c x",
            "kubectl exec pg-0 psql",
            "kubectl get pg-0 -- psql",
        ] {
            assert_eq!(sql_client_at(&words(line), 0), None, "{line}");
        }
    }

    #[test]
    fn a_container_runner_needs_a_program_after_the_container() {
        assert_eq!(container_exec_program(&words("exec db psql")), Some(2));
        assert_eq!(container_exec_program(&words("exec db")), None);
        assert_eq!(container_exec_program(&words("exec -it db")), None);
    }

    #[test]
    fn kubectl_names_the_pod_only_after_exec() {
        assert_eq!(kubectl_exec_program(&words("exec pg-0 -- psql")), Some(3));
        assert_eq!(kubectl_exec_program(&words("pg-0 exec -- psql")), None);
    }

    #[test]
    fn runners_are_read_only_so_deep() {
        let four = "docker exec a docker exec b docker exec c docker exec d psql";
        assert_eq!(
            sql_client_at(&words(four), 0),
            Some(("psql".to_owned(), 12))
        );
        let five = "docker exec a docker exec b docker exec c docker exec d docker exec e psql";
        assert_eq!(sql_client_at(&words(five), 0), None);
    }

    #[test]
    fn unquoted_bytes_map_back_to_where_they_were_written() {
        let mut out = Vec::new();
        let mut map = Vec::new();
        assert_eq!(
            unquote_mapped(b"x'ab'\\c", 10, &mut out, &mut map),
            Some(())
        );
        assert_eq!(out, b"xabc");
        assert_eq!(map, vec![Some(10), Some(12), Some(13), Some(16)]);
    }

    #[test]
    fn only_a_line_that_runs_a_sql_client_gives_one() {
        assert_eq!(
            line_sql_client("psql -d app -c 'select 1'"),
            Some((
                "psql".to_owned(),
                vec![
                    "-d".to_owned(),
                    "app".to_owned(),
                    "-c".to_owned(),
                    "select 1".to_owned()
                ]
            ))
        );
        assert_eq!(line_sql_client("echo psql"), None);
        assert_eq!(line_sql_client("psql $X"), None);
    }

    #[test]
    fn the_remote_words_are_blanked_where_their_line_is_judged() {
        let judged = vec!["grep x f".to_owned()];
        let blanked = ssh_remote_words_blanked("ssh h1 'grep x f'; ls", &judged).expect("blanked");
        assert!(!blanked.contains("grep"), "{blanked}");
        assert!(blanked.starts_with("ssh h1 "), "{blanked}");
        assert!(blanked.ends_with("; ls"), "{blanked}");
        assert_eq!(blanked.len(), "ssh h1 'grep x f'; ls".len());
        assert_eq!(ssh_remote_words_blanked("ssh h1 'grep y f'", &judged), None);
        assert_eq!(ssh_remote_words_blanked("ssh h1 'grep x f'", &[]), None);
        assert_eq!(ssh_remote_words_blanked("grep x f", &judged), None);
        assert_eq!(
            ssh_remote_words_blanked("ssh h1 'grep x f' (", &judged),
            None
        );
        let judged = vec!["a\nb".to_owned()];
        let blanked = ssh_remote_words_blanked("ssh h1 'a\nb'", &judged).expect("blanked");
        assert!(blanked.contains('\n'), "{blanked:?}");
    }
}
