//! Text handed to a SQL client is data, not a shell line.
//!
//! `psql`, `sqlite3`, `mysql`, `mariadb` and `duckdb` run the SQL they
//! are given (by `-c`, `-e`, `--command=`, `--execute=`, `-cmd`, a
//! positional argument of `sqlite3` and `duckdb`, a here-document, a
//! here-string or a pipe from `echo` or `printf`) inside the database. A
//! word of the guard in a string of an `INSERT` or `UPDATE` is a value
//! the client stores, not a command anything runs. Measured 2026-11-25 on
//! the branch at 077b6c0: `psql -c "INSERT ... VALUES ('... innerwarden
//! disable ...')"`, the same in a here-document and piped from `echo`,
//! were refused as the guard switched off.
//!
//! A client can reach the shell, or the files of this machine, from its
//! own commands: `\!`, `\o |`, `\g |` and `\copy ... program` in
//! `psql`, `.shell`, `.system`, `.once |` and `edit()` in `sqlite3`
//! and `duckdb`, `system`, `\!` and `pager` in `mysql`, and on the
//! server `COPY ... PROGRAM`, functions in other languages and the file
//! functions. SQL text that holds any of them, or anything this reader is
//! not sure of, is not data: it is read as it was before, every word of it
//! as a shell line.

/// The SQL clients whose text is read here, by the name
/// [`super::normalized_command_name`] gives, with or without the trailing
/// digits (`sqlite3` and `sqlite`).
const SQL_CLIENTS: &[&str] = &["psql", "sqlite", "sqlite3", "mysql", "mariadb", "duckdb"];

/// Whether `name`, a normalized program name, is a SQL client read here.
pub(super) fn is_sql_client(name: &str) -> bool {
    SQL_CLIENTS.contains(&name)
}

/// Words that, outside a string, let the SQL reach the shell, a file of the
/// machine, code in another language, or the client's own commands; or
/// change how the rest is read. Any of them and the text is not data.
const NOT_DATA_WORDS: &[&str] = &[
    "program",
    "copy",
    "execute",
    "exec",
    "language",
    "function",
    "procedure",
    "trigger",
    "rule",
    "extension",
    "plugin",
    "soname",
    "install",
    "load",
    "load_extension",
    "load_file",
    "attach",
    "vacuum",
    "outfile",
    "dumpfile",
    "infile",
    "lo_import",
    "lo_export",
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_file_write",
    "dblink",
    "system",
    "shell",
    "edit",
    "pager",
    "source",
    "tee",
    "delimiter",
    "connect",
    "prompt",
    "charset",
    "call",
];

/// What may stand right before the parenthesis that holds a string for the
/// string to stay data: a keyword that lists values, or a function that
/// only computes a value from them. A string inside the parentheses of any
/// other name may be handed to a function that runs it (`sys_exec('...')`,
/// `read_csv('|cmd')`).
const VALUE_PARENS: &[&str] = &[
    "values",
    "in",
    "exists",
    "any",
    "all",
    "not",
    "and",
    "or",
    "as",
    "on",
    "using",
    "where",
    "set",
    "when",
    "then",
    "else",
    "coalesce",
    "nullif",
    "lower",
    "upper",
    "trim",
    "ltrim",
    "rtrim",
    "concat",
    "concat_ws",
    "length",
    "char_length",
    "replace",
    "substr",
    "substring",
    "left",
    "right",
    "now",
    "date",
    "datetime",
    "to_date",
    "to_timestamp",
    "to_char",
    "cast",
    "jsonb_build_object",
    "json_build_object",
    "jsonb_build_array",
    "json_build_array",
    "to_jsonb",
    "to_json",
    "json_object",
    "json_array",
    "array",
    "row",
    "md5",
    "greatest",
    "least",
    "round",
    "abs",
    "count",
    "max",
    "min",
    "sum",
    "avg",
];

/// Whether `text`, handed to a SQL client as SQL, is only data for the
/// shell: none of the ways a client reaches the shell or the machine
/// ([`NOT_DATA_WORDS`], a backslash command, a dot command, a backtick, a
/// dollar quote, a MySQL executable comment), and every string stands where
/// only a value is made of it ([`VALUE_PARENS`]). Anything this reader does
/// not follow (a quote left open) is not data.
pub(crate) fn sql_text_is_data(text: &str) -> bool {
    if text.trim().is_empty() || text.contains(['\\', '`', '$']) || text.contains("/*!") {
        return false;
    }
    // A client command written at the start of a line or of a statement:
    // `.shell` in sqlite3 and duckdb, `!` in some clients.
    if text
        .split(['\n', ';'])
        .map(str::trim_start)
        .any(|start| start.starts_with(['.', '!']))
    {
        return false;
    }
    let bytes = text.as_bytes();
    // The word before each open parenthesis, lowercased; `None` for a
    // parenthesis that follows no word.
    let mut parens: Vec<Option<String>> = Vec::new();
    let mut last_word: Option<String> = None;
    let mut at = 0;
    while at < bytes.len() {
        let byte = bytes[at];
        match byte {
            b'\'' | b'"' => {
                let Some(end) = quote_end(bytes, at, byte) else {
                    return false;
                };
                // A quoted name (`"table"`) is a name in PostgreSQL and
                // SQLite and a string in MySQL: read as a string either way.
                let inside_values_only = parens.iter().all(|owner| {
                    owner
                        .as_deref()
                        .is_none_or(|owner| VALUE_PARENS.contains(&owner))
                });
                if !inside_values_only {
                    return false;
                }
                last_word = None;
                at = end;
            }
            b'-' if bytes.get(at + 1) == Some(&b'-') => {
                at = text[at..].find('\n').map_or(bytes.len(), |end| at + end);
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                let Some(end) = text[at + 2..].find("*/") else {
                    return false;
                };
                at += end + 4;
            }
            b'(' => {
                parens.push(last_word.take());
                at += 1;
            }
            b')' => {
                parens.pop();
                last_word = None;
                at += 1;
            }
            _ if byte.is_ascii_alphanumeric() || byte == b'_' => {
                let start = at;
                while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                    at += 1;
                }
                let word = text[start..at].to_ascii_lowercase();
                if NOT_DATA_WORDS.contains(&word.as_str()) {
                    return false;
                }
                // Spaces may stand between a function and its parenthesis.
                last_word = Some(word);
            }
            _ if byte.is_ascii_whitespace() => at += 1,
            _ => {
                last_word = None;
                at += 1;
            }
        }
    }
    true
}

/// The index just past the quote that closes the one opened at `open`
/// (`quote` doubled stands for itself), or `None` when it stays open.
fn quote_end(bytes: &[u8], open: usize, quote: u8) -> Option<usize> {
    let mut at = open + 1;
    while at < bytes.len() {
        if bytes[at] == quote {
            if bytes.get(at + 1) == Some(&quote) {
                at += 2;
                continue;
            }
            return Some(at + 1);
        }
        at += 1;
    }
    None
}

/// The options of each client that hand it SQL in the next word, or glued
/// after `=` for the long ones.
fn sql_flags(client: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match client {
        "psql" => (&["-c", "--command"], &["--command="]),
        "mysql" | "mariadb" => (&["-e", "--execute"], &["--execute="]),
        "sqlite" | "sqlite3" => (&["-cmd", "--cmd"], &[]),
        "duckdb" => (&["-c", "-s", "-cmd", "--cmd"], &[]),
        _ => (&[], &[]),
    }
}

/// The options of `sqlite3` and `duckdb` that take the next word, which is
/// then not the database file.
const SQLITE_VALUED: &[&str] = &[
    "-init",
    "-separator",
    "-newline",
    "-nullvalue",
    "-vfs",
    "-maxsize",
    "-mmap",
    "-pagecache",
    "-lookaside",
    "-heap",
    "-escape",
    "-quote",
];

/// Which of `args` (the words after the client's name, shell quotes taken
/// off) are SQL the client runs, as `(index, sql)`: the value of a SQL
/// option, and for `sqlite3` and `duckdb` each word after the database
/// file that holds a blank or a `;` (a plain word may be a path, and is
/// never taken for SQL). A glued short option (`-cSELECT`) is not read.
pub(super) fn sql_arguments(client: &str, args: &[String]) -> Vec<(usize, String)> {
    let (separate, glued) = sql_flags(client);
    let positional_sql = matches!(client, "sqlite" | "sqlite3" | "duckdb");
    let mut out = Vec::new();
    let mut database_seen = false;
    let mut at = 0;
    while at < args.len() {
        let word = &args[at];
        if separate.contains(&word.as_str()) {
            if let Some(value) = args.get(at + 1) {
                out.push((at + 1, value.clone()));
            }
            at += 2;
            continue;
        }
        if let Some(value) = glued.iter().find_map(|prefix| word.strip_prefix(prefix)) {
            out.push((at, value.to_owned()));
            at += 1;
            continue;
        }
        if positional_sql {
            if SQLITE_VALUED.contains(&word.as_str()) {
                at += 2;
                continue;
            }
            if !word.starts_with('-') {
                if database_seen && word.contains([' ', '\t', '\n', ';']) {
                    out.push((at, word.clone()));
                }
                database_seen = true;
            }
        }
        at += 1;
    }
    out
}

/// The text `printf` prints of its format: the escapes for a line end and
/// a tab read; `None` when the format holds any other escape, or `%b`,
/// which reads escapes in its argument.
pub(super) fn printf_format_text(format: &str) -> Option<String> {
    if format.contains("%b") {
        return None;
    }
    let text = format.replace("\\n", "\n").replace("\\t", "\t");
    (!text.contains('\\')).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_and_updates_are_data() {
        assert!(sql_text_is_data(
            "INSERT INTO product.items (key, title) VALUES ('FP-1', 'innerwarden disable was refused');"
        ));
        assert!(sql_text_is_data(
            "UPDATE t SET note = coalesce(note, '') || 'systemctl stop innerwarden-agent' WHERE id = 1"
        ));
        assert!(sql_text_is_data(
            "INSERT INTO t (k) VALUES ('a') ON CONFLICT (k) DO UPDATE SET v = 'innerwarden allow *'"
        ));
    }

    #[test]
    fn ways_to_the_shell_are_not_data() {
        for text in [
            "\\! innerwarden disable",
            ".shell innerwarden disable",
            "select 1;\n.system innerwarden disable",
            "system innerwarden disable",
            "COPY t FROM PROGRAM 'innerwarden disable'",
            "select sys_exec('innerwarden disable')",
            "select * from read_csv('|innerwarden disable')",
            "select edit('x', 'innerwarden disable')",
            "DO LANGUAGE plpython3u 'import os'",
            "select `innerwarden disable`",
            "select $$innerwarden disable$$",
            "/*!50000 select 1 */",
            "insert into t values ('open",
            "",
        ] {
            assert!(!sql_text_is_data(text), "{text}");
        }
    }

    #[test]
    fn arguments_by_client() {
        let words = |list: &[&str]| list.iter().map(|w| (*w).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            sql_arguments("psql", &words(&["-d", "crm", "-c", "select 1"])),
            vec![(3, "select 1".to_owned())]
        );
        assert_eq!(
            sql_arguments("mysql", &words(&["--execute=select 1"])),
            vec![(0, "select 1".to_owned())]
        );
        assert_eq!(
            sql_arguments(
                "sqlite3",
                &words(&["-init", "x.sql", "a.db", "select 1", "b.db"])
            ),
            vec![(3, "select 1".to_owned())]
        );
    }
}
