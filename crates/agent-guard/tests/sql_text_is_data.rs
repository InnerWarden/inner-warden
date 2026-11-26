//! Text handed to a SQL client (`psql`, `sqlite3`, `mysql`, `mariadb`,
//! `duckdb`) by `-c`, `-e`, a positional argument, a here-document, a
//! here-string or a pipe from `echo` or `printf` is SQL the client runs in
//! the database: a guard word inside a string of an `INSERT` or `UPDATE` is
//! a value, not a command. Measured before this reading: every line of the
//! first test was refused as the guard switched off. What the client runs
//! as a shell (`\!`, `.shell`, `.system`, `.once |`, `system`, `\o |`,
//! `COPY ... PROGRAM`, a function that is not a plain value) is still read as
//! a shell line.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation.to_string()
}

/// FAILS ON REVERT of `shell::sql_text` and its use in `shell.rs`.
#[test]
fn sql_that_only_names_the_guard_is_data() {
    for line in [
        "psql -d app -c \"INSERT INTO app.notes (key, title) VALUES ('FP-1', 'agent ran innerwarden disable and the guard refused it')\"",
        "psql -d app -v ON_ERROR_STOP=1 <<'SQL'\nINSERT INTO app.notes (key, title) VALUES ('FP-1', 'innerwarden dry-run read as self disable');\nSQL",
        "sudo psql -d app <<'SQL'\nINSERT INTO t VALUES ('innerwarden allow * was quoted');\nSQL",
        "psql -d app <<< \"INSERT INTO t VALUES ('innerwarden disable')\"",
        "echo \"INSERT INTO t VALUES ('innerwarden disable')\" | psql -d app",
        "printf '%s\\n' \"INSERT INTO t VALUES ('innerwarden dry-run')\" | sqlite3 notes.db",
        "sqlite3 notes.db \"INSERT INTO notes VALUES ('innerwarden disable is refused')\"",
        "mysql -e \"INSERT INTO t VALUES ('systemctl stop innerwarden-agent was refused')\"",
        "mariadb -e \"UPDATE t SET note='innerwarden uninstall' WHERE id=1\"",
        "duckdb x.db -c \"INSERT INTO t VALUES ('innerwarden disable')\"",
        "psql -d app -v ON_ERROR_STOP=1 <<'SQL'\nupdate notes set body = body || ' refused: systemctl stop innerwarden-agent' where id = 7;\nSQL",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// What a SQL client runs as a shell stays a shell line.
#[test]
fn a_client_command_that_reaches_the_shell_is_still_refused() {
    for line in [
        "innerwarden disable",
        "psql -c '\\! innerwarden disable'",
        "psql <<'SQL'\n\\! innerwarden disable\nSQL",
        "echo '\\! innerwarden disable' | psql",
        "psql -c \"\\o |innerwarden disable\"",
        "psql -c \"COPY t FROM PROGRAM 'innerwarden disable'\"",
        "psql -c \"select sys_exec('innerwarden disable')\"",
        "sqlite3 db '.shell innerwarden disable'",
        "sqlite3 db '.system innerwarden disable'",
        "sqlite3 db '.once |innerwarden disable'",
        "sqlite3 db <<'X'\n.shell innerwarden disable\nX",
        "duckdb x.db -c '.shell innerwarden disable'",
        "mysql -e 'system innerwarden disable'",
        "mysql -e '\\! innerwarden disable'",
        "mysql <<'X'\nsystem innerwarden disable\nX",
        "psql -c \"INSERT INTO t VALUES ('innerwarden disable')\" > x.sh && sh x.sh",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}
