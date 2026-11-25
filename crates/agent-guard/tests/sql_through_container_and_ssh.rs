//! SQL handed to a SQL client that runs inside a container or on another
//! host (`docker exec`, `podman exec`, `kubectl exec ... --`, the remote
//! line of `ssh`) is read as the same client run here is
//! (`tests/sql_text_is_data.rs`): a guard word inside a string of an
//! `INSERT` or `UPDATE` is a value, not a command. Measured before this
//! reading: every line of the first test was refused as the guard switched
//! off, because `exec` and `ssh` run their words and the line was read as
//! written. What the client or the runner runs as a shell stays a shell
//! line. Known limit, not read: what the database already holds (a
//! trigger or a user function that runs a shell) is not on the line.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation.to_string()
}

/// FAILS ON REVERT of `shell::sql_runner` and its use in `shell.rs`.
#[test]
fn sql_through_a_container_or_ssh_that_only_names_the_guard_is_data() {
    for line in [
        "ssh crm \"sudo docker exec -i crm-postgres psql -U postgres -d crm -v ON_ERROR_STOP=1\" <<'SQL'\nINSERT INTO product.items (key, title) VALUES ('FP-1', 'agent ran innerwarden disable and the guard refused it');\nSQL",
        "sudo docker exec -i crm-postgres psql -U postgres -d crm <<'SQL'\nUPDATE product.items SET status='fixed' WHERE title LIKE '%systemctl stop innerwarden-agent%';\nSQL",
        "docker exec crm-postgres psql -U postgres -d crm -c \"INSERT INTO t VALUES ('innerwarden disable')\"",
        "podman exec -i pg psql -d crm <<'SQL'\nINSERT INTO t VALUES ('innerwarden disable');\nSQL",
        "kubectl -n db exec -i pg-0 -- psql -d crm -c \"INSERT INTO t VALUES ('innerwarden disable')\"",
        "ssh crm \"psql -d crm -c \\\"INSERT INTO t VALUES ('innerwarden disable')\\\"\"",
        "ssh -p 2222 crm \"sudo docker exec -i crm-postgres psql -d crm\" <<< \"INSERT INTO t VALUES ('innerwarden disable')\"",
        "echo \"INSERT INTO t VALUES ('innerwarden disable')\" | docker exec -i crm-postgres psql -d crm",
        "docker exec -i db mysql -e \"INSERT INTO t VALUES ('innerwarden disable')\"",
        "docker exec app sqlite3 /data/notes.db \"INSERT INTO notes VALUES ('innerwarden disable')\"",
        "ssh crm \"sudo -u postgres psql -c \\\"INSERT INTO t VALUES ('innerwarden disable')\\\"\"",
        "ssh crm docker exec -i c psql <<'SQL'\nINSERT INTO t VALUES ('innerwarden disable');\nSQL",
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// What the client or the runner runs as a shell is still refused.
#[test]
fn a_shell_reached_through_a_container_or_ssh_is_still_refused() {
    for line in [
        "docker exec crm-postgres psql -c '\\! innerwarden disable'",
        "docker exec -i crm-postgres psql <<'SQL'\n\\! innerwarden disable\nSQL",
        "ssh crm \"sudo docker exec -i crm-postgres psql -d crm\" <<'SQL'\n\\! innerwarden disable\nSQL",
        "ssh crm \"sudo docker exec -i crm-postgres psql -d crm -c '\\! innerwarden disable'\"",
        "kubectl exec pg-0 -- psql -c \"COPY t FROM PROGRAM 'innerwarden disable'\"",
        "docker exec app sqlite3 db '.shell innerwarden disable'",
        "podman exec -i db mysql -e 'system innerwarden disable'",
        "echo '\\! innerwarden disable' | docker exec -i crm-postgres psql",
        "docker exec crm-postgres sh -c \"psql -c \\\"INSERT INTO t VALUES ('innerwarden disable')\\\"\"",
        "kubectl exec pg-0 -- innerwarden disable",
        "ssh crm \"psql -d crm -c \\\"INSERT INTO t VALUES ('x')\\\"; innerwarden disable\"",
        "ssh crm \"sudo docker exec -i crm-postgres psql -d crm\" <<'SQL'\nINSERT INTO t VALUES ('x');\nSQL\ninnerwarden disable",
        "docker exec crm-postgres psql -o '|innerwarden disable' -c \"INSERT INTO t VALUES ('innerwarden disable')\"",
        "docker exec crm-postgres psql -c \"INSERT INTO t VALUES ('innerwarden disable')\" -c '\\! innerwarden disable'",
        "ssh crm \"psql -c \\\"INSERT INTO t VALUES ('\\$(innerwarden disable)')\\\"\"",
        "ssh crm \"psql\" < <(echo '\\! innerwarden disable')",
        "docker exec crm-postgres psql -c \"INSERT INTO t VALUES ('innerwarden disable')\" > x.sh && sh x.sh",
        "docker exec -i c psql <<SQL\nINSERT INTO t VALUES ('$(innerwarden disable)');\nSQL",
        "$(docker exec c psql -tAc \"select 'innerwarden disable'\")",
        "ssh crm psql -tAc \"\\\"select 'innerwarden disable'\\\"\" '|' sh",
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}
