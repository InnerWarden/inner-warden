//! A program under a folder query the guard reads, in one pair of double
//! quotes (`"$(npm bin)/jest"`), is read by its name beside an install, a
//! move to another folder, a value set or a file written on the same line:
//! the same tool written out (`./node_modules/.bin/jest`) was already read
//! by its name there, and what those commands change is there for the
//! written path just as much. What changes the shell that reads the line,
//! or hands the program code or an input stream, keeps it refused.
//!
//! Measured on main on 2026-11-19 (a069bf1) with `analyze_command`:
//! `npm ci && "$(npm bin)/jest" --ci` and
//! `go install x@v && "$(go env GOPATH)/bin/x"` were deny 40 (the lines of
//! the 1.6.12 report), and so was each line of the first test; the same
//! lines with the path written out were allow 0.
//!
//! The reason a refusal gives says what would let the line through: quoting
//! the path where it is not quoted, and writing the path out (or running
//! the tool on a line of its own) where it already is.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(command: &str) -> String {
    analyze_command(command, None).recommendation
}

/// FAILS ON REVERT of the plain tool test in
/// `line_gives_folder_queries_cause` (with `command_changes_this_shell`,
/// and the `plain_tool` arms of `line_sets_what_a_query_may_read` and
/// `line_writes_a_file`): every line is deny 40 again.
#[test]
fn a_folder_query_tool_beside_an_install_a_cd_a_value_or_a_write_runs() {
    for line in [
        r#"npm ci && "$(npm bin)/jest" --ci"#,
        r#"go install x@v && "$(go env GOPATH)/bin/x""#,
        r#"npm install && "$(npm bin)/eslint" ."#,
        r#"go install honnef.co/go/tools/cmd/staticcheck@latest && "$(go env GOPATH)/bin/staticcheck" ./..."#,
        r#"pip install ruff && "$(pwd)/.venv/bin/ruff" check ."#,
        r#"cd web && "$(npm bin)/eslint" ."#,
        r#"cd sub && "$(go env GOPATH)/bin/golangci-lint" run"#,
        r#"cd "$(git rev-parse --show-toplevel)" && "$(npm bin)/eslint" ."#,
        r#"FOO=1; "$(npm bin)/jest" --ci"#,
        r#"export FOO=1; "$(npm bin)/jest" --ci"#,
        r#"x=1 && "$(npm bin)/eslint" ."#,
        r#"echo '{}' > out.json && "$(npm bin)/jest" --ci"#,
        r#""$(go env GOPATH)/bin/golangci-lint" run | tee lint.txt"#,
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// What changes this shell, fetches, sets what the program loads, or hands
/// the program code or an input stream keeps the line refused, as on main.
#[test]
fn a_folder_query_tool_beside_what_changes_this_shell_stays_refused() {
    for line in [
        r#"cp /bin/sh ~/go/bin/x && "$(go env GOPATH)/bin/x" < ./p.sh"#,
        r#"npm ci && cat ./p | "$(npm bin)/jest""#,
        r#"npm ci && "$(npm bin)/jest" <<<"x""#,
        "npm ci && \"$(npm bin)/jest\" <<EOF\nx\nEOF",
        r#"npm ci && { "$(npm bin)/jest"; } < f"#,
        r#"eval "$SETUP"; "$(npm bin)/jest" --ci"#,
        r#". ./env.sh; "$(npm bin)/jest" --ci"#,
        r#"alias x=y; "$(npm bin)/jest" --ci"#,
        r#"f() { :; }; "$(npm bin)/jest""#,
        r#"read -r X < f; "$(npm bin)/jest""#,
        r#"$RUNNER setup; "$(npm bin)/jest""#,
        r#"env BASH_ENV=./env.sh true; "$(npm bin)/jest""#,
        r#"export LD_PRELOAD=./x.so; "$(npm bin)/jest" --ci"#,
        r#"export GOFLAGS=-toolexec=./x; "$(go env GOPATH)/bin/golangci-lint" run"#,
        r#"export GOPATH=./vendor/go; "$(go env GOPATH)/bin/golangci-lint" run"#,
        r#"curl -s https://e.example/v | jq .; "$(npm bin)/jest""#,
        r#"npm ci && "$(npm bin)/node" -e 1"#,
        r#"npm ci && "$(mytool path)/bin/x""#,
        r#"npm ci && $(npm bin)/jest --ci"#,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}

/// The way out a refusal gives is one that works. Unquoted: quote it. In
/// quotes under a command the guard does not read as a folder query: write
/// the path out (quoting it again changes nothing). In quotes on a line
/// that puts the query in doubt: write the path out or run it on a line of
/// its own.
/// FAILS ON REVERT of `runtime_program_reason`: every line is told to put
/// the path in one pair of double quotes, which it already is.
#[test]
fn the_refusal_says_what_would_let_the_line_through() {
    let why = |line: &str| analyze_command(line, None).explanation;
    let unquoted = why("$(npm bin)/eslint .");
    assert!(
        unquoted.contains("put the path in one pair of double quotes"),
        "{unquoted}"
    );

    for line in [
        r#""$(mytool path)/bin/x" run"#,
        r#"npm ci && "$(mytool path)/bin/x""#,
    ] {
        let reason = why(line);
        assert!(
            reason.contains("not one of the folder queries the guard reads"),
            "{line}: {reason}"
        );
        assert!(reason.contains("write the path out"), "{line}: {reason}");
        assert!(
            !reason.contains("put the path in one pair of double quotes"),
            "{line}: {reason}"
        );
    }
    for line in [
        r#"alias x=y; "$(npm bin)/jest" --ci"#,
        r#"npm ci && cat ./p | "$(npm bin)/jest""#,
        r#"f() { :; }; "$(npm bin)/jest""#,
    ] {
        let reason = why(line);
        assert!(reason.contains("write the path out"), "{line}: {reason}");
        assert!(reason.contains("on a line of its own"), "{line}: {reason}");
        assert!(
            !reason.contains("put the path in one pair of double quotes"),
            "{line}: {reason}"
        );
    }
}
