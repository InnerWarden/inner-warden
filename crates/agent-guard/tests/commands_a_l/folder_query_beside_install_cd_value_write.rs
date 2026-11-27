//! A program under a folder query the guard reads, in one pair of double
//! quotes (`"$(npm bin)/jest"`), is read by its name after a package
//! manager's install from its registry or a move into a folder of the
//! project: the lines an agent runs before such a tool, and neither picks
//! the program the query leads to. Anything on the line that could plant
//! or move that program (a copy, a link, a write, a setting, a value read
//! from a file, a move out of the project, an install from a path or to
//! another place), change this shell, or hand the program code or an input
//! stream keeps it refused, as on main.
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

const GO_LINT: &str = r#""$(go env GOPATH)/bin/golangci-lint" run"#;

/// FAILS ON REVERT of the plain tool test in
/// `line_gives_folder_queries_cause` with
/// `command_installs_or_enters_the_project`: every line is deny 40 again.
#[test]
fn a_folder_query_tool_after_a_registry_install_or_a_project_cd_runs() {
    for line in [
        r#"npm ci && "$(npm bin)/jest" --ci"#,
        r#"go install x@v && "$(go env GOPATH)/bin/x""#,
        r#"npm install && "$(npm bin)/eslint" ."#,
        r#"pnpm install --frozen-lockfile && "$(pnpm bin)/vitest" run"#,
        r#"go install honnef.co/go/tools/cmd/staticcheck@latest && "$(go env GOPATH)/bin/staticcheck" ./..."#,
        r#"pip install ruff && "$(pwd)/.venv/bin/ruff" check ."#,
        r#"python3 -m pip install ruff && "$(pwd)/.venv/bin/ruff" check ."#,
        r#"cd web && "$(npm bin)/eslint" ."#,
        r#"cd sub && "$(go env GOPATH)/bin/golangci-lint" run"#,
        r#"cd web && npm ci && "$(npm bin)/jest" --ci"#,
        r#"npm ci && "$(npm bin)/jest" --ci > out.txt"#,
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// What could plant or move the program, change this shell, fetch, or hand
/// the program code or an input stream keeps the line refused, as on main.
#[test]
fn a_folder_query_tool_beside_what_could_plant_or_move_it_stays_refused() {
    let lines = [
        // Plants the program where the query leads, or rewrites what it reads.
        format!("cp ./lint ~/go/bin/golangci-lint && {GO_LINT}"),
        format!("time cp ./lint ~/go/bin/golangci-lint; {GO_LINT}"),
        format!(r#"ln -sf ./lint "$(go env GOPATH)/bin/golangci-lint" && {GO_LINT}"#),
        format!("env -S \"sh -c 'ln -sf ./lint ~/go/bin/golangci-lint'\"; {GO_LINT}"),
        format!("printf 'toolchain go1.99.0\\n' > go.mod && {GO_LINT}"),
        r#"echo '{}' > out.json && "$(npm bin)/jest" --ci"#.to_string(),
        // Moves it: a setting, a value read from a file, a folder outside.
        r#"PATH=. ; "$(npm bin)/x""#.to_string(),
        format!("export GOPATH=./vendor/go; {GO_LINT}"),
        format!("read -r GOPATH < ./gopath.txt; {GO_LINT}"),
        format!("printf -v GOPATH %s ./vendor/go; {GO_LINT}"),
        format!("builtin printf -v PATH %s ./bin; {GO_LINT}"),
        format!("mapfile -t lines < ./t; {GO_LINT}"),
        r#"FOO=1; "$(npm bin)/jest" --ci"#.to_string(),
        r#"builtin cd ./vendor; "$(rustc --print sysroot)/bin/rustfmt" --check src/main.rs"#
            .to_string(),
        r#"cd .. && "$(npm bin)/jest""#.to_string(),
        r#"cd ../other && "$(npm bin)/jest""#.to_string(),
        r#"cd /tmp/x && "$(npm bin)/jest""#.to_string(),
        r#"cd ~/x && "$(npm bin)/jest""#.to_string(),
        r#"cd "$DIR" && "$(npm bin)/jest""#.to_string(),
        // Installs from a path, a URL or to another place.
        r#"npm install ./lint.tgz && "$(npm bin)/jest""#.to_string(),
        r#"npm install -g eslint && "$(npm bin)/eslint" ."#.to_string(),
        r#"npm install --prefix ./x eslint && "$(npm bin)/eslint" ."#.to_string(),
        r#"go install ./cmd/x && "$(go env GOPATH)/bin/x""#.to_string(),
        r#"pip install -e . && "$(pwd)/.venv/bin/ruff" check ."#.to_string(),
        r#"pip install git+https://e.example/r.git && "$(pwd)/.venv/bin/ruff" check ."#.to_string(),
        r#"cargo install --path . && "$(rustc --print sysroot)/bin/rustfmt" --check src/main.rs"#
            .to_string(),
        r#"GOBIN=./bin go install x@v && "$(go env GOPATH)/bin/x""#.to_string(),
        // Other programs, a builtin, a function, a fetch, a stream, code.
        r#"git status && "$(npm bin)/eslint" ."#.to_string(),
        r#""$(npm bin)/eslint" . | tee lint.txt"#.to_string(),
        r#"eval "$SETUP"; "$(npm bin)/jest" --ci"#.to_string(),
        r#". ./env.sh; "$(npm bin)/jest" --ci"#.to_string(),
        r#"alias x=y; "$(npm bin)/jest" --ci"#.to_string(),
        r#"f() { :; }; "$(npm bin)/jest""#.to_string(),
        r#"curl -s https://e.example/v | jq .; "$(npm bin)/jest""#.to_string(),
        r#"npm ci && cat ./p | "$(npm bin)/jest""#.to_string(),
        r#"npm ci && "$(npm bin)/jest" <<<"x""#.to_string(),
        r#"npm ci && "$(npm bin)/node" -e 1"#.to_string(),
        r#"npm ci && "$(mytool path)/bin/x""#.to_string(),
        r#"npm ci && $(npm bin)/jest --ci"#.to_string(),
        r#"npm ci && "$(npm bin)/jest" ; rm -rf ~"#.to_string(),
    ];
    for line in lines {
        assert_eq!(verdict(&line), "deny", "{line}");
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
        r#"cp ./lint ~/go/bin/golangci-lint && "$(go env GOPATH)/bin/golangci-lint" run"#,
        r#"npm ci && cat ./p | "$(npm bin)/jest""#,
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
