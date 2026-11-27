//! Two or more tools built by folder queries on one line, after a registry
//! install or a move into a folder of the project, are read as one.
//!
//! The rule of `folder_query_beside_install_cd_value_write` asked of a line
//! with one such tool. Measured on main (2026-11-20, again 2026-11-24) with `analyze_command`:
//! each line of the first test was deny 40, the same as a line whose program
//! is named at run time, because the line held two of them. Every tool must
//! be a plain one, and nothing else on the line may plant, move or feed it.

use innerwarden_agent_guard::mcp::analyze_command;

fn verdict(line: &str) -> String {
    analyze_command(line, None).recommendation
}

/// FAILS ON REVERT: take the built commands of a line as a set only when
/// there is one (`commands_built_by_a_substitution`) and each is deny 40.
#[test]
fn two_folder_query_tools_after_an_install_or_a_project_cd_run() {
    for line in [
        r##"npm ci && "$(npm bin)/eslint" . && "$(npm bin)/jest" --ci"##,
        r##"npm install && "$(npm bin)/tsc" --noEmit && "$(npm bin)/vitest" run"##,
        r##"cd web && "$(npm bin)/eslint" . && "$(npm bin)/prettier" --check ."##,
        r##"go install honnef.co/go/tools/cmd/staticcheck@latest && "$(go env GOPATH)/bin/staticcheck" ./... && "$(go env GOPATH)/bin/golangci-lint" run"##,
        r##"cd sub && "$(go env GOPATH)/bin/golangci-lint" run; "$(go env GOPATH)/bin/staticcheck" ./..."##,
        r##"pnpm install --frozen-lockfile && "$(pnpm bin)/tsc" -b && "$(pnpm bin)/vitest" run"##,
    ] {
        assert_eq!(verdict(line), "allow", "{line}");
    }
}

/// What keeps one tool refused keeps two refused: a tool that runs code or
/// reads a stream, one the guard does not read as a folder query, a copy,
/// a move out of the project, a setting, a loop, an install from a path, a
/// removal beside them.
#[test]
fn two_folder_query_tools_beside_what_could_plant_or_move_them_stay_refused() {
    for line in [
        r##"npm ci && "$(npm bin)/eslint" . && "$(npm bin)/node" -e 1"##,
        r##"npm ci && "$(npm bin)/eslint" . && cat ./p | "$(npm bin)/jest""##,
        r##"cp ./x ~/go/bin/golangci-lint && "$(go env GOPATH)/bin/staticcheck" ./... && "$(go env GOPATH)/bin/golangci-lint" run"##,
        r##"npm ci && "$(npm bin)/eslint" . && "$(mytool path)/bin/x""##,
        r##"cd .. && "$(npm bin)/eslint" . && "$(npm bin)/jest""##,
        r##"npm ci && "$(npm bin)/eslint" . && "$(npm bin)/jest" ; rm -rf ~"##,
        r##"npm ci && "$(npm bin)/eslint" . && $(npm bin)/jest"##,
        r##"for i in 1 2; do "$(npm bin)/eslint" .; done && "$(npm bin)/jest""##,
        r##"npm ci && "$(npm bin)/eslint" . && "$(npm bin)/bash" -c id"##,
        r##"npm ci && "$(npm bin)/eslint" . && "$(npm bin)/jest" <<<"x""##,
        r##"PATH=. ; "$(npm bin)/eslint" . && "$(npm bin)/jest""##,
        r##"npm install ./x.tgz && "$(npm bin)/eslint" . && "$(npm bin)/jest""##,
    ] {
        assert_eq!(verdict(line), "deny", "{line}");
    }
}
