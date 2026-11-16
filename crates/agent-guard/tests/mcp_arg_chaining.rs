//! A command chained onto an argument of a tool that is not a shell.
//!
//! # Why this test exists
//!
//! A server that builds a shell line from an argument (`ping -c 1 {host}`)
//! runs every command the argument adds after a control operator. Measured on
//! 2026-11-14 against a deliberately vulnerable MCP server, behind
//! `innerwarden proxy` in guard mode: a host followed by `;`, `|` or `$(...)`
//! and a file read was refused, and the same read after `&&` reached the
//! server and ran. The rule that screened tool arguments listed a different,
//! shorter set of programs for each operator, never read a newline at all
//! (the arguments it saw were JSON text, where a newline is two characters),
//! and missed a program written with its folder or in quotes.
//!
//! Every operator is now read the same way, on the value the server gets.
//!
//! FAILS ON REVERT: take the chained-command check out of
//! `inspect_declared_tool_call` and the `&&`, `||`, newline, `&`, path and
//! quoting cases below are forwarded.

use innerwarden_agent_guard::mcp::{inspect_tool_call, Verdict};
use innerwarden_agent_guard::rules::RuleEngine;

fn engine() -> RuleEngine {
    RuleEngine::load_embedded()
}

fn chained(verdict: &Verdict) -> bool {
    verdict.alerts.iter().any(|alert| alert.rule == "AG-CHAIN")
}

/// The measured case, in its own words: a network tool whose host argument
/// carries a second command after `&&`.
#[test]
fn a_file_read_chained_after_a_double_ampersand_is_refused() {
    let engine = engine();
    let verdict = inspect_tool_call(
        "ping_host",
        &serde_json::json!({"host": "10.0.0.1 && cat /tmp/lab/flag.txt"}),
        Some(&engine),
    );
    assert!(
        !verdict.allowed,
        "a second command after && must not reach the server: {verdict:?}"
    );
}

/// Every operator that ends a command in a shell, followed by the same
/// program, gets the same answer.
#[test]
fn every_operator_that_chains_a_command_is_refused_alike() {
    let engine = engine();
    for host in [
        "10.0.0.1; cat /tmp/lab/flag.txt",
        "10.0.0.1 && cat /tmp/lab/flag.txt",
        "10.0.0.1 || cat /tmp/lab/flag.txt",
        "10.0.0.1 | cat /tmp/lab/flag.txt",
        "10.0.0.1 & cat /tmp/lab/flag.txt",
        "10.0.0.1\ncat /tmp/lab/flag.txt",
        "10.0.0.1\rcat /tmp/lab/flag.txt",
        "10.0.0.1\r\ncat /tmp/lab/flag.txt",
        // A tab is a blank to the shell and an escape in JSON text.
        "10.0.0.1;\tcat /tmp/lab/flag.txt",
        "10.0.0.1 && env",
        "10.0.0.1 && id",
        "10.0.0.1 || export -p",
        "10.0.0.1 | base64 /tmp/lab/flag.txt",
        "10.0.0.1 && rm -rf /tmp/lab",
        "10.0.0.1 && sudo cat /etc/shadow",
        "10.0.0.1 && python3 -c 'print(1)'",
        "10.0.0.1 && nohup cat /tmp/lab/flag.txt",
        "10.0.0.1 && timeout 5 cat /tmp/lab/flag.txt",
        "10.0.0.1 && eval 'cat /tmp/lab/flag.txt'",
        "10.0.0.1 && if cat /tmp/lab/flag.txt; then :; fi",
        "10.0.0.1; (cat /tmp/lab/flag.txt)",
        "10.0.0.1; { cat /tmp/lab/flag.txt; }",
    ] {
        let verdict = inspect_tool_call(
            "ping_host",
            &serde_json::json!({ "host": host }),
            Some(&engine),
        );
        assert!(
            !verdict.allowed && chained(&verdict),
            "{host:?} must be refused as a chained command: {verdict:?}"
        );
    }
}

/// How the program is spelled does not change what the shell runs.
#[test]
fn a_chained_program_written_with_a_path_quotes_or_no_space_is_refused() {
    let engine = engine();
    for host in [
        "10.0.0.1&&cat /tmp/lab/flag.txt",
        "10.0.0.1&&/bin/cat /tmp/lab/flag.txt",
        "10.0.0.1 && /usr/bin/cat /tmp/lab/flag.txt",
        "10.0.0.1 && 'cat' /tmp/lab/flag.txt",
        "10.0.0.1 && \"cat\" /tmp/lab/flag.txt",
        "10.0.0.1 && c'a't /tmp/lab/flag.txt",
        "10.0.0.1 && \\cat /tmp/lab/flag.txt",
        "10.0.0.1 && /bin/c?t /tmp/lab/flag.txt",
        "10.0.0.1 && c${u}at /tmp/lab/flag.txt",
        "10.0.0.1; A=/bin/cat; $A /tmp/lab/flag.txt",
        "10.0.0.1 && CAT /tmp/lab/flag.txt",
        // A server that quotes the argument: the value closes the quote.
        "10.0.0.1' && cat /tmp/lab/flag.txt '",
        "10.0.0.1\" && cat /tmp/lab/flag.txt \"",
        // A substitution runs wherever it is, with or without a folder.
        "$(/bin/cat /tmp/lab/flag.txt)",
        "`/bin/cat /tmp/lab/flag.txt`",
        "10.0.0.1 > $(cat /tmp/lab/flag.txt)",
    ] {
        let verdict = inspect_tool_call(
            "ping_host",
            &serde_json::json!({ "host": host }),
            Some(&engine),
        );
        assert!(
            !verdict.allowed && chained(&verdict),
            "{host:?} must be refused as a chained command: {verdict:?}"
        );
    }
}

/// A value nested inside the arguments is what a server may interpolate too.
#[test]
fn a_chained_command_deep_in_the_arguments_is_refused() {
    let engine = engine();
    let verdict = inspect_tool_call(
        "scan_hosts",
        &serde_json::json!({"targets": {"hosts": ["10.0.0.2", "10.0.0.1 && cat /tmp/lab/flag.txt"]}}),
        Some(&engine),
    );
    assert!(!verdict.allowed && chained(&verdict), "{verdict:?}");
}

/// The other half: text that only looks like chaining. An ampersand in prose
/// or a URL query and a parenthesis in a sentence are forwarded.
#[test]
fn prose_and_urls_are_not_taken_for_a_chained_command() {
    let engine = engine();
    let cases = [
        ("search", serde_json::json!({"query": "R&D budget for Q3"})),
        (
            "search",
            serde_json::json!({"query": "Tom && Jerry episodes"}),
        ),
        (
            "search",
            serde_json::json!({"query": "AT&T and Q&A notes; salt & pepper"}),
        ),
        (
            "search",
            serde_json::json!({"query": "funny pets (cat videos) and more"}),
        ),
        ("ping_host", serde_json::json!({"host": "127.0.0.1"})),
        (
            "fetch",
            serde_json::json!({"url": "https://api.example.com/items?page=2&id=17&env=prod&cat=3"}),
        ),
    ];
    for (tool, args) in cases {
        let verdict = inspect_tool_call(tool, &args, Some(&engine));
        assert!(
            !chained(&verdict),
            "{tool} {args} is not a chained command: {verdict:?}"
        );
        assert!(
            verdict.allowed,
            "{tool} {args} must be forwarded: {verdict:?}"
        );
    }
}

/// Code carried in an argument: a logical AND, a program name used as a
/// variable, a JavaScript module that exports, SQL that concatenates. Other
/// rules judge some of these on their own grounds; this one must not.
#[test]
fn code_in_an_argument_is_not_taken_for_a_chained_command() {
    let engine = engine();
    let cases = [
        (
            "run_js",
            serde_json::json!({"code": "const ok = a && b;\nif (ready || done) { go(); }\nexport default ok;"}),
        ),
        (
            "write_file",
            serde_json::json!({
                "path": "/home/dev/app/src/index.ts",
                "content": "import { a } from './a';\nconst { id, env } = req;\nexport { id, env };\nexport const url = `/users/${id}`;\n",
            }),
        ),
        (
            "write_file",
            serde_json::json!({
                "path": "/home/dev/app/tool.py",
                "content": "import os\nenv = os.environ.copy()\nid = 5\nset_value = set()\nresult = sum(range(10))\nexec(compile(src, 'x', 'exec'))\n",
            }),
        ),
        (
            "write_file",
            serde_json::json!({
                "path": "/home/dev/app/q.sql",
                "content": "SELECT 'user-' || id AS key FROM users;\nSET search_path = app;\n",
            }),
        ),
    ];
    for (tool, args) in cases {
        let verdict = inspect_tool_call(tool, &args, Some(&engine));
        assert!(
            !chained(&verdict),
            "{tool} {args} is not a chained command: {verdict:?}"
        );
    }
}

/// A real shell tool keeps its own screening: chaining is how a command line
/// is written, so it is judged by the command analyzer, not refused here.
#[test]
fn a_shell_tool_is_not_judged_as_a_chained_argument() {
    let engine = engine();
    let verdict = inspect_tool_call(
        "bash",
        &serde_json::json!({"command": "cargo build && cat target/build.log"}),
        Some(&engine),
    );
    assert!(!chained(&verdict), "{verdict:?}");
    assert!(verdict.allowed, "{verdict:?}");
}

fn refused_as_chained(tool: &str, args: serde_json::Value, engine: &RuleEngine) {
    let verdict = inspect_tool_call(tool, &args, Some(engine));
    assert!(
        !verdict.allowed && chained(&verdict),
        "{tool} {args} must be refused as a chained command: {verdict:?}"
    );
}

fn forwarded(tool: &str, args: serde_json::Value, engine: &RuleEngine) {
    let verdict = inspect_tool_call(tool, &args, Some(engine));
    assert!(
        !chained(&verdict),
        "{tool} {args} is not a chained command: {verdict:?}"
    );
    assert!(
        verdict.allowed,
        "{tool} {args} must be forwarded: {verdict:?}"
    );
}

/// Review finding: only a short list of programs counted, so a file read
/// by any other reader, or by the shell's own `read` on its input, was
/// forwarded. Measured on the lab server: each of these returned the file.
#[test]
fn a_file_read_by_any_reader_or_on_the_input_is_refused() {
    let engine = engine();
    for host in [
        "10.0.0.1 || head /tmp/lab/flag.txt",
        "10.0.0.1 && tail -n 1 /tmp/lab/flag.txt",
        "10.0.0.1 && awk 1 /tmp/lab/flag.txt",
        "10.0.0.1 && grep . /tmp/lab/flag.txt",
        "10.0.0.1 && more /tmp/lab/flag.txt",
        "10.0.0.1 && tac /tmp/lab/flag.txt",
        "10.0.0.1 && od -c /tmp/lab/flag.txt",
        "10.0.0.1; read l < /tmp/lab/flag.txt; echo $l",
        "10.0.0.1; while read l; do echo $l; done < /tmp/lab/flag.txt",
        "10.0.0.1 && declare -p",
    ] {
        refused_as_chained("ping_host", serde_json::json!({ "host": host }), &engine);
    }
    refused_as_chained(
        "network_diagnostic",
        serde_json::json!({"command": "ping 127.0.0.1 || sed -n p /tmp/lab/flag.txt"}),
        &engine,
    );
}

/// Review finding: an unquoted parameter glued to the program name is split
/// by the shell into two words, the program and its operand, and the name in
/// front of it was never read as a program.
#[test]
fn a_program_split_off_by_a_parameter_is_refused() {
    let engine = engine();
    for host in [
        "10.0.0.1||cat$IFS/tmp/lab/flag.txt",
        "10.0.0.1&&cat$IFS/tmp/lab/flag.txt",
        "10.0.0.1&&cat${IFS}/tmp/lab/flag.txt",
    ] {
        refused_as_chained("ping_host", serde_json::json!({ "host": host }), &engine);
    }
}

/// Review finding: a program the line computes (a substitution, or two
/// parameters) cannot be named before it runs, and it was let through.
#[test]
fn a_computed_program_that_is_handed_a_file_is_refused() {
    let engine = engine();
    for host in [
        "10.0.0.1 || $(echo cat) /tmp/lab/flag.txt",
        "10.0.0.1 || `printf cat` /tmp/lab/flag.txt",
        "10.0.0.1; A=ca; B=t; $A$B /tmp/lab/flag.txt",
        "10.0.0.1; $X$Y /tmp/lab/flag.txt",
        "10.0.0.1\n$PROG /tmp/lab/flag.txt",
    ] {
        refused_as_chained("ping_host", serde_json::json!({ "host": host }), &engine);
    }
}

/// Review finding: a search query in prose with a lone `&` before a word
/// that names a program was refused. A lone `&` joins two words in prose;
/// what follows it counts only for what it is handed.
#[test]
fn prose_with_a_lone_ampersand_is_forwarded() {
    let engine = engine();
    for query in [
        "dog & cat food",
        "data science & python course",
        "bash & zsh tips",
        "it's my dog & cat",
    ] {
        forwarded(
            "search_documents",
            serde_json::json!({ "query": query }),
            &engine,
        );
    }
    // The same operator still chains a command handed a file.
    refused_as_chained(
        "ping_host",
        serde_json::json!({"host": "10.0.0.1 & cat /tmp/lab/flag.txt"}),
        &engine,
    );
}

/// Review finding: any line of a note, a report, a memory, a calendar entry,
/// a commit message or a chat message that started with a word naming a
/// program (in any case) was refused.
#[test]
fn multi_line_text_is_forwarded() {
    let engine = engine();
    let cases = [
        (
            "upload_document",
            serde_json::json!({"content": "Shopping list\ncat food\neggs\nmilk"}),
        ),
        (
            "upload_document",
            serde_json::json!({"content": "Steps:\n1. start the app\n2. it crashes\n\nEnvironment:\nPython 3.12\nUbuntu 24.04"}),
        ),
        (
            "create_entities",
            serde_json::json!({"entities": [{"name": "c1", "observations": ["Customer record\nID 4471\nName: Ana"]}]}),
        ),
        (
            "create_event",
            serde_json::json!({"description": "Saturday plan\nTee time 9:00 with Bob"}),
        ),
        (
            "git_commit",
            serde_json::json!({"message": "fix: worker shutdown\n\nkill the old worker before the new one starts"}),
        ),
        (
            "send_message",
            serde_json::json!({"text": "Deployed v2. If it misbehaves:\nsudo systemctl restart app"}),
        ),
    ];
    for (tool, args) in cases {
        forwarded(tool, args, &engine);
    }
    // A line break still chains a command handed a path from the root.
    refused_as_chained(
        "ping_host",
        serde_json::json!({"host": "10.0.0.1\nhead /tmp/lab/flag.txt"}),
        &engine,
    );
}

/// Review finding: a Makefile, a shell script or a markdown table written
/// through a file tool was refused line by line.
#[test]
fn file_contents_written_through_a_file_tool_are_forwarded() {
    let engine = engine();
    for (path, content) in [
        (
            "Makefile",
            "build:\n\tgo build ./...\n\nclean:\n\trm -rf bin\n",
        ),
        (
            "scripts/release.sh",
            "#!/bin/sh\nset -e\nmkdir -p dist\ncp build/app dist/\nchmod +x dist/app\n",
        ),
        (
            "notes/pets.md",
            "| Pet | Name |\n|-----|------|\n| cat | Tom  |\n| dog | Rex  |\n",
        ),
    ] {
        forwarded(
            "write_file",
            serde_json::json!({ "path": path, "content": content }),
            &engine,
        );
    }
}
