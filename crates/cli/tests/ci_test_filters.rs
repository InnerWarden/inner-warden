//! A CI step that picks its tests by name must fail when the name matches
//! fewer tests than it did.
//!
//! libtest exits 0 when a name filter matches nothing ("0 passed; N filtered
//! out"). The arm64 job is the only place the sandbox filter runs on a real
//! aarch64 kernel, and it picks its tests by name: a rename or a moved module
//! would leave it green and checking nothing. So every `cargo test` in the
//! workflows that takes a name filter goes through
//! `scripts/cargo-test-at-least.sh`, which counts what passed, and these
//! tests hold both halves: no workflow runs a filtered `cargo test` without
//! it, and the script fails a run that passed too few.

use std::path::{Path, PathBuf};

const GATE: &str = "scripts/cargo-test-at-least.sh";

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The `cargo test` options that take the next word as their value.
const TAKES_A_VALUE: &[&str] = &[
    "-p",
    "--package",
    "--bin",
    "--test",
    "--example",
    "--bench",
    "--exclude",
    "-F",
    "--features",
    "--target",
    "--target-dir",
    "--manifest-path",
    "-j",
    "--jobs",
    "--profile",
    "--color",
    "--message-format",
    "--config",
    "-Z",
];

/// The name filters in the words after `cargo test` (or after the gate's
/// MIN): every word before `--` that is neither an option nor an option's
/// value, up to the end of the command.
fn name_filters<'a>(words: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut filters = Vec::new();
    let mut value_next = false;
    for word in words {
        if matches!(word, "--" | "|" | "||" | "&&" | ";") {
            break;
        }
        if value_next {
            value_next = false;
            continue;
        }
        if word.starts_with('<') || word.starts_with('>') || word.starts_with("2>") {
            continue;
        }
        if word.starts_with('-') {
            value_next = TAKES_A_VALUE.contains(&word);
            continue;
        }
        filters.push(word);
    }
    filters
}

/// Every workflow line that runs `cargo test`, with its file.
fn cargo_test_lines() -> Vec<(String, String)> {
    let dir = repo().join(".github/workflows");
    let mut lines = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("the workflows") {
        let path = entry.unwrap().path();
        if !matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yml" | "yaml")
        ) {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        for line in std::fs::read_to_string(&path).unwrap().lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            if line.contains("cargo test") || line.contains(GATE) {
                lines.push((name.clone(), line.to_string()));
            }
        }
    }
    lines
}

/// No workflow runs a `cargo test` with a name filter except through the
/// gate, and every gate asks for at least one test. The arm64 job's
/// filtered runs are among them.
///
/// FAILS ON REVERT: run `cargo test -p innerwarden-agent-guard --lib
/// seccomp` straight from a workflow again, or give the gate a MIN of 0.
#[test]
fn every_filtered_test_run_in_ci_counts_what_it_ran() {
    let lines = cargo_test_lines();
    assert!(
        lines
            .iter()
            .any(|(_, l)| l.contains("cargo test --workspace")),
        "the reader found the workflows' test runs: {lines:?}"
    );
    let mut gated = Vec::new();
    for (file, line) in &lines {
        if let Some((_, after)) = line.split_once(GATE) {
            let mut words = after.split_whitespace();
            let min: u32 = words
                .next()
                .and_then(|w| w.parse().ok())
                .unwrap_or_else(|| panic!("{file}: the gate without a MIN: {line}"));
            assert!(min >= 1, "{file}: a gate that may run no test: {line}");
            gated.push(line.as_str());
            continue;
        }
        for (at, command) in line.match_indices("cargo test") {
            let filters = name_filters(line[at + command.len()..].split_whitespace());
            assert!(
                filters.is_empty(),
                "{file}: `cargo test` with the name filter {filters:?} passes when the \
                 filter matches no test; run it through {GATE} MIN ...: {line}"
            );
        }
    }
    for wanted in ["--lib seccomp", "the_launcher_hands_bwrap"] {
        assert!(
            gated.iter().any(|l| l.contains(wanted)),
            "the arm64 job's `{wanted}` run goes through the gate: {gated:?}"
        );
    }
}

/// The reader of a command line finds a name filter, and only a filter.
#[test]
fn a_name_filter_is_told_from_options_and_their_values() {
    let filters = |line: &str| -> Vec<String> {
        name_filters(line.split_whitespace())
            .into_iter()
            .map(String::from)
            .collect()
    };
    assert!(filters("--workspace").is_empty());
    assert!(filters("-p innerwarden --test cjc_j007_ai_jail </dev/null").is_empty());
    assert!(filters("-p a --test hot_path_budget -- --nocapture").is_empty());
    assert_eq!(filters("-p a --lib seccomp </dev/null"), ["seccomp"]);
    assert_eq!(
        filters("-p innerwarden --bin innerwarden the_launcher_hands_bwrap"),
        ["the_launcher_hands_bwrap"]
    );
    assert_eq!(filters("-p a --features=x name"), ["name"]);
}

/// A stand-in `cargo` on `PATH` that prints `$FAKE_OUT`, then its own
/// arguments, and exits `$FAKE_STATUS`.
#[cfg(unix)]
fn run_gate(min: &str, fake_out: &str, fake_status: u8) -> std::process::Output {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let cargo = dir.path().join("cargo");
    std::fs::write(
        &cargo,
        "#!/bin/sh\nprintf '%s\\n' \"$FAKE_OUT\"\necho \"args: $*\"\nexit \"$FAKE_STATUS\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&cargo, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        dir.path().display(),
        std::env::var("PATH").unwrap_or_default()
    );
    std::process::Command::new("bash")
        .arg(repo().join(GATE))
        .args([min, "-p", "some-crate", "--lib", "some_filter"])
        .env("PATH", path)
        .env("FAKE_OUT", fake_out)
        .env("FAKE_STATUS", fake_status.to_string())
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run the gate")
}

/// The gate passes a run whose binaries passed at least MIN tests in all,
/// and fails one that passed fewer (a filter that matched nothing above
/// all), a run cargo failed, and a MIN that would let no test run.
///
/// FAILS ON REVERT: let the gate pass "0 passed" (the libtest answer to a
/// filter that matched nothing), count one binary only, or swallow cargo's
/// failure.
#[cfg(unix)]
#[test]
fn the_gate_fails_a_filtered_run_that_passed_too_few() {
    let nothing = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 14 filtered out; finished in 0.00s";
    let out = run_gate("1", nothing, 0);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("REFUSED"), "{stderr}");
    assert!(stderr.contains("passed 0 test(s)"), "{stderr}");

    let two_binaries = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.01s\n\
                        test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s";
    let out = run_gate("3", two_binaries, 0);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("args: test -p some-crate --lib some_filter"),
        "cargo test gets the arguments: {stdout}"
    );
    assert!(stdout.contains("3 test(s) passed (at least 3)"), "{stdout}");
    assert_eq!(run_gate("4", two_binaries, 0).status.code(), Some(1));

    let failed = "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s";
    assert_eq!(run_gate("1", failed, 101).status.code(), Some(101));

    for bad in ["0", "", "x", "-1"] {
        let out = run_gate(bad, two_binaries, 0);
        assert_eq!(out.status.code(), Some(2), "MIN {bad:?}");
        assert!(
            !String::from_utf8_lossy(&out.stdout).contains("args:"),
            "MIN {bad:?}: cargo never ran"
        );
    }
}
