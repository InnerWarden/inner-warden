//! End-to-end tests for `innerwarden status`, the command a beginner is told to
//! start with.
//!
//! These drive the REAL binary over a disposable HOME, because every defect this
//! file locks down lived in the I/O half: what `status` read, what it hardcoded,
//! and whether anybody could find the command at all. A unit test over `Facts`
//! cannot see any of that.

use std::path::Path;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// The CLI under test, pointed at a disposable HOME and a disposable record.
///
/// Both matter. Without the record redirect, `cargo test` writes the suite's
/// commands into the developer's own graph; without the HOME redirect, these
/// tests would wire a PreToolUse hook into the developer's real agent config.
fn cli(home: &Path) -> Command {
    let mut command = Command::new(bin());
    command
        .env("HOME", home)
        // What `hook::home_dir` reads on Windows, so the same temp home is in
        // force on every platform this binary ships to.
        .env("USERPROFILE", home)
        .env("IW_GRAPH_FILE", home.join("graph.json"));
    command
}

fn run(home: &Path, args: &[&str]) -> String {
    let out = cli(home).args(args).output().expect("run innerwarden");
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A command that exists and is not in `--help` may as well not exist.
///
/// `status` was dispatched all along and appeared NOWHERE in the built binary's
/// help, so the one command that answers "is this thing on?" could only be found
/// by reading the source.
///
/// FAILS ON REVERT: drop the line from `help_text()` and no help line names it.
#[test]
fn the_status_command_can_be_found_in_help() {
    let help = {
        let out = Command::new(bin())
            .arg("--help")
            .output()
            .expect("run innerwarden --help");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    assert!(
        help.lines()
            .any(|line| line.trim_start().starts_with("innerwarden status")),
        "`innerwarden status` must be listed in --help; a command nobody can \
         find may as well not exist. Got:\n{help}"
    );
}

/// A fresh install is not a broken one, and `status` must say so in one line
/// without handing the reader a fault to chase.
///
/// The premise is checked out loud: a machine that is itself running an AI agent
/// is NOT a fresh install, and the fault it reports there is real. On such a
/// host this asserts the part that still holds, rather than pretending.
#[test]
fn a_fresh_install_says_so_without_reporting_a_fault() {
    let home = tempfile::TempDir::new().expect("temp home");
    // Discovery also looks along `PATH`, so the developer's own installed agents
    // would otherwise make this box look configured and the assertions below
    // would quietly stop testing anything.
    let empty_path = home.path().to_owned();
    let out = {
        let output = cli(home.path())
            .env("PATH", &empty_path)
            .arg("status")
            .output()
            .expect("run innerwarden status");
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    };

    assert!(
        !out.contains("could not be read"),
        "nothing on a fresh box was read, so nothing may be blamed for failing \
         to read:\n{out}"
    );

    // `PATH` is controlled above, but a LIVE agent process is not: a machine
    // running one is not a fresh install, and the fault reported there is real.
    // Say so instead of pretending the premise held.
    let host_runs_an_agent = out.contains("agent is running") || out.contains("Wired into");
    if host_runs_an_agent {
        return;
    }
    assert!(
        out.contains("InnerWarden is installed and waiting to be set up."),
        "a fresh install must be told it is fresh:\n{out}"
    );
    assert!(
        out.contains("innerwarden setup"),
        "a fresh install needs a first step, not a diagnosis:\n{out}"
    );
    assert!(
        !out.contains("[off]"),
        "nothing was established as off on a box with nothing on it:\n{out}"
    );
}

/// REGRESSION ANCHOR. `status` counted `guard-events.jsonl`, a sink that holds
/// BLOCKS, and labelled the number "screening decision(s)". Worse, it collapsed
/// a missing file into `None`, so every install that had never blocked anything
/// (which is most of them, and all new ones) was told
///
///   [unknown] The decision record could not be read.
///
/// about a file that was never written because nothing had gone wrong.
///
/// FAILS ON REVERT: read the sink again and a record that does not exist is a
/// read failure again.
#[test]
fn a_record_that_was_never_written_is_not_a_read_failure() {
    let home = tempfile::TempDir::new().expect("temp home");
    // A configured agent, so the fresh-install short-circuit does not answer
    // for us: this is the state of a real install that has screened nothing yet.
    std::fs::create_dir_all(home.path().join(".claude")).expect("agent config dir");

    let out = run(home.path(), &["status"]);
    assert!(
        !out.contains("The decision record could not be read"),
        "a record nothing has written to yet is empty, not unreadable:\n{out}"
    );
    assert!(
        out.contains("No screening decisions recorded yet"),
        "say the honest thing: nothing has been screened yet:\n{out}"
    );
}

/// REGRESSION ANCHOR, and the reason this command exists at all.
///
/// `main.rs` hardcoded `mode: None` with the comment "Mode is not persisted
/// anywhere this command can read today". The rows it had already fetched carry
/// exactly that: `agents_ops::rows` reads each wiring back and reports whether
/// it records or blocks. So the mode line read [unknown] on every machine, most
/// visibly in the seconds after `innerwarden enforce` prints success.
///
/// This drives the real sequence a user runs: wire in monitor, read it back,
/// flip to enforce, read it back, screen one command, read the count.
///
/// FAILS ON REVERT: hardcode `mode: None` and the enforce assertion trips with
/// the [unknown] line in the message.
#[test]
fn the_mode_line_tracks_what_the_wiring_actually_does() {
    let home = tempfile::TempDir::new().expect("temp home");

    let installed = run(home.path(), &["install", "claude-code", "--monitor"]);
    assert!(
        home.path().join(".claude/settings.json").exists(),
        "the hook must be wired for this test to mean anything: {installed}"
    );

    let monitoring = run(home.path(), &["status"]);
    assert!(
        monitoring.contains("Guard mode is dry-run"),
        "wiring that records must not read as protection:\n{monitoring}"
    );

    let flipped = run(home.path(), &["enforce"]);
    assert!(
        !flipped.contains("no guarded agent found"),
        "the flip must have something to flip: {flipped}"
    );

    let enforcing = run(home.path(), &["status"]);
    assert!(
        enforcing.contains("Guard mode is enforce"),
        "the mode line must say enforce the moment enforce is on:\n{enforcing}"
    );
    assert!(
        !enforcing.contains("Guard mode is not something this command can see"),
        "the mode IS something this command can see:\n{enforcing}"
    );

    // One screened command, so the record has something honest to count.
    run(home.path(), &["check", "ls -la"]);
    let screening = run(home.path(), &["status"]);
    assert!(
        screening.contains("1 screening decision(s) recorded"),
        "an allowed command is still a screening decision and must be counted:\n{screening}"
    );
    // The whole point: there must EXIST an install this command calls fine.
    assert!(
        screening.contains("InnerWarden is on and screening."),
        "a wired, enforcing, actively screening install must be reported as \
         fine; a verdict nothing can reach teaches readers to ignore it:\n{screening}"
    );
}
