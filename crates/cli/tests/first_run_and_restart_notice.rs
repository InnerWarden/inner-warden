//! Two ways this CLI let a user believe they were protected when they were not.
//!
//! 1. A bare `innerwarden` on a fresh install answered with a 60-line usage
//!    block in which `setup` was one of 24 subcommands. Nothing in npm, `.deb`
//!    or `.rpm` says "you are not protected yet", so that screen was the only
//!    chance to say it, and it did not.
//! 2. `innerwarden agents connect` printed "connected" and stopped. An agent
//!    reads its hook / MCP configuration at STARTUP, so the user went back to a
//!    session that was still unscreened, believing it was screened.
//!
//! Both defects live in the I/O half: which arm answers, and what gets printed
//! after the engine's lines. They are driven against the REAL binary over a
//! disposable HOME for that reason.

use std::path::Path;
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// The CLI under test over a disposable HOME.
///
/// `IW_GRAPH_FILE` is deliberately pointed at the REAL relative layout
/// (`.config/innerwarden/graph.json`) rather than at the temp root: the first
/// defect is about that directory being absent, and redirecting the record to a
/// directory that already exists would make every assertion below vacuous.
fn cli(home: &Path) -> Command {
    let mut command = Command::new(bin());
    command
        .env("HOME", home)
        .env("USERPROFILE", home)
        .env("IW_GRAPH_FILE", home.join(".config/innerwarden/graph.json"));
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

/// A guardable agent that exists on every platform and needs nothing installed:
/// a recognizable MCP configuration under HOME.
fn a_guardable_agent(home: &Path) {
    let dir = home.join(".new-agent");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("mcp.json"),
        r#"{"mcpServers":{"local":{"command":"node"}}}"#,
    )
    .unwrap();
}

/// The one thing a fresh install must hear.
///
/// FAILS ON REVERT: fold the `None` arm back into the `--help` arm and this
/// prints the usage block, which says "USAGE:" and never says nothing is wired.
#[test]
fn a_bare_command_on_a_fresh_install_says_nothing_is_wired_yet() {
    let home = tempfile::TempDir::new().unwrap();

    let out = run(home.path(), &[]);

    assert!(
        out.contains("Nothing is wired yet"),
        "a fresh install must be told it is not protected yet, got:\n{out}"
    );
    assert!(
        out.contains("innerwarden setup"),
        "it must name the command that fixes that, got:\n{out}"
    );
    assert!(
        out.contains("innerwarden status"),
        "and the command that confirms it afterwards, got:\n{out}"
    );
    assert!(
        !out.contains("USAGE:"),
        "the 24-subcommand usage block is exactly what buried `setup`, got:\n{out}"
    );
    assert!(
        out.lines().count() <= 8,
        "the first-run panel must stay glanceable, got {} lines:\n{out}",
        out.lines().count()
    );
}

/// The regression the split of the match arm exists to prevent.
///
/// `--help`, `-h` and `help` must keep answering with the full reference on the
/// very machines where the panel fires, or a fresh install would have no way to
/// reach the command list at all.
///
/// FAILS ON REVERT: share one arm between the empty case and the help case and
/// every one of these three loses `USAGE:` on a fresh box.
#[test]
fn explicit_help_is_never_swallowed_by_the_first_run_panel() {
    let home = tempfile::TempDir::new().unwrap();

    for flag in ["--help", "-h", "help"] {
        let out = run(home.path(), &[flag]);
        assert!(
            out.contains("USAGE:"),
            "`innerwarden {flag}` must print full usage even on a fresh install, got:\n{out}"
        );
        assert!(
            !out.contains("Nothing is wired yet"),
            "`innerwarden {flag}` asked for the reference, not the panel, got:\n{out}"
        );
    }
}

/// An install with state is not a first run, so it keeps today's behaviour.
#[test]
fn an_install_that_has_state_still_gets_the_usage_block() {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join(".config/innerwarden")).unwrap();

    let out = run(home.path(), &[]);

    assert!(
        out.contains("USAGE:"),
        "an install that has already been used must not be told it is fresh, got:\n{out}"
    );
    assert!(!out.contains("Nothing is wired yet"), "{out}");
}

/// Silent false protection: "connected" with no word about the restart.
///
/// FAILS ON REVERT: drop the `outcome.configured > 0` block from `agents_io`
/// and the output ends at the per-agent line, with no mention of a restart.
#[test]
fn connecting_an_agent_says_it_must_be_restarted() {
    let home = tempfile::TempDir::new().unwrap();
    a_guardable_agent(home.path());

    let out = run(home.path(), &["agents", "connect", "--all", "--monitor"]);

    assert!(
        out.contains("new-agent"),
        "fixture agent was not connected, so the rest of this test proves \
         nothing:\n{out}"
    );
    assert!(
        out.contains("Restart guarded agents"),
        "the hook is read at agent STARTUP; without this line the user returns \
         to an unscreened session believing it is screened, got:\n{out}"
    );
}

/// Telling someone to restart after they deliberately unwired is noise, and a
/// naive `contains("connected")` would produce exactly that: `disconnect` prints
/// `was not connected`, which contains the word.
///
/// FAILS ON REVERT: key the notice on the `mutating` flag (which covers
/// disconnect) or on scanning the lines for `connected`, and this fires.
#[test]
fn disconnecting_never_tells_anyone_to_restart() {
    let home = tempfile::TempDir::new().unwrap();
    a_guardable_agent(home.path());
    run(home.path(), &["agents", "connect", "--all", "--monitor"]);

    let out = run(home.path(), &["agents", "disconnect", "--all"]);

    assert!(
        out.contains("new-agent"),
        "fixture agent was not addressed, so this test proves nothing:\n{out}"
    );
    assert!(
        !out.contains("Restart"),
        "unwiring needs no restart advice, got:\n{out}"
    );
}

/// Listing changes nothing, so it owes no restart advice either.
#[test]
fn listing_agents_never_tells_anyone_to_restart() {
    let home = tempfile::TempDir::new().unwrap();
    a_guardable_agent(home.path());

    let out = run(home.path(), &["agents"]);

    assert!(out.contains("new-agent"), "{out}");
    assert!(!out.contains("Restart"), "{out}");
}
