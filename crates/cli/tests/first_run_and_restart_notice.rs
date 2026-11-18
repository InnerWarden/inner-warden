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

/// The suite's PATH less every folder that holds a `codex`. `agents connect`
/// and a mode switch ask the Codex they find there to trust the hook they
/// wrote, and a test never starts the real one.
fn path_without_codex() -> std::ffi::OsString {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let kept = std::env::split_paths(&path)
        .filter(|dir| !dir.join("codex").exists() && !dir.join("codex.exe").exists());
    std::env::join_paths(kept).expect("folders split from PATH join back")
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
        .env("IW_GRAPH_FILE", home.join(".config/innerwarden/graph.json"))
        // No real Codex: none on PATH to ask, no other folder for it to read.
        .env("PATH", path_without_codex())
        .env_remove("CODEX_HOME");
    // The person's shell, even when the suite runs under an AI agent's: the
    // wiring that lowers a guard is refused inside one.
    for marker in [
        "CLAUDECODE",
        "CLAUDE_CODE_ENTRYPOINT",
        "CODEX_SANDBOX",
        "CODEX_SANDBOX_NETWORK_DISABLED",
        "GEMINI_CLI",
        "OPENCLAW_SHELL",
    ] {
        command.env_remove(marker);
    }
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
    // How to restart THIS agent, not only that agents must be restarted.
    // FAILS ON REVERT of the call site to the shared line alone.
    assert!(
        out.contains("  New Agent: Quit New Agent and start it again."),
        "each connected agent's own restart words, got:\n{out}"
    );
}

/// A mode switch changes every connected agent's config: each one is named
/// with how to restart it. FAILS ON REVERT of either call site to the shared
/// line alone (`enforce` and `dry-run` share one; `connect` has its own).
#[test]
fn a_mode_switch_says_how_to_restart_each_connected_agent() {
    let home = tempfile::TempDir::new().unwrap();
    a_guardable_agent(home.path());
    let connected = run(home.path(), &["agents", "connect", "--all", "--monitor"]);
    assert!(connected.contains("new-agent"), "{connected}");
    for verb in ["enforce", "dry-run"] {
        let out = run(home.path(), &[verb]);
        assert!(out.contains("Restart guarded agents"), "{verb}: {out}");
        assert!(
            out.contains("  New Agent: Quit New Agent and start it again."),
            "{verb} must say how to restart each agent it switched, got:\n{out}"
        );
    }
}

/// A mode switch rewrites Codex's hook line, and Codex runs a hook only while
/// it trusts the line it has. With no Codex to ask (the PATH of [`cli`] holds
/// none), the switch leaves a hook Codex skips: `enforce` exits 1 and its
/// summary names the agent and the one step. A second `enforce` rewrites
/// nothing, and Codex still skips the hook: it fails the same way, and never
/// says enforcement is configured.
///
/// FAILS ON REVERT: drop `stopped.extend(result.hook_stopped)` from
/// `cmd_mode` and the summary does not name the agent; drop the `NotActive`
/// arm guarded by `mode_switch` in `connect_hook_and_proxy` and the first
/// `enforce` exits 0; guard that arm on this run having written the line and
/// the second `enforce` exits 0.
#[test]
fn a_mode_switch_that_stops_codexs_hook_exits_1_and_names_the_step() {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join(".codex")).unwrap();
    let connected = run(home.path(), &["agents", "connect", "codex", "--monitor"]);
    assert!(
        home.path().join(".codex/hooks.json").is_file(),
        "the connect wrote no Codex hook, so the rest of this test proves \
         nothing:\n{connected}"
    );

    for run in ["first", "second"] {
        let switched = cli(home.path())
            .arg("enforce")
            .output()
            .expect("run innerwarden enforce");
        let said = String::from_utf8_lossy(&switched.stderr);
        let out = String::from_utf8_lossy(&switched.stdout);
        assert_eq!(switched.status.code(), Some(1), "{run}: {said}");
        assert!(
            said.contains(
                "  codex - its PreToolUse hook is not active after this switch. Run `/hooks` \
                 inside Codex and trust the innerwarden hook"
            ),
            "{run}: {said}"
        );
        assert!(!out.contains("ENFORCEMENT configured"), "{run}: {out}");
    }
}

/// Taking the hook out of a group it shares with a hook of the person's
/// moves that hook inside the group (a group cannot hold an empty hook), and
/// the note that says so names its program only. Its command says
/// `failed:`, and the disconnect did not fail.
///
/// FAILS ON REVERT: name a moved hook by its whole command in
/// `agent_hooks::theirs_at` and the note holds `failed:`, which `agents
/// disconnect` reads as a failed agent: it exits 1.
#[test]
fn a_moved_hook_whose_command_says_failed_does_not_fail_the_disconnect() {
    let home = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join(".codex")).unwrap();
    let connected = run(home.path(), &["agents", "connect", "codex", "--monitor"]);
    let file = home.path().join(".codex/hooks.json");
    let mut settings: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&file)
            .unwrap_or_else(|_| panic!("the connect wrote no Codex hook:\n{connected}")),
    )
    .expect("the hooks file is JSON");
    settings["hooks"]["PreToolUse"][0]["hooks"]
        .as_array_mut()
        .expect("the connect wrote one group with our hook")
        .push(serde_json::json!({"type": "command", "command": "echo \"audit failed: x\""}));
    std::fs::write(&file, settings.to_string()).unwrap();

    let out = cli(home.path())
        .args(["agents", "disconnect", "codex"])
        .output()
        .expect("run innerwarden agents disconnect");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(0), "{said}");
    assert!(said.contains("of your own moved"), "{said}");
    assert!(said.contains("`echo`"), "{said}");
    assert!(!said.contains("failed:"), "{said}");
}

/// `install` wires Claude Code's hook: it says how to restart Claude Code,
/// in the same words as every other step.
#[test]
fn install_says_how_to_restart_claude_code() {
    let home = tempfile::TempDir::new().unwrap();
    // A configured Claude Code (an empty ~/.claude is no sign of it), so the
    // run does not depend on a `claude` on this machine's PATH.
    std::fs::create_dir_all(home.path().join(".claude")).unwrap();
    std::fs::write(home.path().join(".claude/settings.json"), "{}\n").unwrap();
    let out = run(home.path(), &["install"]);
    assert!(
        out.contains("InnerWarden guard hook installed for claude-code"),
        "{out}"
    );
    assert!(
        out.contains("  Claude Code: In Claude Code, type /exit, then run claude."),
        "install must say how to restart the agent whose hook it wrote, got:\n{out}"
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
