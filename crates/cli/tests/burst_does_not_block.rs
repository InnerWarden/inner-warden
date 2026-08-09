//! End-to-end: a burst of harmless commands must not stop the agent.
//!
//! THE DEFECT, measured on the operator's own machine over ten days of real
//! hook traffic: 15,602 screened commands produced 1,620 blocks, and 1,493 of
//! those were the session rate rule. 1,485 carried no other suspicion at all.
//! `cat build.mjs` and `sed -n '730,830p' Cargo.lock` were refused for arriving
//! quickly, roughly 150 interruptions a day for nothing.
//!
//! The unit tests in `main.rs` cover the decision function. This runs the REAL
//! binary over the REAL session store, because the bug lived in the seam
//! between them: a rate alert crossing from the persisted tracker into the
//! verdict, then `--block-review` turning it into a refusal.
//!
//! Both env vars keep the run off the developer's own state.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// Above `NOTABLE_CALLS_PER_MINUTE`, so the rate alert genuinely FIRES during
/// this run. That is the point: the property under test is not "no alert", it
/// is "an alert that fires does not refuse the command". A burst that stayed
/// under the threshold would pass whatever the verdict logic did, and prove
/// nothing about it.
const BURST: usize = innerwarden_agent_guard::session::NOTABLE_CALLS_PER_MINUTE as usize + 10;

struct Host {
    _dir: tempfile::TempDir,
    graph: std::path::PathBuf,
    sessions: std::path::PathBuf,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::TempDir::new().expect("scratch dir");
        let graph = dir.path().join("graph.json");
        let sessions = dir.path().join("sessions.json");
        Self {
            _dir: dir,
            graph,
            sessions,
        }
    }

    /// Screen one command exactly as the PreToolUse hook does. `true` = allowed.
    fn screen(&self, session: &str, command: &str) -> bool {
        let payload = serde_json::json!({
            "session_id": session,
            "tool_name": "Bash",
            "tool_input": {"command": command},
        })
        .to_string();

        let mut child = Command::new(bin())
            .args(["hook", "--block-review"])
            .env("IW_GRAPH_FILE", &self.graph)
            .env("IW_SESSION_FILE", &self.sessions)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run innerwarden");
        child
            .stdin
            .as_mut()
            .expect("stdin")
            .write_all(payload.as_bytes())
            .expect("write stdin");
        child
            .wait_with_output()
            .expect("collect output")
            .status
            .success()
    }
}

/// FAILS ON REVERT: restore the `allow` -> `review` promotion in
/// `apply_behaviour` and every command past the threshold is refused.
#[test]
fn a_burst_of_harmless_commands_is_never_refused() {
    let host = Host::new();
    let mut refused = Vec::new();

    for n in 0..BURST {
        // Deliberately dull: reading a file in the repo is the single most
        // common thing an agent does, and it is what the rate rule was refusing.
        let command = format!("cat README.md # read {n}");
        if !host.screen("burst-session", &command) {
            refused.push(n);
        }
    }

    assert!(
        refused.is_empty(),
        "{} of {BURST} harmless commands refused (first at #{}). Tempo is not \
         evidence about the command in hand.",
        refused.len(),
        refused[0],
    );
}

/// Guards against the test above passing for the wrong reason.
///
/// If session tracking silently stopped running, every command would be allowed
/// and the burst test would go green while proving nothing. So assert the state
/// the tracker is supposed to be keeping actually exists and counted the burst.
#[test]
fn the_session_layer_really_ran_during_the_burst() {
    let host = Host::new();
    for n in 0..BURST {
        host.screen("counted-session", &format!("cat README.md # read {n}"));
    }

    let raw = std::fs::read_to_string(&host.sessions)
        .expect("the hook must persist session state for the next process");
    let store: serde_json::Value = serde_json::from_str(&raw).expect("session store is valid JSON");
    // `Entry` flattens `PersistedSession`, so the call log sits directly on the
    // session entry rather than under a `state` key.
    let calls = store["sessions"]["counted-session"]["call_times_ms"]
        .as_array()
        .expect("the burst must be recorded against the session id")
        .len();
    assert!(
        calls as u32 > innerwarden_agent_guard::session::NOTABLE_CALLS_PER_MINUTE,
        "only {calls} calls recorded, below the threshold that raises the alert; \
         the burst test would pass without the alert ever firing"
    );
}
