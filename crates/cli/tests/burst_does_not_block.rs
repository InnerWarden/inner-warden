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
//! The env vars keep the run off the developer's own state: HOME above all,
//! because the hook rewires the Claude Code settings under it once per
//! version, and this test run against the real home once pointed every guard
//! hook of a machine at `target/debug/innerwarden`.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_innerwarden")
}

/// The burst, on top of the seeded calls, is above
/// `NOTABLE_CALLS_PER_MINUTE`, so the rate alert genuinely FIRES during
/// this run. That is the point: the property under test is not "no alert", it
/// is "an alert that fires does not refuse the command". A burst that stayed
/// under the threshold would pass whatever the verdict logic did, and prove
/// nothing about it.
///
/// The burst is counted, not timed. Spawning that many hooks inside the
/// tracker's one-minute window failed on a loaded runner (load 13 on 4 cores):
/// the early calls aged out of the window before the late ones ran, the alert
/// never fired, and the guard test below went red over the machine's speed.
/// So the session starts with `NOTABLE_CALLS_PER_MINUTE` calls already on
/// record ([`Host::seed_busy`]) and the burst only has to add the rest.
const NOTABLE: usize = innerwarden_agent_guard::session::NOTABLE_CALLS_PER_MINUTE as usize;
const BURST: usize = 10;

/// Unix milliseconds now, from the same clock the hook reads.
fn now_ms() -> i64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970");
    i64::try_from(since.as_millis()).expect("fits")
}

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

    /// Put `NOTABLE` calls on record for `session`, stamped an hour ahead of
    /// the clock so the one-minute window never ages them out however slow
    /// the run is. The next call the hook records crosses the threshold.
    fn seed_busy(&self, session: &str) {
        let ahead = now_ms() + 60 * 60 * 1000;
        let store = serde_json::json!({
            "sessions": {
                session: {
                    "last_seen_ms": now_ms(),
                    "call_times_ms": vec![ahead; NOTABLE],
                }
            }
        });
        std::fs::write(&self.sessions, store.to_string()).expect("seed the session store");
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
            .env("HOME", self._dir.path())
            .env("USERPROFILE", self._dir.path())
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
    host.seed_busy("burst-session");
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
///
/// Skipped under coverage, for the reason `.tarpaulin.toml` already predicts:
/// "if a coverage run dies with no failing test named, look for a test whose
/// assertion depends on TIME or on process supervision". This one spawns the
/// hook once per command in the burst (over a hundred processes when that was
/// measured, before the session was seeded), and
/// instrumenting every one of them turns a test of the session tracker into a
/// test of how fast the instrumentation can fork. Measured on the runner:
/// `Timed out waiting for test response` after sixty seconds, against sixteen
/// seconds uninstrumented locally.
///
/// It still runs, uninstrumented, in `build and test` on Linux, macOS and
/// Windows, which is where its answer actually matters.
#[cfg_attr(
    tarpaulin,
    ignore = "spawns the hook once per burst command; instrumented it times out rather than measures"
)]
#[test]
fn the_session_layer_really_ran_during_the_burst() {
    let host = Host::new();
    host.seed_busy("counted-session");
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
    // Every call of the burst was counted on top of the seeded ones: the
    // tracker ran in each hook, and the alert was over its threshold for all
    // of them. A count, so it holds on a runner of any speed.
    assert_eq!(
        calls,
        NOTABLE + BURST,
        "{calls} calls recorded; the burst test would pass without the alert ever firing"
    );
}
