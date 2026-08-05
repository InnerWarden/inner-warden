//! Behavioural session state that survives between hook invocations.
//!
//! # Why a file
//!
//! `agent-guard` ships `SessionTracker`, which detects behaviour that only shows
//! up ACROSS calls: a burst of tool calls, repeated failures, several sensitive
//! files read in one session. None of it was reachable from this binary, and the
//! reason was structural rather than commercial.
//!
//! `SessionTracker` holds `Instant`s. `Instant` is monotonic and process local,
//! so it cannot be serialised and handed to the next process. That is fine for a
//! long-running daemon, which is where it was used. But `innerwarden hook` is a
//! ONE-SHOT process: it starts, screens one tool call, answers, and exits. An
//! in-memory tracker is empty on every single call, so a rate per minute could
//! never be observed no matter how many calls the agent made.
//!
//! `PersistedSession` fixes the shape (wall-clock milliseconds instead of
//! `Instant`), and this module gives it somewhere to live: one small JSON file,
//! keyed by the session id the hook already reads out of the agent's payload.
//!
//! # Deliberately best-effort
//!
//! Every failure here is swallowed. A corrupt or unreadable state file must
//! never wedge an agent's tool call: the command has already been screened by
//! the pattern engine, and this layer only ADDS a behavioural signal on top. A
//! guard that stops working because it could not write a counter would be worse
//! than the counter being missed.

use std::collections::BTreeMap;
use std::path::PathBuf;

use innerwarden_agent_guard::session::{Alert, PersistedSession};

/// Sessions kept in the file. Old ones are evicted oldest-first so a machine
/// that runs agents for months does not accumulate state without end.
const MAX_SESSIONS: usize = 64;

/// A session with no activity for this long is dropped on the next write. Well
/// past the one-minute rate window, so an idle-then-resumed session is still
/// treated as the same session by a human's standards.
const SESSION_TTL_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Store {
    /// session id -> state
    #[serde(default)]
    sessions: BTreeMap<String, Entry>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Entry {
    #[serde(default)]
    last_seen_ms: i64,
    #[serde(flatten)]
    state: PersistedSession,
}

fn store_path() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("IW_SESSION_FILE") {
        return Some(PathBuf::from(explicit));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/innerwarden/sessions.json"))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Record one screened call for `session` and return any behavioural alert.
///
/// `None` when there is nothing to say, when no session id was supplied, or when
/// the state could not be read or written. See the module note on why failure is
/// silent.
pub fn record_call(session: Option<&str>) -> Option<Alert> {
    let session = session?.trim();
    if session.is_empty() {
        return None;
    }
    let path = store_path()?;
    let now = now_ms();

    let mut store: Store = std::fs::read_to_string(&path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default();

    let entry = store.sessions.entry(session.to_string()).or_default();
    entry.last_seen_ms = now;
    let alert = entry.state.record_call(now);

    prune(&mut store, now);

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(raw) = serde_json::to_string(&store) {
        let _ = write_private(&path, &raw);
    }
    alert
}

/// Drop expired sessions, then the oldest ones if still over the cap.
///
/// Pure over the store so the eviction rule is testable without the filesystem.
fn prune(store: &mut Store, now: i64) {
    store
        .sessions
        .retain(|_, e| now.saturating_sub(e.last_seen_ms) < SESSION_TTL_MS);
    if store.sessions.len() <= MAX_SESSIONS {
        return;
    }
    let mut by_age: Vec<(String, i64)> = store
        .sessions
        .iter()
        .map(|(k, e)| (k.clone(), e.last_seen_ms))
        .collect();
    by_age.sort_by_key(|(_, ts)| *ts);
    let excess = store.sessions.len() - MAX_SESSIONS;
    for (key, _) in by_age.into_iter().take(excess) {
        store.sessions.remove(&key);
    }
}

/// Write 0600. The file records which sessions touched sensitive paths, so it is
/// not world-readable even though it holds no file contents.
fn write_private(path: &std::path::Path, body: &str) -> std::io::Result<()> {
    std::fs::write(path, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(last_seen_ms: i64) -> Entry {
        Entry {
            last_seen_ms,
            state: PersistedSession::default(),
        }
    }

    /// REGRESSION ANCHOR. The behavioural limit must be observable ACROSS
    /// processes, which is the only reason this store exists: `innerwarden hook`
    /// is a fresh process per tool call, so an in-memory tracker would report a
    /// rate of one, forever, no matter what the agent did.
    ///
    /// FAILS ON REVERT: drop the persistence and the alert never fires.
    #[test]
    fn a_burst_across_separate_invocations_raises_an_alert() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("sessions.json");
        std::env::set_var("IW_SESSION_FILE", &file);

        let mut alerted = false;
        // Each iteration reads and writes the file exactly as a separate hook
        // process would.
        for _ in 0..=(innerwarden_agent_guard::session::MAX_CALLS_PER_MINUTE + 1) {
            if record_call(Some("sess-1")).is_some() {
                alerted = true;
            }
        }
        std::env::remove_var("IW_SESSION_FILE");
        assert!(
            alerted,
            "a burst beyond the limit must be visible even though every call is a new process"
        );
    }

    /// No session id means no tracking, and must never panic or create a file.
    #[test]
    fn an_absent_or_blank_session_is_ignored() {
        assert!(record_call(None).is_none());
        assert!(record_call(Some("   ")).is_none());
    }

    #[test]
    fn expired_sessions_are_dropped() {
        let mut store = Store::default();
        store.sessions.insert("fresh".into(), entry(1_000_000));
        store.sessions.insert("stale".into(), entry(0));
        prune(&mut store, 1_000_000 + SESSION_TTL_MS - 1);
        assert!(store.sessions.contains_key("fresh"));
        assert!(
            !store.sessions.contains_key("stale"),
            "a session past its TTL must not be kept"
        );
    }

    /// The file cannot grow without bound on a machine that runs agents for
    /// months: past the cap, the oldest sessions go first.
    #[test]
    fn the_store_is_capped_and_evicts_the_oldest_first() {
        let mut store = Store::default();
        for i in 0..(MAX_SESSIONS as i64 + 10) {
            // All within TTL, so only the cap can evict.
            store.sessions.insert(format!("s{i:03}"), entry(1_000 + i));
        }
        prune(&mut store, 2_000);
        assert_eq!(store.sessions.len(), MAX_SESSIONS);
        assert!(
            store
                .sessions
                .contains_key(&format!("s{:03}", MAX_SESSIONS as i64 + 9)),
            "the newest session must survive"
        );
        assert!(
            !store.sessions.contains_key("s000"),
            "the oldest session must be the one evicted"
        );
    }
}
