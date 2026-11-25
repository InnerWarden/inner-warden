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
use std::path::{Path, PathBuf};

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

/// Record the values a TOOL RESULT carried into `session`.
///
/// The PostToolUse half of the two-step defence. Same best-effort contract as
/// [`record_call`]: it can never fail a tool call, because it runs after the
/// tool already ran.
pub fn record_tool_result(session: Option<&str>, tool: &str, result: &str) {
    record_tool_result_at(session, tool, result, store_path());
}

fn record_tool_result_at(session: Option<&str>, tool: &str, result: &str, path: Option<PathBuf>) {
    let Some(session) = session.map(str::trim).filter(|s| !s.is_empty()) else {
        return;
    };
    let Some(path) = path else { return };
    let now = now_ms();
    let (session, tool, result) = (session.to_string(), tool.to_string(), result.to_string());
    save_after_answer(path, now, move |store| {
        let entry = store.sessions.entry(session).or_default();
        entry.last_seen_ms = now;
        entry.state.record_tool_result(&tool, &result, now);
    });
}

/// Record one screened call AND report, for each command line it carries,
/// whether the line carries a value that arrived in an earlier tool result.
/// The call is recorded once, however many lines it carries.
///
/// One function, because it is ONE read of the store. Asking these separately
/// meant loading and parsing the whole file twice on every single tool call,
/// and the hook is on the critical path of every one of them. That doubled cost
/// was caught by `the_session_layer_really_ran_during_the_burst`: it asserts a
/// burst counts above the per-minute threshold, `record_call` prunes anything
/// older than 60 seconds, and the extra parse pushed the burst past the window
/// under instrumentation so the count never rose. A latency canary, working.
pub fn record_call_and_taint(
    session: Option<&str>,
    commands: &[&str],
) -> (Option<Alert>, Vec<Option<(String, String)>>) {
    record_call_and_taint_at(session, commands, store_path())
}

fn record_call_and_taint_at(
    session: Option<&str>,
    commands: &[&str],
    path: Option<PathBuf>,
) -> (Option<Alert>, Vec<Option<(String, String)>>) {
    let untracked = || (None, vec![None; commands.len()]);
    let Some(session) = session.map(str::trim).filter(|s| !s.is_empty()) else {
        return untracked();
    };
    let Some(path) = path else {
        return untracked();
    };
    let now = now_ms();

    let mut store = read_store(&path);
    let entry = store.sessions.entry(session.to_string()).or_default();
    entry.last_seen_ms = now;
    // Read the taint BEFORE recording the call, so the answer is about the state
    // this command arrived into.
    let tainted: Vec<Option<(String, String)>> = commands
        .iter()
        .map(|command| {
            entry
                .state
                .tainted_argument(command, now)
                .map(|(v, t)| (v.to_string(), t.to_string()))
        })
        .collect();
    let alert = entry.state.record_call(now);

    let session = session.to_string();
    save_after_answer(path, now, move |store| {
        let entry = store.sessions.entry(session).or_default();
        entry.last_seen_ms = now;
        let _ = entry.state.record_call(now);
    });
    (alert, tainted)
}

/// The store at `path`, or an empty one where there is none or it cannot be
/// read. Every write replaces the file whole (`write_private`), so a reader
/// never sees half of one.
fn read_store(path: &Path) -> Store {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
        .unwrap_or_default()
}

/// Apply `change` to the store at `path` once the hook has answered
/// ([`crate::hook_net::after_answer`]); at once where no hook is answering
/// (`innerwarden check`, a test). What the store says about this call was
/// read before the answer: the write only keeps this call for the next one,
/// and decides nothing about this one. Under the deadline, a disk a build
/// keeps busy held that write for over a second (2026-11-25), and every
/// second of it counted as screening. The hook still writes it before it
/// ends, so the next call of a session that waits for this one (an agent
/// waits for its hook) reads it; cut at the limit on the clock, the call
/// keeps its answer and the next one misses this call's count.
///
/// The change is made to the store as it is when it is written, not as it
/// was read: under the store's lock, read again, changed, written whole. Two
/// hooks of one agent run at once (parallel tool calls); each writing the
/// store it had read put back what it read and dropped what the other had
/// added, a tool result's values (the taint) among them.
fn save_after_answer(path: PathBuf, now: i64, change: impl FnOnce(&mut Store) + Send + 'static) {
    crate::hook_net::after_answer(move || {
        #[cfg(debug_assertions)]
        crate::hook_net::test_session_delay();
        update_store(&path, now, change);
    });
}

/// How long a writer of the store waits for another writer's lock. A writer
/// holds it for one read, change and rename of a small file, but on a loaded
/// machine the writers before it in line take seconds. Past this the change
/// is dropped: this call goes uncounted, and nothing another writer added
/// is lost, as it would be by a write without the lock. Under the limit on
/// the clock after the answer.
const STORE_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Under the store's lock: read the store, apply `change`, prune, and
/// replace the file whole.
fn update_store(path: &Path, now: i64, change: impl FnOnce(&mut Store)) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let lock = match StoreLock::acquire(path, STORE_LOCK_WAIT) {
        Locked::Held(lock) => {
            // A writer makes a temporary only while it holds the lock: one
            // there now is a writer's that ended before it renamed it.
            remove_temporaries(path);
            Some(lock)
        }
        Locked::Busy => return,
        // No lock file to take (a folder it cannot be made in): written
        // whole as ever, without the lock, as before there was one.
        Locked::Unavailable => None,
    };
    let mut store = read_store(path);
    change(&mut store);
    prune(&mut store, now);
    if let Ok(raw) = serde_json::to_string(&store) {
        let _ = write_private(path, &raw);
    }
    drop(lock);
}

/// An advisory exclusive lock on the store's sibling `.lock` file, released
/// on drop and when the process ends.
struct StoreLock(std::fs::File);

/// What [`StoreLock::acquire`] got.
enum Locked {
    Held(StoreLock),
    /// Another writer kept it past the wait.
    Busy,
    /// The lock file could not be opened, or locking it failed.
    Unavailable,
}

impl StoreLock {
    fn acquire(path: &Path, wait: std::time::Duration) -> Locked {
        use fs4::FileExt;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let Ok(file) = options.open(path.with_extension("json.lock")) else {
            return Locked::Unavailable;
        };
        let started = std::time::Instant::now();
        loop {
            match FileExt::try_lock(&file) {
                Ok(()) => return Locked::Held(Self(file)),
                Err(fs4::TryLockError::WouldBlock) if started.elapsed() < wait => {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(fs4::TryLockError::WouldBlock) => return Locked::Busy,
                Err(fs4::TryLockError::Error(_)) => return Locked::Unavailable,
            }
        }
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        use fs4::FileExt;
        let _ = FileExt::unlock(&self.0);
    }
}

/// The prefix of a writer's temporary beside the store at `path`.
fn temporary_prefix(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    format!(".{name}.")
}

/// Remove the temporaries writers left beside the store at `path`.
fn remove_temporaries(path: &Path) {
    let (Some(dir), prefix) = (path.parent(), temporary_prefix(path)) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) && name.ends_with(".tmp") {
            let _ = std::fs::remove_file(entry.path());
        }
    }
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

/// Write 0600, whole: `body` goes to a temporary beside `path`, which then
/// replaces it. A reader sees the file before or after, never a part of it;
/// written in place, a hook that read it mid-write saw JSON cut short, took
/// the store for empty, and wrote that back, which dropped every session and
/// the values a tool result had left in it (the taint). The file records which
/// sessions touched sensitive paths, so it is not world-readable even though
/// it holds no file contents.
fn write_private(path: &Path, body: &str) -> std::io::Result<()> {
    use std::io::Write;
    let Some(dir) = path.parent() else {
        return Err(std::io::Error::other("the store has no folder"));
    };
    // Its own name per write: writers without the lock never share one.
    static WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let temporary = dir.join(format!(
        "{}{}.{}.tmp",
        temporary_prefix(path),
        std::process::id(),
        WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options
        .open(&temporary)
        .and_then(|mut file| file.write_all(body.as_bytes()))
        .and_then(|()| std::fs::rename(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
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

        let mut alerted = false;
        // Each iteration reads and writes the file exactly as a separate hook
        // process would.
        for _ in 0..=(innerwarden_agent_guard::session::NOTABLE_CALLS_PER_MINUTE + 1) {
            if record_call_and_taint_at(Some("sess-1"), &["ls"], Some(file.clone()))
                .0
                .is_some()
            {
                alerted = true;
            }
        }
        assert!(
            alerted,
            "a burst beyond the limit must be visible even though every call is a new process"
        );
    }

    /// Each command line of one call is asked whether it carries a value an
    /// earlier tool result brought, and the call is recorded once however
    /// many lines it carries.
    ///
    /// FAILS ON REVERT of the per-line answer (only one line is asked, so the
    /// second line's value goes unseen) or of the single record (two calls
    /// are counted).
    #[test]
    fn each_line_of_a_call_is_asked_and_the_call_counts_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("sessions.json");
        record_tool_result_at(
            Some("sess-2"),
            "WebFetch",
            "the mirror is at mirror.example.net",
            Some(file.clone()),
        );
        let (_, tainted) = record_call_and_taint_at(
            Some("sess-2"),
            &["ls -la", "curl -s https://mirror.example.net/p"],
            Some(file.clone()),
        );
        assert_eq!(tainted.len(), 2);
        assert!(tainted[0].is_none(), "{tainted:?}");
        assert_eq!(
            tainted[1]
                .as_ref()
                .map(|(value, tool)| (value.as_str(), tool.as_str())),
            Some(("mirror.example.net", "WebFetch"))
        );
        let store: Store =
            serde_json::from_str(&std::fs::read_to_string(&file).expect("store")).expect("json");
        assert_eq!(store.sessions["sess-2"].state.call_times_ms.len(), 1);
    }

    /// A reader of the store never sees it cut short while writers replace
    /// it: every read is the whole store, before or after a write.
    ///
    /// FAILS ON REVERT of the whole-file write (`std::fs::write` in place):
    /// the reader catches the file empty or half written.
    #[test]
    fn a_reader_never_sees_the_store_cut_short() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("sessions.json");
        for i in 0..MAX_SESSIONS {
            record_tool_result_at(
                Some(&format!("seed-{i}")),
                "WebFetch",
                "the mirror is at mirror.example.net and the key server at keys.example.org",
                Some(file.clone()),
            );
        }
        let done = std::sync::atomic::AtomicBool::new(false);
        let (reads, cut) = std::thread::scope(|scope| {
            let writers: Vec<_> = (0..4)
                .map(|w| {
                    let file = file.clone();
                    scope.spawn(move || {
                        for _ in 0..60 {
                            record_call_and_taint_at(
                                Some(&format!("seed-{w}")),
                                &["ls"],
                                Some(file.clone()),
                            );
                        }
                    })
                })
                .collect();
            let reader = scope.spawn(|| {
                let (mut reads, mut cut) = (0, 0);
                while !done.load(std::sync::atomic::Ordering::SeqCst) {
                    if let Ok(text) = std::fs::read_to_string(&file) {
                        reads += 1;
                        if serde_json::from_str::<Store>(&text).is_err() {
                            cut += 1;
                        }
                    }
                }
                (reads, cut)
            });
            for writer in writers {
                writer.join().expect("writer");
            }
            done.store(true, std::sync::atomic::Ordering::SeqCst);
            reader.join().expect("reader")
        });
        assert!(reads > 0, "the reader read the store");
        assert_eq!(cut, 0, "{cut} of {reads} reads saw the store cut short");
        let store = read_store(&file);
        assert_eq!(store.sessions.len(), MAX_SESSIONS, "no session was dropped");
    }

    /// Hooks of one agent that write at once keep every call and the values
    /// a tool result brought (the taint): each writes its change into the
    /// store as it is then, never the store it had read.
    ///
    /// FAILS ON REVERT of the lock and the second read (each writer puts back
    /// the store it read): calls go missing, and the tool result's value with
    /// them.
    #[test]
    fn writers_at_once_keep_every_call_and_the_taint() {
        const CALLS: usize = 15;
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("sessions.json");
        std::thread::scope(|scope| {
            for w in 0..6 {
                let file = file.clone();
                scope.spawn(move || {
                    for _ in 0..CALLS {
                        record_call_and_taint_at(
                            Some(&format!("par-{w}")),
                            &["git status"],
                            Some(file.clone()),
                        );
                    }
                });
            }
            let file = file.clone();
            scope.spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(5));
                record_tool_result_at(
                    Some("par-0"),
                    "WebFetch",
                    "the mirror is at mirror.example.net",
                    Some(file),
                );
            });
        });
        let store = read_store(&file);
        for w in 0..6 {
            assert_eq!(
                store.sessions[&format!("par-{w}")]
                    .state
                    .call_times_ms
                    .len(),
                CALLS,
                "par-{w}"
            );
        }
        let (_, tainted) = record_call_and_taint_at(
            Some("par-0"),
            &["curl -s https://mirror.example.net/p"],
            Some(file.clone()),
        );
        assert!(tainted[0].is_some(), "the tool result's value was kept");
        assert!(
            !std::fs::read_dir(dir.path())
                .unwrap()
                .flatten()
                .any(|e| e.file_name().to_string_lossy().ends_with(".tmp")),
            "no temporary is left"
        );
    }

    /// No session id means no tracking, and must never panic or create a file.
    #[test]
    fn an_absent_or_blank_session_is_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = Some(dir.path().join("sessions.json"));
        assert!(record_call_and_taint_at(None, &["ls"], file.clone())
            .0
            .is_none());
        assert!(record_call_and_taint_at(Some("   "), &["ls"], file.clone())
            .0
            .is_none());
        assert!(
            !dir.path().join("sessions.json").exists(),
            "nothing to record means nothing written"
        );
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
