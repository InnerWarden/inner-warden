//! Whether the local record is actually recording, and for how long it has not.
//!
//! # Why this exists
//!
//! On 2026-08-05 an install stopped recording for six hours. The graph had
//! reached 16,777,528 bytes, 312 past the reader limit applied to it, so every
//! write failed at its verification read. The failure path was a single
//! `eprintln!` into hook stderr, which nobody reads, so the only symptom the
//! operator ever saw was a dashboard whose newest entry was six hours old. They
//! had to ask "where are the current ones?" to find out.
//!
//! The size bug is fixed. This module fixes the worse half: a guardrail that
//! stops recording must say so somewhere a human will look. The record file
//! itself cannot carry the signal, because the thing that failed IS writing it,
//! so the state lives in a small sibling file that the CLI and the dashboard
//! both read.
//!
//! Best-effort throughout. This is health reporting for a telemetry path; it
//! must never be able to change a verdict or fail a command.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Sibling of the graph file. Never inside it: the write that failed is the one
/// that would have carried the news.
fn health_path(graph: &Path) -> PathBuf {
    graph.with_file_name("record-health.json")
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A recording outage in progress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outage {
    /// Stable, path-free error code, so a health report cannot echo local data.
    pub code: String,
    /// Unix seconds of the FIRST failure in this episode. Kept across repeats
    /// because "failing since 17:43" is the fact that matters, not "failed 4s
    /// ago", which is what a last-failure timestamp would have shown after six
    /// hours of silence.
    pub since_unix: u64,
    /// How many writes have been lost in this episode.
    pub lost: u64,
}

impl Outage {
    pub fn seconds(&self) -> u64 {
        now_unix().saturating_sub(self.since_unix)
    }

    /// One line, safe to print anywhere: no paths, no command text.
    pub fn summary(&self) -> String {
        let secs = self.seconds();
        let ago = if secs >= 7200 {
            format!("{} hours", secs / 3600)
        } else if secs >= 120 {
            format!("{} minutes", secs / 60)
        } else {
            format!("{secs} seconds")
        };
        let lost = if self.lost == 0 {
            "actions lost".to_string()
        } else {
            format!("{} action(s) lost", self.lost)
        };
        format!(
            "InnerWarden has not recorded for {ago} ({lost}, {}). \
             Screening still ran; only the local record is affected. \
             Run `innerwarden graph --stats` after the next command to confirm recovery.",
            self.code
        )
    }
}

fn parse(bytes: &str) -> Option<Outage> {
    let v: Value = serde_json::from_str(bytes).ok()?;
    Some(Outage {
        code: v.get("code")?.as_str()?.to_string(),
        since_unix: v.get("since_unix")?.as_u64()?,
        lost: v.get("lost").and_then(Value::as_u64).unwrap_or(1),
    })
}

/// The persisted outage for this graph path, if any.
pub fn read_at(graph: &Path) -> Option<Outage> {
    parse(&std::fs::read_to_string(health_path(graph)).ok()?)
}

/// The outage to REPORT for this graph path.
///
/// A marker file cannot cover every fault: the commonest one, a graph directory
/// that is not writable, also stops the marker being written. So when there is
/// no marker, probe. The graph's own mtime dates the episode, which is the
/// precise fact the operator wanted ("the newest entry is six hours old").
pub fn report_at(graph: &Path) -> Option<Outage> {
    if let Some(persisted) = read_at(graph) {
        return Some(persisted);
    }
    if directory_is_writable(graph) {
        return None;
    }
    Some(Outage {
        code: "graph_directory_unwritable".into(),
        since_unix: last_write_unix(graph).unwrap_or_else(now_unix),
        lost: 0,
    })
}

/// Can this process still write beside the graph? Probes rather than inspecting
/// mode bits, which say nothing about ACLs, read-only mounts, or a full disk.
///
/// # A directory that does not exist yet is not a fault
///
/// This used to answer `false` the moment the store directory was absent, and
/// [`report_at`] turns `false` into an outage. On a brand-new install nothing
/// has been recorded, so the store has never been created, so the first
/// `innerwarden graph` a new user ran told them:
///
/// ```text
/// InnerWarden has not recorded for 0 seconds (actions lost, graph_directory_unwritable)
/// ```
///
/// and the dashboard served the same sentence. A fresh box is not a broken one:
/// this is the mistake [`crate::status`] was written to forbid, reproduced in a
/// different module. "Not there yet" is not "cannot be written".
///
/// So walk up to the nearest ancestor that DOES exist and probe that instead: if
/// a file can be created there, the store can be created there too, and there is
/// nothing to report. Asking the question must not create the directory as a
/// side effect, so nothing here calls `create_dir_all`; the recording path
/// creates the store when it has something to record.
fn directory_is_writable(graph: &Path) -> bool {
    let Some(dir) = graph.parent() else {
        return false;
    };
    // A bare filename has an empty parent, which means the current directory
    // rather than the filesystem root.
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    let Some(existing) = nearest_existing_ancestor(dir) else {
        return false;
    };
    // Something is there and it is not a directory: a file standing where the
    // store must go can never become the store, and no amount of waiting fixes
    // it. That IS a fault, and it is reported as one.
    if !existing.is_dir() {
        return false;
    }
    probe_writable(existing)
}

/// The closest ancestor of `dir` (including `dir`) that exists on disk.
///
/// `None` only when the walk runs out of components without finding anything,
/// which on a real filesystem means the root itself is unreadable.
fn nearest_existing_ancestor(dir: &Path) -> Option<&Path> {
    let mut candidate = dir;
    loop {
        // `symlink_metadata` rather than `exists()`: a dangling symlink standing
        // where the store must go exists as an entry, and treating it as "not
        // there yet" would have us probe its parent and report health while
        // every write to it fails.
        if std::fs::symlink_metadata(candidate).is_ok() {
            return Some(candidate);
        }
        candidate = match candidate.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => return None,
        };
    }
}

/// Write and remove a file in `dir`. The same permissions creating the store
/// needs, exercised rather than inferred.
fn probe_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".iw-write-probe.{}", std::process::id()));
    match std::fs::write(&probe, b"") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn last_write_unix(graph: &Path) -> Option<u64> {
    std::fs::metadata(graph)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// The outage in progress for the configured graph path, if any.
///
/// Resolved through [`crate::graph_io::graph_path`] and NOT by calling the model
/// crate a second time. A second resolver is how a path fix ships doing nothing:
/// this call site had its own copy of "env override, else `$HOME`", so it would
/// have gone on reporting the health of a file in the operator home while every
/// write went to the location `/etc/innerwarden/guard.toml` declares.
pub fn current() -> Option<Outage> {
    report_at(&crate::graph_io::graph_path()?)
}

/// Record one lost write, preserving the episode's start time.
///
/// Returns the resulting state so a caller can decide whether this is the first
/// failure of an episode and therefore worth an out-of-band notification.
pub fn note_failure_at(graph: &Path, code: &str) -> Outage {
    let previous = read_at(graph);
    // A new fault opens a new episode, so it may notify again. Only a REPEAT of
    // the same fault must stay quiet, or a broken install sends one message per
    // command.
    let first_of_episode = previous.as_ref().is_none_or(|p| p.code != code);
    let outage = match previous {
        Some(p) if p.code == code => Outage {
            lost: p.lost.saturating_add(1),
            ..p
        },
        // A DIFFERENT failure code restarts the episode: it is a new fault, and
        // carrying the old start time forward would misreport how long this one
        // has been happening.
        _ => Outage {
            code: code.to_string(),
            since_unix: now_unix(),
            lost: 1,
        },
    };
    let body = json!({
        "code": outage.code,
        "since_unix": outage.since_unix,
        "lost": outage.lost,
        "first_of_episode": first_of_episode,
    });
    let _ = std::fs::write(health_path(graph), body.to_string());
    outage
}

/// Clear the outage after a write succeeds. Returns the episode that just
/// ended, so recovery can be reported as plainly as the failure was.
pub fn note_success_at(graph: &Path) -> Option<Outage> {
    let previous = read_at(graph)?;
    let _ = std::fs::remove_file(health_path(graph));
    Some(previous)
}

/// True when this failure opened a new episode, i.e. worth telling someone
/// about. Repeats within an episode must stay quiet or a broken install would
/// send a notification per command.
pub fn is_first_of_episode_at(graph: &Path) -> bool {
    std::fs::read_to_string(health_path(graph))
        .ok()
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| v.get("first_of_episode").and_then(Value::as_bool))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn graph_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("graph.json")
    }

    /// REGRESSION ANCHOR. Six hours of lost recording were reported only on
    /// stderr. A failure must leave state a human-facing surface can read.
    ///
    /// FAILS ON REVERT: drop the write in `note_failure_at` and nothing persists.
    #[test]
    fn a_failed_write_leaves_a_readable_outage() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        assert!(read_at(&g).is_none(), "healthy install reports nothing");

        let outage = note_failure_at(&g, "write_failed");
        assert_eq!(outage.lost, 1);
        assert!(is_first_of_episode_at(&g));

        let read_back = read_at(&g).expect("outage is durable");
        assert_eq!(read_back.code, "write_failed");
        assert_eq!(read_back.lost, 1);
    }

    /// The start time is what makes the report useful. Overwriting it on every
    /// repeat would have reported "failing for 4 seconds" after six hours.
    #[test]
    fn repeats_accumulate_losses_and_keep_the_first_timestamp() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        let first = note_failure_at(&g, "write_failed");
        let third = {
            note_failure_at(&g, "write_failed");
            note_failure_at(&g, "write_failed")
        };
        assert_eq!(third.lost, 3);
        assert_eq!(
            third.since_unix, first.since_unix,
            "the episode start must not move"
        );
        assert!(
            !is_first_of_episode_at(&g),
            "only the first failure may notify, or a broken install spams"
        );
    }

    /// A new fault is a new episode; inheriting the old start time would
    /// misreport its duration.
    #[test]
    fn a_different_failure_starts_a_new_episode() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        note_failure_at(&g, "write_failed");
        note_failure_at(&g, "write_failed");
        let other = note_failure_at(&g, "lock_timed_out");
        assert_eq!(other.code, "lock_timed_out");
        assert_eq!(other.lost, 1, "losses belong to their own episode");
        assert!(is_first_of_episode_at(&g), "a new fault may notify again");
    }

    #[test]
    fn a_successful_write_clears_the_outage_and_reports_what_ended() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        note_failure_at(&g, "write_failed");
        note_failure_at(&g, "write_failed");
        let ended = note_success_at(&g).expect("the ended episode is returned");
        assert_eq!(ended.lost, 2);
        assert!(read_at(&g).is_none(), "recovery must clear the state");
        assert!(
            note_success_at(&g).is_none(),
            "a healthy install reports no recovery"
        );
    }

    /// The summary is printed to terminals and may reach a notification
    /// transport, so it must carry no local detail.
    #[test]
    fn the_summary_names_the_impact_without_leaking_anything() {
        let outage = Outage {
            code: "write_failed".into(),
            since_unix: now_unix().saturating_sub(6 * 3600),
            lost: 1414,
        };
        let s = outage.summary();
        assert!(s.contains("6 hours"), "duration must be legible: {s}");
        assert!(s.contains("1414"), "the loss count must be there: {s}");
        assert!(
            s.contains("Screening still ran"),
            "must not read as 'you were unprotected': {s}"
        );
        assert!(!s.contains('/'), "no paths in a health line: {s}");
    }

    /// The commonest recording fault, an unwritable graph directory, also stops
    /// the marker being written. A file-only signal would be silent for exactly
    /// the case it exists to catch, so the report probes as well.
    ///
    /// FAILS ON REVERT: point `report_at` back at `read_at` and this reports a
    /// healthy install while nothing is being recorded.
    #[cfg(unix)]
    #[test]
    fn an_unwritable_directory_is_reported_even_though_no_marker_can_be_written() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::create_dir(&store).unwrap();
        let g = store.join("graph.json");
        std::fs::write(&g, "{}").unwrap();
        assert!(report_at(&g).is_none(), "writable means healthy");

        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o500)).unwrap();
        let outage = report_at(&g).expect("an unwritable store is an outage");
        assert_eq!(outage.code, "graph_directory_unwritable");
        assert!(
            outage.since_unix > 0,
            "the last successful write dates the episode"
        );
        assert!(outage.summary().contains("has not recorded"));

        std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(report_at(&g).is_none(), "recovery must clear the report");
    }

    /// A persisted marker wins over the probe: it carries the real error code
    /// and the real loss count, which a probe cannot know.
    #[test]
    fn a_persisted_marker_is_preferred_over_the_probe() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        note_failure_at(&g, "graph_write_failed");
        let reported = report_at(&g).expect("marker is reported");
        assert_eq!(reported.code, "graph_write_failed");
        assert_eq!(reported.lost, 1);
    }

    /// REGRESSION ANCHOR. A brand-new install reported itself broken.
    ///
    /// Nothing has been recorded yet, so the store directory has never been
    /// created, so `directory_is_writable` answered false and `report_at` turned
    /// that into "InnerWarden has not recorded for 0 seconds (actions lost,
    /// graph_directory_unwritable)" on the first `innerwarden graph` and on the
    /// dashboard. A fresh box is not a broken one.
    ///
    /// FAILS ON REVERT: put back `if !dir.exists() { return false; }` and this
    /// reports an outage on a directory nothing is wrong with.
    #[test]
    fn a_store_directory_that_does_not_exist_yet_is_not_an_outage() {
        let dir = tempfile::tempdir().unwrap();
        // Two levels deep and absent, exactly as a fresh install finds it before
        // its first recorded action.
        let store = dir.path().join("innerwarden").join("store");
        let g = store.join("graph.json");
        assert!(!store.exists(), "precondition: the store is not there yet");

        assert!(
            report_at(&g).is_none(),
            "a fresh install has recorded nothing; that is not an outage"
        );
        assert!(
            !store.exists(),
            "asking whether the store could be written must not create it"
        );
    }

    /// The other half of the same question: "could be created" is established by
    /// probing the nearest existing ancestor, so an absent store under an
    /// ancestor that CANNOT be written is still reported.
    ///
    /// Without this the fix would be indistinguishable from deleting the check.
    ///
    /// FAILS ON REVERT: return `true` for any absent directory instead of
    /// probing, and a store that can never be created reads as healthy.
    #[cfg(unix)]
    #[test]
    fn an_absent_store_under_an_unwritable_parent_is_still_an_outage() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("locked");
        std::fs::create_dir(&parent).unwrap();
        let g = parent.join("store").join("graph.json");
        assert!(
            report_at(&g).is_none(),
            "precondition: creatable while the parent is writable"
        );

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
        let outage = report_at(&g).expect("a store that cannot be created is an outage");
        assert_eq!(outage.code, "graph_directory_unwritable");

        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(report_at(&g).is_none(), "recovery must clear the report");
    }

    /// A plain file standing where the store must go can never become the store.
    /// Unlike an absent directory, waiting does not fix it, so it is a fault.
    #[test]
    fn a_file_standing_where_the_store_belongs_is_an_outage() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        std::fs::write(&store, b"not a directory").unwrap();
        let g = store.join("graph.json");

        let outage = report_at(&g).expect("a file in the way is a real fault");
        assert_eq!(outage.code, "graph_directory_unwritable");
    }

    #[test]
    fn corrupt_health_state_reads_as_healthy_rather_than_failing() {
        let dir = tempfile::tempdir().unwrap();
        let g = graph_in(&dir);
        std::fs::write(health_path(&g), "{not json").unwrap();
        assert!(read_at(&g).is_none());
        assert!(!is_first_of_episode_at(&g));
    }
}
