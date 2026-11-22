//! A mark that a hook has record work still to do after its answer.
//!
//! The hook answers first and then writes its record and its alert
//! (`hook_net::after_answer`). That work still runs under the limit on the
//! clock (`hook_net::WALL_CAP`), and a hook that reaches it ends there: the
//! answer stands, and the record and the alert of that call were lost without
//! a trace (`record_health` heard only of a write that failed). Now the hook
//! leaves a mark beside the record before that work and takes it away after.
//! A mark whose hook is gone, or older than any hook may live, is a record
//! cut at the limit: the next hook, `innerwarden status` or the dashboard
//! turns it into a failure in `record_health`, with one alert per episode,
//! and removes the temporaries the cut writer left.
//!
//! The mark is `.hook-pending.<pid>` in the record's folder, holding the
//! second it was made. A temporary of the graph writer is
//! `.graph.json.<pid>.<n>.tmp` (`file_update::private_temp`).

use std::path::{Path, PathBuf};
use std::time::Duration;

/// The code a record cut at the limit is noted under in `record_health`.
pub const CUT_CODE: &str = "hook_record_cut_at_limit";

/// The name every mark starts with.
const MARK_PREFIX: &str = ".hook-pending.";

/// A mark older than this is stale whatever its process: a hook ends at
/// [`crate::hook_net::WALL_CAP`], plus the waits it may add
/// ([`crate::hook_net::allow_wait`], at most
/// [`crate::hook_net::MAX_ALLOWED_WAIT`]), and a pid can be reused.
pub fn stale_after() -> Duration {
    crate::hook_net::WALL_CAP + crate::hook_net::MAX_ALLOWED_WAIT + Duration::from_secs(30)
}

/// The mark this process leaves for `graph`.
fn mark_path(graph: &Path) -> Option<PathBuf> {
    Some(
        graph
            .parent()?
            .join(format!("{MARK_PREFIX}{}", std::process::id())),
    )
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Leave the mark before the work after the answer. Nothing where the
/// record's folder is not there or cannot be written (a jail whose launcher
/// keeps the record, say): the mark is a best effort, as the record is.
pub fn begin(graph: &Path) -> Option<PathBuf> {
    let mark = mark_path(graph)?;
    if !graph.parent().is_some_and(Path::is_dir) {
        return None;
    }
    std::fs::write(&mark, now_unix().to_string()).ok()?;
    Some(mark)
}

/// Take the mark away once the work is done.
pub fn finish(mark: &Path) {
    let _ = std::fs::remove_file(mark);
}

/// The temporaries the graph writer of process `pid` leaves beside
/// `graph` when it is cut: `.graph.json.<pid>.<n>.tmp`.
fn temporaries_of(graph: &Path, pid: u32) -> Vec<PathBuf> {
    let (Some(dir), Some(name)) = (graph.parent(), graph.file_name().and_then(|n| n.to_str()))
    else {
        return Vec::new();
    };
    let start = format!(".{name}.{pid}.");
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with(&start) && n.ends_with(".tmp"))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Remove the temporaries this process's graph writer left beside
/// `graph`: the end at the limit on the clock, which leaves the mark.
pub fn clean_own_temporaries(graph: &Path) {
    for temp in temporaries_of(graph, std::process::id()) {
        let _ = std::fs::remove_file(temp);
    }
}

/// Whether process `pid` is still running. Where that cannot be asked, it
/// is taken as running, and only the age of the mark makes it stale.
fn alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        // SAFETY: signal 0 sends nothing; it only asks whether the process
        // exists. ESRCH is "no such process"; EPERM means it exists.
        let sent = unsafe { libc::kill(pid, 0) };
        sent == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}

/// PURE: whether a mark made at `made_unix` by a process that is (or is
/// not) `alive` is stale at `now_unix`.
fn is_stale(made_unix: Option<u64>, alive: bool, now_unix: u64, stale_after: Duration) -> bool {
    !alive || made_unix.is_none_or(|made| now_unix.saturating_sub(made) > stale_after.as_secs())
}

/// The marks beside `graph` that are stale, each with its pid. This
/// process's own mark is never one.
fn stale_marks(graph: &Path, now: u64) -> Vec<(PathBuf, u32)> {
    let Some(dir) = graph.parent() else {
        return Vec::new();
    };
    let own = std::process::id();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let pid = name
                .to_str()?
                .strip_prefix(MARK_PREFIX)?
                .parse::<u32>()
                .ok()?;
            (pid != own).then(|| (entry.path(), pid))
        })
        .filter(|(path, pid)| {
            let made = std::fs::read_to_string(path)
                .ok()
                .and_then(|text| text.trim().parse::<u64>().ok());
            is_stale(made, alive(*pid), now, stale_after())
        })
        .collect()
}

/// Turn the stale marks beside `graph` into lost records: noted in
/// `record_health` under [`CUT_CODE`], one alert for the episode, the
/// marks and their writers' temporaries removed. The count of records
/// found lost.
pub fn sweep(graph: &Path) -> u64 {
    sweep_with(graph, crate::notify_io::fire_text)
}

/// [`sweep`] with the alert given: the tests hear it instead of the
/// channels of whoever runs them.
fn sweep_with(graph: &Path, alert: impl FnOnce(&str)) -> u64 {
    let stale = stale_marks(graph, now_unix());
    let mut lost = 0u64;
    for (mark, pid) in &stale {
        for temp in temporaries_of(graph, *pid) {
            let _ = std::fs::remove_file(temp);
        }
        // Removed first: two sweeps at once count a mark once, by whoever
        // took it away.
        if std::fs::remove_file(mark).is_ok() {
            lost += 1;
        }
    }
    if lost > 0 {
        let outage = crate::record_health::note_failures_at(graph, CUT_CODE, lost);
        if crate::record_health::is_first_of_episode_at(graph) {
            alert(&outage.summary());
        }
    }
    lost
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_mark_is_stale_when_its_hook_is_gone_or_too_old() {
        let limit = Duration::from_secs(100);
        assert!(is_stale(Some(1_000), false, 1_001, limit));
        assert!(!is_stale(Some(1_000), true, 1_050, limit));
        assert!(is_stale(Some(1_000), true, 1_101, limit));
        assert!(is_stale(None, true, 1_000, limit), "an unreadable mark");
    }

    /// FAILS ON REVERT of the sweep: a mark left by a hook that is gone (a
    /// pid no process has) becomes one lost record in `record_health`, its
    /// writer's temporary is removed, and a second sweep finds nothing.
    #[cfg(unix)]
    #[test]
    fn a_mark_left_by_a_hook_that_is_gone_is_a_lost_record() {
        let dir = tempfile::tempdir().unwrap();
        let graph = dir.path().join("graph.json");
        std::fs::write(&graph, "{}").unwrap();
        // Past any pid the kernel hands out (pid_max is at most 2^22).
        let gone = 4_194_304u32 + 17;
        let mark = dir.path().join(format!("{MARK_PREFIX}{gone}"));
        std::fs::write(&mark, now_unix().to_string()).unwrap();
        let temp = dir.path().join(format!(".graph.json.{gone}.0.tmp"));
        std::fs::write(&temp, "partial").unwrap();
        let other = dir.path().join(".graph.json.1.0.tmp");
        std::fs::write(&other, "someone else's").unwrap();

        let mut alerts = Vec::new();
        assert_eq!(sweep_with(&graph, |text| alerts.push(text.to_string())), 1);
        assert_eq!(alerts.len(), 1, "one alert for the episode");
        assert!(!mark.exists());
        assert!(!temp.exists());
        assert!(other.exists(), "another writer's temporary stays");
        let outage = crate::record_health::report_at(&graph).expect("noted");
        assert_eq!(outage.code, CUT_CODE);
        assert_eq!(outage.lost, 1);
        assert_eq!(sweep_with(&graph, |_| panic!("nothing new")), 0);

        // A second cut in the same episode is counted, and not alerted on.
        let again = dir.path().join(format!("{MARK_PREFIX}{}", gone + 1));
        std::fs::write(&again, now_unix().to_string()).unwrap();
        assert_eq!(sweep_with(&graph, |_| panic!("one alert per episode")), 1);
        assert_eq!(crate::record_health::report_at(&graph).unwrap().lost, 2);
    }

    /// A mark of this process (its work is running) and a young mark of a
    /// running process are no lost record.
    #[test]
    fn a_mark_whose_hook_still_runs_is_left() {
        let dir = tempfile::tempdir().unwrap();
        let graph = dir.path().join("graph.json");
        let own = begin(&graph).expect("the folder is there");
        // pid 1 runs on every unix machine.
        let running = dir.path().join(format!("{MARK_PREFIX}1"));
        std::fs::write(&running, now_unix().to_string()).unwrap();
        assert_eq!(sweep_with(&graph, |_| panic!("no alert")), 0);
        assert!(own.exists() && running.exists());
        finish(&own);
        assert!(!own.exists());
        assert!(crate::record_health::report_at(&graph).is_none());
    }
}
