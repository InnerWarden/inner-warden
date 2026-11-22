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
///
/// The mark appears whole: written to `.hook-pending.<pid>.tmp` and renamed
/// to its name, so a sweep never reads it empty (a mark created and then
/// written was read empty in between, taken for stale with its hook alive,
/// alerted on and removed, and that hook's record lost). The folder is
/// shared with the agent's account and the names are predictable, so the
/// temporary is created only where nothing stands (a link planted there is
/// never followed), and takes the mode and group the folder implies, as
/// every file this product creates there. A rename replaces a link at the
/// mark's name, never writes through it.
pub fn begin(graph: &Path) -> Option<PathBuf> {
    let mark = mark_path(graph)?;
    let dir = graph.parent()?;
    if !dir.is_dir() {
        return None;
    }
    let temp = dir.join(format!("{MARK_PREFIX}{}{TEMP_SUFFIX}", std::process::id()));
    let file = match create_new(&temp) {
        Ok(file) => file,
        // Left by an earlier process of the same pid, or planted: removing a
        // name never follows it.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(&temp).ok()?;
            create_new(&temp).ok()?
        }
        Err(_) => return None,
    };
    let written = write_mark(file, dir);
    if !written || std::fs::rename(&temp, &mark).is_err() {
        let _ = std::fs::remove_file(&temp);
        return None;
    }
    Some(mark)
}

/// The suffix of a mark's temporary, before it is renamed to its name.
const TEMP_SUFFIX: &str = ".tmp";

/// Create `path` where nothing stands, without following a link.
fn create_new(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    innerwarden_safe_io::harden(&mut options);
    options.open(path)
}

/// Give the new mark the folder's mode and group, and the second it was made.
fn write_mark(mut file: std::fs::File, dir: &Path) -> bool {
    use std::io::Write;
    // Best effort, as for the health record: a mark the next writer cannot
    // read is still a mark this one can remove.
    #[cfg(unix)]
    let _ = innerwarden_agent_guard::file_update::apply_new_file_ownership(&file, dir);
    #[cfg(not(unix))]
    let _ = dir;
    file.write_all(now_unix().to_string().as_bytes()).is_ok()
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

/// PURE: whether a mark is stale at `now_unix`: its process is not
/// `alive`, or it is older than any hook may live, by the second written in
/// it (`made_unix`) or, when that cannot be read, by the file's own time
/// (`modified_unix`). A mark that cannot be read is never stale for that
/// alone while its process runs: that was a mark being written.
fn is_stale(
    made_unix: Option<u64>,
    modified_unix: Option<u64>,
    alive: bool,
    now_unix: u64,
    stale_after: Duration,
) -> bool {
    let too_old = |at: u64| now_unix.saturating_sub(at) > stale_after.as_secs();
    !alive || made_unix.or(modified_unix).is_some_and(too_old)
}

/// What a mark holds, read without following a link: the second it was
/// made, if it says one, and the file's own time. `None` for what is not
/// a regular file (a link or a folder planted at the name), which is no
/// mark of a hook's.
fn read_mark(path: &Path) -> Option<(Option<u64>, Option<u64>)> {
    use std::io::Read;
    let file = innerwarden_safe_io::open_no_follow(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !innerwarden_safe_io::is_regular_file(&metadata) {
        return None;
    }
    let modified = metadata
        .modified()
        .ok()
        .and_then(|at| at.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    let mut text = String::new();
    let made = file
        .take(32)
        .read_to_string(&mut text)
        .ok()
        .and_then(|_| text.trim().parse::<u64>().ok());
    Some((made, modified))
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
            read_mark(path).is_some_and(|(made, modified)| {
                is_stale(made, modified, alive(*pid), now, stale_after())
            })
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
        if let Some(dir) = graph.parent() {
            let _ = std::fs::remove_file(dir.join(format!("{MARK_PREFIX}{pid}{TEMP_SUFFIX}")));
        }
        // Removed first: two sweeps at once count a mark once, by whoever
        // took it away.
        if std::fs::remove_file(mark).is_ok() {
            lost += 1;
        }
    }
    if lost == 0 {
        return 0;
    }
    // An outage of another fault in progress (a lock that timed out on a
    // busy disk, say) takes the cut records into its count, without a new
    // alert: a fresh episode under this code reset its start and its count
    // and alerted again, and the two codes took turns on a busy disk.
    match crate::record_health::report_at(graph) {
        Some(going) if going.code != CUT_CODE => {
            crate::record_health::note_failures_at(graph, &going.code, lost);
        }
        _ => {
            let outage = crate::record_health::note_failures_at(graph, CUT_CODE, lost);
            if crate::record_health::is_first_of_episode_at(graph) {
                alert(&outage.summary());
            }
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
        assert!(is_stale(Some(1_000), Some(1_000), false, 1_001, limit));
        assert!(!is_stale(Some(1_000), Some(1_000), true, 1_050, limit));
        assert!(is_stale(Some(1_000), Some(1_000), true, 1_101, limit));
    }

    /// Review of #414, item 3: a mark that says no second (being written,
    /// or unreadable) is stale by the file's own time or a process that is
    /// gone, never with its process running and the file young.
    ///
    /// FAILS ON REVERT of `is_stale` taking an unreadable mark for stale.
    #[test]
    fn an_unreadable_mark_of_a_running_hook_is_stale_only_by_age() {
        let limit = Duration::from_secs(100);
        assert!(!is_stale(None, Some(1_000), true, 1_050, limit));
        assert!(!is_stale(None, None, true, 1_050, limit));
        assert!(is_stale(None, Some(1_000), true, 1_101, limit));
        assert!(is_stale(None, None, false, 1_050, limit));
    }

    /// Review of #414, item 4: the mark's names are predictable in a folder
    /// the agent's account writes. A link planted at the temporary's name or
    /// at the mark's own name is never written through: the files they point
    /// at keep what they held, and the mark is a regular file of its own.
    ///
    /// FAILS ON REVERT of `begin` to `fs::write` at the mark's name.
    #[cfg(unix)]
    #[test]
    fn a_link_planted_at_a_mark_is_never_written_through() {
        let dir = tempfile::tempdir().unwrap();
        let graph = dir.path().join("graph.json");
        let outside = tempfile::tempdir().unwrap();
        let at_mark = outside.path().join("victim-a");
        let at_temp = outside.path().join("victim-b");
        std::fs::write(&at_mark, "kept a").unwrap();
        std::fs::write(&at_temp, "kept b").unwrap();
        let pid = std::process::id();
        let mark_name = dir.path().join(format!("{MARK_PREFIX}{pid}"));
        let temp_name = dir.path().join(format!("{MARK_PREFIX}{pid}{TEMP_SUFFIX}"));
        std::os::unix::fs::symlink(&at_mark, &mark_name).unwrap();
        std::os::unix::fs::symlink(&at_temp, &temp_name).unwrap();

        let mark = begin(&graph).expect("a mark of its own");
        assert_eq!(std::fs::read_to_string(&at_mark).unwrap(), "kept a");
        assert_eq!(std::fs::read_to_string(&at_temp).unwrap(), "kept b");
        let meta = std::fs::symlink_metadata(&mark).unwrap();
        assert!(meta.file_type().is_file(), "{meta:?}");
        assert!(!temp_name.exists() && std::fs::symlink_metadata(&temp_name).is_err());
        finish(&mark);
    }

    /// Review of #414, item 4: a new mark takes the mode the folder implies,
    /// as the record and the health file do, whatever the umask.
    #[cfg(unix)]
    #[test]
    fn a_mark_takes_the_mode_its_folder_implies() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let graph = dir.path().join("graph.json");
        let mark = begin(&graph).unwrap();
        let wanted = innerwarden_agent_guard::file_update::new_file_ownership(dir.path()).mode;
        let mode = std::fs::metadata(&mark).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, wanted);
        finish(&mark);
    }

    /// Review of #414, item 4: the sweep reads a mark without following a
    /// link. A link at a mark's name, to a file holding an old second, is no
    /// hook's mark: nothing is counted and nothing alerted.
    #[cfg(unix)]
    #[test]
    fn the_sweep_does_not_follow_a_link_at_a_mark() {
        let dir = tempfile::tempdir().unwrap();
        let graph = dir.path().join("graph.json");
        let old = dir.path().join("old-second");
        std::fs::write(&old, "1").unwrap();
        let gone = 4_194_304u32 + 23;
        std::os::unix::fs::symlink(&old, dir.path().join(format!("{MARK_PREFIX}{gone}"))).unwrap();
        assert_eq!(sweep_with(&graph, |_| panic!("no alert")), 0);
        assert!(crate::record_health::report_at(&graph).is_none());
    }

    /// Review of #414, item 5: with an outage of another fault in progress,
    /// a cut record is counted in it, under its code, with its start kept
    /// and no new alert. A fresh episode reset both and alerted again.
    ///
    /// FAILS ON REVERT of the `report_at` branch in `sweep_with`.
    #[cfg(unix)]
    #[test]
    fn a_cut_during_another_outage_is_counted_in_it() {
        let dir = tempfile::tempdir().unwrap();
        let graph = dir.path().join("graph.json");
        std::fs::write(&graph, "{}").unwrap();
        let first = crate::record_health::note_failure_at(&graph, "lock_timed_out");
        let gone = 4_194_304u32 + 29;
        std::fs::write(
            dir.path().join(format!("{MARK_PREFIX}{gone}")),
            now_unix().to_string(),
        )
        .unwrap();
        assert_eq!(sweep_with(&graph, |_| panic!("no new alert")), 1);
        let outage = crate::record_health::report_at(&graph).unwrap();
        assert_eq!(outage.code, "lock_timed_out");
        assert_eq!(outage.lost, 2);
        assert_eq!(outage.since_unix, first.since_unix);
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
